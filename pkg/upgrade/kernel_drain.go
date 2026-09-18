package upgrade

import (
	"fmt"
	"strings"
	"time"
)

// Non-interactive drain/rejoin for the external LANE-1 HA kernel roll
// (#1930 INC-2). These reuse the RollingCluster surface (#1917) so the kernel
// roll drives the SAME proven automation path as the binary rolling cut — and,
// critically, CONFIRM the strong predicates (r1 Codex Critical: the external
// driver must never arm+reboot an undrained primary, nor advance to the peer
// before this node is fully rejoined).

// drainPollInterval is how often the predicates are re-checked while waiting.
const drainPollInterval = 1 * time.Second

// DrainAndConfirm demotes the local node and waits for the STRONG drain
// predicate (peer owns the RGs + sync clean) within deadline. It first refuses
// to drain if the peer is not alive or not takeover-ready — so a drain can never
// strand VIPs. Unless allowMixedHA is set, it ALSO refuses an HA-incompatible
// peer (exact-equality), so a single-version LANE-1 roll never splits a
// mixed-protocol cluster. allowMixedHA=true (the LANE-2 image-roll second drain,
// whose mixed-base gate already validated window-compat) intentionally BYPASSES
// only that exact-equality HA check; the peer-alive and takeover-ready prechecks
// still apply (Copilot).
func DrainAndConfirm(cl RollingCluster, deadline time.Duration, allowMixedHA bool) error {
	// Pre-checks: a peer that cannot take over must NOT be drained to.
	alive, err := cl.PeerAlive()
	if err != nil {
		return fmt.Errorf("peer-alive check: %w", err)
	}
	if !alive {
		return fmt.Errorf("peer is not alive — refusing to drain (no node to take over)")
	}
	// HAProtocolCompatible is EXACT-equality (local==peer). For the LANE-1
	// kernel roll the cluster is single-version, so equality is correct. For the
	// LANE-2 image-roll the mixed-base gate has ALREADY validated window-compat
	// (peer in [min-compat, version]), and the SECOND node's drain runs against
	// an already-rolled peer that may legitimately differ within that window —
	// exact-equality would wrongly abort it (r3 Codex HIGH). The orchestrator
	// passes allowMixedHA to relax this one check in that vetted case only.
	if !allowMixedHA {
		compat, err := cl.HAProtocolCompatible()
		if err != nil {
			return fmt.Errorf("HA-protocol check: %w", err)
		}
		if !compat {
			// #7990: this message used to say "HA/session-sync protocol
			// incompatible" while the check looked only at the HA protocol
			// version — a claim the code did not support, and since #7925 the
			// two are separate counters. Name only what was checked.
			return fmt.Errorf("HA protocol incompatible with peer — " +
				"this kernel roll is not safe; use image-replace (LANE 2)")
		}
	}
	// #7990: the session-sync WIRE version is a SEPARATE gate from the HA
	// protocol one, and until now the in-place path had neither the channel nor
	// the check. A drain hands the RGs to the peer; if the peer cannot decode
	// this node's session frames, that handover drops every established flow
	// while heartbeat, election and failover all keep working — so the cluster
	// looks healthy and the loss is only discovered at the failover.
	//
	// NOT gated behind allowMixedHA. That flag exists because the LANE-2
	// mixed-base gate already validated the HA WINDOW and exact-equality would
	// wrongly abort the second node; it says nothing about the session wire,
	// which GateMixedBaseSwap checks for EXACT equality in both cases. Reusing
	// it here would silently disable this gate on exactly the path that most
	// needs it.
	syncOK, syncWhy, err := cl.SessionSyncWireCompatible()
	if err != nil {
		return fmt.Errorf("session-sync wire check: %w", err)
	}
	if !syncOK {
		return fmt.Errorf("session-sync wire incompatible with peer (%s) — draining would "+
			"hand over to a node that cannot receive this node's sessions; use "+
			"image-replace (LANE 2), which gates on this version explicitly", syncWhy)
	}
	ready, err := cl.PeerTakeoverReady()
	if err != nil {
		return fmt.Errorf("peer-takeover-ready check: %w", err)
	}
	if !ready {
		return fmt.Errorf("peer is not takeover-ready — refusing to drain (would strand VIPs)")
	}

	if err := cl.ForceSecondary(); err != nil {
		return fmt.Errorf("force secondary: %w", err)
	}

	// Wait for the STRONG drain predicate. If it does not hold within the
	// deadline, the caller must NOT proceed AND we must NOT leave the node
	// force-demoted with the peer not having taken over — that would strand the
	// VIPs (r2 Codex). FAIL BACK (ResetFailover) before returning the error, so
	// this node resumes serving rather than sitting demoted with no primary.
	dl := time.Now().Add(deadline)
	for {
		ok, derr := cl.DrainComplete()
		if derr == nil && ok {
			return nil
		}
		// Bound the next sleep to the remaining time so we do not overshoot the
		// deadline by up to a full poll interval (Copilot): small deadlines (incl.
		// tests) must not silently turn into deadline+interval.
		if time.Now().After(dl) {
			if rbErr := cl.ResetFailover(); rbErr != nil {
				return fmt.Errorf("drain did not complete within %s AND failback "+
					"failed (%v) — node may be stranded demoted; operator attention needed "+
					"(drain error: %v)", deadline, rbErr, derr)
			}
			// #9038: "failed back" here was an acknowledgement, not an
			// observation — same defect as the rolling abort branch, same fix.
			// A nil ResetFailover re-runs the election; with a healthy peer
			// holding the RG the node stays SECONDARY and the reset still
			// returns nil.
			rejoined, rerr := cl.LocalRejoinComplete()
			if rerr != nil || !rejoined {
				return fmt.Errorf("drain did not complete within %s AND the failback was "+
					"ACKNOWLEDGED but this node has NOT resumed ownership of every "+
					"redundancy group (local-rejoined=%v readback-error=%v) — operator "+
					"attention needed (drain error: %v)", deadline, rejoined, rerr, derr)
			}
			if derr != nil {
				return fmt.Errorf("drain did not complete within %s (failed back, CONFIRMED; last error: %w)", deadline, derr)
			}
			return fmt.Errorf("drain did not complete within %s (peer did not take over / sync not clean; failed back, CONFIRMED)", deadline)
		}
		sleepBounded(dl, drainPollInterval)
	}
}

// sleepBounded sleeps for `interval`, but never past dl — so a poll loop
// re-checks (and reports timeout) at the deadline rather than overshooting it by
// up to a full interval.
//
// #7424: `interval` was `drainPollInterval` until rolling.go's waitPredicate
// became the third caller. That loop polls on the caller-supplied
// RollingConfig.PollInterval, so the interval is a parameter rather than a
// package constant; the two kernel-drain callers pass drainPollInterval and are
// unchanged in behaviour.
func sleepBounded(dl time.Time, interval time.Duration) {
	rem := time.Until(dl)
	if rem <= 0 {
		return
	}
	if rem < interval {
		time.Sleep(rem)
		return
	}
	time.Sleep(interval)
}

// RejoinAndConfirm confirms inbound bulk state before clearing the local
// ForceSecondary hold, then confirms election eligibility after the reset.
// The node must remain held secondary while the restarted daemon's session
// table is incomplete: resetting first would let election promote it before
// #10261's late bulk flow arrives.
func RejoinAndConfirm(cl RollingCluster, deadline time.Duration) error {
	dl := time.Now().Add(deadline)
	var lastAErr, lastSErr, lastBErr, lastRErr error
	timeout := func(alive, synced, bulkPrimed, rejoined bool) error {
		base := fmt.Errorf("rejoin not confirmed within %s "+
			"(peer-alive=%v sync-established=%v bulk-primed=%v local-rejoined=%v)",
			deadline, alive, synced, bulkPrimed, rejoined)
		var details []string
		if lastAErr != nil {
			details = append(details, fmt.Sprintf("last peer-alive error: %v", lastAErr))
		}
		if lastSErr != nil {
			details = append(details, fmt.Sprintf("last sync-established error: %v", lastSErr))
		}
		if lastBErr != nil {
			details = append(details, fmt.Sprintf("last session-sync bulk-prime error: %v", lastBErr))
		}
		if lastRErr != nil {
			details = append(details, fmt.Sprintf("last local-rejoin error: %v", lastRErr))
		}
		if len(details) > 0 {
			return fmt.Errorf("%w; %s", base, strings.Join(details, "; "))
		}
		return base
	}

	// Phase 1: the node is still held secondary. Wait for the peer, sync
	// transport, and the actual inbound BulkEnd before allowing election to
	// resume. LocalRejoinComplete is intentionally not queried yet: reset has
	// not been requested and false is expected.
	for {
		alive, aerr := cl.PeerAlive()
		synced, serr := cl.SyncEstablished()
		bulkPrimed, berr := cl.SessionSyncBulkPrimed()
		if aerr == nil && serr == nil && berr == nil && alive && synced && bulkPrimed {
			break
		}
		if aerr != nil {
			lastAErr = aerr
		}
		if serr != nil {
			lastSErr = serr
		}
		if berr != nil {
			lastBErr = berr
		} else if !bulkPrimed {
			lastBErr = fmt.Errorf("session-sync inbound bulk prime not complete")
		}
		if time.Now().After(dl) {
			return timeout(alive, synced, bulkPrimed, false)
		}
		sleepBounded(dl, drainPollInterval)
	}

	// Phase 2: only now clear the hold, then confirm every configured RG has
	// actually resumed election eligibility before the caller advances.
	if err := cl.ResetFailover(); err != nil {
		return fmt.Errorf("reset failover: %w", err)
	}
	for {
		alive, aerr := cl.PeerAlive()
		synced, serr := cl.SyncEstablished()
		bulkPrimed, berr := cl.SessionSyncBulkPrimed()
		rejoined, rerr := cl.LocalRejoinComplete()
		if aerr == nil && serr == nil && berr == nil && rerr == nil &&
			alive && synced && bulkPrimed && rejoined {
			return nil
		}
		if aerr != nil {
			lastAErr = aerr
		}
		if serr != nil {
			lastSErr = serr
		}
		if berr != nil {
			lastBErr = berr
		} else if !bulkPrimed {
			lastBErr = fmt.Errorf("session-sync inbound bulk prime not complete")
		}
		if rerr != nil {
			lastRErr = rerr
		}
		if time.Now().After(dl) {
			return timeout(alive, synced, bulkPrimed, rejoined)
		}
		sleepBounded(dl, drainPollInterval)
	}
}
