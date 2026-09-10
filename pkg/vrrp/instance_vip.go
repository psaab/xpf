package vrrp

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

// vipRemoveReconcileMax bounds the async retry that clears a stale VIP left on a
// now-BACKUP node when the synchronous removeVIPs failed (#5482).
const vipRemoveReconcileMax = 5

// defaultVIPReconcileBackoff spaces the stale-VIP remove retries in production:
// a transient netlink failure clears within ~1s without hammering the kernel.
// Per-instance override via vipReconcileBackoff (tests shorten it).
const defaultVIPReconcileBackoff = 200 * time.Millisecond

// surfaceStaleVIP records and self-heals a failed VIP removal on a BACKUP-side
// transition (#5482). It is a no-op on nil err (a clean removal clears the
// divergence flag). On a real failure it bumps the monotonic vipRemoveFailures
// counter, sets vipDiverged, logs at Error, and launches a bounded async retry so
// the stale VIP is cleared without leaving a silent duplicate-address hazard. The
// caller MUST have already published the BACKUP state (setState) so the retry's
// state guard sees BACKUP. `where` identifies the call site in logs.
func (vi *vrrpInstance) surfaceStaleVIP(err error, where string) {
	if err == nil {
		vi.vipDiverged.Store(false)
		return
	}
	vi.vipRemoveFailures.Add(1)
	vi.vipDiverged.Store(true)
	slog.Error("vrrp: VIP remove failed on BACKUP transition; a stale VIP may "+
		"remain on this now-BACKUP node — scheduling reconcile",
		"key", vi.key(), "where", where, "err", err)
	vi.scheduleVIPRemoveReconcile()
}

// errReconcileSuperseded signals that the stale-VIP reconcile observed a
// re-promotion — state != BACKUP or the ownership generation advanced past the
// tenure that scheduled it — while holding vipMu, so it aborted the delete
// rather than stripping a VIP a concurrent becomeMaster just re-added (#5482
// re-promotion TOCTOU). It is a control signal, not a failure: the goroutine
// returns and does NOT bump vipRemoveFailures.
var errReconcileSuperseded = errors.New("vrrp: stale-VIP reconcile superseded by re-promotion")

// removeVIPsIfBackup atomically re-validates, UNDER vipMu, that this instance is
// still the same BACKUP tenure identified by wantGen before removing the VIP set
// (#5482 re-promotion TOCTOU fix). It mirrors reconcileVIP's capture+recheck-
// under-lock: becomeMaster runs setState(MASTER) — which bumps ownerGen — BEFORE
// it takes vipMu to add the VIP, so a state+generation recheck under the SAME
// vipMu hold that would perform the delete reliably detects a racing re-promotion.
// Without it the reconcile's bare removeVIPs (state checked OUTSIDE the lock)
// could interleave between the check and the lock acquisition and delete the VIP
// becomeMaster just added — a MASTER self-blackhole until the next ReconcileVIPs.
//
// Returns errReconcileSuperseded (no delete performed) when state != BACKUP or
// ownerGen advanced past wantGen; otherwise returns the removeVIPsLocked outcome.
func (vi *vrrpInstance) removeVIPsIfBackup(wantGen uint64) error {
	vi.vipMu.Lock()
	defer vi.vipMu.Unlock()
	// Recheck under the lock: setState bumps ownerGen independently of vipMu, so
	// a demotion/re-promotion that raced in is observed here even though it
	// happened while we held vipMu (identical to reconcileVIP's revalidation).
	if vi.getState() != StateBackup || vi.ownerGen.Load() != wantGen {
		return errReconcileSuperseded
	}
	return vi.removeVIPsLocked(nil)
}

// scheduleVIPRemoveReconcile launches a bounded background retry that re-attempts
// the VIP removal that failed during a BACKUP transition (#5482). The BACKUP role
// is already published (we ARE a backup); this goroutine drives the kernel VIP
// state back into agreement with that role WITHOUT blocking the run-loop, and
// clears vipDiverged on success. It stops early if the node is re-promoted to
// MASTER (it then WANTS the VIP) or the instance shuts down. Per-attempt failures
// are logged but do NOT bump vipRemoveFailures — that counter stays a clean count
// of BACKUP transitions whose synchronous removal failed.
//
// Re-promotion TOCTOU (#5482): the removal runs through removeVIPsIfBackup, which
// re-validates state + ownerGen UNDER vipMu before deleting. Capturing the tenure
// generation here (right after the failing BACKUP transition, which already ran
// setState(StateBackup)) lets the retry abort if a later becomeMaster re-owns the
// VIP — otherwise the reconcile could strip a re-promoted MASTER's VIP.
func (vi *vrrpInstance) scheduleVIPRemoveReconcile() {
	backoff := vi.vipReconcileBackoff
	if backoff <= 0 {
		backoff = defaultVIPReconcileBackoff
	}
	// Identity of the BACKUP tenure that failed its synchronous removal. The
	// reconcile deletes VIPs on behalf of THIS tenure only.
	gen := vi.ownerGen.Load()
	go func() {
		for attempt := 1; attempt <= vipRemoveReconcileMax; attempt++ {
			select {
			case <-vi.stopCh:
				return
			case <-time.After(backoff):
			}
			// The state/gen recheck and the delete are atomic under vipMu inside
			// removeVIPsIfBackup, so a concurrent becomeMaster (setState(MASTER)
			// → vipMu → addVIPsLocked) cannot interleave between the recheck and
			// the delete and lose the re-added VIP.
			err := vi.removeVIPsIfBackup(gen)
			if errors.Is(err, errReconcileSuperseded) {
				// Re-promoted to MASTER (or a newer tenure began) → we now WANT
				// the VIP; the new tenure owns the divergence decision. Stop.
				return
			}
			if err != nil {
				slog.Warn("vrrp: stale-VIP remove reconcile attempt failed",
					"key", vi.key(), "attempt", attempt, "err", err)
				continue
			}
			vi.vipDiverged.Store(false)
			slog.Info("vrrp: stale-VIP remove reconcile succeeded",
				"key", vi.key(), "attempt", attempt)
			return
		}
		slog.Error("vrrp: stale-VIP remove reconcile exhausted retries; a VIP may "+
			"remain on this BACKUP node until the next transition",
			"key", vi.key())
	}()
}

// addVIPs adds virtual IP addresses to the interface via netlink.
// vipActuationResult reports the outcome of an attempt to add the instance's
// virtual IP set on the interface (#5082). It lets becomeMaster/ReconcileVIPs
// gate ownership publication on the ACTUAL kernel state instead of assuming the
// add succeeded (the old void addVIPs swallowed every failure).
type vipActuationResult struct {
	// applied lists the VIPs confirmed present after the op — freshly added
	// OR already present (EEXIST). These are the addresses to roll back if the
	// tenure turns out to be stale/degraded.
	applied []string
	// failed lists VIPs that could not be actuated: an unresolvable interface
	// (linkErr set — every VIP fails), a parse error, or a netlink AddrAdd
	// error other than EEXIST.
	failed []string
	// linkErr is non-nil if the interface itself could not be resolved via
	// netlink; in that case no VIP could be actuated at all.
	linkErr error
}

// ok reports whether the FULL required VIP set actuated: the interface
// resolved and no VIP failed. becomeMaster claims ownership only when ok().
func (r vipActuationResult) ok() bool {
	return r.linkErr == nil && len(r.failed) == 0
}

// nlLinkByName resolves an interface, via the test seam when set.
func (vi *vrrpInstance) nlLinkByName(name string) (netlink.Link, error) {
	if vi.linkByNameFn != nil {
		return vi.linkByNameFn(name)
	}
	return netlink.LinkByName(name)
}

// nlAddrAdd adds an address, via the test seam when set.
func (vi *vrrpInstance) nlAddrAdd(link netlink.Link, addr *netlink.Addr) error {
	if vi.addrAddFn != nil {
		return vi.addrAddFn(link, addr)
	}
	return netlink.AddrAdd(link, addr)
}

// nlAddrDel deletes an address, via the test seam when set.
func (vi *vrrpInstance) nlAddrDel(link netlink.Link, addr *netlink.Addr) error {
	if vi.addrDelFn != nil {
		return vi.addrDelFn(link, addr)
	}
	return netlink.AddrDel(link, addr)
}

// addVIPsLocked adds the instance's configured virtual IP set to the interface
// and returns which VIPs actuated and which failed. The caller MUST hold vipMu.
// It replaces the old void addVIPs: a swallowed LinkByName/AddrAdd failure used
// to let becomeMaster publish an owner that could not receive VIP traffic
// (#5082). EEXIST counts as applied (the address is present regardless).
func (vi *vrrpInstance) addVIPsLocked() vipActuationResult {
	var res vipActuationResult
	link, err := vi.nlLinkByName(vi.cfg.Interface)
	if err != nil {
		slog.Warn("vrrp: failed to find interface for VIP add",
			"key", vi.key(), "err", err)
		res.linkErr = err
		res.failed = append(res.failed, vi.cfg.VirtualAddresses...)
		return res
	}
	for _, vip := range vi.cfg.VirtualAddresses {
		addr, err := netlink.ParseAddr(vip)
		if err != nil {
			slog.Warn("vrrp: failed to parse VIP",
				"key", vi.key(), "vip", vip, "err", err)
			res.failed = append(res.failed, vip)
			continue
		}
		// Skip DAD for IPv6 VIPs — VRRP handles ownership; DAD would
		// fail because the secondary may still have the address briefly.
		if addr.IP.To4() == nil {
			addr.Flags |= unix.IFA_F_NODAD
		}
		if err := vi.nlAddrAdd(link, addr); err != nil {
			// EEXIST is fine — address already present, so it IS actuated.
			if strings.Contains(err.Error(), "exists") {
				res.applied = append(res.applied, vip)
			} else {
				slog.Warn("vrrp: failed to add VIP",
					"key", vi.key(), "vip", vip, "err", err)
				res.failed = append(res.failed, vip)
			}
		} else {
			slog.Info("vrrp: added VIP", "key", vi.key(), "vip", vip)
			res.applied = append(res.applied, vip)
		}
	}
	return res
}

// removeVIPs removes ALL configured virtual IP addresses from the interface.
// It acquires vipMu so it is safe to call from the run-loop (becomeBackup, run
// startup/shutdown) without interleaving a concurrent ReconcileVIPs add (#5082).
// It returns the first genuine netlink removal failure (nil on success) so a
// BACKUP-side caller can surface a stale VIP instead of swallowing it (#5482).
func (vi *vrrpInstance) removeVIPs() error {
	vi.vipMu.Lock()
	defer vi.vipMu.Unlock()
	return vi.removeVIPsLocked(nil)
}

// removeVIPsLocked removes the given VIPs (nil ⇒ all configured VirtualAddresses)
// from the interface via netlink. The caller MUST hold vipMu. Passing a subset
// (res.applied) lets a failed/superseded actuation roll back exactly the
// addresses it added.
//
// It returns the first genuine removal failure so becomeBackup can detect a VIP
// that is still on the wire (#5482). A benign case is NOT an error: an
// unresolvable interface means the address is gone with the link (best-effort
// teardown cleanup), and an already-absent AddrDel — ENODEV/ENOENT
// ("not found"/"no such") OR EADDRNOTAVAIL ("cannot assign requested address",
// the common already-absent errno on a clean boot) — means the address was never
// on the interface. Neither leaves a stale VIP answering ARP, so neither is a
// divergence. Only an AddrDel that fails for another reason against a resolvable
// interface is a real divergence.
func (vi *vrrpInstance) removeVIPsLocked(vips []string) error {
	if vips == nil {
		vips = vi.cfg.VirtualAddresses
	}
	if len(vips) == 0 {
		return nil
	}
	link, err := vi.nlLinkByName(vi.cfg.Interface)
	if err != nil {
		// Interface gone/mid-rename → no live address to strand; best-effort.
		slog.Debug("vrrp: failed to find interface for VIP remove",
			"key", vi.key(), "err", err)
		return nil
	}
	var firstErr error
	for _, vip := range vips {
		addr, err := netlink.ParseAddr(vip)
		if err != nil {
			// A malformed VIP was never actuated, so it is not on the wire.
			continue
		}
		if err := vi.nlAddrDel(link, addr); err != nil {
			// Benign already-absent cases: the address is not on the interface,
			// so there is no stale VIP left answering ARP. The kernel signals an
			// absent address several ways on AddrDel:
			//   - ENODEV/ENOENT → "not found"/"no such" (the original checks)
			//   - EADDRNOTAVAIL → "cannot assign requested address" — the MOST
			//     common already-absent errno. A fresh boot / restart-as-backup
			//     runs the run-startup BACKUP removal (and becomeBackup) against
			//     VIPs that were NEVER on the interface, so every AddrDel returns
			//     EADDRNOTAVAIL. Treating that as a real failure would flag
			//     vipDiverged on EVERY clean boot and the reconcile would retry
			//     the still-absent address to exhaustion, leaving the operator-
			//     facing divergence flag stuck TRUE for the daemon's life —
			//     cry-wolfing the exact diagnostic #5482 exists to provide.
			// errors.Is unwraps the netlink errno even when it is annotated with
			// NLMSGERR_ATTR TLV text; the string check is a belt-and-suspenders
			// match for wrappers that only expose Error().
			if errors.Is(err, unix.EADDRNOTAVAIL) ||
				strings.Contains(err.Error(), "cannot assign requested address") ||
				strings.Contains(err.Error(), "not found") ||
				strings.Contains(err.Error(), "no such") {
				continue
			}
			slog.Debug("vrrp: failed to remove VIP",
				"key", vi.key(), "vip", vip, "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("del vip %q: %w", vip, err)
			}
		}
	}
	return firstErr
}

// reconcileVIP re-adds this instance's VIPs if it is currently MASTER, then
// forces a GARP burst — but only if the instance is STILL the current-generation
// MASTER after the netlink add completes (#5082). ReconcileVIPs runs on the
// manager goroutine while becomeMaster/becomeBackup run on the run-loop, so the
// old `if getState()==StateMaster { addVIPs() }` was a check-then-act TOCTOU: a
// superior advert transitioning us to BACKUP could interleave between the state
// check and the netlink add, re-adding VIPs and forcing GARP while BACKUP
// (duplicate address, ARP/ND, split routing).
//
// The fix holds vipMu across "state check + generation capture + netlink add +
// revalidation". becomeBackup's removeVIPs also takes vipMu, so it cannot
// interleave the add; and setState bumps ownerGen independently of vipMu, so the
// post-add revalidation observes a racing demotion even though it happened while
// we held vipMu. On a superseding transition we roll back exactly the VIPs we
// re-added and suppress the forced GARP — a BACKUP never announces VIPs.
func (vi *vrrpInstance) reconcileVIP() {
	vi.vipMu.Lock()
	if vi.getState() != StateMaster {
		vi.vipMu.Unlock()
		return
	}
	gen := vi.ownerGen.Load()
	res := vi.addVIPsLocked()
	// Revalidate under vipMu: a becomeBackup that raced in bumped ownerGen (and
	// flipped state). If superseded, undo the re-added VIPs and do NOT GARP —
	// announcing a VIP we no longer own is the split-routing hazard this closes.
	if vi.getState() != StateMaster || vi.ownerGen.Load() != gen {
		// #9509: a failed rollback HERE is not stranded, so it is logged, not
		// surfaced. The only transition that can supersede a reconcile holding
		// vipMu is becomeBackup: every state write goes through setState, and
		// becomeMaster's own state changes cannot interleave. becomeBackup blocks
		// on vipMu behind this rollback, then removes ALL configured VIPs and
		// surfaces that result. Pinned by
		// TestSupersededReconcileRollbackIsCoveredByBecomeBackup_9509.
		rollbackErr := vi.removeVIPsLocked(res.applied)
		vi.vipMu.Unlock()
		slog.Warn("vrrp: ReconcileVIPs superseded by demotion; rolled back re-added VIPs, GARP suppressed",
			"key", vi.key(), "rolled_back", res.applied, "rollback_err", rollbackErr)
		return
	}
	// Bump garpEpoch so the epoch-dedup in sendGARP() doesn't block this send.
	// ReconcileVIPs is called after programRethMAC (link DOWN/UP) which changes
	// the MAC — GARP is critical here.
	vi.garpEpoch.Add(1)
	suppress := vi.suppressGARP.Load()
	vi.vipMu.Unlock()
	if !suppress {
		// force=true: bypass the 500ms time dampener. The epoch bump above
		// defeats the epoch-dedup, but the dampener would STILL suppress this
		// burst if any routine GARP was emitted in the prior 500ms — leaving
		// peers with a stale ARP entry for the just-changed RETH virtual MAC
		// until it ages out (#2081).
		vi.sendGARP(true)
	}
}
