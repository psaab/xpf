package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #8607: keep the persistent-NAT SHOW table populated under the userspace
// dataplane.
//
// THE DEFECT, and it is structural rather than a race.
// `show security nat source persistent-nat-table` printed "No persistent NAT
// bindings" for the whole life of a pool that was demonstrably translating —
// during traffic, in steady state, and after the sessions aged out.
//
// The renderer reads dataplane.PersistentNATTable, whose only binding writer is
// PersistentNATTable.Save, reached only from preservePersistentNATV4/V6 on
// dataPlaneSessionStore's DELETE path. The hook itself is intact — deleting a
// SNAT'd session through that store produces exactly the binding the report
// observed, which was instrumented rather than argued. What never happens on
// this path is the delete:
//
//	daemon_run.go — "When the userspace dataplane is active, skip BPF session
//	map GC entirely":  gc.SkipSweep = func() bool { return true }
//
// and gc.sweep() returns at its FIRST statement when that is set — before
// DeleteBatchKnownV4 (which calls the preserve hook) AND before pnat.GC(). So
// the table is dead in BOTH directions on the only runtime forwarding path the
// product has: never written, and never expired either. The remaining caller of
// the delete path is commit-time policy invalidation, which requires an
// operator to delete or modify a policy — not something steady-state forwarding
// produces.
//
// WHY NOT RE-ENABLE THE SWEEP. It is disabled for a measured reason (~19% CPU
// scanning maps not used for forwarding, #333) and the Rust helper owns session
// lifetime. Re-enabling it to populate a display table would pay a forwarding-
// path cost for an operator surface.
//
// WHY NOT TEACH THE RENDERER TO ASK THE BACKEND. That was the first design and
// it is worse here. natshow's Reader is satisfied by a fixture that embeds a
// NIL Reader (persistent_single_resolution_2114_test.go's vanishingTableReader),
// so any new method the renderer calls nil-panics those cells — and the failure
// reads as a #2114 single-resolution regression rather than a fixture gap.
// natshow also cannot import pkg/dataplane/userspace: that package's own
// in-package test imports natshow, so the edge would be an import cycle.
// Filling the table the renderer already reads leaves both renderers, the
// Reader interface and all three existing cells untouched.
//
// WHAT THIS SHOWS — updated by #8615, which closed the gap this paragraph used
// to describe as deliberate.
//
// #8607 filled the table from `export_idle_leases` (#8121), which carries the
// IDLE population only (`active_flows == 0 && expires_at_ns > now_ns`), so a
// binding was observable once its sessions were gone and NOT while they were
// open. That could not be fixed by widening the sync record:
// nat/idle_lease_sync_8121.rs's first design rule is "Never carry
// `active_flows`", because a standby installs a strict subset and a carried
// count credits a lease for sessions that node does not hold, so it never
// reaches zero and no GC path can reclaim it.
//
// #8615 added a SEPARATE display-only record and verb instead —
// `export_persistent_lease_display`, filtered by the allocator's own reuse
// predicate (`active_flows > 0 || expires_at_ns > now_ns`) so the table answers
// exactly "which bindings will this node reuse". The refresher below prefers it
// and degrades to `ExportIdleLeases` only against a helper that predates it,
// which is a rolling-upgrade window rather than a steady state. The sync record
// is untouched and still cannot carry a flow count — pinned by
// TestTheSyncLeaseRecordStillCarriesNoFlowCount8615.
//
// The idle half remains the half that was entirely missing, and it is still the
// half that matters most: while a session is open its translation is already
// visible in `show security flow session`, and what persistent-nat-table
// uniquely answers is which bindings SURVIVE the session. It is also exactly the
// population #8573's failover measurement has to assert.

// persistentNatShowRefreshInterval paces the refresh.
//
// Matched to the #8121 lease-sync tick rather than chosen freely, and slow on
// purpose: manager_idle_leases_8121.go and CLAUDE.md are both explicit that the
// control socket is shared with the 1 Hz status poll, HA session sync, session
// installs and snapshot sync, and that a new caller above 1/s starves session
// installs during bulk sync. This is an operator-visibility refresh, so a
// 30-second staleness is the right trade against that contention.
const persistentNatShowRefreshInterval = 30 * time.Second

// runPersistentNatShowRefreshLoop keeps the SHOW table in step with the helper.
//
// It is started from the daemon run path rather than from cluster-comms wiring
// on purpose: the #8121 push loop lives there and is gated on being RG master,
// which is right for a peer push and wrong for an operator table — a standalone
// box with a persistent-NAT pool would otherwise keep the empty table this
// exists to fix.
func (d *Daemon) runPersistentNatShowRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(persistentNatShowRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refreshPersistentNatShowTable()
		}
	}
}

// refreshPersistentNatShowTable replaces the SHOW table with the helper's view.
//
// EVERY EARLY RETURN LEAVES THE TABLE ALONE, which is the difference between
// "the helper has no bindings" and "we could not ask". Emptying it on an error
// would render as "No persistent NAT bindings" — the exact false statement this
// issue is about — for a helper that is merely restarting.
func (d *Daemon) refreshPersistentNatShowTable() {
	if d == nil {
		return
	}
	rt := d.dataplane()
	if rt == nil {
		return
	}
	table := persistentNatShowTable(rt)
	if table == nil {
		return
	}
	mgr := d.persistentNatLeaseManager()
	if mgr == nil {
		// Not the userspace backend: whatever populates the table on that
		// path keeps doing so, and this refresher must not clear it.
		return
	}
	// #8615: prefer the DISPLAY verb, which carries bindings with LIVE flows
	// too. Degrade to the idle-only export only when the helper does not
	// implement it — a mixed-version window during a rolling upgrade.
	// Capture before export; a concurrent clear changes the table generation and
	// makes this response ineligible for ReplaceAll.
	clearGen := table.ClearGeneration()
	display, err := mgr.ExportPersistentLeaseDisplay()
	if err == nil {
		applyPersistentNatShowRefreshDisplay(table, display, nil, time.Now(), clearGen)
		return
	}
	if !errors.Is(err, dpuserspace.ErrPersistentLeaseDisplayUnsupported) {
		// A genuine failure. Hand it to the decision half, which keeps the
		// previous snapshot rather than asserting an emptiness nobody observed.
		applyPersistentNatShowRefreshDisplay(table, nil, err, time.Now(), clearGen)
		return
	}
	// The helper predates #8615. Say so once per tick at Debug — loud enough to
	// explain a table that shows only idle bindings, quiet enough for a 30s
	// loop — then answer the half we can.
	slog.Debug("userspace helper does not implement export_persistent_lease_display; "+
		"persistent-NAT show table will omit bindings that still have live flows",
		"verb", "export_persistent_lease_display")
	leases, idleErr := mgr.ExportIdleLeases()
	applyPersistentNatShowRefresh(table, leases, idleErr, time.Now(), clearGen)
}

// applyPersistentNatShowRefreshDisplay is applyPersistentNatShowRefresh for the
// #8615 record. Same error discipline, stated there and not repeated: an error
// leaves the previous snapshot standing rather than rendering an emptiness
// nobody observed.
func applyPersistentNatShowRefreshDisplay(
	table *dataplane.PersistentNATTable,
	leases []dpuserspace.DisplayLeaseWire,
	err error,
	now time.Time,
	clearGen uint64,
) bool {
	if table == nil {
		return false
	}
	if err != nil {
		slog.Debug("persistent-NAT show table refresh failed; keeping the previous "+
			"snapshot rather than reporting an emptiness that was not observed",
			"err", err)
		return false
	}
	if !table.ReplaceAllUnlessClearedSince(
		persistentNatBindingsFromDisplayLeases(leases, now),
		clearGen,
	) {
		return false
	}
	return true
}

// persistentNatBindingsFromDisplayLeases converts the #8615 display record.
//
// THE ONE THING THIS DOES THAT THE IDLE CONVERTER DOES NOT, and it is the
// reason the two are not one function: a binding with LIVE flows has a
// meaningless RemainingNs. The allocator writes expires_at_ns at the most
// recent reuse and does NOT refresh it per packet — the countdown is rewritten
// only when the LAST flow closes (allocator.rs:2246-2250). So a long-lived
// session routinely leaves a perfectly healthy binding reading
// `remaining_ns == 0`, and back-dating LastSeen by (timeout - 0) would render
// every actively-used binding as expired. That is a worse lie than the empty
// table #8607 fixed, because it looks like data.
//
// While ActiveFlows > 0 the binding does not expire at all, and the floor on
// its remaining life is the FULL timeout measured from whenever the last flow
// closes. LastSeen = now renders exactly that floor.
func persistentNatBindingsFromDisplayLeases(
	leases []dpuserspace.DisplayLeaseWire,
	now time.Time,
) []*dataplane.PersistentNATBinding {
	if len(leases) == 0 {
		return nil
	}
	out := make([]*dataplane.PersistentNATBinding, 0, len(leases))
	for _, l := range leases {
		srcIP, err := netip.ParseAddr(l.SrcIP)
		if err != nil {
			continue
		}
		natIP, err := netip.ParseAddr(l.TranslatedIP)
		if err != nil {
			continue
		}
		timeout := time.Duration(l.TimeoutNs)
		lastSeen := now
		if l.ActiveFlows == 0 {
			remaining := time.Duration(l.RemainingNs)
			if remaining > timeout {
				remaining = timeout
			}
			lastSeen = now.Add(-(timeout - remaining))
		}
		out = append(out, &dataplane.PersistentNATBinding{
			SrcIP:    srcIP,
			SrcPort:  l.SrcPort,
			NatIP:    natIP,
			NatPort:  l.TranslatedPort,
			PoolName: l.Pool,
			LastSeen: lastSeen,
			Timeout:  timeout,
			Permit:   persistentNatPermitFromDisplayWire(l),
		})
	}
	return out
}

func persistentNatPermitFromDisplayWire(l dpuserspace.DisplayLeaseWire) config.PersistentNATPermit {
	if l.RemoteIP == "" {
		return config.PersistentNATPermitAnyRemoteHost
	}
	if l.RemotePort == 0 {
		return config.PersistentNATPermitTargetHost
	}
	return config.PersistentNATPermitTargetHostPort
}

// applyPersistentNatShowRefresh is the DECISION half, extracted so the
// distinction it exists for is testable without a helper process.
//
// "The helper reports no bindings" and "we could not ask the helper" are
// different answers that must not render the same. Replacing on an error would
// print "No persistent NAT bindings" — the exact false statement #8607 is
// about — for a helper that is merely restarting, and it would do it for the
// 30 seconds until the next tick. So an error leaves the previous snapshot
// standing, stale and labelled by its own remaining-time column, rather than
// asserting an emptiness nobody observed.
//
// Returns whether the table was replaced, so a caller (and a test) can tell the
// two apart without reading the table.
func applyPersistentNatShowRefresh(
	table *dataplane.PersistentNATTable,
	leases []dpuserspace.IdleLeaseWire,
	err error,
	now time.Time,
	clearGen uint64,
) bool {
	if table == nil {
		return false
	}
	if err != nil {
		slog.Debug("persistent-NAT show table refresh failed; keeping the previous "+
			"snapshot rather than reporting an emptiness that was not observed",
			"err", err)
		return false
	}
	if !table.ReplaceAllUnlessClearedSince(
		persistentNatBindingsFromLeases(leases, now),
		clearGen,
	) {
		return false
	}
	return true
}

// persistentNatShowTable resolves the table the renderers read, through the
// same accessor they use, so this cannot populate a different object from the
// one `show` prints.
func persistentNatShowTable(rt dataplane.RuntimeDataPlane) *dataplane.PersistentNATTable {
	g, ok := dataplane.Unwrap(rt).(interface {
		GetPersistentNAT() *dataplane.PersistentNATTable
	})
	if !ok {
		return nil
	}
	return g.GetPersistentNAT()
}

// persistentNatBindingsFromLeases converts the helper's wire leases into the
// SHOW record.
//
// LastSeen IS DERIVED, not stamped with now. The renderer computes remaining as
// `time.Until(LastSeen.Add(Timeout))`, and the wire carries REMAINING lifetime
// (never an absolute deadline — #8121 design note 2: expires_at_ns is
// CLOCK_MONOTONIC and boot-relative). Setting LastSeen = now would therefore
// display the FULL timeout for every binding on every refresh, counting down
// from a value it never had. Back-dating by (timeout - remaining) makes the
// rendered column the helper's actual remaining lifetime.
//
// Permit is derived from the remote tuple the wire already carries, because the
// record does not carry the mode itself: the #8121 comment states the
// convention ("Empty => permit-any-remote-host") and the port half distinguishes
// target-host from target-host-port. That is a read of the same three-way scope
// #2823/#3193 added, not a new one.
func persistentNatBindingsFromLeases(leases []dpuserspace.IdleLeaseWire, now time.Time) []*dataplane.PersistentNATBinding {
	if len(leases) == 0 {
		return nil
	}
	out := make([]*dataplane.PersistentNATBinding, 0, len(leases))
	for _, l := range leases {
		srcIP, err := netip.ParseAddr(l.SrcIP)
		if err != nil {
			continue
		}
		natIP, err := netip.ParseAddr(l.TranslatedIP)
		if err != nil {
			continue
		}
		timeout := time.Duration(l.TimeoutNs)
		remaining := time.Duration(l.RemainingNs)
		if remaining > timeout {
			remaining = timeout
		}
		out = append(out, &dataplane.PersistentNATBinding{
			SrcIP:    srcIP,
			SrcPort:  l.SrcPort,
			NatIP:    natIP,
			NatPort:  l.TranslatedPort,
			PoolName: l.Pool,
			LastSeen: now.Add(-(timeout - remaining)),
			Timeout:  timeout,
			Permit:   persistentNatPermitFromWire(l),
		})
	}
	return out
}

func persistentNatPermitFromWire(l dpuserspace.IdleLeaseWire) config.PersistentNATPermit {
	if l.RemoteIP == "" {
		return config.PersistentNATPermitAnyRemoteHost
	}
	if l.RemotePort == 0 {
		return config.PersistentNATPermitTargetHost
	}
	return config.PersistentNATPermitTargetHostPort
}
