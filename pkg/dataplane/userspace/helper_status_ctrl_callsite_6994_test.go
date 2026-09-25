package userspace

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
)

// #6994: bind applyHelperStatusLocked's ctrl-gate CALL SITE, not the predicate.
//
// WHAT WAS UNBOUND, measured rather than inferred. On the pre-#6994 head,
// deleting `m.resolveCtrlEnableLocked(status, &ctrl)` from
// applyHelperStatusLocked left BOTH pkg/dataplane/userspace and pkg/daemon
// fully green. The reason is structural: the function opened by resolving
// userspace_ctrl and userspace_bindings straight off m.bpfShim and returning
// "userspace_ctrl map not loaded" when either was absent, so on an
// unprivileged machine — every machine CI runs on — every test stopped on line
// one and the entire body behind it was reached by nothing.
//
// WHY THE #6871 PREDICATE TABLE IS NOT THIS. #6871 round 9 extracted
// ctrlMustStayDisabledLocked precisely so the clause could be tabled without
// privileges, and that binding is real and load-bearing: dropping
// `|| m.linkCycleInFlight()` from it reds
// TestCtrlMustStayDisabledDuringLinkCycle_6871 (verified by mutation on this
// branch). What a predicate table cannot see is production no longer
// CONSULTING the predicate. Those are different properties and they need
// different cells — which is the whole point of this file.
//
// WHY BOTH CELLS ARE REQUIRED, and why either alone certifies the bug it is
// aimed at:
//
//   - The link-cycle cell alone asserts "ctrl ends DISABLED during a cycle".
//     `ctrl` is initialised as `userspaceCtrlValue{Enabled: 0, ...}`, so
//     deleting the resolve call leaves it at 0 and that cell PASSES. It cannot
//     see the severance it would be assumed to cover.
//   - The enable cell alone asserts "ctrl ends ENABLED for a ready helper".
//     Removing `|| m.linkCycleInFlight()` from the predicate does not change
//     that outcome, so it PASSES too.
//
// Only the pair discriminates: the enable cell is what reds on a severed call
// site, and the link-cycle cell is what reds on a weakened gate. A single cell
// varying only one of the two axes would sample the passing point of the other.

// fakeBindingsMap is the userspace_bindings half of the #6994 seam. It is
// deliberately permissive about the value type — applyPrimaryBindingRowsLocked
// writes a binding row, not a ctrl value, so fakeCtrlMap's typed assertion does
// not fit — and records nothing beyond call counts, because the assertions here
// are about the CTRL map's contents.
type fakeBindingsMap struct {
	lookups int
	updates int
}

func (f *fakeBindingsMap) Lookup(_, _ interface{}) error { f.lookups++; return ebpf.ErrKeyNotExist }
func (f *fakeBindingsMap) Update(_, _ interface{}, _ ebpf.MapUpdateFlags) error {
	f.updates++
	return nil
}

// readyHelperStatus is a helper status that satisfies every readiness gate
// resolveCtrlEnableLocked consults on its arming branch: one registered, armed
// and bound binding (probeBindingsReady && allBindingsBound) and a non-zero
// neighbour generation (neighborSyncReady). Without all three the arming branch
// falls through to `ctrl.Enabled = 0` and the enable cell below would be
// vacuous — passing for the wrong reason, which is the failure mode this whole
// file exists to avoid.
func readyHelperStatus() *ProcessStatus {
	return &ProcessStatus{
		Enabled: true,
		Workers: 1,
		Bindings: []BindingStatus{{
			Slot: 0, QueueID: 0, WorkerID: 0,
			Interface: "ge-0-0-1", Ifindex: 7,
			Registered: true, Armed: true, Ready: true, Bound: true,
			RXPackets: 1000,
		}},
		NeighborGeneration: 1,
	}
}

// seamedManager returns a Manager whose two applyHelperStatusLocked map handles
// and classifier-map writes are routed through test doubles, so the function's
// body runs unprivileged. It returns the ctrl fake so a cell can read back what
// production actually WROTE, rather than asserting on in-memory manager state
// that a severed map write would leave untouched.
func seamedManager(t *testing.T) (*Manager, *fakeCtrlMap) {
	t.Helper()
	m := New()
	ctrl := &fakeCtrlMap{}
	m.helperStatusCtrlMapHook = ctrl
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	// Liveness already proven: advanceXSKLivenessLocked then takes its
	// restore-the-shim arm instead of starting a 10 s probe, which keeps the
	// enable cell deterministic and independent of wall-clock.
	m.xskLivenessProven = true
	// Precondition. A cell that reads Enabled==0 out of a map that was never
	// written proves nothing, and a cell that reads Enabled==1 out of a
	// pre-populated one proves less. Assert the fixture starts blank.
	if ctrl.haveStored {
		t.Fatal("fixture invalid: the ctrl map already holds a value before any apply")
	}
	return m, ctrl
}

// The ready-helper path must end with ctrl ENABLED in the map.
//
// RED on revert: delete `m.resolveCtrlEnableLocked(status, &ctrl)` from
// applyHelperStatusLocked and this fails — `ctrl.Enabled` stays at the literal
// 0 it is constructed with, the `if ctrl.Enabled == 1` write never runs, and
// the ctrl map is never written at all. Measured on the pre-#6994 head: that
// same deletion left the entire package green.
func TestApplyHelperStatusEnablesCtrlForAReadyHelper6994(t *testing.T) {
	m, ctrl := seamedManager(t)

	if err := m.applyHelperStatusLocked(readyHelperStatus()); err != nil {
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}

	if !ctrl.haveStored {
		t.Fatal("applyHelperStatusLocked wrote NOTHING to the userspace_ctrl map for a " +
			"ready helper. The ctrl-enable resolution is not reached: the shim never " +
			"starts redirecting to XSK and all transit stays fail-closed, with no test " +
			"outside this one able to see it (#6994)")
	}
	if ctrl.stored.Enabled != 1 {
		t.Fatalf("ctrl.Enabled = %d after applying a ready helper status, want 1. "+
			"applyHelperStatusLocked is not consulting resolveCtrlEnableLocked, so the "+
			"gate is stuck at the value the struct literal initialises (#6994)",
			ctrl.stored.Enabled)
	}
	if !m.ctrlWasEnabled {
		t.Fatal("m.ctrlWasEnabled is false after a ctrl-enabling apply: the map write " +
			"and the manager's derived state disagree, so the next disable would not " +
			"stamp ctrlDisabledAt (#6994)")
	}
}

// The same ready helper, with a link cycle in flight, must end DISABLED.
//
// RED on revert: drop `|| m.linkCycleInFlight()` from
// ctrlMustStayDisabledLocked and this fails — the identical status now arms the
// gate mid-cycle. That is the #6871 hazard: UpdateRGActive reaches
// applyHelperStatusLocked off the daemon's applySem, so the status tick's own
// lease skip does not cover it, and re-enabling here points the XDP shim at XSK
// queues the cycle is about to destroy.
func TestApplyHelperStatusKeepsCtrlDisabledDuringLinkCycle6994(t *testing.T) {
	fakeLinkCycleClock(t)
	m, ctrl := seamedManager(t)
	t.Cleanup(m.releaseLinkCycleLease)
	m.acquireLinkCycleLease()
	if !m.linkCycleInFlight() {
		t.Fatal("fixture invalid: the link-cycle lease is not held, so this cell would " +
			"be asserting the ungated path and would pass for the wrong reason")
	}

	if err := m.applyHelperStatusLocked(readyHelperStatus()); err != nil {
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}

	if ctrl.haveStored && ctrl.stored.Enabled != 0 {
		t.Fatalf("ctrl.Enabled = %d with a link cycle in flight, want 0. The gate that "+
			"holds ctrl at 0 for the duration of a RETH MAC link cycle is not reached "+
			"from applyHelperStatusLocked, so the shim redirects into XSK sockets whose "+
			"queues the cycle is tearing down (#6871/#6994)",
			ctrl.stored.Enabled)
	}
	if m.ctrlWasEnabled {
		t.Fatal("m.ctrlWasEnabled is true after an apply that ran during a link cycle: " +
			"the enable half of the ctrl branch executed despite the gate (#6871/#6994)")
	}
}

// RED on revert: a 30-second value in the published userspace_ctrl map would
// let the shim redirect transit for six times its enforced 5-second stale
// window. Read the value actually written by applyHelperStatusLocked and
// compare it with the shim's constant so the publisher and consumer cannot
// silently drift.
func TestApplyHelperStatusPublishesShimHeartbeatTimeout10710(t *testing.T) {
	m, ctrl := seamedManager(t)
	if err := m.applyHelperStatusLocked(readyHelperStatus()); err != nil {
		t.Fatalf("applyHelperStatusLocked: %v", err)
	}
	if !ctrl.haveStored {
		t.Fatal("applyHelperStatusLocked wrote nothing to the userspace_ctrl map")
	}
	if ctrl.stored.Enabled != 1 {
		t.Fatalf("userspace_ctrl.Enabled = %d, want 1 so the shim consumes this row", ctrl.stored.Enabled)
	}

	const shimPath = "../../../userspace-xdp/src/lib.rs"
	shimSource, err := os.ReadFile(shimPath)
	if err != nil {
		t.Fatalf("read shim source %s: %v", shimPath, err)
	}
	timeoutDecl := regexp.MustCompile(
		`(?m)^const USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS: u32 = ([0-9]+);$`,
	).FindAllSubmatch(shimSource, -1)
	if len(timeoutDecl) != 1 {
		t.Fatalf("found %d USERSPACE_DEFAULT_HEARTBEAT_TIMEOUT_MS declarations in shim, want exactly 1",
			len(timeoutDecl))
	}
	shimTimeout, err := strconv.ParseUint(string(timeoutDecl[0][1]), 10, 32)
	if err != nil {
		t.Fatalf("parse shim heartbeat timeout %q: %v", timeoutDecl[0][1], err)
	}
	const wantTimeoutMS = uint32(5_000)
	if shimTimeout != uint64(wantTimeoutMS) {
		t.Fatalf("shim stale-heartbeat timeout = %d ms, want 5 seconds (%d ms)",
			shimTimeout, wantTimeoutMS)
	}
	if ctrl.stored.HeartbeatTimeoutMS != uint32(shimTimeout) {
		t.Fatalf("shim-visible userspace_ctrl.HeartbeatTimeoutMS = %d ms, want shim timeout %d ms",
			ctrl.stored.HeartbeatTimeoutMS, shimTimeout)
	}
}
