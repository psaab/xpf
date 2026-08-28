package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
	"github.com/vishvananda/netlink"
)

// #7007: the link-cycle lease must survive until the LAST repair of the apply,
// not end at the first.
//
// The apply loop ACQUIRES per MEMBER (each member's PrepareLinkCycle) and
// RELEASES per REPAIR — one inside the loop for an aborted member's rollback,
// plus at most one for the whole apply at step 2.6b2, which sits OUTSIDE the
// loop and is gated on needLinkCycleRecovery. On a MIXED multi-member apply,
// where one member cycles cleanly and another aborts, the aborted member's
// in-loop rollback is the first NotifyLinkCycle — so it ends the lease while
// the cycled member's apply is still running, and every renewal after it is a
// no-op against a zeroed word.
//
// WHY THIS FIXTURE HAD TO BE BUILT RATHER THAN REUSED. Three existing pieces
// each block it:
//
//   - rethCallsiteConfig is deliberately ONE member.
//   - newRecordingRethOps returns a single shared fake link that IGNORES the
//     interface name, with one global liveFail — so it cannot give member A a
//     completed cycle and member B an abort in the same apply.
//   - abortRecoveryLinkController models the lease as a bool that only
//     AbandonLinkCycle clears; PrepareLinkCycle does not set it and
//     NotifyLinkCycle does not clear it, so it cannot observe "still held".
//
// ORDER INDEPENDENCE IS LOAD-BEARING. The apply iterates `rethToPhys`, a Go
// map, so member order is randomised per run. The assertions below are
// therefore counts and invariants, never sequences: the releasing
// NotifyLinkCycle must happen EXACTLY ONCE, and the lease must be held
// continuously from the first acquire to it. Both hold in either order — which
// is what stops this being a 50/50 flake.

// leaseTracingLinkController models the REAL manager semantics the production
// lease has: acquire is a store, release is a store of the 0 sentinel, and a
// release-when-not-held is legal and silent.
type leaseTracingLinkController struct {
	mu sync.Mutex

	prepareErrFor map[string]error // keyed by nothing — see prepareErrSeq
	prepareErrSeq []error          // consumed in call order; nil = success

	prepareCalls  int
	notifyCalls   int
	keepCalls     int
	renewCalls    int
	abandonCalls  int
	held          bool
	everHeld      bool
	abandonHeld   []bool // what each AbandonLinkCycle FOUND — the discriminator
	trace         []string
	releasedEarly bool // a release observed while a later acquire could still come
	acquiresAfter int  // acquires seen after the first release
}

func (c *leaseTracingLinkController) SetDeferWorkers(bool) {}

func (c *leaseTracingLinkController) PrepareLinkCycle() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prepareCalls++
	var err error
	if len(c.prepareErrSeq) > 0 {
		err = c.prepareErrSeq[0]
		c.prepareErrSeq = c.prepareErrSeq[1:]
	}
	// The lease is taken BEFORE the fallible work, so a PrepareLinkCycle that
	// ERRORS still holds one. That is production's documented acquire point —
	// "the window that needs covering opens at the ctrl disable, not at the
	// successful join" (process_linkcycle.go), pinned by
	// TestPrepareLinkCycleHoldsTheLeaseWhenTheJoinFails_6871.
	//
	// An earlier version of this fake released on the error path, on the guess
	// that a failed prepare arms nothing. That guess made the abort-only fixture
	// below hold NO lease at all, so it had nothing to leak and mutation cell R2
	// — delete the end-of-apply release — passed against it. The fixture was
	// certifying an arm it never reached.
	if c.notifyCalls > 0 {
		c.acquiresAfter++
	}
	c.held = true
	c.everHeld = true
	if err != nil {
		c.trace = append(c.trace, "acquire(then prepare FAILED — lease still held)")
		return err
	}
	c.trace = append(c.trace, "acquire")
	return nil
}

// NotifyLinkCycle is the RELEASING repair: production releases first and
// unconditionally, at the top of the critical section.
func (c *leaseTracingLinkController) NotifyLinkCycle() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notifyCalls++
	c.held = false
	c.trace = append(c.trace, "notify(release)")
	return nil
}

// NotifyLinkCycleKeepingLease is the REPAIR-WITHOUT-RELEASE variant #7007 adds.
// Until it exists this fake's method is simply never called, which is exactly
// what the count assertions detect.
func (c *leaseTracingLinkController) NotifyLinkCycleKeepingLease() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keepCalls++
	c.trace = append(c.trace, "notify(keep)")
	return nil
}

func (c *leaseTracingLinkController) RenewLinkCycle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.renewCalls++
	if !c.held {
		// A renewal against a released lease is the SYMPTOM: production's
		// RenewLinkCycle refuses the 0 sentinel, so this is a no-op there.
		c.releasedEarly = true
		c.trace = append(c.trace, "renew(NO-OP: lease already released)")
		return
	}
	c.trace = append(c.trace, "renew")
}

func (c *leaseTracingLinkController) AbandonLinkCycle() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.abandonCalls++
	was := c.held
	c.abandonHeld = append(c.abandonHeld, was)
	c.held = false
	if was {
		c.trace = append(c.trace, "abandon(LEASE WAS STILL HELD)")
	} else {
		c.trace = append(c.trace, "abandon")
	}
	return was
}

func (c *leaseTracingLinkController) snapshot() (int, int, int, bool, bool, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prepareCalls, c.notifyCalls, c.keepCalls, c.releasedEarly, c.held,
		append([]string(nil), c.trace...)
}

// deferredAbandonFoundLease reports what the LAST AbandonLinkCycle of the apply
// found. That last one is applyDataplaneAndHACore's deferred backstop, and it is
// the only observation that separates "the apply released the lease" from "the
// apply leaked it and the backstop cleaned up".
//
// `held == false` at the end cannot make that distinction — the backstop clears
// it either way — which is exactly how the first version of the abort-only test
// below passed against a build with the end-of-apply release DELETED.
func (c *leaseTracingLinkController) deferredAbandonFoundLease(t *testing.T) bool {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.abandonHeld) == 0 {
		t.Fatalf("no AbandonLinkCycle at all: applyDataplaneAndHACore defers one over its "+
			"whole body, so its absence means the apply never got that far and every "+
			"assertion here is about nothing. trace=%v", c.trace)
	}
	return c.abandonHeld[len(c.abandonHeld)-1]
}

// perNameRethOps is newRecordingRethOps' missing sibling: a fake netlink seam
// whose behaviour is keyed by the LINUX INTERFACE NAME, so one apply can give
// member A a completed cycle and member B an abort.
func perNameRethOps(t *testing.T, cur net.HardwareAddr, liveFail map[string]bool,
	events *[]string, mu *sync.Mutex) rethLinkOps {
	t.Helper()
	links := map[string]netlink.Link{}
	down := map[string]bool{}
	get := func(name string) netlink.Link {
		mu.Lock()
		defer mu.Unlock()
		if l, ok := links[name]; ok {
			return l
		}
		la := netlink.NewLinkAttrs()
		la.Name = name
		la.HardwareAddr = cur
		l := &netlink.Device{LinkAttrs: la}
		links[name] = l
		return l
	}
	record := func(s string) { mu.Lock(); *events = append(*events, s); mu.Unlock() }
	return rethLinkOps{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		byName:     func(n string) (netlink.Link, error) { return get(n), nil },
		byIndex:    func(int) (netlink.Link, error) { return nil, errors.New("byIndex unused") },
		setDown: func(l netlink.Link) error {
			n := l.Attrs().Name
			mu.Lock()
			down[n] = true
			mu.Unlock()
			record(n + ":link-down")
			return nil
		},
		setUp: func(l netlink.Link) error {
			record(l.Attrs().Name + ":link-up")
			return nil
		},
		setName: func(netlink.Link, string) error { return nil },
		setHardwareAddr: func(l netlink.Link, _ net.HardwareAddr) error {
			n := l.Attrs().Name
			mu.Lock()
			isDown := down[n]
			fail := liveFail[n]
			mu.Unlock()
			if !isDown {
				record(n + ":set-mac-live")
				if fail {
					return errors.New("EBUSY: device busy (no IFF_LIVE_ADDR_CHANGE)")
				}
				return nil
			}
			record(n + ":set-mac-cycled")
			return nil
		},
	}
}

// twoMemberRethConfig is the fixture rethCallsiteConfig deliberately is not: two
// RETH interfaces, each with its own physical member, so the apply's per-member
// loop runs twice in one commit.
func twoMemberRethConfig() *config.Config {
	return &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{ClusterID: 1, NodeID: 0},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1},
				"reth1":    {Name: "reth1", RedundancyGroup: 1},
				"ge-0/0/1": {Name: "ge-0/0/1", RedundantParent: "reth0"},
				"ge-0/0/2": {Name: "ge-0/0/2", RedundantParent: "reth1"},
			},
		},
	}
}

// leaseTracingTestDP publishes the tracing controller through the #2114 cell.
// It cannot reuse abortRecoveryTestDP, whose `link` field is concretely typed.
type leaseTracingTestDP struct {
	deferredMACReapplyTestDP
	link *leaseTracingLinkController
}

func (d *leaseTracingTestDP) Link() dataplane.LinkController { return d.link }

func twoMemberRethDaemon(t *testing.T, lc *leaseTracingLinkController) *Daemon {
	t.Helper()
	installFakeNetworkctl(t)
	d := &Daemon{
		cluster: cluster.NewManager(0, 1),
		vrrpMgr: vrrp.NewManager(),
		store:   newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		opts:    Options{NoDataplane: true},
	}
	d.setDataplane(&leaseTracingTestDP{link: lc})
	return d
}

// TestMixedMultiMemberApplyHoldsTheLeaseToTheLastRepair7007 is the #7007
// fail-on-revert.
//
// Both members are forced to cycle (live set refused). One member's
// PrepareLinkCycle then FAILS, aborting it and driving its in-loop rollback,
// while the other completes its cycle. The lease the cycled member depends on
// must still be held when that rollback returns.
func TestMixedMultiMemberApplyHoldsTheLeaseToTheLastRepair7007(t *testing.T) {
	var events []string
	var mu sync.Mutex
	withRethOps(t, perNameRethOps(t, curMAC5103, map[string]bool{
		"ge-0-0-1": true, "ge-0-0-2": true,
	}, &events, &mu))

	// Order-independent by construction: the FIRST member the map yields
	// succeeds its join and cycles; the SECOND fails its join and aborts.
	lc := &leaseTracingLinkController{
		prepareErrSeq: []error{nil, errors.New("worker join failed")},
	}
	d := twoMemberRethDaemon(t, lc)

	_ = d.applyConfigLocked(context.Background(), twoMemberRethConfig())

	prepare, notify, keep, releasedEarly, stillHeld, trace := lc.snapshot()

	// FIXTURE LIVENESS. Without these the assertions below are about nothing:
	// a fixture that never reached the hook would report notify=0 and "pass".
	if prepare != 2 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 2 — the apply must reach BOTH "+
			"members' worker-join hooks, or this is not a multi-member fixture. "+
			"trace=%v events=%v", prepare, trace, events)
	}
	mu.Lock()
	cycled := 0
	for _, e := range events {
		if len(e) > 14 && e[len(e)-14:] == "set-mac-cycled" {
			cycled++
		}
	}
	evCopy := append([]string(nil), events...)
	mu.Unlock()
	if cycled != 1 {
		t.Fatalf("completed cycles = %d, want exactly 1 (one member cycles, the other "+
			"aborts before its DOWN/UP) — events=%v", cycled, evCopy)
	}

	// THE DISCRIMINATOR. The releasing repair must happen exactly once, and it
	// must be the apply-wide one — so the in-loop rollback must have used the
	// non-releasing variant.
	if notify != 1 {
		t.Errorf("releasing NotifyLinkCycle calls = %d, want 1 (#7007). Two means the "+
			"aborted member's in-loop rollback released a lease the CYCLED member still "+
			"depends on: everything after it — the remaining members' tails and all "+
			"three renewal sites — runs unprotected, with the 1 Hz reconcile free to "+
			"resume against half-repaired state. trace=%v", notify, trace)
	}
	if keep != 1 {
		t.Errorf("non-releasing repairs = %d, want 1 (#7007): the aborted member must "+
			"still REBIND — its own workers are stopped — but must not end the apply's "+
			"lease to do it. Repair and release are different acts. trace=%v", keep, trace)
	}
	if releasedEarly {
		t.Errorf("a lease renewal ran against an ALREADY-RELEASED lease — the exact "+
			"symptom #7007 describes: production's RenewLinkCycle refuses the 0 "+
			"sentinel, so those renewals silently stop extending the window. trace=%v",
			trace)
	}
	if lc.deferredAbandonFoundLease(t) {
		t.Errorf("the deferred abandonLinkCycleLease still FOUND a held lease: the apply "+
			"leaked it rather than releasing at its last repair, and that backstop's "+
			"ERROR now fires on an ordinary mixed commit. trace=%v", trace)
	}
	_ = stillHeld
}

// TestAbortOnlyApplyStillReleasesTheLease7007 covers the arm the other two
// cannot reach: an apply where EVERY member aborts.
//
// This is the case the fix could most easily get wrong, and the mutation matrix
// proved the other two tests are blind to it — deleting the end-of-apply release
// leaves both of them green. Step 2.6b2 is gated on needLinkCycleRecovery, which
// only a member that COMPLETED a cycle arms, so an all-abort apply reaches no
// NotifyLinkCycle at all. Once the rollbacks stopped releasing (#7007), nothing
// else would end the lease: it would survive to the deferred abandon and make
// that backstop's ERROR routine on a path that is not a bug — which is exactly
// the failure mode the issue rejects a refcount for, arrived at by another
// route.
func TestAbortOnlyApplyStillReleasesTheLease7007(t *testing.T) {
	var events []string
	var mu sync.Mutex
	withRethOps(t, perNameRethOps(t, curMAC5103, map[string]bool{
		"ge-0-0-1": true, "ge-0-0-2": true,
	}, &events, &mu))

	// BOTH joins fail, so both members abort and neither cycle completes.
	lc := &leaseTracingLinkController{
		prepareErrSeq: []error{
			errors.New("worker join failed"),
			errors.New("worker join failed"),
		},
	}
	d := twoMemberRethDaemon(t, lc)

	_ = d.applyConfigLocked(context.Background(), twoMemberRethConfig())

	prepare, notify, keep, _, stillHeld, trace := lc.snapshot()

	// FIXTURE LIVENESS, and it is doing real work here: if either member had
	// cycled, needLinkCycleRecovery would arm, 2.6b2 would run, and this test
	// would be a duplicate of the mixed one rather than the arm it is for.
	if prepare != 2 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 2 — both members must reach the "+
			"hook. trace=%v", prepare, trace)
	}
	mu.Lock()
	for _, e := range events {
		if len(e) > 14 && e[len(e)-14:] == "set-mac-cycled" {
			mu.Unlock()
			t.Fatalf("a member COMPLETED a cycle; this fixture requires that none does, "+
				"or step 2.6b2 runs and the end-of-apply arm is not the thing under "+
				"test. events=%v", events)
		}
	}
	mu.Unlock()
	if notify != 0 {
		t.Errorf("releasing NotifyLinkCycle calls = %d, want 0: no member cycled, so "+
			"needLinkCycleRecovery is clear and step 2.6b2 must not run. trace=%v",
			notify, trace)
	}
	if keep != 2 {
		t.Errorf("non-releasing repairs = %d, want 2 (one per aborted member): each "+
			"aborted member still owns its own rebind. trace=%v", keep, trace)
	}

	// THE DISCRIMINATOR for the end-of-apply arm.
	//
	// NOT `stillHeld`. The deferred abandonLinkCycleLease clears the word on
	// every exit, so the apply always ENDS with it released — the first version
	// of this test asserted exactly that and passed against a build with the
	// end-of-apply release deleted (mutation cell R2). What separates the two is
	// WHO released it: if the deferred backstop still FOUND a lease, the apply
	// leaked one and that backstop logs its ERROR, which is the routine-noise
	// outcome this whole design avoids.
	if lc.deferredAbandonFoundLease(t) {
		t.Errorf("the deferred abandonLinkCycleLease still FOUND a held lease, so the "+
			"apply leaked it. With no member cycled there is no step 2.6b2 to release "+
			"it, and since the rollbacks stopped releasing (#7007) the explicit "+
			"end-of-apply release is the only thing that can. Without it that backstop's "+
			"\"leaving with a RETH link-cycle lease still held\" ERROR fires on an "+
			"ordinary all-abort commit — the same failure mode the issue rejects a "+
			"refcount for. trace=%v", trace)
	}
	_ = stillHeld
}

// TestAllMembersCyclingReleasesExactlyOnce7007 is the anti-over-fix control.
//
// Two acquires and ONE release is the ordinary multi-member shape, and it must
// stay that way. This is the cell that rules out the fix the issue explicitly
// warns against: a refcount would sit at 1 here, strand the lease to the
// deferred abandon, and turn its ERROR into routine noise on every such commit.
func TestAllMembersCyclingReleasesExactlyOnce7007(t *testing.T) {
	var events []string
	var mu sync.Mutex
	withRethOps(t, perNameRethOps(t, curMAC5103, map[string]bool{
		"ge-0-0-1": true, "ge-0-0-2": true,
	}, &events, &mu))

	lc := &leaseTracingLinkController{} // both joins succeed
	d := twoMemberRethDaemon(t, lc)

	if err := d.applyConfigLocked(context.Background(), twoMemberRethConfig()); err != nil {
		t.Fatalf("an apply where both members cycled cleanly must succeed: %v", err)
	}

	prepare, notify, keep, releasedEarly, stillHeld, trace := lc.snapshot()
	if prepare != 2 {
		t.Fatalf("PrepareLinkCycle calls = %d, want 2 — fixture liveness. trace=%v",
			prepare, trace)
	}
	if notify != 1 || keep != 0 {
		t.Errorf("release=%d keep=%d, want 1/0: with no member aborting there is no "+
			"in-loop rollback, so step 2.6b2's single repair is the only one. trace=%v",
			notify, keep, trace)
	}
	if lc.deferredAbandonFoundLease(t) {
		t.Errorf("two acquires and one release must leave the lease RELEASED by the "+
			"apply, not by the backstop. A refcount would sit at 1 here and strand it — "+
			"which is why #7007 is not fixed by refcounting. trace=%v", trace)
	}
	_ = stillHeld
	if releasedEarly {
		t.Errorf("no renewal may run unprotected on the all-cycling path. trace=%v", trace)
	}
	_ = fmt.Sprint(events)
}
