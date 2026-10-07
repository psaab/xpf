package daemon

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// ri_member_late_bind_6805_test.go — #6805.
//
// Step 0a is the designated owner of routing-instance interface-LIST binds. The
// tunnel manager refuses to bind a list-only member (reconcileVRFClaimLocked
// case 2 only OBSERVES, with an explicit "0a owns list binds" veto), so 0a is
// the only thing that can. But 0a runs BEFORE applyInterfaceReconcile creates
// tunnel/xfrmi devices — the owner ran before the thing it owns existed.
//
// On a FIRST apply that meant: 0a warns "not found", the tunnel manager observes
// a link with no master and takes no claim, and the tunnel comes up OUTSIDE its
// VRF, forwarding in the default table, on a commit that reported success.
//
// The fixture that matters is therefore one where the device is ABSENT for the
// early pass and PRESENT for the late one. A fixture that pre-creates the device
// cannot see the defect at all: 0a would bind it and every cell here passes with
// the whole fix deleted.

// bindRecorderOps wraps the shared fake link table and records every
// LinkSetMaster, which the shared fake discards. Embedding rather than copying
// keeps LinkByName's netlink.LinkNotFoundError behaviour — the type routing's
// isLinkNotFound recognises — identical to every other test using it.
type bindRecorderOps struct {
	*reconcileFakeLinkOps
	mu      sync.Mutex
	binds   []string // "member->master"
	unbound []string // members detached from a master
}

func (b *bindRecorderOps) LinkSetMaster(l, master netlink.Link) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.binds = append(b.binds, l.Attrs().Name+"->"+master.Attrs().Name)
	return nil
}

func (b *bindRecorderOps) LinkSetNoMaster(l netlink.Link) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.unbound = append(b.unbound, l.Attrs().Name)
	l.Attrs().MasterIndex = 0
	return nil
}

func (b *bindRecorderOps) LinkList() ([]netlink.Link, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	links := make([]netlink.Link, 0, len(b.links))
	for _, link := range b.links {
		links = append(links, link)
	}
	return links, nil
}

func (b *bindRecorderOps) recorded() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.binds...)
}

func (b *bindRecorderOps) unboundRecorded() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.unbound...)
}

// addLink6805 makes a device exist in the fake table, modelling
// applyInterfaceReconcile having created it.
func addLink6805(ops *bindRecorderOps, name string) {
	ops.links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// listOnlyCfg6805 is a routing instance whose member is a LIST member only —
// there is no `routing-instance` stanza on the tunnel, which is the whole point.
// With a stanza the tunnel manager binds it itself (case 1) and 0a's timing is
// irrelevant.
func listOnlyCfg6805() *config.Config {
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{
		Name:         "blue",
		InstanceType: "vrf",
		TableID:      100,
		Interfaces:   []string{"gr-0/0/0.0"},
	}}
	return cfg
}

// TestLateBindCatchesAMemberCreatedAfterStep0a6805 is the cell the issue turns
// on, and it is ORDERED: the device does not exist for the early pass and does
// for the late one, which is the only shape in which the two passes disagree.
//
// FAIL-ON-REVERT: delete the d.rebindRoutingInstanceMembers(cfg) call and the
// member is never bound — exactly the pre-fix behaviour.
func TestLateBindCatchesAMemberCreatedAfterStep0a6805(t *testing.T) {
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	cfg := listOnlyCfg6805()

	// Step 0a: the VRF device gets created by ReconcileVRFs, but the tunnel does
	// NOT exist yet. This is the state a first apply is genuinely in.
	if _, vrfErr := d.applyVRFReconcile(context.Background(), cfg); vrfErr != nil {
		t.Fatalf("applyVRFReconcile vrfErr = %v, want nil", vrfErr)
	}
	early := ops.recorded()
	for _, b := range early {
		if strings.HasPrefix(b, "gr-0-0-0->") {
			t.Fatalf("the fixture bound the member at step 0a (%q); the device was "+
				"supposed to be absent there, so this fixture cannot see the defect", b)
		}
	}

	// applyInterfaceReconcile creates the tunnel device.
	addLink6805(ops, "gr-0-0-0")

	d.rebindRoutingInstanceMembers(cfg)

	var bound bool
	for _, b := range ops.recorded() {
		if b == "gr-0-0-0->vrf-blue" {
			bound = true
		}
	}
	if !bound {
		t.Fatalf("the late pass did not bind the list-only member to its VRF; the "+
			"tunnel comes up in the DEFAULT table on a first apply that reported "+
			"success (#6805). binds seen: %v", ops.recorded())
	}
}

// TestLateBindStaysBestEffort6805 pins the boundary #5700 drew and this change
// must not move.
//
// A routing-instance `interface` list can legitimately name an interface that is
// genuinely absent on this chassis. Surfacing the late bind's failure into
// commit truth would reject configs that are correct for the fleet — a different
// defect from the one being fixed, and a worse one.
//
// FAIL-ON-REVERT: join the late pass's error into networkdErr and this reds.
func TestLateBindStaysBestEffort6805(t *testing.T) {
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	cfg := listOnlyCfg6805()

	// The member is absent for BOTH passes — a NIC that is not on this chassis.
	if _, vrfErr := d.applyVRFReconcile(context.Background(), cfg); vrfErr != nil {
		t.Fatalf("applyVRFReconcile vrfErr = %v, want nil", vrfErr)
	}
	d.rebindRoutingInstanceMembers(cfg) // must not panic and must not surface

	for _, b := range ops.recorded() {
		if strings.HasPrefix(b, "gr-0-0-0->") {
			t.Fatalf("a genuinely absent member was somehow bound: %q", b)
		}
	}
}

// TestBothPassesBindTheSameNameSet6805 binds the AGREEMENT between the two
// passes rather than pinning either to a name.
//
// The tunnel manager's unbind VETO is written against "whatever 0a binds". If a
// second loop drifted from the first, the veto would be guarding a different set
// than the one being bound — and that divergence is always a bug, never a
// legitimate difference, which is why the two share ONE implementation rather
// than being two loops kept in step by hand.
//
// FAIL-ON-REVERT: give rebindRoutingInstanceMembers its own loop that differs
// (e.g. drops the forwarding-instance skip, or skips riMemberLinuxName) and the
// two recorded sets stop matching.
func TestBothPassesBindTheSameNameSet6805(t *testing.T) {
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "blue", InstanceType: "vrf", TableID: 100, Interfaces: []string{"gr-0/0/0.0", "ge-0/0/5"}},
		// A FORWARDING instance must be skipped by BOTH passes. Without it in the
		// fixture, a late pass that forgot the skip would agree with 0a anyway and
		// this cell could not see the drift it exists to catch.
		{Name: "fwd", InstanceType: "forwarding", TableID: 101, Interfaces: []string{"ge-0/0/6"}},
	}
	run := func(late bool) []string {
		ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
		d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
		// Every member present, so the comparison is about WHICH names each pass
		// selects, not about which happened to exist.
		for _, n := range []string{"gr-0-0-0", "ge-0-0-5", "ge-0-0-6"} {
			addLink6805(ops, n)
		}
		ops.links["vrf-blue"] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-blue"}, Table: 100}
		ops.links["vrf-fwd"] = &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: "vrf-fwd"}, Table: 101}
		if late {
			d.rebindRoutingInstanceMembers(cfg)
		} else {
			d.bindRoutingInstanceMembers(cfg)
		}
		return ops.recorded()
	}

	early, lateSet := run(false), run(true)
	if len(early) == 0 {
		t.Fatal("the early pass bound nothing; the comparison would be vacuous")
	}
	if strings.Join(early, ",") != strings.Join(lateSet, ",") {
		t.Fatalf("the two passes bind DIFFERENT name sets — the tunnel manager's "+
			"unbind veto is written against what 0a binds, so a drifted second loop "+
			"makes the veto guard the wrong set (#6805).\n  early: %v\n  late:  %v",
			early, lateSet)
	}
	for _, b := range lateSet {
		if strings.HasPrefix(b, "ge-0-0-6->") {
			t.Errorf("a FORWARDING instance's member was bound (%q); forwarding "+
				"instances have no VRF device", b)
		}
	}
}

// TestApplyCallsTheLateRebind6805 is the WIRING cell.
//
// Every cell above drives rebindRoutingInstanceMembers directly, so an apply
// path that never calls it would pass all of them — and "nothing calls it" is
// the entire defect, one layer up. applyDataplaneAndHACore cannot be driven from
// a unit test (netlink, a dataplane, sockets, a cluster), so the call is
// asserted at the source with comments stripped: a source-scanning gate that
// greps for a line its own doc comment quotes is satisfied by the comment.
//
// It must also land BEFORE the management re-bind, which is where "the devices
// exist by this phase" first becomes true.
func TestApplyCallsTheLateRebind6805(t *testing.T) {
	src := stripLineComments6791(readDaemonSourceFile6805(t, "daemon_apply_dataplane.go"))

	const call = "d.rebindRoutingInstanceMembers(cfg)"
	i := strings.Index(src, call)
	if i < 0 {
		t.Fatalf("the apply path does not call rebindRoutingInstanceMembers; a " +
			"list-only routing-instance member created after step 0a is never bound " +
			"and its tunnel forwards in the default table (#6805)")
	}
	j := strings.Index(src, "d.rebindManagementVRFIfaces()")
	if j < 0 {
		t.Fatal("could not find the management re-bind to order against")
	}
	if i > j {
		t.Error("the routing-instance re-bind runs AFTER the management re-bind; " +
			"it belongs at the same post-networkd point, where the tunnel/xfrmi " +
			"devices are known to exist")
	}
}

func readDaemonSourceFile6805(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// TestStep0aStillBindsAnExistingMember6805 keeps the EARLY pass load-bearing.
//
// It exists because the mutation matrix found it was not: deleting step 0a's
// call left the whole package green, since the late pass re-drives the same loop
// in the same apply and every other cell here is satisfied by that.
//
// 0a is not redundant, and the reason is the CLAIM rather than the bind. The
// tunnel manager's observation (`reconcileVRFClaimLocked` case 2, via
// `observeListClaimLocked`) runs during `applyInterfaceReconcile` — BETWEEN 0a
// and the late pass — and takes the `appliedRI` claim only when the link's
// master already IS `vrf-<RIListMember>`. For a member that ALREADY EXISTS at
// 0a time (a physical NIC, or a tunnel from a previous apply), 0a is what puts
// that master there in time to be observed. Without it the observation finds no
// master, no claim is recorded, and a later "config wants no RI" has nothing to
// identity-gate its unbind against.
//
// So the two passes are not interchangeable even though they call one function:
// 0a is early enough to be observed, the late pass is late enough to see
// devices 0a could not. This cell pins the first half; M1's wiring cell pins the
// second.
//
// FAIL-ON-REVERT: delete the d.bindRoutingInstanceMembers(cfg) call from
// applyVRFReconcile and this reds, while every other cell in the file stays
// green — which is exactly what the matrix measured before it was added.
func TestStep0aStillBindsAnExistingMember6805(t *testing.T) {
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	d := &Daemon{routing: routing.NewManagerWithLinkOpsForTest(ops)}
	cfg := listOnlyCfg6805()

	// The member ALREADY EXISTS — a physical NIC, or a tunnel from a previous
	// apply. This is the case 0a owns and the late pass cannot substitute for,
	// because the tunnel manager's observation runs between them.
	addLink6805(ops, "gr-0-0-0")

	if _, vrfErr := d.applyVRFReconcile(context.Background(), cfg); vrfErr != nil {
		t.Fatalf("applyVRFReconcile vrfErr = %v, want nil", vrfErr)
	}

	var bound bool
	for _, b := range ops.recorded() {
		if b == "gr-0-0-0->vrf-blue" {
			bound = true
		}
	}
	if !bound {
		t.Fatalf("step 0a did not bind a member that already exists; the tunnel "+
			"manager's observation runs BEFORE the late pass, so it would find no "+
			"master, record no appliedRI claim, and leave a later config-wants-no-RI "+
			"unbind with nothing to identity-gate against (#6805). binds seen: %v",
			ops.recorded())
	}
}
