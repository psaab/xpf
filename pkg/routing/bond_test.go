package routing

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// fakeBondLinkOps is a minimal in-memory linkOps double for the #4823
// bondManager.Apply() error-propagation tests. It implements only the
// linkOps methods bond.go actually calls; failure injection is keyed by
// link name so a single test can target exactly one netlink call.
type fakeBondLinkOps struct {
	links     map[string]netlink.Link // name -> existing link (LinkByName hits)
	nextIndex int                     // monotonic kernel index assigner for LinkAdd

	failLinkAdd       map[string]error // bond name -> LinkAdd error
	failLinkSetUp     map[string]error // link name -> LinkSetUp error
	failLinkSetMaster map[string]error // member name -> LinkSetMaster error
	failLinkDel       map[string]error // link name -> LinkDel error
	failLinkSetMTU    map[string]error // link name -> LinkSetMTU error

	// substituteAfterAdd[name], when set, replaces the link stored under name
	// during LinkAdd so the post-create LinkByName readback returns the
	// substitute — models the #6396 create-path TOCTOU where a same-name
	// foreign link is swapped in between LinkAdd and the readback.
	substituteAfterAdd map[string]netlink.Link

	setUpCalls  []string
	masterCalls []string
	addCalls    []string // names passed to LinkAdd
	delCalls    []string // names passed to LinkDel
	mtuCalls    []mtuCall
}

// mtuCall records one LinkSetMTU invocation.
type mtuCall struct {
	name string
	mtu  int
}

func newFakeBondLinkOps() *fakeBondLinkOps {
	return &fakeBondLinkOps{
		links:              map[string]netlink.Link{},
		nextIndex:          1000, // created bonds get 1001+, clear of small seeded indices
		failLinkAdd:        map[string]error{},
		failLinkSetUp:      map[string]error{},
		failLinkSetMaster:  map[string]error{},
		failLinkDel:        map[string]error{},
		failLinkSetMTU:     map[string]error{},
		substituteAfterAdd: map[string]netlink.Link{},
	}
}

// reset zeroes the recorded call slices so a test can assert on the link
// operations issued by a SECOND Apply in isolation from the first.
func (f *fakeBondLinkOps) reset() {
	f.setUpCalls = nil
	f.masterCalls = nil
	f.addCalls = nil
	f.delCalls = nil
	f.mtuCalls = nil
}

func (f *fakeBondLinkOps) LinkByName(name string) (netlink.Link, error) {
	if l, ok := f.links[name]; ok {
		return l, nil
	}
	return nil, errors.New("link not found")
}

func (f *fakeBondLinkOps) LinkAdd(l netlink.Link) error {
	name := l.Attrs().Name
	f.addCalls = append(f.addCalls, name)
	if err, ok := f.failLinkAdd[name]; ok {
		return err
	}
	// A real kernel bond is assigned a non-zero index; model that so
	// observedMembers can key enslavement off a freshly-created bond too.
	if l.Attrs().Index == 0 {
		f.nextIndex++
		l.Attrs().Index = f.nextIndex
	}
	f.links[name] = l
	if sub, ok := f.substituteAfterAdd[name]; ok {
		// The intended bond was created, but a foreign link now wears the name
		// by the time the readback runs (#6396 TOCTOU).
		f.links[name] = sub
	}
	return nil
}

func (f *fakeBondLinkOps) LinkDel(l netlink.Link) error {
	name := l.Attrs().Name
	f.delCalls = append(f.delCalls, name)
	if err, ok := f.failLinkDel[name]; ok {
		return err
	}
	idx := l.Attrs().Index
	delete(f.links, name)
	// Deleting the bond detaches its slaves (their MasterIndex clears).
	if idx != 0 {
		for _, m := range f.links {
			if m.Attrs().MasterIndex == idx {
				m.Attrs().MasterIndex = 0
			}
		}
	}
	return nil
}

func (f *fakeBondLinkOps) LinkSetUp(l netlink.Link) error {
	name := l.Attrs().Name
	f.setUpCalls = append(f.setUpCalls, name)
	if err, ok := f.failLinkSetUp[name]; ok {
		return err
	}
	return nil
}

func (f *fakeBondLinkOps) LinkSetDown(netlink.Link) error { return nil }

func (f *fakeBondLinkOps) LinkSetMaster(member, master netlink.Link) error {
	name := member.Attrs().Name
	f.masterCalls = append(f.masterCalls, name)
	if err, ok := f.failLinkSetMaster[name]; ok {
		return err
	}
	// Enslavement sets the member's MasterIndex to the bond's index so
	// observedMembers reports it as realized on a later reconcile.
	member.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func (f *fakeBondLinkOps) LinkSetNoMaster(netlink.Link) error { return nil }
func (f *fakeBondLinkOps) LinkSetMTU(l netlink.Link, mtu int) error {
	f.mtuCalls = append(f.mtuCalls, mtuCall{name: l.Attrs().Name, mtu: mtu})
	if err, ok := f.failLinkSetMTU[l.Attrs().Name]; ok {
		return err
	}
	l.Attrs().MTU = mtu
	return nil
}
func (f *fakeBondLinkOps) AddrAdd(netlink.Link, *netlink.Addr) error { return nil }
func (f *fakeBondLinkOps) AddrDel(netlink.Link, *netlink.Addr) error { return nil }
func (f *fakeBondLinkOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

// LinkList returns every seeded link so bondManager.observedMembers can
// enumerate a bond's enslaved members by MasterIndex (#5261).
func (f *fakeBondLinkOps) LinkList() ([]netlink.Link, error) {
	links := make([]netlink.Link, 0, len(f.links))
	for _, l := range f.links {
		links = append(links, l)
	}
	return links, nil
}

// seedMember pre-populates a member link so LinkByName(linuxName) in the
// enslave loop succeeds and the test reaches LinkSetMaster.
func (f *fakeBondLinkOps) seedMember(name string) {
	f.links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// seedBond pre-populates an already-present kernel bond with a non-zero
// index so observedMembers can key member enslavement off it (a real bond
// never has index 0; index 0 makes observedMembers fall back). Models the
// daemon-restart adopt case where the bond outlived in-memory tracking.
func (f *fakeBondLinkOps) seedBond(name string, index int) {
	f.links[name] = &netlink.Bond{
		LinkAttrs: netlink.LinkAttrs{Name: name, Index: index},
	}
}

// seedEnslavedMember pre-populates a member link already enslaved to the
// bond whose kernel index is masterIndex (MasterIndex set), so
// observedMembers reports it as part of the realized member set.
func (f *fakeBondLinkOps) seedEnslavedMember(name string, masterIndex int) {
	f.links[name] = &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{Name: name, MasterIndex: masterIndex},
	}
}

func bondFabricConfig(name string, members ...string) *config.InterfaceConfig {
	return &config.InterfaceConfig{
		Name:          name,
		FabricMembers: members,
		BondMode:      "active-backup",
	}
}

// TestBondApplyReportsLinkAddFailure is the #4823 RED-on-revert guard for
// the bond-creation failure path: a LinkAdd error must make Apply() return
// non-nil instead of being logged and swallowed.
func TestBondApplyReportsLinkAddFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.failLinkAdd["bond0"] = errors.New("injected: EPERM")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")}); err == nil {
		t.Fatal("Apply() = nil error, want non-nil after an injected LinkAdd failure")
	}
}

// TestBondApplyReportsLinkSetMasterFailure is the #4823 RED-on-revert guard
// for the member-enslavement failure path.
func TestBondApplyReportsLinkSetMasterFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.failLinkSetMaster["ge-0-0-1"] = errors.New("injected: EBUSY")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")}); err == nil {
		t.Fatal("Apply() = nil error, want non-nil after an injected LinkSetMaster failure")
	}
}

// TestBondApplyReportsLinkSetUpFailure is the #4823 RED-on-revert guard for
// the final bring-up failure path.
func TestBondApplyReportsLinkSetUpFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.failLinkSetUp["bond0"] = errors.New("injected: ENETDOWN")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")}); err == nil {
		t.Fatal("Apply() = nil error, want non-nil after an injected LinkSetUp failure")
	}
}

// TestBondApplyReportsExistingBondLinkSetUpFailure covers the OTHER
// LinkSetUp call site — the "bond already exists" fast path — which uses
// the identical swallowed-error pattern the issue reports for the
// newly-created-bond bring-up.
func TestBondApplyReportsExistingBondLinkSetUpFailure(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.links["bond0"] = &netlink.Bond{LinkAttrs: netlink.LinkAttrs{Name: "bond0"}}
	ops.failLinkSetUp["bond0"] = errors.New("injected: ENETDOWN")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")}); err == nil {
		t.Fatal("Apply() = nil error, want non-nil after an injected LinkSetUp failure on an already-existing bond")
	}
}

// TestBondApplySucceedsCleanly is the positive control: with no injected
// failures, Apply() must still return nil (errors.Join of zero errors is
// nil) and both bonds must be created and tracked.
func TestBondApplySucceedsCleanly(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
		bondFabricConfig("bond1", "ge-0-0-2"),
	})
	if err != nil {
		t.Fatalf("Apply() = %v, want nil (no injected failures)", err)
	}
	if len(b.bonds) != 2 {
		t.Fatalf("len(b.bonds) = %d, want 2: %+v", len(b.bonds), b.bonds)
	}
}

// TestBondApplyContinuesPastOneFailedBond asserts the fix does not regress
// the existing "one bad bond must not block the rest" tolerance: with two
// fabric bonds where the first's LinkAdd fails, the second must still be
// created (and tracked in b.bonds) AND Apply() must still report the first
// bond's failure via a non-nil error — an aggregated error must not turn
// back into an early return that skips the remaining interfaces.
func TestBondApplyContinuesPastOneFailedBond(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.failLinkAdd["bond0"] = errors.New("injected: EPERM")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
		bondFabricConfig("bond1", "ge-0-0-2"),
	})
	if err == nil {
		t.Fatal("Apply() = nil error, want non-nil (bond0's LinkAdd failed)")
	}
	if _, ok := b.bonds["bond0"]; ok {
		t.Fatalf("bond0 tracked despite its LinkAdd failure: %+v", b.bonds)
	}
	if _, ok := b.bonds["bond1"]; !ok {
		t.Fatalf("bond1 (unaffected by bond0's failure) was not created: %+v", b.bonds)
	}
}

// TestBondApplyRecreatesTrackedBondMissingFromKernel is the #5703 /
// codex-review-182 M29 RED-on-revert guard. A bond that was created and is
// still desired with an IDENTICAL signature, but whose kernel device has
// VANISHED (deleted out from under the daemon — an operator `ip link del`, a
// driver reset, a transient kernel failure), must be RECREATED on the next
// reconcile. On master the "unchanged" branch verified nothing: LinkByName
// missed, the bring-up block was skipped, and Apply `continue`d — false
// convergence, so the bond stayed down forever while the reconciler reported
// success.
//
// RED on revert: with the recreate branch removed, the second Apply issues
// ZERO LinkAdd for bond0 (the `contains(ops.addCalls, "bond0")` assertion
// fails) and the member is never re-enslaved.
func TestBondApplyRecreatesTrackedBondMissingFromKernel(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1")}
	full := bondSigOf(cfg[0])

	// First Apply creates and tracks the bond.
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("first Apply() = %v, want nil", err)
	}
	if !contains(ops.addCalls, "bond0") {
		t.Fatalf("first Apply did not create bond0: addCalls=%v", ops.addCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("after create b.bonds[bond0]=%+v, want full desired %+v", got, full)
	}

	// The kernel bond disappears out from under the daemon. Its member
	// detaches (MasterIndex clears) but stays present in the kernel. The
	// tracked signature is UNCHANGED — this is exactly the false-convergence
	// case: still desired, identical sig, but no kernel device.
	delete(ops.links, "bond0")
	for _, l := range ops.links {
		l.Attrs().MasterIndex = 0
	}

	// Re-apply the identical config. The bond MUST be recreated, not treated
	// as unchanged.
	ops.reset()
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("second Apply() (bond vanished) = %v, want nil", err)
	}
	if !contains(ops.addCalls, "bond0") {
		t.Fatalf("vanished bond0 was NOT recreated — false convergence (#5703/M29): "+
			"addCalls=%v", ops.addCalls)
	}
	if !contains(ops.masterCalls, "ge-0-0-1") {
		t.Fatalf("recreated bond0 did NOT re-enslave its member ge-0-0-1: masterCalls=%v",
			ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("after recreate b.bonds[bond0]=%+v, want full desired %+v", got, full)
	}
	if _, ok := ops.links["bond0"]; !ok {
		t.Fatalf("bond0 kernel device absent after recreate: %+v", ops.links)
	}
}

// contains reports whether s appears in xs.
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// TestBondApplyIdempotentNoFlap is the #5119 RED-on-revert guard: applying
// the SAME fabric bond config twice must not tear down and rebuild the
// unchanged bond. The second Apply must issue ZERO LinkDel, LinkAdd, and
// LinkSetMaster calls — otherwise an unrelated policy-only commit flaps the
// LAG (LinkDel->LinkAdd->re-enslave->LACP re-converge). Reverting to the
// unconditional clearLocked()-then-rebuild fails this test.
func TestBondApplyIdempotentNoFlap(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2"),
	}
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("first Apply() = %v, want nil", err)
	}
	if !contains(ops.addCalls, "bond0") {
		t.Fatalf("first Apply did not create bond0: addCalls=%v", ops.addCalls)
	}

	// Re-apply the identical config. Nothing changed, so the bond must be
	// left in place.
	ops.reset()
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("second Apply() = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 {
		t.Fatalf("second (identical) Apply issued LinkDel(s) %v — the "+
			"unchanged bond was flapped", ops.delCalls)
	}
	if len(ops.addCalls) != 0 {
		t.Fatalf("second (identical) Apply issued LinkAdd(s) %v — the "+
			"unchanged bond was rebuilt", ops.addCalls)
	}
	if len(ops.masterCalls) != 0 {
		t.Fatalf("second (identical) Apply re-enslaved member(s) %v — the "+
			"unchanged bond was flapped", ops.masterCalls)
	}
	if _, ok := b.bonds["bond0"]; !ok {
		t.Fatalf("bond0 dropped from tracking after idempotent re-apply: %+v", b.bonds)
	}
}

// TestBondApplyAddedMemberCompletesInPlace asserts that ADDING a member to an
// existing bond (the desired member set is a strict superset of the realized
// set, same mode/MTU) is reconciled IN PLACE — the new member is enslaved with
// no LinkDel/LinkAdd, so the live LAG is not flapped to grow it (FINDING 1 of
// the #5533 review; enslaving a slave into an existing bond is non-disruptive
// to the members already forwarding). The already-enslaved member is NOT
// re-enslaved.
func TestBondApplyAddedMemberCompletesInPlace(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
	}); err != nil {
		t.Fatalf("first Apply() = %v, want nil", err)
	}

	// Add a second member — a pure superset, so the bond is completed in
	// place, not delete+recreated.
	ops.reset()
	full := bondSigOf(bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2"))
	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2"),
	}); err != nil {
		t.Fatalf("second Apply() = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("member-add flapped the bond (delete+recreate): delCalls=%v addCalls=%v",
			ops.delCalls, ops.addCalls)
	}
	if !contains(ops.masterCalls, "ge-0-0-2") {
		t.Fatalf("new member ge-0-0-2 was NOT enslaved in place: masterCalls=%v", ops.masterCalls)
	}
	if contains(ops.masterCalls, "ge-0-0-1") {
		t.Fatalf("already-enslaved member ge-0-0-1 was re-enslaved (flap): masterCalls=%v", ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("after member-add b.bonds[bond0]=%+v, want full desired %+v", got, full)
	}
}

// TestBondApplyRecreatesOnMemberRemoval asserts a GENUINE identity change (a
// member REMOVED — desired is NOT a superset of the realized set) still takes
// the delete+recreate path: a slave cannot be dropped via the in-place
// completion path, so the bond is torn down and rebuilt with the smaller
// member set. This guards against over-broadening in-place completion to cover
// non-superset changes.
func TestBondApplyRecreatesOnMemberRemoval(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2"),
	}); err != nil {
		t.Fatalf("first Apply() = %v, want nil", err)
	}

	// Remove ge-0-0-2 — the realized set is no longer a subset of the desired
	// set, so this is a genuine identity change → delete+recreate.
	ops.reset()
	want := bondSigOf(bondFabricConfig("bond0", "ge-0-0-1"))
	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
	}); err != nil {
		t.Fatalf("second Apply() = %v, want nil", err)
	}
	if !contains(ops.delCalls, "bond0") {
		t.Fatalf("member removal did NOT delete bond0: delCalls=%v", ops.delCalls)
	}
	if !contains(ops.addCalls, "bond0") {
		t.Fatalf("member removal did NOT rebuild bond0: addCalls=%v", ops.addCalls)
	}
	if got := b.bonds["bond0"]; got != want {
		t.Fatalf("after removal b.bonds[bond0]=%+v, want %+v", got, want)
	}
}

// TestBondApplyDeletesRemovedBond asserts a bond dropped from the desired
// set (its fabric interface was removed from config) is deleted, while an
// UNCHANGED sibling bond in the same commit is left untouched (no flap).
func TestBondApplyDeletesRemovedBond(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	ops.seedMember("ge-0-0-2")
	b := &bondManager{ops: ops}

	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
		bondFabricConfig("bond1", "ge-0-0-2"),
	}); err != nil {
		t.Fatalf("first Apply() = %v, want nil", err)
	}

	// Drop bond1; bond0 is unchanged.
	ops.reset()
	if err := b.Apply([]*config.InterfaceConfig{
		bondFabricConfig("bond0", "ge-0-0-1"),
	}); err != nil {
		t.Fatalf("second Apply() = %v, want nil", err)
	}
	if !contains(ops.delCalls, "bond1") {
		t.Fatalf("removed bond1 was NOT deleted: delCalls=%v", ops.delCalls)
	}
	if contains(ops.delCalls, "bond0") {
		t.Fatalf("unchanged bond0 was deleted (flapped): delCalls=%v", ops.delCalls)
	}
	if contains(ops.addCalls, "bond0") {
		t.Fatalf("unchanged bond0 was rebuilt (flapped): addCalls=%v", ops.addCalls)
	}
	if _, ok := b.bonds["bond1"]; ok {
		t.Fatalf("bond1 still tracked after removal: %+v", b.bonds)
	}
	if _, ok := b.bonds["bond0"]; !ok {
		t.Fatalf("bond0 dropped from tracking despite being unchanged: %+v", b.bonds)
	}
}

// TestBondAdoptPartialMemberSetNotTrackedAsComplete is the #5261 RED-on-revert
// guard. A daemon restart adopts a kernel bond that was realized with a
// PARTIAL member set (one member was absent at realization time — a #4823 soft
// error). The adopt path must NOT record the full desired signature (which
// would make every future reconcile see "unchanged" and KEEP the partial bond
// forever); it must track the ACTUAL realized member set so a later reconcile
// completes the enslavement once the missing member appears. Reverting the fix
// tracks the full desired sig → the partial bond is KEEP'd forever (RED here on
// both the tracked-sig assertion AND the completion assertion).
func TestBondAdoptPartialMemberSetNotTrackedAsComplete(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("bond0", 10)
	ops.seedEnslavedMember("ge-0-0-1", 10) // realized member
	// ge-0-0-2 is absent from the kernel — the partial realization.
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2")}
	full := bondSigOf(cfg[0])

	if err := b.Apply(cfg); err != nil {
		t.Fatalf("first Apply() (adopt) = %v, want nil", err)
	}
	// Adopt must not flap the good member: no LinkDel/LinkAdd, and the absent
	// member cannot be enslaved yet (soft error), so no LinkSetMaster either.
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("adopt flapped the bond: delCalls=%v addCalls=%v", ops.delCalls, ops.addCalls)
	}
	got, ok := b.bonds["bond0"]
	if !ok {
		t.Fatalf("bond0 not tracked after adopt: %+v", b.bonds)
	}
	if got == full {
		t.Fatalf("partial adopt tracked the FULL desired sig %+v — a subsequent "+
			"reconcile will KEEP the partial bond forever (#5261)", got)
	}
	if got.members != "ge-0-0-1" {
		t.Fatalf("adopt tracked members=%q, want %q (only the realized member)",
			got.members, "ge-0-0-1")
	}

	// The missing member now appears in the kernel. The next reconcile must
	// complete the enslavement IN PLACE — no delete+recreate of the live
	// (degraded) bond (FINDING 1 of the #5533 review).
	ops.reset()
	ops.seedMember("ge-0-0-2")
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("second Apply() (member appeared) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("partial completion flapped the bond (delete+recreate): "+
			"delCalls=%v addCalls=%v — must complete in place", ops.delCalls, ops.addCalls)
	}
	if !contains(ops.masterCalls, "ge-0-0-2") {
		t.Fatalf("missing member ge-0-0-2 was NOT enslaved on the follow-up "+
			"reconcile: masterCalls=%v", ops.masterCalls)
	}
	if contains(ops.masterCalls, "ge-0-0-1") {
		t.Fatalf("already-enslaved member ge-0-0-1 was re-enslaved (flap): masterCalls=%v", ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("after completion b.bonds[bond0]=%+v, want full desired %+v", got, full)
	}
}

// TestBondAdoptPartialCompletesImmediatelyWhenMemberPresent covers the common
// restart case where the previously-absent member has since appeared in the
// kernel (the enumeration race resolved across the restart). The adopt path
// must enslave the now-present member in place — without an intervening
// recreate — and track the full desired sig, and it must NOT re-enslave the
// member that was already attached (#5259 no-flap for the good member). A
// subsequent identical reconcile is then a clean KEEP.
func TestBondAdoptPartialCompletesImmediatelyWhenMemberPresent(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("bond0", 10)
	ops.seedEnslavedMember("ge-0-0-1", 10) // already enslaved
	ops.seedMember("ge-0-0-2")             // present in kernel but NOT yet enslaved
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2")}
	full := bondSigOf(cfg[0])

	if err := b.Apply(cfg); err != nil {
		t.Fatalf("Apply() (adopt+complete) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("adopt+complete recreated the bond: delCalls=%v addCalls=%v",
			ops.delCalls, ops.addCalls)
	}
	if !contains(ops.masterCalls, "ge-0-0-2") {
		t.Fatalf("present member ge-0-0-2 was NOT enslaved at adopt: masterCalls=%v", ops.masterCalls)
	}
	if contains(ops.masterCalls, "ge-0-0-1") {
		t.Fatalf("already-enslaved member ge-0-0-1 was re-enslaved (flap): masterCalls=%v", ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("after in-place completion b.bonds[bond0]=%+v, want full desired %+v", got, full)
	}

	// Healed: the next identical reconcile is a pure KEEP (no ops at all).
	ops.reset()
	// Reflect the enslavement the fake does not model automatically so the
	// re-adopt sees a complete member set.
	ops.seedEnslavedMember("ge-0-0-2", 10)
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("third Apply() = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 || len(ops.masterCalls) != 0 {
		t.Fatalf("healed bond flapped on KEEP: delCalls=%v addCalls=%v masterCalls=%v",
			ops.delCalls, ops.addCalls, ops.masterCalls)
	}
}

// TestBondAdoptCompleteMemberSetNoFlap is the #5259 no-flap guarantee for the
// adopt path: a daemon restart that adopts a FULLY-realized kernel bond (every
// desired member already enslaved) must track the full desired sig and only
// bring the bond up — zero LinkDel, zero LinkAdd, zero LinkSetMaster. The
// partial-member verification must NOT tear down or re-enslave a good bond.
func TestBondAdoptCompleteMemberSetNoFlap(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("bond0", 10)
	ops.seedEnslavedMember("ge-0-0-1", 10)
	ops.seedEnslavedMember("ge-0-0-2", 10)
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2")}
	full := bondSigOf(cfg[0])

	if err := b.Apply(cfg); err != nil {
		t.Fatalf("Apply() (adopt complete) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 {
		t.Fatalf("fully-realized adopt issued LinkDel(s) %v — flapped a good bond", ops.delCalls)
	}
	if len(ops.addCalls) != 0 {
		t.Fatalf("fully-realized adopt issued LinkAdd(s) %v — rebuilt a good bond", ops.addCalls)
	}
	if len(ops.masterCalls) != 0 {
		t.Fatalf("fully-realized adopt re-enslaved member(s) %v — flapped a good bond", ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("adopt tracked %+v, want full desired %+v", got, full)
	}
}

// TestBondAdoptPermanentlyMissingMemberNoFlapConverges is FINDING 1/2 of the
// #5533 review: a member that stays absent across many reconciles must NOT
// cause a per-commit flap (the tracked partial sig must be completed IN PLACE,
// never delete+recreated every ApplyBonds), and the bond must still CONVERGE
// (enslave the member in place) the moment it finally appears. On master a
// partial bond is stable-degraded (no flap); the fix must not regress that
// while also fixing the eventual convergence.
func TestBondAdoptPermanentlyMissingMemberNoFlapConverges(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("bond0", 10)
	ops.seedEnslavedMember("ge-0-0-1", 10)
	// ge-0-0-2 is absent and stays absent for the first few reconciles.
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2")}
	full := bondSigOf(cfg[0])

	// Adopt + several reconciles with the member still missing: zero flap.
	for i := 0; i < 4; i++ {
		ops.reset()
		if err := b.Apply(cfg); err != nil {
			t.Fatalf("Apply() #%d (member absent) = %v, want nil", i, err)
		}
		if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
			t.Fatalf("reconcile #%d flapped a partial bond: delCalls=%v addCalls=%v — "+
				"a permanently-missing member must NOT delete+recreate every commit",
				i, ops.delCalls, ops.addCalls)
		}
		if got := b.bonds["bond0"]; got == full {
			t.Fatalf("reconcile #%d tracked the FULL sig despite the missing member %+v", i, got)
		}
	}

	// The member finally appears: the next reconcile completes it in place.
	ops.reset()
	ops.seedMember("ge-0-0-2")
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("Apply() (member appeared) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("convergence flapped the bond: delCalls=%v addCalls=%v", ops.delCalls, ops.addCalls)
	}
	if !contains(ops.masterCalls, "ge-0-0-2") {
		t.Fatalf("member ge-0-0-2 was NOT enslaved in place once it appeared: masterCalls=%v", ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("after convergence b.bonds[bond0]=%+v, want full desired %+v", got, full)
	}
}

// TestBondFreshCreateAbsentMemberConvergesInPlace is FINDING 2 of the #5533
// review: a bond FIRST CREATED with a member absent (a #4823 soft error) must
// track the REALIZED (partial) sig, not the full desired sig — otherwise the
// member is never enslaved when it appears (KEEP-forever, the fresh-create
// analogue of #5261). With the fix, the fresh-create tracks partial, does not
// flap on subsequent still-absent commits, and completes IN PLACE when the
// member appears. RED on revert: a fresh-create that tracks the full sig makes
// the tracked-partial assertion fail AND leaves ge-0-0-2 never enslaved.
func TestBondFreshCreateAbsentMemberConvergesInPlace(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-1")
	// ge-0-0-2 absent at creation time.
	b := &bondManager{ops: ops}

	cfg := []*config.InterfaceConfig{bondFabricConfig("bond0", "ge-0-0-1", "ge-0-0-2")}
	full := bondSigOf(cfg[0])

	if err := b.Apply(cfg); err != nil {
		t.Fatalf("first Apply() (fresh create) = %v, want nil", err)
	}
	got, ok := b.bonds["bond0"]
	if !ok {
		t.Fatalf("bond0 not tracked after fresh create: %+v", b.bonds)
	}
	if got == full {
		t.Fatalf("fresh-create tracked the FULL desired sig %+v despite the absent "+
			"member — the member is never enslaved when it appears (#5261 fresh-create)", got)
	}

	// Still absent: no flap.
	ops.reset()
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("second Apply() (still absent) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("still-absent reconcile flapped the bond: delCalls=%v addCalls=%v",
			ops.delCalls, ops.addCalls)
	}

	// Member appears: completes in place.
	ops.reset()
	ops.seedMember("ge-0-0-2")
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("third Apply() (member appeared) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("convergence flapped the bond: delCalls=%v addCalls=%v", ops.delCalls, ops.addCalls)
	}
	if !contains(ops.masterCalls, "ge-0-0-2") {
		t.Fatalf("absent-at-create member ge-0-0-2 was NOT enslaved when it appeared: masterCalls=%v", ops.masterCalls)
	}
	if got := b.bonds["bond0"]; got != full {
		t.Fatalf("after convergence b.bonds[bond0]=%+v, want full desired %+v", got, full)
	}
}

// TestBondKeepRestoresInterfaceMTUAfterOverrideRemoved_9872 is the parent-review
// transition the planner-only #9872 fix loses: a no-cluster fabric bond with
// interface MTU 1400 and a zoned untagged unit-0 override at 1300 has the
// override written onto fab0 by the dataplane; the operator then removes unit 0,
// leaving only tagged fab0.10. The bond signature carries no units, so it is
// unchanged and Apply takes the KEEP path — which must restore the live MTU to
// 1400, because nothing else writes the bond's MTU anymore (the dataplane
// plans nothing for a bond-mode tagged ref, and networkd only stamps MTU at
// creation). RED without reconcileBondMTU: the second Apply issues no MTU
// write and the bond sits at 1300 forever.
func TestBondKeepRestoresInterfaceMTUAfterOverrideRemoved_9872(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-0")
	ops.seedMember("ge-0-0-1")
	b := &bondManager{ops: ops}

	ifc := bondFabricConfig("fab0", "ge-0/0/0", "ge-0/0/1")
	ifc.MTU = 1400
	cfg := []*config.InterfaceConfig{ifc}
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("first Apply() (create) = %v, want nil", err)
	}
	if got := ops.links["fab0"].Attrs().MTU; got != 1400 {
		t.Fatalf("premise: created bond MTU = %d, want the interface-level 1400", got)
	}

	// The dataplane's untagged unit-0 override (1300) lands on fab0 while the
	// unit exists; the unit is then removed. Same interface MTU and members,
	// so the desired signature is unchanged.
	ops.links["fab0"].Attrs().MTU = 1300

	ops.reset()
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("second Apply() (KEEP) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 || len(ops.masterCalls) != 0 {
		t.Fatalf("KEEP flapped the bond: delCalls=%v addCalls=%v masterCalls=%v",
			ops.delCalls, ops.addCalls, ops.masterCalls)
	}
	if len(ops.mtuCalls) != 1 || ops.mtuCalls[0] != (mtuCall{name: "fab0", mtu: 1400}) {
		t.Fatalf("KEEP MTU writes = %+v, want exactly [{fab0 1400}]: the retained bond never reconverged", ops.mtuCalls)
	}
	if got := ops.links["fab0"].Attrs().MTU; got != 1400 {
		t.Fatalf("live bond MTU = %d after KEEP, want the interface-level 1400", got)
	}

	// Converged: a further identical Apply writes nothing (compare-then-write).
	ops.reset()
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("third Apply() (converged) = %v, want nil", err)
	}
	if len(ops.mtuCalls) != 0 {
		t.Fatalf("converged Apply wrote MTU %v, want no netlink churn on an unchanged bond", ops.mtuCalls)
	}
}

// TestBondAdoptRestoresInterfaceMTU_9872 is the same handoff on the adopt
// path: a bond that outlived in-memory tracking (daemon restart) carries
// whatever live MTU the last writer left — possibly a since-removed unit
// override — and adoption must converge it to the interface level without
// flapping the bond.
func TestBondAdoptRestoresInterfaceMTU_9872(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedBond("fab0", 7)
	ops.seedEnslavedMember("ge-0-0-0", 7)
	ops.seedEnslavedMember("ge-0-0-1", 7)
	ops.links["fab0"].Attrs().MTU = 1300 // left by a since-removed override
	b := &bondManager{ops: ops}

	ifc := bondFabricConfig("fab0", "ge-0/0/0", "ge-0/0/1")
	ifc.MTU = 1400
	cfg := []*config.InterfaceConfig{ifc}
	full := bondSigOf(cfg[0])
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("Apply() (adopt) = %v, want nil", err)
	}
	if len(ops.delCalls) != 0 || len(ops.addCalls) != 0 {
		t.Fatalf("adopt flapped the bond: delCalls=%v addCalls=%v", ops.delCalls, ops.addCalls)
	}
	if len(ops.mtuCalls) != 1 || ops.mtuCalls[0] != (mtuCall{name: "fab0", mtu: 1400}) {
		t.Fatalf("adopt MTU writes = %+v, want exactly [{fab0 1400}]", ops.mtuCalls)
	}
	if got := ops.links["fab0"].Attrs().MTU; got != 1400 {
		t.Fatalf("live bond MTU = %d after adopt, want the interface-level 1400", got)
	}
	if got := b.bonds["fab0"]; got != full {
		t.Fatalf("after adopt b.bonds[fab0]=%+v, want full desired %+v", got, full)
	}
}

// TestBondKeepMTUSetFailureIsHardAndRetried_9872 pins the #4823 shape of the
// new write: a LinkSetMTU failure on the KEEP path surfaces (like LinkSetUp),
// the bond stays tracked, and the next reconcile retries the convergence.
func TestBondKeepMTUSetFailureIsHardAndRetried_9872(t *testing.T) {
	ops := newFakeBondLinkOps()
	ops.seedMember("ge-0-0-0")
	ops.seedMember("ge-0-0-1")
	b := &bondManager{ops: ops}

	ifc := bondFabricConfig("fab0", "ge-0/0/0", "ge-0/0/1")
	ifc.MTU = 1400
	cfg := []*config.InterfaceConfig{ifc}
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("first Apply() (create) = %v, want nil", err)
	}
	ops.links["fab0"].Attrs().MTU = 1300
	ops.failLinkSetMTU["fab0"] = errors.New("injected: EINVAL")

	ops.reset()
	if err := b.Apply(cfg); err == nil {
		t.Fatalf("KEEP Apply() with failing LinkSetMTU = nil, want the hard error")
	} else if !strings.Contains(err.Error(), "MTU") {
		t.Fatalf("KEEP Apply() error = %v, want it to name the MTU write", err)
	}
	if !contains(ops.setUpCalls, "fab0") {
		t.Fatalf("LinkSetUp not attempted alongside the failed MTU write: setUpCalls=%v", ops.setUpCalls)
	}

	// The failure clears: the next reconcile converges.
	delete(ops.failLinkSetMTU, "fab0")
	ops.reset()
	if err := b.Apply(cfg); err != nil {
		t.Fatalf("retry Apply() = %v, want nil", err)
	}
	if len(ops.mtuCalls) != 1 || ops.mtuCalls[0] != (mtuCall{name: "fab0", mtu: 1400}) {
		t.Fatalf("retry MTU writes = %+v, want exactly [{fab0 1400}]", ops.mtuCalls)
	}
	if got := ops.links["fab0"].Attrs().MTU; got != 1400 {
		t.Fatalf("live bond MTU = %d after retry, want 1400", got)
	}
}
