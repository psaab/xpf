package dataplane

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// NOTE (#10642 vocabulary): these tests call the UP-zoned-unshimmed surface a
// "blackholed zone member". Pre-#10302 the same surface was "the policy-free
// router": the armed forward fence drops transit from never-pinholed links,
// so the gap is outage-plus-uncovered-zone, not a bypass. The StillForwarding
// FIELD keeps its name (churn); every use below means UP-zoned-unshimmed.

// #5275 PR1 — the observe-only arm-coverage proof.
//
// These tests pin the proof's DEFINITION, which is the part that must not
// drift: which surfaces count as covered, and why. The plan's §5/D1 wording
// ("strict program INSTANCE identity on every mapped attach point (native or
// generic)") is a native/generic binary and misses the delegated case
// entirely; implemented literally it would fail-close every VLAN deployment.
//
// They also bind the MANAGER path, not only the classifier: the report is a
// diagnostic whose whole value is being true about live state, and a suite that
// only ever drives classifyArmCoverage with an injected lookup can be fully
// green while the production source of that lookup reports the opposite of the
// truth.

// newProofResult builds a CompileResult carrying only what the proof reads.
func newProofResult(pending []int) *CompileResult {
	return &CompileResult{
		pendingXDP:          pending,
		tunnelIfindexes:     map[int]bool{},
		genericXDPIfindexes: map[int]bool{},
		linkIdxMap:          map[int]netlink.Link{},
		linkCache:           map[string]netlink.Link{},
	}
}

// vlanChild registers ifidx as a VLAN sub-interface of parent, exactly as
// compiler_iface.go marks them: genericXDPIfindexes set, not a tunnel.
//
// NetNsID is netnsIDLocal because that is what LinkDeserialize produces for a
// vlan whose real_dev shares its namespace — the ordinary case. The zero value
// of a hand-built netlink.LinkAttrs is 0, which is a REAL foreign nsid, so
// leaving it unset would model a link production never hands back and would
// quietly route every fixture through the foreign-parent belt.
func vlanChild(r *CompileResult, ifidx, parent int) {
	r.genericXDPIfindexes[ifidx] = true
	r.linkIdxMap[ifidx] = &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Index: ifidx, ParentIndex: parent, NetNsID: netnsIDLocal},
	}
}

// lookupFrom builds an instanceLookup from a table of covered ifindexes.
func lookupFrom(covered map[int]uint32, generic map[int]bool) instanceLookup {
	return func(ifidx int) (uint32, bool, bool) {
		id, ok := covered[ifidx]
		if !ok {
			return 0, false, false
		}
		return id, generic[ifidx], true
	}
}

// swapArmProbes replaces the two live-state probes Manager.attachedInstance
// reads. Neither is reachable from a unit test otherwise: XDP cannot be
// attached without CAP_NET_ADMIN, and link.Link carries an unexported method so
// no fake can satisfy it. A nil argument leaves that probe alone.
//
// These are PACKAGE-level vars, so a caller MUST NOT t.Parallel(): the swap
// would be visible to every other test running at the same time. It is safe
// today only because Go resumes parallel tests after the serial ones finish and
// no parallel test in this package reads a probe — do not rely on that
// accident, mark the constraint here instead.
func swapArmProbes(t *testing.T, mode func(int) bool, progID func(link.Link) (uint32, bool)) {
	t.Helper()
	oldMode, oldID := xdpLinkModeGeneric, xdpLinkProgramID
	if mode != nil {
		xdpLinkModeGeneric = mode
	}
	if progID != nil {
		xdpLinkProgramID = progID
	}
	t.Cleanup(func() {
		xdpLinkModeGeneric, xdpLinkProgramID = oldMode, oldID
	})
}

// captureLogs redirects the default slog handler for the duration of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// TestArmProofGenericFallbackCountsAsArmed pins the STATED DECISION that a
// generic (skb-mode) attach is armed.
//
// It is deliberately a test and not only a comment. A generic shim still
// steers packets to userspace-dp and still enforces policy — slower, but
// #5275 exists to prevent a POLICY-FREE kernel, and this box is not policy
// free. iavf SR-IOV VFs have NO native XDP support at all, so the fallback is
// a supported steady state; failing it closed would brick a supported
// deployment to prevent a condition that is not occurring.
//
// Without this test the decision is an implicit consequence of how the
// readback happens to be written, and a later "tighten the proof" change flips
// those boxes to fail-closed with nobody intending it.
func TestArmProofGenericFallbackCountsAsArmed(t *testing.T) {
	r := newProofResult([]int{10})

	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 77}, map[int]bool{10: true}))

	if rep.Uncovered != 0 || rep.Direct != 1 {
		t.Fatalf("generic fallback must count as armed; got %+v", rep)
	}
	if rep.WouldGate {
		t.Fatal("a gating build would have REFUSED a box running the shim in skb-mode — " +
			"that is a supported deployment (iavf VFs have no native XDP at all)")
	}
	s := rep.Surfaces[0]
	if s.Kind != CoverageDirect || !s.Generic {
		t.Fatalf("expected direct+generic; got kind=%s generic=%v", s.Kind, s.Generic)
	}
	if s.ProgramID != 77 {
		t.Fatalf("proof did not record the attached program instance; got %d", s.ProgramID)
	}
}

// TestArmProofGenericModeSurvivesASecondCompile is the reason the attach mode
// is read from the KERNEL and not from anything this compile recorded.
//
// attachUserspaceShimXDP falls back to generic ONCE. The m.xdpLinks entry it
// leaves behind survives every later compile — syncInterfaceAttachments detaches
// only ifindexes outside the allowed ingress set, and the pin sweep in
// userspace/manager_compile.go deletes link PINS, not this map — so AttachXDP
// short-circuits on "already attached" and the compile records nothing. Every
// commit, HA config sync and deferred-MAC reapply after the first therefore has
// a FRESH, EMPTY per-compile record while the box is still on skb-mode.
//
// A proof sourced from that record logs "went native" on a box that did not,
// on precisely the population (iavf SR-IOV VFs) whose size this phase exists to
// measure. That is worse than no measurement.
func TestArmProofGenericModeSurvivesASecondCompile(t *testing.T) {
	const ifidx = 7
	swapArmProbes(t,
		func(i int) bool { return i == ifidx },             // kernel: still skb-mode
		func(link.Link) (uint32, bool) { return 42, true }, // bpf_link readback
	)

	m := New()
	m.loaded.Store(true) // #2114 A3: loaded is atomic.Bool
	m.SelectUserspaceXDPShimEntryProgram()
	m.programs[m.XDPEntryProgram()] = nil
	// What compile #1 left behind after its native->generic fallback.
	m.xdpLinks[ifidx] = nil

	// Compile #2 — a FRESH CompileResult, exactly as CompileConfig builds one
	// on every commit.
	result := newProofResult([]int{ifidx})
	if err := m.attachUserspaceShimXDP(result); err != nil {
		t.Fatalf("second compile attach: %v", err)
	}
	// A real compile-#2 Manager carries a lastCompile (CompileUserspaceShim
	// assigns one at the tail of every compile), so set one. The assertion
	// below must not be dismissible as an artefact of a nil field.
	m.lastCompile = result

	rep := m.ProveArmCoverage(result)
	if len(rep.Surfaces) != 1 {
		t.Fatalf("expected exactly the one required surface; got %+v", rep.Surfaces)
	}
	s := rep.Surfaces[0]
	if s.Kind != CoverageDirect {
		t.Fatalf("the tracked link is attached; expected direct, got %s (%s)", s.Kind, s.Detail)
	}
	if !s.Generic {
		t.Fatalf("proof reported NATIVE for a link the kernel has in skb-mode: %q — "+
			"the second compile short-circuits on \"already attached\" and records no fallback, "+
			"so a per-compile source reads native and the fleet log says the box went native "+
			"when it never left the slow path", rep.SurfaceSummary())
	}
	if got := rep.SurfaceSummary(); !strings.Contains(got, "7:direct/generic") {
		t.Fatalf("summary must name the LIVE attach mode; got %q", got)
	}
}

// TestArmProofNativeSurfaceIsNotReportedGeneric is the over-reach guard for the
// test above: reading ground truth must not turn every surface generic. A
// driver-mode attach still reports native.
func TestArmProofNativeSurfaceIsNotReportedGeneric(t *testing.T) {
	swapArmProbes(t,
		func(int) bool { return false }, // kernel: driver mode
		func(link.Link) (uint32, bool) { return 9, true },
	)

	m := New()
	m.loaded.Store(true) // #2114 A3: loaded is atomic.Bool
	m.xdpLinks[5] = nil

	rep := m.ProveArmCoverage(newProofResult([]int{5}))
	if len(rep.Surfaces) != 1 || rep.Surfaces[0].Kind != CoverageDirect {
		t.Fatalf("expected one direct surface; got %+v", rep.Surfaces)
	}
	if rep.Surfaces[0].Generic {
		t.Fatalf("a driver-mode attach must NOT be reported as skb-mode; got %q", rep.SurfaceSummary())
	}
	if got := rep.SurfaceSummary(); !strings.Contains(got, "5:direct/native") {
		t.Fatalf("expected 5:direct/native; got %q", got)
	}
}

// TestArmProofUntrackedIfindexIsUncovered is the other over-reach guard on the
// Manager path: reading the kernel must not manufacture coverage for an
// ifindex the Manager tracks no link for.
func TestArmProofUntrackedIfindexIsUncovered(t *testing.T) {
	swapArmProbes(t,
		func(int) bool { return true },
		func(link.Link) (uint32, bool) { return 1, true },
	)

	m := New() // no xdpLinks entries at all

	rep := m.ProveArmCoverage(newProofResult([]int{5}))
	if rep.Uncovered != 1 || rep.Direct != 0 {
		t.Fatalf("an ifindex with no tracked link must be uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("a required surface with no link at all must be reported as WOULD-GATE")
	}
}

// TestArmProofDelegatedVlanChildResolvesToParent pins the third category the
// plan's native/generic binary misses.
//
// A VLAN sub-interface under the userspace shim is NEVER attached — both
// attach loops skip it and it is recorded in VlanSubInterfaces instead —
// because the PARENT's XDP sees VLAN-tagged frames before kernel VLAN
// demuxing, and attaching the shim to the child breaks IPv6 NDP. Policy is
// enforced, at a different attach point.
//
// A proof demanding an instance on every mapped attach point fails here, and
// the loss cluster (reth0.50 / reth0.80) plus the standalone VM (VLAN 50) both
// have such surfaces — i.e. it would fail-close essentially every real
// deployment.
func TestArmProofDelegatedVlanChildResolvesToParent(t *testing.T) {
	r := newProofResult([]int{10, 20})
	vlanChild(r, 20, 10) // 20 is a VLAN child of 10

	// Only the PARENT carries an instance. That is the correct steady state.
	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 55}, nil))

	if rep.Uncovered != 0 {
		t.Fatalf("a VLAN child covered by its parent must not read as uncovered; got %+v", rep)
	}
	if rep.Direct != 1 || rep.Delegated != 1 {
		t.Fatalf("expected 1 direct (parent) + 1 delegated (child); got %+v", rep)
	}
	if rep.Skipped != 0 {
		t.Fatalf("nothing was declined here; got %+v", rep)
	}
	if rep.WouldGate {
		t.Fatal("a gating build would have REFUSED a plain VLAN deployment — " +
			"the loss cluster and the standalone VM both run VLAN sub-interfaces")
	}
	var child SurfaceCoverage
	for _, s := range rep.Surfaces {
		if s.Ifindex == 20 {
			child = s
		}
	}
	if child.Kind != CoverageDelegated || child.Via != 10 {
		t.Fatalf("child must resolve to its covering parent; got kind=%s via=%d", child.Kind, child.Via)
	}
	if child.ProgramID != 55 {
		t.Fatalf("delegated surface must carry the DELEGATE's instance; got %d", child.ProgramID)
	}
}

// TestArmProofDelegationIsResolvedNotAssumed is the other half of the pair
// above, and the reason "skip VLAN children" is not an acceptable shortcut.
//
// If the parent carries no instance, the child is NOT covered — nothing is
// enforcing its traffic. A proof that skipped VLAN children unconditionally
// would pass this box, which is precisely the blackholed-zone-member state #5275
// exists to surface (pre-#10302: "the policy-free-router state").
func TestArmProofDelegationIsResolvedNotAssumed(t *testing.T) {
	r := newProofResult([]int{10, 20})
	vlanChild(r, 20, 10)

	// NOTHING is attached — parent included.
	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	if rep.Delegated != 0 {
		t.Fatalf("a child whose parent carries no instance must NOT read as delegated; got %+v", rep)
	}
	if rep.Uncovered != 2 {
		t.Fatalf("both parent and child are uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("a fully unattached dataplane must be reported as WOULD-GATE — " +
			"this is the uncovered dataplane #5275 is about (pre-#10302: \"the policy-free kernel\")")
	}
}

// TestArmProofDelegateMustBeARequiredSurface pins the stronger half of the
// documented invariant — "the parent must itself be DIRECTLY covered" — which a
// bare "does a link exist for the parent" check does not deliver.
//
// The case this covers is an UNACCOUNTED-FOR parent: the child is required, the
// parent is outside the required set, and the compiler recorded NOTHING about
// it — so nothing in the whole compile says what happened to it. A stale
// bpf_link from a previous compile still reads back an instance (the
// enabled->disabled transition leaves the old link in place while the parent is
// admin-DOWN and about to be torn down), and taking that as proof would report
// a covered child with nothing enforcing its traffic. It stays UNCOVERED.
//
// The sibling case — the compiler DID record the parent, and proved it down —
// is TestArmProofVLANChildOfProvenDownParentIsSkipped. The difference is the
// record: an unaccounted-for parent is a hole in the proof, a proven-down one
// is an answer. Both are reachable from `set interfaces ge-0-0-2 disable` with
// ge-0-0-2.50 still in a zone, because compiler_iface.go appends the CHILD ~130
// lines above the isDisabled check and never appends a disabled parent.
func TestArmProofDelegateMustBeARequiredSurface(t *testing.T) {
	r := newProofResult([]int{20}) // ONLY the child is required
	vlanChild(r, 20, 10)
	// Deliberately NO unarmed record for the parent: nothing in this compile
	// accounts for ifindex 10 at all.

	// The parent's stale link still reads back an instance.
	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 55}, nil))

	if rep.Delegated != 0 {
		t.Fatalf("delegation to a parent that is not a required surface must NOT count as covered; got %+v", rep)
	}
	if rep.Uncovered != 1 {
		t.Fatalf("the child is uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("a VLAN child whose delegate nothing proves armed must be reported as WOULD-GATE")
	}
	if rep.Surfaces[0].Via != 10 {
		t.Fatalf("the record must still name the parent that failed to cover it; got via=%d", rep.Surfaces[0].Via)
	}
}

// TestArmProofVLANChildOfProvenDownParentIsSkipped pins the classification of
// the interface shape BOTH reference deployments run.
//
// `set interfaces ge-0-0-2 disable` with ge-0-0-2.50 still in a zone leaves the
// child in pendingXDP and the parent out of it — compiler_iface.go appends the
// VLAN child ~130 lines ABOVE the isDisabled check and never appends a disabled
// parent. Classified purely on "is the delegate required", the child lands
// UNCOVERED and drives WouldGate on a clean operator action, on exactly the
// shape the loss cluster (reth0.50/reth0.80) and the standalone VM (VLAN 50)
// both run. This PR's deliverable is a NUMBER that calibrates a later gate's
// threshold, so a baseline inflated by legitimate configs is the failure it
// exists to prevent — and it contradicts this file's own stated rule that a
// clean disable stays out of would-gate.
//
// It is not a hole in the proof either: a VLAN device cannot pass traffic while
// its real device is DOWN, so the parent's proven-down record answers for the
// child too. SKIPPED, the third unknown, is that answer.
func TestArmProofVLANChildOfProvenDownParentIsSkipped(t *testing.T) {
	r := newProofResult([]int{20}) // ONLY the child is required
	vlanChild(r, 20, 10)
	// The compiler's OWN record for a CLEAN disable: the link resolved and
	// LinkSetDown succeeded, so the netdev is proven down.
	r.recordUnarmedSurface(disabledSurfaceRecord("ge-0-0-2", 10, nil, nil))

	// Nothing is attached anywhere — a disabled parent never gets a shim.
	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	if rep.Uncovered != 0 {
		t.Fatalf("a VLAN child whose parent the compiler declined and PROVED down must not read "+
			"uncovered — the parent netdev is down, so nothing forwards through the child either, "+
			"and reading it uncovered inflates the baseline on every VLAN-over-parent deployment; "+
			"got %+v (%s)", rep, rep.SurfaceSummary())
	}
	if rep.WouldGate {
		t.Fatalf("a clean `disable` must stay OUT of would-gate — this file's own stated rule for "+
			"a legitimate operator action; got %+v (%s)", rep, rep.SurfaceSummary())
	}
	// The child and the parent's own record: two surfaces, counted once each.
	if rep.Skipped != 2 {
		t.Fatalf("expected the child AND the parent record as 2 skipped surfaces; got %+v (%s)",
			rep, rep.SurfaceSummary())
	}
	child := rep.Surfaces[0]
	if child.Kind != CoverageSkipped || child.Via != 10 {
		t.Fatalf("the child's record must be skipped and still name the parent; got %+v", child)
	}
	if !strings.Contains(child.Detail, "ge-0-0-2") {
		t.Fatalf("the child's detail must NAME the proven-down parent, not just its ifindex, or an "+
			"operator cannot tell which interface answered for it; got %q", child.Detail)
	}
}

// TestArmProofVLANChildOfUnprovenParentStaysUncovered is the OVER-REACH GUARD
// for the test above: the promotion is conditioned on the netdev being PROVEN
// down, not merely on the compiler having declined it.
//
// Same operator action, but netlink.LinkSetDown FAILED. The disable branch logs
// that at WARN and continues, address reconciliation runs regardless, and the
// parent is left possibly UP, still in a zone, with no XDP — a blackholed
// zone member (pre-#10302: "the policy-free-router condition"), its transit
// fence-dropped for want of a pinhole. The VLAN child rides that same netdev, so it must NOT inherit the
// benign reading.
func TestArmProofVLANChildOfUnprovenParentStaysUncovered(t *testing.T) {
	r := newProofResult([]int{20})
	vlanChild(r, 20, 10)
	r.recordUnarmedSurface(disabledSurfaceRecord("ge-0-0-2", 10, nil, errors.New("device or resource busy")))

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	if rep.Uncovered != 2 {
		t.Fatalf("a parent whose link-down FAILED is a blackholed zone member and the child "+
			"rides the same netdev — BOTH must read uncovered; got %+v (%s)", rep, rep.SurfaceSummary())
	}
	if rep.Skipped != 0 {
		t.Fatalf("nothing here is a benign skip; got %+v (%s)", rep, rep.SurfaceSummary())
	}
	if !rep.WouldGate {
		t.Fatalf("an unproven-down parent carrying a zoned, XDP-less netdev must be reported "+
			"WOULD-GATE; got %+v", rep)
	}
}

// TestArmProofProvenDownRecordCoversOnlyItsOwnChild is the second OVER-REACH
// GUARD: a proven-down record answers for the VLAN children delegating to THAT
// ifindex and for nothing else. An ordinary direct surface with no instance is
// still a blackholed zone member no matter what else on the box was
// cleanly disabled.
func TestArmProofProvenDownRecordCoversOnlyItsOwnChild(t *testing.T) {
	// 20 is a VLAN child of the proven-down 10; 30 is an unrelated direct
	// surface with nothing attached.
	r := newProofResult([]int{20, 30})
	vlanChild(r, 20, 10)
	r.recordUnarmedSurface(disabledSurfaceRecord("ge-0-0-2", 10, nil, nil))

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	var thirty SurfaceCoverage
	for _, s := range rep.Surfaces {
		if s.Ifindex == 30 {
			thirty = s
		}
	}
	if thirty.Kind != CoverageUncovered {
		t.Fatalf("a direct surface with no instance stays uncovered however many OTHER surfaces "+
			"were proven down; got %+v (%s)", thirty, rep.SurfaceSummary())
	}
	if !rep.WouldGate {
		t.Fatalf("an unattached direct surface must still drive would-gate; got %+v (%s)",
			rep, rep.SurfaceSummary())
	}
}

// The link kinds a "<phys>.<vid>" name can actually hold. Each constructor
// builds what netlink.LinkByIndex deserialises that device to, and every
// ParentIndex/NetNsID pair below is a shape verified against this netlink
// version in a network namespace — not a hypothetical.
//
//	genuine vlan   p0.100@p0  -> type=vlan     parentIdx=<real_dev>          netnsid=-1
//	orphan vlan    p0.100@if5 -> type=vlan     parentIdx=<real_dev, FOREIGN> netnsid=0
//	cross-ns veth  p0.100@if6 -> type=veth     parentIdx=<PEER, foreign ns>  netnsid=0
//	macvlan        r0.300@r0  -> type=macvlan  parentIdx=<lower dev>         netnsid=-1
//
// Two of these are sharp, for the same reason: their ParentIndex is an ifindex
// in ANOTHER namespace, so it carries no relationship at all to the
// same-numbered local interface it collides with. The veth is caught by the
// KIND belt. The orphan vlan is not — it really is an 802.1Q device — which is
// why the namespace belt exists.
//
// NetNsID is set explicitly on every one of them. LinkDeserialize seeds -1 and
// overwrites it only from IFLA_LINK_NETNSID, which the kernel emits exactly
// when link_net != dev_net; a hand-built LinkAttrs zero-values it to 0, which
// is a real foreign nsid. An unset field here would silently be the FOREIGN
// case.
func genuineVlanLink(ifidx, parent int) netlink.Link {
	return &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Index: ifidx, ParentIndex: parent, NetNsID: netnsIDLocal},
		VlanId:    50,
	}
}

// foreignParentVlanLink is the orphan: a genuine 802.1Q device whose real_dev
// was left behind in another namespace. Measured shape — type "vlan",
// ParentIndex naming an ifindex in that other namespace, netnsid 0 (NOT a
// positive id, which is why the belt tests `!= -1`). It is a LIVE surface: it
// refuses LinkSetUp only while the foreign real_dev is down, and comes up and
// forwards once that device is up in its own namespace.
func foreignParentVlanLink(ifidx, parent int) netlink.Link {
	return &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{Index: ifidx, ParentIndex: parent, NetNsID: 0},
		VlanId:    50,
	}
}

func foreignPeerVethLink(ifidx, parent int) netlink.Link {
	return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Index: ifidx, ParentIndex: parent, NetNsID: 0}}
}

func lowerDevMacvlanLink(ifidx, parent int) netlink.Link {
	return &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{Index: ifidx, ParentIndex: parent, NetNsID: netnsIDLocal},
	}
}

// delegatedChild registers ifidx as a surface the COMPILER filed as a VLAN
// child of parent — genericXDPIfindexes set, not a tunnel, exactly as
// compiler_iface.go marks them — while letting the caller choose what the
// netdev at that ifindex actually IS.
//
// That split is the whole point: the compiler's marking comes from
// ensureVLANSubInterface, which adopts any existing "<phys>.<vid>" device
// without checking its kind, so "filed as a VLAN child" and "is a VLAN" are
// independent facts and the fixture must be able to vary one without the other.
func delegatedChild(r *CompileResult, ifidx, parent int, kind func(int, int) netlink.Link) {
	r.genericXDPIfindexes[ifidx] = true
	r.linkIdxMap[ifidx] = kind(ifidx, parent)
}

// TestArmProofNonVLANChildNeverInheritsItsParentIndex is the belt against the
// proof UNDER-counting, which is strictly worse than the over-count this file
// already removed: an over-count inflates a baseline, an under-count silently
// hides a live forwarding surface with no shim on it.
//
// vishvananda/netlink folds IFLA_LINK into LinkAttrs.ParentIndex in the COMMON
// attribute loop, for every link kind. Both branches that can make a child read
// as covered — the proven-down promotion to SKIPPED and the delegation to a
// covered required parent — read that field as a LOCAL VLAN parent. For a
// cross-namespace veth, IFLA_LINK is the PEER's ifindex in the foreign
// namespace, which can numerically alias any local interface; for a macvlan it
// is a lower device that demuxes nothing; and for an ORPHAN VLAN — a genuine
// 802.1Q device whose real_dev was left in another namespace — it is that
// real_dev's ifindex over there, which aliases just as freely while the KIND
// belt waves it through. Either way an unrelated local interface answers for a
// surface it has no relationship to.
//
// It is reachable, not theoretical: ensureVLANSubInterface adopts ANY existing
// device named "<phys>.<vid>", without checking its kind OR where its real_dev
// lives; the ifindex is then recorded as a delegated VLAN child, the userspace
// attach loop skips it so it never gets a shim, and the unmanaged sweep will
// not remove it because the name's prefix before '.' is a managed interface.
// The device stays UP with no XDP (its transit is fence-dropped for want of a pinhole).
func TestArmProofNonVLANChildNeverInheritsItsParentIndex(t *testing.T) {
	// The two arms are the two ways a child can end up counted as covered.
	// Both must be closed: closing one leaves the other as a live under-count.
	arms := []struct {
		name string
		// setup makes ifindex 10 the thing the defect would have delegated to.
		setup func(*CompileResult)
		// wrong is the kind the defect produced for the CHILD.
		wrong  SurfaceCoverageKind
		lookup instanceLookup
	}{
		{
			name: "parent_proven_down_would_promote_to_skipped",
			setup: func(r *CompileResult) {
				// A clean `disable` of an unrelated LOCAL interface that just
				// happens to sit at the ifindex the child's IFLA_LINK names.
				r.recordUnarmedSurface(disabledSurfaceRecord("ge-0-0-2", 10, nil, nil))
			},
			wrong:  CoverageSkipped,
			lookup: lookupFrom(nil, nil),
		},
		{
			name: "parent_required_and_covered_would_delegate",
			setup: func(r *CompileResult) {
				// ifindex 10 is a required, directly-covered surface — an
				// entirely healthy interface elsewhere on the box.
				r.pendingXDP = append(r.pendingXDP, 10)
			},
			wrong:  CoverageDelegated,
			lookup: lookupFrom(map[int]uint32{10: 55}, nil),
		},
	}
	kinds := []struct {
		name string
		make func(int, int) netlink.Link
	}{
		{"cross_namespace_veth", foreignPeerVethLink},
		{"macvlan", lowerDevMacvlanLink},
		// The orphan vlan passes the KIND belt — it IS an 802.1Q device — so
		// only the namespace belt stops it. Its ParentIndex is an ifindex in
		// the namespace its real_dev was left in, free to collide with any
		// local one. Unlike the two above, this row cannot be dismissed as an
		// inert device: measured on this kernel, the orphan refuses LinkSetUp
		// only while that foreign real_dev is DOWN (rc=2, ENETDOWN) and comes
		// up and forwards the moment it is brought up there (rc=0,
		// up|broadcast|running). An earlier revision of the source comment
		// asserted the opposite; that experiment had simply left the real_dev
		// down.
		{"foreign_namespace_vlan", foreignParentVlanLink},
	}

	for _, arm := range arms {
		for _, kind := range kinds {
			t.Run(arm.name+"/"+kind.name, func(t *testing.T) {
				r := newProofResult([]int{20})
				delegatedChild(r, 20, 10, kind.make)
				arm.setup(r)

				rep := classifyArmCoverage(r, arm.lookup)

				var child SurfaceCoverage
				found := false
				for _, s := range rep.Surfaces {
					if s.Ifindex == 20 && s.Name == "" {
						child, found = s, true
					}
				}
				if !found {
					t.Fatalf("the child surface vanished from the report; got %s", rep.SurfaceSummary())
				}
				if child.Kind != CoverageUncovered {
					t.Fatalf("a %s carries no LOCAL 802.1Q parent, so its ParentIndex names nothing "+
						"in this namespace — it must read UNCOVERED, not %s. Reading it as %s lets "+
						"ifindex 10 answer for a surface it has no relationship to, and hides a "+
						"live interface forwarding with no shim on it; got %+v (%s)",
						kind.name, child.Kind, arm.wrong, child, rep.SurfaceSummary())
				}
				if child.Via != 0 {
					t.Fatalf("the record must NOT name ifindex %d as a covering parent — it is not "+
						"one, and printing it repeats the same confusion in the operator's log; "+
						"got via=%d", child.Via, child.Via)
				}
				if !rep.WouldGate {
					t.Fatalf("a live, XDP-less UP-zoned surface is exactly the blackholed-zone-member "+
						"condition #5275 measures and MUST drive would-gate; got %+v (%s)",
						rep, rep.SurfaceSummary())
				}
				if rep.Uncovered != 1 {
					t.Fatalf("expected exactly the child uncovered; got %+v (%s)", rep, rep.SurfaceSummary())
				}
			})
		}
	}
}

// TestArmProofVLANKindIsTheDiscriminator is the OVER-REACH GUARD for the test
// above, and its negative control.
//
// It drives the SAME two arms over the SAME fixture — same ifindexes, same
// aliasing, same unarmed record, same lookup — varying ONE thing: the child is
// an ordinary LOCAL 802.1Q device (kind "vlan", NetNsID netnsIDLocal, i.e. the
// exact shape LinkDeserialize returns for reth0.50 on the loss cluster). Both
// arms must still reach their covered readings.
//
// It is the negative control for BOTH belts in coverDelegated, and it is what
// stops either from being widened into "make every delegated child uncovered":
// that mutation passes the test above while re-breaking every VLAN deployment
// the earlier fold fixed — the loss cluster's reth0.50/reth0.80 and the
// standalone VM's VLAN 50 would go back to driving would-gate on a clean
// operator action. What discriminates is the kind AND the parent's locality,
// never the delegation itself. It is also why the namespace belt is spelled
// `!= netnsIDLocal` rather than a positive-id test: this control fixture
// carries -1, and the orphan it must reject carries 0.
func TestArmProofVLANKindIsTheDiscriminator(t *testing.T) {
	t.Run("parent_proven_down_still_skips", func(t *testing.T) {
		r := newProofResult([]int{20})
		delegatedChild(r, 20, 10, genuineVlanLink)
		r.recordUnarmedSurface(disabledSurfaceRecord("ge-0-0-2", 10, nil, nil))

		rep := classifyArmCoverage(r, lookupFrom(nil, nil))

		if rep.Surfaces[0].Kind != CoverageSkipped {
			t.Fatalf("a GENUINE vlan over a proven-down parent cannot forward and must stay "+
				"SKIPPED — the kind is what disqualifies a squatter, not the delegation itself; "+
				"got %+v (%s)", rep.Surfaces[0], rep.SurfaceSummary())
		}
		if rep.WouldGate {
			t.Fatalf("a clean `disable` must stay OUT of would-gate; got %+v (%s)", rep, rep.SurfaceSummary())
		}
	})

	t.Run("parent_required_and_covered_still_delegates", func(t *testing.T) {
		r := newProofResult([]int{20})
		delegatedChild(r, 20, 10, genuineVlanLink)
		r.pendingXDP = append(r.pendingXDP, 10)

		rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 55}, nil))

		var child SurfaceCoverage
		for _, s := range rep.Surfaces {
			if s.Ifindex == 20 {
				child = s
			}
		}
		if child.Kind != CoverageDelegated || child.Via != 10 || child.ProgramID != 55 {
			t.Fatalf("a GENUINE vlan whose parent carries a shim IS covered by it — the parent's "+
				"XDP sees the tagged frames before kernel demuxing; got %+v (%s)",
				child, rep.SurfaceSummary())
		}
		if rep.WouldGate {
			t.Fatalf("a plain VLAN-over-covered-parent deployment must not drive would-gate; "+
				"got %+v (%s)", rep, rep.SurfaceSummary())
		}
	})
}

// TestArmProofDeclinedSurfaceLogsAtInfo pins the two per-surface LEVELS apart.
//
// WARN is the would-gate set — the surfaces a gating build would refuse on. A
// declined surface is the benign branch, and its dominant member is a clean
// `disable`, which this file deliberately excludes from would_gate. Emitting it
// at WARN puts a routine commit's expected output at the same level as the
// blackholed-zone-member condition, which trains operators to ignore both.
func TestArmProofDeclinedSurfaceLogsAtInfo(t *testing.T) {
	buf := captureLogs(t)

	r := newProofResult([]int{40}) // 40 is attached to nothing -> uncovered
	r.recordUnarmedSurface(disabledSurfaceRecord("ge-0-0-2", 10, nil, nil))
	classifyArmCoverage(r, lookupFrom(nil, nil)).LogArmCoverage("post-attach", 9)

	for _, line := range strings.Split(buf.String(), "\n") {
		switch {
		case strings.Contains(line, "DECLINED to arm"):
			if !strings.Contains(line, "level=INFO") {
				t.Fatalf("a declined surface is the benign branch and must log at INFO, not "+
					"alongside the would-gate set; got %q", line)
			}
		case strings.Contains(line, "WOULD fail a gating proof"):
			if !strings.Contains(line, "level=WARN") {
				t.Fatalf("a would-gate surface must stay at WARN — demoting it hides the "+
					"blackholed-zone-member condition this PR exists to measure; got %q", line)
			}
		}
	}
	if !strings.Contains(buf.String(), "DECLINED to arm") || !strings.Contains(buf.String(), "WOULD fail a gating proof") {
		t.Fatalf("this cell needs BOTH per-surface lines present to compare their levels; got %q", buf.String())
	}
}

// TestArmProofUncoveredIsTheZeroValue pins the fail-safe default. An entry that
// was never populated must read as uncovered, so a partially-built report can
// only ever be more conservative, never less.
func TestArmProofUncoveredIsTheZeroValue(t *testing.T) {
	var k SurfaceCoverageKind
	if k != CoverageUncovered {
		t.Fatalf("the zero SurfaceCoverageKind must be Uncovered, got %s — "+
			"an unpopulated entry would otherwise read as covered", k)
	}
	var s SurfaceCoverage
	if s.Kind != CoverageUncovered {
		t.Fatal("a zero SurfaceCoverage must read as uncovered")
	}
}

// TestArmProofReadbackFailureIsUncovered pins that a tracked link whose
// identity cannot be read is not treated as proof of coverage. The lookup
// returning ok=false is exactly what Manager.attachedInstance does when the
// bpf_link info call errors.
func TestArmProofReadbackFailureIsUncovered(t *testing.T) {
	r := newProofResult([]int{10})
	// Link tracked (generic flag known) but the instance readback failed.
	rep := classifyArmCoverage(r, func(int) (uint32, bool, bool) { return 0, true, false })

	if rep.Uncovered != 1 || rep.Direct != 0 {
		t.Fatalf("a failed instance readback must degrade to uncovered; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("unreadable link identity must be reported as WOULD-GATE, not assumed benign")
	}
}

// TestArmProofIsDeterministic pins the stable ordering the log line depends on:
// two reports of the same box must be diffable.
func TestArmProofIsDeterministic(t *testing.T) {
	r := newProofResult([]int{30, 10, 20})
	lookup := lookupFrom(map[int]uint32{10: 1, 20: 2, 30: 3}, nil)

	rep := classifyArmCoverage(r, lookup)
	if len(rep.Surfaces) != 3 {
		t.Fatalf("expected 3 surfaces; got %d", len(rep.Surfaces))
	}
	for i, want := range []int{10, 20, 30} {
		if rep.Surfaces[i].Ifindex != want {
			t.Fatalf("surfaces must be in ascending ifindex order; got %+v", rep.Surfaces)
		}
	}
	// The input slice must not be reordered underneath the caller — the proof
	// runs mid-apply against live compile state.
	if r.pendingXDP[0] != 30 {
		t.Fatalf("proof MUTATED the compile result's pendingXDP order: %v", r.pendingXDP)
	}
}

// TestArmProofDoesNotMemoiseIntoTheCompileResult pins the observe-only claim
// literally. cachedLinkByIndex memoises a successful lookup into linkIdxMap AND
// linkCache; the proof must use the non-memoising peek instead, or the claim
// "it mutates nothing" is false and a CompileResult reachable by any other
// reader takes an unannounced map write.
//
// ifindex 1 is loopback in every Linux network namespace, so the lookup here
// SUCCEEDS — which is the case that matters, because cachedLinkByIndex only
// writes on success. lo has no parent, so the surface lands uncovered; the
// assertions are about the caches, not the verdict.
func TestArmProofDoesNotMemoiseIntoTheCompileResult(t *testing.T) {
	r := newProofResult([]int{1})
	// Classify ifindex 1 as a VLAN child so the delegated path resolves it,
	// and deliberately leave it OUT of linkIdxMap so resolution must go to the
	// kernel rather than hitting the pre-seeded entry.
	r.genericXDPIfindexes[1] = true

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))
	if len(rep.Surfaces) != 1 {
		t.Fatalf("expected the one required surface; got %+v", rep.Surfaces)
	}
	if len(r.linkIdxMap) != 0 {
		t.Fatalf("the proof MEMOISED into the CompileResult it is proving: linkIdxMap=%v — "+
			"an observe-only diagnostic must not write into the object it observes", r.linkIdxMap)
	}
	if len(r.linkCache) != 0 {
		t.Fatalf("the proof MEMOISED into the CompileResult it is proving: linkCache=%v", r.linkCache)
	}
}

// TestArmProofSoftSkippedSurfaceIsDistinguishable pins that a surface the
// COMPILER declined to arm is not silently absent.
//
// compiler_iface.go soft-skips three ways — interface not found, VLAN child
// create failed, administratively disabled — each behind nothing but a slog
// line, each leaving the compile SUCCESSFUL and the surface out of pendingXDP.
// Without a record the proof reports Uncovered=0 for a config whose surfaces it
// never even looked at, which reads identically to a fully-armed box.
func TestArmProofSoftSkippedSurfaceIsDistinguishable(t *testing.T) {
	r := newProofResult(nil)
	r.recordUnarmedSurface(UnarmedSurface{
		Name:   "ge-0-0-9",
		Reason: "interface not found in zone trust: no such device",
	})

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	if len(rep.Surfaces) != 1 {
		t.Fatalf("a surface the compiler declined must appear in the report; got %+v", rep)
	}
	if rep.Skipped != 1 || rep.Surfaces[0].Kind != CoverageSkipped {
		t.Fatalf("a declined surface must be its own branch, not folded into covered or uncovered; got %+v", rep)
	}
	if rep.WouldGate {
		t.Fatal("a netdev that does not exist forwards nothing — declining it is not a blackholed zone member")
	}
	if got := rep.SurfaceSummary(); !strings.Contains(got, "ge-0-0-9:skipped") {
		t.Fatalf("the summary must name the declined surface; got %q", got)
	}
}

// TestArmProofDisabledSurfaceClassification pins the judgement the compiler
// site cannot express in a unit test: WHEN a disabled interface is proven down.
//
// `set interfaces ge-0-0-1 disable` whose netlink.LinkSetDown fails is a
// slog.Warn and nothing else — the netdev stays UP, address reconciliation
// still runs (that call sits outside the disable guard), it is still in a zone,
// the kernel still forwards through it, and no XDP is attached. The link never
// resolving is the same condition by a different route: LinkSetDown was never
// even attempted. Only a clean resolve AND a clean down prove the netdev is
// down.
func TestArmProofDisabledSurfaceClassification(t *testing.T) {
	linkErr := errors.New("no such device")
	downErr := errors.New("device or resource busy")

	for _, tc := range []struct {
		name             string
		linkErr, downErr error
		wantForwarding   bool
	}{
		{"clean disable", nil, nil, false},
		{"link-down failed", nil, downErr, true},
		{"link never resolved", linkErr, nil, true},
		{"both failed", linkErr, downErr, true},
	} {
		got := disabledSurfaceRecord("ge-0-0-1", 12, tc.linkErr, tc.downErr)
		if got.StillForwarding != tc.wantForwarding {
			t.Fatalf("%s: StillForwarding=%v, want %v — this is the whole difference between "+
				"a benign operator action and an UP, zoned, XDP-less netdev the kernel forwards "+
				"through; detail=%q", tc.name, got.StillForwarding, tc.wantForwarding, got.Reason)
		}
		if got.Name != "ge-0-0-1" || got.Ifindex != 12 {
			t.Fatalf("%s: record lost its identity: %+v", tc.name, got)
		}
		// End to end: the classification must reach the report's verdict.
		r := newProofResult(nil)
		r.recordUnarmedSurface(got)
		rep := classifyArmCoverage(r, lookupFrom(nil, nil))
		if rep.WouldGate != tc.wantForwarding {
			t.Fatalf("%s: WouldGate=%v, want %v; got %+v",
				tc.name, rep.WouldGate, tc.wantForwarding, rep)
		}
	}
}

// TestArmProofMissingInterfaceClassification pins that "not found" is not
// assumed from an error the code never inspected.
//
// net.InterfaceByName reports a genuine absence and a netlink DUMP failure
// (ENOBUFS / ENOMEM / EINTR) through the same *net.OpError. Only the first
// proves nothing forwards through the netdev; a dump failure says nothing at
// all about whether it exists, and treating it as absence is a fail-OPEN
// classification on an interface that may be live and UP.
func TestArmProofMissingInterfaceClassification(t *testing.T) {
	absent := &net.OpError{Op: "route", Net: "ip+net", Err: errors.New("no such network interface")}
	if got := missingInterfaceRecord("ge-0-0-9", 0, "trust", absent); got.StillForwarding {
		t.Fatalf("a proven absence must not read as still-forwarding; got %+v", got)
	}

	dumpFailed := &net.OpError{Op: "route", Net: "ip+net", Err: os.NewSyscallError("recvmsg", syscall.ENOBUFS)}
	got := missingInterfaceRecord("ge-0-0-9", 0, "trust", dumpFailed)
	if !got.StillForwarding {
		t.Fatalf("a netdev ENUMERATION failure does not prove the interface is absent — it may "+
			"be live, UP and in a zone; got %+v", got)
	}
	r := newProofResult(nil)
	r.recordUnarmedSurface(got)
	if rep := classifyArmCoverage(r, lookupFrom(nil, nil)); !rep.WouldGate {
		t.Fatalf("an unproven absence must reach the verdict as would-gate; got %+v", rep)
	}
}

// TestArmProofXDPModeClassification pins every kernel attach mode, including
// the two a test cannot produce.
//
// XDP_ATTACHED_MULTI is reachable: attachUserspaceShimXDP DISCARDS
// m.DetachXDP's error on the native fallback path, so a failed detach followed
// by the generic re-attach leaves programs in two modes. Reading it as native
// undercounts the skb-mode population — the same direction as the defect that
// moved this flag to the kernel in the first place.
func TestArmProofXDPModeClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		attached bool
		mode     uint32
		want     bool
	}{
		{"not attached", false, xdpAttachedNone, false},
		{"driver/native", true, xdpAttachedDrv, false},
		{"generic/skb", true, xdpAttachedSKB, true},
		{"hardware offload", true, xdpAttachedHW, false},
		{"multi-mode", true, xdpAttachedMulti, true},
		{"mode set but not attached", false, xdpAttachedSKB, false},
	} {
		if got := xdpModeIsGeneric(tc.attached, tc.mode); got != tc.want {
			t.Fatalf("%s: xdpModeIsGeneric(%v, %d)=%v, want %v",
				tc.name, tc.attached, tc.mode, got, tc.want)
		}
	}
}

// TestArmProofLiveProbesReadRealState exercises the production probe bodies,
// which every other test in this file replaces.
//
// Loopback is ifindex 1 in every Linux network namespace and carries no XDP, so
// the "attached=false means not generic" leg runs against the real kernel; a
// bogus ifindex exercises the error leg. Without this the six-line netlink body
// and the nil-link guard are unbound.
func TestArmProofLiveProbesReadRealState(t *testing.T) {
	if xdpLinkModeGeneric(1) {
		t.Fatal("loopback carries no XDP program; the probe must not report skb-mode for it")
	}
	if xdpLinkModeGeneric(0x7ffffff) {
		t.Fatal("an unresolvable ifindex must not report skb-mode")
	}
	if id, ok := xdpLinkProgramID(nil); ok || id != 0 {
		t.Fatalf("a nil tracked link is not proof of coverage; got id=%d ok=%v", id, ok)
	}
}

// TestArmProofApplyGenerationAdvances pins that the stage label's sequence
// actually moves. A constant would collapse the RETH deferred-MAC path's two
// records onto one label, which is the thing the label exists to prevent.
func TestArmProofApplyGenerationAdvances(t *testing.T) {
	m := New()
	first := m.nextApplyGeneration()
	if first == 0 {
		t.Fatal("the first compile's sequence must not be zero — a constant 0 is indistinguishable " +
			"from a stubbed accessor")
	}
	if again := m.nextApplyGeneration(); again != first {
		t.Fatalf("nextApplyGeneration must not itself advance the counter; got %d then %d", first, again)
	}
	m.recordApplyResult(&ApplyResult{})
	if next := m.nextApplyGeneration(); next != first+1 {
		t.Fatalf("the sequence must advance once per recorded apply; got %d, want %d", next, first+1)
	}
}

// TestArmProofUnarmedSurfacesAreDeduplicated pins that one surface counts once.
//
// mapZoneInterface runs once per ZONE REFERENCE and the per-phys dedup sits far
// below the soft skips, so an interface named by two zones reaches the skip
// twice. The count is this phase's deliverable, so a double count is a wrong
// number. A repeat sighting must never DOWNGRADE the classification.
func TestArmProofUnarmedSurfacesAreDeduplicated(t *testing.T) {
	r := newProofResult(nil)
	r.recordUnarmedSurface(UnarmedSurface{Name: "ge-0-0-9", Reason: "not found in zone trust"})
	r.recordUnarmedSurface(UnarmedSurface{Name: "ge-0-0-9", Reason: "not found in zone dmz"})

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))
	if rep.Skipped != 1 || len(rep.Surfaces) != 1 {
		t.Fatalf("one missing interface named by two zones is ONE unarmed surface; got %+v", rep)
	}

	// A later, more conservative sighting must win.
	r.recordUnarmedSurface(UnarmedSurface{Name: "ge-0-0-9", Reason: "enumeration failed", StillForwarding: true})
	rep = classifyArmCoverage(r, lookupFrom(nil, nil))
	if rep.Uncovered != 1 || rep.Skipped != 0 || !rep.WouldGate {
		t.Fatalf("a repeat sighting must never downgrade a surface to benign; got %+v", rep)
	}
}

// armProofZoneDP is a netlink-free DataPlane stub for driving programZoneMaps
// over interfaces that do not resolve. It embeds the interface (nil) and
// overrides only SetZoneConfig; mapZoneInterface returns at the missing-netdev
// skip long before any other method, so a call to one is an intended nil-panic
// tripwire saying the fixture stopped exercising the path it claims to.
type armProofZoneDP struct{ DataPlane }

func (armProofZoneDP) SetZoneConfig(uint16, ZoneConfig) error { return nil }

// requireAbsentInterface asserts the fixture's premise: the netdev must NOT
// exist on this host, because the whole path under test starts at
// cachedInterfaceByName FAILING. A t.Skip here would turn a mutation cell into
// an unknown, so this is a hard failure.
func requireAbsentInterface(t *testing.T, name string) {
	t.Helper()
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("%s exists on this host — this fixture requires the interface lookup to FAIL", name)
	}
}

// zoneCfgForAbsentPhys builds the smallest config that reaches the
// missing-interface skip: one physical interface (which will not resolve)
// carrying the given VLAN units, named by the given zones through the given
// refs. Unit 0 always exists so a plain "<phys>.0" reference is legal.
func zoneCfgForAbsentPhys(phys string, vlans []int, zones map[string][]string) *config.Config {
	units := map[int]*config.InterfaceUnit{0: {Number: 0}}
	for _, v := range vlans {
		units[v] = &config.InterfaceUnit{Number: v, VlanID: v}
	}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				phys: {Name: phys, VlanTagging: len(vlans) > 0, Units: units},
			},
		},
	}
	cfg.Security.Zones = make(map[string]*config.ZoneConfig, len(zones))
	for name, refs := range zones {
		cfg.Security.Zones[name] = &config.ZoneConfig{Interfaces: refs}
	}
	return cfg
}

// unarmedFromZoneMaps drives the REAL programZoneMaps -> mapZoneInterface path
// and returns the surfaces it declined to arm, sorted by name so a count
// mismatch reads clearly.
func unarmedFromZoneMaps(t *testing.T, cfg *config.Config) []string {
	t.Helper()
	result := &CompileResult{
		ZoneIDs:             make(map[string]uint16),
		ScreenIDs:           make(map[string]uint16),
		ifCache:             make(map[string]*net.Interface),
		rxTagStripOffCache:  make(map[string]bool),
		ethtoolApplied:      make(map[string]bool),
		genericXDPIfindexes: make(map[int]bool),
	}
	for name := range cfg.Security.Zones {
		result.ZoneIDs[name] = config.StableZoneID(name)
	}
	if _, err := programZoneMaps(armProofZoneDP{}, cfg, result); err != nil {
		t.Fatalf("programZoneMaps: %v", err)
	}
	names := make([]string, 0, len(result.unarmedSurfaces))
	for _, u := range result.unarmedSurfaces {
		names = append(names, u.Name)
	}
	sort.Strings(names)
	return names
}

// TestArmProofAbsentParentRecordsEachVlanChildSeparately binds the CALL SITE in
// mapZoneInterface, which is where the surface identity is chosen — the record
// helper alone cannot be wrong about it.
//
// mapZoneInterface resolves "<phys>.<vid>" to its PARENT before the netdev
// lookup, so a missing parent delivers only the parent's name to the record.
// recordUnarmedSurface dedups on exactly (Name, Ifindex), and every child of an
// absent parent has Ifindex 0, so filing them under the parent folds ALL of
// them — and the parent's own reference — into ONE record. When the parent
// resolves, the proof counts the parent and each VLAN child separately: the
// same configured topology would report a different number of surfaces
// depending on a condition unrelated to how many surfaces exist, always in the
// UNDER direction. An under-count hides a live forwarding surface, which is
// what #5275 exists to see.
func TestArmProofAbsentParentRecordsEachVlanChildSeparately(t *testing.T) {
	const phys = "ge-9-0-9"
	requireAbsentInterface(t, phys)

	got := unarmedFromZoneMaps(t, zoneCfgForAbsentPhys(phys, []int{50, 80}, map[string][]string{
		"wan": {phys + ".50", phys + ".80"},
	}))

	want := []string{phys + ".50", phys + ".80"}
	if len(got) != len(want) {
		t.Fatalf("two configured VLAN children of one absent parent produced %d unarmed record(s) %v, "+
			"want %d %v — the record was filed under the resolved PARENT name, so the "+
			"(Name, Ifindex) dedup collapsed both children onto one key; the surface count is "+
			"this phase's deliverable and it now depends on whether the parent happened to resolve",
			len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unarmed surfaces %v must name the CONFIGURED children %v — the parent belongs "+
				"in the reason, not in the identity", got, want)
		}
	}
}

// TestArmProofOneSurfaceNamedByTwoZonesStaysOneRecord is the over-reach guard
// for the test above: giving the record the child's identity must not defeat
// the dedup that is there on purpose.
//
// mapZoneInterface runs once per ZONE REFERENCE and the per-phys dedup sits far
// below the soft skips, so one interface named by two zones legitimately
// reaches the skip twice and must still count once. Both legs hold before and
// after the identity fix — the guard's job is to stay green while the test
// above goes red.
func TestArmProofOneSurfaceNamedByTwoZonesStaysOneRecord(t *testing.T) {
	const phys = "ge-9-0-8"
	requireAbsentInterface(t, phys)

	// The same VLAN child named by two zones.
	if got := unarmedFromZoneMaps(t, zoneCfgForAbsentPhys(phys, []int{50}, map[string][]string{
		"wan": {phys + ".50"},
		"dmz": {phys + ".50"},
	})); len(got) != 1 {
		t.Fatalf("one VLAN child named by two zones is ONE unarmed surface; got %d %v", len(got), got)
	}

	// The same physical unit-0 reference named by two zones. This leg also
	// pins that a non-VLAN surface keeps the bare interface name.
	got := unarmedFromZoneMaps(t, zoneCfgForAbsentPhys(phys, nil, map[string][]string{
		"wan": {phys + ".0"},
		"dmz": {phys + ".0"},
	}))
	if len(got) != 1 || got[0] != phys {
		t.Fatalf("one physical interface named by two zones is ONE unarmed surface named %q; got %v",
			phys, got)
	}
}

// TestArmProofReportsTheReadbackInstanceWithoutVerifyingIt pins the SCOPE of
// the program-instance half of the proof. It is a RESIDUAL RECORD, not a
// guard: it asserts what the proof does NOT check, so the documents and the
// code cannot drift apart silently in either direction.
//
// xdpLinkProgramID accepts any readable program id. It never compares it
// against m.programs[m.XDPEntryProgram()] — the program AttachXDP installs —
// and never checks Info.XDP().Ifindex. A `direct` verdict therefore means "an
// instance exists here and this is its id", not "the shim covers this
// surface". That is sound today only by an invariant held in OTHER functions
// (every writer of m.xdpLinks installs the entry program; nothing outside the
// package can reach a tracked link), which is exactly why a gating build
// cannot inherit it.
//
// The gating PR MUST add the comparison, at which point this test goes red —
// deliberately. Replace it then, and update the residual paragraphs at
// xdpLinkProgramID, in pkg/dataplane/README.md and in plan §13/D1 in the same
// change.
func TestArmProofReportsTheReadbackInstanceWithoutVerifyingIt(t *testing.T) {
	const ifidx, readback = 11, 4242
	swapArmProbes(t,
		func(int) bool { return false },
		func(link.Link) (uint32, bool) { return readback, true },
	)

	m := New()
	m.loaded.Store(true) // #2114 A3: loaded is atomic.Bool
	m.SelectUserspaceXDPShimEntryProgram()
	// The Manager holds NO shim program to compare against — AttachXDP's own
	// source of truth is absent — and the surface still classifies covered.
	delete(m.programs, m.XDPEntryProgram())
	m.xdpLinks[ifidx] = nil

	rep := m.ProveArmCoverage(newProofResult([]int{ifidx}))
	if len(rep.Surfaces) != 1 {
		t.Fatalf("expected exactly the one required surface; got %+v", rep.Surfaces)
	}
	s := rep.Surfaces[0]
	if s.Kind != CoverageDirect || rep.WouldGate {
		t.Fatalf("this phase classifies from the readback ALONE; if that changed, the residual "+
			"paragraphs at xdpLinkProgramID / README / plan D1 are now stale: got kind=%s "+
			"would_gate=%v (%s)", s.Kind, rep.WouldGate, s.Detail)
	}
	if s.ProgramID != readback {
		t.Fatalf("the proof REPORTS the instance the readback returned; got %d, want %d",
			s.ProgramID, readback)
	}
}

// TestArmProofNilZoneSlotIsRecorded pins the FOURTH surface-dropping soft skip.
//
// programZoneMaps skips a nil zone value — reachable on the tolerant and
// HA-peer-sync config paths — and mapZoneInterface is the only writer of
// pendingXDP, so EVERY interface in that zone leaves the required set while the
// compile succeeds. Before this the proof logged skipped=0 uncovered=0
// would_gate=false for it, biasing the divergence rate optimistic on exactly
// the HA path.
func TestArmProofNilZoneSlotIsRecorded(t *testing.T) {
	r := newProofResult(nil)
	r.recordUnarmedSurface(UnarmedSurface{
		Name:   "zone:untrust",
		Reason: "nil zone slot — every interface in this zone was dropped",
	})

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))
	if rep.Skipped != 1 {
		t.Fatalf("a dropped zone must be visible in the report; got %+v", rep)
	}
	if got := rep.SurfaceSummary(); !strings.Contains(got, "zone:untrust:skipped") {
		t.Fatalf("the summary must name the dropped zone; got %q", got)
	}
}

// TestArmProofSkippedButStillForwardingIsUncovered pins the sharp variant.
//
// `set interfaces ge-0-0-1 disable` whose netlink.LinkSetDown then FAILS is a
// slog.Warn and nothing else: the netdev stays UP, address reconciliation still
// runs, it is still in a security zone, the kernel still forwards through it —
// and no XDP is attached, because the disabled branch skipped the attach. That
// is the blackholed zone member #5275 exists to surface, and it must not read as a
// benign operator action.
func TestArmProofSkippedButStillForwardingIsUncovered(t *testing.T) {
	r := newProofResult(nil)
	r.recordUnarmedSurface(UnarmedSurface{
		Name:            "ge-0-0-1",
		Ifindex:         12,
		Reason:          "administratively disabled but link-down FAILED",
		StillForwarding: true,
	})

	rep := classifyArmCoverage(r, lookupFrom(nil, nil))

	if rep.Uncovered != 1 || rep.Skipped != 0 {
		t.Fatalf("a skipped surface whose netdev is still UP and forwarding must read as UNCOVERED, "+
			"not as a benign decline; got %+v", rep)
	}
	if !rep.WouldGate {
		t.Fatal("an UP, zoned netdev carrying no XDP is exactly the blackholed zone member " +
			"#5275 is about — it must be reported as WOULD-GATE")
	}
}

// TestArmProofEmptySurfaceSetGatesNothingButStillReports keeps the two things
// the original empty-set test protected — a box with nothing to arm is not an
// unarmed box, and nil inputs are inert — and adds the distinction the original
// shape implied away: a proof that RAN and enumerated nothing must not read the
// same as a proof that never ran.
func TestArmProofEmptySurfaceSetGatesNothingButStillReports(t *testing.T) {
	rep := classifyArmCoverage(newProofResult(nil), lookupFrom(nil, nil))
	if len(rep.Surfaces) != 0 || rep.WouldGate {
		t.Fatalf("an empty surface set must not report a gate; got %+v", rep)
	}
	if !rep.Ran {
		t.Fatal("a proof that executed against a real compile result must report ran=true, " +
			"or 'nothing to arm' is indistinguishable from 'the proof never ran'")
	}
	// nil result / nil lookup must be inert too — the proof runs on paths where
	// the dataplane may not exist — but they are a DIFFERENT unknown.
	for _, tc := range []struct {
		name string
		rep  ArmCoverageReport
	}{
		{"nil compile result", classifyArmCoverage(nil, lookupFrom(nil, nil))},
		{"nil lookup", classifyArmCoverage(newProofResult([]int{1}), nil)},
	} {
		if tc.rep.WouldGate {
			t.Fatalf("%s must not report a gate", tc.name)
		}
		if tc.rep.Ran {
			t.Fatalf("%s did not run the proof; it must not report ran=true", tc.name)
		}
	}
}

// TestArmProofLogsEvenWhenItEnumeratedNothing pins that the record exists.
//
// This file argues at DidGate that "an absence is indistinguishable from a
// proof that never ran". Suppressing the line on an empty surface set commits
// exactly that error: a box with nothing to arm, a build with the proof removed
// and a daemon that crashed before the proof all produce the same silence.
func TestArmProofLogsEvenWhenItEnumeratedNothing(t *testing.T) {
	buf := captureLogs(t)

	classifyArmCoverage(newProofResult(nil), lookupFrom(nil, nil)).LogArmCoverage("post-attach", 3)

	out := buf.String()
	if !strings.Contains(out, "arm-coverage proof") {
		t.Fatalf("a proof that enumerated nothing emitted NO line — indistinguishable from a "+
			"proof that never ran, which is the failure this file's DidGate rationale rejects; got %q", out)
	}
	if !strings.Contains(out, "ran=true") {
		t.Fatalf("the line must say the proof ran; got %q", out)
	}

	buf.Reset()
	classifyArmCoverage(nil, nil).LogArmCoverage("post-attach", 4)
	if out := buf.String(); !strings.Contains(out, "ran=false") {
		t.Fatalf("a proof that did NOT run must say so on its own line; got %q", out)
	}
}

// TestArmProofStageLabelIsDistinctPerCompile pins that two proofs from ONE
// daemon apply are distinguishable.
//
// daemon_apply_dataplane.go issues a second ApplyConfig in the same apply on the
// RETH deferred-MAC path (reapplyAfterDeferredMAC), so this fires twice with the
// same stage word. Two records carrying an identical label cannot be told apart
// in a log archive — and it is the SECOND that reflects the final state.
func TestArmProofStageLabelIsDistinctPerCompile(t *testing.T) {
	buf := captureLogs(t)
	// A NON-empty report deliberately, so this cell isolates the stage label
	// and does not also move when the empty-report suppression changes.
	rep := classifyArmCoverage(newProofResult([]int{10}), lookupFrom(map[int]uint32{10: 1}, nil))

	rep.LogArmCoverage("post-attach", 1)
	rep.LogArmCoverage("post-attach", 2)

	out := buf.String()
	if strings.Count(out, "stage=post-attach#1") != 1 || strings.Count(out, "stage=post-attach#2") != 1 {
		t.Fatalf("two compiles in one apply must carry DISTINCT stage labels; got %q", out)
	}
}

// TestArmProofReportsBranchPerSurface pins that the record carries the branch
// for EVERY surface, not only the failing ones. The whole point of the
// observe-only phase is measuring the direct/delegated/uncovered mix across
// real deployments; a pass/fail summary cannot answer that, and a report that
// only names failures cannot distinguish a fleet of native boxes from a fleet
// of VLAN boxes.
//
// The delegated token carries the delegate's attach MODE for the same reason: a
// VLAN child behind an skb-mode parent is on the slow path, and without the
// mode it is indistinguishable from one behind a native parent.
func TestArmProofReportsBranchPerSurface(t *testing.T) {
	r := newProofResult([]int{10, 20, 30, 40})
	vlanChild(r, 20, 10) // delegated to 10
	// 40 is attached to nothing at all.
	rep := classifyArmCoverage(r, lookupFrom(
		map[int]uint32{10: 1, 30: 3}, map[int]bool{30: true}))

	got := rep.SurfaceSummary()
	for _, want := range []string{
		"10:direct/native",
		"20:delegated/via-10/native",
		"30:direct/generic",
		"40:uncovered",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("per-surface summary missing %q; got %q", want, got)
		}
	}
}

// TestArmProofDelegatedSummaryCarriesTheDelegateMode is the sibling of the
// above: a child behind a GENERIC parent must render generic, or the skb-mode
// population is undercounted by exactly the VLAN deployments — which is every
// deployment this project ships.
func TestArmProofDelegatedSummaryCarriesTheDelegateMode(t *testing.T) {
	r := newProofResult([]int{10, 20})
	vlanChild(r, 20, 10)

	rep := classifyArmCoverage(r, lookupFrom(map[int]uint32{10: 1}, map[int]bool{10: true}))

	if got := rep.SurfaceSummary(); !strings.Contains(got, "20:delegated/via-10/generic") {
		t.Fatalf("a VLAN child behind an skb-mode parent must render generic; got %q", got)
	}
}

// TestArmProofDidGateIsDistinctFromWouldGate pins that the two are separate
// fields. Reporting only would_gate makes "the proof said refuse" and "the
// proof refused" indistinguishable in a log archive — and an absent
// enforcement line is also indistinguishable from a proof that never ran.
func TestArmProofDidGateIsDistinctFromWouldGate(t *testing.T) {
	// A box the gating build would refuse.
	rep := classifyArmCoverage(newProofResult([]int{10}), lookupFrom(nil, nil))
	if !rep.WouldGate {
		t.Fatal("precondition: an unattached surface must be would-gate")
	}
	if rep.DidGate {
		t.Fatal("OBSERVE-ONLY VIOLATION: the proof reported that it actually withheld " +
			"something — this phase must never gate")
	}
}

// --- source canaries -------------------------------------------------------
//
// CompileUserspaceShim cannot be driven from a unit test: its first act is
// reading /sys/fs/bpf/xpf/links, which is root-only. The wiring is therefore
// bound structurally. Without these, deleting the production call site or a
// recording site leaves the whole suite green, because every behavioural test
// above drives the classifier directly.

func parseDataplaneFile(t *testing.T, name string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return fset, f
}

func findFuncDecl(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name && fn.Body != nil {
			return fn
		}
	}
	t.Fatalf("func %s not found", name)
	return nil
}

func selectorName(e ast.Expr) string {
	if sel, ok := e.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

// identName returns the name when e is a bare identifier.
func identName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// stmtCallsFunc reports whether stmt contains a call to a method named name.
func stmtCallsFunc(stmt ast.Stmt, name string) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && selectorName(call.Fun) == name {
			found = true
		}
		return !found
	})
	return found
}

// stmtListRecords reports whether a statement list directly calls
// recordUnarmedSurface.
func stmtListRecords(list []ast.Stmt) bool {
	for _, stmt := range list {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		if call, ok := expr.X.(*ast.CallExpr); ok && selectorName(call.Fun) == "recordUnarmedSurface" {
			return true
		}
	}
	return false
}

// stmtBody returns the statement list a node carries, if it carries one.
//
// A *ast.BlockStmt is the obvious carrier, and matching only that is what the
// previous version of this walk did — but ast.CaseClause.Body and
// ast.CommClause.Body are BARE []ast.Stmt with no enclosing block node. So a
// `return nil` or `continue` written inside a `switch { case ...: }` or a
// `select { case ...: }` arm was invisible to the canary while the
// byte-identical statement written under a plain `if` was caught. That gap was
// demonstrated, not theorised: a real early `return nil` inserted into a switch
// case in mapZoneInterface left `go vet` and the whole ArmProof suite green.
func stmtBody(n ast.Node) ([]ast.Stmt, bool) {
	switch b := n.(type) {
	case *ast.BlockStmt:
		return b.List, true
	case *ast.CaseClause:
		return b.Body, true
	case *ast.CommClause:
		return b.Body, true
	}
	return nil, false
}

// isReturnNil reports whether stmt is `return nil`.
func isReturnNil(stmt ast.Stmt) bool {
	ret, ok := stmt.(*ast.ReturnStmt)
	return ok && len(ret.Results) == 1 && identName(ret.Results[0]) == "nil"
}

// TestArmProofIsInvokedFromCompileUserspaceShim binds the production call site.
//
// A shape check is only worth the shapes it REJECTS. Each assertion below
// corresponds to an edit that leaves the call textually present while making
// the measurement permanently dead, and every one of them passed the first
// version of this test: wrapping the statement in a dead branch; calling it on
// a nil *Manager (the m == nil guard then reports ran=false forever); handing
// it a fresh &CompileResult{} (uncovered=0 on every box forever); and moving it
// ABOVE attachUserspaceShimXDP, which makes every surface uncovered and
// contradicts the comment at the call site that states the ordering as the
// reason the proof means anything.
func TestArmProofIsInvokedFromCompileUserspaceShim(t *testing.T) {
	_, file := parseDataplaneFile(t, "loader.go")
	fn := findFuncDecl(t, file, "CompileUserspaceShim")

	proofIdx, attachIdx := -1, -1
	var proof *ast.CallExpr
	for i, stmt := range fn.Body.List {
		if attachIdx < 0 && stmtCallsFunc(stmt, "attachUserspaceShimXDP") {
			attachIdx = i
		}
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok || selectorName(call.Fun) != "LogArmCoverage" {
			continue
		}
		proofIdx, proof = i, call
	}

	if proofIdx < 0 {
		t.Fatal("CompileUserspaceShim has no TOP-LEVEL ProveArmCoverage(...).LogArmCoverage(...) " +
			"statement — the #5275 measurement is either unwired or buried in a branch, and every " +
			"other test in this file drives the classifier directly so nothing else notices")
	}
	if attachIdx < 0 {
		t.Fatal("CompileUserspaceShim no longer calls attachUserspaceShimXDP — this canary's " +
			"ordering assertion has nothing to anchor to")
	}
	if proofIdx < attachIdx {
		t.Fatalf("the proof runs BEFORE attachUserspaceShimXDP (stmt %d vs %d) — it would report "+
			"every surface uncovered, which is the opposite of the ordering the call site's own "+
			"comment gives as the reason the proof is meaningful", proofIdx, attachIdx)
	}

	recv, ok := proof.Fun.(*ast.SelectorExpr)
	if !ok {
		t.Fatal("LogArmCoverage is not called as a method")
	}
	inner, ok := recv.X.(*ast.CallExpr)
	if !ok || selectorName(inner.Fun) != "ProveArmCoverage" {
		t.Fatal("LogArmCoverage's receiver is not a live ProveArmCoverage call — a stashed or " +
			"hand-built report measures nothing")
	}
	innerSel, ok := inner.Fun.(*ast.SelectorExpr)
	if !ok || identName(innerSel.X) != "m" {
		t.Fatalf("ProveArmCoverage is not called on the live Manager `m` — a nil receiver makes "+
			"the m == nil guard report ran=false forever; got %q", identName(innerSel.X))
	}
	if len(inner.Args) != 1 || identName(inner.Args[0]) != "result" {
		t.Fatal("ProveArmCoverage is not passed the compile's own `result` — a fresh CompileResult " +
			"has no pendingXDP, so the proof reports uncovered=0 on every box forever")
	}
	if len(proof.Args) != 2 {
		t.Fatalf("LogArmCoverage takes a stage and a sequence; got %d args", len(proof.Args))
	}
	if _, isCall := proof.Args[1].(*ast.CallExpr); !isCall {
		t.Fatal("the arm-coverage sequence argument is not a live call — the RETH deferred-MAC " +
			"path compiles twice per apply, and a constant makes the two records indistinguishable")
	}
}

// TestArmProofEverySurfaceDroppingBranchRecords enumerates the compiler's
// surface-dropping branches STRUCTURALLY.
//
// The first version of this test matched three hand-written log messages, so it
// could only ever check spellings already guessed: a fourth soft skip carrying a
// new message passed it unnoticed, and there WAS a fourth (the nil zone slot in
// programZoneMaps). Control flow is what actually drops a surface, so control
// flow is what is enumerated.
//
// mapZoneInterface is the SOLE writer of st.xdpIfindexes, which becomes
// result.pendingXDP, so every early `return nil` in it drops a configured attach
// point while the compile SUCCEEDS. programZoneMaps sits one frame up and its
// `continue` drops every interface in a whole zone.
//
// "Control flow" means every statement list a branch can live in, not just
// *ast.BlockStmt — see stmtBody. Matching blocks alone let a `return nil` in a
// switch case escape the enumeration entirely.
func TestArmProofEverySurfaceDroppingBranchRecords(t *testing.T) {
	_, file := parseDataplaneFile(t, "compiler_iface.go")

	// mapZoneInterface: every early `return nil` must record.
	fn := findFuncDecl(t, file, "mapZoneInterface")
	final := fn.Body.List[len(fn.Body.List)-1]
	dropping := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		body, ok := stmtBody(n)
		if !ok {
			return true
		}
		for _, stmt := range body {
			if stmt == final || !isReturnNil(stmt) {
				continue
			}
			dropping++
			if !stmtListRecords(body) {
				t.Errorf("mapZoneInterface has an early `return nil` at line %d that records no "+
					"unarmed surface — the compile succeeds, the surface vanishes from pendingXDP, "+
					"and the proof reports Uncovered=0 for an attach point it never looked at",
					stmt.Pos())
			}
		}
		return true
	})
	// Vacuity guard, not a correctness claim: if a refactor moves the soft
	// skips out of this function the walk above silently checks nothing.
	if dropping < 2 {
		t.Fatalf("found only %d early `return nil` in mapZoneInterface — this canary has gone "+
			"vacuous; re-point it at wherever the soft skips now live", dropping)
	}

	// programZoneMaps: every `continue` drops a whole zone's interfaces.
	zoneFn := findFuncDecl(t, file, "programZoneMaps")
	continues := 0
	ast.Inspect(zoneFn.Body, func(n ast.Node) bool {
		body, ok := stmtBody(n)
		if !ok {
			return true
		}
		for _, stmt := range body {
			br, ok := stmt.(*ast.BranchStmt)
			if !ok || br.Tok != token.CONTINUE {
				continue
			}
			continues++
			if !stmtListRecords(body) {
				t.Errorf("programZoneMaps skips a zone at line %d without recording it — "+
					"mapZoneInterface is the only writer of pendingXDP, so EVERY interface in "+
					"that zone is dropped from the required set while the compile succeeds",
					stmt.Pos())
			}
		}
		return true
	})
	if continues < 1 {
		t.Fatal("found no `continue` in programZoneMaps — this canary has gone vacuous")
	}
}

// TestArmProofDisabledSiteThreadsBothErrors binds the WIRE for StillForwarding.
//
// disabledSurfaceRecord's classification is bound behaviourally below, but the
// compiler half — that the real link and link-down errors reach it — is not
// reachable from any unit test: producing the condition needs a live netdev
// whose LinkSetDown fails. Passing nil for either argument makes every disabled
// interface read as a benign, proven-down operator action forever, and the
// whole-suite result is unchanged. That is the exact edit this asserts against.
func TestArmProofDisabledSiteThreadsBothErrors(t *testing.T) {
	_, file := parseDataplaneFile(t, "compiler_iface.go")
	fn := findFuncDecl(t, file, "mapZoneInterface")

	var calls []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && identName(call.Fun) == "disabledSurfaceRecord" {
			calls = append(calls, call)
		}
		return true
	})

	if len(calls) != 1 {
		t.Fatalf("expected exactly one disabledSurfaceRecord call in mapZoneInterface; got %d — "+
			"the administratively-disabled skip is the sharp one and must classify in one place",
			len(calls))
	}
	call := calls[0]
	if len(call.Args) != 4 {
		t.Fatalf("disabledSurfaceRecord takes name, ifindex, linkErr, downErr; got %d args", len(call.Args))
	}
	for i, what := range map[int]string{2: "the link-resolution error", 3: "LinkSetDown's error"} {
		name := identName(call.Args[i])
		if name == "" || name == "nil" {
			t.Fatalf("%s is not threaded into disabledSurfaceRecord (arg %d is %q) — every "+
				"administratively disabled interface would then read as proven-down and benign, "+
				"including one whose netdev is still UP, zoned and carrying "+
				"no XDP, which is the blackholed zone member this PR exists to measure", what, i, name)
		}
	}
}
