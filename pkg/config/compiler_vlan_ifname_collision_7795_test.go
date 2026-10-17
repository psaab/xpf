package config

import (
	"strings"
	"testing"
)

// #7795: an authored `<base>.<n>` and a unit that resolves to the same
// `<base>.<n>` are two config objects on ONE kernel device.
//
// Sibling of #6964 (the per-unit TUNNEL device) reached by a different
// derivation. The authored-name gate cannot see it: the two authored keys are
// `ge-0/0/0.100` and `ge-0/0/0`, which canonicalize differently.
//
// Every fixture here uses ParseSetCommand + tree.SetPath in a loop, never
// NewParser: the parser treats newlines as whitespace and merges all set lines
// into one node, so a NewParser fixture would not build the shape under test.

func compileSet7795(t *testing.T, lines ...string) error {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	_, err := CompileConfig(tree)
	return err
}

// FAIL-ON-REVERT: delete the third pass and this reds. It is the issue's own
// three-line repro.
func TestVlanIDSubInterfaceCollidesWithAuthoredName7795(t *testing.T) {
	err := compileSet7795(t,
		"set interfaces ge-0/0/0 unit 100 vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0.100 unit 0 family inet address 10.0.2.1/24",
	)
	if err == nil {
		t.Fatal("STRICT compile accepted a config where `ge-0/0/0 unit 100 vlan-id 100` " +
			"and the authored interface `ge-0/0/0.100` both resolve to ge-0-0-0.100. " +
			"pkg/routing keys addresses, VRF claim and zone by device name, so the two " +
			"reconcile one kernel device twice per commit with no stable winner (#7795)")
	}
	if !strings.Contains(err.Error(), "ge-0-0-0.100") {
		t.Errorf("error must name the colliding DEVICE so the operator can find it; got: %v", err)
	}
}

// The derivation the issue does NOT name, and the reason this pass calls
// ResolveKernelIfName rather than re-deriving base + "." + vlan-id.
//
// types.go resolves a non-zero unit with NO vlan-id to `base + "." + unit
// number`, which is the same shape. A gate written from the issue's text would
// have policed half the defect and reported nothing here.
//
// FAIL-ON-REVERT: replace the ResolveKernelIfName call with a local
// fmt.Sprintf("%s.%d", base, unit.VlanID) guarded on VlanID > 0 — the literal
// reading of the issue — and this cell reds while the vlan-id cell above stays
// green.
func TestUnitNumberSubInterfaceCollidesWithAuthoredName7795(t *testing.T) {
	err := compileSet7795(t,
		"set interfaces ge-0/0/0 unit 100 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0.100 unit 0 family inet address 10.0.2.1/24",
	)
	if err == nil {
		t.Fatal("STRICT compile accepted `ge-0/0/0 unit 100` (no vlan-id) alongside the " +
			"authored `ge-0/0/0.100`; both resolve to ge-0-0-0.100. The unit-number " +
			"derivation produces the same device-name shape as the vlan-id one (#7795)")
	}
}

// A unit carrying a TUNNEL must be adjudicated by pass 2 only, not reported
// twice by pass 3.
//
// The resolver returns unit.Tunnel.Name for such a unit, so pass 3 would
// compute the identical device name pass 2 already checked — and report one
// collision twice, with two different messages naming two different
// derivations for one device. This asserts the message an operator gets names
// the TUNNEL derivation, which is the one that produced the name.
//
// (The sub-interface-vs-tunnel cross-product itself is unreachable: a
// sub-interface device is `<base>.<digits>` and a tunnel device is
// `<base>u<digits>`, so the character before the trailing digit run is "." in
// one and "u" in the other and they can never be equal. That argument is
// recorded on the check in the gate rather than asserted by a cell, because a
// cell for an unreachable branch tests nothing — an earlier version of this
// file had one, and it passed by catching pass 2's authored-vs-tunnel error
// instead.)
//
// NO FAIL-ON-REVERT, stated rather than implied. Deleting the
// `unit.Tunnel != nil` skip from pass 3 does NOT red this cell, and I measured
// that rather than assuming it: pass 2 returns on any tunnel-device collision
// before pass 3 runs, and a tunnel device that collides with nothing produces
// no report from either pass. So the skip has no observable effect today and
// this cell cannot bind it.
//
// The skip stays because it makes the ownership explicit — pass 3 must not
// compute a name pass 2 owns — and because the ordering that makes it
// unobservable is pass 2's `return`, not a property of the derivations. If a
// future change collects collisions instead of returning on the first, the
// duplicate report appears immediately and the skip is what prevents it.
//
// What this cell DOES bind is that the operator gets the TUNNEL derivation in
// the message, so pass 3 has not preempted pass 2's clearer explanation.
func TestTunnelUnitIsNotReportedTwice7795(t *testing.T) {
	err := compileSet7795(t,
		"set interfaces gr-0/0/0 unit 1 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 1 tunnel destination 10.0.0.2",
		"set interfaces gr-0-0-0u1 unit 0 family inet address 10.0.3.1/24",
	)
	if err == nil {
		t.Fatal("an authored name colliding with a per-unit tunnel device must be " +
			"rejected; #6964's pass 2 owns this case")
	}
	if !strings.Contains(err.Error(), "per-unit tunnel") {
		t.Errorf("the collision must be reported with the TUNNEL derivation that "+
			"produced the name, not a sub-interface one; got: %v", err)
	}
}

// CONTROL: a config where the names genuinely do NOT collide must still
// compile. Without this, the cells above are satisfied by a pass that rejects
// every config carrying a vlan-id — which is the over-rejection this file's
// header says the gate must not commit, and it would break every real VLAN
// config in the tree.
func TestNonCollidingVlanSubInterfaceStillCompiles7795(t *testing.T) {
	// #14574 migration: the parents now carry `vlan-tagging`. Without it
	// this shape is the #14574 defect itself (vlan-id without tagging),
	// not a legitimate non-colliding VLAN config; the collision gate's
	// control must exercise the tagged form every real config uses.
	if err := compileSet7795(t,
		"set interfaces ge-0/0/0 vlan-tagging",
		"set interfaces ge-0/0/0 unit 100 vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/1 vlan-tagging",
		"set interfaces ge-0/0/1 unit 200 vlan-id 200",
		"set interfaces ge-0/0/1 unit 200 family inet address 10.0.2.1/24",
	); err != nil {
		t.Fatalf("two VLAN sub-interfaces on DIFFERENT bases do not collide and must "+
			"compile; rejecting them is the over-rejection this gate must not commit: %v", err)
	}
}

// CONTROL: the ordinary `unit 0` case must still compile. The resolver
// collapses a unit 0 with no vlan-id onto the base device by design, and the
// authored pass already owns that name — so reporting it would reject every
// plain interface in the tree.
func TestUnitZeroCollapseStillCompiles7795(t *testing.T) {
	if err := compileSet7795(t,
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	); err != nil {
		t.Fatalf("a plain `unit 0` shares the base device BY DESIGN and must compile; "+
			"this is the single most common shape in any config: %v", err)
	}
}

// CONTROL: a RETH must still compile. This is the SECOND by-design collapse and
// I did not find it by reading — the full `make test-go` did, via
// TestReconcilePassUsesOneDataplaneSnapshot in pkg/daemon.
//
// A reth's units resolve onto its PHYSICAL MEMBER's device (`reth1 unit 0`
// becomes ge-0-0-0), and that member is itself an authored interface, so the
// authored pass has legitimately already claimed the name. A pass comparing
// against the unresolved "reth1" reports a collision between an interface and
// its own member — rejecting every RETH config, which is every HA cluster in
// the tree.
//
// FAIL-ON-REVERT: change pass 3's base back to LinuxIfName(name) and this reds.
func TestRethUnitCollapseStillCompiles7795(t *testing.T) {
	if err := compileSet7795(t,
		// The member is a bare L2 port: a reth member configuring its own
		// unit 0 is rejected by a DIFFERENT strict gate, which would make this
		// cell fail for a reason that has nothing to do with #7795.
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
		"set chassis cluster reth-count 2",
		// Unrelated strict gate: a cluster without a PSK is rejected before
		// this one runs, which would make these cells pass or fail for the
		// wrong reason.
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
	); err != nil {
		t.Fatalf("a RETH unit resolves onto its physical member's device BY DESIGN and "+
			"must compile; rejecting it breaks every HA cluster config in the tree: %v", err)
	}
}

// A reth VLAN unit aliasing an authored dotted name must COMPILE.
//
// I had this cell backwards. It originally asserted the collision was
// REJECTED, and `make test-go` showed that #6722 had already decided the
// opposite: an authored dotted name that aliases a reth's VLAN unit is legal,
// and #6722 built the resolution for it — "the dotted name is a real, separate
// configured interface AND an alias of a reth unit ... Resolving the AUTHORED
// binding through the aliasing does" (egress_zone_identity_6722_test.go, case
// C). Rejecting it here would un-ship that decision.
//
// So the reth aliasing is out of scope for this gate. That is a correction to
// #7795's framing, which treats every shared `<base>.<n>` device as a defect.
//
// FAIL-ON-REVERT: remove the reth skip from pass 3 and this reds — along with
// three #6722 cells in pkg/dataplane/userspace, which is how the over-rejection
// was found in the first place.
func TestRethVlanAliasOfAuthoredNameStillCompiles7795(t *testing.T) {
	if err := compileSet7795(t,
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 50 vlan-id 50",
		"set interfaces reth0 unit 50 family inet address 172.16.50.8/24",
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
		"set interfaces ge-0/0/2 gigether-options redundant-parent reth0",
		"set interfaces ge-0/0/2.50 unit 0 family inet address 10.0.9.1/24",
	); err != nil {
		t.Fatalf("a reth unit's device is its MEMBER's device, and #6722 established "+
			"that an authored dotted name aliasing it is legal and resolvable; "+
			"rejecting it here un-ships that decision: %v", err)
	}
}
