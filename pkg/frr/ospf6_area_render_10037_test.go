package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10037: OSPFv3 area activation must render the FRR 10.6 INTERFACE_NODE form
// `ipv6 ospf6 area <id>` inside per-interface `interface <name>` blocks. The
// old ` interface <name> area <id>` line under `router ospf6` was DEFUN_HIDDEN
// in FRR 9.1 and is ABSENT at frr-10.6.0 (stable/10.6 head 2ab78e9), so it is
// dead config on the deployed line: OSPFv3 areas never activate. Grammar
// pinned against FRR stable-10.6 docs, "OSPF6 interface":
// `ipv6 ospf6 area <A.B.C.D|(0-4294967295)>` — "Enable OSPFv3 on the interface
// and add it to the specified area" — whose `router ospf6` section lists no
// `interface ... area` command.
//
// The render mirrors the OSPFv2 #1712 shape: the `interface <name>` block is
// emitted UNCONDITIONALLY for every configured interface (area activation is
// the block's reason to exist), with the area line gated by the #9820 belt.
// No version gate: the tree targets the single deployed FRR line (stable/10.6;
// every grammar transcription in pkg/frr pins it), so the removed command has
// no live target left to gate for.
//
// FAIL-ON-REVERT: restoring the router-level ` interface <name> area` line
// (or dropping the interface-level area line) turns the two valid-area
// activation cells RED; re-gating interface blocks on optional settings also
// turns the primary valid-area cell RED because area-only dmz0 disappears.
// The invalid-ID and OSPFv2 cells are green-on-both-sides preservation pins
// for the #9820 belt and unchanged OSPFv2 output.

// ospf6Stanza10037 extracts the `router ospf6` stanza (up to its closing
// "exit") so cells can assert the dead router-level form is gone without
// tripping over interface blocks elsewhere in the output.
func ospf6Stanza10037(t *testing.T, got string) string {
	t.Helper()
	start := strings.Index(got, "router ospf6")
	if start < 0 {
		t.Fatalf("expected a router ospf6 block, got:\n%s", got)
	}
	rest := got[start:]
	end := strings.Index(rest, "exit\n")
	if end < 0 {
		t.Fatalf("unterminated router ospf6 block, got:\n%s", got)
	}
	return rest[:end]
}

func TestOSPFv3AreaRendersInterfaceNodeForm_10037(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFv3Area{{
			ID: "0.0.0.0",
			Interfaces: []*config.OSPFv3Interface{
				{Name: "trust0", Passive: true, Cost: 10},
				{Name: "dmz0"},
			},
		}},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil, nil)

	// The removed router-level form must be gone entirely.
	if stanza := ospf6Stanza10037(t, got); strings.Contains(stanza, "interface ") {
		t.Errorf("router ospf6 stanza must not carry interface-area lines (removed before FRR 10.6), stanza:\n%s", stanza)
	}
	for _, dead := range []string{" interface trust0 area", " interface dmz0 area"} {
		if strings.Contains(got, dead) {
			t.Errorf("dead router-level form %q still rendered, got:\n%s", dead, got)
		}
	}

	// Every configured interface activates in-area via the 10.6 form. The
	// bare dmz0 interface is the crux: pre-fix it got NO interface block at
	// all (blocks were settings-gated), so its only activation was the dead
	// router-level line.
	for _, want := range []string{
		"interface trust0\n ipv6 ospf6 area 0.0.0.0\n ipv6 ospf6 passive\n ipv6 ospf6 cost 10\nexit\n",
		"interface dmz0\n ipv6 ospf6 area 0.0.0.0\nexit\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing 10.6 interface-node activation block %q, got:\n%s", want, got)
		}
	}
}

func TestOSPFv3TwoAreasOwnActivation_10037(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFv3Area{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{{Name: "trust0"}}},
			{ID: "0.0.0.1", Interfaces: []*config.OSPFv3Interface{{Name: "dmz0"}}},
		},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil, nil)

	// Each interface activates in its OWN area (the OSPFv2 #1712 shape).
	for _, want := range []string{
		"interface trust0\n ipv6 ospf6 area 0.0.0.0\nexit\n",
		"interface dmz0\n ipv6 ospf6 area 0.0.0.1\nexit\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("interface not activated in its own area, want %q, got:\n%s", want, got)
		}
	}

	// Exactly two activations (trust0, dmz0); an interface absent from every
	// area (here untrust0, never configured) is never activated.
	if n := strings.Count(got, "ipv6 ospf6 area "); n != 2 {
		t.Errorf("expected exactly 2 'ipv6 ospf6 area' activations, got %d:\n%s", n, got)
	}
	if strings.Contains(got, "untrust0") {
		t.Errorf("unconfigured interface must never be activated, got:\n%s", got)
	}
}

func TestOSPFv3InvalidAreaOmitsLineKeepsBlock_10037(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFv3Area{{
			ID:         "::ffff:192.0.2.1",
			Interfaces: []*config.OSPFv3Interface{{Name: "trust0", Cost: 10}},
		}},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil, nil)

	// The #9820 belt still refuses the unrenderable ID — no area line
	// anywhere — but the interface block (and its other settings) survives,
	// exactly like the OSPFv2 invalid-ID shape.
	if strings.Contains(got, "::ffff") {
		t.Errorf("invalid area id must be omitted, got:\n%s", got)
	}
	if strings.Contains(got, "ipv6 ospf6 area") {
		t.Errorf("no area line must render for an invalid area id, got:\n%s", got)
	}
	if !strings.Contains(got, "interface trust0\n ipv6 ospf6 cost 10\n") {
		t.Errorf("interface block with surviving settings missing, got:\n%s", got)
	}
}

// TestOSPFv2AreaRenderUnchanged_10037 is the control: OSPFv2 area rendering
// keeps its byte shape (`ip ospf area` activation, last line of the block)
// with no ospf6 leakage. Green on both sides of the fix.
func TestOSPFv2AreaRenderUnchanged_10037(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{
		RouterID: "1.1.1.1",
		Areas: []*config.OSPFArea{{
			ID: "0.0.0.1",
			Interfaces: []*config.OSPFInterface{
				{Name: "trust0", Cost: 10},
				{Name: "dmz0"},
			},
		}},
	}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)

	for _, want := range []string{
		"interface trust0\n ip ospf cost 10\n ip ospf area 0.0.0.1\nexit\n",
		"interface dmz0\n ip ospf area 0.0.0.1\nexit\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("OSPFv2 activation block changed, want %q, got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ospf6") {
		t.Errorf("OSPFv2-only render must not leak ospf6 lines, got:\n%s", got)
	}
}
