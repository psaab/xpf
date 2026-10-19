package frr

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15185 (C04-03): the family-less `protocols bgp damping` knob rendered
// `bgp dampening ...` directly under `router bgp`. bgpd files a
// router-level dampening line under `address-family ipv4 unicast` only,
// so IPv6 unicast route-flap damping was silently never enabled. The
// renderer must emit the line inside EACH rendered unicast AF block
// (ipv4 and ipv6, default instance and every routing instance) and never
// at router level.

// afDampening15185 reports the indent+text of every `bgp dampening` line
// inside the named AF block, and every router-level occurrence.
func afDampening15185(t *testing.T, rendered, family string) []string {
	t.Helper()
	var in []string
	for _, line := range strings.Split(bgpAFBlock11374(rendered, family), "\n") {
		if strings.TrimSpace(line) != "" && strings.HasPrefix(strings.TrimSpace(line), "bgp dampening") {
			in = append(in, strings.TrimSpace(line))
		}
	}
	return in
}

func dampeningBGP15185(neighbors ...*config.BGPNeighbor) *config.BGPConfig {
	return &config.BGPConfig{
		LocalAS:              65001,
		RouterID:             "1.1.1.1",
		Dampening:            true,
		DampeningHalfLife:    10,
		DampeningReuse:       500,
		DampeningSuppress:    3000,
		DampeningMaxSuppress: 45,
		Neighbors:            neighbors,
	}
}

const dampeningLine15185 = "bgp dampening 10 500 3000 45"

func TestBGPDampeningRenderedPerAddressFamily15185(t *testing.T) {
	// Mixed family-less neighbors: an IPv4 peer (FRR default-activates it
	// under ipv4 unicast) and an IPv6 peer (explicitly deactivated in
	// ipv4, activated in ipv6). Both AF blocks render, so both must
	// carry the configured dampening parameters.
	bgp := dampeningBGP15185(
		&config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002},
		&config.BGPNeighbor{Address: "2001:db8::1", PeerAS: 65002},
	)
	got := New().generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)

	// Anti-vacuity: both AF blocks and the IPv6 activation really rendered.
	if !strings.Contains(got, " address-family ipv4 unicast\n") ||
		!strings.Contains(got, " address-family ipv6 unicast\n") ||
		!strings.Contains(got, "  no neighbor 2001:db8::1 activate\n") ||
		!strings.Contains(got, "  neighbor 2001:db8::1 activate\n") {
		t.Fatalf("fixture did not render both AF blocks/activations:\n%s", got)
	}

	// Router level must carry no dampening line at all: bgpd would file
	// it under ipv4 unicast only, silently skipping IPv6.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, " bgp dampening") {
			t.Errorf("router-level dampening line rendered (files under ipv4 only in bgpd):\n%s", got)
			break
		}
	}

	for _, family := range []string{bgpInet4AF11374, bgpInet6AF11374} {
		lines := afDampening15185(t, got, family)
		if len(lines) != 1 || lines[0] != dampeningLine15185 {
			t.Errorf("address-family %s dampening = %v, want exactly [%q]:\n%s", family, lines, dampeningLine15185, got)
		}
	}
	if n := strings.Count(got, dampeningLine15185); n != 2 {
		t.Errorf("rendered %d dampening lines, want 2 (one per unicast AF):\n%s", n, got)
	}
}

func TestBGPDampeningNoNeighborsStillPerFamily15185(t *testing.T) {
	// Dampening with no neighbors at all: no AF block is opened for
	// neighbors today, but the configured damping must still reach both
	// unicast families (a later peer must see it, mirroring the #9667
	// IPv6-redistribute-alone precedent). Both AF blocks open carrying
	// only the dampening line.
	bgp := dampeningBGP15185()
	got := New().generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	for _, family := range []string{bgpInet4AF11374, bgpInet6AF11374} {
		lines := afDampening15185(t, got, family)
		if len(lines) != 1 || lines[0] != dampeningLine15185 {
			t.Errorf("no-neighbor address-family %s dampening = %v, want exactly [%q]:\n%s", family, lines, dampeningLine15185, got)
		}
	}
	if strings.Contains(got, " bgp dampening") && !strings.Contains(got, "  bgp dampening") {
		t.Errorf("router-level dampening rendered:\n%s", got)
	}
}

func TestBGPDampeningRoutingInstancePerFamily15185(t *testing.T) {
	// Routing-instance stanza: `router bgp <as> vrf <name>` must carry
	// the same per-AF dampening, never a router-level line.
	fc := &FullConfig{
		Instances: []InstanceConfig{{
			Name:    "cust-a",
			VRFName: "vrf-cust-a",
			BGP: dampeningBGP15185(
				&config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002},
				&config.BGPNeighbor{Address: "2001:db8::1", PeerAS: 65002},
			),
		}},
	}
	got := New().buildManagedSection(fc)
	if !strings.Contains(got, "router bgp 65001 vrf vrf-cust-a\n") {
		t.Fatalf("routing-instance router bgp stanza missing (anti-vacuity):\n%s", got)
	}
	for _, family := range []string{bgpInet4AF11374, bgpInet6AF11374} {
		lines := afDampening15185(t, got, family)
		if len(lines) != 1 || lines[0] != dampeningLine15185 {
			t.Errorf("routing-instance address-family %s dampening = %v, want exactly [%q]:\n%s", family, lines, dampeningLine15185, got)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, " bgp dampening") {
			t.Errorf("routing-instance router-level dampening rendered:\n%s", got)
			break
		}
	}
}

func TestBGPDampeningControls15185(t *testing.T) {
	// Control: dampening disabled renders no dampening line anywhere.
	off := dampeningBGP15185(&config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002})
	off.Dampening = false
	got := New().generateProtocols(nil, nil, off, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "dampening") {
		t.Errorf("dampening disabled must render no dampening line:\n%s", got)
	}

	// Control (#14585 belt preserved): suppress <= reuse renders no
	// dampening line in either family (bgpd refuses the combination).
	bad := dampeningBGP15185(
		&config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002},
		&config.BGPNeighbor{Address: "2001:db8::1", PeerAS: 65002},
	)
	bad.DampeningReuse, bad.DampeningSuppress = 750, 500
	got = New().generateProtocols(nil, nil, bad, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "dampening") {
		t.Errorf("suppress<=reuse must render no dampening line (#14585):\n%s", got)
	}
	if !strings.Contains(got, "  no neighbor 2001:db8::1 activate\n") ||
		!strings.Contains(got, "  neighbor 2001:db8::1 activate\n") {
		t.Errorf("suppress<=reuse control dropped neighbor activation:\n%s", got)
	}

	// Control: defaults (all knobs zero) render the FRR defaults inside
	// the AF blocks, not at router level.
	def := &config.BGPConfig{
		LocalAS:   65001,
		Dampening: true,
		Neighbors: []*config.BGPNeighbor{{Address: "2001:db8::1", PeerAS: 65002}},
	}
	got = New().generateProtocols(nil, nil, def, nil, nil, "", 0, nil, nil)
	if !strings.Contains(bgpAFBlock11374(got, bgpInet6AF11374), "bgp dampening 15 750 2000 60") {
		t.Errorf("default dampening parameters missing from ipv6 unicast:\n%s", got)
	}
}

// TestBGPDampeningAcceptedByFRR15185 feeds the rendered dampening config
// to the real FRR parser (when installed) and proves, via two mutations,
// that the per-AF placement is load-bearing rather than vacuous: the
// same line is accepted under an AF block and parses there, while the
// suite already rejects unknown keywords (control).
func TestBGPDampeningAcceptedByFRR15185(t *testing.T) {
	vtysh := os.Getenv("FRR_VTYSH_BINARY")
	if vtysh == "" {
		var err error
		vtysh, err = exec.LookPath("vtysh")
		if err != nil {
			t.Skip("FRR vtysh is not installed; FRR config-load validation unavailable")
		}
	}
	bgp := dampeningBGP15185(
		&config.BGPNeighbor{Address: "192.0.2.1", PeerAS: 65002},
		&config.BGPNeighbor{Address: "2001:db8::1", PeerAS: 65002},
	)
	got := New().buildManagedSection(&FullConfig{BGP: bgp})
	if output, err := validateRenderedRouting11417(t, vtysh, got); err != nil {
		t.Fatalf("FRR rejected per-AF dampening config: %v\n%s\nconfig:\n%s", err, output, got)
	}
	// Mutation control: corrupting one AF dampening line must fail the
	// load, proving the parser actually reached and consumed it.
	mutated := strings.Replace(got, dampeningLine15185, "bgp dampening-xpf-invalid 10 500 3000 45", 1)
	if mutated == got {
		t.Fatalf("fixture did not render the dampening line needed for its mutation control")
	}
	output, err := validateRenderedRouting11417(t, vtysh, mutated)
	if err == nil {
		t.Fatalf("FRR accepted a corrupted AF dampening line; validation cannot detect placement:\n%s", mutated)
	}
	if !bytes.Contains(output, []byte("dampening")) {
		t.Fatalf("FRR failure did not identify the corrupted dampening line: %v\n%s", err, output)
	}
}
