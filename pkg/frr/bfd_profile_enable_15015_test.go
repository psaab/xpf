package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBFDProfileEnableLines15015 is the #15015 (A12-03) fail-on-revert
// guard. In FRR 10.6 the per-interface `<proto> bfd profile <name>` line
// does NOT by itself enable BFD monitoring:
//
//   - OSPFv2 (ospfd/ospf_bfd.c, ip_ospf_bfd_prof DEFUN): the handler
//     refuses with "ip ospf bfd has not been set" (CMD_WARNING) when no
//     bfd_config exists, i.e. when `ip ospf bfd` was never issued.
//     ospf_bfd_write_config likewise prints ` ip ospf bfd` first and the
//     profile line second.
//   - IS-IS (isisd/isis_cli.c): `isis bfd profile` only modifies the
//     bfd-monitoring/profile leaf; the separate bfd-monitoring/enabled
//     leaf is set only by `isis bfd`, and bfd_handle_adj_up skips any
//     adjacency whose circuit->bfd_config.enabled is false.
//     cli_show_ip_isis_bfd_monitoring prints ` isis bfd` before the
//     profile line.
//
// So an interface configured with bfd-liveness-detection
// minimum-interval/multiplier rendered ONLY the profile-binding line:
// frr-reload reported success, yet no BFD session ever ran and
// convergence silently fell back to the OSPF dead interval / IS-IS
// hold time. OspFv3 is deliberately NOT covered: its single command
// `ipv6 ospf6 bfd [profile BFDPROF]` enables BFD in the same DEFUN
// (ospf6_bfd.c sets bfd_config.enabled=true), so the bare-enable leg
// does not exist there; BGP is likewise a single self-enabling command
// (`neighbor X bfd profile` is documented as "Same as neighbor X bfd").
//
// The renderer must therefore emit the bare enable line immediately
// before the profile line for OSPFv2 and IS-IS, inside the interface
// block.
func TestBFDProfileEnableLines15015(t *testing.T) {
	m := New()

	// --- OSPFv2 with custom timers ---
	ospf := &config.OSPFConfig{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFArea{
			{
				ID: "0.0.0.0",
				Interfaces: []*config.OSPFInterface{
					{Name: "trust0", BFD: true, BFDInterval: 300, BFDMultiplier: 3},
				},
			},
		},
	}
	gotOSPF := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	prof300 := bfdProfileName(300, 3)
	if !strings.Contains(gotOSPF, " ip ospf bfd\n"+" ip ospf bfd profile "+prof300+"\n") {
		t.Errorf("OSPFv2 profile interface must render ` ip ospf bfd` immediately before the profile line (#15015), got:\n%s", gotOSPF)
	}
	if !strings.Contains(gotOSPF, "\n profile "+prof300+"\n") {
		t.Errorf("missing BFD profile definition %s in:\n%s", prof300, gotOSPF)
	}

	// --- IS-IS with custom timers ---
	isis := &config.ISISConfig{
		NET:   "49.0001.0100.0000.0001.00",
		Level: "level-2",
		Interfaces: []*config.ISISInterface{
			{Name: "ge-0-0-1", BFD: true, BFDInterval: 250, BFDMultiplier: 4},
		},
	}
	gotISIS := m.generateProtocols(nil, nil, nil, nil, isis, "", 1, nil, nil)
	prof250 := bfdProfileName(250, 4)
	if !strings.Contains(gotISIS, " isis bfd\n"+" isis bfd profile "+prof250+"\n") {
		t.Errorf("IS-IS profile interface must render ` isis bfd` immediately before the profile line (#15015), got:\n%s", gotISIS)
	}
	// The pair must sit inside the interface block, before its exit (#2942).
	ifaceIdx := strings.Index(gotISIS, "interface ge-0-0-1")
	if ifaceIdx < 0 {
		t.Fatalf("expected an `interface ge-0-0-1` block; got:\n%s", gotISIS)
	}
	exitIdx := strings.Index(gotISIS[ifaceIdx:], "exit\n")
	bfdIdx := strings.Index(gotISIS[ifaceIdx:], " isis bfd\n")
	if exitIdx < 0 || bfdIdx < 0 || bfdIdx > exitIdx {
		t.Errorf("IS-IS BFD enable+profile lines must be inside the interface block before exit (#15015/#2942), got:\n%s", gotISIS)
	}
	if !strings.Contains(gotISIS, "\n profile "+prof250+"\n") {
		t.Errorf("missing BFD profile definition %s in:\n%s", prof250, gotISIS)
	}

	// --- Controls: bare BFD (no custom timers) stays a single line ---
	gotBareOSPF := m.generateProtocols(&config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0", BFD: true}}},
		},
	}, nil, nil, nil, nil, "", 0, nil, nil)
	if n := strings.Count(gotBareOSPF, " ip ospf bfd\n"); n != 1 {
		t.Errorf("bare OSPFv2 BFD must render exactly one ` ip ospf bfd` line, got %d in:\n%s", n, gotBareOSPF)
	}
	if strings.Contains(gotBareOSPF, "bfd profile") {
		t.Errorf("bare OSPFv2 BFD must not bind a profile, got:\n%s", gotBareOSPF)
	}

	gotBareISIS := m.generateProtocols(nil, nil, nil, nil, &config.ISISConfig{
		NET:        "49.0001.0100.0000.0001.00",
		Level:      "level-2",
		Interfaces: []*config.ISISInterface{{Name: "ge-0-0-1", BFD: true}},
	}, "", 1, nil, nil)
	if n := strings.Count(gotBareISIS, " isis bfd\n"); n != 1 {
		t.Errorf("bare IS-IS BFD must render exactly one ` isis bfd` line, got %d in:\n%s", n, gotBareISIS)
	}
	if strings.Contains(gotBareISIS, "bfd profile") {
		t.Errorf("bare IS-IS BFD must not bind a profile, got:\n%s", gotBareISIS)
	}

	// --- Control: an interval-only interface (multiplier unset) also
	// takes the profile branch and needs the enable line; the profile
	// name defaults the multiplier (bfdProfileName). ---
	gotIntOnly := m.generateProtocols(&config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0", BFD: true, BFDInterval: 500}}},
		},
	}, nil, nil, nil, nil, "", 0, nil, nil)
	profInt := bfdProfileName(500, 0)
	if !strings.Contains(gotIntOnly, " ip ospf bfd\n"+" ip ospf bfd profile "+profInt+"\n") {
		t.Errorf("interval-only OSPFv2 interface must render enable+profile (#15015), got:\n%s", gotIntOnly)
	}

	// --- Control: no BFD at all renders neither line. ---
	gotNone := m.generateProtocols(&config.OSPFConfig{
		Areas: []*config.OSPFArea{
			{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "trust0"}}},
		},
	}, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(gotNone, "bfd") {
		t.Errorf("interface without BFD must not render any bfd line, got:\n%s", gotNone)
	}
}
