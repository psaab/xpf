package config

import (
	"strings"
	"testing"
)

// #15206 (A17-03, the #9407 residual): a DHCP-server group interface ref
// naming no configured interface or unit committed clean with an advisory
// saying "the segment gets no leases". The daemon renders the unresolved
// ref verbatim into Kea's interfaces-config (`reth1.7`, `ge-0-0-9.0`);
// Kea refuses the whole rendered file, so every pool of the family stops,
// not just the named segment. Strict commit must refuse the ref naming
// family/group/ref/reason and the whole-family consequence; the tolerant
// path keeps warning (#1960) and keeps the group; the survivors stay
// green (declared bare/unit/VLAN/reth, dash spelling, a legitimately
// dotted DECLARED interface name, wildcard `ge-*`, fxp0, and a group
// with no interfaces stanza at all).
//
// FAIL-ON-REVERT: drop the validateDHCPServerInterfaceRefStrict dispatch
// (compiler_uniformgates_dhcp_app.go) or its unresolvedInterfaceRef check
// and every C5 refusal below goes green on the BAD config; widen the
// verdict (e.g. a blanket ".0" strip or a LinuxIfName-only compare) and a
// C0 survivor reds instead.

func undeclaredIfaceTree15206(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range lines {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// declaredFixture15206 declares ge-0/0/1 (bare, unit 0, VLAN unit 80),
// reth1 on member ge-0/0/2 (units 0 and 80 with vlan-id 180), and a
// dotted interface name declared exactly as authored (#8994).
var declaredFixture15206 = []string{
	"set interfaces ge-0/0/1 vlan-tagging",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	"set interfaces ge-0/0/1 unit 80 vlan-id 180 family inet address 10.0.80.1/24",
	"set interfaces ge-0/0/2 gigether-options redundant-parent reth1",
	"set interfaces reth1 vlan-tagging",
	"set interfaces reth1 redundant-ether-options redundancy-group 1",
	"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
	"set interfaces reth1 unit 80 vlan-id 180 family inet address 10.0.180.1/24",
	"set interfaces gr-0/0/0.0 unit 0 family inet address 10.0.99.1/24",
}

func dhcpGroup15206(server, group, iface, subnet, low, high string) []string {
	p := "set system services " + server + " group " + group
	lines := []string{p + " interface " + iface}
	if subnet != "" {
		lines = append(lines,
			p+" pool p1 subnet "+subnet,
			p+" pool p1 address-range low "+low+" high "+high)
	}
	return lines
}

func join15206(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

func TestUndeclaredDHCPServerInterfaceRefRefusedAtCommit15206(t *testing.T) {
	const v4, v6 = "dhcp-local-server", "dhcpv6-local-server"
	cases := []struct {
		name  string
		lines []string
		want  []string // nil = must commit (survivor)
	}{
		// --- C5 refusals (RED on origin/master) ---
		{
			name:  "C5 v4 undeclared unit on declared interface",
			lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "reth1.7", "10.0.61.0/24", "10.0.61.100", "10.0.61.199")),
			want:  []string{v4, `group "g1"`, `"reth1.7"`, "names no configured unit on reth1", "every pool of the dhcp-local-server family stops serving"},
		},
		{
			name:  "C5 v4 undeclared interface",
			lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "reth9.0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199")),
			want:  []string{v4, `group "g1"`, `"reth9.0"`, "names no configured interface", "every pool of the dhcp-local-server family stops serving"},
		},
		{
			name:  "C5 v4 malformed unit",
			lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "ge-0/0/1.foo", "10.0.61.0/24", "10.0.61.100", "10.0.61.199")),
			want:  []string{`group "g1"`, `"ge-0/0/1.foo"`, "has an unparseable unit"},
		},
		{
			name:  "C5 v6 undeclared unit (twin family)",
			lines: join15206(declaredFixture15206, dhcpGroup15206(v6, "g6", "reth1.7", "2001:db8:61::/64", "2001:db8:61::10", "2001:db8:61::20")),
			want:  []string{v6, `group "g6"`, `"reth1.7"`, "names no configured unit on reth1", "every pool of the dhcpv6-local-server family stops serving"},
		},
		{
			// Scope parity with #9407/#15048: with no interfaces stanza
			// there is no declared set to judge against, so the gate is
			// silent (degenerate config, guarded elsewhere). This pins
			// the dhcpPool14601-style fixture shape as a survivor.
			name:  "survivor no interfaces stanza at all",
			lines: dhcpGroup15206(v4, "g1", "ge-0-0-1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"),
		},
		{
			// One bad ref among good refs of the same group still refuses:
			// it renders into the same interfaces-config list.
			name: "C5 one bad ref among good refs",
			lines: join15206(declaredFixture15206, []string{
				"set system services " + v4 + " group g1 interface reth1.0",
				"set system services " + v4 + " group g1 interface reth1.7",
				"set system services " + v4 + " group g1 pool p1 subnet 10.0.61.0/24",
				"set system services " + v4 + " group g1 pool p1 address-range low 10.0.61.100 high 10.0.61.199",
			}),
			want: []string{`group "g1"`, `"reth1.7"`, "names no configured unit on reth1"},
		},
		// --- Survivors (must stay green) ---
		{name: "survivor declared bare", lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "ge-0/0/1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))},
		{name: "survivor declared unit zero", lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "reth1.0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))},
		{name: "survivor declared VLAN unit", lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "reth1.80", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))},
		{name: "survivor declared reth bare", lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "reth1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))},
		{name: "survivor dash spelling", lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "ge-0-0-1", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))},
		{name: "survivor dash spelling with unit", lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "ge-0-0-1.0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))},
		{name: "survivor legitimately dotted declared name (#8994)", lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "gr-0/0/0.0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))},
		{name: "survivor wildcard selector (#6696)", lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "ge-*", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))},
		{name: "survivor management interface fxp0", lines: join15206(declaredFixture15206, dhcpGroup15206(v4, "g1", "fxp0", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))},
		{
			name: "survivor group with no interface ref",
			lines: join15206(declaredFixture15206, []string{
				"set system services " + v4 + " group g1 pool p1 subnet 10.0.61.0/24",
				"set system services " + v4 + " group g1 pool p1 address-range low 10.0.61.100 high 10.0.61.199",
			}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(undeclaredIfaceTree15206(t, tc.lines...))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("SURVIVOR BROKE: want the config to commit, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want the undeclared DHCP-server interface ref refused at commit, got a clean compile")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q does not contain %q", err, w)
				}
			}
			// The old understating wording must not survive in the refusal.
			if strings.Contains(err.Error(), "segment gets no leases") {
				t.Errorf("refusal still understates the blast radius: %v", err)
			}
		})
	}
}

// The tolerant load / peer-sync paths must warn and keep the group so a
// persisted config still boots (#1960); CompileConfigForNodeLenient (the
// HA sync path) shares the posture.
func TestUndeclaredDHCPServerInterfaceRefLenientWarns15206(t *testing.T) {
	lines := join15206(declaredFixture15206,
		dhcpGroup15206("dhcp-local-server", "g1", "reth1.7", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))
	if _, err := CompileConfig(undeclaredIfaceTree15206(t, lines...)); err == nil {
		t.Fatal("CompileConfig: want the undeclared ref refused, got a clean compile")
	}
	const warn = "DHCP server group interface (downgraded to warning on tolerant path)"
	cfg, err := CompileConfigLenient(undeclaredIfaceTree15206(t, lines...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: want a warning, not an error: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, warn) {
		t.Fatalf("CompileConfigLenient: want %q, got %+v", warn, cfg.Warnings)
	}
	if !hasWarningContaining(cfg.Warnings, "reth1.7") || !hasWarningContaining(cfg.Warnings, "every pool of the dhcp-local-server family stops serving") {
		t.Fatalf("CompileConfigLenient: warning must name the ref and the whole-family consequence, got %+v", cfg.Warnings)
	}
	if got := len(cfg.System.DHCPServer.DHCPLocalServer.Groups); got != 1 {
		t.Fatalf("CompileConfigLenient: want the group kept, got %d groups", got)
	}
	if got := cfg.System.DHCPServer.DHCPLocalServer.Groups["g1"].Interfaces; len(got) != 1 || got[0] != "reth1.7" {
		t.Fatalf("CompileConfigLenient: authored ref must survive for the renderer, got %v", got)
	}
	cfgN, errN := CompileConfigForNodeLenient(undeclaredIfaceTree15206(t, lines...), 0)
	if errN != nil {
		t.Fatalf("CompileConfigForNodeLenient: want a warning, not an error: %v", errN)
	}
	if !hasWarningContaining(cfgN.Warnings, warn) {
		t.Fatalf("CompileConfigForNodeLenient: want %q, got %+v", warn, cfgN.Warnings)
	}
	// Control: a declared ref warns about nothing ref-related.
	cfgOK, err := CompileConfigLenient(undeclaredIfaceTree15206(t,
		join15206(declaredFixture15206, dhcpGroup15206("dhcp-local-server", "g1", "reth1.80", "10.0.61.0/24", "10.0.61.100", "10.0.61.199"))...))
	if err != nil {
		t.Fatalf("CompileConfigLenient(declared): %v", err)
	}
	for _, w := range cfgOK.Warnings {
		if strings.Contains(w, "DHCP server group interface") {
			t.Errorf("declared VLAN-unit ref must not warn as unresolved: %v", cfgOK.Warnings)
		}
	}
}
