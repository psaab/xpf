package config

import (
	"strings"
	"testing"
)

// #16694: no commit-time correlation between DHCP-server and DHCP-relay
// interfaces. A resolved kernel device in both a dhcp-local-server
// group and a dhcp-relay group of the same family (v6 twin likewise)
// makes Kea and the relay bind the same UDP port; whichever starts
// second fails and the segment is served by only one service while
// both report healthy. Strict commit must refuse naming the device,
// both groups and both refs; single-service rows and cross-family
// rows still commit; the tolerant path warns and keeps both groups.
//
// FAIL-ON-REVERT: drop the validateDHCPServerRelayOverlapStrict
// dispatch (compiler_uniformgates_dhcp_app.go) and every refusal
// below goes green on the BAD config; compare authored strings
// instead of resolved devices and the reth/member + unit-0/bare
// cells go green too; skip the wildcard expansion and the ge-*
// cells go green.

func overlapTree16694(t *testing.T, lines ...string) *ConfigTree {
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

var overlapIfaces16694 = []string{
	"set interfaces ge-0/0/1 vlan-tagging",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	"set interfaces ge-0/0/1 unit 0 family inet6 address 2001:db8:1::1/64",
	"set interfaces ge-0/0/1 unit 80 vlan-id 180 family inet address 10.0.80.1/24",
	"set interfaces ge-0/0/1 unit 80 vlan-id 180 family inet6 address 2001:db8:80::1/64",
	"set interfaces ge-0/0/2 gigether-options redundant-parent reth1",
	"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
	"set interfaces ge-0/0/3 unit 0 family inet6 address 2001:db8:3::1/64",
	// NOTE: ge-0/0/2 declares no unit of its own (a reth member must
	// not); member refs are authored as reth1 refs in the cells below.
	// The member-as-server direction is not committable at all today:
	// the #15206 gate refuses ge-0/0/2.0 as undeclared, so it cannot
	// reach this gate — the relay-only member ref in the lenient and
	// reth/member cells covers the member spelling.
	"set interfaces reth1 vlan-tagging",
	"set interfaces reth1 redundant-ether-options redundancy-group 1",
	"set interfaces reth1 unit 0 family inet address 10.0.61.1/24",
	"set interfaces reth1 unit 0 family inet6 address 2001:db8:61::1/64",
	"set interfaces reth1 unit 80 vlan-id 180 family inet address 10.0.180.1/24",
	"set interfaces reth1 unit 80 vlan-id 180 family inet6 address 2001:db8:180::1/64",
}

func overlapServer16694(server, group, iface string) []string {
	subnet, low, high := "10.0.61.0/24", "10.0.61.100", "10.0.61.199"
	if strings.Contains(server, "v6") {
		subnet, low, high = "2001:db8:61::/64", "2001:db8:61::10", "2001:db8:61::20"
	}
	p := "set system services " + server + " group " + group
	return []string{
		p + " interface " + iface,
		p + " pool p1 subnet " + subnet,
		p + " pool p1 address-range low " + low + " high " + high,
	}
}

func overlapRelay16694(group, iface string) []string {
	return []string{
		"set forwarding-options dhcp-relay server-group sg1 192.0.2.53",
		"set forwarding-options dhcp-relay group " + group + " active-server-group sg1",
		"set forwarding-options dhcp-relay group " + group + " interface " + iface,
	}
}

func overlapRelayV616694(group, iface string) []string {
	return []string{
		"set forwarding-options dhcp-relay dhcpv6 server-group sg6 2001:db8::53",
		"set forwarding-options dhcp-relay dhcpv6 group " + group + " active-server-group sg6",
		"set forwarding-options dhcp-relay dhcpv6 group " + group + " interface " + iface,
	}
}

func join16694(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s...)
	}
	return out
}

func TestDHCPServerRelayOverlapRefusedAtCommit16694(t *testing.T) {
	const v4, v6 = "dhcp-local-server", "dhcpv6-local-server"
	cases := []struct {
		name  string
		lines []string
		want  []string // nil = must commit (survivor)
	}{
		{
			name:  "both-row same authored ref v4",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-0/0/1.0"), overlapRelay16694("r1", "ge-0/0/1.0")),
			want:  []string{v4, `group "g1"`, `"ge-0/0/1.0"`, "dhcp-relay", `group "r1"`, `"ge-0-0-1"`, "both resolve to kernel device", "only one of the two configured services"},
		},
		{
			name:  "unit-0 server vs bare relay",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-0/0/1.0"), overlapRelay16694("r1", "ge-0/0/1")),
			want:  []string{`group "g1"`, `group "r1"`, `"ge-0-0-1"`},
		},
		{
			name:  "reth server vs member relay",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "reth1.0"), overlapRelay16694("r1", "ge-0/0/2.0")),
			want:  []string{`group "g1"`, `"reth1.0"`, `group "r1"`, `"ge-0/0/2.0"`, `"ge-0-0-2"`},
		},
		{
			// A member ref as the SERVER side never reaches this gate:
			// #15206 refuses ge-0/0/2.0 as undeclared first (the member
			// declares no unit; reth1 owns it). Pin that the refusal is
			// the #15206 one, so this spelling is refused either way.
			name:  "member server ref refused earlier by 15206",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-0/0/2.0"), overlapRelay16694("r1", "reth1.0")),
			want:  []string{"#15206", `"ge-0/0/2.0"`},
		},
		{
			name:  "VLAN unit both sides different spellings",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "reth1.80"), overlapRelay16694("r1", "ge-0-0-2.180")),
			want:  []string{`group "g1"`, `group "r1"`, `"ge-0-0-2.180"`},
		},
		{
			name:  "dash spelling relay vs slash server",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-0/0/1.0"), overlapRelay16694("r1", "ge-0-0-1")),
			want:  []string{`group "g1"`, `group "r1"`},
		},
		{
			name:  "v6 both-row",
			lines: join16694(overlapIfaces16694, overlapServer16694(v6, "g6", "ge-0/0/1.0"), overlapRelayV616694("r6", "ge-0/0/1.0")),
			want:  []string{v6, `group "g6"`, "dhcp-relay dhcpv6", `group "r6"`, `"ge-0-0-1"`},
		},
		{
			name:  "v6 reth vs member",
			lines: join16694(overlapIfaces16694, overlapServer16694(v6, "g6", "reth1.0"), overlapRelayV616694("r6", "ge-0/0/2.0")),
			want:  []string{v6, `group "g6"`, `group "r6"`, `"ge-0-0-2"`},
		},
		{
			name:  "wildcard server covers concrete relay",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-*"), overlapRelay16694("r1", "ge-0/0/1.0")),
			want:  []string{`group "g1"`, `"ge-*"`, `group "r1"`, `"ge-0-0-1"`},
		},
		{
			name:  "wildcard relay covers concrete server",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-0/0/1.0"), overlapRelay16694("r1", "ge-*")),
			want:  []string{`group "g1"`, `group "r1"`, `"ge-*"`},
		},
		// --- Survivors ---
		{name: "server only", lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-0/0/1.0"))},
		{name: "relay only", lines: join16694(overlapIfaces16694, overlapRelay16694("r1", "ge-0/0/1.0"))},
		{
			name:  "disjoint devices same family",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-0/0/1.0"), overlapRelay16694("r1", "ge-0/0/3.0")),
		},
		{
			name:  "cross-family same device is legal",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-0/0/1.0"), overlapRelayV616694("r6", "ge-0/0/1.0")),
		},
		{
			name:  "v6 disjoint",
			lines: join16694(overlapIfaces16694, overlapServer16694(v6, "g6", "ge-0/0/1.0"), overlapRelayV616694("r6", "ge-0/0/3.0")),
		},
		{
			name:  "different VLAN units same parent",
			lines: join16694(overlapIfaces16694, overlapServer16694(v4, "g1", "ge-0/0/1.80"), overlapRelay16694("r1", "ge-0/0/1.0")),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(overlapTree16694(t, tc.lines...))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("SURVIVOR BROKE: want commit, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want server/relay overlap refused at commit, got clean compile")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q does not contain %q", err, w)
				}
			}
		})
	}
}

func TestDHCPServerRelayOverlapNoInterfacesStanza16694(t *testing.T) {
	// No interfaces stanza: identical spellings still resolve
	// identically, so the exact both-row is refused; the gate must
	// not invent devices for distinct refs.
	lines := join16694(overlapServer16694("dhcp-local-server", "g1", "ge-0-0-1"), overlapRelay16694("r1", "ge-0-0-1"))
	if _, err := CompileConfig(overlapTree16694(t, lines...)); err == nil || !strings.Contains(err.Error(), "ge-0-0-1") {
		t.Fatalf("both-row without interfaces stanza: want refusal naming ge-0-0-1, got %v", err)
	}
	disjoint := join16694(overlapServer16694("dhcp-local-server", "g1", "ge-0-0-1"), overlapRelay16694("r1", "ge-0-0-9"))
	if _, err := CompileConfig(overlapTree16694(t, disjoint...)); err != nil {
		t.Fatalf("disjoint refs without interfaces stanza must commit, got %v", err)
	}
}

func TestDHCPServerRelayOverlapLenientWarns16694(t *testing.T) {
	lines := join16694(overlapIfaces16694, overlapServer16694("dhcp-local-server", "g1", "reth1.0"), overlapRelay16694("r1", "ge-0/0/2.0"))
	if _, err := CompileConfig(overlapTree16694(t, lines...)); err == nil {
		t.Fatal("CompileConfig: want overlap refused, got clean compile")
	}
	const warn = "DHCP server/relay interface overlap (downgraded to warning on tolerant path)"
	cfg, err := CompileConfigLenient(overlapTree16694(t, lines...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: want warning not error: %v", err)
	}
	if !hasWarningContaining(cfg.Warnings, warn) || !hasWarningContaining(cfg.Warnings, "ge-0-0-2") {
		t.Fatalf("CompileConfigLenient: want %q naming ge-0-0-2, got %+v", warn, cfg.Warnings)
	}
	if len(cfg.System.DHCPServer.DHCPLocalServer.Groups) != 1 || len(cfg.ForwardingOptions.DHCPRelay.Groups) != 1 {
		t.Fatalf("lenient must keep both groups, got server=%v relay=%v", cfg.System.DHCPServer.DHCPLocalServer.Groups, cfg.ForwardingOptions.DHCPRelay.Groups)
	}
	cfgN, err := CompileConfigForNodeLenient(overlapTree16694(t, lines...), 0)
	if err != nil {
		t.Fatalf("CompileConfigForNodeLenient: %v", err)
	}
	if !hasWarningContaining(cfgN.Warnings, warn) {
		t.Fatalf("CompileConfigForNodeLenient: want %q, got %+v", warn, cfgN.Warnings)
	}
	// ValidateConfig advisory (recompute-from-active surfaces).
	if ws := ValidateConfig(cfg); !hasWarningContaining(ws, "both resolve to kernel device") {
		t.Fatalf("ValidateConfig must advise on the overlap, got %+v", ws)
	}
	// Control: disjoint config warns about nothing overlap-related.
	okLines := join16694(overlapIfaces16694, overlapServer16694("dhcp-local-server", "g1", "ge-0/0/1.0"), overlapRelay16694("r1", "ge-0/0/3.0"))
	cfgOK, err := CompileConfigLenient(overlapTree16694(t, okLines...))
	if err != nil {
		t.Fatalf("CompileConfigLenient(disjoint): %v", err)
	}
	for _, w := range cfgOK.Warnings {
		if strings.Contains(w, "server/relay interface overlap") {
			t.Errorf("disjoint config must not warn overlap: %v", cfgOK.Warnings)
		}
	}
	if ws := ValidateConfig(cfgOK); hasWarningContaining(ws, "both resolve to kernel device") {
		t.Errorf("ValidateConfig(disjoint) must not advise overlap, got %+v", ws)
	}
}
