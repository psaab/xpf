package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14977 (D33-05): the FRR renderer must fail closed — never activate a
// routing protocol unauthenticated — when an auth key that config
// carries cannot be rendered as a single vtysh token, and it must not
// emit out-of-range / unrenderable interface or DHCP operands that fail
// the whole managed frr-reload. Strict commit rejects these values;
// the tolerant load / HA peer-sync / rollback paths only warn (#1960),
// so the renderer is the last gate. Each test below exercises the exact
// claimed mechanism and has a legitimate-traffic control in the same
// test so a blanket suppression cannot pass.

// OSPF simple with a non-empty but unrenderable key: previously the
// interface block was emitted with `ip ospf area` and zero auth lines.
func TestOSPFSimpleUnrenderableKeyOmitsInterface14977(t *testing.T) {
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0", AuthType: "simple", AuthKey: "bad key with spaces"},
	}}}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") {
		t.Fatalf("unrenderable OSPF simple key activated the interface unauthenticated:\n%s", got)
	}
	// Control: a renderable simple key still activates with auth.
	ospf.Areas[0].Interfaces[0].AuthKey = "s3cret"
	got = m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	for _, w := range []string{"interface ge-0/0/1.0\n", " ip ospf authentication\n", " ip ospf authentication-key s3cret\n", " ip ospf area 0.0.0.0\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("renderable simple key lost %q:\n%s", w, got)
		}
	}
}

// OSPF with an unrecognized non-empty AuthType: previously emitted
// `ip ospf area` with zero auth lines. (A key with NO type is not in
// this shape: the compiler only ever sets AuthKey together with a
// type — md5 union or simple-password — so that state is no-auth.)
func TestOSPFUnrecognizedAuthTypeOmitsInterface14977(t *testing.T) {
	for _, tc := range []struct {
		name     string
		authType string
		authKey  config.Secret
	}{
		{"unrecognized type with key", "md-5", "s3cret"},
		{"unrecognized type no key", "cryptographic", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
				{Name: "ge-0/0/1.0", AuthType: tc.authType, AuthKey: tc.authKey},
			}}}}
			got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if strings.Contains(got, "interface ge-0/0/1.0") || strings.Contains(got, "ip ospf area") {
				t.Fatalf("OSPF auth (%q) activated the interface unauthenticated:\n%s", tc.authType, got)
			}
		})
	}
	// Control: no auth configured at all still activates (plain OSPF).
	m := New()
	ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{
		{Name: "ge-0/0/1.0"},
	}}}}
	got := m.generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
	if !strings.Contains(got, "interface ge-0/0/1.0\n") || !strings.Contains(got, " ip ospf area 0.0.0.0\n") {
		t.Fatalf("unauthenticated-by-design OSPF interface no longer activates:\n%s", got)
	}
}

// RIP with a non-empty but unrenderable key: previously enrolled every
// interface and emitted `ip rip authentication mode` with no string.
func TestRIPUnrenderableKeyDoesNotEnroll14977(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{AuthType: "md5", AuthKey: "bad key", Interfaces: []string{"trust0"}}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	if strings.Contains(got, "network trust0") || strings.Contains(got, "ip rip authentication") {
		t.Fatalf("unrenderable RIP key enrolled trust0 unauthenticated:\n%s", got)
	}
	// Control: renderable key enrolls with mode + string.
	rip.AuthKey = "s3cret"
	got = m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	for _, w := range []string{" network trust0\n", " ip rip authentication mode md5\n", " ip rip authentication string s3cret\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("renderable RIP key lost %q:\n%s", w, got)
		}
	}
	// Control: no auth at all still enrolls plain RIP.
	rip.AuthType, rip.AuthKey = "", ""
	got = m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	if !strings.Contains(got, " network trust0\n") || strings.Contains(got, "ip rip authentication") {
		t.Errorf("plain RIP no longer enrolls cleanly:\n%s", got)
	}
}

// RIP with an unrecognized auth type carrying a key: the renderer must
// not silently downgrade it to a plaintext mode+string adjacency.
func TestRIPUnrecognizedAuthTypeDoesNotEnroll14977(t *testing.T) {
	m := New()
	rip := &config.RIPConfig{AuthType: "bogus", AuthKey: "s3cret", Interfaces: []string{"trust0"}}
	got := m.generateProtocols(nil, nil, nil, rip, nil, "", 0, nil, nil)
	if strings.Contains(got, "network trust0") || strings.Contains(got, "ip rip authentication") {
		t.Fatalf("unrecognized RIP auth type enrolled trust0 (silent downgrade):\n%s", got)
	}
}

// IS-IS with an auth policy whose key cannot render (global or
// per-interface, empty or unrenderable, or unrecognized type): no
// interface may be activated without its password, and a global
// failure withholds the router stanza too.
func TestISISUnrenderableAuthDoesNotActivate14977(t *testing.T) {
	cases := map[string]*config.ISISConfig{
		"global unrenderable md5": {NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5", AuthKey: "bad key",
			Interfaces: []*config.ISISInterface{{Name: "trust0"}}},
		"global type no key": {NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5",
			Interfaces: []*config.ISISInterface{{Name: "trust0"}}},
		"global unrecognized": {NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "bogus", AuthKey: "s3cret",
			Interfaces: []*config.ISISInterface{{Name: "trust0"}}},
		"iface unrenderable alone": {NET: "49.0001.0100.0000.0001.00", Level: "level-2",
			Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5", AuthKey: "bad key"}}},
		"iface type no key alone": {NET: "49.0001.0100.0000.0001.00", Level: "level-2",
			Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5"}}},
	}
	for name, isis := range cases {
		t.Run(name, func(t *testing.T) {
			got := New().generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
			if strings.Contains(got, "ip router isis") || strings.Contains(got, "isis password") {
				t.Fatalf("IS-IS activated an interface without a renderable password:\n%s", got)
			}
			if strings.HasPrefix(name, "global") && strings.Contains(got, "router isis") {
				t.Fatalf("global IS-IS auth failure still emitted the router stanza:\n%s", got)
			}
		})
	}
	// Controls: keyed global+iface render; no-auth IS-IS still activates.
	keyed := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5", AuthKey: "s3cret",
		Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: "md5", AuthKey: "s3cret"}}}
	got := New().generateProtocols(nil, nil, nil, nil, keyed, "", 0, nil, nil)
	for _, w := range []string{"router isis xpf\n", " area-password md5 s3cret\n", " ip router isis xpf\n", " isis password md5 s3cret\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("keyed IS-IS lost %q:\n%s", w, got)
		}
	}
	plain := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2",
		Interfaces: []*config.ISISInterface{{Name: "trust0"}}}
	got = New().generateProtocols(nil, nil, nil, nil, plain, "", 0, nil, nil)
	if !strings.Contains(got, "router isis xpf\n") || !strings.Contains(got, " ip router isis xpf\n") {
		t.Errorf("plain IS-IS no longer activates:\n%s", got)
	}
	if strings.Contains(got, "password") {
		t.Errorf("plain IS-IS gained a password line:\n%s", got)
	}
}

// IS-IS per-interface auth failure must not take down a healthy global
// stanza: only the offending interface is withheld.
func TestISISBadIfaceAuthKeepsHealthyGlobal14977(t *testing.T) {
	isis := &config.ISISConfig{NET: "49.0001.0100.0000.0001.00", Level: "level-2", AuthType: "md5", AuthKey: "s3cret",
		Interfaces: []*config.ISISInterface{
			{Name: "trust0", AuthType: "md5", AuthKey: "bad key"},
			{Name: "trust1", AuthType: "md5", AuthKey: "s3cret"},
		}}
	got := New().generateProtocols(nil, nil, nil, nil, isis, "", 0, nil, nil)
	if !strings.Contains(got, " area-password md5 s3cret\n") {
		t.Fatalf("healthy global IS-IS auth was suppressed with the bad interface:\n%s", got)
	}
	if strings.Contains(got, "interface trust0\n") {
		t.Errorf("bad-auth interface trust0 was activated:\n%s", got)
	}
	if !strings.Contains(got, "interface trust1\n") || !strings.Contains(got, " isis password md5 s3cret\n") {
		t.Errorf("healthy interface trust1 was withheld:\n%s", got)
	}
}

// BGP neighbor whose configured password cannot render: the neighbor
// must not be declared/activated without it (#9050 deliberately kept
// the neighbor; #14977 supersedes that for the auth-configured case —
// an unauthenticated BGP session is the claimed defect).
func TestBGPUnrenderablePasswordExcludesNeighbor14977(t *testing.T) {
	m := New()
	bgp := &config.BGPConfig{LocalAS: 65000, Neighbors: []*config.BGPNeighbor{
		{Address: "10.0.0.1", PeerAS: 65001, AuthPassword: "bad password"},
		{Address: "10.0.0.2", PeerAS: 65002, AuthPassword: "s3cret"},
		{Address: "10.0.0.3", PeerAS: 65003},
	}}
	got := m.generateProtocols(nil, nil, bgp, nil, nil, "", 0, nil, nil)
	if strings.Contains(got, "10.0.0.1") {
		t.Fatalf("neighbor with unrenderable password was declared/activated unauthenticated:\n%s", got)
	}
	// Controls: renderable password and password-less neighbors render.
	for _, w := range []string{" neighbor 10.0.0.2 remote-as 65002\n", " neighbor 10.0.0.2 password s3cret\n", " neighbor 10.0.0.3 remote-as 65003\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("healthy neighbor lost %q:\n%s", w, got)
		}
	}
}

// generateInterfaceSettings: out-of-range bandwidth must clamp to the
// FRR ceiling (1-100000000 kbps) and an unrenderable interface name
// must be skipped, not interpolated raw.
func TestInterfaceSettingsBandwidthClampAndNameBelt14977(t *testing.T) {
	m := New()
	fc := &FullConfig{InterfaceBandwidths: map[string]uint64{
		"ge-0/0/1.0":     400_000_000_000, // 400 Gbps
		"bad iface\nfoo": 1_000_000_000,
		"trust0":         100_000_000, // 100 Mbps control
	}}
	got := m.generateInterfaceSettings(fc)
	if !strings.Contains(got, "interface ge-0/0/1.0\n bandwidth 100000000\n") {
		t.Errorf("400Gbps bandwidth not clamped to the FRR ceiling:\n%s", got)
	}
	if strings.Contains(got, "bad iface") {
		t.Errorf("unrenderable interface name was emitted raw:\n%s", got)
	}
	if !strings.Contains(got, "interface trust0\n bandwidth 100000\n") {
		t.Errorf("100Mbps control bandwidth changed:\n%s", got)
	}
}

// renderDHCPDefaults: an empty/malformed gateway or a malformed
// non-default destination must drop only that route, never emit an
// `ip route` line FRR rejects (which fails the whole reload).
func TestDHCPDefaultsInvalidGatewayOrDestDropped14977(t *testing.T) {
	render := func(routes []DHCPRoute) string {
		var b strings.Builder
		renderDHCPDefaults(&b, &FullConfig{DHCPRoutes: routes})
		return b.String()
	}
	cases := map[string][]DHCPRoute{
		"empty gateway":        {{Gateway: ""}},
		"spaced gateway":       {{Gateway: "10.0.2.1 extra"}},
		"zoned v6 gateway":     {{Gateway: "fe80::1%eth0", IsIPv6: true}},
		"garbage gateway":      {{Gateway: "not-an-ip"}},
		"bad classless dest":   {{Destination: "10.0.0.0/33", Gateway: "10.0.2.1"}},
		"spaced classless dst": {{Destination: "10.0.0.0/8 evil", Gateway: "10.0.2.1"}},
	}
	for name, routes := range cases {
		t.Run(name, func(t *testing.T) {
			if got := render(routes); strings.Contains(got, "ip route") || strings.Contains(got, "ipv6 route") {
				t.Fatalf("invalid DHCP route was emitted:\n%s", got)
			}
		})
	}
	// Controls: ordinary v4/v6 defaults and a valid classless route.
	got := render([]DHCPRoute{{Gateway: "10.0.2.1"}, {Gateway: "fe80::1", IsIPv6: true, Interface: "ge-0/0/1.0"}})
	if !strings.Contains(got, "ip route 0.0.0.0/0 10.0.2.1 200\n") {
		t.Errorf("valid v4 DHCP default changed:\n%s", got)
	}
	if !strings.Contains(got, "ipv6 route ::/0 fe80::1") {
		t.Errorf("valid v6 DHCP default changed:\n%s", got)
	}
	got = render([]DHCPRoute{{Destination: "192.168.0.0/24", Gateway: "10.0.2.1"}})
	if !strings.Contains(got, "ip route 192.168.0.0/24 10.0.2.1 200\n") {
		t.Errorf("valid classless DHCP route changed:\n%s", got)
	}
	// A bad route must not take its healthy sibling down with it.
	got = render([]DHCPRoute{{Gateway: "bad gw"}, {Gateway: "10.0.2.1"}})
	if strings.Contains(got, "bad gw") || !strings.Contains(got, "ip route 0.0.0.0/0 10.0.2.1 200\n") {
		t.Errorf("bad DHCP route poisoned or blocked its healthy sibling:\n%s", got)
	}
}
