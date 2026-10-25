package config

import (
	"strings"
	"testing"
)

// #16845 (R3-F15-02): the #15989/#14591 strict gates treated only "" as
// "no peer selector". A gateway address of 0.0.0.0/::, an inline
// endpoint of 0.0.0.0, and a responder-only gateway whose
// remote-identity is inet 0.0.0.0 / inet6 :: all committed, then
// rendered remote_addrs / remote.id / PSK id selectors that strongSwan
// parses as ID_ANY — the unscoped PSK those gates exist to refuse.
// The shared IsAnyIPsecSelector / IsAnyIPsecRemoteIdentity /
// HasDiscriminatingIPsecAddress predicates now close every spelling;
// real addresses and discriminating remote-identities are unchanged.
func TestIPsecUnspecifiedSelector16845(t *testing.T) {
	build := func(t *testing.T, commands []string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, command := range commands {
			path, err := ParseSetCommand(command)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", command, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", command, err)
			}
		}
		return tree
	}
	base := func() []string {
		return []string{
			"set security ike proposal p1 authentication-method pre-shared-keys",
			"set security ike proposal p1 encryption-algorithm aes-256-cbc",
			"set security ike proposal p1 authentication-algorithm sha-256",
			"set security ike proposal p1 dh-group group14",
			"set security ike policy ike-pol proposals p1",
			"set security ike policy ike-pol pre-shared-key ascii-text site-secret",
		}
	}
	withGateway := func(addr string, extra ...string) []string {
		cmds := append(base(),
			"set security ike gateway gw ike-policy ike-pol",
			"set security ike gateway gw address "+addr)
		cmds = append(cmds, extra...)
		return append(cmds,
			"set security ipsec vpn site ike gateway gw",
			"set security ipsec vpn site bind-interface st0.0")
	}

	refused := []struct {
		name string
		cmds []string
	}{
		{"gateway address 0.0.0.0", withGateway("0.0.0.0")},
		{"gateway address ::", withGateway("::")},
		{"gateway address 0::0", withGateway("0::0")},
		{"inline gateway 0.0.0.0", append(base(),
			"set security ipsec vpn site ike gateway 0.0.0.0",
			"set security ipsec vpn site bind-interface st0.0",
			"set security ipsec vpn site pre-shared-key ascii-text site-secret")},
		{"inline gateway ::", append(base(),
			"set security ipsec vpn site ike gateway ::",
			"set security ipsec vpn site bind-interface st0.0",
			"set security ipsec vpn site pre-shared-key ascii-text site-secret")},
		{"responder-only remote-identity inet 0.0.0.0", append(base(),
			"set security ike gateway gw ike-policy ike-pol",
			"set security ike gateway gw dynamic",
			"set security ike gateway gw remote-identity inet 0.0.0.0",
			"set security ipsec vpn site ike gateway gw",
			"set security ipsec vpn site bind-interface st0.0")},
		{"responder-only remote-identity inet6 ::", append(base(),
			"set security ike gateway gw ike-policy ike-pol",
			"set security ike gateway gw dynamic",
			"set security ike gateway gw remote-identity inet6 ::",
			"set security ipsec vpn site ike gateway gw",
			"set security ipsec vpn site bind-interface st0.0")},
		{"responder-only remote-identity *", append(base(),
			"set security ike gateway gw ike-policy ike-pol",
			"set security ike gateway gw dynamic",
			"set security ike gateway gw remote-identity hostname *",
			"set security ipsec vpn site ike gateway gw",
			"set security ipsec vpn site bind-interface st0.0")},
		{"fixed gateway remote-identity inet 0.0.0.0 with hostname address", withGateway("peer.example.test",
			"set security ike gateway gw remote-identity inet 0.0.0.0")},
	}
	for _, tc := range refused {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			if _, err := CompileConfig(build(t, tc.cmds)); err == nil ||
				!strings.Contains(err.Error(), "#16845") && !strings.Contains(err.Error(), "#14591") {
				t.Fatalf("commit must refuse the ID_ANY selector (#16845), got %v", err)
			}
		})
	}

	// Tolerant path: same warning prefix family, VPN kept for render belt.
	t.Run("tolerant path warns and keeps wildcard gateway VPN", func(t *testing.T) {
		lenient, err := CompileConfigLenient(build(t, withGateway("0.0.0.0")))
		if err != nil {
			t.Fatalf("tolerant path must not refuse: %v", err)
		}
		warned := false
		for _, w := range lenient.Warnings {
			if strings.Contains(w, "ipsec responder-only remote identity") {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("tolerant path must warn, warnings=%v", lenient.Warnings)
		}
		if lenient.Security.IPsec.VPNs["site"] == nil {
			t.Fatal("tolerant path must keep the VPN (render belt skips it)")
		}
	})

	controls := []struct {
		name string
		cmds []string
	}{
		{"gateway address 203.0.113.1 (control)", withGateway("203.0.113.1")},
		{"gateway address 2001:db8::1 (control)", withGateway("2001:db8::1")},
		{"inline gateway 203.0.113.1 (control)", append(base(),
			"set security ipsec vpn site ike gateway 203.0.113.1",
			"set security ipsec vpn site bind-interface st0.0",
			"set security ipsec vpn site pre-shared-key ascii-text site-secret")},
		{"responder-only remote-identity inet 198.51.100.77 (control)", append(base(),
			"set security ike gateway gw ike-policy ike-pol",
			"set security ike gateway gw dynamic",
			"set security ike gateway gw remote-identity inet 198.51.100.77",
			"set security ipsec vpn site ike gateway gw",
			"set security ipsec vpn site bind-interface st0.0")},
		{"responder-only remote-identity hostname (control)", append(base(),
			"set security ike gateway gw ike-policy ike-pol",
			"set security ike gateway gw dynamic",
			"set security ike gateway gw remote-identity hostname rw.example.com",
			"set security ipsec vpn site ike gateway gw",
			"set security ipsec vpn site bind-interface st0.0")},
		{"mixed unspecified and real address commits on real selector", withGateway("0.0.0.0",
			"set security ike gateway gw address 203.0.113.1")},
		{"fixed gateway ID_ANY remote-identity rescued by real address", withGateway("203.0.113.1",
			"set security ike gateway gw remote-identity inet 0.0.0.0")},
	}
	for _, tc := range controls {
		t.Run("commits: "+tc.name, func(t *testing.T) {
			if _, err := CompileConfig(build(t, tc.cmds)); err != nil {
				t.Fatalf("control must commit unchanged (#16845), got: %v", err)
			}
		})
	}
}

// TestIsAnyIPsecSelector16845 pins the shared predicate directly: every
// ID_ANY spelling, and the discriminating controls that must not match.
func TestIsAnyIPsecSelector16845(t *testing.T) {
	anyCases := []string{"", "%any", "%any6", "*", "0.0.0.0", "::", "0::0", "::ffff:0.0.0.0", "0:0:0:0:0:0:0:0"}
	for _, s := range anyCases {
		if !IsAnyIPsecSelector(s) {
			t.Errorf("IsAnyIPsecSelector(%q) = false, want true (ID_ANY)", s)
		}
	}
	notAny := []string{"203.0.113.1", "2001:db8::1", "::1", "127.0.0.1", "peer.example.com", "@peer.example.com", "CN=peer"}
	for _, s := range notAny {
		if IsAnyIPsecSelector(s) {
			t.Errorf("IsAnyIPsecSelector(%q) = true, want false", s)
		}
	}
	if !IsAnyIPsecRemoteIdentity("inet", "0.0.0.0") || !IsAnyIPsecRemoteIdentity("inet6", "::") ||
		!IsAnyIPsecRemoteIdentity("hostname", "*") {
		t.Error("ID_ANY remote-identities must be recognised")
	}
	if IsAnyIPsecRemoteIdentity("inet", "198.51.100.77") || IsAnyIPsecRemoteIdentity("hostname", "rw.example.com") ||
		IsAnyIPsecRemoteIdentity("inet6", "2001:db8::1") {
		t.Error("discriminating remote-identities must not be ID_ANY")
	}
	if HasDiscriminatingIPsecAddress("0.0.0.0,::") || !HasDiscriminatingIPsecAddress("0.0.0.0,203.0.113.1") ||
		HasDiscriminatingIPsecAddress("peer.example.test") || !HasDiscriminatingIPsecAddress("203.0.113.1") {
		t.Error("HasDiscriminatingIPsecAddress mismatch")
	}
}
