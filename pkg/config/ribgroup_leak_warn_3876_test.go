package config

import (
	"strings"
	"testing"
)

// ribGroupLeakConfig builds a config with one routing instance whose
// interface-routes rib-group imports the ribs named by importRibs. The
// instance owns one member interface unit carrying the given static
// addresses (empty = DHCP-only / unaddressed).
func ribGroupLeakConfig(importRibs, addrs []string) *Config {
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"ge-0/0/1": {Name: "ge-0/0/1", Units: map[int]*InterfaceUnit{
			0: {Number: 0, Addresses: addrs},
		}},
	}
	cfg.RoutingOptions.RibGroups = map[string]*RibGroup{
		"leak": {Name: "leak", ImportRibs: importRibs},
	}
	cfg.RoutingInstances = []*RoutingInstanceConfig{
		{
			Name:                    "dmz-vr",
			TableID:                 101,
			Interfaces:              []string{"ge-0/0/1.0"},
			InterfaceRoutesRibGroup: "leak",
		},
	}
	return cfg
}

// TestRibGroupLeakWarnsVRFtoVRF is the #3876 fail-on-revert warn guard: an
// interface-routes rib-group whose import target is another instance's rib
// (a VRF→VRF import, not main) must WARN at commit that Phase 1 does not
// install it — a fail-loud diagnostic rather than a silent no-op.
//
// RED-on-revert: dropping validateRibGroupLeakWarnings (or its vrf-target
// branch) removes the warning.
func TestRibGroupLeakWarnsVRFtoVRF(t *testing.T) {
	cfg := ribGroupLeakConfig([]string{"other-vr.inet.0"}, []string{"10.0.30.1/24"})
	// A second defined instance so other-vr.inet.0 resolves as a real VRF rib.
	cfg.RoutingInstances = append(cfg.RoutingInstances,
		&RoutingInstanceConfig{Name: "other-vr", TableID: 102})

	warns := validateRibGroupLeakWarnings(cfg)
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "VRF→VRF") || !strings.Contains(joined, "other-vr.inet.0") {
		t.Fatalf("expected a VRF→VRF import warning naming other-vr.inet.0, got: %q", joined)
	}
}

// TestRibGroupLeakWarnsNoEnumerablePrefix is the #3876 fail-on-revert warn
// guard for a DHCP-only / unaddressed source: a rib-group importing main but
// with no enumerable static connected prefix installs no ip rule, so the
// operator must be warned rather than left with a silent no-op.
func TestRibGroupLeakWarnsNoEnumerablePrefix(t *testing.T) {
	// Imports main (inet.0) but the member unit carries no static address.
	cfg := ribGroupLeakConfig([]string{"inet.0"}, nil)

	warns := validateRibGroupLeakWarnings(cfg)
	joined := strings.Join(warns, "\n")
	if !strings.Contains(joined, "no enumerable static connected prefix") {
		t.Fatalf("expected a no-enumerable-prefix warning, got: %q", joined)
	}
}

// TestRibGroupLeakNoWarnHappyPath pins that a well-formed import-into-main
// with a static connected prefix produces NO warning (guards against an
// over-eager warn that would cry wolf on every valid rib-group).
func TestRibGroupLeakNoWarnHappyPath(t *testing.T) {
	cfg := ribGroupLeakConfig([]string{"dmz-vr.inet.0", "inet.0"}, []string{"10.0.30.1/24"})
	if warns := validateRibGroupLeakWarnings(cfg); len(warns) != 0 {
		t.Fatalf("expected no rib-group leak warnings for a valid import-into-main, got: %v", warns)
	}
}

// TestRibGroupConnectedPrefixes verifies the SSOT prefix derivation: a
// leaking instance's member-unit static addresses are masked to their
// network prefixes (host + link-local skipped), matching the userspace FIB.
func TestRibGroupConnectedPrefixes(t *testing.T) {
	cfg := ribGroupLeakConfig([]string{"inet.0"}, []string{
		"10.0.30.1/24",      // → 10.0.30.0/24
		"2001:db8:30::1/64", // → 2001:db8:30::/64
		"192.0.2.5/32",      // host route → skipped
		"fe80::1/64",        // link-local → skipped
	})
	cfg.RoutingInstances = append([]*RoutingInstanceConfig{nil}, cfg.RoutingInstances...)
	got := RibGroupConnectedPrefixes(cfg)["dmz-vr"]
	want := map[string]bool{"10.0.30.0/24": true, "2001:db8:30::/64": true}
	if len(got) != len(want) {
		t.Fatalf("RibGroupConnectedPrefixes = %v, want %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("unexpected leaked prefix %q (host/link-local should be skipped)", p)
		}
	}
}

func TestRibGroupConnectedPrefixesSortsAndCompacts11452(t *testing.T) {
	cfg := ribGroupLeakConfig([]string{"inet.0"}, []string{
		"10.0.31.1/24",
		"10.0.30.3/24",
		"10.0.30.2/24",
		"10.0.30.1/24",
	})

	got := RibGroupConnectedPrefixes(cfg)["dmz-vr"]
	want := []string{"10.0.30.0/24", "10.0.31.0/24"}
	if len(got) != len(want) {
		t.Fatalf("RibGroupConnectedPrefixes = %v, want sorted unique prefixes %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("RibGroupConnectedPrefixes = %v, want sorted unique prefixes %v", got, want)
		}
	}
}

// TestConnectedNetworkPrefix pins the shared address→network derivation used
// by both the rib-group leak and the userspace FIB.
func TestConnectedNetworkPrefix(t *testing.T) {
	cases := []struct {
		in         string
		wantPrefix string
		wantFamily string
		wantOK     bool
	}{
		{"10.0.30.1/24", "10.0.30.0/24", "inet", true},
		{"2001:db8:30::1/64", "2001:db8:30::/64", "inet6", true},
		{"192.0.2.5/32", "", "inet", false},     // host route
		{"2001:db8::1/128", "", "inet6", false}, // host route
		{"fe80::1/64", "", "inet6", false},      // link-local
		{"0.0.0.0/0", "", "inet", false},        // default route
		{"garbage", "", "", false},              // unparseable
	}
	for _, c := range cases {
		prefix, family, ok := ConnectedNetworkPrefix(c.in)
		if ok != c.wantOK || prefix != c.wantPrefix {
			t.Errorf("ConnectedNetworkPrefix(%q) = (%q, %q, %v), want (%q, _, %v)",
				c.in, prefix, family, ok, c.wantPrefix, c.wantOK)
		}
		if c.wantOK && family != c.wantFamily {
			t.Errorf("ConnectedNetworkPrefix(%q) family = %q, want %q", c.in, family, c.wantFamily)
		}
	}
}

func TestIPv6LinkCandidate(t *testing.T) {
	for _, tc := range []struct {
		address string
		want    bool
	}{
		{"2001:db8::1/64", true},
		{"fe80::1/64", true},
		{"::1/128", true},
		{"192.0.2.1/24", false},
		{"not-an-address", false},
	} {
		if got := IPv6LinkCandidate(tc.address); got != tc.want {
			t.Errorf("IPv6LinkCandidate(%q) = %v, want %v", tc.address, got, tc.want)
		}
	}
}

func TestTargetReturnPathWarningsCoverNextTableAndPBR(t *testing.T) {
	cfg := ribGroupLeakConfig(nil, []string{"10.0.30.1/24"})
	unit := cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0]
	unit.FilterInputV4 = "steer"
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"steer": {Terms: []*FirewallFilterTerm{{RoutingInstance: "dmz-vr"}}},
	}
	cfg.RoutingOptions.Inet6StaticRoutes = []*StaticRoute{
		{Destination: "2001:db8:ffff::/48", NextTable: "dmz-vr"},
	}
	targetWarnings := func(cfg *Config) []string {
		var found []string
		for _, warning := range ValidateConfig(cfg) {
			if strings.Contains(warning, `routing-instance "dmz-vr" is targeted by next-table or PBR`) {
				found = append(found, warning)
			}
		}
		return found
	}
	warnings := targetWarnings(cfg)
	if len(warnings) != 1 {
		t.Fatalf("next-table and PBR references to one target should produce one warning, got: %v", warnings)
	}
	for _, part := range []string{"dmz-vr", "main-only peer", "routing-options static", "next-hop", "Per-instance next-table is unsupported"} {
		if !strings.Contains(warnings[0], part) {
			t.Errorf("target return warning missing %q: %s", part, warnings[0])
		}
	}

	cfg.RoutingInstances[0].InstanceType = "forwarding"
	warnings = targetWarnings(cfg)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "type forwarding") {
		t.Fatalf("expected forwarding-instance return-path warning, got: %v", warnings)
	}
}
