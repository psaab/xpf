package config

import (
	"strings"
	"testing"
)

// vrrpBareVIPTree15050 builds ONE hierarchical config tree from an inner
// vrrp-group spelling under address 10.0.1.1/24. Hierarchical on purpose:
// the defect is invisible through `set`, because SetPath normalizes packed
// tokens into schema-structured children and the structured virtual-address
// leaf is CIDR-gated (ValidateIPv4CIDR/ValidateIPv6CIDR). See #8483 test.
func vrrpBareVIPTree15050(t *testing.T, inner string) *ConfigTree {
	t.Helper()
	src := `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.1.1/24 { ` +
		inner + ` } } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

func vrrpBareVIPTreeV6_15050(t *testing.T, inner string) *ConfigTree {
	t.Helper()
	src := `interfaces { ge-0/0/0 { unit 0 { family inet6 { address 2001:db8::1/64 { ` +
		inner + ` } } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

func compiledBareVIPs15050(t *testing.T, cfg *Config) []string {
	t.Helper()
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil {
		t.Fatalf("compiled config dropped the interface/unit: %+v", cfg.Interfaces.Interfaces)
	}
	var out []string
	for _, vg := range ifc.Units[0].VRRPGroups {
		out = append(out, vg.VirtualAddresses...)
	}
	return out
}

// TestPackedBareVRRPVIPFailsStrict15050 is the #15050 gate: a prefix-less
// virtual-address carried by the packed hierarchical one-liner must fail
// strict compile, because netlink.ParseAddr rejects it at runtime and
// #5082 fail-closed reverts every promotion. The CIDR controls in the same
// table are what distinguish the gate from an all-reject one.
func TestPackedBareVRRPVIPFailsStrict15050(t *testing.T) {
	rows := []struct {
		name    string
		inner   string
		wantErr string
	}{
		{
			name:    "packed bare IPv4 VIP is rejected",
			inner:   `vrrp-group 1 virtual-address 10.0.1.100;`,
			wantErr: "virtual-address 10.0.1.100",
		},
		{
			name:    "packed bare VIP first in bracketed run is rejected",
			inner:   `vrrp-group 1 virtual-address [ 10.0.1.100 10.0.1.101/24 ];`,
			wantErr: "virtual-address 10.0.1.100",
		},
		{
			name:    "braced bare VIP is also rejected by the compiled gate",
			inner:   `vrrp-group 1 { virtual-address 10.0.1.100; priority 200; }`,
			wantErr: "virtual-address 10.0.1.100",
		},
		{
			name:  "packed CIDR VIP still commits",
			inner: `vrrp-group 1 virtual-address 10.0.1.100/24 priority 200;`,
		},
		{
			name:  "braced CIDR VIP still commits",
			inner: `vrrp-group 1 { virtual-address 10.0.1.100/24; priority 200; }`,
		},
		{
			name:  "packed CIDR VIPs still commit",
			inner: `vrrp-group 1 virtual-address [ 10.0.1.100/24 10.0.1.101/24 ];`,
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			tree := vrrpBareVIPTree15050(t, row.inner)
			cfg, err := CompileConfig(tree)
			if row.wantErr == "" {
				if err != nil {
					t.Fatalf("must commit, got: %v", err)
				}
				for _, vip := range compiledBareVIPs15050(t, cfg) {
					if !strings.Contains(vip, "/") {
						t.Fatalf("CIDR control compiled to a bare VIP %q", vip)
					}
				}
				return
			}
			if err == nil {
				t.Fatalf("must be rejected, but committed clean (cfg=%+v)", cfg)
			}
			if !strings.Contains(err.Error(), row.wantErr) {
				t.Fatalf("rejected for the wrong reason\n  want substring: %q\n  got: %v", row.wantErr, err)
			}
			if !strings.Contains(err.Error(), "prefix") {
				t.Fatalf("error %q does not name the missing prefix", err.Error())
			}
		})
	}
}

func TestPackedBareVRRPV6VIPFailsStrict15050(t *testing.T) {
	tree := vrrpBareVIPTreeV6_15050(t, `vrrp-group 1 virtual-address 2001:db8::100;`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("must reject a bare IPv6 virtual-address, but committed clean")
	} else if !strings.Contains(err.Error(), "2001:db8::100") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
	// CIDR control.
	treeOK := vrrpBareVIPTreeV6_15050(t, `vrrp-group 1 virtual-address 2001:db8::100/64;`)
	if _, err := CompileConfig(treeOK); err != nil {
		t.Fatalf("CIDR IPv6 control must commit: %v", err)
	}
}

// TestPackedBareVRRPVIPLenientNormalizes15050 pins the #1960 no-brick side
// AND the acceptance requirement that the tolerant compile actuates: the
// bare VIP is warned about and normalized to the enclosing address prefix
// (10.0.1.1/24 -> /24), so the leniently-loaded config reaches
// netlink.ParseAddr in a form it accepts instead of reverting every
// promotion forever.
func TestPackedBareVRRPVIPLenientNormalizes15050(t *testing.T) {
	tree := vrrpBareVIPTree15050(t, `vrrp-group 1 virtual-address 10.0.1.100;`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("control failed: strict path must reject, or the lenient assertion proves nothing")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant path must not brick the node: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "virtual-address 10.0.1.100") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("tolerant path must WARN, not swallow; warnings: %v", cfg.Warnings)
	}
	vips := compiledBareVIPs15050(t, cfg)
	if len(vips) != 1 || vips[0] != "10.0.1.100/24" {
		t.Fatalf("tolerant path must normalize the bare VIP to the enclosing /24, got %v", vips)
	}
}

// TestBareVRRPVIPWithoutEnclosingPrefixNormalizesToHost15050: when the unit
// carries no parseable enclosing prefix for the VIP family, the tolerant
// path falls back to a host prefix (/32 or /128) — still ParseAddr-legal.
func TestBareVRRPVIPWithoutEnclosingPrefixNormalizesToHost15050(t *testing.T) {
	cfg := &Config{Interfaces: InterfacesConfig{Interfaces: map[string]*InterfaceConfig{
		"ge-0/0/0": {Units: map[int]*InterfaceUnit{
			0: {VRRPGroups: map[string]*VRRPGroup{"1": {ID: 1, VirtualAddresses: []string{"10.0.1.100", "2001:db8::100"}}}},
		}},
	}}}
	if err := validateVRRPVIPPrefixStrict(cfg); err == nil {
		t.Fatal("strict gate must reject bare VIPs")
	}
	normalizeBareVRRPVIPs(cfg)
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	for _, vg := range ifc.Units[0].VRRPGroups {
		got := strings.Join(vg.VirtualAddresses, ",")
		if got != "10.0.1.100/32,2001:db8::100/128" {
			t.Fatalf("host-prefix fallback = %v, want 10.0.1.100/32,2001:db8::100/128", vg.VirtualAddresses)
		}
	}
	// After normalization the strict gate passes: the tolerant config actuates.
	if err := validateVRRPVIPPrefixStrict(cfg); err != nil {
		t.Fatalf("normalized config must pass the strict gate: %v", err)
	}
}
