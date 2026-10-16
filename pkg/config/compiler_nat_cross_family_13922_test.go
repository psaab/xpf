package config

import (
	"strings"
	"testing"
)

// #13922 (H02-05): strict commit accepted cross-family static-NAT host
// pairs even though the dataplane installs static mappings in family-specific
// tables. Both endpoints can be valid host addresses while the pair is not.

func dnatFamilySet13922(dst, poolAddr string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security nat destination pool dp address " + poolAddr,
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match destination-address " + dst,
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}
}

func TestDNATCrossFamilyPoolRejected13922(t *testing.T) {
	for _, tc := range []struct{ name, dst, pool string }{
		{"v4 destination v6 pool", "203.0.113.10/32", "2001:db8::10/128"},
		{"v6 destination v4 pool", "2001:db8::10/128", "10.0.0.10/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, dnatFamilySet13922(tc.dst, tc.pool)))
			if err == nil || !strings.Contains(err.Error(), "address family") {
				t.Fatalf("cross-family DNAT (%s -> %s) must be rejected with a family diagnostic, got: %v", tc.dst, tc.pool, err)
			}
		})
	}
}

func TestDNATSameFamilyPoolCompiles13922(t *testing.T) {
	for _, tc := range []struct{ name, dst, pool string }{
		{"v4 to v4", "203.0.113.10/32", "10.0.0.10/32"},
		{"v6 to v6", "2001:db8::10/128", "2001:db8:1::10/128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, dnatFamilySet13922(tc.dst, tc.pool))); err != nil {
				t.Fatalf("same-family DNAT (%s -> %s) must compile, got: %v", tc.dst, tc.pool, err)
			}
		})
	}
}

func staticNATFamilySet13922(match, prefix string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security nat static rule-set rs1 from zone untrust",
		"set security nat static rule-set rs1 rule r1 match destination-address " + match,
		"set security nat static rule-set rs1 rule r1 then static-nat prefix " + prefix,
	}
}

func TestStaticNATCrossFamilyPairRejected13922(t *testing.T) {
	for _, tc := range []struct{ name, match, prefix string }{
		{"v4 external v6 internal", "203.0.113.5/32", "2001:db8::5/128"},
		{"v6 external v4 internal", "2001:db8::5/128", "10.0.0.5/32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, staticNATFamilySet13922(tc.match, tc.prefix)))
			if err == nil {
				t.Fatalf("cross-family static NAT (%s -> %s) committed CLEAN; dataplane builds a family-typed entry and drops it", tc.match, tc.prefix)
			}
			if !strings.Contains(err.Error(), "address family") {
				t.Fatalf("error must name the address-family mismatch, got: %v", err)
			}
		})
	}
}

func TestStaticNATSameFamilyPairCompiles13922(t *testing.T) {
	for _, tc := range []struct{ name, match, prefix string }{
		{"v4 to v4", "203.0.113.5/32", "10.0.0.5/32"},
		{"v6 to v6", "2001:db8::5/128", "2001:db8:1::5/128"},
		{"v4 block pair same family", "203.0.113.0/24", "10.0.0.0/24"},
		{"v6 block pair same family", "2001:db8::/64", "2001:db8:1::/64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, staticNATFamilySet13922(tc.match, tc.prefix))); err != nil {
				t.Fatalf("same-family static NAT (%s -> %s) must compile, got: %v", tc.match, tc.prefix, err)
			}
		})
	}
}

// Cross-family block pairs remain rejected by the existing static
// block/host-mask checks.
func TestStaticNATCrossFamilyBlockRejected13922(t *testing.T) {
	_, err := CompileConfig(buildTree(t, staticNATFamilySet13922("203.0.113.0/24", "2001:db8:1::/120")))
	if err == nil {
		t.Fatal("cross-family block static NAT committed CLEAN")
	}
}
