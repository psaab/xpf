package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13548: CompileUserspaceShim reaches CompileConfig -> compileNAT before any
// snapshot is built, even in userspace-only deployments. compileNAT hard-
// rejected two shapes the Rust userspace snapshot/DnatTable supports:
//
//   - a non-host CIDR `match destination-address` (198.51.100.0/24,
//     2001:db8:1::/64): dnatDestinationParts classifies it as a prefix and
//     DnatTable installs a longest-prefix-match entry (#3164) translating
//     every host in the block to the rule's (single-host) pool;
//   - a `then destination-nat off` exemption: the guard at the top of the
//     DNAT loop skipped it (PoolName == ""), so it never got a counter ID,
//     while the snapshot builder (#3844) installs the exemption keyed on
//     CounterID from CompileResult.NATCounterIDs — the exemption therefore
//     arrived at the Rust table with counter 0 ("no counter").
//
// Pool addresses stay host-only: DNATPoolHostIP /
// DestinationNATRuleExcludedReason and the Rust `pool_address.parse::<IpAddr>()`
// both support exactly one host, so a prefix pool must still be rejected.
//
// RED-on-revert: restoring either hard error (or the PoolName=="" skip)
// makes the matching case below fail.

func dnatShimCfg13548(rules []*config.NATRule, pools map[string]*config.NATPool) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Interfaces: []string{"ge-0-0-0"}},
	}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: pools,
		RuleSets: []*config.NATRuleSet{{
			Name:     "rs-dnat",
			FromZone: "untrust",
			Rules:    rules,
		}},
	}
	return cfg
}

func compileDNAT13548(t *testing.T, cfg *config.Config) (*CompileResult, error) {
	t.Helper()
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	err := compileNAT(idProbeDP{}, cfg, result)
	return result, err
}

// A non-host CIDR match destination (v4 and v6) must compile in the shim
// path, exactly as the snapshot builder + Rust table accept it.
func TestCompileNATDNATPrefixMatchCompiles13548(t *testing.T) {
	pools := map[string]*config.NATPool{
		"p1": {Name: "p1", Address: "10.0.0.5"},
		"p6": {Name: "p6", Address: "2001:db8::5"},
	}
	for _, tc := range []struct{ name, match, pool string }{
		{"v4-prefix", "198.51.100.0/24", "p1"},
		{"v6-prefix", "2001:db8:1::/64", "p6"},
		{"v4-host-cidr", "198.51.100.9/32", "p1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := dnatShimCfg13548([]*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{DestinationAddress: tc.match},
				Then:  config.NATThen{Type: config.NATDestination, PoolName: tc.pool},
			}}, pools)
			result, err := compileDNAT13548(t, cfg)
			if err != nil {
				t.Fatalf("compileNAT rejected Rust-supported DNAT match %q: %v", tc.match, err)
			}
			key := NATCounterKey(NATCounterTypeDest, "rs-dnat", "r1")
			if id, ok := result.NATCounterIDs[key]; !ok || id == 0 {
				t.Fatalf("NATCounterIDs[%q] = (%d, %v), want non-zero counter for prefix rule", key, id, ok)
			}
		})
	}
}

// The pool side stays host-only on every surface (Go predicate + Rust
// IpAddr parse), so a prefix pool address must still fail the shim compile
// rather than being silently coerced to its network base.
func TestCompileNATDNATPrefixPoolStillRejected13548(t *testing.T) {
	cfg := dnatShimCfg13548([]*config.NATRule{{
		Name:  "r1",
		Match: config.NATMatch{DestinationAddress: "198.51.100.9"},
		Then:  config.NATThen{Type: config.NATDestination, PoolName: "p1"},
	}}, map[string]*config.NATPool{
		"p1": {Name: "p1", Address: "10.0.0.0/24"},
	})
	if _, err := compileDNAT13548(t, cfg); err == nil {
		t.Fatal("compileNAT accepted a non-host DNAT pool prefix; Rust pool_address is a single host IpAddr")
	}
}

// A `then destination-nat off` exemption must receive a counter ID in the
// shim compile so the snapshot's CounterID lookup (natCounterID with
// NATCounterTypeDest) finds it instead of stamping 0.
func TestCompileNATDNATOffGetsCounterID13548(t *testing.T) {
	cfg := dnatShimCfg13548([]*config.NATRule{
		{
			Name:  "r-off",
			Match: config.NATMatch{DestinationAddress: "198.51.100.0/24"},
			Then:  config.NATThen{Type: config.NATDestination, Off: true},
		},
		{
			Name:  "r-pool",
			Match: config.NATMatch{DestinationAddress: "198.51.100.9"},
			Then:  config.NATThen{Type: config.NATDestination, PoolName: "p1"},
		},
	}, map[string]*config.NATPool{
		"p1": {Name: "p1", Address: "10.0.0.5"},
	})
	result, err := compileDNAT13548(t, cfg)
	if err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	for _, rule := range []string{"r-off", "r-pool"} {
		key := NATCounterKey(NATCounterTypeDest, "rs-dnat", rule)
		if id, ok := result.NATCounterIDs[key]; !ok || id == 0 {
			t.Errorf("NATCounterIDs[%q] = (%d, %v), want non-zero counter ID", key, id, ok)
		}
	}
	if result.NATCounterIDs[NATCounterKey(NATCounterTypeDest, "rs-dnat", "r-off")] ==
		result.NATCounterIDs[NATCounterKey(NATCounterTypeDest, "rs-dnat", "r-pool")] {
		t.Error("off and pool rules share a counter ID; hits would merge")
	}
}
