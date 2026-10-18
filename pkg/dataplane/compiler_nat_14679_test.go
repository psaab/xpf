package dataplane

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14679 D8-03 arm 1: compileNAT64 auto-assign ignored singular pool.Address,
// prefix-expansion usability and PersistentNAT registration.
func TestCompileNAT64SingularPoolAddressAndPersistentNAT14679(t *testing.T) {
	persistent := &config.PersistentNATConfig{Permit: config.PersistentNATPermitAnyRemoteHost, InactivityTimeout: 600}
	cfg := &config.Config{
		Security: config.SecurityConfig{
			Zones: map[string]*config.ZoneConfig{"trust": {Name: "trust"}, "untrust": {Name: "untrust"}},
			NAT: config.NATConfig{
				SourcePools: map[string]*config.NATPool{
					"nat64-singular": {Name: "nat64-singular", Address: "198.51.100.7/32", PersistentNAT: persistent},
				},
				NAT64: []*config.NAT64RuleSet{{Name: "n64", Prefix: "64:ff9b::/96", SourcePool: "nat64-singular"}},
			},
		},
	}
	pnat := NewPersistentNATTable()
	dp := &persistentPoolDP14110{pnat: pnat}
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	if err := compileNAT(dp, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	if err := compileNAT64(dp, cfg, result); err != nil {
		t.Fatalf("compileNAT64 failed on singular pool.Address: %v", err)
	}
	if pool, _, ok := pnat.LookupPool(netip.MustParseAddr("198.51.100.7")); !ok || pool != "nat64-singular" {
		t.Fatalf("LookupPool(198.51.100.7) = %q, ok=%v; want nat64-singular", pool, ok)
	}
}

// Poisoned NAT64-only pool: any unusable member must fail validate (not silently skip),
// and must register nothing.
func TestCompileNAT64PoisonedPoolRejected14679(t *testing.T) {
	for _, tc := range []struct {
		name  string
		addrs []string
		addr  string
	}{
		{name: "bad-member", addrs: []string{"not-an-ip", "203.0.113.7/32"}},
		{name: "non-host-prefix", addrs: []string{"203.0.113.0/24"}},
		{name: "ipv6-member", addrs: []string{"2001:db8::5/128"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			persistent := &config.PersistentNATConfig{Permit: config.PersistentNATPermitAnyRemoteHost, InactivityTimeout: 600}
			pool := &config.NATPool{Name: "p1", Addresses: tc.addrs, PersistentNAT: persistent}
			if tc.addr != "" {
				pool.Address = tc.addr
			}
			cfg := &config.Config{Security: config.SecurityConfig{
				Zones: map[string]*config.ZoneConfig{"trust": {Name: "trust"}},
				NAT: config.NATConfig{
					SourcePools: map[string]*config.NATPool{"p1": pool},
					NAT64:       []*config.NAT64RuleSet{{Name: "n64", Prefix: "64:ff9b::/96", SourcePool: "p1"}},
				},
			}}
			pnat := NewPersistentNATTable()
			dp := &persistentPoolDP14110{pnat: pnat}
			result := newValidationResult()
			assignZoneIDs(result, cfg)
			if err := compileNAT(dp, cfg, result); err != nil {
				t.Fatalf("compileNAT: %v", err)
			}
			err := compileNAT64(dp, cfg, result)
			if err == nil {
				t.Fatalf("compileNAT64 accepted poisoned NAT64 pool %v; want hard error (helper skips whole rule)", tc.addrs)
			}
			if !strings.Contains(err.Error(), "no valid addresses") {
				t.Fatalf("error = %v, want no-valid-addresses rejection", err)
			}
			// Nothing registered for the poisoned pool.
			for _, a := range []string{"203.0.113.7", "203.0.113.0"} {
				if poolName, _, ok := pnat.LookupPool(netip.MustParseAddr(a)); ok {
					t.Fatalf("LookupPool(%s)=%q for poisoned pool; want miss", a, poolName)
				}
			}
		})
	}
}

// Control: a plain valid Addresses pool still compiles and registers.
func TestCompileNAT64ValidAddressesPoolRegisters14679(t *testing.T) {
	persistent := &config.PersistentNATConfig{Permit: config.PersistentNATPermitAnyRemoteHost, InactivityTimeout: 600}
	cfg := &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{"trust": {Name: "trust"}},
		NAT: config.NATConfig{
			SourcePools: map[string]*config.NATPool{"p1": {Name: "p1", Addresses: []string{"198.51.100.7/32", "198.51.100.8"}, PersistentNAT: persistent}},
			NAT64:       []*config.NAT64RuleSet{{Name: "n64", Prefix: "64:ff9b::/96", SourcePool: "p1"}},
		},
	}}
	pnat := NewPersistentNATTable()
	dp := &persistentPoolDP14110{pnat: pnat}
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	if err := compileNAT(dp, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	if err := compileNAT64(dp, cfg, result); err != nil {
		t.Fatalf("compileNAT64: %v", err)
	}
	for _, a := range []string{"198.51.100.7", "198.51.100.8"} {
		if pool, _, ok := pnat.LookupPool(netip.MustParseAddr(a)); !ok || pool != "p1" {
			t.Fatalf("LookupPool(%s)=%q,%v want p1", a, pool, ok)
		}
	}
}

// Arm 2: a compile failure after entry must not wipe prior pool configs.
func TestCompileNATFailurePreservesPersistentPools14679(t *testing.T) {
	pnat := compilePersistentPools14110(t)
	if _, _, ok := pnat.LookupPool(netip.MustParseAddr("192.0.2.5")); !ok {
		t.Fatal("precondition: 192.0.2.5 not registered")
	}
	// Failing config: source rule-set references unknown zone (error at compileNAT top checks).
	cfg := persistentPoolCfg14110()
	cfg.Security.NAT.Source[0].FromZone = "no-such-zone"
	// Keep stamp: FromZone non-empty so HasNATFromScopeStamp true, zone lookup fails.
	result := newValidationResult()
	assignZoneIDs(result, persistentPoolCfg14110())
	if err := compileNAT(&persistentPoolDP14110{pnat: pnat}, cfg, result); err == nil {
		t.Fatal("expected compileNAT to fail on unknown zone")
	}
	if _, _, ok := pnat.LookupPool(netip.MustParseAddr("192.0.2.5")); !ok {
		t.Fatal("failed compileNAT wiped prior persistent pool configs (192.0.2.5 lost)")
	}
	if _, _, ok := pnat.LookupPool(netip.MustParseAddr("198.51.100.7")); !ok {
		t.Fatal("failed compileNAT wiped singular pool registration")
	}
}

// Successful recompile still removes stale pools (atomic swap semantics).
func TestCompileNATSuccessRemovesStalePools14679(t *testing.T) {
	pnat := compilePersistentPools14110(t)
	// Recompile with empty NAT: stale pools must be gone after success.
	cfg := &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{"trust": {Name: "trust"}, "untrust": {Name: "untrust"}},
		NAT:   config.NATConfig{SourcePools: map[string]*config.NATPool{}},
	}}
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	if err := compileNAT(&persistentPoolDP14110{pnat: pnat}, cfg, result); err != nil {
		t.Fatalf("compileNAT empty: %v", err)
	}
	if _, _, ok := pnat.LookupPool(netip.MustParseAddr("192.0.2.5")); ok {
		t.Fatal("stale pool still resolves after successful empty recompile")
	}
}

// Arm 3: DNAT rule-set that lost its from stamp via JSON round-trip (lenient/peer-sync producer)
// must be rejected by compileNAT, like source NAT.
func TestCompileNATRejectsUnstampedDNAT14679(t *testing.T) {
	// Build via config compiler so DNAT gets stamped, then JSON round-trip to lose stamp.
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat destination pool dpool address 10.0.0.5/32",
		"set security nat destination rule-set DRS rule r1 match destination-address 203.0.113.5/32",
		"set security nat destination rule-set DRS rule r1 then destination-nat pool dpool",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand %q: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		t.Fatal("fixture produced no DNAT rule-sets")
	}
	if !cfg.Security.NAT.Destination.RuleSets[0].HasNATFromScopeStamp() {
		t.Fatal("precondition: lenient DNAT should be stamped (absent from = stamped match-any)")
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var rt config.Config
	if err := json.Unmarshal(encoded, &rt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rs := rt.Security.NAT.Destination.RuleSets[0]
	if rs.HasNATFromScopeStamp() {
		t.Fatal("precondition: JSON round-trip should lose unexported stamp for empty from scope")
	}
	result := newValidationResult()
	assignZoneIDs(result, &rt)
	err = compileNAT(idProbeDP{}, &rt, result)
	if err == nil || !strings.Contains(err.Error(), `destination NAT from-zone "" not found`) {
		t.Fatalf("unstamped DNAT error = %v, want destination NAT from-zone \"\" not found", err)
	}
	// Control: stamped original passes.
	result2 := newValidationResult()
	assignZoneIDs(result2, cfg)
	if err := compileNAT(idProbeDP{}, cfg, result2); err != nil {
		t.Fatalf("stamped DNAT control failed: %v", err)
	}
}
