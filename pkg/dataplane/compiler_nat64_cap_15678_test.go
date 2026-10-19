package dataplane

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15678: the retired MAX_NAT64_PREFIXES=4 guard broke out of
// compileNAT64WithStaging after four rule-sets, so a 5th+ rule-set existed
// in the userspace snapshot but never got a pool ID or persistent-NAT
// registration. Fail-on-revert: restoring the cap leaves rs5's pool
// unregistered and this test fails.
func TestCompileNAT64FivePrefixesAllRegistered15678(t *testing.T) {
	persistent := &config.PersistentNATConfig{Permit: config.PersistentNATPermitAnyRemoteHost, InactivityTimeout: 600}
	pools := map[string]*config.NATPool{}
	var ruleSets []*config.NAT64RuleSet
	for i := 1; i <= 5; i++ {
		poolName := fmt.Sprintf("p64-%d", i)
		addr := fmt.Sprintf("100.64.0.%d/32", i)
		pools[poolName] = &config.NATPool{Name: poolName, Addresses: []string{addr}, PersistentNAT: persistent}
		ruleSets = append(ruleSets, &config.NAT64RuleSet{
			Name:       fmt.Sprintf("rs%d", i),
			Prefix:     fmt.Sprintf("64:ff9b:%d::/96", i),
			SourcePool: poolName,
		})
	}
	cfg := &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{"trust": {Name: "trust"}},
		NAT:   config.NATConfig{SourcePools: pools, NAT64: ruleSets},
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
	for i := 1; i <= 5; i++ {
		poolName := fmt.Sprintf("p64-%d", i)
		if _, ok := result.PoolIDs[poolName]; !ok {
			t.Fatalf("pool %s (rule-set %d) got no pool ID — the 4-prefix cap is back", poolName, i)
		}
		addr := netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", i))
		if pool, _, ok := pnat.LookupPool(addr); !ok || pool != poolName {
			t.Fatalf("LookupPool(%s) = %q,%v; want %s (persistent-NAT registration missing)", addr, pool, ok, poolName)
		}
	}
}
