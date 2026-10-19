package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15000 A08-02: compileNAT64 must warn-and-skip a rule-set whose source pool
// is empty/undefined instead of returning an error that aborts the whole
// #4960 pre-pass / dataplane compile. Defined-pool control stays green.

func nat64Cfg15000(sourcePool string, pools map[string]*config.NATPool) *config.Config {
	if pools == nil {
		pools = map[string]*config.NATPool{}
	}
	return &config.Config{Security: config.SecurityConfig{
		Zones: map[string]*config.ZoneConfig{"trust": {Name: "trust"}},
		NAT: config.NATConfig{
			SourcePools: pools,
			NAT64:       []*config.NAT64RuleSet{{Name: "rs1", Prefix: "64:ff9b::/96", SourcePool: sourcePool}},
		},
	}}
}

func TestCompileNAT64UndefinedPoolWarnSkips15000(t *testing.T) {
	cfg := nat64Cfg15000("missing-pool", nil)
	result := newValidationResult()
	if err := compileNAT64(discardingDataPlane{}, cfg, result); err != nil {
		t.Fatalf("compileNAT64 must warn-skip undefined pool, got error: %v", err)
	}
	if _, ok := result.PoolIDs["missing-pool"]; ok {
		t.Fatalf("undefined pool must not be assigned an ID")
	}
}

func TestCompileNAT64OmittedPoolWarnSkips15000(t *testing.T) {
	cfg := nat64Cfg15000("", nil)
	result := newValidationResult()
	if err := compileNAT64(discardingDataPlane{}, cfg, result); err != nil {
		t.Fatalf("compileNAT64 must warn-skip omitted pool, got error: %v", err)
	}
}

func TestValidateBeforeMutateUndefinedNAT64Pool15000(t *testing.T) {
	// Mixed: one bad rule-set (missing pool) + one good rule-set.
	// Pre-pass must return nil and the good pool must still be numbered.
	pools := map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.7/32"}},
	}
	cfg := nat64Cfg15000("missing-pool", pools)
	cfg.Security.NAT.NAT64 = append(cfg.Security.NAT.NAT64,
		&config.NAT64RuleSet{Name: "good", Prefix: "64:ff9b:1::/96", SourcePool: "p64"})
	result := newValidationResult()
	if err := validateBeforeMutateWithResult(discardingDataPlane{}, cfg, result); err != nil {
		t.Fatalf("validateBeforeMutate must return nil for undefined NAT64 pool, got: %v", err)
	}
	if _, ok := result.PoolIDs["p64"]; !ok {
		t.Fatalf("defined-pool rule-set must still be compiled, PoolIDs=%v", result.PoolIDs)
	}
	if _, ok := result.PoolIDs["missing-pool"]; ok {
		t.Fatalf("missing pool must not get an ID")
	}
}

func TestCompileNAT64DefinedPoolControl15000(t *testing.T) {
	pools := map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"100.64.0.7/32"}},
	}
	cfg := nat64Cfg15000("p64", pools)
	result := newValidationResult()
	if err := compileNAT64(discardingDataPlane{}, cfg, result); err != nil {
		t.Fatalf("defined pool must compile: %v", err)
	}
	if _, ok := result.PoolIDs["p64"]; !ok {
		t.Fatalf("defined pool must be auto-assigned, PoolIDs=%v", result.PoolIDs)
	}
}
