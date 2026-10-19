package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15278 D02-01: empty NAT64 prefix must not abort validateBeforeMutate / real compile.
func TestNAT64EmptyPrefixValidateBeforeMutate15278(t *testing.T) {
	cfg := emptyCfgWith(func(c *config.Config) {
		c.Security.NAT.SourcePools = map[string]*config.NATPool{
			"p64": {Name: "p64", Address: "100.64.0.7/32", Addresses: []string{"100.64.0.7/32"}},
		}
		c.Security.NAT.NAT64 = []*config.NAT64RuleSet{
			{Name: "rs1", Prefix: "", SourcePool: "p64"},
			{Name: "rs-good", Prefix: "64:ff9b::/96", SourcePool: "p64"},
		}
	})
	if err := validateBeforeMutate(cfg); err != nil {
		t.Fatalf("validateBeforeMutate must skip empty-prefix NAT64, got: %v", err)
	}
	// Real pass also must not abort on empty prefix.
	result := &CompileResult{PoolIDs: make(map[string]uint8)}
	if err := compileNAT64(idProbeDP{}, cfg, result); err != nil {
		t.Fatalf("compileNAT64 real pass must skip empty-prefix, got: %v", err)
	}
}
