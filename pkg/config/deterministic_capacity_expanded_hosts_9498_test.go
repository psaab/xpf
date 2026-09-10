package config

import (
	"strings"
	"testing"
)

// #9498: the deterministic capacity gate counted address STATEMENTS, so a CIDR
// member counted once. One /24 statement (256 hosts) at block-size 1024
// (63 blocks per address) has 16,128 blocks. Counted as a single address it had
// 63, and a /20 subscriber (4,096 hosts) was rejected although the pool fits it.

func deterministicPoolCmds9498(subscriber string) []string {
	return []string{
		"set security nat source pool CG address 203.0.113.0/24",
		"set security nat source pool CG port deterministic block-size 1024",
		"set security nat source pool CG port deterministic host address " + subscriber,
	}
}

// FAIL-ON-REVERT: rejected before #9498 as "insufficient capacity (63 blocks)".
func TestDeterministicCapacityCountsExpandedPoolHosts9498(t *testing.T) {
	if _, err := CompileConfig(natOverlapTree(t, deterministicPoolCmds9498("100.64.0.0/20")...)); err != nil {
		t.Fatalf("#9498: a /24 pool (256 hosts x 63 blocks = 16,128) fits a /20 subscriber (4,096); the gate must "+
			"count EXPANDED hosts, not the one address statement. got: %v", err)
	}
}

// CONTROL: the gate still bites, in the expanded unit. 16,128 blocks < 65,536 subscribers.
func TestDeterministicCapacityStillRejectsAnOversizedSubscriberPrefix9498(t *testing.T) {
	_, err := CompileConfig(natOverlapTree(t, deterministicPoolCmds9498("100.64.0.0/16")...))
	if err == nil || !strings.Contains(err.Error(), "insufficient capacity (16128 blocks) for 65536 subscribers") {
		t.Fatalf("#9498 control: a /16 subscriber exceeds the pool's 16,128 expanded blocks and must be rejected with "+
			"the EXPANDED count in the message; got: %v", err)
	}
}
