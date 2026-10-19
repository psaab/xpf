package api

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15177: deterministicPoolBlockCapacity must use the same v4-only count as
// the compiler gate. A mixed pool (1 v4 + v6 /112) has 63 blocks at
// block-size 1024, not the all-family expanded count.
func TestDeterministicPoolBlockCapacityFamily15177(t *testing.T) {
	pool := &config.NATPool{
		Address:   "203.0.113.1",
		Addresses: []string{"2001:db8::/112", "::ffff:203.0.113.9"},
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   1024,
			HostAddress: "100.64.0.0/20",
		},
	}
	if got := deterministicPoolBlockCapacity(pool, "p", nil); got != 63 {
		t.Fatalf("#15177: mixed pool capacity = %d, want 63 (1 v4 x 63 blocks)", got)
	}
	// Mode 2: only bare//32 v4 hosts count; a v4 /25 prefix is filtered by
	// NAT64 parse_pool_v4, duplicates count (no dedupe there).
	v6Pool := &config.NATPool{
		Addresses: []string{"203.0.113.0/25", "203.0.113.1/32", "203.0.113.1", "2001:db8::1"},
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   2016,
			HostAddress: "2001:db8::/32",
		},
	}
	// NAT64 range 64512/2016 = 32 blocks per counted host; 2 counted hosts.
	if got := deterministicPoolBlockCapacity(v6Pool, "p", nil); got != 64 {
		t.Fatalf("#15177: mode-2 capacity = %d, want 64 (2 bare//32 v4 hosts x 32)", got)
	}
}
