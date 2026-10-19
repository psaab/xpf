package config

import (
	"strings"
	"testing"
)

// #15177 (C05-01): the deterministic CGNAT capacity gate counted OTHER-family
// pool members. A mixed pool with one usable IPv4 address (63 blocks at
// block-size 1024) plus a v6 /112 (65536 hosts, clamped by the sum to a huge
// count) committed clean for a /20 IPv4 subscriber (4096), yet Rust builds
// deterministic_v4 only from pool_addresses_v4 (1 address) — so subscribers
// past the first 63 get AllocatorExhausted at runtime.

func deterministicMixedPoolCmds15177(extra string, subscriber string) []string {
	cmds := []string{
		"set security nat source pool CG address 203.0.113.1",
	}
	if extra != "" {
		cmds = append(cmds, "set security nat source pool CG address "+extra)
	}
	return append(cmds,
		"set security nat source pool CG port deterministic block-size 1024",
		"set security nat source pool CG port deterministic host address "+subscriber,
	)
}

// FAIL-ON-REVERT: at base this committed clean (v6 hosts inflated the count).
func TestDeterministicCapacityIgnoresV6MembersForV4Subscriber15177(t *testing.T) {
	_, err := CompileConfig(natOverlapTree(t, deterministicMixedPoolCmds15177("2001:db8::/112", "100.64.0.0/20")...))
	if err == nil || !strings.Contains(err.Error(), "insufficient capacity (63 blocks) for 4096 subscribers") {
		t.Fatalf("#15177: 1 v4 addr (63 blocks) + v6 /112 must reject a /20 v4 subscriber with the v4-only count; got: %v", err)
	}
}

// FAIL-ON-REVERT: IPv4-mapped v6 textual members land in Rust pool_addresses_v6
// (colon-bearing), not v4 — they must not inflate the v4 gate either.
func TestDeterministicCapacityIgnoresV4MappedMembersForV4Subscriber15177(t *testing.T) {
	_, err := CompileConfig(natOverlapTree(t, deterministicMixedPoolCmds15177("::ffff:203.0.113.9", "100.64.0.0/20")...))
	if err == nil || !strings.Contains(err.Error(), "insufficient capacity (63 blocks) for 4096 subscribers") {
		t.Fatalf("#15177: v4-mapped member must not count toward v4 deterministic capacity; got: %v", err)
	}
}

// CONTROL (twin): same subscriber with a genuine v4 /25 pool (128 addrs x 63 =
// 8064 blocks >= 4096) still commits — the fix must not over-reject v4 capacity.
func TestDeterministicCapacityV4PoolStillCommits15177(t *testing.T) {
	cmds := []string{
		"set security nat source pool CG address 203.0.113.0/25",
		"set security nat source pool CG port deterministic block-size 1024",
		"set security nat source pool CG port deterministic host address 100.64.0.0/20",
	}
	if _, err := CompileConfig(natOverlapTree(t, cmds...)); err != nil {
		t.Fatalf("#15177 control: v4 /25 pool fits /20 subscriber and must commit; got: %v", err)
	}
}

// FAIL-ON-REVERT (overlap): Rust dedupes expanded v4 addresses
// (seen_v4 first-occurrence). A /28 (16 addrs, 1008 blocks) plus a host
// inside it counts 1008, not 1071 — both reject a /20 (4096), so the exact
// message pins the unique count.
func TestDeterministicCapacityDedupesOverlappingV4Members15177(t *testing.T) {
	cmds := []string{
		"set security nat source pool CG address 203.0.113.0/28",
		"set security nat source pool CG address 203.0.113.1",
		"set security nat source pool CG port deterministic block-size 1024",
		"set security nat source pool CG port deterministic host address 100.64.0.0/20",
	}
	_, err := CompileConfig(natOverlapTree(t, cmds...))
	if err == nil || !strings.Contains(err.Error(), "insufficient capacity (1008 blocks) for 4096 subscribers") {
		t.Fatalf("#15177: overlapping v4 members must count once (1008 blocks); got: %v", err)
	}
}

// CONTROL: IPv6 subscriber (mode 2) gate counts only v4 pool members too —
// Rust NAT64 pool_v4 holds bare//32 v4 hosts only. One v4 host = 63 blocks;
// the gate's v6 arm only requires totalBlocks>0 today, so this pins that a
// pure-v6 pool still rejects (0 blocks) and a v4-bearing pool still commits.
func TestDeterministicCapacityV6SubscriberZeroV4StillRejects15177(t *testing.T) {
	cmds := []string{
		"set security nat source pool CG address 2001:db8::/112",
		"set security nat source pool CG port deterministic block-size 1024",
		"set security nat source pool CG port deterministic host address 2001:db8::/64",
	}
	_, err := CompileConfig(natOverlapTree(t, cmds...))
	if err == nil || !strings.Contains(err.Error(), "insufficient capacity (0 blocks)") {
		t.Fatalf("#15177: v6-host pool with no v4 members must keep rejecting (0 blocks); got: %v", err)
	}
}
