package config

import (
	"fmt"
	"strings"
	"testing"
)

// Tests for #5877: the per-field / per-member source-NAT pool gates bound ONE
// pool (a member's host count to MaxSourceNATPoolPrefixHosts, a pool's port
// range to 1..65535) but nothing bounded the AGGREGATE across a whole config —
// pool COUNT, the SUM of every pool's address cardinality, or total port
// capacity. Snapshot/apply builds a PortAllocator (a per-address occupancy
// bitmap sized to the port range) for each pool-mode rule BEFORE reuse dedup is
// known, so a large-but-syntactically-valid config forces multi-gigabyte
// allocator construction during a security-critical commit-apply. The fix
// (validateSourceNATAggregateCardinalityStrict, wired in
// compiler_uniformgates.go) rejects an over-budget config at commit, fail-closed,
// before apply builds any allocator state.
//
// The gate is scoped to the DISTINCT pools a pool-mode `then source-nat pool`
// rule references (the exact set apply expands into a PortAllocator), so the
// fixtures below define each pool AND reference it from a rule-set.
//
// FAIL-ON-REVERT: dropping the `if err :=
// validateSourceNATAggregateCardinalityStrict(cfg); ...` dispatch in
// compiler_uniformgates.go (or making the validator `return nil`) turns every
// over-budget reject case GREEN and so RED here.

// snat5877Tree builds a ConfigTree from a list of flat-set `set` commands.
// Mirrors the #5627 / #3906 pattern (ParseSetCommand + SetPath, never
// NewParser — the flat-set testing gotcha in CLAUDE.md).
func snat5877Tree(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	cmds = prependNATZoneDefs15001(cmds)
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// snat5877Pools emits, for each pool index in [0,nPools), a `security nat source
// pool p<i>` definition whose address is addrFor(i) (and, when portRange is
// non-empty, a `port range <portRange>`), PLUS a pool-mode rule that references
// it so the aggregate gate (scoped to referenced pools) counts it. All
// references live in one rule-set RS.
//
// addrFor MUST return a DISTINCT, non-overlapping address per pool: these
// fixtures exercise the AGGREGATE cardinality budgets (#5877), not overlap, and
// the #5144 external-tuple overlap gate independently rejects two referenced
// pools that share an address. distinctHostIP / distinctSlash16 below supply
// per-index addresses that preserve the host-count each budget test needs while
// staying non-overlapping.
func snat5877Pools(nPools int, addrFor func(i int) string, portRange string) []string {
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i := 0; i < nPools; i++ {
		cmds = append(cmds, fmt.Sprintf("set security nat source pool p%d address %s", i, addrFor(i)))
		if portRange != "" {
			cmds = append(cmds, fmt.Sprintf("set security nat source pool p%d port range %s", i, portRange))
		}
		cmds = append(cmds,
			fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", i),
			fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool p%d", i, i),
		)
	}
	return cmds
}

// distinctHostIP returns a distinct /32-host bare IP per pool index (host count 1
// each), so a large pool COUNT is exercised without any two pools sharing an
// address. 10.<i/256>.<i%256>.1 stays distinct for every index these tests use.
func distinctHostIP(i int) string {
	return fmt.Sprintf("10.%d.%d.1", i/256, i%256)
}

// distinctSlash16 returns a distinct, non-overlapping /16 per pool index (65,536
// hosts each) by varying the second octet, so the address- and port-capacity
// budgets are exercised without tripping the #5144 overlap gate.
func distinctSlash16(i int) string {
	return fmt.Sprintf("10.%d.0.0/16", i)
}

// TestSourceNATAggregatePoolCountRejected proves the pool-COUNT budget: a config
// referencing MaxSourceNATPoolCount+1 pools (each a single bare IP so the address
// and port-capacity budgets stay far under) is rejected at strict commit; a
// config referencing exactly MaxSourceNATPoolCount pools compiles clean.
func TestSourceNATAggregatePoolCountRejected(t *testing.T) {
	// Over budget by exactly one pool → rejected, naming the pool budget.
	_, err := CompileConfig(snat5877Tree(t, snat5877Pools(MaxSourceNATPoolCount+1, distinctHostIP, "")...))
	if err == nil {
		t.Fatalf("expected strict commit to reject %d pools (over the %d budget)",
			MaxSourceNATPoolCount+1, MaxSourceNATPoolCount)
	}
	for _, want := range []string{"distinct pools", "over the aggregate budget"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err.Error(), want)
		}
	}

	// Exactly at the budget → accepted (no false positive).
	if _, err := CompileConfig(snat5877Tree(t, snat5877Pools(MaxSourceNATPoolCount, distinctHostIP, "")...)); err != nil {
		t.Fatalf("exactly %d pools must compile clean on the strict path: %v", MaxSourceNATPoolCount, err)
	}
}

// TestSourceNATAggregateAddressesRejected proves the total-ADDRESS-cardinality
// budget. Each pool carries a /16 (MaxSourceNATPoolPrefixHosts hosts) and a
// tiny explicit port range so the port-capacity budget stays under while the
// address budget is exercised in isolation. 17 × /16 = 1,114,112 hosts exceeds
// the 16 × 65,536 = 1,048,576 budget; 16 × /16 sits exactly at the budget.
func TestSourceNATAggregateAddressesRejected(t *testing.T) {
	// Narrow port range (2 slots) keeps the port-capacity budget out of the way
	// so the address budget is what trips.
	over := snat5877Pools(17, distinctSlash16, "5000 to 5001")
	under := snat5877Pools(16, distinctSlash16, "5000 to 5001")

	_, err := CompileConfig(snat5877Tree(t, over...))
	if err == nil {
		t.Fatal("expected strict commit to reject 17 /16 pools (over the aggregate address budget)")
	}
	if !strings.Contains(err.Error(), "total pool addresses") {
		t.Fatalf("error %q does not name the total-pool-addresses budget", err.Error())
	}

	if _, err := CompileConfig(snat5877Tree(t, under...)); err != nil {
		t.Fatalf("16 /16 pools (exactly at the address budget) must compile clean: %v", err)
	}
}

// TestSourceNATAggregatePortCapacityRejected proves the total-PORT-capacity
// budget, the real occupancy-bitmap memory driver. Each pool is a /16 at the
// DEFAULT 1024-65535 PAT range (64,512 slots/address), so port capacity =
// 65,536 × 64,512 ≈ 4.23e9 slots per pool. Three such pools (≈1.27e10) exceed
// the 2^33 (≈8.59e9) budget while the address total (196,608) stays well under
// its own budget; two pools (≈8.46e9) sit just under.
func TestSourceNATAggregatePortCapacityRejected(t *testing.T) {
	// No explicit port range → defaults to the full 1024-65535 PAT range.
	over := snat5877Pools(3, distinctSlash16, "")
	under := snat5877Pools(2, distinctSlash16, "")

	_, err := CompileConfig(snat5877Tree(t, over...))
	if err == nil {
		t.Fatal("expected strict commit to reject 3 full-range /16 pools (over the aggregate port-capacity budget)")
	}
	if !strings.Contains(err.Error(), "total port slots") {
		t.Fatalf("error %q does not name the total-port-capacity budget", err.Error())
	}

	if _, err := CompileConfig(snat5877Tree(t, under...)); err != nil {
		t.Fatalf("2 full-range /16 pools (just under the port-capacity budget) must compile clean: %v", err)
	}
}

// TestSourceNATAggregateLenientWarns asserts the tolerant load / peer-sync path
// (#1960 no-brick) does NOT fail-closed on an over-budget config: it records a
// warning and boots (apply builds the state it always did, and the operator is
// warned to shrink it).
func TestSourceNATAggregateLenientWarns(t *testing.T) {
	cfg, err := CompileConfigLenient(snat5877Tree(t, snat5877Pools(MaxSourceNATPoolCount+1, distinctHostIP, "")...))
	if err != nil {
		t.Fatalf("lenient compile must not brick on an over-budget config: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "source-nat aggregate pool cardinality") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile must record a source-nat aggregate pool cardinality warning; warnings = %v", cfg.Warnings)
	}
}

// TestSourceNATAggregateUnreferencedPoolNotCounted pins the scoping decision:
// the gate counts only pools a pool-mode rule references (the set apply expands
// into a PortAllocator), so a large-but-UNREFERENCED pool that never reaches the
// allocator is not counted. A single unreferenced /16-per-pool set far over the
// aggregate budget (if it were counted) must still compile clean.
func TestSourceNATAggregateUnreferencedPoolNotCounted(t *testing.T) {
	cmds := []string{}
	for i := 0; i < 64; i++ { // 64 × /16 = 4,194,304 hosts — 4× over the address budget if counted
		cmds = append(cmds, fmt.Sprintf("set security nat source pool orphan%d address 203.0.113.0/16", i))
	}
	if _, err := CompileConfig(snat5877Tree(t, cmds...)); err != nil {
		t.Fatalf("unreferenced pools (never expanded by apply) must not be counted / rejected: %v", err)
	}
}

// TestSourceNATAggregateMemberHostCount pins the per-member host-count helper to
// the Rust expand_pool_address enumeration: a bare IP is one host, a CIDR its
// full prefix range, an unparseable member zero, and a >= /64-host v6 prefix
// saturates. This is the arithmetic the aggregate budgets sum over.
func TestSourceNATAggregateMemberHostCount(t *testing.T) {
	cases := []struct {
		addr string
		want uint64
	}{
		{"203.0.113.10", 1},
		{"203.0.113.10/32", 1},
		{"203.0.113.0/24", 256},
		{"100.64.0.0/16", 65536},
		{"2001:db8::1/128", 1},
		{"2001:db8::/112", 65536},
		{"not-an-ip", 0},
		{"203.0.113.1/garbage", 0},
		{"::/0", ^uint64(0)},    // saturates (2^128 hosts)
		{"10.0.0.0/0", 1 << 32}, // full v4 space
	}
	for _, tc := range cases {
		if got := sourceNATPoolMemberHostCount(tc.addr); got != tc.want {
			t.Errorf("sourceNATPoolMemberHostCount(%q) = %d, want %d", tc.addr, got, tc.want)
		}
	}
}
