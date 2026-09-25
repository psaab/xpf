package config

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// Tests for #6812 (opus-review-001 R73): SourceNATAggregateOverBudgetPools —
// the deterministic FIRST-FIT admission that picks WHICH referenced pools do
// not fit the #5877 aggregate budgets, so the tolerant snapshot builder
// (pkg/dataplane/userspace/nat_source.go) can poison exactly those pools
// instead of shipping them to a dataplane that would eagerly build their
// per-address occupancy bitmaps (three full-range /16 pools = 12,683,575,296
// bitmap bits, ~1.48 GiB).
//
// The fixtures reuse the #5877 helpers (snat5877Tree / snat5877Pools /
// distinctSlash16 / distinctHostIP) and compile via the LENIENT path: the
// strict path rejects these configs outright, so the poison set only ever
// matters for tolerated configs.
//
// FAIL-ON-REVERT: any change that drops pools from the poison set (or stops
// charging a budget) turns the over-budget cases GREEN -> RED here; a change
// that over-rejects (poisons pools that fit) turns the at-budget / first-fit
// cases RED.

// poisonSet compiles the fixture leniently and returns the over-budget pool
// set, failing the test on compile error.
func poisonSet(t *testing.T, cmds ...string) map[string]bool {
	t.Helper()
	cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return SourceNATAggregateOverBudgetPools(cfg)
}

func assertPoison(t *testing.T, got map[string]bool, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("poison set = %v, want exactly %v", got, want)
	}
	for _, name := range want {
		if !got[name] {
			t.Fatalf("poison set = %v, missing %q (want %v)", got, name, want)
		}
	}
}

// TestAggregateOverBudgetPoolsPortCapacity_6812 pins the port-capacity
// budget walk on the review's exact scenario: three full-range /16 pools
// (65,536 addresses x 64,512 default PAT slots ≈ 4.23e9 each). Two fit under
// 2^33; the third does not — and ONLY the third is poisoned.
func TestAggregateOverBudgetPoolsPortCapacity_6812(t *testing.T) {
	assertPoison(t,
		poisonSet(t, snat5877Pools(3, distinctSlash16, "")...),
		"p2")
	// Two full-range /16 pools sit just under the budget: nothing poisoned.
	assertPoison(t,
		poisonSet(t, snat5877Pools(2, distinctSlash16, "")...))
}

// TestAggregateOverBudgetPoolsAddresses_6812 pins the total-address budget:
// 17 x /16 = 1,114,112 hosts exceeds 1,048,576; only pool 16 is poisoned.
func TestAggregateOverBudgetPoolsAddresses_6812(t *testing.T) {
	assertPoison(t,
		poisonSet(t, snat5877Pools(17, distinctSlash16, "5000 to 5001")...),
		"p16")
	// Exactly at the budget: nothing poisoned.
	assertPoison(t,
		poisonSet(t, snat5877Pools(16, distinctSlash16, "5000 to 5001")...))
}

// #10700: Go's tolerated-load aggregate budget must charge the unique expanded
// addresses the Rust parser installs, not repeated member host counts.
func TestAggregateBudgetCountsUniqueExpandedMembers10700(t *testing.T) {
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i := range 17 {
		// SetPath retains these distinct host-bit spellings, but each /16
		// expands to the same network address set.
		cmds = append(cmds, fmt.Sprintf("set security nat source pool p address 10.0.%d.0/16", i))
	}
	cmds = append(cmds,
		"set security nat source rule-set RS rule r1 match source-address 192.0.2.0/24",
		"set security nat source rule-set RS rule r1 then source-nat pool p",
	)
	cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	members := SourceNATPoolMembers(cfg.Security.NAT.SourcePools["p"])
	if len(members) != 17 {
		t.Fatalf("pool members = %d, want 17 distinct configured spellings: %v", len(members), members)
	}
	if got := sourceNATPoolUniqueAddressCount(members); got != 1<<16 {
		t.Fatalf("unique expanded addresses = %d, want 65536", got)
	}
	if got := SourceNATAggregateOverBudgetPools(cfg); got["p"] {
		t.Fatalf("overlapping /16 members were charged 17 times and poisoned their pool: %v", got)
	}
}

// TestAggregateOverBudgetPoolsCount_6812 pins the distinct-pool COUNT
// budget: pools 0..1023 fit, pool 1024 (the 1025th) is poisoned.
func TestAggregateOverBudgetPoolsCount_6812(t *testing.T) {
	assertPoison(t,
		poisonSet(t, snat5877Pools(MaxSourceNATPoolCount+1, distinctHostIP, "")...),
		fmt.Sprintf("p%d", MaxSourceNATPoolCount))
}

// TestAggregateOverBudgetPoolsFirstFit_6812 pins the first-fit-continue
// rule (parity with the Rust resolve_pool_allocators): a pool that is
// refused does NOT consume budget, so a later, smaller pool still installs.
// p1 alone (17 x /16 members = 1,114,112 addresses) exceeds the address
// budget by itself; p0 and p2 are tiny and must survive.
func TestAggregateOverBudgetPoolsFirstFit_6812(t *testing.T) {
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
		"set security nat source pool p0 address 203.0.113.1/32",
		"set security nat source rule-set RS rule r0 match source-address 10.0.0.0/24",
		"set security nat source rule-set RS rule r0 then source-nat pool p0",
	}
	// p1: 17 distinct /16 members in ONE pool — over the 1,048,576-address
	// aggregate budget on its own.
	for i := 0; i < 17; i++ {
		cmds = append(cmds, fmt.Sprintf("set security nat source pool p1 address 10.%d.0.0/16", i))
	}
	cmds = append(cmds,
		"set security nat source rule-set RS rule r1 match source-address 10.0.1.0/24",
		"set security nat source rule-set RS rule r1 then source-nat pool p1",
		"set security nat source pool p2 address 203.0.113.2/32",
		"set security nat source rule-set RS rule r2 match source-address 10.0.2.0/24",
		"set security nat source rule-set RS rule r2 then source-nat pool p2",
	)
	assertPoison(t, poisonSet(t, cmds...), "p1")
}

// TestAggregateOverBudgetPoolsUnreferenced_6812 pins the scoping parity with
// the strict gate: pools no pool-mode rule references never reach the
// allocator and are never poisoned, however large.
func TestAggregateOverBudgetPoolsUnreferenced_6812(t *testing.T) {
	cmds := []string{}
	for i := 0; i < 64; i++ {
		cmds = append(cmds, fmt.Sprintf("set security nat source pool orphan%d address 203.0.113.0/16", i))
	}
	assertPoison(t, poisonSet(t, cmds...))
}

// snat6812UnusablePools emits `n` referenced pools that the snapshot builder
// will independently mark UNUSABLE (poolCmds decides how), followed by ONE
// small healthy pool "good" referenced LAST. Every unusable pool carries a
// single distinct /32 so the ONLY aggregate axis these fixtures can cross is
// the distinct-pool COUNT — the address and port-capacity budgets stay orders
// of magnitude below their limits, so a poison verdict here cannot be
// attributed to another axis.
func snat6812UnusablePools(n int, poolCmds func(i int, name string) []string) []string {
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("bad%d", i)
		cmds = append(cmds, poolCmds(i, name)...)
		cmds = append(cmds,
			fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", i),
			fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool %s", i, name),
		)
	}
	// The healthy pool is referenced LAST, so under the first-fit walk it is
	// the one an over-charge of the unusable pools would refuse.
	return append(cmds,
		"set security nat source pool good address 198.51.100.7/32",
		"set security nat source pool good port range 10000 to 10009",
		fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", n),
		fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool good", n),
	)
}

// TestAggregateBudgetExcludesUnusablePools_6812 is the #6812 F1 regression
// (Codex gate finding): a pool the snapshot builder ALREADY marks unusable
// builds NO allocator in the dataplane — the Rust parse loop gates
// `PendingPoolAllocator` on `pool_failure.is_none()`
// (userspace-dp/src/nat/source.rs), so a failed pool is never charged and
// never occupies a slot in `resolve_pool_allocators`' first-fit walk. Charging
// it Go-side therefore refuses a pool Rust would admit.
//
// The concrete damage is fail-closed OVER-rejection on the TOLERANT recovery
// path — a lenient load / peer-sync (#1960 no-brick) is precisely how an
// operator gets back to a working state, and this took a healthy pool down
// with the broken ones. MaxSourceNATPoolCount unusable pools exactly fill the
// count budget, so the healthy pool referenced after them was poisoned as
// number 1,025.
//
// The dataplane half of the parity claim is
// `production_entry_admits_a_healthy_pool_after_failed_pools_6812`
// (userspace-dp/src/nat/tests_aggregate_budget.rs), which drives the SAME
// scenario — MaxSourceNATPoolCount unusable pools then one healthy pool —
// through the Rust production entry and asserts the healthy pool installs a
// real allocator. The snapshot-shape half (that Go actually emits the
// `pool_unusable` markers that test consumes) is
// TestSourceNATSnapshotUnusablePoolsDoNotPoisonHealthy_6812
// (pkg/dataplane/userspace).
//
// RED-on-revert: restore the unconditional charge in
// sourceNATAggregateReferencedCharges and the poison set comes back
// {"good"} — the healthy pool disabled by pools that install nothing.
func TestAggregateBudgetExcludesUnusablePools_6812(t *testing.T) {
	cases := []struct {
		name string
		// wantReason is what SourceNATPoolUnusableReason must say about the
		// fixture's pools. Every case now names a reason: since round 2 the
		// shared verdict is the ONLY exclusion, so a "" here would mean the pool
		// is charged and the case is not testing an exclusion at all.
		wantReason string
		// wantSum is the round-1 host-count sum for ONE of these pools — the
		// derived quantity the budget walk used to consult. It is asserted
		// exactly, because it is what separates the classes: a case with sum 0
		// was already excluded by the old zero-total rule, while a case with a
		// NON-ZERO sum was charged by round 1 and is only excluded now that the
		// walk asks the runtime's all-or-nothing question instead. Without this
		// the two round-2 cases would be indistinguishable from the round-1 ones
		// and could pass on the old code path.
		wantSum uint64
		cmds    func(i int, name string) []string
		about   string
	}{
		{
			name:       "invalid_port_range",
			wantReason: "invalid_port_range",
			wantSum:    1, // one /32 member
			about:      "a reversed `port range` leaves PortRangeInvalidSpec set (#5457); the builder marks the pool unusable",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address 10.%d.%d.1/32", name, i/256, i%256),
					fmt.Sprintf("set security nat source pool %s port range 20000 to 10000", name),
				}
			},
		},
		{
			name:       "zone_scoped_pool_address",
			wantReason: "zone_scoped_pool_address",
			// sourceNATPoolMemberHostCount still counts 1 (netip.ParseAddr
			// honors a zone) — it is the GRAMMAR predicate, not the counter,
			// that round 3 narrowed.
			wantSum: 1,
			// RE-CUT IN ROUND 3 — this cell now binds PRECEDENCE, not just zone
			// detection. Through round 2 the bare `fe80::1%eth0` passed
			// sourceNATPoolAddressReason (netip carries a zone), so
			// zone_scoped_pool_address was the ONLY clause that fired and the
			// clause ORDER did not matter to it. Round 3 made the grammar
			// clause reject a zone too (std::net::IpAddr has no zone model, so
			// the runtime refused this member all along), so the pool now trips
			// BOTH clauses and this assertion holds only because the zone
			// clause is written AFTER the grammar clause.
			// TestZoneScopedBarePoolAddressKeepsItsSpecificReason_6812 states
			// that as its own claim.
			about: "a `%zone` member is not dataplane-representable (#5875); the builder marks the pool unusable",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address fe80::%d%%eth0", name, i+1),
				}
			},
		},
		{
			name:       "empty_pool",
			wantReason: "empty_pool",
			wantSum:    0, // no members at all
			about:      "a referenced pool with no address member ships nothing; the builder marks the pool unusable",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s port range 10000 to 10009", name),
				}
			},
		},
		{
			// RE-CUT IN ROUND 2. This cell used to assert wantReason "": the
			// pool definition looked fine (members present, no zone qualifier,
			// valid port range), so the shared predicate said nothing and the
			// budget walk skipped the pool only because its members summed to
			// ZERO expanded addresses. It now binds through the shared verdict
			// instead — the membership grammar clause rejects the member, so the
			// pool is excluded for the same reason every other unusable pool is.
			// The cell is NOT green by construction: "invalid_pool" is a
			// distinct, asserted value that only the new clause produces, and
			// the discriminator below still fails if the pool is charged.
			name:       "no_member_expands",
			wantReason: "invalid_pool",
			wantSum:    0, // the round-1 zero-total path
			about:      "every member is unparseable, so Rust expands zero addresses and builds no allocator",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address 999.999.999.%d", name, i%256),
				}
			},
		},
		{
			// ROUND 2 ORDERING GUARD. A zone-scoped CIDR fails BOTH the
			// membership grammar (netip.ParsePrefix rejects a zone qualifier
			// outright) and the #5875 zone check. The grammar clause is placed
			// BELOW zone_scoped_pool_address precisely so this member keeps
			// reporting the specific reason it reported before round 2 — a
			// comment says so in SourceNATPoolUnusableReason, and this cell is
			// what makes that true rather than merely stated. Swap the two
			// clauses and this reds with "invalid_pool".
			//
			// The STRICT path is unaffected either way: the zone-scope gate
			// (runUniformGatesNAT:163) precedes the address-grammar gate
			// (:189), so the commit diagnostic still names zone/scope —
			// TestSourceNATPoolZoneScopedAddressRejected/scoped-cidr.
			name:       "zone_scoped_prefix",
			wantReason: "zone_scoped_pool_address",
			wantSum:    0, // ParsePrefix rejects the zone, so the member counts 0
			about:      "a zone-scoped CIDR fails the grammar too; the #5875 reason must still win",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address fe80::%d%%eth0/64", name, i+1),
				}
			},
		},
		{
			// ROUND 2, THE FIFTH CLASS (Codex re-gate at a00a03fc1). One
			// honorable member plus one malformed member. The runtime is
			// ALL-OR-NOTHING — expand_pool_address failing on ANY member sets
			// `invalid_pool_address` and fails the WHOLE pool as InvalidPool, so
			// the dataplane builds no allocator — but the round-1 budget walk
			// summed host counts (1 + 0 = 1), found the total non-zero, and
			// charged the pool. 1,024 of them consumed the entire pool-count
			// budget and poisoned the healthy pool referenced after them.
			//
			// Neither of the two round-1 skips caught it: the pool is not
			// unusable by the definition checks, and its expanded count is not
			// zero. That is why round 2 replaced the derived quantity with the
			// runtime's own verdict rather than adding a fifth condition.
			name:       "some_member_fails",
			wantReason: "invalid_pool",
			wantSum:    1, // 1 + 0: NON-zero, so round 1 charged it
			about:      "one malformed member among honorable ones fails the WHOLE pool in Rust",
			cmds: func(i int, name string) []string {
				return []string{
					fmt.Sprintf("set security nat source pool %s address 198.51.100.%d", name, i%256),
					fmt.Sprintf("set security nat source pool %s address not-an-ip", name),
				}
			},
		},
		{
			// ROUND 2, the same class reached by CAPACITY rather than grammar.
			// `10.<i>.0.0/15` parses cleanly and expands to 131,072 hosts —
			// twice MaxSourceNATPoolPrefixHosts — so expand_pool_address refuses
			// it and the pool builds nothing. Round 1 charged it 131,072
			// addresses (and 8,455,716,864 port-capacity slots) against budgets
			// of 1,048,576 and 2^33: eight such pools exhausted the address
			// budget and one alone exhausted the port capacity, all on behalf of
			// allocators that never exist. It survived the zero-total skip
			// precisely because it expands to a large number, not to nothing.
			name:       "member_over_capacity",
			wantReason: "invalid_pool",
			wantSum:    131072, // 2x the 65,536 allocator cap
			about:      "an over-capacity /15 expands to 131,072 hosts, above the 65,536 allocator cap",
			cmds: func(i int, name string) []string {
				return []string{
					// Even /15 bases (i*2 % 256) keep each prefix canonical and
					// distinct, so the fixture is 1,024 genuinely separate pools.
					fmt.Sprintf("set security nat source pool %s address 10.%d.0.0/15", name, (i*2)%256),
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmds := snat6812UnusablePools(MaxSourceNATPoolCount, tc.cmds)
			cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			// PRECONDITION: the fixture really did build MaxSourceNATPoolCount
			// unusable pools plus the healthy one. Without this a fixture that
			// silently dropped its pools would pass the assertion below while
			// exercising nothing.
			if got := len(cfg.Security.NAT.SourcePools); got != MaxSourceNATPoolCount+1 {
				t.Fatalf("fixture defined %d pools, want %d — the scenario never reached the budget",
					got, MaxSourceNATPoolCount+1)
			}
			if reason := SourceNATPoolUnusableReason(cfg.Security.NAT.SourcePools["bad0"]); reason != tc.wantReason {
				t.Fatalf("bad0 unusable reason = %q, want %q (%s); the fixture is not building the shape under test",
					reason, tc.wantReason, tc.about)
			}
			// Pin the DERIVED QUANTITY round 1 consulted, so each case is
			// provably the class it claims to be. A non-zero sum means round 1
			// charged this pool: those cases (some_member_fails,
			// member_over_capacity) are excluded only because the walk now asks
			// the runtime's all-or-nothing question. A zero sum means the old
			// zero-total rule already excluded it.
			var sum uint64
			for _, m := range SourceNATPoolMembers(cfg.Security.NAT.SourcePools["bad0"]) {
				sum = checkedAddU64(sum, sourceNATPoolMemberHostCount(m))
			}
			if sum != tc.wantSum {
				t.Fatalf("bad0 host-count sum = %d, want %d — the fixture is not the class under "+
					"test (%s), so the exclusion it exercises is not the one this case names",
					sum, tc.wantSum, tc.name)
			}
			if reason := SourceNATPoolUnusableReason(cfg.Security.NAT.SourcePools["good"]); reason != "" {
				t.Fatalf("the healthy pool is itself unusable (%q); the fixture proves nothing", reason)
			}
			// THE DISCRIMINATOR: pools that build no allocator must not consume
			// aggregate budget, so nothing is poisoned.
			poison := SourceNATAggregateOverBudgetPools(cfg)
			if poison["good"] {
				t.Fatalf("the healthy pool was poisoned %q by %d pools that build NO allocator "+
					"(%s) — fail-closed over-rejection on the tolerant recovery path, and a "+
					"divergence from the Rust walk, which skips failed pools entirely",
					"aggregate_over_budget", MaxSourceNATPoolCount, tc.name)
			}
			if len(poison) != 0 {
				t.Fatalf("poison set = %v, want empty — no pool in this fixture crosses a budget "+
					"once the unusable pools are excluded", poison)
			}
		})
	}
}

// TestBudgetChargeImpliesHonorableMembers_6812 binds the invariant that
// replaced the zero-expanded-addresses skip in sourceNATAggregateReferencedCharges
// (#6812 F1 round 2).
//
// The skip was deleted rather than kept as a belt because it became
// UNREACHABLE: the shared verdict is all-or-nothing over
// sourceNATPoolAddressReason, so any pool with a member that fails to parse is
// already excluded, and a pool with no members reports empty_pool. A charged
// pool therefore has at least one member, every member parses, and a parsing
// member has a host count of at least 1.
//
// Deleting a branch leaves nothing to test, so this tests the two premises the
// deletion rests on, over the full grammar surface:
//
//  1. HONORABLE => COUNTABLE. Every member sourceNATPoolAddressReason accepts
//     has sourceNATPoolMemberHostCount >= 1. If this ever fails, a charged pool
//     could sum to zero and the deleted branch would be needed again.
//  2. The walk never emits a zero-address charge, driven through the real
//     compiler over the same member shapes.
//
// RED-on-revert: make sourceNATPoolAddressReason accept an unparseable member
// (e.g. return ("", true) unconditionally) and premise 1 reds on "not-an-ip"
// with hostCount 0 — the exact combination that made the fifth class possible.
func TestBudgetChargeImpliesHonorableMembers_6812(t *testing.T) {
	// The grammar surface: accepted and rejected shapes, v4 and v6, bare and
	// CIDR, at and over the prefix cap.
	//
	// ROUND 3: `fe80::1%eth0` moved sides. It used to be ACCEPTED here (netip
	// carries a zone) with a host count of 1, so it exercised premise 1's
	// positive arm; it is now REJECTED, so premise 1 skips it and it exercises
	// premise 2 instead (a pool carrying it must not be charged). The
	// leading-zero-octet shapes are added for the same reason the round-3
	// divergence existed: a member the Go predicate rejects must never carry a
	// non-zero count into a charge.
	members := []string{
		"198.51.100.1", "198.51.100.0/32", "203.0.113.0/28", "10.0.0.0/16",
		"2001:db8::1", "2001:db8::/128", "2001:db8::/112",
		"not-an-ip", "203.0.113.1/garbage", "999.999.999.1", "",
		"10.0.0.0/15", "10.0.0.0/8", "2001:db8::/111", "::/0",
		"fe80::1%eth0", "fe80::/112%eth0",
		"010.0.0.0/24", "192.168.001.1/32", "::ffff:010.0.0.0/120",
	}
	for _, m := range members {
		_, ok := sourceNATPoolAddressReason(m)
		n := sourceNATPoolMemberHostCount(m)
		if ok && n == 0 {
			t.Fatalf("member %q is honorable by the shared grammar but expands to 0 addresses: "+
				"a pool of such members would be CHARGED with a zero total, the shape the "+
				"deleted zero-expanded-addresses skip used to catch", m)
		}
	}

	// Premise 2, through the real compiler: no charge is ever zero-address,
	// whatever mix of honorable and rejected members a pool carries.
	cmds := []string{
		"set security nat source rule-set RS from zone trust",
		"set security nat source rule-set RS to zone untrust",
	}
	for i, m := range members {
		if m == "" {
			continue // not expressible as a `set` token
		}
		cmds = append(cmds,
			fmt.Sprintf("set security nat source pool q%d address 198.51.100.1", i),
			fmt.Sprintf("set security nat source pool q%d address %s", i, m),
			fmt.Sprintf("set security nat source rule-set RS rule r%d match source-address 10.0.0.0/24", i),
			fmt.Sprintf("set security nat source rule-set RS rule r%d then source-nat pool q%d", i, i),
		)
	}
	cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	charges := sourceNATAggregateReferencedCharges(cfg)
	if len(charges) == 0 {
		t.Fatal("no pool was charged at all — the fixture proves nothing about charged pools")
	}
	for _, c := range charges {
		if c.addrs == 0 {
			t.Fatalf("pool %s was charged with 0 expanded addresses; the invariant that let the "+
				"zero-total skip be deleted no longer holds", c.name)
		}
		// And the charged set is exactly the honorable one.
		if reason := SourceNATPoolUnusableReason(cfg.Security.NAT.SourcePools[c.name]); reason != "" {
			t.Fatalf("pool %s was charged despite being unusable (%q)", c.name, reason)
		}
	}
}

// TestAggregateValidatorMatchesPoisonWalk_6812 pins validator/poison
// agreement: whenever the strict validator rejects, the poison set is
// non-empty (the tolerant path degrades the same config per-pool); whenever
// the validator accepts, the poison set is empty (no over-reject). This is
// the drift guard for the shared sourceNATAggregateReferencedCharges walk.
func TestAggregateValidatorMatchesPoisonWalk_6812(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{"count-over", snat5877Pools(MaxSourceNATPoolCount+1, distinctHostIP, "")},
		{"count-at", snat5877Pools(MaxSourceNATPoolCount, distinctHostIP, "")},
		{"addrs-over", snat5877Pools(17, distinctSlash16, "5000 to 5001")},
		{"addrs-at", snat5877Pools(16, distinctSlash16, "5000 to 5001")},
		{"cap-over", snat5877Pools(3, distinctSlash16, "")},
		{"cap-at", snat5877Pools(2, distinctSlash16, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := snat5877Tree(t, tc.cmds...)
			_, strictErr := CompileConfig(tree)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			poison := SourceNATAggregateOverBudgetPools(cfg)
			over := strings.HasSuffix(tc.name, "-over")
			if strictErr == nil == over {
				t.Fatalf("strict reject = %v, want over-budget = %v (err %v)", !over, over, strictErr)
			}
			if over && len(poison) == 0 {
				t.Fatalf("over-budget config must poison at least one pool on the tolerant path")
			}
			if !over && len(poison) != 0 {
				t.Fatalf("at-budget config must poison nothing, got %v", poison)
			}
		})
	}
}

// TestAggregateChargeConsultsResolvedPortRange_6812 pins #6812 F2 round 3: the
// budget walk CONSULTS SourceNATPoolPortRange — the resolver the snapshot
// builder ships to the dataplane — instead of recomputing the range from the
// raw PortLow/PortHigh fields.
//
// This is a CONTRACT test, not a live-bug repro, and the distinction is the
// point. compileNATSource defaults an unset port range to 1024/65535 before
// storing the pool, so on every config the compiler can produce the two
// agreed (TestCompiledPoolCarriesDefaultedPortRange_6812 pins that half).
// The walk's correctness therefore RESTED on a defaulting three files away,
// with nothing binding the two together: a *NATPool built any other way — the
// resolver's own documented input, raw 0/0 — was charged ZERO port slots and
// admitted, while the builder shipped the resolved 1024-65535 and the
// dataplane charged 64,512 slots per address.
//
// FAIL-ON-REVERT: restoring `if pool.PortLow > 0 && pool.PortHigh >= pool.PortLow`
// over the raw fields makes portCap 0 here and reds the test.
func TestAggregateChargeConsultsResolvedPortRange_6812(t *testing.T) {
	// Three /16 members, NO port range stamped — exactly the shape
	// SourceNATPoolPortRange resolves to the 1024-65535 PAT default.
	pool := &NATPool{
		Name:      "p0",
		Addresses: []string{"10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16"},
	}
	if pool.PortLow != 0 || pool.PortHigh != 0 {
		t.Fatalf("fixture must carry an UNSET raw range, got %d-%d", pool.PortLow, pool.PortHigh)
	}
	lo, hi, ok := SourceNATPoolPortRange(pool)
	if !ok || lo != 1024 || hi != 65535 {
		t.Fatalf("SourceNATPoolPortRange = %d-%d ok=%v, want 1024-65535 ok=true", lo, hi, ok)
	}
	cfg := &Config{}
	cfg.Security.NAT.SourcePools = map[string]*NATPool{"p0": pool}
	cfg.Security.NAT.Source = []*NATRuleSet{{
		Name:     "RS",
		FromZone: "trust",
		ToZone:   "untrust",
		Rules:    []*NATRule{{Name: "r0", Then: NATThen{PoolName: "p0"}}},
	}}

	charges := sourceNATAggregateReferencedCharges(cfg)
	if len(charges) != 1 {
		t.Fatalf("charges = %+v, want exactly one", charges)
	}
	const wantAddrs = 3 * 65536
	const wantPortCap = wantAddrs * (65535 - 1024 + 1)
	if charges[0].addrs != wantAddrs {
		t.Fatalf("addrs = %d, want %d", charges[0].addrs, wantAddrs)
	}
	if charges[0].portCap != wantPortCap {
		t.Fatalf("portCap = %d, want %d (a zero-width charge means the walk recomputed "+
			"from the raw fields instead of consulting the resolver)",
			charges[0].portCap, wantPortCap)
	}
	// And the charge is over the 2^33 budget, so the guard actually FIRES —
	// a zero-width charge would have admitted this pool silently.
	if poison := SourceNATAggregateOverBudgetPools(cfg); !poison["p0"] {
		t.Fatalf("poison = %v, want p0 refused (%d port slots > %d budget)",
			poison, uint64(wantPortCap), MaxSourceNATAggregatePortCapacity)
	}
}

// TestCompiledPoolCarriesDefaultedPortRange_6812 pins the OTHER half of the
// #6812 F2 equivalence: a pool with no `port` leaf leaves compileNATSource
// with the 1024/65535 PAT default already stamped on its raw fields. Together
// with TestAggregateChargeConsultsResolvedPortRange_6812 this bounds the fix
// as behavior-preserving on the live path while the walk stops depending on it.
func TestCompiledPoolCarriesDefaultedPortRange_6812(t *testing.T) {
	cfg, err := CompileConfigLenient(snat5877Tree(t, snat5877Pools(1, distinctSlash16, "")...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	pool := cfg.Security.NAT.SourcePools["p0"]
	if pool == nil {
		t.Fatal("pool p0 missing")
	}
	if pool.PortLow != 1024 || pool.PortHigh != 65535 {
		t.Fatalf("compiled raw range = %d-%d, want the 1024-65535 default", pool.PortLow, pool.PortHigh)
	}
}

// TestAggregateFirstFitFollowsEmittedScopeOrder_6812 pins #6812 F3 round 3:
// the first-fit walk admits pools in the order the DATAPLANE charges them —
// the emitted #4161 scope-tier order — not rule-set NAME order.
//
// `aaa` is a ZONE-scoped rule-set (tier 1) naming a 2x/16 pool that consumes
// 98% of the 2^33 port-slot budget; `zzz` is an INTERFACE-scoped rule-set
// (tier 0, MORE specific) naming a 1x/16 pool. Each fits alone; together they
// do not. The snapshot builder stable-sorts its emitted rules by tier, so the
// interface-scoped rule is emitted FIRST and resolve_pool_allocators charges
// `small` first — which means `big` is the pool that must lose.
//
// FAIL-ON-REVERT: restoring the `rulesets[i].Name < rulesets[j].Name` sort
// poisons `small` instead and reds this test.
func TestAggregateFirstFitFollowsEmittedScopeOrder_6812(t *testing.T) {
	cmds := []string{
		"set security nat source rule-set aaa from zone trust",
		"set security nat source rule-set aaa to zone untrust",
		"set security nat source rule-set aaa rule r0 match source-address 10.0.0.0/24",
		"set security nat source rule-set aaa rule r0 then source-nat pool big",
		"set security nat source pool big address 10.100.0.0/16",
		"set security nat source pool big address 10.101.0.0/16",
		"set security nat source rule-set zzz from interface ge-0/0/1.0",
		"set security nat source rule-set zzz rule r0 match source-address 10.0.0.0/24",
		"set security nat source rule-set zzz rule r0 then source-nat pool small",
		"set security nat source pool small address 10.200.0.0/16",
	}
	cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	// Precondition: each pool fits ALONE, so the fixture is decided by ORDER
	// and not by one pool being individually impossible.
	charges := sourceNATAggregateReferencedCharges(cfg)
	if len(charges) != 2 {
		t.Fatalf("charges = %+v, want two pools", charges)
	}
	for _, c := range charges {
		if c.portCap > MaxSourceNATAggregatePortCapacity {
			t.Fatalf("pool %s alone (%d slots) exceeds the budget; the fixture no longer "+
				"discriminates on ORDER", c.name, c.portCap)
		}
	}
	if charges[0].portCap+charges[1].portCap <= MaxSourceNATAggregatePortCapacity {
		t.Fatalf("both pools fit together (%d + %d <= %d); the fixture no longer "+
			"discriminates on ORDER", charges[0].portCap, charges[1].portCap,
			MaxSourceNATAggregatePortCapacity)
	}
	// The interface-scoped rule-set is charged FIRST — the emitted order.
	if charges[0].name != "small" {
		t.Fatalf("charge order = [%s %s], want the interface-scoped pool (small) first",
			charges[0].name, charges[1].name)
	}
	assertPoison(t, SourceNATAggregateOverBudgetPools(cfg), "big")
}

// TestAggregateFirstFitSameTierFollowsConfigOrder_6812 pins the STABILITY half
// of #6812 F3, which the round-3 tests left unbound.
//
// The round-3 fixtures put the two competing rule-sets in DIFFERENT tiers, so
// they bind the tier ORDERING and nothing else: swapping sort.SliceStable for
// an unstable tier-only sort leaves them green. The property that carries the
// rest of the claim — that a same-tier tie resolves in CONFIG order, which is
// what makes the walk's sequence equal the builder's emitted sequence — had no
// test at all.
//
// The fixture size is load-bearing. Go's sort.Slice runs an insertion sort
// below n=12 and detects an already-ordered input above it, so a handful of
// same-tier rule-sets would be order-preserving under an unstable sort too and
// the mutation would be indistinguishable. Measured directly: with MIXED tiers
// and same-tier ties, sort.Slice first reorders equal elements at n=13. This
// fixture uses 20 rule-sets across two tiers, where sort.Slice was observed to
// permute same-tier entries.
//
// FAIL-ON-REVERT: sort.SliceStable -> sort.Slice in
// sourceNATAggregateReferencedCharges reds this.
func TestAggregateFirstFitSameTierFollowsConfigOrder_6812(t *testing.T) {
	const nPerTier = 10
	var cmds []string
	var wantOrder []string
	// Interface-scoped (tier 0) and zone-scoped (tier 1) rule-sets INTERLEAVED
	// in config order, so the sort has real work to do and same-tier ties are
	// spread across the slice rather than adjacent.
	// DESCENDING declaration (#6812 F-A): with ascending names, config order and
	// ascending lexicographic NAME order are the SAME sequence within a tier,
	// so a (tier, Name ASC) tiebreak — the very rule F3 removed — was GREEN.
	for i := nPerTier - 1; i >= 0; i-- {
		iface := fmt.Sprintf("if%02d", i)
		zone := fmt.Sprintf("zn%02d", i)
		cmds = append(cmds,
			fmt.Sprintf("set security nat source rule-set %s from interface ge-0/0/%d.0", iface, i),
			fmt.Sprintf("set security nat source pool %s address 10.%d.0.1", iface, 100+i),
			fmt.Sprintf("set security nat source rule-set %s rule r0 match source-address 10.0.0.0/24", iface),
			fmt.Sprintf("set security nat source rule-set %s rule r0 then source-nat pool %s", iface, iface),
			fmt.Sprintf("set security nat source rule-set %s from zone trust%d", zone, i),
			fmt.Sprintf("set security nat source pool %s address 10.%d.0.1", zone, 200+i),
			fmt.Sprintf("set security nat source rule-set %s rule r0 match source-address 10.0.0.0/24", zone),
			fmt.Sprintf("set security nat source rule-set %s rule r0 then source-nat pool %s", zone, zone),
		)
	}
	// Expected charge order: every interface-scoped pool in CONFIG order, then
	// every zone-scoped pool in CONFIG order — which is DESCENDING by name, so
	// a name tiebreak produces a different sequence and reds.
	for i := nPerTier - 1; i >= 0; i-- {
		wantOrder = append(wantOrder, fmt.Sprintf("if%02d", i))
	}
	for i := nPerTier - 1; i >= 0; i-- {
		wantOrder = append(wantOrder, fmt.Sprintf("zn%02d", i))
	}

	cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}

	// Preconditions (#6812 round 7). This fixture had none, so both shape
	// assumptions its comment states — interleaved tiers, descending names —
	// were load-bearing but unguarded. (1) the input must not already be
	// tier-sorted, or an unstable sort has nothing to permute; (2) no tier may
	// be declared in ascending name order, or a (tier, Name ASC) tiebreak is
	// indistinguishable from the config order this test pins.
	var tiers []int
	var names []string
	for _, rs := range cfg.Security.NAT.Source {
		tiers = append(tiers, natRuleSetScopeTier(rs))
		names = append(names, rs.Name)
	}
	if len(tiers) != 2*nPerTier {
		t.Fatalf("compiled %d rule-sets, want %d", len(tiers), 2*nPerTier)
	}
	tierSorted := true
	for i := 1; i < len(tiers); i++ {
		if tiers[i] < tiers[i-1] {
			tierSorted = false
		}
	}
	if tierSorted {
		t.Fatal("declaration order is already tier-sorted; an unstable sort would have " +
			"nothing to permute and this fixture would not bind stability")
	}
	assertNoTierDeclaredNameAscending6812(t, tiers, names)

	orderedCharges := sourceNATAggregateReferencedCharges(cfg)
	var got []string
	for _, c := range orderedCharges {
		got = append(got, c.name)
	}
	if len(got) != len(wantOrder) {
		t.Fatalf("charged %d pools, want %d: %v", len(got), len(wantOrder), got)
	}
	for i := range wantOrder {
		if got[i] != wantOrder[i] {
			t.Fatalf("charge order[%d] = %s, want %s — a same-tier tie was not resolved in "+
				"CONFIG order, so the walk no longer reproduces the builder's emitted "+
				"sequence.\n got: %v\nwant: %v", i, got[i], wantOrder[i], got, wantOrder)
		}
	}
}

// TestAggregateChargeOrderFollowsWithinRuleSetRuleOrder_6812 is the #6812 F3
// order equality at the THIRD nesting level (round 8).
//
// sourceNATAggregateReferencedCharges documents three ordering clauses:
// rule-sets stable-sorted by scope tier, RULES IN CONFIG ORDER, pools deduped
// by name. Rounds 4 and 7 bound the first (and round 7 de-correlated the
// rule-set names so a name tiebreak on it is visible). NOTHING ASSERTED the
// second: every ordering fixture on this side declares exactly ONE rule per
// rule-set, so there is no within-set order to permute at all.
//
// It was not completely undetectable — and the distinction matters, because
// what detected it was an accident. Measured at 52f7e735a: inserting a
// `sort.SliceStable(rs.Rules, byName)` ahead of the charge walk also reds
// TestAggregateOverBudgetPoolsAddresses_6812 and
// TestAggregateOverBudgetPoolsCount_6812 ("poison set = map[p999:true],
// missing p1024"). Those two are COUNT/ADDRESS budget fixtures, not order
// fixtures; they move only because their 1,025 rules are named r0..r1024 and
// "r1000" < "r999" lexicographically, so a name sort permutes them. Zero-pad
// those names — a plausible readability edit — and both go blind while the
// clause stays unbound. This test asserts the clause instead of catching it
// sideways.
//
// The builder-side sibling (TestBuilderEmittedOrderIsStableWithinATier_6812,
// pkg/dataplane/userspace) does assert within-set order, but through round 7
// declared its rules r0-then-r1 — config order AND ascending name order at
// once — and was measured GREEN under exactly this mutation. Both halves are
// now de-correlated.
//
// This fixture isolates the rule walk. ONE rule-set, so every rule sits at the
// same tier and the tier sort is a no-op — the only thing that can reorder the
// charges is the rule walk itself.
//
// EVERY COLUMN IS AN INDEPENDENT PERMUTATION (#6812 round 9). Round 8 wrote
// this fixture with the rule and pool NAMES permuted and then generated the
// match address and the pool member address from the loop index `i` — so both
// of those ascended with declaration order, and a stable sort keyed on either
// was invisible. Measured at 1995806ee: sorting rs.Rules by
// `Match.SourceAddress` ahead of the charge walk left this test AND the whole
// pkg/config suite GREEN. The round-8 comment also claimed the names were
// "neither ascending nor descending in either coordinate"; the rule column
// r03 r02 r01 r00 is exactly descending, so a reverse name sort was blind too
// (measured GREEN).
//
// Ranks in parentheses are each value's position in ITS COLUMN's ascending
// order. No column is the identity permutation (ascending) or its reverse
// (descending), and the permutations are pairwise distinct, so each axis fails
// for its own reason rather than shadowing another. Round 10 added the last
// three columns — pool cardinality and the port range, which round 9 held
// identical for every pool and therefore could not see (see PRECONDITION (c)):
//
//	slot  rule     pool    match source-address  pool member      members  port range
//	  0   r07 (2)  qb (1)  10.0.3.0/24 (3)       203.0.113.2 (1)  2 (2)    3000-3999 (2/0)
//	  1   r02 (0)  qd (3)  10.0.0.0/24 (0)       203.0.113.3 (2)  1 (0)    1200-9200 (0/3)
//	  2   r09 (3)  qa (0)  10.0.2.0/24 (2)       203.0.113.1 (0)  3 (3)    5000-5099 (3/1)
//	  3   r05 (1)  qc (2)  10.0.1.0/24 (1)       203.0.113.4 (3)  1 (1)    2000-8000 (1/2)
//
// The derived keys those two columns feed are permuted too, and asserted:
// port-range WIDTH 1000, 8001, 100, 6001 and allocator CAPACITY (members ×
// width) 2000, 8001, 300, 6001 — neither ascending nor descending.
//
// The rule names are ZERO-PADDED on purpose. `r0..r10` style names sort
// "r10" < "r9", which is precisely how the two neighbouring budget fixtures
// noted above detect a rule-name sort by accident instead of by assertion.
// Padding removes the accident, so what this fixture reports is the asserted
// kind of coverage.
//
// assertDeclarationOrderIsNotSortedBy6812 enforces the property on every
// column, in BOTH directions, reading the values back out of the compiled
// config rather than from the table — so a future edit to the table cannot
// quietly reintroduce a monotone column.
//
// FAIL-ON-REVERT: a stable sort of rs.Rules keyed on Name, Match.SourceAddress,
// Then.PoolName, the referenced pool's NAME, first member, member COUNT, port
// low/high, or the width or allocator capacity derived from those — in EITHER
// direction — reds the sequence assertion. The last five joined the list in
// round 10; before it they were identical for every pool here and a sort keyed
// on any of them was a measured no-op.
func TestAggregateChargeOrderFollowsWithinRuleSetRuleOrder_6812(t *testing.T) {
	cfg, wantDeclRules, wantDeclPools := aggregateChargeOrderFixtureConfig6812(t)

	// sequence below really is config order and not an artifact of the AST.
	if n := len(cfg.Security.NAT.Source); n != 1 {
		t.Fatalf("compiled %d rule-sets, want 1 — a second rule-set would let the TIER "+
			"sort do the reordering this test attributes to the rule walk", n)
	}
	var gotDeclRules, gotDeclPools []string
	for _, rule := range cfg.Security.NAT.Source[0].Rules {
		gotDeclRules = append(gotDeclRules, rule.Name)
		gotDeclPools = append(gotDeclPools, rule.Then.PoolName)
	}
	if strings.Join(gotDeclRules, ",") != strings.Join(wantDeclRules, ",") {
		t.Fatalf("compiled rule order %v != declared %v — the fixture's premise (config "+
			"order survives compilation) does not hold", gotDeclRules, wantDeclRules)
	}

	// PRECONDITION (b): NO AXIS THE FIXTURE EMITS MAY BE MONOTONE (#6812 round
	// 9). If the values of some column arrive already sorted — in EITHER
	// direction — then a stable sort keyed on that column is a no-op and every
	// assertion below is blind to it. Round 8 checked only that the two NAME
	// columns differed from their ascending order, which missed the two ADDRESS
	// columns entirely (both generated from the loop index, both ascending) and
	// missed the reverse direction on the rule names (declared descending).
	//
	// Read from the COMPILED config, not the fixture table, so an edit to the
	// table cannot reintroduce a monotone column while this check keeps passing.
	var declMatch, declPoolAddr []string
	for _, rule := range cfg.Security.NAT.Source[0].Rules {
		declMatch = append(declMatch, rule.Match.SourceAddress)
		pool := cfg.Security.NAT.SourcePools[rule.Then.PoolName]
		if pool == nil || len(pool.Addresses) == 0 {
			t.Fatalf("rule %s references pool %q with no members; the pool-address axis is "+
				"not defined", rule.Name, rule.Then.PoolName)
		}
		// FIRST member: round 10 gives the pools DIFFERENT cardinalities so the
		// length is an axis of its own, and the first member keeps the round-8
		// permutation this named guard was written for.
		declPoolAddr = append(declPoolAddr, pool.Addresses[0])
	}
	assertDeclarationOrderIsNotSortedBy6812(t, "Rule.Name", gotDeclRules)
	assertDeclarationOrderIsNotSortedBy6812(t, "Then.PoolName", gotDeclPools)
	assertDeclarationOrderIsNotSortedBy6812(t, "Match.SourceAddress", declMatch)
	assertDeclarationOrderIsNotSortedBy6812(t, "pool member address", declPoolAddr)

	// PRECONDITION (c), ASKED OF THE STRUCT (#6812 round 10). The four calls
	// above are the named regression guards for the specific columns rounds 7
	// and 8 found coming back; they are a LIST, which is the shape of blindness
	// this fixture keeps reproducing one level up. sweepAxes6812 reflects over
	// every field of the rule the walk reads AND of the pool it resolves
	// (nat_source_axis_sweep_6812_test.go), so a field added to NATRule /
	// NATMatch / NATThen / NATPool later joins the sweep with no edit here, and
	// a column this fixture holds constant must be REGISTERED rather than
	// silently skipped.
	//
	// The slots come from ruleAxisSlots6812 — the SINGLE builder shared with
	// walkWitness6812 and with TestDerivedChargeColumnsComeFromProduction_6812,
	// which asserts over THIS function's output (#6812 round 13). Round 12 built
	// the slot here and a second one inside the guard, so a wrong formula HERE
	// was invisible to the guard that exists to catch exactly that.
	slots := ruleAxisSlots6812(t, "charged rule", cfg, cfg.Security.NAT.Source[0].Rules)
	sweepAxes6812(t, "charged rule",
		[]axisGroup6812{{label: "rule-set RS", slots: axisAnySlots6812(slots)}},
		walkRuleAxisExemptions6812)

	// The sequences each candidate sort would produce, for the failure text —
	// so a red names WHICH sort the walk started behaving like.
	byRuleName := poolsSortedByKey6812(wantDeclPools, gotDeclRules)
	byPoolName := poolsSortedByKey6812(wantDeclPools, gotDeclPools)
	byMatch := poolsSortedByKey6812(wantDeclPools, declMatch)
	config0 := strings.Join(wantDeclPools, ",")

	orderedCharges := sourceNATAggregateReferencedCharges(cfg)
	var got []string
	for _, c := range orderedCharges {
		got = append(got, c.name)
	}
	if strings.Join(got, ",") != config0 {
		t.Fatalf("charge order = %v, want %v — the budget walk did not charge this "+
			"rule-set's rules in CONFIG order, so a budget boundary falling between two "+
			"rules of ONE rule-set poisons a different pool than the builder emits.\n"+
			"rule-name ASC would give %v; pool-name ASC would give %v; match-address ASC "+
			"would give %v (reverse any of them for the DESC variant)",
			got, wantDeclPools, byRuleName, byPoolName, byMatch)
	}
}

// poolsSortedByKey6812 returns pools[] reordered into ascending order of the
// parallel keys[] — the sequence a stable sort on that key would produce.
// Insertion sort; the slices are fixture-sized. Neither input is mutated.
func poolsSortedByKey6812(pools, keys []string) []string {
	out := append([]string(nil), pools...)
	k := append([]string(nil), keys...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && k[j] < k[j-1]; j-- {
			k[j], k[j-1] = k[j-1], k[j]
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// assertDeclarationOrderIsNotSortedBy6812 fails when the values a fixture
// emits in DECLARATION order are already sorted on some axis — in EITHER
// direction — because a stable sort keyed on that axis is then a no-op and
// invisible to every ordering assertion built on the fixture.
//
// This generalises the round-7/8 name tripwires (#6812 round 9). Those asked
// "is this column ascending?" about the columns whoever wrote them had in
// mind. The failure mode that produced this helper is that a fixture emits
// more columns than its author was thinking about: round 8 permuted the rule
// and pool NAMES and then generated the match address and the pool member
// address from the loop counter, so both ascended and a sort on either was
// measured GREEN against the whole pkg/config suite. Asking the question
// mechanically, of every column, removes the dependence on remembering.
//
// A CONSTANT column is NOT handled here (#6812 round 10). Round 9 skipped one
// silently, arguing that a stable sort keyed on a value identical for every
// element cannot permute anything. That is true of the FIXTURE and says nothing
// about production: fixture-only constancy is a blind spot, not a non-axis.
// Classifying a constant column is sweepAxes6812's job — it demands an explicit
// registration that records whether the column is invariant in production too.
// Callers must therefore filter constants out before calling this; a constant
// sequence reaching here reports as ASCENDING, which is technically true and
// unhelpful.
//
// Fewer than three values is a hard failure rather than a skip: a two-element
// sequence is ascending or descending by construction, so it CANNOT be
// de-correlated from both directions and any claim that it is would be false.
func assertDeclarationOrderIsNotSortedBy6812(t *testing.T, axis string, values []string) {
	t.Helper()
	if len(values) < 3 {
		t.Fatalf("axis %q has %d values %v; a sequence shorter than three is ascending or "+
			"descending by construction, so it cannot be de-correlated from BOTH sort "+
			"directions", axis, len(values), values)
	}
	if sort.StringsAreSorted(values) {
		t.Fatalf("axis %q is declared in ASCENDING order %v — declaration order and a stable "+
			"sort keyed on this axis produce the SAME sequence, so such a sort is invisible "+
			"to every assertion in this fixture. Permute this column.", axis, values)
	}
	if sort.SliceIsSorted(values, func(i, j int) bool { return values[i] > values[j] }) {
		t.Fatalf("axis %q is declared in DESCENDING order %v — a stable sort keyed on this "+
			"axis in reverse produces the SAME sequence and is equally invisible. Permute "+
			"this column rather than flipping it.", axis, values)
	}
}

// TestAggregateSameTierBudgetBoundaryFollowsConfigOrder_6812 is the same
// property at the place it decides something: a budget boundary falling
// BETWEEN two same-tier rule-sets. Config order alone decides which pool keeps
// its allocator, so an unstable tie-break poisons a different pool.
//
// RE-CUT (#6812 round-4 amendment). The first version used 17 rule-sets ALL at
// the zone tier — an ALL-EQUAL sort key — and therefore did not bind the
// property its own comment claimed. Go's sort.Slice detects an already-ordered
// input, so with one key value it preserves order at every size, and
// sort.SliceStable -> sort.Slice left this test GREEN. That is the same
// mechanism the sibling test was built to defeat; it was found by re-running
// the mechanism as a query against neighbouring cells rather than by a new
// review round.
//
// The fixture now INTERLEAVES four interface-scoped rule-sets (tier 0, one
// host each) among sixteen zone-scoped ones (tier 1, one /16 each), so the
// input is neither tier-sorted nor single-keyed and the sort has real work to
// do. The four interface pools are charged first and consume 4 addresses, so
// the 1,048,576-address budget admits fifteen /16 pools (4 + 15 x 65,536 =
// 983,044) and refuses the sixteenth (4 + 1,048,576). WHICH zone pool that is
// depends only on config order among equal-tier rule-sets — the property under
// test.
func TestAggregateSameTierBudgetBoundaryFollowsConfigOrder_6812(t *testing.T) {
	const nZone, nIface = 16, 4
	var cmds []string
	emitZone := func(i int) {
		rs := fmt.Sprintf("zrs%02d", i)
		cmds = append(cmds,
			fmt.Sprintf("set security nat source rule-set %s from zone z%d", rs, i),
			fmt.Sprintf("set security nat source pool q%02d address 10.%d.0.0/16", i, 100+i),
			fmt.Sprintf("set security nat source rule-set %s rule r0 match source-address 10.0.0.0/24", rs),
			fmt.Sprintf("set security nat source rule-set %s rule r0 then source-nat pool q%02d", rs, i),
			fmt.Sprintf("set security nat source pool q%02d port range 5000 to 5001", i),
		)
	}
	emitIface := func(i int) {
		rs := fmt.Sprintf("irs%02d", i)
		cmds = append(cmds,
			fmt.Sprintf("set security nat source rule-set %s from interface ge-0/0/%d.0", rs, i),
			fmt.Sprintf("set security nat source pool p%02d address 203.0.113.%d", i, i+1),
			fmt.Sprintf("set security nat source rule-set %s rule r0 match source-address 10.0.0.0/24", rs),
			fmt.Sprintf("set security nat source rule-set %s rule r0 then source-nat pool p%02d", rs, i),
			fmt.Sprintf("set security nat source pool p%02d port range 5000 to 5001", i),
		)
	}
	// Interleave, so the declaration order is NOT already tier-sorted, and go
	// high-to-low so config order is not ascending NAME order either (#6812
	// F-A) — otherwise a (tier, Name ASC) tiebreak is indistinguishable from
	// the config order this test exists to pin.
	iface := nIface - 1
	for i := nZone - 1; i >= 0; i-- {
		emitZone(i)
		if i%4 == 0 && iface >= 0 {
			emitIface(iface)
			iface--
		}
	}
	for ; iface >= 0; iface-- {
		emitIface(iface)
	}

	cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}

	// Preconditions. (1) Both tiers are present and the input is NOT already
	// sorted by tier — without that, an unstable sort has nothing to permute
	// and the mutation is a no-op, which is exactly how the first version of
	// this test went vacuous.
	var tiers []int
	var names []string
	for _, rs := range cfg.Security.NAT.Source {
		tiers = append(tiers, natRuleSetScopeTier(rs))
		names = append(names, rs.Name)
	}
	if len(tiers) != nZone+nIface {
		t.Fatalf("compiled %d rule-sets, want %d", len(tiers), nZone+nIface)
	}
	sorted := true
	for i := 1; i < len(tiers); i++ {
		if tiers[i] < tiers[i-1] {
			sorted = false
		}
	}
	if sorted {
		t.Fatal("declaration order is already tier-sorted; an unstable sort would have " +
			"nothing to permute and this fixture would not bind stability")
	}
	// (1b) No tier may be declared in ascending NAME order (#6812 F-A / round
	// 7), or a (tier, Name ASC) tiebreak emits the same sequence as config
	// order and the q00-vs-q15 assertion below cannot see it.
	assertNoTierDeclaredNameAscending6812(t, tiers, names)

	// (2) The boundary must fall between two ZONE-tier rule-sets, so config
	// order among EQUALS is what decides the loser.
	charges := sourceNATAggregateReferencedCharges(cfg)
	if len(charges) != nZone+nIface {
		t.Fatalf("charged %d pools, want %d", len(charges), nZone+nIface)
	}
	for i := 0; i < nIface; i++ {
		if !strings.HasPrefix(charges[i].name, "p") {
			t.Fatalf("charge[%d] = %s, want the interface-tier pools first", i, charges[i].name)
		}
	}

	// The LAST-declared zone pool loses. With descending declaration that is
	// q00 — under a (tier, Name ASC) tiebreak it would be q15 instead, which is
	// what makes this assertion see a name tiebreak.
	assertPoison(t, SourceNATAggregateOverBudgetPools(cfg), "q00")
}

// assertNoTierDeclaredNameAscending6812 is the #6812 F-A fixture tripwire for
// the WALK-side fixtures: it fails unless every tier holding two or more
// rule-sets is declared in an order that DIFFERS from ascending lexicographic
// name order, and unless at least one such tier exists.
//
// Keyed on the RULE-SET name because that is what
// sourceNATAggregateReferencedCharges sorts, and what its round-2 name ordering
// — the rule F3 removed — actually used.
//
// Why per-tier and not over the whole sequence (round 7). A (tier, Name ASC)
// stable sort consults the name ONLY among equal tiers, so the blindness that
// matters is a tier whose declaration order already IS name-ascending: that
// tier's charge sequence is then identical under both sorts. The first version
// of this check (in the sibling builder fixture) asked whether the WHOLE
// declared sequence was non-decreasing by name, which these interleaved
// fixtures can never be — they emit if00 zn00 if01 zn01 ..., and "zn00" >
// "if01" breaks monotonicity at index 2 whichever direction the loop runs — so
// the flag was always false and the t.Fatal unreachable.
//
// A single-element tier is skipped rather than failed: it is trivially both
// ascending and descending, so it neither discriminates nor blinds, and failing
// on it would fire the tripwire on a fixture that is still sound.
//
// tiers and names are parallel slices in DECLARATION order. The builder-side
// fixture in pkg/dataplane/userspace carries its own copy (different package;
// a test helper cannot be shared across the two without exporting it from
// production) keyed on PoolName, which is the only per-rule-set string the
// emitted snapshot slice carries.
func assertNoTierDeclaredNameAscending6812(t *testing.T, tiers []int, names []string) {
	t.Helper()
	if len(tiers) != len(names) {
		t.Fatalf("precondition harness: %d tiers vs %d names — the caller's slices are "+
			"not parallel", len(tiers), len(names))
	}
	var order []int
	byTier := map[int][]string{}
	for i, tier := range tiers {
		if _, ok := byTier[tier]; !ok {
			order = append(order, tier)
		}
		byTier[tier] = append(byTier[tier], names[i])
	}
	discriminating := 0
	for _, tier := range order {
		n := byTier[tier]
		if len(n) < 2 {
			continue
		}
		ascending := true
		for i := 1; i < len(n); i++ {
			if n[i] < n[i-1] {
				ascending = false
				break
			}
		}
		if ascending {
			t.Fatalf("tier %d is declared in ascending NAME order %v; that is the SAME "+
				"sequence a (tier, name ASC) tiebreak emits, so this fixture could not see "+
				"the rule #6812 F3 removed coming back. Re-cut the fixture so this tier's "+
				"declaration order is not name-ascending.", tier, n)
		}
		discriminating++
	}
	if discriminating == 0 {
		t.Fatal("no tier holds two or more rule-sets, so there is no within-tier tie: a " +
			"(tier, name ASC) tiebreak would have nothing to reorder and this fixture " +
			"cannot bind the tie-break rule at all")
	}
}

// derivedChargeRival6812 is one WRONG way to compute a slot's derived charge
// column — a formula someone could plausibly write instead of reading the
// production value — together with the reason it is wrong.
//
// The table is the falsifiability half of
// TestDerivedChargeColumnsComeFromProduction_6812: for the claim "the swept
// slots carry the production charge" to have content, the FIXTURE has to be
// able to tell the production charge apart from each rival. A rival no fixture
// pool distinguishes is a formula this test would silently accept.
type derivedChargeRival6812 struct {
	name string
	why  string
	// column names the slot field this rival would fill wrongly, for the red.
	column string
	// rival computes the rival's value for one pool; production reads the value
	// the charge walk produced for the same pool.
	rival      func(t *testing.T, pool *NATPool) uint64
	production func(ch sourceNATAggregatePoolCharge) uint64
}

// sourceNATPoolMemberHostSum6812 is the host expansion the PRODUCTION charge
// sums. It exists here only so the rivals below can be written as "production
// with ONE substitution", which is what makes each one a plausible mistake
// rather than a strawman.
func sourceNATPoolMemberHostSum6812(pool *NATPool) uint64 {
	var hosts uint64
	for _, m := range SourceNATPoolMembers(pool) {
		hosts += sourceNATPoolMemberHostCount(m)
	}
	return hosts
}

// derivedChargeRivals6812 enumerates the formulas a round has actually shipped
// or been caught re-deriving, in the MEMBERS-versus-EXPANDED-HOSTS confusion
// that produced the round-12 defect. Both columns are covered: round 12 checked
// only ChargePortCap, so a builder that filled ChargeAddrs with `len(members)`
// had no rival to be caught by.
func derivedChargeRivals6812() []derivedChargeRival6812 {
	return []derivedChargeRival6812{
		{
			name:   "len(members) × width",
			column: "ChargePortCap",
			why: "round 11 shipped this. It counts MEMBERS where production counts " +
				"EXPANDED HOSTS, so it under-charges any pool with a prefix member. " +
				"Distinguished by a pool carrying a /30.",
			rival: func(t *testing.T, pool *NATPool) uint64 {
				t.Helper()
				lo, hi, ok := SourceNATPoolPortRange(pool)
				if !ok {
					t.Fatalf("pool %q has an unusable port range", pool.Name)
				}
				return uint64(len(SourceNATPoolMembers(pool))) * (uint64(hi-lo) + 1)
			},
			production: func(ch sourceNATAggregatePoolCharge) uint64 { return ch.portCap },
		},
		{
			name:   "len(members)",
			column: "ChargeAddrs",
			why: "the same members-for-hosts substitution on the OTHER derived column. " +
				"Round 12's guard checked ChargePortCap only, so this one had no rival " +
				"at all. Distinguished by the same /30 pool: two members, five hosts.",
			rival: func(t *testing.T, pool *NATPool) uint64 {
				t.Helper()
				return uint64(len(SourceNATPoolMembers(pool)))
			},
			production: func(ch sourceNATAggregatePoolCharge) uint64 { return ch.addrs },
		},
	}
}

// TestRawPortFieldsAreNotAThirdFormula_6812 settles a rival the round-13 review
// raised and MEASUREMENT refutes, and pins the fact the refutation rests on.
//
// The candidate: `Σ host-count × (PortHigh − PortLow + 1)` read from the RAW
// NATPool fields instead of consulting SourceNATPoolPortRange. It is the
// re-derive-instead-of-consult shape round 3's F2 removed, and it agrees with
// production on every fixture pool — which the review read as a third
// undistinguished formula needing a witness pool with no `port` leaf ("raw
// width 1 vs production 64512").
//
// It does not need one, because the divergence is UNREACHABLE through the
// compiler. compileNATSource stamps the 1024/65535 default into PortLow/PortHigh
// itself (compiler_nat_source.go, the `if pool.PortLow == 0` tail of the pool
// loop), so a compiled no-port-leaf pool already carries raw 1024/65535 —
// measured, not argued: qe below has no `port` leaf and raw width 64512. And a
// pool whose EXPLICIT range was rejected (#5457 PortRangeInvalidSpec) is
// unusable, so sourceNATAggregateReferencedCharges never charges it and no slot
// is built for it at all. Every pool a slot can exist for therefore has raw
// width == resolved width.
//
// That makes the raw-field formula extensionally EQUAL to production on this
// domain — not a drift risk, and not something a fixture can witness. Claiming
// a witness for it would be the fixture-coincidence error in reverse: inventing
// discrimination that does not exist.
//
// What is worth binding is the PREMISE. If compileNATSource ever stops
// pre-defaulting — or another path builds a referenced NATPool with a zero
// endpoint — the two formulas separate and the rival becomes live. This test
// reds then, which is the signal to move it into derivedChargeRivals6812.
func TestRawPortFieldsAreNotAThirdFormula_6812(t *testing.T) {
	cfg, _, _ := aggregateChargeOrderFixtureConfig6812(t)
	charges := productionChargeByPool6812(t, cfg)

	defaulted := 0
	for _, rule := range cfg.Security.NAT.Source[0].Rules {
		name := rule.Then.PoolName
		pool := cfg.Security.NAT.SourcePools[name]
		ch, ok := charges[name]
		if !ok {
			t.Fatalf("pool %q was not charged", name)
		}
		if pool.PortLow <= 0 || pool.PortHigh <= 0 {
			t.Fatalf("pool %q reached the charge walk with a ZERO port endpoint "+
				"(PortLow=%d PortHigh=%d). The compiler's own default no longer covers "+
				"every charged pool, so `Σ host-count × (PortHigh − PortLow + 1)` read "+
				"from the raw fields is now a DISTINCT formula from the production "+
				"charge. Move it into derivedChargeRivals6812 — this pool is its witness.",
				name, pool.PortLow, pool.PortHigh)
		}
		raw := sourceNATPoolMemberHostSum6812(pool) * (uint64(pool.PortHigh-pool.PortLow) + 1)
		if raw != ch.portCap {
			t.Fatalf("pool %q: the raw-field formula gives %d, production charges %d. "+
				"They have separated; the raw-field formula is a real rival now and "+
				"belongs in derivedChargeRivals6812.", name, raw, ch.portCap)
		}
		if !sourceNATPoolHasExplicitPortLeaf6812(pool) {
			defaulted++
		}
	}
	if defaulted == 0 {
		t.Fatal("every pool in this fixture carries an EXPLICIT `port range` leaf, so the " +
			"agreement above never exercises the compiler default that makes it hold. " +
			"Keep a pool with no `port` leaf in the fixture — otherwise this test would " +
			"stay green even if the default were removed, which is the one change it " +
			"exists to catch.")
	}
}

// sourceNATPoolHasExplicitPortLeaf6812 reports whether the operator wrote a
// `port range` leaf, as opposed to inheriting the compiler's 1024-65535
// default. There is no field recording this directly — a valid explicit
// `1024 to 65535` is indistinguishable from the default post-compile — so it
// asks the FIXTURE's declaration table, which is where the distinction lives.
func sourceNATPoolHasExplicitPortLeaf6812(pool *NATPool) bool {
	for _, d := range aggregateChargeFixtureDecl6812() {
		if d.pool == pool.Name {
			return d.lo != 0 || d.hi != 0
		}
	}
	return true
}

// TestDerivedChargeColumnsComeFromProduction_6812 is the guard on the round-11
// wrapper.
//
// The wrapper exists because reflection cannot reach a key DERIVED from fields.
// Round 11 filled it by recomputing one — `len(members) × width` — and that is
// not the charge production spends. sourceNATAggregateReferencedCharges spends
// `Σ sourceNATPoolMemberHostCount(member) × range`; the Rust apply boundary
// spends allocator_capacity over the EXPANDED addresses. All three agreed only
// because every fixture pool member was a bare host, which is the
// fixture-coincidence class this round exists to eliminate — sitting inside the
// construct added because reflection could not reach it.
//
// Two halves, and the second is the one that keeps working:
//
//  1. the SWEPT slots carry the production charge. Round 13: "swept" is
//     load-bearing. Round 12 asserted this about a slot it built HERE, which is
//     `x := T{F: v}; if x.F != v` — true of any struct, and blind to the slot
//     the sweep actually consumed. The subject is now ruleAxisSlots6812's
//     output, the single builder every sweep site goes through, so replacing
//     the formula there reds this test.
//  2. the fixture can TELL PRODUCTION APART FROM EVERY RIVAL FORMULA in
//     derivedChargeRivals6812. Without this the first half is unfalsifiable —
//     every value would agree with every formula. Round 12 checked one rival;
//     a second (raw PortLow/PortHigh instead of SourceNATPoolPortRange) also
//     agreed on all four pools, so "there is no second implementation left to
//     drift" was not established. Each rival now needs its own witness pool.
func TestDerivedChargeColumnsComeFromProduction_6812(t *testing.T) {
	cfg, _, _ := aggregateChargeOrderFixtureConfig6812(t)
	charges := productionChargeByPool6812(t, cfg)
	rules := cfg.Security.NAT.Source[0].Rules

	// THE SUBJECT: what the sweep sites consume, not a literal built here.
	slots := ruleAxisSlots6812(t, "derived-charge guard", cfg, rules)
	if len(slots) != len(rules) {
		t.Fatalf("the shared slot builder returned %d slots for %d rules", len(slots), len(rules))
	}

	rivals := derivedChargeRivals6812()
	discriminating := make([]int, len(rivals))
	for i, slot := range slots {
		name := rules[i].Then.PoolName
		if slot.Rule != rules[i] {
			t.Fatalf("slot %d carries rule %v, want the rule-set's rule %s",
				i, slot.Rule, rules[i].Name)
		}
		ch, ok := charges[name]
		if !ok {
			t.Fatalf("pool %q was not charged", name)
		}
		if slot.ChargePortCap != ch.portCap || slot.ChargeAddrs != ch.addrs {
			t.Fatalf("pool %q: the SWEPT slot does not carry the production charge "+
				"(addrs %d, want %d; portCap %d, want %d). ruleAxisSlots6812 must READ "+
				"sourceNATAggregateReferencedCharges, never recompute it — a wrapper column "+
				"asserting a derived key is a second implementation of that key, and second "+
				"implementations drift.", name,
				slot.ChargeAddrs, ch.addrs, slot.ChargePortCap, ch.portCap)
		}
		for r, rival := range rivals {
			if rival.rival(t, slot.Pool) != rival.production(ch) {
				discriminating[r]++
			}
		}
	}
	for r, rival := range rivals {
		if discriminating[r] == 0 {
			t.Fatalf("no pool in this fixture distinguishes the rival formula `%s` (for "+
				"%s) from the production charge, so a builder that recomputed it would "+
				"agree with production HERE and the defect would be invisible again.\n"+
				"Why the rival is wrong: %s\nAdd a fixture pool that distinguishes it.",
				rival.name, rival.column, rival.why)
		}
	}
}

// aggregateChargeOrderFixtureConfig6812 builds the fixture config, shared with
// TestDerivedChargeColumnsComeFromProduction_6812 so both read ONE input.
// It also returns the DECLARED rule and pool sequences, so the order assertions
// compare against the table rather than re-deriving it.
// aggregateChargeFixtureDecl6812 is the fixture's DECLARATION table, lifted out
// of aggregateChargeOrderFixtureConfig6812 so the derived-charge tests can ask
// it which pools carry an explicit `port range` leaf — a distinction the
// compiled *Config cannot answer, because a valid explicit `1024 to 65535` is
// byte-identical to the default post-compile (#6812 round 13).
//
// EVERY column here is permuted on purpose. assertDeclarationOrderIsNotSortedBy6812
// and the struct sweep both require declaration order to be non-monotone in
// BOTH directions on every axis, so a row cannot be appended without checking
// that it keeps each column unsorted.
func aggregateChargeFixtureDecl6812() []struct {
	rule, pool, match, poolAddr string
	// #6812 round 10: two more columns, each of which round 9's four helper
	// calls could not see because the FIXTURE held it constant while
	// production varies it. Every pool used to carry exactly one member at
	// the default 1024-65535 range, so a sort by len(Addresses), by the
	// port-range width, or by the allocator charge this very walk computes
	// was a no-op here and not in general. Extra members ride on `extra`;
	// the FIRST member stays as it was so the Addresses[0] permutation is
	// untouched.
	extra  []string
	lo, hi int
} {
	type row = struct {
		rule, pool, match, poolAddr string
		extra                       []string
		lo, hi                      int
	}
	return []row{
		{"r07", "qb", "10.0.3.0/24", "203.0.113.2", []string{"198.51.100.8/30"}, 3000, 3999},
		{"r02", "qd", "10.0.0.0/24", "203.0.113.3", nil, 1200, 9200},
		{"r09", "qa", "10.0.2.0/24", "203.0.113.1", []string{"198.51.100.9", "198.51.100.19"}, 5000, 5099},
		{"r05", "qc", "10.0.1.0/24", "203.0.113.4", nil, 2000, 8000},
		// #6812 round 13: NO `port` leaf (lo == hi == 0). This pool inherits the
		// compiler's 1024-65535 default, which is what makes
		// TestRawPortFieldsAreNotAThirdFormula_6812's agreement exercise the
		// defaulting instead of trivially holding on explicit ranges. Its
		// charge (1 host x 64512) also keeps the ChargePortCap column
		// non-monotone: 5000, 8001, 300, 6001, 64512.
		{"r04", "qe", "10.0.4.0/24", "203.0.113.5", nil, 0, 0},
	}
}

func aggregateChargeOrderFixtureConfig6812(t *testing.T) (*Config, []string, []string) {
	t.Helper()
	decl := aggregateChargeFixtureDecl6812()
	cmds := []string{"set security nat source rule-set RS from zone trust"}
	for _, d := range decl {
		cmds = append(cmds,
			fmt.Sprintf("set security nat source pool %s address %s", d.pool, d.poolAddr))
		for _, a := range d.extra {
			cmds = append(cmds, fmt.Sprintf("set security nat source pool %s address %s", d.pool, a))
		}
		// lo == 0 && hi == 0 means NO `port` leaf: the pool inherits the
		// compiler's 1024-65535 default (#6812 round 13, see
		// TestRawPortFieldsAreNotAThirdFormula_6812).
		if d.lo != 0 || d.hi != 0 {
			cmds = append(cmds,
				fmt.Sprintf("set security nat source pool %s port range %d to %d", d.pool, d.lo, d.hi))
		}
		cmds = append(cmds,
			fmt.Sprintf("set security nat source rule-set RS rule %s match source-address %s", d.rule, d.match),
			fmt.Sprintf("set security nat source rule-set RS rule %s then source-nat pool %s", d.rule, d.pool),
		)
	}

	cfg, err := CompileConfigLenient(snat5877Tree(t, cmds...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	var wantRules, wantPools []string
	for _, d := range decl {
		wantRules = append(wantRules, d.rule)
		wantPools = append(wantPools, d.pool)
	}
	return cfg, wantRules, wantPools
}
