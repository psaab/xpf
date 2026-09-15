package userspace

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9874: the tolerant-path snapshot must carry the fail-closed poison for an
// authored-but-empty NAT match — end to end from flat-set tree through
// CompileConfigLenient to the snapshot builder. Before the fix the snapshot
// shipped the rule with empty match lists and no marker, which the Rust table
// reads as UNCONSTRAINED (catch-all translator).

func poisonTree9874(t *testing.T, paths ...[]string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, p := range paths {
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", p, err)
		}
	}
	return tree
}

func snatLenient9874(t *testing.T, matchPaths ...[]string) []SourceNATRuleSnapshot {
	t.Helper()
	paths := [][]string{
		{"security", "nat", "source", "pool", "p1", "address", "172.16.0.5/32"},
		{"security", "nat", "source", "rule-set", "RS", "from", "zone", "lan"},
		{"security", "nat", "source", "rule-set", "RS", "to", "zone", "wan"},
	}
	paths = append(paths, matchPaths...)
	paths = append(paths,
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "then", "source-nat", "pool", "p1"})
	cfg, err := config.CompileConfigLenient(poisonTree9874(t, paths...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return buildSourceNATSnapshots(cfg, nil)
}

func dnatLenientCfg9874(t *testing.T, matchPaths ...[]string) *config.Config {
	t.Helper()
	paths := [][]string{
		{"security", "nat", "destination", "pool", "p1", "address", "192.168.1.10"},
		{"security", "nat", "destination", "rule-set", "RS", "from", "zone", "untrust"},
	}
	paths = append(paths, matchPaths...)
	paths = append(paths,
		[]string{"security", "nat", "destination", "rule-set", "RS", "rule", "R1", "then", "destination-nat", "pool", "p1"})
	cfg, err := config.CompileConfigLenient(poisonTree9874(t, paths...))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// The empty-match rule ships WITH the marker the Rust table drops closed.
// RED-on-revert: drop the builder assignment and the marker is false while
// the match lists are empty — the shipped catch-all.
func TestLenientEmptyMatchSNATSnapshotCarriesPoison_9874(t *testing.T) {
	snaps := snatLenient9874(t,
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match"})
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1 (the rule must ship, marked)", len(snaps))
	}
	if !snaps[0].LenientMatchDropped {
		t.Fatalf("empty-match rule shipped WITHOUT the poison marker — the Rust table would install a catch-all")
	}
}

// The valueless route (#8430's second shape) is poisoned too — a fix that only
// sees the bare container leaves it open.
func TestLenientValuelessMatchSNATSnapshotCarriesPoison_9874(t *testing.T) {
	snaps := snatLenient9874(t,
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match", "source-address"})
	if len(snaps) != 1 {
		t.Fatalf("len(snaps) = %d, want 1", len(snaps))
	}
	if !snaps[0].LenientMatchDropped {
		t.Fatalf("valueless-match rule shipped WITHOUT the poison marker")
	}
}

// No-over-reject: populated and scope-only rules ship unmarked.
func TestLenientHealthySNATSnapshotUnmarked_9874(t *testing.T) {
	pop := snatLenient9874(t,
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match", "source-address", "10.0.0.0/24"})
	if len(pop) != 1 || pop[0].LenientMatchDropped {
		t.Fatalf("populated rule poisoned — over-reject")
	}
	scopeOnly := snatLenient9874(t)
	if len(scopeOnly) != 1 || scopeOnly[0].LenientMatchDropped {
		t.Fatalf("scope-only rule poisoned — the legitimate catch-all must stay unmarked")
	}
}

// Byte-identical wire for healthy rules: the marker key is omitted when false
// (omitempty), and present-and-true when set.
func TestSNATSnapshotWireOmitsMarkerWhenFalse_9874(t *testing.T) {
	pop := snatLenient9874(t,
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match", "source-address", "10.0.0.0/24"})
	j, err := json.Marshal(pop[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(j), "lenient_match_dropped") {
		t.Fatalf("healthy snapshot carries the marker key — wire not byte-identical: %s", j)
	}
	marked := snatLenient9874(t,
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match"})
	mj, err := json.Marshal(marked[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(mj), `"lenient_match_dropped":true`) {
		t.Fatalf("marked snapshot missing the wire marker: %s", mj)
	}
}

// DNAT half: an empty-match rule publishes NO entry (already fail-closed),
// and the shared predicate names the reason so every show surface agrees.
func TestLenientEmptyMatchDNATPublishesNoEntry_9874(t *testing.T) {
	cfg := dnatLenientCfg9874(t,
		[]string{"security", "nat", "destination", "rule-set", "RS", "rule", "R1", "match"})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 0 {
		t.Fatalf("empty-match DNAT published %d entries, want 0 (fail-closed)", len(snaps))
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if reason := config.DestinationNATRuleExcludedReason(cfg.Security.NAT.Destination, rule); reason == "" {
		t.Fatalf("predicate reports the poisoned DNAT rule installed — show would lie")
	} else if !strings.Contains(reason, "9874") {
		t.Fatalf("predicate reason does not name the cause: %q", reason)
	}
	healthy := dnatLenientCfg9874(t,
		[]string{"security", "nat", "destination", "rule-set", "RS", "rule", "R1", "match", "destination-address", "203.0.113.10/32"})
	hsnaps := buildDestinationNATSnapshots(healthy, nil)
	if len(hsnaps) == 0 {
		t.Fatalf("populated DNAT published no entry — over-reject")
	}
}

func snatPoisonedPlusHealthyCfg_9874(t *testing.T, nBad int) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	set := func(p ...string) {
		t.Helper()
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", p, err)
		}
	}
	set("security", "nat", "source", "rule-set", "RS", "from", "zone", "lan")
	set("security", "nat", "source", "rule-set", "RS", "to", "zone", "wan")
	for i := range nBad {
		pool := fmt.Sprintf("bad%d", i)
		rule := fmt.Sprintf("r%d", i)
		set("security", "nat", "source", "pool", pool, "address", fmt.Sprintf("10.%d.%d.1/32", i/256, i%256))
		set("security", "nat", "source", "rule-set", "RS", "rule", rule, "match")
		set("security", "nat", "source", "rule-set", "RS", "rule", rule, "then", "source-nat", "pool", pool)
	}
	set("security", "nat", "source", "pool", "good", "address", "198.51.100.7/32")
	set("security", "nat", "source", "rule-set", "RS", "rule", "rgood", "match", "source-address", "10.0.0.0/24")
	set("security", "nat", "source", "rule-set", "RS", "rule", "rgood", "then", "source-nat", "pool", "good")
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// The compiler→snapshot half of the #9874 budget parity: MaxSourceNATPoolCount
// pools referenced ONLY by poisoned rules build NO allocator in Rust, so they
// must not consume the aggregate pool-count budget. Before the
// sourceNATAggregateReferencedCharges skip they consumed all 1,024 slots and
// the healthy pool referenced after them shipped PoolUnusable=true /
// "aggregate_over_budget" — a pool the dataplane would have installed,
// disabled on the tolerant recovery path. Mirrors
// TestSourceNATSnapshotUnusablePoolsDoNotPoisonHealthy_6812, whose pools fail
// on definition where these fail on the empty match.
//
// RED-on-revert (drop the LenientMatchDropped skip in the charges walk): the
// "good" snapshot comes back PoolUnusable=true with reason
// "aggregate_over_budget".
func TestSourceNATSnapshotPoisonedOnlyPoolsDoNotConsumeBudget_9874(t *testing.T) {
	nBad := config.MaxSourceNATPoolCount
	cfg := snatPoisonedPlusHealthyCfg_9874(t, nBad)
	snaps := buildSourceNATSnapshots(cfg, nil)
	if len(snaps) != nBad+1 {
		t.Fatalf("snapshots = %d, want %d — the fixture never reached the pool-count budget",
			len(snaps), nBad+1)
	}

	// PRECONDITION: every bad pool ships marked (the fixture IS poisoned) and
	// definition-usable (its pool fails on nothing else), so the ONLY reason
	// to skip it in the budget walk is the poison.
	for i := range nBad {
		s := snapByPool_6812(t, snaps, fmt.Sprintf("bad%d", i))
		if !s.LenientMatchDropped {
			t.Fatalf("bad%d: LenientMatchDropped = false — the fixture is not poisoned, "+
				"so the healthy-pool assertion below would prove nothing", i)
		}
		if s.PoolUnusable {
			t.Fatalf("bad%d: PoolUnusable = true (reason %q), want false — the fixture pools "+
				"must be definition-usable so the poison is the only skip", i, s.PoolUnusableReason)
		}
	}

	// THE DISCRIMINATOR: the healthy pool survives, and ships intact.
	good := snapByPool_6812(t, snaps, "good")
	if good.PoolUnusable {
		t.Fatalf("good: PoolUnusable = true (reason %q), want false — %d pools that build NO "+
			"allocator consumed the whole pool-count budget and disabled a healthy pool. "+
			"The Rust walk (resolve_pool_allocators) builds nothing for poisoned rules and "+
			"would have installed this one, so the two sides disagree about which pools live",
			good.PoolUnusableReason, nBad)
	}
	if good.LenientMatchDropped {
		t.Fatalf("good: LenientMatchDropped = true — the healthy pool's rule was poisoned (over-reject)")
	}
	if len(good.PoolAddresses) != 1 || good.PoolAddresses[0] != "198.51.100.7/32" {
		t.Fatalf("good: PoolAddresses = %v, want [198.51.100.7/32]", good.PoolAddresses)
	}
}
