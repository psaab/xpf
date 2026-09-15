package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// #9874: the typed poison for an authored-but-empty NAT match.
//
// The #8430 strict gate rejects such a rule at commit; the tolerant load /
// peer-sync path downgrades to a warning. Without a marker the rule ships with
// an empty match set, which the dataplane reads as UNCONSTRAINED — a catch-all
// translator. compileNATSource/compileNATDestination therefore derive
// LenientMatchDropped from the SAME predicate the gate uses, so the snapshot
// builders can ship the rule fail-closed.

func poisonTree9874(t *testing.T, paths ...[]string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, p := range paths {
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", p, err)
		}
	}
	return tree
}

func snatPaths9874(matchPaths ...[]string) [][]string {
	paths := [][]string{
		{"security", "nat", "source", "pool", "p1", "address", "172.16.0.5/32"},
		{"security", "nat", "source", "rule-set", "RS", "from", "zone", "lan"},
		{"security", "nat", "source", "rule-set", "RS", "to", "zone", "wan"},
	}
	paths = append(paths, matchPaths...)
	return append(paths,
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "then", "source-nat", "pool", "p1"})
}

func dnatPaths9874(matchPaths ...[]string) [][]string {
	paths := [][]string{
		{"security", "nat", "destination", "pool", "p1", "address", "192.168.1.10"},
		{"security", "nat", "destination", "rule-set", "RS", "from", "zone", "untrust"},
	}
	paths = append(paths, matchPaths...)
	return append(paths,
		[]string{"security", "nat", "destination", "rule-set", "RS", "rule", "R1", "then", "destination-nat", "pool", "p1"})
}

func snatRule9874(t *testing.T, cfg *Config) *NATRule {
	t.Helper()
	if len(cfg.Security.NAT.Source) == 0 || len(cfg.Security.NAT.Source[0].Rules) == 0 {
		t.Fatalf("lenient compile produced no source-NAT rule")
	}
	return cfg.Security.NAT.Source[0].Rules[0]
}

func dnatRule9874(t *testing.T, cfg *Config) *NATRule {
	t.Helper()
	d := cfg.Security.NAT.Destination
	if d == nil || len(d.RuleSets) == 0 || len(d.RuleSets[0].Rules) == 0 {
		t.Fatalf("lenient compile produced no destination-NAT rule")
	}
	return d.RuleSets[0].Rules[0]
}

// The marker derivation matrix, one cell per shape. RED-on-revert: delete
// either setter and the poisoned shapes red while the gate tests stay green
// (the gate reads matchAuthored, not the marker).
func TestLenientMatchDroppedSourceEmpty_9874(t *testing.T) {
	tree := poisonTree9874(t, snatPaths9874(
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match"},
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected the empty-match rule (no-brick): %v", err)
	}
	r := snatRule9874(t, cfg)
	if !r.matchAuthored {
		t.Fatalf("premise broken: bare `match` container did not set matchAuthored")
	}
	if !r.LenientMatchDropped {
		t.Fatalf("empty authored match left LenientMatchDropped=false — the rule would ship catch-all")
	}
}

func TestLenientMatchDroppedSourceValueless_9874(t *testing.T) {
	tree := poisonTree9874(t, snatPaths9874(
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match", "source-address"},
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected the valueless-match rule (no-brick): %v", err)
	}
	if r := snatRule9874(t, cfg); !r.LenientMatchDropped {
		t.Fatalf("valueless `source-address;` left LenientMatchDropped=false — the #8430 valueless route")
	}
}

func TestLenientMatchDroppedSourcePopulated_9874(t *testing.T) {
	tree := poisonTree9874(t, snatPaths9874(
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match", "source-address", "10.0.0.0/24"},
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected a populated rule: %v", err)
	}
	if r := snatRule9874(t, cfg); r.LenientMatchDropped {
		t.Fatalf("populated match set LenientMatchDropped=true — over-reject")
	}
}

func TestLenientMatchDroppedSourceScopeOnly_9874(t *testing.T) {
	tree := poisonTree9874(t, snatPaths9874()...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected a scope-only rule: %v", err)
	}
	r := snatRule9874(t, cfg)
	if r.matchAuthored {
		t.Fatalf("premise broken: scope-only rule reports matchAuthored")
	}
	if r.LenientMatchDropped {
		t.Fatalf("scope-only rule (no `match`) poisoned — the legitimate catch-all must stay unmarked")
	}
}

func TestLenientMatchDroppedSourceExplicitCatchAll_9874(t *testing.T) {
	tree := poisonTree9874(t, snatPaths9874(
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match", "source-address", "0.0.0.0/0"},
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected an explicit catch-all: %v", err)
	}
	if r := snatRule9874(t, cfg); r.LenientMatchDropped {
		t.Fatalf("explicit `0.0.0.0/0` poisoned — an explicit catch-all is constrained and legal")
	}
}

func TestLenientMatchDroppedDestEmpty_9874(t *testing.T) {
	tree := poisonTree9874(t, dnatPaths9874(
		[]string{"security", "nat", "destination", "rule-set", "RS", "rule", "R1", "match"},
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected the empty-match DNAT rule (no-brick): %v", err)
	}
	if r := dnatRule9874(t, cfg); !r.LenientMatchDropped {
		t.Fatalf("empty authored DNAT match left LenientMatchDropped=false")
	}
}

func TestLenientMatchDroppedDestPopulated_9874(t *testing.T) {
	tree := poisonTree9874(t, dnatPaths9874(
		[]string{"security", "nat", "destination", "rule-set", "RS", "rule", "R1", "match", "destination-address", "203.0.113.10/32"},
	)...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile rejected a populated DNAT rule: %v", err)
	}
	if r := dnatRule9874(t, cfg); r.LenientMatchDropped {
		t.Fatalf("populated DNAT match poisoned — over-reject")
	}
}

// Strict behavior unchanged: the same tree the tolerant path marks is still
// hard-rejected at commit.
func TestStrictStillRejectsEmptyMatch_9874(t *testing.T) {
	tree := poisonTree9874(t, snatPaths9874(
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "R1", "match"},
	)...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict compile ACCEPTED the empty-match rule — the #8430 gate moved")
	} else if !strings.Contains(err.Error(), "8430") {
		t.Fatalf("strict rejected but not via the #8430 gate: %v", err)
	}
}

// The marker is a compile-time diagnostic (`json:"-"`): it must not join the
// typed Config's JSON (no #4406 golden churn) and the fingerprint therefore
// cannot see it — assert both, so a retag reds here rather than as a golden
// avalanche.
func TestLenientMatchDroppedNotSerialized_9874(t *testing.T) {
	r := &NATRule{Name: "r", LenientMatchDropped: true}
	j, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal NATRule: %v", err)
	}
	if strings.Contains(string(j), "LenientMatchDropped") {
		t.Fatalf("marker leaked into typed JSON: %s", j)
	}
	marked := &Config{}
	marked.Security.NAT.Source = []*NATRuleSet{{Name: "rs", Rules: []*NATRule{r}}}
	clean := &Config{}
	clean.Security.NAT.Source = []*NATRuleSet{{Name: "rs", Rules: []*NATRule{{Name: "r"}}}}
	if ConfigFingerprint(marked) != ConfigFingerprint(clean) {
		t.Fatalf("fingerprint sees the marker — the documented fingerprint-blindness broke")
	}
}

// A pool referenced ONLY by poisoned rules consumes no aggregate budget —
// Rust builds no allocator for it — while a pool ALSO referenced by a
// healthy rule IS charged, at its first HEALTHY reference (the poisoned rule
// ships but carries no pending, so the dataplane charges the shared key
// where the first pending rule for it is emitted). RED-on-revert (drop the
// LenientMatchDropped skip in sourceNATAggregateReferencedCharges): charges
// come back [poolA poolB poolC].
func TestAggregateBudgetSkipsPoisonedOnlyPools_9874(t *testing.T) {
	tree := poisonTree9874(t,
		[]string{"security", "nat", "source", "pool", "poolA", "address", "198.51.100.1/32"},
		[]string{"security", "nat", "source", "pool", "poolB", "address", "198.51.100.2/32"},
		[]string{"security", "nat", "source", "pool", "poolC", "address", "198.51.100.3/32"},
		[]string{"security", "nat", "source", "rule-set", "RS", "from", "zone", "lan"},
		[]string{"security", "nat", "source", "rule-set", "RS", "to", "zone", "wan"},
		// r0: poisoned reference to poolA (bare match).
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "r0", "match"},
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "r0", "then", "source-nat", "pool", "poolA"},
		// r1: healthy reference to poolB.
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "r1", "match", "source-address", "10.0.0.0/24"},
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "r1", "then", "source-nat", "pool", "poolB"},
		// r2: healthy reference to poolA — poolA charges HERE, not at r0.
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "r2", "match", "source-address", "10.1.0.0/24"},
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "r2", "then", "source-nat", "pool", "poolA"},
		// r3: poisoned-only poolC.
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "r3", "match"},
		[]string{"security", "nat", "source", "rule-set", "RS", "rule", "r3", "then", "source-nat", "pool", "poolC"},
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	// Premise: the bare-match rules are marked, the populated ones are not.
	// A fixture whose markers drifted would prove nothing about the skip.
	byName := map[string]*NATRule{}
	for _, rs := range cfg.Security.NAT.Source {
		for _, r := range rs.Rules {
			byName[r.Name] = r
		}
	}
	for name, want := range map[string]bool{"r0": true, "r1": false, "r2": false, "r3": true} {
		r, ok := byName[name]
		if !ok {
			t.Fatalf("rule %s missing — the fixture never compiled", name)
		}
		if r.LenientMatchDropped != want {
			t.Fatalf("rule %s: LenientMatchDropped = %v, want %v", name, r.LenientMatchDropped, want)
		}
	}
	var got []string
	for _, c := range sourceNATAggregateReferencedCharges(cfg) {
		got = append(got, c.name)
	}
	want := []string{"poolB", "poolA"}
	if len(got) != len(want) {
		t.Fatalf("charges = %v, want %v (poolC is poisoned-only and must not charge)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("charges = %v, want %v (poolA charges at its first HEALTHY reference r2, after poolB at r1)", got, want)
		}
	}
	if poison := SourceNATAggregateOverBudgetPools(cfg); len(poison) != 0 {
		t.Fatalf("poison = %v, want empty — nothing here crosses a budget", poison)
	}
}
