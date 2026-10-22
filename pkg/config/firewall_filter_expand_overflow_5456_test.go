package config

import (
	"math"
	"strings"
	"testing"
)

// #5456: FilterTermExpansionCount is the per-term counter-slot STRIDE every
// counter reader walks. It used to compute the src×dst×dstPort×srcPort
// cross-product as int products and cast the result straight to uint32 with NO
// overflow check. A term whose product exceeds 2^32 (a large prefix-list
// cross-product) therefore WRAPPED to a small wrong stride, making
// `show firewall filter` / the Prometheus collector read into a neighbouring
// term's counter slots (unbounded drift), and the same unbounded product drove
// a config-driven commit-time expansion DoS.
//
// The fix computes the product in overflow-checked uint64
// (FilterTermExpansionCount64) and CLAMPS the uint32 stride to
// MaxFilterTermExpansion instead of wrapping. The over-bound term is NOT
// rejected — the live userspace dataplane enforces it natively (prefix-set
// membership, name-keyed counters, no cross-product), so commit only appends an
// ADVISORY warning (warnFilterTermExpansionOverBound); the drift/DoS harm
// existed only on the retired-eBPF counter path.

// bigPrefixList returns a PrefixList carrying n distinct-in-name (content is
// irrelevant to the count, which reads len(Prefixes)) prefixes. It builds the
// slice directly — no parsing — so a multi-thousand-entry list is cheap.
func bigPrefixList(name string, n int) *PrefixList {
	pfx := make([]string, n)
	for i := range pfx {
		pfx[i] = "10.0.0.0/32"
	}
	return &PrefixList{Name: name, Prefixes: pfx}
}

// TestFilterExpansionCount64ExceedsUint32NoWrap pins the core arithmetic: a
// cross-product past 2^32 is computed exactly in uint64 and the uint32 stride
// CLAMPS to the cap rather than wrapping.
//
// RED-ON-REVERT: restore `return uint32(nSrc * nDst * nDstPorts * nSrcPorts)`
// and FilterTermExpansionCount returns the WRAPPED value (uint32 of the true
// product), not the clamp — the wrapCheck assertion below fails.
func TestFilterExpansionCount64ExceedsUint32NoWrap(t *testing.T) {
	const n = 66000 // 66000 * 66000 = 4_356_000_000 > MaxUint32 (4_294_967_296)
	prefixLists := map[string]*PrefixList{
		"src": bigPrefixList("src", n),
		"dst": bigPrefixList("dst", n),
	}
	term := &FirewallFilterTerm{
		Name:              "t",
		Action:            FilterActionDiscard,
		SourcePrefixLists: []PrefixListRef{{Name: "src"}},
		DestPrefixLists:   []PrefixListRef{{Name: "dst"}},
	}

	want64 := uint64(n) * uint64(n)
	if got := FilterTermExpansionCount64(term, prefixLists); got != want64 {
		t.Fatalf("FilterTermExpansionCount64 = %d, want exact %d", got, want64)
	}
	if want64 <= math.MaxUint32 {
		t.Fatalf("test misconfigured: product %d does not exceed MaxUint32", want64)
	}

	got := FilterTermExpansionCount(term, prefixLists)
	if got != MaxFilterTermExpansion {
		t.Fatalf("FilterTermExpansionCount = %d, want clamp to MaxFilterTermExpansion (%d)",
			got, MaxFilterTermExpansion)
	}
	// The load-bearing assertion: the stride is NOT the silently-wrapped value
	// the old `uint32(product)` cast produced.
	if wrapped := uint32(want64); got == wrapped {
		t.Fatalf("FilterTermExpansionCount returned the WRAPPED value %d — the "+
			"uint32 truncation was not fixed", wrapped)
	}
}

// TestFilterExpansionOverCapWarnsNotRejects proves an over-cap term is
// COMMITTED with an advisory warning — NOT hard-rejected. The harm (stride drift
// / materialization) is retired-eBPF-only; the live userspace dataplane enforces
// the term natively, so rejecting would false-reject a legitimate config.
//
// RED-ON-REVERT: remove the `if count > MaxFilterTermExpansion` guard in
// warnFilterTermExpansionOverBound and no warning is appended.
func TestFilterExpansionOverCapWarnsNotRejects(t *testing.T) {
	const n = 66000
	cfg := &Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*PrefixList{
		"src": bigPrefixList("src", n),
		"dst": bigPrefixList("dst", n),
	}
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"f": {Name: "f", Terms: []*FirewallFilterTerm{
			{
				Name:              "huge",
				Action:            FilterActionDiscard,
				SourcePrefixLists: []PrefixListRef{{Name: "src"}},
				DestPrefixLists:   []PrefixListRef{{Name: "dst"}},
			},
		}},
	}
	warnFilterTermExpansionOverBound(cfg)
	if !anyWarningContains(cfg, "huge") || !anyWarningContains(cfg, "filter \"f\"") {
		t.Fatalf("advisory warning must name the offending filter/term; warnings=%v", cfg.Warnings)
	}
	if !anyWarningContains(cfg, "COMMITTED") {
		t.Fatalf("advisory should state the term is committed/enforced; warnings=%v", cfg.Warnings)
	}
}

// TestFilterExpansionAtCapNoWarning pins the boundary: a term whose product is
// exactly MaxFilterTermExpansion produces NO advisory (the warn is strictly `>`
// the bound, not `>=`).
func TestFilterExpansionAtCapNoWarning(t *testing.T) {
	cfg := &Config{}
	cfg.PolicyOptions.PrefixLists = map[string]*PrefixList{
		"src": bigPrefixList("src", MaxFilterTermExpansion),
	}
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{
		"f": {Name: "f", Terms: []*FirewallFilterTerm{
			{
				Name:              "atcap",
				Action:            FilterActionDiscard,
				SourcePrefixLists: []PrefixListRef{{Name: "src"}}, // nSrc=cap, others=1
			},
		}},
	}
	if got := FilterTermExpansionCount64(cfg.Firewall.FiltersInet["f"].Terms[0], cfg.PolicyOptions.PrefixLists); got != MaxFilterTermExpansion {
		t.Fatalf("count64 at boundary = %d, want %d", got, MaxFilterTermExpansion)
	}
	warnFilterTermExpansionOverBound(cfg)
	if len(cfg.Warnings) != 0 {
		t.Fatalf("a term expanding to exactly the cap must produce no advisory, got: %v", cfg.Warnings)
	}
}

// TestFilterExpansionNormalTermUnchanged pins that the ordinary (small) case is
// bit-for-bit unchanged: the exact product is returned and no advisory fires.
func TestFilterExpansionNormalTermUnchanged(t *testing.T) {
	prefixLists := map[string]*PrefixList{
		"src": {Name: "src", Prefixes: []string{"10.1.0.0/24", "10.2.0.0/24"}},
	}
	term := &FirewallFilterTerm{
		Name:              "t",
		Action:            FilterActionAccept,
		SourceAddresses:   []string{"192.0.2.1/32"},         // nSrc = 1 literal + 2 prefixes = 3
		SourcePrefixLists: []PrefixListRef{{Name: "src"}},   //
		DestinationPorts:  []string{"80", "443"},            // nDstPorts = 2
		SourcePorts:       []string{"1024", "2048", "4096"}, // nSrcPorts = 3
	}
	// nSrc(3) × nDst(1) × nDstPorts(2) × nSrcPorts(3) = 18
	if got := FilterTermExpansionCount(term, prefixLists); got != 18 {
		t.Fatalf("FilterTermExpansionCount = %d, want 18 (normal case unchanged)", got)
	}
	if got := FilterTermExpansionCount64(term, prefixLists); got != 18 {
		t.Fatalf("FilterTermExpansionCount64 = %d, want 18", got)
	}
	cfg := &Config{}
	cfg.PolicyOptions.PrefixLists = prefixLists
	cfg.Firewall.FiltersInet = map[string]*FirewallFilter{"f": {Name: "f", Terms: []*FirewallFilterTerm{term}}}
	warnFilterTermExpansionOverBound(cfg)
	if len(cfg.Warnings) != 0 {
		t.Fatalf("a normal small term must produce no advisory, got: %v", cfg.Warnings)
	}
}

// TestFilterExpansionCommitWarnsOverCap drives the FULL, WIRED commit path
// (CompileConfig → runUniformGates → warnFilterTermExpansionOverBound) with a
// real ConfigTree whose term cross-product exceeds 2^32
// (256×256×256×257 = 4_311_744_512), and asserts commit SUCCEEDS with an
// advisory warning and a CLAMPED (never wrapped) stride.
//
// RED-ON-REVERT (two independent regressions this catches):
//   - Restore the `uint32(...)` cast in FilterTermExpansionCount → the re-checked
//     stride wraps to 16_777_216 instead of the clamp; the clamp assertion fails.
//   - Remove the warnFilterTermExpansionOverBound call in runUniformGates → the
//     warning-present assertion fails.
//
// This is the reconciliation anchor (#5514 review): a config the LIVE dataplane
// enforces must COMMIT, not be rejected. Both the strict commit path and the
// lenient (#1960) path boot it.
func TestFilterExpansionCommitWarnsOverCap(t *testing.T) {
	var lines []string
	// 256 source prefixes, 256 destination prefixes.
	for i := 0; i < 256; i++ {
		lines = append(lines,
			"set policy-options prefix-list SRC 10."+itoa(i)+".0.0/24",
			"set policy-options prefix-list DST 172.16."+itoa(i)+".0/24",
		)
	}
	lines = append(lines,
		"set firewall family inet filter f term t from source-prefix-list SRC",
		"set firewall family inet filter f term t from destination-prefix-list DST",
	)
	// 256 destination ports + 257 source ports → product = 256*256*256*257.
	for i := 0; i < 256; i++ {
		lines = append(lines, "set firewall family inet filter f term t from destination-port "+itoa(1+i))
	}
	for i := 0; i < 257; i++ {
		lines = append(lines, "set firewall family inet filter f term t from source-port "+itoa(1+i))
	}
	lines = append(lines, "set firewall family inet filter f term t then discard")

	tree := buildTree(t, lines)

	// Strict commit SUCCEEDS (the live dataplane enforces the term).
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict commit must COMMIT an over-cap term the live path enforces, got: %v", err)
	}
	// Sanity: the compiled term's exact cross-product exceeds 2^32 so the old
	// uint32 cast would have wrapped (this is what makes the RED-on-revert real).
	term := cfg.Firewall.FiltersInet["f"].Terms[0]
	prod := FilterTermExpansionCount64(term, cfg.PolicyOptions.PrefixLists)
	if prod <= math.MaxUint32 {
		t.Fatalf("test misconfigured: compiled product %d does not exceed 2^32 "+
			"(nSrc=%d nDst=%d nDstPorts=%d nSrcPorts=%d)", prod,
			len(term.SourcePrefixLists), len(term.DestPrefixLists),
			len(term.DestinationPorts), len(term.SourcePorts))
	}
	// The stride is CLAMPED, never the wrapped value.
	if got := FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists); got != MaxFilterTermExpansion {
		t.Fatalf("stride = %d, want clamp %d (never the wrap %d)",
			got, MaxFilterTermExpansion, uint32(prod))
	}
	if !anyWarningContains(cfg, "expands to") {
		t.Errorf("commit should carry the expansion advisory; warnings=%v", cfg.Warnings)
	}

	// The lenient (#1960) path also boots it.
	if _, lerr := CompileConfigLenient(tree); lerr != nil {
		t.Fatalf("lenient path must also boot an over-cap config (#1960), got: %v", lerr)
	}
}

// TestFilterExpansionLegitimateLargeConfigCommits encodes the #5514 reviewer's
// concrete example: two ~1500-entry prefix-lists on one term (1501×1501 ≈ 2.25M
// > MaxFilterTermExpansion but < 2^32). The live userspace dataplane handles
// 1500+1500 prefixes trivially, so this MUST commit (not false-reject) — with
// the clamped stride and an advisory.
func TestFilterExpansionLegitimateLargeConfigCommits(t *testing.T) {
	var lines []string
	for i := 0; i < 1500; i++ {
		// 1500 distinct /24s each: 10.<hi>.<lo>.0/24.
		lines = append(lines,
			"set policy-options prefix-list BIGSRC 10."+itoa(i/256)+"."+itoa(i%256)+".0/24",
			"set policy-options prefix-list BIGDST 172."+itoa(16+i/256)+"."+itoa(i%256)+".0/24",
		)
	}
	lines = append(lines,
		"set firewall family inet filter big term t from source-prefix-list BIGSRC",
		"set firewall family inet filter big term t from destination-prefix-list BIGDST",
		"set firewall family inet filter big term t then discard",
	)
	tree := buildTree(t, lines)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("a legitimate 1500×1500 term the live path enforces must COMMIT, got: %v", err)
	}
	term := cfg.Firewall.FiltersInet["big"].Terms[0]
	// Both prefix-lists resolved onto the committed term (config is intact).
	if len(term.SourcePrefixLists) != 1 || len(term.DestPrefixLists) != 1 {
		t.Fatalf("committed term must retain both prefix-list refs, got src=%v dst=%v",
			term.SourcePrefixLists, term.DestPrefixLists)
	}
	prod := FilterTermExpansionCount64(term, cfg.PolicyOptions.PrefixLists)
	if prod <= MaxFilterTermExpansion || prod > math.MaxUint32 {
		t.Fatalf("test misconfigured: product %d should be in (cap, 2^32)", prod)
	}
	if got := FilterTermExpansionCount(term, cfg.PolicyOptions.PrefixLists); got != MaxFilterTermExpansion {
		t.Fatalf("stride = %d, want clamp %d", got, MaxFilterTermExpansion)
	}
	if !anyWarningContains(cfg, "expands to") {
		t.Errorf("commit should carry the expansion advisory; warnings=%v", cfg.Warnings)
	}
}

func anyWarningContains(cfg *Config, sub string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
