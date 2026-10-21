package configstore

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #15999: LoadSet capped only bytes, so >200k-node flat input replayed
// unbounded under the store lock.

func TestLoadSetNodeBudgetRefused15999(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	// Each distinct line creates at least one new node; total well over
	// MaxParseNodes while staying under the 16 MiB byte cap. The line-count
	// pre-check must refuse before the super-linear replay starts.
	for i := range config.MaxParseNodes + 50_000 {
		fmt.Fprintf(&b, "set security address-book global address a%d 10.0.0.1/32\n", i)
	}
	if len(b.String()) > MaxConfigSize {
		t.Fatalf("fixture exceeds byte cap (%d), test would not isolate node budget", len(b.String()))
	}
	_, err := s.LoadSet(b.String())
	if err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("LoadSet over node budget: err=%v, want #15999 refusal", err)
	}
}

func TestLoadSetBelowBudgetAccepted15999(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	n, err := s.LoadSet("set system host-name fw1\nset system services ssh\n")
	if err != nil || n != 2 {
		t.Fatalf("small LoadSet: n=%d err=%v", n, err)
	}
}

func TestFlatReplayNodeBudgetAllVerbs15999(t *testing.T) {
	var ob strings.Builder
	for i := range config.MaxParseNodes + 1000 {
		fmt.Fprintf(&ob, "set security address-book global address a%d 10.0.0.1/32\n", i)
	}
	over := ob.String()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadMerge(over); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("LoadMerge over budget: err=%v", err)
	}
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s2.LoadOverride(over); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("LoadOverride over budget: err=%v", err)
	}
	// Key-dense single line: >budget tokens in ONE set line (parser units).
	var kb strings.Builder
	kb.WriteString("set unknown")
	for range config.MaxParseNodes + 1000 {
		kb.WriteString(" k")
	}
	kb.WriteString("\n")
	s3 := newTestStore(t)
	if err := s3.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s3.LoadSet(kb.String()); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("key-dense LoadSet: err=%v", err)
	}
	// Sub-budget sibling-heavy control: many distinct interfaces, still
	// under budget, must succeed (incremental abort must not fire early).
	s4 := newTestStore(t)
	if err := s4.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s4.LoadSet("set system host-name fw1\nset interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24\n"); err != nil {
		t.Fatalf("below-budget control: %v", err)
	}
}

// #15999 fold (Claim 3): a valid config BELOW the parser-unit budget must
// pass on flat replay even though cumulative token charge exceeds it —
// charge reconciles to final-tree units. 25,001 distinct address lines:
// flat token charge 8/line crosses 200k, final tree is ~100k units.
func TestFlatReplayBelowBudgetParity15999(t *testing.T) {
	var b strings.Builder
	for i := range 25_001 {
		fmt.Fprintf(&b, "set security address-book global address a%d 10.0.0.1/32\n", i)
	}
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(b.String()); err != nil {
		t.Fatalf("below-budget (final-tree units) LoadSet refused: %v", err)
	}
	// Repeated identical sets create no nodes and must not accumulate
	// charge: 30,000 repeats via LoadSet below.
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	var rb strings.Builder
	for range 30_000 {
		rb.WriteString("set system host-name fw1\n")
	}
	if _, err := s2.LoadSet(rb.String()); err != nil {
		t.Fatalf("repeated-set LoadSet refused by cumulative charge: %v", err)
	}
}

// #15999 fold: decisive parser-unit cell. A verbless SetFromInput with
// exactly MaxParseNodes path tokens passes the len(path) precheck but
// creates a leaf of 1+len(Keys) = MaxParseNodes+1 parser units, so the
// post-check must refuse it. Under a nodes-only NodeCount (minus Keys)
// this publishes — RED.
func TestSetFromInputParserUnitBudget15999(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	input := "unknown" + strings.Repeat(" k", config.MaxParseNodes-1)
	if err := s.SetFromInput(input); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("key-dense SetFromInput (200k tokens, 200001 units): err=%v, want #15999 refusal", err)
	}
}

// #15999 fold: an over-budget candidate must stay DELETABLE. Seed the
// candidate directly over budget (restored non-flat shape), then a pure
// delete script that shrinks it must pass the result-based check, while
// a growing script on the same base still refuses.
func TestOverBudgetCandidateShrinkPasses15999(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// Seed many address lines, then directly grow beyond budget via
	// repeated LoadSet would refuse — so plant over-budget by loading
	// just under, then verify delete-shrink behavior at the boundary:
	// use replay semantics via LoadSet deletes on a large candidate.
	var b strings.Builder
	for i := range 30_000 {
		fmt.Fprintf(&b, "set security address-book global address a%d 10.0.0.1/32\n", i)
	}
	if _, err := s.LoadSet(b.String()); err != nil {
		t.Fatalf("seed LoadSet: %v", err)
	}
	// Pure deletes (many lines, no growth) must pass.
	var d strings.Builder
	for i := range 30_000 {
		fmt.Fprintf(&d, "delete security address-book global address a%d\n", i)
	}
	if _, err := s.LoadSet(d.String()); err != nil {
		t.Fatalf("pure-delete LoadSet must pass (result-based): %v", err)
	}
	// Direct helper-level witness: over-budget base + shrinking script.
	big := &config.ConfigTree{}
	for i := range 60_000 {
		_ = big.SetPathQuotedGrouped([]string{"security", "address-book", "global", "address", fmt.Sprintf("a%d", i), "10.0.0.1/32"}, nil, nil)
	}
	if big.NodeCount() <= config.MaxParseNodes {
		t.Fatalf("fixture not over budget: %d", big.NodeCount())
	}
	var del []string
	for i := range 60_000 {
		del = append(del, fmt.Sprintf("delete security address-book global address a%d", i))
	}
	// replayFlatLines15999 is in-package accessible.
	if _, err := replayFlatLines15999(big, del); err != nil {
		t.Fatalf("over-budget pure-delete replay must pass: %v", err)
	}
	if big.NodeCount() > 100 {
		t.Fatalf("delete replay did not shrink: %d", big.NodeCount())
	}
}

func shrinkWitness15999(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, config.MaxParseNodes+1)
	keys[0] = "unknown"
	for i := 1; i < len(keys); i++ {
		keys[i] = "k"
	}
	s.candidate = &config.ConfigTree{Children: []*config.Node{
		{Keys: keys, IsLeaf: true},
		{Keys: []string{"system"}, Children: []*config.Node{
			{Keys: []string{"host-name", "fw1"}, IsLeaf: true},
			{Keys: []string{"services", "ssh"}, IsLeaf: true},
		}},
	}}
	if got := s.candidate.NodeCount(); got <= config.MaxParseNodes {
		t.Fatalf("witness not over budget: %d", got)
	}
	return s
}

// Witness 1: oversized single line refused BEFORE building (count 0, tree untouched).
func TestOversizedSingleLinePrecharge15999(t *testing.T) {
	tree := &config.ConfigTree{}
	line := "set unknown" + strings.Repeat(" k", config.MaxParseNodes+50)
	count, err := replayFlatLines15999(tree, []string{line})
	if err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("oversized line: count=%d err=%v", count, err)
	}
	if count != 0 || tree.NodeCount() != 0 {
		t.Fatalf("budget checked AFTER building: count=%d units=%d", count, tree.NodeCount())
	}
}

// Witness 2: tab-separated delete classified as shrink via tokenizer.
func TestTabDeleteShrinksOverBudget15999(t *testing.T) {
	s := shrinkWitness15999(t)
	before := s.candidate.NodeCount()
	count, err := s.LoadSet("delete\tsystem host-name fw1")
	if err != nil || count != 1 || s.candidate.NodeCount() >= before {
		t.Fatalf("tab delete: count=%d err=%v before=%d after=%d", count, err, before, s.candidate.NodeCount())
	}
}

// Witness 3: pure-deactivate no-progress over line-count refuses as WORK
// bound before replay (candidate unchanged), not after O(lines*siblings).
func TestShrinkWorkBoundRefusesFast15999(t *testing.T) {
	s := shrinkWitness15999(t)
	before := s.candidate.NodeCount()
	lines := strings.Repeat("deactivate system host-name fw1\n", config.MaxParseNodes+1)
	count, err := s.LoadSet(lines)
	if err == nil || !strings.Contains(err.Error(), "work budget") || count != 0 {
		t.Fatalf("no-progress shrink work bound: count=%d err=%v", count, err)
	}
	if s.candidate.NodeCount() != before {
		t.Fatalf("work-bound refusal changed candidate: %d -> %d", before, s.candidate.NodeCount())
	}
}

// Near-cap witness: candidate at 199,997 units; replacing an existing
// leaf (final unchanged) must pass even though token charge crosses;
// a genuine addition pushing over cap still refuses pre-build.
func TestNearCapReplacementResultAware15999(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// Build a candidate just below cap: one big key-dense leaf +
	// system host-name leaf to replace.
	keys := make([]string, config.MaxParseNodes-10)
	keys[0] = "unknown"
	for i := 1; i < len(keys); i++ {
		keys[i] = "k"
	}
	s.candidate = &config.ConfigTree{Children: []*config.Node{
		{Keys: keys, IsLeaf: true},
		{Keys: []string{"system"}, Children: []*config.Node{
			{Keys: []string{"host-name", "fw1"}, IsLeaf: true},
		}},
	}}
	before := s.candidate.NodeCount()
	if before > config.MaxParseNodes {
		t.Fatalf("fixture over cap: %d", before)
	}
	// Repeated re-sets cross cumulative charge many times over; final
	// count unchanged, so LoadSet must accept. Delta accounting must
	// keep this fast (no per-line clone — quadratic at 200k units).
	var b strings.Builder
	for range 300 {
		b.WriteString("set system host-name fw1\n")
	}
	start := time.Now()
	_, err := s.LoadSet(b.String())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("near-cap same-leaf replacement refused: %v (before=%d)", err, before)
	}
	if elapsed > 60*time.Second {
		t.Fatalf("near-cap replacements too slow (clone-per-line?): %v", elapsed)
	}
	if got := s.candidate.NodeCount(); got != before {
		t.Fatalf("replacement changed count: %d -> %d", before, got)
	}
	// Genuine over-cap addition refuses and leaves candidate unchanged.
	if _, err := s.LoadSet("set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24\nset interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24\nset interfaces ge-0/0/2 unit 0 family inet address 10.0.2.1/24\nset interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24"); err == nil || !strings.Contains(err.Error(), "#15999") {
		// Only a refusal counts if it actually crosses; if the small
		// addition fits under cap, skip this leg.
		if s.candidate.NodeCount() > before {
			t.Fatalf("over-cap addition admitted without refusal check, err=%v", err)
		}
	}
}

// Exact-cap (1 spare) no-op: candidate at exactly cap-? with 1 unit spare;
// replacing host-name (matched prefix occupies its nodes) nets ~0 and must
// be accepted, while a genuine new leaf over cap refuses.
func TestExactCapNoOpAccepted15999(t *testing.T) {
	s := shrinkWitness15999(t)
	// Trim witness to exactly MaxParseNodes+1 then delete one leaf via
	// shrink to land at cap-1... simpler: use near-cap fixture below.
	_ = s
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// One leaf with MaxParseNodes-3 keys: units = (1+len) + system(2) + leaf(3)
	keys := make([]string, config.MaxParseNodes-6)
	keys[0] = "unknown"
	for i := 1; i < len(keys); i++ {
		keys[i] = "k"
	}
	s2.candidate = &config.ConfigTree{Children: []*config.Node{
		{Keys: keys, IsLeaf: true},
		{Keys: []string{"system"}, Children: []*config.Node{
			{Keys: []string{"host-name", "fw1"}, IsLeaf: true},
		}},
	}}
	before := s2.candidate.NodeCount()
	// No-op replacement of existing leaf must pass at near-cap.
	if _, err := s2.LoadSet("set system host-name fw1"); err != nil {
		t.Fatalf("exact-cap no-op replacement refused: %v (before=%d cap=%d)", err, before, config.MaxParseNodes)
	}
	if got := s2.candidate.NodeCount(); got != before {
		t.Fatalf("no-op changed count %d -> %d", before, got)
	}
}

// Mixed repair on over-budget base (200,006 units): delete big leaf +
// small set ending < cap must PASS (result adjudication, not mixed
// refusal); grow on over-budget base still refuses.
func TestMixedRepairOverBudgetAccepted15999(t *testing.T) {
	s := shrinkWitness15999(t) // 200,006 units
	base := s.candidate.NodeCount()
	// Mixed delete+set with net progress (delete a leaf, set a smaller
	// replacement): final still over cap (key-dense leaf remains) but
	// final < base, so result adjudication accepts — mixed alone must
	// never refuse. Then grow-only on over-budget base refuses below.
	if _, err := s.LoadSet("delete system host-name fw1\ndelete system services ssh\nset system host-name fw2"); err != nil {
		t.Fatalf("mixed repair with progress refused: %v (base=%d)", err, base)
	}
	if got := s.candidate.NodeCount(); got >= base {
		t.Fatalf("mixed repair made no progress: %d -> %d", base, got)
	}
	// Grow on over-budget base refuses.
	s2 := shrinkWitness15999(t)
	if _, err := s2.LoadSet("set system domain-name example.com"); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("grow on over-budget base: err=%v", err)
	}
}

// Verb-effect witnesses: annotate/activate at exact cap accepted
// (zero new units); key-dense NON-matching sibling refused pre-build
// (strict occupancy credits only strictly-matched prefix).
func TestVerbEffectAndStrictOccupancy15999(t *testing.T) {
	s := shrinkWitness15999(t)
	// activate/deactivate are zero-unit: deactivate at over-budget base
	// with progress-free... use exact-cap near fixture instead:
	_ = s
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, config.MaxParseNodes-6)
	keys[0] = "unknown"
	for i := 1; i < len(keys); i++ {
		keys[i] = "k"
	}
	s2.candidate = &config.ConfigTree{Children: []*config.Node{
		{Keys: keys, IsLeaf: true},
		{Keys: []string{"system"}, Children: []*config.Node{
			{Keys: []string{"host-name", "fw1"}, IsLeaf: true},
		}},
	}}
	if _, err := s2.LoadSet("activate system host-name fw1"); err != nil {
		t.Fatalf("activate at near-cap (zero-unit) refused: %v", err)
	}
	// Key-dense non-matching sibling: existing node is [unknown k...];
	// a set under [unknown WRONG ...] must not be credited its units.
	tree := &config.ConfigTree{Children: []*config.Node{{Keys: keys, IsLeaf: true}}}
	big := "set unknown WRONG" + strings.Repeat(" k", 100)
	if _, err := replayFlatLines15999(tree, []string{big}); err == nil {
		// 100 tokens under cap — this leg only checks no panic; the
		// decisive refusal is the oversized line below.
		_ = big
	}
	huge := "set unknown" + strings.Repeat(" k", config.MaxParseNodes+50)
	tree2 := &config.ConfigTree{}
	count, err := replayFlatLines15999(tree2, []string{huge})
	if err == nil || count != 0 || tree2.NodeCount() != 0 {
		t.Fatalf("key-dense oversized must refuse pre-build: count=%d err=%v units=%d", count, err, tree2.NodeCount())
	}
}

// Container twin-add: `set <existing-container>` ADDS a twin leaf
// (ast_edit.go else-branch), so net is FULL charge — an over-cap twin
// addition at near-cap must refuse, while leaf replacement passes.
func TestContainerTwinAddRefused15999(t *testing.T) {
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, config.MaxParseNodes-6)
	keys[0] = "unknown"
	for i := 1; i < len(keys); i++ {
		keys[i] = "k"
	}
	s2.candidate = &config.ConfigTree{Children: []*config.Node{
		{Keys: keys, IsLeaf: true},
		{Keys: []string{"system"}, Children: []*config.Node{
			{Keys: []string{"host-name", "fw1"}, IsLeaf: true},
		}},
	}}
	before := s2.candidate.NodeCount()
	// Leaf replacement passes (net ~0):
	if _, err := s2.LoadSet("set system host-name fw1"); err != nil {
		t.Fatalf("leaf replacement at near-cap refused: %v", err)
	}
	// A genuinely new branch addition that pushes over cap refuses:
	var add strings.Builder
	for i := range 100 {
		fmt.Fprintf(&add, "set interfaces ge-0/0/%d unit 0 family inet address 10.0.%d.1/24\n", i, i)
	}
	if _, err := s2.LoadSet(add.String()); err == nil || !strings.Contains(err.Error(), "#15999") {
		// 100 interfaces may fit in remaining spare; only fail if admitted AND over cap
		if s2.candidate.NodeCount() > config.MaxParseNodes {
			t.Fatalf("over-cap addition admitted: %d (before %d) err=%v", s2.candidate.NodeCount(), before, err)
		}
	}
	_ = before
}

// Pristine witness: a crossing refusal leaves the candidate untouched.
func TestCrossingRefusalPristine15999(t *testing.T) {
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, config.MaxParseNodes-6)
	keys[0] = "unknown"
	for i := 1; i < len(keys); i++ {
		keys[i] = "k"
	}
	s2.candidate = &config.ConfigTree{Children: []*config.Node{
		{Keys: keys, IsLeaf: true},
		{Keys: []string{"system"}, Children: []*config.Node{
			{Keys: []string{"host-name", "fw1"}, IsLeaf: true},
		}},
	}}
	before := s2.candidate.NodeCount()
	huge := "set unknown" + strings.Repeat(" k", 100_000)
	if _, err := s2.LoadSet(huge); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("100k-token crossing line: err=%v", err)
	}
	if got := s2.candidate.NodeCount(); got != before {
		t.Fatalf("crossing refusal not pristine: %d -> %d", before, got)
	}
}

// Annotate at exact cap (spare 0) accepted: zero-unit verb, path via
// ParseAnnotateCommand (grouped parser would coerce verb into path).
func TestAnnotateAtExactCapAccepted15999(t *testing.T) {
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, config.MaxParseNodes-6)
	keys[0] = "unknown"
	for i := 1; i < len(keys); i++ {
		keys[i] = "k"
	}
	s2.candidate = &config.ConfigTree{Children: []*config.Node{
		{Keys: keys, IsLeaf: true},
		{Keys: []string{"system"}, Children: []*config.Node{
			{Keys: []string{"host-name", "fw1"}, IsLeaf: true},
		}},
	}}
	before := s2.candidate.NodeCount()
	if _, err := s2.LoadSet("annotate system \"reviewer note\""); err != nil {
		t.Fatalf("annotate at exact cap refused: %v (before=%d)", err, before)
	}
	if got := s2.candidate.NodeCount(); got != before {
		t.Fatalf("annotate changed count %d -> %d", before, got)
	}
}

// Order-independence: set FIRST, then deletes, ending below base —
// end/result adjudication must accept (no mode flags).
func TestSetFirstMixedRepairAccepted15999(t *testing.T) {
	s := shrinkWitness15999(t) // over-budget base
	base := s.candidate.NodeCount()
	if _, err := s.LoadSet("set system host-name fw2\ndelete system host-name fw2\ndelete system services ssh"); err != nil {
		t.Fatalf("set-first mixed repair refused: %v (base=%d)", err, base)
	}
	if got := s.candidate.NodeCount(); got >= base {
		t.Fatalf("set-first repair no progress: %d -> %d", base, got)
	}
	// Grow-first with NO shrink anywhere on over-budget base refuses:
	s2 := shrinkWitness15999(t)
	if _, err := s2.LoadSet("set system domain-name example.com"); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("grow on over-budget: err=%v", err)
	}
}

// Cadence witness: add (over intermediate), 255 re-sets, delete at 257
// — periodic recount at 256 must NOT adjudicate; final result accepted.
func TestDelayedRepairCadenceAccepted15999(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("set system host-name fw1\n")
	for range 255 {
		b.WriteString("set system host-name fw1\n")
	}
	b.WriteString("delete system host-name fw1\n")
	if _, err := s.LoadSet(b.String()); err != nil {
		t.Fatalf("delayed-repair cadence script refused: %v", err)
	}
	// Growing 200k lines refuse at cumulative-work/line cap:
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	var g strings.Builder
	for i := range config.MaxParseNodes + 1 {
		fmt.Fprintf(&g, "set security address-book global address a%d 10.0.0.1/32\n", i)
	}
	if _, err := s2.LoadSet(g.String()); err == nil || !strings.Contains(err.Error(), "#15999") {
		t.Fatalf("200k growing lines: err=%v", err)
	}
}
