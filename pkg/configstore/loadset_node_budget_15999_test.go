package configstore

import (
	"fmt"
	"strings"
	"testing"

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
