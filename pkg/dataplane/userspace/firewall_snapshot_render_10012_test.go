package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #10012 (terminal lie): a term carrying a REAL terminating action
// (accept/reject/discard) AND `then next term` is a contradiction the strict
// commit gate rejects (validateFilterTerminalConflictStrict, #5142/#9140),
// but the tolerant load / peer-sync path downgrades that gate to a warning
// (#1960 no-brick), so the shape can still reach the snapshot builder and the
// renderer. The Rust evaluator resolves the contradiction in favour of the
// action — `continue_term: snap.action.is_empty() &&
// snap.routing_instance.is_empty()` (userspace-dp/src/filter/compiler.rs) —
// and TERMINATES. The snapshot renderer branched on `term.NextTerm` alone and
// printed ONLY `then next term (fall-through)`, omitting the action the
// runtime enforces: the surface lied while enforcement stayed fail-closed.
//
// These cells pin the corrected contract: the renderer computes effective
// fall-through with the SAME predicate as the Rust evaluator (no action AND
// no routing-instance), shows the terminating action, and annotates the
// contradictory next-term bit as IGNORED instead of printing the bare
// fall-through claim.
//
// FAIL-ON-REVERT: restore `if term.NextTerm {` as the renderer branch and the
// contradictory cells go RED — the render again claims fall-through while the
// Rust predicate terminates.

// snapshotTerms10012 builds snapshots for a hand-built control fixture and
// returns the terms of the named filter. The issue cell below uses
// compileLenientFilter10012 to exercise the real tolerant config path.
func snapshotTerms10012(t *testing.T, filterName string, terms []*config.FirewallFilterTerm) []FirewallTermSnapshot {
	t.Helper()
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		filterName: {Name: filterName, Terms: terms},
	}
	for _, s := range BuildFirewallFilterSnapshots(cfg) {
		if s.Name == filterName {
			return s.Terms
		}
	}
	t.Fatalf("filter %q missing from snapshots", filterName)
	return nil
}

// compileLenientFilter10012 exercises the actual tolerant config path that
// keeps a strict-gate contradiction available to the snapshot builder. The
// strict compiler rejects the action+next-term shape, while the lenient
// compiler downgrades it to a warning and retains the term (#1960).
func compileLenientFilter10012(t *testing.T, action, rejectType string) *config.Config {
	t.Helper()
	actionLine := "set firewall family inet filter edge term clash then " + action
	if rejectType != "" {
		actionLine += " " + rejectType
	}
	lines := []string{
		"set firewall family inet filter edge term clash from protocol tcp",
		"set firewall family inet filter edge term clash from destination-port 22",
		actionLine,
		"set firewall family inet filter edge term clash then next term",
	}
	tree := &config.ConfigTree{}
	for _, line := range lines {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must retain the contradiction: %v", err)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "next term") && strings.Contains(warning, action) {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("lenient compile retained no terminal/next-term warning: %v", cfg.Warnings)
	}
	return cfg
}

func snapshotTermsFromConfig10012(t *testing.T, cfg *config.Config, filterName string) []FirewallTermSnapshot {
	t.Helper()
	for _, s := range BuildFirewallFilterSnapshots(cfg) {
		if s.Name == filterName {
			return s.Terms
		}
	}
	t.Fatalf("filter %q missing from snapshots", filterName)
	return nil
}

// rustContinues10012 is the Go spelling of the Rust evaluator's termination
// predicate (`continue_term: snap.action.is_empty() &&
// snap.routing_instance.is_empty()`, userspace-dp/src/filter/compiler.rs,
// #5142). The renderer's implied decision must agree with it on every cell.
func rustContinues10012(snap FirewallTermSnapshot) bool {
	return snap.Action == "" && snap.RoutingInstance == ""
}

// TestSnapshotRenderContradictoryActionNextTermTerminates10012 is the issue
// cell: action+next_term through the tolerant builder must render the
// terminating action (what the runtime enforces), must NOT print the bare
// fall-through claim, and must annotate the ignored next-term bit.
func TestSnapshotRenderContradictoryActionNextTermTerminates10012(t *testing.T) {
	cases := []struct {
		name       string
		action     string
		rejectType string
		wantThen   string
	}{
		{"discard", "discard", "", "then discard"},
		{"accept", "accept", "", "then accept"},
		{"reject", "reject", "", "then reject"},
		{"reject-typed", "reject", "host-unreachable", "then reject host-unreachable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// CompileConfigLenient preserves the contradictory shape and
			// downgrades the strict gate to a warning; the snapshot builder
			// then carries both Action and NextTerm to this renderer.
			cfg := compileLenientFilter10012(t, c.action, c.rejectType)
			terms := snapshotTermsFromConfig10012(t, cfg, "edge")
			if len(terms) != 1 {
				t.Fatalf("expected 1 snapshot term, got %d: %+v", len(terms), terms)
			}
			snap := terms[0]
			// The tolerant snapshot preserves the contradiction (both bits
			// set) so the renderer can annotate it; clearing NextTerm in the
			// builder would hide the shape instead of disclosing it.
			if snap.Action != c.action || !snap.NextTerm {
				t.Fatalf("tolerant snapshot lost the contradiction: got Action=%q NextTerm=%v, want Action=%q NextTerm=true",
					snap.Action, snap.NextTerm, c.action)
			}
			if rustContinues10012(snap) {
				t.Fatalf("Rust predicate continues on Action=%q — the test fixture contradicts #5142", snap.Action)
			}
			out := RenderFirewallFilterSnapshot(&FirewallFilterSnapshot{Name: "edge", Family: "inet", Terms: terms})
			if !strings.Contains(out, c.wantThen) {
				t.Errorf("render omits the terminating action %q the runtime enforces.\n%s", c.wantThen, out)
			}
			if strings.Contains(out, "then next term (fall-through)") {
				t.Errorf("render claims fall-through while the runtime TERMINATES on %q (terminal lie).\n%s", c.action, out)
			}
			if !strings.Contains(out, "then next term (ignored") || !strings.Contains(out, "contradictory") {
				t.Errorf("render must annotate the contradictory next-term bit as ignored.\n%s", out)
			}
		})
	}
}

// TestSnapshotRenderPureFallThroughControl10012 pins the unchanged pure
// fall-through shape: empty action + next_term renders the bare fall-through
// line with its modifiers and no terminal, no IGNORED annotation.
func TestSnapshotRenderPureFallThroughControl10012(t *testing.T) {
	terms := snapshotTerms10012(t, "edge", []*config.FirewallFilterTerm{
		{Name: "count-only", Protocols: []string{"tcp"}, Count: "hits", NextTerm: true},
	})
	if len(terms) != 1 {
		t.Fatalf("expected 1 snapshot term, got %d: %+v", len(terms), terms)
	}
	if !rustContinues10012(terms[0]) {
		t.Fatalf("Rust predicate terminates the pure fall-through fixture: %+v", terms[0])
	}
	out := RenderFirewallFilterSnapshot(&FirewallFilterSnapshot{Name: "edge", Family: "inet", Terms: terms})
	if !strings.Contains(out, "then next term (fall-through)") {
		t.Errorf("pure fall-through must still render the fall-through line.\n%s", out)
	}
	if !strings.Contains(out, "then count hits") {
		t.Errorf("pure fall-through must still render its modifiers.\n%s", out)
	}
	for _, terminal := range []string{"then accept", "then discard", "then reject"} {
		if strings.Contains(out, terminal) {
			t.Errorf("pure fall-through must not render a terminal %q.\n%s", terminal, out)
		}
	}
	if strings.Contains(out, "ignored") {
		t.Errorf("pure fall-through carries no contradiction — must not render ignored.\n%s", out)
	}
}

// TestSnapshotRenderPureTerminalControl10012 pins the unchanged pure terminal
// shape: a real action without next_term renders exactly the action.
func TestSnapshotRenderPureTerminalControl10012(t *testing.T) {
	terms := snapshotTerms10012(t, "edge", []*config.FirewallFilterTerm{
		{Name: "deny", Protocols: []string{"tcp"}, DestinationPorts: []string{"22"}, Action: "discard", TerminalActions: []string{"discard"}},
	})
	if len(terms) != 1 {
		t.Fatalf("expected 1 snapshot term, got %d: %+v", len(terms), terms)
	}
	if rustContinues10012(terms[0]) {
		t.Fatalf("Rust predicate continues the pure terminal fixture: %+v", terms[0])
	}
	out := RenderFirewallFilterSnapshot(&FirewallFilterSnapshot{Name: "edge", Family: "inet", Terms: terms})
	if !strings.Contains(out, "then discard") {
		t.Errorf("pure terminal must render its action.\n%s", out)
	}
	if strings.Contains(out, "fall-through") || strings.Contains(out, "ignored") {
		t.Errorf("pure terminal must render neither fall-through nor ignored.\n%s", out)
	}
}

// TestSnapshotRenderImplicitFallThroughWithoutBit10012 pins the Rust
// belt-and-suspenders parity: an empty action with NO next_term bit (a shape
// a hand-built or older-control-plane snapshot can carry — the Rust test
// `fallthrough_modifier_only_term_reaches_later_discard` falls through on
// exactly it) still renders as fall-through, because the renderer branches
// on the Rust predicate, not on the advisory bit.
func TestSnapshotRenderImplicitFallThroughWithoutBit10012(t *testing.T) {
	snap := FirewallTermSnapshot{Name: "mo", Count: "hits"}
	if !rustContinues10012(snap) {
		t.Fatalf("Rust predicate terminates the empty-action fixture: %+v", snap)
	}
	out := RenderFirewallFilterSnapshot(&FirewallFilterSnapshot{
		Name: "edge", Family: "inet", Terms: []FirewallTermSnapshot{snap},
	})
	if !strings.Contains(out, "then next term (fall-through)") {
		t.Errorf("empty action without the next-term bit must still render fall-through (runtime continues).\n%s", out)
	}
	if strings.Contains(out, "then accept") {
		t.Errorf("render must not claim a terminating accept the runtime never takes.\n%s", out)
	}
}

// TestSnapshotRenderRoutingInstanceNextTermHandBuilt10012 pins the PBR arm of
// the Rust predicate: a routing-instance term terminates even when a snapshot
// still carries next_term (the Go builder clears the bit for RI terms, so
// only a hand-built or mixed-version-peer snapshot carries both —
// `continue_term` is false whenever the routing-instance is set). The render
// must show the terminating accept, not the fall-through claim, and annotate
// the ignored bit.
func TestSnapshotRenderRoutingInstanceNextTermHandBuilt10012(t *testing.T) {
	snap := FirewallTermSnapshot{Name: "steer", RoutingInstance: "mgmt-vrf", NextTerm: true}
	if rustContinues10012(snap) {
		t.Fatalf("Rust predicate continues the routing-instance fixture: %+v", snap)
	}
	out := RenderFirewallFilterSnapshot(&FirewallFilterSnapshot{
		Name: "edge", Family: "inet", Terms: []FirewallTermSnapshot{snap},
	})
	if !strings.Contains(out, "then routing-instance mgmt-vrf") {
		t.Errorf("PBR term must render its routing-instance.\n%s", out)
	}
	if !strings.Contains(out, "then accept") {
		t.Errorf("PBR term must render the terminating accept the runtime takes.\n%s", out)
	}
	if strings.Contains(out, "then next term (fall-through)") {
		t.Errorf("PBR term must not claim fall-through while the runtime terminates.\n%s", out)
	}
	if !strings.Contains(out, "then next term (ignored") {
		t.Errorf("PBR term must annotate the contradictory next-term bit as ignored.\n%s", out)
	}
}
