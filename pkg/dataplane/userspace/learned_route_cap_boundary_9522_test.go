package userspace

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// #9522: the learned-route import cap's EXACT boundary, and the diagnostic the
// operator reads when the cap fires.
//
// The cap predicate itself is unchanged by #9522 — what changed is the owned
// disposition above it (fail-closed adjudication, counted as policy denials,
// instead of the unowned #9054 delegation). These cells pin both halves of
// that composition from the Go side: the boundary both halves key on, and the
// operator-facing sentence that must describe the NEW disposition rather than
// the old one. The Rust half of the disposition is in
// userspace-dp/src/afxdp/forwarding/tests_noroute_capped_import_9054.rs.

// TestAtTheCapTheTableIsImportedWhole9522 pins the boundary EXACTLY.
//
// learnedRouteCapExceeded declines at count > maxLearnedRoutes(), so a table
// of exactly maxLearnedRoutes() routes is the largest import that fits — it
// must import WHOLE, declare the snapshot uncapped, and leave the cap counter
// still. Pair with TestOverTheCapNothingIsImported8355 (max+1 declines) and
// TestUnderTheCapTheTableIsImportedWhole8355 (64 imports): the three together
// pin below/at/above, and any off-by-one in the predicate reds exactly one of
// them.
func TestAtTheCapTheTableIsImportedWhole9522(t *testing.T) {
	at := maxLearnedRoutes()
	if at <= 0 {
		t.Fatalf("maxLearnedRoutes() = %d, want positive — the boundary cell cannot pin a degenerate cap", at)
	}
	before := LearnedRouteCapHits()

	routes, capped := capStateForTable(t, at)
	if capped {
		t.Fatalf("a table of exactly the cap (%d routes) declares the import capped; "+
			"the decline must fire only ABOVE the cap", at)
	}
	if len(routes) != at {
		t.Fatalf("a table of exactly the cap imported %d of %d routes — an at-cap table "+
			"must import whole, like any under-cap table", len(routes), at)
	}
	if got := LearnedRouteCapHits(); got != before {
		t.Errorf("the cap counter moved (%d -> %d) for a table exactly at the limit", before, got)
	}
}

// TestTheCapDiagnosticStatesTheOwnedFailClosedDisposition9522 asserts the
// OPERATOR-FACING sentence after #9522 re-owned it.
//
// Until #9054 the log line stated the opposite of what the box did; #9054 made
// it true by describing the delegation it restored. #9522 removes that
// delegation, so a diagnostic still describing it would point away from the
// cause in the other direction: the operator would read "delegates" while the
// box drops. The sentence must therefore name the adjudication, the denial,
// and the counters that make the state readable without log scraping.
//
// FAIL-ON-REVERT: restore the #9054 consequence text and every new-marker
// assertion reds while the stale-delegation assertion reds on the old
// sentence — which is exactly the unowned tradeoff this issue closes.
func TestTheCapDiagnosticStatesTheOwnedFailClosedDisposition9522(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if !learnedRouteCapExceeded(maxLearnedRoutes() + 1) {
		t.Fatal("precondition: learnedRouteCapExceeded did not fire")
	}
	got := buf.String()
	if got == "" {
		t.Fatal("the cap fired and logged nothing — this cell would then assert over an empty " +
			"string and pass for the wrong reason")
	}
	// The stale #9054 sentence, verbatim as it shipped: the helper no longer
	// delegates while capped, so the log must no longer say it does.
	if strings.Contains(got, "DELEGATES those frames to the kernel instead of adjudicating them") {
		t.Error("the cap log still tells the operator that a capped NoRoute frame is " +
			"delegated to the kernel. Since #9522 it is adjudicated exactly as uncapped " +
			"and DROPPED on a default-deny box")
	}
	for _, want := range []string{
		"DROPPED as policy denials",
		"xpf_policy_denies_total",
		"xpf_learned_route_import_capped",
		"protocol 27",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the cap log does not mention %q; the operator cannot tell what the box "+
				"now does with a capped NoRoute frame, where it is counted, or which helper "+
				"generation the pairing requires", want)
		}
	}
}
