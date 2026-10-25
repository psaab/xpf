package docsref

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16763 (R3-A46-09): pkg/flowexport/README.md is the module contract, but
// after #15946/#16126/#16303 it still described the pre-tracker design:
// sampling decided per SESSION_CLOSE, records assembled only from close
// events, and active-timeout interim records DEFERRED. The code instead
// makes one sampling decision at SESSION_OPEN, tracks sampled flows for
// active/inactive export, feeds the tracker from a 1s live-counter poll,
// and exports only the unexported remainder at real close. A reader of
// the stale contract would conclude closes are sampled independently,
// hiding R3-A46-01/02/03. This gate pins the corrected contract.
//
// FAIL-ON-REVERT: restore any stale string below, or drop any required
// contract phrase, and this test fails.
func TestFlowexportReadmeOpenDecisionContract16763(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "pkg/flowexport/README.md"))
	if err != nil {
		t.Fatalf("read flowexport README: %v", err)
	}
	// Collapse whitespace so line wrapping in the markdown does not hide
	// a stale (or required) phrase that spans a line break.
	norm := strings.Join(strings.Fields(string(b)), " ")

	stale := []string{
		"flow records are assembled in this package from SESSION_CLOSE `logging.EventRecord`s",
		"per SESSION_CLOSE event",
		"per instance per SESSION_CLOSE",
		"evaluates `ShouldExport` exactly once per instance per SESSION_CLOSE",
		// Close-only assembly: tracker interim/final records now exist.
		"(still one record per session)",
		// Active-timeout interims landed in #15655/#15946/#16303.
		"active-timeout interim records — DEFERRED",
		"It is NOT implemented here; the converged design is recorded on #3748.",
	}
	for _, bad := range stale {
		if strings.Contains(norm, bad) {
			t.Errorf("#16763: flowexport README still contains stale claim %q", bad)
		}
	}

	required := []string{
		// Open-time single decision.
		"one sampling decision at SESSION_OPEN",
		"`SampledForOpen`",
		"`flowExportOpenCallback`",
		// Close consumes the recorded decision, exports the remainder.
		"`CloseFlow`",
		"`ExportSessionCloseRemainder`",
		"no second 1-in-N decision at close",
		// Tracker active/inactive semantics and defaults.
		"`FlowActiveTimeout`",
		"`FlowInactiveTimeout`",
		"60s",
		"15s",
		"close-only",
		// Live feed source and cadence.
		"live-counter poll",
		"100ms batch ticker",
		// Absent-open / evicted-flow behaviour (R3-A46-01/03 current state).
		"exports nothing",
		"inactive expiry",
		// New files the layout must name.
		"`tracker_15655.go`",
		"`exporter_core.go`",
	}
	for _, want := range required {
		if !strings.Contains(norm, want) {
			t.Errorf("#16763: flowexport README lost required contract text %q", want)
		}
	}

	// The issue also requires correcting the per-SESSION_CLOSE sampler
	// wording in the ipfix.go comments, not only in the README.
	ib, err := os.ReadFile(filepath.Join(root, "pkg/flowexport/ipfix.go"))
	if err != nil {
		t.Fatalf("read ipfix.go: %v", err)
	}
	inorm := strings.Join(strings.Fields(string(ib)), " ")
	if strings.Contains(inorm, "per SESSION_CLOSE event") {
		t.Errorf("#16763: ipfix.go still describes sampling as per SESSION_CLOSE event")
	}
	if !strings.Contains(inorm, "at SESSION_OPEN") {
		t.Errorf("#16763: ipfix.go sampler comment does not describe the SESSION_OPEN decision")
	}
}
