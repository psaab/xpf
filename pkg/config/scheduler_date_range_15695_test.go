package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15695 limb 3: inverted start-date > stop-date must reject at strict
// commit instead of committing clean and never activating. Effective
// stop bound: date-time stop is exclusive at that instant; date-only
// stop is exclusive at the start of the following day.
func TestSchedulerInvertedDateRangeRejected15695(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"inverted date-only", `schedulers { scheduler S { start-date 2026-03-31; stop-date 2026-03-01; } }`},
		{"same instant date-time", `schedulers { scheduler S { start-date 2026-03-01.08:30; stop-date 2026-03-01.08:30; } }`},
		{"start at date-only stop exclusive bound", `schedulers { scheduler S { start-date 2026-03-02.00:00; stop-date 2026-03-01; } }`},
		{"inverted date-time", `schedulers { scheduler S { start-date 2026-03-31.17:00; stop-date 2026-03-01.08:30; } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := config.NewParser(tc.text).Parse()
			if len(errs) != 0 {
				t.Fatalf("parse: %v", errs)
			}
			if err := config.SchemaValidate(tree, nil); err != nil {
				t.Fatalf("SchemaValidate should not be the range gate: %v", err)
			}
			if _, err := config.CompileConfig(tree); err == nil {
				t.Fatalf("inverted range %s committed clean; want strict rejection", tc.text)
			} else if !strings.Contains(err.Error(), "inverted date range") {
				t.Fatalf("error must name inverted date range, got %v", err)
			}
		})
	}
	// Flat-set spelling must reject identically.
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set schedulers scheduler S start-date 2026-03-31",
		"set schedulers scheduler S stop-date 2026-03-01",
	} {
		p, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("flat inverted range committed clean")
	}
}

func TestSchedulerValidDateRangeAccepted15695(t *testing.T) {
	for _, text := range []string{
		`schedulers { scheduler S { start-date 2026-03-01; stop-date 2026-03-31; } }`,
		`schedulers { scheduler S { start-date 2026-03-01; stop-date 2026-03-01; } }`, // same date-only day: valid
		`schedulers { scheduler S { start-date 2026-03-01.08:30; stop-date 2026-03-31.17:00; } }`,
		`schedulers { scheduler S { start-date 2026-03-01; } }`,
		`schedulers { scheduler S { stop-date 2026-03-31; } }`,
		`schedulers { scheduler S { start-date 2026-03-01 stop-date 2026-03-31; } }`, // one-liner
	} {
		compileHierStrict11305(t, text)
	}
}
func TestSchedulerInvertedDateRangeLenientWarns15695(t *testing.T) {
	tree, errs := config.NewParser(`schedulers { scheduler S { start-date 2026-03-31; stop-date 2026-03-01; } }`).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must boot inverted range, got %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "inverted date range") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant load must warn on inverted range, warnings=%v", cfg.Warnings)
	}
	if cfg.Schedulers["S"] == nil {
		t.Fatal("scheduler must be retained on tolerant load")
	}
}
