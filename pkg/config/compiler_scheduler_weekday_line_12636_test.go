package config

import (
	"strings"
	"testing"
)

func TestSchedulerRejectsWeekdayPackedOnSchedulerLine12636(t *testing.T) {
	for _, day := range []string{"monday", "modnay"} {
		t.Run(day, func(t *testing.T) {
			tree, parseErrs := NewParser(`schedulers { scheduler S ` + day + ` { start-time 09:00:00; stop-time 17:00:00; } }`).Parse()
			if len(parseErrs) != 0 {
				t.Fatalf("parse errors: %v", parseErrs)
			}
			if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), day) {
				t.Fatalf("SchemaValidate error = %v, want rejection naming %q", err, day)
			}
		})
	}
}

func TestSchedulerWeekdayInsideBlockRemainsAccepted12636(t *testing.T) {
	tree, parseErrs := NewParser(`schedulers { scheduler S { monday { start-time 09:00:00; stop-time 17:00:00; } } }`).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse errors: %v", parseErrs)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate rejected canonical weekday block: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected canonical weekday block: %v", err)
	}
	window := cfg.Schedulers["S"].Days["monday"]
	if window == nil || window.StartTime != "09:00:00" || window.StopTime != "17:00:00" {
		t.Fatalf("compiled Monday window = %+v, want 09:00:00–17:00:00", window)
	}
}
