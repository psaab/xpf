package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12637: canonical Junos scheduler one-liners pack two valued leaves onto
// the scheduler line itself:
//
//	scheduler S { start-time 09:00:00 stop-time 17:00:00; }
//	scheduler S { start-date 2026-03-01 stop-date 2026-03-31; }
//
// Both were strict-rejected as `unknown modifier "stop-time"` /
// `"stop-date"` because the first leaf accepted no trailing modifiers,
// even though the braced/split spellings compiled the same windows.

func TestSchedulerLevelTimeOneLinerCompiles12637(t *testing.T) {
	cfg := compileHierStrict11305(t,
		`schedulers { scheduler S { start-time 09:00:00 stop-time 17:00:00; } }`)
	s := cfg.Schedulers["S"]
	if s == nil || s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
		t.Fatalf("scheduler-level time one-liner did not compile its window: %+v", s)
	}
}

func TestSchedulerLevelDateOneLinerCompiles12637(t *testing.T) {
	cfg := compileHierStrict11305(t,
		`schedulers { scheduler S { start-date 2026-03-01 stop-date 2026-03-31; } }`)
	s := cfg.Schedulers["S"]
	if s == nil || s.StartDate != "2026-03-01" || s.StopDate != "2026-03-31" {
		t.Fatalf("scheduler-level date one-liner did not compile its range: %+v", s)
	}
}

func TestSchedulerLevelDateTimeOneLinerCompiles12637(t *testing.T) {
	cfg := compileHierStrict11305(t,
		`schedulers { scheduler S { start-date 2026-03-01.08:30 stop-date 2026-03-31.17:00; } }`)
	s := cfg.Schedulers["S"]
	if s == nil || s.StartDate != "2026-03-01.08:30" || s.StopDate != "2026-03-31.17:00" {
		t.Fatalf("scheduler-level date-time one-liner did not compile its range: %+v", s)
	}
}

func TestSchedulerLevelOneLinersFlatSet12637(t *testing.T) {
	cfg := compileFlatStrict11305(t,
		"set schedulers scheduler S start-time 09:00:00 stop-time 17:00:00",
		"set schedulers scheduler D start-date 2026-03-01 stop-date 2026-03-31",
	)
	s := cfg.Schedulers["S"]
	if s == nil || s.StartTime != "09:00:00" || s.StopTime != "17:00:00" {
		t.Fatalf("flat scheduler-level time one-liner did not compile its window: %+v", s)
	}
	d := cfg.Schedulers["D"]
	if d == nil || d.StartDate != "2026-03-01" || d.StopDate != "2026-03-31" {
		t.Fatalf("flat scheduler-level date one-liner did not compile its range: %+v", d)
	}
}

// Mutant-killing cells: accepting the pair by silently swallowing the tail
// (rather than modelling both leaves with their validators) must fail here.
func TestSchedulerLevelOneLinerRejectsBadTail12637(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want string
	}{
		{
			name: "misspelled stop-time still unknown modifier",
			text: `schedulers { scheduler S { start-time 09:00:00 stop-timee 17:00:00; } }`,
			want: `unknown modifier "stop-timee"`,
		},
		{
			name: "misspelled stop-date still unknown modifier",
			text: `schedulers { scheduler S { start-date 2026-03-01 stop-datee 2026-03-31; } }`,
			want: `unknown modifier "stop-datee"`,
		},
		{
			name: "unknown token after valid time pair",
			text: `schedulers { scheduler S { start-time 09:00:00 stop-time 17:00:00 bogus 1; } }`,
			want: `unknown modifier "bogus"`,
		},
		{
			name: "invalid stop-time value",
			text: `schedulers { scheduler S { start-time 09:00:00 stop-time 25:00:00; } }`,
			want: "stop-time",
		},
		{
			name: "invalid stop-date value",
			text: `schedulers { scheduler S { start-date 2026-03-01 stop-date 2026-13-31; } }`,
			want: "stop-date",
		},
		{
			name: "missing stop-time value",
			text: `schedulers { scheduler S { start-time 09:00:00 stop-time; } }`,
			want: "stop-time",
		},
		{
			name: "missing stop-date value",
			text: `schedulers { scheduler S { start-date 2026-03-01 stop-date; } }`,
			want: "stop-date",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := config.NewParser(tc.text).Parse()
			if len(errs) != 0 {
				t.Fatalf("parse fixture: %v", errs)
			}
			err := config.SchemaValidate(tree, nil)
			if err == nil {
				t.Fatalf("strict validation accepted %q", tc.text)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to name %q", err, tc.want)
			}
		})
	}
}
