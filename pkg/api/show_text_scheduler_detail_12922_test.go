package api

// #12922 on the REST show-text surface: `show schedulers` must carry the
// daily exclude/all-day qualifiers and the per-weekday override arms. On
// master this handler printed only start/stop + "Recurrence: daily", so a
// daily-exclude scheduler — never active in the shown window — was
// indistinguishable from an ordinary active window (RED on master).

import (
	"strings"
	"testing"
)

func TestShowTextSchedulerRecurrenceDetail12922(t *testing.T) {
	s := stageShowTextConfig(t, []string{
		// The issue's shape: a daily window suppressed by `daily exclude`.
		"set schedulers scheduler excluded daily exclude",
		"set schedulers scheduler excluded daily start-time 09:00:00",
		"set schedulers scheduler excluded daily stop-time 17:00:00",
		// A daily window with per-weekday overrides: monday never active,
		// sunday active around the clock.
		"set schedulers scheduler mixed daily start-time 08:00:00",
		"set schedulers scheduler mixed daily stop-time 16:00:00",
		"set schedulers scheduler mixed monday exclude",
		"set schedulers scheduler mixed sunday all-day",
		// `daily all-day` on its own.
		"set schedulers scheduler always daily all-day",
	})

	// PREMISE, asserted rather than assumed: if the compiler dropped the
	// exclude flag, the cells below would measure nothing.
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Schedulers["excluded"] == nil || !cfg.Schedulers["excluded"].DailyExclude {
		t.Fatalf("fixture missing daily-exclude scheduler: %+v", cfg.Schedulers)
	}
	if d := cfg.Schedulers["mixed"].Days["monday"]; d == nil || !d.Exclude {
		t.Fatalf("fixture missing monday exclude arm: %+v", cfg.Schedulers["mixed"].Days)
	}

	out := renderShowTextBody(t, s, "schedulers")
	if !linePresent12922(out, "  Recurrence: daily exclude") {
		t.Fatalf("daily exclude qualifier missing — the excluded window still looks active:\n%s", out)
	}
	if !linePresent12922(out, "  Recurrence: daily all-day") {
		t.Fatalf("daily all-day qualifier missing:\n%s", out)
	}
	if !linePresent12922(out, "  monday:    exclude") {
		t.Fatalf("monday exclude override missing:\n%s", out)
	}
	if !linePresent12922(out, "  sunday:    all-day") {
		t.Fatalf("sunday all-day override missing:\n%s", out)
	}
	// Narrowness: the ordinary daily window of `mixed` keeps its plain
	// recurrence line.
	if !linePresent12922(out, "  Recurrence: daily") {
		t.Fatalf("plain daily recurrence line regressed:\n%s", out)
	}
}

// linePresent12922 asserts an exact line, so the plain "Recurrence: daily"
// expectation cannot be satisfied by the "Recurrence: daily exclude" line.
func linePresent12922(out, line string) bool {
	for _, l := range strings.Split(out, "\n") {
		if l == line {
			return true
		}
	}
	return false
}
