package scheduler

// #12922: `show schedulers` printed start/stop + "Recurrence: daily" with no
// exclude/all-day/weekday detail, so a `daily exclude` scheduler — INACTIVE
// for the whole shown window — rendered exactly like an ordinary active
// window. These cells pin the shared renderer every show surface now uses:
// the recurrence qualifiers, the per-weekday override arms, their render
// order, and the empty/nil tolerance the three private copies had drifted on.

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func renderSchedulers12922(t *testing.T, cfg *config.Config) string {
	t.Helper()
	var buf strings.Builder
	FormatSchedulers(&buf, cfg)
	return buf.String()
}

// hasLine asserts an exact line, not a substring: "Recurrence: daily" must
// not be satisfied by the "Recurrence: daily exclude" line (or vice versa).
func hasLine(out, line string) bool {
	for _, l := range strings.Split(out, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

func TestFormatSchedulersEmpty12922(t *testing.T) {
	for name, cfg := range map[string]*config.Config{"nil": nil, "empty": {}} {
		if out := renderSchedulers12922(t, cfg); out != "No schedulers configured\n" {
			t.Fatalf("%s: got %q, want the no-schedulers notice", name, out)
		}
	}
}

func TestFormatSchedulersDailyExcludeVisible12922(t *testing.T) {
	// The exact shape from the issue: a daily window that never applies
	// because the daily arm excludes it.
	out := renderSchedulers12922(t, &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"excluded": {Name: "excluded", Daily: true, DailyExclude: true,
				StartTime: "09:00:00", StopTime: "17:00:00"},
		},
	})
	want := "Scheduler: excluded\n" +
		"  Start time: 09:00:00\n" +
		"  Stop time:  17:00:00\n" +
		"  Recurrence: daily exclude\n" +
		"\n"
	if out != want {
		t.Fatalf("daily-exclude block:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

func TestFormatSchedulersAllDayVisible12922(t *testing.T) {
	out := renderSchedulers12922(t, &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"always": {Name: "always", Daily: true, AllDay: true},
		},
	})
	if !hasLine(out, "  Recurrence: daily all-day") {
		t.Fatalf("daily all-day qualifier missing:\n%s", out)
	}
	// A compiled config restored via peer-sync can carry both flags; both
	// must render (exclude first — evaluator precedence).
	out = renderSchedulers12922(t, &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"both": {Name: "both", Daily: true, AllDay: true, DailyExclude: true},
		},
	})
	if !hasLine(out, "  Recurrence: daily exclude all-day") {
		t.Fatalf("combined qualifiers missing:\n%s", out)
	}
}

func TestFormatSchedulersPlainDailyUnchanged12922(t *testing.T) {
	// Narrowness: the ordinary daily window keeps the exact pre-#12922
	// rendering; only the missing detail was added.
	out := renderSchedulers12922(t, &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"workday": {Name: "workday", Daily: true,
				StartTime: "09:00:00", StopTime: "17:00:00"},
		},
	})
	want := "Scheduler: workday\n" +
		"  Start time: 09:00:00\n" +
		"  Stop time:  17:00:00\n" +
		"  Recurrence: daily\n" +
		"\n"
	if out != want {
		t.Fatalf("plain daily block changed:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

func TestFormatSchedulersWeekdayArmsVisible12922(t *testing.T) {
	out := renderSchedulers12922(t, &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"mixed": {Name: "mixed", Daily: true,
				StartTime: "08:00:00", StopTime: "16:00:00",
				Days: map[string]*config.SchedulerDayWindow{
					// Staged out of order on purpose: render order is
					// monday..sunday, never map order.
					"sunday":    {AllDay: true},
					"monday":    {Exclude: true},
					"wednesday": {StartTime: "10:00:00", StopTime: "12:00:00"},
					"friday":    {StartTime: "07:30:00"}, // half window, fails closed
					"empty":     nil,                     // nil slot: skipped
				}},
		},
	})
	want := "Scheduler: mixed\n" +
		"  Start time: 08:00:00\n" +
		"  Stop time:  16:00:00\n" +
		"  Recurrence: daily\n" +
		"  monday:    exclude\n" +
		"  wednesday: 10:00:00 - 12:00:00\n" +
		"  friday:    07:30:00 -\n" +
		"  sunday:    all-day\n" +
		"\n"
	if out != want {
		t.Fatalf("weekday arms block:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

func TestFormatSchedulersSortedNamesAndNilSlots12922(t *testing.T) {
	out := renderSchedulers12922(t, &config.Config{
		Schedulers: map[string]*config.SchedulerConfig{
			"zzz":  nil, // present-but-nil slot: skipped, not rendered
			"aaa":  {Name: "aaa", Daily: true, AllDay: true},
			"mid":  {Name: "mid", Daily: true},
			"nadd": {Name: "nadd"},
		},
	})
	want := "Scheduler: aaa\n" +
		"  Recurrence: daily all-day\n" +
		"\n" +
		"Scheduler: mid\n" +
		"  Recurrence: daily\n" +
		"\n" +
		"Scheduler: nadd\n" +
		"\n"
	if out != want {
		t.Fatalf("sorted/nil-slot render:\ngot:\n%s\nwant:\n%s", out, want)
	}
}
