package scheduler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// weekdayRenderOrder is the canonical order per-day override arms render in:
// monday..sunday, the authoring order of the Junos `schedulers` hierarchy.
// Any non-canonical key that reached the Days map through a lenient
// restore/peer-sync load sorts alphabetically after the canonical seven so
// the render stays deterministic and total over arbitrary map contents.
var weekdayRenderOrder = []string{
	"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
}

// FormatSchedulers renders the operator-facing `show schedulers` table into
// buf. It is the single renderer shared by the local CLI, the REST show-text
// handler, and the gRPC ShowText surface so the three cannot drift (#12922 —
// each had a private copy, and the copies had already diverged on key order
// and nil-slot tolerance).
//
// #12922: the per-scheduler block must carry the full recurrence detail, not
// just "Recurrence: daily". `daily exclude` suppresses the daily window (the
// runtime evaluator returns INACTIVE while an ordinary daily window would be
// ACTIVE in the same bounds), `daily all-day` is active around the clock, and
// a per-weekday arm overrides the daily window for that weekday. Rendering
// only start/stop + "daily" made a daily-exclude scheduler indistinguishable
// from an ordinary active window — an operator auditing a scheduled policy
// could not see that the shown window never applies.
//
// Qualifiers render in evaluator precedence order (exclude suppresses, then
// all-day activates, then the time bounds apply), matching the config
// spellings `daily exclude` / `daily all-day` the compiler accepted.
func FormatSchedulers(buf *strings.Builder, cfg *config.Config) {
	if cfg == nil || len(cfg.Schedulers) == 0 {
		buf.WriteString("No schedulers configured\n")
		return
	}
	names := make([]string, 0, len(cfg.Schedulers))
	for name := range cfg.Schedulers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sched := cfg.Schedulers[name]
		if sched == nil {
			// #10439/#12903: a present-but-nil map value is admitted by the
			// tolerant-load / peer-sync path (#1960); skip it rather than
			// dereferencing it and panicking the display surface.
			continue
		}
		fmt.Fprintf(buf, "Scheduler: %s\n", name)
		if sched.StartTime != "" {
			fmt.Fprintf(buf, "  Start time: %s\n", sched.StartTime)
		}
		if sched.StopTime != "" {
			fmt.Fprintf(buf, "  Stop time:  %s\n", sched.StopTime)
		}
		if sched.StartDate != "" {
			fmt.Fprintf(buf, "  Start date: %s\n", sched.StartDate)
		}
		if sched.StopDate != "" {
			fmt.Fprintf(buf, "  Stop date:  %s\n", sched.StopDate)
		}
		if rec := recurrenceLabel(sched); rec != "" {
			fmt.Fprintf(buf, "  Recurrence: %s\n", rec)
		}
		for _, day := range orderedDayKeys(sched.Days) {
			win := sched.Days[day]
			if win == nil {
				// Same nil-slot tolerance as the scheduler loop above.
				continue
			}
			// Labels pad to the width of the longest weekday ("wednesday")
			// so the day values align with each other and with the
			// Start/Stop time value column.
			fmt.Fprintf(buf, "  %-10s %s\n", day+":", dayWindowLabel(win))
		}
		buf.WriteString("\n")
	}
}

// recurrenceLabel builds the `Recurrence:` value from the compiled daily
// flags: `daily`, `daily exclude`, `daily all-day`, or `daily exclude
// all-day`. The compiler only sets the qualifiers from a `daily` arm, but a
// restored/peer-synced compiled config can carry any combination, so each
// flag renders independently of the others and nothing compiled is hidden.
func recurrenceLabel(sched *config.SchedulerConfig) string {
	var parts []string
	if sched.Daily {
		parts = append(parts, "daily")
	}
	if sched.DailyExclude {
		parts = append(parts, "exclude")
	}
	if sched.AllDay {
		parts = append(parts, "all-day")
	}
	return strings.Join(parts, " ")
}

// dayWindowLabel renders one per-day override arm: its qualifiers in
// evaluator precedence order (Exclude makes the day never active, AllDay
// active for the whole day) followed by the time bounds when present. A
// qualifier-less arm renders as `closed`: the runtime evaluator fails closed
// on an empty window (#3849), so the honest label is "inactive", not a
// blank that could read as unconstrained.
func dayWindowLabel(win *config.SchedulerDayWindow) string {
	var parts []string
	if win.Exclude {
		parts = append(parts, "exclude")
	}
	if win.AllDay {
		parts = append(parts, "all-day")
	}
	switch {
	case win.StartTime != "" && win.StopTime != "":
		parts = append(parts, win.StartTime+" - "+win.StopTime)
	case win.StartTime != "":
		parts = append(parts, win.StartTime+" -")
	case win.StopTime != "":
		parts = append(parts, "- "+win.StopTime)
	}
	if len(parts) == 0 {
		return "closed"
	}
	return strings.Join(parts, " ")
}

// orderedDayKeys returns the Days map's keys in monday..sunday order, with
// any non-canonical keys sorted alphabetically after them.
func orderedDayKeys(days map[string]*config.SchedulerDayWindow) []string {
	if len(days) == 0 {
		return nil
	}
	keys := make([]string, 0, len(days))
	for k := range days {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make([]string, 0, len(days))
	for _, canonical := range weekdayRenderOrder {
		if _, ok := days[canonical]; ok {
			ordered = append(ordered, canonical)
		}
	}
	for _, k := range keys {
		canonical := false
		for _, c := range weekdayRenderOrder {
			if k == c {
				canonical = true
				break
			}
		}
		if !canonical {
			ordered = append(ordered, k)
		}
	}
	return ordered
}
