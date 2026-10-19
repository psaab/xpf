package config

import (
	"fmt"
	"sort"
	"time"
)

// validateSchedulerDateRangeStrict rejects a scheduler whose configured
// start-date is at or after the effective stop bound (#15695). Both bounds
// are already format-validated at commit (ValidateDate), but nothing
// compared them: `start-date 2026-03-31 stop-date 2026-03-01` committed
// clean and the runtime evaluator simply never activated it — an
// inverted window the operator believed was live. The effective stop
// bound mirrors pkg/scheduler.withinDateRange: a date-time stop is that
// exclusive instant, a date-only stop is exclusive at the start of the
// following day (the date itself stays inclusive). Start must be
// strictly before that bound, so an empty range rejects.
// Unparseable bounds are skipped: the typed-leaf validators already
// reject them at commit, and the runtime fails closed on them.
func validateSchedulerDateRangeStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Schedulers))
	for name := range cfg.Schedulers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := cfg.Schedulers[name]
		if s == nil || s.StartDate == "" || s.StopDate == "" {
			continue
		}
		start, _, err := parseSchedulerDateBound(s.StartDate)
		if err != nil {
			continue
		}
		stop, stopHasTime, err := parseSchedulerDateBound(s.StopDate)
		if err != nil {
			continue
		}
		effectiveStop := stop
		if !stopHasTime {
			effectiveStop = stop.AddDate(0, 0, 1)
		}
		if !start.Before(effectiveStop) {
			return fmt.Errorf("scheduler %q has inverted date range: start-date %q is not before stop-date %q (effective stop bound %s)",
				s.Name, s.StartDate, s.StopDate, effectiveStop.Format(time.DateTime))
		}
	}
	return nil
}
