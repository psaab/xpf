package config

import (
	"fmt"
	"strings"
	"time"
)

// ParseSchedulerTimeOfDay parses a Junos scheduler time in HH:MM or HH:MM:SS
// 24-hour form, treating omitted seconds as zero. It is the single source of
// truth for this grammar (#17187): schema validation, the compiler helpers
// and the pkg/scheduler runtime evaluator all call it, so a grammar change
// cannot land in one copy and silently diverge from the others. The input
// is parsed RAW, with no whitespace trim: a padded bound is rejected here
// and at runtime alike (the runtime then fails closed — inactive).
func ParseSchedulerTimeOfDay(raw string) (time.Time, error) {
	switch strings.Count(raw, ":") {
	case 1:
		if len(raw) != len("15:04") {
			return time.Time{}, fmt.Errorf("expected HH:MM")
		}
		return time.Parse("15:04", raw)
	case 2:
		return time.Parse("15:04:05", raw)
	default:
		return time.Time{}, fmt.Errorf("expected HH:MM or HH:MM:SS")
	}
}

// ParseSchedulerDateBound parses a Junos scheduler date bound in loc:
// YYYY-MM-DD (date-only, second return false) or YYYY-MM-DD.HH:MM
// (date-time, second return true). Like ParseSchedulerTimeOfDay it is the
// single source of truth for the grammar (#17187) and parses raw input
// with no whitespace trim, so validation and runtime agree on padded
// bounds. A nil loc parses in UTC (time.ParseInLocation semantics).
func ParseSchedulerDateBound(raw string, loc *time.Location) (time.Time, bool, error) {
	if strings.Contains(raw, ".") {
		if len(raw) != len("2006-01-02.15:04") {
			return time.Time{}, true, fmt.Errorf("expected YYYY-MM-DD.HH:MM")
		}
		t, err := time.ParseInLocation("2006-01-02.15:04", raw, loc)
		return t, true, err
	}
	t, err := time.ParseInLocation("2006-01-02", raw, loc)
	return t, false, err
}

// parseSchedulerTimeOfDay is kept as the in-package spelling of
// ParseSchedulerTimeOfDay for existing internal callers.
func parseSchedulerTimeOfDay(raw string) (time.Time, error) {
	return ParseSchedulerTimeOfDay(raw)
}

// parseSchedulerDateBound is the in-package (UTC) spelling of
// ParseSchedulerDateBound for compiler callers that compare bounds
// without a location.
func parseSchedulerDateBound(raw string) (time.Time, bool, error) {
	return ParseSchedulerDateBound(raw, time.UTC)
}

// ValidateTimeOfDay accepts ONLY the raw Junos scheduler times
// ParseSchedulerTimeOfDay parses (HH:MM or HH:MM:SS). It deliberately
// does not trim: the compiler stores the bound verbatim and the runtime
// evaluator parses it with the same parser, so accepting a padded value
// here would commit a bound the runtime then rejects as inactive
// (#17187; the scheduler-leg of the validator-trims/consumer-raw class).
// A whitespace-only value is unparseable, not "missing".
func ValidateTimeOfDay(raw string) error {
	if raw == "" {
		return fmt.Errorf("missing value (expected a time of day, e.g. 09:00 or 09:00:00)")
	}
	if _, err := ParseSchedulerTimeOfDay(raw); err != nil {
		return fmt.Errorf("invalid time of day %q (expected 24-hour HH:MM or HH:MM:SS, e.g. 09:00 or 17:30:00)", raw)
	}
	return nil
}

// ValidateDate accepts ONLY the raw Junos scheduler dates
// ParseSchedulerDateBound parses (YYYY-MM-DD or YYYY-MM-DD.HH:MM), with
// no whitespace trim, for the same validator/runtime parity reason as
// ValidateTimeOfDay (#17187).
func ValidateDate(raw string) error {
	if raw == "" {
		return fmt.Errorf("missing value (expected a date or date-time, e.g. 2026-03-01 or 2026-03-01.08:30)")
	}
	if _, _, err := ParseSchedulerDateBound(raw, time.UTC); err != nil {
		return fmt.Errorf("invalid date/time %q (expected YYYY-MM-DD or YYYY-MM-DD.HH:MM)", raw)
	}
	return nil
}
