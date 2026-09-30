package config

import (
	"fmt"
	"strings"
	"time"
)

// ValidateTimeOfDay accepts Junos scheduler times in HH:MM or HH:MM:SS
// 24-hour form. The runtime evaluator parses the same two forms, treating
// omitted seconds as zero.
func parseSchedulerTimeOfDay(raw string) (time.Time, error) {
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

func ValidateTimeOfDay(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a time of day, e.g. 09:00 or 09:00:00)")
	}
	if _, err := parseSchedulerTimeOfDay(trimmed); err != nil {
		return fmt.Errorf("invalid time of day %q (expected 24-hour HH:MM or HH:MM:SS, e.g. 09:00 or 17:30:00)", raw)
	}
	return nil
}

func parseSchedulerDateBound(raw string) (time.Time, bool, error) {
	if strings.Contains(raw, ".") {
		if len(raw) != len("2006-01-02.15:04") {
			return time.Time{}, true, fmt.Errorf("expected YYYY-MM-DD.HH:MM")
		}
		t, err := time.Parse("2006-01-02.15:04", raw)
		return t, true, err
	}
	t, err := time.Parse("2006-01-02", raw)
	return t, false, err
}

// ValidateDate accepts a Junos scheduler date (YYYY-MM-DD) or local
// date-time (YYYY-MM-DD.HH:MM).
func ValidateDate(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a date or date-time, e.g. 2026-03-01 or 2026-03-01.08:30)")
	}
	if _, _, err := parseSchedulerDateBound(trimmed); err != nil {
		return fmt.Errorf("invalid date/time %q (expected YYYY-MM-DD or YYYY-MM-DD.HH:MM)", raw)
	}
	return nil
}

