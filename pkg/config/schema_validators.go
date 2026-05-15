package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Schema validators used by #1319 SchemaValidate. Each returns nil for
// accepted input and a descriptive error otherwise. They run at commit
// check time only — the existing compiler parsers (parseBandwidthLimit,
// parseBurstSizeLimit, ...) keep their zero-return-on-error contract so
// downstream callers don't need to learn new error paths.
//
// Validators take a (raw string, cfg *Config) pair so future validators
// can cross-reference compiled state (e.g. "scheduler X must exist").
// Today the schedulers leaves don't need cfg, so they ignore it.

// LeafValidator is the function signature for typed-leaf validators.
// The mirrored cmdtree.LeafValidator alias has the same shape so
// cmdtree Nodes can hold one of these directly. We define it here too
// (rather than importing cmdtree) to avoid a config→cmdtree→config
// import cycle.
type LeafValidator func(raw string, cfg *Config) error

// validateRate accepts a Junos bandwidth value (bits/sec) like
// "100k", "10m", "1g", or a bare positive integer. Empty input is
// rejected — a typed leaf with no value is meaningless.
func ValidateRate(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected bandwidth, e.g. 100k, 10m, 1g)")
	}
	bps, err := parseScaledDecimalUnitStrict(raw)
	if err != nil {
		return fmt.Errorf("not a valid bandwidth (expected k/m/g suffix, e.g. 10m): %w", err)
	}
	if bps == 0 {
		return fmt.Errorf("bandwidth must be > 0 (got %q)", raw)
	}
	return nil
}

// validateByteSizeOrPercent accepts either:
//   - a byte-count with optional k/m/g suffix (e.g. "16m"); or
//   - a bare integer 0..100 interpreted as a percent of buffer.
//
// Junos `buffer-size` accepts both forms; we don't try to disambiguate
// here, only validate that the string parses as one or the other.
func ValidateByteSizeOrPercent(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected byte-size like 16m, or percent 0..100)")
	}
	// Try percent first (bare integer 0..100).
	if pct, err := strconv.Atoi(raw); err == nil {
		if pct < 0 || pct > 100 {
			return fmt.Errorf("percent must be in 0..100 (got %d)", pct)
		}
		return nil
	}
	if _, err := parseBurstSizeLimitStrict(raw); err != nil {
		return fmt.Errorf("not a valid byte-size or percent (expected 16m, 256k, or 0..100): %w", err)
	}
	return nil
}

// validateInteger returns a closure that accepts a bare integer in
// [min, max] inclusive. min > max disables the range check.
func ValidateInteger(min, max int64) LeafValidator {
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value (expected integer)")
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("not an integer: %q", raw)
		}
		if min <= max && (v < min || v > max) {
			return fmt.Errorf("integer out of range [%d..%d] (got %d)", min, max, v)
		}
		return nil
	}
}

// validateEnum returns a closure that accepts only one of the listed
// names (case-sensitive, exact match).
func ValidateEnum(allowed []string) LeafValidator {
	sorted := append([]string(nil), allowed...)
	sort.Strings(sorted)
	set := make(map[string]struct{}, len(sorted))
	for _, a := range sorted {
		set[a] = struct{}{}
	}
	return func(raw string, _ *Config) error {
		if _, ok := set[raw]; ok {
			return nil
		}
		return fmt.Errorf("invalid value %q (expected one of: %s)", raw, strings.Join(sorted, ", "))
	}
}

// validatePercent returns a closure that accepts a real number in
// [min, max] inclusive. The input must parse as a float.
func ValidatePercent(min, max float64) LeafValidator {
	return func(raw string, _ *Config) error {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("missing value (expected percent %.0f..%.0f)", min, max)
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return fmt.Errorf("not a number: %q", raw)
		}
		if v < min || v > max {
			return fmt.Errorf("percent out of range [%.2f..%.2f] (got %s)", min, max, raw)
		}
		return nil
	}
}
