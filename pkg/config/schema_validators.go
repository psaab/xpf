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
// rejected — a typed leaf with no value is meaningless. Values below
// 8 bps are rejected because the compiler stores scheduler rates in
// bytes/sec; accepting 1..7 bps would round-trip as 0 and silently
// disable the configured rate.
func ValidateRate(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected bandwidth, e.g. 100k, 10m, 1g)")
	}
	bps, err := parseScaledDecimalUnitStrict(raw)
	if err != nil {
		return fmt.Errorf("not a valid bandwidth (expected k/m/g suffix, e.g. 10m): %w", err)
	}
	if bps < 8 {
		return fmt.Errorf("bandwidth must be at least 8 bps so it compiles to a non-zero byte/sec rate (got %q)", raw)
	}
	return nil
}

// validateByteSize accepts the byte-size form the current CoS compiler
// actually consumes. Junos also has percent-shaped buffer-size syntax,
// but xpf has no percent representation yet and parseBurstSizeLimit
// treats a bare integer as bytes. Reject bare integers here so
// `buffer-size 50` cannot pass validation and compile as a 50-byte
// queue.
func ValidateByteSize(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected byte-size with k/m/g suffix, e.g. 16m)")
	}
	if _, err := strconv.ParseUint(trimmed, 10, 64); err == nil {
		return fmt.Errorf("bare byte-size %q is ambiguous; use an explicit suffix like 50k or 16m", raw)
	}
	if _, err := parseBurstSizeLimitStrict(trimmed); err != nil {
		return fmt.Errorf("not a valid byte-size (expected 16m, 256k, or 1g): %w", err)
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
