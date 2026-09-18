package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

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
// consumes. Reject bare integers here so `buffer-size 50` cannot pass
// validation and compile as a 50-byte queue.
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

// ValidatePolicerBurstSize validates a legacy firewall policer
// `if-exceeding burst-size-limit` value (#5299). Junos accepts a byte
// count either bare (100000) or with a k/m/g suffix (15k), so — unlike
// the CoS ValidateByteSize gate — a bare integer is NOT rejected here
// (it is unambiguous bytes for a policer bucket and was a valid,
// compiling input before this gate). What IS rejected is the fail-closed
// input the pre-#5299 parseBurstSizeLimit silently coerced to 0 (or, on
// overflow, wrapped to a small nonzero), plus a bucket smaller than one
// maximum-sized packet. A sub-packet bucket cannot admit an ordinary MTU
// frame and otherwise commits a configuration that drops/marks every such
// packet.
const minPolicerBurstBytes uint64 = 1500

func ValidatePolicerBurstSize(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a burst size in bytes, e.g. 15k, 100000, 1m)")
	}
	n, err := parseBurstSizeLimitStrict(trimmed)
	if err != nil {
		return fmt.Errorf("not a valid burst-size-limit (expected bytes, optionally with a k/m/g suffix, e.g. 15k): %w", err)
	}
	if n < minPolicerBurstBytes {
		return fmt.Errorf(
			"burst-size-limit must be at least one 1500-byte packet (%d bytes), got %d",
			minPolicerBurstBytes,
			n,
		)
	}
	return nil
}

// ValidateCoSTransmitRateTail validates the whole tail of a CoS scheduler
// `transmit-rate` leaf (#4228 Gap 2). Junos accepts three mutually-exclusive
// heads — a bandwidth (10m), `percent <n>`, or `remainder` — each optionally
// followed by the `exact` modifier. The percent/remainder forms are accepted
// for vSRX-config import parity; they compile to a stored percent/flag that
// the userspace dataplane does not yet resolve to an absolute rate (a commit
// advisory surfaces the inertness).
func ValidateCoSTransmitRateTail(tokens []string, siblingTails [][]string) error {
	return validateCoSRateTail(tokens, siblingTails, true /*allowRemainder*/, true /*allowExact*/)
}

// ValidateCoSShapingRateTail validates the tail of a CoS `shaping-rate` leaf
// (traffic-control-profiles, #4228 Gap 2): a bandwidth (10m) or `percent <n>`.
// Junos shaping-rate has no `remainder` or `exact` modifier, so both are
// rejected here.
func ValidateCoSShapingRateTail(tokens []string, siblingTails [][]string) error {
	return validateCoSRateTail(tokens, siblingTails, false /*allowRemainder*/, false /*allowExact*/)
}

// validateCoSRateTail is the shared grammar check for transmit-rate /
// shaping-rate. It rejects garbage loud at commit (preserving the #4217
// silent-zero protection) while accepting the percent/remainder forms.
func validateCoSRateTail(tokens []string, siblingTails [][]string, allowRemainder, allowExact bool) error {
	forms := "a bandwidth (e.g. 10m) or `percent <n>`"
	if allowRemainder {
		forms = "a bandwidth (e.g. 10m), `percent <n>`, or `remainder`"
	}
	if len(tokens) == 0 {
		return fmt.Errorf("missing value (expected %s)", forms)
	}
	head := tokens[0]
	rest := tokens[1:]
	switch {
	case head == "percent":
		if len(rest) == 0 {
			return fmt.Errorf("percent requires a value (e.g. percent 50)")
		}
		if err := validateCoSPercentValue(rest[0]); err != nil {
			return err
		}
		rest = rest[1:]
	case allowRemainder && head == "remainder":
		// remainder takes no operand.
	case allowExact && head == "exact":
		// Modifier-only split-set line (`transmit-rate exact` beside a
		// sibling `transmit-rate 1g`). Accept iff a sibling supplies a value
		// head; otherwise `exact` alone is meaningless.
		if coSRateSiblingSuppliesValue(siblingTails, allowRemainder) {
			return nil
		}
		return fmt.Errorf("exact requires a rate (e.g. a sibling transmit-rate <value>)")
	default:
		if err := ValidateRate(head, nil); err != nil {
			return fmt.Errorf("not a valid rate (expected %s): %w", forms, err)
		}
	}
	// Only `exact` may trail the value (transmit-rate); shaping-rate allows no
	// trailing modifier.
	for _, t := range rest {
		if allowExact && t == "exact" {
			continue
		}
		return fmt.Errorf("unknown modifier %q", t)
	}
	return nil
}

// validateCoSPercentValue accepts a percent operand in the range (0, 100].
// 0% is rejected because a zero rate compiles indistinguishably from "unset".
func validateCoSPercentValue(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("percent requires a value (e.g. percent 50)")
	}
	v, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return fmt.Errorf("invalid percent %q: not a number", raw)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return fmt.Errorf("invalid percent %q: non-finite", raw)
	}
	if v <= 0 || v > 100 {
		return fmt.Errorf("percent out of range (0,100] (got %s)", raw)
	}
	return nil
}

// coSRateSiblingSuppliesValue reports whether any sibling tail begins with a
// value head (a bandwidth, `percent`, or — when allowed — `remainder`), used to
// accept a modifier-only `exact` split-set line.
func coSRateSiblingSuppliesValue(siblingTails [][]string, allowRemainder bool) bool {
	for _, tail := range siblingTails {
		if len(tail) == 0 {
			continue
		}
		head := tail[0]
		if head == "percent" {
			return true
		}
		if allowRemainder && head == "remainder" {
			return true
		}
		if ValidateRate(head, nil) == nil {
			return true
		}
	}
	return false
}

// ValidateByteSizeOrPercent accepts the two scheduler buffer-size forms
// that the CoS runtime can represent: explicit byte sizes with k/m/g
// suffixes, or Junos percent values with a trailing percent sign. Bare
// integers stay rejected because they are ambiguous between bytes and
// percent.
func ValidateByteSizeOrPercent(raw string, _ *Config) error {
	trimmed := strings.TrimSpace(raw)
	if strings.HasSuffix(trimmed, "%") {
		if _, err := parsePercentWithSuffixStrict(trimmed); err != nil {
			return fmt.Errorf("not a valid percent buffer-size (expected >0%%..100%%; xpf rejects Junos 0%% because zero is the legacy absent-field value): %w", err)
		}
		return nil
	}
	return ValidateByteSize(raw, nil)
}

// ValidateCoSBufferSizeTail validates the whole tail of a CoS scheduler
// `buffer-size` leaf (#4228 Gap 2 follow-up). Junos accepts three
// mutually-exclusive forms: an absolute byte-size (16m), a percent of the
// interface buffer pool (10%), or `temporal <microseconds>` (size the buffer
// by target queue delay). The byte/percent forms preserve the #4217 silent-
// zero protection (garbage rejected loud); the temporal form is accepted for
// vSRX-config import parity and compiles to a stored microsecond value the
// dataplane does not yet resolve to bytes (a commit advisory surfaces the
// inertness).
func ValidateCoSBufferSizeTail(tokens []string, _ [][]string) error {
	const forms = "a byte-size (e.g. 16m), a percent (e.g. 10%), or `temporal <microseconds>`"
	if len(tokens) == 0 {
		return fmt.Errorf("missing value (expected %s)", forms)
	}
	if tokens[0] == "temporal" {
		rest := tokens[1:]
		if len(rest) == 0 {
			return fmt.Errorf("temporal requires a value in microseconds (e.g. temporal 50000)")
		}
		if err := validateCoSTemporalValue(rest[0]); err != nil {
			return err
		}
		for _, t := range rest[1:] {
			return fmt.Errorf("unknown modifier %q after temporal", t)
		}
		return nil
	}
	if err := ValidateByteSizeOrPercent(tokens[0], nil); err != nil {
		return fmt.Errorf("not a valid buffer-size (expected %s): %w", forms, err)
	}
	for _, t := range tokens[1:] {
		return fmt.Errorf("unknown modifier %q", t)
	}
	return nil
}

// validateCoSTemporalValue accepts a `buffer-size temporal` operand: a positive
// integer number of microseconds. 0 is rejected because a zero delay compiles
// indistinguishably from "unset"; a non-integer or negative value is garbage.
func validateCoSTemporalValue(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("temporal requires a value in microseconds (e.g. temporal 50000)")
	}
	v, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid temporal %q: expected a whole number of microseconds (e.g. 50000)", raw)
	}
	if v == 0 {
		return fmt.Errorf("temporal must be a positive number of microseconds (0 compiles the same as unset)")
	}
	return nil
}

func parsePercentWithSuffixStrict(raw string) (float64, error) {
	orig := raw
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("empty value")
	}
	if !strings.HasSuffix(trimmed, "%") {
		return 0, fmt.Errorf("missing percent suffix in %q", orig)
	}
	number := strings.TrimSpace(strings.TrimSuffix(trimmed, "%"))
	if number == "" {
		return 0, fmt.Errorf("empty percent in %q", orig)
	}
	v, err := strconv.ParseFloat(number, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid percent %q: %w", orig, err)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("invalid percent %q: non-finite", orig)
	}
	// xpf intentionally rejects 0% even though Junos allows it.
	// A 0% buffer allocation compiles to zero bytes at runtime and is
	// indistinguishable from "no buffer-size configured" -- the runtime
	// would silently fall back to the default 10 ms burst calculation.
	// Using the default path directly is unambiguous; disallowing 0%
	// avoids silent no-op configs that look correct but do nothing.
	if v <= 0 || v > 100 {
		return 0, fmt.Errorf("percent out of range (0,100] (got %s); note: 0%% is not supported -- omit buffer-size to use the default burst", orig)
	}
	return v, nil
}

// validateForwardingClassRef is the #1319 PR 3 tree-based
// cross-reference validator for `firewall family inet/inet6 filter
// <f> term <t> then forwarding-class <name>`. The dataplane resolves
// the name with a map lookup against the CONFIGURED forwarding classes
// (queue_by_forwarding_class, userspace-dp
// src/afxdp/tx/cos_classify.rs:371) and silently leaves the packet on
// the default queue when it misses — a dangling reference commits fine
// and then does nothing. The reference is valid when:
//
//   - the name is defined via `class-of-service forwarding-classes
//     queue <n> <name>` anywhere in the candidate tree (collected by
//     collectSchemaRefs from the SAME tree being committed, so a
//     definition + reference in one commit validates atomically), or
//   - the name is "best-effort": when no forwarding-classes are
//     configured the dataplane synthesizes a best-effort queue
//     (forwarding_build/cos.rs:404-407), so that name is always
//     resolvable.
//
// xpf-DIVERGENT from Junos: the other three Junos default classes
// (expedited-forwarding, assured-forwarding, network-control) are NOT
// implicitly defined by the xpf runtime — referencing them without a
// definition is exactly the silent no-op this gate exists to close.
func validateForwardingClassRef(raw string, refs *schemaRefs) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("missing value (expected a forwarding-class name)")
	}
	if raw == "best-effort" {
		return nil
	}
	if refs != nil {
		if _, ok := refs.forwardingClasses[raw]; ok {
			return nil
		}
	}
	return fmt.Errorf("forwarding-class %q is not defined; add `set class-of-service forwarding-classes queue <queue-id> %s` in the same commit (xpf does not implicitly define the Junos default classes other than best-effort)", raw, raw)
}

// ValidateForwardingClassName rejects an EMPTY forwarding-class identity at any
// slot that names one — #8442.
//
// # The defect this closes is a Go/Rust SET DISAGREEMENT, not a bad name
//
// An empty name committed clean and crossed the wire. Measured at master by
// dumping the emitted snapshot:
//
//	{"forwarding_classes":[{"name":"","queue":5},{"name":"realfc","queue":6}],
//	 "scheduler_maps":[{"name":"sm1","entries":[{"forwarding_class":""},...]}]}
//
// The Rust `build_cos_classifier_tables` then SKIPS an empty class name when
// building `class_to_queue` — deliberately, as "the legitimate placeholder
// case" — while the Go emitter KEEPS it in both `forwarding_classes` and the
// scheduler-map entries. Each side is reasonable alone. Their disagreement is
// the fault: the scheduler-map entry's lookup misses, and
// `build_cos_iface_config` fails the WHOLE snapshot closed with
// `SchedulerMapUnknownClass { forwarding_class: "" }`.
//
// So the apply preflight keeps the previous live forwarding state and EVERY
// forwarding change in that commit silently does not apply — not just the CoS
// stanza, and not just the offending class. The operator sees a successful
// commit. That blast radius, not the bad name, is what this gate is worth.
//
// # Why here rather than in the #6455 family gate
//
// The quoted-empty-name family (`rule ""`, `group ""`, `interface ""`,
// `ids-option ""`) is handled by the pre-expansion duplicate-name scanners,
// which walk `namedInstances(FindChildren(keyword))` — NAMED BLOCKS. A
// forwarding-class name is not one: it is a positional VALUE token, either
// arg 1 of `forwarding-classes queue <id> <name>` or the identity arg of a
// `forwarding-class <name>` reference. That registry cannot see it, so
// extending it would have meant reshaping the scanner around a different
// grammar. The typed-leaf validators are where value slots are gated.
func ValidateForwardingClassName(raw string, _ *Config) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf(
			"empty forwarding-class name — a forwarding class is an identity the " +
				"dataplane resolves by name (scheduler-map entries, classifiers and " +
				"rewrite rules all reference it), and the helper drops an empty one " +
				"from its class-to-queue map. The resulting snapshot is rejected " +
				"WHOLE, so every forwarding change in the commit silently fails to " +
				"apply while the commit reports success (#8442)")
	}
	return nil
}

// ValidateForwardingClassQueueArg gates
// `class-of-service forwarding-classes queue <queue-id> <class-name>` — #8442.
//
// Positional because the leaf is `args: 2` with two different grammars: arg 0
// is the queue id and arg 1 is the class NAME, and only the name slot carries
// the identity this gate is about.
//
// It cannot false-reject a shorter authoring. The walker's declared-arg span is
// clamped to `len(node.Keys)`, so arg 1 is only ever visited when the operator
// actually wrote a second token — a bare `queue 5` never reaches this at index
// 1. Only a present-but-empty token (`queue 5 ""`) is rejected.
func ValidateForwardingClassQueueArg(argIdx int, raw string, cfg *Config) error {
	if argIdx != 1 {
		// The queue-id slot keeps its existing compiler-side handling; this gate
		// deliberately adds no new grammar there.
		return nil
	}
	return ValidateForwardingClassName(raw, cfg)
}
