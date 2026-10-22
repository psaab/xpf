package config

import (
	"fmt"
	"strings"
)

// #9408: `protocols ospf reference-bandwidth` — the Junos bandwidth grammar,
// its unit, and the conversion to what FRR can actually render.
//
// THE UNITS DIFFER, and that is the whole content of this file.
//
//   - Junos `[edit protocols ospf] reference-bandwidth` is BITS PER SECOND.
//     Its range is 9 600 .. 100 000 000 000 000 bits/s and its default is
//     100 Mbps (100 000 000 bits/s). Junos accepts the plain integer form and
//     the k/m/g suffix form, exactly like every other Junos bandwidth leaf
//     (which is why this leaf is typed `ValueRate` — the type's own doc
//     comment already says "bits/sec with k/m/g suffix").
//   - FRR's `auto-cost reference-bandwidth (1-4294967)` is MEGABITS PER
//     SECOND.
//
// Before #9408 the leaf was untyped and the compiler stored the operator's
// token with a bare `strconv.Atoi` whose error was DISCARDED. Two things
// followed, both silent:
//
//  1. Every suffixed spelling — `1g`, `100m`, the forms Junos documentation
//     and every worked example use — failed `Atoi`, compiled to 0, and
//     rendered NO `auto-cost` line at all. The operator's cost basis stayed
//     at FRR's default and nothing said so. `-5` behaved the same way.
//  2. The bare-integer spelling was passed through VERBATIM into an FRR
//     directive whose unit is Mbps, so a Junos-faithful value was three to
//     six orders of magnitude too large for the grammar it was written into.
//
// This file is the single source of truth for the leaf: both the commit-time
// validator (`ValidateOSPFReferenceBandwidth`, wired on the `setSchema` leaf)
// and the compiler (`compileProtocols`) call `ospfReferenceBandwidthMbps`, so
// the gate and the value cannot drift apart in either direction — a schema
// behind the compiler drops values, a compiler behind the schema accepts what
// the gate rejected.
//
// SEMANTIC CHANGE, stated plainly rather than buried: a bare integer now means
// BITS PER SECOND, not Mbps. `reference-bandwidth 10000` used to render
// `auto-cost reference-bandwidth 10000` (10 Gbps); it now names 10 kbps, which
// FRR cannot express, and is REJECTED at commit with a message naming the
// unit. That is a loud failure on the commit path and a warning-plus-FRR-
// default on the tolerant load / HA-sync path (SchemaValidate violations are
// downgraded to warnings by configstore.compileTreeLenient), so an
// already-persisted config boots rather than blacking out — it just boots on
// FRR's default cost basis instead of a value three orders of magnitude wrong.
const (
	// ospfRefBandwidthMinBps is FRR's floor, 1 Mbps, expressed in the leaf's
	// own unit. It is ABOVE Junos's own 9 600 bits/s floor and therefore the
	// binding constraint: xpf cannot render a sub-Mbps reference bandwidth
	// into `auto-cost reference-bandwidth`, so it refuses rather than
	// truncating one to 0 (which renders nothing) or to 1 (which is a
	// silently wrong cost basis).
	ospfRefBandwidthMinBps = 1_000_000
	// ospfRefBandwidthMaxBps is FRR's ceiling, 4 294 967 Mbps, in bits/s.
	// Junos's own ceiling (100 Tbps) is higher, so this one binds too.
	ospfRefBandwidthMaxBps = 4_294_967_000_000
	// ospfRefBandwidthStepBps is one FRR unit: 1 Mbps.
	ospfRefBandwidthStepBps = 1_000_000
)

// ospfReferenceBandwidthMbps converts a Junos `reference-bandwidth` token to
// the Mbps integer FRR's `auto-cost reference-bandwidth` takes.
//
// It is total on its input: every rejection carries a message naming the unit,
// because "the operator does not know the unit" is the defect this leaf had.
func ospfReferenceBandwidthMbps(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("missing value (expected an OSPF reference bandwidth in BITS PER SECOND, e.g. 100m, 1g, or 1000000000)")
	}
	bps, err := parseScaledDecimalUnitStrict(trimmed)
	if err != nil {
		return 0, fmt.Errorf("not a valid bandwidth %q (expected bits per second, optionally with a k/m/g suffix, e.g. 100m or 1g): %w", raw, err)
	}
	if bps < ospfRefBandwidthMinBps {
		return 0, fmt.Errorf(
			"reference-bandwidth %q is %d bits/s, below the %d bits/s (1 Mbps) minimum this platform can express — "+
				"the value is BITS PER SECOND (Junos units), so 100 Mbps is written 100m or 100000000, not 100",
			raw, bps, uint64(ospfRefBandwidthMinBps))
	}
	if bps > ospfRefBandwidthMaxBps {
		return 0, fmt.Errorf(
			"reference-bandwidth %q is %d bits/s, above the %d bits/s (4294967 Mbps) maximum FRR's "+
				"`auto-cost reference-bandwidth (1-4294967)` accepts",
			raw, bps, uint64(ospfRefBandwidthMaxBps))
	}
	if bps%ospfRefBandwidthStepBps != 0 {
		lower := (bps / ospfRefBandwidthStepBps) * ospfRefBandwidthStepBps
		return 0, fmt.Errorf(
			"reference-bandwidth %q is %d bits/s, which is not a whole number of Mbps — FRR's "+
				"`auto-cost reference-bandwidth` is expressed in Mbps and truncating would silently change "+
				"every interface cost; write %d (%d Mbps) or %d (%d Mbps)",
			raw, bps,
			lower, lower/ospfRefBandwidthStepBps,
			lower+ospfRefBandwidthStepBps, lower/ospfRefBandwidthStepBps+1)
	}
	return int(bps / ospfRefBandwidthStepBps), nil
}

// ValidateOSPFReferenceBandwidth is the #1319 typed-leaf validator for
// `protocols ospf reference-bandwidth`, wired in schema_routing.go.
//
// It runs on the STRICT commit / commit-check path (SchemaValidate) and is
// downgraded to a warning on the tolerant Store.Load / Store.SyncApply paths,
// which is why `compileProtocols` must ALSO fail safe: see the compiler's own
// comment at the `reference-bandwidth` case.
func ValidateOSPFReferenceBandwidth(raw string) error {
	_, err := ospfReferenceBandwidthMbps(raw)
	return err
}
