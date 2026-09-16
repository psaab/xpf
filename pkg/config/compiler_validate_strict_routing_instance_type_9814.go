package config

import (
	"fmt"
	"strings"
)

// routingInstanceTypeNames9814 is the single-sourced SSOT for the
// `routing-instances <name> instance-type` value domain (#9814): the schema
// leaf (schema_routing.go) and the strict gate below both reference this
// slice so the two cannot drift (the #9323 lesson — the compiler keeps no
// keyword list of its own to drift from).
//
// The three values are the documented contract: `forwarding` for
// filter-based forwarding, `virtual-router` or `vrf` for a VRF
// (docs/multi-wan.md; types_routing.go). Every consumer branches on the
// literal "forwarding" (the daemon's VRF-creation skip, the FRR and
// ip-monitoring VRF paths, the #9409 gate). Any other non-empty value
// previously committed clean and was silently treated as a VRF — the harmful
// direction, since losing `forwarding` creates a VRF the operator asked NOT
// to have and moves interfaces into it.
var routingInstanceTypeNames9814 = []string{"forwarding", "virtual-router", "vrf"}

func isRoutingInstanceType9814(v string) bool {
	for _, a := range routingInstanceTypeNames9814 {
		if v == a {
			return true
		}
	}
	return false
}

// ValidateRoutingInstanceType9814 is the schema-leaf validator for
// `instance-type` (#9814 round 3). It checks the same SSOT the compiler gate
// uses (isRoutingInstanceType9814), so the two cannot drift — but unlike the
// generic ValidateEnum it tags the rejection with (#9814), unifying the
// strict diagnostic across the schema and compiler legs (both name the
// value, the expected set, and the issue). The `expected one of: ` clause is
// kept verbatim so enumPairFromValidator's message probe still parses (and
// re-verifies) the accepted set; the leaf's three valueExamples remain the
// primary #2419 synthesis source.
func ValidateRoutingInstanceType9814(raw string, _ *Config) error {
	if isRoutingInstanceType9814(raw) {
		return nil
	}
	return fmt.Errorf("invalid instance-type %q (expected one of: %s) (#9814)",
		raw, strings.Join(routingInstanceTypeNames9814, ", "))
}

// validateRoutingInstanceTypeStrict9814 rejects a routing instance whose
// AUTHORED `instance-type` falls outside the supported domain (#9814).
//
// An omitted type (never authored AND empty) is ACCEPTED: it is the
// established VRF default — every consumer treats non-"forwarding" as a VRF,
// and existing tests compile typeless instances — so rejecting it would
// refuse configs that boot and forward today. An explicitly-EMPTY type is
// REJECTED: an `instance-type "";` spelling, a valueless `instance-type;`, or a stray
// nested under an untyped leaf and hoisted by #9792 (overwriting even a
// valid value with "") is malformed, and the old `== ""` skip let it pass
// silently on both paths (round-2 bypass). Junos types xpf does not
// implement (`no-forwarding`, `l2vpn`, `vpls`, ...) are rejected exactly
// like typos: at the value domain they are indistinguishable from
// `forwardng`, and silently VRF-ing them is the defect.
//
// Strict on commit / commit-check (hard-reject so the typo is
// operator-visible before it creates an unwanted VRF); downgraded to a
// cfg.Warnings entry on the tolerant load / peer-sync paths
// (opts.lenientRoutingInstanceType9814) so an already-persisted or
// peer-synced config carrying it still BOOTS (#1960). The downgrade keeps
// the raw value live as a VRF — deliberately, not as an oversight: the
// lenient config is already-running state accepted by an older binary, and
// the #1319 doctrine is that it "still compiles it the same way today".
// There is no inert posture available (#4713's leave-unset has no analogue
// since "" IS a VRF; #9409 drops at assembly), and quarantining a la
// #3855/#9622 would unbind running interfaces on upgrade. The operator's
// next strict commit rejects loudly.
//
// Instances are walked in declaration order so the first-reported error is
// deterministic.
func validateRoutingInstanceTypeStrict9814(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || (!ri.instanceTypeExplicit9814 && ri.InstanceType == "") || isRoutingInstanceType9814(ri.InstanceType) {
			continue
		}
		return fmt.Errorf(
			"routing-instances %q: invalid instance-type %q (expected one of: %s) — "+
				"a mistyped or unimplemented type is silently treated as a VRF by every "+
				"consumer, creating a VRF the operator may have asked NOT to have; use "+
				"`forwarding` for filter-based forwarding or `virtual-router` (or `vrf`) "+
				"for a VRF (#9814)",
			ri.Name, ri.InstanceType, strings.Join(routingInstanceTypeNames9814, ", "))
	}
	return nil
}

// runUniformGatesRoutingInstanceType9814 wires
// validateRoutingInstanceTypeStrict9814 into the P6b uniform-gate phase.
// Strict on commit / commit-check (hard-reject); lenient on load /
// peer-sync (downgrade to a warning — #1960 no-brick; the raw value stays
// live as a VRF, see above). Called DEAD-LAST from runUniformGates, after
// the #9821 gate — same doctrine as its comment: a NEW gate inserted
// between existing ones would steal the first-error slot from a config that
// trips two.
func runUniformGatesRoutingInstanceType9814(_ *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := validateRoutingInstanceTypeStrict9814(cfg); err != nil {
		if opts.lenientRoutingInstanceType9814 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("routing-instance instance-type (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	return nil
}
