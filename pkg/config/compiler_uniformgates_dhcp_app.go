package config

import "fmt"

// runUniformGatesDHCPApp runs the dhcp app sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesDHCPApp(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// #2243 DHCP-server static (fixed/reserved) host bindings. Strict on
	// commit / commit-check (hard-reject a fixed-address that is malformed,
	// family-mismatched, outside the enclosing pool subnet, or duplicates
	// another binding's MAC/address in the same pool); lenient on load /
	// peer-sync (warn so an already-persisted or peer-synced config carrying a
	// bad binding still boots — #1960 no-brick). Moved OUT of the strictErrs
	// accumulator (#2243 review): like every sibling fail-open gate it must
	// downgrade on the tolerant path, not hard-reject the whole config-load.
	// The Kea renderer skips an empty/unparseable binding independently, so a
	// leniently-loaded bad binding is inert. Runs AFTER the accumulator so a
	// structural CoS/policer/device-map/policy error still wins the first-error
	// slot.
	if err := validateDHCPStaticBindingsStrict(cfg); err != nil {
		if opts.lenientDHCPStaticBindings {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("DHCP static binding (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #9785 duplicate pool-subnet gate. Strict on commit / commit-check: two
	// pools of one DHCP server with the same subnet render two Kea subnet
	// entries for one prefix, Kea refuses the whole config, and the node stops
	// serving every pool while the commit reports success. The tolerant load /
	// peer-sync paths warn so a persisted config still boots (#1960); the Kea
	// renderer keeps the first such pool in its stable order and skips the rest
	// (claimPoolSubnet), so Kea still loads.
	if err := validateDHCPPoolSubnetsUniqueStrict(cfg); err != nil {
		if opts.lenientDHCPPoolSubnets {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("DHCP pool subnet (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2142 application-definition port/protocol fail-open gate. Strict on
	// commit / commit-check (hard-reject a `set applications application` whose
	// destination-port / source-port is malformed or whose protocol is unknown
	// — such a spec was only warned, then compiled into a never-match AppID a
	// referenced policy depends on, failing CLOSED on permit / OPEN on deny);
	// lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config carrying a bad app def still boots — the dataplane skips the bad
	// port and the #2124 runtime capability gate fails closed for a referenced
	// app it cannot represent). Reuses validatePortSpec / validateProtocol, the
	// same config-layer validators that produced the warning, so this gate adds no
	// new alias table of its own.
	//
	// #3372: a clarification on the divergence the dataplane DOES keep. The
	// runtime #2124 capability gate (pkg/dataplane/userspace
	// userspacePortSpecRepresentable, mirroring Rust parse_port_spec) matches the
	// 15 literal service aliases CASE-SENSITIVELY, whereas validatePortSpec here is
	// case-INSENSITIVE. That asymmetry would be a commit/apply split (a mixed-case
	// `destination-port HTTPS` accepted here but unrepresentable at apply) EXCEPT
	// that compileApplications / parseApplicationTerms run every application port
	// spec through resolveAppPort FIRST, which canonicalizes any recognized service
	// name (case-insensitively, against the single-source-of-truth
	// junosServicePorts catalog) to its NUMERIC form. So by the time this gate or
	// the userspace gate runs, a recognized mixed-case name is already a number and
	// the case-sensitive gate never sees a raw alias.
	//
	// The "apply" failure mode is the #3261 class-(i) unrepresentable-content
	// path, NOT a disarm/fail-open. Were the resolveAppPort case-fold removed, the
	// raw mixed-case alias would reach the userspace gate, the policy term would be
	// class-(i) unrepresentable, buildOneRuleSnapshot would emit the
	// __unsupported__ sentinel term and record snap.Capabilities.PolicyContentRejected
	// (collectPolicyContentRejections), and a current preflight-capable helper would
	// REJECT the whole snapshot while STAYING ARMED: a running node keeps its
	// previous-good policy state, a fresh boot lands on default-deny. It does NOT
	// disarm or XDP_PASS to the kernel for a current helper — disarm here is only
	// the narrow pre-preflight-protocol-version backstop
	// (pkg/dataplane/userspace/manager_ha.go class-(i) handling;
	// capabilities.go:53 documents that this cfg-only gate decides ONLY class-(ii)
	// semantics, never class-(i) content). So the regression a removed case-fold
	// would cause is broken APPLY (the new config silently does not take effect /
	// the snapshot is rejected), not a fail-open admit. The 15-name lists in
	// validatePortSpec and userspacePortSpecRepresentable are belt-and-suspenders
	// backstops kept consistent with junosServicePorts by the drift canary
	// TestNamedPortAliasTablesDoNotDrift.
	if err := validateApplicationSpecsStrict(cfg); err != nil {
		if opts.lenientApplicationSpecs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("application spec (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3352/#3353: syntactic application errors (an unknown leaf inside an
	// opaque inline `term`, or an unsupported `alg` name) are rejected for ALL
	// user-defined applications — referenced or not — unlike the
	// reference-scoped semantic specs above. These are grammar / enum
	// violations Junos rejects at commit regardless of policy wiring; a typo'd
	// term-leaf silently widens a term and a bogus `alg` silently no-ops from
	// the moment the app is defined, so they must be caught at definition.
	// Lenient-downgrade on the tolerant load / peer-sync path, identical to
	// validateApplicationSpecsStrict (#1960 no-brick).
	if err := validateApplicationSyntaxStrict(cfg); err != nil {
		if opts.lenientApplicationSpecs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("application syntax (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3366: structural application errors (a direct match body mixed with
	// `term` sub-blocks, or a duplicate single-valued leaf inside one term) are
	// rejected for ALL user-defined applications — referenced or not — like the
	// #3352/#3353 syntactic gate above. Mixing a direct body with terms silently
	// dropped the direct match (the term-store branch keeps only the terms), and
	// a repeated scalar term leaf was last-writer-wins; both are Junos config
	// errors caught at definition. Lenient-downgrade on the tolerant load /
	// peer-sync path (#1960 no-brick).
	if err := validateApplicationStructureStrict(cfg); err != nil {
		if opts.lenientApplicationSpecs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("application structure (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5821 reserved application-name gate. The AppID display/filter surface
	// (ResolveSessionName / SessionMatches, pkg/appid/runtime.go) uses the
	// literal "UNKNOWN" as the "no known application" sentinel and carries a
	// user-defined application/application-set name verbatim into the SAME
	// flattened string, so a catalog application literally named UNKNOWN
	// (case-insensitively, since SessionMatches folds case) is indistinguishable
	// from the sentinel — `show ... application UNKNOWN` cannot tell unclassified
	// sessions from the configured app, and the destructive `clear ...
	// application UNKNOWN` selector could delete both. Reserve the sentinel out
	// of the user application/application-set namespace at commit. This is a NEW
	// fail-closed restriction that can reject a config an older binary accepted;
	// lenient on load / peer-sync (warn so an already-persisted or peer-synced
	// config carrying the reserved name still BOOTS — #1960 no-brick), strict on
	// commit so the operator's next edit fails loudly.
	if err := validateReservedApplicationNamesStrict(cfg); err != nil {
		if opts.lenientReservedApplicationNames {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("reserved application name (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
