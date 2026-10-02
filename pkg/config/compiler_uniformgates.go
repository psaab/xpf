package config

import "fmt"

// runUniformGates runs the P6b "uniform fail-open gate" phase of config
// compilation — the long contiguous run of ~75 independent validation gates
// extracted from compileExpanded as step 4 of the #4406 god-orchestrator
// decomposition (ps-review-011 / codex-173 #4).
//
// Every gate in this phase has the SAME shape: it validates one typed
// sub-struct of the compiled *Config and either (a) returns its first error on
// the strict commit / commit-check path, or (b) downgrades to a warning
// appended to cfg.Warnings on its per-gate tolerant flag (load / peer-sync,
// #1960 no-brick). The phase performs NO cfg mutation — it only reads the
// compiled config, threads warnings, and dispatches the first strict error.
// (validateEventOptionsWithinAST is an AST pre-walk, so this phase also reads
// the group-expanded, inactive-pruned *ConfigTree; it is read-only there.)
//
// Behavior-preserving invariants (do NOT reorder relative to master): the
// source order of every gate is observable — on the strict path the FIRST
// failing gate wins the returned error slot (invariant #6), and on the
// tolerant path all gates run and their warnings accumulate in this exact
// sequence (invariant #7). This is a verbatim contiguous lift of the gate run;
// it runs AFTER P6a's early-strict + folds accumulator and BEFORE the P7 tail
// gates. Covered by the reusable golden-output gate in
// compile_golden_4406_test.go.
//
// The gate run is decomposed (#6423) into per-domain sub-runs living in
// compiler_uniformgates_<domain>.go sibling files. Each sub-run is a verbatim
// contiguous slice of the original flat gate sequence, and runUniformGates
// dispatches them in the SAME order, so the observable first-error and
// warning-accumulation ordering is unchanged.
func runUniformGates(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	if err := runUniformGatesCoSPlatform(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesPolicy(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesScreen(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesClusterZone(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesNAT(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesDHCPApp(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesFilter(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesIPsecEvent(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesLogFeedRouting(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesFirewallNAT2(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesSamplingAppSet(tree, cfg, opts); err != nil {
		return err
	}
	if err := runUniformGatesRoutingRibRPM(tree, cfg, opts); err != nil {
		return err
	}
	// #9424: appended at the END of the phase deliberately. The source order of
	// the gates is observable — on the strict path the FIRST failing gate wins
	// the returned error slot (invariant #6) — so a NEW gate inserted between
	// existing ones would change which error an operator is shown for a config
	// that trips two. Last means it can only claim the slot when nothing else
	// failed.
	if err := runUniformGatesInterfaceAddr(tree, cfg, opts); err != nil {
		return err
	}
	// #9821: appended at the END of the phase deliberately, after the #9424
	// gate above — same doctrine as its comment: a NEW gate inserted between
	// existing ones would steal the first-error slot from a config that trips
	// two. Dead-last means the member-collision error only surfaces when no
	// earlier gate (in particular the #5832 canonical-name and #7795
	// kernel-device collision gates, which also see these shapes) failed.
	if err := runUniformGatesRIMemberCollision(tree, cfg, opts); err != nil {
		return err
	}
	// #9814: appended at the END of the phase deliberately, after the #9821
	// gate above — same doctrine as its comment: a NEW gate inserted between
	// existing ones would steal the first-error slot from a config that trips
	// two. Dead-last means the instance-type error only surfaces when no
	// earlier gate failed.
	if err := runUniformGatesRoutingInstanceType9814(tree, cfg, opts); err != nil {
		return err
	}
	// #11060: keep dual routing-instance membership dead-last as well. The
	// order of uniform gates is observable: do not steal the first-error slot
	// from an existing validation.
	if err := runUniformGatesRIDualClaim11060(tree, cfg, opts); err != nil {
		return err
	}

	// #11310: appended after #11060 at the end of this phase, preserving the
	// existing first-error order. Gates appended after this one must preserve
	// its diagnostic priority. Protocol interface references must match the
	// routing-instance membership of the resolved Linux device. A global
	// protocol cannot claim an RI-owned device, and an RI protocol must
	// reference a device owned by that same instance; otherwise FRR activates
	// the interface in a different routing context from the configured device.
	// Known aliases are compared by kernel identity, while undeclared refs
	// remain owned by the #9405 advisory.
	if mismatches := protocolInterfaceMembershipMismatches11310(cfg); len(mismatches) > 0 {
		if opts.lenientProtocolInterfaceMembership11310 {
			for _, mismatch := range mismatches {
				cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
					"protocol interface membership (downgraded to warning on tolerant path): %s",
					mismatch))
			}
		} else {
			return fmt.Errorf("%s", mismatches[0])
		}
	}

	// #11312 follows #11310 at the tail of the phase, preserving its first-error
	// priority while remaining after #11060 so dual claims keep their existing
	// cross-instance diagnostic priority. The tolerant dual-claim path defers
	// quarantine until after all gates, so forwarding members are still visible
	// here to warn.
	if err := runUniformGatesForwardingInstanceMembers11312(tree, cfg, opts); err != nil {
		return err
	}
	// #11392 follows the existing routing-instance membership gates so their
	// strict diagnostic priority remains unchanged. Management-class devices
	// are owned by vrf-mgmt, never by a tenant VRF.
	if err := runUniformGatesRIMgmtMember11392(tree, cfg, opts); err != nil {
		return err
	}
	// #11364 fences configured cluster lifelines out of tenant routing
	// instances. Their member netdev is indistinguishable from data co-members
	// at LOCAL_IN, where ingress identifies the shared VRF master.
	if err := runUniformGatesRILifelineMember11364(tree, cfg, opts); err != nil {
		return err
	}
	// #11313 runs after all existing tail gates so it cannot steal an
	// established first-error diagnostic. A missing router AS is checked on
	// the fully-derived config after routing-options inheritance is resolved.
	if err := validateBGPRouterASStrict(cfg); err != nil {
		if opts.lenientBGPRouterAS {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("BGP router AS (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #11445: appended after all existing uniform gates so sampling source
	// validation cannot change which established error wins. Tolerant loads
	// retain the invalid value with a warning (#1960).
	if err := validateSamplingSourceAddressesStrict(cfg); err != nil {
		if opts.lenientSamplingSourceAddress {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("sampling source-address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #11400: appended after every established uniform gate so the OSPF area
	// reuse diagnosis cannot displace an existing first-error slot.
	if err := validateOSPFAreaInterfaceReuse11400(cfg); err != nil {
		if opts.lenientOSPFAreaInterface11400 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("OSPF interface area membership (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	return nil
}
