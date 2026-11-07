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
// #1960 no-brick). Tolerant gates may append warnings and replace malformed
// typed values with safe placeholders; strict gates dispatch the first error.
// This phase does not mutate the source AST. (validateEventOptionsWithinAST
// is an AST pre-walk, so the phase also reads the group-expanded,
// inactive-pruned *ConfigTree; it is read-only there.)
//
// Gate order is an execution detail, not a validation-priority API.
// Cross-gate first-error identity and tolerant-warning order are unpinned
// artefacts of execution order, not priority contracts, except where explicitly
// pinned by NAT registry #16145 and RI-collision precedence tests #9821.
// Current execution order of the newer gates is:
// #11794 -> #14397 -> #16628/#17680 -> #15935 -> #11823 -> #12089 -> #15001 -> #15278 -> #15717 -> #12217 -> #16770.
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
	// #9424 validates bracketed interface-address lists, and #9837 validates
	// tagged-unit MTUs.
	if err := runUniformGatesInterfaceAddr(tree, cfg, opts); err != nil {
		return err
	}
	// #9821 detects the remaining declared-name/unit-key collision. The
	// collision regressions pin its precedence behind #7795 and unit-reference
	// diagnostics; gate order elsewhere is not a priority contract.
	if err := runUniformGatesRIMemberCollision(tree, cfg, opts); err != nil {
		return err
	}
	// #9814 rejects explicitly configured, unsupported routing-instance types.
	if err := runUniformGatesRoutingInstanceType9814(tree, cfg, opts); err != nil {
		return err
	}
	// #11060 detects dual routing-instance membership claims. Its tolerant
	// path records quarantine evidence consumed by #12089 below.
	if err := runUniformGatesRIDualClaim11060(tree, cfg, opts); err != nil {
		return err
	}

	// #11310 validates protocol interface references against routing-instance
	// membership: global protocols cannot claim RI-owned devices, and an RI
	// protocol must reference a device owned by that same instance. Known
	// aliases are compared by kernel identity; undeclared refs remain owned
	// by the #9405 advisory.
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

	// #11312 checks forwarding-instance members. Tolerant dual-claim handling
	// leaves those memberships visible here for warning evaluation.
	if err := runUniformGatesForwardingInstanceMembers11312(tree, cfg, opts); err != nil {
		return err
	}
	// #11392 checks that management-class devices belong to vrf-mgmt rather
	// than a tenant routing instance.
	if err := runUniformGatesRIMgmtMember11392(tree, cfg, opts); err != nil {
		return err
	}
	// #11364 fences configured cluster lifelines out of tenant routing
	// instances. Their member netdev is indistinguishable from data co-members
	// at LOCAL_IN, where ingress identifies the shared VRF master.
	if err := runUniformGatesRILifelineMember11364(tree, cfg, opts); err != nil {
		return err
	}
	// #11313 validates router AS after routing-options inheritance is resolved.
	if err := validateBGPRouterASStrict(cfg); err != nil {
		if opts.lenientBGPRouterAS {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("BGP router AS (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #11445 validates sampling source addresses. Tolerant loads retain the
	// invalid value with a warning (#1960).
	if err := validateSamplingSourceAddressesStrict(cfg); err != nil {
		if opts.lenientSamplingSourceAddress {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("sampling source-address (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #11400 validates OSPF area reuse.
	if err := validateOSPFAreaInterfaceReuse11400(cfg); err != nil {
		if opts.lenientOSPFAreaInterface11400 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("OSPF interface area membership (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #11575 warns about unknown zone children on tolerant compile; since
	// #12623 (owner option (b)) ANY unknown child leaves the zone unbound.
	if err := runUniformGatesUnknownSecurityZoneChild11575(cfg, opts); err != nil {
		return err
	}
	// #11387 validates bridge-domain membership.
	if err := runUniformGatesBridgeDomainMembership11387(tree, cfg, opts); err != nil {
		return err
	}
	// #11456: a contributing-route policy on a generate route cannot be
	// evaluated against xpf's incomplete contributor feed. Strict compilation
	// rejects this unsupported shape; the tolerant path preserves the config
	// and lets ValidateConfig add the warning used by the alarm surface. Both
	// renderers omit the aggregate.
	if err := validateGenerateRoutePolicyStrict(cfg); err != nil && !opts.lenientGenerateRoutePolicy {
		return err
	}
	// #11794 rejects OSPF MD5 key IDs outside FRR's 1..255 domain. Tolerant
	// loads preserve the config with a warning; the renderer omits an invalid
	// MD5 authentication block.
	if err := validateOSPFMD5KeyIDs11794(cfg); err != nil {
		if opts.lenientOSPFMD5KeyID11794 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("OSPF MD5 key-id (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #14397 rejects OSPF authentication types without a key (MD5 with every
	// key empty, or simple-password with an empty password). Tolerant loads
	// preserve the config with a warning; the renderer omits the keyless-auth
	// interface.
	if w, err := validateOSPFAuthKeyPresenceStrict(cfg, opts.lenientOSPFAuthKeyPresence14397); err != nil {
		return err
	} else {
		cfg.Warnings = append(cfg.Warnings, w...)
	}
	// #16628/#17680 rejects OSPF MD5 keys over 16 bytes and simple-passwords
	// over 8 bytes, which FRR silently truncates. Validation runs after
	// decodeJunos9AtCompile (#15051, first in runUniformGatesLogFeedRouting),
	// so the bound applies to decoded plaintext. Tolerant loads preserve the
	// config with a warning; the renderer withholds the over-long key.
	if w, err := validateOSPFKeyLengthStrict(cfg, opts.lenientOSPFKeyLength16628); err != nil {
		return err
	} else {
		cfg.Warnings = append(cfg.Warnings, w...)
	}
	// #15935 rejects the same OSPF MD5 key ID restated with a different key.
	if err := validateOSPFMD5DuplicateKeys15935(cfg); err != nil {
		if opts.lenientOSPFMD5DuplicateKey15935 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("OSPF MD5 duplicate key-id (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #11823 validates IS-IS interface metric values. Tolerant loads retain
	// invalid values with a warning; the FRR renderer omits out-of-domain
	// metrics.
	if err := validateISISMetrics11823(cfg); err != nil {
		if opts.lenientISISMetric11823 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("IS-IS interface metric (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	// #12089 checks IPsec gateway routing-instance warnings. It consumes the
	// #11060 quarantine evidence recorded above to exclude tolerant conflicts.
	// Effective local-address selection follows the renderer (VPN, gateway,
	// then external-interface-derived).
	gatewayRIRoutingWarnings, err := validateIPsecGatewayRoutingInstance12089(
		cfg, opts.lenientIPsecGatewayVRF12089)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, gatewayRIRoutingWarnings...)

	// #15001 (A08-04) validates NAT zones. Strict compilation rejects a
	// rule-set naming an undefined zone; the tolerant path warns per offender
	// and records the rule-sets for dataplane skip (#1960).
	if err := validateNATUndefinedZoneStrict(cfg); err != nil {
		if opts.lenientNATUndefinedZone {
			for _, offender := range natUndefinedZoneOffenders(cfg) {
				cfg.Warnings = append(cfg.Warnings,
					fmt.Sprintf("nat undefined zone (downgraded to warning on tolerant path): %s", offender))
			}
			cfg.LenientNATUndefinedZoneRuleSets = NATUndefinedZoneRuleSets(cfg)
		} else {
			return err
		}
	}

	// #15278 (D02-02) validates undefined NAT interface/RI scopes. Strict
	// compilation rejects them; tolerant compilation warns with the same
	// per-axis findings and preserves the authored scope in snapshots.
	// #17247 consolidates diagnostics without changing the dataplane verdict.
	// #16827: fold unit-less NAT interface scopes onto unit 0 before the
	// gate judges them, so an admitted ref is the name the dataplane
	// compares; bare refs that cannot resolve stay bare for the gate.
	canonicalizeNATInterfaceScopes(cfg)
	if err := validateNATUndefinedScopeStrict(cfg); err != nil {
		if opts.lenientNATUndefinedScope {
			for _, offender := range natUndefinedScopeOffenders(cfg) {
				cfg.Warnings = append(cfg.Warnings,
					fmt.Sprintf("nat undefined scope (downgraded to warning on tolerant path): %s", offender))
			}
		} else {
			return err
		}
	}

	// #15717 validates post-compile login-class references: a
	// `system login user <n> class <c>` whose class is neither built-in
	// nor defined in the effective config (e.g. defined only in an
	// un-applied group, which the permissive schema-refs union passes)
	// is rejected here; tolerant loads warn and keep booting (#1960).
	if err := validateLoginUserClassReferencesStrict(cfg); err != nil {
		if opts.lenientLoginUserClassRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("login user class (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	if err := runUniformGatesUnknownSecurityPoliciesChild12217(cfg, opts); err != nil {
		return err
	}
	// #16770 rejects ssh-known-hosts entries whose host/key the daemon
	// renderer would skip; tolerant loads warn and the daemon revokes the
	// stale managed file.
	if err := ValidateSSHKnownHostsStrict(cfg); err != nil {
		if opts.lenientSSHKnownHosts16770 {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ssh-known-hosts (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}
	return nil
}
