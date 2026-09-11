package config

import "fmt"

// runUniformGatesIPsecEvent runs the ipsec event sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesIPsecEvent(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// #2073 IPsec policy proposal cross-reference gate. Strict on commit /
	// commit-check (hard-reject a dangling ipsec policy -> proposal
	// reference that would silently drop the configured perfect-forward-
	// secrecy group to the strongSwan default); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots — the
	// render-path safety net in pkg/ipsec preserves the PFS group on that
	// boot). Runs alongside the other tolerant-downgradable cross-ref gates.
	if err := validateIPsecPolicyProposalReferencesStrict(cfg); err != nil {
		if opts.lenientIPsecPolicyProposalRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec policy proposal reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2008 M7 / #2141: event-options attributes-match patterns are RE2
	// regexes (Junos `matches` semantics). The strict validator rejects at
	// commit not only an uncompilable pattern (#2008 M7) but also a malformed
	// match expression and an unknown <field> name (#2141) — both previously
	// fail-open: the runtime matcher silently DROPPED the constraint, turning
	// targeted remediation into broad config mutation while commit succeeded.
	// Strict-reject gives the operator immediate feedback. On the tolerant
	// LOAD path (#2063 review), downgrade to a warning: a config persisted
	// under the pre-#2008 literal-equality matcher could hold a non-RE2
	// pattern or a now-rejected malformed/unknown line, and an upgrading node
	// must still boot through it (mirrors every sibling validator above). The
	// runtime matcher then fails CLOSED on the legacy malformed line (#2141 /
	// #2124 doctrine) so the suspicious policy does not over-fire. Commit
	// stays strict.
	if err := ValidateEventAttributesMatchStrict(cfg); err != nil {
		if opts.lenientEventAttributesMatch {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("event-options attributes-match (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3751: event-options within/trigger numerics. compileEventOptions
	// parsed the within time-interval and the trigger count with strconv.Atoi
	// and SILENTLY dropped the error, so a typo (`within bogus`, `trigger on
	// typo`) coerced the field to 0. The engine then treated a 0 threshold as
	// an unconditional match — a threshold-gated remediation silently became
	// ALWAYS-FIRE (fail-open). This gate rejects a non-numeric / negative /
	// zero / out-of-range value and a within clause carrying both `trigger on`
	// and `trigger until` (contradictory). It is an AST pre-walk (the raw
	// typo'd token is lost once compileEventOptions coerces it to 0) run on
	// the group-expanded, inactive-pruned tree so an apply-groups-inherited
	// clause is caught and an inactive one is ignored. Strict (commit /
	// commit-check): hard-reject naming the policy and value. Lenient (load /
	// peer-sync): warn so an already-persisted or peer-synced config an older
	// binary silently accepted still boots (#1960) — the engine's withinMatches
	// then fails CLOSED on the leftover 0 threshold rather than over-firing.
	withinWarnings, werr := validateEventOptionsWithinAST(tree.Children, opts.lenientEventWithinTrigger)
	if werr != nil {
		return werr
	}
	cfg.Warnings = append(cfg.Warnings, withinWarnings...)

	// #2074 IPsec VPN -> IKE gateway cross-reference. A VPN that
	// references a gateway which is neither a defined gateway object nor a
	// usable inline IP/hostname would render `remote_addrs = <gateway-name>`
	// — a config-object name strongSwan cannot use, a silently-dead tunnel.
	// Strict on commit / commit-check (hard reject so the operator gets a
	// diagnostic); lenient on load / peer-sync (warn so a pre-fix or
	// peer-synced config still boots — #1960 fail-closed-on-load class).
	// Runs on the fully-compiled *Config so both ike{} and ipsec{} gateway
	// definitions are present regardless of stanza authoring order. Mirrors
	// validateDeviceMapStrict / the policy match-address gate above.
	if err := validateIPsecGatewayReferencesStrict(cfg); err != nil {
		if opts.lenientIPsecGatewayRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec gateway reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5630 IPsec endpoint value gate. An IKE gateway `address` /
	// `dynamic hostname` / `local-address`, or a VPN `local-address`, is
	// copied verbatim from a one-argument schema slot into swanctl
	// `remote_addrs` / `local_addrs`. A printable-but-invalid value (a
	// malformed IP octet like 10.0.0.999, or a malformed FQDN) is neither a
	// usable IP nor a valid hostname, so `swanctl --load-all` rejects or
	// mishandles the generated connection — a config that commits but never
	// loads (a silently broken tunnel). Strict on commit / commit-check (hard
	// reject so the operator gets a diagnostic); lenient on load / peer-sync
	// (warn so a pre-fix or peer-synced config still boots — #1960 fail-
	// closed-on-load class). Runs on the fully-compiled *Config so both ike{}
	// and ipsec{} gateway definitions are present regardless of stanza
	// authoring order. Mirrors validateIPsecGatewayReferencesStrict.
	if err := validateIPsecEndpointsStrict(cfg); err != nil {
		if opts.lenientIPsecEndpoints {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec endpoint (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #9624: reject two IPsec VPNs that render the same swanctl SA name
	// (child/child or connection/child). The renderer keeps child names unique
	// only within one VPN (#5122), and `swanctl --initiate --child` identifies a
	// child by name alone, so HA failover could not say which tunnel it brings
	// up. The names come from pkg/ipsecname, the same derivation the renderer
	// uses. Strict on commit / commit-check; lenient on load / peer-sync (warn
	// so the config still boots).
	if err := validateIPsecSANameCollisionsStrict(cfg); err != nil {
		if opts.lenientIPsecSANameCollision {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec SA name collision (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #9008 IKE/IPsec proposal `lifetime-seconds` value gate. The schema's
	// ValidateIntegerMin(1) on both leaves is enforced only by SchemaValidate,
	// which compileTreeStrict runs and compileTreeLenient downgrades — so a
	// negative or non-numeric lifetime committed clean at Store.Commit but was
	// accepted with NO diagnostic at all by Store.Load and HA SyncApply, and a
	// negative was carried into the swanctl renderer as a stored value. Strict
	// on commit, warn on the tolerant path (#1960 fail-closed-on-load class).
	if err := validateIPsecProposalLifetimesStrict(cfg); err != nil {
		if opts.lenientIPsecProposalLifetime {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec proposal lifetime (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #2270 IKE (Phase 1) gateway -> ike-policy -> ike-proposal cross-
	// reference. A gateway that names an ike-policy whose chain does not
	// resolve (the policy is undefined, or its `proposals` reference
	// dangles) made resolveIKESettings return an empty proposal, which
	// renderConfig omitted — strongSwan then negotiated phase-1 with its
	// compiled-in default set instead of the configured crypto (a silent
	// downgrade). Strict on commit / commit-check (hard reject so the
	// operator gets a diagnostic); lenient on load / peer-sync (warn so a
	// pre-fix or peer-synced config still boots — #1960 fail-closed-on-load
	// class; the render belt in pkg/ipsec skips the unrenderable VPN rather
	// than negotiating with defaults). Runs on the fully-compiled *Config so
	// both ike{} and ipsec{} gateway/policy/proposal definitions are present
	// regardless of stanza authoring order. Mirrors
	// validateIPsecPolicyProposalReferencesStrict (its Phase-2 sibling).
	if err := validateIKEPolicyChainReferencesStrict(cfg); err != nil {
		if opts.lenientIKEPolicyChainRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ike-policy chain reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4298 (V-2): reject an IPsec proposal with `protocol ah`. AH is
	// integrity-only and xpf has no AH render path, so a `protocol ah`
	// proposal used to render as ESP with a fabricated cipher — a crypto
	// misrepresentation. Strict on commit / commit-check (hard reject);
	// lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config still boots — the render belt skips the VPN rather
	// than emitting the fabricated ESP tunnel).
	if err := validateIPsecProposalProtocolStrict(cfg); err != nil {
		if opts.lenientIPsecProposalProtocol {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec proposal protocol (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4300 (V-4): reject an IPsec VPN configuring a `manual { ... }`
	// manual-key SA. xpf has no manual-key path; the block was silently
	// dropped, leaving a dead tunnel that committed OK. Strict on commit /
	// commit-check (hard reject with a clear "use an IKE-negotiated VPN"
	// message); lenient on load / peer-sync (warn — the block was already
	// inert, so the boot is fail-safe).
	if err := validateIPsecManualKeyStrict(cfg); err != nil {
		if opts.lenientIPsecManualKey {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec manual-key SA (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #9623: reject an IPsec name that becomes a swanctl SA identifier but is
	// not display-safe (a C1 control, a line or paragraph separator, or invalid
	// UTF-8). The name renders raw into the swanctl config, but GetSAStatus
	// display-escapes it (#6584), so HA IPsec SA sync publishes a DIFFERENT
	// string and the peer's `swanctl --initiate --child` / `--terminate --ike`
	// never matches it: that tunnel is not re-initiated on failover. Strict on
	// commit / commit-check; lenient on load / peer-sync (warn so the config
	// still boots).
	if err := validateIPsecSANamesDisplaySafeStrict(cfg); err != nil {
		if opts.lenientIPsecSANameDisplay {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec SA name display safety (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
