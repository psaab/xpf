package config

import "fmt"

// runUniformGatesCoSPlatform runs the cos platform sub-run of the P6b uniform
// fail-open gate phase. It is a verbatim contiguous slice of the
// original runUniformGates god-function (#6423 decomposition): the
// gate order here and the segment-call order in runUniformGates together
// reproduce the exact flat gate sequence, so the first-failing-gate-wins
// strict ordering (invariant #6) and the tolerant warning-accumulation
// order (invariant #7) are preserved. See runUniformGates.
func runUniformGatesCoSPlatform(tree *ConfigTree, cfg *Config, opts compileOpts) error {
	// class-of-service scheduler-map -> scheduler cross-reference gate.
	// Strict on commit / commit-check (hard-reject a scheduler-map entry
	// naming an undefined scheduler — such a reference was only warned,
	// then compiled and KEPT, and the userspace dataplane resolved the
	// dangling name to no scheduler: the class silently lost its
	// guarantee and, pre-fix, won the MAXIMUM best-effort surplus share).
	// Lenient on load / peer-sync (warn so an already-persisted or
	// peer-synced config with a stale scheduler reference still boots —
	// #1960 no-brick; the dataplane applies the scheduler-unresolved SAFE
	// default on that boot). Runs AFTER the strict accumulator +
	// device-map so a structural CoS/policer/device-map error still wins
	// the first-error slot.
	if err := validateClassOfServiceSchedulerMapRefsStrict(cfg.ClassOfService); err != nil {
		if opts.lenientSchedulerMapRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("class-of-service scheduler-map reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #7337 class-of-service INTERFACE reference gate. Strict on commit /
	// commit-check (hard-reject a binding naming a scheduler-map,
	// traffic-control-profile, classifier or rewrite-rule that does not
	// exist). Runs immediately after the scheduler-map -> scheduler gate
	// above because the two are the outer and inner halves of one reference
	// chain, and the outer failing first gives the operator the message
	// closest to what they typed. Lenient on load / peer-sync (#1960
	// no-brick): all seven were warn-only before this gate, so an
	// already-persisted or peer-synced config may carry a dangling name and
	// must still boot. The dataplane resolves such a name to None, which is
	// the fail-open this gate stops on NEW edits — not a crash, so a
	// leniently-loaded config degrades exactly as it does today.
	if err := validateClassOfServiceInterfaceRefsStrict(cfg.ClassOfService); err != nil {
		if opts.lenientCoSInterfaceRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("class-of-service interface reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3995 class-of-service loss-priority value gate. Strict on commit /
	// commit-check (hard-reject an unrecognized loss-priority such as an
	// operator typo `medum-low`, which the dataplane would otherwise apply
	// as the SAFE default LOW / wildcard — silently wrong QoS). Lenient on
	// load / peer-sync (warn so an already-persisted or peer-synced config
	// still boots — #1960 no-brick; the dataplane applies the SAFE default
	// on that boot).
	if err := validateClassOfServiceLossPriorityStrict(cfg.ClassOfService); err != nil {
		if opts.lenientCoSLossPriority {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("class-of-service loss-priority (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #6847 dscp + inet-precedence same-unit conflict. Strict on commit (the
	// operator must pick one — the two read the same TOS byte and the loser
	// would be silently dead). Lenient on load / peer-sync so an
	// already-persisted config still boots (#1960); DSCP wins on that boot.
	if err := validateCoSUnitClassifierConflict(cfg.ClassOfService); err != nil {
		if opts.lenientCoSUnitClassifierConflict {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("class-of-service unit classifiers (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4594 class-of-service forwarding-class queue-range gate. Strict on
	// commit / commit-check (hard-reject a queue outside 0..255, which the
	// userspace helper deserializes via a checked u8::try_from and
	// fail-closes the WHOLE CoS snapshot on — CosQueueIdOutOfRange #2410 —
	// while silently keeping stale CoS forwarding state). Lenient on load /
	// peer-sync (warn so an already-persisted config that only warned +
	// committed under an older binary, or a peer-synced config, still boots
	// — #1960 no-brick; the dataplane's CosQueueIdOutOfRange fail-close is
	// the stale-but-safe backstop on that boot).
	if err := validateClassOfServiceForwardingClassQueueStrict(cfg.ClassOfService); err != nil {
		if opts.lenientCoSForwardingClassQueue {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("class-of-service forwarding-class queue (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #1956 device-map cross-entry validation. Strict on commit /
	// commit-check (hard-reject duplicate names/PCI/MAC, RETH key-mac,
	// FPC/node misalignment); lenient on load / peer-sync (warn so an
	// already-persisted or peer-section config still boots — V-1). Runs
	// AFTER the accumulator so a structural CoS/policer error still wins
	// the first-error slot.
	if err := validateDeviceMapStrict(cfg); err != nil {
		if opts.lenientDeviceMap {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("device-map (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #5636 empty-api-auth-secret gate. Strict on commit / commit-check
	// (hard-reject an api-auth stanza with an empty Basic password or empty
	// api-key — a quoted-empty secret authenticates any request presenting the
	// empty value, an auth bypass on an off-loopback bind); lenient on load /
	// peer-sync (warn so an already-persisted config still boots — #1960; the
	// daemon drops the empty credential at runtime wiring and the middleware
	// rejects an empty configured secret). Runs BEFORE the #4047 gate so the
	// precise empty-secret diagnosis wins over the more general "no api-auth"
	// message when a stanza is present but carries only empty secrets.
	if err := validateAPIAuthNoEmptySecretsStrict(cfg); err != nil {
		if opts.lenientWebManagementAuth {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("web-management api-auth (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #4047 web-management REST-auth gate. Strict on commit / commit-check
	// (hard-reject a web-management config that binds the unauthenticated REST /
	// config API off-loopback without api-auth — exposing the mutating config
	// endpoints to the network); lenient on load / peer-sync (warn so an
	// already-persisted or peer-synced config still boots — #1960; the daemon's
	// runtime bind path clamps such a bind back to loopback, so the leniently-
	// loaded config is preserved but not left exposed).
	if err := validateWebManagementAuthStrict(cfg); err != nil {
		if opts.lenientWebManagementAuth {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("web-management auth (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// Custom HTTPS credentials are an all-or-nothing pair and cannot coexist
	// with the explicit system-generated-certificate choice.
	if err := validateWebManagementTLSCertificateStrict(cfg); err != nil {
		if opts.lenientWebManagementAuth {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("web-management TLS certificate (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	return nil
}
