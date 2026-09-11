package config

import "fmt"

// runTailGates runs the P7 "tail gates" phase of config compilation — the
// contiguous trailing validation / finalization gate sequence extracted from
// compileExpanded as step 3 of the #4406 god-orchestrator decomposition
// (ps-review-011 / codex-173 #4).
//
// It runs the ValidateConfig structural warnings, then the interleaved
// warn/err tail gates (VRRP track-config advisories, NAT pool-utilization
// alarm, backup-router destination family, VRRP virtual-address subnet,
// screen scan/sweep + SYN-flood sub-threshold advisories, VRF overlap,
// static-NAT/NAT64 host-mask, NPTv6, NAT64 prefix, multi-peer WireGuard,
// retired userspace/DPDK-knob + login-class + SSH-hardening advisories),
// mutating the shared *Config in place. Each strict gate returns its first
// error on the strict path; each lenient/advisory gate appends warnings.
//
// Behavior-preserving invariants (do NOT reorder relative to master): this is
// the LAST phase of compileExpanded, running AFTER the P6b uniform fail-open
// gates and BEFORE the final `return cfg, nil`, so the strict first-error slot
// (invariant #6) and the tolerant-path warning accumulation ORDER (invariant
// #7) are unchanged. The gate sequence and its warning-append order are a
// verbatim lift of the tail block; it is covered by the reusable golden-output
// gate in compile_golden_4406_test.go.
func runTailGates(cfg *Config, opts compileOpts) error {
	if warnings := ValidateConfig(cfg); len(warnings) > 0 {
		for _, w := range warnings {
			cfg.Warnings = append(cfg.Warnings, w)
		}
	}

	// #1814 typed-config track warnings (both strict and lenient paths):
	// track-interface without any priority-cost (no effect),
	// track-priority-cost without track-interface (no effect), and
	// tracking on an address-owner group (priority 255) where the
	// runtime ignores tracking.
	cfg.Warnings = append(cfg.Warnings, vrrpTrackConfigWarnings(cfg)...)

	// #2079: NAT source pool-utilization-alarm threshold gate. Require
	// 0 < clear < raise <= 100. Strict (commit / commit-check): hard-reject a
	// bare `pool-utilization-alarm;` (raise=0/clear=0, always-firing) or an
	// inverted/equal pair. Lenient (load / peer-sync): warn + let the runtime
	// monitor treat raise<=0 as disabled, so an upgraded node loading a legacy
	// config committed before this gate existed still boots (#1960
	// fail-closed-on-compile-failure would otherwise brick it).
	napWarnings, err := validatePoolUtilizationAlarm(cfg, opts.lenientNATPoolAlarmThreshold)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, napWarnings...)

	// #2911: backup-router destination/next-hop family-mismatch gate. #2907
	// (#2891) made the EMPTY destination default next-hop-family-aware, but an
	// EXPLICIT destination whose family differs from the next-hop still renders
	// an FRR-invalid static line (e.g. `ipv6 route 0.0.0.0/0 <v6nh>`), which
	// frr-reload rejects and which fails the ENTIRE static config load. Strict
	// (commit / commit-check): hard-reject. Lenient (load / peer-sync): warn so
	// a config committed before this gate existed still boots (renderBackupRouter
	// still emits the bad line, but the rest of the static config no longer
	// depends on this validator to load — the operator is told to correct it).
	brWarnings, err := validateBackupRouterDst(cfg, opts.lenientBackupRouterDst)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, brWarnings...)

	// #3013: VRRP virtual-address subnet-containment gate. A virtual-address
	// must fall within a subnet configured on the same interface unit for the
	// matching family — otherwise the installed VIP has no connected route and
	// return traffic from it blackholes. vSRX rejects this at commit; xpf did
	// not. Strict (commit / commit-check): hard-reject naming the offending
	// field. Lenient (load / peer-sync): warn so a config committed before this
	// gate existed still boots (#1960 fail-closed-on-load class).
	vaWarnings, err := validateVRRPVirtualAddressSubnet(cfg, opts.lenientVRRPVirtualAddress)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, vaWarnings...)

	// #4114: port-scan / ip-sweep detection-window advisory. The `threshold`
	// is a Junos MICROSECOND detection WINDOW (the detection count is a fixed
	// constant); a value outside the Junos [1000, 1000000] us range is
	// preserved unchanged but advised here — never rejected, so existing /
	// peer-synced configs (including pre-#4114 count-shaped values) keep
	// booting on both compile paths. This is the count->window migration net.
	cfg.Warnings = append(cfg.Warnings, validateScreenScanSweepWindows(cfg)...)

	// #3315: SYN-flood sub-threshold advisories. `timeout` parses but is not yet
	// enforced (maps to the half-open session window, a tracked follow-up) and an
	// attack/source ratio orders of magnitude wide can false-throttle legitimate
	// sources on the per-source count-min sketch. Warn (never reject) so a config
	// using these leaves commits and the operator is told what is/ isn't honoured.
	cfg.Warnings = append(cfg.Warnings, validateScreenSynFloodSubThresholds(cfg)...)

	// #2387 / #7924: warn when two DISTINCT routing-instances carry overlapping
	// L3 address space, and refuse that overlap combined with a PBR `then
	// routing-instance` term. Since #7160 the session identity separates flows
	// on member interfaces by routing domain; flows PBR steers in from
	// default-instance ingress stay domain 0 and can still share an entry, which
	// is the residual the refusal covers (validateVRFOverlap's doc, #9809). The
	// warnings are appended either way, so the lenient path keeps the advisory.
	vrfOverlapWarnings, _, err := validateVRFOverlap(cfg, opts.lenientVRFOverlapPBR)
	cfg.Warnings = append(cfg.Warnings, vrfOverlapWarnings...)
	if err != nil {
		return err
	}

	// #2173: static-NAT / NAT64 host-mask gate. #2132 made the Rust
	// dataplane tolerate the canonical /32-/128 host mask and PR #2167 then
	// hardened it to REJECT a non-host mask — so a misconfigured non-host
	// static-NAT match/prefix or NAT64 pool address is now SILENTLY DROPPED
	// at the dataplane (parsed-out, never installed) with no operator
	// feedback. Strict (commit / commit-check): hard-reject a non-host mask
	// (static NAT is strictly host-1:1, NAT64 pool entries are discrete host
	// IPs). Lenient (load / peer-sync): warn so a config committed before
	// this gate existed (or peer-synced) still boots (#1960
	// fail-closed-on-compile-failure would otherwise brick restart); the
	// dataplane drops the bad entry independently, so it is already inert.
	hostMaskWarnings, err := validateNATHostMaskStrict(cfg, opts.lenientNATHostMask)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, hostMaskWarnings...)

	// #2240: NPTv6 (RFC 6296) validation gate. The dataplane compiler
	// (compileNPTv6) historically warned + `continue`d past a malformed NPTv6
	// rule and then deleted stale entries over only the VALID subset, so a typo
	// in one rule silently tore down a previously-working translation
	// (fail-open). Strict (commit / commit-check): hard-reject a malformed NPTv6
	// rule so the operator sees the misconfiguration and the previous forwarding
	// state is preserved. Lenient (load / peer-sync): warn so a config committed
	// before this gate existed still boots; the Rust helper independently
	// rejects the snapshot and keeps the previous live state, so the bad config
	// is inert.
	nptv6Warnings, err := validateNPTv6Strict(cfg, opts.lenientNPTv6)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, nptv6Warnings...)

	// #5818: NPTv6 unsupported-scope fail-closed gate. The config model supports
	// the full static-NAT match scope (rule-set `from interface` / `from routing-
	// instance`, per-rule `match source-address`), but NPTv6 compilation carries
	// only `from zone` (buildNptv6Snapshots + Nptv6RuleSnapshot). An NPTv6 rule
	// scoped to an interface/VRF or a client source prefix was therefore installed
	// as a broader zone/global prefix rewrite — traffic that cannot match the
	// configured rule was still translated (the security-widening class #5176
	// fixed for `from zone`, for the remaining scope dimensions). Until the wire +
	// dataplane carry and evaluate those dimensions (deferred /research follow-up),
	// reject the unsupported-scope NPTv6 rule at strict commit rather than silently
	// widen it. Strict (commit / commit-check): hard-reject naming the rule-set /
	// rule + the unsupported constraint. Lenient (load / peer-sync): warn so a
	// config persisted before this gate existed still boots (#1960 no-brick); the
	// snapshot builder (buildNptv6Snapshots) independently EXCLUDES the scope-
	// carrying rule so it installs nothing rather than a widened rewrite. A
	// from-zone-only / fully-unscoped NPTv6 rule is unaffected (#5176-correct
	// path); an ordinary static-NAT rule with the same dimensions is honored, not
	// touched. Runs AFTER validateNPTv6Strict so a malformed-prefix error still
	// wins the first-error slot.
	nptv6ScopeWarnings, err := validateNPTv6ScopeStrict(cfg, opts.lenientNPTv6)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, nptv6ScopeWarnings...)

	// #6483: static-NAT single-translation-target cardinality gate. A Junos
	// static-nat rule maps to EXACTLY ONE of `prefix`/`prefix-name`/
	// `nptv6-prefix`/`inet`; authoring two or more (both a prefix and a
	// prefix-name, an inet sibling plus a prefix sibling, two prefixes, …) is
	// invalid but the compiler silently accepted it by honoring one target (by a
	// fixed priority) and dropping the rest into the shared Then field — which
	// also let a malformed `mapped-port` riding on a dropped target slip through
	// (the #6479/C179-038 residual). Runs AFTER the host-mask (#2173) and NPTv6
	// (#2240/#5818) gates so a rule that ALSO carries a malformed mapped-port or a
	// bad nptv6 prefix reports that concrete token first (the multi-target defect
	// is still caught on the next compile once the token is fixed — never masked);
	// a rule whose ONLY defect is the extra target — or one whose dropped-target
	// mapped-port those earlier gates never saw (the residual) — is caught here.
	// Strict (commit / commit-check): hard-reject so the multi-target rule is
	// operator-visible. Lenient (load / peer-sync): warn (opts.lenientFirewallRefs,
	// the same opt the sibling static-NAT target gates use) so a config persisted
	// before this gate existed still boots (#1960 no-brick); the compiler still
	// lowers the single honored target, so a leniently-loaded config is no worse
	// than before the gate.
	if err := validateStaticNATSingleTargetStrict(cfg); err != nil {
		if opts.lenientFirewallRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("static NAT translation-target cardinality (downgraded to warning on tolerant path): %v", err))
		} else {
			return err
		}
	}

	// #3886: NAT64 prefix commit gate. A NAT64 rule-set `prefix` is read
	// verbatim into the wire snapshot and parsed at dataplane apply by the Rust
	// Nat64State::try_from_snapshots /96-integrity check. A non-/96 or malformed
	// prefix committed green then makes that check ABORT the entire forwarding
	// rebuild without publishing — freezing the dataplane at the last-good
	// snapshot so every later commit silently stops reaching it. Strict (commit
	// / commit-check): hard-reject anything that is not `<ipv6-address>/96`,
	// matching the Rust check exactly so there is no commit-accept ->
	// runtime-abort gap. Lenient (load / peer-sync): warn so a config committed
	// before this gate existed still boots; the Rust helper independently keeps
	// the previous live state, so the bad rule is inert.
	nat64PrefixWarnings, err := validateNAT64PrefixStrict(cfg, opts.lenientNAT64Prefix)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, nat64PrefixWarnings...)

	// #5144: source-NAT / NAT64 external-tuple overlap gate — the source-NAT
	// analog of the #2241 NPTv6 overlap check above. Differently-named
	// overlapping source pools, a source pool that also backs a NAT64 rule-set,
	// two NAT64 rule-sets sharing a pool under different prefixes, and duplicate
	// members within one pool each own an INDEPENDENT PortAllocator/occupancy
	// bitmap in the Rust dataplane (source.rs keys by pool-name+addresses, nat64.rs
	// by (prefix, pool_v4)). Independent bitmaps can each mint the same translated
	// (family, address, port) external tuple, and the reverse (1:N) NAT index then
	// misdelivers the return packet. Reject the overlap at commit (material choice
	// S1 — the commit-time detection half of #5144; the deferred packet-path global
	// cross-domain allocator is NOT implemented here). Strict (commit /
	// commit-check): hard-reject naming both allocators and the overlapping members.
	// Lenient (load / peer-sync): warn so a config committed before this gate
	// existed still boots (#1960 no-brick) — unlike NPTv6/NAT64 the dataplane does
	// NOT reject the overlapping snapshot, so the latent collision persists until
	// corrected and the warning says so. Runs AFTER the NAT64 prefix gate so a
	// malformed-prefix error still wins the first-error slot.
	natOverlapWarnings, err := validateNATPoolExternalTupleOverlapStrict(cfg, opts.lenientNATPoolOverlap)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, natOverlapWarnings...)

	// #1434 multi-peer WireGuard: per-tunnel commit gate. Strict (commit /
	// commit-check): hard-reject a WG tunnel with a missing/invalid
	// local identity (listen-port not in [1,65535] or a private-key that
	// is not 64 hex chars, #3863), zero peers, a duplicate or malformed
	// (non-64-hex) peer pubkey, a malformed PSK, or endpoint-bearing
	// peers that disagree on outer transport family.
	// Lenient (load / peer-sync): warn so an already-persisted or
	// peer-synced config still boots — the Rust hydrate path drops a row
	// with a malformed key independently and the engine reconcile is
	// dup-safe, so a leniently-loaded bad config is inert.
	wgPeerWarnings, err := validateWireguardPeersStrict(cfg, opts.lenientWireguardPeers)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, wgPeerWarnings...)

	// #1434 Increment 2 (deferred): the AF_XDP shim's WG-RX steering gate is a
	// SINGLE scalar (UserspaceCtrl.wg_listen_port), fed by the FIRST configured
	// WireGuard endpoint's port (snapshotWgListenPort). A config declaring two
	// WireGuard tunnels on DISTINCT listen ports therefore commits clean while
	// the second tunnel receives no inbound transport at all — permanently and
	// silently down. Warn (never reject): the config is legal, the first tunnel
	// works exactly as authored, and generalizing the shim to a port SET is a
	// verifier-gated lab change. This removes the silence; it does not remove
	// the limitation.
	cfg.Warnings = append(cfg.Warnings, validateWireguardSingleSteeredPort(cfg)...)

	// #5162: non-WireGuard tunnel outer-family cross-field gate. A GRE/IPIP
	// tunnel whose OUTER source and destination are different address
	// families (v4 source + v6 destination, or the reverse) passes per-leaf
	// validation and COMMITS CLEAN, but the snapshot producer tags the
	// endpoint `inet6` when EITHER endpoint is v6, so the Rust GRE encoder
	// hits the AF_INET6 arm, finds a v4 endpoint, and returns None → every
	// encapsulated packet is silently dropped. Strict (commit /
	// commit-check): hard-reject the mixed-family pair, mirroring the
	// WireGuard endpoint-family gate above (one encap = one outer family).
	// Lenient (load / peer-sync): warn so a config committed before this
	// gate existed still boots — the Rust helper independently skips a
	// mixed-family non-WG row (forwarding_build/tunnels.rs), so the bad
	// tunnel is inert rather than a silent blackhole. Runs after the WG gate
	// so a WG-specific error still wins the first-error slot.
	tunnelFamilyWarnings, err := validateTunnelOuterFamilyStrict(cfg, opts.lenientTunnelOuterFamily)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, tunnelFamilyWarnings...)

	// #4785 half 1: IPIP (ip-in-ip, proto-4/41) has NO userspace dataplane
	// primitive in either direction — the endpoint is never entered into
	// gre_decap_index (only TunnelKind::Gre is) and the egress encap
	// dispatcher's TunnelKind::Unknown arm fails closed — so a `mode ipip`
	// tunnel is created, comes UP, and passes no traffic at all. Until #4785
	// half 2 implements the decap stage, reject at commit / commit-check rather
	// than accept into a blackhole (this replaces the #4788 warn-only
	// advisory). Lenient on load / peer-sync (warn) so a config committed
	// before this gate still boots — #1960; the runtime keeps it inert anyway.
	// Runs after the outer-family gate so a family error still wins the
	// first-error slot.
	ipipWarnings, err := validateIpipTunnelUnimplementedStrict(cfg, opts.lenientIpipTunnelMode)
	if err != nil {
		return err
	}
	cfg.Warnings = append(cfg.Warnings, ipipWarnings...)

	// #1892: retired DPDK-era `system dataplane` knobs (cores, memory,
	// socket-mem, rx-mode, ports) parse for stored-config compatibility
	// but configure nothing — warn so the operator knows the stanza is
	// inert instead of silently dropping it.
	cfg.Warnings = append(cfg.Warnings, userspaceRetiredKnobWarnings(cfg)...)

	// #7172 cut 6 RETIRED the #5831/#6838 admission gate that used to sit here.
	//
	// It hard-rejected a class carrying deny-commands / deny-configuration on
	// commit, and folded it to a repair floor on the tolerant load path,
	// because accepting the statement would have left the denied verbs ALLOWED
	// while the config said otherwise — a restriction that does not restrict.
	// Cuts 1-5b implement the restriction: both dispatch surfaces (pkg/cli's
	// operational and config-mode gates, and the gRPC listener) now evaluate
	// the regexes. Refusing a control we DO implement would be the opposite
	// error, so the gate goes, exactly as its own comment said it would.
	//
	// TWO THINGS DELIBERATELY SURVIVE IT, and neither is obvious from the
	// deletion:
	//
	//   - loginClassLeafRestrictive stays. It is not part of the gate; it
	//     populates DenyLeavesPresent, which is the ONLY thing distinguishing
	//     `deny-commands ""` (an empty POSIX regex — denies EVERY command) from
	//     an absent leaf (denies nothing). Deleting the table with the gate
	//     would collapse two opposite configurations into one.
	//   - the tolerant path no longer folds anything, and must not. The fold
	//     existed to resolve an UNENFORCEABLE statement in the restrictive
	//     direction; now that the statement is enforced, folding would narrow
	//     the class a second time on top of its own regexes.
	//
	// UPGRADE: a config carrying deny-commands / deny-configuration was
	// REJECTED at commit before this and commits now — and takes effect. An
	// operator carrying such a config through the rejection will find it
	// suddenly enforced. docs/system-login.md carries the note.

	// #4304 S-2: custom `system login class <name>` definitions are
	// accepted-with-advisory — recognized so a valid vSRX RBAC config commits,
	// with a per-class note on which Junos permissions map to xpf's coarse
	// model and which sub-statements are recognized-but-not-enforced.
	cfg.Warnings = append(cfg.Warnings, loginClassAdvisoryWarnings(cfg)...)

	// #4305 S-4: SSH hardening knobs are rendered into the sshd drop-in; the
	// ones sshd cannot honor (protocol-version on an SSH-2-only daemon) get an
	// advisory instead of silently doing nothing.
	cfg.Warnings = append(cfg.Warnings, sshHardeningAdvisoryWarnings(cfg)...)

	// #5300: the shared-umem Phase 0 audit artifact is audit evidence only
	// (docs/shared-umem-plan.md) — it does NOT gate runtime shared-UMEM
	// selection. The read is non-blocking (stat-first, refuses non-regular
	// files, bounded) and NON-GATING: a missing / unreadable / malformed
	// artifact on a peer or after a restart becomes a commit WARNING, never a
	// compile error, and its content never enters the typed config, so the same
	// committed tree compiles to the identical typed config on every node. It
	// runs last because it is a pure advisory read that depends on no other gate.
	cfg.Warnings = append(cfg.Warnings, sharedUMEMAuditWarnings(cfg)...)

	// #6859: `then log` no longer forwards filter hits to the syslog streams
	// (Junos routes only `then syslog` off-box). The correction is right, and it
	// silently stops a stream some deployments may have built alerting on — so
	// name the affected terms at commit, while the operator has the config in
	// front of them. Advisory only, and self-silencing on a box that installs no
	// syslog clients, where nothing was leaving in the first place.
	//
	// Runs here, after the compile, because the predicate reads the COMPILED
	// Log/Syslog bits rather than the AST: `then syslog` sets both, so an AST
	// walk would have to re-derive the pairing the compiler already did.
	cfg.Warnings = append(cfg.Warnings, filterLogSyslogRoutingWarnings(cfg)...)

	return nil
}
