package config

// compileOpts carries per-call compilation policy. It is threaded into
// compileExpanded so the strict commit path and the tolerant
// load/peer-sync path can share the identical compile + group-expansion
// pipeline while differing on a single, narrow validator's severity.
type compileOpts struct {
	// #1830 (e): the former lenientEqualFlowWorkerCap flag (#1733) is
	// retired along with validateEqualFlowWorkerCapStrict — the
	// dataplane no longer caps equal-flow-enforcement at 32 workers, so
	// there is no severity to downgrade. The lenient compile entry
	// points remain for the flags below.

	// sanitizeFreeTextControlChars (#1798) downgrades the control-
	// character gate from a hard compile error to sanitize-in-place
	// plus a cfg.Warnings entry. The strict commit / commit-check path
	// rejects any value or annotation containing ASCII control
	// characters — the lexer maps "\n" inside a quoted string to a
	// real newline, which injects arbitrary directives into generated
	// networkd/FRR/strongSwan files. The tolerant load / peer-sync /
	// peer-display paths must instead scrub the value and keep going
	// so an already-persisted bad config cannot blackout-boot a node
	// or alarm-loop HA config sync. This check deliberately does NOT
	// live in SchemaValidate: the tolerant paths need the value scrubbed
	// in place, which the read-only schema walk cannot do (and since
	// #1319 PR 2 SchemaValidate violations are themselves downgraded to
	// warnings on the tolerant paths — see configstore.compileTreeLenient).
	// See freetext.go for the full three-layer design.
	sanitizeFreeTextControlChars bool

	// lenientVRRPTrackDuplicates (#1814) downgrades the duplicate
	// `track-interface` gate (more than one track-interface statement
	// inside a single vrrp-group) from a hard compile error to a
	// cfg.Warnings entry with deterministic first-wins pruning of the
	// extras. Set ONLY on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient) so an
	// already-persisted or peer-synced config still boots; candidate
	// commit / commit-check stay strict and hard-reject new operator
	// edits. Like the other lenient gates, this check deliberately does
	// NOT live in SchemaValidate: pruning the duplicates is an AST-level
	// compile decision the read-only schema walk cannot make (and since
	// #1319 PR 2 SchemaValidate violations only warn on tolerant paths).
	lenientVRRPTrackDuplicates bool

	// lenientVRRPAuthentication (#4288) downgrades the VRRP authentication
	// reject (a vrrp-group carrying authentication-type / authentication-key)
	// from a hard compile error to a cfg.Warnings entry. The native dataplane
	// is RFC 5798 VRRPv3, which REMOVED authentication — the auth config is
	// parsed but never enforced, so silently accepting it lets an operator
	// believe adverts are authenticated when they are not (a rogue host can
	// hijack mastership). Strict (commit / commit-check): hard-reject so the
	// operator is not misled into a false-security posture. Set ONLY on the
	// tolerant load / peer-sync paths so an already-persisted or peer-synced
	// config an older binary silently accepted still boots (#1960).
	lenientVRRPAuthentication bool

	// lenientDeviceMap (#1956 V-1) downgrades the cross-entry device-map
	// validator (validateDeviceMapStrict) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient): an active node's
	// strict commit validates only ITS OWN node section against its own
	// hardware (R-8 pre-flight does the live-hardware half), but it cannot
	// fail on the PEER node's section (different box, structural rules like
	// FPC/node alignment differ per node). The peer's SyncApply compiles
	// leniently, so a peer-section structural finding warns rather than
	// stalling the whole config sync. The narrow management-lockout class
	// that lenient must NOT swallow is handled by the daemon's passive-node
	// SyncApply admission gate (V-1), not by this compile flag.
	lenientDeviceMap bool

	// lenientTCPMSSRange (#1979 Layer B Tier 3) downgrades the tcp-mss
	// commit-time range gate (validateTCPMSSRanges) from a hard compile
	// error to a cfg.Warnings entry. Set ONLY on the tolerant load /
	// peer-sync paths (CompileConfigLenient / CompileConfigForNodeLenient):
	// a persisted or peer-synced config carrying an out-of-range MSS value
	// an OLDER binary accepted (before this gate existed) must still boot,
	// not blackout the upgraded node — the dataplane coerces it safely
	// (Layer A, flow.go coerceWireU16) and the operator's next strict commit
	// rejects it loudly. Same doctrine as lenientVRRPTrackDuplicates. Like
	// the other lenient gates this is an AST-level compile decision (the MSS
	// value can live in two positions) and deliberately does NOT live in
	// SchemaValidate (tcp-mss stays opaque there).
	lenientTCPMSSRange bool

	// lenientLogStreamPort (#3349) downgrades the security-log stream port
	// range gate (validateSecurityLogStreamPortsAST) from a hard compile
	// error to a cfg.Warnings entry. Set ONLY on the tolerant load /
	// peer-sync paths: a persisted or peer-synced config carrying a
	// non-numeric / out-of-range `stream port` (or nested `host { port }`)
	// that an older binary accepted — and that the compiler still maps to the
	// default 514 — must still boot, not blackout the upgraded node (#1960
	// fail-closed-on-load class). Like the tcp-mss gate this is an AST-level
	// compile decision (the port value can live in two positions) and so does
	// NOT live in SchemaValidate. Same doctrine as lenientTCPMSSRange.
	lenientLogStreamPort bool

	// lenientLogTLSProfile (#3350) downgrades the security-log stream
	// tls-profile gate (validateSecurityLogStreamTLSProfileAST) from a hard
	// compile error to a cfg.Warnings entry. Set ONLY on the tolerant load /
	// peer-sync paths: a persisted or peer-synced config naming a
	// `transport tls-profile` that an older binary accepted (and that the
	// runtime silently ignored, falling back to system CA roots) must still
	// boot, not blackout the upgraded node (#1960 / #3261 fail-closed-on-load
	// class). The profile was never applied either way, so a leniently-loaded
	// value is inert. Like the port gate this is an AST-level compile decision
	// (the token lives under the `transport` block) and so does NOT live in
	// SchemaValidate. Same doctrine as lenientLogStreamPort.
	lenientLogTLSProfile bool

	// lenientFlowTraceFile (#3420) downgrades the flow-trace file path-traversal
	// gate (validateFlowTraceFileAST) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths: a
	// persisted or peer-synced config carrying a non-basename
	// `security flow traceoptions file` value (an absolute path or a ".."
	// escape) that an older binary accepted must still boot — NewTraceWriter
	// independently refuses the unsafe path at runtime, so a leniently-loaded
	// value just disables tracing instead of writing outside /var/log (#1960
	// fail-closed-on-load class). Like the port/tls-profile gates the filename
	// is an AST value SchemaValidate treats as opaque, so the check does NOT
	// live there. Same doctrine as lenientLogStreamPort.
	lenientFlowTraceFile bool

	// lenientFlowTraceFilter (#3422) downgrades the flow-trace flag /
	// packet-filter-prefix gate (validateFlowTraceFlagsAndFiltersAST) from a
	// hard compile error to a cfg.Warnings entry. Set ONLY on the tolerant
	// load / peer-sync paths: a persisted or peer-synced config carrying an
	// unparseable `packet-filter <n> source-prefix` value or an unimplemented
	// `flag` token (values an older binary accepted) must still boot — the
	// runtime fixes in NewTraceWriter keep an invalid filter match-none and
	// drop an unknown flag so the defaults still apply, so a leniently-loaded
	// value is fail-safe rather than the pre-#3422 fail-open (trace
	// everything) / fail-silent (trace nothing). Like the file gate the flag
	// and prefix values are AST leaves SchemaValidate treats as opaque, so the
	// check does NOT live there. Same doctrine as lenientFlowTraceFile.
	lenientFlowTraceFilter bool

	// lenientFlowTraceSizeFiles (#3424) downgrades the flow-trace size/files
	// range gate (validateFlowTraceSizeFilesAST) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths: a
	// persisted or peer-synced config carrying an out-of-range
	// `security flow traceoptions file <name> size <s> files <n>` (e.g. the
	// `size 1 files 1000000000` that an older binary accepted and that turned
	// each rotation into a ~1e9-iteration rename storm under the writer mutex)
	// must still boot — NewTraceWriter clamps an out-of-range value to the same
	// FlowTraceMin/Max bounds at runtime, so a leniently-loaded value is
	// fail-safe rather than a per-event CPU storm. Like the file/filter gates
	// the size/files values are AST leaves SchemaValidate treats as opaque, so
	// the check does NOT live there. Same doctrine as lenientFlowTraceFilter.
	lenientFlowTraceSizeFiles bool

	// lenientLogEventModeFormat (#3349) downgrades the event-mode log-format
	// compatibility gate (validateLogEventModeFormatStrict) from a hard
	// compile error to a cfg.Warnings entry. Set ONLY on the tolerant load /
	// peer-sync paths: a persisted or peer-synced config carrying
	// `mode event; format structured|sd-syslog` (which an older binary
	// accepted and the event writer silently renders as standard text) must
	// still boot, not blackout the upgraded node (#1960 fail-closed-on-load
	// class). The runtime already falls back, so a leniently-loaded value is
	// inert. Same doctrine as lenientLogProfileStreamRef.
	lenientLogEventModeFormat bool

	// lenientNATPoolAlarmThreshold (#2079) downgrades the
	// security-nat-source pool-utilization-alarm threshold gate
	// (validatePoolUtilizationAlarm) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient): the thresholds
	// had NO validation before #2079, so an operator could (and would) have
	// committed a bare `pool-utilization-alarm;` (raise=0/clear=0) or an
	// inverted/equal pair, persisted to active.json. After upgrade that
	// config must still LOAD (warn) instead of failing the daemon closed on
	// restart (fail-closed-on-compile-failure, #1960); the operator's next
	// strict commit rejects it loudly. The runtime monitor treats raise<=0 as
	// "feature disabled", so a leniently-loaded bad config is inert, not
	// always-firing. Same doctrine as lenientTCPMSSRange.
	lenientNATPoolAlarmThreshold bool

	// lenientPolicyMatchAddress (#2008) downgrades the policy match-
	// address validator (validatePolicyMatchAddressesStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a policy source-address /
	// destination-address token that is neither a known address-book
	// name, the `any` keyword, nor a parseable CIDR / IP — a typo would
	// otherwise reach the dataplane, be silently dropped to an empty
	// set, and (under `*-address-excluded` inversion) FAIL OPEN to
	// match-all. The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config still boots
	// (the dataplane is independently hardened to fail CLOSED on an
	// empty excluded set, so a slipped-through typo denies rather than
	// opens). Like the other lenient gates this is an AST/typed-config
	// compile decision and deliberately does NOT live in SchemaValidate
	// (which only warns on the tolerant paths since #1319 PR 2).
	lenientPolicyMatchAddress bool
	// lenientEventAttributesMatch downgrades an uncompilable
	// event-options attributes-match regex from a hard error to a warning
	// on the tolerant load path. A config persisted under pre-#2008 xpf
	// (literal-equality matcher, any string accepted) may hold a pattern
	// that is not valid RE2; a node upgrading to the regex matcher must
	// still boot through that already-committed config rather than fail to
	// load. Commit stays strict (see the validator call site).
	lenientEventAttributesMatch bool
	// lenientIPsecPolicyProposalRef (#2073) downgrades the IPsec policy
	// proposal cross-reference check from a hard error to a warning on the
	// tolerant load / peer-sync paths. A dangling `proposals` reference (or
	// a PFS policy with no resolvable proposal) silently drops the
	// configured perfect-forward-secrecy group to the strongSwan default at
	// render time; commit/commit-check hard-reject it so a new operator edit
	// fails loudly, but an already-persisted or peer-synced config carrying
	// this latent misconfiguration must still boot (the render-path safety
	// net in pkg/ipsec resolveESPSettings preserves the PFS group on that
	// boot). Same doctrine as lenientPolicyMatchAddress.
	lenientIPsecPolicyProposalRef bool

	// lenientSchedulerMapRef downgrades the class-of-service
	// scheduler-map -> scheduler cross-reference check
	// (validateClassOfServiceSchedulerMapRefsStrict) from a hard error to
	// a warning on the tolerant load / peer-sync paths. A scheduler-map
	// entry naming an undefined scheduler was warn-only at commit before
	// this gate, so a config persisted by an older binary — or synced
	// from a peer — may carry the dangling reference; an upgrading /
	// receiving node must still boot through it (warn) rather than
	// fail-closed-on-load (#1960 class). Commit / commit-check stay strict
	// — a new operator edit that would silently strip a class's
	// scheduling guarantee and (pre-fix) hand it the MAXIMUM best-effort
	// surplus share in the dataplane is rejected. The render-path safety
	// net (the scheduler-unresolved SAFE default in
	// userspace-dp forwarding_build/cos.rs, surplus_weight pinned to 1)
	// preserves the fail-SAFE posture on that boot. Same doctrine as
	// lenientIPsecPolicyProposalRef.
	lenientSchedulerMapRef bool

	// lenientCoSLossPriority (#3995) downgrades the class-of-service
	// classifier / rewrite-rule loss-priority value check
	// (validateClassOfServiceLossPriorityStrict) from a hard error to a
	// warning on the tolerant load / peer-sync paths. An unrecognized
	// loss-priority (an operator typo like `medum-low`) is rejected at
	// commit / commit-check so it is LOUD rather than silently applied as
	// the default LOW / a wildcard by the dataplane, but a config
	// persisted by an older binary — or synced from a peer — must still
	// boot through it (warn) rather than fail-closed-on-load (#1960
	// class). The dataplane's parse (cos_loss_priority_index in
	// userspace-dp forwarding_build/cos.rs) maps an unrecognized value to
	// the SAFE default, preserving the fail-SAFE posture on that boot.
	// Same doctrine as lenientSchedulerMapRef.
	lenientCoSLossPriority bool
	// lenientCoSUnitClassifierConflict (#6847) downgrades the
	// dscp+inet-precedence same-unit conflict to a warning on the tolerant
	// Load / SyncApply paths, mirroring lenientCoSLossPriority. Strict on the
	// operator commit path.
	lenientCoSUnitClassifierConflict bool

	// lenientCoSForwardingClassQueue (#4594) downgrades the
	// class-of-service forwarding-class queue-range check
	// (validateClassOfServiceForwardingClassQueueStrict) from a hard
	// error to a warning on the tolerant load / peer-sync paths. An
	// out-of-range queue (queue < 0 || queue > 255) was warn-only at
	// commit before this gate (ValidateConfig only), so it COMMITTED —
	// while the userspace helper fail-closes the WHOLE CoS snapshot on
	// CosQueueIdOutOfRange (#2410) and keeps its STALE CoS forwarding
	// state, a config/dataplane divergence the operator cannot see.
	// Commit / commit-check now reject it loudly; a config persisted by
	// an older binary — or synced from a peer — must still boot through
	// it (warn) rather than fail-closed-on-load (#1960 class). Same
	// doctrine as lenientCoSLossPriority.
	lenientCoSForwardingClassQueue bool

	// lenientIPsecGatewayRefs (#2074) downgrades the IPsec VPN -> IKE
	// gateway cross-reference check from a hard error to a warning on the
	// tolerant load / peer-sync paths (CompileConfigLenient /
	// CompileConfigForNodeLenient). A config persisted by an older binary,
	// or synced from a peer, may carry a VPN that references an undefined
	// or addressless gateway; an upgrading / receiving node must still
	// boot through it (warn) rather than fail-closed-on-load (#1960
	// class). Commit / commit-check stay strict — a new operator edit that
	// would render `remote_addrs = <gateway-name>` (a silently-dead
	// tunnel) is rejected. Same doctrine as lenientDeviceMap /
	// lenientPolicyMatchAddress.
	lenientIPsecGatewayRefs bool

	// lenientIKEPolicyChainRef (#2270) downgrades the IKE (Phase 1)
	// gateway -> ike-policy -> ike-proposal cross-reference check from a
	// hard error to a warning on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient). A dangling
	// ike-policy reference (the policy is undefined, or its `proposals`
	// reference dangles) made resolveIKESettings return an empty proposal,
	// which renderConfig omitted entirely — strongSwan then negotiated
	// phase-1 with its compiled-in default set (a silent crypto downgrade).
	// Commit / commit-check hard-reject it so a new operator edit fails
	// loudly, but an already-persisted or peer-synced config carrying this
	// latent misconfiguration must still boot (the render-path safety net in
	// pkg/ipsec resolveIKESettings -> renderConfig skips the unrenderable VPN
	// rather than negotiating with defaults). Same doctrine as
	// lenientIPsecPolicyProposalRef.
	lenientIKEPolicyChainRef bool

	// lenientIPsecEndpoints (#5630) downgrades the IPsec endpoint value gate
	// (validateIPsecEndpointsStrict) from a hard compile error to a
	// cfg.Warnings entry on the tolerant load / peer-sync paths. An IKE
	// gateway `address` / `dynamic hostname` / `local-address`, or a VPN
	// `local-address`, that is printable but not a usable strongSwan endpoint
	// (neither a literal IP nor a valid dotted hostname/FQDN — e.g. a
	// malformed IP octet 10.0.0.999 or a malformed FQDN) is copied verbatim
	// into swanctl `remote_addrs` / `local_addrs`, where `swanctl --load-all`
	// rejects or mishandles it — a config that commits but never loads (a
	// silently broken tunnel). Commit / commit-check hard-reject it so a new
	// operator edit fails loudly; an already-persisted or peer-synced config
	// an older binary accepted must still BOOT (warn) per the #1960
	// fail-closed-on-load doctrine. Same doctrine as lenientIPsecGatewayRefs.
	lenientIPsecEndpoints bool

	// lenientIPsecTrafficSelectors (#4098) downgrades the IPsec
	// `traffic-selector local-ip / remote-ip` value gate
	// (validateIPsecTrafficSelectorsStrict) from a hard compile error to a
	// cfg.Warnings entry on the tolerant load / peer-sync paths. A selector
	// value containing a control character (a newline in particular) or
	// whitespace, or one that is not a CIDR prefix / host address / IP range,
	// would otherwise inject an arbitrary `key = value` line — e.g.
	// `updown = <script>`, executed by the root charon daemon, or an
	// `esp_proposals` override — into the rendered swanctl.conf children
	// block (the swanctl-injection class already closed for the connection
	// name / IKE identity / cert / PSK, #1798/#2126). Commit / commit-check
	// stay strict so a new operator edit is rejected; an already-persisted or
	// peer-synced config carrying such a value must still BOOT (warn) per the
	// #1960 fail-closed-on-load doctrine — the render path now strips control
	// chars (sanitizeSwanctlValue in pkg/ipsec/policy.go) so the malformed
	// line stays inert. Same doctrine as lenientIKEPolicyChainRef.
	lenientIPsecTrafficSelectors bool

	// lenientReservedProposalSetNames (#5195, codex-177 A3-b2-F7) downgrades
	// the reserved-proposal-name gate (validateReservedIPsecProposalNamesAST)
	// from a hard compile error to a cfg.Warnings entry on the tolerant load /
	// peer-sync paths. An operator-authored `security {ike|ipsec} proposal`
	// whose name uses the compiler-owned `__proposal-set/` prefix would alias a
	// synthetic proposal-set member and silently overwrite it (or be overwritten
	// by it), installing a different / weaker crypto proposal than configured (a
	// silent downgrade). Commit / commit-check stay strict so a new operator edit
	// is rejected; an already-persisted or peer-synced config an older binary
	// accepted must still BOOT (warn) per the #1960 fail-closed-on-load doctrine —
	// the expand-time occupancy guard then keeps the authored proposal from being
	// clobbered. Same doctrine as lenientIPsecTrafficSelectors.
	lenientReservedProposalSetNames bool

	// lenientChassisClusterIdentities (#5694, codex-182 M15) downgrades the
	// malformed chassis-cluster identity gate
	// (validateChassisClusterIdentitiesAST) from a hard compile error to a
	// cfg.Warnings entry on the tolerant load / peer-sync paths. A
	// `redundancy-group <name>` or per-RG `node <id>` whose raw token is not a
	// non-negative integer collapses to id 0 in compileChassis (Atoi-then-
	// default), aliasing redundancy-group / node 0 and silently mis-assigning
	// cluster ownership. Commit / commit-check stay strict so a new operator
	// edit is rejected; an already-persisted or peer-synced config an older
	// binary accepted must still BOOT (warn) per the #1960 fail-closed-on-load
	// doctrine — compileChassis keeps the stable zero coercion, now flagged.
	// Same doctrine as lenientReservedProposalSetNames.
	lenientChassisClusterIdentities bool

	// lenientChassisMonitorWeight (#6588) downgrades the redundancy-group
	// monitor weight gate (validateMonitorWeightTokensAST) from a hard compile
	// error to a cfg.Warnings entry on the tolerant load / peer-sync paths. A
	// weight that is malformed (`weight nope`) or specified twice with
	// different values compiles to the 0 default / a spelling-dependent pick,
	// so the monitored link going down deducts NO weight (or the wrong one) and
	// the redundancy group does not demote — the same silent-nothing class as
	// the packed-statement drop #6588 fixes. Commit / commit-check stay strict
	// so a new operator edit is rejected; an already-persisted or peer-synced
	// config an older binary accepted must still BOOT (warn) per the #1960
	// fail-closed-on-load doctrine — compileChassis keeps the stable
	// first-wins / 0-default coercion, now flagged. Same doctrine as
	// lenientChassisClusterIdentities.
	lenientChassisMonitorWeight bool

	// lenientChassisRGStatementArity (#6588) downgrades the redundancy-group
	// no-argument statement gate (validateRGNoArgStatementsAST) from a hard
	// compile error to a cfg.Warnings entry on the tolerant load / peer-sync
	// paths. `preempt` and `strict-vip-ownership` compile to a bool and never
	// read the node, so trailing tokens or a block body — including the real
	// Junos `preempt delay <n>` that xpf does not implement — are discarded in
	// silence and the operator believes they configured something that does not
	// exist. Commit / commit-check stay strict so a new operator edit is
	// rejected; an already-persisted or peer-synced config an older binary
	// accepted must still BOOT (warn) per the #1960 fail-closed-on-load
	// doctrine — the flag itself still compiles, now with the discarded tokens
	// flagged. Same doctrine as lenientChassisMonitorWeight.
	lenientChassisRGStatementArity bool

	// lenientLoginPackedStatements (#6662) downgrades the `system login`
	// packed-body gate (validateLoginPackedStatementsAST) from a hard compile
	// error to a cfg.Warnings entry on the tolerant load / peer-sync paths.
	// `user alice class ops;` and `class ops permissions [ view configure ];`
	// are valid Junos spellings that xpf compiles to an EMPTY object, and an
	// empty user class is exactly pkg/cli's legacy "no RBAC configured"
	// shortcut — allow every command, render secrets in cleartext — so an
	// operator's configured restriction goes missing in the PERMISSIVE
	// direction with a clean commit. Commit / commit-check stay strict so a new
	// operator edit (or a `load override` of a hand-migrated vSRX config) is
	// rejected with the rewrite spelled out; an already-persisted or
	// peer-synced config an older binary accepted must still BOOT (warn) per
	// the #1960 fail-closed-on-load doctrine — leniently loaded the stanza is
	// exactly as inert as it already was, now flagged. Same doctrine as
	// lenientChassisRGStatementArity.
	lenientLoginPackedStatements bool

	// lenientLoginClassShadowsBuiltin (#6701) downgrades the `system login
	// class <name>` built-in-shadowing gate
	// (validateLoginClassShadowsBuiltinAST) from a hard compile error to a
	// cfg.Warnings entry on the tolerant load / peer-sync paths. A custom class
	// named after a system-defined one is INERT at runtime (resolveClassPerms
	// resolves the built-in first), so a narrowed `class super-user { permissions
	// view; }` grants full super-user while the commit advisory reports the
	// narrowing took effect. Commit / commit-check stay strict so a new operator
	// edit is rejected; an already-persisted or peer-synced config an older
	// binary accepted must still BOOT (warn) per the #1960 fail-closed-on-load
	// doctrine — leniently loaded the definition is exactly as inert as it
	// already was, now flagged, and built-in-first precedence keeps the runtime
	// class from being ESCALATED by the shadow. Same doctrine as
	// lenientLoginPackedStatements.
	lenientLoginClassShadowsBuiltin bool

	// lenientIPsecProposalProtocol (#4298, V-2) downgrades the IPsec
	// proposal `protocol ah` reject (validateIPsecProposalProtocolStrict)
	// from a hard error to a warning on the tolerant load / peer-sync paths.
	// AH is integrity-only (no encryption) and xpf has no AH render path, so
	// a `protocol ah` proposal used to render as ESP with a fabricated
	// cipher — a crypto misrepresentation. Commit / commit-check hard-reject
	// it; an already-persisted or peer-synced config carrying it must still
	// BOOT (warn), and the render-path belt (vpnUsesAHProposal ->
	// renderConfig skips the VPN) keeps the fabricated ESP tunnel out of the
	// generated swanctl.conf. Same doctrine as lenientIKEPolicyChainRef.
	lenientIPsecProposalProtocol bool

	// lenientIPsecManualKey (#4300, V-4) downgrades the IPsec VPN
	// manual-key SA reject (validateIPsecManualKeyStrict) from a hard error
	// to a warning on the tolerant load / peer-sync paths. xpf has no
	// manual-key path; the block was silently dropped, leaving a dead
	// tunnel. Commit / commit-check hard-reject it so a new operator edit
	// fails loudly; an already-persisted or peer-synced config still boots
	// (warn) — the manual block was already inert, so the boot is fail-safe.
	// Same doctrine as lenientIPsecGatewayRefs.
	lenientIPsecManualKey bool

	// lenientLogProfileStreamRef (#2008 H7) downgrades the
	// `security log profile <name> stream-name <stream>` cross-reference
	// from a hard error to a warning on the tolerant load / peer-sync
	// paths. A config persisted by an older binary (which silently dropped
	// the whole profile stanza), or synced from a peer, may carry a profile
	// naming a stream that is not configured; an upgrading / receiving node
	// must still boot through it (warn) rather than fail-closed-on-load
	// (#1960 class). Commit / commit-check stay strict — a new operator
	// edit that names a non-existent stream (a typo whose log routing would
	// silently never fire) is rejected. Same doctrine as
	// lenientIPsecPolicyProposalRef.
	lenientLogProfileStreamRef bool

	// lenientDynamicAddressFeedRef (#3300) downgrades the
	// `security dynamic-address address-name <addr> profile feed-name <feed>`
	// cross-reference (validateDynamicAddressFeedReferencesStrict) from a
	// hard error to a warning on the tolerant load / peer-sync paths. An
	// already-persisted config (older binaries never validated the feed-name
	// reference), or one synced from a peer, may carry an address-name whose
	// profile feed-name does not resolve to a declared feed; an upgrading /
	// receiving node must still boot through it (warn) rather than
	// fail-closed-on-load (#1960 / #3261 class). The runtime is already
	// fail-closed (an unknown feed resolves to an empty, match-nothing
	// address book), so a leniently-loaded typo denies nothing rather than
	// bricking. Commit / commit-check stay strict — a new operator edit that
	// names an undefined feed (whose deny policy would silently match
	// nothing) is rejected. Same doctrine as lenientLogProfileStreamRef.
	lenientDynamicAddressFeedRef bool

	// lenientDuplicateNamedBlock (#5180) downgrades the duplicate
	// hierarchical named-block gate (validateDuplicateNamedBlockAST) from a
	// hard error to a warning on the tolerant load / peer-sync paths. An
	// already-persisted config (older binaries silently reduced a repeated
	// `groups`/`interfaces`/`screen ids-option` block to last-writer-wins),
	// or one synced from a peer, may carry such a duplicate; an upgrading /
	// receiving node must still boot through it (warn — the runtime keeps the
	// historical last-writer-wins result) rather than fail-closed-on-load
	// (#1960 class). Commit / commit-check stay strict — a new operator edit
	// that authors a block twice (silently dropping the earlier one) is
	// rejected so the author is told to write it once.
	lenientDuplicateNamedBlock bool

	// lenientDuplicateNATRuleName (#5649, C181-M18) downgrades the duplicate
	// NAT rule-name gate (validateDuplicateNATRuleNamesAST) from a hard error
	// to a warning on the tolerant load / peer-sync paths. Unlike #5180 the
	// duplicate is NOT last-writer-wins: both same-named rules survive as
	// separate first-match entries sharing one config identity (the rule name —
	// the counter for ordinary rules, but NPTv6 static is counter-less). An already-persisted
	// config (or one synced from a peer) may carry such a duplicate; an
	// upgrading / receiving node must still boot through it (warn — the runtime
	// keeps the historical two-row behavior) rather than fail-closed-on-load
	// (#1960 class). Commit / commit-check stay strict — a new operator edit
	// that authors a rule twice is rejected so the author is told to write it
	// once.
	lenientDuplicateNATRuleName bool

	// lenientDuplicateNATRuleSetName (#6454, C181-M18 sibling) downgrades the
	// duplicate NAT rule-SET-name gate (validateDuplicateNATRuleSetNamesAST) from
	// a hard error to a warning on the tolerant load / peer-sync paths. Like
	// #5649 (and unlike #5180) the duplicate is NOT last-writer-wins: two
	// same-named rule-sets within one nat type (source/destination/static/nat64)
	// BOTH survive as separate first-match tables sharing one name (the from/to
	// scope binding and the CLI show key), and the named-rule-set show lookup
	// returns on the first match so the operator cannot disambiguate the two — not
	// a per-rule counter merge (NATCounterKey includes the rule name, so disjoint
	// rules get distinct counters). An
	// already-persisted config (or one synced from a peer) may carry such a
	// duplicate; an upgrading / receiving node must still boot through it (warn —
	// the runtime keeps the historical two-table behavior) rather than
	// fail-closed-on-load (#1960 class). Commit / commit-check stay strict — a new
	// operator edit that authors a rule-set twice is rejected so the author is
	// told to write it once. Same doctrine as lenientDuplicateNATRuleName.
	lenientDuplicateNATRuleSetName bool

	// lenientNATHostMask (#2173) downgrades the static-NAT / NAT64
	// host-mask gate (validateNATHostMaskStrict) from a hard compile error
	// to a cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync
	// paths (CompileConfigLenient / CompileConfigForNodeLenient): #2132 made
	// the Rust dataplane tolerate the canonical host mask, PR #2167 then
	// hardened it to REJECT a non-host mask, so a config persisted/synced
	// with a non-host static-NAT match/prefix or NAT64 pool address (which
	// an older binary parsed-out silently, or a peer authored) must still
	// BOOT after upgrade (warn) instead of failing closed (#1960). Commit /
	// commit-check stay strict — a new operator edit whose rule the
	// dataplane will silently drop is rejected loudly. The dataplane drops
	// the bad entry independently, so a leniently-loaded config is already
	// inert for that rule. Same doctrine as lenientNATPoolAlarmThreshold.
	lenientNATHostMask bool

	// lenientUnsupportedInterfaceStanzas (#2008 H9/H10) downgrades the
	// interface silent-drop gate (validateUnsupportedInterfaceStanzasAST:
	// `interface [unit] mac` static-MAC override, `family inet|inet6
	// policer arp` per-unit ARP policer) from a hard error to a warning on
	// the tolerant load / peer-sync paths. Both stanzas parse-accept and
	// silently drop on every binary up to this gate, so an
	// already-persisted or peer-synced config may carry them; an upgrading
	// / receiving node must still boot through it (warn) rather than
	// fail-closed-on-load (#1960 class). Commit / commit-check stay strict
	// — a new operator edit that the dataplane cannot honour is rejected
	// instead of silently ignored. Same doctrine as
	// lenientVRRPTrackDuplicates / lenientLogProfileStreamRef.
	lenientUnsupportedInterfaceStanzas bool

	// lenientQinQVLANStack (#5879) downgrades the canonical per-physical-
	// interface QinQ / stacked-VLAN honesty gate (validateQinQVLANStackAST:
	// an aggregate inner/second VLAN tag spelled `inner-vlan-id` OR
	// `vlan-tags inner`, possibly split across statements or contributed by
	// a peer-only group) from a hard error to a warning on the tolerant load
	// / peer-sync paths. The AF_XDP dataplane unwinds a single VLAN tag, so
	// an inner tag was already silently dropped on every binary up to this
	// gate; an already-persisted or peer-synced config may carry one, and an
	// upgrading / receiving node must still boot through it (warn) rather
	// than fail-closed-on-load (#1960 class). Commit / commit-check stay
	// strict — a new operator edit whose stacked-VLAN stack the dataplane
	// cannot honour is rejected loudly. Same doctrine as
	// lenientUnsupportedInterfaceStanzas (#2008 H9/H10), whose QinQ half this
	// gate subsumes.
	lenientQinQVLANStack bool

	// lenientVLANMap (#6178) downgrades the input-vlan-map / output-vlan-map
	// (per-unit VLAN rewrite) honesty gate (validateVLANMapAST) from a hard
	// error to a warning on the tolerant load / peer-sync paths. Neither
	// spelling is in the unit setSchema and neither has a compiler consumer,
	// so a configured VLAN tag push/pop/swap was already silently dropped on
	// every binary up to this gate; an already-persisted or peer-synced
	// config may carry one, and an upgrading / receiving node must still boot
	// through it (warn) rather than fail-closed-on-load (#1960 class). Commit
	// / commit-check stay strict — a new operator edit requesting a rewrite
	// the AF_XDP dataplane cannot perform is rejected loudly rather than
	// silently ignored. Same doctrine as lenientQinQVLANStack (#5879).
	lenientVLANMap bool

	// lenientRoutingExportRef (#2144) downgrades the routing-export
	// cross-reference gate (validateRoutingExportReferencesStrict) from a
	// hard compile error to a cfg.Warnings entry. Set ONLY on the tolerant
	// load / peer-sync paths (CompileConfigLenient /
	// CompileConfigForNodeLenient): a dynamic-protocol `export`, RIP
	// `redistribute`, BGP group/neighbor `export`, or `routing-options
	// forwarding-table export` naming an undefined policy-statement (or a
	// non-protocol typo) passed commit on every binary up to this gate, so
	// an already-persisted or peer-synced config may carry it; an upgrading
	// / receiving node must still BOOT through it (warn) rather than fail
	// closed (#1960). Commit / commit-check stay strict — a new operator
	// edit whose export FRR would reject, silently no-op, fail open
	// (route-map permit-all), or silently disable ECMP is rejected loudly.
	// The render-path fallbacks keep a leniently-loaded config behaving
	// exactly as it did before this gate. Same doctrine as
	// lenientLogProfileStreamRef.
	lenientRoutingExportRef bool
	// lenientFRRAuthValues (#2889) downgrades the FRR auth-value gate
	// (validateFRRAuthValuesStrict) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths.
	// A BGP neighbor TCP-MD5 password or an OSPF/RIP/IS-IS authentication
	// key containing whitespace cannot be expressed as a single FRR/vtysh
	// token (FRR's command lexer, lib/command_lex.l, tokenizes purely on
	// whitespace and has NO quoted-string and NO rest-of-line token), so it
	// would be split into multiple args at frr.conf load — truncating the
	// secret at the first space or, worse, treating trailing words as extra
	// vtysh arguments. This gate rejects such a value at commit so the
	// operator sees it, instead of a silently-broken authentication setup.
	// Commit / commit-check stay strict; an already-persisted or peer-synced
	// config carrying such a value must still BOOT (warn) per the #1960
	// fail-closed-on-load doctrine — the render path already strips control
	// chars (sanitizeFRRValue) so the malformed line stays inert/single-line.
	// Same doctrine as lenientRoutingExportRef.
	lenientFRRAuthValues bool
	// lenientRouteFilterMatchTypes (#2525) downgrades the route-filter
	// match-type gate (validateRouteFilterMatchTypesStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects an FRR-unsupported `through` match-type and a
	// malformed / inverted / out-of-range / below-base `prefix-length-range`.
	// These match-types committed unnoticed before this gate (the schema
	// admitted them and the renderer silently degraded them to an open-ended
	// `le maxLen`), so an already-persisted or peer-synced config may carry
	// one; an upgrading / receiving node must still BOOT through it (warn)
	// rather than fail closed (#1960). The renderer skips the offending entry
	// on the tolerant path (match-nothing, fail-closed). Same doctrine as
	// lenientRoutingExportRef.
	lenientRouteFilterMatchTypes bool
	// lenientApplicationSpecs (#2142) downgrades the application-definition
	// port/protocol gate (validateApplicationSpecsStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `set applications application <name>` whose
	// destination-port / source-port is malformed (non-numeric, out of
	// 1..65535, or an inverted low>high range) or whose protocol token is
	// neither a known name, a junos-* alias, nor a 0..255 number. Such a spec
	// was previously only WARNED (ValidateConfig): commit succeeded, the
	// dataplane app-id compiler skipped the unparsable port (recording the
	// AppID name first, then `continue`-ing past the bad port — a never-match
	// AppID), and a policy referencing it failed CLOSED on permit / fell
	// through OPEN on deny. The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config carrying a bad app
	// def still BOOTS (#1960 no-brick) — the dataplane independently skips the
	// unparsable port, and the runtime #2124 capability gate
	// (expandUserspacePolicyApplications) fails the snapshot closed
	// (ForwardingSupported=false) for a referenced app it cannot represent, so
	// a leniently-loaded bad app is inert rather than silently mis-matching.
	// Commit stays strict so the operator's next edit fails loudly. This is an
	// AST/typed-config compile decision and deliberately does NOT live in
	// SchemaValidate (applications stay opaque there). Same doctrine as
	// lenientPolicyMatchAddress / lenientNATHostMask.
	lenientApplicationSpecs bool
	// lenientApplicationNameCollisions (#3339, Codex review 080 M07/M08)
	// downgrades the application / application-set name-collision gate
	// (validateApplicationNameCollisionsAST) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// duplicate application or application-set definition, a name authored as both
	// an application and an application-set (an explicit set silently overwriting
	// the implicit set minted for a multi-term application), or two terms whose
	// generated per-term application names collide — all of which compileApplications
	// resolves last-write-wins with no commit error, leaving policy expansion and
	// the AppID catalog free to pick different definitions. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or peer-synced
	// config an older binary silently accepted still BOOTS (#1960 no-brick); the
	// last-write-wins maps it always produced are unchanged on that path. Same
	// doctrine as lenientApplicationSpecs / lenientApplicationSetMembers.
	lenientApplicationNameCollisions bool

	// lenientReservedApplicationNames (#5821) downgrades the reserved-name gate
	// (validateReservedApplicationNamesStrict) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// user-defined `applications application <name>` or `application-set <name>`
	// whose name equals the AppID unknown sentinel "UNKNOWN"
	// (ReservedApplicationName) case-insensitively — a real catalog application
	// so named is indistinguishable from the "no known application" sentinel on
	// the AppID display/filter surface (ResolveSessionName / SessionMatches,
	// pkg/appid/runtime.go), so a `show`/`clear ... application UNKNOWN` selector
	// cannot separate the two and a filtered clear could delete both classes.
	// This is a NEW fail-closed restriction that can reject a config an older
	// binary accepted, so the tolerant load / peer-sync paths downgrade it to a
	// warning: an already-persisted or peer-synced config carrying the reserved
	// name still BOOTS (#1960 no-brick) rather than bricking a running node on
	// upgrade, while the operator's next commit fails loudly. Same doctrine as
	// lenientApplicationNameCollisions / lenientApplicationSpecs.
	lenientReservedApplicationNames bool

	// lenientFirewallFilterFamilyCollisions (#3884, fable-review-161 F-030)
	// downgrades the firewall-filter cross-family name-collision gate
	// (validateFirewallFilterFamilyCollisionsAST) from a hard compile error to a
	// cfg.Warnings entry. compileFirewall folds every filter family except inet6
	// (inet, any, mpls, ccc, vpls, bridge, ...) into ONE name-keyed map
	// (fw.FiltersInet) with an unconditional `dest[name] = filter` write, so a
	// same-name filter authored under a second such family silently OVERWRITES
	// the first — a `discard` filter can be replaced by a same-name accept-all
	// (fail-open). Downstream consumers key filters by name within the inet (V4) /
	// inet6 (V6) buckets only, with no family dimension to disambiguate, so the
	// reuse is genuinely ambiguous. The strict commit / commit-check path hard-
	// rejects it; the tolerant load / peer-sync paths downgrade to a warning so
	// an already-persisted or peer-synced config an older binary silently
	// accepted still BOOTS (#1960 no-brick), keeping the arbitrary-but-stable
	// last-write-wins map compileFirewall always produced. Same doctrine as
	// lenientApplicationNameCollisions.
	lenientFirewallFilterFamilyCollisions bool

	// lenientFirewallFilterFamilyAnyMatches (#4296, fable-review-167 F-1
	// residual) downgrades the firewall-filter family-any specific-match gate
	// (validateFirewallFilterFamilyAnyMatchesAST) from a hard compile error to a
	// cfg.Warnings entry. #4287 dual-compiles a `family any` filter into BOTH the
	// inet and inet6 pools; a family-specific match under `family any` (a v4/v6
	// source/destination-address literal or a per-family icmp-type/icmp-code) is
	// then dual-compiled verbatim and can never match the other family — an
	// imperfect v6 under-block. The strict commit / commit-check path hard-rejects
	// it (pointing the operator at family inet/inet6); the tolerant load / peer-
	// sync paths downgrade to a warning so an already-persisted or peer-synced
	// config an older binary silently accepted still BOOTS (#1960 no-brick),
	// keeping the existing dual-compile behavior. Same doctrine as
	// lenientFirewallFilterFamilyCollisions.
	lenientFirewallFilterFamilyAnyMatches bool
	// lenientFilterProtocols (#2175 review) downgrades the firewall-filter
	// `from protocol <token>` gate (validateFilterProtocolsStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a term whose protocol token is neither
	// a known protocol name, a junos-* alias, nor a 0..255 number — the same
	// acceptance set the centralized appid.ProtocolNumber SSOT admits (#2124
	// / #2175). Before this gate such a token was caught only by the
	// dataplane compiler (compileFirewallFilters → validateFilterProtocols),
	// whose error the daemon SWALLOWS (it is not in
	// requiredProtocolGateSentinels, so compileErrorMustAbortApply == false):
	// commit returned SUCCESS, the config was promoted, and the term silently
	// programmed NO protocol match (the pre-#2175 "match protocol 0"
	// surprise). The dataplane gate stays as defense-in-depth; this commit-
	// check gate makes the refusal operator-visible. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config carrying a bad token still BOOTS (#1960 no-brick) —
	// the dataplane independently drops the protocol constraint, so a
	// leniently-loaded bad term is inert (it matches without a protocol
	// constraint, never silently "protocol 0"). Same doctrine as
	// lenientApplicationSpecs.
	lenientFilterProtocols bool
	// lenientFilterCrossField (#3723) downgrades the firewall-filter cross-field
	// satisfiability gate (validateFilterCrossFieldStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a term whose `from` block combines a port with a non-port
	// protocol (gre/esp/icmp/...), tcp-flags with a non-TCP protocol, or
	// icmp-type/icmp-code with a non-ICMP protocol (and an icmp-code with no
	// icmp-type) — cross-field pairs the dataplane matcher can never satisfy, so
	// a `then discard`/`reject` term silently NEVER matches and the traffic is
	// admitted by the implicit accept (fail-OPEN). The tolerant load / peer-sync
	// paths downgrade to a warning so an already-persisted or peer-synced config
	// carrying such a term still BOOTS (#1960 no-brick); the Rust snapshot
	// builder's UnsatisfiableFilterCrossField backstop then rejects the whole
	// snapshot (fail closed) so the never-match term never silently forwards.
	// Same doctrine as lenientFilterProtocols; mirrors the application
	// cross-field gate (#3373/#3348, lenientApplicationSpecs).
	lenientFilterCrossField bool
	// lenientFilterActions (#2399 finding 032-16) downgrades the
	// firewall-filter `then` action gate (validateFilterActionsStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a term whose `then` block carries a token
	// that is neither a recognized terminating action (accept/reject/discard)
	// nor a recognized modifier. Before this gate such a token was silently
	// DROPPED at compile, leaving Action == "" which the dataplane compiler and
	// the Rust filter both map to ACCEPT (a fail-open permit). The tolerant
	// load / peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config carrying an unknown action still BOOTS (#1960
	// no-brick). Same doctrine as lenientFilterProtocols.
	lenientFilterActions bool
	// lenientFilterMatchValues (#3205, agy-070 #07/#08) downgrades the
	// firewall-filter symbolic-match-value gate (validateFilterMatchValuesStrict)
	// from a hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a term whose icmp-type/icmp-code name or
	// named port could not be resolved to a number. Before this gate such a value
	// was silently dropped: an unresolved icmp-type matched ALL ICMP (policy
	// bypass) and an unresolved named port made a `*-port-except` term match ALL
	// ports (fail open). The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config still BOOTS (#1960
	// no-brick); the unresolved token is kept verbatim so the dataplane fails
	// CLOSED independently. Same doctrine as lenientFilterActions.
	lenientFilterMatchValues bool
	// lenientFlexMatch (#3203, agy-070 #02/#03/#04) downgrades the
	// firewall-filter flexible-match-range gate (validateFilterFlexMatchStrict)
	// from a hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a term whose byte-offset/bit-length/
	// match-value/match-mask could not be parsed or fell outside the
	// representable range. Before this gate such a token was silently ignored,
	// leaving the field at its zero default — a malformed or >32-bit
	// match-value became 0x0 and the rule matched the WRONG pattern with a clean
	// commit. The tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config still BOOTS (#1960 no-brick).
	// Same doctrine as lenientFilterMatchValues.
	lenientFlexMatch bool
	// lenientFilterPortExcept (#3297) downgrades the firewall-filter
	// positive-vs-except port mutual-exclusion gate
	// (validateFilterPortExceptStrict) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// term that carries BOTH a positive port match (source-port /
	// destination-port) AND the negated *-port-except list in the SAME
	// direction — Junos treats those as mutually exclusive match families and
	// rejects the term at commit. Before this gate xpf accepted the ambiguous
	// term and the Rust matcher resolved it deterministically as positive-wins
	// (the except side silently dropped) — fail-safe at runtime but a
	// Junos-invalid config accepted with one side of the operator's intent
	// lost. The tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config still BOOTS (#1960 no-brick); the
	// dataplane's positive-wins fallback keeps that direction fail-safe. Same
	// doctrine as lenientFilterMatchValues.
	lenientFilterPortExcept bool
	// lenientFilterAddressExcept (#3359) downgrades the firewall-filter
	// positive-vs-except ADDRESS mutual-exclusion gate
	// (validateFilterAddressExceptStrict) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// term that mixes a positive address match (a literal source-address /
	// destination-address OR a non-except prefix-list) with an `except`
	// prefix-list in the SAME direction — Junos treats those as mutually
	// exclusive and rejects the term at commit. Before this gate xpf accepted
	// the ambiguous term and the userspace lowering FOLDED the except prefixes
	// into the positive match set (dropping the except modifier) — a silent
	// fail-OPEN for a discard/reject term (#3359). The runtime fold is now
	// positive-wins (the except side ignored, never folded in) so a
	// leniently-loaded term is fail-safe; the tolerant load / peer-sync paths
	// downgrade to a warning so an already-persisted or peer-synced config still
	// BOOTS (#1960 no-brick). Sibling of lenientFilterPortExcept (#3297).
	lenientFilterAddressExcept bool
	// lenientFilterFromMatch (#3307) downgrades the firewall-filter
	// unenforced-`from`-leaf gate (validateFilterFromMatchStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects a term whose `from` block carries a match leaf the
	// dataplane does NOT enforce (ttl / source-mac-address / ip-options /
	// fragment-offset / hop-limit / ...). Before this gate such a leaf passed
	// the opt-in schema gate and was silently dropped by compileFilterFrom (no
	// default arm), so the term enforced a BROADER match than authored — an
	// accept over-permits (fail open), a discard/reject over-drops. The tolerant
	// load / peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config carrying the unsupported leaf still BOOTS (#1960
	// no-brick); the dataplane never represented the leaf, so the term keeps
	// matching without it independently. Same doctrine as lenientFilterActions.
	lenientFilterFromMatch bool
	// lenientFilterAddressLiterals (#3433) downgrades the firewall-filter
	// literal-address gate (validateFilterAddressLiteralsStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a term whose literal source/destination-address is malformed
	// (`10.0.0.0/99`) or of the wrong family for the filter (a v4 CIDR under
	// `family inet6`). Before this gate the bad literal reached the kernel lo0 nft
	// mirror verbatim and failed the atomic load (or left the mirror absent on the
	// lenient path while userspace stayed armed). The tolerant load / peer-sync
	// paths downgrade to a warning so an already-persisted or peer-synced config
	// still BOOTS (#1960 no-brick); the lowering family-filter and the userspace
	// matcher both fail closed for the bad token independently. Same doctrine as
	// lenientFilterFromMatch.
	lenientFilterAddressLiterals bool
	// lenientFilterRoutingInstanceConflict (#3308) downgrades the firewall-filter
	// routing-instance-vs-discard/reject mutual-exclusion gate
	// (validateFilterRoutingInstanceConflictStrict) from a hard compile error to
	// a cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// term that co-locates `then routing-instance <x>` with a terminating
	// `then discard` / `then reject` — a contradiction the PBR runtime resolves
	// by ROUTING the packet anyway while logging it as denied (the audit trail
	// lies; fail-open PBR). The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config still BOOTS (#1960
	// no-brick); the runtime routes-and-mislogs the term independently. Same
	// doctrine as lenientFilterPortExcept.
	lenientFilterRoutingInstanceConflict bool
	// lenientFilterTerminalConflict (#4375, avo-review-007 H3) downgrades the
	// firewall-filter conflicting-terminal-actions gate
	// (validateFilterTerminalConflictStrict) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// term that specifies more than one DISTINCT terminating action
	// (accept/reject/discard — mutually exclusive in Junos). Before this gate
	// compileFilterThen wrote each keyword onto the single-valued term.Action
	// (last-write-wins), so a term with `then accept` AND `then reject` silently
	// compiled to whichever came last — an ambiguous config accepted with one
	// side of the operator's intent lost. The tolerant load / peer-sync paths
	// downgrade to a warning so an already-persisted or peer-synced config still
	// BOOTS (#1960 no-brick); the last-wins Action drives the dataplane
	// deterministically. Sibling of lenientFilterRoutingInstanceConflict (#3308).
	lenientFilterTerminalConflict bool
	// lenientFilterDSCP (#3309) downgrades the firewall-filter DSCP /
	// traffic-class range gate (validateFilterDSCPStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `from dscp` / `from traffic-class` match token or a
	// `then dscp` / `then traffic-class` rewrite token that is neither a known
	// code-point name nor an integer 0..63. Before this gate such a token was
	// appended raw and SILENTLY DROPPED by the snapshot builder: a dropped match
	// value left the term matching ALL DSCPs (a policy widening) and a dropped
	// rewrite no-opped. The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config still BOOTS (#1960
	// no-brick); the snapshot builder drops the bad token independently. Same
	// doctrine as lenientFilterMatchValues.
	lenientFilterDSCP bool
	// lenientNPTv6 (#2240) downgrades the NPTv6 (RFC 6296) validation gate
	// (validateNPTv6Strict) from a hard compile error to a cfg.Warnings entry.
	// The strict commit / commit-check path hard-rejects an NPTv6 static-NAT
	// rule whose `match destination-address` / `then static-nat nptv6-prefix` is
	// unparseable, not a /48 or /64, has mismatched prefix lengths, or is
	// non-IPv6. Before this gate such a rule was only WARNED by the dataplane
	// compiler (compileNPTv6 logged + `continue`d) and then DeleteStaleNPTv6
	// tore down the working translation entries of the valid subset's
	// predecessors — a fail-OPEN that silently disabled a working translation on
	// a typo. The tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config carrying a bad NPTv6 rule still
	// BOOTS (#1960 no-brick) — the Rust helper's #2240 backstop
	// (Nptv6State::try_from_snapshots) rejects the snapshot at apply, so the
	// preflight keeps the previous live state and a leniently-loaded bad config
	// is inert. Commit stays strict so the operator's next edit fails loudly.
	// Same doctrine as lenientNATHostMask.
	lenientNPTv6 bool
	// lenientNAT64Prefix (#3886) downgrades the NAT64 `prefix` /96 commit gate
	// (validateNAT64PrefixStrict) from a hard compile error to a cfg.Warnings
	// entry. The strict commit / commit-check path hard-rejects a NAT64
	// rule-set prefix that is not an IPv6 `<address>/96` (a non-/96 length, a
	// missing/garbage mask, or a non-IPv6 address). Before this gate such a
	// prefix committed green, then the Rust Nat64State::try_from_snapshots
	// /96-integrity check aborted the WHOLE forwarding rebuild without
	// publishing — freezing the dataplane at the last-good snapshot so every
	// later commit silently stopped taking effect. The tolerant load / peer-sync
	// paths downgrade to a warning so an already-persisted or peer-synced config
	// carrying a bad NAT64 prefix still BOOTS (#1960 no-brick) — the helper's own
	// try_from_snapshots backstop keeps the previous live state, so a
	// leniently-loaded bad prefix is inert. Commit stays strict so the operator's
	// next edit fails loudly. Same doctrine as lenientNPTv6.
	lenientNAT64Prefix bool
	// lenientNATPoolOverlap (#5144) downgrades the source-NAT / NAT64
	// external-tuple overlap gate (validateNATPoolExternalTupleOverlapStrict)
	// from a hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a config in which two independent source-NAT
	// / NAT64 allocators (differently-named overlapping source pools, a source
	// pool that also backs a NAT64 rule-set, two NAT64 rule-sets sharing a pool
	// under different prefixes, or duplicate members within one pool) can mint the
	// same translated external tuple. The tolerant load / peer-sync paths downgrade
	// to a warning so an already-persisted or peer-synced config committed before
	// this gate existed still BOOTS (#1960 no-brick). Unlike lenientNPTv6 /
	// lenientNAT64Prefix the dataplane does NOT reject the overlapping snapshot —
	// the config installs with a LATENT reverse-index collision that persists until
	// corrected — so the warning carries that caveat. Commit stays strict so the
	// operator's next edit fails loudly. Same doctrine as lenientNPTv6.
	lenientNATPoolOverlap bool
	// lenientFirewallRefs (#2217) downgrades the firewall-filter term
	// cross-reference gates — `then policer <name>` (Finding A,
	// validateFirewallPolicerReferencesStrict) and `then routing-instance
	// <name>` FBF (Finding C, validateFirewallRoutingInstanceReferencesStrict)
	// — from a hard compile error to a cfg.Warnings entry. Both references were
	// previously unvalidated: a dangling policer silently never rate-limited
	// (fail-open) and a dangling FBF routing-instance silently blackholed /
	// fell through to the default table. The strict commit / commit-check path
	// hard-rejects so the typo is operator-visible; the tolerant load /
	// peer-sync paths warn so an already-persisted or peer-synced config still
	// BOOTS (#1960 fail-closed-on-load class) — the dataplane behaves as it did
	// before (term unpoliced / steered to a missing table), so a leniently-
	// loaded config is no worse than before the gate. Same doctrine as
	// lenientRoutingExportRef.
	lenientFirewallRefs bool
	// lenientFlowServerTemplateRef (#2461) downgrades the per-flow-server
	// NetFlow v9 / IPFIX template cross-reference gate
	// (validateFlowServerTemplateReferencesStrict) from a hard compile
	// error to a cfg.Warnings entry. A flow-server `version9 { template
	// <name> }` / `version-ipfix { template <name> }` (or the flat
	// `version9-template` / `version-ipfix-template`) reference that names
	// no defined `services flow-monitoring` template was previously
	// unvalidated: the live exporter ignored the reference and silently
	// used the first map-iteration template, so a collector received a
	// template (timeouts / export-extensions) it never requested and the
	// choice flipped nondeterministically across restarts. The strict
	// commit / commit-check path hard-rejects so the typo is operator-
	// visible; the tolerant load / peer-sync paths warn so an already-
	// persisted or peer-synced config carrying a dangling reference still
	// BOOTS (#1960 fail-closed-on-load class) — the resolver drops a group
	// whose template is undefined, so a leniently-loaded config exports
	// nothing for that collector rather than the wrong template. Same
	// doctrine as lenientLogProfileStreamRef.
	lenientFlowServerTemplateRef bool
	// lenientSamplingInstanceConflicts (#2462) downgrades the
	// multi-sampling-instance conflict gate
	// (validateSamplingInstanceConflictsStrict) from a hard compile error to
	// a cfg.Warnings entry. Two `forwarding-options sampling instance` blocks
	// that each export the SAME (export-version, address-family) pair are
	// genuinely ambiguous — there is no per-interface sampling-instance
	// selector, so a flow of that family cannot be attributed to one instance
	// — and were previously silently flattened into one global policy (one
	// map-order-dependent rate, one merged collector set; flows from instance
	// A reaching instance B's collectors). The strict commit / commit-check
	// path hard-rejects so the operator sees it; the tolerant load / peer-sync
	// paths warn so an already-persisted or peer-synced config still BOOTS
	// (#1960) — the resolver still emits both instances' independent
	// ExportConfigs, so eligible flows duplicate to both instances rather than
	// bricking the load. Same doctrine as lenientFlowServerTemplateRef.
	lenientSamplingInstanceConflicts bool
	// lenientSamplingInputRate (#5244) downgrades the sampling instance
	// input-rate lower-bound gate (validateSamplingInputRateStrict) from a
	// hard compile error to a cfg.Warnings entry. A negative
	// `forwarding-options sampling instance <name> input rate` was previously
	// stored unchecked: the flow exporter's 1-in-N gate (`SamplingRate > 1`)
	// then silently ignored the configured ratio and exported every eligible
	// flow, and the retired eBPF cast would wrap it into a huge divisor. The
	// strict commit / commit-check path hard-rejects so the typo is operator-
	// visible; the tolerant load / peer-sync paths warn so an already-persisted
	// or peer-synced config authored by a pre-guard version still BOOTS (#1960)
	// — the userspace snapshot builder clamps `rate <= 0 -> 1`, so a leniently-
	// loaded negative rate runs safely as sample-all. Same doctrine as
	// lenientSamplingInstanceConflicts.
	lenientSamplingInputRate bool
	// lenientApplicationSetMembers (#2217 Finding B) downgrades the
	// application-set member cross-reference gate
	// (validateApplicationSetMembersStrict) from a hard compile error to a
	// cfg.Warnings entry. An application-set member referencing neither a
	// defined application (user / junos-* predefined) nor a defined nested
	// application-set was previously unvalidated: a policy matching such a set
	// silently failed to match the intended traffic (the unresolved member
	// never matches — an effective no-op term, fail-open). The strict commit /
	// commit-check path hard-rejects; the tolerant load / peer-sync paths warn
	// so an already-persisted or peer-synced config carrying a dangling member
	// still BOOTS (#1960) — the dataplane drops the unresolved member
	// independently, so it is already inert. Same doctrine as
	// lenientApplicationSpecs.
	lenientApplicationSetMembers bool
	// lenientPolicyMatchApplications (#3144) downgrades the policy
	// match-application definedness gate
	// (validatePolicyMatchApplicationsStrict) from a hard compile error to a
	// cfg.Warnings entry. A security-policy `match application <name>` token
	// resolving to no predefined junos-* application, no user-defined
	// application, and no application-set was previously only WARNED at commit
	// — yet the userspace capability gate resolves the same name set and
	// REFUSES to arm security policies for an unknown name, silently disarming
	// the firewall's allow/deny path (a commit/apply split, fail-open). The
	// strict commit / commit-check path hard-rejects so the typo is
	// operator-visible; the tolerant load / peer-sync paths warn so an
	// already-persisted or peer-synced config that an older binary accepted
	// still BOOTS (#1960) — the dataplane independently refuses such a policy,
	// so a leniently-loaded bad config is no worse off, now flagged. Same
	// doctrine as lenientApplicationSetMembers.
	lenientPolicyMatchApplications bool
	// lenientNATMatchApplications (#3434, Codex audit 095 H07/H08) downgrades
	// the source/destination-NAT match-application definedness gate
	// (validateNATMatchApplicationsStrict) from a hard compile error to a
	// cfg.Warnings entry. A NAT `match application <name>` token resolving to
	// no predefined junos-* application, no user-defined application, and no
	// non-empty application-set was previously unvalidated — yet the DNAT
	// snapshot builder then fell through to a wildcard match-all term
	// (protocol="" + destination-port 0) and published the pool VIP for EVERY
	// flow to the destination (a fail-open wildcard translation; the NAT
	// sibling of #3144/#3146). The strict commit / commit-check path
	// hard-rejects so the typo is operator-visible; the tolerant load /
	// peer-sync paths warn so an already-persisted or peer-synced config that
	// an older binary accepted still BOOTS (#1960) — the dataplane now
	// independently fails such a rule closed (never-match term), so a
	// leniently-loaded bad config is no worse off, now flagged. Same doctrine
	// as lenientPolicyMatchApplications.
	lenientNATMatchApplications bool
	// lenientPolicyMatchAddressSetMembers (#3149, folds #3147) downgrades the
	// policy match address-set member / empty-set gate
	// (validatePolicyMatchAddressSetMembersStrict) from a hard compile error to
	// a cfg.Warnings entry. A security-policy source/destination address naming
	// a DEFINED address-book entry whose (recursive) members dangle, or that is
	// a defined-but-EMPTY address-set / prefix-less address, was previously only
	// WARNED at commit — yet the runtime address resolver
	// (resolveUserspaceAddressBookEntry) returns false for the same name and the
	// userspace gate then REFUSES to arm security policies, silently disarming
	// the firewall's allow/deny path (a commit/apply split, fail-open; the
	// address-book sibling of #3144/#3146). The strict commit / commit-check
	// path hard-rejects so the gap is operator-visible; the tolerant load /
	// peer-sync paths warn so an already-persisted or peer-synced config that an
	// older binary accepted still BOOTS (#1960) — the dataplane independently
	// refuses such a policy, so a leniently-loaded bad config is no worse off,
	// now flagged. Same doctrine as lenientPolicyMatchApplications.
	lenientPolicyMatchAddressSetMembers bool
	// lenientRibGroupRefs (#2226) downgrades the rib-group import-rib
	// cross-reference gate (validateRibGroupImportRibReferencesStrict) from a
	// hard compile error to a cfg.Warnings entry. An `import-rib` naming a rib
	// that resolves to no real routing table (a typo, a non-existent instance,
	// or unparseable garbage) was previously unvalidated: the applier mapped
	// the unresolvable name to a bare table 0, which differs from any
	// instance's (>= 100) source table, so it spuriously installed an `ip rule
	// from all lookup <sourceTable>` — a silent mis-leak of the source table
	// into the main lookup. The strict commit / commit-check path hard-rejects
	// so the typo is operator-visible; the tolerant load / peer-sync paths warn
	// so an already-persisted or peer-synced config carrying a dangling
	// import-rib still BOOTS (#1960) — the applier's resolveRibTable ok=false
	// guard skips the phantom rib and installs no rule, so a leniently-loaded
	// config is already inert. Same doctrine as lenientRoutingExportRef.
	lenientRibGroupRefs bool
	// lenientNextTableRefs (#5693) downgrades the next-table target
	// definedness gate (validateNextTableTargetReferencesStrict) from a hard
	// compile error to a cfg.Warnings entry. A static route whose
	// `next-table <target>` names an undefined routing-instance was previously
	// unvalidated: the applier resolved the target through a name→table-id map
	// built only from defined instances, missed, warned, and skipped the rule,
	// so the inter-VRF leak silently never happened. The strict commit /
	// commit-check path hard-rejects so the typo is operator-visible; the
	// tolerant load / peer-sync paths warn so an already-persisted or peer-
	// synced config carrying a dangling next-table still BOOTS (#1960) — the
	// applier's tableIDs !ok guard keeps it inert. Same doctrine as
	// lenientRibGroupRefs.
	lenientNextTableRefs bool
	// lenientRoutingRuleWindows (#5854) downgrades the next-table / rib-group
	// ip-rule window over-subscription gate (validateRoutingRuleWindowsStrict)
	// from a hard compile error to a cfg.Warnings entry. The runtime applier
	// programs next-table and interface-routes rib-group leaks into FIXED
	// priority windows (pkg/routing/rules.go: 100 next-table rules, 1000
	// rib-group leak rules) and HARD-CAPS at each boundary, silently skipping any
	// rule past it, so a config that exceeds a window commits green while the
	// reconciler stops at the limit and returns success — the committed
	// generation claims routes the kernel never programs (blackhole / asymmetric
	// routing). The strict commit / commit-check path hard-rejects so the
	// over-subscription is operator-visible; the tolerant load / peer-sync paths
	// warn so an already-committed or peer-synced over-limit config still BOOTS
	// (#1960) — the applier's window hard-cap keeps the excess inert. Same
	// doctrine as lenientNextTableRefs.
	lenientRoutingRuleWindows bool
	// lenientPolicyRouteMapSeq (#5701) downgrades the route-map
	// sequence-number overflow gate (validatePolicyRouteMapSequenceBoundStrict)
	// from a hard compile error to a cfg.Warnings entry. A policy-statement
	// whose per-term Cartesian expansion exceeds the FRR route-map
	// sequence-number ceiling (1..65535, step 10) renders a `route-map` line
	// past seq 65535 that FRR rejects, poisoning the whole vtysh-batched
	// frr-reload. The strict commit / commit-check path hard-rejects so the
	// oversized policy is operator-visible; the tolerant load / peer-sync paths
	// warn so an already-persisted or peer-synced config still BOOTS (#1960) —
	// the renderer's generatePolicyOptions SKIPS an over-ceiling policy, so a
	// leniently-loaded config renders nothing for it rather than poisoning the
	// reload. Same doctrine as lenientNextTableRefs.
	lenientPolicyRouteMapSeq bool
	// lenientRouteDispositionConflict (#5633) downgrades the static-route
	// disposition-conflict gate (validateStaticRouteDispositionConflictStrict)
	// from a hard compile error to a cfg.Warnings entry. Repeated same-prefix
	// static-route `set` lines merge into a single StaticRoute
	// (compileStaticRoutes) with appended next-hops and sticky terminal /
	// next-table fields, so declaring one prefix as `discard` (or `next-table X`)
	// AND with a `next-hop` compiled into one route holding both a blackhole /
	// leak and a forwarding next-hop. The strict commit / commit-check path
	// hard-rejects so the contradiction is operator-visible; the tolerant load /
	// peer-sync paths warn so an already-persisted or peer-synced config still
	// BOOTS (#1960) — the dataplane resolves the deterministic disposition
	// precedence (discard > next-table > next-hop). Same doctrine as
	// lenientNextTableRefs.
	lenientRouteDispositionConflict bool
	// lenientDHCPStaticBindings (#2243 review) downgrades the DHCP-server
	// static (fixed/reserved) host-binding gate (validateDHCPStaticBindingsStrict)
	// from a hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a binding whose fixed-address is malformed,
	// family-mismatched, outside the enclosing pool subnet, or duplicates another
	// binding's MAC/address in the same pool. The tolerant load / peer-sync paths
	// downgrade to a warning so an already-persisted or peer-synced config
	// carrying a bad binding still BOOTS (#1960 no-brick) — without the gate the
	// whole config-load HARD-REJECTED, unlike every sibling validator. The Kea
	// renderer skips an empty/unparseable binding independently (and canonicalizes
	// the MAC), so a leniently-loaded bad binding is inert. Same doctrine as
	// lenientPolicyMatchAddress.
	lenientDHCPStaticBindings bool
	// lenientWireguardPeers (#1434 multi-peer) downgrades the WireGuard
	// per-peer gate (validateWireguardPeersStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects a WG tunnel with zero peers, a duplicate peer
	// pubkey, a malformed (non-64-hex) pubkey/PSK, or endpoint-bearing
	// peers that disagree on outer transport family (one UDP socket = one
	// outer family). The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config still BOOTS
	// (#1960 no-brick) — the Rust hydrate path independently drops a WG
	// row with a malformed key (hydrate_wg_identity) and the engine
	// reconcile is dup-pubkey-safe, so a leniently-loaded bad config is
	// inert. Same doctrine as lenientNATHostMask.
	lenientWireguardPeers bool
	// lenientTunnelOuterFamily (#5162) downgrades the non-WireGuard tunnel
	// outer-family cross-field gate (validateTunnelOuterFamilyStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a GRE/IPIP tunnel whose outer source
	// and destination are different address families (a mixed pair commits
	// clean but the dataplane silently drops every encapsulated packet). The
	// tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config still BOOTS (#1960 no-brick) —
	// the Rust populate_tunnel_endpoints independently skips a mixed-family
	// non-WG row (fail-closed with a loud eprintln), so a leniently-loaded
	// bad tunnel is inert. Same doctrine as lenientWireguardPeers.
	lenientTunnelOuterFamily bool

	// lenientIpipTunnelMode (#4785 half 1) downgrades the IPIP-unimplemented
	// gate (validateIpipTunnelUnimplementedStrict) from a hard compile error to
	// a cfg.Warnings entry. IPIP has no userspace decap stage and no egress
	// encap arm — the endpoint is never entered into gre_decap_index and the
	// egress dispatcher's TunnelKind::Unknown arm drops — so a `mode ipip`
	// tunnel is created and passes NO traffic in either direction. The strict
	// commit / commit-check path hard-rejects so an unimplemented feature fails
	// loudly instead of succeeding into a blackhole; the tolerant load /
	// peer-sync paths warn so a config an OLDER binary accepted (it was only an
	// advisory before this gate) still BOOTS (#1960) — the runtime's own
	// fail-closed arms keep the tunnel inert either way. Same doctrine as
	// lenientTunnelOuterFamily.
	//
	// #6861 F3 — "load / peer-sync" is NOT the whole set of readers, and the
	// omission is a trap for whoever tightens this next. The peer-effective
	// commit gate (ValidatePeerEffectiveStrict, compiler_peer_effective.go)
	// also compiles LENIENTLY, from a STRICT commit path, on purpose: it must
	// MODEL the standby's tolerant SyncApply ingest before applying its own
	// strict subjects to the resulting *Config. That makes this leniency
	// load-bearing in the opposite direction from how the paragraph above
	// reads. Set it false and CompileConfigForNodeLenient starts returning an
	// error for exactly the configs the peer gate exists to catch;
	// ValidatePeerEffectiveStrict's `err != nil -> return nil` arm swallows it,
	// and the gate silently stops rejecting peer-only dead tunnels. Any
	// tightening here must be reviewed against that call site, not only
	// against Store.Load and Store.SyncApply.
	lenientIpipTunnelMode bool
	// lenientPolicyZoneRefs (#2401) downgrades the security-policy
	// zone-pair reference gate (validatePolicyZoneReferencesStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a `from-zone`/`to-zone` policy stanza
	// that names a security zone the config never defines. ValidateConfig
	// only WARNED on this, so the commit succeeded with an unenforceable
	// rule. The tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config carrying a stale zone reference
	// still BOOTS the daemon (#1960 no-brick: the management plane stays
	// alive so the operator can fix it). The dataplane is independently
	// hardened to fail CLOSED on such a snapshot: since #3402 the Rust
	// integrity preflight rejects the WHOLE snapshot
	// (SnapshotIntegrityError::UnresolvableZoneReference) rather than dropping
	// the unindexed rule and letting its zone pair fall through to the default
	// action (a silent fail-OPEN under permit-all, a blackhole under
	// deny-all). The previous good dataplane state is retained (a fresh boot
	// keeps the default-deny PolicyState), so a leniently-loaded bad config
	// cannot silently un-enforce a configured rule. Same doctrine as
	// lenientPolicyMatchAddress.
	lenientPolicyZoneRefs bool
	// lenientZoneCount (#2391, cap SUPERSEDED by #3075) downgrades the security-
	// zone count cap gate (validateZoneCountStrict) from a hard compile error to
	// a cfg.Warnings entry. After #3075 the cap is a pigeonhole belt: a config
	// cannot define more than MaxUsableZoneID (65533) distinct zones in the u16
	// stable-name-hash space. The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config an older binary
	// accepted still BOOTS (#1960 no-brick). Same doctrine as lenientPolicyZoneRefs.
	lenientZoneCount bool
	// lenientWebManagementAuth (#4047, fable-161 F-155) downgrades the
	// web-management REST-auth gate (validateWebManagementAuthStrict) from a hard
	// compile error to a cfg.Warnings entry. The REST/config API is unauthenticated
	// unless `system services web-management api-auth` is configured; binding it to
	// a non-loopback address (`web-management http|https interface <mgmt-if>`)
	// without api-auth exposes the mutating config endpoints (set / commit /
	// rollback / system action) to the network. The strict commit / commit-check
	// path hard-rejects such a config; the tolerant load / peer-sync paths downgrade
	// to a warning so an already-persisted or peer-synced config an older binary
	// accepted still BOOTS (#1960 no-brick). The daemon's runtime bind path
	// independently clamps a non-loopback + no-auth bind back to loopback (part B,
	// daemon_run.go), so a leniently-loaded vulnerable config is not left exposed.
	// Same doctrine as lenientZoneCount.
	lenientWebManagementAuth bool
	// lenientZoneIDCollision (#3075) downgrades the stable-zone-id collision
	// gate (validateZoneIDCollisionAST) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// config whose two zone names fold to the same StableZoneID — the later-
	// sorting zone would otherwise be dropped by the dataplane and its
	// interfaces fall back to the wrong / unknown zone. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or peer-
	// synced config still BOOTS (#1960 no-brick) — the dataplane independently
	// fails closed on the unresolvable later-folding zone, so a leniently-loaded
	// colliding config is inert on that zone rather than mis-attributed. Same
	// doctrine as lenientZoneCount; mirrors the #1873 tunnel-id gate's
	// strict/lenient split.
	lenientZoneIDCollision bool
	// lenientRoutingInstanceTableIDCollision (#3855) downgrades the stable
	// routing-instance table-id collision gate
	// (validateRoutingInstanceTableIDCollisionAST) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// config whose two routing-instance names fold to the same kernel table (two
	// VRFs on one table = a cross-VRF route leak). The tolerant load / peer-sync
	// paths downgrade to a warning so an already-persisted or peer-synced config
	// still BOOTS (#1960 no-brick); compileRoutingInstances then QUARANTINES the
	// later-sorting instance so the two never actually share a table. Same
	// doctrine as lenientZoneIDCollision; mirrors the #3075 / #1873 id gates.
	lenientRoutingInstanceTableIDCollision bool
	// lenientAddressBookNames (#3061, narrowed in #4340) downgrades the
	// address-book / zone name gate (validateAddressBookEntryNamesStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects only an address-book entry name that begins
	// with the reserved `zone-local/` prefix (global or zone-local address /
	// address-set) or a security-zone name that contains `/` — the two invariants
	// that keep the synthetic `zone-local/<zone>/<name>` internal name
	// (resolveZoneLocalAddressBooks) collision-proof. A `/` elsewhere in an entry
	// name (net_10.0.0.0/8, the #4340 prefix-in-name convention) is accepted. The
	// tolerant load / peer-sync paths downgrade the reject to a warning so an
	// already-persisted config an older binary accepted still BOOTS (#1960
	// no-brick); the fold's no-clobber guard keeps such a config from silently
	// overwriting an operator entry. Same doctrine as lenientZoneCount.
	lenientAddressBookNames bool
	// lenientAddressBookNameCollision (#5676) downgrades the same-name
	// `address` + `address-set` collision gate
	// (validateAddressBookNameCollisionStrict) from a hard compile error to a
	// cfg.Warnings entry. An address book (global or zone-local) that defines
	// the SAME name as BOTH a plain `address` and an `address-set` was
	// previously unvalidated — the two kinds share one operator-visible
	// namespace but are stored in separate maps, so every name→prefix resolver
	// (dataplane expandBookNameRecursive, host-inbound junos_host_deny) silently
	// resolved address-first and the plain address SHADOWED the same-named
	// address-set, dropping the set's other members and changing which traffic a
	// permit/deny rule covers. The strict commit / commit-check path
	// hard-rejects so the ambiguity is operator-visible (Junos forbids the
	// collision outright); the tolerant load / peer-sync paths warn so an
	// already-persisted or peer-synced config carrying a pre-existing collision
	// still BOOTS (#1960) — the runtime keeps the deterministic address-first
	// winner it already used, so a leniently-loaded config forwards exactly as
	// before, now flagged. Same doctrine as lenientAddressBookNames.
	lenientAddressBookNameCollision bool
	// lenientZoneInterfaceMembership (#3072) downgrades the zone-interface
	// membership gate (validateZoneInterfaceMembershipStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects a config that assigns the same interface to more than
	// one security zone — pkg/dataplane/userspace.buildInterfaceZoneMap resolves
	// such a duplicate first-writer-wins over the SORTED zone names, so the
	// interface silently lands in whichever zone sorts first and traffic is
	// evaluated against the wrong zone's policy. The tolerant load / peer-sync
	// paths downgrade to a warning so an already-persisted or peer-synced config
	// an older binary accepted still BOOTS (#1960 no-brick) — buildInterfaceZoneMap
	// keeps its deterministic first-writer-wins resolution, so the leniently-
	// loaded config forwards exactly as before, just with an operator-visible
	// warning. Same doctrine as lenientPolicyZoneRefs.
	lenientZoneInterfaceMembership bool
	// lenientZoneInterfaceDefined (ps-review-002 F6, #4515) downgrades the
	// zone-interface DEFINED gate (validateZoneInterfaceDefinedStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a `security zones security-zone <z>
	// interfaces <if>` entry that names an interface which is neither configured
	// under `interfaces` nor a daemon-materialized dynamic interface (lo0 / an
	// IPsec secure-tunnel bind-interface) — Junos rejects such a zone member,
	// whereas xpf previously only warned then compiled it (the runtime brings the
	// absent interface DOWN, so it is fail-closed but silent). The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary accepted still BOOTS (#1960 no-brick);
	// on that path behavior is unchanged (the unresolved member carries no
	// traffic), just with an operator-visible warning. The reference set is the
	// GENEROUS zoneReferenceableInterfaceBases union (lo0 + IPsec secure-tunnel
	// bases + every configured interface) so the promotion cannot false-reject a
	// legitimate dynamic-interface reference (the #4191 over-rejection class).
	// Same doctrine as lenientZoneInterfaceMembership.
	lenientZoneInterfaceDefined bool
	// lenientZoneInterfacesNonEmpty (#6525) downgrades the zone-interfaces
	// NON-EMPTY gate (validateZoneInterfacesNonEmptyStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `security zones security-zone <z> interfaces` stanza that
	// carries content yet contributes ZERO members — the shape the hierarchical
	// compact-leaf spelling `interfaces ge-0/0/1.0;` used to produce, where the
	// member name sat on the stanza's own Keys tail that compileZones never
	// read. Such a zone binds no interface: the dataplane leaves the interface
	// with Zone == "" (UserspaceBoundLinuxInterfaces skips it, so it is never
	// AF_XDP-bound) and every policy naming the zone applies to nothing, while
	// the two gates above pass VACUOUSLY over the empty member set. The tolerant
	// load / peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary accepted still BOOTS (#1960 no-brick) —
	// on that path behavior is unchanged (the stanza contributed no members
	// before this gate existed and still contributes none), just with an
	// operator-visible warning. Same doctrine as lenientZoneInterfaceDefined.
	lenientZoneInterfacesNonEmpty bool
	// lenientZoneInterfacePackedTail (#6735) downgrades the zone-interfaces
	// PACKED-TAIL gate (validateZoneInterfacePackedTailStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects a `security zones security-zone <z> interfaces` stanza
	// in which `host-inbound-traffic` appears on a member's Keys with further
	// tokens AFTER it. The lexer strips brackets (#2419), so the bracket member
	// list `[ a host-inbound-traffic b ]` and the packed body
	// `a host-inbound-traffic system-services ssh` are structurally identical by
	// the time the compiler sees them, and their readings disagree about zone
	// membership: the truncator keeps only the names BEFORE the keyword, so the
	// first loses member `b` (left with Zone == "", never dataplane-bound, no
	// policy naming the zone applies to it) and the second loses the whole
	// override. The tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config an older binary accepted still
	// BOOTS (#1960 no-brick) — on that path behavior is unchanged (the trailing
	// tokens were dropped before this gate existed and still are), just with an
	// operator-visible warning naming what was lost. Same doctrine as
	// lenientZoneInterfacesNonEmpty.
	lenientZoneInterfacePackedTail bool
	// lenientHostInboundTokens (#3200) downgrades the host-inbound-traffic
	// token gate (validateHostInboundTokensStrict) from a hard compile error
	// to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `host-inbound-traffic system-services`/`protocols` token
	// that is not in the recognized SSOT (host_inbound_tokens.go) — such a
	// typo committed cleanly and then enforced inconsistently across the
	// nftables kernel mirror (fail OPEN for an all-unknown stanza) and the
	// Rust AF_XDP classifier (fail CLOSED), a split-brain posture. The
	// tolerant load / peer-sync paths downgrade to a warning so an already-
	// persisted or peer-synced config carrying a stale token still BOOTS
	// (#1960 no-brick) — both enforcement layers independently ignore the
	// unknown token (Rust ignores it; nft now emits a catch-all drop for the
	// zone so it too fails CLOSED), so a leniently-loaded bad config is inert
	// and consistent. Same doctrine as lenientPolicyZoneRefs.
	lenientHostInboundTokens bool
	// lenientDuplicateHostLocalAddress (#3718 Option B) downgrades the
	// duplicate host-local-address gate (validateDuplicateHostLocalAddressStrict)
	// from a hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a firewall-local address (interface address
	// or VRRP VIP) that is host-inbound-reachable from more than one security
	// zone with DIFFERING host-inbound service/protocol sets — the kernel
	// host-inbound nftables chain matches destination address only (no ingress
	// predicate), so the admission verdict for such an address is decided
	// order-dependently by whichever zone sorts first, and can disagree with the
	// ingress-scoped userspace-dp path (split-brain). The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary accepted still BOOTS (#1960 no-brick);
	// on that path the ambiguity is NOT self-healing, so the runtime reporter
	// (dataplane/userspace.AmbiguousHostInboundAddresses) and the
	// xpf_host_inbound_ambiguous_addresses metric are the operator's signal. Same
	// doctrine as lenientZoneInterfaceMembership.
	lenientDuplicateHostLocalAddress bool
	// lenientClusterAuthKey (#6611) downgrades the cluster control-channel
	// authentication gate (validateClusterAuthKeyStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `chassis cluster` with no `authentication-key`: the
	// fabric gRPC listener (#4357), the heartbeat (#4326) and the session-sync
	// channel (#4369) all authenticate with that one PSK and all three
	// deliberately fail OPEN when it is absent, so an unkeyed cluster runs its
	// entire control channel unauthenticated. The tolerant load / peer-sync
	// paths downgrade to a warning so a cluster that was already unkeyed
	// before this gate existed still BOOTS after the upgrade (#1960 no-brick)
	// — that is the migration path. NOTE the grace is no longer uniform: #5078
	// removed dual-accept from SESSION SYNC, so a keyed node now rejects an
	// unkeyed peer's connection outright. The heartbeat and fabric gRPC
	// channels still dual-accept, so the cluster does not drop, but keying one
	// node at a time takes SESSION SYNC DOWN until both nodes are keyed and
	// both have restarted (a connection only picks the key up on a new
	// handshake). See pkg/cluster/README.md -> "Rolling it onto a live unkeyed
	// cluster", which marks the old one-node-at-a-time sequence STALE (#6881).
	// Same doctrine as lenientChassisRG.
	lenientClusterAuthKey bool
	// lenientDestNATAddresses (#2396) downgrades the destination-NAT
	// destination-address gate (validateDestinationNATAddressesStrict) from a
	// hard compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a DNAT rule whose `match
	// destination-address` resolves to NO parseable host IP at all — every
	// configured destination is malformed/empty. The Go snapshot builder skips
	// each unparseable destination (#2395) and the Rust DNAT table `continue`s
	// on a destination it cannot parse, so such a rule emits NO table entry and
	// silently translates NOTHING — an operator who fat-fingered the only
	// destination gets a committed-but-inert rule with no feedback (the #2396
	// (c) silent-drop). Hard-rejecting it at commit makes the mistake visible.
	// The tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config carrying a bad destination still
	// BOOTS (#1960 no-brick) — the dataplane drops the rule independently, so a
	// leniently-loaded bad config is inert. Same doctrine as
	// lenientPolicyZoneRefs / lenientNATHostMask.
	lenientDestNATAddresses bool
	// lenientNATMatchAddressLiterals (#7145) downgrades the NAT match-address
	// literal gate (validateNATMatchAddressLiteralsStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a source / destination / static NAT rule whose literal
	// `match source-address` (any kind) or `match destination-address` (source
	// kind) carries a value the dataplane cannot parse. Before #7145 those four
	// (kind x leaf) slots had NO parse gate at all, while the sibling slot in
	// the SAME rule — destination-NAT and static-NAT `match
	// destination-address` — rejected the identical value (#3228 / #3206): one
	// operator typo, opposite verdicts depending on which slot it landed in.
	// The values reach the wire verbatim and each Rust consumer drops what it
	// cannot parse while keeping the rule CONSTRAINED, so a malformed entry
	// narrows the rule and an all-malformed list makes it match NOTHING —
	// visible only as a bounded NAT parse-error counter. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config carrying a malformed prefix still BOOTS (#1960
	// no-brick), and the value is deliberately KEPT in the compiled config on
	// that path: dropping it Go-side would empty an all-malformed list, clear
	// the Rust `*_constrained` flag and collapse the rule to MATCH-ANY, turning
	// a fail-closed break into a fail-open one. Same doctrine as
	// lenientDestNATAddresses.
	lenientNATMatchAddressLiterals bool
	// lenientRPMSourceAddress (#2492) downgrades the RPM test
	// source-address gate (validateRPMSourceAddressStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects an RPM test whose `source-address`
	// is non-empty but unparseable, or whose source address-family does
	// not match an IP-literal target. A malformed source silently turns
	// the tcp-ping/http-get probe dialer into a wildcard/kernel-chosen
	// source bind (net.ParseIP -> nil -> TCPAddr{IP:nil}), so the probe
	// measures the DEFAULT uplink instead of the pinned source path and
	// publishes PASS/FAIL for the wrong path — and RPM feeds
	// event-options / ip-monitoring failover. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config carrying a bad source still BOOTS (#1960
	// no-brick); the runtime probeDialer guard returns ErrProbeSetup for
	// the same malformed source, so the leniently-loaded test HOLDS
	// state rather than actuating routes off a wildcard measurement.
	// Same doctrine as lenientDestNATAddresses / lenientNATHostMask.
	lenientRPMSourceAddress bool
	// lenientRPMLinkLocalZone (#2494) downgrades the bare-link-local RPM
	// target gate (validateRPMLinkLocalZoneStrict) from a hard compile
	// error to a cfg.Warnings entry. An IPv6 link-local target with no
	// `%zone` and no destination-interface has no egress-link scope, so
	// the kernel cannot pick the link and the probe is dead. Strict on
	// commit / commit-check (hard reject so the gap is operator-visible);
	// lenient on load / peer-sync (warn — #1960 no-brick; the runtime
	// probeICMP guard returns ErrProbeSetup for the same scopeless
	// link-local, so the leniently-loaded test HOLDS state rather than
	// actuating off a dead measurement). Same doctrine as
	// lenientRPMSourceAddress.
	lenientRPMLinkLocalZone bool
	// lenientRPMHTTPGetScheme (#2495) downgrades the http-get target
	// scheme gate (validateRPMHTTPGetSchemeStrict) from a hard compile
	// error to a cfg.Warnings entry. An http-get target that carries a
	// scheme other than http/https (ftp://, gopher://, …) makes
	// http.NewRequestWithContext error before a packet is sent, so the
	// probe never runs and publishes a permanent FAIL into event-options
	// / ip-monitoring failover. Strict on commit / commit-check (hard
	// reject so the bad scheme is operator-visible); lenient on load /
	// peer-sync (warn — #1960 no-brick; the runtime canonicalizeHTTPTarget
	// guard returns the same error for the bad scheme, so the
	// leniently-loaded test HOLDS state rather than actuating off a probe
	// that can never run). Same doctrine as lenientRPMLinkLocalZone.
	lenientRPMHTTPGetScheme bool
	// lenientRPMRoutingInstance (#2496) downgrades the RPM test
	// routing-instance cross-reference gate
	// (validateRPMRoutingInstanceStrict) from a hard compile error to a
	// cfg.Warnings entry. An RPM test whose `routing-instance` names a
	// nonexistent instance makes the runtime bind the probe DATA socket to
	// a synthesized vrf-<name> device (SO_BINDTODEVICE) that does not exist
	// → ENODEV → the probe never sends a packet and the test HOLDS its
	// state forever (no PASS, no FAIL), starving any event-options /
	// ip-monitoring policy keyed off it of a failover signal. Strict on
	// commit / commit-check (hard reject so the typo is operator-visible);
	// lenient on load / peer-sync (warn — #1960 no-brick; the runtime bind
	// returns ENODEV for the same nonexistent instance, so the leniently-
	// loaded test HOLDS state rather than actuating off a dead measurement).
	// Same doctrine as lenientRPMHTTPGetScheme.
	lenientRPMRoutingInstance bool
	// lenientBGPNeighborPeerAS (#2963) downgrades the BGP neighbor peer-as
	// gate (validateBGPNeighborPeerASStrict) from a hard compile error to a
	// cfg.Warnings entry. A BGP neighbor whose effective peer-as (remote-as)
	// is missing/0 (or out of [1, 4294967295]) was previously unvalidated:
	// peer-as is optional in the parser/compiler, so a neighbor authored
	// without one keeps the zero value and the FRR renderer (policy_render.go)
	// emitted `neighbor <addr> remote-as 0`. AS 0 is reserved (RFC 7607) and
	// FRR/vtysh rejects it, failing the whole frr-reload (a single vtysh -f
	// add-batch exits non-zero on any CMD_WARNING_CONFIG_FAILED) and leaving
	// dynamic routing in a broken/stale state — a commit-accepted config the
	// routing daemon cannot load. The strict commit / commit-check path
	// hard-rejects so the missing peer-as is operator-visible, naming the
	// neighbor; the tolerant load / peer-sync paths warn so an
	// already-persisted or peer-synced config carrying such a neighbor still
	// BOOTS (#1960 fail-closed-on-load class) — the render path now skips a
	// remote-as-0 neighbor (defense-in-depth), so AS 0 never reaches frr.conf
	// and a leniently-loaded bad neighbor is inert. Same doctrine as
	// lenientRoutingExportRef.
	lenientBGPNeighborPeerAS bool
	// lenientRouterID (#2980) downgrades the OSPF/OSPFv3/BGP router-id gate
	// (validateRouterIDStrict) from a hard compile error to a cfg.Warnings
	// entry. router-id is parsed as a raw string with no validation, so a
	// malformed value (not a 32-bit IPv4 dotted-quad — e.g. garbage, an
	// out-of-range octet, or an IPv6 address) flowed verbatim into frr.conf.
	// FRR/vtysh requires an IPv4 router-id for ALL routing protocols
	// (including the IPv6 protocols OSPFv3 and BGP) and rejects anything else,
	// failing the whole frr-reload (a single vtysh -f add-batch exits non-zero
	// on any CMD_WARNING_CONFIG_FAILED) and leaving dynamic routing
	// broken/stale — a commit-accepted config the routing daemon cannot load.
	// The strict commit / commit-check path hard-rejects so the bad value is
	// operator-visible, naming the scope and protocol; the tolerant load /
	// peer-sync paths warn so an already-persisted or peer-synced config
	// carrying such a router-id still BOOTS (#1960 fail-closed-on-load class)
	// — the render path now skips an invalid router-id (defense-in-depth), so
	// the malformed value never reaches frr.conf and a leniently-loaded bad
	// router-id is inert. Same doctrine as lenientBGPNeighborPeerAS.
	lenientRouterID bool
	// lenientSNMPTrapGroup (#2990) downgrades the SNMP trap-group commit gate
	// (unknown trap-group child key, e.g. a `tragets` typo, and an
	// enabled-but-zero-target trap group) from a hard compile error to a
	// cfg.Warnings entry. Before #2990 the trap-group schema had children:nil
	// and the compiler silently dropped every child but `targets`, so a typo'd
	// or zero-target trap group COMMITTED CLEANLY and persists in active.json.
	// The #2990 strict gate rejects such a group at commit (operator-visible,
	// naming the offending key) — but on the tolerant load / peer-sync path it
	// MUST warn, not error, or an already-persisted bad trap group would fail
	// CompileConfigLenient and blackout the boot / alarm-loop HA sync (the
	// exact #1960 fail-closed-on-load class compileTreeLenient exists to
	// prevent). Runtime is already inert for both cases — sendLinkTraps skips a
	// zero-target group and never reads an unknown key — so a leniently-loaded
	// bad group is harmless. Same doctrine as lenientRouterID.
	lenientSNMPTrapGroup bool
	// lenientDDNSDuration (#4837) downgrades the `system services
	// dynamic-dns` `forced-refresh` / `error-backoff-max` unparseable-value
	// gate from a hard compile error to a cfg.Warnings entry. Both leaves
	// accept a Go duration string ("24h") or a bare-seconds integer
	// ("86400"); before #4837 a value that parsed as NEITHER (a typo like
	// "24hh", or a negative/garbage value) was silently discarded —
	// compileDDNSServices left the field unset (falling back to its
	// downstream default) with no commit-time signal, so the operator
	// believed their tuning applied when it silently did not. The strict
	// commit / commit-check path hard-rejects, naming the offending value;
	// the tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted config an older binary accepted still BOOTS (#1960
	// fail-closed-on-load class) — the field stays unset either way (the
	// pre-#4837 runtime behavior is unchanged on the lenient path), only the
	// warning is new. Same doctrine as lenientSNMPTrapGroup.
	lenientDDNSDuration bool
	// lenientPolicyTerminalAction (#3043) downgrades the security-policy
	// terminal-action gate (validatePolicyTerminalActionStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a policy that does not name EXACTLY one
	// terminal action: a log-only / count-only or typo'd policy compiled with
	// Action == PolicyPermit (the zero value) and silently PERMITTED all
	// matching traffic — a fail-OPEN security hole — while a policy naming
	// more than one terminal action resolved last-wins by parse order. The
	// tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config that an older binary accepted
	// still BOOTS (#1960 no-brick); the runtime is independently safe because
	// compilePolicy defaults an actionless policy's Action to PolicyDeny (NOT
	// permit), so a leniently-loaded actionless policy DENIES rather than
	// fails open. Same doctrine as lenientPolicyZoneRefs / lenientPolicyMatchAddress.
	lenientPolicyTerminalAction bool
	// lenientPolicyLogAction (#3060) downgrades the security-policy `then log`
	// gate (validatePolicyLogActionStrict) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects a
	// policy whose `then log` names neither session-init nor session-close: a
	// bare `then log` compiles to pol.Log = &PolicyLog{} with both flags false,
	// so the policy REPORTS logging enabled over REST/gRPC/CLI yet emits NO
	// session records — audit looks active while producing nothing (a silent
	// gap on a security appliance). Junos requires at least one of
	// session-init/session-close. The tolerant load / peer-sync paths downgrade
	// to a warning so an already-persisted or peer-synced config an older binary
	// accepted still BOOTS (#1960 no-brick); a leniently-loaded bare-log policy
	// is harmless (it logs nothing, the pre-existing behavior). Same doctrine as
	// lenientPolicyTerminalAction.
	lenientPolicyLogAction bool
	// lenientDuplicatePolicyNames (#3473) downgrades the duplicate-policy-name
	// gate (validateDuplicatePolicyNamesStrict) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects two
	// security policies that share a name within the same from/to-zone zone-pair
	// (or within the global rulebase), matching Junos. xpf accepted duplicates
	// silently and, because the userspace hit counter is name-keyed
	// (RuleID = "<from>-><to>/<name>"), the duplicates COALESCE onto one counter:
	// `show security policies hit-count` cannot tell them apart, deleting one
	// duplicate hands its accumulated hits to the survivor, and the Go-side
	// buildPolicyRuleCounterIndex is last-write-wins on the RuleID. The tolerant
	// load / peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary accepted still BOOTS (#1960 no-brick);
	// first-match enforcement is still correct on that path (only the shared-
	// counter observability bug remains). Same doctrine as lenientPolicyLogAction.
	lenientDuplicatePolicyNames bool
	// lenientScreenProfileRefs (#3066) downgrades the zone screen-profile
	// reference gate (validateScreenProfileReferencesStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit / commit-check
	// path hard-rejects a security zone whose `screen <name>` references a
	// screen-ids-option profile the config never defines. Before this gate the
	// reference was warned only, so the commit succeeded; at runtime the
	// userspace dataplane fails OPEN (screen/mod.rs returns ScreenVerdict::Pass
	// for a missing profile), silently skipping every screen check for the zone
	// while the operator believes screening is active. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config that an older binary accepted still BOOTS (#1960
	// no-brick). Unlike the policy gates, the dataplane is NOT independently
	// safe on the lenient path (a missing profile fails open), so the strict
	// commit gate — keeping a bad reference from ever reaching the dataplane —
	// is the real fix; the warning is the only signal on a leniently-loaded
	// config. Same doctrine as lenientPolicyZoneRefs.
	lenientScreenProfileRefs bool
	// lenientScreenNumeric (#3317) downgrades the screen numeric-value gate
	// (validateScreenNumericStrict) from a hard compile error to a cfg.Warnings
	// entry. The strict commit / commit-check path hard-rejects a screen
	// threshold / count leaf whose explicitly-provided value is not a positive
	// integer. Before this gate compileScreen swallowed the strconv.Atoi error
	// and fell back to a Junos default (icmp/udp flood, ip-sweep, port-scan,
	// syn-flood attack-threshold) or to zero/disabled (the other syn-flood
	// subfields, limit-session) — a typo'd threshold silently disabled or
	// weakened the protection (fail-open). The tolerant load / peer-sync paths
	// downgrade to a warning so an already-persisted or peer-synced config that
	// an older binary accepted still BOOTS (#1960 no-brick); compileScreen
	// independently applies the default for the bad value on that path, so the
	// leniently-loaded profile is no worse than the pre-gate behavior. Same
	// doctrine as lenientFilterDSCP.
	lenientScreenNumeric bool
	// lenientScreenUnknown (#3318) downgrades the unknown-screen-leaf gate
	// (validateScreenUnknownStrict) from a hard compile error to a cfg.Warnings
	// entry. The strict commit / commit-check path hard-rejects a screen leaf
	// the dataplane does NOT support. The screen schema subtrees are open and
	// compileScreen switched only on known child names with no default case, so
	// a misspelled or unsupported leaf committed cleanly and was silently
	// dropped — the operator believed a protection was enabled when it was
	// absent. compileScreen now records every unsupported leaf on
	// ScreenProfile.UnknownLeaves; this gate makes the refusal operator-visible
	// at commit. The tolerant load / peer-sync paths downgrade to a warning so
	// an already-persisted or peer-synced config still BOOTS (#1960 no-brick);
	// the dataplane never represented the leaf, so a leniently-loaded profile
	// runs without it independently. Same doctrine as lenientFilterFromMatch.
	lenientScreenUnknown bool
	// lenientTrailingTokens (#3332) downgrades the trailing-token gate
	// (validateTrailingTokensStrict) from a hard compile error to a
	// cfg.Warnings entry. The strict commit / commit-check path hard-rejects
	// a token that rode past a leaf's value arity in a shape the generic
	// schema-walk scalar gate cannot reach — address-book `address <name>
	// <prefix>` / `... description <text>` (the `address` node is multi:true)
	// and IKE gateway compact-hierarchical `dynamic hostname <fqdn> <extra>`
	// (the tokens collapse onto the parent `dynamic` node's Keys). The
	// compiler read only the value slot and silently dropped the rest. The
	// tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config still BOOTS (#1960 no-brick);
	// the dropped token never reached the dataplane, so a leniently-loaded
	// config is no different from before the gate. Same doctrine as
	// lenientScreenUnknown.
	lenientTrailingTokens bool
	// lenientFlowAging (#3440 H2) downgrades the flow-aging gate
	// (validateFlowAgingStrict) from a hard compile error to a cfg.Warnings
	// entry. The strict commit / commit-check path hard-rejects an unknown
	// `security flow aging` leaf or a low-watermark >= high-watermark
	// cross-field violation. The aging subtree was an opaque untyped node, so
	// these bad shapes used to commit cleanly and be silently dropped /
	// oscillate. The tolerant load / peer-sync paths downgrade to a warning
	// so an already-persisted or peer-synced config still BOOTS (#1960
	// no-brick); watermark aging is not enforced on the userspace dataplane
	// anyway (#3440 H1), so a leniently-loaded bad value is inert. Same
	// doctrine as lenientScreenUnknown.
	lenientFlowAging bool
	// lenientChassisRG (#4434) downgrades the chassis-cluster heartbeat
	// wire-width gate (validateChassisClusterStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a redundancy-group cardinality or id that exceeds the
	// single-byte heartbeat count / GroupID fields (256 RGs advertise as a
	// count of 0 and desync the wire; an id > 255 truncates and collides).
	// The tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config still BOOTS (#1960 no-brick);
	// the heartbeat marshaler independently caps the group section to the
	// wire limit (pkg/cluster/heartbeat.go maxHeartbeatGroups), so a
	// leniently-loaded over-size config is bounded on the wire, not a panic.
	// Same doctrine as lenientFlowAging.
	lenientChassisRG bool
	// lenientVRRPGroupID (#4573) downgrades the VRRP VRID wire-width gate
	// (validateVRRPGroupIDStrict) from a hard compile error to a cfg.Warnings
	// entry. The strict commit / commit-check path hard-rejects a
	// `vrrp-group <id>` outside the RFC 5798 VRID range 1..255 (the id is
	// truncated onto a single wire byte, so 256 wraps to the reserved VRID 0
	// and the VIP never masters, 257 aliases VRID 1 onto another group). The
	// `vrrp-group <id>` instance slot has no schema value validator (documented
	// deferral, schema_interfaces.go), so an out-of-range numeric id used to
	// commit cleanly and produce a live wrong-VRID instance. The tolerant load
	// / peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary accepted still BOOTS (#1960 no-brick);
	// the pkg/vrrp instance-creation range check independently refuses to
	// advertise an out-of-range VRID, so a leniently-loaded bad id is bounded,
	// not a wrong-VRID advert. Same doctrine as lenientChassisRG.
	lenientVRRPGroupID bool
	// lenientVRRPGroupPriority (#5184) downgrades the VRRP priority
	// wire-width gate (validateVRRPGroupPriorityStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `vrrp-group <id> priority <n>` outside the RFC 5798
	// range 1..255 (the priority is truncated onto a single wire byte in
	// sendAdvert, so 256 wraps to the reserved priority 0 — the group
	// advertises resignation and never masters the VIP — and 300 aliases to
	// 44). The structured spellings are gated at the schema layer
	// (ValidateInteger(1,255)), but the PACKED hierarchical one-liner
	// `vrrp-group 1 priority 256;` packs the priority onto the instance
	// node's Keys, which the schema walker consumes as an unvalidated
	// identity token (walkInstanceChildren), so an out-of-range packed
	// priority used to commit cleanly and produce a resigning instance. The
	// tolerant load / peer-sync paths downgrade to a warning so an already-
	// persisted or peer-synced config an older binary accepted still BOOTS
	// (#1960 no-brick). Same doctrine as lenientVRRPGroupID.
	lenientVRRPGroupPriority bool
	// lenientRethVRRPGroupID (#4826) downgrades the reth-derived VRRP VRID
	// wire-width gate (validateRethVRRPGroupIDStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `redundant-ether-options redundancy-group <id>` whose
	// id would push the reth-derived VRRP GroupID (100+id) past the RFC 5798
	// VRID range 1..255 — the chassis redundancy-group id gate
	// (validateChassisClusterStrict) alone permits id up to 255, which is
	// the heartbeat wire bound, not the VRRP one, so an id in 156..255 used
	// to commit cleanly and then silently lose VRRP for that redundancy
	// group. The tolerant load / peer-sync paths downgrade to a warning so
	// an already-persisted or peer-synced config still BOOTS (#1960
	// no-brick); the pkg/vrrp/manager.go runtime range check independently
	// refuses to advertise the out-of-range VRID, so a leniently-loaded bad
	// id is bounded, not a wrong-VRID advert. Same doctrine as
	// lenientVRRPGroupID.
	lenientRethVRRPGroupID bool
	// lenientIfNameCollision (#5832) downgrades the interface-name canonical
	// collision / IFNAMSIZ gate (validateInterfaceNameCollisionStrict) from a
	// hard compile error to a cfg.Warnings entry. LinuxIfName only replaces '/'
	// with '-', so two distinct authored names (ge-0/0/0 and ge-0-0-0)
	// canonicalize to the same Linux device / ifindex; the Rust
	// forwarding-state builder overwrites the earlier row and the
	// lexicographically later name silently wins, hijacking that device's
	// security-zone / routing identity. The strict commit / commit-check path
	// hard-rejects so the collision is operator-visible; the tolerant load /
	// peer-sync paths warn (naming the winner) so an already-persisted or
	// peer-synced config that predates this gate still BOOTS (#1960 no-brick).
	// Same doctrine as lenientRethVRRPGroupID.
	lenientIfNameCollision bool
	// lenientRethMember (#6722) downgrades the redundant-ethernet membership
	// coherence gate (validateRethMemberStrict) from a hard compile error to a
	// cfg.Warnings entry. A reth member is an L2 port whose L3 identity — units,
	// addresses, tunnel, zone — lives on the reth; the egress-zone answer
	// (stampEgressZones, pkg/dataplane/userspace/interfaces.go) treats a reth and
	// its member as ONE device on exactly that basis. A member that names itself,
	// names an unconfigured parent, carries its own logical units, or carries its
	// own tunnel breaks the premise, and the last two fail OPEN (an
	// independently addressed member unit, or an independently routed tunnel
	// endpoint, silently inherits the reth's zone). The strict commit /
	// commit-check path hard-rejects so the incoherence is operator-visible; the
	// tolerant load / peer-sync paths warn so an already-persisted or peer-synced
	// config that predates this gate still BOOTS (#1960 no-brick). Bounded on the
	// lenient path by the SAME rule the gate states: a member that is not a bare
	// port is not a member, so the shared device has two independent claimants
	// and its ifindex identifies no zone (fail-closed).
	// Same doctrine as lenientIfNameCollision.
	lenientRethMember bool
	// lenientReservedZoneNames (#3055) downgrades the reserved zone-name
	// definition gate (validateReservedZoneNamesStrict) from a hard compile
	// error to a cfg.Warnings entry. The strict commit / commit-check path
	// hard-rejects a `security zones security-zone <name>` whose name is a
	// reserved sentinel ("junos-global", "any", "junos-host"). A zone named
	// "junos-global" is reclassified by the userspace dataplane
	// (userspace-dp/src/policy.rs) as a device-wide global fallback evaluated
	// for every flow, so its zone-scoped policies silently permit traffic for
	// unrelated zone pairs — a security-boundary escape. The tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary accepted still BOOTS (#1960 no-brick).
	// Same doctrine as lenientPolicyZoneRefs.
	lenientReservedZoneNames bool
	// #3096: lenientNATRuleSetScope (the #3079 interim NAT rule-set
	// from/to scope reject) is removed — interface/routing-instance scopes
	// are now fully captured and enforced in the dataplane match path, so
	// there is no longer an unsupported-scope reject to make lenient.
	// lenientBackupRouterDst (#2911) downgrades the backup-router
	// destination/next-hop family-mismatch gate (validateBackupRouterDst)
	// from a hard compile error to a cfg.Warnings entry. #2907 (#2891)
	// made the EMPTY backup-router destination default next-hop-family-aware
	// (a v6 next-hop with no explicit destination defaults to ::/0), but an
	// EXPLICIT destination whose family MISMATCHES the next-hop — e.g.
	// `backup-router 2001:db8::1` + `destination 0.0.0.0/0` — still renders an
	// FRR-invalid static line (`ipv6 route 0.0.0.0/0 2001:db8::1 250`).
	// frr-reload rejects a mismatched-family static and that failure fails the
	// ENTIRE static config load, not just the one line — exactly the breakage
	// #2907 set out to prevent. The strict commit / commit-check path hard-
	// rejects so the operator-error is visible (naming both addresses and
	// families); the tolerant load / peer-sync paths downgrade to a warning so
	// an already-persisted or peer-synced config an older binary accepted still
	// BOOTS (#1960 fail-closed-on-load class). Same doctrine as
	// lenientReservedZoneNames.
	lenientBackupRouterDst bool
	// lenientSecureTunnelBindIface (#2933) downgrades the secure-tunnel
	// bind-interface alias-collision gate (validateSecureTunnelBindInterfaceAST)
	// from a hard compile error to a cfg.Warnings entry. Two VPNs that bind two
	// DISTINCT bind-interface strings deriving the SAME XFRM if_id (e.g.
	// `bind-interface st0` and `bind-interface st0.0`, both if_id 1 via
	// XFRMIfNameAndID) committed cleanly but collide at apply time: only one
	// xfrm device can carry the if_id, so the routing manager (#2929 guard)
	// refuses to create EITHER and both tunnels go down. The strict commit /
	// commit-check path hard-rejects so the operator-error is visible (naming
	// the offending bind-interface strings, their VPNs, and the shared if_id);
	// the tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config an older binary silently accepted
	// still BOOTS (#1960 fail-closed-on-load class) — the #2929 routing guard
	// remains the runtime backstop. Same doctrine as lenientBackupRouterDst.
	lenientSecureTunnelBindIface bool
	// lenientPolicyMatchLeaves (#3113) downgrades the security-policy
	// unsupported-match-leaf gate (validatePolicyMatchLeavesStrict) from a
	// hard compile error to a cfg.Warnings entry. A security policy whose
	// `match` clause carries a leaf the compiler does not enforce — e.g.
	// `dynamic-application`, `url-category`, `source-identity` — committed
	// cleanly but had that criterion SILENTLY DROPPED: compilePolicy's
	// `match` switch handles only the supported subset (source/destination
	// address, excluded, application) and the set-schema/schema_walk ignore
	// unknown keywords. Dropping a match criterion WIDENS the policy — a
	// rule meant to match only one dynamic-application became a broad L3/L4
	// permit/deny over all applications, a fail-OPEN. The strict commit /
	// commit-check path hard-rejects so the misconfiguration is operator-
	// visible (naming the policy scope, the policy, and the unsupported
	// leaf); the tolerant load / peer-sync paths downgrade to a warning so
	// an already-persisted or peer-synced config an older binary silently
	// accepted still BOOTS (#1960 fail-closed-on-load class) — the leaf
	// stays dropped (the pre-existing behaviour), now flagged. Full
	// support for those match types is a deferred follow-up. Same doctrine
	// as lenientSecureTunnelBindIface.
	lenientPolicyMatchLeaves bool
	// lenientPolicyThenPermit (#3114) downgrades the security-policy
	// unsupported-then-permit-child gate (validatePolicyThenPermitStrict)
	// from a hard compile error to a cfg.Warnings entry. A security policy
	// whose `then permit` arm carries a child the compiler does not
	// enforce — e.g. `application-services` (UTM/IDP/AppFW/SSL-proxy),
	// `firewall-authentication`, `tunnel ipsec-vpn` — committed cleanly but
	// had that modifier SILENTLY DROPPED: compilePolicy's `then` switch
	// `permit` arm sets pol.Action = PolicyPermit and never inspects
	// t.Children, and the set-schema/schema_walk ignore unknown keywords.
	// Dropping a then-permit service chain turns a permit-only-with-
	// inspection rule into an UNCONDITIONAL permit — a fail-OPEN. The strict
	// commit / commit-check path hard-rejects so the misconfiguration is
	// operator-visible (naming the policy scope, the policy, and the
	// unsupported child); the tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config an older binary
	// silently accepted still BOOTS (#1960 fail-closed-on-load class) — the
	// child stays dropped (the pre-existing behaviour), now flagged. Full
	// service-chain support is a deferred follow-up. Same doctrine as
	// lenientPolicyMatchLeaves.
	lenientPolicyThenPermit bool
	// lenientPolicyThenReject (#3115) downgrades the security-policy
	// unsupported-then-reject-child gate (validatePolicyThenRejectStrict)
	// from a hard compile error to a cfg.Warnings entry. A security policy
	// whose `then reject` arm carries a child the compiler does not enforce
	// — a reject `profile <name>` (custom reject response) or a packet-type
	// reject like `tcp-reset` — committed cleanly but had that modifier
	// SILENTLY DROPPED: compilePolicy's `then` switch `reject` arm sets
	// pol.Action = PolicyReject and never inspects t.Children, and the
	// set-schema/schema_walk ignore unknown keywords. Unlike #3114 this is
	// not a fail-open (reject still rejects), but the configured custom
	// reject response is inert — a wire-contract / operator-observability
	// divergence the operator cannot detect at commit. The strict commit /
	// commit-check path hard-rejects so it is operator-visible (naming the
	// policy scope, the policy, and the unsupported child); the tolerant
	// load / peer-sync paths downgrade to a warning so an already-persisted
	// or peer-synced config an older binary silently accepted still BOOTS
	// (#1960 fail-closed-on-load class) — the child stays dropped (the
	// pre-existing behaviour), now flagged. Reject-profile support is a
	// deferred follow-up. Same doctrine as lenientPolicyThenPermit.
	lenientPolicyThenReject bool
	// lenientPolicyThenDeny (#3141) downgrades the security-policy
	// unsupported-then-deny-modifier gate (validatePolicyThenDenyStrict)
	// from a hard compile error to a cfg.Warnings entry. A flat-set
	// `then deny log session-init` collapses `log session-init` onto the
	// deny node (Keys=["deny","log","session-init"]) instead of nesting a
	// sibling `then log` node; compilePolicy's `then` switch `deny` arm used
	// to read only t.Name() and silently dropped the collapsed modifier, so
	// deny-with-logging committed but `pol.Log` was never set (a deny-rule
	// observability / compliance failure). #3141 WIRES the legitimate
	// log/count modifiers (applyCollapsedDenyModifiers) so deny+log works in
	// both the flat-collapsed and the separate-node forms; this gate is the
	// safety net for any REMAINING collapsed deny modifier the compiler
	// cannot enforce — the strict commit / commit-check path hard-rejects so
	// it is operator-visible, the tolerant load / peer-sync paths downgrade
	// to a warning so an already-persisted or peer-synced config an older
	// binary silently accepted still BOOTS (#1960). Same doctrine as
	// lenientPolicyThenReject.
	lenientPolicyThenDeny bool
	// lenientPolicyMissingMatch (#3044) downgrades the security-policy
	// required-match gate (validatePolicyRequiredMatchStrict) from a hard
	// compile error to a cfg.Warnings entry. A security policy whose `match`
	// clause omits one of the three Junos-mandatory dimensions —
	// source-address, destination-address, application — or that omits the
	// `match` block entirely committed cleanly but had the missing dimension
	// SILENTLY compiled as match-ANY: compilePolicy fills each slice only
	// when the leaf is present and the userspace dataplane treats an empty
	// slice as match-any. A partial policy is therefore broader than typed —
	// `match source-address corp; then permit` permits corp->any:any, and a
	// match-less policy becomes a zone-pair-wide permit/deny — a fail-OPEN
	// for permit, an over-broad block for deny. On Junos this cannot commit.
	// The strict commit / commit-check path hard-rejects so the misconfig is
	// operator-visible (naming the policy scope, the policy, and every
	// missing dimension); the tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config an older binary
	// silently accepted still BOOTS (#1960 fail-closed-on-load class) — the
	// policy keeps its match-any-for-missing compilation, now flagged. A
	// missing dimension is distinct from an explicit `any`: the operator
	// must write `any` for an intentional wildcard (Junos parity). Same
	// doctrine as lenientPolicyMatchLeaves.
	lenientPolicyMissingMatch bool
	// lenientPolicyValuelessMatch (#6526) downgrades the security-policy
	// VALUELESS-match-dimension gate — the second finding emitted by
	// validatePolicyRequiredMatchStrict — from a hard compile error to a
	// cfg.Warnings entry. A `match` dimension written with NO OPERAND
	// (`source-address;`, or a `set ... match source-address` line with the
	// value left off) satisfied the #3044 name-based required-dimension gate
	// yet compiled to the BYTE-IDENTICAL empty slice the omitted form
	// produces, which the userspace matcher reads as match-ANY: `then permit`
	// then permits every source, and a scoped-global `match from-zone` /
	// `to-zone` collapses to the all-zones wildcard. The strict commit /
	// commit-check path hard-rejects so the typo is operator-visible (naming
	// the policy scope, the policy, and every valueless dimension); the
	// tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config an older binary silently
	// accepted still BOOTS (#1960 fail-closed-on-load class) — and there the
	// policy is additionally poisoned by compilePolicy's #5575
	// LenientContentDropped flag rather than published as a widened permit —
	// but ONLY on the userspace dataplane, which is the sole plane that reads
	// that flag. The kernel host-inbound actuator (junos_host_deny.go ->
	// daemon_apply_tail.go) does NOT consult it, so a poisoned `junos-host`
	// policy still projects to nft with an empty source list read as
	// source-any: it becomes permitAll and suppresses a following deny. That
	// gap is PRE-EXISTING (the OMITTED spelling reaches it identically on
	// master) and is tracked as #6705, not introduced here. The runtime
	// consequences of the snapshot rejection itself — the transit window, HA
	// divergence, and a poisoned commit-confirmed rollback target — are
	// likewise pre-existing and tracked as #6707.
	// Kept as its own flag (not folded into lenientPolicyMissingMatch) so the
	// two findings stay independently attributable. Same doctrine as
	// lenientPolicyMissingMatch.
	lenientPolicyValuelessMatch bool
	// lenientPolicyCommunityRef (#2881) downgrades the policy community
	// cross-reference gate (validatePolicyCommunityReferencesStrict) from a
	// hard compile error to a cfg.Warnings entry. A policy term's
	// `from community <name>` (rendered `match community <name>`) and
	// `then community delete <name>` (rendered `set comm-list <name> delete`,
	// added in #2848) both reference an FRR `bgp community-list <name>` that
	// xpf renders ONLY from a defined `policy-options community <name>`. With
	// no validation, a term naming an UNDEFINED community committed cleanly and
	// broke at FRR render time: a dangling `match community <name>` is rejected
	// by frr-reload (a single vtysh -f add-batch exits non-zero on any
	// CMD_WARNING_CONFIG_FAILED, failing the WHOLE reload and leaving routing
	// stale), and a dangling `set comm-list <name> delete` is likewise
	// rejected. The strict commit / commit-check path hard-rejects so the typo
	// is operator-visible (naming the policy, term, and missing community); the
	// tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config carrying the typo still BOOTS
	// (#1960 fail-closed-on-load class). Runs on the fully-compiled *Config so
	// the community map is populated regardless of authoring order. Only a
	// NAME reference is validated — `then community (set|add) <value>` carries a
	// community VALUE (e.g. 65000:100), not a list reference, and is not
	// checked. Same doctrine as lenientRoutingExportRef.
	lenientPolicyCommunityRef bool
	// lenientPolicyReservedRedistName (#5116) downgrades the reserved
	// route-map-suffix gate (validatePolicyReservedRedistNameStrict) from a
	// hard compile error to a cfg.Warnings entry. An operator policy-statement
	// whose name ends in the reserved ReservedRedistSuffix ("-xpf-redist")
	// collides in FRR's global name-keyed route-map namespace with the
	// per-use-site fail-closed redistribute alias the renderer derives (#4481),
	// which can silently reintroduce BGP/IGP redistribution leakage. The strict
	// commit / commit-check path hard-rejects such a name so it is
	// operator-visible; an already-persisted or peer-synced config an older
	// binary accepted must still BOOT (warn) per the #1960 fail-closed-on-load
	// doctrine — the render path carries a defense-in-depth collision guard
	// (redistAliasCollision, pkg/frr) that fails the managed-section apply CLOSED
	// on the tolerant path, so a leniently-loaded collision cannot leak. Same
	// doctrine as lenientRoutingExportRef.
	lenientPolicyReservedRedistName bool
	// lenientPolicyReservedChainName (#5442) downgrades the reserved
	// composed-chain route-map-suffix gate (validatePolicyReservedChainNameStrict)
	// from a hard compile error to a cfg.Warnings entry. An operator
	// policy-statement whose name ends in the reserved ReservedChainSuffix
	// ("-xpf-chain") collides in FRR's global name-keyed route-map namespace with
	// the composed BGP policy-chain route-map the renderer derives for an ordered
	// import/export chain of length >= 2 (#5277); FRR merges same-named
	// route-maps, which can silently alter the operator's BGP filtering. The
	// strict commit / commit-check path hard-rejects such a name so it is
	// operator-visible; an already-persisted or peer-synced config an older
	// binary accepted must still BOOT (warn) per the #1960 fail-closed-on-load
	// doctrine — the render path carries a defense-in-depth collision guard
	// (bgpComposedChainCollision, pkg/frr) that fails the managed-section apply
	// CLOSED on the tolerant path, so a leniently-loaded collision cannot leak.
	// Same doctrine as lenientPolicyReservedRedistName.
	lenientPolicyReservedChainName bool
	// lenientVRRPVirtualAddress (#3013) downgrades the VRRP virtual-address
	// subnet-containment gate (validateVRRPVirtualAddressSubnet) from a hard
	// compile error to a cfg.Warnings entry. A VRRP virtual-address that does
	// not fall within any subnet configured on the same interface unit for the
	// matching family — e.g. `family inet address 10.0.61.1/24` with
	// `vrrp-group 1 virtual-address 10.0.99.1/24` — committed cleanly but is a
	// commit-time configuration error in Junos/vSRX. At runtime the daemon
	// installs the VIP with no connected route covering it, so return traffic
	// sourced from the VIP has no on-link subnet association — a silent
	// blackhole the operator only sees as dropped traffic. The strict commit /
	// commit-check path hard-rejects so the operator-error is visible (naming
	// the interface, unit, group, VIP, and family); the tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary accepted still BOOTS (#1960
	// fail-closed-on-load class). Same doctrine as lenientBackupRouterDst.
	lenientVRRPVirtualAddress bool

	// lenientDNATToScope (#3444) downgrades the destination-NAT rule-set
	// `to` scope reject (validateDNATRuleSetToScopeAST) from a hard compile
	// error to a cfg.Warnings entry. Junos destination NAT rule-sets have
	// only a `from` clause (DNAT translates the destination on inbound, so
	// there is no egress context yet); xpf's schema briefly advertised a
	// `to` scope under `security nat destination rule-set` and the compiler
	// Cartesian-expanded it onto each NATRuleSet, but the userspace snapshot
	// builder and the Rust DNAT runtime model ONLY the `from` clause — so a
	// configured `to zone|interface|routing-instance` was silently dropped
	// and the translation applied regardless of the operator's declared
	// destination context (a silent functional lie). The strict commit /
	// commit-check path hard-rejects so the operator error is visible; the
	// tolerant load / peer-sync paths downgrade to a warning so an
	// already-persisted or peer-synced config an older binary accepted still
	// BOOTS (#1960 fail-closed-on-load class) — the `to` scope is ignored
	// either way, now flagged. Same doctrine as
	// lenientUnsupportedInterfaceStanzas.
	lenientDNATToScope bool

	// lenientNATMixedScope (#4881) downgrades the NAT rule-set mixed-scope-kind
	// reject (validateNATRuleSetMixedScopeAST) from a hard compile error to a
	// cfg.Warnings entry. A single `from` / source-`to` / static-`from` NAT
	// clause that mixes scope KINDS (e.g. `from zone trust` + `from interface
	// ge-0/0/1.0`) is OR-expanded by the #3096 Cartesian product into multiple
	// typed rule-sets — matching EITHER scope, which WIDENS the NAT match beyond
	// the intended ingress/egress boundary and contradicts Junos' one-kind-per-
	// clause rule. The strict commit / commit-check path hard-rejects so the
	// operator error is visible; the tolerant load / peer-sync paths downgrade
	// to a warning so an already-persisted or peer-synced config an older binary
	// accepted still BOOTS (#1960 fail-closed-on-load class). Same doctrine as
	// lenientDNATToScope.
	lenientNATMixedScope bool

	// lenientNATTerminalAction (#5628, codex-review-181 M16) downgrades the
	// source/destination NAT terminal-action cardinality gate
	// (validateNATTerminalActionCardinalityStrict) from a hard compile error to
	// a cfg.Warnings entry. A NAT rule whose complete `then {}` block carries
	// ZERO terminal actions (actionless — the snapshot builder installs no
	// translation and the rule does not stop evaluation, so an intended `off`
	// exemption silently disappears and the traffic falls through: translated by
	// a later broader rule if one matches, otherwise left untranslated) or TWO+
	// mutually-exclusive actions inside
	// one block (`off` + `pool`, `interface` + `pool` — before #5628 the compiler
	// picked one by packed-key / child order; it now records every field and the
	// DATAPLANE resolves the rule by a fixed precedence, so all but one authored
	// action is silently discarded) was previously accepted. The strict commit /
	// commit-check
	// path hard-rejects so the malformed rule is operator-visible; the tolerant
	// load / peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary accepted still BOOTS (#1960 fail-
	// closed-on-load class) — a leniently-loaded actionless rule is NOT inert
	// (see the ZERO-actions wording above), though HOW it fails to be inert
	// differs by kind: source NAT EMITS the rule and the Rust matcher's `else`
	// arm continues past it, destination NAT SKIPS it in the builder. Either way
	// the traffic falls through rather than being exempted. A contradictory rule
	// records EVERY authored field (the else-if→if setter change) — two of them,
	// or three for `interface` + `off` + `pool` — unifying the hierarchical path
	// with the pre-existing flat-set behavior rather than the old Go
	// single-field child-order pick. Resolution is then by a FIXED precedence,
	// which is off-precedence only when the contradiction CONTAINS `off`:
	// `interface` + `pool` carries none, and interface mode wins there while the
	// authored pool is discarded (#6820 round 3 — the earlier "off-precedence
	// governs" wording was quantified over all contradictions and is false for
	// that pair).
	// Only a malformed rule reaches this — the strict commit path rejects it.
	// Duplicate `then` CONTAINERS remain #3850 last-wins (the gate counts the
	// winning block only). Same doctrine as lenientNATMixedScope.
	lenientNATTerminalAction bool
	// lenientInterfaceUnitAliasCollisions (#5631, codex-review-181 M23)
	// downgrades the numeric interface-unit alias reject
	// (validateInterfaceUnitAliasCollisionsAST) from a hard compile error to a
	// cfg.Warnings entry. Two distinct unit spellings under one interface that
	// canonicalize to the same logical unit (e.g. `unit 00` and `unit 0`)
	// collide on `ifc.Units[unitNum]` with last-writer-wins for the unit
	// filter but append-only accumulation for the interface tunnel addresses —
	// so the winning firewall filter and the surviving tunnel addresses depend
	// on config order (a fail-open on the security filter). The strict commit /
	// commit-check path hard-rejects so the operator collapses the aliases; the
	// tolerant load / peer-sync paths downgrade to a warning so an already-
	// persisted or peer-synced config an older binary accepted still BOOTS
	// (#1960 fail-closed-on-load class). Same doctrine as
	// lenientUnsupportedInterfaceStanzas.
	lenientInterfaceUnitAliasCollisions bool

	// lenientEventWithinTrigger (#3751) downgrades the event-options
	// within/trigger numeric gate (validateEventOptionsWithinAST) from a hard
	// compile error to a cfg.Warnings entry. A non-numeric / negative / zero /
	// out-of-range `within <seconds>` or `trigger (on|until) <count>` value,
	// or a `within` clause carrying BOTH `trigger on` and `trigger until`, was
	// previously accepted: compileEventOptions dropped the strconv.Atoi error
	// and coerced the field to 0, and the engine's withinMatches then treated
	// a 0 threshold as an unconditional match — a typo silently converted a
	// threshold-gated remediation into an ALWAYS-FIRE one (fail-open). The
	// strict commit / commit-check path hard-rejects so the operator error is
	// visible (naming the policy and the exact value); the tolerant load /
	// peer-sync paths downgrade to a warning so an already-persisted or
	// peer-synced config an older binary silently accepted still BOOTS (#1960
	// fail-closed-on-load class) — on that boot the engine's withinMatches
	// fails CLOSED (does not fire) on a clause with no usable positive
	// threshold, so the mis-arrived 0 no longer over-fires. Same doctrine as
	// lenientEventAttributesMatch (its attributes-match sibling).
	lenientEventWithinTrigger bool

	// lenientFirewallTCPFlags (#4953) downgrades the firewall-filter
	// `from tcp-flags` enforceability reject (validateFirewallTCPFlagsStrict:
	// disjunction, negated group, unknown flag, dangling negation, or a
	// required/forbidden contradiction) from a hard compile error to a
	// cfg.Warnings entry. Before #3076 such an expression committed cleanly and
	// the constraint was silently dropped on the wire (fail-OPEN); #3076 added
	// an inline reject in compileFirewall, but the P4 section dispatch calls
	// compileFirewall with NO compileOpts, so the reject could not be
	// mode-gated — an upgraded node whose already-persisted config carried the
	// expression blacked out on load (CompileConfigLenient returned the error →
	// ActiveConfig()==nil) and a standby's SyncApply alarm-looped. Set ONLY on
	// the tolerant load / peer-sync paths so an already-accepted config still
	// BOOTS; commit / commit-check stay strict. The leniently-loaded term keeps
	// its raw TCPFlags, which the userspace snapshot builder marks
	// TCPFlagsUnparseable to fail the term CLOSED (#3367) — a fail-closed deny
	// sentinel, never a match-all widening. Same doctrine as lenientFilterDSCP.
	lenientFirewallTCPFlags bool

	// lenientCoSNumericCodePoint (#4953) downgrades the class-of-service
	// numeric DSCP/PCP code-point range reject (a `code-point`/`code-points`
	// token that is an integer outside the 6-bit DSCP domain 0..63 or the
	// 3-bit PCP domain 0..7, on either a classifier or a rewrite-rule) from a
	// hard compile error to a cfg.Warnings entry. Before #2447 such a token was
	// silently dropped at the Go layer and the dataplane masked it (dscp&0x3f /
	// pcp.min(7)) onto a DIFFERENT traffic class; #2447 made it a hard commit
	// reject, but the reject lives inside compileClassOfService (which the P4
	// dispatch calls with no compileOpts), so it could not be mode-gated — an
	// upgraded node whose already-persisted config carried the value blacked
	// out on load and a standby's SyncApply alarm-looped. Set ONLY on the
	// tolerant load / peer-sync paths so an already-accepted config still
	// BOOTS; on that boot the offending entry is dropped, exactly the pre-#2447
	// fail-safe. Commit / commit-check stay strict. Same doctrine as
	// lenientFirewallTCPFlags.
	lenientCoSNumericCodePoint bool

	// lenientNonNumericUnit (#5829) downgrades the malformed logical-unit
	// identity gate (a non-numeric / negative / overflow `interfaces <if>
	// unit <id>`) from a hard compile error to a cfg.Warnings entry with the
	// offending unit quarantined (skipped, its children NOT reattached to any
	// other unit). Strict commit / commit-check hard-reject so a unit-level
	// firewall filter cannot commit and then silently vanish (fail-open). Set
	// ONLY on the tolerant load / peer-sync paths (CompileConfigLenient /
	// CompileConfigForNodeLenient) so a config an older binary already
	// persisted — which silently dropped the bad unit — still BOOTS, now with
	// a deterministic warning instead of a silent drop. Same doctrine as
	// lenientCoSNumericCodePoint. Like the other lenient gates this is an
	// AST-level compile decision the read-only SchemaValidate walk cannot make
	// (and since #1319 PR 2 SchemaValidate violations only warn on tolerant
	// paths anyway).
	lenientNonNumericUnit bool

	// lenientInterfaceUnitRef (#5933) downgrades the cross-subsystem interface
	// `.unit`-suffix reference gate (a malformed logical unit in a
	// class-of-service / security-zone / routing-instance interface reference)
	// from a hard compile error to a cfg.Warnings entry. Strict commit /
	// commit-check hard-reject so a malformed `.unit` reference cannot commit and
	// then silently mis-bind (the CoS shaper never attaches, the zone-membership
	// key never matches, the route-leak member is dropped). Set ONLY on the
	// tolerant load / peer-sync paths so a config an older binary already
	// persisted — which silently ignored the bad reference — still BOOTS, now
	// with a deterministic warning. Same doctrine as lenientNonNumericUnit
	// (#5829); this closes the residual #5829 deferred to #5933.
	lenientInterfaceUnitRef bool

	// lenientLoginClassDeny (#5831) downgrades the custom-login-class
	// restrictive-regex gate (deny-commands / deny-configuration, which xpf's
	// coarse RBAC does not enforce) from a hard compile error to a
	// cfg.Warnings entry PLUS a restrictive fold of the affected class's mapped
	// permissions. Set ONLY on the tolerant load / peer-sync paths so a config
	// persisted before this gate existed — or synced from a peer running older
	// code — still BOOTS (#1960 no-brick). Unlike most lenient flags this one
	// is not warn-and-continue-unchanged: leaving the permission set intact
	// would preserve exactly the fail-open the strict gate rejects, so the
	// tolerant path resolves the un-enforceable restriction in the RESTRICTIVE
	// direction instead — bounded by a repair floor, because a class the
	// console operator is bound to must keep the access that deletes the
	// statement. See foldLoginClassDenyToRepairableFloor.
	lenientLoginClassDeny bool

	// lenientBridgeDomainVlanID (#6687) downgrades the bridge-domain
	// `vlan-id-list` parse / range gate from a hard compile error to a
	// cfg.Warnings entry plus a dropped value. The strict commit /
	// commit-check path rejects a non-numeric or out-of-range (not 1-4094)
	// id in ANY slot of the list; before #6687 only slot 0 was examined, so
	// `vlan-id-list [ 10 99999 ]` committed clean and compiled as VLAN 10.
	// Widening the read without this flag would make a config that the old
	// gate ACCEPTED refuse to boot after an upgrade, which is precisely what
	// the tolerant load / peer-sync path exists to prevent (#1960). The
	// dropped value was never installed under the old compiler either, so a
	// leniently-loaded config carries exactly the VLAN set master compiled —
	// only the warning is new. This is a per-value decision inside
	// compileBridgeDomains rather than a declarative typed leaf, so the check
	// does NOT live in SchemaValidate; putting it there would also mask the
	// tail, since a strict schema gate firing first hides whether the
	// compiler's own check ever ran. Same doctrine as lenientSNMPTrapGroup.
	lenientBridgeDomainVlanID bool

	// nodeAware / stampNodeID (#4329) carry the runtime cluster node
	// identity (from /etc/xpf/node-id, or `-node-id` on `xpfd
	// check-config`) into compileExpanded so it can be stamped onto the
	// compiled ClusterConfig.NodeID BEFORE any NodeID-dependent derivation
	// runs. Only the node-aware entry (compileConfigForNodeWithOpts) sets
	// nodeAware; the standalone CompileConfig path leaves it false so
	// single-node compiles are unchanged. See the stamp in compileExpanded
	// for the full rationale and guards.
	nodeAware   bool
	stampNodeID int
}

// lenientCompileOpts returns a compileOpts with every tolerant-path
// severity downgrade enabled. It is the single source of truth for the
// lenient flag set that CompileConfigLenient and
// CompileConfigForNodeLenient share; both formerly inlined a byte-
// identical ~125-field composite literal (#6423 dedup). compileOpts is a
// value type, so each call returns a fresh copy — equivalent to the
// original inline literals.
func lenientCompileOpts() compileOpts {
	return compileOpts{
		sanitizeFreeTextControlChars:           true,
		lenientVRRPTrackDuplicates:             true,
		lenientVRRPAuthentication:              true,
		lenientDeviceMap:                       true,
		lenientPolicyMatchAddress:              true,
		lenientTCPMSSRange:                     true,
		lenientLogStreamPort:                   true,
		lenientLogTLSProfile:                   true,
		lenientFlowTraceFile:                   true,
		lenientFlowTraceFilter:                 true,
		lenientFlowTraceSizeFiles:              true,
		lenientLogEventModeFormat:              true,
		lenientEventAttributesMatch:            true,
		lenientIPsecPolicyProposalRef:          true,
		lenientSchedulerMapRef:                 true,
		lenientCoSLossPriority:                 true,
		lenientCoSUnitClassifierConflict:       true,
		lenientCoSForwardingClassQueue:         true,
		lenientIPsecGatewayRefs:                true,
		lenientIKEPolicyChainRef:               true,
		lenientIPsecEndpoints:                  true,
		lenientIPsecTrafficSelectors:           true,
		lenientReservedProposalSetNames:        true,
		lenientChassisClusterIdentities:        true,
		lenientChassisMonitorWeight:            true,
		lenientChassisRGStatementArity:         true,
		lenientLoginPackedStatements:           true,
		lenientLoginClassShadowsBuiltin:        true,
		lenientIPsecProposalProtocol:           true,
		lenientIPsecManualKey:                  true,
		lenientLogProfileStreamRef:             true,
		lenientDynamicAddressFeedRef:           true,
		lenientDuplicateNamedBlock:             true,
		lenientDuplicateNATRuleName:            true,
		lenientDuplicateNATRuleSetName:         true,
		lenientNATPoolAlarmThreshold:           true,
		lenientNATHostMask:                     true,
		lenientUnsupportedInterfaceStanzas:     true,
		lenientQinQVLANStack:                   true,
		lenientVLANMap:                         true,
		lenientRoutingExportRef:                true,
		lenientFRRAuthValues:                   true,
		lenientRouteFilterMatchTypes:           true,
		lenientApplicationSpecs:                true,
		lenientApplicationNameCollisions:       true,
		lenientReservedApplicationNames:        true,
		lenientFirewallFilterFamilyCollisions:  true,
		lenientFirewallFilterFamilyAnyMatches:  true,
		lenientFilterProtocols:                 true,
		lenientFilterCrossField:                true,
		lenientFilterActions:                   true,
		lenientFilterMatchValues:               true,
		lenientFlexMatch:                       true,
		lenientFilterPortExcept:                true,
		lenientFilterAddressExcept:             true,
		lenientFilterFromMatch:                 true,
		lenientFilterAddressLiterals:           true,
		lenientFilterRoutingInstanceConflict:   true,
		lenientFilterTerminalConflict:          true,
		lenientFilterDSCP:                      true,
		lenientNPTv6:                           true,
		lenientNAT64Prefix:                     true,
		lenientNATPoolOverlap:                  true,
		lenientFirewallRefs:                    true,
		lenientFlowServerTemplateRef:           true,
		lenientSamplingInstanceConflicts:       true,
		lenientSamplingInputRate:               true,
		lenientApplicationSetMembers:           true,
		lenientPolicyMatchApplications:         true,
		lenientNATMatchApplications:            true,
		lenientPolicyMatchAddressSetMembers:    true,
		lenientRibGroupRefs:                    true,
		lenientNextTableRefs:                   true,
		lenientRoutingRuleWindows:              true,
		lenientPolicyRouteMapSeq:               true,
		lenientRouteDispositionConflict:        true,
		lenientDHCPStaticBindings:              true,
		lenientWireguardPeers:                  true,
		lenientTunnelOuterFamily:               true,
		lenientIpipTunnelMode:                  true,
		lenientPolicyZoneRefs:                  true,
		lenientZoneCount:                       true,
		lenientWebManagementAuth:               true,
		lenientZoneIDCollision:                 true,
		lenientRoutingInstanceTableIDCollision: true,
		lenientAddressBookNames:                true,
		lenientAddressBookNameCollision:        true,
		lenientZoneInterfaceMembership:         true,
		lenientZoneInterfaceDefined:            true,
		lenientZoneInterfacesNonEmpty:          true,
		lenientZoneInterfacePackedTail:         true,
		lenientHostInboundTokens:               true,
		lenientDuplicateHostLocalAddress:       true,
		lenientClusterAuthKey:                  true,
		lenientDestNATAddresses:                true,
		lenientNATMatchAddressLiterals:         true,
		lenientRPMSourceAddress:                true,
		lenientRPMLinkLocalZone:                true,
		lenientRPMHTTPGetScheme:                true,
		lenientRPMRoutingInstance:              true,
		lenientBGPNeighborPeerAS:               true,
		lenientRouterID:                        true,
		lenientSNMPTrapGroup:                   true,
		lenientBridgeDomainVlanID:              true,
		lenientDDNSDuration:                    true,
		lenientPolicyTerminalAction:            true,
		lenientPolicyLogAction:                 true,
		lenientDuplicatePolicyNames:            true,
		lenientScreenProfileRefs:               true,
		lenientScreenNumeric:                   true,
		lenientScreenUnknown:                   true,
		lenientTrailingTokens:                  true,
		lenientFlowAging:                       true,
		lenientChassisRG:                       true,
		lenientVRRPGroupID:                     true,
		lenientVRRPGroupPriority:               true,
		lenientRethVRRPGroupID:                 true,
		lenientIfNameCollision:                 true,
		lenientRethMember:                      true,
		lenientReservedZoneNames:               true,
		lenientBackupRouterDst:                 true,
		lenientSecureTunnelBindIface:           true,
		lenientPolicyMatchLeaves:               true,
		lenientPolicyThenPermit:                true,
		lenientPolicyThenReject:                true,
		lenientPolicyThenDeny:                  true,
		lenientPolicyMissingMatch:              true,
		lenientPolicyValuelessMatch:            true,
		lenientPolicyCommunityRef:              true,
		lenientPolicyReservedRedistName:        true,
		lenientPolicyReservedChainName:         true,
		lenientVRRPVirtualAddress:              true,
		lenientDNATToScope:                     true,
		lenientNATMixedScope:                   true,
		lenientNATTerminalAction:               true,
		lenientInterfaceUnitAliasCollisions:    true,
		lenientEventWithinTrigger:              true,
		lenientFirewallTCPFlags:                true,
		lenientCoSNumericCodePoint:             true,
		lenientNonNumericUnit:                  true,
		lenientInterfaceUnitRef:                true,
		lenientLoginClassDeny:                  true,
	}
}
