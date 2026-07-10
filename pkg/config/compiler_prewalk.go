package config

import "fmt"

// runPreWalkGates runs the P1 "AST pre-walk" phase of config compilation —
// the contiguous SAFE first phase extracted from compileExpanded as step 1 of
// the #4406 god-orchestrator decomposition (ps-review-011 / codex-173 #4).
//
// It runs the ~22 AST-level validators/gates that must observe the
// group-expanded, inactive-pruned tree BEFORE section compilation, threads
// their warnings in execution order, and returns the FIRST gate error (strict
// paths return it; lenient paths downgrade to warnings via the opts.lenient*
// flags). It MUTATES `tree` in place via expandInterfaceRanges (#4027) — the
// unsupported-stanza gate here and compileInterfaces (P4) both must see the
// expanded members, not a phantom "interface-range" iface — and via the
// #1798 control-char sanitize on the lenient path.
//
// Behavior-preserving invariants (do NOT reorder any gate relative to
// master; the source order is observable through both the strict first-error
// slot and the lenient warning order — see the #4406 plan): the returned
// warnings slice is the exact concatenation compileExpanded previously built
// in its P3 append block, so the caller does a single
// `cfg.Warnings = append(cfg.Warnings, preWalkWarnings...)`. This phase runs
// FIRST in compileExpanded, before the base *Config skeleton (P2) and the
// section dispatch (P4). It is covered by the reusable golden-output gate in
// compile_golden_4406_test.go.
func runPreWalkGates(tree *ConfigTree, opts compileOpts) ([]string, error) {
	// #1798 free-text control-character gate. Strict (commit /
	// commit-check): hard-reject. Lenient (load / peer-sync / peer
	// display): scrub in place on this already-cloned tree and warn.
	// Runs on the group-expanded tree so values inherited via
	// apply-groups are covered, and BEFORE section compilation so the
	// lenient path's typed Config is built from the scrubbed values.
	var ctrlCharWarnings []string
	if opts.sanitizeFreeTextControlChars {
		for _, p := range sanitizeNodesControlChars(tree.Children, "") {
			ctrlCharWarnings = append(ctrlCharWarnings, fmt.Sprintf(
				"sanitized control characters in configuration value at %q (#1798)", p))
		}
	} else if err := validateNodesControlChars(tree.Children, ""); err != nil {
		return nil, err
	}

	// #1814 VRRP track-interface AST pre-walk. Runs on the group-expanded
	// tree (so apply-groups-inherited statements are covered) and BEFORE
	// section compilation so the lenient path's first-wins pruning is
	// what the compiler actually sees. Strict (commit / commit-check):
	// duplicate track-interface inside one vrrp-group hard-rejects.
	// Lenient (load / peer-sync): prune to the first + warn. Shape-only
	// warnings (nested+sibling both present, orphan priority-cost) come
	// from here too — the typed config cannot distinguish them
	// post-compile.
	trackWarnings, err := validateVRRPTrackInterfaceAST(tree.Children, "", opts.lenientVRRPTrackDuplicates)
	if err != nil {
		return nil, err
	}

	// #4288 VRRP authentication reject. The native dataplane is RFC 5798
	// VRRPv3, which REMOVED authentication (VRRPv2 had it; v3 does not). xpf
	// parses authentication-type / authentication-key
	// (compiler_interfaces.go), stores them on the VRRPGroup, and copies them
	// into the VRRP instance (pkg/vrrp/vrrp.go) — but the packet build/receive
	// path NEVER references them, so the config is inert. Silently accepting it
	// lets an operator believe adverts are authenticated when they are not: a
	// rogue host on the segment can send higher-priority adverts and hijack
	// mastership. Runs on the group-expanded, inactive-pruned tree so an
	// apply-groups-inherited auth statement is covered. Strict (commit /
	// commit-check): hard-reject so the operator is not misled into a
	// false-security posture. Lenient (load / peer-sync): warn so an
	// already-persisted or peer-synced config an older binary silently
	// accepted still boots (#1960).
	vrrpAuthWarnings, err := validateVRRPAuthenticationAST(tree.Children, "", opts.lenientVRRPAuthentication)
	if err != nil {
		return nil, err
	}

	// #1979 Layer B Tier 3: tcp-mss range AST pre-walk. tcp-mss carries its
	// MSS value in either the kind node's flat Keys[1] or a hierarchical
	// `mss` child — a dual value-location the declarative SchemaValidate
	// walker cannot express, so it stays opaque in setSchema and is
	// range-checked here on the group-expanded tree (apply-groups-inherited
	// values covered), BEFORE the snapshot builder's Layer-A coercion would
	// see it. Strict (commit / commit-check): out-of-range hard-rejects.
	// Lenient (load / peer-sync): warn + let Layer A coerce so an upgraded
	// node loading a legacy out-of-range MSS still boots.
	mssWarnings, err := validateTCPMSSRanges(tree.Children, "", opts.lenientTCPMSSRange)
	if err != nil {
		return nil, err
	}

	// #3349 security-log stream port range gate. The syslog port lives in two
	// AST locations (direct `stream port` and nested `host { port }`) that the
	// declarative SchemaValidate walker cannot express, so — like tcp-mss — it
	// is range-checked here on the group-expanded tree, BEFORE compileLog
	// swallows a bad value and silently keeps the default 514. Strict (commit
	// / commit-check): a non-numeric / out-of-range port hard-rejects. Lenient
	// (load / peer-sync): warn so an already-persisted or peer-synced config
	// still boots.
	logStreamPortWarnings, err := validateSecurityLogStreamPortsAST(tree.Children, "", opts.lenientLogStreamPort)
	if err != nil {
		return nil, err
	}

	// #3350 security-log stream tls-profile gate. `transport tls-profile <name>`
	// is parsed, validated, and stored but NEVER resolved into a *tls.Config at
	// runtime (daemon_system.go always passes nil), and there is no TLS profile
	// definition stanza to resolve it to — so a TLS syslog stream silently uses
	// the system CA roots instead of the named profile (a secure-syslog posture
	// silently downgraded, fail-open). Like the port gate this is an AST-level
	// decision under the `transport` block, so it lives here, not in
	// SchemaValidate. Strict (commit / commit-check): a present tls-profile
	// hard-rejects. Lenient (load / peer-sync): warn so an already-persisted or
	// peer-synced config still boots (the profile was never applied either way).
	logTLSProfileWarnings, err := validateSecurityLogStreamTLSProfileAST(tree.Children, "", opts.lenientLogTLSProfile)
	if err != nil {
		return nil, err
	}

	// #3420 flow-trace file path-traversal gate. The compiler stores
	// `security flow traceoptions file <name>` verbatim and NewTraceWriter
	// opens it under /var/log without rejecting an absolute path or a ".."
	// escape — a committed config can append root-written flow telemetry
	// outside the appliance log area. The filename is a single AST value
	// SchemaValidate treats as opaque, so it is checked here on the
	// group-expanded tree. Strict (commit / commit-check): a non-basename value
	// hard-rejects. Lenient (load / peer-sync): warn so an already-persisted or
	// peer-synced config still boots (NewTraceWriter refuses the unsafe path at
	// runtime, so tracing is simply disabled).
	flowTraceFileWarnings, err := validateFlowTraceFileAST(tree.Children, "", opts.lenientFlowTraceFile)
	if err != nil {
		return nil, err
	}

	// #3422 flow-trace flag / packet-filter prefix gate. The compiler copies
	// flag tokens and filter prefixes verbatim; an unparseable prefix makes
	// NewTraceWriter drop the filter (every-filter-invalid -> trace everything,
	// M01) and an unimplemented flag makes matchFlags never match (trace
	// nothing while reporting enabled, M02). Strict (commit / commit-check):
	// reject. Lenient (load / peer-sync): warn so a persisted/peer-synced value
	// still boots — the runtime now fails safe either way.
	flowTraceFilterWarnings, err := validateFlowTraceFlagsAndFiltersAST(
		tree.Children, "", opts.lenientFlowTraceFilter)
	if err != nil {
		return nil, err
	}

	// #3424 flow-trace size/files range gate. The compiler stored any positive
	// `size`/`files` integer verbatim; an absurd `size 1 files 1000000000`
	// rotates on every trace line and runs a ~1e9-iteration rename loop under
	// the writer mutex (a per-event CPU storm). Strict (commit / commit-check):
	// reject an out-of-range value. Lenient (load / peer-sync): warn so a
	// persisted/peer-synced value still boots — NewTraceWriter clamps to the
	// same bounds at runtime.
	flowTraceSizeWarnings, err := validateFlowTraceSizeFilesAST(
		tree.Children, "", opts.lenientFlowTraceSizeFiles)
	if err != nil {
		return nil, err
	}

	// #4027 interface-range expansion. Rewrites every `interfaces
	// interface-range <name> { member <if>; <shared cfg> }` stanza into its
	// member interfaces BEFORE section compilation (and before the
	// unsupported-stanza gate below, so that gate and compileInterfaces both
	// see the expanded members, not a phantom "interface-range" interface).
	// Runs on the group-expanded, inactive-pruned clone (apply-groups-
	// inherited ranges expanded; `inactive:` ranges already stripped) and
	// MUTATES the clone in place. A config with no interface-range stanza is
	// left byte-identical. See compiler_interface_range.go.
	ifaceRangeWarnings := expandInterfaceRanges(tree)

	// #2008 H9/H10 interface silent-drop gate. Runs on the group-expanded,
	// inactive-pruned tree (apply-groups-inherited stanzas covered;
	// `inactive:` stanzas already stripped upstream) and BEFORE section
	// compilation. Strict (commit / commit-check): a static `mac` override
	// or a `family inet|inet6 policer arp` — neither of which the dataplane
	// can honour — hard-rejects. Lenient (load / peer-sync): warn so an
	// already-persisted or peer-synced config that an older binary silently
	// accepted still boots (#1960 fail-closed-on-load class).
	unsupportedIfaceWarnings, err := validateUnsupportedInterfaceStanzasAST(
		tree.Children, opts.lenientUnsupportedInterfaceStanzas)
	if err != nil {
		return nil, err
	}

	// #3339 (Codex review 080 M07/M08) application / application-set name
	// collision gate. compileApplications collects applications and
	// application-sets into name-keyed maps with last-write-wins semantics — a
	// duplicate definition, an application and application-set sharing a name (an
	// explicit set overwriting the implicit set minted for a multi-term
	// application), or two terms generating the same per-term application name all
	// silently keep the last definition with no commit error, and policy
	// expansion vs the AppID catalog can then resolve the name to different
	// definitions. Strict (commit / commit-check): the first collision hard-
	// rejects. Lenient (load / peer-sync): warn so an already-persisted or
	// peer-synced config an older binary silently accepted still BOOTS (#1960 /
	// #3261). Runs on the group-expanded, inactive-pruned AST because the
	// colliding definitions are merged away by last-write-wins by the time the
	// typed maps exist — only the raw AST still carries every definition.
	appCollisionWarnings, err := validateApplicationNameCollisionsAST(
		tree.Children, opts.lenientApplicationNameCollisions)
	if err != nil {
		return nil, err
	}

	// #3884 (fable-review-161 F-030) firewall-filter cross-family name-collision
	// gate. compileFirewall folds every filter family except inet6 into ONE
	// name-keyed map (fw.FiltersInet) with an unconditional overwrite, so a
	// same-name filter under a second non-inet6 family silently replaces the
	// first — a discard filter can become a same-name accept-all (fail-open).
	// Strict (commit / commit-check): the collision hard-rejects. Lenient (load /
	// peer-sync): warn so an already-persisted or peer-synced config an older
	// binary silently accepted still BOOTS (#1960 / #3261). Runs on the group-
	// expanded, inactive-pruned AST because the colliding definitions are merged
	// away by last-write-wins by the time fw.FiltersInet exists — only the raw
	// AST still carries every family's definition.
	fwFilterFamilyWarnings, err := validateFirewallFilterFamilyCollisionsAST(
		tree.Children, opts.lenientFirewallFilterFamilyCollisions)
	if err != nil {
		return nil, err
	}

	// #4296 firewall-filter family-any specific-match gate. #4287 dual-compiles a
	// `family any` filter into BOTH the inet and inet6 pools; a family-specific
	// match under `family any` (a v4/v6 source/destination-address literal or a
	// per-family icmp-type/icmp-code) is then dual-compiled verbatim and can never
	// match the other family — an imperfect v6 under-block. Strict (commit /
	// commit-check): the first such match hard-rejects, pointing at family
	// inet/inet6. Lenient (load / peer-sync): warn so an already-persisted or
	// peer-synced config an older binary silently accepted still BOOTS (#1960).
	// Runs on the group-expanded, inactive-pruned AST for the same reason as the
	// collision gate above — only the raw AST still carries the family-any match.
	fwFilterFamilyAnyWarnings, err := validateFirewallFilterFamilyAnyMatchesAST(
		tree.Children, opts.lenientFirewallFilterFamilyAnyMatches)
	if err != nil {
		return nil, err
	}

	// #3096: the #3079 interim NAT rule-set scope reject is LIFTED. A
	// `security nat {source|destination|static}` rule-set whose `from`/`to`
	// clause scopes traffic by `interface` or `routing-instance` is now
	// CAPTURED by the compiler (collectNATScopes / parseNATMatchScopes,
	// compiler_nat.go), carried on the typed NATRuleSet / StaticNATRuleSet,
	// plumbed through the userspace snapshot, and ENFORCED per-flow in the
	// dataplane NAT match path (nat/source.rs, nat/destination.rs,
	// nat/static_nat.rs) — so the scope restricts matched traffic to the
	// named ingress/egress interface or routing-instance instead of being
	// silently widened to match-any. The validateNATRuleSetScopeAST gate and
	// its lenientNATRuleSetScope opt are removed.
	//
	// #3444 caveat: this enforcement covers the `from` scope for all three
	// NAT kinds AND the `to` scope for SOURCE NAT (source.rs reads to_*).
	// DESTINATION NAT has only a `from` clause (Junos) — the DNAT snapshot /
	// runtime model no `to_*`, so a DNAT `to` scope is rejected at commit by
	// validateDNATRuleSetToScopeAST below rather than enforced.

	// #2933 secure-tunnel bind-interface alias-collision gate. Two VPNs that
	// bind two DISTINCT bind-interface strings deriving the SAME XFRM if_id
	// (e.g. `bind-interface st0` and `bind-interface st0.0`, both if_id 1 via
	// XFRMIfNameAndID) committed cleanly but collide at apply time — only one
	// xfrm device can carry the if_id, so the #2929 routing guard refuses to
	// create EITHER and both tunnels go down with a journal ERROR. Runs on the
	// group-expanded, inactive-pruned tree so an apply-groups-inherited
	// bind-interface is caught. Strict (commit / commit-check): hard-reject
	// naming the offending bind-interface strings, their VPNs, and the shared
	// if_id. Lenient (load / peer-sync): warn so an already-persisted or
	// peer-synced config still boots (#1960) — the #2929 routing guard stays
	// the runtime backstop.
	bindIfaceWarnings, err := validateSecureTunnelBindInterfaceAST(
		tree.Children, opts.lenientSecureTunnelBindIface)
	if err != nil {
		return nil, err
	}

	// #4098 IPsec traffic-selector injection gate. `security ipsec vpn
	// <name> traffic-selector <ts> local-ip / remote-ip` are free-form 1-arg
	// strings the IPsec renderer interpolates into the swanctl.conf
	// children{} block as `local_ts = <value>` / `remote_ts = <value>`.
	// Unlike the sibling child SA name they were emitted raw, so a value
	// carrying a materialized `\n` (lexer.go) injected an arbitrary
	// `key = value` line — `updown = <script>` runs as ROOT under charon, or
	// an `esp_proposals` override silently rewrites the crypto posture — into
	// the generated config. Runs on the group-expanded, inactive-pruned tree
	// so an apply-groups-inherited selector is covered and an inactive VPN is
	// ignored; it inspects EVERY value token (both parser shapes + a
	// bracketed list, #2419) so a malicious token the typed compiler's
	// nodeVal would drop is still caught. Strict (commit / commit-check):
	// hard-reject naming the VPN, selector, leaf, and reason. Lenient (load /
	// peer-sync): warn so an already-persisted or peer-synced config still
	// boots (#1960) — the render belt (sanitizeSwanctlValue) keeps the value
	// inert. Mirrors validateSecureTunnelBindInterfaceAST.
	ipsecTSWarnings, err := validateIPsecTrafficSelectorsStrict(
		tree.Children, opts.lenientIPsecTrafficSelectors)
	if err != nil {
		return nil, err
	}

	// #3113 security-policy unsupported-match-leaf gate. A policy whose
	// `match` clause carries a leaf the compiler does not enforce (e.g.
	// `dynamic-application`, `url-category`, `source-identity`) committed
	// cleanly but had that criterion SILENTLY DROPPED — compilePolicy's
	// `match` switch handles only source/destination address, excluded, and
	// application; the set-schema and schema_walk ignore unknown keywords.
	// Dropping a match criterion WIDENS the policy into a broad L3/L4
	// permit/deny the operator never intended — a fail-open. Runs on the
	// group-expanded, inactive-pruned tree so an apply-groups-inherited
	// match leaf is caught and an inactive policy is ignored. Strict
	// (commit / commit-check): hard-reject naming the policy scope, the
	// policy, and the unsupported leaf. Lenient (load / peer-sync): warn so
	// an already-persisted or peer-synced config still boots (#1960) — the
	// leaf stays dropped, now flagged. Full match-type support is a deferred
	// follow-up.
	policyMatchWarnings, err := validatePolicyMatchLeavesStrict(
		tree.Children, opts.lenientPolicyMatchLeaves)
	if err != nil {
		return nil, err
	}

	// #3114: reject a security-policy `then permit <child>` carrying an
	// unsupported action modifier (application-services / UTM / IDP / AppFW
	// / SSL-proxy, firewall-authentication, tunnel). compilePolicy's `then`
	// switch `permit` arm sets pol.Action = PolicyPermit and never inspects
	// the children, so the modifier is silently dropped — turning a
	// permit-only-with-inspection rule into an unconditional permit, a
	// fail-open. Runs on the group-expanded, inactive-pruned tree so an
	// apply-groups-inherited child is caught and an inactive policy is
	// ignored. Strict (commit / commit-check): hard-reject naming the
	// policy scope, the policy, and the unsupported child. Lenient (load /
	// peer-sync): warn so an already-persisted or peer-synced config still
	// boots (#1960) — the child stays dropped, now flagged. Full
	// then-permit service-chain support is a deferred follow-up.
	policyThenPermitWarnings, err := validatePolicyThenPermitStrict(
		tree.Children, opts.lenientPolicyThenPermit)
	if err != nil {
		return nil, err
	}

	// #3115: reject any policy whose `then reject` arm carries a child the
	// compiler does not enforce (a reject `profile <name>` custom response,
	// or a packet-type reject like `tcp-reset`). compilePolicy's `then`
	// switch `reject` arm sets pol.Action = PolicyReject and never inspects
	// the children, so the modifier is silently dropped — the configured
	// custom reject response is inert and the operator cannot tell from
	// commit. Sibling of the #3114 then-permit gate above; same group-
	// expanded / inactive-pruned tree, same strict-with-lenient (#1960)
	// doctrine. Reject-profile support is a deferred follow-up.
	policyThenRejectWarnings, err := validatePolicyThenRejectStrict(
		tree.Children, opts.lenientPolicyThenReject)
	if err != nil {
		return nil, err
	}

	// #3141: a flat-set `then deny log session-init` collapses the
	// log/count modifier onto the deny node (Keys=["deny","log",
	// "session-init"]) instead of nesting a sibling `then log` node.
	// compilePolicy's `then` switch `deny` arm used to read only t.Name()
	// and silently dropped the collapsed modifier, so deny-with-logging
	// committed but never logged. #3141 WIRES the legitimate log/count
	// modifiers (applyCollapsedDenyModifiers); this gate rejects any
	// REMAINING collapsed deny modifier the compiler cannot enforce.
	// Sibling of the #3114 then-permit / #3115 then-reject gates above;
	// same group-expanded / inactive-pruned tree, same strict-with-lenient
	// (#1960) doctrine.
	policyThenDenyWarnings, err := validatePolicyThenDenyStrict(
		tree.Children, opts.lenientPolicyThenDeny)
	if err != nil {
		return nil, err
	}

	// #3044: reject a security policy whose `match` clause omits a required
	// Junos dimension (source-address, destination-address, application) or
	// omits the `match` block entirely. compilePolicy fills each match slice
	// only when the leaf is present, and the userspace dataplane treats an
	// empty slice as match-ANY, so a partial policy silently widens to
	// traffic the operator did not intend — a fail-open for permit, an
	// over-broad block for deny. On Junos such a policy cannot commit. Runs
	// on the group-expanded, inactive-pruned tree so an apply-groups-
	// inherited dimension counts and an inactive policy is ignored. Strict
	// (commit / commit-check): hard-reject naming the policy scope, the
	// policy, and every missing dimension. Lenient (load / peer-sync): warn
	// so an already-persisted or peer-synced config still boots (#1960) — the
	// policy keeps its match-any-for-missing compilation, now flagged. A
	// missing dimension is distinct from an explicit `any` (Junos parity).
	policyMissingMatchWarnings, err := validatePolicyRequiredMatchStrict(
		tree.Children, opts.lenientPolicyMissingMatch)
	if err != nil {
		return nil, err
	}

	// #3444: reject a `security nat destination rule-set <name> to ...`
	// scope. A Junos destination-NAT rule-set has only a `from` clause —
	// DNAT translates the destination on inbound, so there is no egress
	// context yet. xpf briefly advertised a `to` scope under the DNAT
	// rule-set and Cartesian-expanded it onto each NATRuleSet, but the
	// userspace snapshot builder and the Rust DNAT runtime model ONLY the
	// `from` clause, so the `to` scope was silently dropped and the
	// translation applied regardless of the declared destination context.
	// Runs on the group-expanded, inactive-pruned tree so an apply-groups-
	// inherited `to` is caught and an inactive rule-set is ignored. Strict
	// (commit / commit-check): hard-reject naming the rule-set. Lenient
	// (load / peer-sync): warn so an already-persisted or peer-synced
	// config still boots (#1960) — the `to` stays ignored, now flagged.
	dnatToScopeWarnings, err := validateDNATRuleSetToScopeAST(
		tree.Children, opts.lenientDNATToScope)
	if err != nil {
		return nil, err
	}

	// #4881 NAT rule-set mixed-scope-kind gate. A single `from` / source-`to`
	// / static-`from` clause that mixes scope KINDS (zone + interface +
	// routing-instance) is OR-expanded by the #3096 Cartesian product into
	// multiple typed rule-sets — matching EITHER scope, which WIDENS the NAT
	// match beyond the intended boundary and contradicts Junos' one-kind-per-
	// clause rule (and the in-tree "AND-ed fail-closed" comment, which never
	// happens). Runs on the group-expanded, inactive-pruned tree so an
	// apply-groups-inherited mixed clause is caught. Strict (commit /
	// commit-check): hard-reject naming the clause + mixed kinds. Lenient (load
	// / peer-sync): warn so an already-persisted or peer-synced config an older
	// binary accepted still boots (#1960).
	natMixedScopeWarnings, err := validateNATRuleSetMixedScopeAST(
		tree.Children, opts.lenientNATMixedScope)
	if err != nil {
		return nil, err
	}

	var warnings []string
	warnings = append(warnings, ctrlCharWarnings...)
	warnings = append(warnings, trackWarnings...)
	warnings = append(warnings, vrrpAuthWarnings...)
	warnings = append(warnings, mssWarnings...)
	warnings = append(warnings, logStreamPortWarnings...)
	warnings = append(warnings, logTLSProfileWarnings...)
	warnings = append(warnings, flowTraceFileWarnings...)
	warnings = append(warnings, flowTraceFilterWarnings...)
	warnings = append(warnings, flowTraceSizeWarnings...)
	warnings = append(warnings, ifaceRangeWarnings...)
	warnings = append(warnings, unsupportedIfaceWarnings...)
	warnings = append(warnings, appCollisionWarnings...)
	warnings = append(warnings, fwFilterFamilyWarnings...)
	warnings = append(warnings, fwFilterFamilyAnyWarnings...)
	warnings = append(warnings, bindIfaceWarnings...)
	warnings = append(warnings, ipsecTSWarnings...)
	warnings = append(warnings, policyMatchWarnings...)
	warnings = append(warnings, policyThenPermitWarnings...)
	warnings = append(warnings, policyThenRejectWarnings...)
	warnings = append(warnings, policyThenDenyWarnings...)
	warnings = append(warnings, policyMissingMatchWarnings...)
	warnings = append(warnings, dnatToScopeWarnings...)
	warnings = append(warnings, natMixedScopeWarnings...)
	return warnings, nil
}
