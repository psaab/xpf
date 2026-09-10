package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateApplicationSetMembersStrict hard-rejects an `applications
// application-set <set>` (Finding B, #2217) whose member references neither a
// defined application (user-defined or junos-* predefined), nor a defined
// nested application-set.
//
// ValidateConfig warned on a POLICY referencing an unknown application but
// never validated the MEMBERS of an application-set. A policy referencing a
// defined application-set whose member is undefined passed validation with no
// warning; at the dataplane that member simply never matches, so the policy
// silently fails to match the intended traffic (an effective no-op term,
// fail-OPEN). This gate validates each set's membership at commit.
//
// Reuses ExpandApplicationSet, the SAME resolver the compiler and the strict
// application-spec gate already use to expand a set: it recurses nested sets
// (max depth 3), resolves each leaf member through ResolveApplication
// (user-defined first, then the junos-* predefined table), and returns an
// error on the first dangling/over-nested member — so no new divergent
// definedness table is introduced. Sets are iterated in sorted name order for
// a deterministic first-error.
//
// IMPLICIT sets minted for multi-term user applications (compileApplications
// stores `applications application <name> term ...` as an ApplicationSet whose
// members are the generated per-term application names) are skipped: their
// members are synthesized by the compiler, always resolve, and are not
// operator-authored references — validating them would only risk a false
// reject on a compiler-internal name shape.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientApplicationSetMembers) so an already-persisted or peer-
// synced config carrying a dangling member still BOOTS (#1960); the dataplane
// drops the unresolved member independently, so it is already inert. Commit /
// commit-check stay strict. Mirrors validateApplicationSpecsStrict.
func validateApplicationSetMembersStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	sets := cfg.Applications.ApplicationSets
	if len(sets) == 0 {
		return nil
	}
	// An implicit set minted for a multi-term application shares its name with
	// a user application term-bundle; its members are compiler-synthesized, not
	// operator references. Skip those.
	isImplicitTermSet := func(setName string) bool {
		set := sets[setName]
		if set == nil {
			return false
		}
		for _, member := range set.Applications {
			// A synthesized term application is named "<parent>-<term>"; the
			// reliable signal that this is a compiler-minted set (rather than an
			// operator `application-set`) is that EVERY member is a user
			// application whose name is prefixed with the set name plus "-". A
			// hand-authored application-set members reference unrelated app names.
			if _, isUserApp := cfg.Applications.Applications[member]; !isUserApp {
				return false
			}
			if !strings.HasPrefix(member, setName+"-") {
				return false
			}
		}
		return true
	}
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		set := sets[name]
		if set == nil || len(set.Applications) == 0 || isImplicitTermSet(name) {
			continue
		}
		if _, err := ExpandApplicationSet(name, &cfg.Applications); err != nil {
			return fmt.Errorf(
				"applications application-set %q: %w (define the missing "+
					"application / application-set or fix the member name — a "+
					"policy matching this set would otherwise silently fail to "+
					"match the intended traffic)", name, err)
		}
	}
	return nil
}

// validateApplicationSpecsStrict hard-rejects a user-defined application
// (`set applications application <name> ...`) whose destination-port /
// source-port is malformed (not a valid numeric port, port range, or known
// service name, out of 1..65535, or an inverted low>high range) or whose
// protocol token is not a known name, a RESOLVABLE junos-* alias (one the
// dataplane's appid.ProtocolNumber actually knows — #3150), is MISSING entirely
// (a protocol-less port-only application the matcher cannot represent — #3109),
// or a 0..255 number
// (#2142) — but ONLY for applications that are
// actually REFERENCED by a security policy or a source/destination-NAT rule's
// `match application` (#2187), or for ALL applications when
// `services application-identification` is enabled (every app then compiles
// into the app-id catalog). Such a spec is accepted by ValidateConfig as a
// WARNING only; commit succeeds, the dataplane app-id compiler records the
// AppID name and then `continue`s past the unparsable port (a never-match
// AppID), and a policy referencing the application fails CLOSED on a permit
// rule or falls through OPEN on a deny rule. Failing the spec at commit turns
// that silent semantic break into an operator-visible error.
//
// The referenced-only scope is deliberate (the issue's explicit
// referenced-vs-unreferenced distinction): an UNREFERENCED, app-id-disabled
// application definition compiles into nothing the dataplane can match against,
// so its malformed spec cannot break a live policy decision — it stays a
// warning so an operator iterating on a not-yet-wired application library is
// not blocked, and so existing configs that carry an unreferenced app with a
// port form the policy matcher cannot represent (e.g. a `source-port 0-N`
// range, which Rust parse_port_spec rejects on low==0) still commit. The moment
// such an app is referenced by a policy, or app-id is turned on, the gate
// engages.
//
// It reuses validatePortSpec for ports. For the protocol it uses
// filterProtocolResolvable (the #2124/#2175 appid.ProtocolNumber mirror) rather
// than the lenient validateProtocol: validateProtocol blanket-accepts any
// "junos-" prefix, so a referenced app with `protocol junos-foobar` would commit
// cleanly while the dataplane's appid.ProtocolNumber rejects it, disarming the
// userspace policy capability gate (a commit/apply split — #3150). Using the
// same authority the dataplane uses keeps commit and apply in agreement (the
// dataplane's #2124 capability gate stays the runtime backstop). Iteration is
// sorted by application name so the first-reported error is deterministic across
// runs (Go map order is randomized).
func validateApplicationSpecsStrict(cfg *Config) error {
	if cfg == nil || len(cfg.Applications.Applications) == 0 {
		return nil
	}
	toCheck := applicationsToValidateStrict(cfg)
	if len(toCheck) == 0 {
		return nil
	}
	names := make([]string, 0, len(toCheck))
	for name := range toCheck {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		app := cfg.Applications.Applications[name]
		if app == nil {
			continue
		}
		if err := validatePortSpec(app.DestinationPort); err != nil {
			return fmt.Errorf("application %q: destination-port: %w", name, err)
		}
		if err := validatePortSpec(app.SourcePort); err != nil {
			return fmt.Errorf("application %q: source-port: %w", name, err)
		}
		// #3109: a referenced application with NO protocol is unrepresentable by
		// the userspace matcher, which keys every term on a protocol number
		// (appid.ProtocolNumber) plus the port — a port has no meaning without a
		// protocol. compileApplications defaults a protocol-less application to the
		// empty protocol (compiler_applications.go: `protocols = []string{""}`),
		// which the runtime then cannot represent on EITHER side: the Go capability
		// gate (pkg/dataplane/userspace/capabilities.go
		// normalizeUserspaceApplicationProtocol == "" → expandUserspacePolicyApplications
		// ok=false) trips #2124's refuse-to-arm, which sets ForwardingSupported=false
		// for the WHOLE userspace dataplane — one protocol-less app silently disables
		// security-policy enforcement for the entire config (it falls to the kernel
		// slow path, a system-level fail-OPEN); and the Rust snapshot builder rejects
		// the snapshot with SnapshotIntegrityError::UnrepresentableApplicationProtocol
		// (parse_protocol("") => None). Junos requires `protocol` for a usable
		// application, so the Junos-parity fix is to reject the protocol-less spec at
		// COMMIT (the same strict-at-commit / #1960 fail-closed doctrine as the #3150
		// unresolvable-protocol case below and the #2142 malformed-port case above).
		// The blast radius of a NEW config is now one NAMED application caught at
		// commit instead of a silent whole-dataplane disable at apply. On the
		// tolerant load / peer-sync path the call site (compiler.go,
		// lenientApplicationSpecs) downgrades this to a warning so an
		// already-persisted or older-peer-synced config still BOOTS (no-brick).
		//
		// IMPORTANT (truthful caveat, see #3261): the #2124 runtime gate does NOT
		// isolate this to one policy. deriveUserspaceCapabilities
		// (pkg/dataplane/userspace/capabilities.go) is coarse — ANY policy whose
		// application is unrepresentable sets ForwardingSupported=false for the
		// WHOLE userspace dataplane, which disarms userspace forwarding and falls
		// back to the kernel slow path (a system-level fail-OPEN). So on the lenient
		// path a single protocol-less app STILL disables enforcement globally. This
		// strict commit gate is the real fix: it keeps such an app from ever being
		// committed. Per-policy fail-closed isolation of the lenient/HA-sync path is
		// design-sensitive (it conflicts with the #2124 whole-snapshot-reject
		// fail-closed family — term-dropping is fail-open for deny rules) and is
		// tracked separately in #3261.
		if app.Protocol == "" {
			// #4410 (F4): a protocol-less application that ALSO carries an
			// icmp-type / icmp-code constraint gets a targeted hint naming that
			// constraint. An operator who set `icmp-type <n>` (or `icmp-code <n>`)
			// but omitted `protocol` almost certainly meant `protocol icmp` (or
			// icmpv6) — an ICMP type/code is meaningful only on an ICMP protocol
			// (see the protocolIsICMPFamily gate below for the protocol-present
			// case). The generic "no protocol" message ignored the icmp-type they
			// had already typed; naming it turns the reject into an actionable
			// "you set icmp-type N — add `protocol icmp`/`icmpv6`" instead of a
			// bare "set a protocol".
			icmpHint := ""
			if desc := icmpConstraintDesc(app); desc != "" {
				icmpHint = fmt.Sprintf(
					" (this application sets %s but no protocol; an ICMP "+
						"type/code constraint is meaningful only on `protocol icmp` "+
						"or `protocol icmpv6` — add one of those)",
					desc)
			}
			return fmt.Errorf(
				"application %q: no protocol specified; an application referenced by "+
					"a security policy or NAT rule (or any application when "+
					"`services application-identification` is enabled) must set "+
					"`protocol` (e.g. tcp/udp/icmp/icmpv6/gre, a junos-* alias such "+
					"as junos-ping, or a numeric value 0-255). The userspace matcher "+
					"keys on protocol+port and cannot represent a protocol-less "+
					"application — accepting it would disarm the userspace dataplane "+
					"for the whole config (the referencing policy's enforcement falls "+
					"to the kernel slow path)%s",
				name, icmpHint)
		}
		// #3150: resolve the protocol against the SAME authority the dataplane
		// uses (appid.ProtocolNumber, mirrored by filterProtocolResolvable) — NOT
		// the lenient validateProtocol, which blanket-accepts any "junos-" prefix.
		// validateProtocol would commit `protocol junos-foobar` cleanly while
		// appid.ProtocolNumber rejects it, so the userspace policy capability gate
		// (pkg/dataplane/userspace) then disarms — a commit-succeeds / apply-fails
		// split. filterProtocolResolvable accepts only the concrete junos-* aliases
		// the catalog knows (e.g. junos-ping, junos-tcp-any), real protocol names,
		// and 0..255 numbers, so a referenced app whose protocol the dataplane
		// cannot represent is rejected at commit instead.
		if !filterProtocolResolvable(app.Protocol) {
			return fmt.Errorf(
				"application %q: unknown protocol %q (use a protocol name such as "+
					"tcp/udp/icmp/icmpv6/gre/esp/ah/sctp/ospf, a resolvable junos-* "+
					"alias such as junos-ping/junos-tcp-any, or a numeric value "+
					"0-255 — the dataplane resolves protocols via appid.ProtocolNumber "+
					"and cannot represent an arbitrary junos-* token, so accepting it "+
					"would commit cleanly but fail to arm the referencing policy)",
				name, app.Protocol)
		}
		// #3373: a source-port/destination-port constraint is only meaningful on a
		// port-bearing transport (TCP/UDP, protocolIsPortBearing). The protocol is already known
		// resolvable here (filterProtocolResolvable passed above), so a port on any
		// OTHER protocol — icmp/icmpv6/gre/ospf/esp/ah/vrrp/igmp/pim/ip-in-ip — is a
		// silent operator error: the userspace matcher (userspace-dp src/policy.rs)
		// indexes every application term by protocol number and keys port terms on
		// src_port/dst_port. A non-port protocol presents no destination port, so a
		// destination-port term never matches (a deny fails OPEN, a permit fails
		// CLOSED). ICMP/ICMPv6 are the exception on the SOURCE side:
		// parse_flow_ports presents the query Identifier as src_port, so a
		// source-port term matches whichever senders choose that Identifier
		// (#9525). On the tolerant path config.ApplicationReferenceMatchDrops makes
		// the userspace expansion refuse a referencing policy either way. Junos does not couple ports to non-port
		// protocols, so reject at COMMIT (the same strict-at-commit / #1960
		// fail-closed doctrine as the protocol-less #3109 and unresolvable-protocol
		// #3150 cases above). The call site downgrades this to a warning on the
		// tolerant load / peer-sync path (compiler.go, lenientApplicationSpecs) so an
		// already-persisted or older-peer-synced config still BOOTS.
		if !protocolIsPortBearing(app.Protocol) {
			if port := app.DestinationPort; port != "" {
				return fmt.Errorf(
					"application %q: destination-port %q is set on protocol %q, which "+
						"does not carry L4 ports — source-port/destination-port are valid "+
						"only on tcp/udp (a non-port protocol presents no destination port "+
						"to the dataplane, so the term would never match; remove the port or "+
						"change the protocol)",
					name, port, app.Protocol)
			}
			if port := app.SourcePort; port != "" {
				return fmt.Errorf(
					"application %q: source-port %q is set on protocol %q, which does "+
						"not carry L4 ports — source-port/destination-port are valid only "+
						"on tcp/udp (for icmp/icmpv6 the dataplane compares a source-port "+
						"term with the ICMP query Identifier, a value the sender chooses, so "+
						"the term would match only senders that pick it; on any other "+
						"non-port protocol it would never match; remove the port or change "+
						"the protocol)",
					name, port, app.Protocol)
			}
		}
		// #3320: an application inactivity-timeout / timeout that did not parse to
		// a valid integer in [1, 86400] seconds (non-numeric like "thirty", a unit
		// suffix like "30s", a negative, or an out-of-range integer) was SILENTLY
		// dropped by compileApplications (the strconv.Atoi error was ignored),
		// leaving InactivityTimeout at its zero default — which the userspace
		// snapshot serializer treats as "use the global per-protocol timeout"
		// (pkg/dataplane/userspace/capabilities.go clampNonNegU32). The operator's
		// intent to age a sensitive application early is silently lost, with no
		// commit error and no log. compileApplications records the offending raw
		// token in app.UnknownTimeouts (mirroring UnknownActions / UnknownFlexMatch
		// for the other fail-open gates); reject the first one here so the silent
		// drop becomes an operator-visible commit error. Junos rejects a
		// non-integer / out-of-range inactivity-timeout at commit. Strict on the
		// commit / commit-check path; the call site (compiler.go,
		// lenientApplicationSpecs) downgrades this to a warning on the tolerant
		// load / peer-sync path so an already-persisted or older-peer-synced config
		// carrying a bad timeout still BOOTS (#1960 no-brick) — the dataplane
		// already falls back to the global timeout for it.
		if len(app.UnknownTimeouts) > 0 {
			return fmt.Errorf(
				"application %q: invalid inactivity-timeout/timeout %q; must be an "+
					"integer number of seconds in %d..%d (a non-numeric, out-of-range, "+
					"or unit-suffixed value is silently dropped and the application "+
					"falls back to the global per-protocol timeout instead of the "+
					"configured one)",
				name, app.UnknownTimeouts[0], appTimeoutMin, appTimeoutMax)
		}
		// #3348: a malformed icmp-type / icmp-code (non-integer or outside
		// 0..255). The schema range-validates the TOP-LEVEL application leaves at
		// commit-check, but an inline `term` is opaque to the schema walk
		// (children:nil), so a bad inline icmp-type would otherwise be silently
		// dropped by parseICMPTypeCode — leaving the term UNCONSTRAINED (matching
		// EVERY ICMP type), a fail-open widening that is the exact inverse of this
		// issue's fix. compileApplications records the raw token in app.UnknownICMP
		// (mirroring UnknownTimeouts); reject the first one here so the silent
		// widening becomes an operator-visible commit error. Strict on the
		// commit / commit-check path; the call site (compiler.go,
		// lenientApplicationSpecs) downgrades it to a warning on the tolerant
		// load / peer-sync path (#1960 no-brick).
		if len(app.UnknownICMP) > 0 {
			return fmt.Errorf(
				"application %q: invalid icmp-type/icmp-code %q; must be an integer "+
					"in 0..255 (a non-numeric or out-of-range value is silently dropped "+
					"and leaves the application matching EVERY ICMP type instead of the "+
					"intended one)",
				name, app.UnknownICMP[0])
		}
		// #3348: an icmp-type/icmp-code constraint is only meaningful on an
		// ICMP/ICMPv6 protocol. The userspace matcher keys icmp_constraints
		// under the ICMP protocol number (userspace-dp policy.rs), and the
		// pkg/policymatch simulator only consults app.ICMPType when the query
		// protocol is ICMP/ICMPv6 — so a type/code on tcp/udp/gre/... compiles a
		// term that can never match (fail-open for a deny rule, fail-closed for a
		// permit rule), the same #3373 hazard as a port on a non-port protocol.
		// Junos couples icmp-type/code to an ICMP application, so reject at COMMIT
		// (strict-at-commit / #1960 fail-closed). The call site downgrades to a
		// warning on the tolerant load / peer-sync path.
		if (app.ICMPType != nil || app.ICMPCode != nil) && !protocolIsICMPFamily(app.Protocol) {
			return fmt.Errorf(
				"application %q: icmp-type/icmp-code is set on protocol %q, which is "+
					"not an ICMP protocol; an ICMP type/code constraint is valid only on "+
					"icmp/icmpv6 (or the junos-ping/junos-pingv6/junos-icmp-all aliases, "+
					"or protocol number 1/58) — on any other protocol the term can never "+
					"match (remove the constraint or change the protocol)",
				name, app.Protocol)
		}
		// A code with no type leaves the matcher constraining the code while
		// ignoring the type (pkg/policymatch matchSingleApp checks ICMPCode
		// independently of ICMPType), an ambiguous half-constraint Junos does not
		// allow. Require a type whenever a code is set.
		if app.ICMPCode != nil && app.ICMPType == nil {
			return fmt.Errorf(
				"application %q: icmp-code is set without icmp-type; an ICMP code is "+
					"meaningful only together with a type (set icmp-type as well, or "+
					"remove icmp-code)",
				name)
		}
	}
	return nil
}

// validateApplicationSyntaxStrict hard-rejects SYNTACTIC errors in a
// user-defined application definition that the typed-schema walk cannot reach:
// an unrecognized leaf inside an opaque inline `term { ... }` (#3352), an
// `alg` name xpf does not support (#3353), an unrecognized token directly on
// the application body (#6524), and an unrecognized member statement inside an
// opaque `application-set { ... }` body (#3890).
//
// Unlike validateApplicationSpecsStrict — whose port / protocol / icmp / timeout
// checks are SEMANTIC and deliberately scoped to REFERENCED applications (an
// unreferenced malformed app cannot break a live policy decision, so it stays a
// warning so an operator iterating on a not-yet-wired application library is not
// blocked, see that function's doc) — these two checks run over EVERY
// user-defined application, referenced or not. They are grammar / enum
// violations (the config names a statement or an ALG that does not exist), the
// same class Junos rejects at commit regardless of whether the application is
// wired into a policy; deferring them until the app is referenced would let a
// typo'd term-leaf silently widen a term, or a bogus `alg` silently no-op, from
// the moment it is defined. The map iterated is cfg.Applications.Applications,
// which holds ONLY user-defined applications and the per-term applications they
// generate (`<parent>-<term>`); PREDEFINED junos-* applications (junos-rtsp /
// junos-h323 / junos-pptp, which legitimately use ALGs outside the supported
// set) are owned by the predefined table and are never in this map, so they are
// never reached by the `alg` check. Iteration is sorted by name so the
// first-reported error is deterministic.
//
// Strict on the commit / commit-check path; the call site (compiler.go,
// lenientApplicationSpecs) downgrades a returned error to a warning on the
// tolerant load / peer-sync path so an already-persisted or older-peer-synced
// config still BOOTS (#1960 no-brick).
func validateApplicationSyntaxStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Applications.Applications))
	for name := range cfg.Applications.Applications {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		app := cfg.Applications.Applications[name]
		if app == nil {
			continue
		}
		// #3352: an unrecognized leaf inside an inline `term { ... }`. The term
		// subtree is an opaque `args:1` schema leaf (children:nil), so the
		// SchemaValidate walk never reaches inside it and a typo'd leaf (e.g.
		// `destination-poort 22`) was silently dropped along with its value —
		// the term kept only its remaining constraints (e.g. `protocol tcp`) and
		// a narrow permit/deny term widened to all-protocol (all-TCP), with no
		// commit error. parseApplicationTerms records the offending token on
		// UnknownTermLeaves (mirroring UnknownTimeouts / UnknownICMP); reject the
		// first one so the silent match-widening becomes an operator-visible
		// commit error.
		// #6564 member 9: a RECOGNIZED value-taking leaf with NO value. Worded
		// separately from UnknownTermLeaves above because the keyword IS
		// supported — calling it an "unknown statement" would send the operator
		// looking for a typo that is not there. The consequence is the same
		// fail-open: the constraint is dropped and the term widens.
		// #8339: the DIRECT-body twin of the check below. The term path has
		// refused this since #6564; the direct body accepted it and matched
		// every port. Ordered before the term check only so the two read as a
		// pair; an application cannot populate both.
		if len(app.IncompleteDirectLeaves) > 0 {
			return fmt.Errorf(
				"application %q: statement %q is missing its value; the "+
					"statement is dropped along with the constraint it was meant to "+
					"impose, WIDENING the application to match more than intended "+
					"(e.g. `protocol tcp destination-port` with no port matches "+
					"EVERY TCP port)",
				name, app.IncompleteDirectLeaves[0])
		}
		if len(app.IncompleteTermLeaves) > 0 {
			return fmt.Errorf(
				"application %q: `term` statement %q is missing its value; the "+
					"statement is dropped along with the constraint it was meant to "+
					"impose, widening the term to match more than intended (e.g. "+
					"`protocol tcp destination-port` with no port matches EVERY TCP port)",
				name, app.IncompleteTermLeaves[0])
		}
		if len(app.UnknownTermLeaves) > 0 {
			return fmt.Errorf(
				"application %q: unknown statement %q inside `term`; a custom "+
					"application term accepts only protocol / source-port / "+
					"destination-port / inactivity-timeout / timeout / icmp-type / "+
					"icmp-code / alg (an unrecognized leaf is silently dropped along "+
					"with its value, widening the term to match more than intended)",
				name, app.UnknownTermLeaves[0])
		}
		// #6524: an unrecognized token directly on the application body. The
		// application body is an opaque `args:1` schema leaf whose three match
		// leaves (protocol / destination-port / source-port) are the only ones
		// neither typed nor `scalar: true`, so no arity gate engages and the
		// SchemaValidate walk accepts any trailing token. Two forms reach here,
		// both of which were silently dropped before #6524 and both of which
		// WIDEN the application (an unset port matches EVERY port, so a permit
		// over-permits and a deny under-matches):
		//
		//   - a bracketed list on a single-valued leaf (`protocol [ tcp udp ]`,
		//     `destination-port [ 22 23 ]`) — a direct application body takes
		//     one protocol and one port, and Application.Protocol /
		//     .DestinationPort are single fields; multi-valued matching is what
		//     `term` sub-blocks are for;
		//   - a typo'd leaf keyword (`destination-poort 8080`).
		//
		// applicationDirectLeaves records the offending token on
		// UnknownDirectLeaves (mirroring UnknownTermLeaves / UnknownMembers);
		// reject the first one so the silent widening becomes an
		// operator-visible commit error. Strict on the commit / commit-check
		// path; the call site downgrades it to a warning on the tolerant load /
		// peer-sync path (#1960 no-brick).
		if len(app.UnknownDirectLeaves) > 0 {
			return fmt.Errorf(
				"application %q: unknown statement %q in the application body; a "+
					"custom application accepts only protocol / source-port / "+
					"destination-port / inactivity-timeout / timeout / icmp-type / "+
					"icmp-code / alg / description / term. Every one of those takes a "+
					"SINGLE value except `description`, whose unquoted multi-word tail "+
					"is absorbed when it trails the chain. "+
					"The token is silently dropped, which changes what the application "+
					"matches: dropping a port or icmp-type constraint WIDENS it (an "+
					"unset port matches every port), while dropping an alternative from "+
					"a bracketed list such as `protocol [ tcp udp ]` NARROWS it to the "+
					"first value — a direct application body holds one protocol and one "+
					"port, so use separate `term` sub-blocks for multiple protocols or "+
					"ports",
				name, app.UnknownDirectLeaves[0])
		}
		// #4337: a per-application `alg <name>` outside the four xpf implements
		// (dns/ftp/sip/tftp) is NO LONGER hard-rejected here. The #3353 commit
		// reject is deliberately relaxed to an accepted-but-inert advisory
		// (ValidateConfig, compiler_validate_warn.go). Rationale: the
		// per-application ALG is NOT carried into the userspace dataplane
		// snapshot (the only ALG signal on the wire is the GLOBAL
		// alg_disable_flags bitfield), so even a KNOWN name is informational
		// today — rejecting an UNKNOWN one blocked real vSRX drop-in configs
		// that tag applications with ALGs xpf does not implement (e.g.
		// `alg ssh`) for a knob with no functional effect. The unknown name now
		// commits with an advisory naming the unenforced alg so a typo is still
		// surfaced; a KNOWN name commits silently, keeping its (informational)
		// behavior. Enforcement of the per-application ALG is deferred to the
		// per-application slice of #2008.
	}
	// #3890: an unrecognized member statement inside an opaque application-set
	// body. The schema declares `application-set` as an args:1 leaf
	// (children:nil), so the SchemaValidate walk never reaches its members and a
	// typo'd member keyword (e.g. `applicaton foo` for `application foo`, or a
	// mistyped `application-set`) was silently dropped by compileApplications —
	// the set was under-populated, and if referenced by a DENY policy the deny
	// matched FEWER applications than intended (a fail-open under-match; traffic
	// the operator meant to block is permitted). compileApplications records the
	// offending keyword on ApplicationSet.UnknownMembers (mirroring
	// UnknownTermLeaves); reject the first one so the silent under-population
	// becomes an operator-visible commit error. Implicit application-sets
	// synthesized for term-bearing applications never carry UnknownMembers, so
	// they are unaffected. Iteration is sorted so the first-reported error is
	// deterministic.
	setNames := make([]string, 0, len(cfg.Applications.ApplicationSets))
	for name := range cfg.Applications.ApplicationSets {
		setNames = append(setNames, name)
	}
	sort.Strings(setNames)
	for _, name := range setNames {
		set := cfg.Applications.ApplicationSets[name]
		if set == nil || len(set.UnknownMembers) == 0 {
			continue
		}
		return fmt.Errorf(
			"application-set %q: unknown member statement %q; an application-set "+
				"member is `application <name>`, `application-set <name>`, or "+
				"`description <text>` (an unrecognized keyword is silently dropped, "+
				"leaving the set under-populated — a deny policy referencing it then "+
				"matches fewer applications than intended, permitting traffic meant "+
				"to be blocked)",
			name, set.UnknownMembers[0])
	}
	return nil
}

// validateApplicationStructureStrict hard-rejects two STRUCTURAL errors in a
// user-defined application that Junos rejects at commit regardless of whether
// the application is wired into a policy (the same all-user-apps scope as
// validateApplicationSyntaxStrict, NOT the reference-scoped semantic specs):
//
//   - #3366 mixed direct + term: an application carrying BOTH a direct match
//     body (protocol / destination-port / source-port / inactivity-timeout /
//     timeout / icmp-type / icmp-code / alg) AND one or more `term` sub-blocks.
//     compileApplications stores only the synthesized term applications for a
//     term-bearing app (the `if len(terms) > 0` branch), so the direct match was
//     SILENTLY DROPPED — for a deny application that erases a deny match and lets
//     traffic fall through to a later permit or the default policy (a fail-open
//     under-match). Junos requires a custom application to be EITHER scalar OR
//     term-based; reject the mix at commit. compileApplications records the
//     parent name on cfg.Applications.MixedDirectTermApps.
//
//   - #3366 duplicate scalar term leaf: a single-valued leaf (destination-port /
//     source-port / inactivity-timeout / timeout / alg, and — since #6766 —
//     icmp-type / icmp-code) repeated with a
//     CONFLICTING value inside one inline term. The term is opaque to the
//     SchemaValidate walk, so the repeat was last-writer-wins — the earlier value
//     silently overwritten by parse order, narrowing/widening the term with no
//     commit error. An idempotent same-value repeat is accepted; a repeated
//     `protocol` is the documented multi-protocol-term syntax and is NOT flagged.
//     parseApplicationTerms records the offending leaf names on
//     Application.DuplicateTermLeaves.
//
//   - #5574 conflicting duplicate DIRECT scalar leaf: the direct-body analogue of
//     the term case above. A single-valued DIRECT leaf (protocol /
//     destination-port / source-port / inactivity-timeout / timeout / icmp-type /
//     icmp-code / alg) repeated with a CONFLICTING value directly on the
//     application body (protocol tcp; protocol udp; destination-port 22;
//     destination-port 53) was assigned straight into a single typed field, so
//     the repeat was last-writer-wins — only the FINAL value was enforced, so a
//     deny referencing the app covered FEWER protocol/port combinations than
//     authored and could fall through to a permit / default-permit (a fail-open
//     under-match). This is reachable via a hierarchical config load / paste, an
//     apply-groups merge, or a peer-synced serialized config (flat-set SetPath
//     collapses a single-value leaf to the last value before the compiler runs).
//     compileApplications records the offending leaf names on
//     Application.DuplicateDirectLeaves. Unlike the term case, `protocol` IS
//     tracked (the direct body has no multi-protocol syntax). An idempotent
//     same-value repeat is accepted.
//
// Strict on the commit / commit-check path; the call site (compiler.go,
// lenientApplicationSpecs) downgrades a returned error to a warning on the
// tolerant load / peer-sync path so an already-persisted or older-peer-synced
// config still BOOTS (#1960 no-brick). Iteration is sorted so the first-reported
// error is deterministic across runs.
func validateApplicationStructureStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// #3366 mixed direct + term — reject the parent application by name.
	if len(cfg.Applications.MixedDirectTermApps) > 0 {
		mixed := append([]string(nil), cfg.Applications.MixedDirectTermApps...)
		sort.Strings(mixed)
		return fmt.Errorf(
			"application %q: a custom application may define EITHER a direct match "+
				"body (protocol / destination-port / source-port / "+
				"inactivity-timeout / timeout / icmp-type / icmp-code / alg) OR one or "+
				"more `term` sub-blocks, not both — Junos rejects the mix, and the "+
				"compiler silently dropped the direct match (keeping only the terms), "+
				"which for a deny application erases the deny and lets traffic fall "+
				"through. Move the direct match into its own `term`",
			mixed[0])
	}
	// #3366 duplicate scalar leaf inside an inline term.
	if len(cfg.Applications.Applications) > 0 {
		names := make([]string, 0, len(cfg.Applications.Applications))
		for name := range cfg.Applications.Applications {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			app := cfg.Applications.Applications[name]
			if app == nil {
				continue
			}
			if len(app.DuplicateTermLeaves) > 0 {
				return fmt.Errorf(
					"application %q: conflicting duplicate %q inside `term`; a single-valued "+
						"term leaf (destination-port / source-port / inactivity-timeout / "+
						"timeout / alg / icmp-type / icmp-code) may carry only one value — a repeat with a different "+
						"value is last-writer-wins and silently overrides the earlier one by "+
						"token order (use repeated `protocol` only for an intentional "+
						"multi-protocol term)",
					name, app.DuplicateTermLeaves[0])
			}
			// #5574 conflicting duplicate DIRECT scalar leaf.
			if len(app.DuplicateDirectLeaves) > 0 {
				return fmt.Errorf(
					"application %q: conflicting duplicate %q; a single-valued application "+
						"leaf (protocol / destination-port / source-port / inactivity-timeout / "+
						"timeout / icmp-type / icmp-code / alg) may be set only once — a repeat "+
						"with a different value is last-writer-wins and silently keeps only the "+
						"LAST value by definition order, so a deny referencing this application "+
						"covers fewer protocol/port combinations than authored and can fall "+
						"through to a permit (split conflicting values into separate `term` "+
						"sub-blocks or separate applications)",
					name, app.DuplicateDirectLeaves[0])
			}
		}
	}
	return nil
}

// applicationsToValidateStrict returns the set of user-defined application
// names whose port/protocol spec is validated as a hard COMMIT error rather
// than a warning. That is every user application referenced (directly, or as a
// member of a referenced application-set) by a zone-pair or global security
// policy, OR by a source/destination-NAT rule's `match application` (#2187 — a
// NAT term consumes the app's port/proto the same way a policy does, so a
// malformed app referenced only by a NAT rule must reject too), plus — when
// `services application-identification` is enabled — every user application
// (app-id compiles them all into the catalog). It mirrors the policy-reference
// walk in appid.CatalogNames; the logic is duplicated here because pkg/appid
// imports pkg/config (so the compiler cannot call back into appid without an
// import cycle). Predefined junos-* applications are never returned — they are
// not in cfg.Applications.Applications and their specs are owned by the
// predefined table, not the operator. Static NAT carries no application match,
// so only source and destination NAT rule-sets are walked.
func applicationsToValidateStrict(cfg *Config) map[string]struct{} {
	out := make(map[string]struct{})
	if cfg == nil {
		return out
	}
	userApps := cfg.Applications.Applications
	// app-id enabled: the catalog compiles every user application, so validate
	// them all.
	if cfg.Services.ApplicationIdentification {
		for name := range userApps {
			out[name] = struct{}{}
		}
		return out
	}
	addRef := func(appName string) {
		if appName == "" || appName == "any" {
			return
		}
		if set, isSet := cfg.Applications.ApplicationSets[appName]; isSet {
			expanded, err := ExpandApplicationSet(appName, &cfg.Applications)
			if err == nil {
				for _, member := range expanded {
					if _, isUser := userApps[member]; isUser {
						out[member] = struct{}{}
					}
				}
				return
			}
			// ExpandApplicationSet bails on the FIRST dangling/undefined or
			// over-nested member, which would otherwise let a MALFORMED user app
			// that is ALSO a direct member of the same set escape the strict gate
			// (commit silently succeeds — the #2142 fail-closed-on-permit
			// pathology, scoped to a set carrying a dangling member). A dangling
			// member is a separate existing concern; it must not mask a malformed
			// spec on a sibling member. Fall back to the set's DIRECT user-app
			// members so each one that resolves is still hard-rejected at commit.
			if set != nil {
				for _, member := range set.Applications {
					if _, isUser := userApps[member]; isUser {
						out[member] = struct{}{}
					}
				}
			}
			return
		}
		if _, isUser := userApps[appName]; isUser {
			out[appName] = struct{}{}
		}
	}
	walk := func(policies []*Policy) {
		for _, pol := range policies {
			if pol == nil {
				continue
			}
			for _, appName := range pol.Match.Applications {
				addRef(appName)
			}
		}
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		walk(zpp.Policies)
	}
	walk(cfg.Security.GlobalPolicies)

	// #2187: a source/destination-NAT rule with `match application <name>` also
	// consumes the referenced app's port/proto (pkg/dataplane/userspace/nat.go
	// appPortsFromSpec). A malformed spec there returns nil ports, so the NAT
	// term silently never-matches (or over-matches on a degenerate proto) with
	// no commit error — and a bad app referenced ONLY by a NAT rule (not by any
	// policy) escaped both this commit gate (policy-only) and the #2124 runtime
	// gate (policy-only). Collect NAT-rule app references the same way as policy
	// references (single app or application-set) so they are hard-rejected at
	// commit, lenient on load — identical wiring to the policy path. Static NAT
	// is intentionally not walked: StaticNATRule has no application match
	// (compileNATStatic parses only source/destination-address), so there is no
	// app reference to validate there.
	walkNATRules := func(rs *NATRuleSet) {
		if rs == nil {
			return
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			addRef(rule.Match.Application)
		}
	}
	for _, rs := range cfg.Security.NAT.Source {
		walkNATRules(rs)
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			walkNATRules(rs)
		}
	}
	return out
}

// icmpConstraintDesc renders the ICMP type/code constraint an application
// carries as a human-readable `icmp-type N [icmp-code M]` token for use in a
// commit-reject message (#4410 F4). It returns "" when the application has no
// ICMP constraint, so callers can treat the empty string as "no hint to add".
func icmpConstraintDesc(app *Application) string {
	if app == nil {
		return ""
	}
	switch {
	case app.ICMPType != nil && app.ICMPCode != nil:
		return fmt.Sprintf("icmp-type %d icmp-code %d", *app.ICMPType, *app.ICMPCode)
	case app.ICMPType != nil:
		return fmt.Sprintf("icmp-type %d", *app.ICMPType)
	case app.ICMPCode != nil:
		return fmt.Sprintf("icmp-code %d", *app.ICMPCode)
	default:
		return ""
	}
}

// ApplicationsToValidateStrict exposes the strict-validation reference set
// (the user-app names the commit-time gate hard-rejects) for cross-checking
// against appid.CatalogNames. The strict walk INLINE-duplicates CatalogNames's
// policy-reference resolution because pkg/appid imports pkg/config (so the
// compiler cannot call back into appid without a cycle). This accessor lets a
// pkg/appid test assert the two walks agree on the user-app subset, so a future
// change to CatalogNames's resolution cannot let the compiler copy drift
// silently. It is a TEST seam, not a runtime coupling — production code uses the
// unexported validateApplicationSpecsStrict directly.
func ApplicationsToValidateStrict(cfg *Config) map[string]struct{} {
	return applicationsToValidateStrict(cfg)
}

// ReservedApplicationName is the AppID display/filter sentinel that means "no
// known application" (appid.Unknown == "UNKNOWN", pkg/appid/runtime.go).
// ResolveSessionName returns this literal for an unstamped / catalog-skew
// session when `services application-identification` is enabled, and
// SessionMatches compares an operator `show ... application <name>` /
// `clear ... application <name>` filter against the flattened result string. A
// user-defined application (or application-set) name is carried verbatim into
// that same flattened string, so a catalog application literally named
// "UNKNOWN" is indistinguishable from the sentinel: a `show`/`clear` filter
// cannot separate "no known application" from the configured application, and a
// destructive filtered session clear can delete BOTH classes (#5821).
//
// pkg/config cannot import pkg/appid (appid imports config — an import cycle),
// so the literal is duplicated here rather than referenced. The pkg/appid
// canary TestReservedApplicationNameMatchesUnknownSentinel asserts the two stay
// equal so the reservation cannot drift away from the sentinel it protects.
const ReservedApplicationName = "UNKNOWN"

// validateReservedApplicationNamesStrict hard-rejects, at commit /
// commit-check, a user-defined `applications application <name>` or
// `applications application-set <name>` whose name equals the AppID unknown
// sentinel (ReservedApplicationName == "UNKNOWN") CASE-SENSITIVELY (#5821,
// relaxed to exact-case in #5820).
//
// Without this reservation the sentinel and a real catalog application share
// one flat string on the AppID display/filter surface (ResolveSessionName /
// SessionMatches, pkg/appid/runtime.go): `show ... application UNKNOWN` cannot
// tell truly-unknown sessions from sessions classified as the user application,
// and the destructive `clear ... application UNKNOWN` selector can delete both
// groups. The sentinel is only ever rendered upper-case `UNKNOWN` by
// ResolveSessionName, and SessionMatches now compares filters case-exactly
// (#5820), so only an application literally named `UNKNOWN` can alias it —
// "unknown"/"Unknown" are distinct names that no longer collide. The
// reservation is therefore case-sensitive, matching the case-exact namespace
// contract of the store/catalog.
//
// Applications and application-sets share one flat Junos namespace, and a
// multi-term application additionally mints an implicit application-set under
// its own name (cfg.Applications.ApplicationSets[<parent>]). Both maps are
// walked so every authored spelling is caught: a simple `application UNKNOWN`
// lands in Applications; an `application-set UNKNOWN` (or the implicit set of a
// multi-term `application UNKNOWN`) lands in ApplicationSets. Generated per-term
// names (`<parent>-<term>`) never equal the reserved name, so they are
// unaffected. Iteration is sorted so the first-reported error is deterministic.
//
// This is a NEW fail-closed restriction (#5821): a previously-valid config that
// already named an application/application-set UNKNOWN now hard-rejects on the
// operator's next commit — the intended fix, called out as a release-note
// behavior change (mirroring the #5539 RETH-generic guard). Strict on the
// commit / commit-check path; the call site (compiler_uniformgates.go,
// lenientReservedApplicationNames) downgrades a returned error to a warning on
// the tolerant load / peer-sync path so an already-persisted or peer-synced
// config carrying the reserved name still BOOTS (#1960 no-brick) rather than
// bricking a running node on upgrade. Mirrors the strict commit-reservation
// pattern of validateVRRPGroupIDStrict (#4573) and the sibling application
// gates.
func validateReservedApplicationNamesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	appNames := make([]string, 0, len(cfg.Applications.Applications))
	for name := range cfg.Applications.Applications {
		appNames = append(appNames, name)
	}
	sort.Strings(appNames)
	for _, name := range appNames {
		if name == ReservedApplicationName {
			return reservedApplicationNameError("application", name)
		}
	}
	setNames := make([]string, 0, len(cfg.Applications.ApplicationSets))
	for name := range cfg.Applications.ApplicationSets {
		setNames = append(setNames, name)
	}
	sort.Strings(setNames)
	for _, name := range setNames {
		if name == ReservedApplicationName {
			return reservedApplicationNameError("application-set", name)
		}
	}
	return nil
}

// reservedApplicationNameError builds the operator-visible commit error for a
// user application / application-set that collides with the AppID unknown
// sentinel. kind is "application" or "application-set".
func reservedApplicationNameError(kind, name string) error {
	return fmt.Errorf(
		"applications %s %q: %q is reserved as the AppID \"no known application\" "+
			"sentinel and may not name a user application or application-set "+
			"(reserved exact-case) — the `show`/`clear ... application "+
			"<name>` filter and the session renderer cannot distinguish a real "+
			"application named %q from the unclassified/unstamped state, so a "+
			"filtered session clear could delete both; rename it (#5821)",
		kind, name, ReservedApplicationName, ReservedApplicationName)
}
