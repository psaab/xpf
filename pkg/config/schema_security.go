package config

// schema_security.go carries the `security` and `applications` subtrees
// of the config-mode grammar SSOT (#1891 domain split). The root
// composition, the schemaNode type, and the split rationale live in
// schema.go; this file is a sibling aspect file in package config — NOT
// a subpackage — because setSchema is unexported and consumed
// in-package by schema_complete.go / schema_walk.go (two-SSOT doctrine,
// #1319).

// Security-log enum value sets (#3349). Each MUST stay in sync with the
// corresponding runtime consumer so the commit-time validator accepts
// exactly the set the runtime applies — a value the validator allows but the
// runtime does not recognize would reintroduce the same silent-fallback bug
// the validator exists to close.
//
//   - syslogLogModes:   pkg/daemon/daemon_system.go (Mode == "event" enters
//     event mode; anything else is stream mode).
//   - syslogLogFormats: pkg/logging (syslog.go "sd-syslog" timestamp branch,
//     ringbuf.go "binary"/"structured" branches; "syslog"/"" => RFC 3164).
//   - syslogSeverities: aliases junosSyslogSeverities (schema_system.go) —
//     the full logging.ParseSeverity domain the runtime applies to a
//     `security log stream ... severity` via SyslogClient.MinSeverity
//     (daemon_system.go): emergency/alert/critical/error/warning/notice/
//     info/debug map to a MinSeverity threshold, plus any=>send-all and
//     none=>send-nothing (#5314). The two severity surfaces (this stream
//     leaf and the system-syslog `<facility> <severity>` leaf) MUST share
//     the one SSOT; before this the stream leaf carried a truncated
//     error/warning/info list that rejected critical/notice/debug/
//     emergency/alert/any/none — every one of which the runtime honors
//     (commit-rejects-valid, codex-179 C179-046).
//   - syslogFacilities: pkg/logging ParseFacility (recognized names; every
//     other name silently remaps to local0).
//   - syslogCategories: pkg/logging ParseCategory (all/session/policy/screen/
//     firewall; every other name => 0 = no filter = send ALL).
var (
	syslogLogModes   = []string{"event", "stream"}
	syslogLogFormats = []string{"binary", "sd-syslog", "structured", "syslog"}
	// syslogSeverities aliases the shared junosSyslogSeverities SSOT so the
	// stream-severity validator accepts exactly the logging.ParseSeverity
	// domain the runtime applies (C179-046). Do NOT re-list the tokens here.
	syslogSeverities = junosSyslogSeverities
	syslogFacilities = []string{
		"auth", "change-log", "daemon", "kern",
		"local0", "local1", "local2", "local3",
		"local4", "local5", "local6", "local7",
		"syslog", "user",
	}
	syslogCategories = []string{"all", "firewall", "policy", "screen", "session"}
)

// securitySessionLogModes is the fixed set of session-logging tokens accepted
// by every session-log LIST surface (#3703): the per-policy `then log`, the
// deny-collapsed `then deny log`, `default-policy-log`, and
// `pre-id-default-policy then log`. It is the SSOT shared by the schema
// (sessionLogModeLeaf below) and the compiler readers (session log values are
// accumulated via firewallMatchValues and matched against these tokens).
var securitySessionLogModes = []string{"session-init", "session-close"}

// sessionLogModeLeaf builds the shared multi-value enum leaf for a session-log
// list surface (#3703). Before this the four surfaces modeled `log` /
// `default-policy-log` as CONTAINERS with session-init / session-close
// children, so a bracket / single-line list (`then log [ session-init
// session-close ]`) mis-nested the tail under the first token and the compiler
// readers dropped everything after session-init (the #2419 collapse class,
// unfixed on these leaves). Modeled here as a `multi && children == nil` typed
// enum leaf so:
//   - SetPath collapses ALL list values onto the one leaf's Keys (ast_edit.go
//     absorbs trailing non-sibling tokens for a multi value-tail leaf), and
//   - SchemaValidate (validateMultiValueLeaf) rejects an UNKNOWN token at
//     commit-check — strict on the operator commit path, downgraded to a
//     warning on the tolerant load / peer-sync path (#1960 no-brick) — instead
//     of the token being silently swallowed.
//
// children MUST stay nil: both the SetPath collapse (ast_edit.go:260) and the
// validateMultiValueLeaf dispatch (schema_walk.go:256) key on children == nil.
// The value-slot `?` completion surfaces the two modes via valueExamples, so
// dropping the container children does not lose completion coverage.
func sessionLogModeLeaf(desc string) *schemaNode {
	return &schemaNode{
		desc:          desc,
		args:          1,
		multi:         true,
		valueType:     ValueEnumOf,
		valueDesc:     "session-logging event",
		valueExamples: securitySessionLogModes,
		validator:     ValidateEnum(securitySessionLogModes),
		placeholder:   "<session-init|session-close>",
		children:      nil,
	}
}

// hostInboundSchemaChildren builds the shared `host-inbound-traffic { ... }`
// child set used at BOTH the zone level and the per-interface override (#3362,
// #3703). system-services / protocols are multi-value value-tail leaves: a
// bracket / single-line / repeated list collapses ALL tokens onto the leaf's
// Keys (the #2419 contract) instead of dropping the tail, and
// validateHostInboundTokensStrict rejects an unrecognized token at commit
// against the host_inbound_tokens.go SSOT (strict on commit, warn on the
// tolerant load path). children MUST stay nil so the SetPath collapse fires;
// the leaves are intentionally UNTYPED (no schema validator) because the token
// allowlist lives in the shared host_inbound_tokens.go SSOT the compiled-slice
// validator reads, not in the schema.
func hostInboundSchemaChildren() map[string]*schemaNode {
	return map[string]*schemaNode{
		"system-services": {desc: "System services", args: 1, multi: true, placeholder: "<service>", children: nil},
		"protocols":       {desc: "Protocols", args: 1, multi: true, placeholder: "<protocol>", children: nil},
	}
}

// policyThenSchemaChildren builds the `then` action subtree shared by
// zone-pair (from-zone/to-zone) and global security policies. It is a
// factory (not a shared package var) so the two scopes get independent
// schemaNode trees — schema nodes are mutable containers and must not be
// aliased between two points in the grammar.
//
// #3377: the terminal actions permit/deny/reject and the count modifier
// were compiled by the security compiler (compilePolicy's `then` switch in
// compiler_security.go — cases permit, deny, reject, log, count) but were
// absent from setSchema, present only as a `// permit, deny, reject, count
// → leaf` comment placeholder. That is the compiled-but-not-schema-visible
// drift the two-SSOT rule (#1319) exists to prevent: `set security
// policies ... then ?` config-mode completion / `?` help could not offer
// the most basic policy actions. This factory makes the schema `then`
// children EXACTLY mirror the compiler switch.
//
// Sub-option modeling matches the EXACT supported surface, so completion
// never advertises a leaf that the commit-check then rejects:
//   - permit / reject: declared childless. A bare `then permit` / `then
//     reject` is supported; any child (application-services, tunnel,
//     firewall-authentication under permit; profile, tcp-reset under
//     reject) is rejected at commit by validatePolicyThenPermitStrict
//     (#3114) / validatePolicyThenRejectStrict (#3115), which stay the SSOT
//     for that rejection (walkSchemaNode ignores unknown descendants of a
//     childless container, so the schema does not double-reject).
//   - deny: carries the log/count observability modifiers it legitimately
//     combines with (applyCollapsedDenyModifiers / #3141); any OTHER deny
//     modifier is rejected by validatePolicyThenDenyStrict.
//   - log: carries its session-init/session-close sub-options (the exact
//     tokens compilePolicy's `log` arm reads).
//
// The canary in schema_policy_then_3377_test.go asserts this child set
// equals the compiler's `then` switch token set for both scopes so a
// future action leaf cannot drift back out of the schema.
func policyThenSchemaChildren() map[string]*schemaNode {
	// #3703: `then log` is a multi-value session-log LIST leaf (see
	// sessionLogModeLeaf) — a bracket / single-line list must land ALL values
	// (session-init AND session-close) on the one leaf and reject an unknown
	// token at commit. It was a container whose bracket tail mis-nested and
	// dropped everything after session-init.
	logNode := func() *schemaNode {
		return sessionLogModeLeaf("Log session")
	}
	return map[string]*schemaNode{
		"permit": {desc: "Permit matching traffic", children: nil},
		"deny": {desc: "Deny matching traffic (silently drop)", children: map[string]*schemaNode{
			"log":   logNode(),
			"count": {desc: "Count matching packets and bytes", children: nil},
		}},
		"reject": {desc: "Reject matching traffic (ICMP unreachable / TCP RST)", children: nil},
		"log":    logNode(),
		"count":  {desc: "Count matching packets and bytes", children: nil},
	}
}

var schemaSecurity = &schemaNode{desc: "Security configuration", children: map[string]*schemaNode{
	"zones": {desc: "Security zones", children: map[string]*schemaNode{
		"security-zone": {desc: "Security zone name", args: 1, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: map[string]*schemaNode{
			"description": {desc: "Zone description", args: 1, scalar: true, placeholder: "<text>", children: nil},
			// #3362: per-interface host-inbound-traffic override. The interface
			// name is a wildcard (dynamic) key; under it the SAME token grammar
			// as the zone-level host-inbound-traffic stanza below (system-services
			// / protocols as untyped containers — tokens validated by
			// validateHostInboundTokensStrict, not the schema). A bare
			// `interfaces <if>` (no body) stays valid (zone membership only). The
			// effective admission set for an interface is THIS interface-level
			// set when the stanza is present — it REPLACES the zone-level stanza
			// below rather than adding to it (#6515; Junos: "Interface
			// configuration overrides that of the zone"). A present-but-EMPTY
			// body is a deny-all override, not a fallback to the zone set.
			"interfaces": {desc: "Interfaces in this zone", wildcard: &schemaNode{
				desc: "Interface name", valueHint: ValueHintInterfaceName, placeholder: "<interface-name>",
				children: map[string]*schemaNode{
					"host-inbound-traffic": {desc: "Per-interface host inbound traffic", children: hostInboundSchemaChildren()},
				},
			}},
			"tcp-rst":              {desc: "Send TCP RST for denied traffic", children: nil},
			"screen":               {desc: "Screen profile name", args: 1, scalar: true, placeholder: "<screen-name>", children: nil},
			"host-inbound-traffic": {desc: "Host inbound traffic", children: hostInboundSchemaChildren()},
			// #3061: zone-local address book. Same entry grammar as the
			// global book (security address-book global) but attached
			// directly under the zone (no `global` wrapper). A policy in
			// this zone resolves a name against the zone-local book first,
			// then falls back to the global book.
			"address-book": {desc: "Zone-local address book", children: map[string]*schemaNode{
				"address": {desc: "Named address (name and prefix)", args: 2, multi: true, placeholder: "<address-name>", children: nil},
				"address-set": {desc: "Address set name", args: 1, valueHint: ValueHintAddressName, placeholder: "<address-set-name>", children: map[string]*schemaNode{
					"address":     {desc: "Address to include in this set", args: 1, multi: true, placeholder: "<address-name>", children: nil},
					"address-set": {desc: "Nested address set to include", args: 1, multi: true, valueHint: ValueHintAddressName, placeholder: "<address-set-name>", children: nil},
					// NOT tagged scalar:true (#3332): AddressSet has no Description
					// field (types_security.go) and parseAddressBookEntries does
					// not read an address-set `description` child, so the value is
					// currently unsupported and discarded at compile. An arity gate
					// here would assert validation on a feature that has no effect;
					// tag it scalar only if/when AddressSet.Description is wired.
					"description": {desc: "Address set description", args: 1, placeholder: "<text>", children: nil},
				}},
			}},
		}},
	}},
	"policies": {desc: "Security policies", children: map[string]*schemaNode{
		// #3065: explicit no-match default override. Unset = deny-all
		// (fail-closed, matching the Junos default-security-policy);
		// permit-all restores the legacy fail-open behaviour.
		"default-policy": {
			desc:          "Action for traffic with no matching policy (default deny-all)",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "No-match default action (permit-all | deny-all | reject-all)",
			valueExamples: []string{"deny-all", "permit-all", "reject-all"},
			validator:     ValidateEnum([]string{"permit-all", "deny-all", "reject-all"}),
			children:      nil,
			// #6774: Junos displays this as `default-policy { deny-all; }` —
			// it is a CHOICE CONTAINER there, modelled here as a valued leaf
			// so the flat-set spelling works. Accept both; the compiler
			// already does.
			blockValue: true,
		},
		// #3534 (split from #3363 Part 2): RT_FLOW session logging for the
		// IMPLICIT default-policy verdict. The `default-policy` leaf above is a
		// typed ValueEnumOf leaf that — per the schema.go typed-leaf invariant —
		// MUST NOT carry structural `then { ... }` children, so the log knob
		// lives in this sibling container (mirroring pre-id-default-policy's
		// session-init/session-close model). `session-init`/`session-close` are
		// presence-only flags wired to ConfigSnapshot.DefaultLogSessionInit/Close.
		// #3703: multi-value session-log LIST leaf (see sessionLogModeLeaf) so a
		// bracket / single-line `default-policy-log [ session-init session-close ]`
		// lands BOTH values and rejects an unknown token at commit. It was a
		// container whose bracket tail mis-nested session-close under session-init
		// and dropped it — losing the most security-relevant fallback-path audit.
		"default-policy-log": sessionLogModeLeaf("RT_FLOW session logging for the implicit default-policy verdict"),
		// #4233: `policy-rematch [extensive]` re-evaluates in-progress
		// sessions against the changed policy set on commit in Junos. xpf
		// records the knob (compiler_security_policy.go) but does not yet
		// enforce it — commit emits an accepted-only advisory
		// (compiler_validate_warn.go), and enforcement is tracked as #4234.
		// Modeled so the leaf gains structural/`?` completion and the
		// optional `extensive` sub-token is grouped rather than mis-parsed.
		"policy-rematch": {desc: "Re-evaluate in-progress sessions on policy change (accepted-only; unenforced)", children: map[string]*schemaNode{
			"extensive": {desc: "Also re-evaluate sessions matched by an unchanged policy when referenced objects change", children: nil},
		}},
		"from-zone": {desc: "From zone", args: 3, valueHint: ValueHintZoneName, midKeyword: "to-zone", midKeywordAt: 2, placeholder: "<zone-name>", children: map[string]*schemaNode{
			"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
				"description": {desc: "Policy description", args: 1, scalar: true, placeholder: "<text>", children: nil},
				"match": {desc: "Match criteria", children: map[string]*schemaNode{
					"source-address":               {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
					"destination-address":          {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
					"source-address-excluded":      {desc: "Match all sources except source-address", children: nil},
					"destination-address-excluded": {desc: "Match all destinations except destination-address", children: nil},
					"application":                  {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
				}},
				"then": {desc: "Action", children: policyThenSchemaChildren()},
				// #3117: `scheduler-name <name>` binds a class-of-service
				// scheduler to the policy. The compiler reads it as a plain
				// string (compiler_security.go: polInst.node.FindChild(
				// "scheduler-name") → nodeVal) and the strict validator
				// rejects an undefined reference (compiler_validate_strict_cos.go
				// validatePolicySchedulerReferencesStrict). It was absent from
				// setSchema, so the leaf had no structural/`?` completion —
				// inconsistent with the two-SSOT rule that every compiled +
				// validated leaf lives in the schema tree. Untyped (plain
				// string) like `description`: the compiler consumes the raw
				// token and the strict reference check stays the SSOT for
				// undefined-scheduler rejection (no treeValidator here).
				"scheduler-name": {desc: "Class-of-service scheduler bound to this policy", args: 1, placeholder: "<scheduler-name>", children: nil},
			}},
		}},
		"global": {desc: "Global policies", children: map[string]*schemaNode{
			"policy": {desc: "Policy name", args: 1, valueHint: ValueHintPolicyName, placeholder: "<policy-name>", children: map[string]*schemaNode{
				"description": {desc: "Policy description", args: 1, scalar: true, placeholder: "<text>", children: nil},
				"match": {desc: "Match criteria", children: map[string]*schemaNode{
					"source-address":               {desc: "Source address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
					"destination-address":          {desc: "Destination address", args: 1, multi: true, valueHint: ValueHintPolicyAddress, placeholder: "<address>", children: nil},
					"source-address-excluded":      {desc: "Match all sources except source-address", children: nil},
					"destination-address-excluded": {desc: "Match all destinations except destination-address", children: nil},
					"application":                  {desc: "Application", args: 1, multi: true, valueHint: ValueHintPolicyApp, placeholder: "<application>", children: nil},
					// #3148: a Junos global policy can carry optional
					// from-zone/to-zone match context so one global policy
					// applies to a chosen zone pair (or one wildcard side)
					// rather than every zone pair. Absent = all zones (the
					// historical global behaviour). These leaves exist ONLY
					// under global policy match — zone-pair policies take
					// their zones from the from-zone/to-zone stanza.
					//
					// #4626 M03: a Junos global policy scope is a zone LIST
					// (`match from-zone [ trust dmz ]`), so these leaves carry
					// `multi: true` (the same marker source-address /
					// application use above) — the #2419 lexer collapses the
					// bracket list onto one leaf's Keys
					// (["from-zone","trust","dmz"]) and the compiler
					// accumulates EVERY value via firewallMatchValues into the
					// Match.FromZones / Match.ToZones set. This replaced the
					// #4415 L12 `scalar: true` fail-closed reject (which
					// dropped every zone past the first) with real Junos
					// multi-zone parity.
					"from-zone": {desc: "Restrict this global policy to packets from these zones", args: 1, multi: true, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
					"to-zone":   {desc: "Restrict this global policy to packets to these zones", args: 1, multi: true, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
				}},
				"then": {desc: "Action", children: policyThenSchemaChildren()},
				// #3117: scheduler-name on global policies — same compiler +
				// strict-validator path as the zone-pair policy above.
				"scheduler-name": {desc: "Class-of-service scheduler bound to this policy", args: 1, placeholder: "<scheduler-name>", children: nil},
			}},
		}},
	}},
	"screen": {desc: "Screen options", children: map[string]*schemaNode{
		"ids-option": {desc: "Screen profile name", args: 1, valueHint: ValueHintScreenProfile, placeholder: "<screen-name>", children: map[string]*schemaNode{
			"icmp": {desc: "ICMP screening", children: map[string]*schemaNode{
				// #3316: exposes `fragment` for tab-completion and routes
				// `icmp fragment` to ICMPScreen.Fragment. This is NOT typo
				// rejection — `fragment` is a childless ValueAny node, and
				// walkSchemaNode ignores unknown keywords (the gate is
				// opt-in; schema_walk.go), so `icmp framgent` is not caught
				// here. Unknown-screen-leaf rejection is the separate #3318.
				"fragment": {desc: "Drop fragmented ICMP/ICMPv6 packets", children: nil},
				// #6683/#7460: every check and every sub-knob is modelled so
				// the schema-driven expander (compact_tail.go) can normalise
				// the PACKED spellings into the nested shape. An unmodelled
				// keyword cannot be resolved, and the body was silently
				// dropped -- the check compiled DISABLED (#6683) or armed at a
				// default instead of the configured threshold (#7460).
				//
				// The sub-knob children are load-bearing, not decoration: as a
				// bare flag the expander would stop at `[flood]` and DROP a
				// trailing `threshold 500`, which is the same silent weakening
				// these issues are about.
				"ping-death": {desc: "Drop oversized ICMP (ping of death)", children: nil},
				"flood": {desc: "ICMP flood protection", children: map[string]*schemaNode{
					"threshold": {desc: "Detection threshold", args: 1, placeholder: "<number>", children: nil},
				}},
			}},
			"tcp": {desc: "TCP screening", children: map[string]*schemaNode{
				"syn-flood": {desc: "SYN flood protection", children: map[string]*schemaNode{
					"alarm-threshold":       {desc: "Detection threshold", args: 1, placeholder: "<number>", children: nil},
					"attack-threshold":      {desc: "Detection threshold", args: 1, placeholder: "<number>", children: nil},
					"source-threshold":      {desc: "Detection threshold", args: 1, placeholder: "<number>", children: nil},
					"destination-threshold": {desc: "Detection threshold", args: 1, placeholder: "<number>", children: nil},
					"timeout":               {desc: "Detection threshold", args: 1, placeholder: "<number>", children: nil},
				}},
				"port-scan": {desc: "Port scan protection", children: map[string]*schemaNode{
					"threshold": {desc: "Detection threshold", args: 1, placeholder: "<number>", children: nil},
				}},
				"land":       {desc: "Drop LAND attack (src == dst)", children: nil},
				"winnuke":    {desc: "Drop WinNuke (OOB to NetBIOS)", children: nil},
				"syn-frag":   {desc: "Drop fragmented SYN", children: nil},
				"syn-fin":    {desc: "Drop SYN+FIN", children: nil},
				"no-flag":    {desc: "Drop TCP with no flags set", children: nil},
				"fin-no-ack": {desc: "Drop FIN without ACK", children: nil},
			}},
			"ip": {desc: "IP screening", children: map[string]*schemaNode{
				"ip-sweep": {desc: "IP sweep protection", children: map[string]*schemaNode{
					"threshold": {desc: "Detection threshold", args: 1, placeholder: "<number>", children: nil},
				}},
				"source-route-option": {desc: "Drop IP source-route option", children: nil},
				"tear-drop":           {desc: "Drop teardrop (overlapping fragments)", children: nil},
			}},
			"udp": {desc: "UDP screening", children: map[string]*schemaNode{
				"flood": {desc: "UDP flood protection", children: map[string]*schemaNode{
					"threshold": {desc: "Detection threshold", args: 1, placeholder: "<number>", children: nil},
				}},
			}},
			"limit-session": {desc: "Session limits", children: map[string]*schemaNode{
				"source-ip-based":      {desc: "Source IP based limit", args: 1, placeholder: "<number>", children: nil},
				"destination-ip-based": {desc: "Destination IP based limit", args: 1, placeholder: "<number>", children: nil},
			}},
			// Profile-wide audit/log-only mode: a tripped check raises a
			// log-only alarm and forwards the packet instead of dropping it
			// (Junos threshold-tuning posture). Boolean flag leaf, no value.
			"alarm-without-drop": {desc: "Alarm but do not drop (audit/log-only mode)", children: nil},
		}},
	}},
	"nat": {desc: "Network Address Translation", children: map[string]*schemaNode{
		"source": {desc: "Source NAT configuration", children: map[string]*schemaNode{
			// #2823: the pool body is a container. The persistent-nat and
			// port (#3864) subtrees are modeled here (commit-check +
			// completion + flat-set grouping); the remaining pool leaves
			// (address, host) are unmodeled and left to the compiler per the
			// opt-in-gate contract (schema_walk.go: unknown keywords return
			// nil). The container also keeps SetPath grouping intact —
			// trailing tokens always descend, and a bare `pool <name>` still
			// emits a leaf.
			//
			// #3864: `port deterministic { block-size N; host address X }`
			// (CGNAT) is modeled so the documented flat-set quick-start
			// GROUPS onto a single `port` container instead of emitting
			// competing sibling `port deterministic ...` leaves that the
			// compiler read last-wins (block-size and host arrive on
			// separate `set` lines). The compiler (compiler_nat.go) still
			// accepts the un-modeled flat-leaf shape and ACCUMULATES across
			// both shapes, so an old on-disk config keeps compiling.
			"pool": {desc: "Source NAT pool name", args: 1, valueHint: ValueHintPoolName, placeholder: "<pool-name>", children: map[string]*schemaNode{
				// #8800: the compiler has read `address` under a source NAT pool
				// since #4521 (multi-value: Keys[1:] plus block children), but the
				// schema never declared it. Undeclared meant (a) completion never
				// offered it and (b) it was not a schema child, so the brace-elision
				// pass was never even ASKED about (pool, address) and the packed
				// spelling `pool p1 address <a>;` compiled to a ZERO-address pool.
				//
				// multi is deliberately NOT set. It is not needed -- SchemaValidate
				// accepts the single, `<low> to <high>` range and bracket-list
				// spellings identically with and without it, in the hierarchical and
				// flat-set shapes, and the compiler reads Keys[1:] regardless. Setting
				// it would make the leaf leaf-list-ELIGIBLE (isLeafListSchema requires
				// multi), silently flipping apply-groups from OVERRIDE to token UNION
				// for a spelling that already worked. On the destination pool, whose
				// grammar puts the port on the same statement, that union corrupted
				// the value outright: inheriting `address 10.0.0.2/32 port 8080;` over
				// an inline `address 10.0.0.1/32 port 80;` compiled the ADDRESS as
				// "8080". Measured, not assumed.
				"address": {desc: "Address or range in the source NAT pool", args: 1, placeholder: "<address>", children: nil},
				"port": {desc: "Source pool port block configuration", children: map[string]*schemaNode{
					// #3906: `range <low> to <high>` (Junos) and the legacy
					// `range low <lo> high <hi>` both collapse onto this multi
					// leaf; the compiler parses both via parseSourcePoolPortRange.
					"range": {desc: "Explicit source port range for the pool (<low> to <high>)", multi: true, children: nil},
					// #3906: preserve the original source port (1:1) — the
					// pool translates the address only. Value-less leaf.
					"no-translation": {desc: "Preserve the source port (translate the address only)", children: nil},
					"deterministic": {desc: "Deterministic (CGNAT) port block allocation", children: map[string]*schemaNode{
						"block-size": {
							desc:          "Ports allocated per subscriber block",
							args:          1,
							valueType:     ValueInteger,
							valueDesc:     "Block size in ports",
							valueExamples: []string{"2016"},
							validator:     ValidateInteger(1, 65535),
							children:      nil,
						},
						"host": {desc: "Subscriber host address range", children: map[string]*schemaNode{
							"address": {desc: "Subscriber CIDR prefix", args: 1, placeholder: "<prefix>", children: nil},
						}},
					}},
				}},
				"persistent-nat": {desc: "Persistent NAT bindings", children: map[string]*schemaNode{
					"permit": {
						desc:          "Remote-host reuse scope for persistent bindings",
						args:          1,
						valueType:     ValueEnumOf,
						valueDesc:     "Persistent NAT permit scope",
						valueExamples: []string{"any-remote-host", "target-host", "target-host-port"},
						validator:     ValidateEnum([]string{"any-remote-host", "target-host", "target-host-port"}),
						children:      nil,
					},
					"inactivity-timeout": {
						desc:          "Persistent binding inactivity timeout",
						args:          1,
						valueType:     ValueInteger,
						valueDesc:     "Timeout in seconds",
						valueExamples: []string{"300", "600"},
						validator:     ValidateInteger(1, 86400),
						children:      nil,
					},
				}},
				// #4291: per-pool port-overloading-factor. Typed so the knob
				// completes and commits; accepted-but-unenforced (advisory in
				// ValidateConfig) — the SNAT allocator has no factor-scaled port
				// budget.
				"port-overloading-factor": {
					desc:          "Concurrent translations per pool address (accepted, not enforced)",
					args:          1,
					valueType:     ValueInteger,
					valueDesc:     "Overloading factor",
					valueExamples: []string{"1", "2", "4"},
					validator:     ValidateInteger(1, 32),
					children:      nil,
				},
				// #4292: per-pool translation-target routing-instance. Typed so
				// it completes and commits; accepted-but-unenforced (advisory in
				// ValidateConfig) — the dataplane does not route the post-
				// translation packet against a non-ingress table.
				"routing-instance": {desc: "Translation-target routing instance (accepted, not enforced)", args: 1, placeholder: "<routing-instance>", children: nil},
			}},
			// #4291: `nat source interface port-overloading off` disables
			// source-port reuse across destinations. Typed so it completes and
			// commits; accepted-but-unenforced (advisory in ValidateConfig) —
			// source-port overloading is always on in the SNAT allocator, so
			// `off` hardens nothing.
			"interface": {desc: "Source NAT interface-address translation options", children: map[string]*schemaNode{
				"port-overloading": {
					desc:          "Source-port overloading control (off = unique src port per mapping; accepted, not enforced)",
					args:          1,
					valueType:     ValueEnumOf,
					valueDesc:     "port-overloading mode",
					valueExamples: []string{"off"},
					validator:     ValidateEnum([]string{"off"}),
					children:      nil,
				},
			}},
			"address-persistent": {desc: "Always map a source IP to the same pool address", children: nil},
			"rule-set": {desc: "Source NAT rule-set name", args: 1, placeholder: "<rule-set-name>", children: map[string]*schemaNode{
				// #3096: from/to scope by zone | interface | routing-instance.
				// All three are now enforced in the dataplane match path, so
				// each is declared for commit-time validation + CLI completion.
				"from": {desc: "Source of traffic to match", children: map[string]*schemaNode{
					"zone":             {desc: "Source zone name", args: 1, multi: true, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
					"interface":        {desc: "Ingress interface name", args: 1, multi: true, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
					"routing-instance": {desc: "Ingress routing instance name", args: 1, multi: true, placeholder: "<routing-instance>", children: nil},
				}},
				"to": {desc: "Destination of traffic to match", children: map[string]*schemaNode{
					"zone":             {desc: "Destination zone name", args: 1, multi: true, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
					"interface":        {desc: "Egress interface name", args: 1, multi: true, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
					"routing-instance": {desc: "Egress routing instance name", args: 1, multi: true, placeholder: "<routing-instance>", children: nil},
				}},
				"rule": {desc: "Source NAT rule name", args: 1, placeholder: "<rule-name>", children: map[string]*schemaNode{
					"match": {desc: "Match criteria", closedWorld: true, children: map[string]*schemaNode{
						"source-address":           {desc: "Source address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"source-address-name":      {desc: "Source address book entry to match", args: 1, multi: true, placeholder: "<address-name>", children: nil},
						"destination-address":      {desc: "Destination address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"destination-address-name": {desc: "Destination address book entry to match", args: 1, multi: true, placeholder: "<address-name>", children: nil},
						"destination-port":         {desc: "Destination port to match", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"application":              {desc: "Application to match", args: 1, multi: true, placeholder: "<application>", children: nil},
					}},
					// #4313: NOT closed-world (unlike the destination-NAT then
					// below). Junos permits `then source-nat pool <name>
					// persistent-nat { ... }` at the rule level, which xpf models
					// per-pool (`security nat source pool <name> persistent-nat`,
					// ~line 360) rather than under the rule-then pool. Flipping
					// closedWorld here would inherit down to the `pool` leaf and
					// false-reject that valid Junos config (#4191 class). Deferred
					// until the rule-level persistent-nat leaves are modeled.
					"then": {desc: "Source NAT action", children: map[string]*schemaNode{
						"source-nat": {desc: "Source NAT translation", children: map[string]*schemaNode{
							"interface": {desc: "Translate to the egress interface address", children: nil},
							"off":       {desc: "Disable source NAT for matching traffic", children: nil},
							"pool":      {desc: "Translate using a source NAT pool", args: 1, valueHint: ValueHintPoolName, placeholder: "<pool-name>", children: nil},
						}},
					}},
				}},
			}},
		}},
		"destination": {desc: "Destination NAT configuration", children: map[string]*schemaNode{
			// #8800: same defect as the SOURCE pool above, at the sibling path.
			// compileNATDestination reads `address` (parseDNATPoolAddress, which
			// deliberately walks every token so `address <ip> port <N>` captures
			// both), but the schema declared `children: nil`, so the head was not
			// a schema child, the brace-elision pass was never asked about it, and
			// `destination pool <p> address <a>;` compiled to an EMPTY address.
			// multi: true because the grammar puts the port on the same statement.
			"pool": {desc: "Destination NAT pool name", args: 1, valueHint: ValueHintPoolName, placeholder: "<pool-name>", children: map[string]*schemaNode{
				"address": {desc: "Translated address (optionally with `port <n>`) for the destination NAT pool", args: 1, placeholder: "<address>", children: nil},
			}},
			"rule-set": {desc: "Destination NAT rule-set name", args: 1, placeholder: "<rule-set-name>", children: map[string]*schemaNode{
				// #3096: `from` scope by zone | interface | routing-instance.
				// #3444: a destination-NAT rule-set has only a `from` clause —
				// DNAT translates the destination on inbound, so there is no
				// egress / `to` context (unlike source NAT, which has both).
				// The `to` subtree was removed here so completion no longer
				// advertises it; a `to` scope under DNAT is rejected at strict
				// commit by validateDNATRuleSetToScopeAST (it was silently
				// dropped before the snapshot builder — the Rust DNAT runtime
				// models only `from`).
				"from": {desc: "Source of traffic to match", children: map[string]*schemaNode{
					"zone":             {desc: "Source zone name", args: 1, multi: true, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
					"interface":        {desc: "Ingress interface name", args: 1, multi: true, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
					"routing-instance": {desc: "Ingress routing instance name", args: 1, multi: true, placeholder: "<routing-instance>", children: nil},
				}},
				"rule": {desc: "Destination NAT rule name", args: 1, placeholder: "<rule-name>", children: map[string]*schemaNode{
					"match": {desc: "Match criteria", closedWorld: true, children: map[string]*schemaNode{
						"source-address":           {desc: "Source address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"source-address-name":      {desc: "Source address book entry to match", args: 1, multi: true, placeholder: "<address-name>", children: nil},
						"destination-address":      {desc: "Destination address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"destination-address-name": {desc: "Destination address book entry to match", args: 1, multi: true, placeholder: "<address-name>", children: nil},
						"destination-port":         {desc: "Destination port or range to match", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"protocol":                 {desc: "IP protocol to match", args: 1, multi: true, placeholder: "<protocol>", children: nil},
						"application":              {desc: "Application to match", args: 1, multi: true, placeholder: "<application>", children: nil},
					}},
					// #4313 PR-B — FIRST production closed-world subtree flip.
					// The destination-NAT rule then-action is LEAF-COMPLETE: the
					// Junos grammar under a DNAT rule `then` is exactly
					// `destination-nat { off | pool <pool-name> }` — there is no
					// persistent-nat (a source-NAT-only feature), no other action
					// keyword, and the pool reference is a terminal name with no
					// sub-block. Every valid keyword at every level below `then`
					// is modeled here (then→destination-nat; destination-nat→
					// off|pool; off/pool→leaf), and the compiler
					// (compileNATDestination, compiler_nat.go) reads only these
					// same keywords — so closing this subtree cannot false-reject
					// any valid config (the #4191 class the umbrella warns about).
					// closedWorld is inherited down every descendant level by
					// walkSchemaNode's childClosed fold, so an unmodeled keyword
					// anywhere under `then` (a typo like `poool`, or garbage
					// trailing a valid action) is REJECTED at strict operator
					// commit instead of committing clean and being silently
					// dropped by the compiler (the #4313 silent-inert bug). The
					// tolerant Load/SyncApply path downgrades the reject to a
					// warning (#1960, configstore compileTreeLenient), so a
					// stored or peer-synced config is not bricked.
					//
					// NOT flipped (yet): the SOURCE-NAT rule then-action above is
					// deliberately left open-world because Junos permits
					// `then source-nat pool <name> persistent-nat { ... }` at the
					// rule level, which xpf instead models per-pool (`security nat
					// source pool <name> persistent-nat`, ~line 360). Closing the
					// source-NAT then would false-reject that valid Junos config;
					// it is a follow-up once the rule-level persistent-nat leaves
					// are modeled (or an accept-with-advisory decision is made).
					"then": {desc: "Destination NAT action", closedWorld: true, children: map[string]*schemaNode{
						"destination-nat": {desc: "Destination NAT translation", children: map[string]*schemaNode{
							"off":  {desc: "Disable destination NAT for matching traffic (no-translate exemption)", children: nil},
							"pool": {desc: "Translate using a destination NAT pool", args: 1, valueHint: ValueHintPoolName, placeholder: "<pool-name>", children: nil},
						}},
					}},
				}},
			}},
		}},
		"static": {desc: "Static NAT configuration", children: map[string]*schemaNode{
			"rule-set": {desc: "Static NAT rule-set name", args: 1, placeholder: "<rule-set-name>", children: map[string]*schemaNode{
				// `from` scopes the rule-set to an ingress context. The
				// dataplane enforces it on the inbound (DNAT) direction and,
				// symmetrically, on the reverse (SNAT) egress direction
				// (static_nat.rs match_dnat / match_snat). Junos static NAT
				// has no `to` clause (unlike source/destination NAT) — only
				// `from` (zone | interface | routing-instance). #3096 enforces
				// all three scope kinds, so each is declared for commit-time
				// validation and CLI completion (#2008 H15).
				"from": {desc: "Source of traffic to match", children: map[string]*schemaNode{
					"zone":             {desc: "Source zone name", args: 1, multi: true, valueHint: ValueHintZoneName, placeholder: "<zone-name>", children: nil},
					"interface":        {desc: "Ingress interface name", args: 1, multi: true, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: nil},
					"routing-instance": {desc: "Ingress routing instance name", args: 1, multi: true, placeholder: "<routing-instance>", children: nil},
				}},
				"rule": {desc: "Static NAT rule name", args: 1, placeholder: "<rule-name>", children: map[string]*schemaNode{
					// M3 (#2008): the static-NAT rule `match` reads
					// `destination-address` and `source-address` children
					// at compile (compiler_nat.go static loop ~762-771),
					// but the schema left `match.children: nil` — so those
					// keywords fell through with no structural completion
					// and schema_walk.go skipped the subtree entirely. The
					// values are address prefixes OR address-book names
					// (consumed verbatim by nodeVal), so they stay untyped
					// like the source/destination-NAT match leaves above.
					"match": {desc: "Match criteria", closedWorld: true, children: map[string]*schemaNode{
						"destination-address": {desc: "Destination address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						"source-address":      {desc: "Source address prefix to match", args: 1, multi: true, placeholder: "<prefix>", children: nil},
						// #2491: external (pre-translation) destination port the
						// inbound packet must carry for a port-mapped static-NAT
						// rule (`then static-nat prefix <ip> mapped-port <port>`).
						// Typed 1..65535 so a garbage or out-of-range port fails
						// at commit instead of silently dropping the rule.
						"destination-port": {desc: "Destination port to match", args: 1, valueType: ValueInteger, valueDesc: "TCP/UDP destination port (1-65535)", valueExamples: []string{"443", "8080"}, validator: ValidateInteger(1, 65535), placeholder: "<port>", children: nil},
					}},
					// #2491: `static-nat` stays a free-form leaf (children: nil)
					// so `prefix <ip> [mapped-port <port>]`, `nptv6-prefix
					// <prefix>`, and `inet` all collapse onto ONE leaf node and
					// the compiler reads the tokens from Keys. Adding children
					// here would split the mapped-port modifier off the prefix
					// value and regress SetPath grouping (schema.go: children==
					// nil is the replace-vs-container signal). The mapped-port
					// range is validated in the compiler (compileNATStatic).
					"then": {desc: "Static NAT action", children: map[string]*schemaNode{
						"static-nat": {desc: "Static NAT translation (prefix [mapped-port <port>]|prefix-name <name>|nptv6-prefix|inet [routing-instance <ri>])", children: nil},
					}},
				}},
			}},
		}},
		// #4313 — closed-world flip. `security nat nat64` is an xpf-NATIVE
		// stanza (Junos does NAT64 via source/destination NAT + `then static-nat
		// inet`, not this spelling), so its grammar IS exactly what xpf models
		// and compiles — there is no external Junos superset to false-reject.
		// The container's only child is `rule-set`, and a rule-set's only
		// children are `prefix` and `source-pool` (both modeled, both value
		// leaves whose value rides on the same statement line). The compiler
		// (compiler_nat.go compileNAT64) reads ONLY prefix + source-pool and the
		// struct (NAT64RuleSet) holds ONLY those two — so the subtree is
		// leaf-complete by construction and closing it cannot false-reject a
		// valid config. Silent-drop here is a real footgun: a typo'd `prefx`
		// left NAT64RuleSet.Prefix empty, validateNAT64PrefixStrict skipped the
		// rule (`Prefix == ""` → continue), and the NAT64 translation silently
		// did nothing — IPv6-only clients lost IPv4 reachability with no error.
		// closedWorld inherits down every level (childClosed fold), so a typo at
		// the nat64 level (`rulset`) OR under a rule-set (`prefx`/`source-pol`)
		// is REJECTED at strict commit; the tolerant Load/SyncApply path
		// downgrades to a warning (#1960).
		"nat64": {desc: "NAT64 (IPv6-to-IPv4) translation", closedWorld: true, children: map[string]*schemaNode{
			"rule-set": {desc: "NAT64 rule-set name", args: 1, placeholder: "<rule-set-name>", children: map[string]*schemaNode{
				"prefix":      {desc: "NAT64 IPv6 prefix (must be /96)", args: 1, placeholder: "<ipv6-prefix>", children: nil},
				"source-pool": {desc: "Source NAT pool for the translated IPv4 source", args: 1, placeholder: "<pool-name>", children: nil},
			}},
		}},
		// #4313 — closed-world flip. `security nat natv6v4` is an xpf-NATIVE
		// options stanza whose entire grammar is the single flag
		// `no-v6-frag-header` (modeled). The compiler (compiler_nat.go) reads
		// ONLY that keyword and the struct (NATv6v4Config) holds ONLY
		// NoV6FragHeader, so the subtree is leaf-complete by construction. A
		// typo (`no-v6-frag-heder`) previously committed clean and silently left
		// the IPv6 fragment header in translated packets; it is now rejected at
		// strict commit (lenient path warns, #1960).
		"natv6v4": {desc: "NAT64 IPv6-to-IPv4 options", closedWorld: true, children: map[string]*schemaNode{
			"no-v6-frag-header": {desc: "Omit the IPv6 fragment header in translated packets", children: nil},
		}},
		"proxy-arp": {desc: "Proxy ARP for NAT pool addresses", children: map[string]*schemaNode{
			"interface": {desc: "Interface to answer proxy ARP on", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>", children: map[string]*schemaNode{
				"address": {desc: "Address, prefix or range to answer ARP for", args: 1, multi: true, placeholder: "<address>", children: nil},
			}},
		}},
	}},
	"address-book": {desc: "Address books", children: map[string]*schemaNode{
		"global": {desc: "Global address book", children: map[string]*schemaNode{
			"address": {desc: "Named address (name and prefix)", args: 2, multi: true, placeholder: "<address-name>", children: nil},
			"address-set": {desc: "Address set name", args: 1, valueHint: ValueHintAddressName, placeholder: "<address-set-name>", children: map[string]*schemaNode{
				"address":     {desc: "Address to include in this set", args: 1, multi: true, placeholder: "<address-name>", children: nil},
				"address-set": {desc: "Nested address set to include", args: 1, multi: true, valueHint: ValueHintAddressName, placeholder: "<address-set-name>", children: nil},
				// NOT tagged scalar:true (#3332): AddressSet has no Description
				// field (types_security.go) and parseAddressBookEntries does
				// not read an address-set `description` child, so the value is
				// currently unsupported and discarded at compile. An arity gate
				// here would assert validation on a feature that has no effect;
				// tag it scalar only if/when AddressSet.Description is wired.
				"description": {desc: "Address set description", args: 1, placeholder: "<text>", children: nil},
			}},
		}},
	}},
	"log": {desc: "Security logging configuration", children: map[string]*schemaNode{
		// #3349: typed enum/value leaves so a typo (`mode steam`,
		// `format sdsyslog`, `severity wraning`, `facility locl0`,
		// `category sesion`, a non-numeric source-interface unit) fails the
		// commit instead of silently falling back at runtime (mode->stream,
		// format->RFC3164, severity->0=no floor, facility->local0,
		// category->0=all). Enum sets are pinned to the runtime parsers in
		// pkg/logging (daemon_system.go applyLogStreams + ParseSeverity /
		// ParseFacility / ParseCategory); keep in sync if those change.
		"mode": {desc: "Logging mode (stream|event)", args: 1, placeholder: "<mode>",
			valueType: ValueEnumOf, valueDesc: "security log mode",
			valueExamples: []string{"stream", "event"},
			validator:     ValidateEnum(syslogLogModes), children: nil},
		"format": {desc: "Log format (sd-syslog|syslog|binary|structured)", args: 1, placeholder: "<format>",
			valueType: ValueEnumOf, valueDesc: "security log format",
			valueExamples: []string{"sd-syslog", "syslog", "binary", "structured"},
			validator:     ValidateEnum(syslogLogFormats), children: nil},
		"source-interface": {desc: "Interface whose address is used as the syslog source", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>",
			valueType: ValueIdentifier, valueDesc: "interface name (optionally .<unit>)",
			valueExamples: []string{"ge-0-0-0", "reth1.100"},
			validator:     ValidateSyslogSourceInterface, children: nil},
		"stream": {desc: "Syslog stream name", args: 1, valueHint: ValueHintStreamName, placeholder: "<stream-name>", children: map[string]*schemaNode{
			"host": {desc: "Syslog server address", args: 1, placeholder: "<address>", children: nil},
			// `port` validation (direct AND nested host{port}) lives in the
			// validateSecurityLogStreamPortsAST compiler pass (#3349): the
			// value has two AST locations the declarative schema walker cannot
			// express, the same dual-location rationale as tcp-mss.
			"port": {desc: "Syslog server port (default 514)", args: 1, placeholder: "<port>", children: nil},
			"severity": {desc: "Severity filter (any|emergency|alert|critical|error|warning|notice|info|debug|none)", args: 1, placeholder: "<severity>",
				valueType: ValueEnumOf, valueDesc: "syslog severity floor",
				valueExamples: []string{"critical", "error", "warning", "info"},
				validator:     ValidateEnum(syslogSeverities), children: nil},
			"facility": {desc: "Syslog facility (e.g. local0; default local0)", args: 1, placeholder: "<facility>",
				valueType: ValueEnumOf, valueDesc: "syslog facility",
				valueExamples: []string{"local0", "local7", "daemon", "change-log"},
				validator:     ValidateEnum(syslogFacilities), children: nil},
			"format": {desc: "Per-stream format override", args: 1, placeholder: "<format>",
				valueType: ValueEnumOf, valueDesc: "security log format",
				valueExamples: []string{"sd-syslog", "syslog", "binary", "structured"},
				validator:     ValidateEnum(syslogLogFormats), children: nil},
			"category": {desc: "Event category filter (all or a specific category)", args: 1, placeholder: "<category>",
				valueType: ValueEnumOf, valueDesc: "security log category",
				valueExamples: []string{"all", "session", "policy", "screen", "firewall"},
				validator:     ValidateEnum(syslogCategories), children: nil},
			"source-address": {desc: "Source IP for this stream", args: 1, placeholder: "<address>",
				valueType: ValueIPAddress, valueDesc: "source IP address for this stream",
				valueExamples: []string{"10.0.1.10", "2001:db8::1"},
				validator:     ValidateIPAddress, children: nil},
			// #6875: modelled so the leaf is VALIDATED rather than absorbed by
			// the open-world stream subtree. Before this it parsed as an
			// unmodelled keyword, committed clean, and was compiled by nothing.
			"source-interface": {desc: "Interface whose address is used as this stream's syslog source", args: 1, valueHint: ValueHintInterfaceName, placeholder: "<interface-name>",
				valueType: ValueIdentifier, valueDesc: "interface name (optionally .<unit>)",
				valueExamples: []string{"ge-0-0-0", "reth1.100"},
				validator:     ValidateSyslogSourceInterface, children: nil},
			// H8 (#2008): transport is fully compiled
			// (compiler_security.go stream loop) and runtime-honored
			// (pkg/logging/syslog.go dial), but the schema declared no
			// `transport` child — so `protocol`/`tls-profile` got no
			// commit-time validation or `?` completion. The protocol enum
			// mirrors the runtime switch (tcp/tls handled, everything else
			// silently falls back to UDP), so a typo like `protocol tpc`
			// committed and then quietly used UDP. Validate it.
			// #6821: packedTail — the compiler reads this container's packed
			// tail (`transport protocol tls;`), so the gate must validate the
			// same expansion. Without the pairing the compact spelling of a
			// bogus `protocol` slipped past the enum below.
			"transport": {desc: "Stream transport (protocol + optional TLS profile)", packedTail: true, children: map[string]*schemaNode{
				"protocol": {desc: "Transport protocol (udp|tcp|tls)", args: 1, placeholder: "<protocol>",
					valueType: ValueEnumOf, valueDesc: "syslog transport protocol",
					valueExamples: []string{"udp", "tcp", "tls"},
					validator:     ValidateEnum([]string{"udp", "tcp", "tls"}), children: nil},
				// #3350: tls-profile is kept as a parseable leaf (so `?` /
				// completion still offer it) but is REJECTED at commit by
				// validateSecurityLogStreamTLSProfileAST (compiler.go) — it is
				// never resolved into a *tls.Config at runtime (daemon_system.go
				// passes nil; there is no TLS profile definition stanza to
				// resolve it to), so a TLS syslog stream silently uses the system
				// CA roots. The compiler gate gives a descriptive reject rather
				// than a bare schema "unknown token". `transport protocol tls`
				// alone (system-root TLS) stays valid.
				"tls-profile": {desc: "TLS profile name (rejected: not applied at runtime, #3350)", args: 1, placeholder: "<tls-profile-name>", children: nil},
			}},
		}},
		// H7 (#2008): `security log profile <name>` is a Junos log-routing
		// object — it targets a configured `stream` (`stream-name`), may be
		// the default profile (`default-profile`), and may carry per-category
		// field configuration. The whole stanza previously parsed but was
		// silently discarded (no schema child, no compiler case), so a real
		// imported config such as vsrx-ha.conf's `profile default-syslog`
		// committed with no validation and no effect. Declaring it restores
		// commit-time validation + `?` completion; the compiler cross-
		// references `stream-name` against the configured streams
		// (validateLogProfileStreamReferencesStrict). xpf per-stream routing
		// is already a Junos superset, so no runtime/dispatch change is made.
		"profile": {desc: "Security log profile (stream-routing object)", args: 1, placeholder: "<profile-name>", children: map[string]*schemaNode{
			"stream-name":     {desc: "Stream this profile routes to", args: 1, valueHint: ValueHintStreamName, placeholder: "<stream-name>", children: nil},
			"default-profile": {desc: "Designate this profile as the default", children: nil},
			"category": {desc: "Per-category field configuration", children: map[string]*schemaNode{
				"session": {desc: "Session category field configuration", children: map[string]*schemaNode{
					// #7502: say so. The compiler's `case "category":` arm is an
					// explicit no-op ("field-extra-name emission is out of scope
					// for this increment"), and LogProfile carries no field for
					// the value — so this leaf commits clean and is never
					// applied. Session log records are an audit surface, and an
					// operator adding an extra field is usually satisfying a
					// logging or compliance requirement; a silent under-record
					// is the worst way for that to fail.
					//
					// Of the 22 leaves the #7484/#7492 spelling-gate analysis
					// found unread by the compiler, 21 declare it in their own
					// `desc` — which is what `?` help shows. This was the
					// exception, and it read exactly like a working feature.
					// Declaring it does not implement it; it removes the false
					// advertisement now, at no risk to anything that works.
					"field-extra-name": {desc: "Extra field to include in session records (parsed, not implemented)", args: 1, placeholder: "<field>", children: nil},
				}},
			}},
		}},
	}},
	"flow": {desc: "Flow and session settings", children: map[string]*schemaNode{
		// #3440 H2: `security flow aging` was an opaque untyped node — the
		// schema walker skipped the whole subtree, so the compiler's
		// strconv.Atoi parse (compiler_security.go compileFlow) silently
		// accepted nonsense: a negative `early-ageout` (cast to a huge
		// uint64 in gc.SetAgingConfig) and an out-of-range watermark (`>100`
		// percent, which can never trip / never clear). Declaring the three
		// value-bearing leaves as typed integers makes the commit-check
		// schema gate (SchemaValidate) bound them: early-ageout is a
		// non-negative duration in seconds (0 = disabled), each watermark is
		// a percent in 0..100 (0 = disabled). The cross-field rule
		// (low-watermark < high-watermark when both nonzero) and unknown-leaf
		// rejection live in validateFlowAgingStrict (compiler_validate_strict.go)
		// because the schema walker is single-leaf and leaves unknown
		// keywords to the compiler. NOTE: aggressive watermark aging is
		// itself accepted-only on the userspace AF_XDP dataplane (see the
		// #3440 H1 warning in compiler_validate_warn.go) — typing the schema
		// only stops invalid values from being persisted, it does not make
		// the knob enforced.
		"aging": {desc: "Aggressive session aging thresholds", children: map[string]*schemaNode{
			"early-ageout":   {desc: "Shortened session timeout applied while aging is active", args: 1, valueType: ValueInteger, valueDesc: "Seconds (0 = disabled)", valueExamples: []string{"20", "60"}, validator: ValidateInteger(0, 86400), placeholder: "<seconds>", children: nil},
			"high-watermark": {desc: "Session-table utilization percent that activates aging", args: 1, valueType: ValueInteger, valueDesc: "Percent of max sessions (0 = disabled)", valueExamples: []string{"90"}, validator: ValidateInteger(0, 100), placeholder: "<percent>", children: nil},
			"low-watermark":  {desc: "Session-table utilization percent that deactivates aging", args: 1, valueType: ValueInteger, valueDesc: "Percent of max sessions (0 = disabled)", valueExamples: []string{"80"}, validator: ValidateInteger(0, 100), placeholder: "<percent>", children: nil},
		}},
		// #1979 Layer B (Tier 2): expand the opaque session-timeout
		// containers to real containers whose value-bearing sub-leaves are
		// typed. The compiler reads tcp-session's four `<kind>-timeout`
		// sub-leaves (compiler_security.go) + three presence flags;
		// EstablishedTimeout reaches the Rust u64 TCPSessionTimeout wire
		// field, the other three are stored only in TCPSessionConfig (not
		// wire-reaching) but share the same Duration-overflow ceiling and
		// declaring them is required for completion parity anyway. The bound
		// is MaxDurationSeconds (NOT u64-max): Rust SessionTimeouts::
		// from_seconds multiplies secs*1e9 unchecked (Layer A,
		// coerceWireSessionTimeout). The presence flags are declared
		// presence-only so completion still offers them.
		"tcp-session": {desc: "TCP session options (timeouts, SYN checks)", closedWorld: true, children: map[string]*schemaNode{
			"established-timeout": {desc: "Established TCP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "Established TCP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"1800"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
			"initial-timeout": {desc: "Initial (pre-established) TCP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "Initial TCP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"20"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
			"closing-timeout": {desc: "Closing TCP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "Closing TCP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"4"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
			"time-wait-timeout": {desc: "TIME_WAIT TCP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "TIME_WAIT TCP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"150"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
			"no-syn-check":           {desc: "Disable SYN check for TCP sessions", children: nil},
			"no-syn-check-in-tunnel": {desc: "Disable SYN check for tunneled TCP sessions", children: nil},
			"rst-invalidate-session": {desc: "Invalidate session on TCP RST", children: nil},
			"no-sequence-check":      {desc: "Disable TCP sequence-number checking for sessions", children: nil},
			"strict-syn-check":       {desc: "Require SYN as the first packet of a TCP session (accepted-only)", children: nil},
		}},
		"udp-session": {desc: "UDP session timeout (default 60 seconds)", closedWorld: true, children: map[string]*schemaNode{
			"timeout": {desc: "UDP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "UDP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"60"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
		}},
		"icmp-session": {desc: "ICMP session timeout (default 60 seconds)", closedWorld: true, children: map[string]*schemaNode{
			"timeout": {desc: "ICMP session timeout in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "ICMP session timeout in seconds (0..9223372036)",
				valueExamples: []string{"60"}, validator: ValidateInteger(0, MaxDurationSeconds), children: nil},
		}},
		// #1979 Layer B (Tier 3): tcp-mss stays OPAQUE here by design. Its
		// MSS value can live in EITHER position (flat `gre-in 1400` OR
		// hierarchical `gre-in { mss 1360; }`), which the declarative schema
		// walker cannot express. Validation runs in the compiler AST pre-walk
		// validateTCPMSSRanges (compiler.go), modeled on
		// validateVRRPTrackInterfaceAST. See compiler_security.go.
		"tcp-mss":                      {desc: "TCP MSS clamping (ipsec-vpn|gre-in|gre-out|all-tcp)", children: nil},
		"allow-dns-reply":              {desc: "Allow unsolicited DNS reply packets", children: nil},
		"allow-embedded-icmp":          {desc: "Allow ICMP error packets for existing sessions", children: nil},
		"gre-performance-acceleration": {desc: "Enable GRE performance acceleration", children: nil},
		"power-mode-disable":           {desc: "Disable power mode", children: nil},
		// #4231 (fable-167 P-3): five `security flow` knobs previously had no
		// schema leaf and no compiler case, so they committed clean and did
		// nothing with zero operator signal. Typing them here makes them
		// first-class (completion + value validation); compileFlow records
		// their presence and compiler_validate_warn.go emits an accepted-only
		// advisory (the #2078 tcp-session doctrine) because the userspace
		// AF_XDP dataplane does not enforce any of them yet. The two duration
		// leaves are bounded seconds (0 = unset); the three toggles are
		// presence-only.
		// Junos bounds: route-change-timeout / multicast-session-lifetime are
		// 6..1800 seconds. Match them so an out-of-range value is rejected at
		// commit (as Junos does) instead of accepted into a no-op knob.
		"route-change-timeout": {desc: "Timeout after a route change before flushing affected sessions (accepted-only)", args: 1, placeholder: "<seconds>",
			valueType: ValueInteger, valueDesc: "Seconds (6..1800)", valueExamples: []string{"30"}, validator: ValidateInteger(6, 1800), children: nil},
		"sync-icmp-session":               {desc: "Sync ICMP sessions to the HA peer (no-op — xpf already syncs ICMP sessions unconditionally)", children: nil},
		"force-ip-reassembly":             {desc: "Force IP fragment reassembly before forwarding (accepted-only)", children: nil},
		"multicast-session-lifetime":      {desc: "Multicast session lifetime in seconds (accepted-only)", args: 1, placeholder: "<seconds>", valueType: ValueInteger, valueDesc: "Seconds (6..1800)", valueExamples: []string{"30"}, validator: ValidateInteger(6, 1800), children: nil},
		"preserve-incoming-fragment-size": {desc: "Preserve incoming fragment size when forwarding (accepted-only)", children: nil},
		"traceoptions": {desc: "Flow trace debugging options", children: map[string]*schemaNode{
			"file": {desc: "Trace file name (with size/files options)", args: 1, placeholder: "<filename>", children: nil},
			// #3984: repeated keyed-list leaf — the compiler accumulates
			// every traceoptions `flag` sibling into Traceoptions.Flags via
			// FindChildren (compiler_security.go). `multi: true` keeps each
			// `set ... flag <flag>` a distinct sibling instead of replacing
			// the previous one.
			"flag": {desc: "Trace flag (e.g. basic-datapath, session)", args: 1, multi: true, placeholder: "<flag>", children: nil},
			"packet-filter": {desc: "Trace packet filter name", args: 1, placeholder: "<filter-name>", children: map[string]*schemaNode{
				"source-prefix":      {desc: "Source prefix to trace", args: 1, placeholder: "<prefix>", children: nil},
				"destination-prefix": {desc: "Destination prefix to trace", args: 1, placeholder: "<prefix>", children: nil},
				"protocol":           {desc: "Protocol to trace (name or number)", args: 1, placeholder: "<tcp|udp|icmp|icmp6|number>", children: nil},
			}},
		}},
	}},
	"alg": {desc: "ALG (application layer gateway) control", children: map[string]*schemaNode{
		"dns":  {desc: "DNS ALG (disable)", children: nil},
		"ftp":  {desc: "FTP ALG (disable)", children: nil},
		"sip":  {desc: "SIP ALG (disable)", children: nil},
		"tftp": {desc: "TFTP ALG (disable)", children: nil},
	}},
	"ike": {desc: "IKE (Phase 1) configuration", children: map[string]*schemaNode{
		// M2 (#2008): the IKE (Phase 1) proposal body is fully compiled
		// (compiler_ipsec.go compileIKE proposal loop) and rendered to
		// swanctl (pkg/ipsec/ipsec.go), but the schema left
		// `proposal.children: nil` — so authentication-method/dh-group/
		// lifetime-seconds got no commit-time validation or `?`
		// completion. A bad authentication-method errors only later at
		// swanctl-generation time (authMethodToSwan); a 0/garbage
		// dh-group or lifetime-seconds silently compiles to 0 and drops
		// the term. encryption/authentication-algorithm stay untyped:
		// the renderer normalizes arbitrary algorithm spellings by string
		// substitution, so an enum here would false-reject valid configs.
		//
		// dh-group uses ValidateDHGroup (both bare-integer and group<N>):
		// the IKE compiler loop (compiler_ipsec.go compileIKE) strips the
		// "group" prefix before strconv.Atoi, so both spellings compile
		// identically. This is the deliberate asymmetry with the Phase-2
		// IPsec proposal below, whose compiler does NOT strip the prefix
		// and therefore validates dh-group as a plain positive integer.
		// #4313 — closed-world flip (Phase-1 IKE proposal crypto). The Junos
		// `security ike proposal <name>` grammar is LEAF-COMPLETE after adding
		// `description` below: the full keyword set is exactly
		// authentication-method, authentication-algorithm, dh-group,
		// encryption-algorithm, lifetime-seconds, and description — all modeled
		// here. The compiler (compiler_ipsec.go, the IKE proposal loop) reads a
		// STRICT SUBSET of those (authentication-method / encryption-algorithm /
		// authentication-algorithm / dh-group / lifetime-seconds); `description`
		// is cosmetic and compiler-ignored. Every modeled leaf carries its value
		// on the same statement line (no nested value block in Junos), so
		// closed-world never descends into an AST child of a value leaf in
		// EITHER parser shape — it cannot false-reject a valid config (the #4191
		// class the umbrella warns about). Phase-1 has no lifetime-kilobytes
		// (that is a Phase-2/ESP volume-rekey knob), so — unlike the sibling
		// `security ipsec proposal` — this subtree is complete with description
		// alone.
		//
		// Silent-drop here FAILS OPEN on crypto: a fat-fingered
		// `encryption-algorith aes-256-cbc` or `authentication-algoritm sha-256`
		// used to commit clean, the compiler then found no such child, and the
		// IKE Phase-1 SA negotiated WITHOUT the operator's chosen cipher/hash —
		// a silent downgrade to whatever the proposal (or a proposal-set
		// default) still carried, believed to be aes-256 while it was not. The
		// flip REJECTS the typo at strict operator commit (SchemaValidate); the
		// tolerant Store.Load / SyncApply path downgrades the reject to a warning
		// (#1960, configstore compileTreeLenient), so a stored or peer-synced
		// config is never bricked.
		"proposal": {desc: "IKE proposal name", args: 1, placeholder: "<proposal-name>", packedStatements: true, closedWorld: true, children: map[string]*schemaNode{
			"authentication-method": {desc: "IKE authentication method", args: 1, placeholder: "<method>",
				valueType: ValueEnumOf, valueDesc: "IKE phase 1 authentication method",
				valueExamples: []string{"pre-shared-keys", "rsa-signatures", "ecdsa-signatures"},
				validator:     ValidateEnum([]string{"pre-shared-keys", "rsa-signatures", "ecdsa-signatures"}), children: nil},
			"dh-group": {desc: "Diffie-Hellman group (e.g. 14 or group14)", args: 1, placeholder: "<dh-group>",
				valueType: ValueDHGroup, valueDesc: "Diffie-Hellman group",
				valueExamples: []string{"2", "14", "group19"}, validator: ValidateDHGroup, children: nil},
			"encryption-algorithm":     {desc: "Encryption algorithm (e.g. aes-256-cbc, aes-256-gcm)", args: 1, placeholder: "<algorithm>", children: nil},
			"authentication-algorithm": {desc: "Authentication/integrity algorithm (e.g. sha-256, hmac-sha-256-128)", args: 1, placeholder: "<algorithm>", children: nil},
			"lifetime-seconds": {desc: "IKE SA lifetime in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "IKE SA lifetime in seconds",
				valueExamples: []string{"3600", "28800"}, validator: ValidateIntegerMin(1), children: nil},
			// #4313: modeled so the closed-world flip is LEAF-COMPLETE. Junos
			// allows a cosmetic `description` on an IKE proposal; xpf ignores it
			// at compile (the IKE proposal loop has no case for it), but it MUST
			// be modeled or closed-world would false-reject a valid config that
			// carries it. scalar:true rejects a trailing token (#3332) — a
			// multi-word description must be quoted.
			"description": {desc: "Proposal description", args: 1, scalar: true, placeholder: "<text>", children: nil},
		}},
		// packedStatements (#8768): compileIPsec reads `mode`, `proposals`,
		// `proposal-set` and `pre-shared-key` as separate statements, and the
		// packed spelling `policy p1 pre-shared-key ascii-text <k> mode main;`
		// used to collapse them into one node, recovering the PSK and silently
		// losing the mode. Both spellings compiled cleanly and disagreed.
		"policy": {desc: "IKE policy name", args: 1, placeholder: "<policy-name>", packedStatements: true, children: map[string]*schemaNode{
			// #3896: type mode/version/nat-traversal so a typo fails closed at
			// commit instead of silently downgrading. The accepted sets mirror
			// exactly what the strongSwan generator (pkg/ipsec) recognizes:
			// mode "aggressive" → aggressive=yes else main (ike.go
			// resolveIKESettings); any unrecognized spelling silently fell back
			// to main-mode before this gate.
			"mode": {desc: "IKE phase 1 mode (main|aggressive)", args: 1, placeholder: "<mode>",
				valueType: ValueEnumOf, valueDesc: "IKE phase 1 negotiation mode",
				valueExamples: []string{"main", "aggressive"},
				validator:     ValidateEnum([]string{"main", "aggressive"}), children: nil},
			// multi (#3904): `proposals [ p1 p2 ]` offers every listed IKE
			// proposal for phase-1 negotiation. Without multi the flat-set
			// path strands every reference past the first as a child node and
			// the compiler dropped them (crypto-negotiation narrowing).
			"proposals": {desc: "IKE proposal reference(s)", args: 1, multi: true, placeholder: "<proposal-name>", children: nil},
			// #4297 (V-1): predefined IKE proposal-set shorthand. Typed so a
			// typo (`proposal-set standrd`) fails closed at commit; the
			// compiler (expandIKEProposalSets) expands a valid keyword into
			// concrete synthetic proposals so the common vSRX idiom commits a
			// working tunnel instead of being silently dropped.
			"proposal-set": {desc: "Predefined IKE proposal set", args: 1, placeholder: "<set>",
				valueType: ValueEnumOf, valueDesc: "predefined IKE proposal set",
				valueExamples: []string{"standard", "suiteb-gcm-128"},
				validator:     ValidateEnum(ProposalSetNames()), children: nil},
			// args: 2 declares the shape the description has always stated and
			// the compiler has always read — `pre-shared-key ascii-text <key>`
			// is THREE tokens, and compileIPsec takes the value from Keys[2].
			// Leaving args at 0 meant consumeNodeKeys could not tell where this
			// statement ended, so a packed tail carrying a SECOND statement
			// (`... mode main`) could not be split and the second was swallowed
			// (#8768). Declaring the arity is what makes the split possible.
			"pre-shared-key": {desc: "Pre-shared key (ascii-text <key>)", args: 2, placeholder: "ascii-text <key>", children: nil},
		}},
		// packedStatements (#8768): compileIPsec reads address, external-interface,
		// local-identity and the rest as separate statements; the packed spelling
		// collapsed them into one node and lost everything after the first.
		"gateway": {desc: "IKE gateway (VPN peer) name", args: 1, placeholder: "<gateway-name>", packedStatements: true, children: map[string]*schemaNode{
			"address":            {desc: "Remote gateway address", args: 1, placeholder: "<address>", children: nil},
			"local-address":      {desc: "Local IKE address", args: 1, placeholder: "<address>", children: nil},
			"ike-policy":         {desc: "IKE policy reference", args: 1, placeholder: "<policy-name>", children: nil},
			"external-interface": {desc: "External interface for IKE (derives local address)", args: 1, placeholder: "<interface-name>", children: nil},
			"local-certificate":  {desc: "Local certificate for IKE authentication", args: 1, placeholder: "<certificate-name>", children: nil},
			"version": {desc: "IKE version (v1-only|v2-only)", args: 1, placeholder: "<version>",
				valueType: ValueEnumOf, valueDesc: "IKE protocol version pin",
				valueExamples: []string{"v1-only", "v2-only"},
				validator:     ValidateEnum([]string{"v1-only", "v2-only"}), children: nil},
			"no-nat-traversal": {desc: "Disable NAT traversal (UDP encapsulation)", children: nil},
			"nat-traversal": {desc: "NAT traversal (enable|disable|force)", args: 1, placeholder: "<mode>",
				valueType: ValueEnumOf, valueDesc: "NAT traversal (UDP encapsulation) mode",
				valueExamples: []string{"enable", "disable", "force"},
				validator:     ValidateEnum([]string{"enable", "disable", "force"}), children: nil},
			// #4313 PR-C — closed-world flip (both the `security ike gateway`
			// and `security ipsec gateway` copies of this identical block). The
			// Junos `dead-peer-detection` grammar is LEAF-COMPLETE: exactly
			// `always-send`, `optimized`, `probe-idle-tunnel`, `interval
			// <seconds>`, and `threshold <count>` (all modeled), and the
			// compiler (compiler_ipsec.go parseDeadPeerDetectionNode) reads ONLY
			// these five keywords. always-send/optimized/probe-idle-tunnel are
			// bare flags; interval/threshold carry their value on the same
			// statement line (no nested block), so closed-world never descends
			// into an AST child — it cannot false-reject a valid config (#4191
			// class). A typo (`intervl`) or garbage keyword under DPD is now
			// REJECTED at strict commit instead of silently dropped (the #4313
			// bug — a fat-fingered interval/threshold would silently keep the
			// Junos default); the tolerant Load/SyncApply path downgrades to a
			// warning (#1960).
			"dead-peer-detection": {desc: "Dead peer detection", packedStatements: true, closedWorld: true, children: map[string]*schemaNode{
				"always-send":       {desc: "Send DPD probes regardless of traffic", children: nil},
				"optimized":         {desc: "Optimized DPD probing", children: nil},
				"probe-idle-tunnel": {desc: "Probe idle tunnels", children: nil},
				"interval":          {desc: "DPD probe interval in seconds (default 10)", args: 1, valueType: ValueInteger, valueDesc: "Probe interval in seconds (1..3600)", valueExamples: []string{"10", "30"}, validator: ValidateInteger(1, 3600), placeholder: "<seconds>", children: nil},
				"threshold":         {desc: "Failed-probe count before peer is dead (default 5)", args: 1, valueType: ValueInteger, valueDesc: "Failed-probe count (1..100)", valueExamples: []string{"5", "3"}, validator: ValidateInteger(1, 100), placeholder: "<count>", children: nil},
			}},
			"local-identity":  {desc: "Local IKE identity (type and value)", args: 2, children: nil},
			"remote-identity": {desc: "Remote IKE identity (type and value)", args: 2, children: nil},
			"dynamic": {desc: "Dynamic peer (peer has a dynamic IP). With `hostname <fqdn>` the peer is DNS-resolved; a bare `dynamic` block marks a responder-only peer (remote_addrs = %any, #2404)", children: map[string]*schemaNode{
				"hostname": {desc: "Dynamic peer FQDN (DNS-resolved)", args: 1, scalar: true, placeholder: "<fqdn>", children: nil},
			}},
		}},
	}},
	"ipsec": {desc: "IPsec configuration", children: map[string]*schemaNode{
		// M2 (#2008): IPsec (Phase 2) proposal mirror of the IKE proposal
		// above. The Phase 2 proposal carries `protocol` (esp|ah) instead
		// of authentication-method and has no DPD; it is compiled by
		// compiler_ipsec.go compileIPsec proposal loop and rendered by
		// buildESPProposal. Same typing rationale: validate dh-group and
		// lifetime-seconds (silent-zero footgun), leave the algorithm and
		// protocol spellings untyped (the renderer accepts a wide set).
		//
		// dh-group is validated with ValidateDHGroup (both the bare integer
		// and the Junos `group<N>` spelling). As of #2639 the Phase-2
		// compiler (compiler_ipsec.go compileIPsec proposal loop) strips the
		// "group" prefix via the shared parseDHGroup helper — exactly like
		// the IKE loop — so `group14` now compiles to DHGroup=14 and renders
		// the modp/ecp term. Before #2639 the loop used a bare strconv.Atoi
		// that dropped `group14` to DHGroup=0 (silent PFS loss), and this
		// gate deliberately rejected the prefixed spelling to stay
		// compiler-faithful; the compiler fix lets both gates accept it.
		// #4313 — closed-world flip (Phase-2 ESP crypto), the sibling of the
		// already-closed Phase-1 `security ike proposal`. The subtree is now
		// LEAF-COMPLETE: the full Junos `security ipsec proposal <name>` grammar
		// is exactly protocol, encryption-algorithm, authentication-algorithm,
		// dh-group, lifetime-seconds, lifetime-kilobytes, and description. The
		// first five were already modeled; this change models lifetime-kilobytes
		// (the ESP volume-rekey knob that DISTINGUISHES the Phase-2 proposal from
		// the Phase-1 IKE proposal — Phase-1 has none) and the cosmetic
		// description. The compiler (compiler_ipsec.go, the IPsec proposal loop)
		// reads protocol / encryption-algorithm / authentication-algorithm /
		// dh-group / lifetime-seconds / lifetime-kilobytes and ignores
		// description, i.e. a subset of the modeled set — so closing carries no
		// false-reject risk (the #4191 class). Every leaf carries its value on
		// the same statement line (no nested value block in Junos), so
		// closed-world never descends into an AST child of a value leaf in
		// either parser shape. Silent-drop here FAILS OPEN on crypto exactly
		// like the IKE proposal: a fat-fingered `encryption-algorith` used to
		// commit clean and the ESP SA negotiated WITHOUT the operator's cipher
		// (a silent downgrade). The flip rejects the typo at strict commit; the
		// tolerant Load/SyncApply path downgrades it to a warning (#1960).
		// lifetime-kilobytes is captured but accepted-only (not enforced) — see
		// the ValidateConfig advisory in compiler_validate_warn.go.
		"proposal": {desc: "IPsec (Phase 2) proposal name", args: 1, placeholder: "<proposal-name>", packedStatements: true, closedWorld: true, children: map[string]*schemaNode{
			// #4298 (V-2): type the protocol so a typo fails closed. `ah`
			// is an accepted value here (grammar-valid) but hard-rejected at
			// commit by validateIPsecProposalProtocolStrict — xpf does not
			// support AH and must NOT silently render it as ESP with a
			// fabricated cipher.
			"protocol": {desc: "IPsec protocol (esp|ah)", args: 1, placeholder: "<protocol>",
				valueType: ValueEnumOf, valueDesc: "IPsec security protocol",
				valueExamples: []string{"esp", "ah"},
				validator:     ValidateEnum([]string{"esp", "ah"}), children: nil},
			"encryption-algorithm":     {desc: "Encryption algorithm (e.g. aes-256-cbc, aes-256-gcm)", args: 1, placeholder: "<algorithm>", children: nil},
			"authentication-algorithm": {desc: "Authentication/integrity algorithm (e.g. hmac-sha-256-128)", args: 1, placeholder: "<algorithm>", children: nil},
			"dh-group": {desc: "Diffie-Hellman group for PFS (e.g. 14 or group14)", args: 1, placeholder: "<dh-group>",
				valueType: ValueDHGroup, valueDesc: "Diffie-Hellman group (PFS modp/ecp number)",
				valueExamples: []string{"2", "14", "group19"}, validator: ValidateDHGroup, children: nil},
			"lifetime-seconds": {desc: "IPsec SA lifetime in seconds", args: 1, placeholder: "<seconds>",
				valueType: ValueInteger, valueDesc: "IPsec SA lifetime in seconds",
				valueExamples: []string{"3600", "28800"}, validator: ValidateIntegerMin(1), children: nil},
			// #4313: modeled so the closed-world flip is LEAF-COMPLETE. The ESP
			// volume-based rekey threshold; captured (IPsecProposal.LifetimeKilobytes)
			// but accepted-only — the renderer does not yet program a byte-based
			// rekey, so ValidateConfig emits an advisory (compiler_validate_warn.go).
			"lifetime-kilobytes": {desc: "IPsec SA volume-based rekey threshold in kilobytes (accepted, not enforced)", args: 1, placeholder: "<kilobytes>",
				valueType: ValueInteger, valueDesc: "IPsec SA lifetime in kilobytes",
				valueExamples: []string{"100000", "4294967294"}, validator: ValidateIntegerMin(1), children: nil},
			// #4313: modeled so the closed-world flip is LEAF-COMPLETE. Junos
			// allows a cosmetic `description` on an IPsec proposal; xpf ignores it
			// at compile (the IPsec proposal loop has no case for it), but it MUST
			// be modeled or closed-world would false-reject a valid config that
			// carries it. scalar:true rejects a trailing token (#3332) — a
			// multi-word description must be quoted.
			"description": {desc: "Proposal description", args: 1, scalar: true, placeholder: "<text>", children: nil},
		}},
		"policy": {desc: "IPsec policy name", args: 1, placeholder: "<policy-name>", children: map[string]*schemaNode{
			"perfect-forward-secrecy": {desc: "Perfect forward secrecy (keys group<N>)", children: nil},
			// multi (#3904): mirror of the IKE proposals leaf — offer every
			// listed ESP proposal for phase-2 negotiation.
			"proposals": {desc: "IPsec proposal reference(s)", args: 1, multi: true, placeholder: "<proposal-name>", children: nil},
			// #4297 (V-1): predefined IPsec (ESP) proposal-set shorthand;
			// mirror of the IKE policy leaf (expandIPsecProposalSets).
			"proposal-set": {desc: "Predefined IPsec proposal set", args: 1, placeholder: "<set>",
				valueType: ValueEnumOf, valueDesc: "predefined IPsec proposal set",
				valueExamples: []string{"standard", "suiteb-gcm-128"},
				validator:     ValidateEnum(ProposalSetNames()), children: nil},
		}},
		// #8796: the `security ipsec` gateway is the same container as the
		// `security ike` one above — same children, same compiler path — and it
		// needs the same opt-in. Fixing one and not the other leaves the defect
		// live at a spelling an operator reaches the same way.
		"gateway": {desc: "IKE gateway (VPN peer) name", args: 1, packedStatements: true, placeholder: "<gateway-name>", children: map[string]*schemaNode{
			"address":            {desc: "Remote gateway address", args: 1, placeholder: "<address>", children: nil},
			"local-address":      {desc: "Local IKE address", args: 1, placeholder: "<address>", children: nil},
			"ike-policy":         {desc: "IKE policy reference", args: 1, placeholder: "<policy-name>", children: nil},
			"external-interface": {desc: "External interface for IKE (derives local address)", args: 1, placeholder: "<interface-name>", children: nil},
			"local-certificate":  {desc: "Local certificate for IKE authentication", args: 1, placeholder: "<certificate-name>", children: nil},
			"version": {desc: "IKE version (v1-only|v2-only)", args: 1, placeholder: "<version>",
				valueType: ValueEnumOf, valueDesc: "IKE protocol version pin",
				valueExamples: []string{"v1-only", "v2-only"},
				validator:     ValidateEnum([]string{"v1-only", "v2-only"}), children: nil},
			"no-nat-traversal": {desc: "Disable NAT traversal (UDP encapsulation)", children: nil},
			"nat-traversal": {desc: "NAT traversal (enable|disable|force)", args: 1, placeholder: "<mode>",
				valueType: ValueEnumOf, valueDesc: "NAT traversal (UDP encapsulation) mode",
				valueExamples: []string{"enable", "disable", "force"},
				validator:     ValidateEnum([]string{"enable", "disable", "force"}), children: nil},
			// #4313 PR-C — closed-world flip (both the `security ike gateway`
			// and `security ipsec gateway` copies of this identical block). The
			// Junos `dead-peer-detection` grammar is LEAF-COMPLETE: exactly
			// `always-send`, `optimized`, `probe-idle-tunnel`, `interval
			// <seconds>`, and `threshold <count>` (all modeled), and the
			// compiler (compiler_ipsec.go parseDeadPeerDetectionNode) reads ONLY
			// these five keywords. always-send/optimized/probe-idle-tunnel are
			// bare flags; interval/threshold carry their value on the same
			// statement line (no nested block), so closed-world never descends
			// into an AST child — it cannot false-reject a valid config (#4191
			// class). A typo (`intervl`) or garbage keyword under DPD is now
			// REJECTED at strict commit instead of silently dropped (the #4313
			// bug — a fat-fingered interval/threshold would silently keep the
			// Junos default); the tolerant Load/SyncApply path downgrades to a
			// warning (#1960).
			"dead-peer-detection": {desc: "Dead peer detection", closedWorld: true, children: map[string]*schemaNode{
				"always-send":       {desc: "Send DPD probes regardless of traffic", children: nil},
				"optimized":         {desc: "Optimized DPD probing", children: nil},
				"probe-idle-tunnel": {desc: "Probe idle tunnels", children: nil},
				"interval":          {desc: "DPD probe interval in seconds (default 10)", args: 1, valueType: ValueInteger, valueDesc: "Probe interval in seconds (1..3600)", valueExamples: []string{"10", "30"}, validator: ValidateInteger(1, 3600), placeholder: "<seconds>", children: nil},
				"threshold":         {desc: "Failed-probe count before peer is dead (default 5)", args: 1, valueType: ValueInteger, valueDesc: "Failed-probe count (1..100)", valueExamples: []string{"5", "3"}, validator: ValidateInteger(1, 100), placeholder: "<count>", children: nil},
			}},
			"local-identity":  {desc: "Local IKE identity (type and value)", args: 2, children: nil},
			"remote-identity": {desc: "Remote IKE identity (type and value)", args: 2, children: nil},
			"dynamic": {desc: "Dynamic peer (peer has a dynamic IP). With `hostname <fqdn>` the peer is DNS-resolved; a bare `dynamic` block marks a responder-only peer (remote_addrs = %any, #2404)", children: map[string]*schemaNode{
				"hostname": {desc: "Dynamic peer FQDN (DNS-resolved)", args: 1, scalar: true, placeholder: "<fqdn>", children: nil},
			}},
		}},
		"vpn": {desc: "IPsec VPN tunnel name", args: 1, placeholder: "<vpn-name>", children: map[string]*schemaNode{
			// #5297: type the leaf so a non-canonical bind-interface (anything
			// but st<N> / st<N>.<unit>) fails closed at commit-check instead of
			// committing and then creating no XFRM device at reconciliation
			// (silent route-based-VPN down). The compiled-config strict gate
			// (compiler_ipsec_bindiface.go) keeps its parallel id-0 rejection
			// for group-expanded / packed forms the schema layer can miss
			// (#1960 layered defense). Tolerant Load/SyncApply downgrades this
			// to a warning (schemaValidateExpandedTree in configstore).
			"bind-interface": {desc: "Secure-tunnel interface to bind (st<N> or st<N>.<unit>)", args: 1, placeholder: "<st-interface>",
				valueType: ValueSecureTunnelIf, valueDesc: "IPsec secure-tunnel interface (st<N> or st<N>.<unit>)",
				valueExamples: []string{"st0", "st0.1"},
				validator:     ValidateSecureTunnelBindInterface, children: nil},
			// #5649 (C181-M22): type the enum so a typo (`cler`) fails closed at
			// commit instead of storing verbatim and silently becoming
			// strongSwan's copy-DF default. The renderer at pkg/ipsec/policy.go
			// only emits copy_df for copy/set/clear and OMITS the directive for
			// anything else, so `df-bit cler` would leave the outer DF copied
			// (the opposite of an intended `clear`) and blackhole oversized
			// encapsulated packets via PMTUD while commit reported success.
			// Mirrors the #4301 establish-tunnels pattern; the copy/set/clear
			// set matches the renderer's switch exactly.
			"df-bit": {desc: "Outer-header DF bit handling (copy|set|clear)", args: 1, placeholder: "<mode>",
				valueType: ValueEnumOf, valueDesc: "outer-header DF bit mode",
				valueExamples: []string{"copy", "set", "clear"},
				validator:     ValidateEnum([]string{"copy", "set", "clear"}), children: nil},
			// #4301 (V-5): type the enum so a typo (`on-tarffic`) fails closed
			// at commit instead of storing verbatim and silently degrading to
			// on-traffic. Only `immediately` is acted on (start_action =
			// start); on-traffic / responder-only are the initiate-later modes.
			"establish-tunnels": {desc: "Tunnel establishment (immediately|on-traffic|responder-only)", args: 1, placeholder: "<mode>",
				valueType: ValueEnumOf, valueDesc: "tunnel establishment mode",
				valueExamples: []string{"immediately", "on-traffic", "responder-only"},
				validator:     ValidateEnum([]string{"immediately", "on-traffic", "responder-only"}), children: nil},
			// #4300 (V-4): manual-key SA block. Grammar present for completion,
			// but validateIPsecManualKeyStrict hard-rejects any VPN carrying it
			// at commit — xpf has no manual-key path and must not leave a silent
			// dead tunnel.
			"manual": {desc: "Manual-key SA (NOT supported — rejected at commit; use an IKE-negotiated VPN)", children: map[string]*schemaNode{
				"protocol":                 {desc: "Manual SA protocol (esp|ah)", args: 1, placeholder: "<protocol>", children: nil},
				"spi":                      {desc: "Security parameter index", args: 1, placeholder: "<spi>", children: nil},
				"encryption":               {desc: "Manual SA encryption (algorithm + key)", children: nil},
				"authentication":           {desc: "Manual SA authentication (algorithm + key)", children: nil},
				"encryption-algorithm":     {desc: "Manual SA encryption algorithm", args: 1, placeholder: "<algorithm>", children: nil},
				"authentication-algorithm": {desc: "Manual SA authentication algorithm", args: 1, placeholder: "<algorithm>", children: nil},
			}},
			// #4299 (V-3): vpn-monitor. Accepted-but-not-enforced — captured so
			// ValidateConfig emits an advisory; xpf has no ICMP-probe liveness /
			// st0 interface-state coupling yet.
			//
			// #4313 PR-C — closed-world flip. The Junos `vpn-monitor` block is
			// LEAF-COMPLETE: its entire grammar is exactly `source-interface`,
			// `destination-ip`, and `optimized` (all modeled), and the compiler
			// (compiler_ipsec.go vpn-monitor arm ~line 478) reads ONLY these
			// three keywords. source-interface/destination-ip are value leaves
			// whose value rides on the same statement line and optimized is a
			// bare flag, so closed-world never descends into an AST child — it
			// cannot false-reject a valid config (#4191 class). A typo under
			// vpn-monitor is now REJECTED at strict commit instead of silently
			// dropped (the #4313 bug); the tolerant Load/SyncApply path
			// downgrades to a warning (#1960).
			// packedStatements (#8768): compileIPsec reads destination-ip and
			// source-interface as separate statements; the packed spelling
			// collapsed both into one node. Measured across every admitted leaf
			// pair, not the one pair it was first reported on.
			"vpn-monitor": {desc: "Tunnel liveness monitoring (accepted-but-not-enforced advisory)", packedStatements: true, closedWorld: true, children: map[string]*schemaNode{
				"source-interface": {desc: "Probe source interface", args: 1, placeholder: "<interface-name>", children: nil},
				"destination-ip":   {desc: "Probe destination IP", args: 1, placeholder: "<address>", children: nil},
				"optimized":        {desc: "Send probes only when there is no outbound traffic", children: nil},
			}},
			"local-identity":  {desc: "Local identity (default local traffic selector)", args: 1, placeholder: "<identity>", children: nil},
			"remote-identity": {desc: "Remote identity (default remote traffic selector)", args: 1, placeholder: "<identity>", children: nil},
			"pre-shared-key":  {desc: "Pre-shared key for this VPN", args: 1, placeholder: "<key>", children: nil},
			"local-address":   {desc: "Local tunnel endpoint address", args: 1, placeholder: "<address>", children: nil},
			// #4313 PR-C — closed-world flip. The Junos IPsec
			// `traffic-selector <name>` block is LEAF-COMPLETE: its entire
			// grammar is exactly `local-ip <prefix>` and `remote-ip <prefix>`
			// (both modeled), and the compiler (compiler_ipsec.go, the
			// traffic-selector loop ~line 495) reads ONLY these two keywords.
			// Each is a value leaf whose prefix rides on the same statement
			// line (no nested block in Junos), so closed-world never descends
			// into an AST child of local-ip/remote-ip in either parser shape —
			// it cannot false-reject a valid config (the #4191 class the
			// umbrella warns about). closedWorld is inherited down every
			// descendant level by walkSchemaNode's childClosed fold, so a typo
			// (`local-op`) or garbage keyword under the selector is REJECTED at
			// strict operator commit (SchemaValidate) instead of committing
			// clean and being silently dropped — the #4313 silent-inert bug
			// (a malformed selector would apply the wrong crypto proxy-id). The
			// tolerant Load/SyncApply path downgrades the reject to a warning
			// (#1960, configstore compileTreeLenient), so a stored or
			// peer-synced config is never bricked.
			"traffic-selector": {desc: "Traffic selector name", args: 1, placeholder: "<selector-name>", closedWorld: true, children: map[string]*schemaNode{
				"local-ip":  {desc: "Local traffic selector prefix", args: 1, placeholder: "<prefix>", children: nil},
				"remote-ip": {desc: "Remote traffic selector prefix", args: 1, placeholder: "<prefix>", children: nil},
			}},
			"ike": {desc: "IKE bindings for this VPN", children: map[string]*schemaNode{
				"gateway":      {desc: "IKE gateway reference", args: 1, placeholder: "<gateway-name>", children: nil},
				"ipsec-policy": {desc: "IPsec policy reference", args: 1, placeholder: "<policy-name>", children: nil},
			}},
		}},
	}},
	"dynamic-address": {desc: "Dynamic address feeds", children: map[string]*schemaNode{
		"feed-server": {desc: "Feed server name", args: 1, placeholder: "<server-name>", children: map[string]*schemaNode{
			"url":             {desc: "Feed URL (takes precedence over hostname)", args: 1, placeholder: "<url>", children: nil},
			"hostname":        {desc: "Server hostname for building per-feed URLs", args: 1, scalar: true, placeholder: "<hostname>", children: nil},
			"update-interval": {desc: "Feed refresh interval in seconds (default 3600)", args: 1, valueType: ValueInteger, valueDesc: "Seconds (> 0)", valueExamples: []string{"3600", "300"}, validator: ValidateInteger(1, MaxDurationSeconds), placeholder: "<seconds>", children: nil},
			"hold-interval":   {desc: "Drop a feed's last-good snapshot to empty after N seconds of fetch failure; omit to retain last-good forever (default)", args: 1, valueType: ValueInteger, valueDesc: "Seconds (> 0)", valueExamples: []string{"86400"}, validator: ValidateInteger(1, MaxDurationSeconds), placeholder: "<seconds>", children: nil},
			"feed-name": {desc: "Named feed on this server", args: 1, placeholder: "<feed-name>", children: map[string]*schemaNode{
				"path": {desc: "Path on the feed server for this feed", args: 1, placeholder: "<path>", children: nil},
			}},
		}},
		"address-name": {desc: "Dynamic address name bound to feeds", args: 1, placeholder: "<address-name>", children: map[string]*schemaNode{
			"profile": {desc: "Feed binding profile", children: map[string]*schemaNode{
				"feed-name": {desc: "Feed to bind to this address name", args: 1, placeholder: "<feed-name>", children: nil},
			}},
		}},
	}},
	"ssh-known-hosts": {desc: "SSH known hosts (written to /etc/ssh/ssh_known_hosts)", children: map[string]*schemaNode{
		"host": {desc: "Known host name or address", args: 1, placeholder: "<hostname>", children: nil},
	}},
	"policy-stats": {desc: "Security policy statistics", children: map[string]*schemaNode{
		"system-wide": {desc: "System-wide policy statistics (enable|disable)", args: 1, placeholder: "<enable|disable>", children: nil},
	}},
	"pre-id-default-policy": {desc: "Default policy before application identification", children: map[string]*schemaNode{
		"then": {desc: "Action", children: map[string]*schemaNode{
			// #3703: multi-value session-log LIST leaf (see sessionLogModeLeaf)
			// so a bracket `then log [ session-init session-close ]` lands BOTH
			// values and rejects an unknown token at commit. It was a container
			// whose bracket tail mis-nested and dropped the tail.
			"log": sessionLogModeLeaf("Logging options"),
		}},
	}},
}}

var schemaApplications = &schemaNode{desc: "Applications", children: map[string]*schemaNode{
	"application": {desc: "Application name", args: 1, valueHint: ValueHintAppName, placeholder: "<name>", children: map[string]*schemaNode{
		"protocol":         {desc: "Protocol", args: 1, placeholder: "<protocol>", children: nil},
		"destination-port": {desc: "Destination port", args: 1, placeholder: "<port>", children: nil},
		"source-port":      {desc: "Source port", args: 1, placeholder: "<port>", children: nil},
		// #3320: typed integer leaves (1..86400 s) so a malformed top-level
		// inactivity-timeout / timeout is rejected at commit-check by the
		// SchemaValidate gate (downgraded to a warning on the tolerant
		// load / peer-sync path by compileTreeLenient) instead of being silently
		// dropped to the global timeout. The inline-term shape (`term <t> ...
		// inactivity-timeout <n>`) is an opaque single statement to the schema
		// walk, so it is covered by validateApplicationSpecsStrict instead.
		"inactivity-timeout": {desc: "Inactivity timeout", args: 1, valueType: ValueInteger, valueDesc: "Timeout in seconds", valueExamples: []string{"300", "1800"}, validator: ValidateInteger(appTimeoutMin, appTimeoutMax), placeholder: "<seconds>", children: nil},
		"timeout":            {desc: "Timeout", args: 1, valueType: ValueInteger, valueDesc: "Timeout in seconds", valueExamples: []string{"300", "1800"}, validator: ValidateInteger(appTimeoutMin, appTimeoutMax), placeholder: "<seconds>", children: nil},
		"alg":                {desc: "Application layer gateway", args: 1, placeholder: "<alg>", children: nil},
		"description":        {desc: "Description", args: 1, scalar: true, placeholder: "<text>", children: nil},
		// #3348: typed ICMP/ICMPv6 type/code constraints (0..255) so an operator
		// can author a constrained custom echo / traceroute / ICMP-control app —
		// the runtime supports it (userspace-dp icmp_constraints, the #3020 fix)
		// but the grammar previously did not. Range-validated at the strict
		// commit gate; validateApplicationSpecsStrict additionally rejects the
		// constraint on a non-ICMP protocol (and a code without a type).
		"icmp-type": {desc: "ICMP/ICMPv6 message type", args: 1, valueType: ValueInteger, valueDesc: "ICMP type (e.g. 8 = echo-request, 128 = ICMPv6 echo-request)", valueExamples: []string{"8", "128"}, validator: ValidateInteger(0, 255), placeholder: "<type>", children: nil},
		"icmp-code": {desc: "ICMP/ICMPv6 message code", args: 1, valueType: ValueInteger, valueDesc: "ICMP code", valueExamples: []string{"0"}, validator: ValidateInteger(0, 255), placeholder: "<code>", children: nil},
		"term":      {desc: "Term", args: 1, placeholder: "<term>", children: nil},
	}},
	"application-set": {desc: "Application set", args: 1, valueHint: ValueHintAppSetName, placeholder: "<name>", children: nil},
}}
