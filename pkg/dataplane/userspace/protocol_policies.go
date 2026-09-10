package userspace

type FirewallFilterSnapshot struct {
	Name   string                 `json:"name"`
	Family string                 `json:"family"` // "inet" or "inet6"
	Terms  []FirewallTermSnapshot `json:"terms"`
}

type FirewallTermSnapshot struct {
	Name            string   `json:"name"`
	SourceAddresses []string `json:"source_addresses,omitempty"`
	DestAddresses   []string `json:"destination_addresses,omitempty"`
	// SourceExcept / DestExcept invert the corresponding address match (#2506):
	// when true, the term matches every address that is NOT in the
	// SourceAddresses / DestAddresses set (Junos `from source-prefix-list NAME
	// except` / `destination-prefix-list NAME except`). The Rust matcher
	// evaluates `(addr ∈ prefixes) XOR except`. These are populated only when the
	// except prefix-list is the sole address source for the direction. The mixed
	// positive+except case (a literal/positive address AND an except prefix-list
	// in the same direction) is hard-rejected at strict commit
	// (config.validateFilterAddressExceptStrict, #3359); on the lenient /
	// peer-sync path resolvePrefixListAddrs resolves it POSITIVE-WINS — the
	// except prefixes are IGNORED (except stays false), NOT folded into the
	// positive set — so a leniently-loaded term is fail-safe (an accept term's
	// admit set is no wider than the positive scope; a discard/reject term drops
	// at least the positive set).
	SourceExcept bool `json:"source_except,omitempty"`
	DestExcept   bool `json:"destination_except,omitempty"`
	// SourceConstrained / DestConstrained record that the term SPECIFIED a
	// source/destination address scope (any literal address OR any prefix-list
	// reference), INDEPENDENT of whether that scope resolved to any prefixes
	// (#2506, Copilot). The Rust matcher uses this — NOT the resolved list
	// length — to decide whether the direction is constrained. Without it, a
	// `from source-prefix-list X` whose X is defined-but-empty or
	// lenient-unresolved resolves to an empty list and the matcher would
	// collapse to match-ANY (fail-open for accept, wrong scope for discard). A
	// constrained direction with an empty positive set matches NOTHING
	// (fail-closed); with except set it matches ALL (the Junos "not in {}"
	// semantic). These default to false, so a term with no address scope behaves
	// exactly as before.
	SourceConstrained bool     `json:"source_constrained,omitempty"`
	DestConstrained   bool     `json:"destination_constrained,omitempty"`
	Protocols         []string `json:"protocols,omitempty"`
	SourcePorts       []string `json:"source_ports,omitempty"` // "80" or "1024-65535"
	DestPorts         []string `json:"destination_ports,omitempty"`
	// SourcePortsExcept / DestPortsExcept are the NEGATED port match sets
	// (#2622, Junos `from source-port-except` / `destination-port-except`):
	// match every port EXCEPT the listed ones. When non-empty, the Rust matcher
	// evaluates `(port ∈ ranges) XOR true` = match-all-but-these, with the same
	// fail-closed-on-all-malformed → match-all-but-{} = match-all semantics as
	// the address `except`. These are wired as separate fields from the positive
	// SourcePorts / DestPorts (Junos treats positive and `-except` as distinct,
	// mutually-exclusive criteria). serde(default) on the Rust side keeps wire
	// parity with an older Go control plane that omits them (#1961).
	SourcePortsExcept []string      `json:"source_ports_except,omitempty"`
	DestPortsExcept   []string      `json:"destination_ports_except,omitempty"`
	DSCPValues        WireUint8List `json:"dscp_values,omitempty"`
	Action            string        `json:"action"` // "accept", "discard", "reject"
	// NextTerm records `then next term` / a modifier-only term — a term whose
	// `then` carries NO terminating action (#2544). Such a term must APPLY its
	// modifiers (count, log, forwarding-class, policer, dscp) and FALL THROUGH
	// to the next term per Junos semantics, instead of terminating as Accept.
	// Action is left empty for these terms (the compiler sets NextTerm true);
	// the Rust evaluator continues to the next term instead of returning. When
	// false (no fall-through), behavior is unchanged. serde(default) on the Rust
	// side keeps wire parity with an older Go control plane that omits it (#1961).
	NextTerm bool   `json:"next_term,omitempty"`
	Count    string `json:"count,omitempty"`
	Log      bool   `json:"log,omitempty"`
	// #6853: `then syslog`, distinct from `then log`. Additive and omitempty,
	// so an older helper that does not know the field is unaffected and a
	// mixed-version HA pair stays wire-compatible.
	Syslog bool `json:"syslog,omitempty"`
	// #6854: the `then reject <message-type>` token (e.g. `host-unreachable`).
	// Empty means the term carried no message-type, which the dataplane
	// resolves to the administratively-prohibited codes it sent for every
	// reject before #6854. Additive + omitempty, so a mixed-version HA pair is
	// unaffected.
	RejectMessageType string `json:"reject_message_type,omitempty"`
	PolicerName       string `json:"policer,omitempty"`
	RoutingInstance   string `json:"routing_instance,omitempty"`
	ForwardingClass   string `json:"forwarding_class,omitempty"`
	DSCPRewrite       *uint8 `json:"dscp_rewrite,omitempty"`
	// Per-packet L4 match conditions (#2362). These are parsed by the Junos
	// firewall-filter compiler but were previously dropped on the wire, so a
	// term like `from { tcp-flags syn; }` silently matched broader than
	// authored. They are NOT part of the 5-tuple SessionKey, so a filter
	// carrying any of them is cache-sensitive (flow-cache must decline — see
	// the #1431 invariant in userspace-dp/src/filter/mod.rs).
	//
	// TCPFlags is a required-bits mask over the TCP flags byte (FIN=0x01,
	// SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20): a TCP packet matches
	// when (flags & mask) == mask. Nil = no required-flags constraint. A non-TCP
	// packet never matches a term that sets this.
	TCPFlags *uint8 `json:"tcp_flags,omitempty"`
	// TCPFlagsForbidden is a forbidden-bits mask over the same TCP flags byte
	// (#3076). A TCP packet matches the term only when (flags & forbidden) == 0
	// — i.e. none of these flags are set. It carries the negated operands of a
	// Junos tcp-flags expression such as `syn & !ack` (required=SYN,
	// forbidden=ACK). Nil = no forbidden-flags constraint. Required and
	// forbidden are independent: a term may set either, both, or neither.
	TCPFlagsForbidden *uint8 `json:"tcp_flags_forbidden,omitempty"`
	// TCPFlagsUnparseable (#3367) is set true when the term's tcp-flags
	// expression could not be parsed into required/forbidden masks (disjunction,
	// negated groups, unknown flags). Such expressions are rejected at commit by
	// compileFirewall, so a committed config never sets this; it is the
	// helper-boundary fail-closed marker for a corrupt / hand-built /
	// version-drifted snapshot. The pre-#3367 builder logged the parse error and
	// left both masks nil, and the Rust matcher treats absent masks as "no
	// tcp-flags constraint" — silently WIDENING the term to match every TCP
	// segment (fail-OPEN for a deny/discard term). With this flag the Rust filter
	// compiler raises SnapshotIntegrityError::UnrepresentableFilterTCPFlags and
	// rejects the whole snapshot instead. omitempty + the Rust serde default keep
	// wire parity with an older control plane that omits the field (#1961).
	TCPFlagsUnparseable bool `json:"tcp_flags_unparseable,omitempty"`
	// IsFragment matches any IP fragment (IPv4 MF set OR non-zero offset; IPv6
	// fragment extension header present). False = no fragment constraint.
	IsFragment bool `json:"is_fragment,omitempty"`
	// ICMPTypes / ICMPCodes match the ICMP/ICMPv6 type and code bytes (#2545,
	// multi-value). An empty slice = no constraint. A non-empty slice matches if
	// the packet's type/code byte is in the set (match-ANY). A non-ICMP(v6)
	// packet never matches a term that sets these. Previously these were scalar
	// (`*uint8` / a single byte): a term carrying two `from icmp-type` values
	// kept only the last, dropping the earlier constraint.
	ICMPTypes WireUint8List `json:"icmp_types,omitempty"`
	ICMPCodes WireUint8List `json:"icmp_codes,omitempty"`
	// ICMPTypeUnrepresentable / ICMPCodeUnrepresentable (#3406) are set true when
	// the term carried at least one `from icmp-type` / `from icmp-code` token the
	// compiler could NOT resolve to a byte in 0..255 (a symbolic name with no
	// mapping, or a numeric value outside the range). compileFilterFrom records
	// such a token on term.UnknownICMPTypes / term.UnknownICMPCodes; the strict
	// commit gate (validateFilterMatchValuesStrict) rejects it, so a committed
	// config never sets these. They are the helper-boundary fail-closed marker for
	// a corrupt / hand-built / version-drifted snapshot. The pre-#3406 builder
	// dropped the unresolved token entirely and emitted only the resolved bytes;
	// when EVERY token was unresolvable the emitted vector was empty, which the
	// Rust matcher reads as "no ICMP constraint" — silently WIDENING the term to
	// match every ICMP(v6) packet (fail-OPEN for a discard/reject term; leaking the
	// excepted type for an accept term). With these flags the Rust filter compiler
	// raises SnapshotIntegrityError::UnrepresentableFilterICMP and rejects the
	// whole snapshot instead. omitempty + the Rust serde default keep wire parity
	// with an older control plane that omits the field (#1961).
	ICMPTypeUnrepresentable bool `json:"icmp_type_unrepresentable,omitempty"`
	ICMPCodeUnrepresentable bool `json:"icmp_code_unrepresentable,omitempty"`
	// DSCPMatchUnrepresentable (#3406) is set true when the term carried a
	// non-empty `from dscp` / `from traffic-class` MATCH token that resolves to
	// neither a known code-point name nor an integer 0..63. The strict commit gate
	// (validateFilterDSCPStrict, #3309) rejects it, so a committed config never
	// sets this. The pre-#3406 builder dropped the unresolved token from
	// DSCPValues; when EVERY DSCP token was unresolvable the emitted vector was
	// empty, which the Rust matcher reads as "no DSCP constraint" — silently
	// WIDENING the term to match all DSCPs (fail-OPEN, a documented #3309 gap). With
	// this flag the Rust filter compiler raises
	// SnapshotIntegrityError::UnrepresentableFilterDSCP and rejects the whole
	// snapshot. Note this covers only the MATCH side; an unrepresentable `then dscp`
	// REWRITE token is CoS-only (no security widening) and is surfaced with a
	// builder warning rather than a snapshot reject. omitempty + the Rust serde
	// default keep wire parity with an older control plane that omits the field
	// (#1961).
	DSCPMatchUnrepresentable bool `json:"dscp_match_unrepresentable,omitempty"`
	// PortsUnrepresentable (#6459) is set true when the term carried at least
	// one `from {source,destination}-port[-except]` token the compiler could
	// NOT resolve to a number (an unknown service name, a malformed range, or
	// a non-canonical token such as "+80"), recorded on term.UnknownPorts. The
	// strict commit gate (validateFilterMatchValuesStrict, #3205) rejects it,
	// so a committed config never sets this; it is the helper-boundary
	// fail-closed marker for the tolerant load / peer-sync path. The
	// pre-#6459 Rust filter compiler dropped the unresolvable token PER-TOKEN
	// (`filter_map(parse_port_spec)`): a PARTIALLY-unresolvable list built a
	// matcher over only the surviving subset, so a discard/reject term
	// silently enforced a NARROWER port set than the operator wrote — the
	// traffic meant for the dropped ports fell through to the implicit accept
	// (fail-OPEN). (An ALL-unresolvable list already failed closed at
	// match-time via `constrained && PortMatcher::Any`, #2400/#3205.) With
	// this flag the Rust filter compiler raises
	// SnapshotIntegrityError::UnrepresentableFilterPorts and rejects the whole
	// snapshot instead. omitempty + the Rust serde default keep wire parity
	// with an older control plane that omits the field (#1961).
	PortsUnrepresentable bool `json:"ports_unrepresentable,omitempty"`
	// AddressUnrepresentable (#6463) is set true when the term carried at
	// least one literal `from source-address` / `destination-address` token
	// that is not a parseable IP/CIDR (classifyFilterAddrFamily rejects it),
	// recorded on term.UnknownAddresses. The strict commit gate
	// (validateFilterAddressLiteralsStrict, #3433) rejects it, so a committed
	// config never sets this; it is the helper-boundary fail-closed marker for
	// the tolerant load / peer-sync path. The pre-#6463 Rust parse_address
	// dropped such a token PER-TOKEN (its `Err(_)` arm pushed nothing): a
	// PARTIALLY-malformed list matched only the surviving prefixes, so a
	// discard/reject term silently enforced a NARROWER address set than the
	// operator wrote — a host in the dropped range was accepted by
	// fall-through (fail-OPEN). (An ALL-malformed direction already failed
	// closed at match-time via `constrained && empty`, #2400.) With this flag
	// the Rust filter compiler raises
	// SnapshotIntegrityError::UnrepresentableFilterAddress and rejects the
	// whole snapshot instead. omitempty + the Rust serde default keep wire
	// parity with an older control plane that omits the field (#1961).
	AddressUnrepresentable bool `json:"address_unrepresentable,omitempty"`
	// FlexMatch is the Junos `from flexible-match-range` byte-offset match
	// (#3077). Before this wiring it was parsed + compiled for the retired
	// legacy dataplane but DROPPED on the userspace wire, so the byte-offset
	// constraint vanished and the term matched too broadly (fail-open). The
	// match reads FlexLength bytes at FlexOffset from the start of the L3
	// header (match-start layer-3, the only start point the compiler emits),
	// interprets them big-endian, ANDs with FlexMask, and requires the result
	// to equal FlexValue. FlexValue is already pre-masked by the compiler. A
	// nil pointer means the term carries no flex constraint — identical to the
	// pre-#3077 behavior for every term that did not use the feature. Like the
	// #2362 per-packet L4 fields this is NOT part of the 5-tuple SessionKey, so
	// a filter carrying it is cache-sensitive (the Rust flow-cache declines).
	// serde(default) on the Rust side keeps wire parity with an older Go
	// control plane that omits the field (#1961).
	FlexMatch *FlexMatchSnapshot `json:"flex_match,omitempty"`
}

// FlexMatchSnapshot is the wire form of a firewall-filter term's
// flexible-match-range byte-offset match (#3077). It mirrors the fields the
// legacy dataplane consumed (pkg/dataplane/compiler_filter.go FlexOffset/
// FlexLength/FlexValue/FlexMask). Offset is the byte offset from the start of
// the L3 header (match-start layer-3); Length is the match width in BYTES
// (1..4, derived from the Junos bit-length); Value is the expected value AFTER
// masking; Mask is applied to the read bytes before the equality compare.
type FlexMatchSnapshot struct {
	Offset uint8 `json:"offset"`
	// Length is the match width in BYTES, derived from the Junos bit-length
	// (ceil(bits/8)). A representable flex match is 1..4 bytes (the Value/Mask
	// wire fields are u32). #3406: the builder NO LONGER caps an oversized width
	// to 4 — a length > 4 (only reachable via a corrupt / hand-built /
	// version-drifted snapshot, since the commit gate bounds bit-length to 1..32 →
	// ceil ≤ 4) is carried verbatim so the Rust filter compiler raises
	// SnapshotIntegrityError::UnrepresentableFilterFlexMatch and rejects the whole
	// snapshot. The pre-#3406 builder capped it to 4 and still emitted the term, so
	// only the truncated 4-byte window was compared and the match BROADENED
	// (fail-open).
	Length uint8  `json:"length"`
	Value  uint32 `json:"value"`
	Mask   uint32 `json:"mask"`
	// MatchStart is the Junos `match-start` base the byte Offset is relative
	// to (#3232). "" (omitted) and "layer-3" both mean the L3/IP-header base
	// — the historical, default behavior — so a layer-3 term stays
	// byte-identical on the wire (omitempty). "layer-4" offsets from the
	// transport (L4) header instead. `payload` and any other value are
	// rejected at commit (validateFilterFlexMatchStrict), so they never reach
	// the wire. omitempty + the Rust serde default keep parity with an older
	// control plane that omits the field (#1961).
	MatchStart string `json:"match_start,omitempty"`
}

type PolicerSnapshot struct {
	Name          string `json:"name"`
	BandwidthBps  uint64 `json:"bandwidth_bps"`
	BurstBytes    uint64 `json:"burst_bytes"`
	DiscardExcess bool   `json:"discard_excess"`
}

type ThreeColorPolicerSnapshot struct {
	Name                   string `json:"name"`
	Mode                   string `json:"mode"` // "single-rate" (srTCM) or "two-rate" (trTCM)
	ColorBlind             bool   `json:"color_blind,omitempty"`
	CommittedRateBytes     uint64 `json:"committed_rate_bytes_per_sec"`
	CommittedBurstBytes    uint64 `json:"committed_burst_bytes"`
	PeakOrExcessRateBytes  uint64 `json:"peak_or_excess_rate_bytes_per_sec,omitempty"`
	PeakOrExcessBurstBytes uint64 `json:"peak_or_excess_burst_bytes"`
	ThenAction             string `json:"then_action,omitempty"`
}

type PolicyApplicationSnapshot struct {
	Name            string `json:"name"`
	Protocol        string `json:"protocol,omitempty"`
	SourcePort      string `json:"source_port,omitempty"`
	DestinationPort string `json:"destination_port,omitempty"`
	// #3020: optional ICMP/ICMPv6 type (and code) constraint. nil = "no
	// constraint" — the term matches every type/code of its protocol (the
	// historical behavior, kept by the all-ICMP aliases). junos-ping sets
	// ICMPType=8, junos-pingv6 sets ICMPType=128. omitempty + pointer keeps
	// the wire additive: an old helper missing the field decodes None and
	// ignores the constraint (match-all, today's behavior), and an old Go
	// snapshot omitting it decodes to None on the Rust side the same way, so
	// version skew degrades safely to match-all rather than failing to decode.
	ICMPType *uint8 `json:"icmp_type,omitempty"`
	ICMPCode *uint8 `json:"icmp_code,omitempty"`
	// #3227: optional per-application inactivity (idle) timeout in seconds,
	// carried from a custom `set applications application <a> inactivity-timeout
	// <n>`. 0/absent means "use the global per-protocol SessionTimeouts" — the
	// historical behavior. When a session is admitted by a policy whose matched
	// application term sets this, the userspace dataplane stamps it on the
	// session and the conntrack GC ages the session out on this value instead
	// of the global TCP/UDP/ICMP timeout. The legacy (retired-eBPF) map
	// compiler wired the same per-app `appTimeout`, so carrying it here closes a
	// userspace parity regression. omitempty keeps the wire additive: an old
	// helper missing the field decodes 0 (use-global, today's behavior), and an
	// old Go snapshot omitting it decodes to None on the Rust side the same way,
	// so version skew degrades safely.
	InactivityTimeout uint32 `json:"inactivity_timeout,omitempty"`
}

// AppCatalogEntrySnapshot is one row of the application-identification catalog
// (#2008 M5). The dataplane scans these on session create and stamps the
// matching AppID on the conntrack session so `show security flow session`
// resolves a real application name. Inclusive port boundaries; a zero
// DstPortLow/DstPortHigh pair means "no destination-port constraint" (match on
// protocol alone, e.g. ICMP), and a zero SrcPortLow/SrcPortHigh pair means "no
// source-port constraint". AppID is never 0 (0 is the reserved unknown
// sentinel). Rust mirror: AppCatalogEntry in protocol/snapshot.rs.
type AppCatalogEntrySnapshot struct {
	AppID       uint16 `json:"app_id"`
	Protocol    uint8  `json:"protocol"`
	DstPortLow  uint16 `json:"dst_port_low,omitempty"`
	DstPortHigh uint16 `json:"dst_port_high,omitempty"`
	SrcPortLow  uint16 `json:"src_port_low,omitempty"`
	SrcPortHigh uint16 `json:"src_port_high,omitempty"`
}

type PolicyRuleSnapshot struct {
	RuleID        string `json:"rule_id,omitempty"`
	PolicyID      uint32 `json:"policy_id,omitempty"`
	Name          string `json:"name"`
	FromZone      string `json:"from_zone,omitempty"`
	ToZone        string `json:"to_zone,omitempty"`
	SchedulerName string `json:"scheduler_name,omitempty"`
	Inactive      bool   `json:"inactive,omitempty"`
	// Legacy field (carries full expansion: literals ∪ book CIDRs).
	// Used by old-Rust binaries reading new-Go snapshots. New-Rust
	// IGNORES this field when the rule is v3-shaped.
	SourceAddresses      []string `json:"source_addresses,omitempty"`
	DestinationAddresses []string `json:"destination_addresses,omitempty"`
	// #1606: dense u32 IDs of named address books cited by the
	// rule.
	SourceBookIDs      []uint32 `json:"source_book_ids,omitempty"`
	DestinationBookIDs []uint32 `json:"destination_book_ids,omitempty"`
	// #1606: free-form CIDR / "any" literals written inline in the
	// rule (NOT a named address-book reference).
	SourceLiterals      []string                    `json:"source_literals,omitempty"`
	DestinationLiterals []string                    `json:"destination_literals,omitempty"`
	Applications        []string                    `json:"applications,omitempty"`
	ApplicationTerms    []PolicyApplicationSnapshot `json:"application_terms,omitempty"`
	Action              string                      `json:"action,omitempty"`
	// #2008 H2: invert the source/destination match sense — the
	// rule matches every address EXCEPT those named in the
	// corresponding address set (Junos `source-address-excluded` /
	// `destination-address-excluded`).
	SourceAddressExcluded      bool `json:"source_address_excluded,omitempty"`
	DestinationAddressExcluded bool `json:"destination_address_excluded,omitempty"`
	// #2508: per-policy `then log session-init` / `session-close`
	// selection (Junos). When set, the dataplane stamps the flag onto
	// the session metadata at install so the per-policy RT_FLOW SYSLOG
	// records (RT_FLOW_SESSION_CREATE / RT_FLOW_SESSION_CLOSE) can be
	// emitted ONLY for the policies the operator configured with
	// `then log`. These gate the SYSLOG logging consumer only — the
	// global NetFlow/IPFIX session-close exporter (#2460) still observes
	// EVERY close regardless of these flags.
	LogSessionInit  bool `json:"log_session_init,omitempty"`
	LogSessionClose bool `json:"log_session_close,omitempty"`
	// #3148: optional from-zone/to-zone match context for a GLOBAL policy.
	// A global rule keeps FromZone/ToZone == "junos-global" (so the Rust
	// classifier keeps it in the global tier and the global config order is
	// preserved); these additive fields narrow which zone pairs the global
	// rule matches. Empty = all zones (the historical behaviour). Additive
	// per #1961: an old Rust helper that omits these decodes them to "" and
	// keeps the all-zones semantics. They are populated only for global
	// policies — a zone-pair rule leaves them empty.
	MatchFromZone string `json:"match_from_zone,omitempty"`
	MatchToZone   string `json:"match_to_zone,omitempty"`
	// #4626 M03: the FULL scoped-global zone SET. A Junos global policy scope
	// is a zone LIST; these ADDITIVE plural fields carry every zone while the
	// singular fields above keep the first element for rolling-upgrade safety.
	// The Rust helper PREFERS the plural when non-empty and falls back to the
	// singular otherwise (build_global_zone_scope, policy.rs). Additive per
	// #1961: an old helper that ignores these still reads the singular field.
	// Populated only for global policies; a zone-pair rule leaves them empty.
	MatchFromZones []string `json:"match_from_zones,omitempty"`
	MatchToZones   []string `json:"match_to_zones,omitempty"`
	// #3376: build-time-only diagnostic detail (deliberately NOT serialized —
	// no JSON tag, never carried on the wire). When buildOneRuleSnapshot
	// collapses an unrepresentable side to the fail-closed sentinel (#3261), it
	// records the exact offending configured tokens here so
	// collectPolicyContentRejections can name them per side
	// (source-address / destination-address / application) instead of the bare
	// "an address" / "an application". A representable rule leaves these nil; a
	// decoded snapshot also leaves them nil (they round-trip to empty), which is
	// fine because the rejection diagnostic is only ever computed from the
	// freshly-built snapshot.
	rejectedSourceAddresses []string
	rejectedDestAddresses   []string
	rejectedApplications    []string
	// #9570: build-time-only, like the three above (no JSON tag, never on the
	// wire). poisonZonePairGlobalSentinel sets it when a ZONE-PAIR stanza names
	// the reserved `junos-global` sentinel on one or both structural sides, to
	// config.ZonePairGlobalSentinelSide's answer. It exists because the
	// both-sided spelling is WIRE-IDENTICAL to a real `security policies global`
	// rule, so FromZone/ToZone alone cannot tell the content-rejection mirror,
	// or the reason's scope rendering, which of the two a rule is. A decoded
	// snapshot leaves it "" and reads as global: that is the honest bound of the
	// wire, and the reason the builder poisons the rule instead of relying on
	// the helper to tell them apart.
	zonePairGlobalSentinelSide string
}
