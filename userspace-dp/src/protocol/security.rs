//! Security-policy DTOs (screens, firewall filters, policers, three-color
//! policers, flow-export, zone policy rules, policy applications) plus
//! their runtime counter twins. Leaf module — no cross-domain protocol
//! refs.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ScreenProfileSnapshot {
    pub zone: String,
    #[serde(default)]
    pub land: bool,
    #[serde(rename = "syn_fin", default)]
    pub syn_fin: bool,
    #[serde(rename = "tcp_no_flag", default)]
    pub tcp_no_flag: bool,
    #[serde(rename = "fin_no_ack", default)]
    pub fin_no_ack: bool,
    #[serde(default)]
    pub winnuke: bool,
    #[serde(rename = "ping_death", default)]
    pub ping_death: bool,
    #[serde(default)]
    pub teardrop: bool,
    #[serde(rename = "icmp_fragment", default)]
    pub icmp_fragment: bool,
    /// #1137: TCP SYN packet that's also the first fragment of a
    /// fragmented datagram — a fragmentation-based attack signature.
    #[serde(rename = "syn_frag", default)]
    pub syn_frag: bool,
    #[serde(rename = "source_route", default)]
    pub source_route: bool,
    #[serde(rename = "icmp_flood_threshold", default)]
    pub icmp_flood_threshold: u32,
    #[serde(rename = "udp_flood_threshold", default)]
    pub udp_flood_threshold: u32,
    #[serde(rename = "syn_flood_threshold", default)]
    pub syn_flood_threshold: u32,
    #[serde(rename = "syn_cookie", default)]
    pub syn_cookie: bool,
    /// #3315: SYN-flood sub-thresholds. Mirror of the Go ScreenProfileSnapshot
    /// additions. The Go compiler parses the full Junos syn-flood shape but only
    /// `syn_flood_threshold` (attack-threshold) used to cross the wire; these
    /// carry the log-only alarm rate and the per-destination / per-source SYN
    /// rate caps so the dataplane can enforce them (`SynRateSketch`).
    /// `#[serde(default)]` keeps wire parity with an older Go control plane that
    /// omits the fields (decode to 0 = disabled — #1961 skew tolerance).
    #[serde(rename = "syn_flood_alarm_threshold", default)]
    pub syn_flood_alarm_threshold: u32,
    #[serde(rename = "syn_flood_dst_threshold", default)]
    pub syn_flood_dst_threshold: u32,
    #[serde(rename = "syn_flood_src_threshold", default)]
    pub syn_flood_src_threshold: u32,
    /// #3527: the Junos `syn-flood timeout` (SECONDS), the half-completed-
    /// connection queue window. It does NOT belong to the screen-rate
    /// substrate above — it maps to the per-zone half-open TCP session window
    /// (`SessionTimeouts.tcp_opening_ns`, 20 s default). The forwarding builder
    /// turns it into a per-ingress-zone override of `tcp_opening_ns`
    /// (`SessionTable::set_opening_overrides`) so a bare-SYN session in this
    /// zone is reaped on the operator's window instead of the global default.
    /// 0 = unset (global default). `#[serde(default)]` keeps wire parity with
    /// an older Go control plane that omits the field (#1961 skew tolerance).
    /// This closes the #3315 deferred leaf (#3527).
    #[serde(rename = "syn_flood_timeout", default)]
    pub syn_flood_timeout: u32,
    #[serde(rename = "session_limit_src", default)]
    pub session_limit_src: u32,
    #[serde(rename = "session_limit_dst", default)]
    pub session_limit_dst: u32,
    /// #4114 Junos: the port-scan/ip-sweep `threshold` is a MICROSECOND
    /// detection WINDOW (not a count); the detection count is the fixed
    /// `SCAN_DETECT_COUNT` (10) in `screen/scan.rs`. 0 = disabled.
    #[serde(rename = "port_scan_threshold", default)]
    pub port_scan_threshold: u32,
    #[serde(rename = "ip_sweep_threshold", default)]
    pub ip_sweep_threshold: u32,
    /// Junos profile-wide `alarm-without-drop` audit/log-only mode. When true,
    /// every screen check that would DROP a packet in this zone instead raises
    /// a log-only alarm (carrying the tripped reason) and the packet forwards.
    /// Mirror of the Go `ScreenProfileSnapshot.AlarmWithoutDrop`.
    /// `#[serde(default)]` keeps wire parity with an older Go control plane
    /// that omits the field (decode to false = drop-on-trip — #1961 skew
    /// tolerance). `skip_serializing_if` mirrors the Go `omitempty` and keeps
    /// the default specimen (protocol_wire_v1 fixture) byte-identical.
    #[serde(
        rename = "alarm_without_drop",
        default,
        skip_serializing_if = "crate::protocol::bool_is_false"
    )]
    pub alarm_without_drop: bool,
}

/// #3082: a zone that references a screen profile which was NOT defined when
/// the Go control plane built the snapshot. Reachable on the lenient/HA-sync
/// path (older-binary `active.json` on upgrade, or an HA sync from an
/// un-upgraded primary). Without this the dataplane cannot tell "zone has no
/// screen configured" (legit Pass) from "zone references a MISSING screen"
/// (error) — both produce no `screens` entry. The dataplane uses this set to
/// emit a rate-limited runtime WARN; the verdict still stays Pass (the
/// fail-closed-vs-pass posture is a deferred decision).
///
/// Additive/skew-tolerant: `#[serde(default)]` on the carrying field means an
/// old helper missing the field decodes an empty set (all-Pass, no warn).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ScreenMissingProfileRef {
    pub zone: String,
    #[serde(default)]
    pub profile: String,
    /// #9425: the referenced profile's `alarm-without-drop` modifier.
    ///
    /// MEANINGFUL ONLY on `screen_inert_profile_zones`, where the profile IS
    /// defined and the operator's audit request is a real statement. On
    /// `screen_missing_profile_zones` (UNDEFINED) there is no profile to read
    /// it from and it is always false; `missing_profile_verdict` consults it
    /// only on the inert arm, so the two sets sharing this struct cannot pick
    /// up each other's meaning.
    ///
    /// Additive/skew-tolerant: an old Go binary that does not emit it decodes
    /// false here, which is the pre-#9425 hard-drop behaviour.
    #[serde(default)]
    pub alarm_without_drop: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FirewallFilterSnapshot {
    pub name: String,
    #[serde(default)]
    pub family: String,
    // #2214: null-tolerant. A filter declared with zero terms makes the Go
    // builder emit `terms:null` (nil slice, no `,omitempty`); plain `default`
    // only covers an ABSENT key, so an explicit null would abort the whole
    // snapshot decode (#1961 no-transit).
    #[serde(default, deserialize_with = "crate::protocol::null_tolerant_vec")]
    pub terms: Vec<FirewallTermSnapshot>,
}

// ============================================================
// CACHE-KEY INVARIANT (#1431) — read before adding a match field
//
// Every match criterion on FirewallTermSnapshot (and its runtime
// twin FilterTerm in userspace-dp/src/filter/mod.rs) MUST be
// classified as either:
//
//   (a) IN cache key — extend SessionKey in session/key.rs AND
//       prove key stability for HA sync (pkg/cluster/),
//       session-table reverse/NAT/forward-wire indices, flow_cache
//       key derivation, expiry hash bucket math, and reverse-NAT
//       lookup. File a tracker issue against session/key.rs.
//
//   (b) NOT in cache key (cache-sensitive) — wire the #1430
//       runbook: Filter.has_<X>_match_terms flag (read per-interface
//       off FilterState.iface_filter_v{4,6}_fast via the
//       interface_input_filter_has_<X>_match accessor — the parallel
//       per-interface has_<X>_match sets were deleted in #6236 PR-2B),
//       flow-cache insertion gate at afxdp/flow_cache.rs (per-flag,
//       input + output direction), established-session re-evaluation at
//       afxdp/poll_descriptor/filter.rs (the DSCP + per-packet-L4
//       prechecks fold to ONE lookup of
//       interface_input_filter_varies_per_packet — the
//       Filter.varies_per_packet_within_flow() OR core — since #6236
//       PR-2C), forwarding rotation purge at
//       afxdp/worker/loop_body/mod.rs, and tests at
//       afxdp/flow_cache_tests.rs.
//
// Skipping this classification SILENTLY breaks flow-cache: a
// first-packet decision gets reused for later packets that can
// differ on the new field. PR #1430 fixed this for DSCP; the same
// class of bug applies to any future per-packet match.
//
// See userspace-dp/src/filter/README.md
//   "Cache-key invariants for per-packet match fields (#1431)"
// for the classification table, the path (a) / path (b) recipes,
// and the canonical reference tests.
// ============================================================
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FirewallTermSnapshot {
    pub name: String,
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    pub destination_addresses: Vec<String>,
    // #2506: invert the source/destination address match. When true, the term
    // matches every address NOT in source_addresses / destination_addresses
    // (Junos `from source-prefix-list NAME except` / `destination-prefix-list
    // NAME except`). The matcher evaluates `(addr ∈ prefixes) XOR except`.
    // serde(default) keeps wire parity with an older Go control plane that omits
    // the field (#1961).
    #[serde(rename = "source_except", default)]
    pub source_except: bool,
    #[serde(rename = "destination_except", default)]
    pub destination_except: bool,
    // #2506 (Copilot): the term SPECIFIED a source/destination address scope
    // (any literal address OR any prefix-list reference), INDEPENDENT of whether
    // it resolved to any prefixes. The matcher derives "constrained" from THIS,
    // not the resolved list length, so a `from source-prefix-list X` whose X is
    // defined-but-empty or lenient-unresolved (empty list) does not collapse to
    // match-ANY. A constrained direction with an empty positive set matches
    // NOTHING (fail-closed); with `except` set, matches ALL (Junos "not in {}").
    // serde(default) keeps wire parity with an older Go control plane that omits
    // the field (#1961). When BOTH this and the addr list are absent/false, the
    // direction is unconstrained (match-any) — unchanged legacy behavior.
    #[serde(rename = "source_constrained", default)]
    pub source_constrained: bool,
    #[serde(rename = "destination_constrained", default)]
    pub destination_constrained: bool,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(rename = "source_ports", default)]
    pub source_ports: Vec<String>,
    #[serde(rename = "destination_ports", default)]
    pub destination_ports: Vec<String>,
    // #2622: NEGATED port match sets (Junos `from source-port-except` /
    // `destination-port-except`) — match every port EXCEPT these. The compiler
    // turns a non-empty list into a port matcher plus a per-direction `except`
    // flag, and the evaluator computes `(port ∈ ranges) XOR except` with the
    // same fail-closed-on-all-malformed semantics as the address except. These
    // are distinct from the positive source_ports / destination_ports (Junos
    // treats positive and `-except` as mutually-exclusive criteria).
    // serde(default) keeps wire parity with an older Go control plane that omits
    // the field (#1961).
    #[serde(rename = "source_ports_except", default)]
    pub source_ports_except: Vec<String>,
    #[serde(rename = "destination_ports_except", default)]
    pub destination_ports_except: Vec<String>,
    #[serde(rename = "dscp_values", default)]
    pub dscp_values: Vec<u8>,
    #[serde(default)]
    pub action: String,
    // #2544: fall-through. A term whose `then` carries NO terminating action
    // (explicit `then next term` OR a modifier-only term) must APPLY its
    // modifiers (count/log/forwarding-class/policer/dscp) and FALL THROUGH to
    // the next term instead of terminating as Accept (Junos semantics). The Go
    // control plane sets this true for both cases (Action left empty). The
    // compiler maps it to FilterTerm.continue_term; the evaluator continues to
    // the next term on a match instead of returning. serde(default) keeps wire
    // parity with an older Go control plane that omits the field (#1961).
    #[serde(rename = "next_term", default)]
    pub next_term: bool,
    #[serde(default)]
    pub count: String,
    #[serde(default)]
    pub log: bool,
    /// #6854: the `then reject <message-type>` token, e.g. `host-unreachable`.
    ///
    /// Empty means the term carried no message-type, which resolves to the
    /// administratively-prohibited codes the dataplane sent for every reject
    /// before #6854. `serde(default)` keeps wire parity with a Go control
    /// plane that omits the field (#1961).
    #[serde(rename = "reject_message_type", default)]
    pub reject_message_type: String,
    /// #6853: `then syslog`, distinct from `then log`.
    ///
    /// A `then syslog` term carries BOTH this and `log`; `log` is what makes
    /// the term emit a filter-log event at all. `serde(default)` keeps wire
    /// parity with a Go control plane that omits the field, so a
    /// mixed-version HA pair is unaffected (#1961).
    #[serde(default)]
    pub syslog: bool,
    #[serde(default)]
    pub policer: String,
    #[serde(rename = "routing_instance", default)]
    pub routing_instance: String,
    #[serde(rename = "forwarding_class", default)]
    pub forwarding_class: String,
    #[serde(rename = "dscp_rewrite", default)]
    pub dscp_rewrite: Option<u8>,
    // Per-packet L4 match conditions (#2362). Mirror of the Go
    // FirewallTermSnapshot fields. These are NOT in SessionKey, so a filter
    // carrying any of them is cache-sensitive — see the #1431 invariant above
    // and the path-(b) wiring in afxdp/flow_cache.rs.
    //
    // tcp_flags is a required-bits mask over the TCP flags byte (FIN=0x01,
    // SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20): a TCP packet matches
    // when (flags & mask) == mask. None = no constraint; a non-TCP packet
    // never matches a term that sets it.
    #[serde(rename = "tcp_flags", default)]
    pub tcp_flags: Option<u8>,
    // tcp_flags_forbidden is a forbidden-bits mask over the same TCP flags byte
    // (#3076): a TCP packet matches the term only when (flags & forbidden) == 0.
    // It carries the negated operands of a Junos tcp-flags expression such as
    // `syn & !ack` (tcp_flags=SYN, tcp_flags_forbidden=ACK). None = no
    // forbidden-flags constraint. Required (`tcp_flags`) and forbidden are
    // independent: a term may set either, both, or neither.
    #[serde(rename = "tcp_flags_forbidden", default)]
    pub tcp_flags_forbidden: Option<u8>,
    // tcp_flags_unparseable (#3367) is set by the Go control plane when the
    // term's tcp-flags expression could not be parsed into required/forbidden
    // masks (disjunction, negated groups, unknown flags). The pre-fix Go builder
    // logged the error and left both masks None, and this matcher treats absent
    // masks as "no tcp-flags constraint" — silently widening the term to match
    // every TCP segment (fail-OPEN for a deny/discard term). With this flag the
    // filter compiler raises SnapshotIntegrityError::UnrepresentableFilterTCPFlags
    // and rejects the whole snapshot. serde(default) keeps wire parity with an
    // older control plane that omits the field (#1961).
    #[serde(rename = "tcp_flags_unparseable", default)]
    pub tcp_flags_unparseable: bool,
    // is_fragment matches any IP fragment (IPv4 MF set OR non-zero offset;
    // IPv6 fragment extension header present).
    #[serde(rename = "is_fragment", default)]
    pub is_fragment: bool,
    // icmp_types / icmp_codes match the ICMP/ICMPv6 type and code bytes (#2545,
    // multi-value). An empty vec = no constraint. A non-empty vec matches if the
    // packet's type/code byte is in the set (match-ANY). A non-ICMP(v6) packet
    // never matches a term that sets them. Previously scalar (`icmp_type`,
    // `icmp_code`): a term carrying two `from icmp-type` values kept only the
    // last, silently dropping the earlier constraint.
    #[serde(rename = "icmp_types", default)]
    pub icmp_types: Vec<u8>,
    #[serde(rename = "icmp_codes", default)]
    pub icmp_codes: Vec<u8>,
    // icmp_type_unrepresentable / icmp_code_unrepresentable (#3406) are set by the
    // Go control plane when the term carried a `from icmp-type` / `from icmp-code`
    // token it could not resolve to a byte in 0..255. The pre-fix Go builder
    // dropped the unresolved token and emitted only the resolved bytes; when EVERY
    // token was unresolvable the vector above was empty, which this matcher reads
    // as "no ICMP constraint" — silently WIDENING the term to match every ICMP(v6)
    // packet (fail-OPEN for a discard/reject term). With these flags the filter
    // compiler raises SnapshotIntegrityError::UnrepresentableFilterICMP and rejects
    // the whole snapshot. serde(default) keeps wire parity with an older control
    // plane that omits the field (#1961).
    #[serde(rename = "icmp_type_unrepresentable", default)]
    pub icmp_type_unrepresentable: bool,
    #[serde(rename = "icmp_code_unrepresentable", default)]
    pub icmp_code_unrepresentable: bool,
    // dscp_match_unrepresentable (#3406) is set by the Go control plane when the
    // term carried a non-empty `from dscp` / `from traffic-class` MATCH token that
    // resolves to neither a known code-point name nor an integer 0..63. The pre-fix
    // Go builder dropped the bad token from dscp_values; when EVERY token was
    // unresolvable the vector was empty, which this matcher reads as "no DSCP
    // constraint" — silently WIDENING the term to match all DSCPs (fail-OPEN). With
    // this flag the filter compiler raises
    // SnapshotIntegrityError::UnrepresentableFilterDSCP and rejects the whole
    // snapshot. An unrepresentable `then dscp` REWRITE is CoS-only and is NOT
    // carried here (the Go builder warns instead of failing closed). serde(default)
    // keeps wire parity with an older control plane that omits the field (#1961).
    #[serde(rename = "dscp_match_unrepresentable", default)]
    pub dscp_match_unrepresentable: bool,
    // ports_unrepresentable (#6459) is set by the Go control plane when the
    // term carried a `from {source,destination}-port[-except]` token it could
    // not resolve to a number (an unknown service name, a malformed range, or
    // a non-canonical token such as "+80"; recorded on term.UnknownPorts). The
    // token is kept VERBATIM in the wire port lists, and the pre-fix filter
    // compiler dropped it PER-TOKEN (`filter_map(parse_port_spec)`): a
    // PARTIALLY-unresolvable list then built a matcher over only the surviving
    // subset — a `then discard`/`reject` term silently enforced a NARROWER
    // port set than the operator wrote (fail-OPEN via fall-through to the
    // implicit accept). With this flag the filter compiler raises
    // SnapshotIntegrityError::UnrepresentableFilterPorts and rejects the whole
    // snapshot. serde(default) keeps wire parity with an older control plane
    // that omits the field (#1961).
    #[serde(rename = "ports_unrepresentable", default)]
    pub ports_unrepresentable: bool,
    // address_unrepresentable (#6463) is set by the Go control plane when the
    // term carried a literal `from source-address` / `destination-address`
    // token that is not a parseable IP/CIDR (classifyFilterAddrFamily rejects
    // it; recorded on term.UnknownAddresses). The pre-fix `parse_address`
    // dropped such a token PER-TOKEN (its `Err(_)` arm pushed nothing): a
    // PARTIALLY-malformed list then matched only the surviving prefixes — a
    // `then discard`/`reject` term silently enforced a NARROWER address set
    // than the operator wrote (fail-OPEN via fall-through to the implicit
    // accept). With this flag the filter compiler raises
    // SnapshotIntegrityError::UnrepresentableFilterAddress and rejects the
    // whole snapshot. serde(default) keeps wire parity with an older control
    // plane that omits the field (#1961).
    #[serde(rename = "address_unrepresentable", default)]
    pub address_unrepresentable: bool,
    // from_unrepresentable (#9875) is set by the Go control plane when the
    // term's `from` block carried a match leaf the dataplane does NOT enforce
    // (recorded on term.UnknownFrom, #3307 — ttl / source-mac-address /
    // ip-options / fragment-offset / hop-limit / ...) or a value-bearing leaf
    // written with NO operand (recorded on term.ValuelessFrom, #8480 — `from
    // protocol;`). Both compile to a term missing a constraint the operator
    // authored: the strict commit gates (validateFilterFromMatchStrict,
    // validateFirewallFilterValuelessFromStrict) reject them, so a committed
    // config never sets this. Without the flag the snapshot carried only the
    // surviving match set — byte-identical to a term authored without the
    // leaf — so an accept term over-permitted and a discard/reject term
    // over-dropped with no signal past the boot warning. With this flag the
    // filter compiler raises
    // SnapshotIntegrityError::UnrepresentableFilterFrom and rejects the whole
    // snapshot (the reconcile preflight keeps the previous good filter
    // state). Whole-snapshot rejection — not term poisoning — because poisoning
    // a discard/reject term to match-nothing would let its traffic fall through
    // to the implicit accept (fail-OPEN); only refusing the snapshot is
    // action-agnostic. serde(default) keeps wire parity with an older control
    // plane that omits the field (#1961).
    #[serde(rename = "from_unrepresentable", default)]
    pub from_unrepresentable: bool,
    // flex_match is the Junos `from flexible-match-range` byte-offset match
    // (#3077). It was parsed + compiled for the retired legacy dataplane but
    // dropped on the userspace wire, so the byte-offset constraint vanished and
    // the term matched too broadly (fail-open). The match reads `length` bytes
    // at `offset` from the start of the L3 header (match-start layer-3),
    // interprets them big-endian, ANDs with `mask`, and requires the result to
    // equal `value` (already pre-masked by the Go compiler). None = no flex
    // constraint (the common case). Like the #2362 per-packet L4 fields this is
    // NOT in the SessionKey, so a filter carrying it is cache-sensitive — see
    // FilterTerm::has_per_packet_l4_match. serde(default) keeps wire parity with
    // an older Go control plane that omits the field (#1961).
    #[serde(rename = "flex_match", default)]
    pub flex_match: Option<FlexMatchSnapshot>,
}

// FlexMatchSnapshot mirrors the Go FlexMatchSnapshot wire form (#3077): the
// firewall-filter flexible-match-range byte-offset match. `offset` is the byte
// offset from the start of the L3 header (match-start layer-3); `length` is the
// match width in BYTES (1..4); `value` is the expected value AFTER masking;
// `mask` is applied to the read bytes before the equality compare.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FlexMatchSnapshot {
    #[serde(default)]
    pub offset: u8,
    #[serde(default)]
    pub length: u8,
    #[serde(default)]
    pub value: u32,
    #[serde(default)]
    pub mask: u32,
    /// #3232: the Junos `match-start` base the `offset` is relative to. ""
    /// (omitted) and "layer-3" both mean the L3/IP-header base (the historical
    /// default); "layer-4" offsets from the transport header. The Go control
    /// plane rejects `payload`/unknown at commit, so only ""/"layer-3"/
    /// "layer-4" reach the wire. `default` + `skip_serializing_if` keep wire
    /// parity with an older control plane that omits the field (#1961) and keep
    /// the layer-3 specimen byte-identical (the protocol_wire_v1 fixture).
    #[serde(rename = "match_start", default, skip_serializing_if = "String::is_empty")]
    pub match_start: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicerSnapshot {
    pub name: String,
    #[serde(rename = "bandwidth_bps", default)]
    pub bandwidth_bps: u64,
    #[serde(rename = "burst_bytes", default)]
    pub burst_bytes: u64,
    #[serde(rename = "discard_excess", default)]
    pub discard_excess: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ThreeColorPolicerSnapshot {
    pub name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "color_blind", default)]
    pub color_blind: bool,
    #[serde(rename = "committed_rate_bytes_per_sec", default)]
    pub committed_rate_bytes_per_sec: u64,
    #[serde(rename = "committed_burst_bytes", default)]
    pub committed_burst_bytes: u64,
    #[serde(rename = "peak_or_excess_rate_bytes_per_sec", default)]
    pub peak_or_excess_rate_bytes_per_sec: u64,
    #[serde(rename = "peak_or_excess_burst_bytes", default)]
    pub peak_or_excess_burst_bytes: u64,
    #[serde(rename = "then_action", default)]
    pub then_action: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FlowExportSnapshot {
    #[serde(rename = "collector_address", default)]
    pub collector_address: String,
    #[serde(rename = "collector_port", default)]
    pub collector_port: u16,
    #[serde(rename = "sampling_rate", default)]
    pub sampling_rate: u32,
    #[serde(rename = "active_timeout", default)]
    pub active_timeout: u32,
    #[serde(rename = "inactive_timeout", default)]
    pub inactive_timeout: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicyRuleSnapshot {
    #[serde(rename = "rule_id", default)]
    pub rule_id: String,
    #[serde(rename = "policy_id", default)]
    pub policy_id: u32,
    pub name: String,
    #[serde(rename = "from_zone", default)]
    pub from_zone: String,
    #[serde(rename = "to_zone", default)]
    pub to_zone: String,
    #[serde(rename = "scheduler_name", default)]
    pub scheduler_name: String,
    #[serde(default)]
    pub inactive: bool,
    /// Legacy back-compat field (kept on v3 wire). Carries the
    /// FULLY EXPANDED literal CIDRs (union of book content + free
    /// CIDRs). Old Rust uses ONLY this field. New Rust uses ONLY
    /// `source_literals` / `source_book_ids` when the rule is
    /// v3-shaped (see #1606).
    #[serde(rename = "source_addresses", default)]
    pub source_addresses: Vec<String>,
    #[serde(rename = "destination_addresses", default)]
    pub destination_addresses: Vec<String>,
    /// #1606: dense u32 IDs of address books cited by this rule.
    #[serde(rename = "source_book_ids", default)]
    pub source_book_ids: Vec<u32>,
    #[serde(rename = "destination_book_ids", default)]
    pub destination_book_ids: Vec<u32>,
    /// #1606: free-form CIDR / "any" literals the operator wrote
    /// inline in the rule match (NOT via a named address book).
    /// New Rust reads these via the v3-shaped predicate.
    #[serde(rename = "source_literals", default)]
    pub source_literals: Vec<String>,
    #[serde(rename = "destination_literals", default)]
    pub destination_literals: Vec<String>,
    #[serde(default)]
    pub applications: Vec<String>,
    #[serde(rename = "application_terms", default)]
    pub application_terms: Vec<PolicyApplicationSnapshot>,
    #[serde(default)]
    pub action: String,
    /// #2008 H2: invert the source/destination match sense. When set,
    /// the rule matches every address EXCEPT those in the source /
    /// destination set (Junos `source-address-excluded` /
    /// `destination-address-excluded`).
    #[serde(rename = "source_address_excluded", default)]
    pub source_address_excluded: bool,
    #[serde(rename = "destination_address_excluded", default)]
    pub destination_address_excluded: bool,
    /// #2508: per-policy Junos `then log session-init` / `session-close`
    /// selection. Stamped onto the session metadata at install so the
    /// per-policy RT_FLOW SYSLOG records can be emitted only for the
    /// policies the operator configured with `then log`. serde(default)
    /// keeps wire parity with an older Go control plane that omits them.
    #[serde(rename = "log_session_init", default)]
    pub log_session_init: bool,
    #[serde(rename = "log_session_close", default)]
    pub log_session_close: bool,
    /// #3148: optional from-zone/to-zone match context for a GLOBAL policy.
    /// A global rule keeps `from_zone`/`to_zone` == "junos-global" (so the
    /// classifier keeps it in the global tier and preserves global config
    /// order); these fields narrow which zone pairs the global rule matches.
    /// Empty = all zones (the historical global behaviour). `serde(default)`
    /// makes an old Go snapshot that omits them decode to "" (all zones), so
    /// version skew degrades safely.
    #[serde(rename = "match_from_zone", default)]
    pub match_from_zone: String,
    #[serde(rename = "match_to_zone", default)]
    pub match_to_zone: String,
    /// #4626 M03: the FULL scoped-global zone SET. A Junos global policy scope
    /// is a zone LIST (`match from-zone [ trust dmz ]`); these ADDITIVE plural
    /// fields carry every zone while the singular fields above keep the first
    /// element for rolling-upgrade safety. `parse_policy_state` PREFERS the
    /// plural when non-empty and falls back to the singular otherwise
    /// (`effective_match_zones` / `build_global_zone_scope`, policy.rs).
    /// `serde(default)` keeps wire parity with an older Go control plane that
    /// omits them (decode to the empty set → singular fallback). Populated only
    /// for global policies; empty for a zone-pair rule.
    #[serde(rename = "match_from_zones", default)]
    pub match_from_zones: Vec<String>,
    #[serde(rename = "match_to_zones", default)]
    pub match_to_zones: Vec<String>,
}

/// #1606: snapshot row for a unique address-book content.
/// Multiple Junos-declared book names whose canonical CIDR sets
/// are identical share one row + one ID. `name` is diagnostic-
/// only (lexicographically smallest declaring name).
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct AddressBookSnapshot {
    /// Stable u32 ID assigned by content-only hashing on the Go
    /// side. ID 0 is reserved as "unused" sentinel.
    pub id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "prefixes_v4", default)]
    pub prefixes_v4: Vec<String>,
    #[serde(rename = "prefixes_v6", default)]
    pub prefixes_v6: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicyApplicationSnapshot {
    pub name: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(rename = "source_port", default)]
    pub source_port: String,
    #[serde(rename = "destination_port", default)]
    pub destination_port: String,
    /// #3020: optional ICMP/ICMPv6 type (and code) constraint. `None` means
    /// "no constraint" — the term matches every type/code of its protocol (the
    /// historical behavior, kept by the all-ICMP aliases). junos-ping sets
    /// `icmp_type = Some(8)`, junos-pingv6 `Some(128)`. `#[serde(default)]`
    /// makes an old Go snapshot that omits the field decode to `None` (match
    /// all ICMP — today's behavior), so version skew degrades safely rather
    /// than failing to decode. `skip_serializing_if = Option::is_none` keeps
    /// the default specimen (and the `protocol_wire_v1` fixture) byte-identical.
    #[serde(rename = "icmp_type", default, skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,
    #[serde(rename = "icmp_code", default, skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,
    /// #3227: optional per-application inactivity (idle) timeout, in SECONDS,
    /// from a custom `set applications application <a> inactivity-timeout <n>`.
    /// `None`/0 means "use the global per-protocol `SessionTimeouts`" — the
    /// historical behavior. When a session is admitted by a policy whose matched
    /// application term carries this, the dataplane stamps it on the session and
    /// the conntrack GC ages the session out on this value instead of the global
    /// TCP/UDP/ICMP timeout (closing the legacy-eBPF `appTimeout` parity
    /// regression). `#[serde(default)]` makes an old Go snapshot that omits the
    /// field decode to `None` (use-global — today's behavior), and
    /// `skip_serializing_if = Option::is_none` keeps the default specimen (and
    /// the `protocol_wire_v1` fixture) byte-identical, so version skew degrades
    /// safely.
    #[serde(
        rename = "inactivity_timeout",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub inactivity_timeout: Option<u32>,
}

/// One row of the L3/L4 application-identification catalog (#2008 M5). Mirrors
/// the Go `AppCatalogEntrySnapshot` (`pkg/dataplane/userspace/protocol.go`). The
/// dataplane scans these on session create and stamps the matching `app_id` on
/// the conntrack session so `show security flow session` resolves a real
/// application name. Inclusive port boundaries; a `(0, 0)` dst-port pair means
/// "no destination-port constraint" (match on protocol alone, e.g. ICMP) and a
/// `(0, 0)` src-port pair means "no source-port constraint". `app_id` is never
/// 0 (0 is the reserved unknown sentinel). All numeric fields default so a
/// snapshot omitting `app_catalog` (old Go binary) decodes to an empty catalog.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct AppCatalogEntry {
    #[serde(rename = "app_id", default)]
    pub app_id: u16,
    #[serde(default)]
    pub protocol: u8,
    #[serde(rename = "dst_port_low", default)]
    pub dst_port_low: u16,
    #[serde(rename = "dst_port_high", default)]
    pub dst_port_high: u16,
    #[serde(rename = "src_port_low", default)]
    pub src_port_low: u16,
    #[serde(rename = "src_port_high", default)]
    pub src_port_high: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct PolicyRuleCounterStatus {
    #[serde(rename = "rule_id", default)]
    pub rule_id: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct FirewallFilterTermCounterStatus {
    #[serde(default)]
    pub family: String,
    #[serde(rename = "filter_name", default)]
    pub filter_name: String,
    #[serde(rename = "term_name", default)]
    pub term_name: String,
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct ThreeColorPolicerStatus {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub mode: String,
    #[serde(rename = "color_blind", default)]
    pub color_blind: bool,
    #[serde(rename = "green_packets", default)]
    pub green_packets: u64,
    #[serde(rename = "green_bytes", default)]
    pub green_bytes: u64,
    #[serde(rename = "yellow_packets", default)]
    pub yellow_packets: u64,
    #[serde(rename = "yellow_bytes", default)]
    pub yellow_bytes: u64,
    #[serde(rename = "red_packets", default)]
    pub red_packets: u64,
    #[serde(rename = "red_bytes", default)]
    pub red_bytes: u64,
    #[serde(rename = "drop_packets", default)]
    pub drop_packets: u64,
    #[serde(rename = "drop_bytes", default)]
    pub drop_bytes: u64,
}
