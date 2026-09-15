//! Firewall filter and policer evaluation for the userspace dataplane.
//!
//! Implements Junos-style firewall filters with ordered terms (first match wins)
//! and token-bucket policers. Mirrors the eBPF filter pipeline
//! (`bpf/xdp/xdp_forward.c` lo0 filter evaluation).
//!
//! Filters can be applied:
//! - Per-interface (input direction): evaluated after zone resolution, before session lookup
//! - lo0 (host-bound traffic): evaluated on local delivery path

use crate::prefix::{PrefixV4, PrefixV6};
// #1049 P2: Snapshot types come from the crate root (protocol.rs) and are
// referenced by both compiler.rs and the tests module. Importing here makes
// them visible to all submodules via `use super::*;`.
use crate::{
    FirewallFilterSnapshot, FirewallTermSnapshot, FlexMatchSnapshot, PolicerSnapshot,
    ThreeColorPolicerSnapshot,
};
use ipnet::IpNet;
#[cfg(not(test))]
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::ip_proto::proto_number;
use crate::policy::SnapshotIntegrityError;
// #2505: filter compilation resolves all protocol tokens through
// `proto_number`, so this module's *compiler* no longer needs the bare
// `PROTO_*` consts. Production code that DOES reference them imports them
// directly where used — e.g. `engine/matching.rs` imports `PROTO_TCP`,
// `PROTO_ICMP`, `PROTO_ICMPV6` from `crate::ip_proto` for per-packet match
// classification. The `#[cfg(test)]` import below re-exports the consts via
// `super::*` ONLY for the filter unit tests in this module (asserting a term
// resolved to the right IANA number); a module-level non-test re-export would
// warn as unused because nothing under `mod.rs`/`compiler.rs` references them
// outside tests anymore.
#[cfg(test)]
use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};

/// The ICMP unreachable codes a `then reject <message-type>` resolves to,
/// one per address family (#6854).
///
/// Junos accepts fifteen tokens after `then reject`. Fourteen are RFC 792
/// ICMPv4 Destination Unreachable codes and map exactly; `tcp-reset` is not an
/// ICMP message at all and carries the default here, because it only changes
/// behaviour on the TCP path where no ICMP reply is built.
///
/// # The v6 column fails closed rather than inventing a counterpart
///
/// RFC 4443 defines six ICMPv6 Destination Unreachable codes and they are not a
/// relabelling of RFC 792's sixteen. Four map honestly:
///
/// * `network-unreachable` -> 0 (no route to destination)
/// * `host-unreachable`    -> 3 (address unreachable)
/// * `port-unreachable`    -> 4 (port unreachable)
/// * the three prohibitions -> 1 (administratively prohibited)
///
/// The rest keep code 1, which is exactly what the dataplane already sent
/// before this change, so an operator who configures one of them sees today's
/// behaviour on v6 rather than a code invented to fill the column. But the
/// REASON differs by token and it is worth being exact, because a later change
/// that widens this struct will read this comment to decide what becomes
/// expressible:
///
/// * Genuinely no ICMPv6 equivalent: TOS-conditional unreachables, precedence
///   violations, source-host-isolated. `source-route-failed` belongs here too --
///   IPv6 has no RFC 791 source routing (RH0 is deprecated by RFC 5095), and
///   RFC 4443 code 5 is "Source address failed ingress/egress policy", a
///   genuinely different condition, so mapping to 5 would be wrong.
///
/// * `protocol-unreachable` is DIFFERENT, and an earlier version of this comment
///   was factually wrong about it. It HAS a specified ICMPv6 counterpart --
///   Parameter Problem, **type 4 code 1**, "unrecognized Next Header type
///   encountered" (RFC 4443 3.4). What puts it out of reach is not the absence
///   of a counterpart but that this struct carries only `{v4_code, v6_code}`
///   while `build_reject_icmp_unreachable` hardcodes ICMPv6 **type 1**: the
///   counterpart lives at a different TYPE, which the struct cannot express.
///   Emitting code 1 today is still right -- inventing a Destination Unreachable
///   code would be worse -- but if a `v6_type` is ever added, this is the one
///   token that becomes expressible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RejectMessage {
    pub(crate) v4_code: u8,
    pub(crate) v6_code: u8,
}

impl RejectMessage {
    /// ICMPv4 code 13 / ICMPv6 code 1 -- "communication administratively
    /// prohibited". What the dataplane hardcoded for every reject before
    /// #6854, and what a term with no message-type still resolves to.
    pub(crate) const ADMIN_PROHIBITED: Self = Self {
        v4_code: 13,
        v6_code: 1,
    };
}

impl Default for RejectMessage {
    fn default() -> Self {
        Self::ADMIN_PROHIBITED
    }
}

/// Resolve a Junos `then reject` message-type token to its per-family codes.
///
/// An unrecognized token resolves to [`RejectMessage::ADMIN_PROHIBITED`]
/// rather than failing the snapshot. That is deliberate and differs from the
/// fail-closed treatment of an unknown filter ACTION: the action decides
/// whether a packet is forwarded, whereas this decides only which code an
/// already-decided reject carries. The Go commit gate validates the token
/// against `rejectMessageTypes` before it is persisted, so an unknown value
/// here means version drift, and degrading to the code the dataplane sent
/// before #6854 is the conservative answer.
pub(crate) fn resolve_reject_message(token: &str) -> RejectMessage {
    // RFC 792 ICMPv4 Destination Unreachable codes.
    let v4 = match token {
        "network-unreachable" => 0,
        "host-unreachable" => 1,
        "protocol-unreachable" => 2,
        "port-unreachable" => 3,
        "source-route-failed" => 5,
        "source-host-isolated" => 8,
        "network-prohibited" => 9,
        "host-prohibited" => 10,
        "bad-network-tos" => 11,
        "bad-host-tos" => 12,
        "administratively-prohibited" => 13,
        "precedence-violation" => 14,
        "precedence-cutoff" => 15,
        // "tcp-reset", "", and anything unrecognized.
        _ => return RejectMessage::ADMIN_PROHIBITED,
    };
    // RFC 4443 ICMPv6 Destination Unreachable, where an honest counterpart
    // exists. See the type doc for why the rest stay at 1.
    let v6 = match token {
        "network-unreachable" => 0,
        "host-unreachable" => 3,
        "port-unreachable" => 4,
        _ => 1,
    };
    RejectMessage {
        v4_code: v4,
        v6_code: v6,
    }
}

/// Result of evaluating a filter term.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FilterAction {
    /// Accept the packet (default if no term matches).
    Accept,
    /// Silently drop the packet.
    Discard,
    /// Request reject behavior.
    ///
    /// Callers that cannot synthesize the reject packet must fail closed as a
    /// silent drop and must not log that an ICMP/RST reject was generated.
    ///
    /// #3615: this contract is enforced at the RT_FLOW / filter-log emit sites.
    /// The reject reply is enqueued FIRST (`poll_descriptor::filter_terminal` /
    /// the input-filter reorder), and its ACTUAL outcome is threaded into
    /// `emit_filter_log_event`. When the reply fail-closes (TX-frame budget,
    /// reject token bucket empty, unparseable built frame, or an egress
    /// output-filter drop of the reflected reply) the logged RT_FLOW action is
    /// downgraded REJECT→DENY, so the event never claims an active reject that
    /// was not sent. Reply-free paths (flowless fragments, the PBR/output-filter
    /// forward path, cached-log replay) pass `reject_reply_enqueued = false`.
    ///
    /// #6854: carries the ICMP codes the term's `then reject <message-type>`
    /// resolves to. A term with no message-type carries
    /// [`RejectMessage::ADMIN_PROHIBITED`], which is what every reject sent
    /// before #6854, so an unset value is bit-identical to the old behaviour.
    Reject(RejectMessage),
}

// ============================================================
// CACHE-KEY INVARIANT (#1431) — read before adding a match field
//
// Every match criterion on FilterTerm (and the wire DTO
// FirewallTermSnapshot) MUST be classified as either:
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
/// #3232: the Junos `flexible-match-range match-start` base the term's
/// `flex_offset` is measured from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum FlexMatchStart {
    /// Offset from the start of the L3/IP header — the #3077 default ("" /
    /// "layer-3" on the wire).
    #[default]
    Layer3,
    /// Offset from the start of the L4/transport header ("layer-4").
    Layer4,
    /// An unrecognized match-start (e.g. "payload") that slipped past the Go
    /// commit gate on the tolerant peer-sync path. The matcher fails the flex
    /// term CLOSED rather than silently evaluate it at the wrong base.
    Unsupported,
}

/// Compiled filter term with pre-parsed match criteria.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct FilterTerm {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) source_v4: Vec<PrefixV4>,
    pub(crate) source_v6: Vec<PrefixV6>,
    pub(crate) dest_v4: Vec<PrefixV4>,
    pub(crate) dest_v6: Vec<PrefixV6>,
    // #2400 (032-18): fail-closed flags for the source/destination ADDRESS
    // match sets. `*_addr_constrained` is true when the term has at least one
    // REAL match entry (`addr_is_real` in compiler.rs — EXCLUDING the empty
    // string and the literal `any`), regardless of how many entries survived
    // parsing. An explicit `from { source-address any; }` therefore stays
    // UNCONSTRAINED (match-any). The matcher in `engine/matching.rs` uses the
    // flag to tell apart an UNSCOPED term (constrained == false → match any
    // address) from a SCOPED term whose entries ALL failed to parse
    // (constrained == true but both prefix vecs empty for that family → match
    // NOTHING, fail closed). Without this flag an all-malformed address list
    // collapses to the empty-list "match any" fail-open broadening (a `discard`
    // term scoped to typo'd addresses would become discard-all). Mirrors the
    // #2398/#2394 NAT `*_constrained` pattern.
    pub(crate) source_addr_constrained: bool,
    pub(crate) dest_addr_constrained: bool,
    // #2506: invert the source/destination address membership test. When true,
    // the term matches every address NOT in the source/dest prefix set (Junos
    // `from source-prefix-list NAME except` / `destination-prefix-list NAME
    // except`). The matcher in engine/matching.rs evaluates
    // `(addr ∈ prefixes) XOR except`. Only meaningful when the direction is
    // `*_addr_constrained` (an UNCONSTRAINED term matches any address
    // regardless of the except flag — there is no prefix set to invert).
    pub(crate) source_except: bool,
    pub(crate) dest_except: bool,
    pub(crate) protocol_bitmap: [u64; 4],
    pub(crate) protocol_match_enabled: bool,
    pub(crate) source_ports: PortMatcher,
    pub(crate) dest_ports: PortMatcher,
    // #2400 (032-19): fail-closed flags for the source/destination PORT match
    // sets. Same shape as the address flags above. A `PortMatcher::Any` arises
    // from BOTH the legitimate unscoped case (no port configured) AND the
    // all-malformed case (every configured port spec failed to parse), so the
    // matcher cannot distinguish them from the `PortMatcher` alone. When
    // `*_port_constrained` is true but the matcher is `PortMatcher::Any`, the
    // term had a port list that ALL failed to parse → match NOTHING (fail
    // closed). A valid scoped term yields a non-`Any` matcher and matches its
    // ports as before.
    pub(crate) source_port_constrained: bool,
    pub(crate) dest_port_constrained: bool,
    // #2622: invert the source/destination PORT membership test (Junos `from
    // source-port-except` / `destination-port-except`). When true, the matcher
    // matches every port NOT in the source/dest port set:
    // `(port ∈ ranges) XOR except`. The except port list builds the SAME
    // PortMatcher and sets `*_port_constrained`; only the inversion differs.
    // #3205 FAIL-CLOSED: when the except list is non-empty but ALL entries fail
    // to parse (`PortMatcher::Any` while constrained), the term matches NOTHING
    // — NOT "match all ports except {}" = match ALL. `port_match`
    // (engine/matching.rs) returns false for `constrained && PortMatcher::Any`
    // in BOTH the positive and the except direction, so an unresolved
    // `destination-port-except <name>` can never invert an empty set into
    // match-ALL (that was the pre-#3205 fail-OPEN hole that accepted the very
    // port it was meant to exclude). This intentionally DIFFERS from the ADDRESS
    // empty-except path (`nets_match_v4`/`nets_match_v6`, which returns `except`
    // → match-ALL): a port scope has no prefix-list indirection, so
    // `constrained && Any` can ONLY mean every token was unparseable — never a
    // legitimately empty scope — whereas an empty address prefix-list scope IS
    // reachable and legitimate and keeps the Junos "match all except {}" =
    // match-ALL semantic. Only meaningful when the direction is
    // `*_port_constrained`.
    pub(crate) source_port_except: bool,
    pub(crate) dest_port_except: bool,
    pub(crate) dscp_bitmap: u64,
    pub(crate) dscp_match_enabled: bool,
    // Per-packet L4 match conditions (#2362). NOT in SessionKey, so a filter
    // carrying any of these is cache-sensitive (path (b) per the #1431
    // invariant above): the flow-cache must decline insertion and the
    // change-detection / re-eval / rotation-purge machinery in
    // cache_sensitive.rs must treat them like dscp.
    //
    // tcp_flags_mask: required-bits mask over the TCP flags byte. A TCP packet
    // matches when (flags & mask) == mask. None = no constraint. Only TCP can
    // match a term that sets this.
    pub(crate) tcp_flags_mask: Option<u8>,
    // tcp_flags_forbidden: forbidden-bits mask over the TCP flags byte (#3076).
    // A TCP packet matches only when (flags & forbidden) == 0. Carries the
    // negated operands of a Junos tcp-flags expression such as `syn & !ack`
    // (tcp_flags_mask=SYN, tcp_flags_forbidden=ACK). None = no forbidden
    // constraint. Independent of tcp_flags_mask: a term may set either, both, or
    // neither. Cache-sensitive (NOT in SessionKey) — see has_per_packet_l4_match
    // and cache_sensitive.rs.
    pub(crate) tcp_flags_forbidden: Option<u8>,
    // is_fragment: matches any IP fragment.
    pub(crate) is_fragment: bool,
    // icmp_type / icmp_code: SET membership over the ICMP/ICMPv6 type/code byte
    // (#2545, multi-value). The bitmap is 256 bits (`[u64; 4]`); a packet's
    // type/code byte matches when its bit is set. `*_match_enabled` is false for
    // an unconstrained term (empty set → match any), so a term that omits the
    // criterion matches every type/code. Only ICMP/ICMPv6 can match a term that
    // enables these. Previously a single `Option<u8>` (exact equality) — a term
    // with two `from icmp-type` values kept only the last.
    pub(crate) icmp_type_bitmap: [u64; 4],
    pub(crate) icmp_type_match_enabled: bool,
    pub(crate) icmp_code_bitmap: [u64; 4],
    pub(crate) icmp_code_match_enabled: bool,
    // flexible-match-range (#3077): a byte-offset match against the L3 header
    // (match-start layer-3, the only start point the Go compiler emits). When
    // `flex_enabled` the matcher reads `flex_length` bytes (1..4) at
    // `flex_offset` from the start of the L3 header (carried in
    // TermMatchExtra::flex_l3), interprets them big-endian into a u32, ANDs with
    // `flex_mask`, and requires the result to equal `flex_value` (pre-masked by
    // the Go control plane). A packet too short to hold the window, or any path
    // without the L3 bytes (flex_l3 == None), makes the term FAIL CLOSED (no
    // match) — never the pre-#3077 fail-open where the constraint was dropped
    // entirely. NOT in the SessionKey, so it is cache-sensitive (see
    // has_per_packet_l4_match): the flow-cache declines for filters using it.
    pub(crate) flex_enabled: bool,
    pub(crate) flex_offset: u8,
    pub(crate) flex_length: u8,
    pub(crate) flex_value: u32,
    pub(crate) flex_mask: u32,
    // #3232: the base `flex_offset` is measured from. Layer3 (default) reads
    // from the L3/IP header (TermMatchExtra::flex_l3) — the #3077 behavior;
    // Layer4 reads from the transport header (TermMatchExtra::flex_l4). The Go
    // compiler rejects `payload`/unknown match-start at commit, but the tolerant
    // peer-sync path could still deliver one, so an unrecognized value lowers to
    // `Unsupported`, which fails the term CLOSED in the matcher (never the
    // pre-#3232 silent L3-base mis-match).
    pub(crate) flex_match_start: FlexMatchStart,
    pub(crate) action: FilterAction,
    // #2544: fall-through. When true, this term carries NO terminating action
    // (an explicit `then next term` OR a modifier-only term). On a MATCH the
    // evaluator applies the term's modifiers (count, log, forwarding-class,
    // policer, dscp) and then CONTINUES to the next term instead of returning —
    // Junos fall-through semantics. `action` is left as Accept (the historical
    // empty-action mapping) but is never returned for a matched fall-through
    // term; it only takes effect as the default if NO later term terminates and
    // no term matched (handled by the trailing default). A term with a
    // terminating action (accept/reject/discard) has this false and returns on
    // match as before.
    pub(crate) continue_term: bool,
    pub(crate) count: String,
    pub(crate) has_count: bool,
    pub(crate) log: bool,
    // #5444: `policer_name`/`routing_instance` are `Arc<str>` (like
    // `forwarding_class`) so `merge_matched_modifiers` propagates them into the
    // per-packet `FilterResult` with a refcount bump instead of a String heap
    // allocation+copy on every matched term. Config-owned, set once at compile
    // time, read-only downstream.
    pub(crate) policer_name: Arc<str>,
    pub(crate) three_color_policer: Option<Arc<ThreeColorPolicerRuntime>>,
    pub(crate) routing_instance: Arc<str>,
    pub(crate) forwarding_class: Arc<str>,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) counter: Arc<FilterTermCounter>,
}

impl FilterTerm {
    /// Whether this term carries any per-packet L4 match condition (#2362)
    /// that is not part of the 5-tuple SessionKey: tcp-flags, is-fragment,
    /// icmp-type, or icmp-code. A filter with such a term is cache-sensitive
    /// (the flow-cache must decline insertion — see `flow_cache.rs`).
    #[inline]
    pub(crate) fn has_per_packet_l4_match(&self) -> bool {
        self.tcp_flags_mask.is_some()
            || self.tcp_flags_forbidden.is_some()
            || self.is_fragment
            || self.icmp_type_match_enabled
            || self.icmp_code_match_enabled
            // #3077: flexible-match-range reads raw packet bytes, not the
            // 5-tuple, so it is cache-sensitive exactly like the other
            // per-packet conditions — the flow-cache must decline for it.
            || self.flex_enabled
    }
}

/// Per-packet match inputs that are NOT in the 5-tuple (#2362). Computed once
/// per packet at each evaluate call site (the only place that has the frame
/// bytes) and threaded into the term predicate. `Default` (all-absent,
/// `l4_present = false`) makes every L4 per-packet condition fail to match, so
/// callers that cannot cheaply compute these (cached/TX-selection rebuild
/// paths, which never carry an L4-match term because the flow-cache declines
/// for such filters) stay behavior-compatible AND fail closed.
///
/// #3077: `flex_l3` carries the L3-header byte slice (match-start layer-3) for
/// the flexible-match-range byte-offset match. It is `None` on every path that
/// has no contiguous frame (cached/TX-selection rebuilds, meta-only synthetic
/// TX) and on the `Default` value, which makes a flex-constrained term FAIL
/// CLOSED there — those paths never carry a flex term (the flow-cache declines),
/// and fail-closed is the correct posture if one ever reaches them. The slice
/// borrows the frame, hence the lifetime; `TermMatchExtra` stays `Copy` because
/// `Option<&[u8]>` is `Copy`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TermMatchExtra<'a> {
    /// Raw TCP flags byte (only meaningful when protocol == TCP and
    /// `l4_present`).
    pub(crate) tcp_flags: u8,
    /// Whether the packet is an IP fragment (any fragment). L3-derived — valid
    /// regardless of `l4_present` (every fragment carries the IP header).
    pub(crate) is_fragment: bool,
    /// ICMP/ICMPv6 type byte (only meaningful when protocol is ICMP/ICMPv6 and
    /// `l4_present`).
    pub(crate) icmp_type: u8,
    /// ICMP/ICMPv6 code byte (only meaningful when protocol is ICMP/ICMPv6 and
    /// `l4_present`).
    pub(crate) icmp_code: u8,
    /// #2362 fold A (Copilot): whether a real L4 header is present at
    /// `l4_offset`. FALSE for a NON-FIRST fragment (its post-IP bytes are
    /// payload, not an L4 header) and for any other no-L4 case. The matcher
    /// gates the tcp-flags / icmp-type / icmp-code constraints on this flag —
    /// NOT on the byte values — because 0 is a VALID icmp-type (echo-reply) and
    /// a VALID icmp-code, so a zeroed byte would still spuriously match
    /// `icmp-type 0` / `icmp-code 0`. `is_fragment` is L3-derived and is NOT
    /// gated by this flag.
    pub(crate) l4_present: bool,
    /// #3077: the L3-header byte slice (start of the IP header) for the
    /// flexible-match-range byte-offset match. `None` => no L3 bytes available
    /// on this path => a flex-constrained term fails closed. See the struct doc.
    pub(crate) flex_l3: Option<&'a [u8]>,
    /// #3232: the L4/transport-header byte slice (start at `meta.l4_offset`) for
    /// a `match-start layer-4` flexible-match-range. `None` => no L4 header on
    /// this path (meta-only/deferred rebuilds, OR a non-first fragment whose
    /// post-IP bytes are payload, not an L4 header) => a layer-4 flex term fails
    /// closed. A layer-3 flex term ignores this and uses `flex_l3`.
    pub(crate) flex_l4: Option<&'a [u8]>,
    /// #7992: the caller has NO port information at all — not "ports are zero",
    /// but "there is no flow to take ports from".
    ///
    /// Polarity is deliberate. `false` is the default, so every existing caller
    /// keeps today's behaviour and only a site that genuinely lacks ports
    /// opts in. Such sites are the FLOWLESS arm of
    /// `resolve_cached_cos_tx_selection_impl`, which passed literal `0, 0`
    /// (#7992), and the flowless input-filter/PBR evaluations, which run on
    /// an L3-only enforcement context whose ports are 0-substituted by
    /// construction (#9894).
    ///
    /// This cannot be expressed with `l4_present`, which is why that was tried
    /// and reverted: the flow-cache path passes REAL `SessionKey` ports with
    /// `l4_present: false`, so the flag is ambiguous between "no L4 header" and
    /// "cached flow with real ports" — and gating ports on it red 11+ tests
    /// (`a_cached_flow_still_matches_a_port_term_despite_no_l4_present_7174`).
    /// This flag is unambiguous by construction: only a caller with no ports
    /// sets it.
    ///
    /// It follows the gating rule this struct already states for tcp-flags and
    /// icmp-type/code — gate on a FLAG, never on the byte value, because a
    /// zeroed value is indistinguishable from a real one. Ports were the case
    /// that rule had not been applied to.
    pub(crate) ports_unknown: bool,
}

// #7212 CONTRACT, stated here because this is where the next author looks.
// `Filter::varies_per_packet_within_flow()` summarises the reads of this struct
// made by `per_packet_l4_matches` ALONE. It does NOT summarise
// `port_terms_match`, which reads `is_fragment` / `l4_present` /
// `ports_unknown` gated on a PORT constraint. The static input-filter
// revalidation depends on knowing exactly which reads that predicate covers, so
// it passes `TermMatchExtra::default()` and derives the flow's 5-tuple verdict
// rather than this packet's. A new read of this struct from outside
// `per_packet_l4_matches` must be re-checked against that argument — see the
// `Never` bullet in `filter/README.md`.


impl<'a> TermMatchExtra<'a> {
    /// #3077: drop the borrowed L3 slice, yielding a `'static`-lifetime copy
    /// safe to STORE in a deferred request (`PendingForwardRequest`) that
    /// outlives the UMEM frame. The frame may be recycled before the deferred
    /// TX-selection / CoS path consumes the request, so the flex byte-offset
    /// condition cannot be re-evaluated there — a flex-constrained term FAILS
    /// CLOSED (under-matches → default forwarding-class), never fail-open. The
    /// security ACCEPT/DISCARD decision is taken on the immediate filter-eval
    /// path, which keeps the live slice. All non-borrow fields are preserved.
    #[inline]
    pub(crate) fn to_static(self) -> TermMatchExtra<'static> {
        TermMatchExtra {
            tcp_flags: self.tcp_flags,
            is_fragment: self.is_fragment,
            icmp_type: self.icmp_type,
            icmp_code: self.icmp_code,
            ports_unknown: self.ports_unknown,
            l4_present: self.l4_present,
            flex_l3: None,
            // #3232: drop the borrowed L4 slice too — a deferred path cannot
            // re-read the frame, so a layer-4 flex term fails closed (same
            // contract as flex_l3).
            flex_l4: None,
        }
    }
}

/// Inclusive port range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PortRange {
    pub(crate) low: u16,
    pub(crate) high: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PortMatcher {
    Any,
    Single(u16),
    Range(PortRange),
    Set(Box<[PortRange]>),
}

impl PortMatcher {
    #[inline(always)]
    fn matches(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(expected) => port == *expected,
            Self::Range(range) => port >= range.low && port <= range.high,
            Self::Set(ranges) => ranges
                .iter()
                .any(|range| port >= range.low && port <= range.high),
        }
    }
}

/// A compiled firewall filter (ordered list of terms).
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct Filter {
    pub(crate) id: u32,
    pub(crate) name: String,
    pub(crate) family: String,
    pub(crate) terms: Vec<FilterTerm>,
    pub(crate) affects_tx_selection: bool,
    pub(crate) affects_route_lookup: bool,
    pub(crate) has_counter_terms: bool,
    pub(crate) has_log_terms: bool,
    pub(crate) has_terminal_action_terms: bool,
    pub(crate) has_dscp_match_terms: bool,
    /// Any term carries a per-packet L4 match (tcp-flags / is-fragment /
    /// icmp-type / icmp-code) — #2362. Cache-sensitive like
    /// `has_dscp_match_terms`: the flow-cache must decline for these filters.
    pub(crate) has_per_packet_l4_match_terms: bool,
    pub(crate) has_three_color_policer_terms: bool,
}

impl Filter {
    /// #6236 PR-2A: the canonical "the output filter must still be walked on the
    /// TX path" predicate. An output filter earns a TX-path evaluation when it
    /// can change or observe the packet: CoS/DSCP tx-selection, a `then count`,
    /// a `then log`, a terminal (non-`accept`) action, or a three-color policer.
    ///
    /// This is the SOLE definition of the five-flag OR. The compiler's
    /// `iface_filter_out_*_needs_tx_eval` set-insert, the
    /// `has_output_needs_tx_eval_*` aggregates, and every `cos_classify` TX arm
    /// call through here so the composite can never drift between the compile
    /// path and the hot path (#2620-adjacent invariant).
    #[inline]
    pub(crate) fn needs_tx_eval(&self) -> bool {
        self.affects_tx_selection
            || self.has_counter_terms
            || self.has_log_terms
            || self.has_terminal_action_terms
            || self.has_three_color_policer_terms
    }

    /// #6236 PR-2C: the #1430/#2362 "this filter's per-packet verdict is NOT a
    /// pure function of the flow-cache 5-tuple" predicate. A DSCP match term
    /// (#1430) or a per-packet L4 match term (#2362: tcp-flags / is-fragment /
    /// icmp-type / icmp-code) keys off a field outside the 5-tuple, so a
    /// first-packet decision must not be replayed: the flow-cache declines and
    /// the session-hit path re-evaluates.
    ///
    /// This is the SOLE definition of the `has_dscp_match_terms ||
    /// has_per_packet_l4_match_terms` OR. The single-lookup accessor
    /// `interface_input_filter_varies_per_packet` and the folded session-hit
    /// re-eval gate (`afxdp/poll_descriptor/filter.rs`) both evaluate it off ONE
    /// borrowed `&Filter`, so they cannot drift from the per-flag accessors
    /// (`interface_input_filter_has_dscp_match` /
    /// `interface_input_filter_has_per_packet_l4_match`) that the flow-cache
    /// decline gate (`afxdp/flow_cache.rs`) still consults individually.
    #[inline]
    pub(crate) fn varies_per_packet_within_flow(&self) -> bool {
        self.has_dscp_match_terms || self.has_per_packet_l4_match_terms
    }
}

#[derive(Debug, Default)]
pub(crate) struct FilterTermCounter {
    pub(crate) packets: AtomicU64,
    pub(crate) bytes: AtomicU64,
}

#[derive(Debug, Default)]
pub(crate) struct ThreeColorPolicerCounter {
    pub(crate) packets: AtomicU64,
    pub(crate) bytes: AtomicU64,
}

impl ThreeColorPolicerCounter {
    fn record(&self, packet_bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(packet_bytes, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub(crate) struct ThreeColorPolicerCounters {
    pub(crate) green: ThreeColorPolicerCounter,
    pub(crate) yellow: ThreeColorPolicerCounter,
    pub(crate) red: ThreeColorPolicerCounter,
    pub(crate) drop: ThreeColorPolicerCounter,
}

#[derive(Debug)]
pub(crate) struct ThreeColorPolicerRuntime {
    pub(crate) id: u32,
    pub(crate) name: Arc<str>,
    // #5390: NO `Mutex`. The token-bucket state meters lock-free through CAS
    // over its own atomics (`filter/policer.rs`), so the RSS-spread flow
    // aggregate no longer serializes on a per-packet futex. Removing the lock
    // also removes the poison failure mode entirely; the only fail-closed path
    // is the `Unsupported`-mode Red/drop inside `meter`.
    state: ThreeColorPolicerState,
    counters: ThreeColorPolicerCounters,
}

impl PartialEq for ThreeColorPolicerRuntime {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.name == other.name
    }
}

impl Eq for ThreeColorPolicerRuntime {}

/// #2544/#4566: the set of fall-through three-color policer terms a cached
/// TX-selection decision must re-meter on every flow-cache replay. With #2544
/// fall-through a single packet can match multiple three-color policer terms;
/// the previous two-`Option` layout (`first`/`second`) silently DROPPED the 3rd
/// (and beyond) policer on the cached path, so a flow with >=3 fall-through
/// policer terms escaped the 3rd+ term's committed/peak rate limit on EVERY
/// cached packet — the uncached full-eval path meters each (#4566). Now backed
/// by a `SmallVec` with an inline capacity of 2 (matching the sibling
/// `CachedFilterCounters`, #2573): the common single- and dual-policer flows
/// record with NO heap allocation, and any spill to the heap for >2 policers
/// happens ONCE at flow-cache install, off the per-packet replay (`for_each`)
/// hot path. Dedup is by policer `id` (`ThreeColorPolicerRuntime` carries an
/// id) so the same policer referenced by two matched terms is metered once per
/// packet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CachedThreeColorPolicers {
    policers: smallvec::SmallVec<[Arc<ThreeColorPolicerRuntime>; 2]>,
}

impl CachedThreeColorPolicers {
    #[inline]
    pub(crate) fn from_option(runtime: Option<Arc<ThreeColorPolicerRuntime>>) -> Self {
        let mut policers = smallvec::SmallVec::new();
        if let Some(runtime) = runtime {
            policers.push(runtime);
        }
        Self { policers }
    }

    #[inline]
    pub(crate) fn push(&mut self, runtime: Arc<ThreeColorPolicerRuntime>) {
        if self
            .policers
            .iter()
            .any(|existing| existing.id == runtime.id)
        {
            return;
        }
        self.policers.push(runtime);
    }

    #[inline]
    pub(crate) fn extend(&mut self, other: Self) {
        for runtime in other.policers {
            self.push(runtime);
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.policers.len()
    }

    #[inline]
    pub(crate) fn for_each(&self, mut f: impl FnMut(&Arc<ThreeColorPolicerRuntime>)) {
        for policer in &self.policers {
            f(policer);
        }
    }
}

/// #2573: the set of `then count` term counters a cached TX-selection decision
/// must increment on every flow-cache replay. With #2544 fall-through, a single
/// packet can match multiple `then count` terms; the old single-`Arc` slot kept
/// only the LAST, so the earlier fall-through count terms were silently
/// under-counted on the cached path (the uncached full-eval path counted each).
///
/// Backed by a `SmallVec` with an inline capacity of 2 so the common single- and
/// dual-counter flows record with NO heap allocation. The descriptor is built
/// ONCE at flow-cache install and then only read (`for_each`) on the per-packet
/// replay, so any spill to the heap for >2 counters happens off the packet hot
/// path. Dedup is by `Arc::ptr_eq` (FilterTermCounter has no id) so the same
/// counter referenced by two matched terms is recorded once per packet.
#[derive(Clone, Debug, Default)]
pub(crate) struct CachedFilterCounters {
    counters: smallvec::SmallVec<[Arc<FilterTermCounter>; 2]>,
}

impl CachedFilterCounters {
    #[inline]
    pub(crate) fn push(&mut self, counter: Arc<FilterTermCounter>) {
        if self
            .counters
            .iter()
            .any(|existing| Arc::ptr_eq(existing, &counter))
        {
            return;
        }
        self.counters.push(counter);
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.counters.len()
    }

    #[inline]
    pub(crate) fn for_each(&self, mut f: impl FnMut(&Arc<FilterTermCounter>)) {
        for counter in &self.counters {
            f(counter);
        }
    }

    /// #3777: drop any counter already present in `other` (by `Arc` identity).
    /// The cos TX-selection rebuild (`resolve_cached_cos_tx_selection`) folds an
    /// interface INPUT filter's `then count` handles into
    /// `tx_selection.filter_counters` when the egress interface carries no
    /// output filter. The dedicated input-filter replay set
    /// (`RewriteDescriptor::input_filter_counters`) captures the SAME handles, so
    /// without this dedup a count-plus-forwarding-class input term would be
    /// recorded TWICE per cache hit. Called once at flow-cache install (seed),
    /// never on the per-packet hit path. Both sets are `SmallVec`s with inline
    /// capacity 2, so this is a bounded O(n*m) identity scan off the hot path.
    #[inline]
    pub(crate) fn retain_absent_from(&mut self, other: &CachedFilterCounters) {
        self.counters
            .retain(|counter| !other.counters.iter().any(|o| Arc::ptr_eq(o, counter)));
    }
}

impl ThreeColorPolicerRuntime {
    pub(crate) fn new(id: u32, name: String, state: ThreeColorPolicerState) -> Self {
        Self {
            id,
            name: Arc::<str>::from(name),
            state,
            counters: ThreeColorPolicerCounters::default(),
        }
    }

    pub(crate) fn meter(
        &self,
        now_ns: u64,
        packet_bytes: u64,
        incoming_color: PacketColor,
    ) -> ThreeColorDecision {
        // #5390: lock-free meter — `&self` CAS over the atomic token bucket.
        let decision = self.state.meter(now_ns, packet_bytes, incoming_color);
        match decision.color {
            PacketColor::Green => self.counters.green.record(packet_bytes),
            PacketColor::Yellow => self.counters.yellow.record(packet_bytes),
            PacketColor::Red => self.counters.red.record(packet_bytes),
        }
        if decision.drop {
            self.counters.drop.record(packet_bytes);
        }
        decision
    }

    pub(crate) fn reusable_for(&self, id: u32, next_shape: &ThreeColorPolicerState) -> bool {
        if self.id != id {
            return false;
        }
        // #5390: shape lives in the immutable `config`; no lock needed.
        self.state.same_runtime_shape(next_shape)
    }

    pub(crate) fn same_runtime_shape_as(&self, other: &Self) -> bool {
        if self.id != other.id || self.name != other.name {
            return false;
        }
        self.state.same_runtime_shape(&other.state)
    }

    pub(crate) fn status(&self) -> crate::protocol::ThreeColorPolicerStatus {
        // #5390: shape reads are lock-free (immutable `config`); counters are
        // Relaxed atomics as before.
        let mode = self.state.mode_name().to_string();
        let color_blind = self.state.color_blind();
        crate::protocol::ThreeColorPolicerStatus {
            id: self.id,
            name: self.name.to_string(),
            mode,
            color_blind,
            green_packets: self.counters.green.packets.load(Ordering::Relaxed),
            green_bytes: self.counters.green.bytes.load(Ordering::Relaxed),
            yellow_packets: self.counters.yellow.packets.load(Ordering::Relaxed),
            yellow_bytes: self.counters.yellow.bytes.load(Ordering::Relaxed),
            red_packets: self.counters.red.packets.load(Ordering::Relaxed),
            red_bytes: self.counters.red.bytes.load(Ordering::Relaxed),
            drop_packets: self.counters.drop.packets.load(Ordering::Relaxed),
            drop_bytes: self.counters.drop.bytes.load(Ordering::Relaxed),
        }
    }
}

impl FilterTermCounter {
    pub(crate) fn record(&self, packet_bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(packet_bytes, Ordering::Relaxed);
    }
}

#[cfg(not(test))]
#[derive(Default)]
struct PendingFilterCounterRecord {
    counter: Option<Arc<FilterTermCounter>>,
    packets: u64,
    bytes: u64,
}

#[cfg(not(test))]
const FILTER_COUNTER_FLUSH_PACKETS: u64 = 64;

#[cfg(not(test))]
thread_local! {
    static PENDING_FILTER_COUNTER_RECORD: RefCell<PendingFilterCounterRecord> =
        RefCell::new(PendingFilterCounterRecord::default());
}

#[cfg(not(test))]
#[inline(always)]
fn flush_pending_filter_counter_record(record: &mut PendingFilterCounterRecord) {
    let Some(counter) = record.counter.take() else {
        return;
    };
    counter.packets.fetch_add(record.packets, Ordering::Relaxed);
    counter.bytes.fetch_add(record.bytes, Ordering::Relaxed);
    record.packets = 0;
    record.bytes = 0;
}

#[cfg(not(test))]
#[inline(always)]
pub(crate) fn record_filter_counter(counter: &Arc<FilterTermCounter>, packet_bytes: u64) {
    PENDING_FILTER_COUNTER_RECORD.with(|pending| {
        let mut pending = pending.borrow_mut();
        if pending
            .counter
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, counter))
        {
            pending.packets = pending.packets.saturating_add(1);
            pending.bytes = pending.bytes.saturating_add(packet_bytes);
        } else {
            flush_pending_filter_counter_record(&mut pending);
            pending.counter = Some(counter.clone());
            pending.packets = 1;
            pending.bytes = packet_bytes;
        }
        if pending.packets >= FILTER_COUNTER_FLUSH_PACKETS {
            flush_pending_filter_counter_record(&mut pending);
        }
    });
}

#[cfg(test)]
#[inline(always)]
pub(crate) fn record_filter_counter(counter: &Arc<FilterTermCounter>, packet_bytes: u64) {
    counter.record(packet_bytes);
}

#[cfg(not(test))]
pub(crate) fn flush_recorded_filter_counters() {
    PENDING_FILTER_COUNTER_RECORD.with(|pending| {
        flush_pending_filter_counter_record(&mut pending.borrow_mut());
    });
}

#[cfg(test)]
pub(crate) fn flush_recorded_filter_counters() {}

// #1049 P2: structural split — engine, compiler, and policer extracted
// into sibling submodules. mod.rs hosts the shared type vocabulary,
// constants, and counter-flush helpers; the submodules import them via
// `use super::*;`.
mod compiler;
mod engine;
mod policer;

// Glob re-exports surface the `pub(crate) fn`/`pub(crate) struct` items from
// each submodule. Private helpers inside compiler/engine stay invisible
// because the glob only re-exports `pub`-visible items.
pub(crate) use compiler::*;
pub(crate) use engine::*;
pub(crate) use policer::*;
/// Aggregate filter state: all compiled filters and policers.
#[derive(Clone, Debug, Default)]
pub(crate) struct FilterState {
    /// Named filters keyed by "family:name" (e.g. "inet:protect-RE").
    pub(crate) filters: rustc_hash::FxHashMap<String, Arc<Filter>>,
    /// Stable three-color policer runtimes keyed by policer name. #4514:
    /// legacy single-rate `firewall policer` token buckets are lowered into
    /// this same set at compile so `then policer X` is metered/enforced through
    /// the three-color runtime rather than the dead `PolicerState` map.
    pub(crate) three_color_policer_by_name:
        rustc_hash::FxHashMap<String, Arc<ThreeColorPolicerRuntime>>,
    /// Name-derived ID-indexed three-color policer runtimes.
    pub(crate) three_color_policers: Vec<Arc<ThreeColorPolicerRuntime>>,
    /// Direct per-interface inet filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_v4_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Whether any inet input filter can affect CoS TX selection.
    pub(crate) has_input_tx_selection_v4: bool,
    /// Whether any inet input filter contains a three-color policer.
    pub(crate) has_input_three_color_policer_v4: bool,
    // #6236 PR-2B: the per-interface inet input capability sets
    // (`iface_filter_v4_affects_route_lookup`, `iface_filter_v4_has_dscp_match`,
    // `iface_filter_v4_has_per_packet_l4_match`) are deleted — every accessor now
    // reads the mirrored `Filter` flag off `iface_filter_v4_fast`.
    /// Direct per-interface inet6 filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_v6_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    /// Whether any inet6 input filter can affect CoS TX selection.
    pub(crate) has_input_tx_selection_v6: bool,
    /// Whether any inet6 input filter contains a three-color policer.
    pub(crate) has_input_three_color_policer_v6: bool,
    // #6236 PR-2B: the per-interface inet6 input capability sets are deleted —
    // the accessors read the mirrored `Filter` flag off `iface_filter_v6_fast`
    // (same as the inet input block above).
    /// Direct per-interface inet output filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_out_v4_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    // #6236 PR-2B: `iface_filter_out_v4_needs_tx_eval` (the former per-interface FxHashSet) and
    // `has_output_tx_selection_v4` (aggregate) are deleted. The
    // `interface_output_filter_needs_tx_eval` accessor reads
    // `Filter::needs_tx_eval()` off `iface_filter_out_v4_fast`, and the global TX
    // gate reads the `has_output_needs_tx_eval_v4` aggregate (PR-2A) which
    // subsumes the deleted `affects_tx_selection`-only aggregate.
    /// #6236 PR-2A: whether any inet output filter needs a TX-path walk
    /// (`Filter::needs_tx_eval` — CoS/DSCP tx-selection, counter, log, terminal
    /// action, or three-color policer). Recomputed from the FINAL output fast map
    /// so a duplicate-ifindex last-wins overwrite cannot leave a stale-true
    /// aggregate. It is the SOLE output clause of the global TX gate: it subsumes
    /// both the old `affects_tx_selection`-only aggregate and the old
    /// per-interface needs-tx-eval set non-emptiness (both deleted in PR-2B).
    pub(crate) has_output_needs_tx_eval_v4: bool,
    /// Direct per-interface inet6 output filter reference for packet hot-path evaluation.
    pub(crate) iface_filter_out_v6_fast: rustc_hash::FxHashMap<i32, Arc<Filter>>,
    // #6236 PR-2B: `iface_filter_out_v6_needs_tx_eval` and
    // `has_output_tx_selection_v6` are deleted (see the inet output block above).
    /// #6236 PR-2A: inet6 mirror of `has_output_needs_tx_eval_v4`.
    pub(crate) has_output_needs_tx_eval_v6: bool,
    /// Direct lo0 inet filter reference for packet hot-path evaluation.
    pub(crate) lo0_filter_v4_fast: Option<Arc<Filter>>,
    /// Direct lo0 inet6 filter reference for packet hot-path evaluation.
    pub(crate) lo0_filter_v6_fast: Option<Arc<Filter>>,
}

impl FilterState {
    pub(crate) fn three_color_policer_statuses(
        &self,
    ) -> Vec<crate::protocol::ThreeColorPolicerStatus> {
        let mut statuses = self
            .three_color_policers
            .iter()
            .map(|policer| policer.status())
            .collect::<Vec<_>>();
        statuses.sort_by_key(|status| status.id);
        statuses
    }
}

/// Result of filter evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FilterResult {
    pub(crate) action: FilterAction,
    pub(crate) dscp_rewrite: Option<u8>,
    // #5444: `None` == no policer matched (semantically identical to the
    // historical empty `""`). `Option<Arc<str>>` mirrors `forwarding_class`
    // (#5151): the accumulator init and the non-routing reset are zero-alloc
    // (`None`), and a matched `then policer` term propagates it with an Arc
    // refcount bump instead of a String heap allocation on the packet path.
    pub(crate) policer_name: Option<Arc<str>>,
    // #5857: OR of every matched term's three-color-policer drop decision. Only
    // the METERED walk (`evaluate_lo0_filter_counted` with `now_ns = Some`, the
    // lo0 host-bound path) sets this; the shared action-eval walk leaves it false
    // (its policer is metered in the tx-selection leg, not here). A late permit
    // cannot erase an earlier policer drop because this is OR-accumulated across
    // the whole `next term` chain. The lo0 caller downgrades an `Accept` verdict
    // to a silent `Discard` when this is set — enforcing the configured
    // control-plane rate limit that was previously inert on host-bound traffic.
    pub(crate) policer_drop: bool,
    // #5444: `Option<Arc<str>>` for the same reason as `policer_name` above —
    // refcount-bump propagation, zero-alloc `None` default/reset.
    pub(crate) routing_instance: Option<Arc<str>>,
    // #5151: `None` == no forwarding-class matched (semantically identical to
    // the historical empty `""`). Mirrors TxSelection/CachedTxSelection which
    // already use `Option<Arc<str>>` — the accumulator init no longer allocates
    // an empty Arc header/data block on every full filter eval (packet path).
    pub(crate) forwarding_class: Option<Arc<str>>,
    pub(crate) log: bool,
    pub(crate) log_match: Option<FilterLogMatch>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilterRoutingInstanceResult<'a> {
    pub(crate) routing_instance: &'a str,
    pub(crate) log: bool,
    pub(crate) action: FilterAction,
    pub(crate) filter_id: u32,
    pub(crate) term_id: u32,
    // #2619: the latest-matched logging term seen while scanning for the
    // routing-instance term — INCLUDING fall-through `then { log; next term; }`
    // terms ahead of the routing-instance term, whose log metadata the PBR path
    // previously dropped. `None` when no matched term carried `then log`. The
    // action is normalized to the verdict the packet receives on the PBR path
    // (#2616): the routing-instance term itself terminates with its own action,
    // so a fall-through log ahead of it logs that terminal action. The legacy
    // `log`/`action`/`filter_id`/`term_id` fields above describe ONLY the
    // routing-instance term; emitters now prefer `log_match`.
    pub(crate) log_match: Option<FilterLogMatch>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FilterLogMatch {
    pub(crate) filter_id: u32,
    pub(crate) term_id: u32,
    pub(crate) action: FilterAction,
}

#[derive(Clone, Debug)]
pub(crate) struct TxSelectionFilterResult<'a> {
    pub(crate) action: FilterAction,
    pub(crate) forwarding_class: Option<&'a str>,
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) policer_drop: bool,
    pub(crate) log_match: Option<FilterLogMatch>,
}

#[derive(Clone, Debug)]
pub(crate) struct CachedTxSelectionFilterResult {
    pub(crate) action: FilterAction,
    pub(crate) forwarding_class: Option<Arc<str>>,
    pub(crate) dscp_rewrite: Option<u8>,
    // #2573: record ALL matched `then count` term counters, not just the last.
    pub(crate) counters: CachedFilterCounters,
    pub(crate) three_color_policers: CachedThreeColorPolicers,
    pub(crate) log_match: Option<FilterLogMatch>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ThreeColorPolicerAction {
    pub(crate) dscp_rewrite: Option<u8>,
    pub(crate) drop: bool,
}

impl Default for FilterResult {
    fn default() -> Self {
        Self {
            action: FilterAction::Accept,
            dscp_rewrite: None,
            // #5444: zero-alloc default — no String buffer allocated on the
            // warmed packet path. A matching `then policer` term sets `Some(..)`
            // in `merge_matched_modifiers` (Arc refcount bump).
            policer_name: None,
            // #5857: no policer drop by default; set only by the metered lo0 walk.
            policer_drop: false,
            // #5444: zero-alloc default, as `policer_name` above.
            routing_instance: None,
            // #5151: zero-alloc default — no Arc header/data block allocated on
            // the warmed packet path. A matching `then forwarding-class` term
            // sets `Some(..)` in `merge_matched_modifiers`.
            forwarding_class: None,
            log: false,
            log_match: None,
        }
    }
}

impl Default for TxSelectionFilterResult<'_> {
    fn default() -> Self {
        Self {
            action: FilterAction::Accept,
            forwarding_class: None,
            dscp_rewrite: None,
            policer_drop: false,
            log_match: None,
        }
    }
}

impl Default for CachedTxSelectionFilterResult {
    fn default() -> Self {
        Self {
            action: FilterAction::Accept,
            forwarding_class: None,
            dscp_rewrite: None,
            counters: CachedFilterCounters::default(),
            three_color_policers: CachedThreeColorPolicers::default(),
            log_match: None,
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

// #7212: the side-effect-free static verdict (`NonRoutingCountPolicy::Never`).
// Its own file rather than another block in the 9k-line `tests.rs`, per the
// modularity rule on test files.
#[cfg(test)]
#[path = "static_verdict_7212_tests.rs"]
mod static_verdict_7212_tests;
