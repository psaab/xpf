//! Snapshot integrity errors surfaced by the policy-snapshot parser
//! (#1606). Relocated verbatim out of `policy.rs` to keep that module
//! under the modularity-discipline LOC threshold. Loaded as a sibling
//! submodule via `#[path = "policy_snapshot_error.rs"]` from `policy.rs`,
//! mirroring how `policy_tests.rs` is attached. Re-exported as
//! `crate::policy::SnapshotIntegrityError` so all crate-wide call sites
//! keep their existing path. Pure code-motion: no behavior change.

/// #1606: snapshot integrity errors from the policy parser.
#[derive(Debug, Clone)]
pub(crate) enum SnapshotIntegrityError {
    AddressBookIdZero,
    DuplicateAddressBookId(u32),
    /// #3713: two policy rules resolved to the SAME stable rule identity
    /// (`stable_policy_rule_id`) — either an identical explicit wire `rule_id`
    /// (corrupt / mixed-version producer) or an identical synthesized
    /// `from->to/name` key (a duplicate policy name in one zone pair). The
    /// rule_id is the get-or-insert key for `PolicyCounterStore::rule_hit_counter`,
    /// so two rules with the same id SHARE one `Arc<PolicyRuleCounter>`:
    /// `counter_snapshots()` then emits two rows with the same id and the same
    /// collapsed totals (hit-count mis-attribution), and it is also the RT_FLOW /
    /// session / display join key, so an incident-response surface joins the
    /// wrong rule. Rejecting the WHOLE snapshot (the preflight keeps the previous
    /// good state; a fresh boot keeps the default-deny `PolicyState`) mirrors
    /// `DuplicateAddressBookId` and the #2124/#3261/#3367/#3711 fail-closed
    /// family. A normal Go snapshot assigns each policy a distinct positional
    /// identity, so this guards a corrupt / hand-built / mixed-version HA
    /// peer-sync snapshot.
    DuplicateRuleId { rule_id: String },
    /// #3713: two policy rules carry the SAME positional `policy_id`. The Go
    /// builder assigns `policy_set_id * MAX_RULES_PER_POLICY + rule_index`
    /// (`walkPolicyRuleSlots`), which is unique per rule by construction, so a
    /// duplicate is a corrupt / mixed-version snapshot. `policy_id` is the
    /// RT_FLOW / `SESSION_CLOSE` / display join key AND the value stored in
    /// `rule_id_to_policy_id` (last-writer-wins), so a duplicate lets an existing
    /// session re-resolve (#3395 live-row refresh) to the WRONG policy — wrong
    /// attribution during incident response. Two values are excluded from the
    /// check (M01): the reserved implicit-default sentinel
    /// (`DEFAULT_POLICY_SENTINEL_ID`, `u32::MAX`), never carried by a configured
    /// rule; and `0`, the `omitempty` wire zero-value that is both the valid
    /// FIRST-policy id AND the "unspecified" value a pre-policy_id producer or
    /// older HA peer leaves on every rule — rejecting duplicate-0 would
    /// fail-close a legitimate older-peer / hand-built (all-zero) snapshot.
    DuplicatePolicyId { policy_id: u32 },
    UnknownAddressBookId { rule_id: String, book_id: u32 },
    /// #2124: a policy rule has at least one `application_terms` entry that
    /// failed to parse (unrepresentable protocol or malformed port). Dropping a
    /// term silently is a security fail-open: an all-dropped rule collapses to
    /// match-any (a permit over-matching), and a partially-dropped rule narrows
    /// the match (for a deny rule, narrowing lets blocked traffic fall through).
    /// The Go capability gate emits a reserved `__unsupported__` sentinel term
    /// for the failed-expansion case, and any corrupt snapshot with an
    /// unparseable term lands here too. Rejecting the whole snapshot (the
    /// preflight keeps the previous good state) is action-agnostic: it never
    /// turns a deny into a pass nor a permit into match-any.
    UnrepresentableApplicationProtocol { rule_id: String },
    /// #3712: a policy rule's application term carried a semantically-invalid
    /// ICMP field combination that the pre-fix compiled matcher silently turned
    /// into a WRONG-behaving term:
    ///
    ///   - `icmp-code` set with NO `icmp-type` (H04): `from_matches` steers a
    ///     term into `icmp_constraints` ONLY when `icmp_type.is_some()`, so a
    ///     code-without-type term fell through to a `range_terms` entry with
    ///     EMPTY port ranges — a protocol-only MATCH-ALL for that ICMP protocol.
    ///     The `icmp_code` was silently ignored, so an intended narrow rule
    ///     (`type any, code 3`) widened to match every ICMP message. For a
    ///     permit under default-deny that is a fail-OPEN (permits more than
    ///     authored).
    ///   - `icmp-type` / `icmp-code` set on a NON-ICMP protocol (H05):
    ///     `from_matches` pushes the term into `icmp_constraints` under the
    ///     non-ICMP protocol (e.g. TCP) because `icmp_type.is_some()`, and the
    ///     exact-dst-port / range classification is skipped, so any real
    ///     destination-port constraint is LOST. `matches` then skips the
    ///     `icmp_constraints` arm for a non-ICMP packet (`packet_icmp` is None),
    ///     so the term NEVER matches — a `deny tcp/80 icmp-type 8` never applies
    ///     and default-permit admits the traffic (a security fail-OPEN).
    ///
    /// The Go STRICT commit gate (`validateApplicationSpecsStrict`, #3348) hard-
    /// rejects BOTH combos at commit, but the tolerant load / peer-sync path
    /// (`lenientApplicationSpecs`) downgrades them to warnings, so a corrupt /
    /// hand-built / older-peer-synced snapshot can still carry them to this
    /// helper — the only enforcement plane in the retired-eBPF world. Rejecting
    /// the WHOLE snapshot (the preflight keeps the previous good state; a fresh
    /// boot keeps the default-deny `PolicyState`) is action-agnostic, consistent
    /// with the #2124/#3261/#3367/#3711 fail-closed family. `application` is the
    /// term's name; `reason` describes which invalid combo was found.
    InvalidApplicationIcmpFields {
        rule_id: String,
        application: String,
        reason: &'static str,
    },
    /// #3261: a policy rule carries the reserved `__unsupported_address__`
    /// sentinel in its source/destination address fields. The Go capability
    /// gate emits it when a policy names an address it cannot represent — an
    /// undefined address-book name, or a defined book whose value is a
    /// non-literal (Junos dns-name / wildcard-address / range-address). This is
    /// the ADDRESS analog of `UnrepresentableApplicationProtocol`: without the
    /// reject, the raw address strings reach the matcher, which SILENTLY drops
    /// an unparseable literal (the non-reporting matcher parser) or empties a
    /// non-literal book, collapsing the side to `MatchNone`. A
    /// `deny <unrepresentable-address>` rule would then match nothing and fall
    /// through to a later permit / default-permit — a deny fail-OPEN. Rejecting
    /// the whole snapshot (the preflight keeps the previous good state; a fresh
    /// boot keeps the default-deny `PolicyState`) is action-agnostic.
    UnrepresentableAddress { rule_id: String },
    /// #3367: a policy rule's LEGACY (`source_addresses` / `destination_addresses`)
    /// address field carried a token that is non-empty, not the bare `any`, not a
    /// family-scoped wildcard (`any-ipv4` / `any-ipv6`), and does NOT parse as an
    /// IP/CIDR literal. The pre-fix `parse_address` `Err(_)` arm silently DROPPED
    /// such a token (pushed nothing, returned). For a fully-malformed token list on
    /// the common "empty -> MatchAny" legacy path (no family-scoped wildcard
    /// present) the side then collapsed to an UNCONSTRAINED MatchAny — broadening a
    /// `deny` rule to match every source/destination (fail-OPEN). The v3-shaped
    /// literal path is fixed by the sibling `UnrepresentableV3Address` reject
    /// (#3711); this is the analogous backstop for the legacy field, which
    /// carries raw literals with no sentinel. A normal Go snapshot only ever
    /// emits parseable literals / `any` / family wildcards, so this guards
    /// against a corrupt / hand-built / version-drifted snapshot. Rejecting the
    /// WHOLE snapshot (the preflight keeps the previous good state) is
    /// action-agnostic.
    UnrepresentableLegacyAddress { rule_id: String, address: String },
    /// #3711: a policy rule's V3-shaped (`source_literals` /
    /// `destination_literals`) address field carried a token that is non-empty,
    /// not `any` / `any4` / `any6` / `any-ipv4` / `any-ipv6`, not the
    /// `__unsupported_address__` sentinel, and does NOT parse as an IP/CIDR
    /// literal. The pre-fix `parse_v3_literal_set` used a non-reporting
    /// family-agnostic parser, whose `Err(_)` arm silently DROPPED such a
    /// token. Because a v3-shaped side uses the `from_v3_literals` factory
    /// (empty -> MatchNone, NOT MatchAny), an all-dropped side collapsed to
    /// MatchNone: a `deny <malformed-literal>` rule then matched nothing and
    /// fell through to a later permit / default-permit — a deny fail-OPEN. This
    /// is the v3 sibling of `UnrepresentableLegacyAddress` (#3367): the sentinel
    /// preflight (`UnrepresentableAddress`, #3261) only catches the exact
    /// `__unsupported_address__` token the Go gate emits, NOT an arbitrary
    /// malformed literal on a corrupt / hand-built / mixed-version HA peer-sync
    /// snapshot. Rejecting the WHOLE snapshot (the preflight keeps the previous
    /// good state) is action-agnostic.
    UnrepresentableV3Address { rule_id: String, address: String },
    /// #3711 (M02): an address-book row carried a token in its `prefixes_v4` /
    /// `prefixes_v6` array that is not a parseable IP/CIDR literal OF THE
    /// DECLARED FAMILY. The pre-fix book builder parsed BOTH family arrays with
    /// one family-agnostic non-reporting parser, so (a) a malformed token
    /// was silently dropped (an all-dropped family collapsed to MatchNone —
    /// same deny fall-through fail-OPEN as the rule-literal path), and (b) a
    /// wrong-family token (an IPv6 CIDR placed in `prefixes_v4` by a corrupt /
    /// mixed-version producer) was accepted into the opposite family's set,
    /// contradicting the wire contract. The reporting builder now rejects the
    /// whole snapshot naming the book id/name, the offending token, and the
    /// declared family. The Go side only ever emits family-separated parseable
    /// CIDRs, so this guards against a corrupt / hand-built / version-drifted
    /// snapshot. `family` is the STATIC declared array (`"v4"` / `"v6"`), not
    /// the token's actual family.
    UnrepresentableAddressBookPrefix {
        book_id: u32,
        book_name: String,
        family: &'static str,
        address: String,
    },
    // #2212/#3888: NAT64 unparseable rules no longer produce an integrity
    // error. `Nat64State::from_snapshots` (nat64.rs) is infallible: it SKIPS
    // the offending NAT64 rule (logging a loud warning) and publishes the rest,
    // scoping a bad NAT64 rule to a NAT64-only degradation instead of aborting
    // the whole forwarding rebuild. The former `Nat64UnparseableRule` variant
    // was removed with that change. NPTv6 (below) intentionally stays
    // fail-CLOSED — its #2241 overlap rejection is order-dependent.
    /// #2240: an NPTv6 (RFC 6296) rule snapshot carried an unparseable or
    /// unsupported prefix — a match/internal prefix that is empty / malformed /
    /// not a /48 or /64, or an internal/external pair whose prefix lengths do
    /// not match. Silently `continue`-ing past the bad rule (the pre-fix parser)
    /// is a fail-OPEN regression: the Go dataplane compiler then calls
    /// `DeleteStaleNPTv6(written)` over only the VALID subset, so editing one
    /// previously-good rule into an invalid one TEARS DOWN the working
    /// translation entry with no replacement installed — traffic that
    /// previously translated silently stops, and HA peers converge on the same
    /// partial state with no hard failure. The Go commit-time validation
    /// (`pkg/config/compiler_nat.go`, #2240) is the primary gate; this is the
    /// helper-boundary backstop, consistent with the #2124/#2142/#2173/#2212
    /// fail-closed family. Rejecting the whole snapshot keeps the previous live
    /// NPTv6 state rather than installing a silently narrower one.
    Nptv6UnparseableRule { rule_name: String, field: String },
    /// #2241: two NPTv6 rules have overlapping prefixes in the same direction
    /// (e.g. a /48 and a nested /64). The dataplane resolves a match by FIRST
    /// hit in insertion order with no longest-prefix-match, so a broad prefix
    /// configured before a more-specific one shadows it and reordering the same
    /// rules changes the translation identity. Rejecting the snapshot keeps
    /// translation deterministic. The Go commit-time gate (#2241) is primary;
    /// this is the helper-boundary backstop.
    Nptv6OverlappingPrefix {
        first_rule: String,
        second_rule: String,
        direction: &'static str,
    },
    /// #2505: a firewall-filter term carried a NON-EMPTY `from protocol` list
    /// with at least one token that `ip_proto::proto_number` cannot resolve.
    /// The pre-fix compiler used a stale local `parse_protocol` (recognizing
    /// only tcp/udp/icmp/icmpv6/gre/ospf/ipip + bare numeric, no
    /// trim/lowercase) and `filter_map`-dropped anything else. A named
    /// protocol the Go commit gate accepts (esp/ah/sctp/vrrp/igmp/pim/egp +
    /// the junos-* aliases) — or a mixed-case / whitespace token the Go gate
    /// normalizes — was silently dropped. When ALL tokens drop, the term's
    /// protocol list collapses to empty, `protocol_match_enabled` becomes
    /// false, and the term matches EVERY protocol: a `from protocol esp; then
    /// discard` term that should drop only ESP instead discards ALL traffic
    /// (fail-WIDE). Rejecting the whole snapshot (the preflight keeps the
    /// previous good state) is the fail-closed backstop; the Go gate
    /// (`filterProtocolResolvable`, #2175/#2505) is the primary defense, so a
    /// gate-passing config never reaches this arm in normal operation — it
    /// guards against version/snapshot drift. An EMPTY input protocol list is
    /// the legitimate "no protocol constraint" case and is NOT an error.
    ///
    /// `family` (inet / inet6) is carried alongside the filter name because
    /// filter names can be REUSED across families — without it the fail-closed
    /// diagnostic could not tell the operator WHICH `family <f> filter <name>`
    /// failed.
    UnrepresentableFilterProtocol {
        family: String,
        filter: String,
        term: String,
        token: String,
    },
    /// #3367: a firewall-filter term carried the `tcp_flags_unparseable` wire
    /// marker — the Go control plane could not parse the term's tcp-flags
    /// expression (disjunction, negated groups, unknown flags) into
    /// required/forbidden masks. The pre-fix Go builder logged the error and left
    /// both masks nil, and the matcher (`engine/matching.rs`) treats absent masks
    /// as "no tcp-flags constraint" — silently WIDENING the term to match every
    /// TCP segment. For a `then discard`/`reject` term that should drop only a
    /// specific flag combination (e.g. SYN floods) that is a fail-WIDE security
    /// bug. The Go commit gate (`compileFirewall` /
    /// `config::ParseTCPFlagsExpression`) is the primary defense — a committed
    /// config never sets the marker — so this is the helper-boundary backstop for
    /// a corrupt / hand-built / version-drifted snapshot, consistent with the
    /// #2505 `UnrepresentableFilterProtocol` fail-closed pattern. Rejecting the
    /// whole snapshot (the reconcile preflight keeps the previous good filter
    /// state) is action-agnostic. `family` (inet / inet6) is carried because
    /// filter names can be reused across families.
    UnrepresentableFilterTCPFlags {
        family: String,
        filter: String,
        term: String,
    },
    /// #3406: a firewall-filter term carried the `icmp_type_unrepresentable` /
    /// `icmp_code_unrepresentable` wire marker — the Go control plane could not
    /// resolve a `from icmp-type` / `from icmp-code` token to a byte in 0..255 (a
    /// symbolic name with no mapping, or a numeric value out of range). The pre-fix
    /// Go builder dropped the unresolved token and emitted only the resolved bytes;
    /// when EVERY token was unresolvable the `icmp_types` / `icmp_codes` vector was
    /// empty, which the matcher reads as "no ICMP constraint" — silently WIDENING
    /// the term to match every ICMP(v6) packet (fail-OPEN for a `then
    /// discard`/`reject` term). The Go commit gate (`validateFilterMatchValuesStrict`)
    /// is the primary defense — a committed config never sets the marker — so this
    /// is the helper-boundary backstop for a corrupt / hand-built / version-drifted
    /// snapshot, consistent with the #2505/#3367 fail-closed family. Rejecting the
    /// whole snapshot (the reconcile preflight keeps the previous good filter state)
    /// is action-agnostic. `dimension` is "icmp-type" or "icmp-code". `family`
    /// (inet / inet6) is carried because filter names can be reused across families.
    UnrepresentableFilterICMP {
        family: String,
        filter: String,
        term: String,
        dimension: &'static str,
    },
    /// #3406: a firewall-filter term carried the `dscp_match_unrepresentable` wire
    /// marker — the Go control plane could not resolve a `from dscp` / `from
    /// traffic-class` MATCH token to a known code-point name or an integer 0..63.
    /// The pre-fix Go builder dropped the bad token from `dscp_values`; when EVERY
    /// token was unresolvable the vector was empty, which the matcher reads as "no
    /// DSCP constraint" — silently WIDENING the term to match all DSCPs (fail-OPEN,
    /// the documented #3309 gap). The Go commit gate (`validateFilterDSCPStrict`) is
    /// the primary defense; this is the helper-boundary backstop, consistent with
    /// the #2505/#3367 fail-closed family. An unrepresentable `then dscp` REWRITE is
    /// CoS-only (no match/action widening) and is surfaced with a Go builder warning
    /// rather than this snapshot reject. `family` (inet / inet6) is carried because
    /// filter names can be reused across families.
    UnrepresentableFilterDSCP {
        family: String,
        filter: String,
        term: String,
    },
    /// #6459: a firewall-filter term carried the `ports_unrepresentable` wire
    /// marker — the Go control plane could not resolve a
    /// `from {source,destination}-port[-except]` token to a number (an unknown
    /// service name, a malformed range, or a non-canonical token such as
    /// "+80"). The pre-fix Rust compiler dropped the token PER-TOKEN
    /// (`filter_map(parse_port_spec)`), so a PARTIALLY-unresolvable list built
    /// a matcher over only the surviving subset: a `then discard`/`reject`
    /// term silently enforced a NARROWER port set than the operator wrote, and
    /// the traffic meant for the dropped ports fell through to the implicit
    /// accept (fail-OPEN). (An ALL-unresolvable list already failed closed at
    /// match-time via `constrained && PortMatcher::Any`, #2400/#3205.) The Go
    /// commit gate (`validateFilterMatchValuesStrict`, #3205) is the primary
    /// defense — a committed config never sets the marker — so this is the
    /// helper-boundary backstop for a lenient / peer-synced / hand-built /
    /// version-drifted snapshot, consistent with the #2505/#3367/#3406
    /// fail-closed family. Rejecting the whole snapshot (the reconcile
    /// preflight keeps the previous good filter state) is action-agnostic.
    /// `family` (inet / inet6) is carried because filter names can be reused
    /// across families.
    UnrepresentableFilterPorts {
        family: String,
        filter: String,
        term: String,
    },
    /// #6463: a firewall-filter term carried the `address_unrepresentable`
    /// wire marker — the Go control plane classified a literal
    /// `from source-address` / `destination-address` token as not a parseable
    /// IP/CIDR (`classifyFilterAddrFamily` rejects it). The pre-fix
    /// `parse_address` dropped the token PER-TOKEN (its `Err(_)` arm pushed
    /// nothing), so a PARTIALLY-malformed list matched only the surviving
    /// prefixes: a `then discard`/`reject` term silently enforced a NARROWER
    /// address set than the operator wrote, and a host in the dropped range
    /// was accepted by fall-through (fail-OPEN). (An ALL-malformed direction
    /// already failed closed at match-time via `constrained && empty`, #2400.)
    /// The Go commit gate (`validateFilterAddressLiteralsStrict`, #3433) is the
    /// primary defense — a committed config never sets the marker — so this is
    /// the helper-boundary backstop for a lenient / peer-synced / hand-built /
    /// version-drifted snapshot, consistent with the #2505/#3367/#3406
    /// fail-closed family. Rejecting the whole snapshot (the reconcile
    /// preflight keeps the previous good filter state) is action-agnostic.
    /// `family` (inet / inet6) is carried because filter names can be reused
    /// across families.
    UnrepresentableFilterAddress {
        family: String,
        filter: String,
        term: String,
    },
    /// #9875: a firewall-filter term carried the `from_unrepresentable` wire
    /// marker — the term's `from` block carried a match leaf the dataplane
    /// does NOT enforce (recorded on term.UnknownFrom, #3307) or a
    /// value-bearing leaf written with NO operand (recorded on
    /// term.ValuelessFrom, #8480). The pre-fix Go builder emitted only the
    /// surviving match set — byte-identical to a term authored without the
    /// leaf — so an accept term over-permitted and a discard/reject term
    /// over-dropped with no signal past the boot warning. The Go commit gates
    /// (`validateFilterFromMatchStrict`, #3307;
    /// `validateFirewallFilterValuelessFromStrict`, #8480) are the primary
    /// defense — a committed config never sets the marker — so this is the
    /// helper-boundary backstop for a lenient / peer-synced / hand-built /
    /// version-drifted snapshot, consistent with the #2505/#3367/#3406
    /// fail-closed family. Rejecting the whole snapshot (the reconcile
    /// preflight keeps the previous good filter state) is action-agnostic:
    /// poisoning a discard/reject term to match-nothing would let its traffic
    /// fall through to the implicit accept (fail-OPEN). `family` (inet /
    /// inet6) is carried because filter names can be reused across families.
    UnrepresentableFilterFrom {
        family: String,
        filter: String,
        term: String,
    },
    /// #3406: a firewall-filter term's `flex_match` carried a byte `length` outside
    /// the representable 1..=4 range (the `value` / `mask` wire fields are u32). The
    /// pre-fix Go builder CAPPED an oversized width to 4 and still emitted the term,
    /// so only the truncated 4-byte window was compared and the match BROADENED
    /// (fail-OPEN). The Go commit gate (`validateFilterFlexMatchStrict`) bounds
    /// bit-length to 1..32 → ceil(bits/8) ≤ 4, so a committed config never produces
    /// an out-of-range length; this is the helper-boundary backstop for a corrupt /
    /// hand-built / version-drifted snapshot, consistent with the #2505/#3367
    /// fail-closed family. A length of 0 with a present `flex_match` is likewise
    /// rejected (the Go builder defaults an unset bit-length to a 4-byte window, so
    /// 0 only arrives via drift). Rejecting the whole snapshot keeps the previous
    /// good filter state. `family` (inet / inet6) is carried because filter names
    /// can be reused across families.
    UnrepresentableFilterFlexMatch {
        family: String,
        filter: String,
        term: String,
        length: u8,
    },
    /// #3715: a firewall-filter term carried a raw DSCP wire value outside the
    /// semantic 0..=63 range (DSCP is a 6-bit field). `dimension` is "match" for a
    /// `snap.dscp_values` entry >= 64 and "rewrite" for a `snap.dscp_rewrite` byte
    /// >= 64; `value` is the offending byte. Unlike the `dscp_match_unrepresentable`
    /// marker (#3406) — which the Go control plane sets after it has already dropped
    /// an unresolvable code-point NAME — a raw numeric value >= 64 is directly
    /// visible on the wire (`dscp_values` is Vec<u8>, `dscp_rewrite` is Option<u8>),
    /// so the range check happens HERE without a Go-side marker. The Go commit gate
    /// (`validateFilterDSCPStrict`, #3309) bounds both tokens to a code-point name or
    /// 0..63 and the Go builder (`filters.go`) only ever emits 0..63, so a committed
    /// config never produces an out-of-range value; this is the helper-boundary
    /// backstop for a corrupt / hand-built / version-drifted / mixed-version
    /// snapshot, consistent with the #2505/#3367/#3406 fail-closed family.
    ///
    /// Pre-fix the MATCH value was silently dropped by `build_u6_match_bitmap` (its
    /// `value < 64` guard skipped it) while `dscp_match_enabled` stayed true — a term
    /// that appears to carry two selectors then matched only the in-range subset
    /// (fail-WIDE / silently-wrong). The REWRITE value was MASKED with `& 0x3f`,
    /// turning e.g. 110 into 46 (EF) — actively marking traffic with a code point the
    /// operator never authored (untrusted traffic could land in EF). Rejecting the
    /// whole snapshot (the reconcile preflight keeps the previous good filter state)
    /// never mis-applies. `family` (inet / inet6) is carried because filter names can
    /// be reused across families.
    FilterDSCPOutOfRange {
        family: String,
        filter: String,
        term: String,
        dimension: &'static str,
        value: u8,
    },
    /// #3723: a firewall-filter term combined a resolved `protocol` (or the inet6
    /// `next-header`) with an L4 predicate the matcher can NEVER satisfy for that
    /// protocol — a source/destination-port with a non-port-bearing protocol
    /// (only TCP/UDP carry extracted ports, ip_proto.rs has_l4_ports), a tcp-flags
    /// match with a non-TCP protocol, or an icmp-type/icmp-code match with a
    /// non-ICMP(v6) protocol. The matcher (engine/matching.rs) keys ports on the
    /// extracted L4 port (0 for a non-port protocol), gates tcp-flags on
    /// protocol==TCP, and gates icmp-type/code on ICMP/ICMPv6, so such a term is a
    /// NEVER-MATCH. Because a filter falls through to the implicit ACCEPT on
    /// no-match (the #3427 no-catchall class), a `then discard`/`reject` term over
    /// such a pair is silently dead and the traffic is admitted — a fail-OPEN.
    /// The Go commit gate (`validateFilterCrossFieldStrict`, #3723) is the primary
    /// defense — a freshly committed config can never carry such a term — so this
    /// is the helper-boundary backstop for a corrupt / hand-built / version-drifted
    /// or leniently-loaded snapshot, consistent with the #2505/#3367/#3406
    /// fail-closed family. Rejecting the whole snapshot (the reconcile preflight
    /// keeps the previous good filter state) is action-agnostic. `predicate` names
    /// the offending L4 dimension ("port" / "tcp-flags" / "icmp-type/code") and
    /// `protocol` is the incompatible IANA number. `family` (inet / inet6) is
    /// carried because filter names can be reused across families.
    UnsatisfiableFilterCrossField {
        family: String,
        filter: String,
        term: String,
        predicate: &'static str,
        protocol: u8,
    },
    /// #3296: an interface (or lo0) snapshot named a NON-EMPTY firewall filter
    /// (`filter_input_v4/v6` / `filter_output_v4/v6`, or the lo0 host-bound
    /// filter) that is not present in the compiled filter table. The pre-fix
    /// compiler left the per-interface fast-path map (and, for output hooks,
    /// the `needs_tx_eval` set) with NO entry for the missing key, so the hot
    /// path returned the default `FilterResult` — Accept. The security hook
    /// was silently disarmed, indistinguishable from "no filter configured": a
    /// fail-OPEN on a typo'd firewall reference (e.g. `filter input WAN-BLOCK`
    /// where the defined filter is `WAN_BLOCK`). Rejecting the whole snapshot
    /// (the preflight keeps the previous good filter state on a warm reconcile)
    /// is the fail-closed backstop, consistent with the
    /// #2124/#2391/#2505 fail-closed family. The Go STRICT commit gate
    /// (`validateFirewallFilterReferencesStrict`, #3296) is the primary
    /// defense — a freshly committed config can never carry a dangling
    /// reference — so a gate-passing config never reaches this arm in normal
    /// operation; it guards against version/snapshot drift on the lenient /
    /// peer-sync path. An EMPTY reference (no filter on the hook) is the
    /// legitimate "unfiltered" case and is NOT an error.
    ///
    /// `family` (inet / inet6) is carried alongside the filter name because
    /// filter names can be REUSED across families.
    MissingFilterRef {
        interface: String,
        family: String,
        direction: String,
        filter: String,
    },
    /// #6540: a firewall-filter term's `then policer <name>` named a policer
    /// that the snapshot defines NEITHER as `firewall policer <name>` NOR as
    /// `firewall three-color-policer <name>`. The pre-fix compiler resolved the
    /// reference with a bare `.get(...)` yielding `None`, and
    /// `apply_term_three_color_policer` then no-opped the meter — so a
    /// configured rate limit (a DoS-mitigation policer, say) forwarded
    /// UNPOLICED with no `Err`, no warning and no counter.
    ///
    /// Policer was the odd one out of three sibling reference mechanisms:
    /// filters raise `MissingFilterRef` (six `return Err` sites in
    /// `filter/compiler.rs`) and screen reports `ScreenMissingProfileRef`, but
    /// `grep MissingPolicerRef` over this tree returned zero. It over-permits
    /// BANDWIDTH rather than admitting traffic a policy would deny, which is
    /// why it is the Medium of that family rather than a High.
    ///
    /// The Go STRICT commit gate (#2217 Finding A,
    /// `compiler_validate_strict_filter.go`) is the primary defense and asks
    /// the SAME question — defined under `firewall policer` or `firewall
    /// three-color-policer` — so a freshly committed config can never carry a
    /// dangling reference. This arm guards the lenient `Store.Load` /
    /// `Store.SyncApply` path (`opts.lenientFirewallRefs`, #1960 no-brick),
    /// where that gate is downgraded to a warning and nothing else was left.
    ///
    /// The predicate is DEFINEDNESS, deliberately NOT presence in the compiled
    /// `three_color_policer_by_name` map. Those two differ, and the difference
    /// matters: `lower_single_rate_policer_runtimes` (#4514) SKIPS a degenerate
    /// zero-rate METER-ONLY policer because it has no action to enforce, so
    /// such a policer is defined, absent from the map, and must NOT be
    /// rejected. Keying this on the map would refuse a config that boots today.
    /// An EMPTY reference (no policer on the term) is the legitimate
    /// "unpoliced" case and is NOT an error.
    MissingPolicerRef {
        family: String,
        filter: String,
        term: String,
        policer: String,
    },
    /// #2391: an interface snapshot named a NON-EMPTY security zone that is not
    /// present in the zone table (`zone_name_to_id`). The pre-fix code resolved
    /// the missing name to `zone_id == 0` (`unwrap_or(0)`), silently collapsing
    /// the interface to the canonical "unknown" zone. With zone 0 the interface
    /// matches no zone-pair policy and its traffic falls through to the default
    /// action — a silent fail-open under a permit default (or a blackhole under a
    /// deny default). This happens when a zone id overflows the u8 event-stream
    /// wire field and the forwarding builder drops it (`populate_zones`), or on a
    /// hostile/version-drifted snapshot where an interface references a zone the
    /// snapshot never defines. The Go commit-time cap (`validateZoneCountStrict`,
    /// #2391) is the PRIMARY gate that prevents the overflow ever reaching the
    /// wire; this is the helper-boundary backstop, consistent with the
    /// #2124/#2142/#2173/#2212/#2505 fail-closed family. An interface with NO
    /// zone (empty string) is the legitimate "unzoned" case and is NOT an error.
    InterfaceUnknownZone { interface: String, zone: String },
    /// #2410: an interface snapshot's `vlan_id` is outside the 0..=65535 range
    /// representable on the 802.1Q wire (and in the `EgressInterface.vlan_id` /
    /// `ingress_logical_ifindex` key u16). The pre-fix code narrowed it with an
    /// unchecked `iface.vlan_id.max(0) as u16`, so a value > 65535 WRAPPED to a
    /// different VLAN id — silently building a DIFFERENT L2 broadcast domain than
    /// the operator configured (a value of 65537 becomes VLAN 1, a value of
    /// 65536 becomes VLAN 0/untagged). That is a security-relevant
    /// misconfiguration: the interface's ingress demux and egress tag would key
    /// off the wrong VLAN. The Go commit-time validation is the primary gate;
    /// this is the helper-boundary backstop, consistent with the
    /// #2173/#2212/#2240/#2391 fail-closed family. Rejecting the whole snapshot
    /// keeps the previous live forwarding state rather than steering traffic onto
    /// a wrapped VLAN.
    InterfaceVlanOutOfRange { interface: String, vlan_id: i32 },
    /// #2410: a tunnel-endpoint snapshot's `ttl` is outside the 0..=255 range
    /// representable in the outer IP TTL/hop-limit octet (`TunnelEndpoint.ttl`,
    /// a u8). The pre-fix code narrowed it with `endpoint.ttl.max(0) as u8`, so
    /// 256 wrapped to 0 (a packet that can never leave the first hop) and 300
    /// wrapped to 44. Silently installing a wrapped TTL produces a tunnel that
    /// either blackholes (TTL 0) or has a surprising reach. Fail closed instead.
    TunnelTtlOutOfRange { tunnel_id: u16, ttl: i32 },
    /// #5193 (A1-b7-F1): two tunnel-endpoint rows in one snapshot carried the
    /// SAME nonzero endpoint id. `populate_tunnel_endpoints` keys
    /// `tunnel_endpoints` by id and `tunnel_endpoint_by_ifindex` by ifindex,
    /// so a duplicate id left the two indexes inconsistent — the last row won
    /// the id while BOTH interfaces' ifindexes pointed at it, and packets on
    /// the losing interface encapsulated with the winner's outer
    /// source/destination/key. The Go producer drops an id collision at build
    /// time (`usedIDs`, #1873), so this is the snapshot-boundary backstop for a
    /// tolerant / mixed-version / corrupt snapshot, in the same fail-closed
    /// family as the #2410 TTL gate a few lines above it.
    TunnelEndpointDuplicateId { tunnel_id: u16, ifindex: i32 },
    /// #2410: a CoS forwarding-class snapshot's `queue` is outside the 0..=255
    /// range representable in the runtime `queue_id` (a u8). The pre-fix code
    /// SILENTLY DROPPED the class via a `filter_map` range check
    /// (`(0..=u8::MAX as i32).contains(&class.queue)`), so a class with a
    /// wrapped/over-range queue disappeared from `class_to_queue` — every
    /// classifier / scheduler-map entry referencing it then silently lost its
    /// queue mapping (see #2409). Fail the snapshot closed rather than installing
    /// a partial CoS table. An EMPTY class name is the legitimate "unnamed /
    /// placeholder" case and is NOT an error (skipped as before).
    CosQueueIdOutOfRange { forwarding_class: String, queue: i32 },
    /// #2706: an interface snapshot's `mtu` is NEGATIVE. The pre-fix code
    /// narrowed it with `iface.mtu.max(0) as usize`, so a negative value
    /// silently collapsed to 0 — and the egress MTU guard
    /// (`forwarded_egress_mtu_decision`) treats mtu 0 as "unknown; forward"
    /// (fail-open), so a negative MTU silently DISABLED PTB / drop enforcement
    /// on that interface. A healthy Go control plane never emits a negative MTU
    /// (netlink MTUs are non-negative; 0 is the legitimate "unknown" sentinel
    /// preserved as permissive). Fail the snapshot closed on a negative value
    /// rather than installing an interface with MTU enforcement off, consistent
    /// with the #2410/#2696 fail-closed family.
    InterfaceMtuInvalid { interface: String, mtu: i32 },
    /// #2409: an interface address snapshot's `address` string did not parse as
    /// an `IpNet` CIDR. The pre-fix code `continue`d past it, so the connected
    /// route / local-address / interface-NAT material for that address silently
    /// disappeared while the apply still SUCCEEDED — a connected route the
    /// operator configured would just never install, with no failure surfaced.
    /// In a retired-eBPF world where this helper is the only forwarding plane,
    /// that is silent connectivity loss. Fail the snapshot closed (the preflight
    /// keeps the previous good state) instead of silently dropping the address.
    InterfaceAddressUnparseable { interface: String, address: String },
    /// #2409: a CoS scheduler-map entry references a `forwarding_class` that is
    /// not in the `class_to_queue` table — either a typo, a version-drifted
    /// snapshot, or a class dropped for an out-of-range queue id (#2410). The
    /// pre-fix code `continue`d past it, so the scheduler-map installed only a
    /// SUBSET of its queues with no apply failure — a partially-installed
    /// scheduler is very hard to troubleshoot (some classes shape, some do not).
    /// Fail the snapshot closed instead of partially installing the scheduler.
    SchedulerMapUnknownClass {
        scheduler_map: String,
        forwarding_class: String,
    },
    /// #2447: a CoS DSCP classifier entry carried a code-point outside the
    /// 6-bit DSCP domain (0..=63). The pre-fix builder masked the index with
    /// `dscp & 0x3f`, so a value of 110 silently installed the classifier for
    /// DSCP 46 — a DIFFERENT traffic class — with no apply failure. The Go
    /// commit-time gate (`expandCoSCodePointToken`, #2447) is the primary
    /// defense; this is the helper-boundary backstop against version/snapshot
    /// drift, consistent with the #2410/#2696/#2713 fail-closed family. Fail
    /// the snapshot closed (the preflight keeps the previous live CoS state)
    /// rather than building a classifier for a different class than configured.
    CosDscpCodePointOutOfRange { classifier: String, dscp: u8 },
    /// #2447: a CoS IEEE 802.1p classifier entry carried a code-point outside
    /// the 3-bit PCP domain (0..=7). The pre-fix builder clamped the index with
    /// `pcp.min(7)`, so a value of 9 silently installed the classifier for PCP
    /// 7 — a DIFFERENT traffic class — with no apply failure. Same fail-closed
    /// rationale as `CosDscpCodePointOutOfRange`.
    CosIeee8021CodePointOutOfRange { classifier: String, pcp: u8 },
    /// #6847: a CoS inet-precedence classifier entry carried a code-point
    /// outside the 3-bit IP-precedence domain (0..=7). The Go commit-time gate
    /// (`collectCoSINetPrecedenceCodePoints`) is the primary defense; this is
    /// the helper-boundary backstop against version/snapshot drift. Fail the
    /// snapshot closed rather than masking the index with `& 0x7`, which would
    /// install the classifier for a DIFFERENT traffic class (9 -> 1). Same
    /// fail-closed rationale as `CosIeee8021CodePointOutOfRange`.
    CosInetPrecedenceCodePointOutOfRange { classifier: String, precedence: u8 },
    /// #5193 (A1-b7-F7): a CoS DSCP REWRITE-RULE entry carried a code-point
    /// outside the 6-bit DSCP domain (0..=63). Unlike the classifier builders
    /// (which have failed closed since #2447), the rewrite ingest stored the
    /// value unchecked and the transmit helper masks it with `dscp & 0x3f`, so
    /// a rule written as 110 silently marked packets DSCP 46 — a different
    /// PHB than configured, on egress, where it is hardest to notice. The Go
    /// commit-time gate (`collectCoSDSCPRewriteCodePoint`) is the primary
    /// defense; this is the helper-boundary backstop against a tolerant /
    /// mixed-version snapshot, consistent with the rest of the fail-closed
    /// family.
    CosDscpRewriteCodePointOutOfRange {
        rule: String,
        forwarding_class: String,
        dscp: u8,
    },
    /// #2458: a CoS scheduler snapshot carried a NON-EMPTY
    /// `equal_flow_target_policy` wire string that is not one of the known
    /// values (`slowest` / `mean` / `ideal-share`). The pre-fix
    /// `EqualFlowTargetPolicy::parse` mapped any unknown string to the
    /// `Slowest` default via a catch-all match arm — identically to the
    /// empty (legacy-default) string — so a typo or a mixed-version snapshot
    /// silently changed queue fairness instead of failing. The Go
    /// commit-time gate (`compiler_validate_strict.go`, #1746/#2458) is the
    /// primary defense; this is the helper-boundary backstop, consistent
    /// with the #2447 CoS fail-closed family. An EMPTY value is the
    /// legitimate legacy/unset default and is NOT an error.
    CosUnknownEqualFlowTargetPolicy {
        forwarding_class: String,
        target_policy: String,
    },
    /// #hb166 T-7: a CoS scheduler snapshot carried a NON-EMPTY `priority`
    /// wire string that is not one of the known Junos scheduler priorities
    /// (`strict-high` / `high` / `medium-high` / `medium-low` / `low`).
    /// There are FIVE, not six: this list named a bare `medium` until
    /// #6849, which Junos does not have and the Go schema's `priority`
    /// enum has never accepted. The pre-fix `cos_priority_rank` mapped any
    /// unrecognized
    /// string to rank 5 (`low`, the strict-priority FLOOR) via a catch-all
    /// match arm — so a typo or a mixed-version snapshot silently demoted a
    /// class to lowest priority with no failure surfaced. Fail-closed here,
    /// directly mirroring the #2458 `CosUnknownEqualFlowTargetPolicy` parse
    /// on the SAME queue a few fields over. The Go commit-time gate is the
    /// primary defense; this is the helper-boundary backstop for
    /// version/snapshot drift, consistent with the #2447/#2458 CoS
    /// fail-closed family. A MISSING scheduler, or a present scheduler with
    /// an EMPTY priority string, is the legitimate legacy default (rank
    /// `low`) and is NOT an error.
    CosUnknownSchedulerPriority {
        forwarding_class: String,
        priority: String,
    },
    /// #3365: a policy rule's `action` field, or the snapshot `default_policy`,
    /// carried a NON-EMPTY string that is not one of `permit` / `reject` /
    /// `deny`. The pre-fix `parse_action` mapped any unrecognized string to
    /// `PolicyAction::Deny` via a catch-all match arm — so a future `reject-*`
    /// variant, a mixed-version snapshot token, or a corrupt/truncated action
    /// silently LOST its intended permit/reject/RST semantics and collapsed to a
    /// plain Deny with no failure surfaced. That is fail-closed for a `permit`
    /// typo but fail-OPEN for a `reject`: an unrecognized reject downgrades to
    /// Deny, dropping the RST/ICMP-unreachable behavior the operator configured,
    /// and it masks wire-contract drift. The Go producer (`policyActionString`
    /// in `pkg/dataplane/userspace/policies.go`) only ever renders the three
    /// known tokens, so a normal Go snapshot never trips this; it is the
    /// helper-boundary backstop for version drift / a corrupt snapshot,
    /// consistent with the #2124/#3261 fail-closed family. Rejecting the WHOLE
    /// snapshot (the preflight keeps the previous good state; a fresh boot keeps
    /// the default-deny `PolicyState`) is action-agnostic. An EMPTY
    /// `default_policy` is the legitimate `omitempty`/unspecified wire state
    /// (decodes to the default Deny) and is NOT an error; an empty per-rule
    /// action IS rejected (every configured rule has a concrete action).
    UnknownPolicyAction { context: String, action: String },
    /// #3402: a policy rule names a from/to zone — or a scoped-global (#3148)
    /// `match from-zone`/`match to-zone` context — that does not resolve in the
    /// snapshot's zone table (`zone_name_to_id`). The pre-fix code handled this
    /// as a stderr-only DROP: the zone-pair / single-wildcard build skipped
    /// indexing the rule ("rule kept, but not indexed"), and the scoped-global
    /// build produced a `GlobalZoneScope::Unresolved` that matched nothing. In
    /// BOTH cases the rule never participated in evaluation and the traffic it
    /// was meant to govern fell through to `default-policy` with no failure
    /// surfaced to the control plane. Under `default-policy permit-all` a stale
    /// `deny` silently becomes an ALLOW (fail-OPEN); under `deny-all` a stale
    /// `permit` silently BLACKHOLES. The Go commit gate
    /// (`validatePolicyZoneReferencesStrict`, #2401) hard-rejects an undefined
    /// zone reference for both shapes, so a clean commit never reaches this arm;
    /// this is the helper-boundary backstop for the lenient / upgrade-state /
    /// HA-replay / corrupt-snapshot path (`lenientPolicyZoneRefs`), consistent
    /// with the #3261/#3365/#3367 fail-closed family. Rejecting the WHOLE
    /// snapshot (the preflight keeps the previous good state; a fresh boot keeps
    /// the default-deny `PolicyState`) is action-agnostic: it never turns a deny
    /// into a pass nor a permit into match-any. The empty token and the special
    /// `any` / `junos-host` zone names always resolve (see
    /// `resolve_policy_zone_id`) and so never trip this. An empty ELEMENT inside
    /// a plural `match_*_zones` list DOES trip this via `build_global_zone_scope`
    /// (#6464); only the empty singular field is exempt (dropped by
    /// `effective_match_zones` as an omitted scope).
    UnresolvableZoneReference { rule_id: String, zone: String },
    /// #3771 (M4): a `RouteSnapshot` carried a NON-EMPTY `family` that does not
    /// match the address family of its `destination` prefix (e.g. family="inet6"
    /// with an IPv4 destination). The pre-fix `populate_routes` chose the FIB
    /// (`routes_v4` vs `routes_v6`) SOLELY by parsing `destination` as
    /// `Ipv4Net` / `Ipv6Net` and never consulted `family`, so an inconsistent
    /// snapshot installed the route into the family the PREFIX parses as while the
    /// `family` metadata claimed the other — a silent divergence between the
    /// control plane's model and the installed FIB. The Go producer derives
    /// `family` from the same prefix (`normalizeRouteSnapshotFamily`,
    /// pkg/dataplane/userspace/routes.go), so a clean snapshot never trips this;
    /// it is the helper-boundary backstop for a corrupt / hand-built /
    /// version-drifted snapshot, consistent with the #2410/#2409 fail-closed
    /// family. This is NOT the #2448 malformed-destination case — the prefix is a
    /// valid CIDR; only the `family` metadata is inconsistent. An EMPTY `family`
    /// is unconstrained (parse-only, the pre-fix behaviour) and is NOT an error.
    RouteFamilyMismatch {
        table: String,
        destination: String,
        family: String,
    },
    /// #6568 (member 1): a `RouteSnapshot` carried a `destination` that parses
    /// as NEITHER `Ipv4Net` NOR `Ipv6Net`, so no FIB can hold it.
    ///
    /// `populate_routes` used to fall off the end of the loop body here — no
    /// `Err`, no counter, no log — at a boundary whose entire #2409/#2410/#3771
    /// contract is "no silent skips". It was filed as a low-materiality
    /// residual with "no traffic fail-open"; that is wrong. `ipnet`'s parsers
    /// REQUIRE a prefix length and nothing in the config compiler validated the
    /// destination, so a bare host address (`10.0.0.1`, `2001:db8::1`) or the
    /// Junos `default` keyword committed cleanly, shipped, and VANISHED here.
    ///
    /// For a `discard`/`reject` route that is a fail-OPEN: the blackhole entry
    /// is absent, the packet longest-prefix matches a LESS-SPECIFIC route
    /// (typically the default) and is FORWARDED where the operator asked for it
    /// to be dropped — and it presents as a routing mystery, because the
    /// control plane, FRR and the kernel all show the route as configured.
    ///
    /// The Go producer now normalises a bare address to its /32 or /128 host
    /// prefix and drops anything still unusable with a WARN naming the route
    /// (`routeDestinationForWire`, pkg/dataplane/userspace/routes.go), so a
    /// clean snapshot never trips this. It is the helper-boundary backstop for
    /// a corrupt / hand-built / version-drifted snapshot, consistent with the
    /// #2410/#2409 fail-closed family.
    RouteDestinationUnparseable { table: String, destination: String },
    /// #3771 (L1): a `RouteSnapshot` carried a NEGATIVE `preference`. Junos route
    /// preference is a non-negative administrative distance (default 5; lower =
    /// more preferred); the FIB tie-breaks same-prefix routes by ASCENDING
    /// preference (fib.rs `sort_routes`, #2390), so a negative preference (e.g.
    /// `i32::MIN`) would sort AHEAD of every legitimate route and silently hijack
    /// the selection for that prefix. The Go boundary (`schema_routing.go`
    /// `ValidateInteger(0, ...)` on the route `preference` leaf) rejects it at
    /// commit; this is the helper-boundary backstop for a corrupt /
    /// version-drifted snapshot, consistent with the #2410 out-of-range
    /// fail-closed family. A preference of 0 is the legitimate most-preferred
    /// value and is NOT an error.
    RoutePreferenceOutOfRange {
        table: String,
        destination: String,
        preference: i32,
    },
    /// #3771 (M11): a `NeighborSnapshot` carried a NON-EMPTY `family` that does
    /// not match the address family of its parsed `ip` (e.g. family="inet" with
    /// an IPv6 address). The pre-fix `populate_neighbors` installed the neighbor
    /// keyed on the parsed IP and never consulted `family`, so an inconsistent
    /// snapshot installed a neighbor under a family that contradicts its own
    /// metadata. The Go producer derives `family` from the netlink family
    /// enumeration (`buildNeighborSnapshots`, pkg/dataplane/userspace/neighbors.go),
    /// so a clean snapshot never trips this; it is the helper-boundary backstop
    /// for a corrupt / hand-built / version-drifted snapshot. An EMPTY `family`
    /// is unconstrained (parse-only) and is NOT an error.
    NeighborFamilyMismatch {
        interface: String,
        ip: String,
        family: String,
    },
    /// #3719 (H03): two DIFFERENT security zones in the same snapshot carried the
    /// same nonzero, non-reserved numeric zone id. #3075/#3704 made the zone id a
    /// stable name-hash (`config.StableZoneID`); two zone names can fold to the
    /// same id, and publishing both would let the later zone silently overwrite
    /// the earlier's `zone_id_to_name` / `zone_host_inbound` / `zone_tcp_rst`
    /// entries in `populate_zones` — MERGING two security zones under one id (one
    /// zone's interfaces / policies / counters / host-inbound set stand in for the
    /// other, a zone-isolation failure). The Go control plane QUARANTINES the
    /// later-sorting colliding zone before it reaches the wire
    /// (`config.QuarantinedZoneNames` -> `quarantineCollidingZones`,
    /// pkg/dataplane/userspace/zones.go), so a clean snapshot never trips this; it
    /// is the helper-boundary backstop for a corrupt / hand-built /
    /// version-drifted snapshot, consistent with the #3402 `UnresolvableZoneReference`
    /// and #3771 fail-closed family. Rejecting the WHOLE snapshot keeps the
    /// previous good forwarding state (a fresh boot keeps the default-deny) and
    /// never merges two zones. Ids of 0, an empty name, or the reserved range are
    /// skipped by `populate_zones` (never installed) and so are NOT treated as
    /// collisions.
    DuplicateZoneId {
        id: u16,
        first: String,
        second: String,
    },
    /// #10683: the bind-less selector-fence marker disagrees with whether
    /// selector rows are present. Ignoring mismatched rows would silently
    /// disable the cleartext fence.
    BindlessSelectorFenceMarkerMismatch { enabled: bool, rows: usize },
    /// #10683: a published traffic-selector pair cannot be represented by the
    /// helper's exact IP-prefix/range matcher. Reject the snapshot rather than
    /// silently omitting a selector and forwarding matching cleartext.
    InvalidBindlessSelector { local_ts: String, remote_ts: String },
}

impl std::fmt::Display for SnapshotIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressBookIdZero => write!(f, "address book has reserved id=0"),
            Self::DuplicateAddressBookId(id) => {
                write!(f, "duplicate address_books.id={}", id)
            }
            Self::DuplicateRuleId { rule_id } => write!(
                f,
                "duplicate policy rule_id {:?} — two rules resolve to the same stable identity (identical explicit rule_id or duplicate policy name in a zone pair); refusing to fail open by sharing one hit counter and aliasing the RT_FLOW/session/display join key",
                rule_id
            ),
            Self::DuplicatePolicyId { policy_id } => write!(
                f,
                "duplicate policy_id {} — two rules carry the same positional policy id (corrupt/mixed-version snapshot); refusing to fail open by letting a session re-resolve to the wrong policy",
                policy_id
            ),
            Self::UnknownAddressBookId { rule_id, book_id } => write!(
                f,
                "rule {:?} references unknown address book id={}",
                rule_id, book_id
            ),
            Self::UnrepresentableApplicationProtocol { rule_id } => write!(
                f,
                "rule {:?} has an unrepresentable application term (unparseable protocol or port) — refusing to fail open by dropping it",
                rule_id
            ),
            Self::InvalidApplicationIcmpFields {
                rule_id,
                application,
                reason,
            } => write!(
                f,
                "rule {:?} application term {:?} has an invalid ICMP field combination: {} — refusing to compile a wrong-behaving term (icmp-code without icmp-type matches ALL ICMP; icmp-type/code on a non-ICMP protocol never matches, so a deny falls through to default-permit)",
                rule_id, application, reason
            ),
            Self::UnrepresentableAddress { rule_id } => write!(
                f,
                "rule {:?} has an unrepresentable address (undefined address book, or a non-literal dns-name/wildcard/range value) — refusing to fail open by collapsing the side to match-none (which lets a deny fall through)",
                rule_id
            ),
            Self::UnrepresentableLegacyAddress { rule_id, address } => write!(
                f,
                "rule {:?} has an unparseable legacy address literal {:?} (not an IP/CIDR, `any`, or family wildcard) — refusing to fail open by dropping it (which on the empty->match-any legacy path widens a deny to match everything)",
                rule_id, address
            ),
            Self::UnrepresentableV3Address { rule_id, address } => write!(
                f,
                "rule {:?} has an unparseable v3 address literal {:?} (not an IP/CIDR, `any`, or family wildcard, and not the unrepresentable-address sentinel) — refusing to fail open by dropping it (which collapses the side to match-none and lets a deny fall through to a later permit / default-permit)",
                rule_id, address
            ),
            Self::UnrepresentableAddressBookPrefix {
                book_id,
                book_name,
                family,
                address,
            } => write!(
                f,
                "address book id={} ({:?}) has prefixes_{} entry {:?} that is not a parseable {} IP/CIDR literal (malformed, or a wrong-family token in the {} array) — refusing to fail open by dropping it (which collapses a book-backed deny to match-none) or by silently routing it to the other family",
                book_id, book_name, family, address, family, family
            ),
            Self::Nptv6UnparseableRule { rule_name, field } => write!(
                f,
                "nptv6 rule {:?} has an unparseable {} — refusing to fail open by silently dropping the rule (which would tear down working translations)",
                rule_name, field
            ),
            Self::Nptv6OverlappingPrefix {
                first_rule,
                second_rule,
                direction,
            } => write!(
                f,
                "nptv6 rules {:?} and {:?} have overlapping {} prefixes — refusing nondeterministic first-match resolution",
                first_rule, second_rule, direction
            ),
            Self::UnrepresentableFilterProtocol {
                family,
                filter,
                term,
                token,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unresolvable protocol token {:?} — refusing to fail wide by dropping it (which would make the term match every protocol)",
                family, filter, term, token
            ),
            Self::UnrepresentableFilterTCPFlags {
                family,
                filter,
                term,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unparseable tcp-flags expression — refusing to fail wide by dropping it (which would make the term match every TCP segment)",
                family, filter, term
            ),
            Self::UnrepresentableFilterICMP {
                family,
                filter,
                term,
                dimension,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unresolvable {} token — refusing to fail wide by dropping it (which would make the term match every ICMP packet)",
                family, filter, term, dimension
            ),
            Self::UnrepresentableFilterDSCP {
                family,
                filter,
                term,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unresolvable from-dscp/traffic-class match token — refusing to fail wide by dropping it (which would make the term match every DSCP)",
                family, filter, term
            ),
            Self::UnrepresentableFilterPorts {
                family,
                filter,
                term,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unresolvable port token — refusing to fail open by dropping it per-token (which would narrow a discard/reject term to only the surviving ports and let the rest fall through to the implicit accept)",
                family, filter, term
            ),
            Self::UnrepresentableFilterAddress {
                family,
                filter,
                term,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has an unparseable address literal — refusing to fail open by dropping it per-token (which would narrow a discard/reject term to only the surviving prefixes and let the rest fall through to the implicit accept)",
                family, filter, term
            ),
            Self::UnrepresentableFilterFrom {
                family,
                filter,
                term,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has a from match leaf the dataplane does not enforce — refusing to fail wide by dropping it (which would let an accept term over-permit and a discard/reject term over-drop)",
                family, filter, term
            ),
            Self::UnrepresentableFilterFlexMatch {
                family,
                filter,
                term,
                length,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has a flexible-match-range byte length {} outside the representable 1..=4 range — refusing to truncate it to a 4-byte window (which would broaden the match)",
                family, filter, term, length
            ),
            Self::FilterDSCPOutOfRange {
                family,
                filter,
                term,
                dimension,
                value,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} has a {} dscp/traffic-class value {} outside the 0..=63 6-bit range — refusing to mask it into a different valid code point (rewrite) or silently drop it from the match bitmap (match)",
                family, filter, term, dimension, value
            ),
            Self::UnsatisfiableFilterCrossField {
                family,
                filter,
                term,
                predicate,
                protocol,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} combines a {} match with protocol {} that cannot carry it — refusing to compile a never-match term (a then discard/reject over it fails open, admitting the traffic via the implicit accept)",
                family, filter, term, predicate, protocol
            ),
            Self::MissingFilterRef {
                interface,
                family,
                direction,
                filter,
            } => write!(
                f,
                "interface {:?} family {:?} filter {} references undefined filter {:?} — refusing to fail open by leaving the hook unarmed (which would forward unfiltered, equivalent to no filter)",
                interface, family, direction, filter
            ),
            Self::MissingPolicerRef {
                family,
                filter,
                term,
                policer,
            } => write!(
                f,
                "firewall family {:?} filter {:?} term {:?} references undefined policer {:?} — refusing to fail open by leaving the rate limit unmetered (which would forward unpoliced, equivalent to no policer)",
                family, filter, term, policer
            ),
            Self::InterfaceUnknownZone { interface, zone } => write!(
                f,
                "interface {:?} references zone {:?} that is not in the zone table — refusing to fail open by collapsing it to the \"unknown\" zone 0 (which would bypass every zone-pair policy)",
                interface, zone
            ),
            Self::InterfaceVlanOutOfRange { interface, vlan_id } => write!(
                f,
                "interface {:?} has vlan_id {} outside the 0..=65535 802.1Q range — refusing to narrow it with an unchecked cast that would wrap to a different VLAN (a different L2 domain)",
                interface, vlan_id
            ),
            Self::TunnelTtlOutOfRange { tunnel_id, ttl } => write!(
                f,
                "tunnel endpoint id={} has ttl {} outside the 0..=255 range — refusing to narrow it with an unchecked cast that would wrap (256→0 blackholes the tunnel)",
                tunnel_id, ttl
            ),
            Self::TunnelEndpointDuplicateId { tunnel_id, ifindex } => write!(
                f,
                "two tunnel endpoints share id {} (second row has ifindex {}) — refusing to install a snapshot whose endpoint id and ifindex indexes would disagree (the later row would win the id while both ifindexes alias it)",
                tunnel_id, ifindex
            ),
            Self::CosQueueIdOutOfRange {
                forwarding_class,
                queue,
            } => write!(
                f,
                "cos forwarding-class {:?} has queue {} outside the 0..=255 range — refusing to silently drop the class (which would unmap every classifier/scheduler entry referencing it)",
                forwarding_class, queue
            ),
            Self::InterfaceMtuInvalid { interface, mtu } => write!(
                f,
                "interface {:?} has a negative mtu {} — refusing to narrow it with an unchecked .max(0) cast that would collapse it to 0 (which the egress MTU guard treats as \"unknown; forward\", silently disabling PTB/drop enforcement)",
                interface, mtu
            ),
            Self::InterfaceAddressUnparseable { interface, address } => write!(
                f,
                "interface {:?} address {:?} is not a parseable IpNet — refusing to silently drop it (which would lose the connected route / local-address material with no apply failure)",
                interface, address
            ),
            Self::SchedulerMapUnknownClass {
                scheduler_map,
                forwarding_class,
            } => write!(
                f,
                "cos scheduler-map {:?} references forwarding-class {:?} that is not in the class-to-queue table — refusing to partially install the scheduler (some queues silently missing)",
                scheduler_map, forwarding_class
            ),
            Self::CosDscpCodePointOutOfRange { classifier, dscp } => write!(
                f,
                "cos dscp classifier {:?} has code-point {} outside the 0..=63 DSCP range — refusing to mask it with & 0x3f (which would install the classifier for a different traffic class)",
                classifier, dscp
            ),
            Self::CosIeee8021CodePointOutOfRange { classifier, pcp } => write!(
                f,
                "cos ieee-802.1 classifier {:?} has code-point {} outside the 0..=7 PCP range — refusing to clamp it with .min(7) (which would install the classifier for a different traffic class)",
                classifier, pcp
            ),
            Self::CosInetPrecedenceCodePointOutOfRange {
                classifier,
                precedence,
            } => write!(
                f,
                "cos inet-precedence classifier {:?} has code-point {} outside the 0..=7 IP-precedence range — refusing to mask it with & 0x7 (which would install the classifier for a different traffic class)",
                classifier, precedence
            ),
            Self::CosDscpRewriteCodePointOutOfRange {
                rule,
                forwarding_class,
                dscp,
            } => write!(
                f,
                "cos dscp rewrite-rule {:?} maps forwarding-class {:?} to code-point {} outside the 0..=63 DSCP range — refusing to let the transmit path mask it with & 0x3f (which would mark the packet with a different PHB than configured)",
                rule, forwarding_class, dscp
            ),
            Self::CosUnknownEqualFlowTargetPolicy {
                forwarding_class,
                target_policy,
            } => write!(
                f,
                "cos forwarding-class {:?} has equal-flow-target-policy {:?} that is not one of slowest | mean | ideal-share — refusing to silently map it to the \"slowest\" default (which would change queue fairness with no failure surfaced)",
                forwarding_class, target_policy
            ),
            Self::CosUnknownSchedulerPriority {
                forwarding_class,
                priority,
            } => write!(
                f,
                "cos forwarding-class {:?} has scheduler priority {:?} that is not one of strict-high | high | medium-high | medium | medium-low | low — refusing to silently rank it lowest (\"low\"), which would demote the class with no failure surfaced",
                forwarding_class, priority
            ),
            Self::UnknownPolicyAction { context, action } => write!(
                f,
                "{} has action {:?} that is not one of permit | reject | deny — refusing to silently map it to Deny (which fail-OPENs an unrecognized reject by dropping its RST/ICMP-unreachable semantics and masks wire-contract drift)",
                context, action
            ),
            Self::UnresolvableZoneReference { rule_id, zone } => write!(
                f,
                "rule {:?} references undefined zone {:?} — refusing to fail open by dropping the unindexed rule (it would fall through to default-policy: a stale deny becomes an allow under permit-all, a stale permit blackholes under deny-all)",
                rule_id, zone
            ),
            Self::RouteFamilyMismatch {
                table,
                destination,
                family,
            } => write!(
                f,
                "route {:?} in table {:?} declares family {:?} that does not match the address family of its destination prefix — refusing to install it into the prefix-parsed FIB while the family metadata claims the other",
                destination, table, family
            ),
            Self::RouteDestinationUnparseable { table, destination } => write!(
                f,
                "route {:?} in table {:?} has a destination that parses as neither an IPv4 nor an IPv6 prefix — refusing to skip it silently, because a dropped discard/reject route falls through to a less-specific route and FORWARDS traffic the operator asked to blackhole (a bare host address needs its /32 or /128)",
                destination, table
            ),
            Self::RoutePreferenceOutOfRange {
                table,
                destination,
                preference,
            } => write!(
                f,
                "route {:?} in table {:?} has negative preference {} — Junos preference is a non-negative admin distance; a negative value would sort ahead of every route in the FIB tie-break",
                destination, table, preference
            ),
            Self::NeighborFamilyMismatch {
                interface,
                ip,
                family,
            } => write!(
                f,
                "neighbor {:?} on interface {:?} declares family {:?} that does not match the address family of its IP — refusing to install it under a contradicting family",
                ip, interface, family
            ),
            Self::DuplicateZoneId { id, first, second } => write!(
                f,
                "security zones {:?} and {:?} share numeric zone id {} — publishing both would merge two zones; rename one zone (#3719)",
                first, second, id
            ),
            Self::BindlessSelectorFenceMarkerMismatch { enabled, rows } => write!(
                f,
                "bind-less selector-fence marker enabled={} disagrees with {} selector rows — refusing to publish an unenforced cleartext selector set (#10683)",
                enabled, rows
            ),
            Self::InvalidBindlessSelector { local_ts, remote_ts } => write!(
                f,
                "bind-less IPsec selector pair local_ts={:?} remote_ts={:?} cannot be represented by the dataplane matcher — refusing to publish it without a cleartext fence (#10683)",
                local_ts, remote_ts
            ),
        }
    }
}

impl std::error::Error for SnapshotIntegrityError {}
