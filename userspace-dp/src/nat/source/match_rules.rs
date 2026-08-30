//! Source-NAT match pipeline.
//!
//! The `match_source_nat*` family, including the 672-line
//! `match_source_nat_result_for_tuple` that is 20% of the pre-split file.
//! Reaches back into `source` for `SourceNatRule::matches` and
//! `address_has_draining_pool_occupancy`, both private in `mod.rs` and therefore
//! visible here without a visibility change (a private item is visible to its
//! module AND that module's descendants).
//!
//! #6988 was PURE CODE MOTION: every line was moved verbatim from
//! `nat/source.rs` lines 2495-3241, with only the visibility widenings
//! enumerated in `source/mod.rs`.
//!
//! That is no longer the whole story and the claim must not be left standing as
//! though it were: #6979 F6 added `reject_peer_owned_identity` here and calls
//! it at the three PAT allocation sites (deterministic-v4, v4 round-robin, v6
//! round-robin). Everything else remains the moved code.

use super::*;

/// #6979 F6: refuse a PAT identity a PEER pool already owns, and roll ours back.
///
/// Two source-NAT pools that cover one address are two independent occupancy
/// bitmaps (`SourceNatPoolAllocatorKey` carries the pool NAME), so each is blind
/// to the other's live translations and both can publish `203.0.113.1:20000`
/// for a different live flow — one wire identity, two sessions, replies the
/// reverse index cannot attribute. Measured on master.
///
/// Called AFTER the allocation, deliberately. Check-then-mint has a window: two
/// workers minting from two peer allocators can both see the tuple free and
/// both take it. Mint-then-check closes it — the claiming `fetch_or` runs
/// before either worker looks, so at least one sees the other's bit and rolls
/// back, and if they see each other simultaneously BOTH roll back. The worst
/// case is a refused flow, never a published duplicate.
///
/// # The `SeqCst` fence is what makes that argument true
///
/// The two workers store to DIFFERENT locations (each allocator owns its own
/// occupancy bitmap) and then load the other's. That is the store-buffer
/// litmus test, and it is NOT forbidden by the release/acquire pair the bitmap
/// already uses: `AddressOccupancy::claim_offset` is `fetch_or(AcqRel)` and
/// `is_occupied` is `load(Acquire)`, which together still permit both workers
/// to observe the peer as free and both to publish — the exact duplicate this
/// function exists to prevent. A `SeqCst` fence executed between the store and
/// the load ON BOTH SIDES is the standard fix, and both sides run this code.
///
/// It sits AFTER the `Option::is_none` early-out, so a config with no
/// overlapping pools — every config a strict commit accepts — never executes
/// it.
///
/// Stated plainly because it cannot be bound by a test: no unit test can
/// distinguish this fence's presence from its absence, since the reordering it
/// forbids is architecture- and timing-dependent (on x86-64 the `lock`-prefixed
/// `fetch_or` is already a full barrier, so the fence is a no-op there). It is
/// here for the memory model, not for an observed failure.
///
/// `None` on every config with no overlapping pools — `overlap_owners` is
/// `None` there and the whole call is one `Option::is_none`.
fn reject_peer_owned_identity(
    rule: &SourceNatRule,
    flow: SourceNatFlowKey,
    translated: TranslatedTuple,
    now_ns: u64,
    holder: NatHolder,
) -> Option<SourceNatLookup> {
    if rule.overlap_owners.is_none() {
        return None;
    }
    std::sync::atomic::fence(Ordering::SeqCst);
    if !rule.peer_holds_identity(translated.ip, translated.port) {
        return None;
    }
    // Undo OUR reservation before failing, or the refused flow leaves a port
    // held with nothing that will ever release it: the flow is never published,
    // so no session teardown will name it.
    //
    // `rollback_flow` rather than `release_flow` because this is an activation
    // being WITHDRAWN, not a flow completing — the two take different
    // persistent-lease arms (#6528), and only rollback's is right for a
    // translation that never went into service.
    //
    // The port DOES go back on the per-address recycle ring, same as any other
    // rollback. That does not re-collide the pool's next flow: `claim()`
    // forward-probes the monotonic fresh cursor BEFORE draining the recycle
    // ring (#3047/#3011), and the cursor has already moved past the colliding
    // port. Measured by
    // `an_overlapping_pool_still_mints_an_identity_its_peer_does_not_own_6979`.
    rule.pool_allocator
        .rollback_flow(flow, translated, now_ns, holder);
    Some(SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
        rule,
        SourceNatFailureReason::PoolPeerAddressOverlap,
    )))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn match_source_nat(
    // #6751: threaded for signature symmetry with the tuple entry point. This
    // wrapper supplies NO L4 tuple, so it always takes the `tuple_unknown`
    // probe-pure arm and mints nothing — but the registry is passed rather
    // than defaulted so a future change to the branch ORDER cannot silently
    // start minting into a throwaway registry no release would ever reach.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    scope: &NatScopeCtx,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
) -> Option<NatDecision> {
    match match_source_nat_result(
        iface_allocs,
        rules,
        scope,
        from_zone,
        to_zone,
        src_ip,
        dst_ip,
        egress_v4,
        egress_v6,
    ) {
        SourceNatLookup::Matched(decision) => Some(decision),
        SourceNatLookup::NoMatch | SourceNatLookup::Unavailable(_) => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn match_source_nat_result(
    // #6751: see `match_source_nat` — probe-pure, threaded for symmetry.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    scope: &NatScopeCtx,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
) -> SourceNatLookup {
    let mut counter = None;
    match_source_nat_result_for_tuple(
        iface_allocs,
        rules,
        scope,
        from_zone,
        to_zone,
        src_ip,
        dst_ip,
        // #5687: `None` is the out-of-band "L4 tuple unknown" signal for the
        // address-only wrapper — distinct from a real HOPOPT (`Some(0)`).
        None,
        0,
        0,
        egress_v4,
        egress_v6,
        0,
        false,
        // #4088: the address-only wrapper never carries an ICMP query id
        // (the tuple is unknown), so there is no identifier to preserve.
        false,
        // #6522: this wrapper has no worker context (its only callers are the
        // `#[cfg_attr(not(test), allow(dead_code))]` helpers in
        // `afxdp/forwarding/nat.rs`), so it keeps the untracked contract.
        NatHolder::Untracked,
        &mut counter,
    )
}

/// #2218: same as `match_source_nat_result_for_tuple` but the matched
/// rule's per-rule hit counter (if any) is written to `matched_counter`.
/// The `SourceNatLookup` enum stays wire-/Eq-frozen (it is destructured
/// and `matches!`-compared in many tests and over no wire), so the counter
/// rides out via this out-parameter rather than a new enum payload — the
/// least-invasive shape. The cold-path commit site clones the captured
/// `Arc` and increments it once per committed translated flow.
#[allow(clippy::too_many_arguments)]
pub(crate) fn match_source_nat_result_for_tuple(
    // #6751: the node-lifetime interface-mode identity registry. Interface
    // SNAT has no pool to allocate from, so this is where its translated
    // identity is minted — preserve the source port when its reverse
    // identity is free, PAT the later collider when it is not. FIRST
    // parameter (rather than appended) so it reads as the allocation
    // CONTEXT alongside `rules`, not as an afterthought.
    iface_allocs: &InterfaceNatAllocators,
    rules: &[SourceNatRule],
    scope: &NatScopeCtx,
    from_zone: &str,
    to_zone: &str,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    // #5687: the L4 protocol is OUT-OF-BAND optional so a genuine IPv4
    // protocol 0 (HOPOPT) is representable and distinct from the synthetic
    // "L4 tuple unknown" caller:
    //   - `None`     => tuple unknown (the address-only `match_source_nat`
    //     wrapper, which has no L4 tuple to supply). Fails L4-constrained
    //     rules closed and takes the synthetic address-only path.
    //   - `Some(0)`  => a REAL protocol-0 (HOPOPT) packet. It is port-less
    //     like GRE/ESP/OSPF, so it takes the real address-only path
    //     (`reserve_address_only` mints the reverse-identity occupancy
    //     token) — its reverse tuple can now be matched.
    //   - `Some(n)`  => any other real protocol (TCP=6, UDP=17, ICMP=1, ...),
    //     byte-identical behavior to before this fix.
    // The `SourceNatFlowKey.protocol` reverse-index key stays `u8` (the real
    // value, 0 for HOPOPT), so the in-map / HA-sync tuple layout is unchanged.
    protocol: Option<u8>,
    src_port: u16,
    dst_port: u16,
    egress_v4: Option<Ipv4Addr>,
    egress_v6: Option<Ipv6Addr>,
    now_ns: u64,
    // #1852: when true, gate port-translating (pool-mode) allocation —
    // a non-first fragment has no L4 ports. Interface-mode (address-only)
    // and `off`/static rules are unaffected.
    non_first_fragment: bool,
    // #4088 (RFC 5508 §3.1): for an ICMP/ICMPv6 tuple this is the
    // authoritative "the tuple carries a real ICMP Query Identifier" signal,
    // replacing the old `src_port != 0` heuristic. The frame parser
    // (`parse_flow_ports`) only lifts an identifier into `src_port` for an
    // identifier-bearing query type, and a `SessionFlow` is only built for an
    // ICMP protocol when that gate matched — so the flow caller passes
    // `matches!(protocol, PROTO_ICMP | PROTO_ICMPV6)`. An ICMP Query
    // Identifier of 0 is a valid on-wire value (0..=65535); keying the query
    // gate on `src_port != 0` misclassified an id==0 query as flowless and
    // took the address-only path, colliding two id==0 flows behind one pool
    // address on the reverse tuple (pool_addr, 0). The synthetic /
    // address-only (`protocol == 0`) callers pass `false`.
    icmp_identifier_present: bool,
    // #6522: the worker whose packet path is making this allocation. The record
    // this call inserts names its own holder, so a sibling worker's replica of
    // the resulting session cannot free a `(pool_addr, port)` this worker is
    // still forwarding through (see `NatHolder` / `LiveAllocation::holders`).
    // `NatHolder::Untracked` keeps the pre-#6522 single-holder contract for the
    // test entry points and the read-only fragment probe.
    holder: NatHolder,
    matched_counter: &mut Option<Arc<NatRuleCounter>>,
) -> SourceNatLookup {
    // #5687: decode the out-of-band protocol. `None` is the tuple-unknown
    // signal (address-only wrapper); a real HOPOPT arrives as `Some(0)` and is
    // NOT confused with it. The reverse-index key keeps the real u8 value.
    let tuple_unknown = protocol.is_none();
    let protocol = protocol.unwrap_or(0);
    let flow = SourceNatFlowKey {
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    };
    // #4161: this is first-match on slice order, and that is INTENTIONALLY
    // most-specific-scope-wins. The Go snapshot builder
    // (pkg/dataplane/userspace/nat.go buildSourceNATSnapshotsWithFeeds) STABLE-
    // sorts the rule-sets by Junos context specificity (interface > zone >
    // routing-instance > unscoped) before publishing, with config order as the
    // tie-break, so the first rule that matches here is the most-specific one.
    // Precedence therefore lives in the snapshot ORDER, not in this loop — do
    // not re-sort or assume raw config order.
    for rule in rules {
        if !rule.matches(
            scope,
            from_zone,
            to_zone,
            src_ip,
            dst_ip,
            tuple_unknown,
            protocol,
            src_port,
            dst_port,
        ) {
            continue;
        }
        if rule.off {
            // An `off` rule applies no translation — leave matched_counter
            // unset so no hit is counted for a no-op match.
            return SourceNatLookup::Matched(NatDecision::default());
        }
        *matched_counter = rule.hit_counter.clone();
        if rule.interface_mode {
            // #5688: interface SNAT translates the source to the egress
            // interface's OWN same-family address. Resolve it by the PACKET's
            // family — a v4 packet needs a v4 egress address, a v6 packet a v6
            // one. If the egress interface has NO address of that family there is
            // nothing to translate to. Returning `Matched` with a `None` rewrite
            // here forwarded the packet UNTRANSLATED — the private/internal source
            // leaked onto the egress. Fail CLOSED instead: report `Unavailable`
            // so the flow funnels through the same drop / `nat_alloc_fail`
            // disposition a pool-mode allocation failure takes, and the leak
            // cannot happen.
            let rewrite_src = match src_ip {
                IpAddr::V4(_) => egress_v4.map(IpAddr::V4),
                IpAddr::V6(_) => egress_v6.map(IpAddr::V6),
            };
            let Some(rewrite_src) = rewrite_src else {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                    rule,
                    SourceNatFailureReason::InterfaceNoEgressAddress,
                ));
            };
            // #6751: PROBE PURITY. Both probe classes mint NOTHING. A
            // non-first fragment carries no L4 header, so the ports that
            // would key its identity are payload bytes; the address-only
            // wrapper (`tuple_unknown`) has no tuple at all. Minting on
            // either would claim an identity no real flow owns and no
            // teardown would ever free it — every fragment of one datagram
            // would claim its own. They keep the pre-#6751 decision exactly.
            if non_first_fragment || tuple_unknown {
                return SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(rewrite_src),
                    rewrite_dst: None,
                    ..NatDecision::default()
                });
            }
            // #7717: UNIFORM MINT QUARANTINE. While a quarantined pool is
            // still DRAINING live allocations on this egress address, the two
            // domains keep independent occupancy — the interface registry
            // reports "uncontended" for a port the draining pool is actively
            // using, preserves it, and both flows go out as one wire identity.
            // That is the collision
            // `defect_pin_pool_and_interface_snat_mint_one_identity_7717`
            // demonstrates.
            //
            // Fail CLOSED rather than PAT around it. The interface registry
            // cannot see which ports the pool holds, so "PAT to something else"
            // would be a guess; and the plan's posture for a mint colliding
            // with a domain it cannot enumerate is to refuse. The refusal is
            // self-limiting: it lifts when the last draining flow closes, which
            // is what makes this a drain rather than a permanent quarantine.
            if address_has_draining_pool_occupancy(rules, rewrite_src) {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                    rule,
                    SourceNatFailureReason::InterfaceOverlapDraining,
                ));
            }
            let Some(alloc) = iface_allocs.allocator_for(rewrite_src) else {
                // The registry cannot create state for this address and
                // nothing was reclaimable. Fail CLOSED rather than fall back
                // to the unconditional preserve — that fallback IS the bug.
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                    rule,
                    SourceNatFailureReason::InterfaceRegistryCap,
                ));
            };
            // #3111/#4088: a protocol with no L4 port concept (GRE/ESP/AH/
            // OSPF, and an ICMP control/error message with no Query
            // Identifier) has ONE identity per `(egress, remote)` and no
            // port to move, so it takes the same fail-closed address-only
            // token pool mode mints. `has_l4_ports` and the ICMP-query gate
            // are read exactly as the pool arm below reads them, so the two
            // arms cannot classify one protocol differently.
            let iface_icmp_query =
                matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) && icmp_identifier_present;
            if !crate::ip_proto::has_l4_ports(protocol) && !iface_icmp_query {
                return match alloc.reserve_address_only(flow, rewrite_src, holder) {
                    Ok(_) => SourceNatLookup::Matched(NatDecision {
                        rewrite_src: Some(rewrite_src),
                        rewrite_dst: None,
                        ..NatDecision::default()
                    }),
                    Err(_) => {
                        crate::nat::INTERFACE_SNAT_IDENTITY_EXHAUSTION
                            .fetch_add(1, Ordering::Relaxed);
                        SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                            rule,
                            SourceNatFailureReason::InterfaceIdentityExhausted,
                        ))
                    }
                };
            }
            return match alloc.allocate_interface_identity(flow, rewrite_src, holder) {
                Ok(identity) => SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(rewrite_src),
                    rewrite_dst: None,
                    // PRESERVE-FIRST: an uncontended flow leaves
                    // `rewrite_src_port` unset, so `checksum.rs`'s
                    // `rewrite_src_port.unwrap_or(key.src_port)` keeps the
                    // packet's own port and the wire is byte-identical to
                    // pre-#6751. Only the LATER collider carries `Some(_)`.
                    rewrite_src_port: identity.patted.then_some(identity.port),
                    ..NatDecision::default()
                }),
                Err(reason) => {
                    match reason {
                        SourceNatFailureReason::InterfaceRegistryCap => {
                            crate::nat::INTERFACE_SNAT_REGISTRY_CAP_EXHAUSTION
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            crate::nat::INTERFACE_SNAT_IDENTITY_EXHAUSTION
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    SourceNatLookup::Unavailable(SourceNatFailure::for_rule(rule, reason))
                }
            };
        }
        if rule.pool_mode {
            if let Some(reason) = rule.pool_failure {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(rule, reason));
            }
        } else {
            // This rule matched the zone/addresses but is neither
            // interface-mode nor pool-mode — it applies no translation, so
            // clear the tentatively-captured counter and try the next rule.
            *matched_counter = None;
            continue;
        }
        // #1852: pool-mode SNAT translates the L4 port. A non-first
        // fragment carries no L4 header at the post-IP offset (its
        // "ports" are payload), so allocating a mapping here would both
        // leak a pool port per fragment and write the allocated port into
        // payload bytes. Without datapath reassembly the fragment cannot
        // be correctly port-mapped — drop it (the caller records the
        // exception). Interface-mode SNAT (address-only) already returned
        // above, so it and static NAT keep working on fragments.
        if non_first_fragment {
            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                rule,
                SourceNatFailureReason::NonFirstFragment,
            ));
        }
        // Pool-mode SNAT: pick address by source-IP hash when
        // address-persistent is enabled, otherwise round-robin by family.
        //
        // #3111: only TCP/UDP carry a 16-bit L4 port at offset +0/+2 that
        // pool-mode SNAT may translate via the flow-keyed allocator. A
        // protocol with NO L4 port concept (GRE/ESP/AH/OSPF/ICMP/...) must
        // NOT have a port allocated or written: pick a pool address and
        // leave `rewrite_src_port` unset so the packet rewriter touches
        // ONLY the IP address. Allocating a pseudo-port for these both
        // leaks a pool port per flow AND (via the descriptor fast path)
        // overwrites the first two L4 bytes, corrupting the tunnel header
        // (ESP SPI / GRE flags). The previous gate special-cased only
        // `protocol == 0`, so GRE/ESP/AH/OSPF fell through to
        // `allocate_translation` and were corrupted.
        //
        // #5687: the "L4 tuple unknown" case is the OUT-OF-BAND `tuple_unknown`
        // flag (`protocol == None` at the boundary), NOT the numeric value 0.
        // It is set only by the address-only `match_source_nat` wrapper (never a
        // real packet) and keeps its historical behavior — a round-robin port
        // via `try_next_port` with no flow-keyed mapping — because the packet
        // rewriters gate every L4 write on `has_l4_ports`, so the port it returns
        // can never be written to a frame. A genuine HOPOPT packet arrives as
        // `Some(0)` (`tuple_unknown == false`) and is classified `port_less`
        // below, exactly like GRE/ESP/OSPF: it takes the real address-only path
        // that mints a reverse-identity token, so its reverse tuple matches.
        // #4074 (RFC 5508 §3.1 "ICMP Query Mappings"): an ICMP/ICMPv6 echo or
        // query message carries a 16-bit Query Identifier that the flow parser
        // (`parse_flow_ports`) lifts into `src_port` (with `dst_port == 0`).
        // That identifier is the ICMP demux key — exactly the role a TCP/UDP
        // port plays — so pool-mode SNAT must translate it, or two internal
        // hosts pinging the same target with the same id, both hidden behind
        // one pool address, collide on the reverse tuple (pool_addr, id) and
        // their replies are mis-associated. A non-identifier ICMP control/error
        // message parses flowless (no `SessionFlow`, `icmp_identifier_present`
        // false) and keeps the address-only path — there is no id to translate.
        // `no_translation` (port no-translation) still preserves the id via the
        // `address_only` gate below. The translated id comes from the same pool
        // port/id space as the TCP/UDP PAT allocation (`allocate_translation`).
        //
        // #4088 (RFC 5508 §3.1): classify by the identifier-present signal, NOT
        // by `src_port != 0`. A valid ICMP echo whose Query Identifier is 0
        // must be treated as a real, keyable query (allocate + rewrite +
        // reverse-recover its id like any other), not misread as flowless.
        let icmp_query = matches!(protocol, PROTO_ICMP | PROTO_ICMPV6) && icmp_identifier_present;
        // #5687: gate `port_less` on the OUT-OF-BAND `tuple_unknown` flag, not
        // `protocol != 0`. A real HOPOPT (`Some(0)`, tuple_unknown == false) has
        // no L4 port, so it is port-less like GRE/ESP; the synthetic unknown
        // caller (tuple_unknown == true) is excluded here and handled by the
        // dedicated `tuple_unknown` branches below. `tuple_unknown` is decoded
        // at the top of the function from `protocol.is_none()`.
        let port_less = !tuple_unknown && !crate::ip_proto::has_l4_ports(protocol) && !icmp_query;
        // #3906: `port no-translation` translates the ADDRESS only and PRESERVES
        // the original source port. It takes the same address-only path as a
        // port-less protocol — pick a pool address, leave `rewrite_src_port`
        // unset so the packet rewriter keeps the packet's own source port
        // (checksum.rs `rewrite_src_port.unwrap_or(key.src_port)`). No pool port
        // is allocated. The chosen address is cached per-flow (flow_cache), so
        // the round-robin selection is stable for the flow's lifetime, exactly
        // like the port-less path.
        let address_only = port_less || tuple_unknown || rule.no_translation;
        match src_ip {
            IpAddr::V4(src_v4) if !rule.pool_addresses_v4.is_empty() => {
                // #4559: deterministic CGNAT (mode 1). The subscriber's internal
                // IPv4 fixes both the external pool address and the port block, so
                // no per-flow log is needed to reverse (external IP, port) back to
                // the subscriber. Address-only cases (port-less / no-translation /
                // tuple-unknown) still pick the DETERMINISTIC external address; a
                // REAL address-only flow additionally mints a reverse-identity
                // occupancy token so a colliding second flow fails closed (#5341,
                // mirroring the round-robin/persistent #5269/#5336 fix), while the
                // synthetic tuple-unknown wrapper mints none. The PAT case allocates
                // a port inside the subscriber's fixed block. An out-of-range
                // subscriber fails closed rather than silently round-robining.
                if let Some(det) = rule.deterministic_v4 {
                    if address_only {
                        let Some((ip_idx, _)) = deterministic_indices_v4(&det, src_v4) else {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule,
                                SourceNatFailureReason::DeterministicSubscriberOutOfRange,
                            ));
                        };
                        if ip_idx >= rule.pool_addresses_v4.len() {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule,
                                SourceNatFailureReason::AllocatorExhausted,
                            ));
                        }
                        let pool_addr = rule.pool_addresses_v4[ip_idx];
                        if tuple_unknown {
                            // Synthetic address-only wrapper (protocol == 0, never
                            // a framed packet): keep the historical round-robin port
                            // for the non-no-translation case, or preserve (None)
                            // for no-translation. No occupancy token — there is no
                            // real flow / reverse session entry to disambiguate and
                            // the returned port is never written to a frame.
                            // Symmetric with the round-robin/persistent branch
                            // below (#5269).
                            let port = if rule.no_translation {
                                None
                            } else {
                                match rule.pool_allocator.try_next_port(ip_idx) {
                                    Ok(port) => Some(port),
                                    Err(reason) => {
                                        return SourceNatLookup::Unavailable(
                                            SourceNatFailure::for_rule(rule, reason),
                                        );
                                    }
                                }
                            };
                            return SourceNatLookup::Matched(NatDecision {
                                rewrite_src: Some(IpAddr::V4(pool_addr)),
                                rewrite_dst: None,
                                rewrite_src_port: port,
                                rewrite_dst_port: None,
                                ..NatDecision::default()
                            });
                        }
                        // #5341: a REAL address-only flow on a DETERMINISTIC-CGNAT
                        // (mode 1) pool — `port no-translation` on a port-bearing
                        // protocol, or a port-less protocol (GRE/ESP/...). Like the
                        // round-robin/persistent branch (#5269, fixed in #5336),
                        // mint a reverse-identity occupancy token on the chosen
                        // DETERMINISTIC external address so a second flow that would
                        // collide on the SAME public reverse tuple (two subscribers
                        // sharing one deterministic pool address, same preserved
                        // source port, same remote) is DENIED as exhaustion instead
                        // of receiving an unowned duplicate the reverse (1:N) index
                        // cannot disambiguate. The wire packet keeps its own source
                        // port (rewrite_src_port left None — checksum.rs preserves
                        // it; the port-less frame rewriter is gated on
                        // `has_l4_ports`). The token is freed by the SAME teardown
                        // path (`release_source_nat_allocation` -> `release_flow`)
                        // as the round-robin branch — no new release site, no leak.
                        match rule
                            .pool_allocator
                            .reserve_address_only(flow, IpAddr::V4(pool_addr), NatHolder::Untracked)
                        {
                            Ok(translated) => {
                                return SourceNatLookup::Matched(NatDecision {
                                    rewrite_src: Some(translated.ip),
                                    rewrite_dst: None,
                                    rewrite_src_port: None,
                                    rewrite_dst_port: None,
                                    ..NatDecision::default()
                                });
                            }
                            Err(reason) => {
                                return SourceNatLookup::Unavailable(
                                    SourceNatFailure::for_rule(rule, reason),
                                );
                            }
                        }
                    }
                    let translated = match rule.pool_allocator.allocate_deterministic_v4(
                        flow,
                        &rule.pool_addresses_v4,
                        det,
                        src_v4,
                        holder,
                    ) {
                        Ok(translated) => translated,
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    };
                    // #6979 F6: refuse an identity a peer pool over the same
                    // address already owns. The deterministic parameters
                    // (`host address` base, block size) are NOT part of the
                    // allocator key, so two deterministic pools over one
                    // address can map DIFFERENT subscribers onto the same
                    // external block and neither can see it. And a
                    // deterministic block is fixed per subscriber, so there is
                    // nowhere else for the collider to go — which is exactly
                    // why it must fail closed rather than publish a duplicate.
                    if let Some(failure) =
                        reject_peer_owned_identity(rule, flow, translated, now_ns, holder)
                    {
                        return failure;
                    }
                    return SourceNatLookup::Matched(NatDecision {
                        rewrite_src: Some(translated.ip),
                        rewrite_dst: None,
                        rewrite_src_port: Some(translated.port),
                        rewrite_dst_port: None,
                        ..NatDecision::default()
                    });
                }
                if address_only {
                    let addr_idx = rule.pool_allocator.address_index(
                        src_ip,
                        0,
                        rule.pool_addresses_v4.len(),
                        rule.address_persistent,
                    );
                    let pool_addr = rule.pool_addresses_v4[addr_idx];
                    if tuple_unknown {
                        // Synthetic address-only wrapper (protocol == 0, never a
                        // framed packet): keep the historical round-robin port for
                        // the non-no-translation case, or preserve (None) for
                        // no-translation. No occupancy token — there is no real
                        // flow / reverse session entry to disambiguate and the
                        // returned port is never written to a frame.
                        let port = if rule.no_translation {
                            None
                        } else {
                            match rule.pool_allocator.try_next_port(addr_idx) {
                                Ok(port) => Some(port),
                                Err(reason) => {
                                    return SourceNatLookup::Unavailable(
                                        SourceNatFailure::for_rule(rule, reason),
                                    );
                                }
                            }
                        };
                        return SourceNatLookup::Matched(NatDecision {
                            rewrite_src: Some(IpAddr::V4(pool_addr)),
                            rewrite_dst: None,
                            rewrite_src_port: port,
                            rewrite_dst_port: None,
                            ..NatDecision::default()
                        });
                    }
                    // #5269: a REAL address-only flow (`port no-translation` on a
                    // port-bearing protocol, or a port-less protocol). Mint an
                    // occupancy token for the translated reverse identity so a
                    // second flow that would collide on the same public tuple is
                    // DENIED as exhaustion instead of receiving an unowned
                    // duplicate the reverse (1:N) index cannot disambiguate. The
                    // wire packet still keeps its own source port (rewrite_src_port
                    // left None — checksum.rs preserves it; the port-less frame
                    // rewriter is gated on `has_l4_ports`).
                    //
                    // #6041: when the pool also configures `persistent-nat`, pin a
                    // public ADDRESS across the configured permit scope via an
                    // address-only persistent LEASE (the lease picks/reuses the
                    // address itself, so the round-robin `pool_addr` chosen above
                    // is bypassed — persistence no longer depends on the global
                    // `address-persistent` hash). The per-flow reverse-identity
                    // token is still minted for the #5269 collision guard.
                    let reserved = if rule.persistent_nat {
                        rule.pool_allocator.reserve_address_only_persistent(
                            flow,
                            PoolAddressFamily::V4(&rule.pool_addresses_v4),
                            0,
                            rule.address_persistent,
                            rule.persistent_nat_permit,
                            rule.persistent_nat_timeout_ns,
                            now_ns,
                            holder,
                        )
                    } else {
                        // #6226: probe the WHOLE pool from the round-robin start
                        // (`addr_idx`) so a colliding reverse identity on the
                        // chosen address rotates to a FREE sibling instead of
                        // falsely exhausting. `addr_idx` already advanced the
                        // round-robin counter above; the loop does not advance it
                        // again. `pool_addr` (= pool_addresses_v4[addr_idx]) is
                        // the loop's first probe — identical to the old single
                        // probe when it is free.
                        rule.pool_allocator.reserve_address_only_roundrobin(
                            flow,
                            PoolAddressFamily::V4(&rule.pool_addresses_v4),
                            0,
                            addr_idx,
                            rule.address_persistent,
                            holder,
                        )
                    };
                    match reserved {
                        Ok(translated) => {
                            return SourceNatLookup::Matched(NatDecision {
                                rewrite_src: Some(translated.ip),
                                rewrite_dst: None,
                                rewrite_src_port: None,
                                rewrite_dst_port: None,
                                ..NatDecision::default()
                            });
                        }
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    }
                }
                let translated = match rule.pool_allocator.allocate_translation(
                    flow,
                    PoolAddressFamily::V4(&rule.pool_addresses_v4),
                    0,
                    rule.address_persistent,
                    rule.persistent_nat,
                    rule.persistent_nat_permit,
                    rule.persistent_nat_timeout_ns,
                    now_ns,
                    holder,
                ) {
                    Ok(translated) => translated,
                    Err(reason) => {
                        return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                            rule, reason,
                        ));
                    }
                };
                // #6979 F6: refuse an identity a peer pool over the same
                // address already owns.
                if let Some(failure) =
                    reject_peer_owned_identity(rule, flow, translated, now_ns, holder)
                {
                    return failure;
                }
                return SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(translated.ip),
                    rewrite_dst: None,
                    rewrite_src_port: Some(translated.port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            IpAddr::V6(_) if !rule.pool_addresses_v6.is_empty() => {
                let v6_offset = rule.pool_addresses_v4.len();
                if address_only {
                    let addr_idx = rule.pool_allocator.address_index(
                        src_ip,
                        v6_offset,
                        rule.pool_addresses_v6.len(),
                        rule.address_persistent,
                    );
                    let v6_idx = addr_idx - v6_offset;
                    let pool_addr = rule.pool_addresses_v6[v6_idx];
                    if tuple_unknown {
                        // Synthetic address-only wrapper (protocol == 0): historical
                        // round-robin port (non-no-translation) or preserve (None).
                        // No occupancy token — see the v4 branch above (#5269).
                        let port = if rule.no_translation {
                            None
                        } else {
                            match rule.pool_allocator.try_next_port(addr_idx) {
                                Ok(port) => Some(port),
                                Err(reason) => {
                                    return SourceNatLookup::Unavailable(
                                        SourceNatFailure::for_rule(rule, reason),
                                    );
                                }
                            }
                        };
                        return SourceNatLookup::Matched(NatDecision {
                            rewrite_src: Some(IpAddr::V6(pool_addr)),
                            rewrite_dst: None,
                            rewrite_src_port: port,
                            rewrite_dst_port: None,
                            ..NatDecision::default()
                        });
                    }
                    // #5269: REAL address-only flow — mint a reverse-identity
                    // occupancy token (deny a colliding second flow as exhaustion),
                    // symmetric with the v4 branch above. #6041: route the
                    // `persistent-nat` combination through the address-only
                    // persistent lease so the public address is pinned across the
                    // permit scope (the lease selects the address; the round-robin
                    // `pool_addr` above is bypassed).
                    let reserved = if rule.persistent_nat {
                        rule.pool_allocator.reserve_address_only_persistent(
                            flow,
                            PoolAddressFamily::V6(&rule.pool_addresses_v6),
                            v6_offset,
                            rule.address_persistent,
                            rule.persistent_nat_permit,
                            rule.persistent_nat_timeout_ns,
                            now_ns,
                            holder,
                        )
                    } else {
                        // #6226: probe the WHOLE pool from the round-robin start
                        // (`addr_idx`, absolute over the combined v4+v6 index
                        // space) so a colliding reverse identity on the chosen
                        // address rotates to a FREE sibling instead of falsely
                        // exhausting. `addr_idx` already advanced the round-robin
                        // counter above; the loop does not advance it again.
                        rule.pool_allocator.reserve_address_only_roundrobin(
                            flow,
                            PoolAddressFamily::V6(&rule.pool_addresses_v6),
                            v6_offset,
                            addr_idx,
                            rule.address_persistent,
                            holder,
                        )
                    };
                    match reserved {
                        Ok(translated) => {
                            return SourceNatLookup::Matched(NatDecision {
                                rewrite_src: Some(translated.ip),
                                rewrite_dst: None,
                                rewrite_src_port: None,
                                rewrite_dst_port: None,
                                ..NatDecision::default()
                            });
                        }
                        Err(reason) => {
                            return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                                rule, reason,
                            ));
                        }
                    }
                }
                let translated = match rule.pool_allocator.allocate_translation(
                    flow,
                    PoolAddressFamily::V6(&rule.pool_addresses_v6),
                    v6_offset,
                    rule.address_persistent,
                    rule.persistent_nat,
                    rule.persistent_nat_permit,
                    rule.persistent_nat_timeout_ns,
                    now_ns,
                    holder,
                ) {
                    Ok(translated) => translated,
                    Err(reason) => {
                        return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                            rule, reason,
                        ));
                    }
                };
                // #6979 F6: refuse an identity a peer pool over the same
                // address already owns.
                if let Some(failure) =
                    reject_peer_owned_identity(rule, flow, translated, now_ns, holder)
                {
                    return failure;
                }
                return SourceNatLookup::Matched(NatDecision {
                    rewrite_src: Some(translated.ip),
                    rewrite_dst: None,
                    rewrite_src_port: Some(translated.port),
                    rewrite_dst_port: None,
                    ..NatDecision::default()
                });
            }
            _ => {
                return SourceNatLookup::Unavailable(SourceNatFailure::for_rule(
                    rule,
                    SourceNatFailureReason::WrongAddressFamily,
                ));
            }
        }
    }
    SourceNatLookup::NoMatch
}
