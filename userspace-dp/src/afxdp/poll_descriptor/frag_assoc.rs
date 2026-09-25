// #6386 leaf extraction: the NAT / NAT64 forward fragment-association
// install & consult helpers (#2562/#5146/#5624/#5689) plus the #6122/#10679
// fail-closed flowless NAT discriminator, lifted out of poll_descriptor/mod.rs.
// The four association helpers keep their #[inline]; flowless_requires_nat_translation
// keeps its deliberate #[cold] #[inline(never)].

use super::*;
use super::nat_exception::source_nat_would_translate_flowless;
use super::prerouting_scope::prerouting_ingress_scope;

use crate::nat64::Nat64ReverseInfo;
/// #5798: resolve the INGRESS SECURITY AUTHORITY for a fragment, i.e. the
/// domain whose enforcement a cached association is allowed to speak for.
///
/// This is the SSOT both the install and the consult go through, and it is
/// deliberately derived from the SAME ingress inputs the flowless enforcement
/// arm uses — `prerouting_ingress_scope` resolves the logical unit with
/// `resolve_ingress_logical_ifindex` and lets a fabric/tunnel
/// `zone_override` win over the unit's configured zone, so this mirrors it
/// field for field. If the key were derived from different inputs than
/// enforcement, "same key <=> same enforcement domain" would not hold and the
/// fix would leak at the seam.
///
/// `ingress_vlan_id` is carried even though the LOGICAL ifindex normally
/// already encodes the unit: `resolve_ingress_logical_ifindex` falls back to
/// the PHYSICAL ifindex when a unit is unresolvable, and without the VLAN byte
/// two VLAN siblings on one physical port would collapse onto the same
/// authority in exactly that fallback. Keeping it closes that residual.
#[inline]
pub(in crate::afxdp) fn frag_ingress_authority(
    forwarding: &ForwardingState,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
) -> crate::fragment_assoc::FragAuthority {
    let physical = meta.ingress_ifindex as i32;
    let logical =
        resolve_ingress_logical_ifindex(forwarding, physical, meta.ingress_vlan_id)
            .unwrap_or(physical);
    // Zone precedence mirrors prerouting_ingress_scope: a fabric-encoded
    // override wins, else the LOGICAL unit's configured zone (#5802). An
    // unzoned ingress resolves to 0, which is itself a distinct authority —
    // an unzoned interface must not inherit a zoned interface's permit.
    //
    // The override is VALIDATED against zone_id_to_name before it wins (#7050),
    // the same way both sibling consumers of this value do it —
    // prerouting_ingress_scope resolves id->name and falls through on a miss,
    // filter_log_ingress_zone_id applies this exact `contains_key` filter. Taking
    // it raw made the association key and enforcement disagree: enforcement
    // normalizes an unknown id away and uses the logical unit's configured zone,
    // while this stamped the raw id, so two fragments of ONE datagram carrying
    // two DIFFERENT unknown ids built two different keys — an over-scope whose
    // miss is a fail-closed drop — for a datagram enforcement treats as one
    // domain.
    //
    // Not reachable today: the sole production binding of ingress_zone_override
    // comes from parse_zone_encoded_fabric_ingress_from_frame, which already
    // rejects an id absent from zone_id_to_name, and every later shadow can only
    // narrow Some -> None. This closes the gap at the consumer so the three
    // consumers agree by construction rather than by a property of one producer.
    let zone = ingress_zone_override
        .filter(|id| forwarding.zone_id_to_name.contains_key(id))
        .or_else(|| forwarding.ifindex_to_zone_id.get(&logical).copied())
        .unwrap_or(0);
    crate::fragment_assoc::FragAuthority {
        ingress_ifindex: logical as u32,
        ingress_vlan_id: meta.ingress_vlan_id,
        ingress_zone: zone,
        routing_table: meta.routing_table,
    }
}

/// #2562: on a FIRST NAT64 fragment that translated and will forward, install
/// the fragment association keyed by `(family, src, dst, ip_id, protocol,
/// authority)` (#5798 widened the original `(family, src, dst, ip_id)`) so its
/// non-first fragments inherit `decision` (see `nat64::FragAssoc`). Gated
/// on a resolved ForwardCandidate — a decision that will NOT forward (no route,
/// missing neighbor) is never cached, so a non-first fragment then misses and
/// drops fail-closed. Only a first fragment (offset 0, MF=1) installs; a
/// non-first fragment can never populate the table.
///
/// #5146: called ONLY at POST-COMMIT sites — the new-flow commit (after `can_admit`
/// passes AND the forward session install succeeds) AND the #9950 session-hit tail
/// (after revocation/TTL/host-inbound/input-filter, owner-only) — NOT at NAT64
/// source-allocation time. Publishing pre-commit left the association LIVE behind
/// every rollback arm (hop-limit ICMP-TE bounce, admission refusal, install-partial),
/// and the rollback releases only the pool port — so a non-first fragment of a
/// rolled-back first fragment inherited a rolled-back verdict AND a now-reusable
/// translation (cross-flow NAT64 fragment ambiguity under port reuse). Moving the
/// install to the commit points makes the association visible ONLY on the outcome the
/// anchor fragment actually authorized. Self-gated on `decision.nat.nat64` so it is
/// safe to call unconditionally at the shared sites next to
/// `nat_install_forward_fragment_assoc`; the two are mutually exclusive (NAT64 vs
/// ordinary same-family), so exactly one fires. #9950/#10132: the hit tail gates
/// v6-side installs on AF_INET6 and carries `Nat64ReverseInfo` for AF_INET reply
/// associations, which the flowless reverse consult returns to the NAT64 builder.
#[inline]
pub(super) fn nat64_install_forward_fragment_assoc(
    forwarding: &ForwardingState,
    l3_packet: &[u8],
    addr_family: i32,
    authority: crate::fragment_assoc::FragAuthority,
    decision: &SessionDecision,
    now_ns: u64,
    nat64_reverse: Option<Nat64ReverseInfo>,
) -> bool {
    // ordinary same-family NAT / NPTv6 association is installed by
    // `nat_install_forward_fragment_assoc` (which self-gates the other way), so
    // both can be called at one commit site and exactly one populates the table.
    if !decision.nat.nat64 {
        return false;
    }
    if decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
        || decision.resolution.neighbor_mac.is_none()
    {
        return false;
    }
    if let Some(key) = crate::fragment_assoc::first_fragment_key(l3_packet, addr_family, authority) {
        // #5624: stamp the association with the generation of the forwarding
        // state that admitted this first fragment. `build_generation` advances
        // on every config reload, so an association installed here is rejected
        // once a later commit changes deny/NAT64 rules.
        return forwarding.nat64.frag_assoc.install(
            key,
            *decision,
            (addr_family == libc::AF_INET).then_some(nat64_reverse).flatten(),
            now_ns,
            forwarding.nat64.build_generation,
            // #6857: stamp the runtime entitlement this admission rested on, so
            // a later fragment can be refused once the RG stops forwarding
            // locally. The config generation beside it cannot see an RG
            // transition: that changes no config and bumps no snapshot.
            crate::afxdp::forwarding::owner_rg_for_resolution(forwarding, decision.resolution),
        );
    }
    false
}

/// #2562: consult the fragment association for a NON-first NAT64 fragment.
/// On a hit whose cached decision is a NAT64 translation, return the decision
/// plus the optional reverse-info payload needed by an AF_INET reply tail so
/// the flowless request can rebuild IPv6 L3 headers. A miss returns `None` and
/// the caller falls through to the ordinary flowless drop (fail-closed, #4617).
/// #10132 enables both v6 forward and v4 reply association paths; the v4
/// install remains populated only when the session-hit record site supplied
/// `Nat64ReverseInfo`.
#[inline]
pub(super) fn nat64_consult_forward_fragment_assoc(
    forwarding: &ForwardingState,
    l3_packet: &[u8],
    addr_family: i32,
    authority: crate::fragment_assoc::FragAuthority,
    now_ns: u64,
    // #6857: the runtime-ownership fence needs to ask whether the association's
    // stamped owner RG is STILL forwarding-active locally.
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::types::HAGroupRuntime>,
    now_secs: u64,
) -> Option<(SessionDecision, Option<Nat64ReverseInfo>)> {
    let key = crate::fragment_assoc::nonfirst_fragment_key(l3_packet, addr_family, authority)?;
    // #5624: consult under the CURRENT forwarding state's generation. An
    // association installed under a prior generation (before a config commit
    // changed deny/NAT64 rules) is treated as a miss + evicted here, so the
    // non-first fragment falls through to the #4617 fail-closed drop instead of
    // inheriting a stale verdict.
    let (decision, reverse) = forwarding.nat64.frag_assoc.lookup(
        &key,
        now_ns,
        forwarding.nat64.build_generation,
        |rg| {
            ha_state
                .get(&rg)
                .is_some_and(|group| group.is_forwarding_active(now_secs))
        },
    )?;
    // Only a genuine NAT64 decision routes to the NAT64 frame builder.
    if !decision.nat.nat64 {
        return None;
    }
    Some((decision, reverse))
}

/// #5689: on a FIRST fragment of an ORDINARY same-family NAT / NPTv6 flow that
/// translated and will forward, install a fragment association keyed by
/// `(family, src, dst, ip_id, protocol, authority)` (#5798 widened the original
/// `(family, src, dst, ip_id)`) so its non-first fragments inherit `decision`
/// and translate L3-only (address-only rewrite) instead of being forwarded
/// UNTRANSLATED (the #5689 leak). Mirrors [`nat64_install_forward_fragment_assoc`]
/// but for the SNAT / DNAT / static-NAT / NPTv6 path. It REUSES the generic
/// `FragAssoc` cache: the key + value are family-agnostic and the `nat64`
/// flag on the cached decision distinguishes a NAT64 entry from an ordinary one
/// (a given datagram installs exactly one entry, so the two never alias). The
/// shared cache is stamped with `build_generation` — which advances on EVERY
/// config commit (`snapshot.generation`), not only NAT64 changes — so a SNAT /
/// DNAT rule change invalidates a stale ordinary-NAT association on lookup.
/// #9950: fires at BOTH the new-flow commit AND the session-hit tail (forward hits
/// of existing flows + reverse replies, owner-only, post-gate). The hit decision for
/// a reply is already the reverse via `NatDecision::reverse`, keyed by the reply's
/// own tuple + authority — the "forward" in the name means "same-tuple".
///
/// Only a first fragment (offset 0, MF=1) carrying a same-family address
/// rewrite whose resolution is a ForwardCandidate with a resolved neighbor
/// installs; a NAT64 decision (it has its own install), a decision
/// with no address rewrite, or one that will not forward is never cached, so an
/// unassociated non-first fragment still falls to the flowless default policy.
#[inline]
pub(super) fn nat_install_forward_fragment_assoc(
    forwarding: &ForwardingState,
    l3_packet: &[u8],
    addr_family: i32,
    authority: crate::fragment_assoc::FragAuthority,
    decision: &SessionDecision,
    now_ns: u64,
) -> bool {
    // Cross-family NAT64 has its own install; here we cache only an ordinary
    // same-family address rewrite.
    //
    // #7899: same-family entries deliberately pass `reverse: None`. NAT64
    // uses the sibling helper above; #10132 supplies `Nat64ReverseInfo` only
    // for its AF_INET reply association, because the v4->v6 builder needs the
    // original v6 endpoints while same-family replies use their own decision.
    if decision.nat.nat64
        || (decision.nat.rewrite_src.is_none() && decision.nat.rewrite_dst.is_none())
    {
        return false;
    }
    if decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
        || decision.resolution.neighbor_mac.is_none()
    {
        return false;
    }
    if let Some(key) = crate::fragment_assoc::first_fragment_key(l3_packet, addr_family, authority) {
        return forwarding.nat64.frag_assoc.install(
            key,
            *decision,
            None,
            now_ns,
            forwarding.nat64.build_generation,
            // #6857: stamp the runtime entitlement this admission rested on, so
            // a later fragment can be refused once the RG stops forwarding
            // locally. The config generation beside it cannot see an RG
            // transition: that changes no config and bumps no snapshot.
            crate::afxdp::forwarding::owner_rg_for_resolution(forwarding, decision.resolution),
        );
    }
    false
}

/// #5689: consult the fragment association for a NON-first ORDINARY same-family
/// NAT / NPTv6 fragment (forward OR reply — #9950 installs reply entries at the
/// session-hit tail, keyed by the reply's own tuple + authority, so the "forward"
/// in the name means "same-tuple"). On a hit whose cached decision carries a
/// same-family address rewrite (SNAT / DNAT / static-NAT / NPTv6, NOT NAT64),
/// return that decision so the flowless arm inherits the first fragment's
/// permitted verdict + egress resolution and the forward-build path
/// L3-translates the fragment (address-only: `apply_nat_ipv4` / `apply_nat_ipv6`
/// skip the L4-checksum + port rewrite for a non-first fragment). A miss returns
/// `None` and the caller falls through to the flowless L3 enforcement (default
/// policy). Unlike the NAT64 forward consult (v6-only) this works for BOTH IPv4
/// and IPv6.
///
/// FAIL-CLOSED MISS (#6122, closing the #5689 residual). On a consult MISS —
/// fragment reorder (non-first before first), TTL straddle (> the ~2s
/// `FragAssoc` TTL between first and non-first), shard-cap eviction under a
/// first-fragment flood, a config-generation bump between first and non-first, or
/// a first fragment that never forwarded (MissingNeighbor/NoRoute → no install) —
/// the caller does NOT blindly forward the fragment untranslated. Instead the
/// flowless arm runs [`flowless_requires_nat_translation`], a read-only
/// NAT'd-miss vs no-NAT-miss discriminator: if a SNAT / static-NAT / DNAT /
/// NPTv6 rule WOULD translate the fragment's L3 identity, the
/// permitted-but-untranslatable fragment is DROPPED fail-closed (counted as
/// `nat_frag_untranslated_dropped`) rather than leaking the internal source
/// (SNAT / NPTv6) or the pre-NAT destination (DNAT); if NO rule matches, the
/// plain fragment forwards exactly as before, so ordinary un-NAT'd fragmented
/// traffic is never blackholed. This brings the same-family arm into line with
/// the NAT64 sibling (whose no-association non-first fragment already drops
/// fail-closed, #4617). The pre-#6122 behavior forwarded the miss UNTRANSLATED
/// (the deliberate fail-OPEN asymmetry #5689 documented as a tracked follow-up);
/// the discriminator is what finally makes the miss fail-closed without
/// over-dropping.
#[inline]
pub(super) fn nat_consult_forward_fragment_assoc(
    forwarding: &ForwardingState,
    l3_packet: &[u8],
    addr_family: i32,
    authority: crate::fragment_assoc::FragAuthority,
    now_ns: u64,
    // #6857: the runtime-ownership fence needs to ask whether the association's
    // stamped owner RG is STILL forwarding-active locally.
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::types::HAGroupRuntime>,
    now_secs: u64,
) -> Option<SessionDecision> {
    let key = crate::fragment_assoc::nonfirst_fragment_key(l3_packet, addr_family, authority)?;
    let (decision, _reverse) = forwarding.nat64.frag_assoc.lookup(
        &key,
        now_ns,
        forwarding.nat64.build_generation,
        |rg| {
            ha_state
                .get(&rg)
                .is_some_and(|group| group.is_forwarding_active(now_secs))
        },
    )?;
    // Only an ordinary same-family NAT / NPT rewrite routes here; a NAT64
    // (cross-family) association is handled by `nat64_consult_forward_fragment_assoc`.
    if decision.nat.nat64
        || (decision.nat.rewrite_src.is_none() && decision.nat.rewrite_dst.is_none())
    {
        return None;
    }
    Some(decision)
}

/// #6122/#10679: fail-closed discriminator for a flowless packet whose
/// ordinary same-family NAT / NPTv6 decision is unavailable. Answers "would this
/// flow have been translated?" using ONLY its L3 identity — source / destination
/// / protocol / ingress + egress zones / interface + routing-instance scope.
/// A flowless non-first fragment that missed the association, or an unfragmented
/// flowless packet such as ESP/GRE/AH, has no flow/session carrying the
/// translation decision. When this returns `true` the caller DROPS rather than
/// forwarding with the default no-NAT decision, which would leak the internal
/// source (SNAT / NPTv6) or the pre-NAT destination (DNAT). A plain (no-NAT)
/// flowless packet matches no rule and keeps forwarding.
///
/// This is READ-ONLY / side-effect-free: source NAT is consulted through
/// `source_nat_would_translate_flowless`, which reports pool-mode matches before
/// allocating a mapping. DNAT / static-DNAT lookups and NPTv6 probes (on scratch
/// address copies) allocate no session, BIB, or pool state.
///
/// A flowless packet has no L4 ports. Address-only NAT is checked by the
/// ordinary read-only probes; L4-scoped rules are separately treated as
/// possible when their known scope/address/protocol attributes allow a match.
/// Protocol 255 is the non-first-fragment unknown sentinel, not a reason to
/// inspect packet bytes.
#[inline(never)]
pub(super) fn flowless_requires_nat_translation(
    forwarding: &ForwardingState,
    l3_flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    from_zone_id: u16,
    to_zone_id: u16,
    egress_ifindex: i32,
    now_ns: u64,
) -> bool {
    // Fast-out when NO same-family NAT is configured at all — the common case,
    // and it keeps a NAT-free box's flowless path byte-identical to pre-#6122.
    if forwarding.source_nat_rules.is_empty()
        && forwarding.static_nat.is_empty()
        && forwarding.dnat_table.is_empty()
        && forwarding.nptv6.is_empty()
    {
        return false;
    }
    let from_zone: &str = forwarding
        .zone_id_to_name
        .get(&from_zone_id)
        .map(|s| s.as_str())
        .unwrap_or("");
    let to_zone: &str = forwarding
        .zone_id_to_name
        .get(&to_zone_id)
        .map(|s| s.as_str())
        .unwrap_or("");

    // --- Source-based translation (internal-source leak: NPTv6 outbound /
    //     interface-SNAT / pool-SNAT / static-SNAT). Matched on the source
    //     address + ingress/egress zones + egress scope, all L3-only. ---
    if let IpAddr::V6(src_v6) = l3_flow.src_ip {
        // An Untranslatable NPTv6 result is NAT-relevant too: a flowless
        // packet must not fall through and forward the address unchanged.
        let mut probe = src_v6;
        match forwarding
            .nptv6
            .translate_outbound_result(&mut probe, to_zone)
        {
            crate::nptv6::Nptv6Translation::NoMatch => {}
            crate::nptv6::Nptv6Translation::Translated
            | crate::nptv6::Nptv6Translation::Untranslatable => return true,
        }
    }
    // Interface / pool / static SNAT — the read-only probe reports a match
    // (including a pool-mode match a flowless packet cannot port-map) without
    // minting any pool mapping or recording a source-NAT allocation failure.
    if source_nat_would_translate_flowless(
        forwarding,
        meta.ingress_ifindex as i32,
        // #9956 F-052: the packet's OWN VLAN, used to resolve logical ingress
        // scope for this per-packet NAT decision.
        meta.ingress_vlan_id,
        from_zone,
        to_zone,
        egress_ifindex,
        l3_flow,
        now_ns,
    ) {
        return true;
    }
    if flowless_nat_rule_possible(
        forwarding,
        l3_flow,
        meta,
        ingress_zone_override,
        from_zone_id,
        to_zone_id,
        egress_ifindex,
        false,
    ) {
        return true;
    }


    // --- Destination-based address-only translation (pre-NAT dst leak:
    // DNAT / static-DNAT / NPTv6 inbound). Port-/protocol-scoped NAT candidates
    // were checked above without inventing an L4 tuple. ---
    let scope = prerouting_ingress_scope(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        ingress_zone_override,
    );
    if let IpAddr::V6(dst_v6) = l3_flow.dst_ip {
        let mut probe = dst_v6;
        match forwarding
            .nptv6
            .translate_inbound_result(&mut probe, scope.zone_name)
        {
            crate::nptv6::Nptv6Translation::NoMatch => {}
            crate::nptv6::Nptv6Translation::Translated
            | crate::nptv6::Nptv6Translation::Untranslatable => return true,
        }
    }
    if !forwarding.dnat_table.is_empty() {
        // The native-fragment 255 protocol is unknown, not a concrete DNAT
        // protocol. Probe the configured concrete-protocol buckets and the
        // protocol-agnostic fallback without attempting protocol recovery.
        let dnat_match = if meta.protocol == crate::session::SHIM_PROTO_FRAGMENT_NO_L4 {
            forwarding
                .dnat_table
                .has_unknown_protocol_translation_match_scoped(
                    l3_flow.src_ip,
                    l3_flow.dst_ip,
                    // No L4 ports on a non-first fragment → 0. A
                    // port-wildcard (address-only) DNAT rule still matches; a
                    // port-specific one does not (documented residual).
                    0,
                    0,
                    scope.zone_name,
                    scope.ifname,
                    scope.routing_instance,
                    None,
                )
        } else {
            forwarding
                .dnat_table
                .lookup_with_counter_scoped(
                    meta.protocol,
                    l3_flow.src_ip,
                    l3_flow.dst_ip,
                    0,
                    0,
                    scope.zone_name,
                    scope.ifname,
                    scope.routing_instance,
                    None,
                )
                .is_some()
        };
        if dnat_match {
            return true;
        }
    }
    if forwarding
        .static_nat
        .match_dnat_with_counter_scoped(
            l3_flow.dst_ip,
            0,
            Some(l3_flow.src_ip),
            scope.zone_name,
            scope.ifname,
            scope.routing_instance,
        )
        .is_some()
    {
        return true;
    }
    false
}
/// #10679: a `NoRoute` disposition has no resolved egress, but a permitted
/// flowless frame can still be reinjected to the kernel FIB. Probe every
/// configured egress, since the kernel may resolve the destination to any of
/// them after reinjection; using egress index 0 would make source-NAT matching
/// return `NoMatch` before the rule is examined.
#[cold]
#[inline(never)]
pub(super) fn flowless_no_route_requires_nat_translation(
    forwarding: &ForwardingState,
    l3_flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    from_zone_id: u16,
    now_ns: u64,
) -> bool {
    let mut has_egress_identity = false;
    for &egress_ifindex in forwarding
        .ifindex_to_config_name
        .keys()
        .chain(forwarding.ifindex_to_routing_instance.keys())
        .chain(forwarding.ifindex_to_zone_id.keys())
        .chain(forwarding.ifindex_unambiguous_zone_id.keys())
        .chain(forwarding.egress.keys())
    {
        has_egress_identity = true;
        if flowless_requires_nat_translation(
            forwarding,
            l3_flow,
            meta,
            ingress_zone_override,
            from_zone_id,
            forwarding.egress_zone_id(egress_ifindex),
            egress_ifindex,
            now_ns,
        ) {
            return true;
        }
    }
    if !has_egress_identity || forwarding.egress.is_empty() {
        // Without an egress row, the kernel may resolve a reinjected packet to
        // an interface NAT cannot match here. Preserve the fail-closed fallback
        // even after probing the configured interface-index maps.
        return flowless_requires_nat_translation(
            forwarding,
            l3_flow,
            meta,
            ingress_zone_override,
            from_zone_id,
            0,
            0,
            now_ns,
        ) || !forwarding.source_nat_rules.is_empty()
            || !forwarding.static_nat.is_empty()
            || !forwarding.nptv6.is_empty();
    }
    false
}

/// #10679: Identify same-family NAT rules that could match using only the
/// known L3/scope fields. Protocol 255 is the unknown sentinel, so rule matches
/// are treated as possible and no packet-header protocol recovery is needed.
#[cold]
#[inline(never)]
pub(super) fn flowless_nat_rule_possible(
    forwarding: &ForwardingState,
    l3_flow: &SessionFlow,
    meta: UserspaceDpMeta,
    ingress_zone_override: Option<u16>,
    from_zone_id: u16,
    to_zone_id: u16,
    egress_ifindex: i32,
    require_l4_selector: bool,
) -> bool {
    let from_zone = forwarding
        .zone_id_to_name
        .get(&from_zone_id)
        .map_or("", String::as_str);
    let to_zone = forwarding
        .zone_id_to_name
        .get(&to_zone_id)
        .map_or("", String::as_str);
    let nat_scope = crate::afxdp::forwarding::nat_scope_ctx_for_flow(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        egress_ifindex,
        l3_flow.forward_key.routing_domain,
    );
    let source_nat_possible = if require_l4_selector {
        forwarding.source_nat_rules.iter().any(|rule| {
            rule.matches_scoped_l4_non_first_fragment(
                &nat_scope,
                from_zone,
                to_zone,
                l3_flow.src_ip,
                l3_flow.dst_ip,
                meta.protocol,
            )
        })
    } else {
        crate::nat::flowless_source_nat_rule_possible(
            &forwarding.source_nat_rules,
            &nat_scope,
            from_zone,
            to_zone,
            l3_flow.src_ip,
            l3_flow.dst_ip,
            meta.protocol,
            false,
        )
    };
    if source_nat_possible {
        return true;
    }

    let ingress = prerouting_ingress_scope(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        ingress_zone_override,
    );
    if forwarding.dnat_table.flowless_l4_translation_possible(
        meta.protocol,
        l3_flow.src_ip,
        l3_flow.dst_ip,
        ingress.zone_name,
        ingress.ifname,
        ingress.routing_instance,
    ) {
        return true;
    }
    forwarding.static_nat.flowless_l4_translation_possible(
        meta.protocol,
        l3_flow.src_ip,
        l3_flow.dst_ip,
        ingress.zone_name,
        ingress.ifname,
        ingress.routing_instance,
        to_zone,
        nat_scope.egress_ifname,
        nat_scope.egress_routing_instance,
    )
}

/// #10130/#10674: session-gated reverse discriminator for a same-family reply
/// tail that missed its fragment association. Unlike a rules-only reverse arm,
/// this asks the worker's live session table whether a forward NAT session has
/// the same reverse L3 addresses. Real-protocol probes require an exact protocol
/// match; a native shim 255 sentinel is treated as an unknown-protocol wildcard.
/// Plain outbound traffic from a translated target therefore has no matching
/// session and remains forwardable.
#[inline]
pub(super) fn session_gated_reverse_fragment_requires_nat_translation(
    sessions: &crate::session::SessionTable,
    l3_flow: &SessionFlow,
    meta: UserspaceDpMeta,
    now_ns: u64,
) -> bool {
    let reply_key = crate::session::l3_reverse_probe(
        l3_flow.src_ip,
        l3_flow.dst_ip,
        meta.protocol,
        meta.addr_family,
    );
    sessions.reverse_nat_fragment_requires_translation(
        &reply_key,
        l3_flow.forward_key.routing_domain,
        now_ns,
    )
}

