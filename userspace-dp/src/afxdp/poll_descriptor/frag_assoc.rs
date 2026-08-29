// #6386 leaf extraction: the NAT / NAT64 forward fragment-association
// install & consult helpers (#2562/#5146/#5624/#5689) plus the #6122
// fail-closed same-family fragment discriminator, lifted verbatim out
// of poll_descriptor/mod.rs. Attr-verbatim: the four association
// helpers keep their #[inline]; flowless_fragment_requires_nat_translation
// keeps its deliberate #[cold] #[inline(never)]. No non-motion change;
// bodies byte-identical to their prior location.

use super::*;
use super::nat_exception::source_nat_would_translate_fragment;
use super::prerouting_scope::prerouting_ingress_scope;

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
) -> crate::nat64::FragAuthority {
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
    crate::nat64::FragAuthority {
        ingress_ifindex: logical as u32,
        ingress_vlan_id: meta.ingress_vlan_id,
        ingress_zone: zone,
        routing_table: meta.routing_table,
    }
}

/// #2562: on a FIRST NAT64 fragment that translated and will forward, install
/// the fragment association keyed by `(family, src, dst, ip_id, protocol,
/// authority)` (#5798 widened the original `(family, src, dst, ip_id)`) so its
/// non-first fragments inherit `decision` (see `nat64::Nat64FragAssoc`). Gated
/// on a resolved ForwardCandidate — a decision that will NOT forward (no route,
/// missing neighbor) is never cached, so a non-first fragment then misses and
/// drops fail-closed. Only a first fragment (offset 0, MF=1) installs; a
/// non-first fragment can never populate the table.
///
/// #5146: called ONLY at the POST-COMMIT install site (after `can_admit` passes
/// AND the forward session install succeeds), NOT at NAT64 source-allocation
/// time. Publishing pre-commit left the association LIVE behind every rollback
/// arm (hop-limit ICMP-TE bounce, admission refusal, install-partial), and the
/// rollback releases only the pool port — so a non-first fragment of a
/// rolled-back first fragment inherited a rolled-back verdict AND a now-reusable
/// translation (cross-flow NAT64 fragment ambiguity under port reuse). Moving
/// the install to the commit point makes the association visible ONLY on the
/// outcome the anchor fragment actually authorized. Self-gated on
/// `decision.nat.nat64` so it is safe to call unconditionally at the shared
/// commit site next to `nat_install_forward_fragment_assoc`; the two are
/// mutually exclusive (NAT64 vs ordinary same-family), so exactly one fires.
#[inline]
pub(super) fn nat64_install_forward_fragment_assoc(
    forwarding: &ForwardingState,
    l3_packet: &[u8],
    addr_family: i32,
    authority: crate::nat64::FragAuthority,
    decision: &SessionDecision,
    now_ns: u64,
) {
    // #5146: only a genuine NAT64 (cross-family) decision installs here. The
    // ordinary same-family NAT / NPTv6 association is installed by
    // `nat_install_forward_fragment_assoc` (which self-gates the other way), so
    // both can be called at one commit site and exactly one populates the table.
    if !decision.nat.nat64 {
        return;
    }
    if decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
        || decision.resolution.neighbor_mac.is_none()
    {
        return;
    }
    if let Some(key) = crate::nat64::nat64_first_fragment_key(l3_packet, addr_family, authority) {
        // #5624: stamp the association with the generation of the forwarding
        // state that admitted this first fragment. `build_generation` advances
        // on every config reload, so an association installed here is rejected
        // once a later commit changes deny/NAT64 rules.
        forwarding.nat64.frag_assoc.install(
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
}

/// #2562: consult the fragment association for a NON-first NAT64 forward
/// fragment (v6->v4). On a hit whose cached decision is a NAT64 translation,
/// return that decision (resolution + `decision.nat` carrying snat_v4/dst_v4) so
/// the flowless arm inherits the first fragment's permitted verdict + egress and
/// the TX path L3-translates the fragment. A miss returns `None` and the caller
/// falls through to the ordinary flowless drop (fail-closed, #4617). The reverse
/// (v4->v6) consult/install is the deferred increment (see the #2562 PR notes).
#[inline]
pub(super) fn nat64_consult_forward_fragment_assoc(
    forwarding: &ForwardingState,
    l3_packet: &[u8],
    addr_family: i32,
    authority: crate::nat64::FragAuthority,
    now_ns: u64,
    // #6857: the runtime-ownership fence needs to ask whether the association's
    // stamped owner RG is STILL forwarding-active locally.
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::types::HAGroupRuntime>,
    now_secs: u64,
) -> Option<SessionDecision> {
    if addr_family != libc::AF_INET6 {
        return None;
    }
    let key = crate::nat64::nat64_nonfirst_fragment_key(l3_packet, addr_family, authority)?;
    // #5624: consult under the CURRENT forwarding state's generation. An
    // association installed under a prior generation (before a config commit
    // changed deny/NAT64 rules) is treated as a miss + evicted here, so the
    // non-first fragment falls through to the #4617 fail-closed drop instead of
    // inheriting a stale verdict.
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
    // Only a genuine NAT64 forward decision (nat64=true, rewrite_src/dst set)
    // routes to the NAT64 frame builder.
    if !decision.nat.nat64 {
        return None;
    }
    Some(decision)
}

/// #5689: on a FIRST fragment of an ORDINARY same-family NAT / NPTv6 flow that
/// translated and will forward, install a fragment association keyed by
/// `(family, src, dst, ip_id, protocol, authority)` (#5798 widened the original
/// `(family, src, dst, ip_id)`) so its non-first fragments inherit `decision`
/// and translate L3-only (address-only rewrite) instead of being forwarded
/// UNTRANSLATED (the #5689 leak). Mirrors [`nat64_install_forward_fragment_assoc`]
/// but for the SNAT / DNAT / static-NAT / NPTv6 path. It REUSES the generic
/// `Nat64FragAssoc` cache: the key + value are family-agnostic and the `nat64`
/// flag on the cached decision distinguishes a NAT64 entry from an ordinary one
/// (a given datagram installs exactly one entry, so the two never alias). The
/// shared cache is stamped with `build_generation` — which advances on EVERY
/// config commit (`snapshot.generation`), not only NAT64 changes — so a SNAT /
/// DNAT rule change invalidates a stale ordinary-NAT association on lookup.
///
/// Only a first fragment (offset 0, MF=1) carrying a same-family address
/// rewrite whose resolution is a ForwardCandidate with a resolved neighbor
/// installs; a NAT64 decision (its own install stamps reverse info), a decision
/// with no address rewrite, or one that will not forward is never cached, so an
/// unassociated non-first fragment still falls to the flowless default policy.
#[inline]
pub(super) fn nat_install_forward_fragment_assoc(
    forwarding: &ForwardingState,
    l3_packet: &[u8],
    addr_family: i32,
    authority: crate::nat64::FragAuthority,
    decision: &SessionDecision,
    now_ns: u64,
) {
    // Cross-family NAT64 has its own install (which also stamps the reverse
    // info); here we cache only an ordinary same-family address rewrite.
    if decision.nat.nat64
        || (decision.nat.rewrite_src.is_none() && decision.nat.rewrite_dst.is_none())
    {
        return;
    }
    if decision.resolution.disposition != ForwardingDisposition::ForwardCandidate
        || decision.resolution.neighbor_mac.is_none()
    {
        return;
    }
    if let Some(key) = crate::nat64::nat64_first_fragment_key(l3_packet, addr_family, authority) {
        forwarding.nat64.frag_assoc.install(
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
}

/// #5689: consult the fragment association for a NON-first ORDINARY same-family
/// NAT / NPTv6 forward fragment. On a hit whose cached decision carries a
/// same-family address rewrite (SNAT / DNAT / static-NAT / NPTv6, NOT NAT64),
/// return that decision so the flowless arm inherits the first fragment's
/// permitted verdict + egress resolution and the forward-build path
/// L3-translates the fragment (address-only: `apply_nat_ipv4` / `apply_nat_ipv6`
/// skip the L4-checksum + port rewrite for a non-first fragment). A miss returns
/// `None` and the caller falls through to the flowless L3 enforcement (default
/// policy). Unlike the NAT64 forward consult (v6-only) this works for BOTH IPv4
/// and IPv6. The reverse-direction (reply) association is a deferred increment,
/// mirroring the NAT64 forward-only wiring.
///
/// FAIL-CLOSED MISS (#6122, closing the #5689 residual). On a consult MISS —
/// fragment reorder (non-first before first), TTL straddle (> the ~2s
/// `Nat64FragAssoc` TTL between first and non-first), shard-cap eviction under a
/// first-fragment flood, a config-generation bump between first and non-first, or
/// a first fragment that never forwarded (MissingNeighbor/NoRoute → no install) —
/// the caller does NOT blindly forward the fragment untranslated. Instead the
/// flowless arm runs [`flowless_fragment_requires_nat_translation`], a read-only
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
    authority: crate::nat64::FragAuthority,
    now_ns: u64,
    // #6857: the runtime-ownership fence needs to ask whether the association's
    // stamped owner RG is STILL forwarding-active locally.
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::types::HAGroupRuntime>,
    now_secs: u64,
) -> Option<SessionDecision> {
    let key = crate::nat64::nat64_nonfirst_fragment_key(l3_packet, addr_family, authority)?;
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

/// #6122: fail-closed discriminator for the flowless non-first-fragment MISS
/// path. Answers "would this fragment's flow have been translated by an
/// ordinary same-family NAT rule (SNAT / static-NAT / DNAT / NPTv6)?" using
/// ONLY the fragment's L3 identity — source / destination / protocol / ingress
/// + egress zones / interface + routing-instance scope — every part of which a
/// non-first fragment carries in its IP header. When it returns `true` the
/// caller DROPS the fragment (fail-closed) instead of forwarding it
/// UNTRANSLATED (the #6122 leak): a permitted-but-untranslatable NAT'd fragment
/// with no association leaks the internal source (SNAT / NPTv6) or the pre-NAT
/// destination (DNAT). A plain (no-NAT) fragment matches NO rule here and keeps
/// forwarding, so ordinary fragmented forwarding is preserved.
///
/// This is the SAME-FAMILY analog of the NAT64 sibling's fail-closed
/// no-association drop (#4617, `nat64_frag_dropped`); NAT64 (cross-family) is
/// out of scope here. #6835: that used to read "its own consult already drops
/// fail-closed on a miss", which was not true of any code — the consult returns
/// `None`, and `None` only means "no association". The cross-family drop is now
/// a real gate: the Pref64-destination check on the flowless arm in
/// `poll_descriptor/mod.rs`, sitting immediately after this one's call site.
///
/// READ-ONLY / side-effect-free — safe on the miss path: source NAT is
/// consulted with `non_first_fragment = true`, which returns BEFORE minting any
/// pool mapping (a pool-mode match reports `Unavailable`, an
/// interface/static-SNAT match reports an address-only `Matched`); the DNAT /
/// static-DNAT lookups and the NPTv6 boolean probes (run on a scratch copy of
/// the address) allocate no session, BIB, or pool state.
///
/// A non-first fragment carries no L4 ports, so this deliberately matches only
/// ADDRESS/zone-scoped NAT rules: a strictly PORT-scoped DNAT rule does not
/// match `dst_port == 0` and is intentionally NOT flagged (that residual is
/// documented in the `nat64.rs` FEATURES.md row — its common in-order case is
/// covered by the association HIT path, and forwarding such a fragment reaches
/// the pre-DNAT public destination, not an internal source).
#[cold]
#[inline(never)]
pub(super) fn flowless_fragment_requires_nat_translation(
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
    // and it keeps a NAT-free box's fragment path byte-identical to pre-#6122.
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
        // NPTv6 outbound translates the SOURCE prefix on egress; probe a copy.
        let mut probe = src_v6;
        if forwarding.nptv6.translate_outbound(&mut probe, to_zone) {
            return true;
        }
    }
    // Interface / pool / static SNAT — the read-only probe reports a match
    // (including a pool-mode match a fragment can't port-map) without minting
    // any pool mapping or recording a source-NAT allocation failure.
    if source_nat_would_translate_fragment(
        forwarding,
        meta.ingress_ifindex as i32,
        from_zone,
        to_zone,
        egress_ifindex,
        l3_flow,
        now_ns,
    ) {
        return true;
    }

    // --- Destination-based translation (pre-NAT dst leak: DNAT / static-DNAT /
    //     NPTv6 inbound). Matched on the destination address + ingress scope.
    //     Strictly port-scoped DNAT rules do not match `dst_port == 0` and are
    //     intentionally not flagged (documented residual). ---
    let scope = prerouting_ingress_scope(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
        ingress_zone_override,
    );
    if let IpAddr::V6(dst_v6) = l3_flow.dst_ip {
        // NPTv6 inbound translates the DESTINATION prefix on ingress.
        let mut probe = dst_v6;
        if forwarding.nptv6.translate_inbound(&mut probe, scope.zone_name) {
            return true;
        }
    }
    if !forwarding.dnat_table.is_empty()
        && forwarding
            .dnat_table
            .lookup_with_counter_scoped(
                meta.protocol,
                l3_flow.src_ip,
                l3_flow.dst_ip,
                // No L4 ports on a non-first fragment → 0. A port-wildcard
                // (address-only) DNAT rule still matches; a port-specific one
                // does not (documented residual).
                0,
                0,
                scope.zone_name,
                scope.ifname,
                scope.routing_instance,
                None,
            )
            .is_some()
    {
        return true;
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
