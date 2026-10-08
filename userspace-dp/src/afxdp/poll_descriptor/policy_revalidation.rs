//! #8356: re-derive ZONE POLICY on the established-session hit path.
//!
//! # The residual this closes
//!
//! #7323 closed on option B — accept that a peer-synced imported session
//! carries the PEER's zone-policy verdict and the receiver never re-asks its
//! own. Input FILTERS are already re-derived on this path (#7212), so the
//! residual was precisely: *a flow the receiver's newer zone policy would deny,
//! whose input filters permit it, surviving as an imported session until it
//! ends.* This module closes it receiver-locally — no wire field, no
//! negotiation, no `ProtocolVersion` bump, so it also protects against an OLD
//! sender during a rolling upgrade.
//!
//! Scope is EVERY session, not only peer-synced imports. #5858/#7212 already
//! tears down a live, locally-admitted session when a commit narrows an input
//! FILTER; not doing the same when a commit narrows ZONE POLICY is the
//! asymmetry, not a safe default.
//!
//! # Host-bound sessions (#9563)
//!
//! A `LocalDelivery` session is declined. Every local-delivery resolution sets
//! `egress_ifindex` to the LOCAL interface, so a zone-pair re-derivation would ask
//! `from -> the local interface's own zone`. Host-inbound admission never
//! consulted that pair, and the re-derivation revoked the session on its owner's
//! first ACK. Host-bound authority is the host-inbound gate plus `to-zone
//! junos-host` policy, and the established-hit path re-evaluates both on every
//! host-bound packet.
//!
//! # TUN-originated sessions (#10038)
//!
//! A FORWARD whose marker says the firewall itself originated it
//! (`tun_origin_forward`: synced-family origin, no ingress identity, tunnel
//! endpoint set, no admitting policy counter) is declined — on BOTH the
//! forward arm and the #9604 reverse-companion arm. Junos runs no security
//! policy on firewall-self-originated traffic (#6224), so there is no
//! admitting pair to re-derive; judging the tunnel zone pair and revoking on
//! the default deny is the #9563 error shape (a pair admission never
//! consulted). Such sessions live by idle timeout, never by policy
//! revocation — the documented tightening asymmetry (host-bound forward
//! sessions still die on tighten; TUN-origin solicited flows survive).
//! The marker ALSO gates the host-inbound/junos-host exemption on the
//! LocalDelivery HIT arm (`tun_origin_reverse_exempt` below): the two share
//! one predicate so #9604 and the HIT gate can never disagree about what
//! "TUN-originated" means.
//!
//! # Fabric-redirected sessions (#7770, with #9604)
//!
//! A `FabricRedirect` entry is judged on its RECORDED egress zone. Its stored
//! egress names the fabric transport, not the flow's egress, so a live
//! to-zone resolution asks `from -> fabric` — a pair admission never
//! evaluated — and revokes the session on its first post-install hit in
//! either direction. The punt seed is adjudicated on the pre-redirect egress
//! zone and records it, so the recorded zone is the pair the permit came
//! from.
//!
//! # ICMP scope (#8618)
//!
//! #8356 shipped declining ICMP outright, leaving #7323's residual open for
//! that protocol alone. #8618 narrows the decline to the configs where it is
//! actually earned: `packet_icmp` is read in exactly ONE place in policy
//! evaluation — the `icmp_constraints` arm of `CompiledApplications::matches`
//! (#3020, `junos-icmp-ping`) — and the gate arms when an active PERMIT rule carries a
//! type-constrained term.
//!
//! #9386: what the type-blind `None` guarantees within this frame-independent
//! derivation is that it can never MANUFACTURE a false DENY, NOT that the
//! verdict equals a fully-informed one. The `icmp_constraints` arm is
//! action-BLIND, so a type-constrained DENY is skipped here and the walk may
//! fall through to a later, more permissive rule. This derivation therefore
//! cannot use that DENY to revoke the session.
//!
//! That does not leave packet forwarding blind: #11064 adds an owner/foreign
//! session-hit check that evaluates constrained rules with the current packet's
//! type/code and drops a denied packet without confusing its type with the
//! typeless session identity. See `PolicyState::icmp_verdict_may_depend_on_type`
//! for why this separate, frame-independent gate remains permit-only.
//!
//! Where such a permit DOES exist the decline stands, and it must: a type-blind
//! evaluation would fail to match the type-specific permit, manufacture a DENY,
//! and revoke a flow the policy allows. That is strictly worse than the
//! residual. The gating predicate
//! (`PolicyState::icmp_verdict_may_depend_on_type`) is whole-snapshot and so
//! deliberately conservative — one `junos-icmp-ping` permit anywhere declines ICMP
//! box-wide, i.e. exactly #8356 — because a per-zone-pair answer would mean
//! reproducing the five-tier applicability selection at a second site, and a
//! tier missed there fails in the direction that revokes live flows.
//!
//! # THREE things here deliberately do NOT mirror #7212
//!
//! **1. The reverse pair is never independently adjudicated for revocation — but reverse HITS are (#9604).**
//! The filter stamp is per-direction on purpose. The reverse companion's own
//! pair must not be. The reverse companion is built with SWAPPED zones
//! (`afxdp/shared_ops.rs`: `ingress_zone: forward.metadata.egress_zone`,
//! `egress_zone: forward.metadata.ingress_zone`; `poll_descriptor/mod.rs` does
//! the same with `to_zone_id`/`from_zone_id`). This is a STATEFUL firewall — a
//! reply is permitted because the session exists, not because a policy admits
//! (to_zone -> from_zone). Re-deriving on the reverse entry would evaluate the
//! reversed pair, find no rule on any ordinary one-way policy set, hit the
//! default deny, and revoke. Per-direction, that revokes EVERY established
//! session in the box on the first packet after ANY commit. It would also pass
//! a test whose fixture uses a symmetric or allow-all policy, which is why the
//! cell for it uses an asymmetric one.
//!
//! What #9604 adds instead: a stale reverse hit resolves its FORWARD companion
//! (`reverse_session_key` with the reverse entry's own nat — the same hop the
//! teardown uses) and re-asks zone policy for the FORWARD tuple, protocol and
//! zones. The reverse entry contributes nothing to the verdict but its
//! staleness and its nat. A lone reverse (no forward companion) and a
//! companion slot holding another reverse both decline — deriving authority
//! from swapped zones is exactly the trap above. The sibling half of the
//! constraint: the foreign path (`session_hit_authority.rs`,
//! `foreign_hit_verdict`) evaluates a foreign reverse packet AS A PACKET for
//! forward/drop only and can never revoke from it — so no path in the tree
//! tears down a session on the verdict of a reverse pair judged as itself.
//!
//! **2. GENERATION-ONLY stamp.** `FilterRevalidationStamp` is keyed
//! `(generation, logical ingress ifindex)` because an input filter is a
//! per-INTERFACE object. A zone-policy verdict is keyed on the (from, to) zone
//! PAIR, which is a property of the FLOW rather than of any one interface, so
//! the stamp does not vary with the arrival interface. (#9384: the from-zone is
//! now RESOLVED from the arrival interface, which is a different statement —
//! the KEY is still the generation alone, deliberately, because a flow has one
//! zone pair and re-deriving it per arrival interface would let a multi-homed
//! arrival re-ask once per interface.) See
//! `SessionEntry::policy_revalidated_gen`.
//!
//! **3. Side-effect freedom is a property of the CALL, enforced by a test — it
//! is NOT structural (#9385).** This item used to say the opposite, and the
//! reasoning was half right in a way that mattered: `evaluate_policy_result_*`
//! does take `&PolicyState` and does RETURN a counter handle
//! (`policy_counter_idx`) for the caller to bump, and this module never bumps
//! what it is handed. But the EVALUATION counts internally — `try_match_rule`
//! calls `rule.hit_counter.add` on every match and the implicit-default path
//! calls `state.default_counter.add` — and `&PolicyState` does not prevent it,
//! because those counters are ATOMICS behind shared references, so an immutable
//! borrow is not the guarantee the claim rested on. Passing `packet_len = 0` did
//! not help either: the zero-length gate in `HitCounter::add` covers BYTES only
//! and the packet increment is unconditional. So every re-derivation recorded a
//! PHANTOM hit on whichever rule (or the implicit default) it matched, inflating
//! `show security policies hit-count` by up to one packet per live session per
//! config generation — arriving at exactly the moment an operator is watching
//! hit-count to confirm a narrowing took effect.
//!
//! The filter needed `NonRoutingCountPolicy::Never` for precisely this reason
//! and this module now needs the same thing: it calls
//! `evaluate_policy_result_without_counting_at` (`PolicyHitCount::Never`), and the
//! freedom is bound by a counter-DELTA assertion with a positive control, not by
//! a type signature. A stated structural guarantee that is not structural is
//! worse than no claim, because it invites the next side effect into this path.
//!
//! # The revoke predicate is PERMIT-or-not, and `reject` tears down SILENTLY (#9381)
//!
//! `PolicyAction` is THREE-valued: `Permit` / `Deny` / `Reject` (`policy.rs`).
//! Admission requires `Permit` and treats `Reject` as terminal non-forwarding,
//! so this arm must too — it tests for `Permit` POSITIVELY rather than for
//! `Deny` negatively. Spelled `!matches!(.., Deny)` (as it was until #9381) the
//! third action silently joined the permit arm and was re-STAMPED, so a commit
//! narrowing `permit` -> `reject` enforced the new verdict on new flows while
//! every established session admitted by that rule kept forwarding until idle
//! timeout — and a later packet of the same generation never re-asked. The
//! positive spelling also fails CLOSED for any fourth action added later.
//!
//! **A revoked-by-reject session is torn down SILENTLY: no ICMP unreachable, no
//! TCP RST, no log, no counter — identical to the `Deny` teardown.** That is a
//! decision, not an omission, for two reasons. First, this derivation is
//! side-effect-free by contract (see item 3 below): minting a reject reply needs
//! the frame, the TX pipeline and the deny-event emitter, which is the whole
//! class of side effect the contract excludes. Second, it is not a loss of
//! operator-visible behaviour: the teardown also evicts both directions'
//! flow-cache slots, so the NEXT packet of that 5-tuple is a session MISS and
//! takes the full admission path, which evaluates `Reject` and emits the
//! reject reply + RT_FLOW deny record from the site that owns them
//! (`reject_reply.rs`). The reject semantics arrive one packet later, from one
//! place, rather than being duplicated here.
//!
//! # The evaluated DESTINATION is the POST-translation one (#9382)
//!
//! Admission evaluates zone policy on the POST-translation destination tuple
//! (#2345/#2358) and this derivation must ask the SAME question, or a session
//! with an inbound destination translation is judged by two different standards.
//! The forward entry is keyed on the WIRE tuple, so reading the destination off
//! `flow` gives the VIP — the address admission REFUSES to match a rule against.
//! Until #9382 that made a permit naming the real server contribute nothing:
//! the derivation matched no rule, fell to the default policy, and revoked a
//! session whose policy had not changed at all. The destination now comes from
//! the entry's `decision.nat` (`rewrite_dst` / `rewrite_dst_port`), which is the
//! same quantity admission folds into `policy_dst_ip` / `policy_dst_port` for
//! DNAT, static-DNAT, NPTv6 and NAT64 alike. The SOURCE stays pre-translation
//! in both places: Junos evaluates after destination NAT and before source NAT.
//!
//! # FIB-stale routing and policy re-judgment
//!
//! #9384: BOTH zones are now read through the LIVE ledger — `to_id` from the
//! egress interface resolved at install/import time, `from_id` from the
//! interface THIS packet arrived on (fabric ingress excepted, see below). So a
//! commit that moves an interface between zones is caught on either side. Until
//! #9384 the from-zone came from the session ENTRY, so the sentence below was
//! true of the EGRESS half only and the claim above it was not qualified:
//! moving an interface OUT of a permitted zone did not tear down its live
//! sessions.
//!
//! #11373: a FIB-stale established hit performs a fresh routing lookup and
//! persists the new resolution. #12074: if that lookup changes the policy
//! egress zone, only that entry's policy stamp is made stale so the ordinary
//! hit path re-derives its (from-zone, to-zone) verdict. A reply-only hit also
//! checks the forward companion's FIB generation: even a Fresh reverse stamp
//! and `LiveEgress` provenance cannot judge the old forward route. It resolves
//! and judges the current forward pair; on permit it persists that route while
//! leaving forward policy stamping unchanged. A same-zone route move retains
//! its policy verdict, session and NAT. Dormant sessions are not walked
//! eagerly; route refresh and any required policy re-judgment happen on hit.
//!
//! #11075's generation-advance alarm therefore reports live sessions awaiting
//! lazy re-resolution at that observation, not a residual of established
//! sessions staying pinned to old routes or bypassing zone policy. Every worker
//! watches its validation's fib_generation each tick: on advance with live
//! sessions, it bumps ROUTE_CHANGE_UNREJUDGED_SESSIONS_TOTAL and rate-limits one
//! journal line reporting the count. The trigger is bounded (fires once per
//! generation step per worker) and performs no routing evaluation itself, so
//! #2620 holds.

use super::*;
use crate::afxdp::FastMap;
use crate::afxdp::worker::SyncedSessionEntry;
use crate::nat::NatDecision;
use crate::policy::evaluate_policy_result_without_counting_at;
use crate::session::{
    PolicyGateAnswer, PolicyGateCurrent, PolicyRevalidationKind, PolicyRevalidationTarget,
    SessionDecision, SessionKey, SessionMetadata, SessionOrigin, SessionTable,
    SourceNatRevalidationTarget,
};
use std::sync::{Arc, Mutex};

/// A zone-policy re-derivation that came back NON-PERMIT (`Deny` or `Reject`,
/// #9381). Carries the CANONICAL key — the primary-index key, which on the NAT
/// reverse-translated alias path is NOT the wire tuple that found it — AND the
/// judged entry's own triple, so the teardown acts on the session that was
/// actually judged, with the decision, metadata and origin it was judged with.
/// On the forward path these are the hit entry's; on the reverse path (#9604)
/// they are the FORWARD companion's. Key and nat must belong to the SAME
/// direction entry: `delete_terminal_filtered_session` and
/// `collect_revoked_flow_cache_keys` both derive the companion from the
/// carried nat, and a mismatched pairing misses it (see §5.3 of the #9604 plan).
///
/// #10582: `canonical_key` is `None` for a SESSIONLESS revocation — a forward
/// judgment derived with no local entry (the keep_transient peer-synced hit,
/// or a stale primary handle). The caller drops the packet without session
/// teardown or flow-cache eviction: there is no entry, and the teardown would
/// emit a close delta and release NAT state for a flow this node never owned.
/// Mirrors #8114's `revoked_key: None`.
/// #11075: cumulative count of established sessions present when workers
/// observe a FIB-generation advance, before each stale entry is lazily
/// re-resolved on its next hit. #11373 performs that route lookup, and #12074
/// re-judges zone policy when the resulting egress zone changes; this metric
/// counts deferred work, not sessions that remain pinned or bypass policy.
/// Bumped once per worker per generation step with its live session count.
pub(crate) static ROUTE_CHANGE_UNREJUDGED_SESSIONS_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// #11075: minimum interval between route-change alarm lines from one worker.
pub(crate) const ROUTE_CHANGE_ALARM_INTERVAL_NS: u64 = 60_000_000_000;

/// #11075: pure edge predicate for the route-change alarm. Fires when the
/// worker's validation advanced to a new FIB generation while sessions are
/// live, at most once per interval. Unit-testable; the worker tick wires it.
pub(crate) fn should_alarm_route_change(
    last_fib_generation: u32,
    live_fib_generation: u32,
    live_sessions: usize,
    last_alarm_ns: u64,
    now_ns: u64,
) -> bool {
    live_fib_generation != last_fib_generation
        && live_sessions > 0
        && (last_alarm_ns == 0
            || now_ns.saturating_sub(last_alarm_ns) >= ROUTE_CHANGE_ALARM_INTERVAL_NS)
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PolicyRevocationReason {
    ZonePolicy,
    StaleSourceNat,
}

pub(super) struct PolicyRevocation {
    pub(super) canonical_key: Option<SessionKey>,
    pub(super) decision: SessionDecision,
    pub(super) metadata: SessionMetadata,
    pub(super) origin: SessionOrigin,
    pub(super) reason: PolicyRevocationReason,
}

/// #9604: where the cold judgment reads the FROM-zone from. A
/// locally-authored ingress identity is resolved live through the ledger,
/// exactly as the forward hit path resolves the packet's arrival; a recorded
/// zone (peer-authored or fabric identities, #6928) is used as-is.
#[derive(Clone, Copy)]
enum FromZoneSource {
    /// Live-resolve through the ledger from this ingress identity.
    LiveIfindex { ifindex: i32, vlan: u16 },
    /// Use the judged entry's recorded ingress zone.
    RecordedZone(u16),
}

/// #9604: what the cold judgment evaluates — always a FORWARD pair, no matter
/// which direction's packet triggered it. Every evaluated field (tuple, ports,
/// protocol, zones) is sourced from the forward entry; the reverse pair is
/// never adjudicated as its own pair (GATE 1's reason, structural).
struct PolicyJudgmentInput {
    /// Its NAT (post-translation dst, #9382) and egress.
    decision: SessionDecision,
    /// Its recorded zones (the `RecordedZone` fallback) and fabric flag.
    metadata: SessionMetadata,
    /// The JUDGED protocol — the forward key's, never the triggering packet's
    /// (under NAT64 the reply's family differs from the judgment's).
    protocol: u8,
    /// Forward wire tuple (source stays pre-translation, Junos order).
    src_ip: IpAddr,
    dst_ip: IpAddr,
    /// Forward wire ports.
    src_port: u16,
    dst_port: u16,
    from_source: FromZoneSource,
    now_ns: u64,
}

/// Check whether a stored forward source translation remains expressible by
/// the same live NAT branch for its original tuple. This is read-only: it
/// never allocates a replacement address, port, or interface-NAT identity.
/// Static and dynamic SNAT can produce identical tuples, so equality of the
/// translated address alone is not enough to carry authorization across a
/// config generation.
fn source_nat_translation_still_valid(
    forwarding: &ForwardingState,
    decision: &SessionDecision,
    metadata: &SessionMetadata,
    forward_key: &SessionKey,
    stored_static: Option<bool>,
) -> (bool, Option<bool>) {
    let nat = decision.nat;
    let Some(translated_src) = nat.rewrite_src else {
        return (true, None);
    };
    if nat.nat64 || nat.nptv6 {
        return (true, None);
    }

    let ingress_ifindex = metadata.ingress_ifindex as i32;
    let egress_ifindex = decision.resolution.egress_ifindex;
    let Some(egress) = forwarding.egress.get(&egress_ifindex) else {
        return (false, None);
    };
    let (from_zone_id, to_zone_id) = if metadata.fabric_ingress || ingress_ifindex == 0 {
        (metadata.ingress_zone, metadata.egress_zone)
    } else {
        crate::afxdp::forwarding::zone_pair_ids_for_flow_with_override(
            forwarding,
            ingress_ifindex,
            None,
            egress_ifindex,
        )
    };
    let Some(from_zone) = forwarding.zone_id_to_name.get(&from_zone_id) else {
        return (false, None);
    };
    let Some(to_zone) = forwarding.zone_id_to_name.get(&to_zone_id) else {
        return (false, None);
    };
    let scope = crate::afxdp::forwarding::nat_scope_ctx_for_flow(
        forwarding,
        ingress_ifindex,
        metadata.ingress_vlan_id,
        None,
        egress_ifindex,
        forward_key.routing_domain,
    );
    let source_nat_dst = nat.rewrite_dst.unwrap_or(forward_key.dst_ip);
    let source_nat_dport = nat.rewrite_dst_port.unwrap_or(forward_key.dst_port);

    // Translation provenance is local-only and the wire NAT decision does not
    // distinguish dynamic from static SNAT. If it is unavailable, fail closed:
    // accepting whichever new branch happens to match could launder a dynamic
    // allocation through a same-tuple static rule installed by this commit.
    if stored_static.is_none() {
        return (false, None);
    }
    // Static source NAT has independent provenance and precedence over
    // dynamic source NAT. Never let a newly installed static mapping validate
    // a session whose existing translation came from a dynamic pool/interface
    // rule, even if it happens to translate to the same tuple.
    if let Some((static_nat, _)) = forwarding.static_nat.match_snat_with_counter_scoped(
        forward_key.src_ip,
        forward_key.src_port,
        Some(source_nat_dst),
        to_zone,
        scope.egress_ifname,
        scope.egress_routing_instance,
    ) {
        let valid = stored_static != Some(false)
            && static_nat.rewrite_src == Some(translated_src)
            && static_nat.rewrite_src_port == nat.rewrite_src_port;
        return (valid, valid.then_some(true));
    }
    if stored_static == Some(true) {
        return (false, None);
    }

    let valid = crate::nat::source_nat_translation_matches(
        &forwarding.source_nat_rules,
        &scope,
        from_zone,
        to_zone,
        forward_key.src_ip,
        source_nat_dst,
        forward_key.protocol,
        forward_key.src_port,
        source_nat_dport,
        nat.source_nat_icmp,
        translated_src,
        nat.rewrite_src_port,
        egress.primary_v4,
        egress.primary_v6,
    );
    (valid, valid.then_some(false))
}

/// Revalidate source NAT before any policy-generation, ICMP, host-delivery, or
/// foreign-hit early exit. A reverse hit is judged through its forward
/// companion; a forward hit with no local entry is checked sessionlessly and
/// drops this packet without claiming ownership of the peer's session.
#[allow(clippy::too_many_arguments)]
pub(super) fn source_nat_revocation_on_session_hit(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    session_key: &SessionKey,
    metadata: &SessionMetadata,
    decision: SessionDecision,
    flow: &SessionFlow,
    origin: SessionOrigin,
) -> Option<PolicyRevocation> {
    let (forward_key, forward_decision, forward_metadata, forward_origin, canonical_key, stored_static) =
        if metadata.is_reverse {
            let reverse_key = sessions.revalidation_canonical_key(session_key)?;
            let (reverse_decision, _, _) = sessions.entry_with_origin(&reverse_key)?;
            let forward_query =
                crate::session::reverse_session_key(&reverse_key, reverse_decision.nat);
            let canonical_key = match sessions.source_nat_revalidation_target(&forward_query) {
                SourceNatRevalidationTarget::Fresh | SourceNatRevalidationTarget::NoLocalEntry => {
                    return None;
                }
                SourceNatRevalidationTarget::Stale { key, static_nat } => (key, static_nat),
            };
            let (forward_decision, forward_metadata, forward_origin) =
                sessions.entry_with_origin(&canonical_key.0)?;
            (
                canonical_key.0.clone(),
                forward_decision,
                forward_metadata,
                forward_origin,
                Some(canonical_key.0),
                canonical_key.1,
            )
        } else {
            match sessions.source_nat_revalidation_target(session_key) {
                SourceNatRevalidationTarget::Fresh => return None,
                SourceNatRevalidationTarget::Stale {
                    key: canonical_key,
                    static_nat,
                } => {
                    let (forward_decision, forward_metadata, forward_origin) =
                        sessions.entry_with_origin(&canonical_key)?;
                    (
                        canonical_key.clone(),
                        forward_decision,
                        forward_metadata,
                        forward_origin,
                        Some(canonical_key),
                        static_nat,
                    )
                }
                SourceNatRevalidationTarget::NoLocalEntry => (
                    flow.forward_key.clone(),
                    decision,
                    metadata.clone(),
                    origin,
                    None,
                    None,
                ),
            }
        };

    let (valid, static_nat) = source_nat_translation_still_valid(
        forwarding,
        &forward_decision,
        &forward_metadata,
        &forward_key,
        stored_static,
    );
    if valid {
        if let Some(canonical_key) = canonical_key.as_ref() {
            sessions.mark_source_nat_revalidated(canonical_key, static_nat);
        }
        return None;
    }
    Some(PolicyRevocation {
        canonical_key,
        decision: forward_decision,
        metadata: forward_metadata,
        origin: forward_origin,
        reason: PolicyRevocationReason::StaleSourceNat,
    })
}


/// Outcome of the cold judgment. Stamping lives with the caller: PERMIT-only,
/// never on decline or revoke (fail-closed).
enum ZonePolicyJudgment {
    /// Still permitted: the caller re-stamps the hit entry.
    Permit,
    /// Declined (unresolvable identity, ICMP-type-armed): keep flowing, stamp
    /// nothing.
    Decline,
    /// `Deny` or `Reject` (#9381): the caller revokes via the carried triple.
    Revoke,
}

/// Re-derive zone policy for an established-session HIT, at most once per
/// session per `config_generation`.
///
/// Returns `Some` only when the live policy does NOT PERMIT a flow this node is
/// still forwarding — `Deny` or `Reject`, #9381 — and the caller revokes. `None`
/// is the answer for every packet but one per session per generation.
#[inline]
fn resolution_is_locally_forwarding(resolution: ForwardingResolution) -> bool {
    matches!(
        resolution.disposition,
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
    ) && resolution.egress_ifindex != 0
}

#[inline]
fn policy_gate_current_for_resolution(resolution: ForwardingResolution) -> PolicyGateCurrent {
    match resolution.disposition {
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor
            if resolution.egress_ifindex != 0 =>
        {
            PolicyGateCurrent::LocalForwarding
        }
        ForwardingDisposition::ForwardCandidate | ForwardingDisposition::MissingNeighbor => {
            PolicyGateCurrent::LocalForwardingNoEgress
        }
        _ => PolicyGateCurrent::NonLocal,
    }
}

fn revocation_for_hit(
    sessions: &SessionTable,
    session_key: &SessionKey,
) -> Option<PolicyRevocation> {
    let canonical_key = sessions.revalidation_canonical_key(session_key)?;
    let (decision, metadata, origin) = sessions.entry_with_origin(&canonical_key)?;
    Some(PolicyRevocation {
        canonical_key: Some(canonical_key),
        decision,
        metadata,
        origin,
        reason: PolicyRevocationReason::ZonePolicy,
    })
}

#[inline]
fn policy_kind_for_resolution(resolution: ForwardingResolution) -> PolicyRevalidationKind {
    if resolution.disposition == ForwardingDisposition::FabricRedirect {
        PolicyRevalidationKind::RecordedEgress
    } else if resolution_is_locally_forwarding(resolution) {
        PolicyRevalidationKind::LiveEgress
    } else {
        PolicyRevalidationKind::Unvalidated
    }
}

pub(super) fn revalidate_zone_policy_on_session_hit(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    // The matched entry's WIRE key (`ResolvedFlowSessionDecision::key`).
    session_key: &SessionKey,
    metadata: &crate::session::SessionMetadata,
    decision: crate::session::SessionDecision,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    // #9384/#10670: owner-only fabric hits use the recorded zone because the
    // fabric link is not the packet's logical arrival interface. Hit authority
    // admits a stamped packet only when its validated zone matches this entry;
    // an unstamped overlay keeps #9519's exemption. A foreign stamp takes the
    // per-packet foreign path before revalidation.
    packet_fabric_ingress: bool,
    fabric_link_ingress: bool,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_ns: u64,
    now_secs: u64,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
    // #10582: the resolved hit's origin, carried ONLY for the sessionless
    // revocation (which has no entry to reload one from). The Stale path still
    // reloads the judged entry's own origin below.
    origin: SessionOrigin,
) -> Option<PolicyRevocation> {
    let flow = flow?;
    // #10507 packet-time provenance fence, single probe. Evaluated before
    // LocalDelivery, reverse dispatch, and ICMP-sensitive exits.
    let gate_current = policy_gate_current_for_resolution(decision.resolution);
    let gate = sessions.policy_revalidation_gate(session_key, gate_current);
    // GATE 1: the reverse companion is never independently policy-adjudicated.
    // #9604: reverse hits judge by the FORWARD companion (same stamp/zones, pair teardown) — never the swapped pair.
    if metadata.is_reverse {
        return reverse_hit_zone_policy(
            forwarding,
            sessions,
            session_key,
            gate,
            gate_current,
            packet_fabric_ingress,
            fabric_link_ingress,
            ha_state,
            dynamic_neighbors,
            now_ns,
            now_secs,
            ingress_ifindex,
            ha_startup_grace_until_secs,
            decision,
            meta,
        );
    }
    // GATE 1b: DECLINE for ICMP, but ONLY when the type actually matters.
    //
    // #8356 declined ICMP outright, and the reasoning was right as far as it
    // went: a zone policy can match on ICMP type/code via an application term
    // (`junos-icmp-ping`, #3020), so where such a term exists an ICMP verdict is a
    // property of the PACKET, not of the flow. This derivation is deliberately
    // frame-independent and has no type to offer, so evaluating with `None`
    // would fail to match a type-specific PERMIT and manufacture a DENY for a
    // flow the policy allows — and revoking on that tears down a live,
    // permitted flow. Stamping one packet's type as the flow's verdict would be
    // just as wrong in the other direction.
    //
    // #8618 narrows the decline to the case that reasoning actually describes.
    // `packet_icmp` is read in exactly ONE place in policy evaluation — the
    // `icmp_constraints` arm of `CompiledApplications::matches` — and the
    // predicate arms on a type-constrained PERMIT.
    //
    // #9386 CORRECTS THE CLAIM THAT USED TO BE HERE. This said that with no
    // type-constrained PERMIT, "a type-blind evaluation returns exactly the
    // verdict a fully-informed one would". That is verdict EQUIVALENCE and it is
    // false: the `icmp_constraints` arm is action-BLIND, so a type-constrained
    // term on a DENY rule populates it too and `matches` fails that term closed
    // for `None` just the same. The guarantee is the weaker, sufficient one — a
    // type-blind walk can never MANUFACTURE a false DENY, because skipping a
    // constrained term can only fall through to a later, more permissive rule.
    // Acting on a DENY here is therefore safe; a PERMIT is not a claim that a
    // fully-informed walk would agree.
    //
    // #9386: this frame-independent derivation cannot use a type-constrained
    // DENY to revoke: `packet_icmp = None` skips its application term and may
    // fall through to a broader permit. #11064's packet-scoped owner/foreign
    // check evaluates that message with its actual type/code and enforces the
    // DENY per packet; the permit-only gate here remains necessary to avoid
    // revoking a flow on a false DENY caused by a skipped constrained PERMIT.
    //
    // The predicate is whole-snapshot and therefore conservative (see
    // `PolicyState::icmp_verdict_may_depend_on_type`): one `junos-icmp-ping` permit
    // anywhere declines ICMP box-wide, which is precisely #8356's behaviour.
    // The failure mode of the coarseness is "no worse than before", never "acts
    // on a verdict it could not derive".
    // GATE 2: one probe answers both "which entry does this WIRE tuple name"
    // and "is its policy verdict stale". `Fresh` — the answer for every packet
    // but one per session per generation — costs a single hash and a compare.
    //
    // COST NOTE, because a promise was made about this and then revised: an
    // earlier design threaded the stamp out of `lookup_with_origin` (which
    // already holds both the entry and its canonical key and discards the
    // latter) to make this a bare integer compare with no hash. That is
    // achievable and would be strictly cheaper, but it widens the session
    // lookup's return type through `ResolvedSessionLookup` and both
    // `ResolvedFlowSessionDecision` construction sites — a hot-path refactor
    // whose benefit is unmeasured. It is unmeasured because this code only runs
    // on a flow-cache MISS: a generation bump invalidates every flow-cache entry
    // (`FlowCacheStamp::config_generation`), so the packet that pays here is one
    // already taking the slow path, and steady-state established traffic never
    // reaches this function at all. Pay the hash, keep the diff narrow; the
    // threading is a measured optimisation if a profile ever asks for it.
    // #9563: a host-bound (LocalDelivery) session is not judged by a transit zone
    // pair. Its authority is the host-inbound gate plus `to-zone junos-host` policy,
    // and the established-hit path re-evaluates both on every host-bound packet.
    // Every local-delivery resolution sets `egress_ifindex` to the LOCAL interface,
    // so re-deriving here asked `from -> the local interface's own zone`, a pair
    // host-inbound admission never consulted. The default policy then denied it and
    // the owner's own first ACK revoked the session. Declined before the revalidation
    // lookup, so host-bound hits pay nothing for it. (#10038: TUN-origin
    // reverse hits additionally bypass the host-inbound/junos-host HIT
    // re-checks themselves via the forward-companion exemption — the
    // tightening asymmetry is deliberate and documented above.)
    if decision.resolution.disposition == super::ForwardingDisposition::LocalDelivery {
        return None;
    }
    let canonical_key = match &gate.target {
        PolicyRevalidationTarget::Fresh if gate.force_cold => {
            sessions.revalidation_canonical_key(session_key)?
        }
        PolicyRevalidationTarget::Fresh => return None,
        // No entry this tuple may safely name (#2120 transient synced hit, or a
        // reused slab slot). There is nothing to stamp, tear down, or evict:
        // this node has no local session or flow-cache slot for the tuple.
        // The verdict itself is still derivable from the flow and arrival
        // identity (#8114 item 2), so derive it sessionlessly; a DENY drops
        // this packet without touching session state.
        PolicyRevalidationTarget::NoLocalEntry => {
            let from_source = if packet_fabric_ingress {
                FromZoneSource::RecordedZone(metadata.ingress_zone)
            } else {
                FromZoneSource::LiveIfindex {
                    ifindex: meta.ingress_ifindex as i32,
                    vlan: meta.ingress_vlan_id,
                }
            };
            return sessionless_zone_policy_verdict(
                forwarding,
                decision,
                metadata,
                flow,
                meta,
                from_source,
                origin,
                now_ns,
            );
        }
        PolicyRevalidationTarget::Stale(k) => k.clone(),
    };
    // Stale targets still bypass policy for a firewall-originated TUN forward;
    // this arm cannot fire for a sessionless hit because that branch returned
    // above. Genuine forward packets bypass the worker (WG socket TX, GRE
    // direct enqueue), so this remains a tunnel-side-arrival guard.
    if let Some((canon_decision, canon_metadata, canon_origin)) =
        sessions.entry_with_origin(&canonical_key)
        && tun_origin_forward(&canon_decision, &canon_metadata, canon_origin)
    {
        return None;
    }
    // The forward pair, judged as itself: the packet's tuple and protocol use
    // the from-zone derived from its arrival identity (#9384). An Owner fabric
    // arrival keeps the entry's recorded zone because the fabric link's zone
    // is structurally not the flow's, and hit authority has already checked
    // the validated stamp against that zone. A foreign stamp does not reach
    // this revalidation path.
    let input = PolicyJudgmentInput {
        decision,
        metadata: (*metadata).clone(),
        protocol: meta.protocol,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        from_source: if packet_fabric_ingress {
            FromZoneSource::RecordedZone(metadata.ingress_zone)
        } else {
            FromZoneSource::LiveIfindex {
                ifindex: meta.ingress_ifindex as i32,
                vlan: meta.ingress_vlan_id,
            }
        },
        now_ns,
    };
    // ICMP's packet-scoped policy decline remains unchanged, but obsolete NAT
    // is revoked first because it is independent of the packet type.
    if forwarding
        .policy
        .icmp_verdict_may_depend_on_type(input.protocol)
    {
        return if gate.fail_closed_icmp {
            revocation_for_hit(sessions, session_key)
        } else {
            None
        };
    }
    match zone_policy_deny_on_session_hit(forwarding, &input) {
        ZonePolicyJudgment::Permit => {
            sessions.mark_policy_revalidated(
                &canonical_key,
                policy_kind_for_resolution(input.decision.resolution),
            );
            None
        }
        ZonePolicyJudgment::Decline if gate.fail_closed_decline => {
            // A forced-authority walk (rule-3 Fresh-forced, or rule-4
            // no-egress) cannot retain authority merely because the cold
            // walk lacks an input identity or packet ICMP type.
            revocation_for_hit(sessions, session_key)
        }
        ZonePolicyJudgment::Decline => None,
        ZonePolicyJudgment::Revoke => {
            // The judged entry's OWN origin: reloaded from the entry just judged
            // rather than trusting the threaded hit origin, which on the NAT
            // alias path names a different tuple. A miss means the entry vanished
            // between the probe and the verdict — nothing left to tear down.
            let (_, _, origin) = sessions.entry_with_origin(&canonical_key)?;
            Some(PolicyRevocation {
                canonical_key: Some(canonical_key),
                decision: input.decision,
                metadata: input.metadata,
                origin,
                reason: PolicyRevocationReason::ZonePolicy,
            })
        }
    }
}

/// Test-only seam for exercising re-derivation without the descriptor MAC gate.
#[cfg(test)]
pub(crate) fn revalidate_zone_policy_declines_for_test(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    session_key: &SessionKey,
    metadata: &SessionMetadata,
    decision: SessionDecision,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    packet_fabric_ingress: bool,
) -> bool {
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    revalidate_zone_policy_on_session_hit(
        forwarding,
        sessions,
        session_key,
        metadata,
        decision,
        flow,
        meta,
        packet_fabric_ingress,
        false,
        &ha_state,
        &dynamic_neighbors,
        0,
        0,
        0,
        0,
        SessionOrigin::ForwardFlow,
    )
    .is_none()
}

/// Test-only seam for proving that a stale local hit is revoked rather than
/// declined. The canonical key is present on this path, unlike the
/// sessionless NoLocalEntry verdict.
#[cfg(test)]
pub(crate) fn revalidate_zone_policy_revokes_for_test(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    session_key: &SessionKey,
    metadata: &SessionMetadata,
    decision: SessionDecision,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    packet_fabric_ingress: bool,
) -> bool {
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    revalidate_zone_policy_on_session_hit(
        forwarding,
        sessions,
        session_key,
        metadata,
        decision,
        flow,
        meta,
        packet_fabric_ingress,
        false,
        &ha_state,
        &dynamic_neighbors,
        0,
        0,
        0,
        0,
        SessionOrigin::ForwardFlow,
    )
    .is_some_and(|revocation| revocation.canonical_key.is_some())
}
/// Test-only revocation projection for pins that must inspect WHAT M2
/// revoked (not just Some-vs-None): the canonical key plus the judged
/// decision. Keeps `PolicyRevocation` super-private; the projection is
/// plain assertable data. #10507 rule 4 pins the NoEgress struct here.
#[cfg(test)]
pub(crate) fn revalidate_zone_policy_revocation_for_test(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    session_key: &SessionKey,
    metadata: &SessionMetadata,
    decision: SessionDecision,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    packet_fabric_ingress: bool,
) -> Option<(SessionKey, SessionDecision)> {
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    revalidate_zone_policy_on_session_hit(
        forwarding,
        sessions,
        session_key,
        metadata,
        decision,
        flow,
        meta,
        packet_fabric_ingress,
        false,
        &ha_state,
        &dynamic_neighbors,
        0,
        0,
        0,
        0,
        SessionOrigin::ForwardFlow,
    )
    .and_then(|rev| rev.canonical_key.map(|key| (key, rev.decision)))
}
/// Test-only view of the #10582 sessionless deny arm.
#[cfg(test)]
pub(crate) fn revalidate_zone_policy_sessionless_denies_for_test(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    session_key: &SessionKey,
    metadata: &SessionMetadata,
    decision: SessionDecision,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    packet_fabric_ingress: bool,
) -> bool {
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    revalidate_zone_policy_on_session_hit(
        forwarding,
        sessions,
        session_key,
        metadata,
        decision,
        flow,
        meta,
        packet_fabric_ingress,
        false,
        &ha_state,
        &dynamic_neighbors,
        0,
        0,
        0,
        0,
        SessionOrigin::ForwardFlow,
    )
    .is_some_and(|revocation| revocation.canonical_key.is_none())
}
/// Test-only view of the canonical key selected by revalidation. Reverse
/// companion denies must carry the forward key so the caller tears down both
/// halves; sessionless forward denies remain keyless.
#[cfg(test)]
pub(crate) fn revalidate_zone_policy_canonical_key_for_test(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    session_key: &SessionKey,
    metadata: &SessionMetadata,
    decision: SessionDecision,
    flow: Option<&SessionFlow>,
    meta: UserspaceDpMeta,
    packet_fabric_ingress: bool,
) -> Option<SessionKey> {
    let ha_state = BTreeMap::new();
    let dynamic_neighbors = Arc::new(ShardedNeighborMap::new());
    revalidate_zone_policy_on_session_hit(
        forwarding,
        sessions,
        session_key,
        metadata,
        decision,
        flow,
        meta,
        packet_fabric_ingress,
        false,
        &ha_state,
        &dynamic_neighbors,
        0,
        0,
        0,
        0,
        SessionOrigin::ForwardFlow,
    )
    .and_then(|revocation| revocation.canonical_key)
}

/// #10038: is this FORWARD entry firewall-self-originated (TUN-originated)?
///
/// The single predicate shared by the #9604 decline (Part C, both arms below)
/// and the LocalDelivery HIT exemption (`tun_origin_reverse_exempt`), so the
/// two can never disagree about what "TUN-originated" means.
///
/// Positive provenance (parent-review item 5): the load-bearing conjunct is
/// `origin == TunOrigin`, stamped ONLY by the two local TUN publishers (WG
/// `tun_origin.rs`, GRE `tunnel.rs`) and preserved across materialize /
/// replica. HA imports hardcode `SyncImport` (`session_sync.rs`), so a
/// legacy-peer transit import — zeroed ingress, zeroed counter, tunnel
/// egress, even a preserved admitting PolicyID — can NEVER match, no
/// matter how closely its metadata aliases. The remaining conjuncts are
/// defense-in-depth over the stamped shape (all must hold):
/// - !is_reverse: the marker describes the forward half only.
/// - ingress_ifindex == 0: TUN-origin has no ingress binding to record
///   (#4983's HOST-OUTBOUND population).
/// - tunnel_endpoint_id != 0: the flow egresses a tunnel.
/// - policy_counter_idx == 0: self-originated runs no policy match (#6224).
///
/// Lifecycle notes: TUN-origin never promotes (refused — promotion would
/// re-tag the marker away), and demotion preserves its node-local provenance.
/// Transient local seeds likewise remain local through demotion and refresh;
/// their origin predicates and demotion markers keep them out of HA export.
/// Every other origin — ForwardFlow/ReverseFlow (MISS installs, the spoof-plant
/// shape), SyncImport/SharedMaterialize/WorkerLocalImport/SharedPromote
/// (HA-synced family, incl. the legacy alias), and LocalMiss — follows the
/// normal policy revalidation gates.
pub(super) fn tun_origin_forward(
    decision: &SessionDecision,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
) -> bool {
    origin == SessionOrigin::TunOrigin
        && !metadata.is_reverse
        && metadata.ingress_ifindex == 0
        && decision.resolution.tunnel_endpoint_id != 0
        && metadata.policy_counter_idx == 0
}

/// #10808: the reverse half of #10038 Part C / #10630. A TUN-origin REVERSE
/// hit declines PBR revalidation for the same reason the forward does:
/// self-originated runs no PBR admission, so there is no admitting route
/// identity to re-derive. The install stamp is deliberately (0,0) (the
/// `_in_table` zero-stamp convention — both TUN-origin builders synthesize
/// the reverse table-scoped but identity-free) while the live native
/// derivation yields the tunnel's instance identity, a mismatch that
/// revoked every VRF TUN-origin pair on its first reply-packet
/// revalidation: the solicited reply HIT, then died to
/// `filter_revoked_sessions` instead of delivering. Domain-0 pairs pinned
/// by accident ((0,0)==(0,0)); VRF pairs died. The decline covers both
/// uniformly. `TunOrigin` is positive provenance (stamped only by the two
/// TUN-origin builders, never a peer wire import), so origin + direction
/// names exactly the synthesized solicited-reply halves — ordinary
/// (non-TUN-origin) reverses revalidate unchanged.
pub(super) fn tun_origin_reverse(metadata: &SessionMetadata, origin: SessionOrigin) -> bool {
    origin == SessionOrigin::TunOrigin && metadata.is_reverse
}

/// #10038 Part B: may this reverse LocalDelivery HIT skip the host-inbound
/// and junos-host NEW-session gates as a solicited reply?
///
/// True iff the hit entry's FORWARD companion exists and is TUN-originated
/// (`tun_origin_forward`) — i.e. the firewall itself sent the request this
/// reply answers. The companion key derivation is byte-identical to #9604's
/// (`reverse_session_key` on the hit key + nat), and the lookup order is
/// local-first (GRE UpsertLocal + pre-installed shapes) then shared
/// (WG shared-only production shape, where the forward never materializes
/// locally). A local hit DECIDES (a non-marker local forward fails closed
/// without consulting shared — local shadows). Lone reverse (no forward
/// anywhere) fails closed, per the #9604 lone-reverse philosophy.

/// Callers keep the lo0 packet filter, TTL, and input-filter gates: only the
/// two NEW-session gates (host-inbound admission, junos-host policy) are
/// skipped, matching Junos (self-originated + solicited replies run no
/// policy). Precedence: revalidation runs BEFORE the HIT arm, so a C-revoke
/// always wins over a B-exempt (fail-closed on any divergence).
pub(super) fn tun_origin_reverse_exempt(
    sessions: &SessionTable,
    shared_sessions: &Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>,
    rev_key: &SessionKey,
    rev_nat: NatDecision,
) -> bool {
    let fwd_key = crate::session::reverse_session_key(rev_key, rev_nat);
    if fwd_key == *rev_key {
        return false;
    }
    if let Some((decision, metadata, origin)) = sessions.entry_with_origin(&fwd_key) {
        return tun_origin_forward(&decision, &metadata, origin);
    }
    match crate::afxdp::shared_ops::lookup_shared_session(shared_sessions, &fwd_key) {
        Some(entry) => tun_origin_forward(&entry.decision, &entry.metadata, entry.origin),
        None => false,
    }
}

/// #10582: derive a zone-policy verdict without a local session entry.
///
/// A keep-transient synced hit can deliberately purge both the local and
/// shared rows before the established-hit policy stage runs. The tuple,
/// decision, metadata, and arrival identity still determine the same zone
/// policy verdict as the ordinary forward arm; only stamping and teardown are
/// unavailable. A non-permit verdict therefore returns a revocation with no
/// canonical key, which tells the caller to drop this packet without touching
/// session or NAT state.
#[cold]
#[inline(never)]
fn sessionless_zone_policy_verdict(
    forwarding: &ForwardingState,
    decision: SessionDecision,
    metadata: &SessionMetadata,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    from_source: FromZoneSource,
    origin: SessionOrigin,
    now_ns: u64,
) -> Option<PolicyRevocation> {
    // The caller supplies authoritative FORWARD data. A reverse hit never
    // reaches this helper with its swapped row; the reverse arm resolves its
    // companion first, preserving #9604's direction invariant.
    if decision.resolution.disposition == super::ForwardingDisposition::LocalDelivery
        || tun_origin_forward(&decision, metadata, origin)
        || forwarding
            .policy
            .icmp_verdict_may_depend_on_type(meta.protocol)
    {
        return None;
    }
    let input = PolicyJudgmentInput {
        decision,
        metadata: metadata.clone(),
        protocol: meta.protocol,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.forward_key.src_port,
        dst_port: flow.forward_key.dst_port,
        from_source,
        now_ns,
    };
    match zone_policy_deny_on_session_hit(forwarding, &input) {
        ZonePolicyJudgment::Permit | ZonePolicyJudgment::Decline => None,
        ZonePolicyJudgment::Revoke => Some(PolicyRevocation {
            canonical_key: None,
            decision: input.decision,
            metadata: input.metadata,
            origin,
            reason: PolicyRevocationReason::ZonePolicy,
        }),
    }
}

/// #9604/#10582: from-zone source for a reverse-triggered forward-pair
/// judgment, derived from the FORWARD companion's provenance — never from
/// the triggering reply packet, which arrives on the flow's egress side and
/// whose arrival zone is the wrong answer. The single helper shared by the
/// Stale arm and the #10582 NoLocalEntry arm so the two can never disagree.
///
/// Locally-authored ingress identities resolve live through the ledger;
/// peer-authored or fabric identities (#6928, #7096) use the recorded zone.
/// Returns `None` (decline) only for the impossible `ReverseFlow` companion
/// origin, with loud accounting matching the Stale arm.
fn reverse_companion_from_source(
    sessions: &mut SessionTable,
    fwd_origin: SessionOrigin,
    fwd_metadata: &SessionMetadata,
) -> Option<FromZoneSource> {
    match fwd_origin {
        SessionOrigin::ForwardFlow
        | SessionOrigin::LocalMiss
        | SessionOrigin::MissingNeighborSeed
            if !fwd_metadata.fabric_ingress =>
        {
            Some(FromZoneSource::LiveIfindex {
                ifindex: fwd_metadata.ingress_ifindex as i32,
                vlan: fwd_metadata.ingress_vlan_id,
            })
        }
        SessionOrigin::ForwardFlow
        | SessionOrigin::LocalMiss
        | SessionOrigin::MissingNeighborSeed
        | SessionOrigin::SyncImport
        | SessionOrigin::SharedMaterialize
        | SessionOrigin::SharedPromote
        | SessionOrigin::WorkerLocalImport
        | SessionOrigin::TunOrigin
        | SessionOrigin::FabricPuntSeed => {
            Some(FromZoneSource::RecordedZone(fwd_metadata.ingress_zone))
        }
        SessionOrigin::ReverseFlow => {
            sessions.note_policy_revalidation_loud_decline();
            debug_assert!(false, "9604: forward companion has ReverseFlow origin");
            None
        }
    }
}

/// #9604: the reverse companion's half of GATE 1 — judge the stale reverse hit
/// by its FORWARD companion, never by the reverse pair.
///
/// The reverse entry carries swapped zones and no ingress identity (#4983), so
/// none of its fields may enter the verdict. Everything evaluated comes from
/// the forward companion entry: its wire tuple and protocol, its NAT (the
/// post-translation destination, #9382), its egress, and its from-zone source
/// — the forward entry's recorded ingress zone whenever the entry was admitted
/// off the fabric (its stamped identity is (0, 0), #7096) or carries
/// peer-authored provenance, otherwise the recorded admitting identity
/// live-resolved. Uses nothing from the triggering packet — not its tuple,
/// not its protocol, not its arrival interface (authority already established
/// the packet is the session's owner before this runs).
///
/// Policy stamping is HIT-ONLY: on PERMIT only the hit (reverse) entry is
/// marked. When a stale forward FIB route is resolved and permitted, that
/// route resolution is persisted without stamping the forward policy verdict;
/// the forward half retains its existing policy freshness semantics.
fn resolve_current_forward_companion(
    forwarding: &ForwardingState,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    fwd_key: &SessionKey,
    fwd_decision: SessionDecision,
    fwd_metadata: &SessionMetadata,
    packet_fabric_ingress: bool,
    fabric_link_ingress: bool,
    now_secs: u64,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
) -> ForwardingResolution {
    let flow = SessionFlow {
        src_ip: fwd_key.src_ip,
        dst_ip: fwd_key.dst_ip,
        forward_key: fwd_key.clone(),
    };
    let resolution_target = resolution_target_for_session(&flow, fwd_decision);
    let looked_up = lookup_forwarding_resolution_for_session_without_cache(
        forwarding,
        dynamic_neighbors,
        &flow,
        fwd_decision,
    );
    let looked_up = prefer_local_forward_candidate_for_fabric_ingress(
        forwarding,
        ha_state,
        dynamic_neighbors,
        now_secs,
        packet_fabric_ingress,
        resolution_target,
        install_table_name_for_session(forwarding, fwd_decision, resolution_target),
        looked_up,
    );
    let enforced = enforce_session_ha_resolution(
        forwarding,
        ha_state,
        now_secs,
        looked_up,
        ingress_ifindex,
        ha_startup_grace_until_secs,
    );
    redirect_session_via_fabric_if_needed(
        forwarding,
        enforced,
        fabric_link_ingress,
        fwd_metadata.ingress_zone,
    )
}

fn reverse_hit_zone_policy(
    forwarding: &ForwardingState,
    sessions: &mut SessionTable,
    session_key: &SessionKey,
    gate: PolicyGateAnswer,
    reverse_current: PolicyGateCurrent,
    packet_fabric_ingress: bool,
    fabric_link_ingress: bool,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
    now_ns: u64,
    now_secs: u64,
    ingress_ifindex: i32,
    ha_startup_grace_until_secs: u64,
    fallback_decision: SessionDecision,
    meta: UserspaceDpMeta,
) -> Option<PolicyRevocation> {
    let PolicyGateAnswer {
        target: rev_target,
        force_cold: rev_force_cold,
        fail_closed_decline: rev_fail_closed_decline,
        fail_closed_icmp: rev_fail_closed_icmp,
        ..
    } = gate;
    let rev_canonical = match &rev_target {
        PolicyRevalidationTarget::Fresh => sessions.revalidation_canonical_key(session_key)?,
        PolicyRevalidationTarget::NoLocalEntry => {
            // A reverse row can only be judged through an authoritative
            // FORWARD companion (#9604). Reconstruct its key with the
            // reverse hit's own NAT decision, then use the companion's actual
            // decision/metadata/origin to build the sessionless input.
            let fwd_key = crate::session::reverse_session_key(session_key, fallback_decision.nat);
            if fwd_key == *session_key {
                sessions.note_policy_revalidation_loud_decline();
                debug_assert!(false, "9604: reverse_session_key inversion is degenerate");
                return None;
            }
            let Some((mut fwd_decision, fwd_metadata, fwd_origin, fwd_generation)) =
                sessions.entry_with_origin_and_forwarding_generation(&fwd_key)
            else {
                // Lone reverse: no forward egress/NAT/zone context exists.
                // Keep this legitimate #9604 population alive; this accepted
                // residual is pinned by
                // `lone_reverse_companion_reaching_revalidation_is_declined_9604`.
                return None;
            };
            if fwd_metadata.is_reverse {
                sessions.note_policy_revalidation_loud_decline();
                debug_assert!(false, "9604: forward companion slot holds a reverse entry");
                return None;
            }
            if fwd_decision.resolution.disposition == super::ForwardingDisposition::LocalDelivery
                || tun_origin_forward(&fwd_decision, &fwd_metadata, fwd_origin)
                || forwarding
                    .policy
                    .icmp_verdict_may_depend_on_type(fwd_key.protocol)
            {
                return None;
            }
            let forward_route_stale = sessions.forwarding_resolution_is_stale(fwd_generation);
            if forward_route_stale {
                let current_fwd_resolution = resolve_current_forward_companion(
                    forwarding,
                    ha_state,
                    dynamic_neighbors,
                    &fwd_key,
                    fwd_decision,
                    &fwd_metadata,
                    fwd_metadata.fabric_ingress,
                    false,
                    now_secs,
                    fwd_metadata.ingress_ifindex as i32,
                    ha_startup_grace_until_secs,
                );
                if resolution_is_locally_forwarding(current_fwd_resolution) {
                    fwd_decision.resolution = current_fwd_resolution;
                } else if current_fwd_resolution.disposition
                    == ForwardingDisposition::LocalDelivery
                {
                    return None;
                } else if current_fwd_resolution.disposition == ForwardingDisposition::FabricRedirect
                {
                    // Continue to judge the recorded policy egress below; the
                    // transport route is not the forward flow's policy zone.
                    fwd_decision.resolution = current_fwd_resolution;
                } else {
                    return Some(PolicyRevocation {
                        canonical_key: Some(fwd_key),
                        decision: fwd_decision,
                        metadata: fwd_metadata,
                        origin: fwd_origin,
                        reason: PolicyRevocationReason::ZonePolicy,
                    });
                }
            }
            let from_source = reverse_companion_from_source(sessions, fwd_origin, &fwd_metadata)?;
            let fwd_flow = SessionFlow {
                src_ip: fwd_key.src_ip,
                dst_ip: fwd_key.dst_ip,
                forward_key: fwd_key.clone(),
            };
            let mut fwd_meta = meta;
            fwd_meta.protocol = fwd_key.protocol;
            if !forward_route_stale {
                let mut revocation = sessionless_zone_policy_verdict(
                    forwarding,
                    fwd_decision,
                    &fwd_metadata,
                    &fwd_flow,
                    fwd_meta,
                    from_source,
                    fwd_origin,
                    now_ns,
                )?;
                // The local forward companion is authoritative, so this uses
                // the ordinary pair-revocation shape rather than drop-only.
                revocation.canonical_key = Some(fwd_key);
                return Some(revocation);
            }
            let input = PolicyJudgmentInput {
                decision: fwd_decision,
                metadata: fwd_metadata.clone(),
                protocol: fwd_key.protocol,
                src_ip: fwd_key.src_ip,
                dst_ip: fwd_key.dst_ip,
                src_port: fwd_key.src_port,
                dst_port: fwd_key.dst_port,
                from_source,
                now_ns,
            };
            return match zone_policy_deny_on_session_hit(forwarding, &input) {
                ZonePolicyJudgment::Permit => {
                    if input.decision.resolution.disposition
                        != ForwardingDisposition::FabricRedirect
                    {
                        let owner_rg_id = crate::afxdp::forwarding::owner_rg_for_resolution(
                            forwarding,
                            input.decision.resolution,
                        );
                        sessions.revalidate_forwarding_resolution(
                            &fwd_key,
                            input.decision.resolution,
                            Some(owner_rg_id),
                        );
                    }
                    None
                }
                ZonePolicyJudgment::Decline => None,
                ZonePolicyJudgment::Revoke => Some(PolicyRevocation {
                    canonical_key: Some(fwd_key),
                    decision: input.decision,
                    metadata: input.metadata,
                    origin: fwd_origin,
                    reason: PolicyRevocationReason::ZonePolicy,
                }),
            };
        }
        PolicyRevalidationTarget::Stale(k) => k.clone(),
    };
    let (rev_decision, _, _) = sessions.entry_with_origin(&rev_canonical)?;
    let fwd_key = crate::session::reverse_session_key(&rev_canonical, rev_decision.nat);
    let reverse_has_intent = !matches!(reverse_current, PolicyGateCurrent::NonLocal);
    // Whether the reverse row itself needs a cold walk (Fresh-forced, or any
    // stale). Combined with intent for the inconsistent-companion arms below.
    let reverse_row_needs_cold =
        rev_force_cold || matches!(rev_target, PolicyRevalidationTarget::Stale(_));
    // Bound once: the no-companion positions below fence LiveEgress
    // reverses too (a Live row retains a recorded Permit).
    let rev_kind = sessions.policy_revalidation_kind(&rev_canonical);
    // #9604 degenerate inversion (key maps to itself): fail closed iff locally-forwarding + cold-needed — no claim this population is impossible.
    if fwd_key == rev_canonical {
        sessions.note_policy_revalidation_loud_decline();
        debug_assert!(false, "9604: reverse_session_key inversion is degenerate");
        return if reverse_has_intent && reverse_row_needs_cold {
            revocation_for_hit(sessions, session_key)
        } else {
            None
        };
    }
    // A fresh reverse entry is not enough when its forward companion's FIB
    // stamp is stale: the reply must judge the current forward pair.
    // Preserve #10635's provenance fence: stale `Unvalidated` has no recorded
    // Permit and must not manufacture a DENY (#8618).
    let fwd_companion = sessions.entry_with_origin_and_forwarding_generation(&fwd_key);
    let companion_forwarding_stale = reverse_has_intent
        && fwd_companion
            .as_ref()
            .is_some_and(|(_, _, _, generation)| sessions.forwarding_resolution_is_stale(*generation));
    // The companion's forwarding generation is checked independently of its
    // policy provenance, including for `LiveEgress`.
    let companion_needs_live = if reverse_has_intent {
        match &fwd_companion {
            Some((fwd_decision, _, _, _)) => {
                fwd_decision.resolution.disposition == ForwardingDisposition::FabricRedirect
                    || sessions.policy_revalidation_fenced(&fwd_key)
            }
            // No forward companion: fence a FENCED or Live reverse row. A
            // never-validated reverse has no recorded Permit to protect.
            None => {
                sessions.policy_revalidation_fenced(&rev_canonical)
                    || matches!(rev_kind, PolicyRevalidationKind::LiveEgress)
            }
        }
    } else {
        false
    };
    let force_reverse_cold =
        rev_force_cold || companion_needs_live || companion_forwarding_stale;
    // Inconsistent-companion arms fail closed when the reverse packet would
    // locally forward and its own row needs cold, or the companion itself
    // demands live. FIB staleness triggers a fresh forward-pair judgment but
    // does not change the existing Decline semantics for unjudgeable policy.
    let reverse_inconsistent_fail_closed =
        (reverse_has_intent && reverse_row_needs_cold) || companion_needs_live;
    if matches!(rev_target, PolicyRevalidationTarget::Fresh) && !force_reverse_cold {
        return None;
    }
    let Some((mut fwd_decision, fwd_metadata, fwd_origin, _)) = fwd_companion
    else {
        // A locally-forwarding reverse hit with no companion is not allowed
        // to retain a recorded Permit or take the old reverse Decline arm.
        // #9604: no tuple synthesis — zones would degrade to recorded-swapped with no live ledger.
        // #10635: ...unless the reverse row itself never earned one.
        let reverse_fenced = sessions.policy_revalidation_fenced(&rev_canonical)
            || matches!(rev_kind, PolicyRevalidationKind::LiveEgress);
        return if reverse_fenced && reverse_inconsistent_fail_closed {
            revocation_for_hit(sessions, session_key)
        } else {
            None
        };
    };
    if fwd_metadata.is_reverse {
        sessions.note_policy_revalidation_loud_decline();
        debug_assert!(false, "9604: forward companion slot holds a reverse entry");
        return if reverse_inconsistent_fail_closed {
            revocation_for_hit(sessions, session_key)
        } else {
            None
        };
    }
    if fwd_decision.resolution.disposition == ForwardingDisposition::LocalDelivery {
        return if reverse_inconsistent_fail_closed {
            revocation_for_hit(sessions, session_key)
        } else {
            None
        };
    }
    if tun_origin_forward(&fwd_decision, &fwd_metadata, fwd_origin) {
        return None;
    }
    // #10507 reverse-first fence: resolve the current forward companion from
    // the local FIB plus HA/lease snapshot when its policy provenance is
    // recorded/non-live OR its cached route generation is stale. This applies
    // to LiveEgress too: reverse-only traffic must not judge an old route and
    // refresh the reverse row while leaving the forward row on the old FIB.
    let stored_fwd_kind = sessions.policy_revalidation_kind(&fwd_key);
    if reverse_has_intent
        && (fwd_decision.resolution.disposition == ForwardingDisposition::FabricRedirect
            || !matches!(stored_fwd_kind, PolicyRevalidationKind::LiveEgress)
            || companion_forwarding_stale)
    {
        let current_fwd_resolution = resolve_current_forward_companion(
            forwarding,
            ha_state,
            dynamic_neighbors,
            &fwd_key,
            fwd_decision,
            &fwd_metadata,
            fwd_metadata.fabric_ingress,
            false,
            now_secs,
            fwd_metadata.ingress_ifindex as i32,
            ha_startup_grace_until_secs,
        );
        if resolution_is_locally_forwarding(current_fwd_resolution) {
            fwd_decision.resolution = current_fwd_resolution;
        } else if current_fwd_resolution.disposition == ForwardingDisposition::FabricRedirect {
            // Redirect retention (plan §4.2.4/§4.3, any origin): the companion
            // is still peer-owned *for the forward's own recorded context*.
            // Admit without revoking, stamp nothing, authorize no local TX
            // here. Cell 1 phase 1 pins SyncImport retention (#7770).
            return None;
        } else {
            // No valid current egress and not a redirect (NoRoute,
            // HAInactive, would-forward without egress): the reverse packet
            // must not locally forward on its stored Permit — fail closed.
            return revocation_for_hit(sessions, session_key);
        }
    }
    let from_source = match reverse_companion_from_source(sessions, fwd_origin, &fwd_metadata) {
        Some(from_source) => from_source,
        // Helper returns None only for ReverseFlow origin (exhaustive match:
        // every other origin yields LiveIfindex or RecordedZone). Preserve
        // master's fail-closed hardening for that arm.
        None => {
            return if reverse_inconsistent_fail_closed {
                revocation_for_hit(sessions, session_key)
            } else {
                None
            };
        }
    };
    let input = PolicyJudgmentInput {
        decision: fwd_decision.clone(),
        metadata: fwd_metadata.clone(),
        protocol: fwd_key.protocol,
        src_ip: fwd_key.src_ip,
        dst_ip: fwd_key.dst_ip,
        src_port: fwd_key.src_port,
        dst_port: fwd_key.dst_port,
        from_source,
        now_ns,
    };
    if forwarding
        .policy
        .icmp_verdict_may_depend_on_type(input.protocol)
    {
        return if rev_fail_closed_icmp || companion_needs_live {
            revocation_for_hit(sessions, session_key)
        } else {
            None
        };
    }
    match zone_policy_deny_on_session_hit(forwarding, &input) {
        ZonePolicyJudgment::Permit => {
            // #10507: reverse evidence does not stamp the forward policy
            // provenance. It does, however, persist a FIB-stale companion's
            // newly resolved route so reply-only streams do not repeat a full
            // route lookup and judgment on every packet.
            if companion_forwarding_stale {
                let owner_rg_id = matches!(
                    input.decision.resolution.disposition,
                    ForwardingDisposition::ForwardCandidate
                        | ForwardingDisposition::FabricRedirect
                        | ForwardingDisposition::HAInactive
                        | ForwardingDisposition::LocalDelivery
                )
                .then(|| {
                    crate::afxdp::forwarding::owner_rg_for_resolution(
                        forwarding,
                        input.decision.resolution,
                    )
                });
                sessions.revalidate_forwarding_resolution(
                    &fwd_key,
                    input.decision.resolution,
                    owner_rg_id,
                );
            }
            sessions.mark_policy_revalidated(
                &rev_canonical,
                policy_kind_for_resolution(input.decision.resolution),
            );
            None
        }
        ZonePolicyJudgment::Decline if rev_fail_closed_decline || companion_needs_live => {
            revocation_for_hit(sessions, session_key)
        }
        ZonePolicyJudgment::Decline => None,
        ZonePolicyJudgment::Revoke => Some(PolicyRevocation {
            canonical_key: Some(fwd_key),
            decision: fwd_decision,
            metadata: fwd_metadata,
            origin: fwd_origin,
            reason: PolicyRevocationReason::ZonePolicy,
        }),
    }
}

/// The cold half. `#[cold] #[inline(never)]` because it runs at most once per
/// session per config generation: keeping it out of line leaves the caller's
/// common path a compare, a hash and two branches.
///
/// The re-stamp happens on the PERMIT exit ONLY, and that asymmetry is
/// deliberate and identical in spirit to #7212's.
///
/// On PERMIT it is the whole point: the session keeps its entry — including its
/// NAT translation, since a purged-and-recreated permitted SNAT flow reinstalls
/// on a DIFFERENT translated port and breaks — and must not re-derive the same
/// verdict on every later packet of this generation.
///
/// On a non-PERMIT verdict (`Deny` or `Reject`, #9381) the caller REVOKES, so
/// normally there is no entry left to stamp. A stamp would matter only if the
/// teardown did NOT take, and in exactly that case it is a fail-OPEN: the
/// session would read "already judged under the live generation" and be
/// FORWARDED for the rest of the generation under a policy that does not permit
/// it. Unstamped, the next packet re-derives the same verdict and drops. Same
/// failure, fail-CLOSED instead of fail-OPEN.
#[cold]
#[inline(never)]
fn zone_policy_deny_on_session_hit(
    forwarding: &ForwardingState,
    input: &PolicyJudgmentInput,
) -> ZonePolicyJudgment {
    let egress_ifindex = input.decision.resolution.egress_ifindex;
    // The FROM-zone comes from the judgment input's explicit source — never from
    // the triggering packet on the reverse path (#9604), where the reply arrives
    // on the flow's egress side and its arrival zone is the wrong answer.
    //
    // `LiveIfindex` resolves a locally-authored ingress identity live through
    // the ledger, symmetric with the to-zone, which has always been resolved
    // live from the stored egress (#9384: a commit that moves an interface
    // BETWEEN ZONES is caught on this arm). Go's commit-time invalidation cannot
    // cover it either: it compares policy match/action text and
    // referenced-object fingerprints and never diffs zone MEMBERSHIP.
    //
    // `RecordedZone` carries a peer-authored or fabric identity whose interface
    // number is meaningless locally (#6928) but whose zone id is
    // cluster-consistent: it is used as-is. Fabric arrivals on the FORWARD path
    // construct this source from the entry's recorded zone for the same reason
    // the old override did — the fabric link's zone is structurally not the
    // flow's.
    //
    // #9383: the live resolution goes through `resolve_ingress_logical_ifindex`.
    // Keying `ifindex_to_zone_id` on the raw physical index would reintroduce the
    // logical-vs-physical defect on a trunk, and this is the site that would make
    // it a revocation rather than a mis-attribution.
    // #9604 meets #7770: a `FabricRedirect` entry's stored egress names the
    // fabric TRANSPORT, not the flow's egress. The punt seed's resolution
    // points at the fabric parent (measured: egress_ifindex 21, ledger zone
    // 0), so the live to-zone is the "unknown" sentinel and the pair falls to
    // the default deny. Admission never evaluated that pair: the seed is
    // adjudicated on the PRE-redirect egress zone
    // (`forwarding/fabric.rs::fabric_punt_seed_metadata`) and records it as
    // `egress_zone`, so the re-derivation judges the recorded zone — the same
    // pair the permit came from. Judging the transport instead revoked the
    // seed on the peer's first RETURN (and would on the next forward packet
    // too): `fabric_punt_seed_admits_the_peers_return_7770` fails with
    // (from lan, to 0). A recorded 0 evaluates exactly as the live 0 it
    // replaces (default policy, #3110), so entries that were never adjudicated
    // keep today's verdict.
    let to_zone_override = (input.decision.resolution.disposition
        == super::ForwardingDisposition::FabricRedirect)
        .then_some(input.metadata.egress_zone);
    let (from_id, live_to_id) = match input.from_source {
        FromZoneSource::LiveIfindex { ifindex, vlan } => {
            let arrival_logical =
                resolve_ingress_logical_ifindex(forwarding, ifindex, vlan).unwrap_or(ifindex);
            if arrival_logical == 0 {
                return ZonePolicyJudgment::Decline;
            }
            zone_pair_ids_for_flow_with_override(forwarding, arrival_logical, None, egress_ifindex)
        }
        FromZoneSource::RecordedZone(z) => {
            zone_pair_ids_for_flow_with_override(forwarding, 0, Some(z), egress_ifindex)
        }
    };
    let to_id = to_zone_override.unwrap_or(live_to_id);
    // #9513: DECLINE on a LOOKUP FAILURE — an interface this packet has no
    // identity for — and NOT on a zone of 0.
    //
    // This arm used to be `if to_id == 0 || from_id == 0 { return None; }`, and
    // the paragraph justifying it was wrong in every clause after the first. It
    // said `ifindex_unambiguous_zone_id` is filled by `populate_egress` "only for
    // interfaces with a resolvable link-layer address", and that a MAC-less
    // IPsec `xfrmi` is therefore absent from it. Measured at this base:
    //
    //   * the map is filled by `populate_interfaces`
    //     (`forwarding_build/interfaces.rs`, the `egress_zone_claim` loop), which
    //     `populate_egress` only READS;
    //   * the fill is not conditioned on a link-layer address in any way — it
    //     reads `iface.egress_zone` corroborated by `iface.zone`, both pure
    //     config;
    //   * #6722 is the change that made a correctly-zoned xfrmi resolve to its
    //     REAL zone, so the comment restated the PRE-#6722 bug as current
    //     behaviour. It was already wrong when it was written.
    //
    // So a zero zone on a RESOLVED ifindex does not mean "the ledger cannot see
    // this interface". It means the box does not consider that ifindex to be in
    // any zone — an operator de-zone, a #7509 contested ifindex, or an
    // uncorroborated Go claim (`EgressZoneClaim::resolve` -> None). All three are
    // states in which NEW flows already fall to the default policy, so declining
    // to re-judge established ones is the asymmetry #8356 exists to remove: after
    // an operator removes an egress interface from its zone, new flows correctly
    // default-deny while existing ones keep forwarding through it indefinitely.
    //
    // THE FIX IS NOT "REVOKE ON ZERO". Zero has a fourth cause that must keep
    // declining: no egress ifindex at all — a flow with no route, or a
    // peer-synced import for an INACTIVE redundancy group, which
    // `upsert_synced` deliberately leaves at `NoRoute`/0. Revoking there would
    // tear down the whole standby population at exactly the moment of promotion.
    // The two are separable today with no new state: `egress_ifindex == 0` is
    // exactly the lookup failure, and a non-zero ifindex whose zone is 0 is
    // exactly the unzoned case.
    //
    // Past this arm a zero zone is simply EVALUATED. `evaluate_policy_result_*`
    // (#3110) refuses to match any zone-pair OR `junos-global` rule against the 0
    // sentinel and falls through to the default action — which is precisely the
    // verdict a NEW flow on that interface gets. That is why this needs no
    // "revoke" branch of its own, and why it is automatically right under both
    // postures: `default-policy deny` revokes the session, `permit-all` keeps it,
    // and in each case the established flow is treated exactly as a new one would
    // be.
    // LOOKUP-FAILURE declines (#9513), enforced here for both callers. The
    // `LiveIfindex` no-identity case already declined inside the match above; a
    // `RecordedZone` that was never zone-adjudicated (fabric-seeded or synced
    // entries without one) declines here. A nonzero identity resolving to zone 0
    // is NOT this arm — it evaluated under the default policy above.
    if egress_ifindex == 0 || matches!(input.from_source, FromZoneSource::RecordedZone(0)) {
        return ZonePolicyJudgment::Decline;
    }
    // #9382: judge the POST-TRANSLATION destination, the tuple admission judges
    // (#2345/#2358) — NOT the wire tuple the forward session is keyed on.
    //
    // The forward entry is installed on the WIRE key (`flow.forward_key`), so a
    // later forward packet of a DNAT'd flow legitimately carries the VIP. Reading
    // the destination off that key asked a DIFFERENT QUESTION from the one
    // admission answered: admission passes `policy_dst_ip` / `policy_dst_port`
    // (`poll_descriptor/mod.rs`), whose comment states they carry "the correct
    // post-translation tuple for all inbound destination translations
    // (DNAT/static-DNAT/NPTv6/NAT64)". So for every session with an inbound
    // destination translation, a permit naming the REAL server — the only rule
    // admission will match — contributed NOTHING here: the derivation compared
    // the VIP, matched nothing, fell to the default policy and REVOKED, with the
    // policy completely unchanged. That is fail-CLOSED and needs no crafted
    // config. The fail-OPEN direction exists too: a deny narrowed against the
    // real server was missed because the VIP still matched a broader permit.
    //
    // The entry's own `decision.nat` is the right source and is already in hand.
    // Only `.resolution` is re-resolved on a session hit (`session_glue/mod.rs`);
    // `.nat` is the translation the flow was ADMITTED with, which is exactly the
    // quantity admission folded into `policy_dst_ip`:
    //
    //   * DNAT / static-DNAT — `rewrite_dst` / `rewrite_dst_port` ARE the
    //     `pre_routing_dnat` values admission read;
    //   * NPTv6 inbound — `nptv6_nat` carries `rewrite_dst = internal_dst` and no
    //     port rewrite, matching `effective_resolution_target` and the wire port;
    //   * NAT64 — `Nat64State::forward_decision` carries
    //     `rewrite_dst = extracted IPv4 target`, i.e. admission's
    //     `effective_resolution_target`, and no port rewrite.
    //
    // With no destination translation both `unwrap_or` arms collapse to the wire
    // values, so every non-translated session is byte-identical to pre-#9382.
    // The SOURCE deliberately stays pre-translation (`input.src_ip`): Junos
    // evaluates policy after destination NAT and BEFORE source NAT, and admission
    // passes the pre-translation source for the same reason.
    let policy_dst_ip = input.decision.nat.rewrite_dst.unwrap_or(input.dst_ip);
    let policy_dst_port = input
        .decision
        .nat
        .rewrite_dst_port
        .unwrap_or(input.dst_port);
    let result = evaluate_policy_result_without_counting_at(
        &forwarding.policy,
        from_id,
        to_id,
        input.src_ip,
        policy_dst_ip,
        input.protocol,
        input.src_port,
        policy_dst_port,
        // Frame-INDEPENDENT, like #7212's static walk: no ICMP type/code is
        // supplied. #8618: an ICMP flow only reaches here when the snapshot has
        // no type-constrained PERMIT term. #9386: that is NOT the same as "the
        // verdict is identical to a fully-informed evaluation" — a
        // type-constrained DENY also feeds the `icmp_constraints` arm and is
        // SKIPPED here. What it does guarantee is that `None` cannot manufacture
        // a false DENY, which is what makes acting on a DENY safe. Gate 1b
        // declines the case where a PERMIT could be missed.
        None,
        input.now_ns,
    );
    // #9381: the revoke predicate is PERMIT-or-not, mirroring admission
    // (`poll_descriptor/mod.rs`: `if let PolicyAction::Permit = policy_result.action`).
    // `PolicyAction` is THREE-valued and `Reject` is a terminal non-forwarding
    // verdict, not a softer permit: the first-packet path drops it
    // (`reject_reply.rs`) and `policy.rs`'s own terminal-action test spells the
    // pair `Deny | Reject`. Spelled as `Deny` alone, this arm re-stamped every
    // `Reject` session as revalidated, so an operator narrowing `permit` ->
    // `reject` got the new verdict for NEW flows while every ESTABLISHED session
    // admitted by that rule kept forwarding in both directions until idle
    // timeout. Spelling it POSITIVELY (match `Permit`) also means a fourth
    // action added later fails CLOSED here instead of inheriting the permit arm.
    if matches!(result.action, crate::policy::PolicyAction::Permit) {
        // Still permitted. Nothing counted, nothing logged, the session and its
        // NAT translation untouched. The CALLER re-stamps on this exit — and
        // only on this exit — so no later packet of this generation re-derives
        // the same verdict.
        return ZonePolicyJudgment::Permit;
    }
    // DENY or REJECT: deliberately NOT re-stamped — see the header.
    ZonePolicyJudgment::Revoke
}

#[cfg(test)]
#[path = "policy_revalidation_tests.rs"]
mod tests;
