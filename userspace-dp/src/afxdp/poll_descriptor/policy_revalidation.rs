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
//! (#3020, junos-ping) — and the gate arms when an active PERMIT rule carries a
//! type-constrained term.
//!
//! #9386: what the type-blind `None` guarantees is that it can never
//! MANUFACTURE a false DENY, NOT that the verdict equals a fully-informed one.
//! The `icmp_constraints` arm is action-BLIND, so a type-constrained DENY
//! populates it too and is SKIPPED here; the walk then falls through to a later,
//! more permissive rule. The accepted consequence is that a type-constrained
//! DENY ahead of a broader permit is not enforced on the established path. See
//! `PolicyState::icmp_verdict_may_depend_on_type` for why arming on a
//! constrained DENY would not change that outcome and would cost coverage.
//!
//! Where such a permit DOES exist the decline stands, and it must: a type-blind
//! evaluation would fail to match the type-specific permit, manufacture a DENY,
//! and revoke a flow the policy allows. That is strictly worse than the
//! residual. The gating predicate
//! (`PolicyState::icmp_verdict_may_depend_on_type`) is whole-snapshot and so
//! deliberately conservative — one junos-ping permit anywhere declines ICMP
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
//! `evaluate_policy_result_without_counting` (`PolicyHitCount::Never`), and the
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
//! # What it does NOT cover, stated so this does not read as more than it is
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
//! What is still NOT covered: a commit that changes a ROUTE so the flow would
//! now leave a DIFFERENT interface. Catching that needs a fresh routing
//! evaluation on the established-hit path, which is exactly what #2620 forbids
//! (that path is the sole counter for its packet precisely because it never
//! calls the routing evaluator). #8356 does not re-open #2620.

use super::*;
use crate::afxdp::FastMap;
use crate::afxdp::worker::SyncedSessionEntry;
use crate::nat::NatDecision;
use crate::policy::evaluate_policy_result_without_counting;
use crate::session::{
    PolicyGateAnswer, PolicyGateCurrent, PolicyRevalidationKind, PolicyRevalidationTarget,
    SessionDecision, SessionKey, SessionMetadata, SessionOrigin, SessionTable,
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
pub(super) struct PolicyRevocation {
    pub(super) canonical_key: Option<SessionKey>,
    pub(super) decision: SessionDecision,
    pub(super) metadata: SessionMetadata,
    pub(super) origin: SessionOrigin,
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
    // #9384: did THIS packet arrive over the fabric link? A fabric-ingress
    // packet's arrival interface is the fabric, NOT the flow's logical ingress,
    // so its live arrival zone is structurally not the flow's and the entry's
    // recorded zone is the only honest answer.
    packet_fabric_ingress: bool,
    fabric_link_ingress: bool,
    ha_state: &BTreeMap<i32, HAGroupRuntime>,
    dynamic_neighbors: &Arc<ShardedNeighborMap>,
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
    // (junos-ping, #3020), so where such a term exists an ICMP verdict is a
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
    // The accepted residual: a type-constrained DENY ahead of a broader permit is
    // not enforced on this path — the walk falls to the permit and the session
    // survives. See `PolicyState::icmp_verdict_may_depend_on_type` for why
    // widening the arming would not change that outcome and would cost #8356
    // coverage, and for what closing it would actually require.
    //
    // The predicate is whole-snapshot and therefore conservative (see
    // `PolicyState::icmp_verdict_may_depend_on_type`): one junos-ping permit
    // anywhere declines ICMP box-wide, which is precisely #8356's behaviour.
    // The failure mode of the coarseness is "no worse than before", never "acts
    // on a verdict it could not derive".
    if forwarding
        .policy
        .icmp_verdict_may_depend_on_type(meta.protocol)
    {
        return if gate.fail_closed_icmp {
            revocation_for_hit(sessions, session_key)
        } else {
            None
        };
    }
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
    // The forward pair, judged as itself: the packet's tuple and protocol with
    // the from-zone resolved live from the packet's arrival interface (#9384),
    // except that a fabric arrival keeps the entry's recorded zone (the fabric
    // link's zone is structurally not the flow's).
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
    };
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
    };
    match zone_policy_deny_on_session_hit(forwarding, &input) {
        ZonePolicyJudgment::Permit | ZonePolicyJudgment::Decline => None,
        ZonePolicyJudgment::Revoke => Some(PolicyRevocation {
            canonical_key: None,
            decision: input.decision,
            metadata: input.metadata,
            origin,
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
        SessionOrigin::ForwardFlow | SessionOrigin::LocalMiss | SessionOrigin::MissingNeighborSeed
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
/// Stamping is HIT-ONLY: on PERMIT only the hit (reverse) entry is marked. The
/// forward half is never written from this path, so no cross-direction
/// equivalence is claimed; the forward half re-derives (cold-only) on its next
/// packet of the generation.
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
        PolicyRevalidationTarget::Fresh => {
            sessions.revalidation_canonical_key(session_key)?
        }
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
            let Some((fwd_decision, fwd_metadata, fwd_origin)) =
                sessions.entry_with_origin(&fwd_key)
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
            let from_source =
                reverse_companion_from_source(sessions, fwd_origin, &fwd_metadata)?;
            let fwd_flow = SessionFlow {
                src_ip: fwd_key.src_ip,
                dst_ip: fwd_key.dst_ip,
                forward_key: fwd_key.clone(),
            };
            let mut fwd_meta = meta;
            fwd_meta.protocol = fwd_key.protocol;
            let mut revocation = sessionless_zone_policy_verdict(
                forwarding,
                fwd_decision,
                &fwd_metadata,
                &fwd_flow,
                fwd_meta,
                from_source,
                fwd_origin,
            )?;
            // The local forward companion is authoritative, so this uses the
            // ordinary pair-revocation shape rather than drop-only.
            revocation.canonical_key = Some(fwd_key);
            return Some(revocation);
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
    // The companion itself is part of the reverse freshness decision: a
    // reverse row must still cold-judge when its forward companion is
    // FabricRedirect or carries fenced provenance — and without a
    // companion, when the reverse row itself is fenced or Live.
    // #10635: `companion_needs_live` keys on FENCED provenance, not bare
    // !LiveEgress. A never-validated (stale `Unvalidated`) forward carries
    // no recorded authorization — fencing it manufactures a DENY for a row
    // that never earned one (#8618): with any type-constrained ICMP permit
    // configured, GATE 1b returns before stamping, so every locally
    // admitted forward stays Unvalidated and the first reply of every ICMP
    // session revoked itself (b03-F1). `RecordedEgress` and fresh
    // `Unvalidated` (A1/A2 reset-distrust) keep fencing exactly as before.
    let companion_needs_live = if reverse_has_intent {
        match sessions.entry_with_origin(&fwd_key) {
            Some((fwd_decision, _, _)) => {
                fwd_decision.resolution.disposition == ForwardingDisposition::FabricRedirect
                    || sessions.policy_revalidation_fenced(&fwd_key)
            }
            // No forward companion: fence a FENCED or Live reverse row. A
            // never-validated reverse (e.g. shared-materialized, gen-0
            // Unvalidated) has no recorded Permit to protect — revoking it
            // kills legitimate lone-reverse replies (r02-F3). Recorded and
            // Live reverses (Cell 6 shape) still fail closed below: a Live
            // row retains a recorded Permit and must never coast (stale or fresh: the forward ledger is orphaned).
            None => {
                sessions.policy_revalidation_fenced(&rev_canonical)
                    || matches!(rev_kind, PolicyRevalidationKind::LiveEgress)
            }
        }
    } else {
        false
    };
    let force_reverse_cold = rev_force_cold || companion_needs_live;
    // Inconsistent-companion arms fail closed when the reverse packet would
    // locally forward and its own row needs cold, or the companion itself
    // demands live. A Fresh Live row with a good companion coasts.
    let reverse_inconsistent_fail_closed =
        (reverse_has_intent && reverse_row_needs_cold) || companion_needs_live;
    if matches!(rev_target, PolicyRevalidationTarget::Fresh) && !force_reverse_cold {
        return None;
    }
    let Some((mut fwd_decision, fwd_metadata, fwd_origin)) =
        sessions.entry_with_origin(&fwd_key)
    else {
        // A locally-forwarding reverse hit with no companion is not allowed
        // to retain a recorded Permit or take the old reverse Decline arm.
        // #9604: no tuple synthesis — zones would degrade to recorded-swapped with no live ledger.
        // #10635: ...unless the reverse row itself never earned one. A
        // never-validated (stale `Unvalidated`) reverse carries no recorded
        // authorization to fence — revoking it kills legitimate
        // lone-reverse replies (materialized/shared shapes, r02-F3). Coast;
        // Recorded and Live reverses (Cell 6 shape) still fail closed.
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
    // #10507 reverse-first fence: when this packet would locally forward and
    // the stored forward companion is recorded or otherwise non-live, resolve
    // that companion from the current local FIB plus HA/lease snapshot. A
    // reverse Permit stamps only the reverse row; the forward row remains cold.
    // Deliberate bare !LiveEgress (not fenced): re-resolution must re-derive any non-live companion.
    let stored_fwd_kind = sessions.policy_revalidation_kind(&fwd_key);
    if reverse_has_intent
        && (fwd_decision.resolution.disposition == ForwardingDisposition::FabricRedirect
            || !matches!(stored_fwd_kind, PolicyRevalidationKind::LiveEgress))
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
            // here. Cell 1 phase 1 pins SyncImport retention (recorded Permit
            // + punt, no revoke); #7770 pins seed retention. No per-origin
            // distinction — all FabricRedirect companions retain identically.
            return None;
        } else {
            // No valid current egress and not a redirect (NoRoute,
            // HAInactive, would-forward without egress): the reverse packet
            // must not locally forward on its stored Permit — fail closed.
            return revocation_for_hit(sessions, session_key);
        }
    }
    if tun_origin_forward(&fwd_decision, &fwd_metadata, fwd_origin) {
        return None;
    }
    if forwarding
        .policy
        .icmp_verdict_may_depend_on_type(fwd_key.protocol)
    {
        return if rev_fail_closed_icmp || companion_needs_live {
            revocation_for_hit(sessions, session_key)
        } else {
            None
        };
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
    };
    match zone_policy_deny_on_session_hit(forwarding, &input) {
        ZonePolicyJudgment::Permit => {
            // #10507: reverse evidence only proves the reverse row's policy
            // walk. Never stamp or update the forward companion here.
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
    let result = evaluate_policy_result_without_counting(
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
mod tests {
    use super::*;

    fn marker_forward_10038() -> (SessionDecision, SessionMetadata, SessionOrigin) {
        (
            SessionDecision {
                resolution: ForwardingResolution {
                    disposition: ForwardingDisposition::ForwardCandidate,
                    local_ifindex: 0,
                    egress_ifindex: 400,
                    tx_ifindex: 6,
                    tunnel_endpoint_id: 1,
                    next_hop: None,
                    neighbor_mac: None,
                    src_mac: None,
                    tx_vlan_id: 0,
                },
                nat: NatDecision::default(),
                install_table_domain: 0,
                install_table_check: 0,
            },
            SessionMetadata {
                ingress_zone: 5,
                egress_zone: 5,
                ingress_zone_check: 0,
                egress_zone_check: 0,
                ingress_ifindex: 0,
                ingress_vlan_id: 0,
                owner_rg_id: 1,
                fabric_ingress: false,
                is_reverse: false,
                nat64_reverse: None,
                log_session_init: false,
                log_session_close: false,
                policy_id: 0,
                inactivity_timeout_ns: None,
                policy_counter_idx: 0,
                policy_counter: None,
            },
            SessionOrigin::TunOrigin,
        )
    }

    /// #10038: the discriminator truth table — positive provenance. ONLY
    /// `TunOrigin` matches; every other origin (the full HA-synced family
    /// included — a `SyncImport` is NEVER TUN-origin, however closely its
    /// metadata aliases) fails, as does flipping any shape conjunct alone.
    #[test]
    fn tun_origin_forward_table_10038() {
        let (decision, metadata, origin) = marker_forward_10038();
        assert!(tun_origin_forward(&decision, &metadata, origin));
        // Every other origin fails — including the whole HA-synced family:
        // SyncImport (the legacy-transit alias — see the dedicated cell
        // below), SharedMaterialize, WorkerLocalImport, SharedPromote (TUN
        // never promotes, so a promoted entry is by definition not TUN),
        // ForwardFlow/ReverseFlow (MISS installs, the spoof-plant shape),
        // LocalMiss and the transient seeds.
        for origin in [
            SessionOrigin::SyncImport,
            SessionOrigin::SharedMaterialize,
            SessionOrigin::WorkerLocalImport,
            SessionOrigin::SharedPromote,
            SessionOrigin::ForwardFlow,
            SessionOrigin::ReverseFlow,
            SessionOrigin::LocalMiss,
            SessionOrigin::MissingNeighborSeed,
            SessionOrigin::FabricPuntSeed,
        ] {
            assert!(
                !tun_origin_forward(&decision, &metadata, origin),
                "{origin:?} must not match"
            );
        }
        // Each remaining conjunct flipped alone.
        let mut rev = metadata.clone();
        rev.is_reverse = true;
        assert!(!tun_origin_forward(&decision, &rev, origin));
        let mut ingress = metadata.clone();
        ingress.ingress_ifindex = 400;
        assert!(!tun_origin_forward(&decision, &ingress, origin));
        let mut untunneled = decision;
        untunneled.resolution.tunnel_endpoint_id = 0;
        assert!(!tun_origin_forward(&untunneled, &metadata, origin));
        let mut admitted = metadata.clone();
        admitted.policy_counter_idx = 1;
        assert!(!tun_origin_forward(&decision, &admitted, origin));
    }

    /// #10038: the exemption's companion lookup — local-first (a non-marker
    /// local forward DECIDES, shadowing a shared marker), shared-only marker
    /// exempts (the WG production shape), lone reverse fails closed, and a
    /// degenerate self-inverse key fails closed.
    #[test]
    fn tun_origin_reverse_exempt_lookup_10038() {
        let nat = NatDecision::default();
        let fwd_key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 17,
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 1)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 5)),
            src_port: 5001,
            dst_port: 5002,
            discriminator: crate::session::TunnelDiscriminator::None,
            routing_domain: 0,
        };
        let rev_key = crate::session::reverse_session_key(&fwd_key, nat);
        assert_ne!(fwd_key, rev_key);
        let (decision, metadata, _) = marker_forward_10038();
        let install_local = |sessions: &mut SessionTable,
                             origin: SessionOrigin,
                             ingress: u32,
                             policy_idx: u32| {
            let mut meta = metadata.clone();
            meta.ingress_ifindex = ingress;
            meta.policy_counter_idx = policy_idx;
            assert!(
                sessions.install_with_protocol_with_origin(
                    fwd_key.clone(),
                    decision,
                    meta,
                    origin,
                    122_000_000_000,
                    17,
                    0,
                ),
                "local forward must install"
            );
        };
        let shared_entry = |origin: SessionOrigin| SyncedSessionEntry {
            key: fwd_key.clone(),
            decision,
            metadata: metadata.clone(),
            leak_incarnation: 0,
            origin,
            protocol: 17,
            tcp_flags: 0,
            generation: 0,
            session_id: 0,
            tcp_close_class: 0,
        };
        let fresh_shared = || Arc::new(Mutex::new(FastMap::default()));

        // Local marker → exempt.
        let mut sessions = SessionTable::new();
        install_local(&mut sessions, SessionOrigin::TunOrigin, 0, 0);
        assert!(tun_origin_reverse_exempt(&sessions, &fresh_shared(), &rev_key, nat));

        // Local non-marker + shared marker → DENY (local shadows shared).
        let mut sessions = SessionTable::new();
        install_local(&mut sessions, SessionOrigin::ForwardFlow, 400, 1);
        let shared = fresh_shared();
        shared.lock().expect("shared map").insert(fwd_key.clone(), shared_entry(SessionOrigin::TunOrigin));
        assert!(!tun_origin_reverse_exempt(&sessions, &shared, &rev_key, nat));

        // Shared-only marker → exempt (WG production: the forward never
        // materializes locally).
        let sessions = SessionTable::new();
        let shared = fresh_shared();
        shared.lock().expect("shared map").insert(fwd_key.clone(), shared_entry(SessionOrigin::TunOrigin));
        assert!(tun_origin_reverse_exempt(&sessions, &shared, &rev_key, nat));

        // Shared-only non-marker → deny.
        let sessions = SessionTable::new();
        let shared = fresh_shared();
        shared
            .lock()
            .expect("shared map")
            .insert(fwd_key.clone(), shared_entry(SessionOrigin::ForwardFlow));
        assert!(!tun_origin_reverse_exempt(&sessions, &shared, &rev_key, nat));

        // Lone reverse (no forward anywhere) → deny (fail-closed).
        let sessions = SessionTable::new();
        assert!(!tun_origin_reverse_exempt(&sessions, &fresh_shared(), &rev_key, nat));

        // Degenerate self-inverse key (src==dst, ports equal) → deny.
        let loop_key = SessionKey {
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 5,
            dst_port: 5,
            ..fwd_key.clone()
        };
        assert_eq!(crate::session::reverse_session_key(&loop_key, nat), loop_key);
        let sessions = SessionTable::new();
        assert!(!tun_origin_reverse_exempt(&sessions, &fresh_shared(), &loop_key, nat));
    }

    /// #10522 Cell 3: an owner-arrival reverse LocalDelivery with a
    /// TUN-origin forward companion is exempt from the two NEW-session gates.
    /// That exemption is an explicit per-packet proof and keeps the trusted
    /// outlet positive control intact.
    #[test]
    fn tun_origin_reverse_exempt_gate_proof_selects_trusted_10522() {
        let nat = NatDecision::default();
        let fwd_key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 17,
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 1)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 5)),
            src_port: 5001,
            dst_port: 5002,
            discriminator: crate::session::TunnelDiscriminator::None,
            routing_domain: 0,
        };
        let rev_key = crate::session::reverse_session_key(&fwd_key, nat);
        let (decision, metadata, _) = marker_forward_10038();
        let mut sessions = SessionTable::new();
        assert!(sessions.install_with_protocol_with_origin(
            fwd_key,
            decision,
            metadata,
            SessionOrigin::TunOrigin,
            122_000_000_000,
            17,
            0,
        ));
        let shared = Arc::new(Mutex::new(FastMap::default()));
        let gate_proof = tun_origin_reverse_exempt(&sessions, &shared, &rev_key, nat);
        assert!(gate_proof, "owner-arrival TUN-origin reply must be exempt");
        assert!(
            crate::afxdp::tx::dispatch::reinject_host_authorized(
                ForwardingDisposition::LocalDelivery,
                gate_proof,
            ),
            "the exemption proof must preserve the trusted LocalDelivery outlet",
        );
    }

    /// Parent-review item 5: the legacy-HA-transit alias is closed. A
    /// legacy-peer's transit import — `SyncImport`, tunnel egress, folded
    /// zero ingress, zeroed counter (`session_sync.rs` defaults missing
    /// fields to 0), even a PRESERVED admitting PolicyID (per
    /// `sync_gen_guard_test.go`) — satisfies every shape conjunct yet must
    /// NOT match: only positive `TunOrigin` provenance matches. Pinned at
    /// both the predicate and the exemption-lookup level.
    #[test]
    fn tun_origin_legacy_ha_transit_import_does_not_match_10038() {
        let (decision, mut metadata, _) = marker_forward_10038();
        // The legacy import shape: admitting PolicyID preserved, counter
        // zeroed by wire truncation.
        metadata.policy_id = 41;
        assert!(
            !tun_origin_forward(&decision, &metadata, SessionOrigin::SyncImport),
            "a legacy transit import must not match, PolicyID or not"
        );
        // And through the exemption lookup: a shared SyncImport alias-shape
        // forward must not exempt its reverse.
        let nat = NatDecision::default();
        let fwd_key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 17,
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 1)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 123, 0, 5)),
            src_port: 5001,
            dst_port: 5002,
            discriminator: crate::session::TunnelDiscriminator::None,
            routing_domain: 0,
        };
        let rev_key = crate::session::reverse_session_key(&fwd_key, nat);
        let sessions = SessionTable::new();
        let shared = Arc::new(Mutex::new(FastMap::default()));
        shared.lock().expect("shared map").insert(
            fwd_key.clone(),
            SyncedSessionEntry {
                key: fwd_key.clone(),
                decision,
                metadata,
                leak_incarnation: 0,
                origin: SessionOrigin::SyncImport,
                protocol: 17,
                tcp_flags: 0,
                generation: 0,
                session_id: 0,
                tcp_close_class: 0,
            },
        );
        assert!(
            !tun_origin_reverse_exempt(&sessions, &shared, &rev_key, nat),
            "a legacy alias-shape forward must not exempt"
        );
        // Provenance lifecycle: local (never peer-synced, never promoted),
        // preserved across materialize/replica (else the first HIT would
        // re-tag the marker away).
        assert!(SessionOrigin::TunOrigin.is_local_tun_origin());
        assert!(!SessionOrigin::TunOrigin.is_peer_synced());
        assert!(!SessionOrigin::TunOrigin.is_promotable_synced());
        assert_eq!(
            SessionOrigin::TunOrigin.materialized_shared_hit_origin(),
            SessionOrigin::TunOrigin
        );
        assert_eq!(
            SessionOrigin::TunOrigin.worker_replica_origin(),
            SessionOrigin::TunOrigin
        );
    }

    fn gate_current_base_10507() -> ForwardingResolution {
        ForwardingResolution {
            disposition: ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            egress_ifindex: 24,
            tx_ifindex: 24,
            tunnel_endpoint_id: 0,
            next_hop: None,
            neighbor_mac: None,
            src_mac: None,
            tx_vlan_id: 0,
        }
    }

    /// #10507 rule-4 mapping pin: only would-forward WITH a valid egress
    /// is LocalForwarding; would-forward WITHOUT egress is NoEgress
    /// (fail-closed), never NonLocal (which would coast/retain). All
    /// other dispositions map NonLocal via the wildcard arm.
    #[test]
    fn gate_current_splits_noegress_from_nonlocal_10507() {
        assert_eq!(
            policy_gate_current_for_resolution(gate_current_base_10507()),
            PolicyGateCurrent::LocalForwarding
        );
        let mut noegress = gate_current_base_10507();
        noegress.egress_ifindex = 0;
        noegress.tx_ifindex = 0;
        assert_eq!(
            policy_gate_current_for_resolution(noegress),
            PolicyGateCurrent::LocalForwardingNoEgress,
            "would-forward without egress is rule-4 fail-closed, never NonLocal"
        );
        let mut missing = gate_current_base_10507();
        missing.disposition = ForwardingDisposition::MissingNeighbor;
        assert_eq!(
            policy_gate_current_for_resolution(missing),
            PolicyGateCurrent::LocalForwarding
        );
        let mut missing_noegress = gate_current_base_10507();
        missing_noegress.disposition = ForwardingDisposition::MissingNeighbor;
        missing_noegress.egress_ifindex = 0;
        assert_eq!(
            policy_gate_current_for_resolution(missing_noegress),
            PolicyGateCurrent::LocalForwardingNoEgress
        );
        for disposition in [
            ForwardingDisposition::FabricRedirect,
            ForwardingDisposition::NoRoute,
            ForwardingDisposition::HAInactive,
            ForwardingDisposition::TableUnavailable,
            ForwardingDisposition::LocalDelivery,
            ForwardingDisposition::PolicyDenied,
            ForwardingDisposition::DiscardRoute,
            ForwardingDisposition::NextTableUnsupported,
        ] {
            let mut nonlocal = gate_current_base_10507();
            nonlocal.disposition = disposition;
            nonlocal.egress_ifindex = 0;
            assert_eq!(
                policy_gate_current_for_resolution(nonlocal),
                PolicyGateCurrent::NonLocal,
                "non-local dispositions stay NonLocal even with egress 0 (#9513 retention)"
            );
        }
    }
}
