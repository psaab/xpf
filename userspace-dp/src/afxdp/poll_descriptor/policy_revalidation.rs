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
//! **1. FORWARD ONLY.** The filter stamp is per-direction on purpose. This one
//! must not be. The reverse companion is built with SWAPPED zones
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
use crate::policy::evaluate_policy_result_without_counting;
use crate::session::{PolicyRevalidationTarget, SessionKey};

/// A zone-policy re-derivation that came back NON-PERMIT (`Deny` or `Reject`,
/// #9381). Carries the CANONICAL key —
/// the primary-index key, which on the NAT reverse-translated alias path is NOT
/// the wire tuple that found it — so the teardown acts on the session that was
/// actually judged.
pub(super) struct PolicyRevocation {
    pub(super) canonical_key: SessionKey,
}

/// Re-derive zone policy for an established-session HIT, at most once per
/// session per `config_generation`.
///
/// Returns `Some` only when the live policy does NOT PERMIT a flow this node is
/// still forwarding — `Deny` or `Reject`, #9381 — and the caller revokes. `None`
/// is the answer for every packet but one per session per generation.
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
    // recorded zone is the only honest answer. It is a property of the PACKET,
    // not of the session: `metadata.fabric_ingress` says the session was
    // INSTALLED from a fabric-punted packet, which tells you nothing about where
    // this one arrived.
    packet_fabric_ingress: bool,
) -> Option<PolicyRevocation> {
    let flow = flow?;
    // GATE 1, and it is free: the reverse companion is never independently
    // policy-adjudicated. See item 1 in the module header — getting this wrong
    // denies the reply of every permitted flow. `is_reverse` is already on the
    // metadata the lookup returned, so this costs no lookup at all and excludes
    // roughly half the established-hit population before anything is hashed.
    if metadata.is_reverse {
        return None;
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
        return None;
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
    // lookup, so host-bound hits pay nothing for it.
    if decision.resolution.disposition == super::ForwardingDisposition::LocalDelivery {
        return None;
    }
    let canonical_key = match sessions.policy_revalidation_target(session_key) {
        PolicyRevalidationTarget::Fresh => return None,
        // No entry this tuple may safely name (#2120 transient synced hit, or a
        // reused slab slot). There is nothing to stamp and nothing to tear down,
        // and deriving a verdict we could not act on would only risk acting on
        // the WRONG session. Same answer #7212 gives.
        PolicyRevalidationTarget::NoLocalEntry => return None,
        PolicyRevalidationTarget::Stale(k) => k,
    };
    zone_policy_deny_on_session_hit(
        forwarding,
        sessions,
        canonical_key,
        metadata,
        decision,
        flow,
        meta,
        packet_fabric_ingress,
    )
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
    sessions: &mut SessionTable,
    canonical_key: SessionKey,
    metadata: &crate::session::SessionMetadata,
    decision: crate::session::SessionDecision,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    packet_fabric_ingress: bool,
) -> Option<PolicyRevocation> {
    let egress_ifindex = decision.resolution.egress_ifindex;
    // #9384: resolve the FROM-zone LIVE from this packet's arrival interface,
    // symmetric with the to-zone, which has always been resolved live from
    // `decision.resolution.egress_ifindex`.
    //
    // It used to be handed `Some(metadata.ingress_zone)` — the ENTRY's zone,
    // which the override makes win over the live ingress map
    // (`forwarding/mod.rs`) and which also made the ifindex argument dead. The
    // asymmetry is exactly the one the module header promised was absent: *"a
    // commit that moves an interface BETWEEN ZONES is caught"* was true of the
    // EGRESS side only. An operator moving an interface OUT of a permitted zone
    // to cut off access got the new verdict for new flows while every live
    // session kept being judged under the zone it was admitted in, was stamped
    // fresh, and kept forwarding. Go's commit-time invalidation cannot cover it
    // either: it compares policy match/action text and referenced-object
    // fingerprints and never diffs zone MEMBERSHIP.
    //
    // Two things make this safe rather than a revoke storm:
    //
    // 1. FABRIC INGRESS keeps the entry's zone. A fabric-punted packet arrives
    //    on the fabric link from the peer, so its arrival zone is structurally
    //    not the flow's — resolving live there would evaluate (fabric -> X) and
    //    revoke every cross-chassis flow, which is a correctness break, not a
    //    hardening. The discriminator is the PACKET's fabric ingress, not the
    //    session's `metadata.fabric_ingress`: a session installed from a
    //    fabric-punted packet whose later packets arrive locally should be
    //    judged on where THEY arrived.
    // 2. An arrival that resolves to NO zone falls to the existing `from_id == 0`
    //    DECLINE below, not to a revocation. See the residual noted there.
    //
    // #9383: the live resolution goes through `resolve_ingress_logical_ifindex`.
    // Keying `ifindex_to_zone_id` on the raw physical index would reintroduce the
    // logical-vs-physical defect on a trunk, and this is the site that would make
    // it a revocation rather than a mis-attribution.
    let arrival_logical = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let (from_id, to_id) = zone_pair_ids_for_flow_with_override(
        forwarding,
        arrival_logical,
        packet_fabric_ingress.then_some(metadata.ingress_zone),
        egress_ifindex,
    );
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
    let egress_unresolved = egress_ifindex == 0;
    // The ingress half is the same split. A FABRIC packet keeps the ENTRY's zone
    // (#9384), so its lookup failure is an entry that was never zone-adjudicated;
    // for every other packet it is an arrival with no interface identity at all.
    let ingress_unresolved = if packet_fabric_ingress {
        metadata.ingress_zone == 0
    } else {
        arrival_logical == 0
    };
    if egress_unresolved || ingress_unresolved {
        return None;
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
    // The SOURCE deliberately stays pre-translation (`flow.src_ip`): Junos
    // evaluates policy after destination NAT and BEFORE source NAT, and admission
    // passes `flow.src_ip` for the same reason.
    let policy_dst_ip = decision.nat.rewrite_dst.unwrap_or(flow.dst_ip);
    let policy_dst_port = decision
        .nat
        .rewrite_dst_port
        .unwrap_or(flow.forward_key.dst_port);
    let result = evaluate_policy_result_without_counting(
        &forwarding.policy,
        from_id,
        to_id,
        flow.src_ip,
        policy_dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
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
        // NAT translation untouched. Re-stamp so no later packet of this
        // generation re-derives the same verdict.
        sessions.mark_policy_revalidated(&canonical_key);
        return None;
    }
    // DENY or REJECT: deliberately NOT re-stamped — see the header.
    Some(PolicyRevocation { canonical_key })
}
