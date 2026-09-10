//! #9519: INGRESS AUTHORITY on an established-session hit.
//!
//! ## The defect
//!
//! `SessionKey` carries no zone and no logical ingress — the 5-tuple, the
//! tunnel discriminator and the routing domain (#7160), nothing else. The flow
//! cache DOES key on logical ingress (#5139), so a packet from a second zone
//! misses the cache and is handed to the authoritative lookup, which returns the
//! first zone's entry without asking where the packet came from. Everything
//! downstream then treated the packet as the entry's own:
//!
//! * it was FORWARDED under the entry's permit, NAT and egress, and no policy of
//!   the zone it actually arrived in was consulted;
//! * with the entry's policy stamp Fresh, nothing was checked at all;
//! * with the stamp Stale, the packet RE-DERIVED the entry — and since #9384 the
//!   re-derivation judges the pair from the packet's arrival zone. Measured on
//!   `3b24fe26e`: one TCP ACK from a `dmz` interface carrying a live `lan` tuple
//!   revoked the `lan` session (`policy_revoked_sessions = 1`, zero rows left).
//!   A foreign PERMIT re-stamped the owner's entry instead, shielding it from its
//!   own zone's narrowed policy until the next commit;
//! * #7212 had the same shape (a foreign interface's static input filter revoked
//!   the owner's session), and the host-inbound gate judged a host-bound packet
//!   by the OWNER's zone services.
//!
//! ## The rule
//!
//! A packet is the session's OWNER when it arrived in the zone that admitted the
//! session: the packet's LIVE arrival zone, resolved exactly as admission
//! resolves it (`resolve_ingress_logical_ifindex`, then `ifindex_to_zone_id`;
//! #9383), equals `metadata.ingress_zone`. Zone, not ifindex, for the reason
//! #7169's `ReverseIngress` gives: a zone spans interfaces, so a LAG member, an
//! ECMP path or a second unit in the same zone is the same authority. A reverse
//! companion records the zone the forward flow went TO, so a reply is the owner
//! exactly when it comes back from there — #7169's rule for the reverse
//! fallback, now applied to the direct hit too.
//!
//! A decapsulated GRE or WireGuard packet needs no case of its own: decap
//! rebuilds the meta with the TUNNEL's logical ifindex (`logical_ingress.rs`),
//! so it resolves to the tunnel's zone at admission and at every later hit.
//!
//! **Fabric ingress is exempt**, as at every sibling site (#7169, #9384). It
//! arrives on the fabric link, whose zone is structurally not the flow's, and
//! the peer already adjudicated it.
//!
//! An owner is the ONLY packet that re-derives the entry (#8356), which is what
//! makes the generation-only policy stamp sound: every packet that can consult
//! or write it judges from the entry's own zone.
//!
//! ## What a FOREIGN packet gets
//!
//! It is judged by the policy of the zone it ARRIVED in, and the verdict applies
//! to THIS packet:
//!
//! * **permit** — forwarded on the entry;
//! * **deny** — dropped, counted in `foreign_authority_drops`.
//!
//! Either way it does not act on the session: no #7212 revocation, no #8356
//! re-derivation or re-stamp, no host-inbound teardown, no flow-cache seed.
//!
//! One foreign packet MAY revoke: one that arrived on the session's own
//! admitting interface. That interface did not move between zones by itself —
//! a commit moved it — so this is #9384's case, not a spoof, and the session is
//! revoked exactly as #8356 would revoke it for an owner. The admitting
//! interface is the `(ingress_ifindex, ingress_vlan_id)` pair the session was
//! stamped with (#4983), trusted only for origins stamped from THIS node's
//! frame. An import carries the PEER's ifindex (`session_sync.rs`), a promoted
//! or replicated entry keeps that metadata, and a peer's ifindex can equal an
//! unrelated local one. A reverse companion and a fabric-seeded entry record 0
//! (#4983, #7096) and never qualify. A type-constrained ICMP verdict never
//! revokes, for #8618's reason.
//!
//! ## Why not an ordinary MISS
//!
//! The table cannot hold two sessions for one key:
//! `install_with_protocol_with_origin` REPLACES an existing key. A miss that
//! installed would overwrite the owner's entry with the foreign zone's —
//! reallocating NAT under a live flow and syncing the replacement to the peer.
//! That is a hijack, the same class of harm this change closes. Adjudicating in
//! place keeps the policy question and loses the overwrite. It is still not a
//! blanket drop: a flow whose ingress legitimately moves between permitted zones
//! (a multi-homed WAN, an asymmetric path) keeps forwarding.
//!
//! How the question is asked:
//!
//! * FORWARD — `(arrival_zone -> metadata.egress_zone)` on the
//!   POST-destination-translation tuple, as #8356 asks it (#9382). The to-zone is
//!   the entry's, not the live resolution's: an HA-inactive hit has already been
//!   rewritten into a fabric redirect by the time this runs, and the fabric
//!   link's zone is not where the flow goes.
//! * REVERSE — the same pair on the WIRE destination. A reply's only destination
//!   translation is an un-SNAT, which admission never applies to a new flow;
//!   judging the un-translated client would let a foreign zone reach an internal
//!   host through a pool address no policy names.
//! * HOST-BOUND (`LocalDelivery`) — passed through here and judged downstream by
//!   the host-inbound gate and `junos-host` policy of the ARRIVAL zone, which is
//!   where host-bound authority lives.
//!
//! ## Residuals
//!
//! * The lookup that found the entry has already refreshed its idle time, and a
//!   synced hit may already have been materialized or promoted. A foreign packet
//!   can keep an idle session alive; it cannot change what the session does.
//! * A permitted foreign packet whose entry is HA-inactive here rides the fabric
//!   redirect computed inside the lookup, which carries the entry's zone stamp.
//! * A deny drops silently: no reject reply, no RT_FLOW deny record.
//! * A session whose admitting interface is moved into another zone that still
//!   PERMITS it is adjudicated per packet, uncached, until it ends.
//! * A packet from a second interface in the owner's OWN zone is an owner, so
//!   #7212's static-filter revocation can still be driven from there. That is a
//!   per-interface filter question, not a zone one.

use super::policy_revalidation::PolicyRevocation;
use super::*;
use crate::policy::evaluate_policy_result_without_counting;
use crate::session::{SessionDecision, SessionKey, SessionMetadata, SessionOrigin};

/// Whether THIS packet may act for the session it hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HitAuthority {
    /// Arrived in the admitting zone, or over the fabric. The ordinary hit path
    /// applies unchanged, revalidation included.
    Owner,
    /// Arrived in a different zone. `arrival_zone` is the live zone the packet
    /// is judged by (0 when the arrival resolves to none);
    /// `on_admitting_interface` is the #9384 re-zone case, the one foreign
    /// arrival allowed to revoke.
    Foreign {
        arrival_zone: u16,
        on_admitting_interface: bool,
    },
}

#[inline]
pub(super) fn session_hit_authority(
    forwarding: &ForwardingState,
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    meta: UserspaceDpMeta,
    packet_fabric_ingress: bool,
) -> HitAuthority {
    if packet_fabric_ingress {
        return HitAuthority::Owner;
    }
    let arrival_logical = resolve_ingress_logical_ifindex(
        forwarding,
        meta.ingress_ifindex as i32,
        meta.ingress_vlan_id,
    )
    .unwrap_or(meta.ingress_ifindex as i32);
    let arrival_zone = forwarding
        .ifindex_to_zone_id
        .get(&arrival_logical)
        .copied()
        .unwrap_or(0);
    if arrival_zone == metadata.ingress_zone {
        return HitAuthority::Owner;
    }
    HitAuthority::Foreign {
        arrival_zone,
        on_admitting_interface: arrived_on_the_admitting_interface(metadata, origin, meta),
    }
}

fn arrived_on_the_admitting_interface(
    metadata: &SessionMetadata,
    origin: SessionOrigin,
    meta: UserspaceDpMeta,
) -> bool {
    matches!(
        origin,
        SessionOrigin::ForwardFlow | SessionOrigin::LocalMiss | SessionOrigin::MissingNeighborSeed
    ) && metadata.ingress_ifindex != 0
        && metadata.ingress_ifindex == meta.ingress_ifindex
        && metadata.ingress_vlan_id == meta.ingress_vlan_id
}

/// What the hit path does with a FOREIGN packet.
pub(super) enum ForeignHitVerdict {
    /// Forward on the entry, acting on nothing.
    Forward,
    /// Drop THIS packet; the session is untouched.
    Drop,
    /// The session's own admitting interface now sits in a zone that denies the
    /// flow (#9384): revoke it, through the same teardown #8356 uses.
    Revoke(PolicyRevocation),
}

#[cold]
#[inline(never)]
#[allow(clippy::too_many_arguments)]
pub(super) fn foreign_hit_verdict(
    forwarding: &ForwardingState,
    sessions: &SessionTable,
    session_key: &SessionKey,
    metadata: &SessionMetadata,
    decision: SessionDecision,
    flow: &SessionFlow,
    meta: UserspaceDpMeta,
    packet_frame: &[u8],
    arrival_zone: u16,
    on_admitting_interface: bool,
) -> ForeignHitVerdict {
    if decision.resolution.disposition == ForwardingDisposition::LocalDelivery {
        return ForeignHitVerdict::Forward;
    }
    let (dst_ip, dst_port) = if metadata.is_reverse {
        (flow.dst_ip, flow.forward_key.dst_port)
    } else {
        (
            decision.nat.rewrite_dst.unwrap_or(flow.dst_ip),
            decision
                .nat
                .rewrite_dst_port
                .unwrap_or(flow.forward_key.dst_port),
        )
    };
    let result = evaluate_policy_result_without_counting(
        &forwarding.policy,
        arrival_zone,
        metadata.egress_zone,
        flow.src_ip,
        dst_ip,
        meta.protocol,
        flow.forward_key.src_port,
        dst_port,
        policy_packet_icmp(packet_frame, meta),
    );
    if matches!(result.action, crate::policy::PolicyAction::Permit) {
        return ForeignHitVerdict::Forward;
    }
    if !on_admitting_interface
        || metadata.is_reverse
        || forwarding
            .policy
            .icmp_verdict_may_depend_on_type(meta.protocol)
    {
        return ForeignHitVerdict::Drop;
    }
    match sessions.revalidation_canonical_key(session_key) {
        Some(canonical_key) => ForeignHitVerdict::Revoke(PolicyRevocation { canonical_key }),
        None => ForeignHitVerdict::Drop,
    }
}

#[cfg(test)]
#[path = "session_hit_authority_tests.rs"]
mod tests;
