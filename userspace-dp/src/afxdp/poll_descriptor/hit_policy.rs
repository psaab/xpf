//! #17027: the established-hit zone-policy query, single-sourced.
//!
//! Four sites used to hand-assemble the same question — from-zone,
//! to-zone, judged source, post-DNAT destination, ICMP selector and the
//! packet clock — at `session_hit_authority.rs` (reverse owner ICMP,
//! forward owner ICMP, foreign) and at `policy_revalidation.rs`
//! (`zone_policy_deny_on_session_hit`). Each rule for the question was
//! fixed in one file and had to be rediscovered in the other:
//! #11285's packet clock (#12868), #9384's live to-zone (#13924), and
//! #12867's canonical pre-SNAT source — the last of which never reached
//! the authority verdicts at all before this change. Every difference
//! between the four questions is an input to one query, so the query
//! now has one builder.
//!
//! ## The shared semantics
//!
//! * **To-zone (`hit_egress_zone`):** `FabricRedirect` keeps the
//!   recorded `metadata.egress_zone` — its stored egress names the
//!   fabric TRANSPORT, not the flow's egress, so the live resolution
//!   asks a pair admission never evaluated (#7770). Every other
//!   disposition resolves the LIVE egress zone from the stored egress
//!   ifindex (#9384/#13924): a commit that moves the egress interface
//!   into a denying zone is caught on the next hit. This is the sole
//!   copy of that rule in the established-hit path.
//! * **Source:** forward policy runs after destination NAT and BEFORE source
//!   NAT (Junos order), so the forward query's judged source is the pre-SNAT
//!   original the caller authenticated — the canonical key for a stale entry,
//!   the resolver's `source_nat_validation_key` for a sessionless/foreign alias
//!   (#12867). `ReverseWire` instead judges the packet's wire responder, never
//!   the translated forward alias. Callers resolve the choice; the builder
//!   receives the finished `(src_ip, src_port)` and cannot substitute a tuple.
//! * **Destination:** `ForwardPostDnat` judges the post-translation
//!   tuple (`nat.rewrite_dst` / `rewrite_dst_port`, #9382);
//!   `ReverseWire` judges the WIRE destination — a reply's only
//!   destination translation is an un-SNAT admission never applies
//!   to a new flow (#10637).
//! * **Clock:** every site evaluates at the caller's packet-captured
//!   `now_ns` (#11285/#12868); nothing here reads a fresh clock.

use super::policy_revalidation::FromZoneSource;
use super::*;
use crate::policy::{
    PolicyEvaluationResult, PolicyQuery, PolicyState, evaluate_policy_query,
};
use crate::session::{SessionDecision, SessionMetadata};
use std::net::IpAddr;

/// Which destination the established-hit question judges (#17027).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum QueryDirection {
    /// Forward pair on the POST-destination-translation tuple (#9382).
    ForwardPostDnat,
    /// Reverse pair on the WIRE destination (#10637): the deliberate
    /// exception that judges the reverse pair as itself, on wire tuples.
    ReverseWire,
}

/// The source selected by the caller: the pre-SNAT original for forward
/// queries (#12867), or the wire responder for `ReverseWire`. The builder
/// consumes this finished tuple without substituting another direction's source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct JudgedSource {
    pub(super) ip: IpAddr,
    pub(super) port: u16,
}

impl JudgedSource {
    pub(super) fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

/// The recorded zone is the policy destination only when the stored
/// egress names a fabric transport rather than the flow's actual
/// egress (#7770); otherwise the LIVE egress zone (#9384/#13924).
/// The sole copy of this rule: `hit_policy_query`,
/// `zone_policy_deny_on_session_hit` (via `hit_egress_zone_for`) and
/// the #14318 egress-zone rebinds all read it through here.
#[inline]
pub(super) fn hit_egress_zone(
    forwarding: &ForwardingState,
    metadata: &SessionMetadata,
    decision: SessionDecision,
) -> u32 {
    hit_egress_zone_for(forwarding, metadata.egress_zone, decision)
}

/// [`hit_egress_zone`] with the recorded zone supplied directly, for
/// callers (the revalidation judgment) that carry it on their input
/// rather than on a `SessionMetadata` borrow.
#[inline]
pub(super) fn hit_egress_zone_for(
    forwarding: &ForwardingState,
    recorded_egress_zone: u32,
    decision: SessionDecision,
) -> u32 {
    if decision.resolution.disposition == ForwardingDisposition::FabricRedirect {
        recorded_egress_zone
    } else {
        forwarding.egress_zone_id(decision.resolution.egress_ifindex)
    }
}

/// Build the one established-hit zone-policy query.
///
/// `from` selects a live-ifindex resolution, a recorded zone, or an
/// already-resolved zone id (the foreign arrival); `source` is the selected
/// judged tuple (pre-SNAT original for forward, wire responder for reverse);
/// `direction` picks the post-DNAT or wire destination; `wire_dst`/
/// `wire_dst_port` are the flow's wire destination (the reverse destination
/// and the forward fallback); `protocol`/`icmp`/`now_ns` are the judged
/// protocol, the packet's ICMP selector (or `None` for frame-independent
/// re-derivation) and the packet clock.
///
/// The revalidation caller keeps its `Decline` arms (no egress
/// ifindex, `RecordedZone(0)`, unresolvable live ifindex): those are
/// properties of its input, checked before it builds the query, and
/// the stale-revalidation path additionally resolves its from-zone
/// with the full `zone_pair_ids_for_flow_with_override` ledger walk
/// whose to-zone half it discards in favour of [`hit_egress_zone`].
#[expect(
    clippy::too_many_arguments,
    reason = "#17027: the query's inputs are the four sites' differences; grouping them would re-hide a drift axis"
)]
pub(super) fn hit_policy_query(
    forwarding: &ForwardingState,
    metadata: &SessionMetadata,
    decision: SessionDecision,
    from: FromZoneSource,
    source: JudgedSource,
    wire_dst: IpAddr,
    wire_dst_port: u16,
    protocol: u8,
    direction: QueryDirection,
    icmp: Option<(u8, u8)>,
    now_ns: u64,
) -> PolicyQuery {
    let from_id = match from {
        FromZoneSource::LiveIfindex { ifindex, vlan } => {
            let arrival_logical =
                resolve_ingress_logical_ifindex(forwarding, ifindex, vlan).unwrap_or(ifindex);
            forwarding
                .ifindex_to_zone_id
                .get(&arrival_logical)
                .copied()
                .unwrap_or(0)
        }
        FromZoneSource::RecordedZone(zone) => zone,
        FromZoneSource::Resolved(zone) => zone,
    };
    let to_id = hit_egress_zone(forwarding, metadata, decision);
    let (dst_ip, dst_port) = match direction {
        QueryDirection::ForwardPostDnat => (
            decision.nat.rewrite_dst.unwrap_or(wire_dst),
            decision.nat.rewrite_dst_port.unwrap_or(wire_dst_port),
        ),
        QueryDirection::ReverseWire => (wire_dst, wire_dst_port),
    };
    PolicyQuery::without_counting_at(
        from_id, to_id, source.ip, dst_ip, protocol, source.port, dst_port, icmp, now_ns,
    )
}

/// The permit predicate shared by every established-hit verdict:
/// `Ok(())` iff the query permits, else the evaluation result for
/// attribution (POLICY_DENY / revoke). Positive `Permit` spelling, so
/// `Reject` and any future action fail closed (#9381).
pub(super) fn permits(
    query: &PolicyQuery,
    state: &PolicyState,
) -> Result<(), PolicyEvaluationResult> {
    let result = evaluate_policy_query(state, query);
    if matches!(result.action, crate::policy::PolicyAction::Permit) {
        Ok(())
    } else {
        Err(result)
    }
}

#[cfg(test)]
#[path = "hit_policy_tests.rs"]
mod tests;
