// #1345: per-verb handler for sync_session. Body byte-identical to
// handlers.rs lines 309-342 (preserves the nested match on
// sync_req.operation).

use super::super::helpers::{build_synced_session_entry, build_synced_session_key, SyncedKeyIntent};
use crate::afxdp::SessionDomain;
use crate::afxdp::{SYNCED_DELETE_REFUSED_PREFIX, SYNCED_IMPORT_REFUSED_PREFIX};
use crate::{ControlResponse, SessionSyncRequest};

/// #7209: served from the SESSION-DOMAIN HANDLE, not from `&mut ServerState`.
///
/// This verb arrives on its own socket and its own thread (#452) but dispatched
/// through the same `Arc<Mutex<ServerState>>` as `apply_snapshot`, which holds
/// that mutex across a 10 s worker-readiness barrier, a 500 ms mlx5 teardown
/// quiesce, worker `join()`s and BPF map-pin opens. Go budgets 3 s for a session
/// round-trip and #5380 ABORTS the remainder of a bulk batch on the first
/// transport failure, so the contention cost was never latency — it was up to
/// 255 dropped session mirrors during the failover this path exists to serve.
///
/// Nothing here reads `ServerState`'s other three fields; the handler only ever
/// touched `guard.afxdp`, and every field it reaches through it is already
/// shared state (see `afxdp/ha/session_domain.rs`).
pub(super) fn handle(
    domain: &SessionDomain,
    session_sync: Option<SessionSyncRequest>,
    response: &mut ControlResponse,
) {
    let Some(sync_req) = session_sync else {
        response.ok = false;
        response.error = "missing session sync request".to_string();
        return;
    };
    // #7160 (#2387): resolve the imported session's routing DOMAIN from the
    // #7095 cluster-stable ingress identity, which the sender resolved into
    // THIS node's own ifindex/vlan before the request got here. Derived, never
    // wire-carried — see `Coordinator::synced_routing_domain`.
    //
    // THREE states, and the third is the one that matters. `Some(0)` is the
    // default routing instance and is correct; `Some(n)` is a tenant's; `None`
    // is "this node runs routing instances and the request named nothing to
    // resolve one from". The two verbs answer `None` differently, because the
    // cost of guessing runs opposite ways:
    //   * UPSERT refuses. Importing under domain 0 would file the session in
    //     the DEFAULT instance's identity space, where a reply that resolved
    //     its own domain can reach it through the domain-agnostic fallback
    //     probe — the HA half of the collision #7160 closes.
    //   * DELETE proceeds at domain 0 and lets the per-domain sweep below do
    //     the work. A refused delete LEAKS a session; a delete that sweeps one
    //     domain too many removes nothing that was not named by the 5-tuple.
    // #7239: PREFER the domain the sender stamped at install over one derived
    // here from the resolved ingress identity. The derivation is downstream of
    // the #7095 fold, which the sender computes against its CURRENT config, so
    // an ifindex recycled onto a sibling between install and sync makes the
    // derivation name the wrong tenant — confidently, since the two-pass
    // reverse preference then matches a reply in that tenant's domain on pass
    // 1. A carried value is immune to a later recycle by construction.
    //
    // Non-zero means the sender STATED a tenant domain. Zero is ambiguous on
    // the wire — it is both the default instance and what a peer predating the
    // field sends — so it falls through to the derivation, preserving the
    // pre-#7239 behaviour for an old peer, #8116's unresolvable-domain refusal
    // included.
    // Three states, decoded rather than defaulted (#7188's shape, and its
    // reason). PRESENT means the sender stated a domain — including the DEFAULT
    // instance, which is a statement and not a silence, so it does NOT fall
    // through to the derivation. ABSENT is a peer predating the field, which
    // keeps the pre-#7239 behaviour including #8116's unresolvable-domain
    // refusal. UNRECOGNIZED is a value this build cannot place, and coercing it
    // into a domain would file the session under an identity we cannot
    // reproduce — the reasoning #7188 refuses on, transferred verbatim.
    // #7209: ONE load of the published runtime view for the whole request. The
    // domain resolution, the zone-name map and the per-domain delete retry all
    // read forwarding; taking three loads would let one request resolve its
    // domain against one generation and its zones against another — the pairing
    // defect #6592 closed, reintroduced at the handler layer.
    let view = domain.view();
    let resolved_domain = match crate::session::routing_domain_from_wire(sync_req.routing_domain) {
        crate::session::WireRoutingDomain::Present(d) => Some(d),
        crate::session::WireRoutingDomain::Absent => {
            view.synced_routing_domain(sync_req.ingress_ifindex, sync_req.ingress_vlan_id)
        }
        crate::session::WireRoutingDomain::Unrecognized => {
            domain.note_unknown_routing_domain_import();
            response.ok = false;
            response.error =
                format!("{SYNCED_IMPORT_REFUSED_PREFIX}routing-domain-unrecognized");
            return;
        }
    };
    match sync_req.operation.as_str() {
        "upsert" if resolved_domain.is_none() => {
            domain.note_unknown_routing_domain_import();
            response.ok = false;
            response.error = format!(
                "{SYNCED_IMPORT_REFUSED_PREFIX}{}",
                crate::afxdp::SyncedImportOutcome::RejectedUnknownRoutingDomain
                    .refusal_reason()
                    .expect("a rejection always carries a reason token")
            );
        }
        "upsert" => match build_synced_session_entry(
            &sync_req,
            view.zone_name_to_id(),
            resolved_domain.expect("the None arm above already returned"),
        ) {
            Ok(entry) => {
                // #6785: a SEMANTIC refusal (stale generation / import cap /
                // translated-tuple reserve) used to return `()` and leave
                // `response.ok` true, so Go recorded a success and kept the BPF
                // mirror row for a session this helper never took — the split
                // truth #5305's transactional install already knows how to
                // compensate, but could not, because the only failure it could
                // see was an IPC error. Report the refusal so that rollback runs.
                //
                // The reason token is prefixed so Go can tell a refusal from a
                // transport failure. That distinction is load-bearing, not
                // cosmetic: a transport failure means the session socket is sick
                // and gates takeover-readiness (#5247), whereas a refusal is the
                // correct answer from a HEALTHY helper and must not block
                // failover on a node that is working.
                let outcome = domain.upsert_synced_session(entry);
                if let Some(reason) = outcome.refusal_reason() {
                    response.ok = false;
                    response.error =
                        format!("{SYNCED_IMPORT_REFUSED_PREFIX}{reason}");
                }
            }
            Err(err) => {
                response.ok = false;
                response.error = err;
            }
        },
        // #7188: a delete reconstructs the key with `Delete` intent, so a peer
        // that could not state the tunnel discriminator retracts the `None`
        // class rather than being refused. A delete can only under-match; it
        // never publishes an identity, which is the reason the install arm
        // above fails closed and this one does not.
        //
        // #7160 (#2387) makes the identical argument on the ROUTING DOMAIN
        // axis, which is why the two land on the same line: an unresolvable
        // domain refuses on upsert and resolves to 0 here, because a refused
        // delete LEAKS a session while an under-matching one removes nothing
        // the 5-tuple did not already name. Two different fields, one rule —
        // fail closed where an identity is PUBLISHED, fail open where one is
        // only RETRACTED.
        "delete" => match build_synced_session_key(
            &sync_req,
            resolved_domain.unwrap_or(0),
            SyncedKeyIntent::Delete,
        ) {
            Ok(key) => {
                // #9714: a delete the Go side marked as made on behalf of the PEER
                // is refused for a live local session whose owner RG is locally
                // active; every other delete stays authoritative.
                let delete = |key| {
                    if sync_req.peer_delete {
                        domain.delete_peer_synced_session(key);
                    } else {
                        domain.delete_synced_session(key);
                    }
                };
                delete(key.clone());
                // #7160 (#2387): a bare-5-tuple delete (the `clear security
                // flow session` / batch-revoke path) carries no ingress
                // identity, so the key above resolved domain 0 and the exact
                // delete cannot reach a session that lives in a routing
                // instance.
                //
                // #8636: RESOLVE the domain, or REFUSE. This used to delete the
                // tuple in EVERY configured domain. Routing instances exist to
                // carry OVERLAPPING address space, so two tenants holding the
                // same 5-tuple is the normal case rather than a corner — and
                // the retry then tore down the other tenant's live session. The
                // rationale it was written under ("a refused delete LEAKS while
                // an under-matching one removes nothing the 5-tuple did not
                // already name") is true on the #7188 DISCRIMINATOR axis it was
                // written for and does not carry to this one: deleting in every
                // domain removes sessions the 5-tuple names in OTHER TENANTS,
                // which is precisely removing something it did not name.
                //
                // So probe first and act on the count. Same loop, same slow
                // path, same handful of domains — a lookup instead of a delete.
                //
                // WHY REFUSING IS NOW CHEAP, and it was not before today. The
                // objection to failing closed is that a session survives a
                // policy invalidation that should have killed it. #8356 changed
                // that: zone policy is re-derived on the established-session hit
                // path once per `config_generation`, a commit bumps the
                // generation and invalidates the flow cache, so the next packet
                // of a surviving session is judged and revoked if the live
                // policy denies. And EVERY reason the Go side invalidates for is
                // a zone-policy change (PolicyDeleted / PolicyModified /
                // DefaultPolicyChanged), so the populations coincide exactly. A
                // refused delete therefore leaks for ONE PACKET, not until idle
                // timeout.
                //
                // The residual is where that re-derivation DECLINES — ICMP under
                // a type-constrained permit (#8618), an unresolvable zone
                // (`to_id == 0 || from_id == 0`), `NoLocalEntry` — INTERSECTED
                // with "the tuple is ambiguous", since a unique tuple is deleted
                // exactly as before. Every member of that intersection fails
                // toward keeping a session too long rather than tearing down
                // another tenant's, which is the direction that makes it
                // acceptable rather than merely small.
                if key.routing_domain == 0 {
                    let mut matched: Vec<u32> = Vec::new();
                    for rd in view.routing_domains() {
                        let mut scoped = key.clone();
                        scoped.routing_domain = rd;
                        if domain.synced_session_contains(&scoped) {
                            matched.push(rd);
                        }
                    }
                    match matched.as_slice() {
                        // No routing-instance copy. The exact delete above was
                        // the whole job; empty in every deployment with no
                        // routing-instance interface membership.
                        [] => {}
                        // Exactly one domain holds it, so the bare tuple names
                        // it unambiguously. This is STRICTLY better than the
                        // old fan-out: it deletes the same session and touches
                        // no other domain.
                        [rd] => {
                            let mut scoped = key.clone();
                            scoped.routing_domain = *rd;
                            delete(scoped);
                        }
                        // Ambiguous: the tuple names a live session in more
                        // than one tenant and nothing in this request says
                        // which. Refuse rather than guess. Go tolerates a
                        // per-key refusal without aborting the batch (#5881),
                        // so the rest of a clear still proceeds.
                        _ => {
                            response.ok = false;
                            response.error = format!(
                                "{SYNCED_DELETE_REFUSED_PREFIX}ambiguous-routing-domain                                  (5-tuple matches {} routing instances)",
                                matched.len()
                            );
                        }
                    }
                }
            }
            Err(err) => {
                response.ok = false;
                response.error = err;
            }
        },
        other => {
            response.ok = false;
            response.error = format!("unknown session sync operation {other}");
        }
    }
}
