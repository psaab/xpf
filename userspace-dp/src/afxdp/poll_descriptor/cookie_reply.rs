// #1697 cold-path extraction: SYN-cookie reply enqueue machinery,
// lifted out of poll_descriptor/mod.rs so the hot ingress loop does not
// carry the cookie/DDoS-path bodies in its codegen unit.
//
// `enqueue_syn_cookie_reply` is on the SYN-cookie challenge path only
// (screen returns ScreenCheckOutcome::SynCookieChallenge), which never
// fires for established transit flows, so it is a true cold/exception
// body — `#[cold] #[inline(never)]` places it in `.text.unlikely`,
// away from the hot loop's cache lines. `syn_cookie_reply_budget_available`
// is a tiny helper called only from the (already-cold) enqueue body, so
// it stays `#[inline]` (let the inliner fold it into its single
// already-cold caller).
//
// The bodies are byte-for-byte identical to their previous location in
// mod.rs; only the enclosing module and the inline attributes change.

use super::worker::WorkerTxPipeline;
use super::*;
use crate::screen::SynCookieChallenge;

pub(super) const SYN_COOKIE_REPLY_PENDING_RESERVE: usize = TX_BATCH_SIZE;

pub(super) enum SynCookieReply {
    SynAck(SynCookieChallenge),
    AckRst,
}

#[inline]
pub(super) fn syn_cookie_reply_budget_available(tx_pipeline: &WorkerTxPipeline) -> bool {
    let max_pending = tx_pipeline.max_pending_tx;
    if max_pending == 0 {
        return false;
    }
    if tx_pipeline.free_tx_frames.len() <= SYN_COOKIE_REPLY_PENDING_RESERVE {
        return false;
    }
    let reserve = SYN_COOKIE_REPLY_PENDING_RESERVE.min(max_pending);
    let admitted = tx_pipeline
        .pending_tx_local
        .len()
        .saturating_add(tx_pipeline.pending_tx_prepared.len());
    admitted < max_pending.saturating_sub(reserve)
}

#[cold]
#[inline(never)]
pub(super) fn enqueue_syn_cookie_reply(
    tx_pipeline: &mut WorkerTxPipeline,
    forwarding: &ForwardingState,
    ifindex: i32,
    packet_frame: &[u8],
    meta: UserspaceDpMeta,
    flow: Option<&SessionFlow>,
    reply: SynCookieReply,
    counters: &mut BatchCounters,
) -> bool {
    if !syn_cookie_reply_budget_available(tx_pipeline) {
        counters.touched = true;
        counters.syn_cookie_reply_budget_drops += 1;
        return false;
    }

    let (bytes, sent_counter): (Option<Vec<u8>>, fn(&mut BatchCounters)) = match reply {
        SynCookieReply::SynAck(challenge) => (
            build_syn_cookie_syn_ack_frame(packet_frame, challenge.cookie_isn, challenge.peer_mss),
            |counters| counters.syn_cookie_syn_ack_sent += 1,
        ),
        SynCookieReply::AckRst => (build_syn_cookie_ack_rst_frame(packet_frame), |counters| {
            counters.syn_cookie_ack_rst_sent += 1
        }),
    };
    let Some(bytes) = bytes else {
        return false;
    };

    // #2238: classify the GENERATED SYN-cookie reply (SYN-ACK or ACK-RST) by
    // its OWN egress 5-tuple + egress interface — the reply egresses on the
    // interface the SYN arrived on, so `ifindex` IS the egress. An output
    // firewall filter terminal `discard`/`reject` (or three-color policer)
    // drops the reply; a parse failure of our own built bytes fails CLOSED
    // (§6.2). A SYN-cookie SYN-ACK dropped by an operator's output filter is
    // a legitimate (rare) choice. Pre-#2238 this enqueued an UNCLASSIFIED
    // TxRequest the drain path honored verbatim — no output filter / CoS /
    // DSCP was applied to the reply.
    //
    // #3035: classify on the LOGICAL egress ifindex, NOT the physical bind
    // `ifindex`. CoS interfaces (forwarding_build/cos.rs) and output filters
    // (filter/compiler.rs) are keyed by the logical unit ifindex; on a VLAN
    // subinterface `ifindex` is the physical parent index, so classifying by
    // it applied the parent's (or first subinterface's) CoS queue / DSCP
    // rewrite / output filter instead of this unit's. Mirrors the #3026
    // generated-ICMP-error fix and the filter/CoS sites via the
    // `resolve_ingress_logical_ifindex` SSOT; the physical `ifindex` is still
    // used for the XSK transmit (`egress_ifindex`) below. For a non-VLAN port
    // the logical and physical indexes coincide, so this is a no-op there.
    let now_ns = monotonic_nanos();
    let classify_ifindex =
        resolve_ingress_logical_ifindex(forwarding, ifindex, meta.ingress_vlan_id)
            .unwrap_or(ifindex);
    let verdict = classify_generated_reply(forwarding, classify_ifindex, &bytes, now_ns);
    if verdict.drop {
        counters.touched = true;
        if verdict.parse_error {
            counters.generated_reply_classify_parse_errors += 1;
        } else {
            counters.syn_cookie_output_filter_drops += 1;
        }
        return false;
    }

    tx_pipeline.pending_tx_local.push_back(TxRequest {
        bytes,
        expected_ports: None,
        expected_addr_family: meta.addr_family,
        expected_protocol: meta.protocol,
        flow_key: flow.map(|flow| flow.forward_key.clone()),
        egress_ifindex: ifindex,
        cos_queue_id: verdict.cos_queue_id,
        dscp_rewrite: verdict.dscp_rewrite,
        mirror_clone: false,
        overlap_admissions: None,
        enqueue_ns: 0,
    });
    counters.touched = true;
    sent_counter(counters);
    true
}

#[cfg(test)]
#[path = "cookie_reply_tests.rs"]
mod tests;
