//! WG control-thread inbound dispatch + TUN-read encap: the type-byte
//! dispatch (handshake consume, cookie challenge/consume, transport
//! decap → TUN write), the auth-before-roam `InboundOutcome`
//! contract, and the cryptokey-routed encap-and-send egress helper.

use super::super::*;
use super::mtu::wg_inner_fits_outer_mtu;
use super::sock::wg_send_to;
use crate::afxdp::wg::counters::WgCounters;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;

/// One inbound datagram's disposition. Handshake completions must be
/// handled INLINE at this site — before the same iteration's TUN
/// burst — so the attempt machine's later pass cannot erase legitimate
/// post-completion state (plan v9, Codex r5/r6 ordering traces).
pub(super) enum InboundOutcome {
    /// Failed authentication / cookie / unknown type — no endpoint
    /// learning, no stamps.
    Unauthenticated,
    /// Authenticated transport record (data or keepalive). Carries the
    /// peer that owned the session (#1434: endpoint roaming is
    /// per-peer — we learn THIS peer's endpoint from `from`).
    Authenticated([u8; 32]),
    /// Valid msg2 consumed — initiator-side handshake completion (carries
    /// the responding peer).
    CompletedInitiator([u8; 32]),
    /// Valid msg1 consumed + msg2 sent — responder-side completion
    /// (carries the initiating peer).
    CompletedResponder([u8; 32]),
}

impl InboundOutcome {
    pub(super) fn authenticated(&self) -> bool {
        !matches!(self, InboundOutcome::Unauthenticated)
    }

    /// The authenticated peer's pubkey, if any (#1434 per-peer endpoint
    /// learning).
    pub(super) fn peer(&self) -> Option<[u8; 32]> {
        match self {
            InboundOutcome::Unauthenticated => None,
            InboundOutcome::Authenticated(pk)
            | InboundOutcome::CompletedInitiator(pk)
            | InboundOutcome::CompletedResponder(pk) => Some(*pk),
        }
    }
}

/// Dispatch one inbound WG datagram on its type byte. The returned
/// `InboundOutcome` tells the caller (a) whether the datagram
/// cryptographically AUTHENTICATED — gating endpoint-learning so a
/// spoofed source cannot redirect egress (Codex r3 MAJOR) — and (b)
/// whether it COMPLETED a handshake, which the caller must handle
/// inline (edge drain + post-msg2 keepalive) before this iteration's
/// TUN burst (plan v9 completion-site ordering). Type-3 (cookie),
/// unknown types, and failed authentication are `Unauthenticated`.
#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch_inbound(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    tun: &mut std::fs::File,
    datagram: &[u8],
    from: SocketAddr,
    outer_ecn: Option<u8>,
    decap_buf: &mut [u8],
    response_buf: &mut [u8],
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
    kernel_transport: crate::afxdp::types::WgKernelTransport,
    // #9594: the interface the kernel received this datagram on, and the posture
    // that places it relative to the XDP shim's adjudicated ingress set.
    ingress_ifindex: Option<u32>,
    kernel_path_view: &dyn super::kernel_path::WgKernelPathView,
    // #10597: live control-to-worker queue table. Production always passes
    // this handle; an empty table selects the explicit G6a fallback.
    forward_queues: Option<
        &Arc<
            ArcSwap<
                BTreeMap<
                    u32,
                    Arc<crate::afxdp::wg_uncovered_forward::WgUncoveredIngressQueue>,
                >,
            >,
        >,
    >,
    tunnel_endpoint_id: u16,
    spawned_logical_ifindex: i32,
    // Attachment state computed from the same forwarding Arc that supplies
    // the advisory generations below. A stale attachment never enqueues.
    tun_origin_attached: bool,
    advisory_config_generation: u64,
    advisory_fib_generation: u32,
) -> InboundOutcome {
    let Some(&wg_type) = datagram.first() else {
        return InboundOutcome::Unauthenticated;
    };
    match wg_type {
        crate::afxdp::wg::WG_TYPE_INITIATION => {
            // #4094 PR-A: responder under-load cookie gate. Before spending
            // a Noise handshake, classify the initiation — under load a
            // valid-MAC1 initiation without a valid MAC2 is answered with a
            // type-3 cookie challenge and dropped (no crypto), defeating a
            // spoofed-source initiation flood. `classify_initiation` writes
            // the cookie into `response_buf` only on the SendCookie arm, so
            // the buffer is free for the response on the Process arm.
            let now = engine.now_ns();
            match engine.classify_initiation(datagram, from, response_buf, now) {
                crate::afxdp::wg::InitiationAction::SendCookie(len) => {
                    // Challenge the real source; DROP the initiation. Not
                    // authenticated for endpoint-learning (a cookie reply is
                    // not proof the source holds the keys).
                    if let Err(e) =
                        wg_send_to(socket, socket_is_v6, &response_buf[..len], from, None)
                    {
                        WgCounters::bump(&engine.counters().hs_send_errors);
                        record_local_tunnel_exception(
                            recent_exceptions,
                            tunnel_name,
                            format!("wg_cookie_send:{from}:{e}"),
                        );
                    }
                    return InboundOutcome::Unauthenticated;
                }
                crate::afxdp::wg::InitiationAction::Drop => {
                    // Under load, a valid-MAC2 source admission or the
                    // cookie-reply budget may be exhausted — drop silently.
                    // The relevant counter was recorded by the classifier.
                    return InboundOutcome::Unauthenticated;
                }
                crate::afxdp::wg::InitiationAction::Process => {}
            }
            match engine.consume_initiation_create_response(datagram, response_buf) {
                Ok((peer_pubkey, _local_index)) => {
                    let len = crate::afxdp::wg::WG_MSG_RESPONSE_LEN;
                    // #1865: the response send error was silently
                    // discarded (`let _ =`) — the responder mirror of
                    // the #1736 initiator-EINVAL class. Count + record.
                    match wg_send_to(socket, socket_is_v6, &response_buf[..len], from, None) {
                        Ok(_) => {
                            // #1888 S5: msg2 on the wire is an
                            // authenticated SEND.
                            engine.note_handshake_sent(&peer_pubkey, monotonic_nanos());
                        }
                        Err(e) => {
                            WgCounters::bump(&engine.counters().hs_send_errors);
                            record_local_tunnel_exception(
                                recent_exceptions,
                                tunnel_name,
                                format!("wg_response_send:{from}:{e}"),
                            );
                        }
                    }
                    InboundOutcome::CompletedResponder(peer_pubkey)
                }
                Err(_e) => {
                    debug_log!("WG[{}]: drop initiation reason={:?}", tunnel_name, _e);
                    InboundOutcome::Unauthenticated
                }
            }
        }
        crate::afxdp::wg::WG_TYPE_RESPONSE => match engine.consume_response(datagram) {
            Ok((peer_pubkey, _idx)) => InboundOutcome::CompletedInitiator(peer_pubkey),
            Err(_e) => {
                debug_log!("WG[{}]: drop response reason={:?}", tunnel_name, _e);
                InboundOutcome::Unauthenticated
            }
        },
        crate::afxdp::wg::WG_TYPE_COOKIE => {
            // #4094 PR-B: initiator-side cookie-reply consume. A responder
            // under load answers our valid-MAC1 initiation with a type-3
            // cookie-reply instead of a handshake response; decrypt it and
            // store the cookie so our NEXT initiation to that peer carries a
            // valid MAC2 (completing the handshake under load). NOT
            // authenticated for endpoint-learning: a cookie-reply is
            // XChaCha-sealed under our own public-key-derived key and proves
            // nothing about whether the source holds the peer's keys.
            // consume_cookie_reply counts internally (hs_rx_cookie_consumed
            // on success, hs_rx_cookie_unsupported on a drop).
            if !engine.consume_cookie_reply(datagram, engine.now_ns()) {
                // Reply we could not attribute (no matching in-flight
                // initiation) or could not decrypt (wrong key / bad AAD /
                // tampered).
                debug_log!("WG[{}]: drop cookie (unconsumable)", tunnel_name);
            }
            InboundOutcome::Unauthenticated
        }
        crate::afxdp::wg::WG_TYPE_DATA => {
            match engine.try_decap(datagram, decap_buf) {
                Ok(outcome) => {
                    // #9521: an UNSTEERED listen port's transport record. The
                    // shim claims transport data for the steered listen-port
                    // SET (#9587), so a record for any port outside the set
                    // reaches this socket on every path, and writing its
                    // plaintext to the TUN hands it to the kernel's forwarding path with no zone
                    // policy, no session and no counters. `try_decap` has
                    // already authenticated it, so key confirmation, the replay
                    // window and endpoint roaming behave as for a keepalive; the
                    // plaintext is dropped and counted instead of written.
                    if kernel_transport == crate::afxdp::types::WgKernelTransport::DropUnsteered {
                        WgCounters::bump(&engine.counters().rx_unsteered_transport_drops);
                        return InboundOutcome::Authenticated(outcome.peer_pubkey);
                    }
                    // #9594/#10527: the STEERED port's record. A healthy shim
                    // claims every steered-port transport record on an ingress
                    // it adjudicates, so reaching this socket there means the
                    // shim took a degraded arm. An ingress it does not
                    // adjudicate is the #8274 residual; Half A applies the
                    // same local-vs-transit posture to it instead of allowing
                    // transit through the kernel's open forward hook.
                    // Traffic addressed to the firewall is delivered (it meets
                    // the nftables input chains); transit is dropped and
                    // counted. See `kernel_path.rs`.
                    let ingress = kernel_path_view.ingress(ingress_ifindex);
                    let inner_is_local =
                        super::kernel_path::inner_destination(&decap_buf[..outcome.len])
                            .is_some_and(|dst| kernel_path_view.destination_is_local(dst));
                    if super::kernel_path::kernel_path_disposition(ingress, inner_is_local)
                        == super::kernel_path::WgKernelPathDisposition::DropDegradedTransit
                    {
                        WgCounters::bump(&engine.counters().rx_degraded_transit_drops);
                        return InboundOutcome::Authenticated(outcome.peer_pubkey);
                    }
                    // #10597: every authenticated Deliver disposition now
                    // enters the worker pipeline, including Covered and
                    // Unknown degraded-path host-inbound records. Transit
                    // returned above and is never forwarded. The worker owns
                    // the RFC 6040 combine for this leg, exactly once.
                    if inner_is_local {
                        if !tun_origin_attached {
                            crate::afxdp::wg_uncovered_forward::WG_UNCOVERED_STALE_TOTAL
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return InboundOutcome::Authenticated(outcome.peer_pubkey);
                        }
                        let queue_table = forward_queues.map(|queues| queues.load());
                        if queue_table
                            .as_ref()
                            .map_or(true, |table| table.is_empty())
                        {
                            // No live worker owns this record. Fail closed:
                            // WG decap must never bypass the worker policy
                            // pipeline with a control-thread TUN write.
                            crate::afxdp::wg_uncovered_forward::WG_UNCOVERED_QUEUE_ORPHAN_TOTAL
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return InboundOutcome::Authenticated(outcome.peer_pubkey);
                        }
                        let queue_table = queue_table.expect("non-empty queue table");
                        let Some((_worker_id, queue)) =
                            crate::afxdp::wg_uncovered_forward::steer_uncovered_queue(
                                &queue_table,
                                crate::afxdp::wg_uncovered_forward::wg_uncovered_flow_hash(
                                    &decap_buf[..outcome.len],
                                ),
                            )
                        else {
                            crate::afxdp::wg_uncovered_forward::WG_UNCOVERED_QUEUE_SHED_TOTAL
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return InboundOutcome::Authenticated(outcome.peer_pubkey);
                        };
                        let descriptor =
                            crate::afxdp::wg_uncovered_forward::WgUncoveredDescriptor {
                                tunnel_endpoint_id,
                                logical_ifindex: spawned_logical_ifindex,
                                tunnel_name: tunnel_name.to_string(),
                                inner: decap_buf[..outcome.len].to_vec(),
                                outer_ecn,
                                config_generation: advisory_config_generation,
                                fib_generation: advisory_fib_generation,
                                ingress_ifindex,
                            };
                        match queue.try_enqueue(descriptor) {
                            Ok(()) => {
                                crate::afxdp::wg_uncovered_forward::WG_UNCOVERED_ENQUEUED_TOTAL
                                    .fetch_add(
                                        1,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                            }
                            Err(_descriptor) if queue.is_closed() => {
                                crate::afxdp::wg_uncovered_forward::WG_UNCOVERED_QUEUE_SHED_TOTAL
                                    .fetch_add(
                                        1,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                            }
                            Err(_descriptor) => {
                                crate::afxdp::wg_uncovered_forward::WG_UNCOVERED_QUEUE_FULL_TOTAL
                                    .fetch_add(
                                        1,
                                        std::sync::atomic::Ordering::Relaxed,
                                    );
                            }
                        }
                        return InboundOutcome::Authenticated(outcome.peer_pubkey);
                    }
                    // #10527 Half-A transit posture: no route to the worker
                    // leg and no control-thread TUN fallback. This is the
                    // authenticated transit drop counted above.
                    InboundOutcome::Authenticated(outcome.peer_pubkey)
                }
                Err(crate::afxdp::wg::DecapError::Keepalive(pk)) => {
                    // #7230: an authenticated zero-length keepalive, WITH
                    // the peer it came from. Attribution is proven, not
                    // inferred: try_decap demuxes the session from
                    // hdr.receiver_index before any AEAD work, and the
                    // record is authenticated by the time this variant is
                    // built, so `pk` is the peer that holds those session
                    // keys. Endpoint learning applies on ANY interface,
                    // multi-peer included.
                    InboundOutcome::Authenticated(pk)
                }
                Err(crate::afxdp::wg::DecapError::MalformedInner(pk)) => {
                    // POST-AEAD, so the sender provably holds the session
                    // keys and this counts for endpoint learning — the #1865
                    // basis, and the reason this arm was never a plain drop.
                    //
                    // #7686: the peer identity now comes OUT of the error
                    // rather than being guessed after it. Both construction
                    // sites in `try_decap` have the session in hand (it is
                    // demuxed from `hdr.receiver_index` before any AEAD work),
                    // so this attribution is proven.
                    //
                    // This closes the discard #7230 fixed for keepalives and
                    // deliberately left here. The `single_peer_pubkey()`
                    // fallback that stood at this site returned None on any
                    // MULTI-PEER interface, so a malformed-but-authenticated
                    // inner packet did not roam its peer's endpoint there —
                    // the same defect, one variant over. That fallback is gone
                    // rather than narrowed: it was the mechanism by which a
                    // discarded identity got guessed, and nothing reaches it
                    // any more.
                    InboundOutcome::Authenticated(pk)
                }
                Err(_e) => {
                    debug_log!("WG[{}]: drop transport reason={:?}", tunnel_name, _e);
                    InboundOutcome::Unauthenticated
                }
            }
        }
        _ => {
            // #1865: type byte outside {1,2,3,4}. Zero-length
            // datagrams never reach here (the recv loop's
            // `Ok(_) => break` arm consumes them), so this counter is
            // exactly "well-formed UDP, non-WG type byte".
            WgCounters::bump(&engine.counters().rx_unknown_type);
            debug_log!("WG[{}]: drop unknown type {}", tunnel_name, wg_type);
            InboundOutcome::Unauthenticated
        }
    }
}

/// #10038: what `encap_and_send` did with one TUN-read inner packet.
///
/// The caller publishes the TUN-origin session pair ONLY on `Sent`: every
/// other arm drops the packet after the decision point (MTU guard,
/// no-session handshake request, encap/sent failure), and a session for a
/// request that never left the box would admit replies with no causally-prior
/// outbound packet (GRE's session-implies-emission invariant — its builder
/// encapsulates BEFORE publishing).
pub(super) enum EncapOutcome {
    Sent,
    NoSession,
    MtuDrop,
    EncapFailed,
    SendFailed,
}

/// Encap one inner IP packet read from the TUN and send it to the peer.
/// NoSession arms the (control-thread) initiation timer; a single
/// round-trip increments the WG egress counter exactly once (telemetry
/// is consolidated on the engine, not per call site).
#[allow(clippy::too_many_arguments)]
pub(super) fn encap_and_send(
    engine: &crate::afxdp::wg::WgEngine,
    socket: &UdpSocket,
    socket_is_v6: bool,
    peer_pubkey: &[u8; 32],
    endpoint: SocketAddr,
    inner_ip: &[u8],
    out: &mut [u8],
    outer_mtu: usize,
    tunnel_name: &str,
    recent_exceptions: &Arc<Mutex<ExceptionEventRing>>,
) -> EncapOutcome {
    // Exact pad-aware MTU guard (plan §4.3 / AGY H1) — symmetric with the
    // transit-egress guard in frame/wg.rs, AND against the SAME MTU model
    // (#2300): `outer_mtu` is the real underlay-egress MTU, not the old
    // `WG_OUTER_MTU = 1500` hardcode. #5291: the caller resolves this
    // PER PEER (the SELECTED peer's underlay, via `per_peer_outer_mtu`),
    // so a multi-peer tunnel with asymmetric underlays sizes each peer's
    // encap against its own path — matching the transit path's per-peer
    // resolution (#2845/#3219). Drop oversize
    // inner rather than emitting an outer datagram the kernel must
    // fragment. The wgN TUN MTU (Go-side) is the first line; this is
    // defense-in-depth for a mis-set MTU or a jumbo inner read off the TUN.
    if !wg_inner_fits_outer_mtu(inner_ip.len(), endpoint.is_ipv6(), outer_mtu) {
        // #1865: the #1736 v4-mapped blackhole class — full-MSS inner
        // packets silently vanishing here moved ZERO bytes of forward
        // TCP while pings passed. Now release-visible.
        WgCounters::bump(&engine.counters().encap_mtu_drops);
        debug_log!(
            "WG[{}]: drop oversize inner {} (encapped > {})",
            tunnel_name,
            inner_ip.len(),
            outer_mtu
        );
        return EncapOutcome::MtuDrop;
    }
    // #7758: RFC 6040 §4.1 ingress + uniform DSCP (RFC 2983 §3) -- copy the
    // inner DS byte onto the outer header, exactly as the TRANSIT encap path
    // does (`frame/wg.rs`, #2303) and GRE does (`gre.rs`, #2303).
    //
    // This path is the HOST-ORIGINATED one (inner read from the wgN TUN); the
    // transit path has copied since #2303. Until now the two disagreed, so the
    // same inner marking produced a different outer DSCP depending on whether
    // the packet was transit or host-originated -- an internal routing detail
    // no operator can see, visible to every downstream classifier.
    //
    // Reuses `gre::inner_tos_byte`, the same helper both other paths call, so
    // the three cannot drift in what "the inner DS byte" means. The family is
    // read from the IP version nibble, matching the decap arm above; an
    // unrecognisable inner yields None and sends unmarked rather than guessing
    // a family for a malformed packet.
    let outer_tos = match inner_ip.first().map(|b| b >> 4) {
        Some(4) => Some(crate::afxdp::gre::inner_tos_byte(
            inner_ip,
            libc::AF_INET as u8,
        )),
        Some(6) => Some(crate::afxdp::gre::inner_tos_byte(
            inner_ip,
            libc::AF_INET6 as u8,
        )),
        _ => None,
    };
    match engine.try_encap(peer_pubkey, inner_ip, out) {
        Ok(outcome) => {
            if let Err(e) = wg_send_to(
                socket,
                socket_is_v6,
                &out[..outcome.len],
                endpoint,
                outer_tos,
            ) {
                WgCounters::bump(&engine.counters().transport_send_errors);
                record_local_tunnel_exception(
                    recent_exceptions,
                    tunnel_name,
                    format!("wg_socket_send:{e}"),
                );
                EncapOutcome::SendFailed
            } else {
                EncapOutcome::Sent
            }
        }
        Err(crate::afxdp::wg::EncapError::NoSession) => {
            // No confirmed session yet — request a handshake for THIS peer
            // (rate-limited, #5164) and drop this packet.
            engine.request_handshake(peer_pubkey, monotonic_nanos());
            EncapOutcome::NoSession
        }
        Err(_e) => {
            debug_log!("WG[{}]: encap drop reason={:?}", tunnel_name, _e);
            EncapOutcome::EncapFailed
        }
    }
}
