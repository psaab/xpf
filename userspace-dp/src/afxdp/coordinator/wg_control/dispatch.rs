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
                    // Under load, cookie-reply budget exhausted — drop
                    // silently (the counter recorded it).
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
                    // shim claims transport data for exactly one port — the
                    // steered one — so a record for any other port reaches this
                    // socket on every path, and writing its plaintext to the TUN
                    // hands it to the kernel's forwarding path with no zone
                    // policy, no session and no counters. `try_decap` has
                    // already authenticated it, so key confirmation, the replay
                    // window and endpoint roaming behave as for a keepalive; the
                    // plaintext is dropped and counted instead of written.
                    if kernel_transport == crate::afxdp::types::WgKernelTransport::DropUnsteered {
                        WgCounters::bump(&engine.counters().rx_unsteered_transport_drops);
                        return InboundOutcome::Authenticated(outcome.peer_pubkey);
                    }
                    // #9594: the STEERED port's record. #8274 kept this TUN write
                    // for ingress the XDP shim does not adjudicate. On an ingress
                    // it DOES adjudicate, a healthy shim claims the record for the
                    // worker, so reaching this socket means the shim took a
                    // degraded arm. Apply the shim's own degraded posture to the
                    // decapsulated packet: traffic addressed to the firewall is
                    // delivered (it meets the nftables input chains), transit is
                    // dropped and counted (it would ride the open forward hook with
                    // no zone policy). See `kernel_path.rs`.
                    let ingress = kernel_path_view.ingress(ingress_ifindex);
                    if ingress != super::kernel_path::WgKernelPathIngress::Uncovered {
                        let inner_is_local =
                            super::kernel_path::inner_destination(&decap_buf[..outcome.len])
                                .is_some_and(|dst| kernel_path_view.destination_is_local(dst));
                        if super::kernel_path::kernel_path_disposition(ingress, inner_is_local)
                            == super::kernel_path::WgKernelPathDisposition::DropDegradedTransit
                        {
                            WgCounters::bump(&engine.counters().rx_degraded_transit_drops);
                            return InboundOutcome::Authenticated(outcome.peer_pubkey);
                        }
                    }
                    // #2317: RFC 6040 §4.2 decap-side ECN combine. The
                    // outer ECN was captured out-of-band via recvmsg's
                    // IP_RECVTOS / IPV6_RECVTCLASS cmsg (the kernel UDP
                    // stack stripped the outer IP header before this WG
                    // record reached userspace). Fold it into the
                    // freshly-decrypted inner IP packet: an outer CE
                    // upgrades an ECN-capable inner to CE (recomputing the
                    // inner IPv4 header checksum), and the illegal
                    // outer-CE / inner-Not-ECT combination is dropped
                    // (counter bumped in apply_decap_ecn_combine). Reuses
                    // the GRE decap combine body, with the WG-specific
                    // illegal-drop counter. Skipped when no TOS cmsg
                    // arrived (`outer_ecn` is None) or the inner family is
                    // unrecognizable — never mutate on a malformed inner.
                    if let Some(outer_ecn) = outer_ecn {
                        let inner = &mut decap_buf[..outcome.len];
                        let inner_family = match inner.first().map(|b| b >> 4) {
                            Some(4) => Some(libc::AF_INET as u8),
                            Some(6) => Some(libc::AF_INET6 as u8),
                            _ => None,
                        };
                        if let Some(fam) = inner_family
                            && !crate::afxdp::gre::apply_decap_ecn_combine(
                                inner,
                                fam,
                                outer_ecn,
                                &crate::afxdp::gre::WG_DECAP_ECN_ILLEGAL_DROPS,
                            )
                        {
                            // Illegal RFC 6040 §4.2 combination — drop the
                            // inner without writing it to the TUN. The
                            // datagram still authenticated (the peer holds
                            // the keys), so endpoint-learning proceeds.
                            return InboundOutcome::Authenticated(outcome.peer_pubkey);
                        }
                    }
                    // Write the plaintext inner IP to the wgN TUN; the
                    // kernel routes/firewalls it (NOT the AF_XDP policy
                    // engine — the AllowedIPs gate inside try_decap is
                    // S2a's inner-src control).
                    //
                    // #2438: the wgN TUN fd is O_NONBLOCK, so this uses
                    // the single-write whole-packet seam
                    // (`write_packet_nonblocking`) — never std
                    // `Write::write_all`, whose short-count stream-resume
                    // would re-write `buf[n..]` and inject the remainder
                    // as a SECOND, malformed inner packet (the #2407
                    // corruption class). The seam retries the WHOLE
                    // packet on WouldBlock/EINTR and drops (counted) on a
                    // genuine partial.
                    if let Err(e) = crate::slowpath::write_packet_nonblocking(
                        tun.as_raw_fd(),
                        &decap_buf[..outcome.len],
                    ) {
                        WgCounters::bump(&engine.counters().tun_write_errors);
                        record_local_tunnel_exception(
                            recent_exceptions,
                            tunnel_name,
                            format!("wg_tun_write:{e}"),
                        );
                    }
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
) {
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
        return;
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
            }
        }
        Err(crate::afxdp::wg::EncapError::NoSession) => {
            // No confirmed session yet — request a handshake for THIS peer
            // (rate-limited, #5164) and drop this packet.
            engine.request_handshake(peer_pubkey, monotonic_nanos());
        }
        Err(_e) => {
            debug_log!("WG[{}]: encap drop reason={:?}", tunnel_name, _e);
        }
    }
}
