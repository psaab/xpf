//! Per-WG-tunnel status rows (`ProcessStatus.wg_tunnels`).
//!
//! Split out of `coordinator/status.rs` by #7936, which pushed that file past
//! the 1500-LOC [WATCH] floor. The seam is a real one rather than a line-count
//! convenience: this is the only builder in that file that joins THREE
//! coordinator maps (`tunnel_endpoints`, `wg_engines`, `wg_control_threads`),
//! it is the only one producing a repeated wire ROW rather than scalars, and it
//! owns its own name-fallback policy (#1873). Everything it needs is
//! `pub(crate)` on `Coordinator`, so the move is mechanical.

use super::Coordinator;
use chrono::Utc;
use std::sync::atomic::Ordering;

use crate::afxdp::monotonic_nanos;
use crate::afxdp::neighbor::monotonic_timestamp_to_datetime;

impl Coordinator {
    /// #1865: per-WG-tunnel telemetry rows for `ProcessStatus.wg_tunnels`.
    /// One row per `mode == "wireguard"` tunnel endpoint with a live
    /// engine, sorted by endpoint id for deterministic wire output but
    /// KEYED by tunnel name (`ifindex_to_name`; positional ids renumber
    /// across commits — #1873). A missing name falls back to
    /// `wg-endpoint-<id>` rather than dropping the row: broken bring-up
    /// is exactly when telemetry matters. Counter loads are relaxed and
    /// NOT transactional across fields (each atomic is read
    /// independently while the control thread increments — fine for
    /// observability, same posture as every other counter family).
    pub fn wg_tunnel_statuses(&self) -> Vec<crate::protocol::WgTunnelStatus> {
        let mut ids: Vec<u16> = self
            .forwarding
            .tunnel_endpoints
            .iter()
            .filter(|(_, ep)| ep.mode == "wireguard")
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        if ids.is_empty() {
            return Vec::new();
        }
        let now_wall = Utc::now();
        let now_mono = monotonic_nanos();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(endpoint) = self.forwarding.tunnel_endpoints.get(&id) else {
                continue;
            };
            let Some(engine) = self.forwarding.wg_engines.get(&id) else {
                continue;
            };
            // #7936: five-tuple snapshot of this tunnel's endpoint resolver.
            let resolver = self
                .wg_control_threads
                .get(&id)
                .and_then(|e| e.resolver_telemetry.as_ref())
                .map(|t| t.snapshot())
                .unwrap_or_default();
            // Name fallback chain (plan §3.2 / Codex code-r1 F1):
            // ifindex_to_name → the snapshot row's attachment label →
            // wg-endpoint-<id>. A row is never dropped, and the
            // stable logical name wins over the positional id even
            // when the live ifindex map has no entry (broken
            // bring-up — exactly when telemetry matters).
            let tunnel = self
                .forwarding
                .ifindex_to_name
                .get(&endpoint.logical_ifindex)
                .cloned()
                .or_else(|| {
                    (!endpoint.interface_label.is_empty()).then(|| endpoint.interface_label.clone())
                })
                .unwrap_or_else(|| format!("wg-endpoint-{id}"));
            let c = engine.counters();
            // Stamp-0 guard (plan §3.3 / SMR r2): a zero stamp means
            // "never" and must NOT run through the monotonic→wall
            // conversion (which would render ~boot time as a
            // valid-looking date). A pre-epoch/failed conversion also
            // maps to 0, never a wrapped huge value (Codex r2 note).
            let stamp = c.last_handshake_complete_ns.load(Ordering::Relaxed);
            let last_handshake_unix_secs = if stamp == 0 {
                0
            } else {
                monotonic_timestamp_to_datetime(stamp, now_mono, now_wall)
                    .map(|dt| dt.timestamp().max(0) as u64)
                    .unwrap_or(0)
            };
            // #1434 multi-peer: one status row per configured peer. The
            // endpoint is read from the ENGINE table (so a runtime-learned
            // endpoint surfaces, not just the configured one), and the
            // confirmed-session flag is per-peer.
            let engine_endpoints: std::collections::HashMap<[u8; 32], Option<std::net::SocketAddr>> =
                engine.peer_endpoints().into_iter().collect();
            let peers = endpoint
                .wg_peers
                .iter()
                .map(|p| crate::protocol::WgPeerStatus {
                    peer_pubkey_hex: crate::afxdp::wg::encode_wg_key_hex(&p.pubkey),
                    peer_endpoint: engine_endpoints
                        .get(&p.pubkey)
                        .copied()
                        .flatten()
                        .map(|ep| ep.to_string())
                        .unwrap_or_default(),
                    session_confirmed: engine.peer_has_confirmed_session(&p.pubkey),
                })
                .collect();
            out.push(crate::protocol::WgTunnelStatus {
                tunnel,
                tunnel_endpoint_id: id,
                listen_port: endpoint.wg_listen_port,
                // #1434 Increment 1: surface our local static public key
                // (the key an operator hands to the peer). Sourced from
                // the engine, not the snapshot — the snapshot redacts the
                // local PRIVATE key (`skip_serializing`), so the public
                // key derived at engine construction is the only place to
                // read it. Hex string on the wire (MEMORY #1961).
                local_pubkey_hex: crate::afxdp::wg::encode_wg_key_hex(&engine.local_public_key()),
                peers,
                last_handshake_unix_secs,
                hs_initiations_created: c.hs_initiations_created.load(Ordering::Relaxed),
                hs_initiation_build_failures: c
                    .hs_initiation_build_failures
                    .load(Ordering::Relaxed),
                hs_responses_created: c.hs_responses_created.load(Ordering::Relaxed),
                hs_completions_initiator: c.hs_completions_initiator.load(Ordering::Relaxed),
                hs_rx_drops_mac1_mismatch: c.hs_rx_drops_mac1_mismatch.load(Ordering::Relaxed),
                hs_rx_drops_malformed: c.hs_rx_drops_malformed.load(Ordering::Relaxed),
                hs_rx_drops_crypto: c.hs_rx_drops_crypto.load(Ordering::Relaxed),
                hs_rx_drops_unknown_peer: c.hs_rx_drops_unknown_peer.load(Ordering::Relaxed),
                hs_rx_drops_stale_response: c.hs_rx_drops_stale_response.load(Ordering::Relaxed),
                hs_rx_drops_index_exhausted: c.hs_rx_drops_index_exhausted.load(Ordering::Relaxed),
                hs_rx_drops_replayed_init: c.hs_rx_drops_replayed_init.load(Ordering::Relaxed),
                hs_rx_cookie_unsupported: c.hs_rx_cookie_unsupported.load(Ordering::Relaxed),
                hs_rx_cookie_consumed: c.hs_rx_cookie_consumed.load(Ordering::Relaxed),
                hs_cookie_replies_sent: c.hs_cookie_replies_sent.load(Ordering::Relaxed),
                hs_rx_under_load_no_mac2: c.hs_rx_under_load_no_mac2.load(Ordering::Relaxed),
                hs_rx_under_load_mac2_ok: c.hs_rx_under_load_mac2_ok.load(Ordering::Relaxed),
                hs_cookie_reply_budget_drops: c
                    .hs_cookie_reply_budget_drops
                    .load(Ordering::Relaxed),
                rx_unknown_type: c.rx_unknown_type.load(Ordering::Relaxed),
                hs_send_errors: c.hs_send_errors.load(Ordering::Relaxed),
                hs_requests_armed: c.hs_requests_armed.load(Ordering::Relaxed),
                decap_packets: c.decap_packets.load(Ordering::Relaxed),
                decap_bytes: c.decap_bytes.load(Ordering::Relaxed),
                decap_keepalives: c.decap_keepalives.load(Ordering::Relaxed),
                decap_drops_malformed_header: c
                    .decap_drops_malformed_header
                    .load(Ordering::Relaxed),
                decap_drops_unknown_session: c.decap_drops_unknown_session.load(Ordering::Relaxed),
                decap_drops_counter_ceiling: c.decap_drops_counter_ceiling.load(Ordering::Relaxed),
                decap_drops_crypto: c.decap_drops_crypto.load(Ordering::Relaxed),
                decap_drops_replay: c.decap_drops_replay.load(Ordering::Relaxed),
                decap_drops_allowed_ips: c.decap_drops_allowed_ips.load(Ordering::Relaxed),
                decap_drops_malformed_inner: c.decap_drops_malformed_inner.load(Ordering::Relaxed),
                decap_drops_buffer: c.decap_drops_buffer.load(Ordering::Relaxed),
                rx_unsteered_transport_drops: c
                    .rx_unsteered_transport_drops
                    .load(Ordering::Relaxed),
                encap_packets: c.encap_packets.load(Ordering::Relaxed),
                encap_bytes: c.encap_bytes.load(Ordering::Relaxed),
                encap_drops_no_session: c.encap_drops_no_session.load(Ordering::Relaxed),
                encap_drops_unconfirmed: c.encap_drops_unconfirmed.load(Ordering::Relaxed),
                encap_drops_rekey_required: c.encap_drops_rekey_required.load(Ordering::Relaxed),
                encap_drops_other: c.encap_drops_other.load(Ordering::Relaxed),
                encap_mtu_drops: c.encap_mtu_drops.load(Ordering::Relaxed),
                transport_send_errors: c.transport_send_errors.load(Ordering::Relaxed),
                tun_write_errors: c.tun_write_errors.load(Ordering::Relaxed),
                tun_rx_drops_no_endpoint: c.tun_rx_drops_no_endpoint.load(Ordering::Relaxed),
                encap_drops_expired: c.encap_drops_expired.load(Ordering::Relaxed),
                decap_drops_expired: c.decap_drops_expired.load(Ordering::Relaxed),
                sessions_expired: c.sessions_expired.load(Ordering::Relaxed),
                rekeys_initiated_age: c.rekeys_initiated_age.load(Ordering::Relaxed),
                rekeys_initiated_dead_peer: c.rekeys_initiated_dead_peer.load(Ordering::Relaxed),
                rekeys_initiated_keepalive_no_session: c
                    .rekeys_initiated_keepalive_no_session
                    .load(Ordering::Relaxed),
                keepalives_tx_passive: c.keepalives_tx_passive.load(Ordering::Relaxed),
                keepalives_tx_persistent: c.keepalives_tx_persistent.load(Ordering::Relaxed),
                pending_aborted_attempt_window: c
                    .pending_aborted_attempt_window
                    .load(Ordering::Relaxed),
                // #7936: endpoint-resolver telemetry, from the coordinator's
                // own Arc rather than from the resolver — the resolver is a
                // local of the control thread and is unreachable from here.
                //
                // A tunnel with no telemetry entry reports zeros. That is not a
                // fallback hiding a lookup failure: a tunnel whose peers are all
                // IP literals starts no resolver at all (#7158), so zero is the
                // true answer, and a tombstoned entry has the same meaning for
                // the same reason.
                endpoint_resolve_ok: resolver.0,
                endpoint_resolve_fail: resolver.1,
                endpoint_family_mismatch: resolver.2,
                endpoint_changed: resolver.3,
                endpoint_last_error: resolver.4.clone(),
            });
        }
        out
    }
}
