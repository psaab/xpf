//! WireGuard engine instantiation for `build_forwarding_state` (#1432
//! S2a). Builds one `Arc<WgEngine>` per `mode == "wireguard"` tunnel
//! endpoint and stores it in `ForwardingState.wg_engines`, keyed by
//! tunnel_endpoint_id.
//!
//! ## Reload stability (plan §4.2)
//!
//! A fresh `WgEngine` per commit resets its `Tai64nClock` and drops all
//! live transport sessions. A kernel WG peer rejects any handshake whose
//! TAI64N is `<=` the last it accepted, so naively rebuilding the engine
//! on every reload causes a re-handshake storm and can permanently
//! black-hole a tunnel.
//!
//! Two cases, both driven off the `previous` `ForwardingState`:
//!
//!   - **Identity unchanged** — if the previous state holds an engine for
//!     the same endpoint and the WG identity tuple (listen_port,
//!     local_privkey, peer_pubkey, allowed_ips, endpoint, keepalive) is
//!     byte-for-byte unchanged, **clone the existing `Arc<WgEngine>` and
//!     do NOT call `reconcile_peers`.** Workers across the reload window
//!     still hold the old `ForwardingState` Arc (and thus the same engine
//!     Arc); mutating shared engine state here would be observed by those
//!     workers. Cloning the Arc keeps the TAI64N clock and live sessions
//!     and avoids any cross-reload engine mutation.
//!
//!   - **Identity changed (or new)** — construct a fresh `WgEngine` (which
//!     reconciles the new peer set at construction) and **seed its TAI64N
//!     high-water from the prior engine** so initiator-timestamp
//!     monotonicity survives the rebuild. This has three sides: the
//!     OUTGOING initiator clock (one engine-wide value, #1432) via
//!     `seed_tai64n_high_water`, the #4092 INCOMING per-peer
//!     responder anti-replay high-water (`Peer::greatest_tai64n`) via
//!     `seed_greatest_tai64n`, keyed by pubkey (#4103), and the #14640
//!     per-peer adopted live endpoint via `seed_live_endpoints`, keyed
//!     by pubkey and carried only when that peer's configured endpoint
//!     is unchanged. Without the incoming side, a routine WG commit (add allowed-ip, rotate a PSK,
//!     add/remove a peer) would reset every surviving peer's responder
//!     high-water to `[0; 12]` and silently disarm the anti-replay.
//!     Without the live-endpoint side, editing one peer would revert
//!     every other peer to its stale configured endpoint (or `None`
//!     for responder-only peers), blackholing hub->peer traffic until
//!     that peer next sends authenticated traffic. Live
//!     sessions are dropped (a real config change re-handshakes once,
//!     seeded so the peer accepts it); S5 adds session migration if
//!     needed.

use super::super::wg::{WgEngine, WgEngineConfig, WgPeerConfig};
use super::super::*;
use std::sync::Arc;

pub(super) fn populate_wg_engines(
    state: &mut ForwardingState,
    previous: Option<&ForwardingState>,
) {
    if !state.has_wg_tunnels {
        return;
    }
    for (&id, endpoint) in state.tunnel_endpoints.iter() {
        if endpoint.mode != "wireguard" {
            continue;
        }
        // #1434: build one WgPeerConfig per configured peer (the engine
        // peer table is multi-peer; the table-feeding collapse to one
        // peer is gone). The peer order is the snapshot order, which the
        // Go builder sorts by pubkey.
        let peers: Vec<WgPeerConfig> = endpoint
            .wg_peers
            .iter()
            .map(|p| WgPeerConfig {
                pubkey: p.pubkey,
                endpoint: p.endpoint,
                persistent_keepalive: p.keepalive_secs,
                allowed_ips: p.allowed_ips.clone(),
                // #4103 F12: clone the Zeroizing carrier (no plaintext
                // deref-copy) — both source and dest are Zeroizing<[u8; 32]>.
                preshared_key: p.preshared_key.clone(),
            })
            .collect();
        // Identity-stable reuse: same endpoint id with an unchanged WG
        // identity tuple reuses the prior engine Arc verbatim.
        if let Some(prev_state) = previous {
            if let (Some(prev_engine), Some(prev_endpoint)) = (
                prev_state.wg_engines.get(&id),
                prev_state.tunnel_endpoints.get(&id),
            ) {
                if wg_identity_unchanged(prev_endpoint, endpoint) {
                    state.wg_engines.insert(id, prev_engine.clone());
                    continue;
                }
            }
        }
        // Config changed or new: fresh engine, seeded from the prior
        // engine's TAI64N high-water (if any) so monotonicity survives.
        let engine = WgEngine::new(WgEngineConfig {
            // #4103 F12: clone the Zeroizing carrier (no plaintext
            // deref-copy) — both are Zeroizing<[u8; 32]>.
            local_private_key: endpoint.wg_local_privkey.clone(),
            listen_port: endpoint.wg_listen_port,
            peers,
        });
        if let Some(prev_state) = previous {
            if let Some(prev_engine) = prev_state.wg_engines.get(&id) {
                if let Some(hw) = prev_engine.tai64n_high_water() {
                    engine.seed_tai64n_high_water(hw);
                }
                // #4103: `seed_tai64n_high_water` above only re-seeds the
                // OUTGOING initiator clock (#1432). The #4092 INCOMING
                // per-peer responder anti-replay high-water
                // (`Peer::greatest_tai64n`) would otherwise reset to
                // [0; 12] on this identity-change rebuild, so a routine WG
                // commit (add allowed-ip, rotate a PSK, add/remove a peer)
                // would silently disarm the anti-replay: an attacker who
                // captured a valid type-1 initiation could replay it. Carry
                // each SURVIVING peer's high-water forward, keyed by pubkey
                // (a new/changed pubkey correctly starts fresh — a
                // different peer identity). Matches kernel / wireguard-go,
                // which retain per-peer `last_timestamp` across reconfigure.
                engine.seed_greatest_tai64n(&prev_engine.greatest_tai64n_by_pubkey());
                // #14640: carry each surviving peer's adopted live
                // endpoint forward, keyed by pubkey, only when that
                // peer's configured endpoint is unchanged. Editing one
                // peer must not revert every other peer's roamed/NATed
                // endpoint to its stale configured address (or None
                // for responder-only peers). If a peer's own configured
                // endpoint was edited, the new configured value wins.
                engine.seed_live_endpoints(&prev_engine.live_endpoints_by_pubkey());
            }
        }
        state.wg_engines.insert(id, Arc::new(engine));
    }
}

/// Whether two WG endpoints have a byte-identical WG identity tuple, so
/// the engine Arc can be reused across a reload without `reconcile_peers`.
/// #1434: the per-peer set is compared via `wg_peers_eq` (order-sensitive
/// — the Go builder sorts by pubkey, so a stable config is stable order).
fn wg_identity_unchanged(prev: &TunnelEndpoint, next: &TunnelEndpoint) -> bool {
    prev.wg_listen_port == next.wg_listen_port
        && *prev.wg_local_privkey == *next.wg_local_privkey
        && super::tunnels::wg_peers_eq(&prev.wg_peers, &next.wg_peers)
}
