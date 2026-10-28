// Tunnel-endpoint descriptors split from forwarding.rs (#16209):
// TunnelEndpoint and its WireGuard runtime peer. Pure code motion
// behind `forwarding/mod.rs`'s `use forwarding::*` glob; zero layout
// or access-site change. Visibility bill: no widening.

use super::super::*;

#[derive(Clone)]
pub(in crate::afxdp) struct TunnelEndpoint {
    pub(in crate::afxdp) id: u16,
    pub(in crate::afxdp) logical_ifindex: i32,
    /// #16514: the tunnel logical interface MTU carried from
    /// `TunnelEndpointSnapshot.mtu` (the configured `interfaces
    /// <tunnel> [unit N] mtu`, else the kernel anchor MTU). For GRE
    /// this is the tunnel IP MTU and caps `native_gre_inner_mtu`;
    /// 0 = unknown (non-limiting, see `min_nonzero_mtu`). WireGuard
    /// deliberately does NOT consume it (#2680/#2684: WG derives its
    /// inner MTU from the physical underlay minus encap overhead).
    pub(in crate::afxdp) mtu: i32,
    /// #1865: the snapshot row's attachment label (linux_name, else
    /// the logical interface name) carried so the telemetry row name
    /// fallback chain matches the plan: ifindex_to_name -> this ->
    /// wg-endpoint-<id>. Same convention as
    /// `wg_tombstone_respawn_coherent`'s row_label.
    pub(in crate::afxdp) interface_label: String,
    /// #1873 R-D: the LOGICAL config interface name (snapshot row's
    /// `interface`, e.g. "wg0.0") — the purge-owner identity. NEVER
    /// linux_name (a cosmetic kernel rename must not purge sessions)
    /// and NEVER interface_label (which prefers linux_name).
    pub(in crate::afxdp) interface: String,
    pub(in crate::afxdp) redundancy_group: i32,
    pub(in crate::afxdp) mode: String,
    /// #17199: typed kind decoded ONCE from `mode` by
    /// `tunnel_mode_kind` when the endpoint is populated (or by test
    /// fixture constructors via the same classifier). `mode` stays
    /// for show/telemetry only; every classification MUST read this
    /// field so an Unknown mode cannot be GRE for one consumer and
    /// non-GRE for another.
    pub(in crate::afxdp) kind: TunnelKind,
    pub(in crate::afxdp) outer_family: i32,
    pub(in crate::afxdp) source: IpAddr,
    pub(in crate::afxdp) destination: IpAddr,
    pub(in crate::afxdp) key: u32,
    pub(in crate::afxdp) ttl: u8,
    pub(in crate::afxdp) clear_dont_fragment_bit: bool,
    pub(in crate::afxdp) transport_table: String,
    // WireGuard (#1432 S2a, multi-peer #1434). Populated only for
    // WireGuard-kind endpoints.
    pub(in crate::afxdp) wg_listen_port: u16,
    /// Local static X25519 private key, hex-decoded. Zeroized on drop
    /// and redacted in Debug — must never leak via `{:?}` or the
    /// on-disk state snapshot.
    pub(in crate::afxdp) wg_local_privkey: zeroize::Zeroizing<[u8; 32]>,
    /// Ordered per-peer set (#1434). Built from the sorted-by-pubkey
    /// wire slice; the engine peer table is fed from this, and the
    /// encap path LPM-selects the peer by inner-dst (#1434 B1b).
    pub(in crate::afxdp) wg_peers: Vec<WgRuntimePeer>,
}

/// One WireGuard peer as hydrated into the runtime forwarding state
/// (#1434). Decoded/parsed from the wire `TunnelWgPeerSnapshot`.
#[derive(Clone)]
pub(in crate::afxdp) struct WgRuntimePeer {
    pub(in crate::afxdp) pubkey: [u8; 32],
    pub(in crate::afxdp) allowed_ips: Vec<ipnet::IpNet>,
    pub(in crate::afxdp) endpoint: Option<std::net::SocketAddr>,
    /// #7158: the authored `host:port` when the endpoint is a DNS HOSTNAME
    /// rather than a literal, so a peer behind a dynamic WAN (DDNS) is
    /// authorable. `None` for a literal endpoint, which is every peer that
    /// existed before #7158.
    ///
    /// `endpoint` stays `None` for such a peer until the tunnel's resolver
    /// produces an address — the same state a learn-only/roaming peer is in at
    /// spawn, which the per-peer outer-MTU resolution already handles by
    /// falling back to the interface MTU.
    pub(in crate::afxdp) endpoint_host: Option<String>,
    pub(in crate::afxdp) keepalive_secs: u16,
    /// Per-peer preshared key (#1434 B2), hex-decoded. 32 zero bytes =
    /// no PSK. Zeroized on drop; redacted in the Debug impl. Must never
    /// leak via `{:?}` or the on-disk state snapshot.
    pub(in crate::afxdp) preshared_key: zeroize::Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for WgRuntimePeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let psk_state = if *self.preshared_key == [0u8; 32] {
            "<unset>"
        } else {
            "<redacted>"
        };
        f.debug_struct("WgRuntimePeer")
            .field("pubkey", &self.pubkey)
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("keepalive_secs", &self.keepalive_secs)
            .field("preshared_key", &psk_state)
            .finish()
    }
}

impl std::fmt::Debug for TunnelEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact wg_local_privkey end-to-end (#1432 S2a invariant).
        f.debug_struct("TunnelEndpoint")
            .field("id", &self.id)
            .field("logical_ifindex", &self.logical_ifindex)
            .field("mtu", &self.mtu)
            .field("interface_label", &self.interface_label)
            .field("redundancy_group", &self.redundancy_group)
            .field("mode", &self.mode)
            .field("outer_family", &self.outer_family)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("key", &self.key)
            .field("ttl", &self.ttl)
            .field("clear_dont_fragment_bit", &self.clear_dont_fragment_bit)
            .field("transport_table", &self.transport_table)
            .field("wg_listen_port", &self.wg_listen_port)
            .field("kind", &self.kind)
            .field(
                "wg_local_privkey",
                &if self.kind == TunnelKind::WireGuard {
                    "<redacted>"
                } else {
                    "<unset>"
                },
            )
            // wg_peers uses WgRuntimePeer's own Debug, which redacts
            // each peer's PSK.
            .field("wg_peers", &self.wg_peers)
            .finish()
    }
}
