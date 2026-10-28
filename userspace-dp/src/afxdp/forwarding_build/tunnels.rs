//! Tunnel-endpoint population for `build_forwarding_state`.
//!
//! Populates `state.tunnel_endpoints` and
//! `state.tunnel_endpoint_by_ifindex`. Must run before the
//! interfaces addresses pass, which reads
//! `tunnel_endpoint_by_ifindex` when building
//! `ConnectedRouteV4/V6.tunnel_endpoint_id`.

use super::super::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub(super) fn populate_tunnel_endpoints(
    snapshot: &ConfigSnapshot,
    state: &mut ForwardingState,
) -> Result<(), crate::policy::SnapshotIntegrityError> {
    // #5193 (A1-b7-F1): duplicate endpoint ids are rejected BEFORE any state is
    // mutated. Both indexes below are keyed independently — `tunnel_endpoints`
    // by id, `tunnel_endpoint_by_ifindex` by ifindex — so a duplicate id used
    // to install the LAST row under that id while BOTH interfaces' ifindexes
    // resolved to it, silently encapsulating one tunnel's traffic with the
    // other's outer source/destination/key. The Go producer already drops an id
    // collision (`usedIDs`, #1873); this is the snapshot-boundary backstop, and
    // running it as a preflight (rather than mid-loop) is what keeps a rejected
    // snapshot from leaving a half-populated forwarding state behind.
    {
        let mut seen_ids: std::collections::HashSet<u16> =
            std::collections::HashSet::with_capacity(snapshot.tunnel_endpoints.len());
        for endpoint in &snapshot.tunnel_endpoints {
            if endpoint.id == 0 || endpoint.ifindex <= 0 {
                continue;
            }
            if !seen_ids.insert(endpoint.id) {
                return Err(
                    crate::policy::SnapshotIntegrityError::TunnelEndpointDuplicateId {
                        tunnel_id: endpoint.id,
                        ifindex: endpoint.ifindex,
                    },
                );
            }
        }
    }
    // #9587: carried for the WireGuard control-thread spawn, which decides from
    // it which threads may deliver kernel-path transport plaintext. The
    // snapshot carries the selected set; the count is clamped defensively
    let mut ports = [0u16; crate::afxdp::types::WG_STEERED_PORT_SET_MAX];
    let n = snapshot
        .wg_steered_listen_ports
        .len()
        .min(crate::afxdp::types::WG_STEERED_PORT_SET_MAX);
    ports[..n].copy_from_slice(&snapshot.wg_steered_listen_ports[..n]);
    state.wg_steered_listen_ports = ports;
    state.wg_steered_listen_port_count = n as u8;
    for endpoint in &snapshot.tunnel_endpoints {
        if endpoint.id == 0 || endpoint.ifindex <= 0 {
            continue;
        }
        // #2410: validate the outer-IP TTL ONCE here instead of narrowing it
        // with an unchecked `endpoint.ttl.max(0) as u8`. A value > 255 fails
        // the snapshot closed rather than wrapping (256→0 blackholes the
        // tunnel).
        let ttl = super::validated::TunnelTtl::try_from_snapshot(endpoint.ttl, endpoint.id)?.get();
        let kind = tunnel_mode_kind(&endpoint.mode);
        let is_wireguard = kind == TunnelKind::WireGuard;
        // #16514: carry the tunnel logical MTU (configured
        // `interfaces gr-… [unit N] mtu`) into the runtime endpoint so
        // `native_gre_inner_mtu` can cap the physical-derived budget.
        // Validated like an interface MTU: negative fails the snapshot
        // closed, 0 stays the non-limiting "unknown" sentinel.
        let mtu = super::validated::TunnelMtu::try_from_snapshot(endpoint.mtu, &endpoint.interface)?
            .get();
        let (source, destination) = if is_wireguard {
            // #11574: the configured outer source address is the worker's
            // listener owner-zone identity. Parse it when present and fall
            // back to unspecified (fail-closed downstream) when the tunnel
            // carries no authorable local source. Peer endpoints, not this
            // snapshot row's Destination, name the remote hop, so only the
            // local source is parsed; the destination stays unspecified
            // (#1432 S2a) exactly as before.
            let source = match endpoint.source.parse::<IpAddr>() {
                Ok(source) => source,
                Err(_) => {
                    if !endpoint.source.is_empty() {
                        eprintln!(
                            "xpf-userspace-dp: wireguard endpoint {} has an unparseable outer source {:?}; using unspecified source so listener admission fails closed (#11574)",
                            endpoint.id, endpoint.source
                        );
                    }
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                }
            };
            (source, IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        } else {
            let Ok(source) = endpoint.source.parse::<IpAddr>() else {
                continue;
            };
            let Ok(destination) = endpoint.destination.parse::<IpAddr>() else {
                continue;
            };
            // #5162: a non-WireGuard tunnel encapsulates in ONE outer IP
            // family, so the outer source and destination MUST be the same
            // family. The Go commit gate (validateTunnelOuterFamilyStrict)
            // rejects a mixed pair, but a config synced from an older peer
            // (pre-#5162) or a corrupt snapshot can still carry one — and the
            // Go producer tags such a row `inet6` when EITHER endpoint is v6,
            // which drives the GRE encoder into the AF_INET6 arm where the v4
            // endpoint yields None → a SILENT per-packet drop. Skip the
            // degenerate row loudly here instead so it installs nothing rather
            // than a blackhole (fail-closed, mirroring the WG hydrate
            // row-drop and the allowed-ips prefix-drop skip-and-continue
            // posture in this file).
            if source.is_ipv6() != destination.is_ipv6() {
                eprintln!(
                    "xpf-userspace-dp: tunnel endpoint {} outer source {} and destination {} are different address families; skipping this endpoint (a GRE/IPIP tunnel encapsulates in one outer family — #5162)",
                    endpoint.id, source, destination
                );
                continue;
            }
            (source, destination)
        };
        let outer_family = match (endpoint.outer_family.as_str(), destination) {
            ("inet6", _) => libc::AF_INET6,
            ("inet", _) => libc::AF_INET,
            (_, IpAddr::V6(_)) => libc::AF_INET6,
            _ => libc::AF_INET,
        };
        let transport_table =
            canonical_route_table(&endpoint.transport_table, outer_family == libc::AF_INET6);

        // WireGuard field hydration (#1432 S2a, multi-peer #1434). On a
        // malformed local privkey OR any malformed peer pubkey the
        // endpoint is dropped — a WG tunnel with a bad key cannot
        // function and must not silently install a half-configured
        // engine. The hydration gates live in `hydrate_wg_identity`
        // (#1866) so the coordinator's tombstone-respawn coherence check
        // and the defer-branch prune can never drift from this path's
        // semantics.
        let mut wg_local_privkey = zeroize::Zeroizing::new([0u8; 32]);
        let mut wg_peers: Vec<WgRuntimePeer> = Vec::new();
        if is_wireguard {
            let Some(identity) = hydrate_wg_identity(endpoint) else {
                continue;
            };
            wg_local_privkey = identity.local_privkey;
            wg_peers = identity.peers;
        }

        state.tunnel_endpoints.insert(
            endpoint.id,
            TunnelEndpoint {
                id: endpoint.id,
                logical_ifindex: endpoint.ifindex,
                mtu: mtu as i32,
                // #1865: attachment label for the telemetry-row name
                // fallback (linux_name, else logical name — mirrors
                // wg_tombstone_respawn_coherent's row_label).
                interface_label: if endpoint.linux_name.is_empty() {
                    endpoint.interface.clone()
                } else {
                    endpoint.linux_name.clone()
                },
                interface: endpoint.interface.clone(),
                redundancy_group: endpoint.redundancy_group,
                mode: endpoint.mode.clone(),
                kind,
                outer_family,
                source,
                destination,
                key: endpoint.key,
                ttl,
                clear_dont_fragment_bit: endpoint.clear_dont_fragment_bit,
                transport_table: transport_table.into_owned(),
                wg_listen_port: endpoint.wg_listen_port,
                wg_local_privkey,
                wg_peers,
            },
        );
        if endpoint.link_up == Some(false) {
            state.tunnel_endpoints_down.insert(endpoint.id);
        }
        // #5193 (A1-b7-F1): ids are unique by the preflight above, but two rows
        // can still name one ifindex (two logical names resolved to the same
        // link). Keep the FIRST — silently overwriting made the decap/connected
        // -route lookups resolve to whichever row happened to sort last.
        if let Some(existing) = state.tunnel_endpoint_by_ifindex.get(&endpoint.ifindex) {
            eprintln!(
                "xpf-userspace-dp: tunnel endpoints {} and {} both claim ifindex {}; keeping {} for the ifindex index (#5193)",
                existing, endpoint.id, endpoint.ifindex, existing
            );
        } else {
            state
                .tunnel_endpoint_by_ifindex
                .insert(endpoint.ifindex, endpoint.id);
        }
        // #2327: kind-segregated decap index — only GRE-mode endpoints
        // are indexed for the GRE (proto-47) decap fast path. A
        // WireGuard or any non-GRE row is intentionally NOT indexed, so
        // a received GRE frame can never be decapped against it even if
        // the outer tuple/key collide. Keyed by the endpoint's own
        // (outer_family, source, destination); the decap lookup queries
        // with the received frame's mirrored (addr_family, outer_dst,
        // outer_src).
        if kind == TunnelKind::Gre {
            state
                .gre_decap_index
                .entry((outer_family, source, destination))
                .or_default()
                .push(endpoint.id);
        }
        if is_wireguard {
            state.has_wg_tunnels = true;
        }
    }
    Ok(())
}

/// #2327/#17199: the typed kind of a tunnel-endpoint `mode` string.
/// Centralizes the kind classification that the decap index, the egress
/// encap dispatcher, and the GRE supervision paths all rely on, so a
/// future tunnel kind is added in exactly one place and the egress
/// dispatcher's fail-closed `_ =>` arm cannot silently treat it as GRE.
/// This is the ONLY place a tunnel `mode` string is compared against
/// mode literals (guarded by the #17199 source-scan test); every other
/// consumer MUST read `TunnelEndpoint.kind`, decoded once here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::afxdp) enum TunnelKind {
    /// `gre` / `ip6gre` — native GRE encapsulation/decapsulation.
    Gre,
    /// `wireguard` — WireGuard engine encap/decap.
    WireGuard,
    /// Any unrecognized / future / malformed mode string. The egress
    /// dispatcher MUST fail closed (drop) on this rather than default to
    /// GRE encap (the pre-#2327 fail-open behavior).
    Unknown,
}

/// Classify a tunnel-endpoint `mode` string into a `TunnelKind`. The
/// sole string-to-kind decoder: `populate_tunnel_endpoints` stores the
/// result on `TunnelEndpoint.kind` and `hydrate_wg_identity` gates on
/// it for snapshot rows; no other site compares a `mode` string.
pub(in crate::afxdp) fn tunnel_mode_kind(mode: &str) -> TunnelKind {
    match mode {
        "gre" | "ip6gre" => TunnelKind::Gre,
        "wireguard" => TunnelKind::WireGuard,
        _ => TunnelKind::Unknown,
    }
}

/// #1866: the hydratable WG identity of one tunnel-endpoint snapshot
/// row — the exact field set `wg_identity_unchanged`
/// (`forwarding_build/wg.rs`) keys engine reuse on, hydrated with the
/// exact gates `populate_tunnel_endpoints` applies. Single source of
/// truth shared by the populate pass, the coordinator's
/// tombstone-respawn coherence check, and the defer-branch prune.
pub(in crate::afxdp) struct WgRowIdentity {
    pub(in crate::afxdp) local_privkey: zeroize::Zeroizing<[u8; 32]>,
    pub(in crate::afxdp) peers: Vec<WgRuntimePeer>,
    pub(in crate::afxdp) listen_port: u16,
}

impl WgRowIdentity {
    /// Whether this row identity is byte-identical to a hydrated
    /// runtime endpoint — the same tuple `wg_identity_unchanged`
    /// compares for engine-Arc reuse. The peer slices are compared
    /// order-sensitively (the Go builder sorts by pubkey, so a stable
    /// config yields a stable order — a reorder is treated as a change,
    /// which only forces a benign engine rebuild).
    pub(in crate::afxdp) fn matches_endpoint(&self, ep: &TunnelEndpoint) -> bool {
        self.listen_port == ep.wg_listen_port
            && *self.local_privkey == *ep.wg_local_privkey
            && wg_peers_eq(&self.peers, &ep.wg_peers)
    }
}

/// Order-sensitive equality of two runtime peer slices (#1434). Compares
/// every identity-bearing field INCLUDING the preshared key, so a PSK
/// rotation forces an engine rebuild (the new key takes effect on the
/// next handshake). #15950: `endpoint_host` is identity too — a hostname
/// peer has `endpoint=None`, so without it a hostname-only change (or
/// host -> None responder-only transition) is invisible and the stale
/// engine/live endpoint is reused.
pub(in crate::afxdp) fn wg_peers_eq(a: &[WgRuntimePeer], b: &[WgRuntimePeer]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).all(|(x, y)| {
        x.pubkey == y.pubkey
            && x.allowed_ips == y.allowed_ips
            && x.endpoint == y.endpoint
            && x.endpoint_host == y.endpoint_host
            && x.keepalive_secs == y.keepalive_secs
            && *x.preshared_key == *y.preshared_key
    })
}

/// #1866 / #1434: hydrate the WG identity of a snapshot row, applying
/// the SAME gates as `populate_tunnel_endpoints`' WireGuard arm: mode
/// must be "wireguard", listen_port must be nonzero, the local privkey
/// AND every peer pubkey must decode. Individually-invalid allowed-ips
/// CIDRs are skipped (the peer is kept). An EMPTY `wg_endpoint` hydrates
/// to `None` (responder-only), but a NON-EMPTY endpoint that does not
/// parse to a `SocketAddr` DROPS the row (#5182) — coercing it to `None`
/// silently degraded every such peer to responder-only. A row with ZERO
/// peers is dropped (a peerless
/// WG tunnel can never handshake; the Go commit gate rejects it, and
/// hydrate fails closed for a leniently-loaded one).
///
/// Returns `None` for non-WG rows and for rows the populate pass would
/// drop. Callers needing the populate pass's id/ifindex gates
/// (`id != 0 && ifindex > 0`) must check those separately.
pub(in crate::afxdp) fn hydrate_wg_identity(
    row: &crate::protocol::snapshot::TunnelEndpointSnapshot,
) -> Option<WgRowIdentity> {
    if tunnel_mode_kind(&row.mode) != TunnelKind::WireGuard {
        return None;
    }
    // A WG tunnel with no listen port cannot bind a socket and is
    // invisible to the shim steering gate (wg_listen_port == 0 ⇒
    // "no WG"). Drop it rather than install a half-dead tunnel
    // that binds port 0 (Codex MAJOR, #1432).
    if row.wg_listen_port == 0 {
        return None;
    }
    let mut local_privkey = zeroize::Zeroizing::new([0u8; 32]);
    if decode_wg_key_hex(&row.wg_local_privkey_hex, &mut local_privkey).is_err() {
        return None;
    }
    // #14373: a degenerate local private key (all-zero / repeated-byte /
    // small-order) clamps to a publicly known scalar — anyone could
    // handshake as any peer. The Go commit gate rejects it; a
    // leniently-loaded row that slipped past the warn path drops here,
    // fail-closed like an undecodable key.
    if crate::afxdp::wg::is_degenerate_wg_key_bytes(&local_privkey) {
        eprintln!(
            "xpf-userspace-dp: wireguard local private key is degenerate (all-zero, repeated-byte, or small-order); dropping this tunnel row (#14373)"
        );
        return None;
    }
    if row.wg_peers.is_empty() {
        return None;
    }
    let mut peers: Vec<WgRuntimePeer> = Vec::with_capacity(row.wg_peers.len());
    for wire in &row.wg_peers {
        let mut peer_pubkey = [0u8; 32];
        // A bad peer pubkey poisons the whole engine (the AllowedIPs
        // LPM / demux index would be inconsistent), so drop the ROW —
        // same fail-closed posture the scalar path had.
        if decode_wg_key_hex(&wire.wg_peer_pubkey_hex, &mut peer_pubkey).is_err() {
            return None;
        }
        // #14373: a small-order / degenerate peer public key yields a
        // zero or enumerable DH secret against any clamped scalar, so
        // anyone could handshake as this peer. Drop the ROW, mirroring
        // the undecodable-pubkey posture above.
        if crate::afxdp::wg::is_degenerate_wg_key_bytes(&peer_pubkey) {
            eprintln!(
                "xpf-userspace-dp: wireguard peer public key is degenerate (all-zero, repeated-byte, or small-order); dropping this tunnel row (#14373)"
            );
            return None;
        }
        let mut allowed_ips: Vec<ipnet::IpNet> = Vec::new();
        for cidr in &wire.wg_allowed_ips {
            match cidr.parse::<ipnet::IpNet>() {
                Ok(net) => allowed_ips.push(net),
                Err(_) => {
                    // #5194 A3-b3-F6: drop only the malformed prefix (keeping the
                    // peer's other routes), but make the drop OBSERVABLE. The Go
                    // commit gate now rejects a malformed allowed-ips at strict
                    // commit and warns on tolerant load, so this only fires for a
                    // leniently-loaded / peer-synced config that slipped a bad
                    // prefix past the warn path — log which route vanished instead
                    // of leaving the operator to debug a silent blackhole.
                    eprintln!(
                        "xpf-userspace-dp: wireguard allowed-ips {:?} is not a valid CIDR; dropping this prefix (the peer keeps its other routes)",
                        cidr
                    );
                    continue;
                }
            }
        }
        let mut endpoint: Option<SocketAddr> = None;
        let mut endpoint_host: Option<String> = None;
        if !wire.wg_endpoint.is_empty() {
            // A non-empty endpoint that does not parse to a concrete
            // SocketAddr must fail the ROW closed rather than silently
            // coerce to None (responder-only) (#5182). The pre-fix
            // `.parse().ok()` turned a malformed/port-stripped endpoint
            // into a peer that could never initiate — the exact silent
            // degradation the Go commit gate now rejects; the dataplane
            // keeps defense-in-depth in agreement so a leniently-loaded
            // config fails loudly (drop) instead of quietly.
            match classify_wg_endpoint(&wire.wg_endpoint) {
                WgEndpointForm::Literal(addr) => {
                    // Canonicalize (unmap ::ffff:a.b.c.d) so a configured
                    // v4-mapped literal gets the same logical-v4 treatment as
                    // a learned endpoint (#1736).
                    endpoint = Some(crate::afxdp::wg::canonicalize_endpoint(addr));
                }
                // #7158: a well-formed `host:port` with a DNS hostname is now
                // ACCEPTED and resolved by the tunnel's endpoint resolver; the
                // peer starts endpoint-less (exactly the learn-only/roaming
                // state) until an answer arrives.
                //
                // The #5182 invariant is preserved, restated at the time of
                // USE: an accepted endpoint becomes a real SocketAddr with the
                // authored port before the peer initiates.
                WgEndpointForm::Hostname => {
                    endpoint_host = Some(normalize_wg_endpoint_host(&wire.wg_endpoint));
                }
                // Neither a usable literal nor a resolvable-shaped host:port:
                // drop the ROW rather than coercing the peer to
                // responder-only.
                WgEndpointForm::Invalid => return None,
            }
        }
        // PSK is OPTIONAL: an empty hex hydrates to the all-zero key
        // (no PSK). A malformed non-empty PSK drops the row (fail
        // closed — a half-applied PSK would silently break the
        // handshake against a peer that DOES use one).
        let mut preshared_key = zeroize::Zeroizing::new([0u8; 32]);
        if !wire.wg_preshared_key_hex.is_empty()
            && decode_wg_key_hex(&wire.wg_preshared_key_hex, &mut preshared_key).is_err()
        {
            return None;
        }
        // #14373: an EXPLICIT degenerate PSK is a publicly known
        // constant, not a secret. Drop the row (fail closed, like a
        // malformed PSK). An absent PSK still hydrates to the all-zero
        // no-PSK value above — that protocol semantics is unchanged.
        if !wire.wg_preshared_key_hex.is_empty()
            && crate::afxdp::wg::is_degenerate_wg_key_bytes(&preshared_key)
        {
            eprintln!(
                "xpf-userspace-dp: wireguard preshared key is degenerate (all-zero, repeated-byte, or small-order); dropping this tunnel row (#14373)"
            );
            return None;
        }
        peers.push(WgRuntimePeer {
            pubkey: peer_pubkey,
            allowed_ips,
            endpoint_host,
            endpoint,
            keepalive_secs: wire.wg_keepalive_secs,
            preshared_key,
        });
    }
    Some(WgRowIdentity {
        local_privkey,
        peers,
        listen_port: row.wg_listen_port,
    })
}

/// Decode a 64-char hex WG key into a 32-byte array. Returns `Err` on
/// any non-hex char or wrong length.
fn decode_wg_key_hex(hex: &str, out: &mut [u8; 32]) -> Result<(), ()> {
    if hex.len() != 64 {
        return Err(());
    }
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(hex.as_bytes()[i * 2])?;
        let lo = hex_nibble(hex.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(())
}

#[inline]
fn hex_nibble(c: u8) -> Result<u8, ()> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(()),
    }
}

/// #7158: how the dataplane reads one authored WireGuard peer endpoint.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum WgEndpointForm {
    /// A usable IP literal with a non-zero port.
    Literal(SocketAddr),
    /// A well-formed `host:port` whose host is a DNS name, to be resolved by
    /// the tunnel's endpoint resolver.
    Hostname,
    /// Unusable: the peer row is dropped (fail closed).
    Invalid,
}

/// The single endpoint decision, used by the hydrate AND by the cross-language
/// agreement test. One function, so the test binds what production does rather
/// than re-deriving it — a test that called `parse::<SocketAddr>()` itself
/// would be testing the standard library and would have missed the zero-port
/// hole below.
pub(super) fn classify_wg_endpoint(s: &str) -> WgEndpointForm {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        // `parse::<SocketAddr>()` ACCEPTS port 0 — "1.2.3.4:0" parses fine.
        // Both this hydrate and the Go commit gate documented that it "rejects
        // a missing/zero port"; the missing-port half is true, the zero-port
        // half never was. The strict commit gate does reject port 0, so this
        // only ever mattered on the TOLERANT load path, which downgrades that
        // check to a warning — precisely the path this fail-closed hydrate
        // exists to backstop (#5182). A port-0 peer "can initiate" to nowhere.
        //
        // Found by the cross-language agreement test, which is the only thing
        // that COMPARES the two gates rather than each restating its own
        // belief about the other.
        if addr.port() == 0 {
            return WgEndpointForm::Invalid;
        }
        return WgEndpointForm::Literal(addr);
    }
    if wg_endpoint_hostname_shape_ok(s) {
        return WgEndpointForm::Hostname;
    }
    WgEndpointForm::Invalid
}

/// Does `s` look like a `host:port` whose host is a DNS name the
/// endpoint resolver could plausibly resolve?
///
/// This is the dataplane half of a two-sided agreement: `endpointFamily` /
/// `isDNSHostname` in `pkg/config/compiler_validate_wireguard.go` decide the
/// same question at commit. The two must accept the same set, or a config
/// commits clean and then silently drops the peer row here — the exact
/// silent-degradation shape #5182 hardened this hydrate against.
///
/// Syntax only, and deliberately no DNS: this runs on the config-apply path,
/// where a blocking lookup would stall the apply.
/// #15966: canonical DNS form for endpoint_host identity: DNS labels are
/// case-insensitive and a single trailing dot is the FQ form, so spelling-
/// only changes must not invalidate a live endpoint. Lowercases the host,
/// strips one trailing dot, preserves the authored port verbatim.
pub(super) fn normalize_wg_endpoint_host(s: &str) -> String {
    match s.rsplit_once(':') {
        Some((host, port)) => {
            let lower = host.to_ascii_lowercase();
            format!("{}:{port}", lower.strip_suffix('.').unwrap_or(&lower))
        }
        None => s.to_ascii_lowercase(),
    }
}

pub(super) fn wg_endpoint_hostname_shape_ok(s: &str) -> bool {
    // Reject a bracketed form here: `[..]:port` is the IPv6 literal spelling,
    // so if it did not parse as a SocketAddr above it is a malformed literal,
    // not a hostname.
    if s.starts_with('[') {
        return false;
    }
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    match port.parse::<u16>() {
        Ok(p) if p >= 1 => {}
        _ => return false,
    }
    wg_endpoint_host_is_dns_name(host)
}

/// RFC 1123 hostname syntax, mirroring `isDNSHostname` on the Go side.
fn wg_endpoint_host_is_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return false;
    }
    // All-digits-and-dots is a malformed IP literal, not a name. Accepting it
    // would defer a certain failure to the resolver.
    if host.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    })
}

#[cfg(test)]
mod wg_endpoint_shape_7158_tests {
    use super::*;
    

    /// #7158: the dataplane half of the cross-language agreement.
    ///
    /// Reads the SAME fixture as
    /// `pkg/config`'s `TestWireguardEndpointShapeMatchesTheSharedFixture_7158`.
    /// Two implementations decide which endpoint spellings are usable — the Go
    /// commit gate and this hydrate — and they must accept the same set. An
    /// endpoint Go accepts but this drops commits clean and then silently loses
    /// the peer, which is the failure #5182 hardened the hydrate against.
    ///
    /// Binding both sides to one file is the point: two literal tables would
    /// pass independently while disagreeing, which is exactly the bug.
    #[test]
    fn hydrate_accepts_the_same_endpoints_the_commit_gate_does_7158() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("test")
            .join("fixtures")
            .join("wg-endpoint-shape.txt");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "the shared #7158 agreement fixture must be readable at {}: {e}. \
                 Without it this test silently checks nothing",
                path.display()
            )
        });

        let mut checked = 0usize;
        for line in text.lines() {
            let line = line.trim_end();
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let (endpoint, verdict) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("malformed fixture line {line:?}"));
            checked += 1;

            // Drive the PRODUCTION decision, not `parse` — see
            // `classify_wg_endpoint`.
            let form = classify_wg_endpoint(endpoint);
            let literal = matches!(form, WgEndpointForm::Literal(_));
            let hostname = form == WgEndpointForm::Hostname;
            let accepted = literal || hostname;

            match verdict {
                "v4" | "v6" => {
                    assert!(
                        literal,
                        "{endpoint:?}: the commit gate classifies this as an IP \
                         literal of family {verdict}, but the hydrate cannot \
                         parse it as a SocketAddr — the peer row would be dropped"
                    );
                    let WgEndpointForm::Literal(addr) = form else {
                        unreachable!("checked literal above")
                    };
                    let want_v6 = verdict == "v6";
                    assert_eq!(
                        addr.is_ipv6(),
                        want_v6,
                        "{endpoint:?}: family disagreement between the commit \
                         gate and the hydrate"
                    );
                }
                "hostname" => {
                    assert!(
                        !literal,
                        "{endpoint:?}: the fixture calls this a hostname but it \
                         parses as a SocketAddr; the commit gate would classify \
                         its family and constrain the mixed-family gate"
                    );
                    assert!(
                        hostname,
                        "{endpoint:?}: the commit gate ACCEPTS this as a DNS \
                         hostname and the hydrate REJECTS it. That config commits \
                         clean and then loses the peer with no diagnostic (#7158)"
                    );
                }
                "reject" => {
                    assert!(
                        !accepted,
                        "{endpoint:?}: the commit gate rejects this, but the \
                         hydrate would accept it — a spelling the dataplane \
                         honours and the operator cannot author"
                    );
                }
                other => panic!("unknown verdict {other:?} in the shared fixture"),
            }
        }
        // Non-vacuity: a fixture that failed to parse would leave every
        // assertion above unrun and this test green.
        assert!(
            checked >= 20,
            "only {checked} fixture cases were checked; the file is supposed to \
             cover literals, hostnames, port rules and malformed hosts"
        );
    }
}

#[cfg(test)]
mod tunnel_kind_17199_tests {
    use super::*;

    fn snapshot_with_mode(mode: &str) -> crate::protocol::ConfigSnapshot {
        let mut snap = crate::protocol::ConfigSnapshot::default();
        snap.tunnel_endpoints = vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 9,
            interface: "gr-0/0/0".into(),
            ifindex: 50,
            mode: mode.into(),
            source: "203.0.113.1".into(),
            destination: "198.51.100.1".into(),
            ttl: 64,
            ..Default::default()
        }];
        snap
    }

    /// #17199 acceptance: an Unknown-mode endpoint is classified ONCE as
    /// `TunnelKind::Unknown` on the populated endpoint, is absent from
    /// the GRE decap index, and is absent from `tunnel_outer_egress_rgs`
    /// (the pre-fix binary string split put it in the GRE arm there).
    /// FAIL-ON-REVERT: restoring a WireGuard-vs-else split in
    /// `forwarding_build/mod.rs` puts id 9 back in the outer-RG map.
    #[test]
    fn unknown_mode_endpoint_is_unknown_and_absent_from_outer_rg_17199() {
        let snap = snapshot_with_mode("ipip");
        let state = crate::afxdp::forwarding_build::build_forwarding_state(&snap);
        let ep = state
            .tunnel_endpoints
            .get(&9)
            .expect("unknown-mode endpoint must still populate (show/telemetry)");
        assert_eq!(ep.kind, TunnelKind::Unknown);
        assert!(
            state
                .gre_decap_index
                .values()
                .all(|ids| !ids.contains(&9)),
            "unknown endpoint must not be in the GRE decap index"
        );
        assert!(
            !state.tunnel_outer_egress_rgs.contains_key(&9),
            "unknown endpoint must be absent from tunnel_outer_egress_rgs"
        );
        // MSS: unknown kind yields 0, not the GRE formula.
        let decision = crate::afxdp::SessionDecision {
            resolution: crate::afxdp::ForwardingResolution {
                disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
                local_ifindex: 0,
                egress_ifindex: 0,
                tx_ifindex: 0,
                tunnel_endpoint_id: 9,
                next_hop: None,
                neighbor_mac: None,
                src_mac: None,
                tx_vlan_id: 0,
                source_ifindex: 0,
                route_mtu: 0,
                transport_route_mtu: 0,
            },
            nat: crate::afxdp::NatDecision::default(),
            install_table_domain: 0,
            install_table_check: 0,
        };
        assert_eq!(
            crate::afxdp::forwarding::tunnel_tcp_mss(&state, &decision, 4),
            0,
            "unknown endpoint must not get the GRE MSS"
        );
    }

    /// #17199: GRE and WireGuard rows still classify and populate their
    /// kind-specific state (positive control for the cell above).
    #[test]
    fn gre_mode_endpoint_is_gre_and_indexed_17199() {
        let snap = snapshot_with_mode("gre");
        let state = crate::afxdp::forwarding_build::build_forwarding_state(&snap);
        assert_eq!(state.tunnel_endpoints[&9].kind, TunnelKind::Gre);
        assert!(
            state
                .gre_decap_index
                .values()
                .any(|ids| ids.contains(&9)),
            "GRE endpoint must be in the decap index"
        );
    }

    /// #17199 guard: no production `.rs` file under `src/` may compare a
    /// tunnel `mode` string against a mode literal outside the sole decoder
    /// `tunnel_mode_kind`. The earlier form matched only six exact `mode ==/!=`
    /// needles and skipped any file whose name contained `test`, so
    /// `m.as_str() != "gre"`, `contains("gre")`, `"gre" == endpoint.mode`,
    /// spacing / line-break variants, and whole production files with a
    /// test-looking name all passed green. This broadened scan takes the
    /// opposite shape (review NEEDS-FOLD on #18264): a production-context
    /// occurrence of a tunnel-mode literal `"wireguard"|"gre"|"ip6gre"` is a
    /// violation unless its `(rel,line)` site is allowlisted below with a
    /// reason. The literal set is deliberately that small — `"gre"` also
    /// names the IP protocol / host-inbound service, so every allowlist entry
    /// must say why that hit is not a tunnel-mode compare. Production context
    /// means: the file is not a `#[cfg(test)]`-declared fixture per
    /// `crate::test_support::source_scan::cfg_test_modules` (the declaration
    /// graph, not the basename — a `*test*` production file stays scanned)
    /// and the line is outside any inline `#[cfg(test)]` module
    /// (`blank_cfg_test_modules`). Comments are scanned on purpose: a
    /// commented-out mode compare is still drift bait.
    /// FAIL-ON-REVERT: reverting to the exact-needle scan, or adding any raw
    /// mode compare outside `tunnel_mode_kind`, makes this red.
    #[test]
    fn no_raw_tunnel_mode_string_compares_outside_ssot_17199() {
        use crate::test_support::source_scan::{
            afxdp_rs_files, blank_cfg_test_modules, cfg_test_modules,
        };
        // True iff `line` combines a tunnel-mode literal with a compare-ish
        // token against a `.mode` receiver — the reviewer's evasion class
        // (as_str / contains / reversed / spaced forms). This is the
        // RED-proving predicate: on its own it would have caught the two
        // mutants below even where they do not sit on an allowlisted site.
        fn compare_like(line: &str) -> bool {
            let lit = ["\"wireguard\"", "\"gre\"", "\"ip6gre\""]
                .iter()
                .any(|l| line.contains(l));
            if !lit {
                return false;
            }
            // Receiver side: any `mode` mention (field, `.mode`, spaced
            // `endpoint. mode`, `mode.as_str()`, `tunnel_mode`, a local named
            // `mode`/`m_mode`). Whitespace inside a field access is legal
            // Rust, so keying on `.mode` alone would miss `endpoint. mode`.
            let modeish = line.contains("mode");
            let cmp = [
                "==",
                "!=",
                ".contains(",
                "matches!",
                ".eq(",
                ".starts_with(",
                ".ends_with(",
            ]
            .iter()
            .any(|c| line.contains(c));
            modeish && cmp
        }
        // Non-vacuity for `compare_like`: every evasion form the old scan
        // missed must be recognised, and plain mode authoring must not be.
        for probe in [
            "if endpoint.mode.as_str() != \"gre\" { return; }",
            "if m.mode.contains(\"gre\") { return; }",
            "if \"gre\" == endpoint.mode { return; }",
            "if endpoint. mode == \"wireguard\" { return; }",
            "matches!(iface.tunnel_mode.as_str(), \"gre\" | \"ip6gre\")",
        ] {
            assert!(
                compare_like(probe),
                "compare_like missed evasion form: {probe}"
            );
        }
        for probe in [
            "mode: \"gre\".to_string(),",
            "ep.mode = \"wireguard\".to_string();",
            "\"gre\" | \"ip6gre\" => TunnelKind::Gre,",
        ] {
            assert!(
                !compare_like(probe),
                "compare_like flagged plain authoring: {probe}"
            );
        }
        // Allowlisted production literal sites: (rel, needle, reason). `needle`
        // must occur on the hit line; a new literal at an unlisted site — or a
        // compare_like line anywhere, listed or not — is a violation. Reasons
        // are per-hit, not per-file, so an entry cannot hide a future compare
        // elsewhere in the same file beyond lines matching its needle.
        const ALLOWED: &[(&str, &str, &str)] = &[
            // Sole string-to-kind decoder: its match arms ARE the SSOT.
            (
                "afxdp/forwarding_build/tunnels.rs",
                "\"gre\" | \"ip6gre\" =>",
                "SSOT match arm in tunnel_mode_kind",
            ),
            (
                "afxdp/forwarding_build/tunnels.rs",
                "\"wireguard\" =>",
                "SSOT match arm in tunnel_mode_kind",
            ),
            (
                "afxdp/forwarding_build/tunnels.rs",
                "must be \"wireguard\"",
                "hydrate_wg_identity doc restating the SSOT gate, not a compare",
            ),
            // IP protocol names, not tunnel modes: proto 47 decoder + doc.
            (
                "ip_proto.rs",
                "\"gre\" | \"junos-gre\"",
                "IP-protocol name decoder (proto 47), not a tunnel mode",
            ),
            (
                "ip_proto.rs",
                "\"gre\"",
                "IP-protocol name doc comment, not a tunnel mode",
            ),
            // InterfaceSnapshot.tunnel_mode is snapshot DATA classified by the
            // Go builder (protocol v65), not a TunnelEndpoint.mode: the GRE-input
            // filter exemption has no Rust TunnelKind for interface rows, so it
            // matches the snapshot string directly. Not an endpoint compare.
            (
                "filter/compiler.rs",
                "tunnel_mode.as_str()",
                "InterfaceSnapshot.tunnel_mode (snapshot data) GRE-input gate; no TunnelKind exists for interface rows",
            ),
            // Host-inbound system-service token "gre" (proto-47 service name).
            (
                "afxdp/forwarding/host_inbound.rs",
                "\"gre\"",
                "host-inbound system-service token, not a tunnel mode",
            ),
            (
                "protocol/snapshot.rs",
                "\"gre\"/\"ip6gre\"/\"wireguard\"/\"ipip\"",
                "TunnelEndpointSnapshot mode field doc, not a compare",
            ),
            // This guard's own literals, probes, allowlist and messages.
            (
                "afxdp/forwarding_build/tunnels.rs",
                "\"wireguard\"",
                "this guard's literal set / probes / allowlist",
            ),
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let fixtures = cfg_test_modules(&root);
        let mut files = Vec::new();
        afxdp_rs_files(&root, &mut files);
        files.sort();
        assert!(files.len() > 50, "scan found only {} files", files.len());
        let mut violations = Vec::new();
        let mut production_files = 0usize;
        let mut compared = 0usize;
        for path in &files {
            let rel = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if fixtures.contains(&rel) {
                continue;
            }
            production_files += 1;
            let src = std::fs::read_to_string(path).expect("read rs");
            // Blank only inline #[cfg(test)] bodies; comments stay scanned.
            let prod = blank_cfg_test_modules(&src);
            for (lineno, line) in prod.lines().enumerate() {
                if !["\"wireguard\"", "\"gre\"", "\"ip6gre\""]
                    .iter()
                    .any(|l| line.contains(l))
                {
                    continue;
                }
                if compare_like(line) {
                    compared += 1;
                    // The one legitimate production compare-shape: the snapshot
                    // interface gate above, allowlisted by its receiver.
                    if !(rel == "filter/compiler.rs" && line.contains("tunnel_mode.as_str()")) {
                        violations.push(format!("{rel}:{}: {}", lineno + 1, line.trim()));
                        continue;
                    }
                }
                let allowed = ALLOWED
                    .iter()
                    .any(|(r, needle, _)| *r == rel && line.contains(needle));
                if !allowed {
                    violations.push(format!("{rel}:{}: {}", lineno + 1, line.trim()));
                }
            }
        }
        // Anti-vacuity: the gate must actually have walked production files and
        // seen the known snapshot-interface compare it deliberately allows.
        assert!(
            production_files > 50,
            "scan walked only {production_files} production files"
        );
        assert!(
            compared >= 1,
            "scan saw no compare-like line; its literal set is blind"
        );
        assert!(
            violations.is_empty(),
            "raw tunnel-mode string compares / unallowlisted tunnel-mode literals outside tunnel_mode_kind (#17199):\n{}",
            violations.join("\n")
        );
    }
}
