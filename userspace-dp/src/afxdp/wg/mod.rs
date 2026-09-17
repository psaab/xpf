//! Clean-room WireGuard tunnel termination for the userspace AF_XDP
//! dataplane. See `docs/pr/wireguard-clean/plan.md` for the design
//! and the explicit list of architectural choices that diverge from
//! the prior attempt in PR #1492.
//!
//! Scope of this PR: engine, framing, allowed-IPs trie, helpers,
//! and unit tests. Hot-path activation in `tx/dispatch.rs` and
//! `poll_descriptor.rs` is intentionally deferred — see the plan
//! doc for the rationale.
//!
//! ### Why this module exists in isolation
//!
//! The WireGuard surface area is small and self-contained — handshake,
//! framing, encap, decap, AllowedIPs LPM, replay window, MSS math.
//! Keeping the engine free of `pub(in crate::afxdp)` types from the
//! rest of `afxdp/` means we can unit-test it end-to-end and audit
//! its security-critical paths without dragging in the dataplane's
//! global type web. The integration PR will add a thin adapter
//! layer that bridges the engine API to the dispatch/poll types.
//!
//! ### Lock poison policy (#6422)
//!
//! Every `Mutex` / `RwLock` in this module is acquired with
//! `unwrap_or_else(|e| e.into_inner())`, never `.unwrap()`. `std` marks
//! a lock POISONED once a thread panics while holding its exclusive
//! guard, and every later acquisition then returns `Err` — so
//! `.unwrap()` converts one contained panic (the #925 worker supervisor
//! contains it) into a panic on EVERY subsequent acquisition. For an
//! `Arc`-shared engine that is a permanent tunnel outage: the
//! supervisor restarts the worker, the restarted worker touches the
//! same lock, and panics again.
//!
//! Recovering is the correct policy for every lock here, not merely the
//! convenient one. The guarded state is either (a) a map that holds the
//! committed prefix of every completed insert (`pending`,
//! `pending_by_peer`, `sessions_by_local_index`, the per-peer keypair
//! slots) — where discarding it would drop live sessions, the exact
//! defect #2402 fixed on the HA shared-session maps — or (b) a value
//! mutated only by infallible integer/array arithmetic with no panic
//! site inside the critical section (`ReplayState::check_and_update`,
//! the TAI64N high-water marks, the cookie load/budget windows), so a
//! recovered value is always a well-formed committed one. Panicking
//! instead repairs nothing and is strictly worse for the security
//! properties: a supervisor restart loop risks the anti-replay marks
//! coming back reset.
//!
//! `worker_queue::lock_recover` and `shared_ops::lock_shared_recover`
//! are NOT reused here. Both stamp a subsystem-specific journald line
//! and bump a subsystem-specific recovery counter (#1807 worker-command
//! queue, #2402 shared sessions) that a WG cookie or replay-window
//! recovery would falsify, and neither covers `RwLock` — which is 39 of
//! the 68 sites. The inline idiom is the tree-wide convention
//! (`nat::allocator`, `event_stream`, `afxdp::sharded_neighbor`,
//! `afxdp::icmp_ratelimit`, and ~10 more).
//!
//! The `#[cfg(test)]` accessors in this module deliberately keep
//! `.unwrap()`: they are compiled out of the shipped helper, so they
//! cannot cause the production failure, and in a test build a poisoned
//! lock is EVIDENCE of a panic that the test should surface rather than
//! paper over.

// TODO(#1499 r4 / integration PR): tighten this to per-item
// `#[allow(dead_code)]` once tx/dispatch.rs and poll_descriptor.rs
// consume the engine API. The module-wide allow exists because the
// engine surface is intentionally complete-but-unused in this PR;
// the integration PR will exercise most of it and the remaining
// dead symbols (e.g. cookie-message helpers) can be allow-listed
// individually.
//
// Re-verified under #1826: removing this allow still surfaces 16
// dead-code warnings (engine surface remains partially unwired even
// after the coordinator/wg_control/ integration), so the
// module-wide allow stays for now.
#![allow(dead_code)] // Most of this module is not yet wired into the hot path.

pub(crate) mod allowed_ips;
// #1865: operator-visible telemetry counters — one `WgCounters` per
// engine (relaxed atomics). See counters.rs for the lifetime/reset
// semantics (engine-Arc-bound; reset on identity rebuild, NEVER
// inherited across #1873 positional-id renumbering) and the
// reserved-reason list (tai64n-replay, under-load admission, rate-limit)
// and their increment sites.
pub(crate) mod counters;
// #8274 step 3: the worker-side transport-data decap stage.
pub(crate) mod decap;
// WireGuard responder-side cookie-reply / MAC2 under-load DoS mitigation
// (#4094 PR-A). Per-tunnel secret rotation + inbound-initiation load gate
// + cookie-reply build + MAC2 verify. Kept out of engine.rs (WATCH-tier)
// so the security-critical cookie crypto is auditable in isolation. The
// initiator-side cookie-reply CONSUME (parse + re-initiate with a real
// MAC2) is PR-B; the inbound type-3 arm stays drop-only here.
pub(crate) mod cookie;
pub(crate) mod dscp;
pub(crate) mod endpoint_resolver;
pub(crate) mod engine;
pub(crate) mod framing;
// WireGuard S1 (#1709): on-wire handshake-message framing (type 1/2,
// MAC1/MAC2) and the TAI64N timestamp. Kept out of engine.rs (WATCH-tier)
// so the security-critical framing is auditable in isolation and the
// engine stays under the modularity threshold.
pub(crate) mod handshake;
// WG handshake orchestration on WgEngine (the three slow-path entry points —
// create_initiation, consume_response, consume_initiation_create_response —
// plus the two-phase index reservation). Split out of engine.rs to keep it under
// the modularity threshold; same `wg` module, so it reaches engine internals
// via `pub(in crate::afxdp::wg)` visibility.
pub(crate) mod handshake_session;
pub(crate) mod mss;
// `outer` module deleted in #1440. Its scaffold helpers
// (write_outer_eth, write_outer_ipv4_udp, outer_l2_len,
// checksum_be) were never wired into the production WG encap
// path; the consolidated outer-header serializers now live in
// `userspace-dp/src/afxdp/frame/headers.rs`. When the WG-encap
// integration PR lands, its `try_encap` will call
// `crate::afxdp::frame::headers::{write_eth_header_slice,
// write_ipv4_header, write_udp_header}` directly.
pub(crate) mod peer;
pub(crate) mod scratch;
pub(crate) mod session;
pub(crate) mod tai64n;
// #1888 S5: engine clock, rekey edge, session expiry, and the pure
// timer decision pass (T6/T7/T8) the per-tunnel control thread runs.
pub(crate) mod timers;

#[cfg(test)]
#[path = "tests.rs"]
pub(crate) mod tests;
#[cfg(test)]
#[path = "decap_tests.rs"]
mod decap_tests;
#[cfg(test)]
#[path = "roam_snapshot_tests.rs"]
mod roam_snapshot_tests;

// #6422: lock poison-recovery regressions. A sibling of `tests` (not a
// child of any one production file) because the sites it pins are spread
// across engine.rs, handshake_session.rs, peer.rs and timers.rs, and it
// reuses `tests::established_pair`.
#[cfg(test)]
#[path = "poison_tests.rs"]
mod poison_tests;

pub(crate) use engine::{
    DecapError, DecapOutcome, EncapError, EncapOutcome, InitiationAction, InstallSessionError,
    WgEngine, WgEngineConfig, WgPeerConfig,
};
pub(crate) use scratch::WgWorkerScratch;

/// Render a 32-byte WG key as the 64-char lowercase hex string used
/// across xpf's WG config/wire surfaces (`wg_peer_pubkey_hex`,
/// protocol/snapshot.rs). The inverse of
/// `forwarding_build::tunnels::decode_wg_key_hex`. PUBLIC keys only —
/// never call this on private key material.
pub(crate) fn encode_wg_key_hex(key: &[u8; WG_KEY_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(WG_KEY_LEN * 2);
    for b in key {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Canonicalize a WG peer endpoint address: unmap a V4-MAPPED IPv6
/// (`::ffff:a.b.c.d`) to its canonical V4 form so overhead math
/// (v4 vs v6 outer), logging, and endpoint comparisons all see the
/// LOGICAL family. Both the learned-endpoint path (dual-stack
/// `recv_from` reports v4 peers mapped) and the configured-endpoint
/// hydration (an operator may write the mapped literal) must call
/// this; the wire-side mirror is `wg_control::wg_send_to`, which
/// re-maps v4 targets iff the bound socket is AF_INET6 (#1736 S2b,
/// Codex r1 finding 1).
pub(crate) fn canonicalize_endpoint(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    if let std::net::SocketAddr::V6(v6) = addr {
        if let Some(v4) = v6.ip().to_ipv4_mapped() {
            return std::net::SocketAddr::new(std::net::IpAddr::V4(v4), v6.port());
        }
    }
    addr
}

/// X25519 public/private key length (bytes).
pub(crate) const WG_KEY_LEN: usize = 32;

/// Noise IKpsk2 pattern with WG primitives.
///
/// WireGuard always uses IKpsk2. When no explicit PSK is configured,
/// the protocol still mixes an all-zero 32-byte PSK in the `psk2`
/// step.
pub(crate) const WG_NOISE_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// All-zero PSK used for the standard "no explicit PSK configured"
/// WG handshake behavior.
pub(crate) const WG_ZERO_PSK: [u8; WG_KEY_LEN] = [0u8; WG_KEY_LEN];

/// WireGuard protocol identifier mixed into the Noise prologue so the
/// initial transcript hash matches the kernel WireGuard / wireguard-go
/// implementations on the wire. See the WireGuard protocol page
/// (https://www.wireguard.com/protocol/) and the kernel source at
/// `drivers/net/wireguard/noise.c` (search for "WireGuard v1 zx2c4").
///
/// The bytes are the ASCII string "WireGuard v1 zx2c4 Jason@zx2c4.com"
/// (34 bytes, no trailing NUL — the kernel passes the same string
/// through `BLAKE2s` without terminator). Without this prologue the
/// Noise hash diverges from byte one and this engine is not
/// interoperable with any real WG peer.
pub(crate) const WG_PROTOCOL_ID_BYTES: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// WireGuard packet type codes (over UDP outer).
pub(crate) const WG_TYPE_INITIATION: u8 = 1;
pub(crate) const WG_TYPE_RESPONSE: u8 = 2;
pub(crate) const WG_TYPE_COOKIE: u8 = 3;
pub(crate) const WG_TYPE_DATA: u8 = 4;

/// Poly1305 authentication tag length.
pub(crate) const POLY1305_TAG_LEN: usize = 16;

/// MAC1/MAC2 field length on a WG handshake message (keyed-BLAKE2s-128
/// output = 16 bytes). Used by `handshake.rs`.
pub(crate) const WG_MAC_LEN: usize = 16;

/// MAC1 label, hashed with the recipient's static public key to form the
/// keyed-BLAKE2s MAC1 key: `key = BLAKE2s-256(LABEL_MAC1 || recipient_pub)`
/// (WireGuard protocol page; wireguard-go `device/cookie.go` `Init`).
pub(crate) const WG_LABEL_MAC1: &[u8; 8] = b"mac1----";

/// Cookie label (used by the type-3 cookie-reply MAC2 path — out of scope
/// for S1, defined here for completeness / future use). `cookie--`.
pub(crate) const WG_LABEL_COOKIE: &[u8; 8] = b"cookie--";

/// WG handshake message 1 (initiation) wire length:
///   type(1) + reserved(3) + sender_index(4) + ephemeral(32)
///   + encrypted_static(32+16) + encrypted_timestamp(12+16)
///   + mac1(16) + mac2(16) = 148.
pub(crate) const WG_MSG_INIT_LEN: usize = 148;

/// WG handshake message 2 (response) wire length:
///   type(1) + reserved(3) + sender_index(4) + receiver_index(4)
///   + ephemeral(32) + encrypted_nothing(0+16) + mac1(16) + mac2(16) = 92.
pub(crate) const WG_MSG_RESPONSE_LEN: usize = 92;

/// Transport data header on the wire:
///   - type        u8  = 4
///   - reserved    [u8; 3]
///   - receiver_id u32 (little-endian)
///   - counter     u64 (little-endian)
pub(crate) const WG_DATA_HEADER_LEN: usize = 1 + 3 + 4 + 8;

/// Round `n` up to the nearest multiple of 16 (WG §5.4.6 data-record
/// pad). Single source of truth for the padding formula — the encap
/// sites (`wg::engine`, `frame::wg`, `coordinator::wg_control::mtu`)
/// previously each carried an identical private copy (#6438).
#[inline]
pub(crate) const fn pad_to_16(n: usize) -> usize {
    (n + 15) & !15
}

/// Total per-packet WG overhead for IPv4 outer:
///   outer IP (20) + UDP (8) + WG data header (16) + Poly1305 tag (16).
pub(crate) const WG_OVERHEAD_V4: usize = 20 + 8 + WG_DATA_HEADER_LEN + POLY1305_TAG_LEN;

/// Total per-packet WG overhead for IPv6 outer.
pub(crate) const WG_OVERHEAD_V6: usize = 40 + 8 + WG_DATA_HEADER_LEN + POLY1305_TAG_LEN;
