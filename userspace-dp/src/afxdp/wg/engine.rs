//! WgEngine: the per-WG-interface state container and API surface.
//!
//! The engine owns:
//!   - The local static key (X25519 private).
//!   - The peer table, keyed by peer pubkey.
//!   - The AllowedIPs LPM trie (used ONLY for inbound src-IP gate).
//!   - The session-by-receiver-index demux map for inbound.
//!
//! API shape:
//!   - `try_encap` — egress fast path. Caller supplies peer pubkey
//!     explicitly (from the forwarding decision). Engine does NOT
//!     consult AllowedIPs for peer selection. This is the
//!     cryptokey-routing safety property the prior PR violated.
//!   - `try_decap` — ingress fast path. Engine demuxes by
//!     `(receiver_index)`, finds the session, decrypts, then checks
//!     the decrypted inner src IP against the owning peer's
//!     AllowedIPs.
//!   - `build_initiator_handshake` / `build_responder_handshake` —
//!     slow path. Construct a snow `HandshakeState` configured with
//!     the WG protocol prologue and (for the initiator) the peer's
//!     remote static key. The caller pumps the handshake by feeding
//!     wire bytes through `read_message` / `write_message`, converts
//!     to a `StatelessTransportState` via `into_stateless_transport_mode`,
//!     and installs the resulting session via `install_session`.
//!
//! Out of scope for this engine (integration PR owns these):
//!   - Building / parsing the on-wire WG handshake framing
//!     (MessageInitiation/MessageResponse: MAC1 over a hash of the
//!     responder's public key, MAC2 cookie reply when under load,
//!     TAI64N timestamp inside the IK payload). This engine only
//!     builds and consumes the snow sub-message bytes — the integration
//!     PR will wrap them in the WG type-1/type-2 outer framing.
//!   - Data-record on-wire framing extras beyond `framing.rs`
//!     (cookie messages, keepalives that double as data records).
//!   - Outer-UDP IO and routing.
//!
//! Hot path discipline:
//!   - No allocations. snow's `write_message` / `read_message` take
//!     pre-sized slices.
//!   - No locks held across crypto operations on the encrypt path
//!     (we clone the `Arc<WgSession>` and release the peer lock).
//!   - Decrypt path takes the per-session replay-window mutex twice:
//!     once for the pre-AEAD `definitely_out_of_window` precheck, and
//!     once for the post-AEAD `check_and_update`. The precheck is
//!     held to avoid paying for a snow decrypt on counters that are
//!     already provably stale — a hostile or replayed flood would
//!     otherwise burn the AEAD cost per packet. Contention is bounded
//!     because each session is demuxed onto a single worker, so the
//!     mutex is effectively a per-session-per-worker SPSC lock with
//!     no cross-worker traffic. (An earlier draft of this comment
//!     claimed the precheck-lock was taken "only on cold arms"; that
//!     was wrong — `try_decap` unconditionally locks the replay
//!     mutex before snow.read_message.)

use super::allowed_ips::AllowedIps;
use super::counters::WgCounters;
use super::framing::{encode_data_header, parse_data_header};
// PendingHandshake is defined alongside the handshake orchestration in
// handshake_session.rs (same `wg` module); the engine struct holds a map of
// them, so it imports the type here.
use super::handshake_session::PendingHandshake;
use super::peer::{decode_roam_endpoint, encode_roam_endpoint, Peer, PeerConfig};
use super::session::{REJECT_AFTER_MESSAGES, ReplayDecision, WgSession};
use super::tai64n::Tai64nClock;
use super::{
    POLY1305_TAG_LEN, WG_DATA_HEADER_LEN, WG_KEY_LEN, WG_NOISE_PATTERN, WG_PROTOCOL_ID_BYTES,
    WG_ZERO_PSK, pad_to_16,
};
use arc_swap::ArcSwap;
use curve25519_dalek::MontgomeryPoint;
use rustc_hash::FxHashMap;
use snow::{Builder, HandshakeState};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use zeroize::{Zeroize, Zeroizing};

/// Errors that can fail the egress path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EncapError {
    /// The caller-supplied peer pubkey is not in the engine table.
    UnknownPeer,
    /// The peer has no completed handshake yet. The caller should
    /// kick the slow path to initiate a handshake.
    NoSession,
    /// The output buffer is too small for the encapsulated frame.
    BufferTooSmall,
    /// snow rejected the encryption — most likely nonce exhaustion
    /// (counter approaching 2^64). Caller MUST drop and re-key.
    CryptoFailed,
    /// Session exceeded WG's reject-after-messages bound.
    RekeyRequired,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct EncapOutcome {
    /// Number of bytes written to the output buffer. The
    /// encapsulated wire image starts at offset 0.
    pub(crate) len: usize,
    /// The receiver_index used (peer-chosen). Useful for tracing.
    pub(crate) receiver_index: u32,
    /// The counter value used (engine-chosen). Useful for tracing.
    pub(crate) counter: u64,
}

/// What the coordinator should do with an inbound WG type-1 initiation,
/// decided by [`WgEngine::classify_initiation`] BEFORE the expensive Noise
/// responder path (#4094 PR-A). The under-load cookie gate lives here so
/// the security-critical ordering (MAC2-good → process; MAC1-good +
/// MAC2-missing → challenge; otherwise cheap drop) is auditable in one
/// place and cannot be reordered at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitiationAction {
    /// Run the full Noise handshake (`consume_initiation_create_response`).
    /// Reached when the responder is NOT under load (spec-correct
    /// skip-verify of MAC2), when an under-load initiation carries a VALID
    /// MAC2, or when the datagram is malformed / MAC1-bad (so the consume
    /// path drops it cheaply, before any crypto, with the correct
    /// per-reason counter and no cookie reply).
    Process,
    /// Under load with no valid MAC2 but a valid MAC1: a WG type-3
    /// CookieReply of this many bytes was written to the caller's output
    /// buffer. Send it to the initiation's real source and DROP the
    /// initiation (no Noise crypto spent).
    SendCookie(usize),
    /// Drop the initiation with no reply and no further processing
    /// (under-load, MAC1-valid, MAC2-missing, but the cookie-reply budget
    /// for this window is exhausted).
    Drop,
}

/// Errors that can fail the slow-path session install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallSessionError {
    /// The caller-supplied peer pubkey is not in the engine table.
    UnknownPeer,
    /// The caller-supplied `local_index` is already mapped to a
    /// live session (any peer). The caller must retry handshake
    /// completion with a fresh `local_index`. Silently overwriting
    /// the existing session — even for the same peer — would
    /// blackhole the in-flight ciphertexts of the rotated-out
    /// `previous` session, which the demux map would no longer be
    /// able to resolve.
    LocalIndexCollision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecapError {
    /// Header was malformed (too short, wrong type, etc.)
    MalformedHeader,
    /// No session with the parsed receiver_index.
    UnknownSession,
    /// snow rejected the decryption — tag verify or nonce reuse.
    CryptoFailed,
    /// Replay window said this counter is a duplicate.
    ReplayDuplicate,
    /// Replay window said this counter is too old.
    ReplayOutOfWindow,
    /// Counter is at or above `REJECT_AFTER_MESSAGES`. Per WG spec
    /// §6.5 the receiver MUST reject these without attempting AEAD.
    CounterRejectAfterMessages,
    /// Decrypted plaintext did not parse as IPv4/IPv6, tagged with the
    /// peer that sent it (#7686).
    ///
    /// It stays an ERROR: there is no deliverable inner packet, so the
    /// "no TUN write" contract is unchanged. What changes is that the
    /// peer identity no longer dies with the error.
    ///
    /// The record is POST-AEAD, so the sender provably holds the session
    /// keys — the same basis on which #1865 made these datagrams count
    /// for endpoint learning. The identity is available at both
    /// construction sites because `try_decap` demuxes the session from
    /// `hdr.receiver_index` BEFORE any AEAD work, so attribution here is
    /// proven, not inferred.
    ///
    /// Before #7686 this discarded the identity and the caller tried to
    /// recover it with a single-peer identity guess, which could not
    /// attribute anything on a MULTI-PEER interface — so a malformed-but-authenticated inner
    /// packet never roamed its peer's endpoint there. Same discard #7230
    /// fixed for keepalives; scoped out of that change rather than
    /// overlooked, and its dispatch comment said so at the site.
    MalformedInner([u8; WG_KEY_LEN]),
    /// Inner src IP is not in this peer's AllowedIPs — cryptokey-
    /// routing violation; drop per WG spec §5.4.6.
    AllowedIpsViolation,
    /// Output buffer too small for plaintext.
    BufferTooSmall,
    /// Record's ciphertext field is shorter than the Poly1305 tag
    /// length. Snow's AEAD decrypt has no short-tag guard internally;
    /// passing a sub-tag ciphertext underflows `ciphertext.len() -
    /// TAGLEN` and panics on the subsequent slice op (release build)
    /// or directly via `usize` underflow assert (debug). Reject the
    /// record before invoking snow so a hostile peer cannot crash the
    /// AF_XDP worker by sending 16..31-byte UDP datagrams with a
    /// valid `receiver_index`.
    ShortRecord,
    /// #7230: an authenticated ZERO-LENGTH transport record — a
    /// WireGuard keepalive — tagged with the peer that sent it.
    ///
    /// It stays an ERROR, deliberately: there is no inner packet, so the
    /// "no TUN write" contract is unchanged and callers that only care
    /// about deliverable packets keep treating it exactly as before.
    /// What changes is that the peer identity no longer dies with the
    /// error. It is available at the construction site — `try_decap`
    /// demuxes the session from `hdr.receiver_index` BEFORE any AEAD
    /// work, and the record is authenticated by the time this is built —
    /// so attribution is proven, not inferred.
    ///
    /// Before #7230 this collapsed into `MalformedInner`, which discarded
    /// the identity; the caller then tried to recover it with
    /// a single-peer identity guess (`single_peer_pubkey()`, deleted in
    /// #7686 once nothing called it), which could attribute nothing on a
    /// MULTI-PEER interface. A peer whose only traffic is keepalives — a roaming
    /// client, or one behind a NAT that rebinds — therefore never roamed
    /// its endpoint and was blackholed until its next handshake
    /// (~120-180s, bounded, not indefinite).
    Keepalive([u8; WG_KEY_LEN]),
    /// #1888 S5: the demuxed session is older than REJECT_AFTER_TIME.
    /// Per WG spec the receiver MUST NOT use such keys — dropped
    /// BEFORE AEAD, and deliberately withOUT arming the rekey edge
    /// (initiation is send-side-only; an attacker replaying old
    /// ciphertext at an expired session must not drive our handshake
    /// cadence — Codex r1 M4).
    Expired,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DecapOutcome {
    /// Length of the un-padded inner-IP packet written at the front
    /// of the caller's `out` buffer. This is the IPv4 `total_length`
    /// / IPv6 `40 + payload_length`, NOT the WG §5.4.6 padded
    /// plaintext length that snow authenticated. The bytes beyond
    /// `len` and before `len + padding` (0..15 bytes) are zero
    /// padding bytes that the receive path has already verified.
    pub(crate) len: usize,
    /// The peer that owned this session (so the caller can route
    /// the inner packet onward — typically into the LAN-side
    /// pipeline as if it had arrived on the WG virtual interface).
    pub(crate) peer_pubkey: [u8; 32],
}

/// Per-peer config passed to `WgEngine::reconcile`.
#[derive(Clone)]
pub(crate) struct WgPeerConfig {
    pub(crate) pubkey: [u8; 32],
    pub(crate) endpoint: Option<std::net::SocketAddr>,
    pub(crate) persistent_keepalive: u16,
    pub(crate) allowed_ips: Vec<ipnet::IpNet>,
    /// Optional per-peer preshared key (#1434 B2). `WG_ZERO_PSK` (32
    /// zero bytes) when no PSK is configured — semantically identical
    /// to "no PSK" in Noise IKpsk2. SECRET: never logged (the manual
    /// Debug below redacts it). #4103 F12: wrapped in `Zeroizing` so a
    /// cloned/dropped config carrier does not leave a plaintext PSK in
    /// freed heap/stack — matching the runtime copy (`PeerConfig`).
    pub(crate) preshared_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for WgPeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Compare by reference (`&[u8; 32]`), not by deref-to-value, so
        // the PSK is never copied to the stack even transiently (#4103
        // F12 key hygiene).
        let psk_state = if &*self.preshared_key == &WG_ZERO_PSK {
            "<unset>"
        } else {
            "<redacted>"
        };
        f.debug_struct("WgPeerConfig")
            .field("pubkey", &self.pubkey)
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("allowed_ips", &self.allowed_ips)
            .field("preshared_key", &psk_state)
            .finish()
    }
}

/// Per-engine config.
#[derive(Clone)]
pub(crate) struct WgEngineConfig {
    /// Local X25519 private key. #4103 F12: `Zeroizing` so a
    /// cloned/dropped config carrier does not leave a plaintext private
    /// key in freed heap/stack — matching the runtime copy (the engine's
    /// own `local_private_key`). SECRET: never logged (the manual Debug
    /// below redacts it — a derived Debug on `Zeroizing<[u8; 32]>` would
    /// print the raw key).
    pub(crate) local_private_key: Zeroizing<[u8; 32]>,
    pub(crate) listen_port: u16,
    pub(crate) peers: Vec<WgPeerConfig>,
}

impl std::fmt::Debug for WgEngineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the private key; surface only non-secret fields.
        f.debug_struct("WgEngineConfig")
            .field("local_private_key", &"<redacted>")
            .field("listen_port", &self.listen_port)
            .field("peers", &self.peers)
            .finish()
    }
}

/// Stack scratch capacity for the padded plaintext on the encap
/// path. Sized to cover an inner IP packet up to `PADDED_PLAINTEXT_MAX
/// - 15` bytes plus the worst-case 15 bytes of WG spec §5.4.6
/// padding. We stage the padded plaintext on the stack rather than
/// inside the caller's `out` buffer because snow's `write_message`
/// requires non-overlapping plaintext and ciphertext slices.
///
/// The buffer is materialized as `MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]>`
/// and only the bytes that snow actually reads are initialized
/// (the `inner_ip.len()` bytes copied from the caller plus the
/// trailing 0..15 padding bytes). This avoids the 4112-byte memset
/// per call that a `[0u8; N]` array-init would force LLVM to emit
/// (LLVM cannot elide the zero-init because snow reads the trailing
/// pad bytes, which must be zero by spec).
///
/// Note on jumbo MTU: the value is 4080 + 16 = 4096. The bound is
/// enforced inside `try_encap` (search for the
/// `if padded_len > PADDED_PLAINTEXT_MAX` guard, which is hoisted
/// above the `next_tx_counter()` consume so a failed staging guard
/// cannot leave the session's counter advanced) as
/// `padded_len > PADDED_PLAINTEXT_MAX`
/// where `padded_len = pad_to_16(inner_ip.len())` — i.e. the post-
/// WG-§5.4.6-padding length. The accepted range is therefore
/// `inner_ip.len() ∈ [0, 4096]` (any inner whose 16-byte-padded
/// length is ≤ 4096): a 4080-byte inner pads to 4080 (already a
/// multiple of 16, accepted), a 4081..=4096-byte inner pads to 4096
/// (accepted, since `pad_to_16(4096) == 4096`), and a 4097-byte inner
/// pads to 4112 and is rejected with `EncapError::BufferTooSmall`.
/// Jumbo MTU configurations (>4096 inner) are not currently
/// supported by this engine; raising the bound is a one-line change
/// when the integration layer needs it.
const PADDED_PLAINTEXT_MAX: usize = 4080 + 16;

/// The largest INNER IP packet length (pre-§5.4.6 padding) the engine
/// can encrypt in one transport message, i.e. the largest `L` for which
/// `pad_to_16(L) <= PADDED_PLAINTEXT_MAX`.
///
/// Because `pad_to_16` rounds up to a 16-byte multiple and
/// `PADDED_PLAINTEXT_MAX` is itself a multiple of 16, the largest
/// accepted unpadded inner length is exactly `PADDED_PLAINTEXT_MAX`
/// (a 4096-byte inner pads to 4096 and is accepted; a 4097-byte inner
/// pads to 4112 and is rejected — see the `encap` guard at line ~908).
///
/// This is the hard ceiling that any ADVERTISED or CONFIGURED inner
/// (wgN-interface) MTU must be clamped to: a sender that honors an
/// advertised inner MTU above this value still has its packets dropped
/// at the encap `padded_len > PADDED_PLAINTEXT_MAX` guard
/// (`encap_mtu_drops`). `wg::mss::wg_inner_mtu` clamps to this value
/// (#2457); the Go control plane mirrors it as
/// `pkg/routing/tunnel.go::wgEngineMaxInnerMTU`.
pub(crate) const WG_ENGINE_MAX_INNER_MTU: usize = PADDED_PLAINTEXT_MAX;

// Compile-time proof that WG_ENGINE_MAX_INNER_MTU is the true ceiling:
// it must itself pad to <= PADDED_PLAINTEXT_MAX (accepted) while the
// next byte does not (rejected). If PADDED_PLAINTEXT_MAX ever changes
// to a non-16-multiple, this catches the silent off-by-pad drift.
const _: () = {
    assert!(pad_to_16(WG_ENGINE_MAX_INNER_MTU) <= PADDED_PLAINTEXT_MAX);
    assert!(pad_to_16(WG_ENGINE_MAX_INNER_MTU + 1) > PADDED_PLAINTEXT_MAX);
};

/// One peer's slot in a published `PeerTable` snapshot: its long-lived
/// session/timer state (`Arc<Peer>`, reused across commits) paired with
/// the immutable per-snapshot config tuple (`Arc<PeerConfig>`, rebuilt
/// every commit). #2836: the config used to be interior-mutable on the
/// reused `Peer`, so a reconcile rewrote it in place and an OLD-table
/// reader instantly observed NEW config (a torn endpoint/keepalive/PSK
/// mix). Freezing the config into the snapshot entry means every
/// `.load()` returns a self-consistent `(peer, config)` pair for its
/// lifetime — the routing-relevant tuple is captured by the same
/// release-store that publishes `peers`/`allowed_ips`.
pub(crate) struct PeerEntry {
    /// Long-lived session + timer state. Same pubkey → same Arc across
    /// commits, so the (current, previous) session pair survives.
    pub(crate) peer: Arc<Peer>,
    /// Immutable config for THIS snapshot. A new commit builds a fresh
    /// bundle; readers of an older snapshot keep the older bundle.
    pub(crate) config: Arc<PeerConfig>,
}

/// Atomically-swappable peer-routing table. The fields are reconciled
/// together (a new config snapshot rebuilds all of them) and a hot-path
/// reader must observe them as a unit, or else it can pair a
/// `peer_index` from the old map with a `peers` entry from the new vec
/// and route to the wrong peer. Holding independent RwLocks does NOT
/// give that property: a reader can release the index lock, the
/// reconciler can swap, and then the reader can acquire the peers lock
/// on the new state. Bundling everything behind a single
/// `ArcSwap<PeerTable>` gives the reader an atomic snapshot — every load
/// returns an `Arc<PeerTable>` that is internally consistent for its
/// lifetime, and the writer publishes the next snapshot in one
/// release-store.
///
/// #2836: each `PeerEntry` also carries an immutable `Arc<PeerConfig>`
/// (endpoint/keepalive/PSK) so the operator-facing tuple is part of the
/// atomic snapshot too — no longer interior-mutated on the reused peer
/// Arc behind the table's back.
pub(crate) struct PeerTable {
    /// peer slab — one entry per configured peer. Indexed by the
    /// `peer_index` referenced from `allowed_ips`.
    pub(crate) peers: Vec<PeerEntry>,
    /// peer_pubkey → index in `peers`.
    pub(crate) peer_index_by_pubkey: FxHashMap<[u8; 32], u32>,
    /// AllowedIPs LPM. Only consulted on the decap path.
    pub(crate) allowed_ips: AllowedIps,
}

impl PeerTable {
    fn empty() -> Self {
        Self {
            peers: Vec::new(),
            peer_index_by_pubkey: FxHashMap::default(),
            allowed_ips: AllowedIps::new(),
        }
    }
}

/// The engine.
pub(crate) struct WgEngine {
    /// Local X25519 private key. Held in the engine because every
    /// slow-path handshake needs it. Wrapped in `Zeroizing` so THIS copy's
    /// 32 bytes of key material are wiped on engine drop — kernel WG and
    /// wireguard-go both do this. #9918 F-142: snow 0.10.0 has NO `zeroize`
    /// and NO `Drop` impl (verified against the locked registry copy: no
    /// `zeroize` dep, no `impl Drop` anywhere in `src/`) — the old comment
    /// claiming "snow internally zeroizes its own copies" was false and is
    /// corrected here. snow COPIES our long-lived secrets into unwiped heap
    /// objects on every handshake build: the static private key via
    /// `Builder::local_private_key` → `(*s_dh).set(k)` (`builder.rs:232`,
    /// owned by `HandshakeState.s`, `handshakestate.rs:35`) and the PSK via
    /// `psk(2, …)`/`set_psk` into owned `psks: [Option<[u8; 32]>; 10]`
    /// (`handshakestate.rs:42,145,457-464`). Those snow-held copies of the
    /// static key and PSKs persist in freed heap with no wipe API and are an
    /// ACCEPTED residual (heap-scrape of per-handshake heap, process-isolated;
    /// only our own carriers — this `Zeroizing` key and the `PeerConfig`
    /// `Zeroizing` PSKs — are wiped). Transport keys are best-effort wiped by
    /// `WgSession::drop` (rekey-to-zero through snow's `set`, a plain
    /// `copy_from_slice` in vendored code we cannot change — the compiler
    /// could theoretically dead-store-eliminate it, so erasure is not
    /// guaranteed; see the `Drop` doc). Chaining keys and ephemerals in
    /// `HandshakeState` (seconds-lived pendings) likewise have no wipe API
    /// and share the same accepted residual.
    local_private_key: Zeroizing<[u8; 32]>,
    /// Local X25519 static PUBLIC key, derived once at construction from
    /// `local_private_key` via `MontgomeryPoint::mul_base_clamped` (the
    /// same clamped base-point multiply snow uses for its static key).
    /// Needed to verify the MAC1 on an INBOUND handshake message — kernel
    /// WG keys mac1 on the recipient's static public key, and for an
    /// inbound message the recipient is us. Derived once so the parse hot
    /// path (slow path, but still) does not repeat the base-point multiply
    /// and so a "private-key-as-public" swap cannot creep in.
    /// `pub(in crate::afxdp::wg)` so the handshake orchestration in
    /// `handshake_session.rs` (a sibling file, same `wg` module) can read it.
    pub(in crate::afxdp::wg) local_public_key: [u8; WG_KEY_LEN],
    /// Precomputed MAC1 keyed-hash key: `BLAKE2s-256("mac1----" ||
    /// local_public_key)`. #9918 F-144: derived once at construction (the
    /// local pub never changes) so the under-load flood path avoids one
    /// BLAKE2s-256 per junk packet. Inbound parses use this; outbound
    /// builds key on the PEER pub and still derive per message.
    pub(in crate::afxdp::wg) mac1_key: [u8; 32],
    /// Monotonic TAI64N clock for the initiator handshake timestamp.
    /// In-process strict monotonicity; cross-restart persistence is a
    /// future control-plane concern (#1703 S6).
    pub(in crate::afxdp::wg) tai64n_clock: Tai64nClock,
    /// In-flight handshakes keyed by OUR reserved local index. A handshake
    /// is recorded here BEFORE the message carrying that index goes on the
    /// wire, then promoted to a live `WgSession` on completion. See the
    /// two-phase reservation discipline in `reserve_pending`.
    pub(in crate::afxdp::wg) pending: RwLock<FxHashMap<u32, PendingHandshake>>,
    /// At-most-one-pending-per-peer index: maps a peer pubkey to its
    /// current pending reservation's local index. A new initiation from a
    /// peer aborts that peer's prior pending reservation, bounding pending
    /// state to O(configured peers) under a valid-MAC1 initiation flood
    /// (the reservation step is reached only after snow authenticates the
    /// static-key AEAD).
    pub(in crate::afxdp::wg) pending_by_peer: RwLock<FxHashMap<[u8; WG_KEY_LEN], u32>>,
    /// UDP port we listen on for inbound. Stored for diagnostics
    /// and for the slow-path responder.
    listen_port: u16,
    /// Combined peer-routing table behind a single ArcSwap. See
    /// `PeerTable` doc for the atomicity rationale.
    table: ArcSwap<PeerTable>,
    /// Slow-path serialization lock for peer-table mutation.
    /// `reconcile_peers` and `install_session` both take it to
    /// prevent stale-Arc install races across peer removal. Hot path
    /// does NOT take this lock — readers only touch `table` via
    /// `.load()`.
    pub(in crate::afxdp::wg) reconcile_lock: std::sync::Mutex<()>,
    /// Demux map: receiver_index → session. Receiver indices are
    /// chosen locally at handshake time so they uniquely identify
    /// a session for as long as it lives. Kept out of `PeerTable`
    /// because session install / rotation is independent of peer
    /// reconcile; only peer REMOVAL touches both (we drain a
    /// dropped peer's sessions out of this map during reconcile).
    pub(in crate::afxdp::wg) sessions_by_local_index: RwLock<FxHashMap<u32, Arc<WgSession>>>,
    /// #5164: the "please initiate a handshake" (NoSession) and "rekey"
    /// worker→control edges are now PER-PEER, stored on each `Peer`
    /// (`handshake_request_pending` / `handshake_request_last_ns` /
    /// `rekey_request_pending` in `peer.rs`) and driven via
    /// `request_handshake(peer_pubkey, …)` / `take_handshake_request(peer_pubkey)`
    /// / `request_rekey(peer_pubkey)` / `take_rekey_request(peer_pubkey)`. They
    /// were engine-global `AtomicBool`s in S2a (single-peer); a global edge
    /// raised by peer B was drained by the first pubkey-sorted peer A in the
    /// control loop, blackholing B (#5164). See `Peer` for the fields.
    /// #1865: per-engine telemetry counters (relaxed atomics). Bound
    /// to the engine Arc: survives control-thread respawns and
    /// unrelated commits (engine reuse); resets with the engine on an
    /// identity-changing rebuild — see counters.rs.
    pub(in crate::afxdp::wg) counters: WgCounters,
    /// #4094 PR-A: responder cookie-reply / MAC2 under-load DoS mitigation
    /// — a per-tunnel rotating secret, an inbound-initiation load gate, a
    /// cookie-reply emission budget, and MAC2 verification, all keyed on
    /// this engine's responder static public key. Consulted by
    /// `classify_initiation` before the expensive Noise responder path.
    pub(in crate::afxdp::wg) cookie: super::cookie::CookieChecker,
    /// #4094 PR-B: initiator-side per-peer cookie state — the last
    /// cookie-reply we decrypted from each responder (used to stamp MAC2 on
    /// our retried initiations until it ages past
    /// `cookie::COOKIE_ROTATION_TIME_NS`) plus the MAC1 of our last-sent
    /// initiation to that peer (the AEAD AAD to decrypt an incoming
    /// cookie-reply). Keyed by peer static public key. Slow-path only
    /// (control thread: `create_initiation` on send, `consume_cookie_reply`
    /// on receive); the `Mutex` provides `&self` interior mutability and is
    /// effectively uncontended.
    pub(in crate::afxdp::wg) cookie_gen:
        std::sync::Mutex<FxHashMap<[u8; WG_KEY_LEN], super::cookie::InitiatorCookie>>,
    /// #1888 S5 test hook: when nonzero, `now_ns()` returns this value
    /// instead of CLOCK_MONOTONIC, making the timer semantics
    /// deterministically testable. Compiled out of release builds.
    #[cfg(test)]
    pub(in crate::afxdp::wg) mock_now_ns: std::sync::atomic::AtomicU64,
}

/// Minimum spacing between worker-driven "please initiate" edges
/// (#1432 S2a). Bounds the NoSession signal under a packet flood to one
/// edge per second so a stream of pre-handshake packets cannot spin the
/// control thread.
pub(crate) const WG_HANDSHAKE_REQUEST_MIN_INTERVAL_NS: u64 = 1_000_000_000;

impl std::fmt::Debug for WgEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact all key material. Only the non-secret listen port is
        // surfaced — `local_private_key` must never reach a log line,
        // and the peer table / session maps carry session keys behind
        // their own types. This keeps `ForwardingState`'s derived
        // `Debug` (which now holds `Arc<WgEngine>`) leak-free.
        f.debug_struct("WgEngine")
            .field("listen_port", &self.listen_port)
            .finish_non_exhaustive()
    }
}

impl WgEngine {
    pub(crate) fn new(config: WgEngineConfig) -> Self {
        let local_public_key =
            MontgomeryPoint::mul_base_clamped(*config.local_private_key).to_bytes();
        let mac1_key = super::handshake::mac1_key_for(&local_public_key);
        let engine = Self {
            // Move the Zeroizing carrier straight into the engine (no
            // intermediate plaintext copy). #4103 F12.
            local_private_key: config.local_private_key,
            local_public_key,
            mac1_key,
            tai64n_clock: Tai64nClock::new(),
            pending: RwLock::new(FxHashMap::default()),
            pending_by_peer: RwLock::new(FxHashMap::default()),
            listen_port: config.listen_port,
            table: ArcSwap::from_pointee(PeerTable::empty()),
            reconcile_lock: std::sync::Mutex::new(()),
            sessions_by_local_index: RwLock::new(FxHashMap::default()),
            counters: WgCounters::default(),
            cookie: super::cookie::CookieChecker::new(&local_public_key),
            cookie_gen: std::sync::Mutex::new(FxHashMap::default()),
            #[cfg(test)]
            mock_now_ns: std::sync::atomic::AtomicU64::new(0),
        };
        engine.reconcile_peers(&config.peers);
        engine
    }

    /// Worker side of the NoSession handshake-request edge (#1432 S2a
    /// §4.3), scoped PER PEER (#5164). Records a "please initiate" request for
    /// `peer_pubkey` at `now_ns`, rate-limited to one edge per
    /// `WG_HANDSHAKE_REQUEST_MIN_INTERVAL_NS` **for that peer**. Hot-path safe:
    /// a table lookup plus a single relaxed load and an at-most-one relaxed
    /// store on the peer's own atomics, no handshake state. Returns `true` if
    /// this call recorded a fresh edge (false if the peer is unknown, still
    /// inside its rate window, or lost the CAS).
    pub(crate) fn request_handshake(&self, peer_pubkey: &[u8; WG_KEY_LEN], now_ns: u64) -> bool {
        use std::sync::atomic::Ordering;
        let Some(peer) = self.peer_arc(peer_pubkey) else {
            return false;
        };
        let last = peer.handshake_request_last_ns.load(Ordering::Relaxed);
        // `last == 0` means "never requested" → always allow the first.
        if last != 0 && now_ns.saturating_sub(last) < WG_HANDSHAKE_REQUEST_MIN_INTERVAL_NS {
            return false;
        }
        // Claim the rate-limit window with a CAS so exactly one concurrent
        // NoSession caller wins per interval FOR THIS PEER (Copilot: a plain
        // load+store let multiple workers all observe the stale `last` and
        // re-arm the edge each tick). A CAS failure means another worker
        // already claimed the window; we drop without re-arming. Relaxed is
        // sufficient — the control thread only needs eventual visibility.
        let stamp = now_ns.max(1);
        if peer
            .handshake_request_last_ns
            .compare_exchange(last, stamp, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        peer.handshake_request_pending.store(true, Ordering::Relaxed);
        WgCounters::bump(&self.counters.hs_requests_armed);
        true
    }

    /// #1865: the engine's telemetry counters. Call-site counters
    /// (MTU guards, send/TUN errors, cookie/unknown-type) increment
    /// through this accessor; engine-internal paths count directly.
    pub(crate) fn counters(&self) -> &WgCounters {
        &self.counters
    }

    /// #4094 PR-A: decide how to handle an inbound WG type-1 initiation
    /// `msg` that arrived from `from` (the ACTUAL datagram source), BEFORE
    /// spending a Noise responder handshake. Records the arrival on the
    /// load gate and, when under load, requires a valid MAC2 (a cookie the
    /// initiator can only hold if it received our cookie reply at its real
    /// source) — otherwise it issues a budget-gated cookie challenge and
    /// drops the initiation. `out` receives the type-3 CookieReply on the
    /// [`InitiationAction::SendCookie`] arm; it is untouched otherwise, so
    /// the caller may reuse the same buffer for `consume_...`'s response.
    ///
    /// Ordering mirrors wireguard-go `device/receive.go`, with the #9918
    /// F-144 MAC1-first reorder: a bad-MAC1 junk packet costs one keyed
    /// hash (precomputed key) instead of 4-6 (MAC2 cookie + expect x2
    /// secrets, then MAC1 with per-message key derivation).
    /// 1. Not under load → `Process` (skip-verify MAC2, spec-correct).
    /// 2. Under load + MAC1 invalid / malformed → `Process` so the consume
    ///    path drops it cheaply (one more precomputed MAC1, no crypto) with
    ///    the right counter and NO reply — a random / bad-MAC1 flood cannot
    ///    turn us into a reflector. MAC2 is never verified for these.
    /// 3. Under load + MAC1 valid + valid MAC2 → `Process` (liveness proved).
    /// 4. Under load + MAC1 valid + MAC2 missing/bad → `SendCookie` (budget
    ///    permitting) else `Drop`.
    pub(crate) fn classify_initiation(
        &self,
        msg: &[u8],
        from: SocketAddr,
        out: &mut [u8],
        now_ns: u64,
    ) -> InitiationAction {
        // Every inbound type-1 counts toward load, including malformed ones
        // (they still cost us). Conservative: trips under-load sooner.
        let under_load = self.cookie.note_initiation(now_ns);
        if !under_load {
            return InitiationAction::Process;
        }
        // Under load, check MAC1 FIRST with the precomputed key (#9918
        // F-144). A malformed or bad-MAC1 datagram falls through to the
        // cheap consume-path drop (which re-verifies MAC1 with the same
        // precomputed key before any Noise crypto, correct per-reason
        // counter) with NO reply and WITHOUT verifying MAC2 — so one
        // junk packet costs ~1 hash here + ~1 in consume, not 4-6.
        // The double-verify is deliberate: classify and consume stay
        // independent (defense in depth), and both are cheap now.
        if super::handshake::parse_initiation_with_key(msg, &self.mac1_key).is_err() {
            return InitiationAction::Process;
        }
        // Valid MAC1. A valid MAC2 (peer holds a fresh cookie bound to this
        // exact source) authorizes the expensive handshake.
        if self.cookie.verify_initiation_mac2(msg, from, now_ns) {
            WgCounters::bump(&self.counters.hs_rx_under_load_mac2_ok);
            return InitiationAction::Process;
        }
        // Valid MAC1, under load, no valid MAC2 → challenge with a cookie
        // reply (gated below). Only a sender that knows our public key
        // (MAC1 proves it) can draw a reply, so a spoofed flood cannot
        // make us a reflector. #4332: gate on the per-SOURCE bucket FIRST
        // so a flood from one source throttles only itself and cannot drain
        // the global per-window budget away from a legit peer at a different
        // source. BOTH the per-source bucket and the global budget must pass.
        if !self.cookie.source_reply_allowed(from.ip(), now_ns) {
            WgCounters::bump(&self.counters.hs_cookie_reply_budget_drops);
            return InitiationAction::Drop;
        }
        if !self.cookie.reply_budget_available(now_ns) {
            WgCounters::bump(&self.counters.hs_cookie_reply_budget_drops);
            return InitiationAction::Drop;
        }
        match self.cookie.build_cookie_reply(msg, from, now_ns, out) {
            Ok(len) => {
                WgCounters::bump(&self.counters.hs_cookie_replies_sent);
                WgCounters::bump(&self.counters.hs_rx_under_load_no_mac2);
                InitiationAction::SendCookie(len)
            }
            // A build failure means we can't challenge → drop with NO reply
            // (fail-closed). Reached by (a) the impossible-on-Linux
            // CookieError::RandUnavailable — a getrandom failure for the
            // secret or nonce, where shipping a predictable cookie would
            // DEFEAT the mitigation (#4094 BUG-2), so dropping is the safe
            // choice; or (b) a defensive buffer/length error (`out` is
            // >= WG_MSG_RESPONSE_LEN 92 at the sole caller and the init
            // length is type-gated, so (b) is unreachable). Counted with the
            // budget-drop family: "under load, dropped without a cookie".
            Err(_) => {
                WgCounters::bump(&self.counters.hs_cookie_reply_budget_drops);
                InitiationAction::Drop
            }
        }
    }

    /// Control side of the NoSession edge, scoped PER PEER (#5164). Returns
    /// `true` if a handshake request is pending FOR `peer_pubkey` and clears
    /// only that peer's edge, so a lower-sorted peer's iteration can no longer
    /// drain an edge raised for another peer. `false` if the peer is unknown or
    /// has no pending edge. Slow path (control thread).
    /// #8274 step 3: a WORKER observed `endpoint` on an authenticated
    /// transport-data record from `peer_pubkey`. Record it for the control
    /// thread to adopt.
    ///
    /// COMPARE BEFORE WRITING — and before locking (#9644). The control
    /// thread's own learning does an unconditional `HashMap::insert` per
    /// authenticated datagram, which is free at control-loop rates and is
    /// not free on the dataplane hot path: this runs once per
    /// transport-data record, i.e. once per packet of every WireGuard
    /// flow. The steady state — a peer that is not roaming — costs an
    /// optimistic snapshot read (relaxed loads + compare, no lock, no
    /// shared write) against the peer's `RoamSnapshot`; the mutex is
    /// taken only on the slow path. Suppression obeys the explicitly
    /// weaker stale-observation contract (`docs/pr/9644/plan.md` §5.3,
    /// exceptions E1–E4, OP-1): a validated snapshot certifies a
    /// complete historical publication, never current slot contents.
    ///
    /// Returns true when something new was recorded, so a caller can count it.
    pub(crate) fn note_worker_observed_endpoint(
        &self,
        peer_pubkey: &[u8; WG_KEY_LEN],
        endpoint: std::net::SocketAddr,
    ) -> bool {
        use std::sync::atomic::Ordering;
        let Some(peer) = self.peer_arc(peer_pubkey) else {
            return false;
        };
        // #9644 fast path: optimistic seqlock read of the snapshot
        // (plan §5.2). A stable, epoch-current, equal snapshot means
        // there is nothing to say — no lock, no shared-memory write.
        let snap = &peer.roam_snapshot;
        let e0 = snap.live_epoch.load(Ordering::Acquire);
        let s0 = snap.seq.load(Ordering::Acquire);
        if s0 & 1 == 0 {
            let words = [
                snap.w0.load(Ordering::Relaxed),
                snap.w1.load(Ordering::Relaxed),
                snap.w2.load(Ordering::Relaxed),
                snap.w3.load(Ordering::Relaxed),
                snap.w4.load(Ordering::Relaxed),
            ];
            let snap_epoch = snap.snap_epoch.load(Ordering::Relaxed);
            std::sync::atomic::fence(Ordering::Acquire);
            let s1 = snap.seq.load(Ordering::Acquire);
            let e1 = snap.live_epoch.load(Ordering::Acquire);
            if s0 == s1
                && snap_epoch == e0
                && snap_epoch == e1
                && decode_roam_endpoint(&words) == Some(endpoint)
            {
                return false;
            }
        }
        // Slow path: the mutex-protected slot is the authority and is
        // always re-checked under lock, so any fast-path staleness
        // resolves here.
        let mut slot = peer
            .roamed_endpoint
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *slot == Some(endpoint) {
            // Equal but snapshot-stale (publish/invalidate race): repair
            // the snapshot so stable traffic regains lock-free
            // suppression on the very next packet (plan §5.2
            // repair-on-equal). Same odd-first protocol.
            let epoch = snap.live_epoch.load(Ordering::Relaxed);
            snap.begin_publish();
            // Slot + pending already hold the right values; only the
            // snapshot needs republishing.
            snap.commit_publish(encode_roam_endpoint(endpoint), epoch);
            return false;
        }
        // ODD-FIRST publish (plan §5.2): the odd mark precedes the slot
        // write, so no reader can observe a slot write unanchored in a
        // publication. Slot + pending live inside the odd..even bracket.
        let epoch = snap.live_epoch.load(Ordering::Relaxed);
        snap.begin_publish();
        *slot = Some(endpoint);
        peer.roamed_endpoint_pending.store(true, Ordering::Relaxed);
        snap.commit_publish(encode_roam_endpoint(endpoint), epoch);
        true
    }

    /// #8274 step 3: take the endpoint a worker last observed for this peer, if
    /// any. Drained by the control thread's per-peer pass, exactly where it
    /// already drains `take_handshake_request`. On a `Some` take the drain
    /// generation bumps under the same mutex (#9644 plan §5.2): the
    /// abstract take linearizes at the bump.
    pub(crate) fn take_worker_observed_endpoint(
        &self,
        peer_pubkey: &[u8; WG_KEY_LEN],
    ) -> Option<std::net::SocketAddr> {
        use std::sync::atomic::Ordering;
        let peer = self.peer_arc(peer_pubkey)?;
        if !peer.roamed_endpoint_pending.swap(false, Ordering::Relaxed) {
            return None;
        }
        let mut slot = peer
            .roamed_endpoint
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let taken = slot.take();
        if taken.is_some() {
            peer.roam_snapshot.bump_live_epoch();
        }
        taken
    }

    /// #9644: bump every peer's drain generation once. Called at
    /// `wg_control_loop` start beside the learned-endpoint seeding, so a
    /// new consumer incarnation never trusts a previous incarnation's
    /// adoptions (plan §5.2 incarnation binding). Cold path; a racing
    /// in-flight publish stamps either side and any stale side
    /// self-repairs on the next equal slow hit.
    pub(crate) fn invalidate_roam_snapshots(&self) {
        for entry in &self.load_table().peers {
            entry.peer.roam_snapshot.bump_live_epoch();
        }
    }

    pub(crate) fn take_handshake_request(&self, peer_pubkey: &[u8; WG_KEY_LEN]) -> bool {
        use std::sync::atomic::Ordering;
        self.peer_arc(peer_pubkey)
            .map(|peer| peer.handshake_request_pending.swap(false, Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// The pubkey of the first (S2a: only) configured peer, if any.
    /// Used by the control thread to drive initiator bring-up without
    /// re-plumbing the peer config through the spawn site.
    pub(crate) fn first_peer_pubkey(&self) -> Option<[u8; WG_KEY_LEN]> {
        self.load_table().peers.first().map(|e| e.peer.pubkey)
    }

    /// The pubkeys of ALL configured peers, in table (pubkey-sorted)
    /// order (#1434). Used by the control thread's per-peer egress +
    /// timer iteration. Slow path (1s tick / TUN-read fallback).
    pub(crate) fn peer_pubkeys(&self) -> Vec<[u8; WG_KEY_LEN]> {
        self.load_table().peers.iter().map(|e| e.peer.pubkey).collect()
    }

    /// Each peer's (pubkey, configured-or-learned endpoint), in table
    /// order (#1434). The control thread seeds its per-peer
    /// effective-endpoint map from this at start. Slow path.
    pub(crate) fn peer_endpoints(&self) -> Vec<([u8; WG_KEY_LEN], Option<std::net::SocketAddr>)> {
        self.load_table()
            .peers
            .iter()
            .map(|e| (e.peer.pubkey, e.config.endpoint))
            .collect()
    }


    /// #1434 B1b cryptokey routing on EGRESS: longest-prefix-match the
    /// inner destination IP against the AllowedIPs trie and return the
    /// owning peer's (pubkey, configured-or-learned endpoint). `None`
    /// when no peer's AllowedIPs cover `inner_dst`. This is the encap
    /// counterpart to the decap-side AllowedIPs src-gate — the engine
    /// owns the LPM so the table swap is observed atomically. Slow-path
    /// / transit-encap (per WG-egress packet — the AllowedIps lookup is
    /// a linear scan of a small, prefix-sorted table; no allocation).
    pub(crate) fn peer_for_dest(
        &self,
        inner_dst: std::net::IpAddr,
    ) -> Option<([u8; WG_KEY_LEN], Option<std::net::SocketAddr>)> {
        let table = self.load_table();
        let idx = table.allowed_ips.lookup(inner_dst)?;
        let entry = table.peers.get(idx as usize)?;
        // #2836 / codex-049-04: endpoint is read from the immutable
        // per-snapshot config bundle captured by this same `load`, so
        // the AllowedIPs match and the endpoint come from ONE atomic
        // snapshot (no torn old-prefix/new-endpoint pairing) and the
        // hot egress path takes NO per-packet RwLock on the endpoint.
        Some((entry.peer.pubkey, entry.config.endpoint))
    }

    /// Whether the named peer currently has a confirmed (usable for
    /// egress) transport session — key-confirmed AND not yet past
    /// REJECT_AFTER_TIME. The control thread uses this to decide
    /// whether to (re-)initiate a handshake on the NoSession edge.
    ///
    /// The age gate is load-bearing (#4546): a confirmed session that
    /// has aged past REJECT_AFTER_TIME (180s) can no longer encrypt —
    /// `try_encap` refuses it at the T3 gate and `expire_sessions` GCs
    /// it on the next ~1s tick — so it must NOT report `confirmed` and
    /// suppress the rekey trigger. Without this check the NoSession-edge
    /// rekey (`wg_control::drive_attempt_machine`) was skipped for a
    /// confirmed-but-expired-yet-not-GC'd session, a bounded ~0-1s
    /// blackhole at the expiry boundary until the GC tick. The check
    /// mirrors `try_encap`'s T3 gate, `expire_sessions`, and
    /// `peer_has_usable_session`, reading the same mock-aware `now_ns()`
    /// clock so every WG age comparison shares one clock domain. Slow
    /// path.
    pub(crate) fn peer_has_confirmed_session(&self, pubkey: &[u8; 32]) -> bool {
        let Some(peer) = self.peer_arc(pubkey) else {
            return false;
        };
        let now_ns = self.now_ns();
        matches!(
            peer.current.read().unwrap_or_else(|e| e.into_inner()).as_ref(),
            Some(session) if session.is_confirmed()
                && now_ns.saturating_sub(session.created_ns)
                    < super::session::REJECT_AFTER_TIME_NS
        )
    }

    /// xpf's local static public key (X25519). The peer needs this to
    /// configure us as its peer and to compute the MAC1 on messages it
    /// sends us. Slow path / config-surface use.
    pub(crate) fn local_public_key(&self) -> [u8; WG_KEY_LEN] {
        self.local_public_key
    }

    pub(crate) fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Seed the engine's TAI64N high-water mark from a prior engine's
    /// snapshot so a fresh engine built on a config change does not
    /// regress the initiator timestamp the peer last accepted (#1432
    /// S2a reload stability, §4.2). Slow path / build-time only.
    pub(crate) fn seed_tai64n_high_water(
        &self,
        hw: [u8; super::tai64n::TAI64N_LEN],
    ) {
        self.tai64n_clock.seed_high_water(hw);
    }

    /// Snapshot the engine's current TAI64N high-water mark, if any, so
    /// a successor engine can be seeded from it across a config-change
    /// rebuild (#1432 S2a). `None` before the first handshake.
    pub(crate) fn tai64n_high_water(&self) -> Option<[u8; super::tai64n::TAI64N_LEN]> {
        self.tai64n_clock.high_water()
    }

    /// #4103: snapshot every configured peer's responder anti-replay
    /// high-water mark (`greatest_tai64n`), keyed by pubkey, so a fresh
    /// engine built on an identity-changing config commit can carry each
    /// SURVIVING peer's mark forward. This is the per-peer INCOMING
    /// mirror of `tai64n_high_water` (which snapshots the single
    /// engine-wide OUTGOING initiator clock). Without it, any WG config
    /// change (add allowed-ip, rotate a PSK, add/remove a peer) rebuilds
    /// the engine via `WgEngine::new` — starting from an empty peer
    /// table, so every peer gets a fresh `Peer::new` with
    /// `greatest_tai64n = [0; 12]` — silently disarming the #4092
    /// responder anti-replay for every peer. Slow path / build-time only.
    pub(crate) fn greatest_tai64n_by_pubkey(
        &self,
    ) -> Vec<([u8; WG_KEY_LEN], [u8; super::tai64n::TAI64N_LEN])> {
        self.load_table()
            .peers
            .iter()
            .map(|e| (e.peer.pubkey, e.peer.greatest_tai64n()))
            .collect()
    }

    /// #4103: seed this engine's per-peer responder anti-replay high-water
    /// marks from a prior engine's snapshot (see `greatest_tai64n_by_pubkey`)
    /// across an identity-change rebuild. A pubkey present in BOTH
    /// `snapshot` and this engine's peer table carries its mark forward
    /// (only advancing, never regressing — see `Peer::seed_greatest_tai64n`);
    /// a pubkey NOT in the snapshot (a new or re-keyed peer) keeps the
    /// fresh `[0; 12]`, because a pubkey change is a different peer
    /// identity for which a reset is correct (matches the kernel /
    /// wireguard-go behaviour of retaining per-peer `last_timestamp`
    /// across a reconfigure while a new peer starts clean). Slow path /
    /// build-time only.
    pub(crate) fn seed_greatest_tai64n(
        &self,
        snapshot: &[([u8; WG_KEY_LEN], [u8; super::tai64n::TAI64N_LEN])],
    ) {
        let table = self.load_table();
        for (pubkey, hw) in snapshot {
            if let Some(&idx) = table.peer_index_by_pubkey.get(pubkey) {
                if let Some(entry) = table.peers.get(idx as usize) {
                    entry.peer.seed_greatest_tai64n(*hw);
                }
            }
        }
    }

    /// Reconcile the engine's peer table against a new config
    /// snapshot. Slow path only.
    ///
    /// Atomicity contract:
    ///   1. Build a fresh `PeerTable` off-line (no readers see partial
    ///      state).
    ///   2. Identify peers present in the old table but absent in the
    ///      new one. Drain their `(current, previous, next)` session
    ///      `local_index` entries from `sessions_by_local_index`
    ///      before publishing the new table — otherwise an inbound
    ///      packet targeting a removed peer's session would decrypt
    ///      successfully (the session Arc is still in the demux map),
    ///      then fail the AllowedIPs gate because the peer is no
    ///      longer in the index, and the demux entry would leak
    ///      forever. Removal also drains the removed peers' other
    ///      per-pubkey side maps that live outside `PeerTable`:
    ///      `pending`/`pending_by_peer` (in-flight handshake
    ///      reservations) and `cookie_gen` (#4362, initiator cookie
    ///      state) — otherwise each removal leaks a stale entry.
    ///   3. `ArcSwap::store` publishes the new `PeerTable` in one
    ///      release-store. Subsequent `.load()` calls observe either
    ///      the entire old table or the entire new one — never a mix.
    pub(crate) fn reconcile_peers(&self, configs: &[WgPeerConfig]) {
        // Serialize concurrent reconciles. The lock does NOT gate the
        // hot path (readers take only the ArcSwap load).
        let _guard = self.reconcile_lock.lock().unwrap_or_else(|e| e.into_inner());
        let old = self.table.load_full();
        let mut new_peers: Vec<PeerEntry> = Vec::with_capacity(configs.len());
        let mut new_index: FxHashMap<[u8; 32], u32> = FxHashMap::default();
        let mut new_allowed = AllowedIps::new();
        for (i, cfg) in configs.iter().enumerate() {
            let idx = i as u32;
            let existing = old
                .peer_index_by_pubkey
                .get(&cfg.pubkey)
                .and_then(|old_idx| old.peers.get(*old_idx as usize).map(|e| e.peer.clone()));
            // Reuse the long-lived session/timer state (same pubkey →
            // same `Arc<Peer>`) so the (current, previous) session pair
            // and timer pacing survive the commit. The operator-facing
            // config (endpoint/keepalive/PSK) is NOT mutated in place
            // anymore (#2836): a FRESH immutable `PeerConfig` is built
            // per commit and paired with the peer in the snapshot, so a
            // reader still holding the OLD table observes the OLD config
            // and a reader of the NEW table observes the NEW config —
            // never a torn mix. #1434 B2: a PSK rotation produces a new
            // bundle that takes effect on the next handshake; the old
            // bundle (with the superseded `Zeroizing` PSK) is wiped when
            // the last reader of the old snapshot drops it.
            let peer = match existing {
                Some(p) => p,
                None => Arc::new(Peer::new(cfg.pubkey)),
            };
            let config = Arc::new(PeerConfig::new(
                cfg.endpoint,
                cfg.persistent_keepalive,
                *cfg.preshared_key,
            ));
            new_peers.push(PeerEntry { peer, config });
            // r7 Codex/Claude nit: duplicate pubkeys in `configs`
            // leave an orphan `Peer` in `new_peers` (unreachable via
            // pubkey lookup) and make `new_allowed` carry entries
            // indexed at the earlier duplicate's slot. The Go control
            // plane is supposed to reject duplicate pubkeys at config
            // validation; this `debug_assert` keeps the engine-side
            // invariant visible during development without panicking
            // production builds if the validation layer is bypassed.
            let prior = new_index.insert(cfg.pubkey, idx);
            debug_assert!(
                prior.is_none(),
                "duplicate peer pubkey in reconcile_peers configs (prior idx={prior:?}, new idx={idx})"
            );
            for cidr in &cfg.allowed_ips {
                new_allowed.insert(*cidr, idx);
            }
        }
        // Drain demux entries for peers that exist in `old` but not
        // in `new`. Walk old peers and check absence from new_index.
        // We collect `local_index` values under read locks on the
        // peer's `current`/`previous`, then drop those locks before
        // taking the demux write lock — this keeps the demux write
        // hold short and avoids any lock-order coupling with peer
        // session rotation.
        let mut dropped_indices: Vec<u32> = Vec::new();
        for (pubkey, old_idx) in old.peer_index_by_pubkey.iter() {
            if new_index.contains_key(pubkey) {
                continue;
            }
            let Some(entry) = old.peers.get(*old_idx as usize) else {
                continue;
            };
            let peer = &entry.peer;
            if let Some(cur) = peer.current.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
                dropped_indices.push(cur.local_index);
            }
            if let Some(prev) = peer.previous.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
                dropped_indices.push(prev.local_index);
            }
            // #3882: the pending `next` (unconfirmed responder) keypair
            // is also demux-registered; drain it too or its entry leaks.
            if let Some(next) = peer.next.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
                dropped_indices.push(next.local_index);
            }
        }
        if !dropped_indices.is_empty() {
            let mut by_index = self
                .sessions_by_local_index
                .write()
                .unwrap_or_else(|e| e.into_inner());
            for li in &dropped_indices {
                by_index.remove(li);
            }
        }
        // Drain in-flight HANDSHAKE RESERVATIONS for removed peers too
        // (Copilot code-review finding). A peer with a pending (not-yet-
        // completed) handshake leaves an entry in `pending` keyed by our
        // reserved index and a `pending_by_peer` marker keyed by its pubkey.
        // Without draining these on peer removal, the reservation (and its
        // consumed index) would leak until process restart, and a stale
        // per-peer marker could mis-fire the at-most-one-pending-per-peer
        // abort after config churn. `pending_by_peer` is keyed by pubkey, so
        // we drain directly for each removed pubkey. Still under
        // `reconcile_lock`, consistent with `reserve_pending`/`release_pending`.
        {
            let mut pending = self.pending.write().unwrap_or_else(|e| e.into_inner());
            let mut by_peer = self.pending_by_peer.write().unwrap_or_else(|e| e.into_inner());
            for pubkey in old.peer_index_by_pubkey.keys() {
                if new_index.contains_key(pubkey) {
                    continue;
                }
                if let Some(reserved_idx) = by_peer.remove(pubkey) {
                    pending.remove(&reserved_idx);
                }
            }
        }
        // #4362: drain per-peer INITIATOR COOKIE state for removed peers.
        // `cookie_gen` (#4094 PR-B) holds each peer's last-decrypted
        // responder cookie plus the MAC1 of our last-sent initiation to it,
        // keyed by peer pubkey. Like `pending_by_peer` above it is NOT part
        // of the atomically-swapped `PeerTable`, so without an explicit
        // drain a removed peer leaves a stale `InitiatorCookie` entry that
        // is unreachable (no `Peer` in the table) yet lives until process
        // restart — a small per-removal leak bounded by config-churn
        // history. Drain it here alongside the other per-peer cleanups so
        // peer removal is complete. Still under `reconcile_lock`; the
        // `consume_cookie_reply` slow path releases its `pending` read lock
        // before taking `cookie_gen`, so there is no lock-order coupling.
        {
            let mut cg = self.cookie_gen.lock().unwrap_or_else(|e| e.into_inner());
            for pubkey in old.peer_index_by_pubkey.keys() {
                if new_index.contains_key(pubkey) {
                    continue;
                }
                cg.remove(pubkey);
            }
        }
        // Publish the new table. Atomic release-store; any reader
        // doing `.load()` after this point sees the new table whole.
        self.table.store(Arc::new(PeerTable {
            peers: new_peers,
            peer_index_by_pubkey: new_index,
            allowed_ips: new_allowed,
        }));
    }

    /// Take an atomic snapshot of the peer-routing table. Hot path.
    /// The returned `Arc<PeerTable>` is internally consistent for as
    /// long as the caller holds it. Module-visible so the #1888 timer
    /// pass (wg/timers.rs) can walk the peer slab for expiry.
    pub(in crate::afxdp::wg) fn load_table(&self) -> Arc<PeerTable> {
        self.table.load_full()
    }

    /// Test-only accessor: same as `load_table`, exposed at module
    /// visibility so tests can reach each `PeerEntry`'s `peer` /
    /// `config` for the reconcile/atomicity regressions. Not used on
    /// the hot path.
    #[cfg(test)]
    pub(crate) fn table_for_test(&self) -> Arc<PeerTable> {
        self.load_table()
    }

    /// Test-only: copy-on-write a single peer's `persistent_keepalive`
    /// without disturbing its sessions or AllowedIPs. Rebuilds the
    /// affected `PeerEntry` with a fresh config bundle and republishes
    /// the table atomically, mirroring how `reconcile_peers` swaps
    /// config (#2836). Used by the timer T8 tests that need to enable
    /// persistent keepalive on an already-established peer.
    #[cfg(test)]
    pub(crate) fn set_keepalive_for_test(&self, pubkey: &[u8; 32], secs: u16) {
        let _guard = self.reconcile_lock.lock().unwrap();
        let old = self.table.load_full();
        let mut peers: Vec<PeerEntry> = Vec::with_capacity(old.peers.len());
        for entry in old.peers.iter() {
            let config = if entry.peer.pubkey == *pubkey {
                Arc::new(PeerConfig::new(
                    entry.config.endpoint,
                    secs,
                    entry.config.preshared_key(),
                ))
            } else {
                entry.config.clone()
            };
            peers.push(PeerEntry {
                peer: entry.peer.clone(),
                config,
            });
        }
        self.table.store(Arc::new(PeerTable {
            peers,
            peer_index_by_pubkey: old.peer_index_by_pubkey.clone(),
            allowed_ips: old.allowed_ips.clone(),
        }));
    }

    /// Test-only: promote a peer's pending `next` keypair to `current`
    /// exactly as the first authenticated inbound data record would
    /// (drives `maybe_promote_next` → `promote_next` + demux cleanup),
    /// WITHOUT running a real decap (no counter / tx / replay side
    /// effects). Lets fixtures model a fully-established tunnel where the
    /// responder session has been confirmed AND promoted. No-op if the
    /// peer's `next` no longer holds `session` (#3882).
    #[cfg(test)]
    pub(crate) fn promote_next_for_test(&self, pubkey: &[u8; 32], session: &Arc<WgSession>) {
        if let Some(peer) = self.peer_arc(pubkey) {
            self.maybe_promote_next(&peer, session);
        }
    }

    /// Test-only: force a session directly into a peer's `current` slot
    /// (and register it for demux), bypassing the role-based install
    /// routing. Used to exercise the egress `is_confirmed()`
    /// defense-in-depth gate, which the #3882 3-slot model makes the
    /// natural responder path no longer reach (an unconfirmed responder
    /// keypair now parks in `next`, never `current`).
    #[cfg(test)]
    pub(crate) fn force_current_for_test(&self, pubkey: &[u8; 32], session: Arc<WgSession>) {
        let peer = self.peer_arc(pubkey).expect("peer exists");
        self.sessions_by_local_index
            .write()
            .unwrap()
            .insert(session.local_index, session.clone());
        *peer.current.write().unwrap() = Some(session);
    }

    /// Long-lived session/timer state for a peer (NOT its config).
    /// Slow-path callers that need the operator-facing config tuple use
    /// `peer_config` / `peer_entry` instead (#2836).
    pub(in crate::afxdp::wg) fn peer_arc(&self, pubkey: &[u8; 32]) -> Option<Arc<Peer>> {
        let table = self.load_table();
        let idx = *table.peer_index_by_pubkey.get(pubkey)?;
        table.peers.get(idx as usize).map(|e| e.peer.clone())
    }

    /// The immutable per-snapshot config bundle for a peer (#2836).
    /// Slow path: handshake PSK selection, the keepalive timer pass.
    pub(in crate::afxdp::wg) fn peer_config(&self, pubkey: &[u8; 32]) -> Option<Arc<PeerConfig>> {
        let table = self.load_table();
        let idx = *table.peer_index_by_pubkey.get(pubkey)?;
        table.peers.get(idx as usize).map(|e| e.config.clone())
    }

    /// Both the long-lived `Peer` and its immutable per-snapshot
    /// `PeerConfig`, taken from ONE `load` so the timer pass reads the
    /// peer's timer atomics and its config (keepalive) from the SAME
    /// atomic snapshot rather than two racing loads (#2836).
    pub(in crate::afxdp::wg) fn peer_entry(
        &self,
        pubkey: &[u8; 32],
    ) -> Option<(Arc<Peer>, Arc<PeerConfig>)> {
        let table = self.load_table();
        let idx = *table.peer_index_by_pubkey.get(pubkey)?;
        let entry = table.peers.get(idx as usize)?;
        Some((entry.peer.clone(), entry.config.clone()))
    }

    /// Install a freshly-completed transport session on a peer and
    /// register it for inbound demux. Called from the slow-path
    /// handshake-complete code.
    ///
    /// Returns `Err(InstallSessionError::LocalIndexCollision)` if the
    /// caller's chosen `local_index` is already in the demux map for
    /// any live session — regardless of which peer owns the existing
    /// entry. WG local indices must be globally unique across every
    /// live (current, previous) session this engine owns; same-peer
    /// rekey collisions are just as fatal as cross-peer collisions
    /// because rotation moves the existing current into `previous`,
    /// and the demux map can only carry one entry per index. The
    /// slow-path installer must retry handshake completion with a
    /// fresh receiver_index when this fires.
    pub(crate) fn install_session(
        &self,
        pubkey: &[u8; 32],
        session: Arc<WgSession>,
    ) -> Result<(), InstallSessionError> {
        // Serialize session installs with reconcile to avoid the
        // stale-Arc orphaning race:
        //   1) install loads `peer` from old snapshot
        //   2) reconcile removes that peer and publishes new snapshot
        //   3) install inserts demux entry against orphan peer Arc
        // Without serialization, that orphan demux entry can survive
        // future reconciles because the peer pubkey no longer exists
        // in published tables. This is slow path, so mutex cost is
        // acceptable and keeps install/reconcile linearizable.
        let _reconcile_guard = self.reconcile_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.install_session_locked(pubkey, session)
    }

    /// Lock-free core of `install_session`: the caller MUST already hold
    /// `reconcile_lock`. Exposed (module-private) so the handshake
    /// completion path can hold `reconcile_lock` across the take-state →
    /// snow-read → install critical section without re-entering the
    /// non-reentrant mutex (which would deadlock). See `consume_response`.
    pub(in crate::afxdp::wg) fn install_session_locked(
        &self,
        pubkey: &[u8; 32],
        session: Arc<WgSession>,
    ) -> Result<(), InstallSessionError> {
        let Some(peer) = self.peer_arc(pubkey) else {
            return Err(InstallSessionError::UnknownPeer);
        };
        // Refuse ANY same-key collision in the demux map. Local
        // indices must be unique across every live session this
        // engine owns — same-peer collisions are just as fatal as
        // cross-peer ones because rotation moves the existing
        // current session into `previous`, and inbound packets that
        // still address the previous session would demux to the new
        // session, fail AEAD, and silently drop. The slow-path
        // session installer is responsible for picking a fresh
        // `local_index` (the 32-bit random allocator already does
        // this trivially in expectation; a collision means the
        // caller must regenerate and retry).
        //
        // After the demux insert, install_new_session() routes the new
        // session into `current` (initiator) or `next` (responder) per
        // the 3-slot lifecycle and returns whichever session(s) fall out
        // of the slots. Those evicted sessions MUST then be removed from
        // the demux map, and because the new session's local_index is
        // now unique by construction, the removes cannot accidentally
        // evict the entry we just inserted. The single-locked-region
        // pattern keeps the (demux, current, previous, next) tuple
        // visible together to any subsequent decap.
        let new_local_index = session.local_index;
        let mut by_index = self.sessions_by_local_index.write().unwrap_or_else(|e| e.into_inner());
        if by_index.contains_key(&new_local_index) {
            return Err(InstallSessionError::LocalIndexCollision);
        }
        by_index.insert(new_local_index, session.clone());
        for old in peer.install_new_session(session) {
            // `old.local_index != new_local_index` is guaranteed by
            // the uniqueness check above; the explicit assert keeps
            // the invariant visible if a future change ever relaxes
            // the collision rule.
            debug_assert_ne!(old.local_index, new_local_index);
            by_index.remove(&old.local_index);
        }
        Ok(())
    }

    /// #3882: promote a peer's pending `next` keypair to `current` when
    /// the just-authenticated inbound `session` IS that pending keypair
    /// (WG confirm-on-first-inbound-data). Called from `try_decap` after
    /// a successful AEAD authenticate.
    ///
    /// Fast path: a cheap `next` RwLock read; if the record was on the
    /// peer's `current`/`previous` (steady state) or the peer has no
    /// pending `next`, return immediately with no `reconcile_lock`.
    /// Slow path (once per responder rekey): take `reconcile_lock` to
    /// serialize with install/reconcile/expiry, re-check `next` identity,
    /// slide next→current (old current→previous), and drop the evicted
    /// previous keypair from the demux map.
    fn maybe_promote_next(&self, peer: &Peer, session: &Arc<WgSession>) {
        // Pre-check WITHOUT the reconcile lock — the double-checked
        // locking pattern (kernel `wg_noise_received_with_keypair`).
        {
            let next = peer.next.read().unwrap_or_else(|e| e.into_inner());
            match next.as_ref() {
                Some(n) if Arc::ptr_eq(n, session) => {}
                _ => return,
            }
        }
        let _guard = self.reconcile_lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dropped_previous) = peer.promote_next(session) {
            self.sessions_by_local_index
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&dropped_previous.local_index);
        }
    }

    /// Hot-path encap.
    ///
    /// `inner_ip` is the inner IP packet (starts at the IP header;
    /// no L2). `out` is the worker's preallocated scratch buffer;
    /// the WG transport record (header + ciphertext + tag) is
    /// written starting at `out[0]`. Outer L2/L3/L4 headers are
    /// the caller's responsibility (`outer.rs` builders).
    pub(crate) fn try_encap(
        &self,
        peer_pubkey: &[u8; 32],
        inner_ip: &[u8],
        out: &mut [u8],
    ) -> Result<EncapOutcome, EncapError> {
        self.encap_inner(peer_pubkey, inner_ip, out, false)
    }

    /// #1888 S5: build an authenticated EMPTY transport record — a WG
    /// keepalive (pad_to_16(0) == 0, so the record is header + tag =
    /// 32 bytes). Keepalives consume a tx counter and obey the same
    /// T3 / REJECT_AFTER_MESSAGES / confirmed gates as data, but do
    /// NOT count as `encap_packets` (the caller attributes them to
    /// `keepalives_tx_passive` / `keepalives_tx_persistent`) and do
    /// NOT arm the T7 no-reply detector (a keepalive is not data).
    pub(crate) fn create_keepalive(
        &self,
        peer_pubkey: &[u8; 32],
        out: &mut [u8],
    ) -> Result<EncapOutcome, EncapError> {
        self.encap_inner(peer_pubkey, &[], out, true)
    }

    fn encap_inner(
        &self,
        peer_pubkey: &[u8; 32],
        inner_ip: &[u8],
        out: &mut [u8],
        is_keepalive: bool,
    ) -> Result<EncapOutcome, EncapError> {
        // Cryptokey-routing safety: the forwarding decision tells
        // us which peer to encrypt to. We do NOT consult
        // AllowedIPs to pick a peer on egress.
        let peer = self
            .peer_arc(peer_pubkey)
            .ok_or_else(|| self.counters.count_encap_err(EncapError::UnknownPeer))?;
        let Some(session) = peer.current.read().unwrap_or_else(|e| e.into_inner()).clone() else {
            // #1865: the no-current-session arm — distinct from the
            // unconfirmed gate below (same wire error, different
            // counter; AGY r2 #1736 mandated the split be visible).
            WgCounters::bump(&self.counters.encap_drops_no_session);
            return Err(EncapError::NoSession);
        };
        // WG key-confirmation: the responder MUST NOT send transport
        // data on a fresh session until it has authenticated the
        // initiator's first data packet. Treat an unconfirmed session
        // as `NoSession` so the caller falls through to its slow path
        // (typically: queue the packet, wait for the initiator to
        // send first). Initiator-role sessions are installed
        // pre-confirmed, so this gate only fires on the responder
        // side and only until the first valid inbound record. See
        // `WgSession::confirmed` doc for the rationale and Codex
        // final pre-merge finding 2 for the missed invariant.
        if !session.is_confirmed() {
            // #1865: counter-only split — the returned variant stays
            // `NoSession` so every caller contract (request_handshake
            // kick + drop) is untouched; only the attribution differs.
            WgCounters::bump(&self.counters.encap_drops_unconfirmed);
            return Err(EncapError::NoSession);
        }

        // #1888 S5: time-based gates, evaluated BEFORE any observable
        // side effect (counter consume, header write) so the on-Err
        // contract below holds. T3 (REJECT_AFTER_TIME): keys older
        // than 180s MUST NOT encrypt — drop, arm the rekey edge so the
        // control loop re-initiates, and return the caller-compatible
        // NoSession. T1 (REKEY_AFTER_TIME): a send on an
        // initiator-role session older than 120s arms the rekey edge
        // and proceeds — the spec's exact "on send" semantics.
        let now_ns = self.now_ns();
        let age_ns = now_ns.saturating_sub(session.created_ns);
        if age_ns >= super::session::REJECT_AFTER_TIME_NS {
            WgCounters::bump(&self.counters.encap_drops_expired);
            self.request_rekey(&session.peer_pubkey);
            return Err(EncapError::NoSession);
        }
        if session.role == super::session::SessionRole::Initiator
            && age_ns >= super::session::REKEY_AFTER_TIME_NS
        {
            self.request_rekey(&session.peer_pubkey);
        }

        // WG spec §5.4.6 mandates the plaintext be zero-padded to a
        // 16-byte multiple before AEAD. This obscures inner packet
        // lengths and is required for wire interoperability with
        // kernel WG / wireguard-go. Compute the padded length and
        // ensure the output buffer can hold header + ciphertext +
        // tag at the padded size.
        //
        // All bound checks fire BEFORE any observable side effect
        // (counter advance, header write into `out`). Callers can
        // therefore rely on the contract "on Err, the output buffer
        // and the session's tx_counter are untouched". An oversized
        // `out` paired with an oversized `inner_ip` previously tripped
        // the PADDED_PLAINTEXT_MAX guard AFTER `next_tx_counter()`
        // had already advanced the counter; the staging guard is
        // hoisted above the counter consume to close that hole.
        let padded_len = pad_to_16(inner_ip.len());
        let required = WG_DATA_HEADER_LEN + padded_len + POLY1305_TAG_LEN;
        if out.len() < required {
            return Err(self.counters.count_encap_err(EncapError::BufferTooSmall));
        }
        if padded_len > PADDED_PLAINTEXT_MAX {
            return Err(self.counters.count_encap_err(EncapError::BufferTooSmall));
        }
        let counter = session
            .next_tx_counter()
            .ok_or_else(|| self.counters.count_encap_err(EncapError::RekeyRequired))?;
        let _ = encode_data_header(out, session.peer_index, counter)
            .ok_or_else(|| self.counters.count_encap_err(EncapError::BufferTooSmall))?;
        // Stage the padded plaintext on the stack. We use
        // `MaybeUninit` to skip the 4096-byte zero-init that a
        // `[0u8; PADDED_PLAINTEXT_MAX]` literal would force on every
        // call. snow's `write_message` requires non-overlapping
        // plaintext and ciphertext slices, so we cannot stage the
        // plaintext inside `out`.
        //
        // Soundness: we NEVER materialize a `&mut [u8; N]` (or
        // `&mut [u8]`) over the uninitialized backing store —
        // creating a Rust reference to uninitialized memory is UB
        // even if the bytes are never read, because references carry
        // a validity invariant over their entire pointee. We only
        // write through the raw `*mut u8` returned by
        // `MaybeUninit::as_mut_ptr`, initializing exactly
        // `[0..padded_len]`. Once that range is initialized via raw
        // pointer writes, we hand snow a `&[u8]` (read-only slice)
        // limited to that initialized range — at which point the
        // reference covers fully-initialized memory and is sound.
        let mut plaintext_uninit: MaybeUninit<[u8; PADDED_PLAINTEXT_MAX]> = MaybeUninit::uninit();
        let plaintext_ptr = plaintext_uninit.as_mut_ptr() as *mut u8;
        // SAFETY:
        //   - `plaintext_ptr` is the start of a writable, properly
        //     aligned `[u8; PADDED_PLAINTEXT_MAX]` backing store on
        //     the current stack frame; it is unique (no aliasing
        //     reference exists — we never created one).
        //   - `inner_ip.len() <= padded_len <= PADDED_PLAINTEXT_MAX`,
        //     so `[0..inner_ip.len())` and
        //     `[inner_ip.len()..padded_len)` are non-overlapping
        //     in-bounds ranges of that store.
        //   - `inner_ip` is `&[u8]`, distinct from our local
        //     `plaintext_uninit`, so the copy source/dest do not
        //     alias.
        //   - After both calls, bytes `[0..padded_len)` are fully
        //     initialized: the payload from `inner_ip`, then
        //     `(padded_len - inner_ip.len()) <= 15` zero bytes (WG
        //     spec §5.4.6 padding).
        //   - Bytes `[padded_len..PADDED_PLAINTEXT_MAX)` remain
        //     uninitialized but are never read: we only borrow the
        //     initialized prefix below, and `plaintext_uninit` is
        //     dropped at end of scope without any further access.
        unsafe {
            std::ptr::copy_nonoverlapping(inner_ip.as_ptr(), plaintext_ptr, inner_ip.len());
            std::ptr::write_bytes(
                plaintext_ptr.add(inner_ip.len()),
                0u8,
                padded_len - inner_ip.len(),
            );
        }
        // SAFETY: `plaintext_ptr` is valid for `padded_len` bytes
        // (proved above) and those bytes are now initialized
        // (`copy_nonoverlapping` + `write_bytes`). Building a `&[u8]`
        // (immutable) over an initialized range is the standard
        // MaybeUninit "assume_init_ref-equivalent" pattern; we use
        // `from_raw_parts` here rather than `MaybeUninit::slice_assume_init_ref`
        // because the latter wants a `&[MaybeUninit<u8>]` source
        // slice which itself crosses the same validity boundary we
        // are avoiding. The returned slice is read-only and lives
        // only until snow consumes it on this line.
        let plaintext: &[u8] = unsafe { std::slice::from_raw_parts(plaintext_ptr, padded_len) };
        let (_hdr, payload) = out.split_at_mut(WG_DATA_HEADER_LEN);
        let n = session
            .transport
            .write_message(counter, plaintext, payload)
            .map_err(|_| self.counters.count_encap_err(EncapError::CryptoFailed))?;
        // #1888 S5 activity stamps (§3 of the plan): any authenticated
        // send clears the T6 passive-keepalive arm; a non-empty DATA
        // send additionally arms (if unarmed) the T7 no-reply
        // detector. Keepalives must not arm T7 — they are not data.
        if is_keepalive {
            peer.note_authenticated_send(now_ns);
        } else {
            peer.note_data_send(now_ns);
            // #1865: success accounting — inner-IP (un-padded) bytes,
            // symmetric with the decap side. Keepalives are counted by
            // the caller under keepalives_tx_*, not as data packets.
            WgCounters::bump(&self.counters.encap_packets);
            self.counters
                .encap_bytes
                .fetch_add(inner_ip.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(EncapOutcome {
            len: WG_DATA_HEADER_LEN + n,
            receiver_index: session.peer_index,
            counter,
        })
    }

    /// Hot-path decap.
    ///
    /// `wg_record` is the WG transport record extracted from the
    /// outer UDP payload (starts at the WG type byte). `out` is
    /// the worker's preallocated scratch; decrypted inner-IP
    /// plaintext is written starting at `out[0]`.
    pub(crate) fn try_decap(
        &self,
        wg_record: &[u8],
        out: &mut [u8],
    ) -> Result<DecapOutcome, DecapError> {
        let hdr = parse_data_header(wg_record)
            .ok_or_else(|| self.counters.count_decap_err(DecapError::MalformedHeader))?;
        // WG spec §6.5: drop inbound data packets whose counter is
        // at or above REJECT_AFTER_MESSAGES without doing AEAD. The
        // counter-space ceiling is symmetric across encap/decap;
        // the encap-side guard alone is not sufficient because a
        // malicious or buggy sender may send arbitrary high counters.
        if hdr.counter >= REJECT_AFTER_MESSAGES {
            return Err(self
                .counters
                .count_decap_err(DecapError::CounterRejectAfterMessages));
        }
        let session = self
            .sessions_by_local_index
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&hdr.receiver_index)
            .cloned()
            .ok_or_else(|| self.counters.count_decap_err(DecapError::UnknownSession))?;
        // Truncated-record DoS guard. `parse_data_header` only checks
        // that the buffer has at least WG_DATA_HEADER_LEN (16) bytes;
        // it does not enforce that the trailing ciphertext field is
        // at least one Poly1305 tag wide. Snow 0.10's ChaCha-Poly1305
        // decrypt computes `ciphertext.len() - TAGLEN` with no short-
        // tag guard — for `ciphertext.len() < POLY1305_TAG_LEN` this
        // wraps to a huge usize and panics on the subsequent slice op
        // (or underflows directly in debug builds). A hostile peer
        // with a known live `receiver_index` could crash the AF_XDP
        // worker by sending 16..31-byte UDP datagrams; remote
        // dataplane DoS. Reject sub-tag records here, before any of
        // the replay-window / snow code runs. Caught by Codex on the
        // r-final-2 review (the truncated-record class was missed by
        // all 9 prior review rounds).
        if hdr.ciphertext.len() < POLY1305_TAG_LEN {
            return Err(self.counters.count_decap_err(DecapError::ShortRecord));
        }
        // #1888 S5 T3 (REJECT_AFTER_TIME), receive side: refuse keys
        // older than 180s BEFORE doing any AEAD work. Drop-only — no
        // rekey arm (see DecapError::Expired). The control thread's
        // expire_sessions tears the session down within one tick.
        let now_ns = self.now_ns();
        if now_ns.saturating_sub(session.created_ns) >= super::session::REJECT_AFTER_TIME_NS {
            return Err(self.counters.count_decap_err(DecapError::Expired));
        }
        let plaintext_len_max = hdr.ciphertext.len() - POLY1305_TAG_LEN;
        if out.len() < plaintext_len_max {
            return Err(self.counters.count_decap_err(DecapError::BufferTooSmall));
        }
        {
            let replay = session.replay.lock().unwrap_or_else(|e| e.into_inner());
            if replay.definitely_out_of_window(hdr.counter) {
                return Err(self.counters.count_decap_err(DecapError::ReplayOutOfWindow));
            }
        }
        // #9918 F-143: snow's decrypt copies ciphertext into `out` then
        // decrypts in place; on tag failure `out[..plaintext_len_max]`
        // holds attacker-influenced unauthenticated bytes. Zero the staging
        // region before returning so a caller that mishandles the error path
        // cannot leak them upstream — matching every sibling post-AEAD arm.
        let n = match session
            .transport
            .read_message(hdr.counter, hdr.ciphertext, out)
        {
            Ok(n) => n,
            Err(_) => {
                out[..plaintext_len_max].zeroize();
                return Err(self.counters.count_decap_err(DecapError::CryptoFailed));
            }
        };
        // WG key-confirmation: a successful AEAD authenticate is
        // proof that the peer has the session keys, so a responder-
        // role session can now be used for egress. Initiator-role
        // sessions install pre-confirmed; this is a no-op for them.
        // Set the flag BEFORE the replay/LPM gates so a packet that
        // authenticates but fails AllowedIPs still flips the
        // confirmation — the authentication is what the WG spec
        // ties confirmation to, not downstream policy gates.
        session.mark_confirmed();
        // #3882 WG 3-slot keypair lifecycle: an authenticated inbound
        // record on a peer's pending `next` (unconfirmed responder)
        // keypair CONFIRMS it — promote next→current (old current→
        // previous) so egress switches to the freshly-confirmed keypair.
        // Done here (before the replay/LPM gates, same rationale as
        // mark_confirmed) off ONE peer snapshot reused by the timer
        // block below. The common steady-state record (on `current` or
        // `previous`) returns from the fast pre-check with only a cheap
        // RwLock read — no reconcile lock.
        let peer = self.peer_arc(&session.peer_pubkey);
        if let Some(peer) = peer.as_ref() {
            self.maybe_promote_next(peer, &session);
        }
        // Check the replay window AFTER successful decrypt — per
        // RFC 6479 / the WG paper, we mustn't update the window
        // for packets that fail authentication, or an attacker
        // could DoS the window by injecting bogus high-counter
        // ciphertexts.
        {
            let mut replay = session.replay.lock().unwrap_or_else(|e| e.into_inner());
            match replay.check_and_update(hdr.counter) {
                ReplayDecision::Accept => {}
                ReplayDecision::Repeat => {
                    // Authentic but replayed: snow has already written
                    // plaintext into `out[..n]`. Zero the staging
                    // region before returning so a caller that
                    // mishandles the error path cannot leak the
                    // plaintext upstream. Cost is one memset per
                    // replay-reject — the rare path.
                    out[..n].fill(0);
                    return Err(self.counters.count_decap_err(DecapError::ReplayDuplicate));
                }
                ReplayDecision::OutOfWindow => {
                    out[..n].fill(0);
                    return Err(self.counters.count_decap_err(DecapError::ReplayOutOfWindow));
                }
            }
        }
        // #1888 S5 activity stamps + T2 receive-horizon, applied to
        // ANY authenticated, replay-accepted transport record. Stamped
        // BEFORE the inner-parse/AllowedIPs gates (Codex r1 M3 —
        // wireguard-go fires its receive timers once the packet
        // authenticates, before routing delivery; an AllowedIPs-
        // rejected packet still proves the peer is alive on this
        // session). The non-empty/keepalive split picks data-recv
        // (arms T6) vs authenticated-recv (clears T7 only — a received
        // keepalive must not arm T6, no keepalive ping-pong).
        {
            if let Some(peer) = peer.as_ref() {
                if n == 0 {
                    peer.note_authenticated_recv(now_ns);
                } else {
                    peer.note_data_recv(now_ns);
                }
            }
            // T2: a receive on an initiator-role session past the 165s
            // horizon arms the rekey edge (covers a receive-only
            // initiator before the responder's 180s discard).
            if session.role == super::session::SessionRole::Initiator
                && now_ns.saturating_sub(session.created_ns)
                    >= super::session::RECV_REKEY_HORIZON_NS
            {
                self.request_rekey(&session.peer_pubkey);
            }
        }
        // #1865: authenticated ZERO-length transport record == WG
        // persistent keepalive (pad_to_16(0) == 0, so snow yields
        // n == 0). It has done its protocol work above (AEAD
        // authenticated, session confirmed, replay window advanced) but
        // carries no inner packet to deliver. Count it as a keepalive
        // and exit through the SAME error the inner-parse would have
        // produced - external behavior is byte-identical to pre-#1865
        // (no TUN write, caller treats it as unauthenticated for
        // endpoint-learning; see plan §9 for that latent gap) - but
        // the telemetry no longer reports a steady stream of false
        // "malformed inner" drops for a keepalive peer (Codex r1 F1 +
        // SMR r1 F1, independent convergence).
        if n == 0 {
            // #7230: carry the peer out instead of discarding it. Routed
            // through count_decap_err so the counter arm is exhaustive-
            // matched rather than bumped by hand here; the counter it
            // lands on (decap_keepalives) is unchanged.
            return Err(self
                .counters
                .count_decap_err(DecapError::Keepalive(session.peer_pubkey)));
        }
        // AllowedIPs gate on the inner src IP. WG spec §5.4.6:
        // "After decryption, the receiver verifies that the source
        // IP of the inner packet belongs to the peer who sent it.
        // If not, drop." This is the cryptokey-routing safety
        // invariant on the receive side.
        //
        // Every error arm at or past `read_message` MUST zero the staging
        // region before returning so the contract "on Err the caller MUST
        // NOT inspect `out`" is structurally enforced: `CryptoFailed` zeros
        // `out[..plaintext_len_max]` at the failure site above; the arms
        // below use a single fall-through that zeros `out[..n]`, so adding
        // a new post-decrypt error arm cannot accidentally skip the wipe.
        //
        // The plaintext is the padded form (WG §5.4.6 zero-padded
        // to a 16-byte multiple at the sender). We parse src IP
        // from the IPv4/IPv6 header's fixed offset, which is well
        // before any padding bytes. The returned `inner_ip_len`
        // truncates `n` down to the real inner-IP packet length;
        // see `inner_ip_len_after_decap` for the IPv4
        // `total_length` / IPv6 `payload_length` math. The caller
        // sees only the un-padded inner-IP packet.
        let outcome = (|| -> Result<(IpAddr, u32, usize), DecapError> {
            let inner_src = inner_src_ip(&out[..n])
                .ok_or(DecapError::MalformedInner(session.peer_pubkey))?;
            // Single atomic snapshot for both peer-index lookup and
            // AllowedIPs gate. Taking these from separate ArcSwap
            // loads would re-introduce the reconcile race window
            // — between the two loads, a config refresh could swap
            // the peer table and we'd pair a peer_idx from the old
            // snapshot with allowed_ips from the new one.
            let table = self.load_table();
            let peer_idx = *table
                .peer_index_by_pubkey
                .get(&session.peer_pubkey)
                .ok_or(DecapError::UnknownSession)?;
            if !table.allowed_ips.matches_for_peer(inner_src, peer_idx) {
                return Err(DecapError::AllowedIpsViolation);
            }
            let inner_len = inner_ip_len_after_decap(&out[..n])
                .ok_or(DecapError::MalformedInner(session.peer_pubkey))?;
            Ok((inner_src, peer_idx, inner_len))
        })();
        match outcome {
            Ok((_inner_src, _peer_idx, inner_len)) => {
                debug_assert!(inner_len <= n);
                // #1865: success accounting - inner-IP (un-padded)
                // bytes, symmetric with the encap side.
                WgCounters::bump(&self.counters.decap_packets);
                self.counters
                    .decap_bytes
                    .fetch_add(inner_len as u64, std::sync::atomic::Ordering::Relaxed);
                Ok(DecapOutcome {
                    len: inner_len,
                    peer_pubkey: session.peer_pubkey,
                })
            }
            Err(e) => {
                // Defensive: zero the plaintext we just authenticated
                // but cannot deliver. Covers MalformedInner,
                // UnknownSession, and AllowedIpsViolation uniformly.
                out[..n].fill(0);
                Err(self.counters.count_decap_err(e))
            }
        }
    }

    /// Build a snow `HandshakeState` configured as the initiator
    /// toward `peer_pubkey`. The caller drives the handshake to
    /// completion (write init, read response) and then uses
    /// `into_stateless_transport_mode` to obtain the
    /// `StatelessTransportState` that `install_session` wraps.
    ///
    /// Slow path only.
    pub(crate) fn build_initiator_handshake(
        &self,
        peer_pubkey: &[u8; 32],
    ) -> Result<HandshakeState, snow::Error> {
        self.build_initiator_handshake_with_ephemeral(peer_pubkey, None)
    }

    /// Test seam for #9918 F-146 deterministic vectors: same production
    /// pattern/prologue/key-role/PSK wiring as [`Self::build_initiator_handshake`],
    /// but with a fixed ephemeral via snow's
    /// `fixed_ephemeral_key_for_testing_only` (a `#[doc(hidden)]` unstable
    /// test API — pinned knowingly, test-only). Vectors driven through this
    /// cover what ships; a prologue/pattern/PSK regression in production
    /// fails them.
    #[cfg(test)]
    pub(crate) fn build_initiator_handshake_with_fixed_for_test(
        &self,
        peer_pubkey: &[u8; 32],
        e_fixed: &[u8],
    ) -> Result<HandshakeState, snow::Error> {
        self.build_initiator_handshake_with_ephemeral(peer_pubkey, Some(e_fixed))
    }

    fn build_initiator_handshake_with_ephemeral(
        &self,
        peer_pubkey: &[u8; 32],
        e_fixed: Option<&[u8]>,
    ) -> Result<HandshakeState, snow::Error> {
        // `.prologue(WG_PROTOCOL_ID_BYTES)` is mandatory for wire
        // interoperability with kernel WireGuard and wireguard-go. The
        // WG protocol mixes the ASCII identifier
        // "WireGuard v1 zx2c4 Jason@zx2c4.com" into the initial Noise
        // hash. Omitting the prologue produces a "WireGuard-shaped"
        // transcript that no real peer will authenticate. Codex final
        // pre-merge review caught this after nine prior review rounds
        // missed it; see WG_PROTOCOL_ID_BYTES doc in mod.rs.
        //
        // #1434 B2: the initiator knows the peer at build time, so it
        // sets that peer's PSK directly. `WG_ZERO_PSK` (no configured
        // PSK) reproduces the pre-#1434 behavior bit-for-bit.
        let psk = self
            .peer_config(peer_pubkey)
            .map(|c| c.preshared_key())
            .unwrap_or(WG_ZERO_PSK);
        let builder = Builder::new(WG_NOISE_PATTERN.parse()?)
            .prologue(WG_PROTOCOL_ID_BYTES)?
            .local_private_key(self.local_private_key.as_slice())?
            .remote_public_key(peer_pubkey)?
            .psk(2, &psk)?;
        let builder = match e_fixed {
            Some(e) => builder.fixed_ephemeral_key_for_testing_only(e),
            None => builder,
        };
        builder.build_initiator()
    }

    /// Build a snow `HandshakeState` configured as the responder.
    /// Slow path only.
    ///
    /// TODO(#1499 r4 / responder-peer-id): the integration layer
    /// needs a thin helper that (a) builds this responder state,
    /// (b) reads the init message, (c) calls
    /// `HandshakeState::get_remote_static` to learn which peer sent
    /// the init, and (d) looks up the peer in the engine table.
    /// snow already supports step (c); we just haven't surfaced a
    /// convenience API yet. Adding it here would couple the engine
    /// to the snow message-bytes parser which is integration-layer
    /// concern. Tracked for the integration PR.
    pub(crate) fn build_responder_handshake(&self) -> Result<HandshakeState, snow::Error> {
        self.build_responder_handshake_with_ephemeral(None)
    }

    /// Test seam for #9918 F-146 (see the initiator seam above).
    #[cfg(test)]
    pub(crate) fn build_responder_handshake_with_fixed_for_test(
        &self,
        e_fixed: &[u8],
    ) -> Result<HandshakeState, snow::Error> {
        self.build_responder_handshake_with_ephemeral(Some(e_fixed))
    }

    fn build_responder_handshake_with_ephemeral(
        &self,
        e_fixed: Option<&[u8]>,
    ) -> Result<HandshakeState, snow::Error> {
        // See `build_initiator_handshake` for the prologue rationale.
        // Both sides must mix the same identifier into the Noise
        // initial hash or the transcripts diverge from byte one.
        let builder = Builder::new(WG_NOISE_PATTERN.parse()?)
            .prologue(WG_PROTOCOL_ID_BYTES)?
            .local_private_key(self.local_private_key.as_slice())?
            .psk(2, &WG_ZERO_PSK)?;
        let builder = match e_fixed {
            Some(e) => builder.fixed_ephemeral_key_for_testing_only(e),
            None => builder,
        };
        builder.build_responder()
    }
}

/// Read the inner-IP packet's total length from its own header, so
/// the caller of `try_decap` receives the un-padded inner-IP packet
/// length (not the §5.4.6 padded plaintext length that snow
/// authenticated). The decrypted plaintext is `padded_inner_ip ||
/// zeros_up_to_16_byte_multiple`; trimming to the on-the-wire
/// inner-IP length here means downstream consumers never see WG's
/// padding bytes.
///
/// Returns `None` if:
///   - the buffer is too short for an IPv4/IPv6 header,
///   - the IP `version` nibble is something other than 4 or 6,
///   - the header-declared length exceeds the decrypted buffer
///     (the sender lied or the AEAD verified a malformed packet —
///     either way, drop).
fn inner_ip_len_after_decap(pkt: &[u8]) -> Option<usize> {
    let version = pkt.first()? >> 4;
    let claimed = match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            // RFC 791: IHL is the IP header length in 32-bit words.
            // Valid values are 5..=15 (20..=60 bytes of header). An
            // IHL < 5 means there isn't even room for the fixed IPv4
            // header. Copilot inline review: an AEAD-authenticated
            // payload with a bogus IHL would otherwise let
            // `total_length` claim a value < ihl*4 and `DecapOutcome
            // .len` could be < 20 — a downstream parser that
            // assumes "len >= 20 ⇒ valid IPv4 header" would
            // mis-interpret the bytes. Reject these here so the
            // post-decap consumer never sees a structurally bogus
            // inner header.
            let ihl = (pkt[0] & 0x0f) as usize;
            if ihl < 5 {
                return None;
            }
            let header_len = ihl * 4;
            let total_length = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            if total_length < header_len {
                return None;
            }
            total_length
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            // IPv6 header fixed at 40; payload_length is bytes 4..6.
            40 + u16::from_be_bytes([pkt[4], pkt[5]]) as usize
        }
        _ => return None,
    };
    // The claimed length must fit inside the AEAD-validated plaintext.
    // `pkt` is the snow `read_message` output (ciphertext_len - 16 tag),
    // so this bound rejects an inner header whose declared length lies
    // about how many bytes were actually decrypted — the only real
    // length invariant on the decap side (#2910).
    if claimed > pkt.len() {
        return None;
    }
    // WG §5.4.6 trailing padding: the protocol is length-driven on
    // receive. The receiver reads the inner-IP length and discards the
    // remainder; it does NOT validate the padding bytes. The AEAD tag
    // already authenticates the entire plaintext (including any
    // padding), so non-zero padding cannot be forged by an attacker —
    // rejecting it buys no security but breaks interop with peers whose
    // padding is not all-zero (kernel WireGuard / wireguard-go do not
    // require zero padding; a peer may randomize it for traffic-analysis
    // resistance). Truncate to `claimed` and deliver; the pad bytes
    // after it are dropped, never forwarded (#2910 / agy-review-053).
    Some(claimed)
}

/// Extract the source IP from the front of an inner-IP packet.
/// Used for the AllowedIPs receive-side gate. Returns `None` for
/// unsupported / malformed inputs.
fn inner_src_ip(pkt: &[u8]) -> Option<IpAddr> {
    let version = pkt.first()? >> 4;
    match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                pkt[12], pkt[13], pkt[14], pkt[15],
            )))
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&pkt[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod engine_internal_tests;
