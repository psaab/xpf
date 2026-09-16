//! Per-peer state.
//!
//! A peer holds:
//!   - Its static public key (the identity used by the engine table).
//!   - Optionally an endpoint (UDP `IP:port`) for outbound handshake.
//!   - The 3-slot keypair lifecycle (#3882): `current` (confirmed,
//!     egress), `previous` (prior current, in-flight rekey handover),
//!     and `next` (unconfirmed responder keypair awaiting the peer's
//!     first inbound data record). See the `Peer` struct doc.
//!
//! Reconciliation: the engine rebuilds the peer set from the config
//! snapshot whenever a new snapshot lands. Existing peer state is
//! preserved across snapshots (same pubkey → same `Arc<Peer>`); the
//! AllowedIPs trie is rebuilt fresh because its index space is
//! tied to the snapshot.

use super::session::{SessionRole, WgSession};
use super::tai64n::TAI64N_LEN;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering, fence};
use std::sync::{Arc, Mutex, RwLock};

/// Immutable per-snapshot peer config tuple (#2836).
///
/// `endpoint`, `persistent_keepalive`, and `preshared_key` are
/// operator-facing fields that change only on a config commit. They
/// USED to be interior-mutable on `Peer` and rewritten in place by
/// `reconcile_peers` on the reused peer Arc. That defeated the
/// documented `PeerTable` atomicity invariant: because the SAME peer
/// Arc is shared between the old and the new published table, an
/// in-place write was instantly visible to a reader still holding the
/// OLD table snapshot — so an old-prefix packet (matched against the
/// old AllowedIPs) could read the NEW endpoint and be encrypted to the
/// wrong underlay, and the endpoint/keepalive/PSK could be observed as
/// a torn mix of old and new.
///
/// The config is now an immutable bundle owned by the `PeerTable`
/// snapshot (one `Arc<PeerConfig>` per `PeerEntry`). `reconcile_peers`
/// builds a FRESH `PeerConfig` for every commit and the whole table is
/// published in a single `ArcSwap::store`, so a reader sees the
/// fully-old or the fully-new tuple, never a mix. The hot egress path
/// reads the endpoint straight from the loaded snapshot — no per-packet
/// `RwLock` (folds codex-049-04).
///
/// Roaming (#1499 r4) is unaffected: a learned-endpoint update would
/// still go through a reconcile (or a future table re-publish), which
/// builds a new immutable bundle and swaps it atomically.
pub(crate) struct PeerConfig {
    /// Optional outbound endpoint. `None` means responder-only.
    pub(crate) endpoint: Option<SocketAddr>,
    /// Optional keepalive interval in seconds (per WG: 0 = off).
    /// Consumed by the #1888 S5 timer pass (`WgEngine::timer_pass` T8 —
    /// see wg/timers.rs).
    pub(crate) persistent_keepalive: u16,
    /// Per-peer preshared key (#1434 B2). 32 zero bytes = no PSK
    /// (semantically identical to the all-zero key in Noise IKpsk2).
    /// SECRET: `Zeroizing` so the key material is wiped when the bundle
    /// drops (i.e. when the snapshot that owns it is freed); redacted in
    /// the manual Debug impl below; never logged. A config commit that
    /// rotates the PSK drops the old bundle, wiping the superseded key.
    pub(crate) preshared_key: zeroize::Zeroizing<[u8; 32]>,
}

impl PeerConfig {
    pub(crate) fn new(
        endpoint: Option<SocketAddr>,
        persistent_keepalive: u16,
        preshared_key: [u8; 32],
    ) -> Self {
        Self {
            endpoint,
            persistent_keepalive,
            preshared_key: zeroize::Zeroizing::new(preshared_key),
        }
    }

    /// Plain copy of the preshared key for the handshake builders (they
    /// hand it straight to snow's `psk`/`set_psk`). 32 zero bytes = no
    /// PSK. The snapshot-resident master copy stays `Zeroizing`.
    pub(crate) fn preshared_key(&self) -> [u8; 32] {
        *self.preshared_key
    }
}

impl std::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let psk_set = *self.preshared_key != [0u8; 32];
        f.debug_struct("PeerConfig")
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("preshared_key", &if psk_set { "<redacted>" } else { "<unset>" })
            .finish()
    }
}

/// A peer's long-lived, config-independent state: its identity, its
/// transport sessions, and its timer bookkeeping. Reused across config
/// commits (same pubkey → same `Arc<Peer>`) so the
/// (current, previous, next) keypair slots and timer pacing survive a
/// commit. The operator-facing config tuple lives in the per-snapshot
/// `PeerConfig` (#2836), NOT here, so config changes are observed
/// atomically with the table swap.
///
/// ## 3-slot keypair lifecycle (#3882)
///
/// The three session slots mirror the kernel WireGuard
/// current/previous/next keypair model (`drivers/net/wireguard/noise.c`,
/// `add_new_keypair` / `wg_noise_received_with_keypair`):
///
///   - **current** — the CONFIRMED keypair egress encrypts with. Only
///     ever set to a confirmed session: an initiator-role session (the
///     handshake response confirmed it) or a `next` session promoted
///     after its first authenticated inbound data record.
///   - **previous** — the prior current, retained across a rotation so
///     in-flight reverse traffic on the old keypair still decrypts.
///   - **next** — a responder-role keypair that has NOT yet been
///     confirmed. When xpf is the RESPONDER to a (re)key, the new
///     session lands here, NOT in `current`; egress keeps using the
///     confirmed `current` until the initiator proves it completed the
///     handshake by sending the first inbound data record on the new
///     keypair, at which point `promote_next` slides next→current
///     (old current→previous). Before #3882 the unconfirmed responder
///     session was rotated straight into `current`, so every
///     peer-initiated rekey blackholed xpf→peer egress until the peer
///     sent data (a replayable egress DoS — the F-019 defect).
///
/// #9644: lock-free last-observed-endpoint snapshot for the WireGuard
/// decap hot path. `note_worker_observed_endpoint` runs once per
/// authenticated transport-data record; the steady state (endpoint
/// unchanged) must cost one optimistic snapshot read — atomic loads
/// (Acquire on the sequence/epochs, Relaxed on the words), an Acquire
/// fence, and a compare — never the peer's roaming `Mutex`. This
/// snapshot is ADVISORY ONLY: the mutex-protected
/// `Peer::roamed_endpoint` slot stays the authority (every report
/// path re-checks under lock).
///
/// Suppression contract — complete statement, normative here (this
/// comment, not an external plan, is what the code implements). A
/// validated read (stable even `seq` across the reader
/// Acquire-fence protocol) certifies the words of exactly one
/// COMPLETE historical publication made while the publisher held
/// the peer mutex with the slot holding the decoded endpoint. It
/// certifies NOTHING about current slot contents, pending state, or
/// epoch freshness, so suppression is permitted on stale snapshots
/// in exactly these cases. E1 missed-odd validation: the reader
/// validates the previous generation while a same-epoch publish is
/// in progress or complete-but-core-invisible. E2 stale-generation
/// read: the reader validates an older same-epoch publication while
/// newer same-epoch publications exist, at any depth. E3 stale-epoch
/// read: both epoch loads pre-date one or more take/start bumps;
/// adoption of the suppressed value is not required. E4
/// take-before-bump interval: epochs match while the physical slot
/// is already `None`; the abstract take linearizes at the bump.
/// Consequences, all accepted: ancestor suppression (a suppressed
/// value may be neither queued-latest nor just-adopted); NO formal
/// bound on recovery packet count; this mailbox is NOT
/// last-write-wins linearizable. Liveness assumption OP-1: live
/// cores observe epoch/seq RMWs promptly via cache coherence
/// (assumed, not proven); every invalid snapshot state terminates
/// in a repairing equal slow hit, so suppression always resumes.
///
/// Counter lifetimes — non-wrapping by margin (no wrap handling;
/// `fetch_add` wraps by definition, so the proof is that reaching
/// the wrap is infeasible). `live_epoch`/`snap_epoch` advance at
/// most once per control pass per peer plus once per consumer
/// start: at one bump per second, 2^64 needs over 10^11 years
/// (over 10^5 years even at an absurd sustained 10^6 bumps/s).
/// `seq` advances twice per publish; publishes serialize on the
/// peer mutex and number at most in the packets-per-second of one
/// peer: even at an unachievable sustained 10^9 publishes/s, the
/// 2^64 parity cycle lasts ~585 years. A confused (wrapped)
/// sequence is therefore unreachable on any real timeline.
///
/// Layout: seq + live/stamped epochs + 5 payload words = 8 × 8 B on
/// ONE cache line, so steady-state readers touch exactly one line
/// that no writer stores to between roams.
///
/// Access protocol: the fields stay `pub(crate)` ONLY for the test
/// cells (controlled torn-state staging + seq/epoch stability
/// oracles). Production code MUST NOT store these fields directly:
/// every production mutation goes through `begin/commit_publish`
/// (peer mutex held) or `bump_live_epoch`, and every production read
/// goes through `read_validated_endpoint`. A direct word store
/// outside the odd..even bracket would publish unanchored words that
/// a concurrent reader could validate as a complete publication.
#[repr(align(64))]
pub(crate) struct RoamSnapshot {
    pub(crate) seq: AtomicU64,
    pub(crate) live_epoch: AtomicU64,
    pub(crate) snap_epoch: AtomicU64,
    pub(crate) w0: AtomicU64,
    pub(crate) w1: AtomicU64,
    pub(crate) w2: AtomicU64,
    pub(crate) w3: AtomicU64,
    pub(crate) w4: AtomicU64,
}

const _: () = assert!(core::mem::size_of::<RoamSnapshot>() == 64);

/// #9644: total `SocketAddr` encoding for the snapshot words.
/// `w0 = (family << 56) | (port << 32) | addr word0`, `w1..w3` the
/// remaining address words (zero for V4), `w4 = (flowinfo << 32) |
/// scope_id`. Family byte 0 decodes to `None` (the initial state,
/// never equal to an endpoint). Exact and injective over the full
/// `SocketAddr` (v4-mapped forms stay distinct — canonicalization
/// is the drain's job, as with the slot).
pub(crate) fn encode_roam_endpoint(endpoint: SocketAddr) -> [u64; 5] {
    match endpoint {
        SocketAddr::V4(v4) => {
            let octets = v4.ip().octets();
            [
                (4u64 << 56)
                    | ((v4.port() as u64) << 32)
                    | (u32::from_be_bytes(octets) as u64),
                0,
                0,
                0,
                0,
            ]
        }
        SocketAddr::V6(v6) => {
            let o = v6.ip().octets();
            let w = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64;
            [
                (6u64 << 56) | ((v6.port() as u64) << 32) | w(&o[0..4]),
                w(&o[4..8]),
                w(&o[8..12]),
                w(&o[12..16]),
                ((v6.flowinfo() as u64) << 32) | (v6.scope_id() as u64),
            ]
        }
    }
}

/// Inverse of [`encode_roam_endpoint`]; `None` for the family-0
/// sentinel or an unknown family discriminant. Round-trips `w4`
/// through [`std::net::SocketAddrV6`] so flowinfo/scope_id survive.
pub(crate) fn decode_roam_endpoint(words: &[u64; 5]) -> Option<SocketAddr> {
    let port = ((words[0] >> 32) & 0xFFFF) as u16;
    match words[0] >> 56 {
        4 => {
            let octets = (words[0] as u32).to_be_bytes();
            Some(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)),
                port,
            ))
        }
        6 => {
            let mut o = [0u8; 16];
            for (i, w) in words[0..4].iter().enumerate() {
                // `w0` low 32 bits hold address word 0; the family/port
                // bits above it are masked out by the `as u32` cast.
                o[i * 4..i * 4 + 4].copy_from_slice(&(*w as u32).to_be_bytes());
            }
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(o),
                port,
                (words[4] >> 32) as u32,
                words[4] as u32,
            )))
        }
        _ => None,
    }
}

impl RoamSnapshot {
    pub(crate) fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            live_epoch: AtomicU64::new(0),
            snap_epoch: AtomicU64::new(0),
            w0: AtomicU64::new(0),
            w1: AtomicU64::new(0),
            w2: AtomicU64::new(0),
            w3: AtomicU64::new(0),
            w4: AtomicU64::new(0),
        }
    }

    /// Drain / consumer-start generation. Bumped under the peer
    /// mutex on take-of-`Some`, lock-free at consumer start (cold).
    /// Release/Acquire-paired with the reader's epoch loads.
    pub(crate) fn bump_live_epoch(&self) {
        self.live_epoch.fetch_add(1, Ordering::Release);
    }

    /// ODD-FIRST publish, part 1: mark the sequence odd BEFORE the
    /// slot write, so no reader can observe a slot write unanchored
    /// in a publication. Call only with the peer mutex
    /// held; the matching [`RoamSnapshot::commit_publish`] must
    /// follow in the same critical section.
    ///
    /// Ordering: `Relaxed` suffices for the mark because it publishes
    /// no data — a reader that observes odd bails WITHOUT touching
    /// the words, and the commit's Release fence (below) retroactively
    /// orders this mark before the word stores for any reader that
    /// goes on to validate. Atomicity (not ordering) is what the
    /// mark needs, and the mutex serializes publishers.
    pub(crate) fn begin_publish(&self) {
        let prev = self.seq.fetch_add(1, Ordering::Relaxed);
        debug_assert!(prev & 1 == 0, "9644: publish without matching close");
    }

    /// ODD-FIRST publish, part 2: fence, word stores, even close.
    /// The slot + pending stores belong between the two calls, in
    /// the same critical section. Only infallible operations may
    /// appear in the odd region — no panic/unwind may abandon it
    /// (preemption remains possible).
    ///
    /// Ordering: the Release fence pairs with the reader's Acquire
    /// fence — together they order the Relaxed word/`snap_epoch`
    /// stores between the odd mark and the even close — and the
    /// Release close lets a validating reader's Acquire `s1` import
    /// the whole publication. The words themselves need no stronger
    /// ordering because no reader consumes them without first
    /// validating the bracketing sequence.
    pub(crate) fn commit_publish(&self, words: [u64; 5], epoch: u64) {
        fence(Ordering::Release);
        self.w0.store(words[0], Ordering::Relaxed);
        self.w1.store(words[1], Ordering::Relaxed);
        self.w2.store(words[2], Ordering::Relaxed);
        self.w3.store(words[3], Ordering::Relaxed);
        self.w4.store(words[4], Ordering::Relaxed);
        self.snap_epoch.store(epoch, Ordering::Relaxed);
        self.seq.fetch_add(1, Ordering::Release);
    }

    /// #9644 fast-path decision: the optimistic seqlock read, exactly
    /// as the decap hot path performs it. Returns the decoded
    /// endpoint iff the sequence is stable and even across the read
    /// AND the stamped epoch matches both live-epoch observations;
    /// `None` for an in-flight (odd) publication, a torn read
    /// (`s0 != s1`), a stale-epoch snapshot, or the family-0
    /// sentinel. This validates coherence only, NOT currentness
    /// (E1–E4 in the contract above may validate stale snapshots).
    /// The sole production caller is
    /// `note_worker_observed_endpoint`'s duplicate-suppression check;
    /// the unit cells below call it directly against controlled
    /// torn/stale states, which is what makes them sensitive to
    /// broken sequence/epoch validation rather than to the mailbox
    /// mutex they never touch.
    pub(crate) fn read_validated_endpoint(&self) -> Option<SocketAddr> {
        // `e0`/`s0` are Acquire so no word load hoists above them and
        // the opening reads import the latest closed publication;
        // `s1`/`e1` are Acquire so a validated read imports it.
        let e0 = self.live_epoch.load(Ordering::Acquire);
        let s0 = self.seq.load(Ordering::Acquire);
        if s0 & 1 == 0 {
            // Relaxed: these words are consumed ONLY under a stable
            // `s0 == s1` below, which proves no publication spanned
            // the read; the Acquire fence pairs with the commit's
            // Release fence to order them before the `s1` re-read
            // (on x86 TSO this is belt-and-braces; on AArch64 the
            // fence is what stops later word stores validating under
            // an earlier sequence).
            let words = [
                self.w0.load(Ordering::Relaxed),
                self.w1.load(Ordering::Relaxed),
                self.w2.load(Ordering::Relaxed),
                self.w3.load(Ordering::Relaxed),
                self.w4.load(Ordering::Relaxed),
            ];
            let snap_epoch = self.snap_epoch.load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            let s1 = self.seq.load(Ordering::Acquire);
            let e1 = self.live_epoch.load(Ordering::Acquire);
            if s0 == s1 && snap_epoch == e0 && snap_epoch == e1 {
                return decode_roam_endpoint(&words);
            }
        }
        None
    }
}

pub(crate) struct Peer {
    pub(crate) pubkey: [u8; 32],
    /// #1888 S5 activity stamps + armed timers, all CLOCK_MONOTONIC ns
    /// relaxed atomics, 0 = never/unarmed. Peer-resident (NOT
    /// session-resident) so a rekey does not reset keepalive pacing or
    /// the dead-peer detector — matching wireguard-go, where all
    /// timers hang off the peer. Semantics are pinned in
    /// `docs/research/1888-wg-timers/plan.md` §3.
    ///
    /// Any authenticated packet SENT: transport data, keepalive, or a
    /// handshake message we emitted. Paces T8 (persistent keepalive).
    pub(crate) last_send_any_ns: AtomicU64,
    /// Any authenticated packet RECEIVED: transport data, keepalive,
    /// or a valid handshake message. Paces T8.
    pub(crate) last_recv_any_ns: AtomicU64,
    /// T6 (passive keepalive) ARMED timer — Linux pending-timer model:
    /// SET only when currently 0 (CAS) on an authenticated,
    /// replay-accepted, NON-EMPTY transport plaintext; CLEARED by any
    /// authenticated send; fires at `armed + KEEPALIVE_TIMEOUT`. A
    /// received keepalive does NOT arm it (no keepalive ping-pong).
    pub(crate) t6_armed_recv_ns: AtomicU64,
    /// T7 (no-reply reinit) ARMED timer: SET only when currently 0 on
    /// a successful NON-EMPTY data encap; CLEARED by any authenticated
    /// receive and by handshake-attempt start; fires at
    /// `armed + NO_REPLY_REINIT_NS`. An armed-not-latest stamp is
    /// load-bearing: a latest-send stamp would be refreshed by every
    /// outbound packet and never accrue 15s under continuous
    /// outbound-only traffic (Codex r3 F1).
    pub(crate) t7_armed_send_ns: AtomicU64,
    /// T8 skip/fail pacing anchor: advanced whenever the control loop
    /// ACTS on a T8 due-tick (send attempt, initiate, or skip), so a
    /// peer with no endpoint cannot leave a past-due deadline spinning
    /// the poll loop (AGY r3 G1).
    pub(crate) t8_last_attempt_ns: AtomicU64,
    /// The current transport session, if a handshake has completed.
    /// RwLock because rekey is a slow-path replacement and the hot
    /// path only takes a read guard to encrypt/decrypt.
    pub(crate) current: RwLock<Option<Arc<WgSession>>>,
    /// The previous transport session, retained across rekey so
    /// in-flight ciphertexts decrypt successfully. Same lock
    /// discipline as `current`.
    pub(crate) previous: RwLock<Option<Arc<WgSession>>>,
    /// The pending (unconfirmed) responder keypair (#3882). Populated
    /// when xpf responds to a peer-initiated (re)key; egress NEVER
    /// reads this slot. Promoted to `current` by `promote_next` on the
    /// first authenticated inbound data record. Same lock discipline as
    /// `current`. Its session is registered in the engine demux map so
    /// that first inbound record can be decrypted and trigger the
    /// promotion.
    pub(crate) next: RwLock<Option<Arc<WgSession>>>,
    /// #4092 responder handshake anti-replay: the greatest TAI64N
    /// timestamp this peer has presented in an accepted type-1
    /// initiation. A received initiation whose recovered TAI64N is
    /// `<=` this value is a replay (or a reorder) and MUST be rejected
    /// — the WireGuard handshake anti-replay rule (whitepaper §5.1;
    /// kernel `wg_noise_handshake_consume_initiation`'s
    /// `memcmp(timestamp, last_timestamp) > 0` gate; wireguard-go's
    /// `t.After(handshake.lastTimestamp)`). TAI64N is big-endian, so a
    /// lexicographic `[u8; 12]` comparison equals the numeric one.
    /// Initialised to all-zeros ("no initiation accepted"); a valid
    /// TAI64N always carries the `2^62` epoch base, so the first real
    /// initiation is strictly greater. Slow control-thread path only
    /// (never per-packet), so a `Mutex` is fine. Peer-resident, so it
    /// survives config commits (same pubkey → same `Arc<Peer>`); an
    /// engine rebuild on a crypto-identity change resets it — the
    /// WG-spec-permitted bounded reset (see `tai64n.rs` cross-restart
    /// note).
    pub(crate) greatest_tai64n: Mutex<[u8; TAI64N_LEN]>,
    /// #5164: worker→control "please initiate a handshake" edge, scoped
    /// PER PEER. When THIS peer's egress `try_encap` hits `NoSession`, the
    /// worker arms this via a single relaxed store, rate-limited by
    /// `handshake_request_last_ns` to one edge per
    /// `WG_HANDSHAKE_REQUEST_MIN_INTERVAL_NS`. The control thread's per-peer
    /// attempt machine consumes ONLY this peer's edge (via
    /// `WgEngine::take_handshake_request(peer_pubkey)`), so an edge raised by
    /// peer B is never drained by a lower-sorted peer A. Peer-resident
    /// (`Arc<Peer>` reused per pubkey), so it survives config commits like the
    /// timer stamps above. Was an engine-GLOBAL `AtomicBool` in S2a
    /// (single-peer); this is the #1434/S6 per-peer generalization.
    /// #8274 step 3: an endpoint a WORKER observed on an authenticated
    /// transport-data record, waiting for the control thread to adopt it.
    ///
    /// Moving type-4 decap into the worker takes the control thread's DOMINANT
    /// source of endpoint-learning signal off its socket: it learns a peer's
    /// endpoint from authenticated datagrams, and data records are most of
    /// them. Without this the learning degrades to handshake/keepalive cadence.
    ///
    /// What it does NOT affect, measured rather than assumed: transit ENCAP
    /// never read a learned endpoint. `peer_for_dest` returns
    /// `entry.config.endpoint` from the per-snapshot config bundle, and
    /// `reconcile_peers` — its only writer — has exactly one production caller,
    /// `WgEngine::new`. The learned map (`effective_endpoints`) is referenced
    /// only inside `coordinator/wg_control/mod.rs`. So what degrades without
    /// this slot is the control thread's OWN sends — keepalives, handshake
    /// initiations, the TUN-read egress — not the dataplane's forwarding.
    ///
    /// Shaped like `handshake_request_pending` beside it: per-peer,
    /// lossy-tolerable, drained by the control thread's existing
    /// per-peer timer pass. The SLOT is last-write-wins among the
    /// reports that reach it — a roam has exactly last-write-wins
    /// semantics, so coalescing is correct rather than merely
    /// acceptable — but the reporting CHANNEL is not: #9644 snapshot
    /// suppression may drop the latest observation (stale-observation
    /// contract on `RoamSnapshot` above: ancestor suppression,
    /// E1–E4), so end to end this mailbox is NOT last-write-wins
    /// linearizable. A `Mutex<Option<SocketAddr>>` and not an atomic
    /// because a `SocketAddr` does not fit one: the lock is taken
    /// only on a CHANGE (the worker compares against the lock-free
    /// snapshot first), so duplicates never take the lock.
    pub(crate) roamed_endpoint: std::sync::Mutex<Option<SocketAddr>>,
    /// Relaxed mirror of `roamed_endpoint.is_some()`, so the per-packet path
    /// can skip the mutex entirely once a roam is already pending and the
    /// control thread has not yet drained it.
    pub(crate) roamed_endpoint_pending: AtomicBool,
    /// #9644: lock-free last-observed-endpoint snapshot (advisory;
    /// authority stays in `roamed_endpoint`). Own cache line; read
    /// on every decapped packet, written only on change/drain.
    pub(crate) roam_snapshot: RoamSnapshot,
    pub(crate) handshake_request_pending: AtomicBool,
    /// #5164: monotonic timestamp of THIS peer's last accepted handshake
    /// request edge (0 = never). Drives the per-peer rate-limit gate only;
    /// distinct from `handshake_request_pending` so a request at `now_ns == 0`
    /// (tests) is not read as "no request".
    pub(crate) handshake_request_last_ns: AtomicU64,
    /// #5164: "session is stale, rekey" edge, scoped PER PEER. Armed by THIS
    /// peer's encap (T1 / send-side T3) and decap (T2 receive-horizon) use
    /// sites, consumed by the control loop's per-peer attempt machine (via
    /// `WgEngine::take_rekey_request(peer_pubkey)`) WITHOUT the
    /// confirmed-session gate. Was an engine-GLOBAL `AtomicBool` (S2a); this is
    /// the per-peer generalization so peer B's rekey drives B's attempt.
    pub(crate) rekey_request_pending: AtomicBool,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The operator-facing config (endpoint/keepalive/PSK) now lives
        // in the per-snapshot `PeerConfig`, not on `Peer`.
        f.debug_struct("Peer")
            .field("pubkey", &self.pubkey)
            .field("current", &self.current)
            .field("previous", &self.previous)
            .field("next", &self.next)
            .finish()
    }
}

impl Peer {
    pub(crate) fn new(pubkey: [u8; 32]) -> Self {
        Self {
            pubkey,
            last_send_any_ns: AtomicU64::new(0),
            last_recv_any_ns: AtomicU64::new(0),
            t6_armed_recv_ns: AtomicU64::new(0),
            t7_armed_send_ns: AtomicU64::new(0),
            t8_last_attempt_ns: AtomicU64::new(0),
            current: RwLock::new(None),
            previous: RwLock::new(None),
            next: RwLock::new(None),
            greatest_tai64n: Mutex::new([0u8; TAI64N_LEN]),
            roamed_endpoint: std::sync::Mutex::new(None),
            roamed_endpoint_pending: AtomicBool::new(false),
            roam_snapshot: RoamSnapshot::new(),
            handshake_request_pending: AtomicBool::new(false),
            handshake_request_last_ns: AtomicU64::new(0),
            rekey_request_pending: AtomicBool::new(false),
        }
    }

    /// #4092 responder handshake anti-replay check-and-update. Given the
    /// TAI64N recovered from a received type-1 initiation, accept it iff
    /// it is STRICTLY greater than the greatest already accepted from
    /// this peer, advancing the high-water on accept. Returns `true` =
    /// fresh (accept the initiation), `false` = replay/reorder (drop it).
    ///
    /// The check and the update are done under one lock so two concurrent
    /// initiations from the same peer cannot both pass with the same (or
    /// a stale) timestamp. Big-endian TAI64N ⇒ `[u8; 12]` lexicographic
    /// order equals numeric order.
    #[inline]
    pub(crate) fn check_and_update_tai64n(&self, ts: &[u8; TAI64N_LEN]) -> bool {
        let mut hw = self.greatest_tai64n.lock().unwrap_or_else(|e| e.into_inner());
        if *ts > *hw {
            *hw = *ts;
            true
        } else {
            false
        }
    }

    /// #4103: snapshot this peer's responder anti-replay high-water mark
    /// (`greatest_tai64n`) so a fresh engine built on an identity-changing
    /// config commit can carry it forward. This is the incoming-side
    /// mirror of the initiator clock's #1432 rebuild-survival seeding
    /// (`WgEngine::tai64n_high_water`): the outgoing clock is one
    /// engine-wide value, but the responder high-water is per-peer, so it
    /// must be snapshotted and re-seeded per pubkey. Slow control-thread
    /// path only.
    pub(crate) fn greatest_tai64n(&self) -> [u8; TAI64N_LEN] {
        *self.greatest_tai64n.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// #4103: seed this peer's responder anti-replay high-water from a
    /// prior engine's snapshot across an identity-change rebuild. Only
    /// advances the mark (never regresses it), mirroring
    /// `Tai64nClock::seed_high_water`, so a concurrent inbound initiation
    /// that already advanced the fresh peer cannot be pulled backwards by
    /// a stale seed. Slow path / build-time only.
    pub(crate) fn seed_greatest_tai64n(&self, hw: [u8; TAI64N_LEN]) {
        let mut cur = self.greatest_tai64n.lock().unwrap_or_else(|e| e.into_inner());
        if hw > *cur {
            *cur = hw;
        }
    }

    /// Record any authenticated packet SENT (transport data,
    /// keepalive, or handshake message). Clears the T6 passive-
    /// keepalive arm — we just proved liveness to the peer.
    #[inline]
    pub(crate) fn note_authenticated_send(&self, now_ns: u64) {
        self.last_send_any_ns.store(now_ns, Ordering::Relaxed);
        self.t6_armed_recv_ns.store(0, Ordering::Relaxed);
    }

    /// Record a NON-EMPTY transport data send: authenticated-send
    /// bookkeeping plus arm-if-unarmed of the T7 no-reply detector
    /// (CAS from 0 so subsequent sends cannot push the deadline —
    /// Linux pending-timer parity).
    #[inline]
    pub(crate) fn note_data_send(&self, now_ns: u64) {
        self.note_authenticated_send(now_ns);
        let _ = self.t7_armed_send_ns.compare_exchange(
            0,
            now_ns.max(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Record any authenticated packet RECEIVED (transport data,
    /// keepalive, or valid handshake message). Clears the T7 arm —
    /// the peer just proved it is alive.
    #[inline]
    pub(crate) fn note_authenticated_recv(&self, now_ns: u64) {
        self.last_recv_any_ns.store(now_ns, Ordering::Relaxed);
        self.t7_armed_send_ns.store(0, Ordering::Relaxed);
    }

    /// Record an authenticated, replay-accepted, NON-EMPTY transport
    /// plaintext: authenticated-recv bookkeeping plus arm-if-unarmed
    /// of the T6 passive-keepalive timer.
    #[inline]
    pub(crate) fn note_data_recv(&self, now_ns: u64) {
        self.note_authenticated_recv(now_ns);
        let _ = self.t6_armed_recv_ns.compare_exchange(
            0,
            now_ns.max(1),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// Install a freshly-completed transport session per the WG 3-slot
    /// keypair lifecycle (#3882, mirrors kernel `add_new_keypair`).
    /// Returns every session EVICTED from a slot so the caller can drop
    /// its demux entry.
    ///
    ///   - **Initiator role** — the handshake response already confirmed
    ///     this keypair, so it becomes `current` immediately: demote the
    ///     old current to `previous`, discard any pending (unconfirmed)
    ///     `next` (superseded by this confirmed keypair), and evict the
    ///     old previous.
    ///   - **Responder role** — the keypair is UNCONFIRMED (the initiator
    ///     has not proven it completed the handshake), so it is parked in
    ///     `next`; `current` keeps serving egress. Any stale pending
    ///     `next` is replaced (and evicted). `current`/`previous` are
    ///     left untouched so a peer-initiated rekey never blackholes the
    ///     xpf→peer direction.
    ///
    /// Each slot lock is taken and released independently (never nested),
    /// matching the rest of the module's discipline; the caller holds the
    /// engine `reconcile_lock` so no concurrent installer/promoter/expiry
    /// can interleave.
    pub(crate) fn install_new_session(&self, new: Arc<WgSession>) -> Vec<Arc<WgSession>> {
        let mut evicted: Vec<Arc<WgSession>> = Vec::new();
        if matches!(new.role, SessionRole::Initiator) {
            // A pending unconfirmed responder keypair is superseded by
            // this confirmed initiator keypair — drop it.
            if let Some(old_next) = self.next.write().unwrap_or_else(|e| e.into_inner()).take() {
                evicted.push(old_next);
            }
            let old_current = self.current.write().unwrap_or_else(|e| e.into_inner()).replace(new);
            if let Some(old_prev) = std::mem::replace(
                &mut *self.previous.write().unwrap_or_else(|e| e.into_inner()),
                old_current,
            ) {
                evicted.push(old_prev);
            }
        } else {
            // Responder: unconfirmed. Park in `next`; egress keeps using
            // the confirmed `current` until the first inbound data record
            // promotes it.
            if let Some(old_next) = self
                .next
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .replace(new)
            {
                evicted.push(old_next);
            }
        }
        evicted
    }

    /// Promote the pending `next` keypair to `current` (moving the old
    /// current to `previous`) IFF `next` is still `expected` (#3882 WG
    /// confirm-on-first-inbound-data). Returns the session evicted from
    /// `previous` (to drop from the demux map), or `None` if `next` no
    /// longer holds `expected` (a concurrent install/promote raced, or
    /// it was already promoted). Caller holds `reconcile_lock`.
    pub(crate) fn promote_next(&self, expected: &Arc<WgSession>) -> Option<Arc<WgSession>> {
        let promoted = {
            let mut next = self.next.write().unwrap_or_else(|e| e.into_inner());
            match next.as_ref() {
                Some(n) if Arc::ptr_eq(n, expected) => {}
                _ => return None,
            }
            next.take().expect("next is Some (matched above)")
        };
        let old_current = self.current.write().unwrap_or_else(|e| e.into_inner()).replace(promoted);
        std::mem::replace(
            &mut *self.previous.write().unwrap_or_else(|e| e.into_inner()),
            old_current,
        )
    }
}
