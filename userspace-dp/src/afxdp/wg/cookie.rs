//! WireGuard responder-side cookie-reply / MAC2 under-load DoS mitigation
//! (#4094 PR-A, WG whitepaper §5.4.7 / wireguard-go `device/cookie.go`).
//!
//! ## The attack this defends against
//!
//! MAC1 keys on the responder's *static public* key — which is not secret
//! and does not bind an initiation to its source address. A flood attacker
//! who knows our public key can forge valid-MAC1 initiations with spoofed
//! sources and force one Noise handshake (an X25519 DH + AEAD) per packet:
//! a CPU-exhaustion DoS. MAC2 is the anti-flood layer: when the responder
//! is under load it answers a valid-MAC1 initiation with a *cookie reply*
//! (type-3) instead of running the handshake. The cookie is a keyed MAC
//! over the initiator's REAL source address, so only a peer that actually
//! received the reply at that source can echo a valid MAC2 in its next
//! initiation. Spoofed sources never receive the reply, so their MAC2
//! never validates and the expensive handshake is never spent on them.
//!
//! #9908 closes the remaining valid-MAC2 admission gap: under load, a
//! per-source handshake token bucket runs after MAC2 verification but
//! before Noise, so a cookie holder cannot make the control thread pay
//! responder DH for an unbounded replay flood. Its state is independent
//! of the cookie-reply bucket and is bounded by the same source-table cap.
//!
//! ## Construction (§5.4.7)
//!
//! - `cookie = MAC(Rm, A_r)` where `MAC = keyed-BLAKE2s-128`, `Rm` is a
//!   random per-responder secret rotated every [`COOKIE_ROTATION_TIME_NS`],
//!   and `A_r` is the initiator's source IP + UDP port (the ACTUAL
//!   datagram source, never a claimed one).
//! - `mac2 = keyed-BLAKE2s-128(cookie, msg[0..offsetof(mac2)])`. The
//!   responder recomputes `cookie` from `Rm` + the current source and
//!   accepts the initiation only if the carried MAC2 matches. When NOT
//!   under load the responder keeps today's spec-correct skip-verify.
//! - The cookie reply carries `cookie` XChaCha20-Poly1305-encrypted under
//!   `key = BLAKE2s-256("cookie--" || responder_static_pub)`, with a
//!   random 24-byte nonce and the triggering initiation's MAC1 as AEAD
//!   associated data. This keeps the cookie opaque on the wire (only a
//!   holder of the responder's public key — i.e. a real configured peer —
//!   can decrypt it and derive a valid MAC2). Decrypting the reply is
//!   PR-B (the xpf-as-initiator interop half); this module is responder-
//!   only, plus a `#[cfg(test)]` decrypt mirror that doubles as the PR-B
//!   reference.
//!
//! ## Secret rotation window
//!
//! wireguard-go holds a single secret and re-challenges across a rotation
//! boundary; the #4094 plan keeps the PREVIOUS secret for one rotation
//! window so a cookie issued just before a rotation still validates its
//! MAC2 (avoids dropping a just-challenged peer that happened to straddle
//! the boundary). A gap of two or more full windows with no activity
//! starts fresh with no previous, bounding any secret's validity to under
//! `2 * COOKIE_ROTATION_TIME_NS`.
//!
//! ## Isolation
//!
//! Like the rest of `wg/`, this module stays free of the wider `afxdp`
//! type web (only `std` + the crypto crates). The load gate, secret
//! rotation, and reply budget are all `std::sync::Mutex`-guarded; the sole
//! caller is the per-tunnel control thread (`dispatch_inbound`), so the
//! locks are effectively uncontended — they exist for `&self` interior
//! mutability, not cross-thread contention. NEVER log a secret, a cookie,
//! or the encryption key.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

use blake2::Blake2s256;
use blake2::Blake2sMac;
use blake2::digest::consts::U16;
use blake2::digest::{Digest, FixedOutput, KeyInit, Update};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{Key, KeyInit as AeadKeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use super::{WG_KEY_LEN, WG_LABEL_COOKIE, WG_MAC_LEN, WG_MSG_INIT_LEN, WG_TYPE_COOKIE};

/// Responder cookie secret (`Rm`) rotation period. Mirrors wireguard-go
/// `CookieRefreshTime` / kernel `COOKIE_SECRET_MAX_AGE` (2 minutes).
pub(crate) const COOKIE_ROTATION_TIME_NS: u64 = 120 * 1_000_000_000;

/// Fixed-window width for the inbound-initiation rate gate.
const UNDER_LOAD_WINDOW_NS: u64 = 1_000_000_000;

/// Once the initiation rate trips the threshold, stay "under load" for
/// this grace period even if the rate falls back — mirrors wireguard-go's
/// `UnderLoadAfterTime` (1 s). Prevents flapping in and out of the cookie
/// path at the threshold boundary.
const UNDER_LOAD_GRACE_NS: u64 = 1_000_000_000;

/// Inbound type-1 initiations per [`UNDER_LOAD_WINDOW_NS`] window above
/// which the responder declares itself "under load" and starts issuing
/// cookie challenges. wireguard-go's analog is a handshake-queue depth of
/// `QueueHandshakeSize/8 == 128`; we process initiations inline (no
/// queue), so a per-second arrival rate is the natural equivalent. 25/s
/// to a single tunnel is far above any legitimate rekey pattern (WG rekeys
/// every ~2 min per peer) yet well below a flood — a conservative floor.
/// Tripping it only adds one cookie round-trip to an honest peer's
/// handshake (self-healing), so a false positive degrades latency, never
/// connectivity. Tunable named constant, not a magic number.
pub(crate) const INITIATIONS_UNDER_LOAD_THRESHOLD: u64 = 25;

/// Cap on cookie replies *emitted* per [`UNDER_LOAD_WINDOW_NS`] window.
/// A valid-MAC1 flood (attacker knows our public key) would otherwise draw
/// one 64-byte reply per initiation; the reply is far cheaper than a
/// handshake (one keyed-BLAKE2s + one XChaCha of 16 bytes) and is
/// de-amplifying (64 B out per 148 B in), but this budget still bounds the
/// CPU/socket cost of the generated-reply burst so it cannot itself become
/// a sink — the WG analog of the syn-cookie reply-budget discipline
/// (#4094 plan item 6). Over budget → the initiation is dropped WITHOUT a
/// reply (`hs_cookie_reply_budget_drops`); an honest peer retries and is
/// challenged in the next window. WG cookie replies leave via the tunnel's
/// UDP socket (not the AF_XDP TX ring), so this bounds CPU/socket load
/// rather than TX-ring descriptors.
pub(crate) const COOKIE_REPLY_BUDGET_PER_WINDOW: u64 = 40;

/// #4332 per-SOURCE cookie-reply token bucket. The [`COOKIE_REPLY_BUDGET_PER_WINDOW`]
/// cap above is GLOBAL per tunnel, so a determined valid-MAC1 flood from ONE
/// source can drain the shared budget and budget-suppress a legit peer's first
/// cookie challenge from a DIFFERENT source. These constants mirror
/// wireguard-go `device/ratelimiter.go` (`packetsPerSecond` /
/// `packetsBurstable` / `packetCost` / `maxTokens` / `garbageCollectTime`) so a
/// flood from one source throttles only itself. Sustained rate and burst:
pub(crate) const SOURCE_REPLIES_PER_SEC: u64 = 20;
/// Burst depth: how many replies a fresh source may draw back-to-back before
/// the sustained [`SOURCE_REPLIES_PER_SEC`] rate applies.
pub(crate) const SOURCE_REPLY_BURST: u64 = 5;
/// #9908 per-SOURCE handshake-admission token bucket. It deliberately uses
/// the same 20/s sustained rate and 5-packet burst as the #4332 cookie-
/// reply bucket: a legitimate source can complete a fresh handshake plus a
/// quick retransmit, while a valid-MAC2 replay flood reaches Noise at most
/// five times before the frozen-clock bucket fails closed.
pub(crate) const SOURCE_HANDSHAKES_PER_SEC: u64 = SOURCE_REPLIES_PER_SEC;
pub(crate) const SOURCE_HANDSHAKE_BURST: u64 = SOURCE_REPLY_BURST;
const HANDSHAKE_PACKET_COST_NS: u64 = 1_000_000_000 / SOURCE_HANDSHAKES_PER_SEC;
const HANDSHAKE_MAX_TOKENS_NS: i64 =
    (HANDSHAKE_PACKET_COST_NS * SOURCE_HANDSHAKE_BURST) as i64;
/// Token cost of one reply, in nanoseconds of accrued time
/// (`1e9 / SOURCE_REPLIES_PER_SEC` = 50 ms). One second of idle accrues exactly
/// `SOURCE_REPLIES_PER_SEC` tokens.
pub(crate) const PACKET_COST_NS: u64 = 1_000_000_000 / SOURCE_REPLIES_PER_SEC;
/// Token ceiling: a bucket never accrues more than one burst's worth of tokens
/// (`PACKET_COST_NS * SOURCE_REPLY_BURST` = 250 ms). Signed to make the
/// refill/spend arithmetic and the monotonic-clock guard total.
pub(crate) const MAX_TOKENS_NS: i64 = (PACKET_COST_NS * SOURCE_REPLY_BURST) as i64;
/// Run the per-source table GC at most this often (mirrors wireguard-go
/// `garbageCollectTime`, 1 s); a bucket idle for a full interval is dropped.
const SOURCE_GC_INTERVAL_NS: u64 = 1_000_000_000;
/// Hard cap on distinct source IPs tracked at once. Bounds the map against a
/// SPOOFED-source-IP flood (the memory-amplification vector this hardening must
/// not itself introduce): a NEW source that would overflow the cap is DENIED
/// (fail closed), never inserted. Idle buckets are GC-reclaimed, so the cap
/// only bites during an active flood of > `SOURCE_TABLE_MAX` live sources.
const SOURCE_TABLE_MAX: usize = 2048;

/// Cookie MAC length (keyed-BLAKE2s-128 output).
pub(crate) const WG_COOKIE_LEN: usize = 16;

/// XChaCha20-Poly1305 nonce length carried in the cookie reply.
pub(crate) const WG_COOKIE_NONCE_LEN: usize = 24;

/// WG type-3 CookieReply wire length:
///   type(1) + reserved(3) + receiver_index(4) + nonce(24)
///   + encrypted_cookie(16 + 16 tag) = 64.
pub(crate) const WG_MSG_COOKIE_LEN: usize = 1 + 3 + 4 + WG_COOKIE_NONCE_LEN + WG_COOKIE_LEN + 16;

// Type-3 field offsets.
const M3_RECEIVER: usize = 4;
const M3_NONCE: usize = 8;
const M3_COOKIE: usize = M3_NONCE + WG_COOKIE_NONCE_LEN; // 32
const _: () = assert!(M3_COOKIE + WG_COOKIE_LEN + 16 == WG_MSG_COOKIE_LEN);

// MAC2 lives at msg[132..148]; the MAC covers msg[0..132] (through MAC1).
const M1_MAC2: usize = WG_MSG_INIT_LEN - WG_MAC_LEN; // 132
const M1_MAC1: usize = M1_MAC2 - WG_MAC_LEN; // 116

/// Cookie-reply build failures. All non-fatal at the call site (the init
/// is simply dropped without a reply).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CookieError {
    /// Output buffer smaller than [`WG_MSG_COOKIE_LEN`].
    OutputTooSmall,
    /// The triggering initiation was not exactly [`WG_MSG_INIT_LEN`].
    WrongInitLength,
    /// XChaCha20-Poly1305 sealing failed (structurally impossible for a
    /// 16-byte plaintext; folded rather than panicked).
    Crypto,
    /// The OS CSPRNG (`getrandom`) failed, so no secure cookie secret or
    /// nonce is available (#4094 BUG-2). The caller MUST fail closed — drop
    /// the initiation with NO reply rather than ship a predictable secret /
    /// nonce. Never returned on Linux (getrandom does not fail there);
    /// defense-in-depth.
    RandUnavailable,
}

/// Keyed-BLAKE2s with 16-byte output — the WG `MAC()` primitive. `key` may
/// be up to 32 bytes (BLAKE2s keyed-hash bound); the cookie secret is 32,
/// the cookie itself is 16. NOT HMAC.
fn keyed_blake2s_128(key: &[u8], data: &[u8]) -> [u8; WG_COOKIE_LEN] {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key)
        .expect("BLAKE2s keyed-hash key length <= 32");
    Update::update(&mut mac, data);
    let mut out = [0u8; WG_COOKIE_LEN];
    FixedOutput::finalize_into(mac, (&mut out).into());
    out
}

/// The cookie-reply AEAD key: `BLAKE2s-256("cookie--" || responder_pub)`.
fn cookie_encryption_key(our_static_pub: &[u8; WG_KEY_LEN]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    Digest::update(&mut h, WG_LABEL_COOKIE);
    Digest::update(&mut h, our_static_pub);
    h.finalize().into()
}

/// Serialize a datagram source into the bytes the cookie MAC covers:
/// canonical IP octets (4 for v4, 16 for v6) followed by the 2-byte
/// big-endian UDP port. Returns a fixed 18-byte buffer plus the used
/// length. This binding is an internal responder detail — the cookie is
/// opaque to the initiator (which only echoes it via MAC2), so the format
/// need only be self-consistent between [`build_cookie_reply`] and
/// [`verify_initiation_mac2`]. A v4-mapped v6 source is canonicalized to
/// v4 first so a peer seen once as `a.b.c.d` and once as `::ffff:a.b.c.d`
/// gets the same cookie.
fn endpoint_cookie_bytes(addr: SocketAddr) -> ([u8; 18], usize) {
    let mut buf = [0u8; 18];
    let n = match super::canonicalize_endpoint(addr) {
        SocketAddr::V4(v4) => {
            buf[0..4].copy_from_slice(&v4.ip().octets());
            buf[4..6].copy_from_slice(&v4.port().to_be_bytes());
            6
        }
        SocketAddr::V6(v6) => {
            buf[0..16].copy_from_slice(&v6.ip().octets());
            buf[16..18].copy_from_slice(&v6.port().to_be_bytes());
            18
        }
    };
    (buf, n)
}

/// Constant-time-ish 16-byte MAC comparison (fold, no short-circuit).
#[inline]
fn macs_equal(a: &[u8; WG_COOKIE_LEN], b: &[u8]) -> bool {
    if b.len() != WG_COOKIE_LEN {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..WG_COOKIE_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Two-slot responder secret with lazy first-use init and a one-window
/// carry of the previous secret.
struct SecretState {
    current: Zeroizing<[u8; 32]>,
    previous: Zeroizing<[u8; 32]>,
    has_previous: bool,
    /// Monotonic ns the `current` secret was generated. `None` = not yet
    /// stamped (lazy: the first observer stamps it without rotating, so a
    /// large monotonic clock does not force an immediate rotation).
    /// Tracked as `Option`, NOT a 0 sentinel: a legitimate `now_ns == 0`
    /// (very early CLOCK_MONOTONIC, or a failed clock read) is a valid
    /// window start, not "uninitialized" (#4094 Copilot BUG-1).
    generated_at_ns: Option<u64>,
    /// True iff `current` was filled from the OS CSPRNG. FALSE means
    /// `getrandom` failed and we hold NO usable secret — the cookie
    /// mechanism fails CLOSED (`with_secrets()` returns `None`, under-load
    /// initiations are dropped) rather than ever using a predictable
    /// secret an attacker could reproduce (#4094 Copilot BUG-2). Never
    /// false on Linux (getrandom does not fail); defense-in-depth.
    secure: bool,
}

/// Fixed-window inbound-initiation rate gate plus a sticky under-load
/// grace window. `window_start_ns` is an `Option`, NOT a 0 sentinel: a
/// legitimate `now_ns == 0` must count as a real window start or the gate
/// would reset every call and NEVER trip — disabling the mitigation
/// exactly when needed (#4094 Copilot BUG-1).
struct LoadState {
    window_start_ns: Option<u64>,
    count: u64,
    under_load_until_ns: u64,
}

/// Fixed-window cookie-reply emission budget. `window_start_ns` is an
/// `Option` for the same #4094 BUG-1 reason as [`LoadState`].
struct BudgetState {
    window_start_ns: Option<u64>,
    emitted: u64,
}

/// #4332 per-source token bucket. `last_ns` is a MONOTONIC high-water mark of
/// the last refill (never lowered by a backwards clock step — #4330/#4321),
/// `tokens_ns` the accrued-time credit (signed, capped at [`MAX_TOKENS_NS`]).
struct SourceBucket {
    last_ns: u64,
    tokens_ns: i64,
}

/// #4332 per-source cookie-reply buckets plus #9908 per-source
/// handshake-admission buckets. Both are bounded and share one GC lock.
/// Each map has its own token state so valid-MAC2 admissions never consume
/// cookie-reply budget, and vice versa.
struct SourceTable {
    buckets: HashMap<IpAddr, SourceBucket>,
    handshake_buckets: HashMap<IpAddr, SourceBucket>,
    last_gc_ns: Option<u64>,
}

/// Responder cookie checker: secret rotation + load detection + reply
/// budget + MAC2 verification, all keyed to one tunnel's responder static
/// key. One per [`super::WgEngine`].
pub(crate) struct CookieChecker {
    /// `BLAKE2s-256("cookie--" || our_pub)`. Public-key-derived, not
    /// secret, but never logged for hygiene.
    enc_key: [u8; 32],
    secret: Mutex<SecretState>,
    load: Mutex<LoadState>,
    budget: Mutex<BudgetState>,
    /// #4332 per-source cookie-reply token buckets, layered BEFORE the global
    /// `budget` so one flooding source cannot drain the shared per-window cap
    /// away from a legit peer at a different source.
    per_source: Mutex<SourceTable>,
    /// Test hook: when true, [`Self::draw_random`] simulates a `getrandom`
    /// failure so the #4094 BUG-2 fail-closed path is exercisable without
    /// mocking the OS CSPRNG. Compiled out of release builds.
    #[cfg(test)]
    rng_fail: std::sync::atomic::AtomicBool,
}

impl CookieChecker {
    pub(crate) fn new(our_static_pub: &[u8; WG_KEY_LEN]) -> Self {
        let mut current = [0u8; 32];
        // FAIL CLOSED on a getrandom failure — never seed the cookie secret
        // from a predictable source (#4094 Copilot BUG-2). `secure == false`
        // disables the mechanism (`with_secrets()` returns None → under-load
        // initiations drop) until secure randomness becomes available.
        let secure = fill_random(&mut current);
        if !secure {
            // One-time, only on a broken OS CSPRNG (never on Linux). The
            // whole system is in a catastrophic state (snow's ephemeral
            // keys need the same RNG); surface it loudly.
            eprintln!(
                "xpf-wg: SECURITY: getrandom failed generating the WireGuard \
                 cookie secret; the under-load cookie DoS mitigation is \
                 fail-closed (under-load initiations will be DROPPED) until \
                 secure randomness is available — the OS CSPRNG is broken"
            );
        }
        Self {
            enc_key: cookie_encryption_key(our_static_pub),
            secret: Mutex::new(SecretState {
                current: Zeroizing::new(current),
                previous: Zeroizing::new([0u8; 32]),
                has_previous: false,
                generated_at_ns: None,
                secure,
            }),
            load: Mutex::new(LoadState {
                window_start_ns: None,
                count: 0,
                under_load_until_ns: 0,
            }),
            budget: Mutex::new(BudgetState {
                window_start_ns: None,
                emitted: 0,
            }),
            per_source: Mutex::new(SourceTable {
                buckets: HashMap::new(),
                handshake_buckets: HashMap::new(),
                last_gc_ns: None,
            }),
            #[cfg(test)]
            rng_fail: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Draw secure random bytes. The single choke point through which the
    /// secret rotation and the cookie-reply nonce acquire randomness, so a
    /// getrandom failure is handled identically (fail closed) at every
    /// site. In tests `rng_fail` can force a simulated failure.
    fn draw_random(&self, buf: &mut [u8]) -> bool {
        #[cfg(test)]
        if self.rng_fail.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        fill_random(buf)
    }

    /// Record one inbound initiation arrival at `now_ns` and return whether
    /// the responder is currently under load. Fixed-window count with a
    /// sticky grace: crossing the threshold arms the under-load state for
    /// [`UNDER_LOAD_GRACE_NS`].
    pub(crate) fn note_initiation(&self, now_ns: u64) -> bool {
        let mut s = self.load.lock().unwrap_or_else(|e| e.into_inner());
        let new_window = match s.window_start_ns {
            None => true,
            Some(start) => now_ns.saturating_sub(start) >= UNDER_LOAD_WINDOW_NS,
        };
        if new_window {
            s.window_start_ns = Some(now_ns);
            s.count = 1;
        } else {
            s.count = s.count.saturating_add(1);
        }
        if s.count > INITIATIONS_UNDER_LOAD_THRESHOLD {
            s.under_load_until_ns = now_ns.saturating_add(UNDER_LOAD_GRACE_NS);
        }
        now_ns < s.under_load_until_ns
    }

    /// True iff a cookie reply may still be emitted in the current window
    /// (and reserves one slot). Fixed-window budget mirroring the load gate.
    pub(crate) fn reply_budget_available(&self, now_ns: u64) -> bool {
        let mut b = self.budget.lock().unwrap_or_else(|e| e.into_inner());
        let new_window = match b.window_start_ns {
            None => true,
            Some(start) => now_ns.saturating_sub(start) >= UNDER_LOAD_WINDOW_NS,
        };
        if new_window {
            b.window_start_ns = Some(now_ns);
            b.emitted = 0;
        }
        if b.emitted >= COOKIE_REPLY_BUDGET_PER_WINDOW {
            return false;
        }
        b.emitted += 1;
        true
    }

    /// #4332: per-SOURCE cookie-reply admission. A small token bucket keyed by
    /// the initiation's source IP (mirrors wireguard-go `device/ratelimiter.go`)
    /// that admits at most [`SOURCE_REPLIES_PER_SEC`] replies/s per source with a
    /// [`SOURCE_REPLY_BURST`] burst. Layered BEFORE the GLOBAL per-window
    /// [`Self::reply_budget_available`] in the cookie-reply path (BOTH must
    /// pass), so a flood from ONE source throttles only its OWN bucket and
    /// cannot drain the shared budget away from a legit peer at a DIFFERENT
    /// source (the isolation #4332 adds over #4330's global-only cap).
    ///
    /// Fail CLOSED against the amplification vector this very hardening could
    /// introduce: the table is GC-swept every [`SOURCE_GC_INTERVAL_NS`] (idle
    /// buckets dropped) and hard-capped at [`SOURCE_TABLE_MAX`] — a NEW source
    /// that would overflow the cap is DENIED (no reply) rather than growing the
    /// map without bound under a spoofed-source-IP flood.
    ///
    /// Monotonic-clock discipline mirrors #4330/#4321: elapsed is
    /// `saturating_sub` (a backwards `now_ns` credits nothing) and `last_ns` is
    /// a high-water mark (`.max(now_ns)`, never lowered), so a clock glitch
    /// cannot be replayed into an over-credit to the ceiling on the next forward
    /// step — the exact weakening that guard prevents.
    pub(crate) fn source_reply_allowed(&self, src_ip: IpAddr, now_ns: u64) -> bool {
        let mut t = self.per_source.lock().unwrap_or_else(|e| e.into_inner());

        // Periodic GC — at most once per interval — drops buckets idle for a
        // full GC interval, so a transient spoofed-IP burst does not keep the
        // table full once it stops. Runs BEFORE the cap check so reclaimed
        // slots are available to a legit new source in the same call.
        let gc_due = match t.last_gc_ns {
            None => true,
            Some(last) => now_ns.saturating_sub(last) >= SOURCE_GC_INTERVAL_NS,
        };
        if gc_due {
            t.last_gc_ns = Some(now_ns);
            t.buckets.retain(|_, b| now_ns.saturating_sub(b.last_ns) < SOURCE_GC_INTERVAL_NS);
            t.handshake_buckets
                .retain(|_, b| now_ns.saturating_sub(b.last_ns) < SOURCE_GC_INTERVAL_NS);
        }

        // Table cap: a NEW source that would overflow the bound is denied
        // WITHOUT inserting — fail closed against a spoofed-source-IP flood.
        // An already-tracked source is never refused here (it is one of the
        // bounded set and gets its normal token check below).
        if !t.buckets.contains_key(&src_ip) && t.buckets.len() >= SOURCE_TABLE_MAX {
            return false;
        }

        // A fresh bucket starts full (one whole burst of credit) so a legit
        // source's first challenge is never throttled by table churn.
        let bucket = t.buckets.entry(src_ip).or_insert(SourceBucket {
            last_ns: now_ns,
            tokens_ns: MAX_TOKENS_NS,
        });
        // Refill by elapsed time (never negative — saturating_sub), cap at the
        // burst ceiling; keep last_ns a monotonic high-water mark.
        let elapsed = now_ns.saturating_sub(bucket.last_ns) as i64;
        bucket.last_ns = bucket.last_ns.max(now_ns);
        bucket.tokens_ns = (bucket.tokens_ns + elapsed).min(MAX_TOKENS_NS);
        let cost = PACKET_COST_NS as i64;
        if bucket.tokens_ns >= cost {
            bucket.tokens_ns -= cost;
            true
        } else {
            false
        }
    }

    /// #9908 per-source handshake-admission gate. Called only after a
    /// valid MAC1 + MAC2 has been verified and before the responder enters
    /// Noise. The bucket is independent of #4332's reply bucket: valid
    /// MAC2 admissions never spend cookie-reply tokens. A new source is
    /// denied when the bounded table is full (fail closed); a tracked source
    /// receives a 5-packet burst and refills at 20/s.
    pub(crate) fn source_handshake_allowed(&self, src_ip: IpAddr, now_ns: u64) -> bool {
        let mut t = self.per_source.lock().unwrap_or_else(|e| e.into_inner());

        // Keep both per-source maps bounded and reclaim idle entries before
        // rejecting a new source. The one GC clock covers both maps under
        // the same mutex, so the table cannot be observed half-swept.
        let gc_due = match t.last_gc_ns {
            None => true,
            Some(last) => now_ns.saturating_sub(last) >= SOURCE_GC_INTERVAL_NS,
        };
        if gc_due {
            t.last_gc_ns = Some(now_ns);
            t.buckets
                .retain(|_, b| now_ns.saturating_sub(b.last_ns) < SOURCE_GC_INTERVAL_NS);
            t.handshake_buckets
                .retain(|_, b| now_ns.saturating_sub(b.last_ns) < SOURCE_GC_INTERVAL_NS);
        }

        // A NEW source that would exceed the bounded table is denied without
        // insertion. Existing sources are never denied at this structural
        // cap; they receive their normal token check below.
        if !t.handshake_buckets.contains_key(&src_ip)
            && t.handshake_buckets.len() >= SOURCE_TABLE_MAX
        {
            return false;
        }

        let bucket = t
            .handshake_buckets
            .entry(src_ip)
            .or_insert(SourceBucket {
                last_ns: now_ns,
                tokens_ns: HANDSHAKE_MAX_TOKENS_NS,
            });
        let elapsed = now_ns.saturating_sub(bucket.last_ns) as i64;
        bucket.last_ns = bucket.last_ns.max(now_ns);
        bucket.tokens_ns = (bucket.tokens_ns + elapsed).min(HANDSHAKE_MAX_TOKENS_NS);
        let cost = HANDSHAKE_PACKET_COST_NS as i64;
        if bucket.tokens_ns >= cost {
            bucket.tokens_ns -= cost;
            true
        } else {
            false
        }
    }

    /// Rotate the secret if due, then run `f` with the live secrets held
    /// under the lock. #9918 F-145: the responder cookie secrets never leave
    /// this lock as bare `[u8; 32]` copies — callers receive only derived
    /// values (cookies, MAC comparisons) computed inside the closure. The
    /// `Zeroizing` refs cannot outlive the guard (`R: owned` by construction
    /// — the closure returns cookies/bools, never secret refs).
    ///
    /// Lazy first-use init stamps `generated_at_ns` without rotating. A gap
    /// of two or more full windows starts fresh with no previous (bounds any
    /// secret's validity to `< 2 * COOKIE_ROTATION_TIME_NS`).
    ///
    /// Returns `None` when NO secure secret is available (#4094 BUG-2 fail-
    /// closed): a getrandom failure at construction leaves `secure == false`
    /// and this NEVER substitutes a predictable secret — it retries the OS
    /// CSPRNG (lazy recovery) and, if that still fails, returns `None` so
    /// the caller (verify/build) fails closed. Every rotation likewise
    /// keeps the existing secure secret rather than rotating to a
    /// predictable one if getrandom fails mid-flight.
    ///
    /// Lock scope: held across rotation + the closure's hashes (2-4
    /// keyed-BLAKE2s for verify, 1 for build's cookie). The hashes and
    /// `draw_random` take no locks, and classify/build run on the single
    /// control thread (locks effectively uncontended — see module doc), so
    /// this cannot deadlock. The XChaCha seal in `build_cookie_reply` runs
    /// OUTSIDE this lock (it needs only the derived cookie).
    /// Poison recovery mirrors the pre-9918 `secrets()`: `into_inner`, so a
    /// prior panic cannot permanently disable MAC2 (#6422).
    fn with_secrets<R>(
        &self,
        now_ns: u64,
        f: impl FnOnce(&Zeroizing<[u8; 32]>, Option<&Zeroizing<[u8; 32]>>) -> R,
    ) -> Option<R> {
        let mut s = self.secret.lock().unwrap_or_else(|e| e.into_inner());
        if !s.secure {
            // Lazy re-acquire — getrandom may have been transiently
            // unavailable at construction. NEVER seed from a weak source.
            let mut fresh = [0u8; 32];
            if self.draw_random(&mut fresh) {
                *s.current = fresh;
                *s.previous = [0u8; 32];
                s.has_previous = false;
                s.generated_at_ns = Some(now_ns);
                s.secure = true;
            } else {
                return None; // fail closed: still no secure secret
            }
        } else {
            match s.generated_at_ns {
                None => s.generated_at_ns = Some(now_ns),
                Some(gen_at) => {
                    let gap = now_ns.saturating_sub(gen_at);
                    if gap >= 2 * COOKIE_ROTATION_TIME_NS {
                        // Both slots would be stale; discard the previous —
                        // but only if we can draw a fresh SECURE secret.
                        let mut fresh = [0u8; 32];
                        if self.draw_random(&mut fresh) {
                            *s.current = fresh;
                            *s.previous = [0u8; 32];
                            s.has_previous = false;
                            s.generated_at_ns = Some(now_ns);
                        }
                        // else: keep the existing secure secret, skip the
                        // rotation this call (retried next call).
                    } else if gap >= COOKIE_ROTATION_TIME_NS {
                        let mut fresh = [0u8; 32];
                        if self.draw_random(&mut fresh) {
                            *s.previous = *s.current;
                            *s.current = fresh;
                            s.has_previous = true;
                            s.generated_at_ns = Some(now_ns);
                        }
                        // else: keep current secure secret, skip rotation.
                    }
                }
            }
        }
        let prev: Option<&Zeroizing<[u8; 32]>> = if s.has_previous {
            Some(&s.previous)
        } else {
            None
        };
        Some(f(&s.current, prev))
    }

    /// Verify the MAC2 carried in an inbound type-1 initiation `msg`
    /// against the cookie the responder would have issued to this exact
    /// datagram source (`from`), under the current secret and — within the
    /// carry window — the previous one. Returns false for a wrong-length
    /// message or a zero/absent MAC2 (the cookie is non-zero). Slow path.
    pub(crate) fn verify_initiation_mac2(&self, msg: &[u8], from: SocketAddr, now_ns: u64) -> bool {
        if msg.len() != WG_MSG_INIT_LEN {
            return false;
        }
        let got = &msg[M1_MAC2..WG_MSG_INIT_LEN];
        let (src, n) = endpoint_cookie_bytes(from);
        let src = &src[..n];
        // Fail closed if no secure secret (#4094 BUG-2): without it we
        // cannot recompute the cookie, so we cannot honestly validate MAC2.
        // #9918 F-145: the secrets never leave the lock — the cookie/MAC
        // recomputation runs inside `with_secrets`.
        self.with_secrets(now_ns, |cur, prev| {
            let cookie_cur = keyed_blake2s_128(&cur[..], src);
            let expect_cur = keyed_blake2s_128(&cookie_cur, &msg[..M1_MAC2]);
            if macs_equal(&expect_cur, got) {
                return true;
            }
            if let Some(prev) = prev {
                let cookie_prev = keyed_blake2s_128(&prev[..], src);
                let expect_prev = keyed_blake2s_128(&cookie_prev, &msg[..M1_MAC2]);
                if macs_equal(&expect_prev, got) {
                    return true;
                }
            }
            false
        })
        .unwrap_or(false)
    }

    /// Build a WG type-3 CookieReply for the initiation `init_msg` that
    /// arrived from `from`, writing it at `out[0..WG_MSG_COOKIE_LEN]`. The
    /// cookie binds to `from` (the ACTUAL datagram source); it is sealed
    /// under XChaCha20-Poly1305 with a fresh random nonce and the
    /// initiation's MAC1 as AEAD associated data. Echoes the initiator's
    /// sender_index as the reply's receiver_index. Slow path.
    pub(crate) fn build_cookie_reply(
        &self,
        init_msg: &[u8],
        from: SocketAddr,
        now_ns: u64,
        out: &mut [u8],
    ) -> Result<usize, CookieError> {
        if out.len() < WG_MSG_COOKIE_LEN {
            return Err(CookieError::OutputTooSmall);
        }
        if init_msg.len() != WG_MSG_INIT_LEN {
            return Err(CookieError::WrongInitLength);
        }
        let (src, n) = endpoint_cookie_bytes(from);
        // Fail closed on a broken CSPRNG (#4094 BUG-2): no secure secret ->
        // no cookie (a predictable cookie would let a spoofed source forge a
        // valid MAC2 and defeat the whole mitigation). #9918 F-145: derive
        // the cookie inside the lock; the XChaCha seal below runs outside
        // (it needs only the derived cookie, never the secret).
        let cookie = self
            .with_secrets(now_ns, |cur, _prev| keyed_blake2s_128(&cur[..], &src[..n]))
            .ok_or(CookieError::RandUnavailable)?;

        // A predictable XChaCha nonce is also unacceptable — fail closed
        // rather than send a weak-nonce reply.
        let mut nonce = [0u8; WG_COOKIE_NONCE_LEN];
        if !self.draw_random(&mut nonce) {
            return Err(CookieError::RandUnavailable);
        }

        // AEAD associated data = the triggering initiation's MAC1.
        let aad = &init_msg[M1_MAC1..M1_MAC2];
        let mut sealed = cookie; // 16-byte plaintext, encrypted in place.
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&self.enc_key));
        let tag = cipher
            .encrypt_in_place_detached(XNonce::from_slice(&nonce), aad, &mut sealed)
            .map_err(|_| CookieError::Crypto)?;

        let msg = &mut out[..WG_MSG_COOKIE_LEN];
        msg[0] = WG_TYPE_COOKIE;
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 0;
        // receiver_index echoes the initiator's sender_index (LE).
        msg[M3_RECEIVER..M3_RECEIVER + 4].copy_from_slice(&init_msg[4..8]);
        msg[M3_NONCE..M3_COOKIE].copy_from_slice(&nonce);
        msg[M3_COOKIE..M3_COOKIE + WG_COOKIE_LEN].copy_from_slice(&sealed);
        msg[M3_COOKIE + WG_COOKIE_LEN..WG_MSG_COOKIE_LEN].copy_from_slice(tag.as_slice());
        Ok(WG_MSG_COOKIE_LEN)
    }

    // --- initiator-side cookie-reply decrypt (#4094 PR-B) + test peek ---

    /// Decrypt a type-3 CookieReply as the xpf-as-initiator half (#4094
    /// PR-B): recover the 16-byte cookie with the RESPONDER's public-key-
    /// derived AEAD key (`BLAKE2s-256("cookie--" || responder_static_pub)`),
    /// the reply's carried nonce, and the AAD MAC1 of the initiation that
    /// triggered it. From the initiator's view `responder_static_pub` is the
    /// PEER's static public key (the responder we are handshaking toward);
    /// the responder-side round-trip test passes its own public key, which
    /// is the same value from its own perspective. Returns `None` on a
    /// malformed reply or an AEAD authentication failure (wrong key / wrong
    /// AAD / tampered ciphertext) — fail closed, no panic, cookie ignored.
    pub(crate) fn decrypt_cookie_reply(
        reply: &[u8],
        responder_static_pub: &[u8; WG_KEY_LEN],
        aad_mac1: &[u8],
    ) -> Option<[u8; WG_COOKIE_LEN]> {
        // #5191 (A1-b9-F5): full 32-bit little-endian type-word check, not a
        // low-byte compare — a CookieReply with nonzero reserved bytes is
        // rejected by kernel WG / wireguard-go, so accepting it here was a
        // parser differential. Length is verified first: is_canonical_type
        // indexes reply[0..4].
        if reply.len() != WG_MSG_COOKIE_LEN
            || !super::handshake::is_canonical_type(reply, WG_TYPE_COOKIE)
        {
            return None;
        }
        let key = cookie_encryption_key(responder_static_pub);
        let nonce = &reply[M3_NONCE..M3_COOKIE];
        let mut buf = [0u8; WG_COOKIE_LEN];
        buf.copy_from_slice(&reply[M3_COOKIE..M3_COOKIE + WG_COOKIE_LEN]);
        let tag = &reply[M3_COOKIE + WG_COOKIE_LEN..WG_MSG_COOKIE_LEN];
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        cipher
            .decrypt_in_place_detached(
                XNonce::from_slice(nonce),
                aad_mac1,
                &mut buf,
                chacha20poly1305::Tag::from_slice(tag),
            )
            .ok()?;
        Some(buf)
    }

    /// The cookie the responder would issue for `from` under the CURRENT
    /// secret at `now_ns` (rotating first if due). Test hook for the
    /// rotation-window vectors.
    #[cfg(test)]
    pub(crate) fn cookie_for_test(&self, from: SocketAddr, now_ns: u64) -> [u8; WG_COOKIE_LEN] {
        let (src, n) = endpoint_cookie_bytes(from);
        self.with_secrets(now_ns, |cur, _prev| keyed_blake2s_128(&cur[..], &src[..n]))
            .expect("test CookieChecker always has a secure secret")
    }

    /// Test hook: simulate a persistent `getrandom` failure (BUG-2 fail-
    /// closed path) without mocking the OS CSPRNG. Sets `rng_fail` so every
    /// `draw_random` fails AND drops the currently-held secret, so the
    /// checker cannot lazily recover a secure secret while the flag is set.
    #[cfg(test)]
    pub(crate) fn set_rng_fail_for_test(&self, fail: bool) {
        self.rng_fail
            .store(fail, std::sync::atomic::Ordering::Relaxed);
        if fail {
            let mut s = self.secret.lock().unwrap();
            s.secure = false;
            *s.current = [0u8; 32];
            *s.previous = [0u8; 32];
            s.has_previous = false;
            s.generated_at_ns = None;
        }
    }

    /// #4332 test hook: number of distinct source IPs currently tracked in the
    /// per-source reply-bucket table (asserts the [`SOURCE_TABLE_MAX`] bound and
    /// GC reclaim).
    #[cfg(test)]
    pub(crate) fn source_table_len_for_test(&self) -> usize {
        self.per_source.lock().unwrap().buckets.len()
    }

    /// #4332 test hook: whether a specific source IP has a live bucket.
    #[cfg(test)]
    pub(crate) fn source_contains_for_test(&self, ip: IpAddr) -> bool {
        self.per_source.lock().unwrap().buckets.contains_key(&ip)
    }

    /// #9908 test hook: number of distinct source IPs currently tracked in
    /// the per-source handshake-admission table.
    #[cfg(test)]
    pub(crate) fn handshake_source_table_len_for_test(&self) -> usize {
        self.per_source.lock().unwrap().handshake_buckets.len()
    }
}

/// Initiator-side per-peer cookie state (#4094 PR-B) — the counterpart to
/// the responder's [`CookieChecker`]. Mirrors wireguard-go
/// `CookieGenerator`'s `mac2` sub-struct: the last cookie we decrypted from
/// a responder's cookie-reply (used to stamp MAC2 on our RETRIED
/// handshake-initiations until it ages past [`COOKIE_ROTATION_TIME_NS`])
/// plus the MAC1 of our most recently sent initiation (the XChaCha20-
/// Poly1305 AAD needed to decrypt an incoming cookie-reply).
///
/// One per peer, held in the [`super::WgEngine`] under a mutex and consulted
/// only on the slow control-thread path (`create_initiation` on send,
/// `consume_cookie_reply` on receive). SECRET-adjacent: the cookie authorizes
/// our initiations under load, so it is never logged.
pub(crate) struct InitiatorCookie {
    /// MAC1 of the last initiation we sent to this peer — the AEAD
    /// associated data for decrypting a cookie-reply. `None` until we have
    /// sent at least one initiation (a cookie-reply arriving before we ever
    /// sent an initiation cannot be attributed, so it is dropped).
    last_mac1: Option<[u8; WG_MAC_LEN]>,
    /// The last cookie decrypted from a cookie-reply and the monotonic-ns
    /// time we stored it. `None` until a reply is consumed. Expiry is
    /// evaluated lazily at stamp time (a cookie older than
    /// [`COOKIE_ROTATION_TIME_NS`] yields a zero MAC2), not on a timer.
    cookie: Option<([u8; WG_COOKIE_LEN], u64)>,
}

impl InitiatorCookie {
    pub(crate) fn new() -> Self {
        Self {
            last_mac1: None,
            cookie: None,
        }
    }

    /// Called on EVERY outbound initiation we send to this peer, AFTER
    /// [`super::handshake::build_initiation`] has written MAC1 and zeroed
    /// MAC2. Two effects, mirroring wireguard-go `CookieGenerator::AddMacs`:
    ///
    /// 1. Record the message's MAC1 (`msg[116..132]`) as [`Self::last_mac1`]
    ///    so a subsequent cookie-reply — whose AEAD AAD is exactly this
    ///    MAC1 — can be decrypted.
    /// 2. If we hold a cookie that has NOT aged past
    ///    [`COOKIE_ROTATION_TIME_NS`], stamp
    ///    `mac2 = keyed-BLAKE2s-128(cookie, msg[0..132])` into the MAC2 slot
    ///    (`msg[132..148]`). Otherwise leave MAC2 zero — the spec-correct
    ///    value when we have no valid cookie (a first, un-challenged
    ///    initiation, or one whose cookie has expired).
    ///
    /// Returns `true` iff a non-zero MAC2 was stamped. A too-short `msg`
    /// (never happens at the sole caller, which passes the 148-byte framed
    /// message) is a no-op returning `false`.
    pub(crate) fn add_macs(&mut self, msg: &mut [u8], now_ns: u64) -> bool {
        if msg.len() < WG_MSG_INIT_LEN {
            return false;
        }
        let mut mac1 = [0u8; WG_MAC_LEN];
        mac1.copy_from_slice(&msg[M1_MAC1..M1_MAC2]);
        self.last_mac1 = Some(mac1);

        // A cookie is fresh iff strictly younger than one rotation window.
        // `saturating_sub` makes a backwards monotonic clock read as
        // zero-elapsed (still fresh) rather than a huge age — conservative,
        // and the cookie is our own so this weakens nothing.
        match self.cookie {
            Some((cookie, set_ns)) if now_ns.saturating_sub(set_ns) < COOKIE_ROTATION_TIME_NS => {
                let mac2 = keyed_blake2s_128(&cookie, &msg[..M1_MAC2]);
                msg[M1_MAC2..WG_MSG_INIT_LEN].copy_from_slice(&mac2);
                true
            }
            _ => {
                // No cookie, or expired: keep MAC2 zero (build_initiation
                // already zeroed it; re-zero defensively in case a stale
                // MAC2 was left by a caller that reused the buffer).
                msg[M1_MAC2..WG_MSG_INIT_LEN].fill(0);
                false
            }
        }
    }

    /// Consume an inbound type-3 cookie-reply from this peer. Decrypts the
    /// sealed cookie with the responder's public-key-derived key and OUR
    /// stored [`Self::last_mac1`] as the AEAD AAD; on success stores the
    /// cookie + `now_ns` so the next [`Self::add_macs`] stamps a valid MAC2.
    ///
    /// Fails closed (`false`, cookie state untouched) when we never sent an
    /// initiation (`last_mac1` unset — nothing to attribute the reply to) or
    /// when decryption fails (wrong key / wrong AAD / tampered ciphertext).
    pub(crate) fn consume_reply(
        &mut self,
        reply: &[u8],
        responder_static_pub: &[u8; WG_KEY_LEN],
        now_ns: u64,
    ) -> bool {
        let Some(aad_mac1) = self.last_mac1 else {
            return false;
        };
        match CookieChecker::decrypt_cookie_reply(reply, responder_static_pub, &aad_mac1) {
            Some(cookie) => {
                self.cookie = Some((cookie, now_ns));
                true
            }
            None => false,
        }
    }

    /// #4094 PR-B test hook: whether a (non-expired-agnostic) cookie is
    /// currently stored.
    #[cfg(test)]
    pub(crate) fn has_cookie_for_test(&self) -> bool {
        self.cookie.is_some()
    }
}

impl Default for InitiatorCookie {
    fn default() -> Self {
        Self::new()
    }
}

/// Fill `buf` from the OS CSPRNG. Returns `true` on success, `false` if
/// `getrandom` fails. There is DELIBERATELY no weak-PRNG fallback (#4094
/// BUG-2): for the cookie secret `Rm` and the reply nonce, unpredictability
/// IS the mitigation — a time-seeded or otherwise predictable value would
/// let an attacker compute valid cookies/MAC2 for spoofed sources and
/// defeat the whole under-load gate. On failure the caller fails closed
/// (drops, no reply) rather than using weak randomness. `getrandom` does
/// not fail on Linux; this is defense-in-depth.
#[must_use]
fn fill_random(buf: &mut [u8]) -> bool {
    getrandom::getrandom(buf).is_ok()
}

/// Stamp `mac2` (keyed-BLAKE2s-128 over `msg[0..132]` with `cookie` as the
/// key) into a type-1 initiation's MAC2 slot. This is what a real
/// initiator does with a decrypted cookie; used by tests and, later, PR-B.
#[cfg(test)]
pub(crate) fn stamp_initiation_mac2(msg: &mut [u8; WG_MSG_INIT_LEN], cookie: &[u8; WG_COOKIE_LEN]) {
    let mac2 = keyed_blake2s_128(cookie, &msg[..M1_MAC2]);
    msg[M1_MAC2..WG_MSG_INIT_LEN].copy_from_slice(&mac2);
}

#[cfg(test)]
#[path = "cookie_tests.rs"]
mod tests;
