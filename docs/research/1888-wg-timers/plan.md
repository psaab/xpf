# Plan: #1888 WireGuard timers (rekey / expiry / keepalive) + #1889 wg_control blocking poll(2)

**Status: DRAFT v1 — pending adversarial plan review**

Combined lane: #1888 (S5 timer semantics — bug, forward-secrecy degradation)
and #1889 (1ms idle busy-poll → blocking `poll(2)` — perf). They are one lane
because the `poll(2)` timeout computation and the timer tick are the same
mechanism in the same loop (`wg_control.rs` per-tunnel control loop), and
whichever lands second would have to rewrite the other's deadline arithmetic.

Issues: #1888 (umbrella #1703 S5), #1889. Both filed from the verified
agy-review-008 triage against master @ 87781db81.

---

## 1. Issue framing

**#1888.** The WgEngine is purely reactive: it holds zero time-based state.
The only session-lifetime bound is the counter ceiling
(`REJECT_AFTER_MESSAGES`, `wg/session.rs:28`). Consequences, verified in-tree:

- AEAD keys never rotate by time. `wg/peer.rs:49-59` documents this as the S5
  TODO verbatim: "the engine has zero time-based state ... Forward secrecy is
  degraded until that timer ships."
- The only re-initiation path is gated on `!peer_has_confirmed_session`
  (`wg_control.rs:275`) — a confirmed engine never re-initiates. PR #1868
  proved this live; the interop harness's P6 "no-flush recovery" branch and
  its "SAME TRAP" comment (wg-interop.sh:765-774) exist *because* of this gap.
- `persistent_keepalive` is parsed, stored, reconciled
  (`engine.rs:511`, `peer.rs:60`) and **never consumed** — NAT pinholes for
  idle tunnels silently expire.
- A spec-compliant peer discards its keys at REJECT_AFTER_TIME (180s). If the
  peer is responder-only, traffic blackholes until our NoSession edge fires.

**#1889.** `wg_control.rs:73` `WG_IDLE_SLEEP = 1ms`; `:285-287` sleeps it on
`!did_work`. One thread per WG tunnel ⇒ ~1,000 wakeups/s per idle tunnel.
Both fds are already non-blocking (`WouldBlock` breaks at :199 and :230), so
the loop is structurally ready for readiness-based waiting.

## 2. Honest scope/value framing

- **Security value (#1888):** today a session key lives until counter
  exhaustion — effectively forever at real traffic rates. One compromised
  session key decrypts the whole session history going forward. Against a
  kernel peer this is masked (the kernel rekeys at 120s and we respond);
  against another xpf instance or any passive responder it is not.
  REJECT_AFTER_TIME enforcement is the forward-secrecy repair; this is a
  correctness-vs-spec fix, not a scale fix.
- **Deployment honesty:** xpf today runs **single-digit tunnel counts**
  (multi-tunnel is #1434, open; S2a is single-tunnel). The realistic idle
  cost of #1889 is ~1-10k wakeups/s on an edge box — cache pollution and
  blocked deep C-states, not a throughput problem. The audit's
  100-endpoint/100k-wakeup figure is hypothetical.
- **Perf value (#1889):** poll with a 100ms cap reduces idle wakeups
  1,000/s → ~10/s per tunnel (100×). Not zero — the cap bounds stop/join
  and worker-edge latency (see §5.2). Idle CPU of the control thread should
  drop from a measurable fraction of a core to noise; before/after numbers
  go in the PR.

*If reviewers conclude the perf gain is too small to justify the churn,
PLAN-KILL is an acceptable verdict.* (Note #1888 alone is a bug with security
consequences, so a kill of the combined lane should say which half dies:
Path B keeps the timer fix and kills only the poll conversion.)

## 3. Timer-semantics table — SECTION OF RECORD

Per the WireGuard whitepaper (Jason A. Donenfeld, *WireGuard: Next Generation
Kernel Network Tunnel*, §6.1-§6.5 timer discipline; constants in §6.1 and the
paper's timer summary) cross-checked against wireguard-go `device/timers.go`
(the reference userspace implementation) and the in-tree audit inventory in
the #1888 body.

| # | Timer / constant | Value | Trigger (spec semantics) | Role restriction | Action | Fidelity in this plan |
|---|------------------|-------|--------------------------|------------------|--------|----------------------|
| T1 | REKEY_AFTER_TIME | 120s | On **sending** a transport data message, if the current session is older than 120s | **Only if we initiated the current session** (prevents both sides rekeying simultaneously) | Initiate new handshake | Event-driven inside `try_encap` success path (exact, not tick-quantized): arm `rekey_needed` edge; control loop drives initiation paced by T4 |
| T2 | Receive-horizon rekey | REJECT_AFTER_TIME − KEEPALIVE_TIMEOUT − REKEY_TIMEOUT = **165s** | On **receiving** a transport data message, if the current session is older than 165s | Only if we initiated the current session | Initiate new handshake (covers a receive-only initiator before the peer's 180s discard) | Event-driven inside `try_decap` success path |
| T3 | REJECT_AFTER_TIME | 180s | Session keys older than 180s MUST NOT be used to send **or** receive | Both roles, both directions | Refuse use; discard session | Exact gate in `try_encap`/`try_decap` (compare against `created_ns`); control-thread timer pass additionally tears down expired sessions (removes demux entries, clears `current`/`previous`) within ≤ ~1.1s |
| T4 | REKEY_TIMEOUT | 5s (+ jitter ≤ 333ms in spec) | After sending a handshake initiation with no response | Initiator of the handshake | Retransmit initiation | Control-loop pacing: re-drive initiation no more often than 5s. **Jitter omitted** — sub-granularity at our tick and pointless at single-digit tunnel counts; documented deviation |
| T5 | REKEY_ATTEMPT_TIME | 90s | Retransmissions (T4) have continued for 90s with no completed handshake | Initiator | Give up; resume only when there is new data to send | Control-loop attempt window; the existing worker `request_handshake` NoSession edge is the "new data" resume signal |
| T6 | KEEPALIVE_TIMEOUT (passive keepalive) | 10s | After **receiving** a data message, if we have **sent nothing** (data or keepalive) within 10s | Both roles | Send a keepalive (authenticated empty transport message) | Timer pass, 1s granularity |
| T7 | No-reply reinit ("suspect dead session") | KEEPALIVE_TIMEOUT + REKEY_TIMEOUT = 15s | After **sending** a data message, if we have **received nothing** (data or keepalive) within 15s | Either side may detect | Initiate new handshake | Timer pass, 1s granularity. This is the rule that makes the #1868 P6 no-flush branch obsolete-but-harmless |
| T8 | persistent_keepalive | configured per peer (0 = off) | Every N seconds, if nothing **sent** within N seconds | Both roles | Send a keepalive; if no usable session exists, initiate a handshake (NAT pinhole maintenance is the whole point) | Timer pass, 1s granularity |
| T9 | Session-state zeroing | REJECT_AFTER_TIME × 3 = 540s | No successful handshake for 540s | Both | Zero all session state | Collapses into T3: we tear down (drop) sessions at 180s, which zeroizes via `Zeroizing`/drop semantics earlier than the spec requires. Pending-handshake state is already bounded (at-most-one-per-peer) and aborted/replaced on each new attempt |

**Activity-stamp semantics** (which sends/receives feed which timers —
this is where naive implementations get T6/T7 wrong):

- `last_recv_data_ns` — set on successful `try_decap` of a **non-empty**
  inner. Arms T6. A received *keepalive* does NOT arm T6 (you don't keepalive
  a keepalive; that would ping-pong forever).
- `last_send_any_ns` — set on any successful encap, data **or** keepalive.
  Clears T6; paces T8.
- `last_send_data_ns` — set on successful encap of a non-empty inner only.
  Arms T7. A *sent keepalive* does not arm T7.
- `last_recv_any_ns` — set on any authenticated inbound transport record
  (including keepalives — `decap_keepalives` site). Clears T7.

These four stamps live on **`Peer`** (not `WgSession`) so a rekey does not
reset keepalive pacing or the dead-peer detector — matching wireguard-go,
where all timers hang off the peer. `created_ns` + `role` live on
**`WgSession`** because age and initiator-ness are per-session facts.

## 4. What's already shipped / partially batched (compose with, don't touch)

- **`wg_control.rs:168-288` loop structure** — `WG_RX_BURST` drain loops,
  authenticated endpoint-learning (:176-196, **correct, untouched**),
  responder-only TUN drain, NoSession edge + 1s `WG_INITIATOR_POLL_NS`
  re-init arm. The re-init arm is what this plan extends/replaces.
- **#1868 (P6 saga):** interop harness proves a confirmed engine never
  re-initiates; harness's no-flush recovery branch + "SAME TRAP" comment
  (wg-interop.sh:765-774) must become obsolete-but-harmless, not break.
- **#1872 tombstone lifecycle:** thread exit ⇒ tombstone ⇒ backoff respawn;
  `stop_remove_wg_control_entry` stops+joins (coordinator/mod.rs:739-752).
  The poll conversion must keep join prompt (§5.2).
- **#1876 telemetry:** `WgCounters` per engine, status.rs → `WgTunnelStatus`
  → protocol.go → Prometheus. New counters follow this exact wire-additive
  chain (both-sides grep per `feedback_wire_protocol_both_sides`).
- **#1882 stable IDs / #1873 renumbering:** counter lifetime follows the
  engine Arc; identity-changed rebuild resets counters deliberately. New
  timer state must have the same lifetime story (§7).
- **Engine reuse across reloads** (`forwarding_build/wg.rs`):
  identity-unchanged ⇒ same `Arc<WgEngine>` (sessions+stamps survive);
  identity-changed ⇒ fresh engine (sessions dropped, timers reset sanely).
  Putting timer state on `Peer`/`WgSession` inherits this for free.
- **Engine primitives the timers ride on:** `peer.current`/`previous`
  rotation (in-flight rekey handover already works), at-most-one-pending-
  per-peer with abort-and-replace, `install_session` demux discipline,
  `decap_keepalives` RX-side keepalive recognition (#1865), and
  `pad_to_16(0) == 0` meaning an empty-plaintext encap is already a valid
  on-wire keepalive.
- **S2a topology fact:** ALL inbound WG (handshake + transport) arrives on
  the control thread's kernel UDP socket; `try_decap` never runs on an
  AF_XDP worker. `try_encap` runs on the control thread plus the rarely-hit
  transit path `frame/wg.rs:108` (which already heap-allocates per packet).
  This is why per-packet clock reads in §5.1 are cheap *today* — and why
  §7 flags the S3 hot-path migration as the invariant to re-check.

## 5. Concrete design

### 5.1 Engine-side timer state + enforcement (#1888)

**`WgSession` additions** (`wg/session.rs`):

```rust
pub(crate) struct WgSession {
    // ... existing ...
    /// CLOCK_MONOTONIC ns at install. Basis for T1/T2/T3 age checks.
    pub(crate) created_ns: u64,
    /// Which side initiated. T1/T2 fire only on Initiator-role sessions.
    pub(crate) role: SessionRole,
}
```

`new_with_role` stamps `created_ns` via `counters::monotonic_now_ns()` and
stores `role` (today the role only picks the initial `confirmed` value and is
discarded). Both handshake completion paths already call `new_with_role`.

**`Peer` additions** (`wg/peer.rs`) — the four activity stamps from §3, all
relaxed `AtomicU64`, 0 = never:

```rust
pub(crate) last_send_any_ns:  AtomicU64,
pub(crate) last_send_data_ns: AtomicU64,
pub(crate) last_recv_any_ns:  AtomicU64,
pub(crate) last_recv_data_ns: AtomicU64,
```

**`WgEngine` additions** (`wg/engine.rs`):

```rust
/// Worker/encap → control "session is stale, rekey" edge. Same relaxed
/// AtomicBool + consume pattern as handshake_request_pending. Armed by
/// try_encap (T1) and try_decap (T2); consumed by the control loop,
/// which initiates WITHOUT the !peer_has_confirmed_session gate.
pub(in crate::afxdp::wg) rekey_request_pending: AtomicBool,
```

**Hot-path enforcement** — `try_encap` success path gains (after the
existing confirmed gate, before counter consume):

```rust
let now_ns = super::counters::monotonic_now_ns();   // vDSO, ~20ns
let age = now_ns.saturating_sub(session.created_ns);
if age >= REJECT_AFTER_TIME_NS {
    WgCounters::bump(&self.counters.encap_drops_expired);
    self.request_rekey();           // arm edge so control re-initiates
    return Err(EncapError::NoSession); // caller contract identical to today
}
if session.role == SessionRole::Initiator && age >= REKEY_AFTER_TIME_NS {
    self.request_rekey();           // T1 — exact spec "on send" semantics
}
// on success: peer.last_send_any_ns.store(now_ns); and if inner non-empty,
// peer.last_send_data_ns.store(now_ns)
```

`try_decap` symmetric: T3 gate before AEAD (drop + count, arm rekey edge),
T2 arm after successful authentication, `last_recv_any/data` stamps at the
existing success/keepalive sites. Ordering note: the T3 gate must fire
**before** `next_tx_counter()`/header writes (encap) so the "on Err the
buffer and counter are untouched" contract holds, and before AEAD (decap) so
expired keys do no crypto work.

This costs one `clock_gettime(CLOCK_MONOTONIC)` vDSO call per encap/decap.
Both paths are control-thread or already-allocating transit today (§4); no
AF_XDP steady-state path is touched.

**Keepalive emission** — extract `try_encap`'s body into
`encap_inner(peer, inner_ip, out, is_keepalive)`:

- `try_encap(...)` = `encap_inner(..., false)` — bumps `encap_packets`/
  `encap_bytes`, stamps both send stamps.
- `create_keepalive(peer_pubkey, out)` = `encap_inner(&[], ..., true)` —
  bumps `keepalives_tx_*` (caller picks passive/persistent attribution),
  stamps `last_send_any_ns` only, skips `encap_packets`. A keepalive still
  consumes a tx counter (spec: keepalives are ordinary transport messages)
  and is still subject to the T3/REJECT_AFTER_MESSAGES gates.

**Expiry teardown** — engine API for the control-thread timer pass:

```rust
/// Tear down current/previous sessions older than REJECT_AFTER_TIME.
/// Takes reconcile_lock (serialized with install/reconcile); removes
/// demux entries exactly like the reconcile peer-removal drain.
pub(crate) fn expire_sessions(&self, now_ns: u64) -> usize;
```

**Timer decision pass** — pure, deterministically testable:

```rust
pub(crate) struct TimerActions {
    pub initiate: bool,           // T7 / T8-no-session / rekey edge
    pub send_keepalive: Option<KeepaliveKind>, // Passive | Persistent
    pub next_deadline_ns: u64,    // earliest future deadline, for poll timeout
}
pub(crate) fn timer_pass(&self, now_ns: u64) -> TimerActions;
```

`timer_pass` reads peer stamps + session age + `persistent_keepalive` and
computes T6/T7/T8 plus the next deadline. It performs no IO — the control
loop owns sends — so mock-clock unit tests drive it with synthetic `now_ns`
and hand-set stamps.

### 5.2 Control-loop conversion to poll(2) (#1889) + timer arm rewrite

```rust
const WG_POLL_CAP: Duration = Duration::from_millis(100);
const WG_TIMER_TICK_NS: u64 = 1_000_000_000; // timer pass granularity

while !stop.load(Ordering::Relaxed) {
    let mut did_work = false;
    // --- socket burst, TUN burst: UNCHANGED (WG_RX_BURST drains) ---

    // --- timer arm (replaces the :261-283 re-init block) ---
    // Runs at most once per WG_TIMER_TICK_NS, including under sustained
    // bursts (one monotonic read + compare per iteration).
    if now - last_timer_pass_ns >= WG_TIMER_TICK_NS {
        engine.expire_sessions(now);
        let actions = engine.timer_pass(now);
        // initiation: NoSession edge OR rekey edge OR timer actions,
        // paced by REKEY_TIMEOUT (5s), capped by REKEY_ATTEMPT_TIME (90s)
        // since attempt_started; rekey edge bypasses the
        // !peer_has_confirmed_session gate (that is the whole point).
        // keepalives: create_keepalive + wg_send_to toward
        // effective_endpoint (skip if none learned/configured).
    }

    if !did_work {
        let timeout = next_deadline.saturating_sub(now).min(WG_POLL_CAP);
        // libc::poll over [socket_fd: POLLIN, tun_fd: POLLIN]
        match poll(&mut fds, timeout_ms) {
            -1 if errno == EINTR => continue,
            ...
        }
    }
}
```

Design points, mapped to #1889's stated constraints:

1. **Stop/join latency:** poll timeout is capped at 100ms regardless of the
   next timer deadline ⇒ `stop_remove_wg_control_entry` joins within
   ~100ms + one burst. No eventfd in the poll set (adjudicated in §11 Q2):
   stop sites are reconcile-time and rare; 100ms join is well inside the
   #1866/#1872 teardown budget and avoids a new fd lifecycle + a change to
   the shared `LocalTunnelSourceHandle` stop contract.
2. **Burst path unchanged:** the `WG_RX_BURST` drain loops are untouched;
   poll only gates the `!did_work` case. Under load the loop never blocks.
3. **No per-packet syscalls added** to any AF_XDP worker path. The control
   thread gains one `poll(2)` per idle interval (that is the entire point)
   and one clock read per iteration.
4. **Worker NoSession/rekey edge latency:** edges are relaxed atomics the
   loop reads on wake. The 100ms cap bounds the added latency at ≤100ms on
   an otherwise idle tunnel (today ≤1ms). Handshake bring-up is 1s+-paced
   already; ≤100ms extra on the *first* packet after deep idle is
   acceptable and goes in the PR notes.
5. **POLLERR/POLLHUP/POLLNVAL discipline:** ERR/HUP on the UDP socket is
   normal (ICMP errors) — drain via the existing `recv_from` error arm.
   ERR/HUP/NVAL on the TUN (device destroyed under us) makes poll return
   instantly while reads keep failing — a spin hazard. Guard: count
   consecutive poll-ready-but-zero-progress iterations; past a small bound
   (e.g. 8) exit the thread cleanly. The #1872 tombstone + backoff respawn
   machinery is the designed recovery path for exactly this.
6. **fd-close-during-poll:** both fds are owned by the loop's stack frame
   and closed only after the loop returns; the coordinator never closes
   them externally (it only flips `stop` and joins). No external-close race
   exists by construction; the test in §9 pins the stop-while-blocked path.

**Initiation pacing change (behavioral):** the unconfirmed-session re-drive
moves from every 1s (`WG_INITIATOR_POLL_NS`) to spec pacing — every
REKEY_TIMEOUT (5s), giving up after REKEY_ATTEMPT_TIME (90s) until a new
NoSession/rekey edge or persistent-keepalive deadline re-arms an attempt.
Slower worst-case bring-up retry (1s → 5s), but spec-correct and kinder to a
cookie-rate-limiting kernel peer. Flagged for reviewers (§11 Q4).

### 5.3 Telemetry (#1876 wire-additive extension)

New `WgCounters` fields → `status.rs` snapshot → `protocol.rs`
`WgTunnelStatus` → `protocol.go` (omitempty) → `pkg/api` Prometheus
collector (both-sides grep is an engineer-phase gate):

- `rekeys_initiated` — timer/age-driven initiations (T1+T2+T7 fold; reason
  split deferred until field need — counters are cheap but wire fields are
  forever).
- `sessions_expired` — T3 teardowns + expired-use refusals
  (`encap_drops_expired`/`decap_drops_expired` feed it or stand alone —
  engineer phase picks one shape and documents it).
- `keepalives_tx_passive`, `keepalives_tx_persistent` — T6 / T8 sends.
  (RX side already exists: `decap_keepalives`.)

### 5.4 Path options

- **Path A (recommended): full §3 timer inventory + poll conversion,
  one PR, logical commits** (poll-loop conversion / session+peer state /
  T3 enforcement / T1+T2 edges / T6+T7+T8 pass / telemetry / tests / docs).
  Natural shape: the poll timeout *is* `min(next timer deadline, cap)`;
  building it twice is the only alternative. Cost: ~600-900 LOC including
  tests across `wg/{session,peer,engine}.rs`, `wg_control.rs`,
  `counters.rs`, `status.rs`, `protocol.rs`, `protocol.go`, Prometheus
  collector, interop-harness notes. Touches the encap/decap enforcement
  paths (the security-sensitive core) — that is where review attention goes.
- **Path B: timers only (#1888), keep the 1ms sleep.** All of §5.1, with
  the timer arm running on the existing 1ms-sleep loop (1s tick throttle
  inside). Smaller diff (~-150 LOC vs A), leaves #1889 open and re-plumbs
  the deadline computation when the poll PR lands later. Choose if reviewers
  judge the combined blast radius too large for one PR.
- **Path C: poll only (#1889), defer timers.** Smallest diff, but the poll
  timeout has only the 1s re-init deadline to wait on, and the
  forward-secrecy bug — the higher-value half — stays open. Only correct if
  reviewers kill the §5.1 design outright.

## 6. Public API preservation

- `WgEngine::try_encap(&self, peer_pubkey, inner_ip, out) -> Result<EncapOutcome, EncapError>` — signature unchanged; new failure mode reuses `NoSession` (expired ⇒ caller kicks slow path, identical contract).
- `WgEngine::try_decap(&self, wg_record, out) -> Result<DecapOutcome, DecapError>` — signature unchanged; new `DecapError::Expired` variant OR reuse of `UnknownSession` (engineer phase: prefer a new variant + counters-mapper arm; the enum is `pub(crate)` and the mapper makes omissions a compile error).
- `create_initiation` / `consume_response` / `consume_initiation_create_response` / `install_session` / `reconcile_peers` — unchanged.
- `WgSession::new` (test-compat constructor) — preserved, stamps `created_ns` internally.
- `wg_control_loop` signature — unchanged (same spawn site).
- Wire protocol — additive only: new `WgTunnelStatus` fields, `omitempty` on the Go side; old Go daemon + new helper and vice versa stay compatible.
- `Peer::update_config`, `peer_has_confirmed_session`, `request_handshake`/`take_handshake_request` — unchanged; `request_rekey`/`take_rekey_request` are new siblings.

## 7. Hidden invariants the change must preserve

1. **On-Err contract of `try_encap`:** "on Err, `out` and `tx_counter` are
   untouched." The T3 gate must sit before `next_tx_counter()` and the
   header write (it does, §5.1).
2. **Decap error paths zero `out[..n]`:** any new post-AEAD error arm must
   route through the existing wipe fall-through. (T3 fires pre-AEAD; T2 is
   success-path-only — nothing new post-AEAD.)
3. **Engine Arc shared across reload identity-reuse:** timer state on
   `Peer`/`WgSession` survives identity-unchanged reloads and control-thread
   tombstone/respawns; resets with the engine on identity-changed rebuilds —
   exactly the #1876 counter-lifetime story. Thread-local state is limited
   to retry pacing (`attempt_started_ns`, `last_initiation_ns`), where a
   respawn restarting the attempt cycle is benign (and is today's behavior).
4. **`reconcile_lock` discipline:** `expire_sessions` takes it (serialized
   with install/reconcile); demux-entry removal mirrors the reconcile
   peer-removal drain so no demux entry can orphan.
5. **No allocation on hot paths; no syscalls on AF_XDP worker paths.** The
   only clock reads added are vDSO calls on control-thread/transit paths
   (§5.1). **S3 migration flag:** if decap ever moves onto AF_XDP workers,
   the per-packet clock read must convert to a control-thread-published
   coarse `AtomicU64` now — record this in the module doc.
6. **Control-socket contention rule:** everything here runs in the
   per-tunnel control thread; zero new control-socket requests.
7. **Keepalives consume tx counters** (spec) and obey
   REJECT_AFTER_MESSAGES/T3 — `create_keepalive` goes through the same
   `encap_inner` gates.
8. **Endpoint-learning gate (:176-196) untouched** — keepalive/rekey sends
   target `effective_endpoint` exactly like data sends; no new
   endpoint-mutation site.
9. **Responder-only peers never timer-initiate cold** (today's rule,
   preserved): T1/T2 fire only on Initiator-role sessions; T7/T8/NoSession
   re-initiation toward a *learned* endpoint is allowed exactly where
   `requested` initiation is allowed today.
10. **eprintln discipline:** timer events log nothing per-tick; rekey/expiry
    are counter-visible, not journald-visible (rare one-line exceptions go
    through `record_local_tunnel_exception` as today).

## 8. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | **MED** | (a) Sessions now die at 180s — against an *old-xpf* peer (zero timers, responder side with no endpoint configured) an idle tunnel that today "works" insecurely forever will need traffic-driven re-establishment after expiry; spec-correct, release-noted. (b) Bring-up retry pacing 1s→5s. (c) Keepalives add ~32-byte datagrams on idle tunnels (the configured intent). Kernel-peer interop is exercised live by wg-interop.sh P1-P7. |
| Lifetime / borrow-checker | **LOW** | New state is atomics + two plain fields on existing structs; `expire_sessions` copies the reconcile drain pattern; no new lock orders (reconcile_lock → demux write, already established). |
| Performance regression | **LOW** | One vDSO clock read per encap/decap on non-hot paths; one poll syscall per idle interval replacing 1000 sleep syscalls/s; burst path byte-identical. P7 fast-path no-regress gate covers the transit path. |
| Architectural mismatch (#961-pattern) | **LOW-MED** | The one real question: enforcing T3 in the engine (per-use exact) vs purely in the control thread (tick-quantized). §5.1 picks exact-in-engine because decap is control-thread-only in S2a; if reviewers judge the S3 hot-path future makes engine-side clock reads a trap, the fallback (tick-only enforcement, ≤1.1s slop) is a 30-line delta. Invited as Q1. |

## 9. Test plan

- `cargo build --release` clean; FULL `cargo test --release` awk-aggregated
  over all "test result" lines (known flakes per ledger: worker_queue
  concurrent_recovery / wg reconcile_peers / tx_latency_hist — standalone
  5×); debug `cargo test wg::`; `go test ./...`.
- **Mock-clock unit tests per timer semantic** (engine-level, synthetic
  `now_ns`, hand-set stamps — no sleeps):
  - T1: initiator-role session age ≥120s + send ⇒ rekey edge armed; NOT
    armed at 119s; NOT armed on responder-role session at any age (the
    initiator-only rule); NOT armed with no send (idle session quietly ages
    to expiry per spec).
  - T2: receive at age ≥165s on initiator-role session ⇒ edge armed.
  - T3: encap refused + counter untouched at ≥180s; decap refused pre-AEAD;
    `expire_sessions` removes demux entries for both current and previous;
    expired previous does not orphan demux.
  - T4/T5: pacing — two initiations <5s apart collapse; attempts stop after
    90s; NoSession edge re-arms a fresh attempt window.
  - T6: recv data then 10s with no send ⇒ passive keepalive; a sent
    keepalive clears it; a *received keepalive* does NOT arm it (ping-pong
    guard).
  - T7: send data then 15s of silence ⇒ initiate; an inbound keepalive
    clears it (this is the keepalive's protocol purpose).
  - T8: persistent_keepalive=N paces sends at N; suppressed by data sends;
    fires handshake when no session; `persistent_keepalive=0` ⇒ fully off.
  - Keepalive encode: `create_keepalive` ⇒ 32-byte record, counter
    consumed, `encap_packets` NOT bumped, kernel-side decodes as keepalive
    (round-trip via existing two-engine test rig in wg/tests.rs).
  - Rekey handover: T1-driven `consume_response` rotates current→previous;
    in-flight old-session ciphertexts still decap (existing rotation tests
    extended with timer-driven trigger).
- **Poll-loop tests:**
  - stop-join latency bound: spawn loop on loopback socket + dummy TUN-like
    fd (pipe), assert `stop`→join completes < 500ms while idle-blocked.
  - readiness wakeup: datagram arrival while blocked wakes and processes
    within the burst (no 1s timer wait).
  - poll-ready-zero-progress guard: erroring fd ⇒ thread exits within the
    bounded spin count (no busy loop).
- Counter-mapper exhaustiveness tests extended for new variants (existing
  pattern in counters_tests).
- Smoke (deferred to engineer phase, runs on loss userspace cluster under
  the lock protocol): wg-interop.sh all (P0-P7, TAINT=0) + the four live
  proofs from the lane contract — (a) rekey at ~120s under active traffic
  with zero traffic gap, (b) idle keepalives at the configured interval
  (peer-side tcpdump count), (c) idle control-thread CPU before/after
  (pidstat), (d) P7 throughput no-regress. CoS re-apply after deploy.

## 10. Out of scope (explicitly)

- **Cookie/MAC2 under-load machinery (S7)** — type-3 stays drop+count.
- **Per-peer TAI64N anti-replay on the responder path** — rides with
  responder hardening (S1 boundary note in handshake_session.rs).
- **Handshake-retransmit jitter (≤333ms)** — documented deviation, §3 T4.
- **Multi-tunnel scale work (#1434 S6)** — per-tunnel thread model
  unchanged; poll conversion reduces idle cost per thread, it does not
  consolidate threads.
- **Roaming `update_endpoint_if_verified` engine API** (peer.rs TODO) —
  endpoint learning stays in the control loop, which is correct for S2a.
- **Session migration across identity-changed rebuilds** (forwarding_build
  wg.rs note) — unchanged: identity change drops sessions, re-handshakes.
- **Removing the #1868 harness no-flush branch** — it becomes
  obsolete-but-harmless; harness simplification is a follow-up after the
  timers soak.
- **Coarse-clock publication for worker-side decap** — only needed if S3
  moves decap onto AF_XDP workers (§7.5 flag).

## 11. Open questions for adversarial review

1. **T3 enforcement locus.** Exact per-use gate inside `try_encap`/`try_decap`
   (one vDSO clock read per packet on today's non-hot paths) vs
   control-thread tick-only teardown (zero engine changes, ≤1.1s
   enforcement slop)? The plan picks exact-in-engine. If you believe the S3
   hot-path future or the clock-read cost makes this wrong, say so —
   PLAN-KILL the locus, not the lane.
2. **Stop wakeup: 100ms poll cap vs eventfd in the poll set.** Cap-only is
   chosen (no new fd lifecycle, no shared-handle changes, ~100ms join is
   inside every existing teardown budget, and it bounds worker-edge latency
   anyway). Is there a teardown path where 100ms×N serial joins on the
   control-socket thread is unacceptable? (N = WG tunnel count, single-digit
   today.)
3. **Stamp placement.** Activity stamps on `Peer` (survive rekey) vs
   `WgSession` (reset on rekey)? §3 argues Peer, matching wireguard-go. A
   concrete counter-example where peer-level stamps mis-fire a timer across
   a rekey boundary would change the design.
4. **Initiation pacing 1s → REKEY_TIMEOUT (5s) + REKEY_ATTEMPT_TIME (90s)
   give-up.** Spec-correct but slows worst-case bring-up retry. Keep today's
   1s instead (spec deviation), or adopt spec pacing? Plan adopts spec.
5. **T7 (15s no-reply reinit) in scope?** It is the rule that actually
   repairs the #1868 confirmed-but-dead blackhole *without* peer
   cooperation. Plan includes it; killing it shrinks the diff but leaves
   dead-session detection to T3 expiry (up to 180s of blackhole).
6. **Expired-decap error shape.** New `DecapError::Expired` variant (clean
   telemetry, +1 enum churn) vs folding into `UnknownSession`? Plan prefers
   the new variant; the counters mapper makes it a compile-time-complete
   change.
7. **Counter granularity.** `rekeys_initiated` folded (T1+T2+T7) vs split by
   reason? Wire fields are forever; plan folds and documents. Live-debug
   value of the split: is one fielded incident worth three wire fields?
