# Plan: #1888 WireGuard timers (rekey / expiry / keepalive) + #1889 wg_control blocking poll(2)

**Status: DRAFT v5 — round-2 fold (Codex r2: 1 BLOCKER + 3 MAJOR + 1 MINOR; AGY r2: 1 BLOCKER + 3 MAJOR + 1 MINOR; SMR r2: F1-F3). Every r1 finding attested RESOLVED by both external reviewers. Pending round-3 convergence.**

v5 (round-2 fold):
- Codex C1 BLOCKER (subsumes SMR r2 F1): attempt success is now an
  IDENTITY check, not a clock inequality — record the current session's
  `local_index` (or None) at attempt start; success when it changes.
  (v4's `>=` was still fragile: a fast msg2 processed in the next burst
  installs with the PREVIOUS published timestamp, strictly older than
  `started_ns`.)
- Codex C2 MAJOR: the v3 cached-clock adjudication is REVERSED for T3
  enforcement — `try_encap`/`try_decap` read CLOCK_MONOTONIC per use
  (vDSO; both paths are control-thread or already-allocating transit). No
  publisher cadence can hard-bound staleness when the control thread
  stalls, and workers must never send past REJECT_AFTER_TIME. A
  `#[cfg(test)]`-gated mock-clock override preserves deterministic tests;
  AGY's S3 hot-path concern stays as the §7.5 documented flag.
- Codex C3 MAJOR: deadline sentinel specified — `u64::MAX` means "no
  deadline"; `next_deadline` initialized to 0 forces one pass on the
  first iteration; every pass recomputes from scratch so no stale
  past-deadline can survive a pass (no zero-timeout poll loop).
- Codex C4 MAJOR: post-msg2 immediate keepalive — on `consume_response`
  Ok the control loop sends one keepalive (Linux receive.c sends a
  keepalive after a handshake response when no data is queued); without
  it the peer's responder-role session stays unconfirmed and ITS egress
  blackholes until our next send.
- Codex C5 + AGY r1 F7 completion: ONE bulk signal-then-join helper used
  by stale-prune, `stop_all_wg_control_threads`, AND
  `prune_wg_control_threads_for_snapshot` (the third serial stop path).
- AGY A1 BLOCKER: T7's trigger stamp is CONSUMED on attempt start
  (`last_send_data_ns := 0`), so T5 give-up cannot immediately re-trigger
  a fresh 90s window — post-give-up re-initiation requires NEW egress
  data (spec: "tries again when wanting to send").
- AGY A2 MAJOR: T8's "usable session" DEFINED = confirmed AND unexpired.
  An unconfirmed responder-role current session ⇒ T8 initiates (else the
  keepalive silently fails the confirmed gate and pinhole maintenance
  breaks).
- AGY A3 MAJOR: UDP `POLLNVAL` (fd invalid) EXITS the thread; only
  transient UDP `POLLERR`/`POLLHUP` remain non-fatal drains.
- AGY A4 MAJOR: T6 predicate pinned:
  `last_recv_data_ns > last_send_any_ns && now − last_send_any_ns ≥ 10s` —
  under an inbound-only stream this emits one keepalive per 10s anchored
  on our last send (kernel-equivalent); the naive recv-anchored reading
  never fires and trips the peer's T7.
- AGY A5 MINOR: `last_timer_pass_ns` advances ONLY on tick-condition
  runs; deadline-driven passes do not reset the 1s anchor.

v3 (AGY r1 fold + Codex/AGY conflict adjudications):
- AGY F1 (peer-stamp infinite T7 loop) — superseded by the v2 traversal
  stamps (AGY reviewed v1): an inbound valid msg2 now stamps
  `last_recv_any_ns` and clears T7. Peer placement RETAINED (moving stamps
  to `WgSession` would zero them on rekey, losing the T6 obligation and
  letting T8 fire immediately post-rekey); AGY's exact trace added as a §9
  regression test for r2 re-verification.
- AGY F2 (BLOCKER, rekey retry starves after a lost initiation) — fixed by
  an explicit control-loop ATTEMPT STATE MACHINE (§5.2): while an attempt
  is active, retries pace at REKEY_TIMEOUT bypassing the confirmed gate,
  until success (fresh `created_ns`) or the 90s window ends.
- AGY F3 (BLOCKER, busy-spin when a deadline lands mid-tick) — timer pass
  now runs when `now >= next_deadline` OR the 1s tick elapses.
- AGY F4 (T8 lock-out after give-up) — T8-due starts a NEW attempt window;
  give-up never permanently disables pinhole maintenance.
- AGY F5/F8 (fatal-fd busy spin) — TUN `POLLERR|POLLHUP|POLLNVAL` revents
  or repeated fatal TUN reads exit the thread; UDP errors never do.
- AGY F6 vs Codex M7 clock conflict ADJUDICATED: exact per-use T3
  enforcement locus (Codex) using an engine-resident CACHED coarse clock
  (`cached_now_ns: AtomicU64`, AGY) published by the control loop each
  iteration — no per-packet vDSO reads, enforcement slop ≤ ~0.2s, and the
  cached atomic doubles as the mock clock for deterministic tests.
- AGY F7 (serial join latency) — multi-entry stop paths signal ALL stop
  flags before joining any (bounds reload latency at ~one cap, not N×cap).
- AGY F9 — old-xpf permanent-blackhole upgrade note strengthened in §8.

Revision log:
- v2: T8 paces on *any authenticated traversal* (sent OR received, incl.
  handshakes) per wireguard-go `timersAnyAuthenticatedPacketTraversal`
  (Codex B1); stamp table extended to authenticated handshake send/receive
  (Codex B2); T6 arming moved before AllowedIPs/inner-parse (Codex M3);
  expired decap is drop-only — initiation is send-side-only (Codex M4); T5
  give-up releases the pending reservation (Codex M5); fd-specific poll
  error guard (Codex M6); Q1 closed — per-use T3 enforcement required
  (Codex M7); T7 jitter deviation documented (Codex m8); initiation
  predicate table added (SMR F1); two-edge truth table added (SMR F2);
  100ms-cap honesty note (SMR F3); keepalive-arm stamp site made explicit
  (SMR F4); keepalive-interval-in-identity-tuple note (SMR F5); per-engine
  edge S6 scoping note (SMR F6); rekeys_initiated split by reason (Codex
  Q7 + SMR F7).

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
| T6 | KEEPALIVE_TIMEOUT (passive keepalive) | 10s | After **receiving** a data message, if we have **sent nothing** (any authenticated packet) within 10s. Predicate pinned (AGY r2 A4): `last_recv_data_ns > last_send_any_ns && now − last_send_any_ns ≥ 10s` — anchored on our LAST SEND so an inbound-only stream emits one keepalive per 10s (kernel-equivalent); a recv-anchored reading would never fire under continuous inbound data and would trip the peer's T7 | Both roles | Send a keepalive (authenticated empty transport message) | Timer pass, 1s granularity |
| T7 | No-reply reinit ("suspect dead session") | KEEPALIVE_TIMEOUT + REKEY_TIMEOUT = 15s (+ jitter ≤ 333ms in spec/wireguard-go — **omitted**, documented deviation like T4) | After **sending** a transport data message, if we have **received no authenticated packet** (data, keepalive, or valid handshake message) within 15s | Either side may detect | Initiate new handshake | Timer pass, 1s granularity. This is the rule that makes the #1868 P6 no-flush branch obsolete-but-harmless |
| T8 | persistent_keepalive | configured per peer (0 = off) | Every N seconds, if there has been **no authenticated packet traversal in EITHER direction** within N seconds (wireguard-go `timersAnyAuthenticatedPacketTraversal` — sent OR received, transport OR handshake, resets the pacing; Codex r2 confirmed against Linux `timers.c:215-219`) | Both roles | Send a keepalive; if no **usable** session exists, initiate a handshake (NAT pinhole maintenance is the whole point). **"Usable" DEFINED (AGY r2 A2): confirmed AND unexpired** — an unconfirmed responder-role current session is NOT usable (its keepalive would silently fail `try_encap`'s confirmed gate), so T8 initiates | Timer pass, 1s granularity |
| T9 | Session-state zeroing | REJECT_AFTER_TIME × 3 = 540s | No successful handshake for 540s | Both | Zero all session state | Collapses into T3: we tear down (drop) sessions at 180s, which zeroizes via `Zeroizing`/drop semantics earlier than the spec requires. Pending-handshake state is already bounded (at-most-one-per-peer) and aborted/replaced on each new attempt |

**Activity-stamp semantics** (which packets feed which timers — this is
where naive implementations get T6/T7/T8 wrong). The stamp set mirrors
wireguard-go's timer events: `timersDataSent`/`timersDataReceived` (transport
data only) and `timersAnyAuthenticatedPacketSent`/`...Received`/`...Traversal`
(transport data, keepalives, AND authenticated handshake messages — Codex r1
B1/B2 corrected v1, which omitted handshake traffic entirely):

- `last_send_data_ns` — successful encap of a **non-empty** inner (transport
  data only). Arms T7. A sent keepalive or handshake does NOT arm T7.
  **CONSUMED (set to 0) when a handshake attempt starts** (AGY r2 A1): the
  T7 obligation transfers to the attempt machine; without this reset, a T5
  give-up would observe the same stale stamp and immediately re-open a
  fresh 90s window, looping forever — post-give-up re-initiation must
  require NEW egress data, per the spec's "tries again when wanting to
  send".
- `last_recv_data_ns` — **authenticated, replay-accepted, non-empty**
  transport plaintext. Stamped immediately after the replay-window accept
  with `n > 0` — **before** the inner-parse/AllowedIPs gates (Codex r1 M3:
  wireguard-go fires `timersDataReceived` once the packet authenticates,
  before routing delivery; an AllowedIPs-rejected packet still proves the
  peer is alive and sending on this session). Arms T6. A received keepalive
  does NOT arm T6 (no keepalive ping-pong).
- `last_send_any_ns` — **any authenticated packet sent**: transport data,
  keepalive, handshake initiation, or handshake response (stamped at the
  call-site on `wg_send_to` success for handshake messages; inside
  `encap_inner` for transport). Clears T6.
- `last_recv_any_ns` — **any authenticated packet received**: transport data,
  keepalive (the `decap_keepalives` arm — which must look up
  `peer_arc(&session.peer_pubkey)` before its early return at
  engine.rs:958-961, SMR F4), or a valid handshake message
  (`consume_response` Ok / `consume_initiation_create_response` Ok — stamped
  in the #1865 counting wrappers). Clears T7.
- T8 paces on `max(last_send_any_ns, last_recv_any_ns)` — i.e. any
  authenticated traversal in either direction resets the persistent-keepalive
  countdown (Codex r1 B1).

These stamps live on **`Peer`** (not `WgSession`) so a rekey does not reset
keepalive pacing or the dead-peer detector — matching wireguard-go, where all
timers hang off the peer. `created_ns` + `role` live on **`WgSession`**
because age and initiator-ness are per-session facts.

**Initiation predicate table** (SMR F1 — today's code distinguishes
configured vs learned endpoints at wg_control.rs:274; the new trigger classes
must each state their rule):

| Trigger | Endpoint required | Confirmed-session gate |
|---------|------------------|------------------------|
| NoSession edge (`take_handshake_request`) | configured OR learned (today's `requested` rule) | gated: only if `!peer_has_confirmed_session` (unchanged) |
| Rekey edge (`take_rekey_request`, T1/T2 + send-side T3) | configured OR learned | **ungated** — a confirmed-but-stale session is exactly what is being replaced (paced by T4 only) |
| Unconfirmed-retry timer (T4/T5 attempt window) | configured ONLY (today's `allow_timer` rule — never spam a designated-initiator peer) | gated (unchanged) |
| T7 no-reply reinit | configured OR learned (we were just exchanging data with this endpoint) | ungated (the session is suspect) |
| T8 keepalive-due with no usable session | configured OR **learned, iff `persistent_keepalive > 0`** — without this the stated NAT-pinhole purpose fails for learned-endpoint peers | gated |

A consumed rekey edge with no known endpoint is dropped, not re-queued: any
subsequent send on the stale session re-arms it (try_encap arms
unconditionally past the age threshold), so the edge cannot be permanently
lost (SMR F2).

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

`new_with_role` gains `created_ns` as a parameter (the completion paths pass
the engine's cached clock — see "Engine clock" below) and stores `role`
(today the role only picks the initial `confirmed` value and is discarded).
Both handshake completion paths already call `new_with_role`.

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
/// try_encap (T1 age threshold + send-side T3 expiry) and try_decap
/// (T2 receive-horizon); consumed by the control loop, which initiates
/// WITHOUT the !peer_has_confirmed_session gate (see the §3 initiation
/// predicate table). Per-ENGINE (single peer in S2a); the per-peer
/// generalization is #1434/S6's, same as handshake_request_pending
/// (SMR F6).
pub(in crate::afxdp::wg) rekey_request_pending: AtomicBool,
```

**Engine clock** — v5 (Codex r2 C2 reversed the v3 cached-clock
adjudication): `WgEngine::now_ns()` reads CLOCK_MONOTONIC per use
(`counters::monotonic_now_ns()`, a vDSO call, ~20-25ns). The v3 publisher
design had no hard staleness bound — `frame/wg.rs:108` worker encap runs
with whatever the control loop last published, and a descheduled/stalled
control thread would let workers send past REJECT_AFTER_TIME indefinitely.
Both consuming paths are the control thread and the already-per-packet-
allocating transit path, so the read is in budget. Deterministic tests use
a `#[cfg(test)]`-gated override inside `now_ns()` (engine-resident
`Option<AtomicU64>`-style mock, compiled out of release builds — zero
release cost). AGY's S3 hot-path concern (per-packet clock reads if decap
ever moves onto AF_XDP workers) remains the §7.5 documented flag.

**Hot-path enforcement** — `try_encap` success path gains (after the
existing confirmed gate, before counter consume):

```rust
let now_ns = self.now_ns();         // CLOCK_MONOTONIC vDSO; cfg(test) mock
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

`try_decap`: T3 gate before AEAD — **drop + count ONLY, no rekey arm**
(Codex r1 M4: wireguard-go's receive path drops expired keypairs and leaves
initiation to the send side; an attacker replaying old ciphertext at an
expired session must not be able to drive our handshake cadence). T2 arm
after successful authentication on an initiator-role session;
`last_recv_data_ns` stamped post-replay-accept, pre-AllowedIPs (§3);
`last_recv_any_ns` stamped in the keepalive arm (with its own `peer_arc`
lookup) and the handshake-consume wrappers. Ordering note: the encap T3 gate
must fire **before** `next_tx_counter()`/header writes so the "on Err the
buffer and counter are untouched" contract holds; the decap T3 gate fires
before AEAD so expired keys do no crypto work.

Per-packet cost is one vDSO clock read plus the stamp stores — no
allocation; no AF_XDP steady-state path is touched (decap is control-thread
only in S2a; the worker transit encap already heap-allocates per packet).
`created_ns` is stamped via the same `now_ns()` at the two
handshake-completion install sites (engine impl methods, which have
`&self`), keeping every age comparison in one clock domain — including
under the test mock.

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

**Pending-handshake attempt window (T5)** — Codex r1 M5: without cleanup, a
forged-or-stale msg2 can complete a handshake long after the 90s give-up
(`pending` entries live until response/re-add/restart,
handshake_session.rs:202, :362). The control loop owns the attempt window
(thread-local `attempt_started_ns` / `last_initiation_ns`); on T5 give-up it
calls a new engine API `abort_pending_for_peer(&pubkey)` (a thin public
wrapper over the existing `release_pending` path via the `pending_by_peer`
marker, under `reconcile_lock`) so the reservation — and with it the ability
of a late msg2 to complete — dies with the attempt. A msg2 arriving after
release hits the existing `NoPendingHandshake` drop. Thread respawn
(#1872) resetting the thread-local window merely restarts an attempt cycle —
benign, and today's behavior.

**Timer decision pass** — pure, deterministically testable:

```rust
pub(crate) enum InitiateReason { Age, DeadPeer, KeepaliveNoSession }
pub(crate) struct TimerActions {
    pub initiate: Option<InitiateReason>, // T7 / T8-no-session (T1/T2/T3 come in via the rekey edge)
    pub send_keepalive: Option<KeepaliveKind>, // Passive | Persistent
    pub next_deadline_ns: u64,    // earliest future deadline; u64::MAX = none (Codex r2 C3)
}
pub(crate) fn timer_pass(&self, now_ns: u64) -> TimerActions;
```

`timer_pass` reads peer stamps + session age + `persistent_keepalive` and
computes T6/T7/T8 plus the next deadline. It performs no IO — the control
loop owns sends — so mock-clock unit tests drive it with synthetic `now_ns`
and hand-set stamps. `InitiateReason` feeds the per-reason counters (§5.3).

### 5.2 Control-loop conversion to poll(2) (#1889) + timer arm rewrite

```rust
const WG_POLL_CAP: Duration = Duration::from_millis(100);
const WG_TIMER_TICK_NS: u64 = 1_000_000_000; // timer pass granularity

// Deadline sentinel discipline (Codex r2 C3): u64::MAX = "no deadline";
// next_deadline initialized to 0 so the FIRST iteration always runs a
// pass and computes real deadlines. Every pass recomputes next_deadline
// from scratch (timer_pass + attempt state both return future-or-MAX
// values for inactive timers), so a stale past-deadline cannot survive a
// pass and produce a permanent 0-timeout poll loop.
let mut next_deadline: u64 = 0;
let mut last_timer_pass_ns: u64 = 0;

while !stop.load(Ordering::Relaxed) {
    let mut did_work = false;
    // --- socket burst, TUN burst: UNCHANGED (WG_RX_BURST drains) ---

    // --- timer arm (replaces the :261-283 re-init block) ---
    // Runs when the 1s tick elapses OR a computed deadline is due (AGY
    // r1 F3: gating on the tick alone lets a mid-tick deadline saturate
    // the poll timeout to 0 and busy-spin until the tick boundary).
    let tick_due = now - last_timer_pass_ns >= WG_TIMER_TICK_NS;
    if tick_due || now >= next_deadline {
        engine.expire_sessions(now);
        let actions = engine.timer_pass(now);
        attempt.drive(now, &actions, ...);   // see attempt machine below
        // keepalives: create_keepalive + wg_send_to toward
        // effective_endpoint (skip if none learned/configured).
        next_deadline = actions.next_deadline_ns.min(attempt.next_retry_ns);
        if tick_due {
            // AGY r2 A5: only tick-condition runs advance the 1s anchor;
            // frequent sub-second deadline runs must not starve the
            // periodic tick work.
            last_timer_pass_ns = now;
        }
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

**Post-msg2 key-confirmation keepalive (Codex r2 C4):** on
`consume_response` Ok the control loop immediately sends ONE keepalive
(stamped through `last_send_any_ns`, counted under `keepalives_tx_passive`).
Linux does exactly this (`receive.c`: keepalive after processing a
handshake response with no queued data) because the responder's fresh
session is UNCONFIRMED until it authenticates our first transport record —
without this, a handshake we initiated with nothing to send (e.g.
T8-no-session) leaves the peer's egress blackholed until our next send.

**Handshake attempt state machine** (AGY r1 F2 BLOCKER + F4; replaces the
bare `last_initiate_ns` thread-local). The v2 edge wiring had a starvation
hole: the rekey edge is consumed on the first initiation, and if that
datagram is lost while traffic then goes idle, the confirmed-session gate
blocks every retry until the session hard-expires at 180s.

```rust
struct HandshakeAttempt {
    started_ns: u64,            // attempt window start (T5 anchor)
    last_tx_ns: u64,            // last initiation send (T4 pacing anchor)
    reason: InitiateReason,     // counter attribution
    baseline_session: Option<u32>, // current session local_index at start
}
// thread-local: attempt: Option<HandshakeAttempt>
```

Starting an attempt also CONSUMES the T7 trigger stamp
(`peer.last_send_data_ns := 0`, AGY r2 A1 — see §3) so a give-up cannot
immediately re-trigger; the obligation lives in the attempt while one is
active, and only new egress data re-arms T7 afterward.

- **Start** a new attempt (if none active) from any §3 trigger class whose
  predicate passes: NoSession edge, rekey edge, T7, T8-no-session, or the
  configured-initiator unconfirmed-retry. Starting sends the first
  initiation immediately. The pre-loop bring-up initiation
  (wg_control.rs:160-166) IS an attempt start of the configured-initiator
  class (SMR r2 F2) so the 5s/90s discipline applies from packet one and
  boot does not double-fire.
- **While active:** retry `drive_initiation` every REKEY_TIMEOUT (5s),
  **bypassing `peer_has_confirmed_session`** — the attempt itself encodes
  the decision to replace the current session; losing one datagram no
  longer starves the rekey (AGY F2). The unconsumed-edge state is
  irrelevant during an active attempt.
- **End on success — IDENTITY check, no clock (Codex r2 C1 BLOCKER,
  subsumes SMR r2 F1):** at attempt start record
  `baseline_session = current session's local_index (or None)`; the
  attempt succeeds when the peer's current session's `local_index`
  differs from the baseline (or current became `Some`). `local_index` is
  unique per live session by the engine's collision-refusing installer
  (engine.rs `install_session_locked`), so ANY fresh install — our msg2
  completing, or the peer beating us with its own initiation — flips the
  identity regardless of clock-stamp ordering. (Both clock formulations,
  `>` and `>=`, were proven fragile across the publish seam: a fast msg2
  processed in the next burst installs with the previous published
  timestamp.) The resulting session may be responder-role and unconfirmed,
  which is correct — key-confirmation is an egress gate, the post-msg2
  keepalive (Codex C4) confirms the peer's side, and a NoSession edge
  re-arms if needed (SMR r2 F3).
- **End on give-up:** `now - started_ns >= REKEY_ATTEMPT_TIME` (90s) ⇒
  call `abort_pending_for_peer` (Codex r1 M5) and clear `attempt`. A LATER
  trigger (including the next T8 due-tick, AGY F4) starts a fresh window —
  give-up never permanently disables initiation.
- Thread respawn resets the machine; the first trigger re-starts it
  (benign, today's behavior).

Design points, mapped to #1889's stated constraints:

1. **Stop/join latency:** poll timeout is capped at 100ms regardless of the
   next timer deadline ⇒ `stop_remove_wg_control_entry` joins within
   ~100ms + one burst. No eventfd in the poll set (adjudicated in §11 Q2):
   stop sites are reconcile-time and rare; 100ms join is well inside the
   #1866/#1872 teardown budget and avoids a new fd lifecycle + a change to
   the shared `LocalTunnelSourceHandle` stop contract.
   **Honesty note (SMR F3):** with a 100ms cap and every §3 deadline ≥1s
   out, the idle timeout is effectively the constant cap — the
   `min(next_deadline, cap)` term only becomes load-bearing if the cap is
   ever raised (eventfd variant). The design is accurately described as
   "poll(…, 100ms) + 1s-throttled timer pass": ~10 wakeups/s/tunnel idle,
   a 100× reduction, not zero.
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
5. **POLLERR/POLLHUP/POLLNVAL discipline — fd-specific (Codex r1 M6):**
   a generic zero-progress exit guard could tombstone the thread on a
   transient UDP `POLLERR` (ICMP port-unreachable bursts are normal and
   already drained via the `recv_from` error arm at wg_control.rs:200).
   The fatal-exit guard covers: the TUN fd's `POLLERR`/`POLLNVAL`/
   `POLLHUP` revents (AGY r1 F8: inspect revents directly), N consecutive
   TUN-ready iterations whose reads all fail with a non-`WouldBlock` error
   (device destroyed under us), AND the UDP fd's `POLLNVAL` specifically
   (AGY r2 A3: NVAL means the fd is invalid/closed — poll returns
   instantly forever, a guaranteed 100% spin; nothing transient produces
   NVAL). Exit ⇒ the #1872 tombstone + backoff respawn machinery recovers
   (a transient operator link-down self-heals via respawn backoff). UDP
   `POLLERR`/`POLLHUP` never exit the thread; those errors surface through
   the existing per-read exception accounting.
7. **Multi-entry stop is signal-then-join (AGY r1 F7 + Codex r2 C5):** the
   stale-prune loop in `spawn_wg_control_threads`,
   `stop_all_wg_control_threads`, AND
   `prune_wg_control_threads_for_snapshot` (coordinator/mod.rs:952-970 —
   the third serial path Codex r2 found) currently stop+join one entry at
   a time; with a 100ms poll cap that serializes to N×~100ms. ONE shared
   bulk helper collects the affected entries, sets ALL their `stop` flags,
   then joins+removes — total stop latency ≈ one cap regardless of tunnel
   count. (`stop_remove_wg_control_entry` keeps its single-entry shape for
   the one-off callers.)
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

- `rekeys_initiated_age` (T1+T2 — session-age-driven), `rekeys_initiated_dead_peer`
  (T7), `rekeys_initiated_keepalive_no_session` (T8) — split by reason per
  Codex r1 Q7 + SMR F7: a fielded "tunnel re-handshakes too often" incident
  is undebuggable with a folded counter, and the wire is omitempty-additive.
- `sessions_expired` — T3 control-pass teardowns; the per-use refusals get
  their own drop counters `encap_drops_expired` / `decap_drops_expired`
  (new `DecapError::Expired` mapper arm keeps the mapping compile-total).
- `keepalives_tx_passive`, `keepalives_tx_persistent` — T6 / T8 sends.
  (RX side already exists: `decap_keepalives`.)
- `pending_aborted_attempt_window` — T5 give-up reservation releases
  (Codex r1 M5 visibility).

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
5. **No allocation on hot paths; no syscalls on AF_XDP worker paths.** v5:
   engine time is a per-use CLOCK_MONOTONIC vDSO read (`WgEngine::now_ns`,
   `#[cfg(test)]` mock override). In S2a no AF_XDP steady-state path calls
   it: decap is control-thread-only and the worker transit encap already
   heap-allocates per packet (frame/wg.rs precedent: it calls
   `monotonic_nanos()` today on the NoSession arm). **S3 flag:** if decap
   ever moves onto AF_XDP workers, `now_ns()` must convert to a published
   coarse clock WITH a hard publisher-cadence bound — record in the module
   doc (this is the AGY r1 F6 concern, deliberately deferred after Codex
   r2 C2 showed an unbounded publisher violates T3).
6. **Control-socket contention rule:** everything here runs in the
   per-tunnel control thread; zero new control-socket requests.
7. **Keepalives consume tx counters** (spec) and obey
   REJECT_AFTER_MESSAGES/T3 — `create_keepalive` goes through the same
   `encap_inner` gates.
8. **Endpoint-learning gate (:176-196) untouched** — keepalive/rekey sends
   target `effective_endpoint` exactly like data sends; no new
   endpoint-mutation site.
9. **Initiation predicates follow the §3 table** (SMR F1 replaced v1's
   blanket "responder-only peers never timer-initiate cold"): the bare
   unconfirmed-retry timer stays configured-endpoint-only (today's
   wg_control.rs:274 rule); edges and T7 may target a learned endpoint;
   T8-with-no-session may initiate toward a learned endpoint iff
   `persistent_keepalive > 0` — otherwise its NAT-pinhole purpose fails
   for exactly the peers that need it.
10. **eprintln discipline:** timer events log nothing per-tick; rekey/expiry
    are counter-visible, not journald-visible (rare one-line exceptions go
    through `record_local_tunnel_exception` as today).

## 8. Risk assessment

| Class | Level | Notes |
|-------|-------|-------|
| Behavioral regression | **MED** | (a) Sessions now die at 180s. Against an *old-xpf* peer (zero timers): if WE have its endpoint (configured or learned), our T1/T7/T8/NoSession initiations re-establish; but an idle tunnel where the old-xpf side is the only possible initiator and never re-initiates is **permanently blackholed after expiry** until its traffic triggers a NoSession edge on its side — AGY r1 F9: this is a rolling-upgrade ordering note for the release notes (upgrade both ends, or accept traffic-driven re-establishment). Spec-correct behavior. (b) Bring-up retry pacing 1s→5s. (c) Keepalives add ~32-byte datagrams on idle tunnels (the configured intent). Kernel-peer interop is exercised live by wg-interop.sh P1-P7. |
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
    90s; NoSession edge re-arms a fresh attempt window; **T5 give-up
    releases the pending reservation and a subsequently delivered valid
    msg2 is dropped as `NoPendingHandshake`** (Codex r1 M5 regression
    test).
  - T6: recv data then 10s with no send ⇒ passive keepalive; a sent
    keepalive OR a sent handshake initiation clears it; a *received
    keepalive* does NOT arm it (ping-pong guard); an
    **AllowedIPs-rejected but authenticated** data packet DOES arm it
    (Codex r1 M3 stamp-ordering test).
  - T7: send data then 15s of silence ⇒ initiate; an inbound keepalive OR
    an inbound valid handshake message clears it. **AGY r1 F1 regression
    trace:** send data on S1 → silence → T7 initiates → valid msg2 installs
    S2 → assert T7 does NOT re-fire on the next tick (the msg2 stamped
    `last_recv_any_ns`).
  - Attempt machine (AGY r1 F2/F4): rekey-edge attempt whose first
    initiation is "lost" (no msg2 delivered) retries at 5s with a confirmed
    session still installed; attempt ends at 90s with the pending
    reservation released; a subsequent T8 due-tick starts a fresh window.
  - Attempt success identity (Codex r2 C1): a fresh session installed
    immediately after attempt start (same-tick AND next-burst orderings)
    ends the attempt — no retry fires at +5s; works when the PEER's
    initiation (not ours) created the session.
  - T5 no-retrigger loop (AGY r2 A1): T7-triggered attempt → give-up at
    90s → assert NO new attempt starts on subsequent ticks without new
    egress data; a new data send re-arms T7 normally.
  - Post-msg2 keepalive (Codex r2 C4): `consume_response` Ok ⇒ exactly one
    keepalive emitted; two-engine rig asserts the responder side flips
    confirmed and its egress unblocks without any data packet.
  - T6 inbound-only stream (AGY r2 A4): continuous inbound data with zero
    egress ⇒ one keepalive per ~10s anchored on our last send (NOT
    suppressed by the ongoing receives).
  - T8: persistent_keepalive=N paces sends at N; reset by authenticated
    traversal in EITHER direction including handshake messages (Codex r1
    B1/B2 test: inbound-only transport traffic suppresses persistent
    keepalives); fires handshake when no session (including learned-only
    endpoint); `persistent_keepalive=0` ⇒ fully off.
  - T3 decap: expired-session inbound is dropped WITHOUT arming the rekey
    edge (Codex r1 M4 — replay-at-expired-session must not drive handshake
    cadence).
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
  - TUN-fatal guard: erroring/closed TUN-side fd ⇒ thread exits within the
    bounded spin count (no busy loop); a UDP-side transient error does NOT
    exit the thread; a UDP-side `POLLNVAL` DOES exit (AGY r2 A3).
  - Mid-tick deadline (AGY r1 F3): a deadline landing between ticks must
    not produce a zero-timeout spin window (assert the timer pass runs and
    the recomputed timeout is positive).
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
- **Handshake-retransmit + T7 jitter (≤333ms)** — documented deviation for
  BOTH T4 and T7 (Codex r1 m8: wireguard-go jitters both); sub-granularity
  at our 1s tick and pointless at single-digit tunnel counts.
- **Narrowing `wg_keepalive_secs` out of the engine identity tuple** (SMR
  F5): today a keepalive-interval-only config change rebuilds the engine and
  drops live sessions (forwarding_build/wg.rs:93); `Peer::update_config`
  could absorb it in place. Pre-existing behavior; candidate follow-up
  issue, not this lane.
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

1. **T3 enforcement locus — RE-CLOSED in v5.** Exact per-use gate inside
   `try_encap`/`try_decap` (Codex r1 M7) reading CLOCK_MONOTONIC per use.
   The v3 cached-clock half of the synthesis was REVERSED by Codex r2 C2
   (no publisher cadence hard-bounds staleness when the control thread
   stalls; workers must never send past REJECT_AFTER_TIME); deterministic
   tests use a `#[cfg(test)]` mock override instead. r3/AGY: this
   deliberately un-does your r1 F6 cached-clock fix for the ENFORCEMENT
   reads — object only with a trace where the vDSO read on the
   control-thread/transit paths is a real cost.
2. **Stop wakeup — CLOSED:** 100ms cap, no eventfd (Codex Q2 + AGY Q2
   concurred), PLUS one bulk signal-then-join helper across all THREE
   multi-entry stop paths (AGY r1 F7 + Codex r2 C5) so reload latency is
   ~one cap, not N×cap.
3. **Stamp placement — CLOSED in round 2.** AGY r2 attested its r1 F1
   RESOLVED with the v3 handshake-traversal stamps and did not produce a
   new mis-fire trace; Codex r2 attested B1/B2 RESOLVED against Linux
   timers.c/send.c/receive.c. Peer placement stands (WgSession placement
   would zero stamps on rekey — dropped T6 obligation, distorted T8
   pacing).
4. **Initiation pacing 1s → REKEY_TIMEOUT (5s) + REKEY_ATTEMPT_TIME (90s)
   give-up.** Spec-correct but slows worst-case bring-up retry. Keep today's
   1s instead (spec deviation), or adopt spec pacing? Plan adopts spec.
5. **T7 (15s no-reply reinit) in scope?** It is the rule that actually
   repairs the #1868 confirmed-but-dead blackhole *without* peer
   cooperation. Plan includes it; killing it shrinks the diff but leaves
   dead-session detection to T3 expiry (up to 180s of blackhole).
6. **Expired-decap error shape — CLOSED in v2.** New `DecapError::Expired`
   variant (Codex Q6 + SMR Q6 converged); the counters mapper makes it a
   compile-time-complete change.
7. **Counter granularity — CLOSED in v2.** Split by reason
   (`rekeys_initiated_{age,dead_peer,keepalive_no_session}`) per Codex Q7;
   SMR concurred once attribution existed in `TimerActions`.
8. **(NEW, v2) T8 traversal-pacing fidelity.** v2 paces persistent
   keepalive on any authenticated traversal (either direction, incl.
   handshakes) per wireguard-go. The whitepaper's own §6.1 text is terser
   ("a keepalive is sent every N seconds, when there is no other traffic").
   Is max(send_any, recv_any) the right reading, or should T8 pace on sends
   only (kernel behavior reading welcome)? Codex r1 B1 says traversal;
   counter-evidence with a kernel-source citation would reopen it.
9. **(NEW, v2) handshake-stamp sites.** v2 stamps `last_send_any_ns` at
   call-site send-success for handshake messages and `last_recv_any_ns` in
   the engine consume wrappers. Asymmetric (send at IO site, recv at engine
   site) but matches where authentication is actually known. Cleaner
   alternative welcome.
