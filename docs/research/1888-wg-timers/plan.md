# Plan: #1888 WireGuard timers (rekey / expiry / keepalive) + #1889 wg_control blocking poll(2)

**Status: DRAFT v9 — round-6 fold. AGY r5: PLAN-READY (zero new findings). Codex r6: r5 t7_arm ordering RESOLVED; the SAME after-bursts hazard applied to the success edge-drain in the peer-initiated case (unconfirmed responder session → legitimate same-iteration NoSession edge) — v9 moves ALL success-side cleanup inline to the authenticated completion site; `attempt.drive` success now only clears `attempt`. Pending final Codex confirm + AGY delta-attest.**

v8 (round-5 fold): success/give-up boundary split in the attempt
machine ("Attempt-boundary state hygiene" bullet) + §9 regression test
for post-completion same-iteration egress retaining its T7 arm.
v9 (round-6 fold): success-side edge drain relocated from
`attempt.drive` to the completion site (Codex r6 — the responder-role
peer-beat-us trace); give-up cleanup unchanged.

v7 (round-4 fold — attempt-boundary state hygiene):
- Codex r4 F3 MAJOR: §5.2 loop sketch now calls
  `engine.timer_pass(now, endpoint_known)` with `endpoint_known =
  effective_endpoint.is_some()` computed in the loop, and the mutation
  locus is explicit: `timer_pass` is READ-ONLY; the loop reports send
  outcomes (success stamps via `encap_inner`; skip/fail calls
  `pace_keepalive_skip(now)`).
- AGY r4 H1 MAJOR: T5 GIVE-UP also clears `t7_arm` (not just attempt
  start) — egress data sent DURING the active attempt re-arms T7 via
  `try_encap`'s unconditional CAS, and without the give-up clear that
  stale arm immediately reopens a fresh 90s window, recreating the A1
  loop. wireguard-go parity: give-up zeroes the timers; only data sent
  AFTER give-up re-triggers.
- AGY r4 H2 MINOR: attempt END (success or give-up) also drains both
  request edges (`take_rekey_request` + `take_handshake_request`) —
  during-attempt sends on the stale session keep re-arming the rekey
  edge, and an undrained edge would fire a second handshake against the
  brand-new session immediately after success.
- AGY r4 H3 NIT: `t8_last_attempt_ns` added to the §5.1 `Peer` additions
  (it must be engine-visible — `timer_pass` reads it for T8 due-ness and
  skip-pacing).

v6 (round-3 fold — ARMED-TIMER model for T6/T7 + skip-pacing):
- Codex r3 F1 BLOCKER: T7 was modeled on the LATEST data send, so
  continuous outbound-only traffic refreshes the stamp every packet and
  the 15s threshold never accrues — the dead-peer repair never fires and
  the blackhole lasts until T3. v6 replaces `last_send_data_ns` with
  **`t7_armed_send_ns`** (Linux pending-timer parity, timers.c:147/:176):
  SET only when unarmed (CAS from 0) on a successful non-empty data
  encap; CLEARED (0) by any authenticated receive and by attempt start
  (the AGY r2 A1 consumption, unchanged in spirit); T7 fires when
  `armed != 0 && now − armed ≥ 15s`.
- Codex r3 F2 MINOR: T6 gets the same armed model —
  **`t6_armed_recv_ns`**: SET when unarmed on an authenticated,
  replay-accepted, non-empty data receive (pre-AllowedIPs, Codex r1 M3
  unchanged); CLEARED by any authenticated send; fires when
  `armed != 0 && now − armed ≥ 10s`. This restores the kernel's
  receive-time+10s first-fire (the v5 send-anchored predicate could fire
  immediately on the first inbound packet after long idle) while keeping
  AGY r2 A4's inbound-only-stream behavior (keepalive every ~10s: each
  fire's own send clears, the next inbound re-arms).
- AGY r3 G1 MAJOR (skip-pacing rule): any due action that CANNOT act
  must advance its pacing anchor so its next deadline is strictly
  future — a fired T6/T8 with no endpoint (or a failed send) re-arms
  to `now`; `timer_pass` emits NO initiation deadlines for peers whose
  §3 endpoint predicate fails. Without this, the recomputed deadline
  stays in the past and the loop spins at timeout 0.
- AGY r3 G2 MINOR: attempt success is
  `current.is_some() && current_index != baseline` — a mid-attempt
  `expire_sessions` clearing current to `None` must NOT read as success
  (the attempt keeps retrying; we WANT a session).
- AGY r3 G3 NIT: poll timeout sketch converts ns→ms explicitly before
  clamping to the cap.

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
| T6 | KEEPALIVE_TIMEOUT (passive keepalive) | 10s | After **receiving** a data message, if we have **sent nothing** (any authenticated packet) within 10s. v6 predicate: armed timer `t6_armed_recv_ns` (see stamp table — set-if-unarmed on data receive, cleared by any authenticated send, fires at armed+10s). Kernel-faithful first-fire at receive+10s; emits one keepalive per ~10s under an inbound-only stream (AGY r2 A4 behavior, Codex r3 F2 timing) | Both roles | Send a keepalive (authenticated empty transport message) | Timer pass, 1s granularity |
| T7 | No-reply reinit ("suspect dead session") | KEEPALIVE_TIMEOUT + REKEY_TIMEOUT = 15s (+ jitter ≤ 333ms in spec/wireguard-go — **omitted**, documented deviation like T4) | After **sending** a transport data message, if we have **received no authenticated packet** (data, keepalive, or valid handshake message) within 15s. v6 predicate: armed timer `t7_armed_send_ns` (set-if-unarmed on data send, cleared by any authenticated receive or attempt start, fires at armed+15s — Codex r3 F1: a latest-send stamp would be refreshed by continuous outbound traffic and never fire, leaving the blackhole until T3) | Either side may detect | Initiate new handshake | Timer pass, 1s granularity. This is the rule that makes the #1868 P6 no-flush branch obsolete-but-harmless |
| T8 | persistent_keepalive | configured per peer (0 = off) | Every N seconds, if there has been **no authenticated packet traversal in EITHER direction** within N seconds (wireguard-go `timersAnyAuthenticatedPacketTraversal` — sent OR received, transport OR handshake, resets the pacing; Codex r2 confirmed against Linux `timers.c:215-219`) | Both roles | Send a keepalive; if no **usable** session exists, initiate a handshake (NAT pinhole maintenance is the whole point). **"Usable" DEFINED (AGY r2 A2): confirmed AND unexpired** — an unconfirmed responder-role current session is NOT usable (its keepalive would silently fail `try_encap`'s confirmed gate), so T8 initiates | Timer pass, 1s granularity |
| T9 | Session-state zeroing | REJECT_AFTER_TIME × 3 = 540s | No successful handshake for 540s | Both | Zero all session state | Collapses into T3: we tear down (drop) sessions at 180s, which zeroizes via `Zeroizing`/drop semantics earlier than the spec requires. Pending-handshake state is already bounded (at-most-one-per-peer) and aborted/replaced on each new attempt |

**Activity-stamp semantics** (which packets feed which timers — this is
where naive implementations get T6/T7/T8 wrong). The stamp set mirrors
wireguard-go's timer events: `timersDataSent`/`timersDataReceived` (transport
data only) and `timersAnyAuthenticatedPacketSent`/`...Received`/`...Traversal`
(transport data, keepalives, AND authenticated handshake messages — Codex r1
B1/B2 corrected v1, which omitted handshake traffic entirely):

- `t7_armed_send_ns` — **armed timer, not a latest-stamp** (Codex r3 F1
  BLOCKER: a latest-send stamp is refreshed by every outbound packet, so
  continuous outbound-only traffic suppresses the 15s dead-peer reinit
  forever; Linux arms its new-handshake timer only `if !pending`,
  timers.c:147, and clears it on authenticated receive, timers.c:176).
  SET to now only when currently 0, on a successful **non-empty** data
  encap (a sent keepalive or handshake does NOT arm it). CLEARED (0) by
  any authenticated receive AND by attempt start (AGY r2 A1: the T7
  obligation transfers to the attempt machine; a T5 give-up must not
  re-trigger without NEW egress data). T7 fires when
  `armed != 0 && now − armed ≥ 15s`.
- `t6_armed_recv_ns` — armed timer, same model (Codex r3 F2): SET to now
  only when currently 0, on an **authenticated, replay-accepted,
  non-empty** transport plaintext — stamped immediately after the
  replay-window accept with `n > 0`, **before** the inner-parse/AllowedIPs
  gates (Codex r1 M3: an AllowedIPs-rejected packet still proves the peer
  is alive on this session). A received keepalive does NOT arm it (no
  keepalive ping-pong). CLEARED by any authenticated send. T6 fires when
  `armed != 0 && now − armed ≥ 10s` — the kernel's receive-time+10s
  first-fire (the earlier send-anchored predicate could fire instantly on
  the first inbound packet after long idle); under an inbound-only stream
  each fire's own keepalive send clears the arm and the next inbound
  re-arms ⇒ one keepalive per ~10s (AGY r2 A4 behavior preserved).
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

**`Peer` additions** (`wg/peer.rs`) — the §3 stamp set, all relaxed
`AtomicU64`, 0 = never/unarmed (armed timers SET via CAS-from-0 so a
concurrent stamp cannot push an armed deadline forward):

```rust
pub(crate) last_send_any_ns:   AtomicU64, // any authenticated send (T8 pacing, clears t6 arm)
pub(crate) last_recv_any_ns:   AtomicU64, // any authenticated receive (T8 pacing, clears t7 arm)
pub(crate) t6_armed_send_keepalive_ns: AtomicU64, // t6_armed_recv_ns in §3
pub(crate) t7_armed_reinit_ns:         AtomicU64, // t7_armed_send_ns in §3
pub(crate) t8_last_attempt_ns:         AtomicU64, // T8 skip/fail pacing anchor (AGY r4 H3)
```

(Field names final at engineer phase; semantics are §3's.)

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
// on success: peer.last_send_any_ns.store(now_ns);
//             peer.t6_arm.store(0)  (any authenticated send clears T6);
//             if inner non-empty: peer.t7_arm CAS(0 -> now_ns)  (arm-if-unarmed)
```

`try_decap`: T3 gate before AEAD — **drop + count ONLY, no rekey arm**
(Codex r1 M4: wireguard-go's receive path drops expired keypairs and leaves
initiation to the send side; an attacker replaying old ciphertext at an
expired session must not be able to drive our handshake cadence). T2 arm
after successful authentication on an initiator-role session; on a
non-empty authenticated record, `t6_arm CAS(0 → now)` post-replay-accept,
pre-AllowedIPs (§3); `last_recv_any_ns` stamped + `t7_arm := 0` in the
non-empty success path, the keepalive arm (with its own `peer_arc`
lookup), and the handshake-consume wrappers. Ordering note: the encap T3 gate
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
pub(crate) fn timer_pass(&self, now_ns: u64, endpoint_known: bool) -> TimerActions;
```

`endpoint_known` is passed by the control loop (SMR r3: the LEARNED
endpoint is control-thread-local `effective_endpoint` state — the engine
only knows the CONFIGURED endpoint, so it cannot evaluate the §3 endpoint
predicates alone). With `endpoint_known == false`, `timer_pass` emits no
initiation or keepalive deadlines at all (AGY r3 G1(b)).

`timer_pass` reads peer stamps + session age + `persistent_keepalive` and
computes T6/T7/T8 plus the next deadline. It performs no IO — the control
loop owns sends — so mock-clock unit tests drive it with synthetic `now_ns`
and hand-set stamps. `InitiateReason` feeds the per-reason counters (§5.3).

### 5.2 Control-loop conversion to poll(2) (#1889) + timer arm rewrite

```rust
const WG_POLL_CAP_MS: i32 = 100;             // poll(2) timeout cap
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
        // endpoint_known: configured OR learned (effective_endpoint is
        // control-thread-local state — Codex r4 F3 call-path fix).
        let endpoint_known = effective_endpoint.is_some();
        let actions = engine.timer_pass(now, endpoint_known);
        attempt.drive(now, &actions, ...);   // see attempt machine below
        // keepalives: create_keepalive + wg_send_to toward
        // effective_endpoint. timer_pass is READ-ONLY (mutation locus,
        // Codex r4 F3): only the loop knows the send outcome —
        //   - send OK: encap_inner already stamped last_send_any and
        //     cleared the t6 arm (nothing else to do);
        //   - send FAILED or skipped: loop calls
        //     engine.pace_keepalive_skip(now) → t6_arm := now + advance
        //     the t8 pacing anchor, so the recomputed deadline is
        //     strictly future (AGY r3 G1(a)).
        next_deadline = actions.next_deadline_ns.min(attempt.next_retry_ns);
        if tick_due {
            // AGY r2 A5: only tick-condition runs advance the 1s anchor;
            // frequent sub-second deadline runs must not starve the
            // periodic tick work.
            last_timer_pass_ns = now;
        }
    }

    if !did_work {
        // AGY r3 G3: explicit ns→ms conversion before clamping to the cap.
        let timeout_ms =
            ((next_deadline.saturating_sub(now) / 1_000_000).min(WG_POLL_CAP_MS as u64)) as i32;
        // libc::poll over [socket_fd: POLLIN, tun_fd: POLLIN]
        match poll(&mut fds, timeout_ms) {
            -1 if errno == EINTR => continue,
            ...
        }
    }
}
```

**Skip-pacing rule (AGY r3 G1 MAJOR):** any due action that CANNOT act
must advance its own pacing anchor, or the recomputed deadline stays in
the past and the loop spins at timeout 0. Concretely: (a) a fired T6/T8
keepalive with no configured-or-learned endpoint, or whose socket send
fails, re-arms its anchor to `now` (`t6_arm := now`; T8 paces on a
`t8_last_attempt_ns` that advances on skip/fail too); (b) `timer_pass`
emits NO initiation deadline for a peer whose §3 endpoint predicate
fails (an endpoint-less peer has no actionable initiation timer at all);
(c) a `drive_initiation` whose send fails still advances
`attempt.last_tx_ns` (the existing exception/`hs_send_errors` accounting
covers visibility — today's behavior, wg_control.rs:439-447).

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

Starting an attempt also CONSUMES the T7 arm (`peer.t7_arm := 0`, AGY r2
A1 — see §3) so a give-up cannot immediately re-trigger; the obligation
lives in the attempt while one is active, and only new egress data re-arms
T7 afterward.

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
  attempt succeeds when `current.is_some() && current_index !=
  baseline_session` (AGY r3 G2: the `is_some()` clause is REQUIRED — a
  mid-attempt `expire_sessions` clearing current to `None` must not read
  as success; the attempt keeps retrying, since a session is exactly what
  it exists to obtain). `local_index` is
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
- **Attempt-boundary state hygiene (AGY r4 H1+H2, ordering corrected per
  Codex r5):** the two end paths differ —
  - **Give-up:** clear `t7_arm` AND drain both request edges
    (`take_rekey_request`, `take_handshake_request`). During the 90s
    window, egress on the stale-but-unexpired session keeps CAS-arming T7
    and re-arming the rekey edge; carried across the boundary, the stale
    arm would reopen a fresh window the very next tick (recreating the A1
    loop). Only traffic AFTER give-up may re-trigger — wireguard-go
    zeroes its timers at give-up the same way.
  - **Success:** `attempt.drive` ONLY clears `attempt` — no stamp or
    edge mutation at all (Codex r5 + r6: `attempt.drive` runs AFTER the
    bursts, so ANY cleanup there can erase legitimate post-completion
    state from the same iteration). ALL success-side cleanup happens
    inline at the authenticated completion site (the control loop's
    `consume_response` / `consume_initiation_create_response` Ok
    handling, which orders BEFORE the TUN burst): the §3
    any-authenticated-receive rule clears the stale `t7_arm`, and the
    completion handling drains both request edges right there. Two
    traces this ordering protects (both verified by Codex):
    (a) msg2 installs S2 in the socket burst → queued TUN egress arms T7
    on S2 → an `attempt.drive` clear would lose that 15s dead-peer
    detection; (b) the PEER's msg1 installs an unconfirmed
    responder-role S2 → same-iteration TUN egress hits the unconfirmed
    gate (`NoSession`) and legitimately arms the handshake-request
    edge → an `attempt.drive` drain would erase it (bounded loss — the
    1/s rate-limited edge re-arms on the next egress packet — but the
    cleanup pattern is wrong). Linux/wireguard-go do handshake-complete
    timer cleanup in the receive path, before later data-send arming —
    same split. Inline draining at completion is safe in the no-attempt
    case too (peer-driven rekey): any pre-completion edge is obsoleted by
    the completion itself, and post-completion egress re-arms within the
    rate limit if the fresh session is unconfirmed.
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
    egress ⇒ one keepalive per ~10s (armed at first unanswered receive,
    cleared by each fire's own send, re-armed by the next inbound — NOT
    suppressed by the ongoing receives).
  - T6 first-fire timing (Codex r3 F2): inbound data after long idle ⇒
    keepalive at receive+10s, NOT immediately.
  - T7 outbound-only stream (Codex r3 F1 BLOCKER regression): continuous
    outbound data with ZERO inbound ⇒ T7 fires at armed+15s (the armed
    stamp is NOT refreshed by subsequent sends).
  - Skip-pacing (AGY r3 G1): T6/T8 due with no endpoint ⇒ no
    zero-timeout spin (anchor advances; deadline strictly future).
  - Expiry mid-attempt (AGY r3 G2): `expire_sessions` clears current
    during an active attempt ⇒ attempt does NOT declare success and keeps
    retrying.
  - Attempt-boundary hygiene (AGY r4 H1/H2): egress data sent DURING an
    active attempt, then give-up ⇒ NO new attempt on the next tick (t7
    arm cleared at give-up); attempt success with a re-armed rekey edge ⇒
    NO second handshake against the fresh session (stale edges drained
    inline at the completion site, v9).
  - Success-boundary ordering (Codex r5): msg2 completes in the socket
    burst, post-completion data egresses on the fresh session in the SAME
    iteration ⇒ that data's T7 arm SURVIVES the attempt-success cleanup
    (and fires at +15s if the peer goes silent).
  - Responder-success edge survival (Codex r6): the PEER's msg1 installs
    an unconfirmed responder session mid-attempt; same-iteration TUN
    egress arms the NoSession edge ⇒ that edge SURVIVES attempt success
    (the completion-site drain ran before the TUN burst, `attempt.drive`
    touches nothing).
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
