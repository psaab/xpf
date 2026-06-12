# Claude SMR hostile plan review — round 1

Plan: `docs/research/1888-wg-timers/plan.md` (DRAFT v1, commit ab54caa59)
Reviewer stance: domain SMR (WireGuard protocol + Rust concurrency + event-loop
design), hostile. Findings verified against worktree code, not the plan's own
prose.

## Findings

**F1 (MAJOR) — §7 invariant 9 contradicts T8's initiate-when-no-session rule.**
Invariant 9 says "responder-only peers never timer-initiate cold ... T7/T8 ...
re-initiation toward a *learned* endpoint is allowed exactly where `requested`
initiation is allowed today." But T8 (§3) says persistent-keepalive with no
usable session ⇒ *initiate a handshake*. For a responder-only peer with a
LEARNED endpoint and `persistent_keepalive` configured, T8 must initiate on
the bare timer — that is not "exactly where `requested` is allowed today"
(today `allow_timer = peer_endpoint.is_some() && timer_due`, wg_control.rs:274,
explicitly excludes learned-only endpoints from timer-driven initiation). The
plan must state the precise new initiation predicate per trigger class:
(a) NoSession/rekey edges → configured OR learned endpoint (today's `requested`
rule); (b) bare unconfirmed-retry timer → configured only (today's rule);
(c) T8 keepalive-due with no session → configured OR learned IFF
persistent_keepalive > 0. Without (c) spelled out, NAT pinhole maintenance —
the stated point of T8 — silently fails for the learned-endpoint case.

**F2 (MAJOR) — edge-consume wiring is under-specified and the confirmed-gate
bypass is load-bearing.** Today's drive gate is
`(requested || allow_timer) && !engine.peer_has_confirmed_session(&pk)`
(wg_control.rs:275). The T1/T2/T3 rekey edge MUST bypass the
`!peer_has_confirmed_session` clause (a 120s-old confirmed session is exactly
the thing being replaced), while the plain NoSession edge must KEEP it (else
every transient `encap_drops_unconfirmed` blip re-initiates against a live
confirmed session). §5.2's sketch says "rekey edge bypasses the gate" in a
comment, but the plan needs the explicit two-edge truth table:
`take_handshake_request` → gated on unconfirmed; `take_rekey_request` →
ungated (paced by T4 only). Also specify what happens to a consumed rekey
edge when no endpoint is known: the edge is consumed and dropped — fine,
because any subsequent send on the stale session re-arms it (try_encap arms
unconditionally past the age threshold) — but say so, or a reviewer will
flag a lost-edge bug.

**F3 (MEDIUM) — with a 100ms cap, the `min(next_deadline, cap)` computation is
vestigial and the plan oversells it.** All §3 deadlines are ≥1s away in
steady state, and the timer tick is 1s, so the idle poll timeout is the
constant 100ms cap essentially always. That is fine (10 wakeups/s, 100×
reduction) but the plan should say plainly: the deadline term only matters if
the cap is ever raised (e.g. eventfd variant), and today's design is
"poll(…, 100ms) + 1s-throttled timer pass". Honesty fix, not a design change.

**F4 (MEDIUM) — keepalive RX stamp site precedes the peer lookup.**
`try_decap`'s keepalive arm returns early at engine.rs:958-961 (n == 0 →
bump `decap_keepalives`, return `Err(MalformedInner)`) BEFORE the
`load_table()` peer lookup. `last_recv_any_ns` (clears T7 — the keepalive's
entire protocol purpose) must be stamped in that arm, which therefore needs
its own `peer_arc(&session.peer_pubkey)` lookup (slow path, acceptable). The
plan's §5.1 "stamps at the existing success/keepalive sites" hand-waves this;
make the lookup explicit so the engineer phase doesn't stamp only the
success path and silently break T7-clearing for keepalive-only reverse
traffic.

**F5 (MINOR) — `wg_keepalive_secs` is part of the identity tuple
(forwarding_build/wg.rs:93), so an operator changing ONLY the keepalive
interval rebuilds the engine and drops live sessions.** Pre-existing behavior,
out of scope to change, but the plan should note it under §4 or §10: T8
testing must not assume an in-place interval change, and `Peer::update_config`
keepalive plumbing remains dead until someone narrows the identity tuple
(possible follow-up issue).

**F6 (MINOR) — `rekey_request_pending` is per-engine, not per-peer.** Correct
for S2a's single-peer engines, wrong shape for #1434 multi-peer. The plan
should add it to §10 with the same "S6 owns it" framing the existing
`handshake_request_pending` edge uses (engine.rs:319 doc).

**F7 (MINOR) — `timer_pass` returning `initiate: bool` is too coarse for the
§5.3 counters.** `rekeys_initiated` vs T7-reinit vs T8-no-session-initiate
attribution needs a reason enum on the action (or fold all into
`rekeys_initiated` as §5.3 proposes — then say the bool is deliberately
reason-free). Pick one in the revision.

**F8 (checked, no finding) — expiry vs in-flight rekey race.** `expire_sessions`
under `reconcile_lock` serializes against `consume_response_inner` (which
holds the lock across validate→read→install, handshake_session.rs:360) and
`install_session`. A msg2 landing concurrently with expiry either completes
first (fresh `created_ns`, not expired) or installs after the old current was
expired (rotation handles a `None` current). Pending reservations are
untouched by expiry. The demux-drain mirrors reconcile's removal pattern. No
orphan window found.

**F9 (checked, no finding) — stamp placement on Peer.** Constructed the
candidate mis-fire: rekey at t=120 rotates sessions; `last_recv_data_ns` from
the OLD session (t=119) arms T6 against the NEW session — sending a keepalive
on the new session within 10s. That is spec-correct behavior (wireguard-go
keeps all timers on the peer precisely so cross-rekey continuity holds; the
peer-level "we received data recently and sent nothing" fact is what T6
encodes). No counter-example survives.

## §11 answers

- Q1: exact-in-engine — YES (decap is control-thread-only in S2a; one vDSO
  read on already-non-hot paths; §7.5's S3 flag is the right escape hatch).
- Q2: cap-only — YES; with F3's honesty fix. Serial joins ≤ ~100ms × N,
  N single-digit, reconcile-time only.
- Q3: Peer for activity stamps, Session for age/role — YES (F9).
- Q4: adopt spec pacing (5s/90s) — YES; bring-up latency is unchanged for the
  FIRST attempt (immediate), only retries slow.
- Q5: keep T7 — YES; it is the actual #1868 repair and costs two stamps.
- Q6: new `DecapError::Expired` variant — YES; the mapper makes it total.
- Q7: fold `rekeys_initiated` — YES, with F7's attribution decision recorded.

## Verdict

**PLAN-NEEDS-REVISION** — the architecture (engine-resident timer state,
event-driven T1/T2/T3 at use sites, 1s timer pass, 100ms-capped poll) is
sound and survives the races I constructed (F8, F9), but F1 and F2 are
real semantic gaps in the initiation predicate / edge wiring that would
produce wrong behavior if implemented as literally written, and F3/F4
need honest/explicit treatment before the plan is the source of truth.
