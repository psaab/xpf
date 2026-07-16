# Claude SMR — plan review r1 (#5865)

Reviewing `plan.md` v1 @ `9238c85010c8`. Hostile pass — looking for what is
wrong, not confirming what is right.

## Verdict: REVISE (3 precision folds), then PLAN-READY

The recommendation (Option B + golden parity test, Option C as follow-up) is the
right altitude and the mixed-version rebuttal (Section 10) is the strongest and
most load-bearing insight in the plan — and it is correct. But three claims are
either over-sold or under-verified and must be tightened before PLAN-READY.

## Findings

### F1 (fold into Section 3 + Q1) — the steady-state claim is now VERIFIABLE, and the generation guard does NOT save us

The plan hedges the steady-state downgrade as "very likely." I traced the
deciding mechanism the plan left open:

- `push_session_delta` (`umem/mod.rs:1325`) pushes into `pending_session_deltas`
  **unconditionally** (capacity-gated only); the binary stream uses a **separate**
  queue, so `pending_session_deltas` is drained **only** by the JSON
  `drain_session_deltas` RPC.
- The daemon runs that drain **every 5 s even while the stream is connected**
  (`daemon_ha_userspace_stream.go:289-311`).
- Each `QueueSessionV4` draws a **fresh strictly-monotonic install generation**
  (`sync_conn.go:66 nextInstallGen`). The peer's `installGenGuardV4`
  (`sync_conn.go:196,385`) refuses only a **STRICTLY-OLDER** generation.

Therefore the reconcile's degraded re-sync carries a **newer** generation than
the original binary-path sync → the guard **applies it** → the degraded value
(PolicyID=0 / AppTimeout=0 / no Nat64SnatV4) **overwrites the good one on the
peer**. The #2170 generation guard does not prevent this; it guarantees the
later (degraded) install wins. The plan must name this mechanism and state the
conclusion: the degradation is **steady-state**, not fallback-only, unless a
test shows `pending_session_deltas` is empty in practice at the 5 s tick. This
is a factual sharpening the plan currently leaves as a soft "very likely."

### F2 (fold into Section 9) — Option E does NOT structurally prevent drift; do not over-sell it

The plan sells the golden parity test as capturing "most of Option A's
drift-prevention." That is too generous. The binary frame has **no keys** — it is
a fixed-offset byte buffer — so any "field-set superset" test requires a
**manually-maintained canonical field list**. That list is itself a drift
surface: add a 6th binary field, forget the list, the test still passes. The
test moves the drift from "two structs" to "one struct + one list" and makes the
failure **louder** (a red test when someone updates the list), but it does **not**
make drift structurally impossible the way codegen (Option A) would. The plan
should say this honestly: B+E *reduces* the drift class and adds a build-time
tripwire; only A *eliminates* it. This does not change the recommendation (A is
still over-engineering for 5 stable fields), but the plan must not claim a
guarantee it doesn't provide.

### F3 (fold into Section 7) — "no Go change" is imprecise

Section 7 says "No Go change for the core fix," but Section 9's golden round-trip
test is a Go (test-only) change. Clarify: **no Go production change; the parity
guard adds a Go test.** Pedantic but the plan should be exact about blast radius.

### Non-blocking observations (note, don't gate)

- **N1 — second JSON surface.** `SessionDeltaInfo` is shared with the
  observability-only `recent_session_deltas` `show` buffer. Option B's fields
  will also appear in `show system ... session deltas` output — a harmless free
  win, but the plan should note it so a reviewer isn't surprised the CLI output
  changes.
- **N2 — `nat64` bool utility.** The Go convert path marks NAT64 off a non-empty
  `Nat64SnatV4`, not the `Nat64` bool. Mirroring the bool is defensible for
  parity/field-set-equality, but the plan should state `Nat64SnatV4` is the
  load-bearing datum and `Nat64` is a redundant marker (so a reviewer doesn't
  read the bool as functionally required).
- **N3 — literal "fail closed at runtime."** The issue asks to "fail closed
  rather than silently zeroing." The plan substitutes a build-time test for a
  runtime handshake, justified by same-version IPC. Sound, but note the residual:
  if the parity test is not run/updated, a degraded session still installs
  silently — there is no runtime tripwire. Acceptable given same-version IPC, but
  the plan should acknowledge the residual explicitly rather than imply the
  issue's requirement is fully met.

## What I did NOT find wrong (and stress-tested)

- **Option B completeness end-to-end.** Verified: Go `SessionDeltaInfo` has all
  five fields with matching tags; convert stamps them; the cluster wire already
  length-gates them. The only missing link really is the Rust struct + producer.
- **Units.** `app_timeout` seconds and `nat64_snat_v4` from `rewrite_src` match
  the binary encoder (`session_sync.rs:163-182`). The plan's conversion is right.
- **Mixed-version rebuttal.** Same-host same-version IPC is real and already
  relied upon by the binary path (`session_sync.rs:108-115`). The node→node wire
  already handles compatibility via length-gating. The rebuttal holds; I could
  not construct a reachable mixed-version helper↔daemon scenario given the #1917
  restart discipline.
- **PLAN-KILL.** Not viable — the fallback is load-bearing (reconnect polling +
  FullResync export + no-event-stream DP path).

## Required for PLAN-READY

Fold F1, F2, F3 into plan v2. The open questions Q1 (now largely answered by F1 —
restate as "confirm via test at /engineer") and Q2 (export re-emit fidelity)
remain legitimate /engineer-phase verification items, not plan blockers.
