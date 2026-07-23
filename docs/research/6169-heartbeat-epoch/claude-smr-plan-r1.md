# Claude SMR — hostile plan review, #6169 boot-epoch, round 1

Reviewer stance: HOSTILE. Goal is to fail the plan if the architecture is wrong
or any of the five findings is not actually closed. Verified against
`origin/master` @ `11e23b49a` + the closed PR #6370 diff.

## What holds up under attack

- **Path A dissolves F1 (verified by tracing both directions).** An
  `origin/master` keyed **v1** receiver decoding a Path-A frame: the tail is the
  **unchanged** `"XPFA"` 52-byte trailer, so `heartbeatAuthTrailer` finds the
  magic at `len-52`, `verifyHeartbeatMAC` recomputes over `data[:len-32]` (=
  body-incl-epoch + `XPFA`+session+counter — exactly what the sender signed) →
  **passes**, `admit()` runs on the same session/counter, and
  `UnmarshalHeartbeat` returns right after `HAProtocolVersion` (confirmed: it
  does not read past the version section, and there is exactly **one** non-test
  caller, `readLoop:796`) → the extra 8 body bytes are ignored. Reverse
  direction (Path-A receiver, v1 sender): `hasEpoch=false`, `sawEpoch` not yet
  latched → accept. **No split. Unconditional keyed emit is safe.** This is a
  genuinely better result than PR #6370 and than a capability-gated v2 trailer.
- **Path A dissolves F5.** There is only one auth-trailer format; the entire
  "v2 magic passes the v1 MAC" ambiguity cannot exist. Correct.
- **F2 reorder kills the churn (verified).** With the epoch gate before
  `admit()`, a lower-epoch retired frame is rejected and never mutates the ring,
  so the live session can never be evicted. Higher-epoch frames are unmintable;
  an equal-epoch frame can only come from the single live session, which the
  #5477 ring still watermarks. The churn is dead. Keeping (not restructuring)
  the ring for same-epoch replay is the right compose-with-held-work call.
- **Blast-radius avoidance is correct and load-bearing.** I confirmed
  `SessionSyncWireVersion = CurrentHAProtocolVersion` and that the frame's
  `HAProtocolVersion` feeds `HAProtocolVersionMismatch` →
  `daemon_ha_userspace_readiness.go` blocks RG transfer. Reusing the version
  field would break session-sync/handoff during rolling upgrade. The
  self-contained additive body field is the right choice and matches the #2239
  precedent.

## Required revisions (this is why the verdict is NEEDS-MINOR, not READY)

**R1 — Kill the "residual 8 bytes / sentinel" framing; specify a forward parse
bounded by `bodyEnd`.** §5.1 and open-Q1 describe detection as "exactly 8
residual bytes" and float a sentinel fallback. As written it is under-specified
and invites the very ambiguity F5 was about. The airtight construction is: the
receiver locates the fixed 52-byte trailer first (so `bodyEnd = len-52`, or
`len` when unkeyed/absent), then `UnmarshalHeartbeat` **forward-parses the body
`[:bodyEnd]`** exactly as today and, after the version section, reads the epoch
iff `off < bodyEnd` (and asserts `bodyEnd-off == 8`, else it is a malformed/
mis-versioned frame → treat as no-epoch and log). Because the sender writes
**either 0 or exactly 8** trailing body bytes and only MAC-valid frames reach
this path, `bodyEnd-off ∈ {0,8}` is guaranteed — **no sentinel, no probability**.
This also requires the plan to state the **readLoop reorder** explicitly:
`parseHeartbeatAuth` (locate trailer, get `bodyEnd`) → `UnmarshalHeartbeat(body)`
→ existing cluster-id / duplicate-node checks → auth+epoch decision →
`handlePeerHeartbeat`. The plan's current sketch calls `UnmarshalHeartbeat(buf[:n])`
first, which cannot read the epoch without knowing the trailer boundary.

**R2 — Only write the epoch when keyed; reserve `BootEpoch==0` as "absent".**
`marshalHeartbeatBody` is shared by the unkeyed `MarshalHeartbeat` path. The plan
must state that the 8 epoch bytes are written **iff keyed** (i.e. the sender sets
`pkt.BootEpoch` only in the keyed branch and it is always non-zero —
wall-clock-nanos is never 0), so an unkeyed frame is byte-identical legacy and a
`BootEpoch==0` is the unambiguous "no epoch" marker feeding the `{0,8}` invariant
in R1. Add a round-trip test across every monitor-truncation boundary to pin the
marshaler-reserve ↔ parser-offset contract (an off-by-8 reserve bug would be a
silent interop break).

**R3 — F3 recovery is a FAILOVER blip; decide whether Option 4-iii ships in v1.**
"Restart the rejecting peer's daemon" (§5.5) is not free: restarting the peer
drops/fails over its RGs. For a *security-hardening* fix to make its only
self-lock recovery a disruptive failover is a poor operator story. The plan
should either (a) promote **Option 4-iii** (a non-disruptive
`request chassis cluster heartbeat-epoch reset` that clears the peer high-water
in place) into the v1 scope, or (b) explicitly justify accepting the failover
blip because the self-lock requires the rare state-loss∧backward-clock
coincidence. I lean (a): the command is small and turns an ugly recovery into a
one-liner. At minimum the plan must not present "restart the daemon" as if it
were costless.

**R4 — Justify Option 4-i against #6169's OWN threat model, don't hand-wave the
residual.** §5.6 admits a post-daemon-restart window but frames it loosely. Make
the argument precise: the ≥65 residual #6169 targets is a **replay-injection**
attack that does **not** block the live peer — so after a daemon restart the
receiver hears the live peer's current-epoch frame within one interval and any
attacker low-anchor is immediately overwritten; sustaining a spoof in that window
additionally requires **actively blocking** the live peer (a strictly stronger
attacker than #4107/#5477 defend against). State this explicitly and label the
active-blocking case out of scope, with disk-persist (Option 4-ii) as the named
follow-up that would close even that. Without this framing a reviewer can argue
4-i partially defeats the fix's purpose; with it, 4-i is defensible.

**R5 — Concurrency spec for the moved state.** Moving `highEpoch`/`sawEpoch` to
`Manager` means they are written from `readLoop` and read cross-goroutine
(status). The plan says "m.mu or atomics" — pick one and state that the epoch
gate + ring admit must be a single critical section relative to the readLoop so
there is no torn read between `sawEpoch` (downgrade gate) and `epochAdmit`. Note
`readLoop` currently holds no `m.mu` during auth; adding `m.mu` inside the hot
receive path needs a word on contention (heartbeat is ~10/s, so negligible —
say so).

## Non-blocking observations

- Retiring the ring for a single `(epoch,counter)` high-water is genuinely
  cleaner, but deferring it (don't restructure #5477/#5639 held work) is the
  right call — agree.
- PLAN-KILL is correctly considered and correctly not recommended; the residual
  is a named #6167 follow-up and the receiver-only alternative only moves the
  constant.

## Verdict

The architecture (Path A) is sound and strictly better than the closed PR — it
dissolves the two hardest findings (F1, F5) and the F2 reorder is correct. The
required revisions are **specification/threat-model tightening**, not redesign,
but R1 (detection ambiguity), R3 (recovery disruptiveness), and R4 (residual
justification) are substantive enough that the plan is not yet implementable
as-is.

VERDICT: PLAN-NEEDS-MINOR

---

## Self-correction (post-Codex, same round)

My NEEDS-MINOR was a soft pass and Codex caught what I missed — the
**session/counter lifetime mismatch** that keeps F2 fully open. Verified
firsthand and I now agree it is the critical flaw:

- The epoch is Manager/daemon-scoped and survives a heartbeat restart, but
  `authSession`/`authCounter` are **transient sender fields** reset on every
  `newHeartbeatSender` (`heartbeat.go:692`), and `RestartHeartbeat` is invoked
  on routine VRF/config rebinds (`daemon_apply_dataplane.go:435`). So a single
  daemon incarnation at epoch `E` emits **many distinct sessions** across routine
  restarts, all at `E`. They all pass `epoch == highEpoch`, reach
  `authReplay.admit`, and **churn the FIFO exactly as today** — no lower-epoch
  frame needed. My "equal-epoch ⇒ one live session" claim (§5.3) is false. A
  single receiver restart is enough for a one-shot equal-epoch replay
  (Manager `highEpoch` survives, the ring is empty).
- Codex's residual-byte parse-desync counterexample is real: monitor count and
  name length are **uncapped uint8** (`heartbeat.go:254/260`), so a MAC-valid
  body can desync the forward parse to leave a stray 8-byte tail. My R1
  ("forward parse bounded by bodyEnd") is necessary but **not sufficient** —
  the marshaler must also cap those fields and the epoch must be a typed,
  length-delimited MAC-covered extension.
- The F4 rollback recovery resets the **wrong node** (restarting the rolled-back
  node does not clear the upgraded peer's `sawEpoch`), and `sync.Once` cannot be
  "un-finalized" for retry. Both correct.

**Corrected verdict: PLAN-NEEDS-MAJOR** — this needs a session/counter-lifetime
fix (Manager-scope + `(epoch,counter)` lexicographic guard, ring→v1-only), a
typed bounded epoch extension, a real F3 init/recovery state machine, and an
explicit race-free re-prime on the rejecting node. Converges with Codex.

VERDICT: PLAN-NEEDS-MAJOR
