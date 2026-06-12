# Claude SMR hostile plan review — round 2 (plan v3, commit eaa45be67)

Stance: attack the NEW v3 machinery (attempt state machine, cached clock,
deadline-driven pass) — the parts no reviewer has seen yet.

## Findings

**F1 (MEDIUM) — attempt success condition has an equality hole across the
cached/fresh clock seam.** §5.2 ends an attempt when
`current.created_ns > started_ns` (strict). `started_ns` is taken from the
loop's fresh `monotonic_nanos()`; `created_ns` is stamped from
`cached_now_ns`, which the loop publishes from that same `now` at iteration
top. A handshake that completes within the same iteration (entirely
possible: timer pass sends the initiation, the same iteration's... or more
realistically the next iteration where `publish_now(now₂)` ran but
`now₂ == started_ns` at ms granularity is unlikely yet `created_ns ==
started_ns` is exactly reachable when the attempt starts and the peer's own
initiation completes in the same tick) leaves `created_ns == started_ns`,
strict `>` fails, and the attempt retries against a healthy fresh session at
+5s — one wasted handshake per occurrence, and with a peer that always
responds in-tick, a periodic re-handshake loop. Same lesson as #1745's
wrap-safe tag check: use **`created_ns >= started_ns`**. The false-positive
direction (a session installed in the same tick just *before* the attempt
trigger) merely ends an attempt that fresh keys have already satisfied —
benign by inspection.

**F2 (MINOR) — initial bring-up is not folded into the attempt machine.**
wg_control.rs:160-166 fires an immediate initiation before the loop. v3's
machine starts attempts only from the §3 trigger classes inside the loop. If
that first initiation is lost, nothing retries until the unconfirmed-retry
trigger starts an attempt at the first timer pass — fine in effect (≤1s
gap), but the plan should say the bring-up initiation IS an attempt start
(configured-initiator class) so the 5s/90s discipline and `last_tx_ns`
pacing apply from packet one, and so two initiations don't fire ~1s apart
at boot (bring-up + first-tick attempt start).

**F3 (NIT) — attempt may end on an UNCONFIRMED responder-role session.**
If the peer's initiation completes first, our attempt ends on a fresh
responder session that is egress-blocked until its first inbound data
record. Correct per spec (keys exist; key-confirmation is the egress gate),
and the NoSession edge re-arms if egress is attempted — but worth one
sentence in §5.2 so the engineer phase doesn't "fix" it.

**F4 (checked, no finding) — retry-hammer of a healthy session.** With F1's
`>=` fix, an active attempt always terminates on the first observed fresh
session; the 90s window bounds the pathological case (peer responds with
msg2s that fail Noise — reservation survives by design, retries stop at
give-up).

**F5 (checked, no finding) — deadline-driven pass initialization.**
`next_deadline = 0` at loop entry forces a pass on the first iteration
(now >= 0), which computes a real deadline; no past-deadline spin window
remains provided the pass ALWAYS recomputes `next_deadline` (the §5.2
sketch does — it assigns unconditionally inside the pass).

**F6 (checked, no finding) — cached-clock staleness.** Worst case is one
blocked poll (≤100ms) + one full double burst + send syscalls — comfortably
inside the claimed ~0.2s and the 60s protocol margin (180s reject vs 120s
rekey). A wedged control thread stalls expiry equally for the thread's own
IO, and the worker transit path fails safe (older cached now ⇒ ages read
SMALLER ⇒ T3 fires later within the slop bound, never spuriously early).

## Verdict

**PLAN-NEEDS-REVISION (narrow)** — F1 (`>=`) and F2 (bring-up = attempt
start) are one-line plan fixes with no architectural impact; fold into v4
and this becomes PLAN-READY from my side. F3 is a documentation sentence.
