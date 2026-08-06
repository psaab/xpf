# Claude SMR — plan review r4 / converging verdict (#4626 L01)

**Verdict: PLAN-KILL.** This supersedes my r3 (`PLAN-READY-WITH-CONDITIONS`),
which was wrong. I missed the finding that decides the issue, and I verified it
firsthand before converging rather than taking the reviewer's word.

## The finding I missed, verified against the tree

Codex r3 raised a race that no bit-on-the-session design can close. I checked
all three of its load-bearing claims:

**1. The clear runs AFTER the new policy set is live — confirmed.**
`applyAndSyncCommitted` (`pkg/daemon/daemon_apply_commit.go:245-262`) calls
`d.applyConfigLocked(...)` first and `d.clearSessionsForPolicyChanges(...)`
after, and the in-tree comment states the ordering as intent: *"Runs under
d.applySem (the caller holds it), **after the dataplane apply so the new policy
set is already live**."*

So between activation and the sweep there is a real window in which packet
workers admit sessions under the **new** numbering while the sweep set was
computed from the **old** numbering.

**2. The resulting over-clear.** With `C1 = [A, B]` → `A=0, B=1` and
`C2 = [B]` → `B=0`:

- the deletion set is `{A's old id} = {0}`;
- a session admitted under C2 after activation and before the scan carries
  `policy_id 0` and is genuinely policy-attributed;
- so a predicate of the form `attributed && ids[PolicyID]` clears a **live,
  correctly-permitted B session** as though it were the deleted A.

`d.applySem` serialises applies, not dataplane admission, so nothing in the
current structure closes it.

**3. Why this kills Path D specifically.** Today that cell is protected — by
accident — by the very `if id == 0 { continue }` the issue asks to remove. The
discriminator bit cannot substitute for it, because the bit answers *"is this
`policy_id` meaningful?"* while the race asks *"which config generation assigned
it?"*. Those are different questions, and the session row carries nothing that
answers the second: no config epoch, no stable admitting-rule identity. A
correct fix needs stable admitting-rule/snapshot identity on every row, or an
admission fence spanning activation→invalidation. Either replaces Path D's
mechanism rather than extending it — a materially different and larger design
than this issue scopes.

## The corollary, which is worth more than the original item

**The same race already exists on master for every policy except the first.**
`C1 = [A,B,C]` → `0,1,2`; delete B → `C2 = [A,C]` → `0,1`; the deletion set is
`{B's old id} = {1}`; a fresh C session admitted after activation carries `1`
and is swept. Nothing excludes non-zero ids. This is a **live over-clear on
master**, not a consequence of anything proposed here, and it is a strictly
better use of engineering time than the item this research was scoped to.

## Other v3/v3.1 claims Codex falsified, which I verified and accept

- **`pkg/policymatch:1516` is not a Path-D plane.** It carries `Matched` plus an
  authoritative `PolicyName` and only emits `policy_id` on a positive match. I
  carried an r2 finding that was specific to B′'s "zero is never assigned"
  invariant into D, where it does not apply. My fold error.
- **"Archived RT_FLOW records still join on the stable `rule_id` string" is
  false.** `rt_flow.rs:99` declares `rule_id: u32` — the field is numeric, not
  the `"<from>-><to>/<name>"` string. My §5.3 mitigation for the renumbering
  path did not exist. (It mattered to B′, which is already dead, but the plan
  asserted it.)
- **The "~1s live-row refresh" figure is wrong.** `bpf_map/mod.rs:375-383`
  documents an incremental budgeted slice, one per ~100 ms, pacing a full-table
  cycle to a **~10 s** freshness window. Note this also means the daemon-side
  comment in `daemon_policy_invalidate.go` that says "~1s live-row refresh"
  disagrees with the Rust implementation — a doc drift worth its own fix.
- **"No signature moves" / "no `.proto` change" are false under D**, since the
  resolvers gain a parameter and the structured discriminator is an additive
  proto field. §6 also still carried heartbeat-capability text from the dead B′.
- **"Both reserved values keep their exact meanings" is false under D**:
  `(0,false)` and `(0,true)` deliberately differ, so only `0xFFFFFFFF` stays
  unconditionally reserved.
- **The plane count is ≥10, not 6**, once the two Rust projections, the separate
  RT_FLOW builders, both Go decoders and the durable sinks are counted.

## What I got right and stand behind

- The `SessionDeltaInfo` gap (§5.0.1) is real and independently verified: no
  `policy_id` field, no constructor assignment, and a production drain loop.
- No production code compares `LogFlags` by equality, so the carrier itself was
  not the problem (r3's verified negative still holds — Codex agrees and adds
  that the BPF-mirror sweep/bulk path can overwrite an event-derived value,
  which is a *further* defect, not a contradiction).
- The B′ kill was correct, and the C kill before it was correct.

## Verdict

**PLAN-KILL**, converging with Codex r3. Not because the ambiguity is imaginary
— it is real and documented in four places in the tree — but because:

1. the literal reservation (B′) is unsafe at the sentinel values and under
   ordinary config skew;
2. the sentinel-move (C) has an end state that fails dangerously and no
   mechanism to retire its guards;
3. the discriminator (D) cannot deliver the principal payoff, because the
   blocker is a positional-id race the bit does not address; and
4. the remaining payoff — one policy exempt from clear, one exempt from
   rematch, one under-claimed name — does not justify a design that would have
   to introduce admission fencing or per-row stable policy identity.

The correct outcome is to **document the limitation as accepted** and spend the
effort on the two live defects this research surfaced instead.
