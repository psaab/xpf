# Claude SMR — hostile plan review r1, #2170 install-generation guard

Reviewer stance: assume the plan is wrong until proven otherwise. Try to
PLAN-KILL it, try to break the generation source, try to find a sequence the
guard fails.

Verdict: **PLAN-READY with three MUST-fix clarifications folded below.** The
race is real (not a PLAN-KILL), the chosen mechanism is sound, but the plan as
first drafted under-specified the generation **carrier on the delete path** and
glossed two correctness corners. None are fatal; all are folded into the plan
text. The single biggest trap (reusing `SessionID`) is correctly identified and
avoided.

---

## A. PLAN-KILL attempts (all failed → race is real)

**A1. "An existing GC on the standby would clean up the wrongly-deleted `S'`,
so it self-heals — KILL."** REFUTED. GC deleting `S'` is the *symptom*. Worse:
the standby does not forward owned-RG traffic until failover, so it cannot
re-learn `S'` on its own; the only repair is the next bulk re-sync or the flow
re-establishing post-failover (i.e. the user already saw a blackhole). Not a
self-heal.

**A2. "The single ordered `sendCh` already serializes delete-then-install, so a
later install always wins — KILL."** REFUTED, and this is the crux. Within ONE
connection epoch, yes. The hazard (plan §3.4) is a delete that is **journaled
and survives a disconnect**, then replayed by `flushDeleteJournal` on the *next*
reconnect — which runs BEFORE incremental sync resumes (sync_conn.go:200). The
`S'(K)` install happened on a *different, healthy* epoch in between. So the
ordered-channel argument does not cover the cross-reconnect replay. #2163's
FIFO-prepend is exactly what carries the stale delete across that boundary.
Confirmed in code.

**A3. "SessionID already distinguishes S from S' — just compare it — KILL the
need for a new field."** REFUTED hard, and this is the most dangerous false
fix. (a) SessionID never crosses the manager→helper boundary
(`SessionSyncRequest` has no SessionID field; `SyncedSessionEntry` has none),
so there is nothing to compare on the apply side without new plumbing anyway.
(b) Even if plumbed, `now_seconds<<16 | slot` collides for same-second
same-slot reuse — and a quickly-reopened connection on a steered flow is
exactly same-slot. A reviewer who "fixed" this by comparing SessionID would ship
a guard that silently no-ops in the precise case it must catch. The plan's §3.3
calls this out; KEEP it front-and-center for the engineer.

**A4. "#1760 was PLAN-KILLED for the same reverse-key-collision reason, so this
is too — KILL."** REFUTED. #1760: two *concurrently live* sessions, genuinely
ambiguous reverse tuple, needs TCP state the fast path lacks. #2170: one live
session per key at a time, disambiguation is *temporal* (old vs new incarnation
of the same key from the same owner), which a per-key monotonic counter solves
without any TCP-state knowledge. Different class. Not killed.

## B. Attacks on the generation MECHANISM

**B1. Cross-node comparison is NOT required — verify.** The plan claims we only
ever compare generations for the *same key from the same owner*. Is that true?
The owner (primary for the RG) mints the install `g(S')` and the delete `g(S)`
for `K`. The standby only *stores and compares*; it never mints a competing `g`
for an owned key. On failover the roles swap, but the new primary re-primes via
bulk (cold-start) or already holds the synced entry with the old owner's `g`.
**Edge the plan must state (FOLDED):** after a failover, the *new* primary
starts minting generations from *its own* counter, which is unrelated to the old
primary's. If the new primary then sends a delete for a key it inherited (stored
with the OLD owner's `g`), `deleteGen` (new counter) vs `existing.Generation`
(old counter) is an apples-to-oranges compare. MITIGATION: on a session the new
primary *re-installs/refreshes* after taking ownership, it bumps the stored `g`
to its own counter first (the install path always overwrites gen), so a
subsequent delete compares within its own domain. For a key the new primary
deletes WITHOUT first refreshing, the comparison could wrongly refuse or wrongly
apply. **Resolution:** the gen==0-fallback does NOT save this (both are
non-zero). The safe rule is: **the guard refuses only a delete whose gen is
strictly older than stored AND from a context where monotonicity holds.** The
simplest robust realization is the plan's "echo the install generation in the
close path" (Option B-echo): the delete carries the exact `g` the *current
owner last installed*, so it is always same-domain as the stored entry the owner
itself installed. This is now the explicit recommendation — the per-key
sender-side counter map (Option A) is demoted because of this cross-owner edge.
**MUST-FIX folded into §5.1: prefer echo-the-install-generation so the delete is
same-domain as the install it cancels; if a sender-side counter is used, it MUST
re-stamp inherited keys on ownership change before any delete.**

**B2. Daemon restart mid-boot resets the counter.** Seed from boot nanos (plan
§5.1) so a restarted primary does not mint `g=1` that is *lower* than a value
the standby already holds for the same key. But a restart ALSO triggers
cold-start bulk (`bulkEverCompleted` false → `doBulkSync`), which re-primes and
re-stamps. So the regression window is "restart without cold-start", which the
code path does not produce (a restart is a fresh process → cold start). LOW.
Documented (§7.6). Acceptable.

**B3. uint64 wrap.** A counter seeded at boot-nanos (~1.8e18 now) incremented
once per session install: even at 10^7 installs/s it wraps in ~58,000 years.
Non-issue. The plan's "wrap-safe equality" nod is overcautious but harmless;
keep the `<` vs `>=` comparison, document the no-wrap assumption. NOT a blocker.

**B4. The reverse companion the standby synthesizes locally must inherit `g`.**
`synthesized_synced_reverse_entry` builds the reverse from the forward entry —
it must copy the forward's generation, else a delete that refuses the forward
but a stale-gen reverse companion lingers (or vice-versa) → split state. Plan
§5.4 says this; MUST be tested (helper parity test). Confirmed as a real
correctness requirement, folded.

## C. Apply-guard corner cases

**C1. Delete arrives, key absent.** No-op today; no-op with guard (nothing to
compare). Fine.

**C2. Delete gen == stored gen.** This is the delete of the installed session →
MUST apply. Plan uses strict `<` for refusal, so equality applies. Correct.
Reviewer note: do NOT write `<=` for refusal — that would make a session
undeletable by its own delete. Explicit warning kept in §5.3.

**C3. Out-of-order installs for the same key (S' then a *delayed* S install).**
Could a *stale install* (not delete) of the old incarnation arrive after S'?
The install path is upsert-by-key and overwrites; a delayed `S(K, g=1)`
arriving after `S'(K, g=2)` would overwrite stored gen back to 1 → then a
legit `D(S', g=2)` is refused (2 < 1 is false, applies — OK actually) but a
stale `D(S, g=1)` now matches and could delete S'. This is a real secondary
hazard the plan did NOT cover. **MUST-FIX (folded into §5.3):** the install
upsert should also be generation-guarded — **refuse to overwrite a stored entry
with a strictly-older-generation install** (same `<` rule on the install path).
This makes both install and delete monotonic-by-generation and closes the
delayed-stale-install variant. Cheap, same comparison, same field. Folded.

**C4. gen==0 legacy entry meets a gen!=0 delete (or vice-versa).** Plan: fall
back to unconditional delete. Is that safe? If the stored entry is a legacy
gen-0 install (old peer or pre-field bulk) and a new-peer delete carries gen=5,
we cannot order them → unconditional delete (today's behavior). Acceptable: we
never make it *worse* than today, and a mixed-version cluster is transient
(rolling upgrade). Confirmed. Keep.

## D. Scope / parity

**D1. Forward-wire fabric alias** (daemon_ha_userspace.go:745-789) issues a
SECOND `QueueDeleteV4(wireKey)`. It must carry the SAME generation as the
primary delete (same close event). Plan §5.4 covers companions/aliases; make
the alias explicit in the engineer checklist. Folded by reference.

**D2. Go BPF-shim path vs Rust synced map.** `Manager.SetClusterSyncedSessionV4`
writes `bpfShim.SetSessionV4` (the BPF conntrack map, which has NO generation
field — it is the C struct) AND mirrors to the Rust helper. The guard lives in
the **Rust synced map + the Go cluster apply layer**, NOT in the BPF C struct.
So a stale delete that the guard refuses must ALSO not reach
`bpfShim.DeleteSession`. The cleanest seam: apply the guard in
`deleteClusterSyncedV4` (cluster layer) BEFORE calling `DeleteWithCompanionsV4`
— if refused, neither the BPF map nor the helper is touched. This keeps the BPF
C struct generation-free (no header change, §10) while still protecting it.
**MUST-FIX clarification (folded into §5.3/§7.7):** put the authoritative guard
in the cluster apply layer (`deleteClusterSynced*`) so a refusal short-circuits
both the BPF map delete and the helper delete; the helper-side guard is
belt-and-suspenders for deletes that originate helper-side. This is cleaner than
the first draft's "push into DeleteWithCompanions" and avoids a header change.

## E. Test rigor

- The headline regression test (`TestStaleDeleteIgnoredForReplacement`) MUST be
  shown to FAIL against pre-fix (delete removes S') — non-tautological, mirrors
  the #2163 discipline. Kept.
- Add C3's delayed-stale-install test (`TestStaleInstallDoesNotRegressGen`).
- Add the failover-domain test from B1 (post-failover the new primary's delete
  of an inherited+refreshed key applies; of an un-refreshed inherited key does
  not wrongly delete a live flow) — at least a unit-level model of it.
- test-failover 14/0 mandatory (HA/session-sync change).

## Folded changes (now in plan.md)

1. §5.1 — recommend **echo-the-install-generation in the close path** (delete
   is same-domain as the install it cancels); demote the per-key counter map;
   require re-stamp on ownership change if a counter is used (B1).
2. §5.3 — add **install-side generation guard** (refuse strictly-older install
   overwrite), closing the delayed-stale-install variant (C3); explicit `<`-only
   warning (C2).
3. §5.3/§7.7 — authoritative guard in the **cluster apply layer**
   (`deleteClusterSynced*`) so a refusal short-circuits BOTH the BPF map and the
   helper, keeping the BPF C struct generation-free (D2).
4. §5.4 / §9 — reverse companion + fabric alias share the install generation;
   add parity + delayed-install + failover-domain tests (B4, C3, D1, D2).

## Residual concerns the engineer must confirm against live code

- That the close delta / helper close path can actually **echo** the install
  generation (preferred carrier). If it cannot without invasive plumbing, the
  bounded per-key counter map + ownership-change re-stamp is the fallback — both
  are specified.
- Exact placement so a refused delete touches neither the BPF map nor the helper
  (D2).

No PLAN-KILL. Proceed to /engineer with the four folded changes as hard
requirements and test-failover as the gate.
