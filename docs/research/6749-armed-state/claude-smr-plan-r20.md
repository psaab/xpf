# Claude SMR plan review — round 20 — #6749 armed-state plan v8.15 (132309631)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — the v8.15 folds are MY text, written this session, so
this pass attacks my own fold text first, source in hand). Attack
surface: full gating + the drain, the deferred set + last-exposed
retention + phased tails, the ordered-loop settlement, the
parameterized markers, the two-leg freshness validation + phase
split, the GO-LOCAL re-sync rule, the fold reduction + head-pop, the
member-boundary model, the restore serialization, the uniform
canonical pair, the errors.As form.

**Verdict: DEMAND-REVISION** — 2 MAJOR + 6 MINOR. SMR20-1/2 are
self-found (the pair-not-current abandon has no named report; the
last-exposed record's update points are unpinned); the rest are
containment pins. AGY r20 (read after this verdict was drafted)
converges: its f2 (the GO-LOCAL/leaked-node circular deadlock)
demands the same qualifier fix as SMR20-7's posture note and is the
round's sharpest find; its f1 (MAC-in-hash vs 19(ii)) is
NOT-VERIFIED on re-derivation (the projection identity excludes MACs
by the v8.12 definition — see the trace); its f3 = SMR20-3; its f4
is answered by rebind idempotency + helper serialization.

---

## SMR20-1 (MAJOR) — the pair-not-current abandon has no named report

The pair-current leg abandons a build when a NEWER promotion
interposed mid-flow (no applySem needed for the promotion) — but
v8.15 names a report only for the accepted-successor case
(SUPERSEDED-BY-NEWER-BUILD). The pair-not-current case is different:
no newer build exists yet (only a newer PROMOTION). Pin: the abandon
reports SUPERSEDED-BY-NEWER-COMMIT (success-equivalent for the apply
flow), with the coverage argument that makes it sound: EVERY
promotion path has an apply owner — the commit's own flow (plain,
commit-confirmed, rollback), the HA peer flow, the auto-revert flow,
the boot flow, the exposure debt's drain (the persistence
transition), or the GO-LOCAL re-sync (anything else) — so the older
commit's dataplane leg is always fulfilled by the newer config's own
apply. §9 (d) asserts the report and one coverage instance per
promotion path.

## SMR20-2 (MAJOR) — the last-exposed record's update points are unpinned

The exposure debt records the last-exposed pair at recording time and
the drain's session invalidation composes last-exposed → current.
The record's OWN update points are never enumerated: it must advance
at EXACTLY the points `m.acceptedCommitRevision` advances (the
compile publish legs (manager_compile.go:361/:365), the pending-XSK
deferred publish's clean leg, the status catch-up leg
(process_status.go:18-37/:120-139), the re-sync's apply, the drain's
apply, the boot apply) — `m.lastExposedPair` updates in the SAME
critical sections as `m.acceptedCommitRevision` (one write, one
truth). A missed point makes the retention itself stale, and a later
drain would invalidate stale→current and delete LIVE sessions (the
class the retention exists to prevent).

## SMR20-3 (MINOR) — the drain's own apply-failure policy (= AGY r20 f3)

The exposure drain's revised `applyConfigLocked` can itself fail
(build error, publish timeout (UNKNOWN), helper refusal). Pin: the
drain's failure KEEPS the debt with the standing backoff shape
(5/10/30/60s + jitter + edge Warn — never a 1s hot loop, never a
clear-on-error), the next drain re-reads `ActivePair()`
(latest-wins), and a publish UNKNOWN routes to the re-sync debt
(the standing UNKNOWN ownership); a deterministic failure retries
forever at the 60s floor with the fingerprint Warn (the standing
persistent-failure posture).

## SMR20-4 (MINOR) — the first-member boundary check + the operator-verb reconcile conflict

The member-boundary model needs a token check BEFORE the FIRST
member's program (post-quiescence) — the v8.15 text implies
boundaries only between members. And the operator's registration
toggle DRIVES a helper-side `reconcile_status_bindings`
(binding.rs:29-47 — VERIFIED), which re-spawns workers while the
batch holds its quiescence: the batch's MAC program then DOWNs the
link under live XSKs. That is the documented §10 follow-up class
(the pre-existing mid-defer-window early-BIND hazard — the toggle's
reconcile is defer-blind, present on master), bounded: the helper
serializes the control socket (the verb's reconcile and the batch's
rebind are full reconciles of the current coherent plan — whichever
runs second converges the same state), the worker spawn on a downed
link fails safe (bind error surfaced at the apply), and the batch's
next boundary check abandons with the unwind. Pin the first-member
check + the cross-reference (the follow-up covers the residual
class; AGY r20 f4's "redundant or racing rebind" is answered by
idempotency + serialization — no new check needed there).

## SMR20-5 (MINOR) — the settlement item's context + FIFO

The ordered-loop settlement item carries `(gen, digest,
deferred-tail context)`: the context is the last-exposed config by
GC-RETAINED POINTER (the store's active object — a superseding
commit replaces the store's pointer, but the debt's reference keeps
the object alive) — the settlement phase re-reads NOTHING from the
store (no TOCTOU). The item's FIFO position behind a large config
push is bounded (the loop is sequential and each item is bounded).

## SMR20-6 (MINOR) — the unresolved peer-MAC case is telemetry (also answers AGY r20 f1)

The projection IDENTITY is (name, parent Linux name, parent
ifindex, effective queue count) (the v8.12 definition) — the peer
MAC is NOT in the identity, so a MAC resolution (zero → learned) is
a TELEMETRY update: it mints a new generation (it IS a BPF map
mutation), updates the canonical payload's telemetry fields, and
flows to the helper (whose fabric forwarding starts using the
learned MAC) — and it NEVER fires the mark-all/replan rule (the
identity is unchanged). §9 test 19(ii)'s "resolved MAC → NO
replan, NO pending marks" is consistent with the canonical pair's
map-authoritative MACs BECAUSE the two live in different fields
(identity vs telemetry) — the Delta 10 "dedup hash covers the FINAL
wire content" text must say it means the note-CAS content hash, NOT
the projection-change detector (AGY r20 f1 reads them as one — the
separation sentence is required, and with it f1 is NOT-VERIFIED as
a contradiction).

## SMR20-7 (MINOR) — the GO-LOCAL rule's qualifier forms a circular deadlock with the leak case (= AGY r20 f2, the round's sharpest find)

My v8.15 fold's "no apply in flight" qualifier was meant to avoid
racing a live compile — but the drain acquires `applySem`, and a
live compile HOLDS `applySem`, so the FIFO already serializes them:
the qualifier is unnecessary AND it deadlocks the leak case
(inFlight stuck true → the GO-LOCAL rule never fires → no new
StartCompile → the orphaned node is never OVERLAP-finalized →
inFlight stuck forever, freezing the (v) latch echo). Fix: the
GO-LOCAL rule fires on `ActivePair().revision >
m.acceptedCommitRevision` PERIOD (the drain's own StartCompile
OVERLAP-finalizes any orphan it finds — the chain's self-healing
does the rest); the Compile's Finish `defer` is unconditional (a
plain `defer` at Compile's top covering EVERY return path — the
leak can only come from a future abort path that forgets it, which
the exit-census canary test pins); and the persistent-failure
posture is stated (the debt retries at the 60s floor with the
fingerprint Warn while the commit's error is also surfaced).

## SMR20-8 (MINOR) — the respawn-mid-flow case is benign for the fences

A helper respawn between the ping (phase 1) and the validation
(phase 3): the fresh helper's stored token/revisions/generation are
all zero, so the build's token and legacy high-waters PASS (no
rollback possible against zero; the legacy-zero mode covers the
revision pair); the send lands on the fresh helper and triggers a
full bring-up (the standing bounded replan interruption, §3). No
refusal, no wedge — stated so the reviewers don't have to re-derive
it.

## Attack trace (what else I tried, and why it fails to break v8.15)

1. **The drain's derived commit-flow state.** The drain re-runs the
   full flow and re-derives everything from the active pair at
   drain time (the `commitOverlay`, the networkd render — derived,
   recomputed; nothing to preserve). Coherent.
2. **The restore's marker re-stamp.** The restore replays an
   ALREADY-EXPOSED pair; the store-side markers stand (they never
   cleared); `applyConfigLocked` runs none of the wrapper markers
   (they live outside) — correct, no action needed.
3. **The canonical pair's population atomicity.** The map's MAC
   fields are populated via the manager's wrapper (inside the same
   section as the sample/mint/build), so the sample never mixes
   states; the pre-population daemon resolution is ordered before
   the call by the daemon's own flow.
4. **Q1, nineteenth enumeration.** Full gating, the phased tails,
   the ordered-loop settlement, the member-boundary model, the
   uniform canonical pair — none mutate binding slots on their
   refuse/degrade paths. No new `Registered && !Armed &&
   state==none` producer.

## Required for convergence

v8.16: SMR20-1's named report + coverage; SMR20-2's update-point
rule; SMR20-3's drain-failure policy; SMR20-4's first-member check +
cross-reference; SMR20-5's context/FIFO pins; SMR20-6's
identity-vs-telemetry sentence (AGY f1's resolution); SMR20-7's
qualifier deletion + unconditional Finish defer (AGY f2's
resolution); SMR20-8's benign-respawn note. AGY r20 f3 → SMR20-3;
AGY r20 f4 → SMR20-4's idempotency answer. Codex r20 pending at this
writing.

**Verdict: DEMAND-REVISION** (2 MAJOR + 6 MINOR — containment, not
architectural; the v8.15 surface otherwise held).
