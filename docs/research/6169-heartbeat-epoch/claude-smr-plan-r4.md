# Claude SMR — hostile plan review, #6169 boot-epoch, round 4 (plan v4)

Stance: HOSTILE re-attack of v4. Verified against `origin/master` @ `11e23b49a`.

## Round-3 findings — resolution check

- **Persist-before-emit (r3 §1).** Correct core: a marker is emitted only after
  `writeDurable` succeeds, so an unpersisted epoch never escapes; the next
  incarnation reads the persisted value and computes a strictly-higher epoch — the
  crash-across-failed-write schedule is impossible. **Resolved** (but see R1 — the
  fail-closed action is under-specified for a was-primary node).
- **Election fence removed (r3 §2).** The ill-defined "fenced-secondary" is gone.
  Mostly right, but not entirely eliminable — R1.
- **Key-gen linearization (r3 §3).** `keyGen` carried into `handlePeerHeartbeat`
  with an `m.mu` recheck + atomic keyGen-bump/reset closes the admit-then-reset-
  then-apply and publish-before-reset windows; a monotonic counter is ABA-safe.
  **Resolved.**
- **Live key-enable barrier (r3 §4).** Async, per-`keyGen`, gates marker emission
  (not `UpdateConfig`'s election, which needs no epoch); markerless-until-resolved
  is safe because an empty→set / rotate transition resets the peer's `sawEpoch`.
  **Resolved.**
- **Epoch-strip gate + `bodyEnd≥16` (r3 §5).** Both restored. **Resolved.**

## Required revision (R1) — persist-before-emit needs a targeted SELF-DEMOTE

§5.4 says a persist-failed node "emits markerless (v1) frames and the peer's
existing timeout/takeover is the fail-closed." That is **incomplete for a
was-primary, higher-priority node**, and it can produce a **sustained
dual-primary**:

1. Node A (higher priority) is **primary** and has previously emitted a marker, so
   the peer B has `sawEpoch(A)=true`.
2. A's disk faults; A cannot persist `prev+1`; per §5.4 A emits **markerless**.
3. The epoch-strip gate (correctly) makes B **REJECT** every markerless A frame →
   B never refreshes `lastSeen(A)` → B times A out and **promotes**.
4. A is still primary and still hears B (B's markers verify), but A has **no
   signal that its own frames are rejected** (UDP, no ack) and A has **higher
   priority**, so A does **not** defer to B.
5. B cannot hear A's (higher) priority (it rejects A), so B does not defer either.
   → **both primary indefinitely** until A's disk recovers.

The epoch-strip gate — which is *required* for security — is exactly what
forbids a graceful markerless degrade once the peer has `sawEpoch`. So a
persist-failed node whose peer expects a marker cannot "degrade in place"; it
must **step aside**. Fix: on persist-failure **with a valid prior epoch** (i.e.
the peer likely holds `sawEpoch`), the node **self-demotes to secondary** and
retries persist — reusing the **existing self-recover fence** that already
demotes a primary and guards both election paths (`kernel_selfrecover.go:52`,
`election.go:44`, `election.go:405`), *not* a new invented state. This is far
narrower than v3's fence: it fires only for a was-primary node with a known prior
epoch, so a state-loss / never-emitted node still emits markerless harmlessly
(peer has no `sawEpoch` → ring), avoiding the "both-nodes-fence" outage v3 had.

**Residual to document:** if **both** nodes lose persistence simultaneously (a
correlated storage/image fault) and both hold prior epochs, both self-demote →
no primary → outage until a disk recovers. This is a triple-fault (cluster +
both disks); the operator recovers via the §5.5 cluster key rotation (which
re-baselines the epoch) or a documented opt-in "stay-primary-degraded" override.
State this explicitly rather than implying persist-failure is always benign.

## Confirmations (genuinely fixed)

- Sole-node markerless→marker-on-recovery is safe: a later-joining peer had no
  `sawEpoch`, so it anchors on the ring then on the first marker — the normal
  "peer began emitting epochs" path, no downgrade.
- The key-derived marker, separated `(epoch,counter)` nonce, #5639 prerequisite
  with owner-generation recheck, and coordinated never-used-key re-prime are all
  sound (validated across rounds 2–3).

## Verdict

v4 fixes every round-3 blocking finding; persist-before-emit is the right core.
The single remaining correctness item is R1: the was-primary persist-fail case
needs a targeted self-demote (reusing the existing self-recover fence) to avoid a
sustained dual-primary, plus honest documentation of the both-nodes-fail
correlated-fault. That is a precise, bounded addition on an existing mechanism —
not a redesign — so this is close, but not yet READY until R1 is in the plan.

VERDICT: PLAN-NEEDS-MINOR

---

## Self-correction (post-Codex-r4, same round)

Codex r4 confirms my R1 (the was-primary markerless case is a one-way partition /
dual-primary, needing an explicit ownership hold that demotes a primary — reuse
`SetKernelUpgradeHold`) and found **three more real blockers** I missed. Verified;
I converge to NEEDS-MAJOR:

1. **The residual is broader than "state-loss ∧ backward-clock."** Rejecting an
   INTACT persisted `prev > now+MARGIN` as corrupt *regresses* a legitimate
   forward-clock value: boot far-forward → emit `Tfuture` → correct the clock →
   reject intact `Tfuture` → emit lower `Treal` → peer rejects → dual-primary.
   Fix: **checksum the persisted epoch; TRUST a checksum-valid value (never
   regress below it)**; only a checksum-*invalid* value is state-loss. Drop the
   read-time far-future heuristic (it causes a worse failure than the corrupt-high
   self-lock it was meant to prevent, and the checksum distinguishes the two).
2. **Async persist retry can overwrite a newer durable epoch** (G1 fails, sleeps;
   G2 writes C2>C1; G1 wakes, overwrites C1 → durable floor regresses). Needs one
   **serialized persistence worker with a read-max-write transaction** (never
   write below the current durable value) + a current-keyGen check before enabling
   the marker.
3. **The live-key barrier is not implementable as "defer only `UpdateConfig`'s
   election"** — heartbeat/timeout/readiness/monitor elect independently
   (`readiness.go:60`), and "peer can't have `sawEpoch`" is false for same-key
   re-enable / staggered config / a surviving peer while this node booted unkeyed.

Plus the precise defects: `lastSeen` must be inside the final gen-checked
transaction; §5.3 must use a locked `handlePeerHeartbeat` helper (no `m.mu`
nesting); restore the **+16-byte tail reserve** (marker frames need 68, not 52);
#5639 must drain/rehandshake pre-arm unauthenticated sync connections.

**The unifying fix:** ONE mechanism — *hold primary (demote if primary, guard
promotion) while you cannot emit a durably-persisted marker a peer might expect;
promote only if the peer is confirmed absent* — subsumes the persist-fail
fail-closed, the live-key barrier, and the ownership hold, reusing the kernel-hold
demote + `PeerHealthyPrimary`.

**Corrected verdict: PLAN-NEEDS-MAJOR.**

VERDICT: PLAN-NEEDS-MAJOR
