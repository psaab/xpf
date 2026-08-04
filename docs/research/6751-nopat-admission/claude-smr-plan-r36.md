# Claude SMR hostile plan review — #6751 plan v15.24 (round 35 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.24 folds AGY r35's
three clarifications and Codex r35's blocker/major/minors. The
finding count has collapsed (16 → 6, all specification-level), and
several of Codex r35's own attacks CLOSED (F1 inventory, quarantine
recording, F4, F8, F9 precedent, M11). This pass attacks the six
folds. Codex r36 and AGY r36 have not been dispatched yet.

## The six folds, attacked

B1 (admission fence, both directions): the fold converts the quiet
interval from a dial-timing rule into an admission fence — refuse
authenticated inbound AND suppress outbound on both fabrics until
the peer's disconnect bound elapses. Attack: does the fence
introduce a deadlock against the peer's own fence? Both sides
fencing simultaneously is the mutual case — each refuses inbound
and suppresses outbound for the same bound, both slots empty on
both sides, then both admit: the interval ends with a clean
both-empty state on BOTH registries. The liveness bound is the
readiness timeout (unchanged). Sound. The remaining question —
authenticated-inbound refusal's wire shape (RST vs silent drop) —
is implementation-level; the peer retries per :435 and succeeds
after the interval, which is the designed recovery.
M2 (worker outcomes): the outcome channel is now mandatory before
the barrier ACK; the §5.6 "not fed back" text is explicitly
superseded (not silently contradicted — the contradiction Codex
r35 named is resolved by making the supersession textual).
Finding 4 (incarnation namespace): daemon-issued monotonic
generation at the barriered handoff, bound to the validated
instance — the restart-reuse trace (E,100 rejecting genuine
(E,1..100)) dies because the daemon's generation is not the
helper's zero-restarting counter. Sound; the daemon side already
has monotonic generation machinery (debtGen, lifecycleSequence) to
model it on.
Finding 5 (ConfirmedAliasNoop terminalization): terminalizes only
after P2 reports deleted / absent / publication-mismatch-to-newer;
purge failure = Failed; timeout/unknown = Pending → fence before
reconcile. This composes with the five-outcome ledger and the
never-ACK-unresolved rule. The one edge: a purge report of
"mismatch-to-newer" means the key is now a legitimate newer row —
the alias row is gone by replacement, no delete needed, and the
newer row's own confirmation ledger entry governs it. Consistent.
Finding 6 (replica refresh predicate): the owner predicate is the
entry's ORIGIN/ownership marker (not the shared adopted id), and
replica last_seen applies monotonically (max(current, candidate)).
The stale-backward-timestamp case dies; the shared-id
indistinguishability case dies with the origin predicate.
NIT (NACK naming): folded already with AGY's identical finding —
the fence names connection teardown as the single mechanism.

## Convergence assessment

The attack surface that remains is implementation-level by
construction: wire shape of the inbound refusal, the concrete
quiet-interval multiple, the outcome-channel's exact struct. Each
is the kind of detail an implementation PR resolves with tests,
not a design decision the plan must make. Codex r35's own closing
list confirms the inventory, quarantine, F4, F8, F9, and M11 are
closed. Both forks remain settled; the option-(a) core has now
survived three independent no-kill-shot confirmations.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.24 that
I can construct. The three nits above are implementation-level.
If Codex r36 and AGY r36 converge, this is terminal.
