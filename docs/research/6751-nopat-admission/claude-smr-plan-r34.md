# Claude SMR hostile plan review — #6751 plan v15.21 (round 33 fork adjudication, concession + verification)

Reviewer: Claude SMR. Posture: hostile — including against my own
r33 document, which recommended PATH B on facts that Codex r33
disproved. This is the adjudication pass: I re-verified the fork
evidence myself, concede the fork to PATH A, and then attack the
§4.0.1 sole-writer specification as written. Codex r34 and AGY r34
have not been dispatched yet.

## The concession, with the verification done independently

My r33 PATH-B recommendation and AGY r33's PATH-A rejection both
rested on the same factual error: that sole-writer rerouting must
cross the shared control socket's >1/s budget. It does not: the
helper binds a SECOND, dedicated session socket
(`userspace-dp-sessions.sock`, lifecycle.rs:165-175 binds both
listeners; process_control.go:172-178 derives it) serviced on a
dedicated thread (lifecycle.rs:344-381), and HA imports ALREADY
ride it (manager_ha.go:1112-1167). Sole-writer changes where the
mutation executes, not the transport. I verified all four of
Codex's PATH-B factual kills independently: no gRPC dependency in
userspace-dp/Cargo.toml; per-worker private tables at
setup.rs:28-42; the WorkerLocalImport retag at
session_glue/mod.rs:868-878 excluded by the owner export at
session_glue/mod.rs:608-635; alias rows installed into worker
tables via upsert_synced.rs:64-78. PATH B-as-written was wrong in
at least four load-bearing places; PATH A's foundation is real.
The fork is conceded: **PATH A**, with AGY's strongest objection
(the unbounded VecDeque) converted — correctly by Codex — into the
specification's bounded-admission rule rather than a foreclose.

## Attacking §4.0.1 (the seven rules)

Rule 1 (writer inventory): the inventory names ten mutation
classes with cites. Attack: is it COMPLETE? The classes Codex
enumerated (local publish, refresh, close, imported fwd/rev,
DNAT/session-map companions, policy clear, filtered clear,
clear-all) are all present with file:line anchors. The one I can
still construct: the retained shim's own bindings — but those are
steering state, not session rows. The gRPC/CLI filtered clears are
named. Neighbor warming (daemon_ha.go:1509-1556) READS but does
not mutate — cosmetic under sole-writer. Complete enough for r34
to test.
Rule 2 (bounded admission + ImportBarrier): the precedent
(export.rs:22-66 enqueue → release mutex → wait ACKs) exists and
matches the shape. Attack: refusal semantics for the SYNC path —
a refused import must not silently strand the peer; the exact
per-key error feeds the applied-transaction ACK conditioning
(rule 3), so the peer's BulkEnd never ACKs over a skipped key.
Coherent.
Rule 3 (applied transaction): recording-after-confirm +
ACK-on-zero-failures is the minimal honest transaction; it
composes with the partial-bulk disposition from r24.
Rule 4 (delete transaction publishes the close inside the commit):
this is the rule that finally kills the r31 fatal inverse AND the
r33 policy-invalidation trace — the close's publication is
conditional on the delete's commit, and a mismatch suppresses
both. Because the helper is the only writer, the stripe is
process-local and sufficient; no cross-process arbiter is needed.
This is exactly what v15.19 could not say.
Rule 5 (field-targeted refresh): kills the refresh-restore inverse
at the root (the id is never rewritten).
Rule 6 (dual-lane dedup): the RPC fallback duplicate lane was a
genuine blind spot in every prior round (mine included — none of
my r28-r32 attacks enumerated it). One source sequence per worker
with drop-older-than-highest is the standard dedup; the barriered
handoff disabling the fallback is the cleaner primary.
Rule 7 (alias provenance): withdraws my false "tables never
contain aliases" premise and gates the legacy machinery honestly.

## §4.0.2 consequence map, attacked

The shrink claims: V1-V4 to known-stale omission — sound, because
the producer-side races were all mirror-consistency races, which
sole-writer eliminates; the remaining window (Go consumed a close
between the bulk's batch copy and its callback) is Go-local state
and the known-stale check covers it. The omission index becoming
exact-result-fed is strictly simpler than v15.19's inference
machinery. P2 in-helper is the atomic seam v15.19 lacked. The
carry-forward retention is the honest call (the Open-publish
window exists under any substrate). The debt correction (record
before End, ACK-only clear, fixing the sync_conn.go:194-206
write-completion clear) closes the r28/r33 tail.

Residual risks I am flagging for r34 rather than resolving
unilaterally: (i) the policy-clear/filtered-clear/clear-all
reroutes change CLI/gRPC clear latency (they now round-trip the
helper transactionally — the plan should state the latency
posture, and whether operator clear-all is allowed to be slow);
(ii) the bounded queue's refusal under a 100k-import bulk plus
concurrent local churn — the backpressure propagates to the
applied transaction, which is correct, but §9 must pin the
sustained-refusal bulk case; (iii) the prime-REQUEST field is a
new protocol bit whose mixed-version behavior (old peer ignores)
needs the usual additive-change tests.

## Verdict

**PLAN-READY-WITH-NITS on v15.21, contingent on r34 confirming no
fourth factual error of the class I made twice.** The fork is
adjudicated correctly (PATH A on verified evidence); the option-(a)
core stands untouched with three independent no-kill-shot
confirmations; §4.0.1's rules are each statable, testable, and
grounded in an existing precedent. The nits: latency posture for
operator clears, the sustained-refusal §9 pin, and the
prime-REQUEST mixed-version tests. If Codex r34 and AGY r34
converge, this is terminal.
