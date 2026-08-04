# Claude SMR hostile plan review — #6751 plan v15.23 (round 34 fold-check)

Reviewer: Claude SMR. Posture: hostile — v15.23 folds AGY r34's five
findings and Codex r34's ten blockers + major into the adjudicated
PATH-A specification. This pass attacks the folds for
self-consistency and hunts a fifth factual error of the class I have
now made twice. Codex r35 and AGY r35 have not been dispatched yet.

## The folds, attacked

F1 (writer inventory + negative bound): the inventory now spans the
ten original classes plus the #5305 rollback, maps_sync cleanup,
idle reap, and terminal teardown, with Codex's own negative
inventory as the completeness bound (steering state, optional
conntrack ctx, fabric-forward, DNAT maps, no NAT64 writers). I
cannot construct a fourteenth class from the tree. The shipped ABI
misread at maps_sync.go:609 (bytes[16:24] read as `Created` — that
is `SessionID` in the current padded ABI, bpf_session_value.go:75)
is a genuine bug found in passing; it is flagged in the plan and in
the round comment for a separate fix issue — this plan should NOT
absorb it (out of scope discipline).
F2 (one deadline + reserve-before-mutate + fence-on-unknown): the
three deadline values Codex cited (15s export, ~3s Go, 5s Rust
socket) are real; the fold makes the Go deadline cover the barrier
wait plus margin and turns every unknown result into a fenced epoch
rather than a silent late commit. The fence-on-unknown is the only
honest terminal state for a system whose re-drive triggers on
disconnect (sync_conn.go:572), not ACK timeout. Sound.
F3 (two ledgers + five outcomes): AGY and Codex found the same Rule-3
contradiction independently (quarantined keys MUST be recorded at
decode for reconcile protection, AGY r15, vs the v15.21 text's
"records only after confirm"). The two-ledger split with
`ConfirmedAliasNoop` as a non-failure terminal outcome is the
correct resolution and matches the existing never-ACK-unresolved
rule.
F4 (table-authoritative predicate + one producer + identity
domains): the mirror-write-failure inverse (B's mirror write fails,
mirror absent, delayed Close(A) publishes G3 > G2, peer deletes
live B) is closed by consulting the table, not the mirror. The
one-producer rule removes the v15.21 self-contradiction (helper
commit AND Go QueueDelete would double-publish). The three identity
domains are named with their conversion cite. Sound — and it
simplifies: Go's delete path for helper-owned rows becomes pure
request/result.
F5 (RMW refresh): the fold no longer pretends BPF can field-update;
the stripe-guarded RMW with id-gating and singular counter
ownership is the only honest shape. Noted: the merge must also
preserve fields the refresh does not own (fib, zones, rewrite
fields) — the named-field merge covers this by construction.
F6 (one arbiter): the stalled-fallback trace required the dedup
check and the generation draw to be separable; making them one
critical section per frame on either lane closes it. The additive
both-lane fields revise §6 honestly (no more absolute "no wire
change"), and the fallback-disabled degradation for non-capable
peers is the safe mixed-version posture. The incarnation-validated
watermark handles restart-vs-reconnect correctly.
F7 (sticky lineage): promotion/demotion overwrite origin, so
lineage must be orthogonal metadata; the promotion-leak trace
(old-peer alias → timeout admission → promote → exported as
canonical) dies. The mirror-bit vs side-index choice is left as an
implementation decision with the correct constraint (every export
path must consult one of them).
F8 (copy-time binding): binding (key, publication id, generation)
at copy and omitting only on a binding MISMATCH is the precise
decision rule — it no longer confuses first-sight absence with
consumed-close absence.
F9 (authoritative recovery source): the helper's owner-RG snapshot
extended with SharedPromote inclusion, alias exclusion, and
BulkStart/BulkEnd framing is the constrained mini-B2 that
sole-writer makes proportionate — and it is honest that debt only
guarantees byte acknowledgement, not byte authoritativeness.
F10 (quiet interval): converts the old-peer fallback from an
assumed both-slots-empty observation into a proven one (wait >
disconnect-detection bound before reconnecting).
M11 (P2 ownership): settled in-helper with the no-close-toward-owner
exception; the contradictory Go-loop text is replaced by a pointer.

## Self-audit for the fifth factual error

My two prior factual errors (socket budget; gRPC existence) came
from asserting infrastructure facts without reading the code. For
v15.23's load-bearing new claims I verified: restoreBPFSession
direct writes (manager_ha.go:1204-1331), the ABI layout note
(bpf_session_value.go:75), the unbounded VecDeque precedent and the
export.rs two-phase wait, the fallback lane's 5s drain and the
event callback's discarded sequence
(daemon_ha_userspace_stream.go:159/254-320), and the promote/demote
origin overwrites (promote.rs:99 / shared_ops.rs:161). All check
out. The one claim I could NOT independently verify in context: the
exact deadline constant at process_control.go:73 (taken from Codex
r34's cite) — it is used only comparatively ("~3s"), not
load-bearing for the rule.

## Verdict

**PLAN-READY-WITH-NITS.** No BLOCKER or MAJOR survives v15.23 that
I can construct, and both forks (behavior + substrate) are closed
with the option-(a) core untouched. Nits (all implementation-level,
not plan defects): the merge-field ownership list for refresh
replicas; the side-index vs mirror-bit choice for lineage
visibility; the quiet interval's concrete multiple of the
keepalive timeout (named at implementation). If Codex r35 and AGY
r35 converge, this is terminal.
