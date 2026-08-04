# Claude SMR hostile plan review — #6751 plan v15.19 + the round-32 inflection (fold-check that became a fork recommendation)

Reviewer: Claude SMR. Posture: hostile — this pass began as the
fold-check of v15.19 against Codex r32's seven blockers, and it must
honestly report what the fold attempt surfaced: **my own folds have
been breeding races for six rounds, and Codex r32's two
cross-process blockers are not foldable at proportionate cost.** The
right hostile verdict on v15.19-as-is is PLAN-NEEDS-REVISION; the
right engineering response is the substrate fork now written into
the plan as §4.0 (v15.20). This document is the self-critique the
feedback memory demands I write instead of another soft-pass.

## Why the r32 fold fails honestly

Finding 1 (cross-process atomicity): the v15.19 stripe is
Rust-process-local by construction, but the mirror writer set spans
two processes — Go's policy invalidation (daemon_policy_invalidate.go:357)
and HA mirror writes (manager_ha.go:1058) are same-map writers no
Rust mutex can serialize. Worse, my own v15.19 text asserted
"publication occurs at session create/delete, not per packet" — and
Codex found the refresh writer (bpf_map/mod.rs:429/451) doing
full-value write-backs INCLUDING session_id with BPF_EXIST, which
resurrects a stale incarnation into the row, after which the delayed
old close MATCHES and deletes and publishes G_del > G_new. My
compare-and-delete was not merely non-atomic — its premise (the row
retains the publisher's id) is violated by a writer I did not
inventory. That is the pattern: every round's mechanism has an
uninventoried writer/producer/path inside it. The honest arbiter
(helper as sole mirror writer) requires rerouting the Go HA/policy
writes through the helper — and the control socket cannot carry
bulk HA import (CLAUDE.md's >1/s budget exists precisely because
bulk sync already starves installs). PATH A's foundation is
therefore a contention redesign I cannot honestly call small.

Finding 7 (P2 atomic seam): same shape — the purge's
exact-publication compare needs atomicity against Rust's direct
BPF_ANY publication and the Go manager's write-BPF-before-mutex
order (manager_ha.go:1338 vs :1058). A Go-side serialized loop
cannot serialize a Rust writer.

Findings 2-6, M8-M10: each individually foldable (purge id from the
import record; omission-index seam; remote-prime request; carried
overflow identity; inbound-static transaction; deferral debt;
contradiction cleanup) — but folding them INTO the mirror substrate
repeats the six-round pattern: next round finds the race inside the
new seam. The finding-count trajectory (5, 7, 11, 7+8, 10, 11) is
flat-to-rising. That is the singularity signature from the project's
own retreat history (6461-blind-rst v48.1): when the mitigation
machinery keeps generating its own attack surface, retreat to the
minimal substrate, don't add a seventh layer.

## Why PATH B (table-truth) is not a cop-out

Every retired mechanism was defending the MIRROR's staleness, not
the registry's correctness: V1-V4 (mirror re-read), omission index
(dirty-mirror zombie), compare-and-delete atomics (mirror writer
races), carry-forward (mirror-hole Opens), the fencing question
(slot-shape-driven primes). The option-(a) core — registry,
occupancy, owner split, holders, drain, static accounting — never
read the mirror once. The delta stream's #2170 discipline never
involved the mirror. What PATH B actually costs: one new lossless
paginated snapshot channel (framing already dictated by the existing
BulkStart/End integrity rules), a generation horizon at
SnapshotStart (replaces carry-forward), and a table-epoch bump on
steering rebalance (replaces the cross-worker incarnation gate —
the common same-worker case was already safe under per-worker
delta ordering: queued [Close, Open] flush in worker order, Go draws
G_del < G_new, the tombstone loses by construction). The daemon's
own comment (daemon_ha_sync.go:974) named table-truth as the
desired end-state and deferred it as a follow-up; the retreat
promotes it because the deferral is what six rounds of machinery
were compensating for.

Residual risks of PATH B, stated against myself: (i) the snapshot
channel is NEW protocol surface — paginated pull, per-page
checksums, SnapshotEnd integrity — but it is SMALL surface with one
writer (helper) and one reader (Go), no shared-mutable state, and
its failure mode (abort before SnapshotEnd, debt re-arms) is the
existing partial-bulk disposition; (ii) the snapshot's table
iteration must be horizon-consistent under concurrent mutation —
the table's per-entry mutation sequence (already present for
RT_FLOW ids) is the ordering token, and the receiver's generation
guard resolves page/delta overlap; (iii) the mirror stays for
CLI/metrics — cosmetic drift only, no correctness consumer remains
(the Go sweep's backfill must move to the table or to the helper's
out-of-sync latch re-export — named in §4.0.1).

## Verdict

**PLAN-NEEDS-REVISION on v15.19-as-substrate; PATH B (table-truth)
RECOMMENDED in the §4.0 fork, with PATH A documented for
completeness.** The option-(a) registry core is unaffected and
retains my earlier endorsements. If Codex and AGY ratify the fork
in round 33, v15.21 should do the surgical section rewrites per
§4.0.1 and this becomes terminal; if either demands PATH A, they
must answer the control-socket contention foreclose with evidence.
