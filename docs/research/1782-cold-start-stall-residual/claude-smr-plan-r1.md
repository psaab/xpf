# Claude SMR hostile plan-review — #1782 r1 (`fa4d5d588`)

**Verdict: PLAN-NEEDS-MINOR**

The capture-first framing and the four hypotheses are sound and code-grounded,
but reading the cold path end-to-end exposes three things the plan gets wrong or
under-specifies. None is fatal; all are fixable in a v2 before plan-ready.

## Finding 1 (must-fix) — the hypothesis ranking is inverted

The plan calls H1 (3 s neg-cache lockout) "prime." Tracing the actual cold
path, **H1 is an amplifier, not the root**, and the real precondition is H2:

1. First cold packet after idle: `dynamic_neighbors` **miss** → packet is
   **buffered** in `pending_neigh` + resolver nudged. (NOT dropped, NOT
   neg-cached yet.)
2. The neg entry is armed only **after** the `pending_neigh` entry times out —
   `neighbor_dispatch.rs:118` calls `neg_neigh_record` from `retry_pending_neigh`
   on timeout, where `PENDING_NEIGH_TIMEOUT_NS` defaults to ~800 ms (tied to
   kernel `retrans_time_ms`, `neighbor_dispatch.rs:80-87`).
3. Then the 3 s neg lockout (`poll_descriptor/mod.rs:2038`) drops subsequent
   packets, but per #1769 it **still routes the key through the resolver**
   (`poll_descriptor/mod.rs:2053+`) — so resolution keeps progressing.

So the necessary precondition is **H2: the next-hop is ABSENT from
`dynamic_neighbors` after overnight idle even though the kernel keeps it
DELAY-usable** (a DELNEIGH/GC during idle removed it via
`neighbor.rs:289`). Without that absence, the dump path
(`neighbor.rs:346-351`, accepts STALE/DELAY) would serve the cold packet with
zero stall. v2 should re-rank: **H2 = root cause**; H1 + the 800 ms pending
timeout + H4 = wall-clock amplifiers; **H3 = why resolution is slow enough to
hit the amplifiers.**

## Finding 2 (must-fix) — H3 is the likely "why slow," and the plan under-weights it

Because the resolver IS nudged even during neg-lockout, the question is not
"does it resolve" but "why does it take >800 ms–3 s." The crux:
`neighbor_resolver.rs` confirms only **REACHABLE/PERMANENT** into
`dynamic_neighbors` and **probes-and-waits** on a DELAY/STALE kernel entry
rather than reusing the lladdr the kernel already has. So even though the
kernel can forward immediately (DELAY is usable kernel-side), the userspace
fast path waits a full DELAY→PROBE→REACHABLE round-trip before
`dynamic_neighbors` is populated. That round-trip IS the few-second stall. v2
should elevate H3 as the prime "why-slow" suspect and make **Path-Option B**
(confirm a DELAY-usable kernel lladdr into `dynamic_neighbors` from the
resolver GET) the leading candidate — it attacks the slow path at the source
without touching the neg cache (avoiding the #1651 trap).

## Finding 3 (must-fix) — the capture is gated on a prior instrumentation merge; the plan blurs this

§7 lists two instrumentation gaps (`neg_neigh_fast_fail` is debug-only at
`types/runtime.rs:261` + `worker/loop_body/mod.rs`; no `dynamic_neighbors`
membership query). Both are **code that must merge before the harness can
read them** — but §6/§7 read as if the harness is a pure research artifact.
This is a sequencing chicken-and-egg. v2 must make explicit that this is a
**two-PR sequence**:
- PR-1 (small, capture-only `/engineer`): expose
  `xpf_userspace_neg_neigh_fast_fail_total` + a `dynamic_neighbors`
  membership/count surface. Mergeable on its own (pure observability).
- Operator runs one overnight capture with PR-1 live.
- PR-2 (`/engineer`): the actual fix, Path-Option chosen by the capture.

The `/research` deliverable is the harness script + PR-1 spec + the
hypothesis/signature table — not a runnable end-to-end capture today.

## Finding 4 (minor) — H4's applicability is conditional, state it precisely

Because the first SYN is **buffered** (Finding 1 step 1), not dropped, H4
(SYN-retransmit backoff) only fires if resolution exceeds the ~800 ms pending
timeout (then the buffered SYN is dropped and TCP retransmits at ~1 s). So H4
is downstream of "resolution slower than 800 ms," which is H3. If H3 is fixed
(sub-800 ms resolution by reusing the kernel lladdr), H4 never triggers and the
PLAN-KILL-if-H4-dominates branch is moot. v2 should tie H4 to the 800 ms
pending-timeout threshold explicitly rather than presenting it as independent.

## Axes that are fine

- The "multiple flows together" → shared `(ifindex,ip)` reasoning is plausible
  AND the plan correctly flags (Q5) the alternative (per-worker/RSS or
  snapshot-regen) for the capture to rule out. Keep.
- The #1651 SYN-flood trap on Option A and the #1769 epoch-race constraint on
  Option B are correctly identified (§8/§9).
- PLAN-KILL-if-acceptable-envelope is a legitimate listed outcome. Keep.
- Capture-first discipline (no speculative fix) is correct and matches the
  project's PLAN-KILL history on unvalidated perf/fix work.

## Required for v2
Re-rank (H2 root / H3 why-slow / H1+H4 amplifiers); make Option B the leading
candidate with B+D as the compound; add the 800 ms-pending × 3 s-neg ×
first-packet-buffered trace to §5; restructure §6/§7 as an explicit two-PR
sequence (capture-instrumentation PR-1 → overnight capture → fix PR-2).
