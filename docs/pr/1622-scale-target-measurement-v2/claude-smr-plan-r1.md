# Claude SMR plan-review r1 — #1622 Scale Target measurement v2

**Reviewer role**: domain SMR — perf measurement methodology, synthetic
workload design, Prometheus histogram percentile extraction, AF_XDP
cold-path microarchitecture, CPU clock/TSC semantics on virtualized
guests, Junos config-deploy contention.

**Plan under review**: `docs/pr/1622-scale-target-measurement-v2/plan.md` v1 @ commit `9d830d12e`.

## Verdict: **PLAN-NEEDS-MAJOR**

Plan v1 is well-structured and correctly identifies most of the prior
PLAN-KILL stream's findings (cross-worker first_key gate, TSC gate,
sample budget for p9999). But three findings need explicit fixes before
PLAN-READY can be reached:

- **F1 [CRITICAL]**: bucket-0 resolution floor (512 ns midpoint) makes
  10/100-rule cell numbers structurally meaningless.
- **F2 [HIGH]**: per-zone-pair semantics in the published table are
  ambiguous — the 16-slot splitmix64 hash is not a direct zone-pair map.
- **F3 [HIGH]**: synthetic policy is a flat linear scan (#1632 Path B
  flattens to sorted lookup) — measurement does NOT inform #1609 v2
  multi-stage DAG.

I will hold MERGE-READY-PLAN until v2 addresses these three.

## Findings

### F1 [CRITICAL]: Bucket-0 resolution floor structurally collapses the 10/100-rule rows

**Quote (plan §2)**: "Bucket 0: `[0, 1024)` ns (`le=1023`)."

**Quote (plan §4.3 step 9)**: "For bucket 0 (`[0, 1024)`), midpoint = 512."

**Quote (plan §7 Q6)**: "For tight cold-path samples (~100-1000 ns, all in bucket 0), this means **the reported p50 is dominated by bucket-0 midpoint resolution** — i.e. we report `p50 ≈ 512 ns` for the 10-rule cell unless bucket 1+ get populated. This is a HARD LIMIT of the 24-bucket layout."

The 10-rule and 100-rule cells in Table A1/A2 are the cells most operators will read first, because they bound the *minimum* cold-path latency. Under any realistic CPU + AF_XDP zero-copy stack, the cold-path policy-eval at 10 rules is ~50-150 ns; at 100 rules it's ~500-1500 ns. The published row will read:

| Rule count | p50 (ns) | p99 (ns) |
|---|---|---|
| 10 | 512 | 512 |
| 100 | 512 | 1535 |

The 10-rule row is **uninformative** — `512 ns` is the bucket midpoint, not a measured number. Operators citing "Table A1 row 10 → p50 = 512 ns" as an empirical bound will be wrong by potentially 4-10×.

The plan acknowledges this as Q6 and offers PLAN-KILL as an option, but does NOT pick a remedy. The remedy choices are:
- **Remedy 1 (out of scope)**: change #1619 to use finer-grained low-end buckets (e.g. `[0,64), [64,128), [128,256), [256,512), [512,1024)`). This adds 4 new buckets and changes the wire-protocol — out of scope here.
- **Remedy 2 (in scope)**: footnote the 10-rule row explicitly as `BUCKET-0-FLOOR; sub-1024 ns latency not resolvable`. Publish the bucket histogram in the TSV anyway so future analysis can use it.
- **Remedy 3 (in scope)**: use the `sum_ns / samples` ratio as a complementary metric — `mean_ns = sum_ns / samples` is NOT bucket-quantized and gives an unbiased mean estimate (though not a percentile). Publish `mean_ns` as a column alongside `p50_ns`. For the 10-rule cell, `mean_ns` will read e.g. "85 ns" giving a useful bound.

**Action**: plan v2 MUST adopt Remedy 2 + Remedy 3. Add a `mean_ns` column to the TSV and the published table (computed as `sum(sum_ns[s]) / sum(samples[s])` across non-aliased slots). Add a footnote to bucket-0-dominated rows.

### F2 [HIGH]: Per-zone-pair semantics ambiguity

**Quote (plan §7 Q5)**: "the 16 splitmix64 slots are a *hash* of `(from_zone, to_zone)`, not a direct map. The harness publishes **per-slot percentiles only after cross-worker first_key validation passes**, with the `first_key` value identifying which zone-pair the slot covers. If the published row claims 'Table A1 / 1000 rules / p50 = X ns', that's the *aggregate across all safe-to-publish slots*."

The published table caption says nothing about "aggregate" — operators will reasonably read "Table A1 / 1000 rules / p50 = X ns" as **the** p50 of the cold-path eval, period. The aggregate-vs-per-zone-pair distinction needs to be:
- (a) **named explicitly** in the column header: rename `p50` to `p50_aggregate` (or `p50_across_published_slots`).
- (b) **disclosed in the section preamble**: state that the published number is the aggregate across non-aliased zone-pair slots, derived by union-ing the per-slot histograms; per-zone-pair detail lives in the raw TSV with the `first_key` value identifying each slot's zone-pair.

Without this, the table is misleading.

**Action**: plan v2 MUST commit to the rename + the preamble disclosure.

### F3 [HIGH]: Linear-scan policy doesn't inform #1609 v2 DAG

**Quote (issue body)**: "Cross-link comment on #1609 v2 PR linking the measured numbers — closes the empirical-grounding gap."

**Quote (plan §11 acceptance)**: "`#1609 v2 acceptance criterion UNBLOCKED` noted in PR body."

But #1632 Path B just shipped, which flattens the policy graph into a sorted linear-scan lookup. The synthetic policy generated by this PR is a flat list of N rules across 4 zone-pairs. The cold-path-eval the harness measures is the **post-#1632 flat sorted lookup**, NOT the multi-stage DAG that #1609 v2 wants to validate.

If #1609 v2 has not yet shipped the DAG, then the empirical-grounding this PR provides is a **baseline** for the DAG to beat, not an unblock of the DAG itself. The plan v1 language `"UNBLOCKED"` is too strong — at best this PR provides a *baseline* against which #1609 v2 can claim a relative improvement.

**Action**: plan v2 MUST downgrade the #1609 v2 claim from "UNBLOCKED" to "baseline established for #1609 v2 DAG to beat". The cross-link comment on the #1609 v2 PR (if open) should say: "post-#1632 flat-lookup baseline at 10K rules: p50 = X ns, mean = Y ns. DAG must beat this at the same rule count."

### F4 [MED]: Zone-pair default = 4 is unrepresentative of production policy graphs

**Quote (plan §3.2)**: "Why 4 zone-pairs by default: the 16-slot `splitmix64` `first_key` bookkeeping aliases at 5+ active zone-pairs on the loss cluster"

Real production firewalls have 10-30 zones and 50-300 active zone-pairs. The 4-zone-pair default is a measurement convenience, not a realistic workload. The plan should:
- Run an additional cell at zone-pairs=8 (so the alias gate fires and the publication gate transparently excludes ~50% of slots — this validates the gate works).
- Document that the published numbers are for the **4 active zone-pair regime**, with a footnote about behavior at higher zone-pair counts.

**Action**: plan v2 SHOULD add a zone-pairs=8 cell to the sweep. NOT required for MERGE-READY-PLAN (this is a "nice to have" not a "must have").

### F5 [MED]: 10K-rule policy commit time is unmeasured

**Quote (plan §10)**: "Junos parser is O(n) so 10K rules commits in ~5-10 s; verified via inspection (no measurement yet)"

"Verified via inspection" is not verified. The commit path includes parser + compiler + diff + apply + push to dataplane. At 10K rules with 100 address-books × 1000 CIDRs = 100K CIDR entries, the compiler does prefix-set deduplication + LPM trie compaction. This can take longer than 60 s. If commit > 60 s, the harness wall-clock blows out.

**Action**: plan v2 MUST pre-flight a 10K-rule commit dry-run in the implementation phase BEFORE invoking the full sweep. If commit > 60 s, the 10K cell drops to STAGED status with a follow-up issue filed.

### F6 [LOW]: Session-table churn vs cold-path eval rate

**Quote (plan §11)**: "30 s × 2.96 Mpps × 1/256 sample-mask = 347 K sample events per worker"

This assumes every packet triggers cold-path eval. With cohort=unbounded (4.2 B unique 5-tuples) and DEFAULT_MAX_SESSIONS = 131_072, the session table churns at ~30 K evictions/sec per worker. The cold-path-eval rate per packet may be LOWER than 1.0 if some packets hit existing session entries (re-flow). At steady state churn, every packet IS a session-miss → cold-path eval, so the math holds — but only at steady state. The 2 s warmup might not be enough to reach steady state.

**Action**: plan v2 SHOULD bump `--warmup` to 5 s for the unbounded-cohort cells to give the session table time to saturate. NOT required for MERGE-READY-PLAN.

### F7 [LOW]: TSC threshold = 5% deviation between workers

**Quote (plan §7 Q7)**: "deviation > 5% between any two workers sets `tsc_gated_publish=false`. Reviewer may challenge — is 5% the right threshold?"

5% TSC deviation is generous. On a single-socket KVM guest with `constant_tsc + nonstop_tsc` passed through, `ns_per_tsc_q32` should agree across workers to within 0.01% (the rdtscp calibration is a 4096-iteration measurement at startup; the median has very low variance). A 5% deviation indicates a real problem (vCPU migration during calibration, frequency scaling, NTP slewing). Recommend tightening to 1%.

**Action**: plan v2 SHOULD tighten the threshold to 1%. NOT required for MERGE-READY-PLAN.

### F8 [LOW]: Cohort=bounded p9999 omission rationale

**Quote (plan §4.4)**: "`p9999_ns` is populated **only** for unbounded cohort rows where `samples_total >= 58_586`"

Bounded cohort (131_072 session table cap) reaches steady state quickly; samples_total can still hit 58K+ at 30 s. The plan's blanket "p9999 omitted for bounded" is overly conservative. Recommend: populate p9999 in bounded if `samples_total >= 58_586` AND `slots_published >= 4`.

**Action**: plan v2 SHOULD relax the bounded-cohort p9999 omission. NOT required for MERGE-READY-PLAN.

## Summary

Three must-fix findings (F1/F2/F3). Three nice-to-have (F4/F5/F6/F7/F8). I am NOT PLAN-KILLING this — the underlying methodology is sound, the wire surface is verified live, and the cluster is reachable. But the bucket-0 floor, the per-zone-pair semantics, and the #1609 v2 claim need explicit fixes in v2.

When plan v2 lands with F1+F2+F3 addressed, I will write `claude-smr-plan-r2.md` with verdict MERGE-READY-PLAN (assuming no new regressions).
