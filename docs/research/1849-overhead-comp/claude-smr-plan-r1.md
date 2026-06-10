# Claude SMR hostile plan review — #1849 r1

Reviewer: Claude (domain SMR: CoS engine, CPU arch, SW design). Target:
`docs/research/1849-overhead-comp/plan.md` v1 @ `fd70645d6`.

## Findings

### F1 (HIGH) — §3a inventory is incomplete: two rate-domain accumulators missing

The plan's own thesis is that a missed debit site breaks invariant I1
(basis pairing → permanent token leak). Verified misses:

- **`root.nonexact_surplus_under_exact_tokens`** — the #1743 residual
  surplus budget for non-exact queues while exact backlog exists. Credited
  from `residual_rate = shaping_rate_bytes - exact_demand_rate` at
  `cos/queue_service/mod.rs:362-373`; debited with payload `sent_bytes` at
  `cos/tx_completion.rs:730-732,838-840`. Rate-domain by construction
  (denominated against configured rates). Not in the R-table.
- **`SharedExactBacklog::consume_residual_surplus_budget(sent_bytes)`**
  (`cos/tx_completion.rs:727-729`) — the shared (cross-worker) twin of the
  above. Also missing.

R7 gestures at "waterfill budgets" but an I1-grade plan needs these named
with credit+debit line refs, exactly like R1-R5. **Plan v2 must add an R9/R10
row and extend the §10 basis-pairing test matrix.**

### F2 (MEDIUM) — R4 names only the debit side of `surplus_deficit`

The credit/sizing side is `cos/queue_service/mod.rs:1368-1384` (deficit
topped up and compared against `head_len`). If `head_len` becomes wire-basis
(R8) but the R4 credit stays as-is, the pairing is implicit, not proven. Name
both sides in the table.

### F3 (MEDIUM) — equal-flow v8 mixed-basis residual is unstated

R5 compensates `SharedCoSQueueLease::consume` (wire basis), but the
equal-flow clip compares **per-bucket payload TX rates**
(`account_flow_bucket_tx`, `queue_service/mod.rs:1496-1527` settle path,
O2) against the wire-denominated lease share. Opt-in, exact-only feature, so
acceptable as a residual — but the plan must say so explicitly in §11, or
`equal-flow-enforcement` + `overhead-accounting` combine into an
undocumented skew on small-packet flows.

### F4 (LOW) — §6.1 warn-and-strip claim needs a both-shapes test callout

Warn-and-strip "when set without shaping-rate" interacts with the nested
spelling: in the flat-set AST, `shaping-rate <bw> overhead-accounting bytes N`
arrives as children of the `shaping-rate` node, so "set without shaping-rate"
is structurally impossible in the nested spelling — the guard is dead code
unless the spelling moves to unit level (§12 Q5). Plan should resolve Q5
first and only then specify the guard.

### F5 (verification) — claims that check out

- R1/R2/R3/R5/R6/R8 line refs verified against
  `token_bucket.rs:115-296`, `tx_completion.rs:368-379,541-571,690-745`,
  `queue_service/mod.rs:1612-1693`, `queue_service/drain.rs:107-108,246-247`.
- Settle fns all return `(sent_packets, sent_bytes)`
  (`queue_service/mod.rs:1443-1560`) — batch-level `+ n×overhead` claim is
  real; no per-packet loop work needed.
- `cos_item_len` choke point: 14 call sites, all with `queue`/`root` in
  scope (verified by grep) — the per-item helper claim is real.
- Struct placement: `CoSInterfaceRuntime.tokens` is the 3rd u64
  (`types/cos.rs:369-372`); an adjacent `overhead_bytes` lands in the same
  first cacheline touched by every refill/debit. `CoSQueueConfigState` is
  read for `exact`/`guarantee_enabled` at every selection. Zero-extra-line
  claim is credible.
- Junos spelling (`overhead-accounting (frame-mode|cell-mode) bytes
  -120..124` under traffic-control-profiles) verified against Juniper docs.

## Q1 position (the kill question)

**Defer (Option D).** The decisive asymmetry: the *win* is deterministic
math, but the *audience* is empirically zero — no user demand, no framed
link in any deployment or lab, and the loss cluster (the only production
target) is exactly the environment the parent plan called this "dead weight"
for. Against that stands MEDIUM-HIGH correctness churn across what is now
(post-F1) **at least 11 basis-paired sites** in the most
regression-sensitive code in the project, where the historical record
(#1545/#1165/#1207/#1317 plan-kills) says hot-path churn without a
demonstrated consumer loses. The 85-95% headroom guidance in
`docs/cos-wan-sqm.md` is a documented, adequate workaround for a
hypothetical user. The correct disposition is: keep #1849 open with a
demand-gate label, keep this plan (v2, with F1-F4 fixed) as the
ready-to-go implementation recipe, and ship Option B only when the first
real framed-uplink user appears.

## Verdict

**PLAN-KILL** (in the specific Option-D sense: defer pending demand
evidence; plan retained as the implementation recipe). If Codex/AGY converge
instead on ship-now, plan v2 must first fix F1 (inventory completeness),
F2/F3 (basis-pairing explicitness), and F4 (Q5 resolution) before any
PLAN-READY is honest.
