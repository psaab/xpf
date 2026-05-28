PLAN-NEEDS-MAJOR

## Findings

### MAJOR: §2 diagnosis is materially wrong about the observed distribution

`docs/pr/1625-per-queue-epoch-cap/plan.md:66-68` claims:

> `Over 30 s of simul-load the result is RR-style equal-byte allocation across all 11 classes ≈ aggregate / 11 ≈ 1.9 Gbps per class`

That is not what the recorded #1618 smoke shows. `docs/pr/1614-multi-rss-cos/smoke-finding.md:9-22` shows roughly equal **percentage of shape**, not equal bytes:

> `iperf-100m | 0.10 G | 0.02 G | 20%`  
> `iperf-24g | 24.00 G | 3.73 G | 16%`

The plan also says token buckets do not gate because large queues replenish to burst on every fast revisit: `plan.md:63-66`. Existing exact queues are not using the plain refill path. `userspace-dp/src/afxdp/cos/token_bucket.rs:180-203` routes exact queues through the shared lease path, and `userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1089-1097` caps class grants by `epoch_total_grant_cap`. That cap is computed as `rate × elapsed_ns / 1e9` in `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:220-225`.

The real scaffold defect I can verify is the persistent Phase-2 lock-in: Phase 1 only refills when `waterfill_pass1_remaining_bytes == 0` (`queue_service/mod.rs:787-801`), but if Phase 1 breaks with a positive remainder (`queue_service/mod.rs:889-893`) and Phase 2 keeps returning work, the reset at `queue_service/mod.rs:1002-1005` is never reached. The timer reset in §3 may fix that, but the plan’s stated diagnosis is not accurate enough.

### MAJOR: §3 cap does not actually cap unless the budget is clipped to remaining allowance

The plan checks only whether the queue is already at/above allowance:

`docs/pr/1625-per-queue-epoch-cap/plan.md:142-146`:

> `if queue.hot.epoch_bytes_serviced >= allowance { continue; }`

Then it debits the full selected budget:

`plan.md:202-207`:

> `epoch_bytes_serviced = ... saturating_add(candidate_budget)`

Existing candidate budget can be much larger than the remaining allowance:

`userspace-dp/src/afxdp/cos/queue_service/mod.rs:984-989`:

> `candidate_budget = queue.hot.tokens.min(cos_guarantee_quantum_bytes(queue)).max(head_len)`

and the quantum is clamped up to 512 KiB:

`userspace-dp/src/afxdp/cos/queue_service/mod.rs:1534-1540`.

Worked counterexample:

- If the intended cap for a large class is 6 Gbps over 200 us, allowance is `750,000,000 B/s × 0.0002 = 150,000 B`.
- A 24g queue’s `candidate_budget` can be `524,288 B`.
- Since `epoch_bytes_serviced = 0 < 150,000`, the queue is selected.
- The first visit can debit/send up to `524,288 B`, already 3.5x the intended epoch cap.

Even under the plan’s own “true rate” helper, 24g allowance is `3,000,000,000 B/s × 0.0002 = 600,000 B`, not 150 KB. First visit sends 524,288 B; second visit is still allowed because `524,288 < 600,000`; total can become 1,048,576 B in one epoch.

Required design fix: compute `remaining = allowance - epoch_bytes_serviced`, require or handle `remaining >= head_len`, and pass `candidate_budget.min(remaining)` into service. Otherwise §3 property 1 at `plan.md:212-214` is false.

### MAJOR: accounting proposed at selection time is wrong for this pipeline

The plan debits `epoch_bytes_serviced` in the selector (`plan.md:195-208`). The actual TX path only knows committed bytes after submit/settle:

`userspace-dp/src/afxdp/cos/queue_service/service.rs:172-194` calls `settle_exact_local_fifo_submission(...)`, then `apply_direct_exact_send_result(...)`.

`userspace-dp/src/afxdp/cos/tx_completion.rs:524-533` applies accounting using `sent_bytes`, not requested budget.

TX ring partial/zero insert is real: `service.rs:155-166` and `service.rs:322-338` return false on insert failure after scratch build. If the new epoch counter is debited in the selector by `candidate_budget`, a no-progress or partial-progress drain consumes epoch allowance without sending bytes. That can starve a class for the epoch and make unit tests lie.

Required design fix: account actual `sent_bytes` in or adjacent to `apply_direct_exact_queue_accounting`, not the selector’s requested budget.

### MAJOR: §4 cross-binding analysis is oversimplified and partly contradicts existing exact-queue leases

The plan says shared coordination exists for `shared_exact` queues only:

`docs/pr/1625-per-queue-epoch-cap/plan.md:232-240`.

But the coordinator allocates queue leases for all exact queues with a transmit rate:

`userspace-dp/src/afxdp/coordinator/mod.rs:1092-1127`.

Workers attach that lease for exact queues:

`userspace-dp/src/afxdp/worker/cos/mod.rs:198-200`.

So the statement “2 bindings each see 50% ⇒ effective cap = 2× rate” is true for a purely per-binding counter, but not generally true for the existing exact-queue path when the shared lease is present and consumed. If §1625 intentionally adds a second local cap on top of the v8 global cap, the plan needs to say exactly which queues are lease-capped, which are only local-capped, and why the new counter changes the smoke distribution beyond the timer reset.

### MEDIUM: §5 floor is not just a harmless liveness floor

`docs/pr/1625-per-queue-epoch-cap/plan.md:273-280` floors allowance at 1500 B. Claude SMR calls it a no-op for MTU-sized heads, but that is only conditionally true. It is not a no-op for small packets, and it becomes actively misleading once the implementation clips to remaining allowance.

Also, existing token buckets already provide low-rate liveness by accumulating tokens until `queue.hot.tokens >= head_len`; the exact selector enforces that gate at `queue_service/mod.rs:853-875`. A 5 Mbps queue does not need a fake 1500 B per 200 us allowance to eventually send a packet. The floor changes the burst-drain envelope to 60 Mbps while tokens exist.

Recommendation: remove the floor from the epoch allowance. Treat first-packet overshoot, if allowed, as an explicit MTU/head-len exception, not as “allowance.”

### MAJOR: §6/§8 smoke gate is underspecified because the fixture does not enable guarantee-rate

The plan says Pass C is:

`docs/pr/1625-per-queue-epoch-cap/plan.md:409-413`:

> `./test/incus/cos-simul-load-smoke.sh push`  
> small classes achieve ≥95%

But the canonical fixture only sets scheduler rates and shaping:

`test/incus/cos-iperf-config.set:69-70`:

> `scheduler-map bandwidth-limit`  
> `shaping-rate 25g`

There is no `oversubscription-policy guarantee-rate` in `test/incus/cos-iperf-config.set`. The apply script loads that fixture as-is at `test/incus/apply-cos-config.sh:68-74`. The smoke reducer even says gate 1 applies “if guarantee-rate mode active” at `test/incus/cos-simul-load-smoke.sh:167-169`.

Required fix: §8.6 must include the exact CLI line or fixture change that sets `oversubscription-policy guarantee-rate 0.7` before Pass C. Otherwise the blocking gate is not testing this PR’s path.

### MEDIUM: test plan misses the invariants most likely to fail

The five cargo tests in `plan.md:338-359` are not sufficient. Add tests for:

- Cap clipping: selected `secondary_budget` must be `<= allowance - epoch_bytes_serviced`.
- Actual-byte accounting: TX ring partial/zero insert must not burn a full epoch allowance.
- Positive `pass1_remaining_bytes` reset on timer rotation, proving the Phase-2 lock-in is broken.
- Shared-lease interaction: exact queue with v8 lease plus local epoch cap must not double-throttle below configured rate.
- Empty mid-epoch semantics: queue becoming empty should not reset `epoch_bytes_serviced`; only epoch rotation should.

### Prior #1618 context

My r1 MAJOR was that `oversubscription_guarantee_fraction` was not actually used. That was addressed in current code: `queue_service/mod.rs:797-799` computes `pass1 = quantum_sum × frac`.

But the new plan reopens a semantics problem: `plan.md:488-499` says fraction controls Phase 1 only, while per-queue cap is always true rate. That no longer implements the v5 predicted residual distribution from `docs/pr/1614-multi-rss-cos/plan.md:298-335`; it implements “small-first plus true-rate caps.” That may be acceptable, but it must be documented as a semantic change.

### §11 plan-kill conditions

`docs/pr/1625-per-queue-epoch-cap/plan.md:516-525` lists testable classes of failure, but not the instrumentation needed to decide them. Add a required trace/counter dump for:

- selector phase entered,
- queue skipped by epoch cap,
- queue skipped by lease/token cap,
- selected budget,
- actual committed bytes,
- root-token starvation,
- binding id and queue id.

Without that, “root cause outside selector” will be argued from smoke output after the fact instead of diagnosed.

## Verdict

Do not implement v1 as written. The timer-based epoch reset is likely the right direction, but the plan’s cap property is false, the accounting point is wrong, and the smoke gate does not currently enable the target mode.

Codex session ID: 019e6ef1-6871-7df1-bd8d-95e2602e76f3
Resume in Codex: codex resume 019e6ef1-6871-7df1-bd8d-95e2602e76f3
