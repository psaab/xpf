BLOCKING-1: The core `t_refill = quantum/rate = 200us` derivation is not what the park code computes.

Source evidence:

> `queue_service/mod.rs:707-714` passes `head_len`, not `cos_guarantee_quantum_bytes(queue)`, into the wake estimator:
> ```rust
> estimate_cos_queue_wakeup_tick(..., head_len, now_ns, true)
> ```

> `queue_service/mod.rs:1566-1575` computes queue refill from `need_bytes`:
> ```rust
> cos_refill_ns_until(queue_tokens, need_bytes, queue_rate_bytes)?
> let wake_ns = now_ns.saturating_add(root_refill_ns.max(queue_refill_ns));
> ```

> `queue_service/mod.rs:722-726` uses `cos_guarantee_quantum_bytes(queue)` only for service batch sizing:
> ```rust
> let secondary_budget = queue.hot.tokens
>     .min(cos_guarantee_quantum_bytes(queue))
>     .max(head_len);
> ```

So the timer-wheel estimator waits until the next frame can fit, not until a 75K/150K quantum refills. The 200us period may still exist via v8 epoch/lease cadence, but §3 attributes it to the wrong source path. That breaks the leading hypothesis as written.

BLOCKING-2: The measured `guarantee-rate 0.7` path does not use only the legacy exact park branch the plan targets.

Source evidence:

> `queue_service/mod.rs:603-613` dispatches `GuaranteeRate` mode into waterfill:
> ```rust
> if matches!(root.oversubscription_policy, CoSOversubscriptionPolicy::GuaranteeRate)
>     && root.oversubscription_guarantee_fraction > 0.0
> {
>     return select_exact_cos_guarantee_queue_waterfill(...);
> }
> ```

> Waterfill has its own queue-token park site at `queue_service/mod.rs:853-872`:
> ```rust
> if queue.hot.tokens < head_len {
>     ...drain_park_queue_tokens.fetch_add...
>     park_cos_queue(root, queue_idx, wake_tick);
> }
> ```

> Waterfill Phase 2 explicitly does not park at `queue_service/mod.rs:973-982`:
> ```rust
> if root.tokens < head_len || queue.hot.tokens < head_len {
>     // Don't park in Phase 2
>     ... continue;
> }
> ```

A fix scoped to the legacy branch around the plan’s cited `:688` is incomplete for the actual experiment configuration.

BLOCKING-3: §5’s `bytes_consumed = total_granted from acquire_v8` does not prove bytes were transmitted.

Source evidence:

> `token_bucket.rs:99-104` records v8 telemetry at lease acquisition:
> ```rust
> let granted = lease.acquire_v8(worker_id, now_ns, requested);
> telemetry.record_v8_grant(granted);
> ```

> `token_bucket.rs:191-202` adds that grant to local queue tokens:
> ```rust
> let (grant, telemetry) = acquire_via_lease(...);
> queue.hot.tokens = queue.hot.tokens.saturating_add(grant)...
> ```

> Actual sent bytes are accounted later at `tx_completion.rs:524-550`:
> ```rust
> apply_direct_exact_queue_accounting(root, queue_idx, sent_bytes);
> shared_root_lease.consume(sent_bytes);
> shared_queue_lease.consume(sent_bytes);
> ```

> And operator-visible drain bytes are written at `tx_completion.rs:481-489`:
> ```rust
> profile.drain_sent_bytes.fetch_add(sent_bytes, ...);
> profile.drain_guarantee_sent_bytes.fetch_add(sent_bytes, ...);
> ```

The bisection must compare `cap_granted` vs actual `drain_sent_bytes` / TX-submitted bytes, not only `v8_granted_bytes`. Otherwise TX-ring refusal, scratch build failure, restore/retry, or TCP delivery artifacts can be misclassified as “consumed grant.”

MAJOR-1: The “real limiter may be lease target” question is not secondary; the source makes it a first-class competing hypothesis.

Source evidence:

> `shared_cos_lease/mod.rs:690-711` derives `lease_bytes` from the 200us target and clamps it:
> ```rust
> const COS_ROOT_LEASE_TARGET_US: u64 = 200;
> let target_lease_bytes = rate_bytes * COS_ROOT_LEASE_TARGET_US / 1_000_000;
> let lease_bytes = target_lease_bytes.max(1500).min(lease_ceiling);
> ```

> Exact queues top up only to that watermark at `token_bucket.rs:184-201`:
> ```rust
> let lease_bytes = shared_queue_lease.lease_bytes()...
> if queue.hot.tokens >= lease_bytes { return ...; }
> ... lease_bytes.saturating_sub(queue.hot.tokens)
> queue.hot.tokens = queue.hot.tokens.saturating_add(grant)...
> ```

For 3g/6g, `lease_bytes` equals the same 200us worth of bytes as the guarantee quantum. The plan needs to distinguish “wheel loses time after credit is ready” from “the 200us lease/epoch target forces starvation.” Current §6 prematurely chooses wheel-path fixes.

MAJOR-2: F-A is effectively a no-op for same-tick future wakes.

Source evidence:

> `tx_completion.rs:112-114` floors nanoseconds to integer ticks:
> ```rust
> pub(in crate::afxdp) fn cos_tick_for_ns(now_ns: u64) -> u64 {
>     now_ns / COS_TIMER_WHEEL_TICK_NS
> }
> ```

> `queue_service/mod.rs:1575-1576` stores only the floored tick:
> ```rust
> Some(cos_tick_for_ns(wake_ns)
>     .max(cos_tick_for_ns(now_ns).saturating_add(1)))
> ```

If `now_ns` and `wake_ns` are both inside the same 50us tick, `cos_tick_for_ns(wake_ns) == cos_tick_for_ns(now_ns)`. The plan’s proposed “honor computed tick unless <= now_tick” still returns `now_tick + 1`. F-A cannot fix sub-tick refills without a non-wheel fast path or higher-resolution wake representation.

MAJOR-3: F-B’s “bucket WILL refill within a tick” claim conflicts with v8 epoch rotation.

Source evidence:

> `rotate_epoch_v8.rs:35-40` refuses rotation before 200us:
> ```rust
> let start = v8.epoch.epoch_start_ns.load(...);
> if start != 0 && now_ns < start.saturating_add(EPOCH_DURATION_NS) {
>     return;
> }
> ```

> `shared_cos_lease/mod.rs:1041-1046` calls rotation before snapshot:
> ```rust
> self.maybe_rotate_epoch_v8(now_ns);
> let Some((cap, my_share, grace, my_tag)) = self.snapshot_epoch_v8(worker_id) else { ... };
> ```

> `shared_cos_lease/mod.rs:1081-1090` stops granting when worker share or class cap is exhausted:
> ```rust
> if my_consumed >= my_effective_share { break; }
> if class_granted >= cap { break; }
> ```

For exact v8 queues, a sub-tick frame deficit does not imply new grant is available in sub-tick time. Staying runnable can just poll a cap-exhausted lease until the 200us epoch boundary.

MINOR-1: Q1 is safe for 3g/6g, but the plan should state the clamp boundary precisely.

Source evidence:

> `queue_service/mod.rs:1534-1540` clamps guarantee quantum:
> ```rust
> bytes_for_visit.clamp(COS_GUARANTEE_QUANTUM_MIN_BYTES,
>                       COS_GUARANTEE_QUANTUM_MAX_BYTES)
> ```

> `tx/drain/mod.rs:561-563` defines:
> ```rust
> COS_GUARANTEE_VISIT_NS = 200_000
> COS_GUARANTEE_QUANTUM_MAX_BYTES = 512 * 1024
> ```

3g = 75,000 B and 6g = 150,000 B are below 512 KiB, so the clamp does not break flatness for those two classes. The high-rate 24g case is outside that derivation.

Required revisions before readiness: rewrite §3 around `head_len` vs lease/epoch cadence, add waterfill-path instrumentation/fix scope, redefine §5’s bisection around actual `drain_sent_bytes`/TX bytes, and demote F-A or replace it with an explicit fast path.

VERDICT: PLAN-NEEDS-MAJOR
