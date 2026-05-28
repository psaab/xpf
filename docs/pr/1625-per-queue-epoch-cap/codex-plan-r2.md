# Codex plan-review r2 — #1625 per-queue epoch-cap

Task: task-mpplbjne-o3eye4 (broker `unix:/tmp/cxc-W8arzs/broker.sock`).
Reviewer model: gpt-5.4 high effort, with read-only sandbox + rg/sed.

**Verdict: PLAN-KILL**

> "I am the second PLAN-KILL reviewer for `feedback_plan_kill_label_required`."

## 1. Salvageability

Plan v1 is not salvageable with minor revisions. The proposed selector-side per-queue epoch cap is structurally wrong because production already has that authority in the v8 shared queue lease.

Evidence:

- `userspace-dp/src/afxdp/coordinator/mod.rs:1092` allocates v8 leases for every exact queue with non-zero rate:

```rust
if !queue.exact || queue.transmit_rate_bytes == 0 {
    continue;
}
...
SharedCoSQueueLease::new_v8_with_rate_mode(
    queue.transmit_rate_bytes,
```

- `userspace-dp/src/afxdp/cos/token_bucket.rs:180` routes exact queue token top-ups through the shared lease, and `userspace-dp/src/afxdp/cos/token_bucket.rs:99` dispatches v8 leases to `acquire_v8`:

```rust
if queue.config.exact {
    let Some(shared_queue_lease) = shared_queue_lease else {
        return CoSQueueLeaseAcquireTelemetry::default();
    };
...
let granted = lease.acquire_v8(worker_id, now_ns, requested);
```

- `userspace-dp/src/afxdp/types/shared_cos_lease/rotate_epoch_v8.rs:220` already computes the proposed cap formula:

```rust
let new_cap_raw =
    ((self.config.rate_bytes as u128) * (elapsed_ns as u128) / 1_000_000_000u128) as u64;
...
epoch_total_grant_cap.store(new_cap, Ordering::Release);
```

- `userspace-dp/src/afxdp/types/shared_cos_lease/mod.rs:1089` enforces that cap in the primary path, and `mod.rs:1201` enforces it again in surplus:

```rust
if (class_granted as u64) >= cap {
    break;
}
...
let take = still_needed.min(class_room).min(u32::MAX as u64);
```

Adding the same rate × elapsed cap inside `select_exact_cos_guarantee_queue_waterfill` would create a second independent throttle plane. That is not a minor revision problem; it is the wrong mechanism.

## 2. Correct Follow-Up Scope

Choose **A: empirical root-cause investigation with per-class trace counters before proposing any mechanism**.

The next issue should instrument and prove where equalization is introduced:

- v8 epoch cap, granted bytes, worker fair share, worker consumed bytes.
- bypass arms/uses and starvation/demand events around `rotate_epoch_v8.rs:182`.
- `worker_fair_share` distribution from `rotate_epoch_v8.rs:230`.
- selector Phase 1/Phase 2 visits, skips, and queue picks around `queue_service/mod.rs:787` and `queue_service/mod.rs:922`.

B and C are plausible fix directions only after counters prove the fault. D is worth doing as a separate surgical PR for known PR-1618 scaffold bugs, but it is not a valid replacement root-cause plan for #1614 equalization.

## 3. Final Verdict

**PLAN-KILL**

The PR-1625 plan v1 mechanism duplicates v8's existing per-queue per-epoch cap and risks double-throttling without addressing the likely equalization source.
