# AGY adversarial plan review r2 (v2 @ db1013506) — VERDICT: PLAN-READY (ratify KILL)
# job: adversarial-review-mptuwo4g-hxaiuy

AGY ratifies PLAN-KILL for #1614's symmetric single-egress topology.

- v2 fairly folds r1: §3.A narrowed to topology-conditional; new §3.C
  (symmetric invariant) + §3.D (foreign-egress carve-out as handoff).
- §3.C sound in steady-state loss cluster: every worker holds one reth0
  queue binding -> tx_owner_live_by_tx_ifindex.get(tx_ifindex) always Some
  (loop_body/mod.rs:150-154) -> shared-exact bail always true
  (cross_binding.rs:69). No worker can process reth0.80 egress without a
  reth0 binding. Edge cases (transient flaps; workers>queues overflow cores)
  are degraded/non-chartered, do not save the plan from kill.
- §3.D handoff-not-lever technically correct: changing owner map alters only
  the MPSC handoff target, NOT total_flows/my_count/new_cap in the v8 share
  split (rotate_epoch_v8.rs:308). Egress-owning worker not CPU-bound (18g=14.25G
  solo, #1614 §2.4). Rate-limiting is downstream and unaffected.
- owner_worker_by_queue acts solely as physical packet-steering handoff for
  cores lacking egress access; does not govern CoS lease/rate.
