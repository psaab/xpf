# Codex plan review r2 (v2 @ db1013506) — VERDICT: PLAN-READY (ratify KILL)

Codex ratifies PLAN-KILL on the narrowed §3.C basis.

- §3.C holds for the healthy loss cluster: ge-0-0-2/reth0 is the WAN mlx5
  VF, 6 queues, `workers 6` (CLAUDE.md:302; docs/ha-cluster-userspace.conf:286;
  loss-userspace-shared-umem-phase0-node0.json:29). Planner assigns
  `worker_id = queue_id % workers` (server/helpers.rs:618,625,636) so queue
  IDs 0-5 give workers 0-5 a ge-0-0-2 binding.
- Propagation verified: bringup groups bindings by worker
  (reconcile/bringup.rs:40,123); each worker builds tx_owner_live_by_tx_ifindex
  from its own bindings (loop_body/mod.rs:150; worker/cos/mod.rs:85);
  build_worker_cos_fast_interfaces fills tx_owner_live from that local map
  (worker/cos/mod.rs:184,221). Shared-exact bail fires before owner_worker_id
  consulted (cross_binding.rs:69,123,187). Dispatch-side keeps requests local
  (tx/dispatch/cos.rs:91).
- Caveat (folded into v2 §3.C): degraded/partial-binding state
  (set_binding_state binding.rs:27; bringup skip :42; worker bind failure
  loop_body:115) could make tx_owner_live==None — NOT the chartered healthy
  topology; §5 job-(a) empirical check guards it.
- §3.D caveat (folded): off-topology the foreign-egress handoff destination
  worker DOES update v8 active-flow counters feeding my_share
  (queue_ops/accounting.rs:70; rotate_epoch_v8.rs:306); not fairness-neutral
  in the abstract, but unreachable for reth0.80 in #1614.
- #761 leg stands: round-robin owner builder (coordinator/mod.rs:1183,1216);
  CoS queues sorted by queue_id (forwarding_build/cos.rs:411); add/remove a
  class shifts existing owners; rate-sorted variant worse.
