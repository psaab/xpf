# Claude SMR hostile plan review (driver) — VERDICT: PLAN-READY (ratify KILL)

As domain SMR I independently verified, before the external reviewers
returned, the load-bearing facts:

- The shared-exact owner-redirect bail is conditional on tx_owner_live.is_some()
  (cross_binding.rs:69,123,187); on tx_owner_live==None it routes via
  owner_worker_id (:74,:126,:190; tx/drain/mod.rs:517-534). This is why v1's
  absolute §3.A was wrong and v2 narrowed it.
- tx_owner_live setter chain: worker/cos/mod.rs:221 reads
  tx_owner_live_by_tx_ifindex, built loop_body/mod.rs:150-154 from the
  worker's OWN bindings (build_worker_cos_owner_live_by_tx_ifindex
  worker/cos/mod.rs:85-96). worker_id = queue_id % workers
  (server/helpers.rs:618-636) => all 6 workers bind reth0 => symmetric.
- dispatch/cos.rs:91-99: shared_exact requests push_back local (current
  RSS-placed worker); only non-shared-exact funnels to owner. #1598 comment
  (:39-90) records owner-routing the shared-exact tier rebuilt a funnel
  regression — the project deliberately removed exactly what Path C proposes.
- v8 share split (rotate_epoch_v8.rs:308) is independent of the owner map;
  placement cannot change total_flows/my_count/new_cap.
- #1692 already 3-of-3 established the §3.B gating layer is L1/L3/demand,
  none placement.

Converges with Codex r2 + AGY r2: PLAN-KILL for #1614's topology.
