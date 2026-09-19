# #9506 T12/G2 observer round

Date: 2026-09-19

## Verdict

**Refs remainder.** The locked live round produced 30 rows, all `VOID`; it is not Closes-ready. The fixture and teardown were real, but the running deployed executable could not be attested to this checkout (`exe_check=UNAVAILABLE`) and the S5 consumer path did not produce delivered packets. No product code was changed.

Archive: `/var/tmp/xpf-t12-g2-9506-1789848356`

## Live proof

Command:

```text
./test/incus/with-cluster.sh '9506 S5 T12/G2' -- ./test/incus/t12-g2-9506.sh
```

Attestation output (archive-verbatim):

```text
T12_G2_ATTEST git_sha=fc57a878db4f2fe90a45eaf33a9f252e1e4febfa local_exe_sha=unknown fw0_exe_sha=90b2cf4d29e1a8e9712514d78f3c2662a4db70cb3a4cd0cc3cafcb728c459f0b fw1_exe_sha=90b2cf4d29e1a8e9712514d78f3c2662a4db70cb3a4cd0cc3cafcb728c459f0b exe_check=UNAVAILABLE exe_scope=both archive=/var/tmp/xpf-t12-g2-9506-1789848356
```

Provenance note: the locked round executed at `fc57a878d`. The observer
numbers that the `fc57` code could not emit were derived by post-round
parser runs pinned to this PR head over retained archive inputs. The
`T12_G2_ATTEST`, `T12_G2_RESTORE`, and `T12_G2_SUMMARY` blocks are
archive-verbatim, as are the ledger-row verdicts in the Rows table below;
structural, runtime, listener, VRF, provenance, and queue-economics observer
numbers are post-round parser output.
The runtime observer captured `daemon_active=1`, `socket_ready=1`, and `reinject_sockets=2` on each node. It did **not** infer S5 actor activity from `xpfd`, Rust helper sockets, or NFQUEUE rows: `actor_active=0`, `permit_open=0`, `consumed=0`, `adjudicated=0`, `reinjected=0`, and `delivered=0` because no authoritative product status/counter surface exports those fields. Static queue provenance was measurable (`queue_rows=8`, `queue_ids=8`, `packet_samples=0`, `mismatch=0` per node).
The fixture converged for the T12 v4-native x2 shape (`stN=2/2`, `SA=1/1`, `queues=8/8`, `nft=1/1`). The observer captured structural fence/divert/order shapes on both nodes, but deliberately did not promote them to exact predicates: dynamic pinhole contents/prohibited-name absence, per-rule four-class/PF-family provenance, and same-priority base-chain absence remain unparsed.

Listener/chain census was collected before and during the fixture: fence-alone listeners were 41/39 (fw0/fw1), fixture listeners were 41/39, and NFQUEUE rows were 0 before the fixture and 8 while attached. The baseline, detached-listener, and idle-listener rows remain `VOID` because no workload/latency samples were run. VRF census was collected, but the fixture did not create or enslave a test VRF (`test_created=0`, `attached=0`).

All routed probes across the capture shapes delivered zero packets (`packets=0`, `loss_pct=100`); the 32-tunnel rows observed 128 queue instances per node and 196/197 daemon FDs. Buffer reservations, socket-buffer accounting, generation rotation overlap, and teardown ownership are intentionally `unknown`, not priced from source constants. The retained v4-native 32-tunnel observer backs the dedicated queue-economics row.

Restore/residue proof:

```text
T12_G2_RESTORE fw0_config_cmp=1 fw1_config_cmp=1 fw0_residue_clear=1 fw1_residue_clear=1 residue_probe_error=0 archive=/var/tmp/xpf-t12-g2-9506-1789848356
T12_G2_SUMMARY cells=30 pass=0 fail=0 void=30 exe_check=UNAVAILABLE archive=/var/tmp/xpf-t12-g2-9506-1789848356
```

## Rows

| Gate | Verdict | Reason |
|---|---|---|
| `t12_9506_fence_shape` | VOID | `measurement-incomplete:exact-armed-pinhole-set` |
| `t12_9506_divert_order` | VOID | `measurement-incomplete:exact-provenance-rule-set` |
| `t12_9506_no_bypass` | VOID | `missing-precondition:exe-attestation-UNAVAILABLE-requires-MATCH` |
| `t12_9506_vrf_refusal` | VOID | `measurement-incomplete:test-vrf-not-created-by-fixture` |
| `t12_9506_coexistence_order` | VOID | `measurement-incomplete:exact-order-and-permit-observer-unavailable` |
| `t12_9506_provenance_metadata` | VOID | `product-observer-unavailable:CaptureOrigin-permit-adjudication-reinject-counters` |
| `t12_9506_ifindex_recreate` | VOID | `missing-precondition:exe-attestation-UNAVAILABLE-requires-MATCH` |
| `t12_9506_bridge_conformance` | VOID | `missing-precondition:exe-attestation-UNAVAILABLE-requires-MATCH` |
| `t12_9506_l2_refusal` | VOID | `missing-precondition:exe-attestation-UNAVAILABLE-requires-MATCH` |
| `t12_9506_rotation_atomicity` | VOID | `missing-precondition:exe-attestation-UNAVAILABLE-requires-MATCH` |
| `t12_9506_integration_ownership` | VOID | `missing-precondition:exe-attestation-UNAVAILABLE-requires-MATCH` |
| `t12_9506_pf_bind_scope` | VOID | `missing-precondition:exe-attestation-UNAVAILABLE-requires-MATCH` |
| `g2_9506_fence_baseline` | VOID | `measurement-incomplete:fence-baseline-workload-observer-unavailable` |
| `g2_9506_divert_detached` | VOID | `measurement-incomplete:detached-listener-workload-observer-unavailable` |
| `g2_9506_divert_idle` | VOID | `measurement-incomplete:idle-listener-workload-observer-unavailable` |
| `g2_9506_capture_8t` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_vrf_overhead` | VOID | `measurement-incomplete:test-vrf-not-created-by-fixture` |
| `g2_9506_v4_native_8` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v4_native_16` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v4_native_32` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v4_nat_t_8` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v4_nat_t_16` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v4_nat_t_32` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v6_native_8` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v6_native_16` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v6_native_32` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v6_nat_t_8` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v6_nat_t_16` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_v6_nat_t_32` | VOID | `product-consumer-path-unavailable:delivered=0; CaptureOrigin/permit/adjudication/reinject counters unavailable` |
| `g2_9506_queue_economics` | VOID | `measurement-incomplete:queue-buffer-and-rotation-observer-unavailable` |
The seven `missing-precondition` reasons are abbreviated here; the ledger carries the full r6 scope suffix.

## Remaining product/harness prerequisites

1. Deploy and attest an executable matching this checkout on both firewalls.
2. Export authoritative S5 capture-actor permit, consume/adjudication/reinject, and delivery counters (or an equivalent packet-level witness), then repeat the consumer round.
3. Add exact dynamic fence-set, per-rule provenance/PF-bind, same-priority-chain, VRF transition, and workload latency observers before claiming green rows.
4. Keep the row verdict `Refs` until all 30 cells are `MATCH` on both nodes and the restore/residue proof remains clean.
