# AGY (Antigravity) — adversarial plan review r1 (#3617)

Task ID: agent a40412981acdcd272 (agy:agy-rescue). Duration ~217s.

## Verdict: PLAN-KILL-CONCUR

All three key claims survived adversarial scrutiny.

1. **Junos parity** — Official Junos docs confirm host/RE-generated egress
   traffic (ICMP errors, TCP RST, ARP, LACP, BPDUs) is never port-mirrored;
   data-plane mirroring is transit-only. xpf's behaviour is conformant.
2. **`mirror_clone` semantics** — Confirmed the issue misreads the mechanism.
   `mirror_clone: true` flags a frame as a clone copy itself (droppable under TX
   reserve), not a clone trigger. Evidence: `tx/transmit/mod.rs:102`,
   `cos/queue_service/drain.rs:73` and `:253`, `tx/cos_classify.rs:648`; the real
   clone is a separate frame at `mirror/fast_path.rs:167`
   (`enqueue_mirror_clone_to_binding`).
3. **Ingress-only mirroring** — Confirmed. Config compiled at
   `compiler_services.go:1295-1333` reads ingress only; `resolve_mirror_config`
   ingress-keyed. No output-direction mirroring.

## Inaccuracies found (do not flip verdict)

- PTB/Frag-Needed generated ICMP error `mirror_clone: false` is at
  `tx/dispatch/mod.rs:1174`, NOT `:438` (which is inside the TCP segmentation
  loop). — FIXED in r3.
- Time-Exceeded reference at `tx/dispatch/mod.rs:204` (Prebuilt→TxRequest,
  hard-coded `mirror_clone: false`) is correct.

L10 residual stated accurately (no PTB / time-exceeded `mirror_clone` test).
Option B not elevated to DEFER — it would diverge from Junos and has no
driveable scope.

## Note

AGY's background `cargo test` showed 3319 passed / 1 failed
(`event_stream::tests::test_paused_telemetry_eviction_does_not_poison_drain_2875`)
— orthogonal to mirroring; pre-existing/flaky, untouched under read-only.
