# #1376 Userspace Port Mirroring Plan

## Goal

Support `forwarding-options port-mirroring` in userspace-dp so ingress mirror
configs no longer fall back to the eBPF dataplane.

## Dependencies

- #1381 should land first so capability removal and config snapshot shape are
  independent of the embedded eBPF manager.
- Cross-binding inject should use the same ownership discipline as existing
  userspace fabric/cross-binding transmit paths.

## Design

Add `MirrorConfig { output_ifindex, rate }` to the userspace snapshot and Rust
state. Preserve the current eBPF data model: one mirror entry per ingress
ifindex. Duplicate ingress ifindex config must be rejected at commit time.

Mirroring runs after ingress policy/forwarding decision while the original
packet bytes are still available. A matched mirror allocates a clone frame,
copies the full L2 frame with no truncation, and queues it to the configured
output binding.

Cross-binding mirror uses cross-binding inject only. Do not use the slow-path
TUN sink because TUN is L3 and strips Ethernet, while port mirroring requires
full L2 packet preservation.

Sampling is per-worker/per-binding, matching the current eBPF per-CPU shape:
`rate == 0` mirrors every packet; `rate == N` mirrors approximately 1 in N for
that binding.

## Hot-Path Invariants

- Normal forwarding wins over mirroring. Mirror clones are discardable under
  pressure.
- Mirror allocation uses a bounded budget or reserve threshold; it cannot drain
  the frame pool needed by primary RX/TX.
- Missing destination binding, queue-full, and no-frame paths drop only the
  mirror clone and account the reason.
- The mirrored bytes are the full original Ethernet frame, including VLAN tags
  and IPv4/IPv6 payload.
- No global sampling atomic unless a future contract explicitly requires exact
  global 1-in-N semantics.

## State and HA Behavior

- Mirror config is snapshot state and is republished on config changes.
- Runtime sampling counters are local per binding and reset on worker restart or
  failover.
- Counters exposed through Rust status, Go protocol, CLI, and Prometheus:
  `mirrored_packets`, `mirrored_bytes`, `mirror_drops_no_frame`,
  `mirror_drops_no_binding`, and `mirror_drops_queue_full`.
- On failover, the new active node mirrors according to the current config; no
  mirror clone state is synchronized.

## Exact Tests

- Cargo: `mirror::sampling_rate_correctness`.
- Cargo: `mirror::cross_binding_inject`.
- Cargo: `mirror::out_of_frame_drops_increment_counter`.
- Cargo: `mirror::missing_destination_binding_drop_counter`.
- Cargo: `mirror::queue_full_drop_counter`.
- Cargo: `mirror::duplicate_ingress_ifindex_rejected`.
- Cargo: `mirror::ipv4_ipv6_full_frame_preservation`.
- Go: userspace snapshot round-trip for mirror config.
- Go: commit validation rejects duplicate ingress mirror entries and logs/skips
  nonexistent output ifindex consistently with current compiler behavior.
- Integration: userspace cluster with mirror config and tcpdump on output
  interface verifies sample ratio, full frame preservation, and primary
  forwarding survival under mirror pressure.

## Non-Goals

- Do not implement a TUN-based mirror sink.
- Do not implement multiple mirror outputs per ingress ifindex.
- Do not make mirror delivery reliable at the expense of forwarding.
- Do not remove eBPF source as part of #1376.
