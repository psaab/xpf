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
- Counters exposed through Rust status, Go protocol, and CLI summary:
  `mirrored_packets`, `mirrored_bytes`, `mirror_drops_no_frame`,
  `mirror_drops_no_binding`, and `mirror_drops_queue_full`.
- On failover, the new active node mirrors according to the current config; no
  mirror clone state is synchronized.

## Current Runtime Slice

The 2026-05-17 runtime slice wires mirror configs into `ForwardingState` and
mirrors forwarded packets while the original frame bytes are still available,
covering the miss/pending-forward path and the self-target flow-cache fast path.
Mirror selection resolves VLAN ingress to the logical ifindex before falling
back to the parent ifindex. Same-worker output copies the full L2 frame into an
output binding TX frame and queues the clone as a prepared TX request;
cross-worker output uses the target binding's live redirect inbox with an owned
full-frame clone. Multi-queue mirror outputs require an exact output queue match;
the single-binding fallback is used only when that output ifindex has no queue
ambiguity. Mirror clones carry the output CoS default/classified queue without
DSCP rewrite, and CoS-bound leftovers are dropped rather than allowed to escape
through backup TX. The clone path keeps a TX-frame reserve and a small
pending-backlog limit so mirror pressure is lossy and does not become a primary
forwarding dependency.

The userspace capability gate remains in place for now. This slice does not yet
claim complete port-mirroring parity for every ingress disposition or for
prebuilt/deferred transmit paths, and it still needs integration evidence with
tcpdump on the mirror output plus primary forwarding survival under mirror
pressure.

## Risks

- Mirror backpressure: mirror clones are intentionally lossy. Queue-full,
  no-frame, and missing-binding cases must drop only the clone and never delay
  primary forwarding.
- Cross-binding ownership: cloned descriptors must use the same recycle/UMEM
  routing discipline as forwarding descriptors; a mirror drop must not return a
  frame to the wrong binding. Ambiguous multi-queue output bindings fail closed
  as `mirror_drops_no_binding` rather than falling back to an arbitrary queue.
- Full-frame fidelity: mirror output must preserve Ethernet/VLAN bytes. Any
  L3-only fallback path silently breaks packet capture/debug workflows.
- Sampling ambiguity: per-binding sampling is cheaper than global exact
  sampling, but docs and counters must not claim exact global 1-in-N behavior.

## Exact Tests

- Cargo: `mirror::sampling_rate_correctness`.
- Cargo: `mirror::cross_binding_inject_preserves_full_frame`.
- Cargo: `mirror::cross_binding_mirror_requires_exact_queue_when_output_is_multiqueue`.
- Cargo: `mirror::live_mirror_requires_exact_queue_when_output_is_multiqueue`.
- Cargo: `mirror::out_of_frame_drops_increment_counter`.
- Cargo: `mirror::missing_destination_binding_drop_counter`.
- Cargo: `mirror::queue_full_drop_counter`.
- Cargo: `mirror::duplicate_ingress_ifindex_rejected`.
- Cargo: `mirror::ipv4_ipv6_full_frame_preservation`.
- Go: userspace snapshot round-trip for mirror config.
- Go/Rust: status/counter wire round-trips include
  `mirrored_packets`, `mirrored_bytes`, `mirror_drops_no_frame`,
  `mirror_drops_no_binding`, and `mirror_drops_queue_full`.
- Go: commit validation rejects duplicate ingress mirror entries and logs/skips
  nonexistent output ifindex consistently with current compiler behavior.
- Go: `deriveUserspaceCapabilities()` admits port-mirroring configs only after
  userspace snapshot/runtime support is wired, and rejects them before that
  point.
- Integration: userspace cluster with mirror config and tcpdump on output
  interface verifies sample ratio, full frame preservation, and primary
  forwarding survival under mirror pressure.

## Non-Goals

- Do not implement a TUN-based mirror sink.
- Do not implement multiple mirror outputs per ingress ifindex.
- Do not make mirror delivery reliable at the expense of forwarding.
- Do not remove eBPF source as part of #1376.
