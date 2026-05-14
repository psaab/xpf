# Shared UMEM Implementation Plan

Status: Revised plan, branch-only until live validation passes

## Summary

The previous plan treated the shared-UMEM bind failure as evidence that
AF_XDP zero-copy shared UMEM does not work across NICs. That conclusion is
wrong. Linux AF_XDP supports `XDP_SHARED_UMEM` across the same queue, across
different queues, and across different netdevs. The current xpf failure is
local:

1. The C bridge still calls `xsk_socket__create`, even though the Rust side
   describes the path as `xsk_socket__create_shared`.
2. Worker startup still creates one `WorkerUmemPool` per binding and passes
   `shared_umem=false`, so no production binding currently shares a UMEM.
3. The Rust wrapper's ring ownership and `WorkerUmem::umem_mut()` API are
   still shaped around private UMEM. A real shared group needs explicit
   private-vs-shared socket creation and a raw UMEM pointer path that does not
   rely on `Rc::get_mut()`.

The new goal is not "turn shared UMEM on everywhere". The goal is to make the
firewall's normal cross-NIC forwarding path capable of in-place shared-UMEM TX,
because that is where xpf pays the current payload copy. Same-device sharing is
useful only as a narrow bring-up/debug milestone; it is not the product target.

## Correct AF_XDP Model

Shared UMEM does not change the basic AF_XDP RX delivery constraint. Packets
still arrive from the NIC queue that RSS selected, and the XDP redirect path
must still respect the queue/socket delivery rules for the running kernel.

Shared UMEM changes buffer ownership:

- each XSK has its own RX and TX rings
- one UMEM allocation can back more than one XSK
- for every unique `{netdev, queue_id}` tuple in a shared group, there must be
  a fill/completion ring pair
- in zero-copy mode, each bound netdev gets its own DMA mapping for the same
  UMEM offsets
- descriptor `addr` values remain UMEM offsets, not device-specific DMA
  addresses

For xpf forwarding, the important win is userspace TX reuse: a frame received
on binding A can be rewritten in the shared UMEM and submitted to binding B's
TX ring without copying the payload into a second UMEM allocation. That is
separate from XDP-layer load balancing and does not make arbitrary XSKMAP
redirects across RX queues safe.

## Current Master Reality

### Bridge is still non-shared

`userspace-dp/csrc/xsk_bridge.c` ignores the per-socket fill/completion rings
and calls:

```c
xsk_socket__create(xsk_out, ifname, queue_id, umem, rx, tx, &cfg)
```

The Rust call sites and errors refer to `xsk_socket__create_shared`, but the
bridge never calls it. A second socket using the same `xsk_umem` therefore
hits libxdp/kernel "busy" behavior instead of the shared-UMEM bind path.

### Worker startup never groups UMEM

`userspace-dp/src/afxdp/worker/mod.rs` allocates a fresh `WorkerUmemPool` for
every binding and always passes `shared_umem=false`. The helper
`shared_umem_group_key_for_device()` exists, but it is test-only and has no
production caller.

### Rust ring ownership is still private-mode shaped

`xsk_ffi::create_xsk_binding()` allocates per-socket fill/completion ring
boxes, but then returns the previous `umem.fill` / `umem.comp` through
`DeviceQueue`:

```rust
fill: std::mem::replace(&mut umem.fill, fill_ring),
comp: std::mem::replace(&mut umem.comp, comp_ring),
```

That is compatible with the current non-shared bridge, where the socket uses
the UMEM's original FQ/CQ. It is wrong for a real shared socket, where the
per-socket FQ/CQ passed to libxdp are the rings the worker must drive.

Also, `WorkerUmem::umem_mut()` uses `Rc::get_mut()`. Once a group has multiple
bindings cloning the same `WorkerUmem`, the code cannot obtain `&mut Umem`
for later socket creation. Shared bind must use a controlled raw pointer path
instead of pretending the UMEM has a unique Rust owner.

### In-place TX is partly ready

`userspace-dp/src/afxdp/tx/dispatch.rs` already has a same-allocation
predicate:

```rust
target_binding.umem.allocation_ptr() == ingress_umem_ptr
```

That path can become the shared-UMEM forwarding fast path once bindings
actually share an allocation. The flow-cache fast path in
`poll_descriptor.rs` is still same-binding-only and should be widened only
after shared bind is proven.

## Design Principles

1. Default runtime attempts cross-NIC shared UMEM on supported dataplane NICs;
   private UMEM is the per-group fallback when live bind validation fails.
2. The bridge must expose private and shared socket creation explicitly.
3. Shared groups are worker-local; no UMEM crosses worker threads.
4. Frame offsets in a shared group are partitioned once at startup, then
   recycled through the existing prepared-TX completion model.
5. Cross-NIC sharing is the primary implementation target because the firewall
   forwards between NICs. Same-device sharing is optional scaffolding for
   isolating bridge/ring bugs.
6. No shared-UMEM change is allowed to weaken current HA deploy, link-cycle,
   and fallback behavior.

## Proposed Implementation

### Phase 0: Repro and Audit Evidence

Phase 0 is bring-up evidence, not a production startup gate. The production
rule is simpler: xpf should try to use cross-NIC shared UMEM by default on
supported dataplane NICs, validate the actual bind result at runtime, and fall
back to private UMEM when the live kernel/driver path rejects the group.

The artifact remains useful as audit evidence for a lab or release note, but
operators should not need to keep `/run/xpf/shared-umem-phase0.json` in sync
just to get copy-free forwarding. Live runtime capability and post-bind
zero-copy validation decide whether a group is used.

The Phase 0 artifact must be machine-readable and include:

- kernel release
- mlx5 driver name and version
- selected NIC interface names and PCI IDs
- selected NIC firmware versions
- libxdp and libbpf versions
- IOMMU mode
- MTU
- queue topology
- selected device set (`selected_device_set`; legacy `selected_device_pair`
  artifacts remain accepted as an alias)
- same-queue, same-netdev/different-queue, and different-netdev result rows
- owner bind flags, secondary bind flags, and post-bind
  `XDP_OPTIONS_ZEROCOPY` result per socket
- create/delete link-cycle result

Add direct repro coverage before changing production bind behavior:

- extend `test/xsk-repro/libbpf_xsk_shared_test.c` to cover:
  - same netdev, same queue
  - same netdev, different queues
  - different mlx5 netdevs
- force `XDP_ZEROCOPY` only on the owner/first bind in each zero-copy shared
  group; secondary shared sockets must bind with exactly `XDP_SHARED_UMEM`
  and none of `XDP_COPY`, `XDP_ZEROCOPY`, `XDP_USE_NEED_WAKEUP`, or
  `XDP_USE_SG`
- assert `XDP_OPTIONS_ZEROCOPY` after bind on the owner socket and every
  secondary shared socket in the zero-copy cells
- verify each shared socket has the correct FQ/CQ pair and can receive/fill
  independently
- run socket delete/link-cycle loops to reproduce or close the old
  `__xsk_setup_xdp_prog` teardown fault
- fail the phase if any socket falls back to copy mode, if any secondary bind
  needs private UMEM, or if teardown/link-cycle produces a fault

The important flag rule is non-negotiable: for libbpf/libxdp shared UMEM, the
owner bind establishes zero-copy and must still be checked after bind.
Secondary sockets join the existing UMEM with exactly `XDP_SHARED_UMEM`; they
must not also pass `XDP_COPY`, `XDP_ZEROCOPY`, `XDP_USE_NEED_WAKEUP`, or
`XDP_USE_SG`. The kernel rejects those flag combinations for shared sockets in
`net/xdp/xsk.c`'s bind validation. Zero-copy is verified after bind through
`XDP_OPTIONS_ZEROCOPY`, not requested again on secondary binds.

### Phase 1: Make the bridge honest

Add two explicit bridge entry points:

- `bridge_xsk_socket_create_private(...)`
- `bridge_xsk_socket_create_shared(...)`

The private function keeps today's baseline behavior. The shared function
calls:

```c
xsk_socket__create_shared(xsk_out, ifname, queue_id, umem,
                          rx, tx, fill, comp, &cfg)
```

Do not switch the baseline private path to shared creation as a side effect.
That keeps the old teardown workaround isolated until shared mode is tested.

### Phase 2: Split Rust XSK creation by ring mode

Replace the single `create_xsk_binding()` helper with an explicit mode:

```rust
enum XskCreateMode {
    PrivateUmem,
    SharedUmem,
}
```

Private mode:

- calls `bridge_xsk_socket_create_private`
- returns the UMEM-owned fill/completion rings as `DeviceQueue`
- preserves current production behavior

Shared mode:

- calls `bridge_xsk_socket_create_shared`
- returns the newly allocated per-socket fill/completion rings as
  `DeviceQueue`
- leaves the original UMEM rings owned by `Umem` unless they are explicitly
  used by the first owner socket
- applies bind flags by socket role:
  - owner socket: normal requested mode flags, including `XDP_ZEROCOPY` when
    the group requires zero-copy; reject the group if post-bind
    `XDP_OPTIONS_ZEROCOPY` is not set
  - secondary shared socket: exactly `XDP_SHARED_UMEM`, with no `XDP_COPY`,
    `XDP_ZEROCOPY`, `XDP_USE_NEED_WAKEUP`, or `XDP_USE_SG`; reject the group
    if post-bind `XDP_OPTIONS_ZEROCOPY` is not set

The diagnostic log should print the mode, bind flags, queue, ifindex, ring
sizes, socket role, and whether the socket reported zero-copy.

### Phase 3: Fix UMEM ownership for shared construction

Introduce a safe worker-local API that can hand libxdp the same raw UMEM
pointer for multiple sockets:

```rust
impl WorkerUmem {
    fn as_raw_umem_ptr(&self) -> *mut XskUmemOpaque;
}
```

`create_xsk_binding_shared()` should use that raw pointer and must not require
`&mut Umem` or `Rc::get_mut()`. The shared path is still single-threaded at
construction time because each worker builds its bindings on one thread.

Also enforce drop order. The XSK sockets must be deleted before the shared
UMEM is deleted. Use an explicit drop wrapper or reorder/wrap fields so
`DeviceQueue` deletion is guaranteed before the last `WorkerUmem` reference
can delete `xsk_umem`.

### Phase 4: Build worker-local cross-NIC UMEM groups

Replace the same-device-only grouping helper with an explicit policy builder
that can construct firewall-relevant cross-NIC groups. Cross-NIC shared UMEM is
the default policy because the firewall normally forwards across NICs and the
copy-free path should be used whenever the device/kernel combination proves it
can support it. The only production knob that should normally matter is the
debug escape hatch that disables shared UMEM.

Modes:

```text
cross-nic/auto/default -> group worker-local eligible cross-NIC bindings
off -> private UMEM only, for debugging or bisecting shared-UMEM issues
same-device-debug -> group by (driver, device_path), only for bring-up tests
```

Cross-NIC eligibility:

- `mlx5_core`
- non-empty PCI device path
- at least two NICs in the group
- selected interfaces are optional; when omitted, xpf discovers all eligible
  worker-local dataplane bindings and groups the distinct NICs automatically
- an explicit interface list may narrow the candidate set for debugging, but
  it is not required for normal operation
- all participating bindings are owned by the same worker
- no `virtio_net`
- zero-copy is required; copy-mode fallback disables the group

Same-device-debug eligibility:

- `mlx5_core`
- same non-empty PCI device path
- at least two bindings in the group
- selected interfaces are optional; an empty list means all eligible same-device
  candidates are considered
- only used to isolate shared bridge/ring/drop-order bugs before cross-NIC
  rollout

For each eligible group:

- compute total frames as the sum of each binding's current private
  `binding_frame_count_for_driver(...)`
- create one `WorkerUmemPool` with that total
- partition offsets from one `VecDeque<u64>` as each binding is constructed
- pass `shared_umem=true`, the group key, and `XskCreateMode::SharedUmem`

Bindings outside an eligible group keep the existing private path.

Shared-group construction must be atomic from the worker's point of view:

- build and bind all sockets in the group into a temporary vector first
- register no XSKMAP entries for the group until every socket is bound and
  post-bind zero-copy validation passes
- if any socket bind or validation fails, delete every socket already created
  for that group, drop the shared `WorkerUmemPool`, mark every binding in the
  group with the same error, and do not leave a partially shared group active
- only after the full group succeeds may the worker move the bindings into the
  live `bindings` vector and register their XSKMAP slots

Runtime bind validation is the deployment contract. An optional Phase 0
artifact is audit material only; runtime selection must not require it, use it
as a hidden knob, or block copy-free forwarding because an audit file is absent
or stale. If the live bind path fails, the group stays private and the reason
is reported in telemetry. If the bind succeeds but post-bind
`XDP_OPTIONS_ZEROCOPY` is false, the group is rejected.

Driver version, selected NIC firmware versions, libxdp/libbpf versions, IOMMU
mode, and the per-cell repro rows remain useful Phase 0 evidence, but the
runtime source of truth is the actual worker-local bind result.

### Phase 5: Use shared allocation for forwarding

Keep the existing conservative copy/direct path for non-shared bindings.

Enable same-allocation in-place forwarding only when:

- ingress and target bindings share `WorkerUmem::allocation_ptr()`
- the source frame is live, not owned/prebuilt
- NAT64 and native tunnel header-size-changing paths are excluded
- CoS ownership checks still pass
- the target TX completion path recycles the original offset only after TX
  completion

`tx/dispatch.rs` already has most of this predicate. After bind validation,
extend the flow-cache fast path in `poll_descriptor.rs` from "same binding"
to "same allocation" using the same checks.

### Phase 6: Telemetry and config contract

Expose enough state to prove what happened:

- shared UMEM mode: off, same-device-debug, cross-nic
- group key per binding
- group total frame count and per-binding frame quota
- socket creation mode: private vs shared
- bind mode: copy vs zero-copy
- in-place TX packets and bytes by binding
- direct-copy TX packets and bytes by binding
- shared-mode bind failures by errno and bind flags

The CLI should make shared mode visibly experimental until the full validation
matrix is green.

### Phase 7: Validation Matrix

Unit tests:

- shared-UMEM policy selection for default-auto, off, same-device-debug, and
  cross-nic modes
- default-auto mode does not require an artifact or explicit interface list
- explicit `off` clears shared-UMEM status and keeps private UMEM
- private bindings never share allocation
- shared groups partition offsets without duplicates
- shared socket creation returns per-socket FQ/CQ rings
- owner and secondary shared socket creation both validate
  `XDP_OPTIONS_ZEROCOPY` after bind
- secondary shared socket creation passes exactly `XDP_SHARED_UMEM`, with no
  `XDP_COPY`, `XDP_ZEROCOPY`, `XDP_USE_NEED_WAKEUP`, or `XDP_USE_SG`
- `WorkerUmem` raw pointer path does not require unique `Rc`
- XSK socket drop happens before UMEM drop
- partial shared-group bind failure rolls back every socket created for that
  group and registers no XSKMAP entries
- same-allocation predicate rejects NAT64/tunnel/prebuilt paths

Direct AF_XDP repro:

- `libbpf_xsk_shared_test` same queue
- `libbpf_xsk_shared_test` different queue same netdev
- `libbpf_xsk_shared_test` different mlx5 netdevs
- all zero-copy cells assert `XDP_OPTIONS_ZEROCOPY`
- repeated create/delete cycles do not fault

xpf lab validation:

- deploy with shared mode off: no behavior change
- deploy with default-auto cross-nic mode: all participating bindings
  bound/ready, no EBUSY
- link-cycle and rolling deploy do not fault
- no frame leak, no ring-full steady-state failure
- cross-NIC firewall transit shows `pending_in_place_tx_packets` rising
- both NICs in the shared group report zero-copy before any performance claim
  is made
- perf shows `memmove` reduction on the real cross-NIC firewall transit path

## Revised Expectations

Cross-NIC shared UMEM is the target. The kernel has supported it for years,
with per-netdev DMA maps for the shared UMEM, and it is the only shared-UMEM
mode that attacks the firewall's normal cross-NIC memcpy.

Same-device shared UMEM is still useful, but only as a bring-up technique. It
can answer "does our bridge call the right libxdp function and drive the right
per-socket FQ/CQ rings?" It cannot answer "did the firewall get faster?" unless
the measured path actually stays on one NIC.

Cross-NIC mode is the normal runtime policy. It remains safe because the bind
path is atomic per group: either every socket in the group binds and reports
zero-copy, or the whole group falls back to private UMEM.

## Loss Lab Deployment Contract

The loss userspace HA config does not need a shared-UMEM stanza for normal
operation. Cross-NIC shared UMEM is attempted by default for eligible
worker-local mlx5 dataplane bindings. Operators can set shared UMEM `mode off`
only when they need a private-UMEM debug/bisect run.

Operational success is not "AF_XDP bind says zerocopy". It is the full chain:

- shared owner sockets bind with zero-copy and normal owner flags
- shared secondary sockets bind with exactly `XDP_SHARED_UMEM`
- the active firewall reports shared-UMEM binding roles for LAN/WAN bindings
- `In-place TX packets` increases during LAN<->WAN forwarding
- `In-place VLAN push desc` / `pop desc` increase for VLAN transitions
- `In-place L2 memmove fb` stays flat
- perf no longer shows `build_forwarded_frame_into_from_frame` as the
  dominant `__memmove_evex_unaligned_erms` caller

If cross-NIC sharing works, it removes the current userspace memcpy from the HA
transit path. If it does not outperform private UMEM in this lab, the failure
should be recorded as an xpf/lab/driver result, not as a general AF_XDP kernel
limitation.

## References

- Local note: `/home/ps/paul.md`
- AF_XDP shared UMEM docs:
  `https://docs.ebpf.io/linux/concepts/af_xdp/#xdp_shared_umem`
- libxdp function signature:
  `https://docs.ebpf.io/ebpf-library/libxdp/functions/xsk_socket__create_shared/`
- Kernel commit adding shared UMEM between devices:
  `a1132430c2c55af62d13e9fca752d46f14d548b3`
- Kernel shared pool implementation:
  `net/xdp/xsk_buff_pool.c::xp_assign_dev_shared`
