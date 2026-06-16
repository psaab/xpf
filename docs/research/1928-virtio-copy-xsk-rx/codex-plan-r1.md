# Codex plan-review r1 (task-mqg2uqd2-xa1mko) — PLAN-NEEDS-MAJOR
1. flags=0 already tries ZC-then-copy (AF_XDP docs) — "virtio never asks ZC" is
   wrong; explicit ZC is a probe not a fix. (bind.rs:194-198, xsk_bridge.c:69-75)
2. fill ring IS primed/refilled (worker/mod.rs:321-349, bind.rs:393-398,
   lifecycle.rs:86/304-310, tx/rings.rs:154-200) BUT smell: prime may reserve a
   partial batch (xsk_ffi.rs:514-541) and uninserted prime offsets are NOT
   retained in pending_fill_frames (worker/mod.rs:395-402).
3. rx_xdp_redirects climbing != delivery — kernel drops if the XSK at the slot
   isn't bound to current netdev+queue. Verify shim trace slot/selected_queue,
   XSKMAP key, socket_queue_id, ifindex (lib.rs:670-680, worker/mod.rs:768-786).
4. Expand Phase 0: forced-ZC errno, negotiated XDP_OPTIONS,
   rx_fill_ring_empty_descs, raw fill/RX ring prod-cons, shim trace slot, socket
   binding tuple.
5. Path 1 won't regress mlx5/i40e if scoped native-virtio-only.
