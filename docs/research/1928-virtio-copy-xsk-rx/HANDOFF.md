# #1928 handoff — virtio copy-mode XSK RX delivery gap

**Goal:** make the AF_XDP dataplane *forward transit* on virtio_net multi-queue.
The shim redirects to the XSKMAP but packets never reach the userspace sockets,
so the #1879 appliance forwards nothing on bridges/virtio. #1921's binding fixes
(PR #1927) are a prerequisite and are done; this is the remaining blocker.

## Confirmed (don't re-litigate)
- virtio binds **Copy mode** and **REJECTS zero-copy**: forcing
  `XSK_BIND_FLAGS_ZEROCOPY` → `libxdp private bind(flags=0x000c): Invalid
  argument`. So **Path 1 (ZC) is out** for virtio on this kernel/backend.
- The shim is attached **native** (`prog/xdp id … xdp_userspace_p`), ingress
  allowlist has the dataplane ifindexes, bindings report
  registered+armed+bound+xsk_registered+**ready**, ctrl **enabled**. Despite all
  that: `rx_xdp_redirects` climbs on all queues but **0 transit sessions, 0
  `tx_completions_total`** → the dataplane does not forward.
- **Forwarding signal = `Unicast-sessions` + `xpf_userspace_binding_tx_completions_total`.**
  `xpf_userspace_binding_rx_packets_total` is a **RED HERRING** — it is 0 even on
  the *working* mlx5 loss cluster. Do not use it.
- v6 ping "works" only via the **kernel** (return route); v4 fails (kernel has no
  SNAT). Neither proves dataplane forwarding.

## Three converged candidate roots (Codex + AGY r1, all code-grounded)
Isolate which one(s) actually cause the drop — do NOT assume:
- **(a) partial fill-prime.** `prime_fill_ring_offsets` may reserve only a
  partial batch (`userspace-dp/src/xsk_ffi.rs:514-541`) and the uninserted
  offsets are NOT retained in `pending_fill_frames`
  (`userspace-dp/src/afxdp/worker/mod.rs:395-402`) → fill ring under-fed; in copy
  mode the kernel drops redirected frames with no fill buffer to copy into.
- **(b) missing `XDP_USE_NEED_WAKEUP` in copy mode.** Copy-mode virtio bind may
  omit need-wakeup so the NAPI-driving logic doesn't run and the fill ring is
  never serviced. (Bind flags: `userspace-dp/src/afxdp/bind.rs:5-9,169-199`;
  wake path: `userspace-dp/src/afxdp/tx/rings.rs:154-200`.)
- **(c) XSKMAP slot↔queue↔bound-ring mismatch.** `rx_xdp_redirects` counts the
  XDP redirect *action*, not delivery. The kernel drops post-redirect if the XSK
  at `xsk_map[slot]` isn't bound to the arriving (netdev, queue). Verify the
  shim's `binding.slot` redirect (`userspace-xdp/src/lib.rs:670-680`) vs the
  registered slot (`userspace-dp/src/afxdp/worker/mod.rs:768-786`) vs each
  socket's actual bound `socket_queue_id`/ifindex.

## Expanded Phase-0 — capture ALL of these on the venue, per binding/queue
1. forced-ZC errno (done: EINVAL flags=0x000c) + negotiated `XDP_OPTIONS`
   (`getsockopt(SOL_XDP, XDP_OPTIONS)` — already in `query_bound_xsk_mode`).
2. `rx_fill_ring_empty_descs` (kernel `xdp_statistics`, already collected at
   `userspace-dp/src/afxdp/worker/loop_body/mod.rs:962`) — directly tests (a)/(b).
3. raw fill ring + RX ring producer/consumer indices over time (is the fill ring
   draining to empty and staying empty?).
4. shim trace stage/slot/selected_queue (`USERSPACE_TRACE`, `lib.rs:670`) for a
   known test flow.
5. each XSK's bound tuple: ifindex + `socket_queue_id` vs the slot it's
   registered at vs the queue the shim redirects from — tests (c).

This is the decision data: (a)/(b) ⇒ fill ring shows empty descs / never
serviced; (c) ⇒ redirect targets a slot whose XSK is bound to a different queue.

## Venue + iteration
- **t1921-fw** (local incus), 4-vCPU → 4-queue virtio. Bridges `t1921-mgmt/lan/
  wan`; hosts `t1921-lan-host` (10.66.1.10 / fd66:1::10, gw=appliance) and
  `t1921-wan-host` (10.66.2.10 / fd66:2::10). Config: `/tmp/t1921/router.conf`
  (LAN ge-0/0/0 10.66.1.1, WAN ge-0/0/1 10.66.2.1, lan→wan permit + interface
  SNAT, v4+v6). Deploy: `scripts/deploy/xpf-deploy.py deploy
  /tmp/t1921/standalone-1921.yaml` (image alias `xpf-appliance-1921`).
- **Fix-iteration loop** (no re-bake): `incus exec t1921-fw -- systemctl stop
  xpfd` → `incus file push xpf-userspace-dp t1921-fw/usr/local/sbin/...` →
  `systemctl start xpfd`. (Binary is text-file-busy unless xpfd is stopped.)
- Before each test, seed the WAN ARP: `incus exec t1921-wan-host -- ping -c2
  10.66.2.1` (the dataplane needs the WAN next-hop resolved).
- Branch this work on top of PR #1927 (it has the dedup → 8 clean bindings); the
  research worktree (off master) does NOT have the dedup.

## GOTCHAS (these cost real time this session)
- **BUILD TRAP:** `make build-userspace-dp` installs from
  `userspace-dp/target/release/`. Do **NOT** run it with
  `CARGO_TARGET_DIR=/dev/shm/cargo` — cargo compiles to /dev/shm but `install`
  copies the **stale** target/release binary → ships old code silently. Build for
  the bake/deploy WITHOUT the override; **verify the binary sha256 changes** after
  an edit, and confirm the deployed `/usr/local/sbin/xpf-userspace-dp` hash matches.
- Codex companion = ONE job globally; a 2nd dispatch kills the 1st. Long sessions
  hit "No jobs recorded" (registry reset) — record task IDs in the ledger.
- AGY `result` flakes/times out; read
  `~/.claude/plugins/data/gemini-abiswas97-gemini/state/jobs/<id>.log` instead.

## Validation gates for the fix
- **virtio (t1921-fw):** LAN→WAN v4+v6 ping 0% loss + iperf3 + nonzero
  `Unicast-sessions` + nonzero `tx_completions_total` + SNAT hits>0.
- **mlx5 no-regression (loss):** `make test-failover` 14/14 + forwarding matrix —
  the bind-flag/fill-ring change must not regress the zero-copy path.
- Generic/fabric virtio (xdpgeneric) must stay copy/auto — keep the
  `interface_uses_generic_xdp` guard (`bind.rs:169-179,201-214`).

## Pointers
- Issue: #1928. Plan + reviews: `docs/research/1928-virtio-copy-xsk-rx/`
  (plan.md v3, codex-plan-r1.md, agy-plan-r1.md, claude-smr-plan-r1.md,
  reviewer-ids.md). Branch: `research/1928-virtio-copy-xsk-rx`.
- Prereq PR: #1927 (binding/rebind, "Part of #1921"). Umbrella: #1921.
- Memory: `project_1921_virtio_mq_afxdp_bug.md`.
