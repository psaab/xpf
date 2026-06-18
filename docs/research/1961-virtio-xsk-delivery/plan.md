# #1961 — virtio AF_XDP delivers 0 packets to the XSK: diagnosis-first plan

**Status:** PLAN-READY (v1.3, converged 2026-06-18). Claude SMR PLAN-READY + Codex PLAN-READY (after r1 PLAN-MAJOR fully folded). AGY infra-unavailable (2 documented attempts, both companion-timeout — sanctioned infra-blocked convergence per feedback_codex_infra_must_retry). Diagnosis-first; no code.
**Base:** origin/master (`fc4ba8eb7`)
**Issue:** #1961 (virtio_net native-XDP→AF_XDP delivers 0 packets to the XSK →
no transit forwarding); supersedes #1928. `/research` only — no code.

## 1. Issue framing

On a plain virtio incus VM the firewall does not forward transit: the XDP shim
attaches native, the netdev's `rx_xdp_redirects` climbs, but the helper's XSK
reports `Packets received: 0` and 0 sessions. The loss cluster (mlx5 SR-IOV VFs)
forwards fine. The issue's original hypothesis — "copy-mode may be required" —
was **refuted** in live testing this session (verified COPY-bound binary still
rx=0; invariant across AUTO/COPY bind, busy-poll/interrupt poll mode, and
kernels 6.17/6.18). So the death is in the **redirect→XSK delivery layer**, and
the real question is *which gate* in that layer drops the transit packet.

## 2. Honest scope/value framing

This unblocks plain-virtio as a forwarding venue (every incus/qemu default VM) —
high value for image validation + bare-metal-ish testing. But the root cause is
**not yet confirmed** (the live thrash this session localized it to "XSK RX
delivery" but never read the built-in per-stage counters). *If the diagnosis
shows this is an inherent virtio generic/native-XDP AF_XDP limitation with no
reasonable in-helper fix, PLAN-KILL (document virtio as control-plane-only) is an
acceptable outcome.*

## 3. The shim gate sequence (where a transit frame can die)

`userspace-xdp/src/lib.rs` runs these gates before a transit frame reaches the
XSK. Most transit failures are `drop_degraded_transit` (XDP_DROP) counted in
`userspace_fallback_stats` by reason. **BUT two corrections (Codex-r1):**
(a) `rx_xdp_redirects` climbing is NOT proof of the cpumap/host-inbound path —
the shim returns XDP_REDIRECT through *both* CPUMAP (lib.rs:1053) and XSKMAP
(lib.rs:680), incrementing the same netdev counter, so a climbing counter is
ambiguous (could be XSK redirect *intent*). (b) A redirect that SUCCEEDS at the
shim but is then stranded by the kernel (queue-bound delivery mismatch — the XSK
isn't bound to the packet's actual RX queue) does **NOT** increment
`userspace_fallback_stats` — the shim already returned "redirect ok"; the frame
dies in the kernel's XSK-delivery, invisible to the shim counters. So the
degraded counters are necessary but NOT sufficient; the **binding/XSK inventory
is the primary discriminator** (§6).

1. `ctrl.enabled`/metadata-version (else cpumap_or_pass) — `reason ctrl_disabled`.
2. binding lookup `USERSPACE_BINDINGS[ifindex*16 + selected_queue]`, flags!=0 —
   `binding_missing`.
3. `USERSPACE_BINDING_READY` flag — `binding_not_ready`.
4. heartbeat fresh at `USERSPACE_HEARTBEAT[binding.slot]` — `heartbeat_missing` /
   `heartbeat_stale`.
5. `bpf_xdp_adjust_meta` + bounds — `adjust_meta` / `meta_bounds`.
6. session-miss transit falls through to `USERSPACE_XSK_MAP.redirect(binding.slot)`
   — failure → `redirect_err`.

## 4. The key enabler — built-in per-stage instrumentation (already shipped)

`pkg/dataplane/userspace/maps_sync.go:783` (`degradedPathReasonNames`) + 
`readDegradedPathStatsLocked()` already read the full 16-reason
`userspace_fallback_stats` breakdown, surfaced as
`status.DegradedPathCounters` ("Degraded path counters:" in `statusfmt.go:355`).
**The earlier live investigation never read this** — it only looked at
sessions/`rx_packets`/`rx_xdp_redirects`. Reading the degraded-path counters on
the failing VM names the exact dying stage with zero bpftool.

## 5. Candidate root causes (from the mapping workflow) + the two reconciliation gaps

| # | Candidate | Stage/reason | Reconciliation status |
|---|---|---|---|
| A | **Queue-bound delivery stranding** (corrected, Codex-r1) — `selected_queue = rx_queue_index % queue_count` (lib.rs:1374), and `queue_count = ctrl.QueueCount = queueCountFromBindings(status.Bindings)` (maps_sync.go:353) — i.e. the **binding inventory**, NOT the worker count. Rust plans bindings from the RX-queue inventory with `worker_id = queue_id % workers` (helpers.rs:759). The shim comment: *"AF_XDP delivery is queue-bound — XDP may only redirect to a socket bound to the packet's actual RX queue."* So a frame on RX queue Q is stranded unless an XSK is **bound to queue Q, ready, xsk-registered, with `socket_queue_id == Q`**. Stranding happens when the binding inventory under-covers the NIC's RX queues — independent of the worker count. | silent kernel stranding (may NOT show in `fallback_stats`); maybe `redirect_err` | **`workers=4` does NOT by itself refute this** — it only matters whether status shows q0..q3 actually bound+ready+xsk-registered with matching `socket_queue_id`. That is the linchpin to READ, not assume. **Fix = one XSK per RX queue (NOT `queue_count=1`).** |
| B | **virtio RX wake/fill delivery fails despite ready 1:1 queue bindings** (reframed, Codex-r1 — a single worker CAN own+poll multiple queue bindings, so it is NOT "queues never drain"). The redirect succeeds, but on virtio the frame never lands in the XSK rx ring because the RX wake/fill path (`tx/rings.rs:154`) doesn't drive virtio NAPI to deliver. | none climb; `rx_xdp_redirects`↑ but helper rx=0 | **Only confirmed AFTER** the inventory shows q0..qN bound+ready+xsk-registered+`socket_queue_id`-matched AND no degraded-path movement. Then it is the leading cause. |
| C | binding-not-ready / heartbeat-missing | `binding_not_ready` (3) / `heartbeat_missing` (4) | **Leans on a STALE premise** (workflow cited the #1921 "Device or resource busy" bind-loop, already fixed; live binds were clean). Counter-driven only. |
| D | heartbeat-stale via slot-mapping mismatch | `heartbeat_stale` (5) | **LOW (Codex-r1)** — the worker updates `heartbeat[binding.slot]` and the shim checks `heartbeat[binding.slot]` (same key: bpf_map/mod.rs:104 ↔ lib.rs:443). Counter-driven only; not co-equal absent evidence. |
| E | ctrl liveness-proof timeout (ctrl disabled) | — | **Ruled out** (that path is cpumap/PASS; ctrl is enabled). |

**The candidates cannot be discriminated by reasoning** (queue_count comes from
the binding inventory not workers; a queue-bound stranding can be invisible to
`fallback_stats`; B vs D need the counter). They are discriminated by reading
the **binding/XSK inventory first**, then the counters.

## 6. Recommendation — diagnosis-first (Path A), then a targeted fix (Path B)

**Path A (do FIRST, cheap, decisive):** on the still-up repro VM (`xpf-fwd`, per
#1961) generate a transit ping burst, then read — **PRIMARY discriminator first
(Codex-r1):**
1. **Binding / XSK inventory** (helper status `Bindings`): for EACH NIC RX queue,
   is there a binding that is **bound + ready + xsk_registered** with
   **`socket_queue_id == rx_queue`**, and what is `queueCountFromBindings`? This
   settles candidate A directly — `workers=4` is only meaningful if status shows
   q0..q3 each bound+ready+xsk-registered+queue-matched. (Confirm the status that
   surfaces this is reachable on a STANDALONE VM — manager.go:1033 / statusfmt.go
   — not cluster-only; if not, surfacing it — incl. socket_queue_id, which the FORMATTED bindings table omits today though raw status carries it (Codex-r2) — is Path A step 0, SMR-r1-m4.)
2. **Degraded-path counters** (`status.DegradedPathCounters`) — SECONDARY, because
   a queue-bound stranding can succeed at the shim and die in the kernel XSK
   delivery WITHOUT incrementing any `fallback_stats` reason.

Interpretation:
- inventory NOT 1:1 (a queue lacks a bound+ready+xsk-registered+queue-matched
  XSK) ⇒ **candidate A** (queue-bound stranding): fix = one XSK per RX queue with
  matching `socket_queue_id` (NOT `queue_count=1`). Bind loop is NOT a blocker
  post-#1921 (SMR-r1-m3).
- inventory IS 1:1 AND no degraded-path movement AND rx still 0 ⇒ **candidate B**
  (virtio RX wake/fill delivery): fix = drive virtio NAPI / fix the RX
  wake/fill path so redirected frames land in the XSK ring.
A dominant degraded-path reason otherwise pins the stage:
- `redirect_err` → candidate A (queue-bound stranding) — fix = one XSK bound per
  NIC RX queue so `rx % queue_count` is the identity (NOT `queue_count=1`, which
  strands non-0 queues — SMR-r1-m1).
- `heartbeat_stale`/`missing` → candidate D — fix the helper's heartbeat
  slot-update keying so it matches the shim's `binding.slot` for virtio's queues.
- `binding_not_ready` → candidate C — investigate why `binding.ready` is false on
  virtio post-#1921 (it should bind clean now).
- **None climb but rx still 0** → candidate B (fill-ring/NAPI starvation) — fix =
  drive virtio NAPI on the RX side (poll/needs_wakeup per binding even when not
  draining), the virtio-specific RX-wakeup path.

**Path B (the fix)** is written only after Path A names the stage. The plan does
NOT pre-commit to a fix — that would repeat this session's blind-hypothesis
thrash (copy-mode, poll-mode, kernel — all refuted). The deliverable of
`/engineer 1961` is: read the counter, then implement the one targeted fix +
a regression test, validated by transit forwarding on the virtio VM going
non-zero (sessions created, `tx_completions` > 0 — NOT `rx_packets`, a known red
herring).

**A small instrumentation aid (optional, in scope for the fix PR):** if the
degraded-path counters aren't easily surfaced on the VM (they're in the helper
status; confirm the CLI/status path shows them on a standalone VM), add a
one-line `show`/log of `DegradedPathCounters` so the operator/CI can see the
dying stage. The `userspace_trace` map (per-flow stage) is the deeper probe if
the aggregate counter is ambiguous.

## 7. Public API / contract preservation
No API changes in the diagnosis. The fix (TBD per stage) is internal to the
shim (lib.rs) + the helper (bind/heartbeat/worker RX) + the Go manager
(maps_sync slot/worker registration); no operator-facing config change expected.

## 8. Hidden invariants the fix must preserve
- mlx5 (the working venue) must stay working — any virtio fix must be virtio-
  gated or count-general, not break the N-queue×N-worker mlx5 path.
- The degraded-path gates (heartbeat freshness, binding-ready, strict-mode
  transit drop) are SAFETY gates — a fix must not make the shim redirect to an
  unbacked/half-initialized XSK (that's the bug, not the fix).
- `rx_packets` is a red herring (0 even on working mlx5); the forwarding signal
  is `Unicast-sessions` + `tx_completions_total`.

## 9. Risk assessment
| Class | Level | Note |
|---|---|---|
| Behavioral regression | MED | touches the shim redirect / worker RX / slot registration — the mlx5 fast path must be protected; gate the virtio fix |
| Lifetime/borrow | LOW | localized |
| Performance | LOW–MED | RX-wakeup changes (candidate B) are on the poll path — measure on mlx5 line-rate |
| Architectural mismatch | LOW | diagnosis-first avoids committing to a wrong mechanism |

## 10. Out of scope
- Copy-mode / poll-mode / kernel-version changes (all refuted this session).
- mlx5/i40e behavior (working).
- The standalone-deploy helper gap (#1962, separate).

## 11. Open questions for adversarial review
1. **Reconcile workers=4**: if candidate A (slot misalignment) is the cause, why
   did `system dataplane workers 4` (== 4 virtio queues) not fix it? Does
   setting workers=N actually register N XSK slots on virtio, or is the
   worker→slot registration broken independently? (This is the crux — answer
   decides A vs B/D.)
2. Is the climbing `rx_xdp_redirects` definitively the cpumap/host-inbound path
   (not XSK)? Confirm cpumap_or_pass increments the same netdev counter.
3. Does `select_userspace_queue` / `selected_queue = rx % queue_count` use
   `queue_count` = workers or = NIC queues? If workers and the shim disagree on
   `queue_count`, that alone mis-keys both XSKMAP and heartbeat.
4. Is candidate B (fill-ring/NAPI starvation) actually reachable given the
   redirect counts as success at the netdev but the XSK ring stays empty — i.e.,
   does virtio need a proactive RX poll the current worker loop doesn't issue?
5. Are the degraded-path counters actually surfaced on a STANDALONE virtio VM
   (not just the cluster)? If not, the fix PR must add the surface first.
6. Is PLAN-KILL warranted — is this an inherent virtio generic-XDP AF_XDP
   limitation with no reasonable in-helper fix?
