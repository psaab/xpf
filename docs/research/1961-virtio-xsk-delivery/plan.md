# #1961 — virtio AF_XDP delivers 0 packets to the XSK: diagnosis-first plan

**Status:** DRAFT v1.1 — SMR r1 PLAN-NEEDS-MINOR folded (queue-bound mechanism + binding-inventory diagnostic); pending Codex + AGY (Codex + AGY + Claude SMR)
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
XSK; **every transit failure is `drop_degraded_transit` (XDP_DROP) and is
counted in the `userspace_fallback_stats` map by reason** (NOT in
`rx_xdp_redirects` — so the climbing redirect counter is the *cpumap/host-inbound*
path, not the XSK path):

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
| A | **Queue-bound delivery stranding** (sharpened, SMR-r1-m1) — `select_userspace_queue` (lib.rs:1374) does `selected_queue = rx_queue_index % queue_count`, `queue_count = ctrl.queue_count(=queueCountFromBindings) ?: workers`. The shim's own comment: *"AF_XDP delivery is queue-bound — XDP may only redirect to a socket bound to the packet's actual RX queue; hashing to a different queue silently strands packets."* With `workers=1` → `queue_count=1` → every packet maps to `selected_queue=0` → only packets that physically arrived on RX queue 0 reach the queue-0 XSK; queues 1..N-1 are stranded. A ping hashing to a non-0 queue ⇒ rx=0. | `redirect_err` (10) and/or silent kernel stranding | **Contradicted by `workers=4`** (== 4 queues, *should* give one XSK per queue → identity map → works), yet it STILL failed. So the linchpin: does the helper actually bind ONE XSK PER NIC RX QUEUE on virtio at workers=N? **NOTE: candidate-A "fix = force queue_count=1" is WRONG-direction** (it strands all non-queue-0 traffic). Correct fix = an XSK bound per RX queue. |
| B | **RX-wakeup / fill-ring starvation** — `poll(POLLIN)` (the only thing that kicks virtio NAPI) only fires when a binding's RX is drained; with N queues × 1 worker, queues 1..N-1 never drain, NAPI never wakes, fill rings starve → redirect "succeeds" but frame never lands in the XSK ring | none climb; `rx_xdp_redirects`↑ but helper rx=0 | **Most consistent with the symptom** (redirects climb, helper rx=0, virtio-specific NAPI-drive). Needs the live counter to confirm no `redirect_err`. |
| C | binding-not-ready / heartbeat-missing | `binding_not_ready` (3) / `heartbeat_missing` (4) | **Leans on a STALE premise** — the workflow cited `docs/image-validation.md:81` "Device or resource busy" bind-loop, which is the **#1921 bug already fixed**; my live runs showed binds clean + helper running. Only live if the post-fix binding/heartbeat path is still wrong on virtio. |
| D | heartbeat-stale via slot-mapping mismatch — helper updates `heartbeat[slotX]` but the shim checks `heartbeat[binding.slot=Y]` for virtio's queue layout | `heartbeat_stale` (5) | Plausible and NOT bind-dependent; would survive workers=N. Discriminated by the counter. |
| E | ctrl liveness-proof timeout (ctrl disabled) | — | **Ruled out**: that path is cpumap/PASS, and `rx_xdp_redirects` climbs (ctrl enabled). |

**The candidates cannot be discriminated by reasoning** (two lean on stale docs;
A is contradicted by workers=4; B vs D both fit). They are discriminated by one
live read.

## 6. Recommendation — diagnosis-first (Path A), then a targeted fix (Path B)

**Path A (do FIRST, cheap, decisive):** on the still-up repro VM (`xpf-fwd`, per
#1961) generate a transit ping burst and read **TWO** things (SMR-r1-m2), after
first confirming the degraded-path counters actually surface on a STANDALONE
(non-cluster) VM — if not, a one-line surface is Path A step 0 (SMR-r1-m4):
(i) the helper's **Degraded path counters** (`status.DegradedPathCounters`), and
(ii) the **binding / XSK inventory** (`show afxdp bindings` or the binding map):
how many XSKs are bound, to which RX queues, and the `queueCountFromBindings`
value — to settle whether `workers=N` actually produced one XSK per NIC RX queue
(the linchpin). Interpretation:
- `redirect_err` climbing AND only 1 XSK bound (or XSKs not 1:1 with NIC RX
  queues) ⇒ queue-bound stranding (candidate A): fix = bind one XSK per RX queue
  (NOT queue_count=1). The bind loop is NOT a blocker post-#1921 (SMR-r1-m3).
- no counter climbing AND N XSKs bound 1:1 to queues ⇒ candidate B (fill-ring /
  NAPI starvation): fix = drive virtio NAPI on the RX side.
The dominant degraded-path reason otherwise pins the stage:
- `redirect_err` → candidate A (XSKMAP slot) — then check whether workers==queues
  actually registered N XSK slots (reconcile the workers=4 evidence); fix =
  populate every queue's slot (register N workers, or steer unbacked queues to a
  backed slot, or force queue_count=1).
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
