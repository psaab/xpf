# Claude SMR hostile plan review — round 1

**Plan:** `plan.md` @ `1cb2dc0ca`
**Verdict: PLAN-NEEDS-MINOR**

The diagnosis-first spine is correct and is the right antidote to this session's
blind-hypothesis thrash (copy-mode/poll-mode/kernel all refuted live). But four
refinements are needed before PLAN-READY — most importantly the plan must
sharpen the crux into the **queue-bound AF_XDP delivery** mechanism, which I
verified in the shim.

## m1 — sharpen the crux: AF_XDP delivery is QUEUE-BOUND

`select_userspace_queue` (lib.rs:1374) computes `selected_queue =
rx_queue_index % queue_count`, where `queue_count = ctrl.queue_count ?:
ctrl.workers` and `ctrl.queue_count = queueCountFromBindings(status.Bindings)`
(maps_sync.go:357). The shim's own comment is the key: *"AF_XDP delivery is
queue-bound. XDP may only redirect to a socket bound to the packet's actual RX
queue. Hashing to a different userspace queue silently strands packets between
redirect intent and ring delivery."*

So the real failure mechanism is not merely "unbacked XSKMAP slots" — it is:
**a packet that arrived on RX queue Q can only be delivered to an XSK that is
bound to queue Q.** With `workers=1` → `queue_count=1` → every packet maps to
`selected_queue=0` → redirected to the queue-0 XSK → the kernel strands every
packet that did not physically arrive on queue 0. A single ping flow hashes to
one RX queue; if it isn't queue 0, rx=0. This unifies the symptom (redirects
"succeed" at the netdev, XSK gets nothing) far better than the slot-count
framing.

**Consequence for candidate A's listed fix:** "Option A: force `queue_count=1`"
is **wrong-direction** — it would make `selected_queue=0` for ALL queues and
strand every non-queue-0 packet. The plan must strike that option. The correct
fix shape is "one XSK bound per NIC RX queue" (so `rx % queue_count` is the
identity and each queue's packet reaches its own queue's XSK).

## m2 — the workers=4 contradiction is the linchpin; make it the first diagnostic, with a binding dump

If the fix is "an XSK per RX queue," then `workers=4` (== 4 virtio queues)
SHOULD have produced 4 per-queue XSKs and worked — but it didn't. So either
(a) the helper does not actually bind one XSK per NIC RX queue even at
workers=4 (worker↔queue assignment gap), or (b) virtio refuses/doesn't steer an
XSK bound to queue>0, or (c) it's candidate B (fill-ring/NAPI starvation,
independent of slots). Path A must therefore read **two** things, not just the
degraded-path counter:
1. `status.DegradedPathCounters` — names the stage (`redirect_err` vs none).
2. the **binding/XSK inventory**: how many XSKs are bound, to which RX queues,
   and `queueCountFromBindings` value — to see whether workers=N actually
   produced one XSK per queue. (The plan mentions `show afxdp bindings`; make it
   explicit and required.)
`redirect_err` climbing + only 1 XSK bound ⇒ queue-bound stranding (m1).
No counter climbing + N XSKs bound ⇒ candidate B (NAPI/fill starvation).

## m3 — correct the stale-bind premise on candidates C and A-Option-C

The plan already flags this for candidate C, but the workflow's "register N
workers is infeasible because the bind loop blocks on Device or resource busy"
(candidate A Option C) rests on the **same stale #1921 symptom** — binds are
clean post-#1921/#1929 (live-confirmed this session). So "one XSK per queue" is
NOT infeasible; it is the leading fix candidate. The plan should say so and stop
treating the bind loop as a live blocker.

## m4 — confirm the counters surface on a STANDALONE VM before relying on them

The whole plan hinges on reading `DegradedPathCounters` on `xpf-fwd`. They are
in `status.DegradedPathCounters` (statusfmt.go:355) — but confirm that the
status that surfaces them is reachable on a standalone (non-cluster) VM via a
CLI/JSON path, not only in cluster status. If not, Path A's first sub-step is a
one-line surface (cheap) — call that out so `/engineer` isn't blocked.

## Sound in v1 (not nits)
- Diagnosis-first over blind fixes — exactly right given the refuted hypotheses.
- `rx_packets` red-herring + `tx_completions`/sessions as the real signal.
- mlx5-must-stay-working invariant; virtio-gate the fix.
- PLAN-KILL kept as a live option (if virtio genuinely can't bind per-queue).

## To reach PLAN-READY
Fold m1 (queue-bound mechanism + strike the queue_count=1 "fix"), m2 (binding/XSK
inventory as a required Path-A read + workers=4 as the linchpin), m3 (drop the
stale-bind infeasibility), m4 (confirm counter surface on standalone). The spine
stays; these make the diagnosis decisive and stop a wrong-direction fix.
