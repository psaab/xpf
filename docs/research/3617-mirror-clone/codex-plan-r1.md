# Codex — hostile plan review r1 (#3617)

Task ID: agent ab7f7be7c69edc4c4 (codex:codex-rescue). Duration ~213s.

## Verdict: PLAN-KILL-CONCUR

No defeating evidence found. All three core mechanism claims confirmed against
source:

- **Q1 (mirror_clone = droppability marker only):** Confirmed. Reserve-pressure
  drop gates at `tx/transmit/mod.rs:102-108`, `cos/queue_service/drain.rs:73-79`
  and `:253-262`, `tx/cos_classify.rs:648-650`. Actual clone is a separate frame
  at `mirror/fast_path.rs:115-170` and `:203-229`. No path where setting
  `mirror_clone: true` on a reply's own TxRequest triggers analyzer cloning.
- **Q2 (ingress-only):** Confirmed. Runtime lookup on ingress at
  `mirror/mod.rs:55-68`; Rust state ingress-keyed at
  `forwarding_build/mod.rs:383-390`; Go compile reads only `input ingress
  interface` at `compiler_services.go:1303-1325`; snapshot emission ingress-keyed
  at `mirrors.go:64-85`. No egress/output mirror path.
- **Q3 (call sites):** Only live non-test mirror-clone sites:
  `flow_cache_hit.rs:284-288`+`:353-360`, `neighbor_dispatch.rs:315-330`,
  `tx/dispatch/mod.rs:253-268`.
- **Q6 (already mirrored?):** No. Reject/cookie enqueue directly to
  `pending_tx_local`; time-exceeded via `PendingForwardFrame::Prebuilt`; PTB
  enqueues directly at `dispatch/mod.rs:1135-1177`. None pass through
  `enqueue_sampled_mirror_clone`.

## Factual corrections (do not flip verdict)

1. PTB `mirror_clone: false` pin is at `tx/dispatch/mod.rs:1162-1175` (~:1174),
   NOT `:438` (that line is a segmented forwarded-frame TxRequest). — FIXED in r3.
2. `enqueue_mirror_clone_to_binding` is at `fast_path.rs:115-170`, not
   `:145-199`. — FIXED in r3.

L10 residual confirmed accurate: reject (`reject_reply.rs:394`) and cookie
(`cookie_reply.rs:504`) pins exist; PTB / time-exceeded have no `mirror_clone`
test assertion.
