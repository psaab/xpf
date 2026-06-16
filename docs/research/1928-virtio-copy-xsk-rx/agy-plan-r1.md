# AGY plan-review r1 (adversarial-review-mqg2uqly-9h12b5) — PLAN-NEEDS-MAJOR
- Reject PLAN-KILL: virtio_net is the only portable virtual driver — must fix.
- Path 3: ZC where available + FIX the copy-mode fallback.
- Fix startup prime mismatch: initial fill frames must not exceed UMEM fill-ring
  capacity (converges with Codex #2).
- Ensure XDP_USE_NEED_WAKEUP in copy mode on native virtio so NAPI driving
  behaves correctly (concrete candidate — may explain the AUTO-vs-explicit delta).
