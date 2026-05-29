# Claude SMR plan-review — r4 (convergence confirmation)

Plan v3.1 (`4aaf909a7`). r4 confirms the sole Codex r3 minor is folded; AGY and
SMR were already PLAN-READY at r3.

## Verdict: PLAN-READY (3-way converged)

## Codex r3 minor — folded, independently verified

The drop-stages-only trace filter (B-2, defeating the retransmit overwrite)
suppresses the local/control-PASS trace stages, so the local-misclassification
sub-branch of W-PASS-KERNEL cannot be trace-pinned. v3.1 splits B-4:
- **B-4a** ingress-iface miss (`lib.rs:364-366`) → throwaway eBPF counter.
- **B-4b** local misclassification → throwaway eBPF counter on the direct-local
  `cpumap_or_pass` returns, corroborated by reason-14.

I re-verified the supporting code:
- `lib.rs:520` records `INTERFACE_NAT_LOCAL`, then `:530` returns
  `Ok(cpumap_or_pass(ctrl))` with NO `incr_fallback_stat` → B-4b genuinely needs a
  new counter.
- `lib.rs:533` records `LOCAL_DESTINATION`, then `:543` returns
  `cpumap_or_pass` with no counter → same.
- `pass_local_control` (`:903-906`) increments reason 14 → the
  PASS_TO_KERNEL/control sub-path already has corroboration.
The B-2 decision tree (`:459`) now references "a B-4 W-PASS-KERNEL counter (B-4a
OR B-4b)". Internally consistent.

## Six-window coverage is complete and consistent

- W-BIND / W-READY / W-HB / W-XSK → `USERSPACE_TRACE` drop-stages (filtered to
  survive the retransmit).
- W-CTRL → B-1 timeline (SYN before T_ctrl-enabled) + `ctrl_disabled`(0) counter.
- W-PASS-KERNEL → B-4a counter (ingress-iface miss) OR B-4b counter (local
  misclassification).
No window is double-counted or uncovered; no trace-overwrite false-negative.

## Bottom line

The plan is Gate-B-ready and the design is sound. Gate-B will pin the dropped SYN
to exactly one of the six windows without measurement artifacts; the honesty gate
(B-6) mandates PLAN-KILL if the readiness-gate framing is refuted (Gate-R
precedent). Favored fix: **Path 1.A** (gate the BPF READY write on the helper's
already-shipped `binding.Ready`/`XSKRegistered` across all four writer sites) —
it eliminates the W-XSK race, strictly tightens fail-closed, reuses existing
status, and additionally fixes the latent crash-blind blackhole; with **Path 1.C**
(event-driven enable) layered ON only if the Gate-B-measured gap is
poll-cadence-dominated, and **Path 3** (accept the deploy-only artifact) the
honest fallback if the cost of touching the fail-closed bringup path is judged to
exceed removing one deploy RTO. PLAN-READY — STOP for manual approval.
