# Claude SMR hostile plan-review — r2

Reviewing plan v2.1 (`347654e84`). Hostile re-verification of the v2 folds + a
hunt for new holes, with quoted file:line.

## Verdict: PLAN-NEEDS-MINOR → trending PLAN-READY

The r1 folds are correct. I caught one real hole in my own v2 (W-CTRL not
trace-pinnable) and fixed it in v2.1 before dispatching r2. One residual
interaction needs a sentence in the plan (alias-child binding still keys on
`Bound`), then I judge the plan Gate-B-ready.

## v2 fold verification (against source)

1. **no_std/no_eprintln (Codex r1-1) — folded correctly.** `lib.rs:1-2`
   `#![no_std] #![no_main]`. v2 B-2 now uses `USERSPACE_TRACE` (`lib.rs:329-330`,
   `record_trace` `:959-1004`) and confines eprintln to helper threads (B-3,
   `worker/loop_body/`). Correct.

2. **Path 1.A "use existing state" (Codex r1-2 / AGY r1-1) — folded correctly.**
   v2 §2.4 + §5 1.A now say gate the BPF READY write on the existing
   `binding.XSKRegistered`/`Ready` (`protocol.go:1012-1016`,
   `refresh_bindings.rs:225-228`), and call out the wrong comment at
   `maps_sync.go:597`. I re-verified `set_bound` stores `bound=true`
   unconditionally at socket create (`umem/mod.rs:761-764`), so the
   chicken-and-egg is genuinely refuted. Correct.

3. **Path 1.B selected-queue (Codex r1-4) — folded.** v2 §5 1.B quotes
   `binding_idx = ingress_ifindex * BINDING_QUEUES_PER_IFACE + selected_queue`
   (`lib.rs:383`) and `select_userspace_queue` (`:1308-1330`). Correct.

4. **Entry-program softening (Codex r1-6 / SMR r1-1) — folded.** §2.1 now defers
   the first-packet claim to Gate-B Q1 and cites `loader.go:581-582` for the
   no-op swap. Correct.

5. **Gap measured not inferred (SMR r1-3) — folded.** B-5 now requires recording
   the actual gap. Correct.

6. **Path 2.A SNAT-blackhole caveat (SMR r1 / AGY r1) — folded** into §5 2.A.

## New hole I caught + fixed (v2.1)

**W-CTRL is NOT trace-pinnable.** `try_xdp_userspace` takes the early return at
`lib.rs:345-347` into `degraded_ctrl_disabled_action` (`:867`), which contains NO
`record_trace` call — it goes straight to `drop_degraded_transit` (`:887`).
Moreover the trace flag lives in `ctrl.flags` and is moot while ctrl is disabled.
So a SYN dropped in W-CTRL leaves no `USERSPACE_TRACE` entry. v1/v2 implied the
trace stage would pin W-CTRL — it cannot. v2.1 fixes B-2 to pin W-CTRL via the
B-1 timeline (SYN arrival before T_ctrl-enabled) + the `ctrl_disabled` cumulative
counter, and spells out the full six-window attribution decision tree. This was
the prime-suspect window, so the hole mattered.

## Residual minor (fold into v2.x)

**Alias-child binding still keys READY on `Bound`, not `XSKRegistered`.** The
primary binding READY write (`maps_sync.go:596`) is what Path 1.A changes, but the
VLAN-alias-child path writes READY on `binding.Registered && binding.Armed &&
binding.Bound` (`maps_sync.go:634`). If Path 1.A is chosen, the alias path should
be updated for consistency (or the plan should note the alias path already
includes `Bound`, which is set with `XSKRegistered` in the same worker create, so
it is already nearly as strong — but `Bound` is set at `:328` BEFORE
`set_xsk_registered` at `:746`, so the alias path has the SAME W-XSK inversion as
the primary). The plan §5 1.A should explicitly cover BOTH the primary
(`:596`) and the alias (`:634`) READY writes. One sentence.

The bindings watchdog (`verifyBindingsMapLocked`, `maps_sync.go:1053`) only runs
when `m.ctrlWasEnabled` (`:1059`) and writes READY on `Registered && Armed`
(`:1101`) — it would need the same XSKRegistered condition for consistency, but it
is repair-only and post-first-enable, so it does not affect the first-SYN window.
Note it in the /engineer scope, non-blocking for the plan.

## Bottom line

v2.1 correctly folds all r1 findings and closes the W-CTRL trace hole. Add the
one sentence covering the alias-child READY write (`maps_sync.go:634`) under Path
1.A and note the watchdog (`:1101`) for /engineer consistency. With that, the plan
is Gate-B-ready. Favored path stands: Path 1.A (if Gate-B pins W-XSK / the
inversion), Path 1.C only if the measured gap is poll-dominated; Path 3 viable if
the fail-closed-path change cost exceeds removing one deploy RTO.
