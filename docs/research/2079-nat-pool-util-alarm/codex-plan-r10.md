# Codex hostile plan review r10 — #2079

TWO Codex r10 passes ran. I PREMATURELY treated the fresh-session retry's "No
findings" as convergence while the ORIGINAL (slower, deeper) pass was still
running — it was NOT wedged, just slow (~11 min), and it returned a real BLOCKER.

## Original (agentId ad6d71ffb69e9ad95, ~11 min): PLAN-REVISE — BLOCKER

1. **BLOCKER (deferred-apply reconcile-skew):** `apply_snapshot` sets
   `last_snapshot_generation` on ACCEPT (`snapshot.rs:63`), but the
   `defer_workers` branch stores the snapshot and SKIPS
   `reconcile_status_bindings` (`snapshot.rs:138-145`/113-144). NAT pool status
   is read from coordinator forwarding state, replaced only on reconcile
   (`server/helpers.rs:244` → `afxdp/coordinator/status.rs:315-316` →
   `afxdp/coordinator/reconcile/snapshot.rs:89`). Go can set `DeferWorkers`
   (`manager.go:677-688`). So `HelperCoherent` (r10: status==appliedGen) can be
   TRUE while counters still belong to old forwarding/NAT rules. Needs an explicit
   HOLD for this window.
2. **MAJOR (capture scope):** Go sends `apply_snapshot` from multiple sites
   (manager.go:688 main apply, 796 policy scheduler, 950 route overlay,
   process.go:352 deferred sync); Rust echoes the gen for all. The plan must say
   every successful apply_snapshot that RECONCILES updates `appliedSnapshot` after
   ack, and pre-publish `m.lastSnapshot = snap` during startup deferral
   (manager.go:648) must NOT.
3. **MINOR (first-boot gen==0):** `last_snapshot_generation` starts 0
   (`lifecycle.rs:91`); `0 == appliedSnapshot.Generation` is not proof of a real
   applied config. After a helper restart this can false-clear unless "no applied
   config" is treated as `Available=false`.
4. **NIT:** a cited Rust path was stale (the real setter is
   `server/handlers/snapshot.rs:63`; FIB-only bump is `snapshot.rs:164`).

Verified despite the revise: FIB/neighbor bumps don't full-apply; §6.1 HOLDs on
!Available/!Coherent; §6.4 deferred (not silent) clears; no new Rust protocol
field needed.

## Fresh-session retry (agentId ac8f3852129726977, ~4 min): PLAN-READY "No
findings" — but LESS THOROUGH; it did not trace the defer_workers reconcile-skip
path. Its clean pass is superseded by the original's BLOCKER.

## r11 resolution
All folded: `appliedSnapshot` recorded ONLY on a RECONCILED apply (never on a
deferred-but-accepted one); `Coherent := status==appliedGen && !m.deferWorkers`;
first-boot/restart gen==0 → `Available=false` HOLD; capture-site list enumerated
in §7. NIT path verified correct in the current plan.

LESSON (process): wait for the deepest/longest reviewer pass before declaring
convergence; a fast "no findings" retry does not override a slower in-flight pass.
