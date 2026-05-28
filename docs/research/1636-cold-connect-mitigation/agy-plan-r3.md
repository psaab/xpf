# AGY adversarial plan review — round 3 (#1636)

**Job ID**: adversarial-review-mppssucj-nhfik0
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v3 @ `a43fd6f9cb6d`

## VERDICT: PLAN-NEEDS-MINOR

## Findings (verbatim from AGY)

### Finding 1 [SEVERITY: MEDIUM] Silent Thread-Death and Telemetry Blind Spot in MPSC Warmer Channel

- Description: The warmer worker thread is spawned at coordinator init, and enqueuing occurs via `try_send` on a bounded channel (capacity 4096). If the warmer worker thread panics or shuts down unexpectedly (e.g., due to OS-level raw socket descriptor failures), the channel will disconnect.
- The Blind Spot in v3: The plan currently handles any `try_send` error by simply incrementing `warm_drops` and printing an `eprintln!` under the compile-time `cfg!(feature = "debug-log")` flag. Since `debug-log` is typically disabled in production builds, a worker thread death — which is a fatal control-plane crash — will fail completely silently without standard operator or syslog visibility.
- Mitigation:
  1. Distinguish between channel congestion (`TrySendError::Full`) and thread death (`TrySendError::Disconnected`).
  2. If the error is `Disconnected`, issue a high-severity log warning or error that is guaranteed to write to syslog/journald in production, rather than hiding it behind `debug-log`.
  3. Mandate that the `warm_drops` atomic counter is exposed as a Prometheus metric (currently "if desired"; should be hard requirement).

### Finding 2 [SEVERITY: MEDIUM-HIGH] Unbounded Memory Growth and GC Bypass under Continuous Load/Churn

- Description: GC runs only on `RecvTimeoutError::Timeout` (idle path).
- The Defect: In an active production network experiencing continuous BGP/FRR routing updates, fabric peer shifts, or neighbor state changes, the channel queue will rarely or never be empty for a consecutive 500ms. Consequently, `recv_timeout` will always return `Ok(item)` immediately, completely bypassing the `Timeout` block. Under continuous load, the GC pruning logic will never run, leading to unbounded memory growth in `last_probed_at`.
- Mitigation: The 60-second GC check must run **both on idle timeout AND on successful dequeue** of items.

### Finding 3 [SEVERITY: MEDIUM] Transient-Down Lockout after Link UP Status Changes

- Description: `Coordinator::on_rg_promote_active()` clears `last_probed_at` on cluster promotions but this does not protect against physical link or VLAN negotiation delays (LACP, STP, etc) taking 1-2 seconds after mastership promotion.
- Trace: t=0 promotion clears cache → enqueue probes → physical link still negotiating → probes dropped → `last_probed_at[(ifindex,hop)] = 0.1s` → t=1.5s link UP → t=2.0s BGP update enqueues again → 2.0s - 0.1s = 1.9s < 5s → SKIPPED → node locked out for 3.1s more.
- Mitigation: The `last_probed_at` rate-limit entries for a specific interface **MUST** be cleared not only on RG promotion, but also whenever that interface transitions from DOWN to UP. Since the key is `(ifindex, IpAddr)`, this can be cleanly achieved by removing all keys matching the `ifindex` of the newly UP interface.

### Finding 4 [SEVERITY: LOW] Asynchronous Kernel State Machine — D=800ms is Mathematically Superior to D=700ms

- Description: The plan recommends D=700ms to drop the packet before the kernel transitions to NUD_FAILED at ~750ms. The kernel neighbor state machine is asynchronous and unaware of userspace queue state; the kernel transitions to NUD_FAILED at 750ms regardless of whether userspace drops at 700ms or 800ms.
  - If we drop at 700ms: we lose the ability to forward the queued packet if a late-stage solicit succeeds between 700ms and 750ms.
  - If we drop at 800ms: we preserve the packet for late resolution, and if it still fails, the client's SYN #2 at 1000ms will encounter NUD_FAILED and trigger a fresh probe exactly the same way.
- Mitigation: Revert the recommendation; use 800ms.

## Verification of Specific Questions

1. r2 #1 (bounded(4096) + warm_drops + log): size sufficient; but disconnect-vs-full distinction + non-debug-log error needed (Finding 1).
2. r2 #2 (on_rg_promote_active() clears last_probed_at): insufficient — needs link-UP clearing too (Finding 3).
3. r2 #3 (60s tick × 5min retention): bound is fine but GC bypass under load is the problem (Finding 2).
4. r2 #4 (fire ONCE; kernel handles 3-attempt): elegant and accepted.
5. r2 #5 (connected subnets out-of-scope): correct.
6. New flaws in v3: Findings 2, 3, 4.

## Recommendation

Iterate to incorporate Findings 1-4. Once updated, plan is PLAN-READY to proceed to implementation.
