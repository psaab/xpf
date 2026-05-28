# AGY adversarial plan review — round 4 (#1636)

**Job ID**: adversarial-review-mppsyvbf-55nkt6
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v4 @ `d5a4a5eb87b5`

## VERDICT: PLAN-NEEDS-MINOR

## Findings (verbatim from AGY)

### Finding 1 [SEVERITY: HIGH-MEDIUM] Silent Warming Death via Mutex Poisoning Guard-Bypass

In the proposed `warmer_loop`:
```rust
let skip = if let Ok(mut map) = last_probed.lock() {
    match map.get(&key) {
        Some(t) if now.saturating_sub(*t) < 5_000_000_000 => true,
        _ => { map.insert(key, now); false }
    }
} else { true };
```

If the `last_probed` mutex becomes poisoned (e.g., another thread panicked while holding it via `on_link_up` or `on_rg_promote_active`), `lock()` returns `PoisonError(Err)`. Because the code defaults `skip = true` on lock error, the worker silently skips all future probes. The worker stays alive (looping, blocking on `recv_timeout`, skipping), so the MPSC channel remains connected. `try_send()` continues to succeed; `warm_disconnected` stays 0; no log fires. Proactive warming is silently disabled.

**Mitigation**: Use `last_probed.lock().expect("last_probed poisoned")` (or `.unwrap()`) so the worker panics and exits on poison, cleanly breaking the channel. The coordinator's `try_send()` will then catch `TrySendError::Disconnected`, bump `warm_disconnected`, and print the critical operator warning.

### Finding 2 [SEVERITY: HIGH] The D=800ms Operational Hazard (RTO Regression if PR-1 Sysctl Fails)

Lowering `PENDING_NEIGH_TIMEOUT_NS` to 800ms (PR-3) is only safe if `retrans_time_ms` is successfully lowered to 250ms (PR-1) at the OS level.

If the sysctl drop-in fails to apply (running in a restricted container, sysctl namespace permission errors, admin overrides, systemd reload failures), the kernel's `retrans_time_ms` remains at its default of 1000ms. With `retrans_time_ms = 1000ms`, the first kernel wire-level solicit fires at t=1000ms. Userspace queue timeout at t=800ms drops SYN #1. SYN #2 at t=1000ms encounters the entry still INCOMPLETE — kernel queues the packet and waits. Userspace probe schedule already expired. SYN #2 held for another 800ms and dropped at t=1800ms. Resolution lands at t=3000ms (SYN #3). **Degrades baseline from ~3.371s today to 3.0s+** — same outcome but lossier.

**Mitigation**: Document the operational hazard in the plan. State PR-3 **must not** deploy unless PR-1 is empirically validated active at runtime. Consider a control-plane check at coordinator init that verifies `sysctl net.ipv4.neigh.default.retrans_time_ms <= 250` before enabling the lower timeout; fall back to 2000ms if the sysctl is unapplied.

### Finding 3 [SEVERITY: LOW] Severe Stderr/Syslog Spamming under Route Churn on Worker Disconnect

If the warmer worker thread dies, the coordinator catches `TrySendError::Disconnected` on the `try_send` path. If a new snapshot with 100 routes arrives while the worker is dead, this `eprintln!` will fire 100 times in quick succession. Under routing churn this floods stderr/syslog.

**Mitigation**: Use an atomic boolean flag (`warned_disconnect: AtomicBool` inside `NeighborManager`) to ensure the critical "neighbor warmer worker disconnected" error is logged exactly once upon transition.

## Verification of Specific Questions

1. **Full vs Disconnected counters Prometheus-exposed**: sufficient. Daemon restart on disconnect is unacceptable (turning silent control-plane failure into HA-failover event). Log path needs rate-limiting (Finding 3).
2. **GC at top of every iteration**: structurally sound; lock acquisition cost negligible. But poisoned mutex (Finding 1) silently disables warming.
3. **DOWN→UP→DOWN flapping**: sufficient as-planned. DOWN omits interface from snapshot; UP clears cache for re-resolve.
4. **D=800ms vs 700ms**: accepted; but Finding 2 operational hazard must be documented.
5. **NEW fatal flaws in v4**: Findings 1 + 2 are new high-severity.

## Recommendation

Iterate with mitigations for Findings 1, 2, 3 into v5. Then PLAN-READY.
