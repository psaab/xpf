# Hostile/Adversarial Plan Review (r3): WireGuard Tunnel Removal Leak

## Verdict: `PLAN-READY`

The revision **r3** of the plan doc `docs/research/1919-wg-addr-route-prune/plan.md` is robust, correct, and fully addresses the residual issue identified in r2. It preserves all codebase invariants, maintains idempotency, and avoids any new regression vectors or locking bugs.

---

## Findings & Analysis

### (a) AddrList-Fallback Leak Fix Verification
In revision **r2**, the proposed `pruneAppliedAddrsLocked` helper only returned `failed` (the set of addresses that failed deletion). If a transient netlink error caused `AddrList` to fail, the function returned `applied` (which would be empty if no addresses were currently tracked or previously applied). In the caller, this caused `retry = len(failed) > 0` to evaluate to `false`, causing the daemon to silently delete the tracking entry (`delete(t.appliedAddrs, name)`) and drop retry tracking. The stale address would then leak forever.

**Revision r3 fixes this by:**
1. Refactoring the helper signature to return `(failed map[string]bool, retry bool)`.
2. Unconditionally returning `(applied, true)` when `ops.AddrList` returns an error.
3. Ensuring that if `retry` is true, the caller preserves the name in the `wgConfigured` retry map and retains the `appliedAddrs` tracking entry (mapping it to the returned `failed` set, which is the previous `applied` set in case of `AddrList` failure).
4. If `AddrList` succeeds on a subsequent retry, it will properly list all addresses on the device, attempt to prune any non-link-local addresses (which do not gate on the `applied` map), and successfully clean the interface.

This fully closes the transient leak vector.

### (b) Review of the (failed, retry) Refactor
We pressure-tested the refactored `(failed, retry)` return parameters for any potential edge-cases or regressions:
1. **Link-Local Logic Safety**: The `a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key])` condition is properly gated.
2. **Nil-Map Handling**: In the case of daemon boot or re-adoption where `t.appliedAddrs[name]` is `nil`, the helper receives `applied = nil`. The short-circuit `applied == nil || !applied[key]` successfully evaluates to `true` for link-locals, skipping deletion and avoiding `nil` map dereference panics.
3. **Overwriting with `failed`**: When `retry` is true because some deletions failed, the caller sets `t.appliedAddrs[name] = failed`. This correctly retains tracking *only* for the addresses that failed to delete (and drops successfully deleted ones, ensuring they are not mistakenly treated as manager-applied if they reappear as foreign/autoconf link-locals later).

### (c) Idempotency, clearLocked, and State Invariants
1. **Idempotency**: A successful prune clears `t.appliedAddrs[name]` and drops the tunnel name from `nextWG` (and thus `t.wgConfigured`). Subsequent applies will see that the name is in neither `wgDesired` nor `t.wgConfigured`, resulting in a safe no-op.
2. **`clearLocked`**: Adding `t.wgConfigured = nil` cleanly clears the WG tracking state, aligning with the existing reset behavior of `ownedNames`, `appliedAddrs`, and `appliedRI`.
3. **`ensureReconcileStateLocked`**: The lazy initialization check (`if t.wgConfigured == nil { t.wgConfigured = map[string]bool{} }`) ensures that the map is always safe to write to, even when the daemon restarts or the manager is constructed in tests.

### (d) Source Code Tracing (`tunnel.go` & `vrf.go`)
1. **Package Scope**: Both `tunnel.go` and `vrf.go` share `package routing`, so `isLinkNotFound` is package-visible and can be called directly from `Apply` in `tunnel.go`.
2. **Link Lookup Error Gating**:
   ```go
   if isLinkNotFound(err) {
       delete(t.appliedAddrs, name) // device genuinely gone; drop
   } else {
       nextWG[name] = true // transient lookup error: retain + retry
   }
   ```
   This is correct because if `LinkByName` returns `LinkNotFoundError` (e.g. manual `ip link del`), the kernel has already freed the interface and its addresses. Dropping tracking here is safe and matches the behavior of GRE removal.
3. **Concurrency**: All map writes and netlink ops are protected by the manager's mutex `t.mu`, which is locked at the beginning of `Apply` and `clearLocked`. No new race conditions are introduced.
