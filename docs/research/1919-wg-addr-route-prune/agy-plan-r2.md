# Adversarial Review of Research Plan #1919 (r2)

**Target Plan**: `docs/research/1919-wg-addr-route-prune/plan.md` (Revision r2)  
**Branch**: `research/1919-wg-addr-route-prune` in worktree `.claude/worktrees/1919-research-wg-addr-route-prune`  
**Verdict**: **`PLAN-READY`**

---

## 1. Verification of Round 1 Findings

### Finding (1): Retry Signal for Regular Addresses on AddrDel Failure (Resolved)
* **Status**: **RESOLVED**
* **Trace**:
  The r2 plan introduces a dedicated, removal-only helper `pruneAppliedAddrsLocked(link, name, applied)` in [pkg/routing/tunnel.go](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go).
  Unlike [reconcileLinkAddrsLocked](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L584), which only returns failed stale deletes for link-local addresses, `pruneAppliedAddrsLocked` populates `failed[key] = true` for **all** address families (both IPv4/IPv6 global unicast and link-local) when `AddrDel` returns an error:
  ```go
  if delErr := t.ops.AddrDel(link, &a); delErr != nil {
      slog.Warn("failed to prune wireguard tun address", "name", name, "addr", key, "err", delErr)
      failed[key] = true // ALL families
  }
  ```
  If `len(failed) > 0`, the `Apply` prune loop retains the failed addresses in `t.appliedAddrs[name]` and sets `nextWG[name] = true` so the removal and address deletion are retried on the next configuration apply.
* **AddrList Error Fallback**: If `AddrList` fails (e.g. netlink socket transient issue), the code correctly falls back to marking all historically applied/tracked addresses as failed, ensuring they are retained in tracking and retried:
  ```go
  if err != nil {
      for k := range applied { failed[k] = true }
      return failed
  }
  ```
* **Autoconf-fe80 Gate**: The link-local gate is correctly preserved:
  ```go
  if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
      continue // kernel autoconf / foreign link-local: never delete
  }
  ```
  This matches the steady-state gate in [reconcileLinkAddrsLocked](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L611), preventing accidental deletion of kernel-autoconfigured or foreign link-local addresses.

### Finding (2): Handling of LinkByName Failures (Resolved)
* **Status**: **RESOLVED**
* **Trace**:
  The r2 plan gates `LinkByName` lookup errors on [isLinkNotFound](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L151):
  ```go
  link, err := t.ops.LinkByName(name)
  if err != nil {
      if isLinkNotFound(err) {
          delete(t.appliedAddrs, name) // device genuinely gone; drop
      } else {
          nextWG[name] = true // transient lookup error: retain + retry
      }
      continue
  }
  ```
  This prevents dropping applied address tracking on transient errors (like netlink buffer exhaustion or timeouts), which would otherwise cause the addresses to leak in the kernel indefinitely.

### Finding (3): "Manager-Applied Addresses Only" Prune (Resolved)
* **Status**: **RESOLVED**
* **Trace**:
  The r2 plan explicitly corrects the scope in §4b to state that the prune deletes **all** non-link-local addresses (present-but-unwanted), aligning with the steady-state address reconciliation semantics. In `pruneAppliedAddrsLocked`, the link-local unicast gate is only bypassed for non-link-local addresses, which correctly triggers `AddrDel` for all stale global addresses, regardless of whether they are in the `applied` tracking map.

---

## 2. Idempotency Proof: Add / Remove / Remove-Again

We trace the tracking map states across successive `Apply` configurations:
1. **Add**: Configuration has `wg0` with address `10.0.0.1/24`.
   - `wgDesired = {"wg0": true}`.
   - `applyWireguardTunLocked` runs, applies address, and sets `t.appliedAddrs["wg0"] = {"10.0.0.1/24": true}`.
   - At the end of `Apply`, `t.wgConfigured = nextWG` (which is `{"wg0": true}`).
2. **Remove**: Configuration drops `wg0`.
   - `wgDesired` is empty. `oldWG = {"wg0": true}`.
   - `Apply` prune loop runs for `wg0`.
   - `LinkByName("wg0")` succeeds.
   - `pruneAppliedAddrsLocked` successfully deletes `10.0.0.1/24` and returns empty `failed`.
   - `delete(t.appliedAddrs, "wg0")` is called.
   - `nextWG` is empty.
   - `t.wgConfigured` is set to `nextWG` (empty).
3. **Remove-Again**: Configuration remains empty.
   - `wgDesired` is empty. `oldWG = t.wgConfigured` (empty).
   - Prune loop does not execute. No netlink commands are run for `wg0`.
   - Idempotency is fully preserved.

---

## 3. Map Initialization and State Reset Wiring

* **`ensureReconcileStateLocked`**:
  Successfully handles lazy initialization of `t.wgConfigured` so direct constructor callers (tests and CLI) are unaffected:
  ```go
  if t.wgConfigured == nil {
      t.wgConfigured = map[string]bool{}
  }
  ```
* **`clearLocked`**:
  Correctly resets `t.wgConfigured = nil` alongside other tracking maps on a full reset, ensuring adoption can happen cleanly post-clear.

---

## 4. Analysis of FRR Route Claims & VRF Deferrals

* **FRR Routes (§1a)**:
  Confirmed correct. WireGuard tunnels do not register or generate static routes in [assembleFRRConfig](file:///home/ps/git/bpfrx/pkg/daemon/daemon_ipmon.go#L89-L153). Any static routes pointing to `wgN` interfaces are operator-owned configurations in `routing-options` and are managed/withdrawn declaratively via the dynamic rewrite of the FRR managed block in [writeManagedSection](file:///home/ps/git/bpfrx/pkg/frr/manager.go#L487).
* **VRF Claims (§4a A1)**:
  Confirmed acceptable. WireGuard bypasses the `reconcileVRFClaimLocked` and `appliedRI` tracking, meaning removing a tunnel leaves the persistent interface enslaved to its VRF master. This is a documented residual aligned with the persistent-interface model and is tracked under issue #1434.

---

## 5. Review of the Proposed Test Cases (§6)

The test coverage defined in §6 is comprehensive and targets all critical edge cases:
- `TestWireguardRemovedFromConfigPrunesAddresses`: Core removal path verification.
- `TestWireguardRemovalPruneIdempotent`: Verifies no-op on subsequent empty configuration applies.
- `TestWireguardRemovalAddrDelFailureRetried`: Ensures both link-local and global unicast failed deletes are retried (the core r1 fix).
- `TestWireguardRemovalDeviceNotFoundDropsTracking`: Validates `isLinkNotFound` handling.
- `TestWireguardRemovalTransientLookupRetained`: Validates transient error retry behavior.
- `TestWireguardReAddAfterRemovalTracksFresh`: Re-add adoption and state refresh.
- `TestWireguardRemovedWhileDaemonDownNotPruned`: Adoption adoption limitation boundary (R5).
