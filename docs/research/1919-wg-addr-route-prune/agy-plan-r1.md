# Adversarial Review of Research Plan #1919 (r1)
**Target**: `docs/research/1919-wg-addr-route-prune/plan.md`
**Verdict**: `PLAN-NEEDS-MAJOR`

The proposed plan contains critical design defects in its core retry/reconciliation logic and transient error handling that will cause address leaks and broken retries in production. It must be revised before proceeding.

---

## Key Question Review

### (1) Retry Signal for Regular Addresses on AddrDel Failure (Broken)
* **Plan §5 Proposal**:
  ```go
  remaining := t.reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name], "wireguard tun")
  if len(remaining) > 0 {
      t.appliedAddrs[name] = remaining
      nextWG[name] = true // AddrDel failed → retry next apply
      continue
  }
  ```
* **Source Reality**: [pkg/routing/tunnel.go:615-620](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L615-L620)
  ```go
  if delErr := t.ops.AddrDel(link, &a); delErr != nil {
      slog.Warn("failed to remove stale "+kind+" address", "name", name, "addr", key, "err", delErr)
      if a.IP != nil && a.IP.IsLinkLocalUnicast() {
          newApplied[key] = true // retry next apply
      }
  }
  ```
* **Verdict**: **CONFIRMED (Broken)**. If `AddrDel` fails for a regular (non-link-local) address, `newApplied[key] = true` is skipped at line 618. The address is omitted from `newApplied` (which is returned as `remaining`). Consequently, `len(remaining)` will be `0` (unless a link-local delete also failed), and the prune loop will execute `delete(t.appliedAddrs, name)` and skip adding `name` to `nextWG`. The retry signal for regular addresses is broken.

### (2) Handling of LinkByName Failures (Defective)
* **Plan §5 Proposal**:
  ```go
  if link, err := t.ops.LinkByName(name); err == nil {
      ...
  }
  delete(t.appliedAddrs, name)
  ```
* **Source Reality**: [pkg/routing/vrf.go:155](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L155) provides `isLinkNotFound(err)` to isolate link absence.
* **Verdict**: **CONFIRMED (Defective)**. Any transient error (e.g. netlink buffer exhaustion, timeout) from `LinkByName` causes the code to jump to `delete(t.appliedAddrs, name)` and drop the tracking entry without retry. Because the persistent `wgN` link survives, the addresses survive on the interface but are forgotten by the daemon.
* **Mitigation**: Retain tracking and retry on transient errors:
  ```go
  link, err := t.ops.LinkByName(name)
  if err != nil {
      if !isLinkNotFound(err) {
          nextWG[name] = true // Retain tracking for retry
      } else {
          delete(t.appliedAddrs, name)
      }
      continue
  }
  ```

### (3) "Manager-Applied Addresses Only" Prune (Overclaim)
* **Plan Claims**: 
  - §4 Path A: "...strips manager-applied addresses (empty desired set), honoring the link-local applied gate..."
  - §8 R1: "Mitigation: only addresses in `appliedAddrs[name]` (manager-applied) are eligible..."
* **Source Reality**: [pkg/routing/tunnel.go:611-614](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L611-L614):
  ```go
  if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
      // Kernel-managed or foreign link-local: never delete.
      continue
  }
  ```
* **Verdict**: **CONFIRMED (Overclaim)**. The `applied` check only gates link-local unicast addresses. For any regular (non-link-local) address on the interface, the gate is bypassed. Running `reconcileLinkAddrsLocked(..., nil, ...)` deletes ALL stale non-link-local addresses on the link, whether they were manager-applied or manually configured.

### (4) FRR Managed-Section Route Synthesis (None)
* **Plan Claim**: §1a: "WireGuard config does not synthesize any FRR routes... No manager-owned FRR route to withdraw."
* **Source Reality**: [pkg/daemon/daemon_ipmon.go:89-153](file:///home/ps/git/bpfrx/pkg/daemon/daemon_ipmon.go#L89-L153) (`assembleFRRConfig`) builds FRR configs completely dynamically from static routes, generate routes, DHCP, interface properties, etc. There is no code mapping WireGuard allowed IPs or tunnel instances to FRR routes.
* **Verdict**: **CONFIRMED (Correct)**. WireGuard configuration does not synthesize FRR routes.

### (5) VRF A1 Deferral (OK with Nit)
* **Plan Claim**: §4a: "prune addresses only; leave the VRF master as-is."
* **Source Reality**: [pkg/routing/tunnel.go:883-888](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L883-L888) (`applyWireguardTunLocked`) binds to VRF if `tc.RoutingInstance != ""`, but lacks any mechanism to unbind if the VRF config is removed while keeping the tunnel.
* **Verdict**: **OK with Nit**. Deferring VRF unbind is acceptable, but the plan must explicitly note that changing a configured WG tunnel to have *no* routing instance will keep it bound to the old VRF in the kernel, as `applyWireguardTunLocked` does not unbind.

### (6) Restart-Adoption R5 (OK)
* **Plan Claim**: §8 R5: "on a fresh daemon, `wgConfigured` is empty... same restart-adoption limitation the rest of the file has."
* **Source Reality**: [pkg/routing/tunnel.go:139-152](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L139-L152) (`ensureReconcileStateLocked`) initializes empty maps.
* **Verdict**: **OK**. The restart limitation is identical to the rest of the file: tunnels removed while the daemon is down are not in memory, so they are not pruned. This is consistent with existing GRE/IPIP adoption limitations.

### (7) #1918 Keepalive Interaction (None)
* **Plan Claim**: §8 R4: "WG has no keepalive."
* **Source Reality**: `applyWireguardTunLocked` does not configure keepalives. Only `applyKernelTunnelLocked` calls `startKeepalive`.
* **Verdict**: **CONFIRMED (Correct)**. No interaction exists.
