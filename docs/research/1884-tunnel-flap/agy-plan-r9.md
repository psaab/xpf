PLAN-READY

Here is the adversarial review of the implementation direction for **xpf issue #1884** based on plan version 9 in [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md).

---

### (Q1) Sweep of the 27 cells: (stanza ∈ {none, bind-ok, bind-fail}) × (list ∈ {none, 0a-ok, 0a-fail}) × (prior claim ∈ {none, stale, fresh})

Below is the state-transition table for all 27 cells under the ordered claim-update and unbind procedure defined in Section A.5 of [plan.md](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md#L351-460). 

*Note: For these evaluations, let "A" be the prior claim VRF, "B" be the stanza VRF, and "C" be the list member VRF.*

| Cell | Stanza | List (0a) | Prior Claim | End Kernel State | End Claim (`appliedRI`) | Unbind Called? | Strands Owned Master? | Unbinds Foreign Master? |
|---|---|---|---|---|---|---|---|---|
| **1** | none | none | none | Unchanged | `""` | No | No | No |
| **2** | none | none | stale (A) | Unchanged (X) | `""` (cleared) | No (mismatch) | No | No |
| **3** | none | none | fresh (A) | Unbound | `""` (cleared) | Yes (success) | No | No |
| **4** | none | 0a-ok (C) | none | `vrf-C` | `"C"` (fresh) | No | No | No |
| **5** | none | 0a-ok (C) | stale (A) | `vrf-C` | `"C"` (fresh) | No | No | No |
| **6** | none | 0a-ok (C) | fresh (C) | `vrf-C` | `"C"` (fresh) | No | No | No |
| **7** | none | 0a-fail (C) | none | Unchanged | `""` | No | No | No |
| **8** | none | 0a-fail (C) | stale (A) | Unchanged | `"A"` (retained) | No | No (retried next) | No |
| **9** | none | 0a-fail (C) | fresh (A) | `vrf-A` | `"A"` (retained) | No | No (intended keep) | No |
| **10** | bind-ok (B) | none | none | `vrf-B` | `"B"` | No | No | No |
| **11** | bind-ok (B) | none | stale (A) | `vrf-B` | `"B"` | No | No | No |
| **12** | bind-ok (B) | none | fresh (A) | `vrf-B` | `"B"` | No | No | No |
| **13** | bind-ok (B) | 0a-ok (C) | none | `vrf-B` | `"B"` (stanza wins) | No | No | No |
| **14** | bind-ok (B) | 0a-ok (C) | stale (A) | `vrf-B` | `"B"` (stanza wins) | No | No | No |
| **15** | bind-ok (B) | 0a-ok (C) | fresh (A) | `vrf-B` | `"B"` (stanza wins) | No | No | No |
| **16** | bind-ok (B) | 0a-fail (C) | none | `vrf-B` | `"B"` | No | No | No |
| **17** | bind-ok (B) | 0a-fail (C) | stale (A) | `vrf-B` | `"B"` | No | No | No |
| **18** | bind-ok (B) | 0a-fail (C) | fresh (A) | `vrf-B` | `"B"` | No | No | No |
| **19** | bind-fail (B) | none | none | Unchanged | `""` | No | No | No |
| **20** | bind-fail (B) | none | stale (A) | Unchanged | `"A"` (retained) | No | No (retried next) | No |
| **21** | bind-fail (B) | none | fresh (A) | `vrf-A` | `"A"` (retained) | No | No (intended keep) | No |
| **22** | bind-fail (B) | 0a-ok (C) | none | `vrf-C` | `"C"` (fallback) | No | No | No |
| **23** | bind-fail (B) | 0a-ok (C) | stale (A) | `vrf-C` | `"C"` (fallback) | No | No | No |
| **24** | bind-fail (B) | 0a-ok (C) | fresh (A) | `vrf-C` | `"C"` (fallback) | No | No | No |
| **25** | bind-fail (B) | 0a-fail (C) | none | Unchanged | `""` | No | No | No |
| **26** | bind-fail (B) | 0a-fail (C) | stale (A) | Unchanged | `"A"` (retained) | No | No (retried next) | No |
| **27** | bind-fail (B) | 0a-fail (C) | fresh (A) | `vrf-A` | `"A"` (retained) | No | No (intended keep) | No |

#### Analysis:
1. **Stranding Owned Masters**: 
   - Under Cell 3, the owned master is successfully unbound, and its claim is cleared.
   - For cells where the transient transition to a new VRF fails (e.g., Cells 8, 9, 20, 21, 26, 27), the prior claim is **retained**. This ensures that if the config is subsequently cleared (transitioning to Cell 3), the manager still possesses the authority to perform the unbind. Thus, no owned master is permanently stranded.
2. **Unbinding Foreign Masters**:
   - Under Cell 2 (stale claim, foreign master `vrf-X` in the kernel), the identity check `LinkByName("vrf-" + appliedRI[name]).Index == link.Attrs().MasterIndex` fails. The unbind step is bypassed, and the claim is cleared. No foreign master is ever unbound.

---

### (Q2) Other defects or re-opened closures in the r8 fold

#### 1. Target Deletion Lookup Failure Recovery (A.1)
In the set-diff removal block in Section A.1:
```go
    if link, err := t.ops.LinkByName(name); err == nil {
        if delErr := t.ops.LinkDel(link); delErr != nil {
            next[name] = true
            slog.Warn(...)
            continue
        }
    }
```
* **Defect**: If `LinkByName` returns a **transient** error (e.g. netlink busy or buffer overflow), `err == nil` is false. The code will skip the `LinkDel` attempt but will also **not** set `next[name] = true` and will delete the tracking maps for `appliedAddrs` and `appliedRI`. Consequently, the manager orphans the tunnel interface in the kernel and ceases tracking it.
* **Fix**: Use `isLinkNotFound(err)` from [vrf.go:L155](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L155) to prune tracking only on explicit not-found or success:
  ```go
  link, err := t.ops.LinkByName(name)
  if err == nil {
      if delErr := t.ops.LinkDel(link); delErr != nil {
          next[name] = true
          slog.Warn(...)
          continue
      }
  } else if !isLinkNotFound(err) {
      next[name] = true
      slog.Warn("transient lookup failure on delete retry", "name", name, "err", err)
      continue
  }
  ```

#### 2. Keepalive ICMP Probe Target & Recovery (A.7)
* **Verification**: In A.7, if the keepalive runner declares a link down (`state.Up == false`), it skips `LinkSetUp` on re-applies to prevent overriding the keepalive loop's state transition. 
* We pressure-tested whether this could trap a tunnel in a permanently down state (since interface down normally drops routing over the interface). Because `startKeepalive` passes `tc.Destination` (the tunnel outer endpoint IP) to the ICMP probe, the packets are routed over the physical underlay network, not the tunnel itself. 
* Therefore, the probes continue to succeed/fail regardless of the tunnel link's administrative state, ensuring keepalive recovery functions normally. No defect exists here.
