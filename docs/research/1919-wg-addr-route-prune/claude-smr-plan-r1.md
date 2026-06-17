# Claude SMR hostile plan-review — #1919 r1

Reviewer: Claude SMR (domain SMR + CPU/design). Stance: HOSTILE.
Verdict: **PLAN-NEEDS-MAJOR** (one real correctness defect in the retry
mechanism; rest is sound and the recommended path is right).

---

## F1 (MAJOR, CORRECTNESS) — the AddrDel-failure retry signal is broken for non-link-local addresses

The plan (§5) detects "AddrDel failed, retain for retry" via:
```go
remaining := t.reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name], "wireguard tun")
if len(remaining) > 0 { t.appliedAddrs[name] = remaining; nextWG[name] = true; continue }
```

But `reconcileLinkAddrsLocked` (`tunnel.go:584-645`) builds `newApplied`
as: successful **adds** + **present-and-wanted** + **link-local whose
delete FAILED**. Walk it for the prune call (desired = `nil`):

- `want` is empty (no addrs passed).
- Delete loop (`:597-625`): for each present address `a` that is not
  wanted (all of them): if `a.IP.IsLinkLocalUnicast() && (applied==nil
  || !applied[key])` → skip. Otherwise `AddrDel`. **On AddrDel failure**
  the ONLY path that records into `newApplied` is the link-local guard at
  `:618`:
  ```go
  if delErr := t.ops.AddrDel(link, &a); delErr != nil {
      ...
      if a.IP != nil && a.IP.IsLinkLocalUnicast() {
          newApplied[key] = true // retry next apply
      }
  }
  ```
  A **regular (non-fe80) address whose AddrDel failed is NOT recorded**.
- Add loop (`:627-643`): wanted set is empty → records nothing.

**Therefore**: when AddrDel of a normal v4/v6 address (e.g.
`172.16.0.1/30`) fails during the prune, `reconcileLinkAddrsLocked`
returns an **empty** map. The plan's `len(remaining)>0` is false →
`delete(t.appliedAddrs, name)` runs and `name` is dropped from
`nextWG`. The failed address is now **untracked and never retried** —
the exact leak this PR exists to fix, re-introduced on the failure path.

This is a real defect, not a nit. The GRE removal loop the plan claims to
mirror does NOT have this problem because it `LinkDel`s the whole device
(addresses go with it) and retains the NAME on LinkDel failure
(`:194-198`) — a different, intact retry signal. The plan borrowed the
"retain name on failure" idea but wired it to a return value that does
not carry non-link-local delete failures.

**Required fix (pick one, state in r2):**

- **F1-a (preferred)**: don't infer retry from the return value. After
  the prune `reconcileLinkAddrsLocked` call, **re-list** the link's
  addresses (or have the prune compare `appliedAddrs[name]` before/after)
  and retain `name` in `nextWG` if any **manager-applied** address is
  still present on the device. Simpler: retain `name` whenever the prune
  ran against a found link and `appliedAddrs[name]` was non-empty going
  in, then only drop it once a subsequent prune confirms the device has
  none of the tracked addresses left. This makes the retry independent of
  `reconcileLinkAddrsLocked`'s asymmetric return contract.
- **F1-b**: add a dedicated prune helper (do NOT overload
  `reconcileLinkAddrsLocked`) that deletes every manager-applied address
  and returns the set that FAILED to delete (all families, not just
  link-local). Keep `reconcileLinkAddrsLocked` untouched (it has a
  carefully-reviewed contract per #1884/#1905 — changing its return
  semantics would ripple into the GRE/anchor/WG-apply callers). This is
  cleaner separation: removal-prune and steady-state-reconcile are
  different operations with different failure-tracking needs.

Recommend **F1-b** — a small `pruneAppliedAddrsLocked(link, name)` that
returns the failed-delete set across all families. It keeps the #1884
reconcile contract frozen and makes the retry signal correct by
construction. r2 must specify this.

## F2 (MINOR) — `appliedAddrs[name]` may be the WRONG eligibility set after a partial steady-state apply

`appliedAddrs[name]` records adds + present-and-wanted, but the prune
deletes by enumerating the **device's current** addresses
(`AddrList`), not by iterating `appliedAddrs[name]`. So the prune will
attempt to delete EVERY non-link-local address currently on the device,
including any an operator may have added out-of-band with `ip addr add
… dev wgN`. For GRE/anchor this is the documented #1884 behavior (the
manager owns the configured set). For a **persistent WG device that the
operator was told persists**, deleting an out-of-band address on removal
is arguably more aggressive than the steady-state reconcile (which also
deletes unconfigured addrs, so this is at least consistent). Not a
blocker, but the plan should STATE that the prune deletes all non-fe80
addresses present on the device, not only `appliedAddrs`-tracked ones —
and confirm that matches the desired semantics (it does: "strip the
addresses the manager assigned" — and the manager's reconcile already
owns the full non-link-local set). Add one sentence to §5.

## F3 (CONFIRM, not a defect) — §1a FRR-routes scoping is correct

I independently confirm: `assembleFRRConfig` (`daemon_ipmon.go:89-153`)
reads only `RoutingOptions.{StaticRoutes,Inet6StaticRoutes,GenerateRoutes}`
+ per-instance static routes — never tunnel/WG config. `writeManagedSection`
(`manager.go:487-545`) is a full strip+rewrite. `WgAllowedIPs` is decap-
only (`types_routing.go:332`). So there is no manager-owned FRR route for
WG to withdraw; the declarative path self-heals operator static routes.
The plan's "clarify, don't code" stance on FRR is correct. KEEP, but in
r2 add the explicit grep evidence list to §1a so a reviewer can't reopen
it without producing a counter-path. Good defensive framing already.

## F4 (CONFIRM) — Path A over B/C is right

Path B (netdev heuristics) is correctly rejected — there is no stable
WG-only netdev marker; `applyWireguardTunLocked` itself only knows a
device is "WG" because the **config** said so. Path C violates #1432.
Path A keying off the tracked name set is the only safe detector. Agree.

## F5 (MINOR) — idempotency proof holds, but state the clear-path reset explicitly

`clearLocked` (`:1086-1113`) resets `ownedNames/appliedAddrs/appliedRI`
to nil. The plan adds `wgConfigured=nil` there — required, else a
post-Clear Apply would carry stale WG tracking and prune a freshly-
adopted device. Plan already says this (§5). Good. But ALSO:
`ensureReconcileStateLocked` (`:139-152`) must init `wgConfigured` — plan
says this too. Both sites covered. ✔

## F6 (CONFIRM) — #1918 interaction is genuinely none

`applyWireguardTunLocked` (`:798-890`) never calls `startKeepalive`; the
keepalive/probeICMP machinery is reached only from
`applyKernelTunnelLocked` (`:531-551`). #1918 touched `keepaliveLoop`/
`probeICMP`. Zero overlap with the WG branch. Plan correct.

## F7 (MINOR) — restart-adoption boundary R5 acceptable but undertested

R5 (a WG tunnel removed while the daemon was DOWN is never pruned because
`wgConfigured` starts empty) is a real boundary. It is consistent with
the rest of the file's "manager only prunes what it tracked" model and
correctly deferred to #1434. ACCEPTABLE. But the plan should add a test
asserting this boundary explicitly (Apply with empty config on a fresh
manager where a wgN with addresses exists in the kernel → assert NO
AddrDel) so the deferral is encoded, not just prose. Add to §6.

## F8 (NIT) — VRF residual (A1) is the right call

Leaving the WG link VRF-bound after removal is correct for this PR: WG
binds VRF directly (`:883-888`) without an `appliedRI` claim, so there is
no identity-gated unbind available, and a blind `LinkSetNoMaster` risks
the exact hazard `reconcileVRFClaimLocked` was built to prevent. A1
(addresses only, VRF residual documented under #1434) is sound. KEEP.

---

## Summary

The design (Path A, FRR-clarify, A1 VRF, #1918-clean) is correct and the
recommendation is right. **F1 is a genuine correctness defect**: the
retry-on-AddrDel-failure signal is wired to a return value
(`reconcileLinkAddrsLocked`'s `newApplied`) that does not record failed
deletes of non-link-local addresses, so a transient AddrDel failure
silently drops tracking and re-leaks the address. r2 must replace the
retry signal with a dedicated prune helper (F1-b) that returns the
all-family failed-delete set, and add the F7 restart-boundary test and
the F2/F3 wording. With F1 fixed the plan is shippable.

Verdict: **PLAN-NEEDS-MAJOR** (F1). F2/F3/F5/F6/F8 confirm; F7 add test.
