# Plan-of-action — #1919: WireGuard tunnel removal leaks kernel addresses (+ FRR routes claim)

- **Issue**: #1919 — routing: removing a WireGuard tunnel leaks its kernel
  addresses + FRR routes (persistent wgN bypasses address reconcile)
- **Revision**: r1 (DRAFT — pre-review)
- **Branch**: `research/1919-wg-addr-route-prune` off `origin/master`
  @ `ee3f336d3` (post-#1918, post-#1947)
- **Status**: PLAN DRAFT — research-only; STOP at PLAN-READY
- **Contract**: `/research`, NOT `/engineer`. No PR, no production source
  touched. Deliverable = converged plan + 3 verdicts + issue comment.

---

## 1. Problem statement

WireGuard TUN devices are intentionally **persistent** (#1432 S2a). In
`pkg/routing/tunnel.go`, the reconcile-in-place `Apply` excludes
`wireguard`-mode tunnels from the `desired` set and from `ownedNames`:

```go
// Apply, line 168-175
desired := make(map[string]bool, len(tunnels))
for _, tc := range tunnels {
    if tc.Mode != "wireguard" {        // WG excluded from removal diff
        desired[tc.Name] = true
    }
}
```

This is **correct** for the link itself — it avoids flapping `wgN` and
tearing the live peer/session on every commit (#1432 S2a, AGY Hazard B).

The bug: a WG tunnel's **addresses** are reconciled only inside
`applyWireguardTunLocked` (`tunnel.go:880`), which runs once per **still-
configured** WG tunnel via the per-tunnel loop:

```go
// Apply, line 208-219
for _, tc := range tunnels {          // tunnels = CURRENT config only
    if tc.Mode == "wireguard" {
        if err := t.applyWireguardTunLocked(tc); err != nil { ... }
        continue
    }
    ...
}
```

When an operator **removes** a WG tunnel from config:

- The `wgN` link is correctly kept (persistent), but
- `tc` for it is **absent** from `tunnels`, so `applyWireguardTunLocked`
  / `reconcileLinkAddrsLocked` is **never called for it again**, and
- It is **not in `ownedNames`**, so the `Apply` removal loop
  (`tunnel.go:188-204`) never visits it either.

Net: the kernel IP addresses this manager previously assigned to that
wgN device (e.g. `172.16.0.1/30`) are **never reconciled away** — they
persist on the live persistent device forever (until `ip link del wgN`
or daemon restart). The in-code comment at `tunnel.go:790-794` already
acknowledges this as a known S2a limitation (AGY M1) deferred to #1434.

### 1a. The FRR-route claim — IMPORTANT scoping correction

The issue title says "+ FRR routes". Investigation (§3) shows the FRR
managed section is **regenerated declaratively and fully every commit**
(`pkg/frr/manager.go:writeManagedSection` strips the entire
`! BEGIN BPFRX MANAGED CONFIG` … `! END` block and rewrites it from
`assembleFRRConfig`, then `frr-reload.py --reload` does a full diff). And
WireGuard config **does not synthesize any FRR routes** — `WgAllowedIPs`
are a decap inner-src gate only (`types_routing.go:328`), not LPM/routing,
and `assembleFRRConfig` (`daemon_ipmon.go:89-153`) never reads tunnel or
WG config. So **explicitly-configured static routes** that point at a wgN
interface are owned by `routing-options static`/`routing-instances`, and
when the operator removes those route statements, the full-rewrite +
`frr-reload.py --reload` full diff withdraws them on the next commit.

**Two sub-cases must be stated precisely** (a reviewer-critical
distinction — do not overclaim a leak that does not exist):

- **(A) Operator removes the static route stanza too** → FRR withdraws
  it via the normal declarative path. **No FRR leak.** The route would,
  however, be left pointing at a still-up wgN carrying stale addresses
  until this fix prunes the addresses — but the route object itself is
  withdrawn by FRR.
- **(B) Operator removes ONLY the `tunnel`/WG stanza but leaves a
  `routing-options static route … next-hop <wgN-addr>` referencing the
  pruned address** → the static route stays in FRR (still configured),
  now dangling toward an interface whose connected address we just
  removed. This is **operator misconfiguration**, not a manager leak;
  FRR/kernel will mark the route unreachable once the connected prefix
  is gone. The plan does NOT chase this — withdrawing operator-owned
  static routes the operator still has in config would be wrong.

**Plan conclusion on FRR routes**: the genuine, in-scope leak is
**kernel addresses on the persistent wgN device**, plus the **kernel
connected route** that the kernel auto-installs for each address (the
connected route is removed automatically by the kernel when its address
is `AddrDel`'d — it is not a separate object we manage). There is **no
manager-owned FRR route to withdraw**. The plan will (a) fix the address
leak, and (b) document in the PR + module docs that FRR static routes are
operator-owned and self-heal via the declarative path, closing the "FRR
routes" portion of the issue by clarification rather than code.

A reviewer who insists on an FRR code path must produce a concrete code
location where WG config synthesizes a managed-section route. None was
found in `pkg/frr/` (config_render.go, manager.go, daemon_ipmon.go all
walked). If one is produced during review, this plan escalates to add a
withdrawal hook; until then, the address prune is the complete fix.

---

## 2. Affected code (walked)

| Location | Role |
|---|---|
| `pkg/routing/tunnel.go:163-233` `Apply` | reconcile entry; builds `desired`/`next`/`oldOwned`; WG excluded from diff |
| `pkg/routing/tunnel.go:188-204` removal loop | deletes non-WG tunnels gone from config; `delete(appliedAddrs,name)` |
| `pkg/routing/tunnel.go:208-230` per-tunnel loop | runs `applyWireguardTunLocked` ONLY for still-configured WG |
| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
| `pkg/routing/tunnel.go:584-645` `reconcileLinkAddrsLocked` | symmetric add/del against desired addr set; link-local gate; returns new applied set |
| `pkg/routing/tunnel.go:104-134` `tunnelManager` fields | `ownedNames`, `appliedAddrs[name]`, `appliedRI[name]` |
| `pkg/routing/tunnel.go:666-722` `reconcileVRFClaimLocked` | VRF claim/unbind (WG also binds VRF at :883-888 but NOT via this reconcile) |
| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
| `pkg/config/types_routing.go:292-335` `TunnelConfig` | WG fields; `WgAllowedIPs` decap-only |
| `pkg/daemon/daemon_ipmon.go:89-153` `assembleFRRConfig` | sole FRR FullConfig constructor; no tunnel/WG input |
| `pkg/frr/manager.go:487-545` `writeManagedSection` | declarative full strip+rewrite of managed block |
| `pkg/routing/tunnel_reconcile_test.go` | existing WG tests: only link-local cases (356/390/410); NO removal test |

### Blast radius

- One file edited (`pkg/routing/tunnel.go`), one test file extended
  (`pkg/routing/tunnel_reconcile_test.go`), plus module-doc note.
- The fix is confined to the WG branch of `Apply`. It must NOT touch the
  GRE/IPIP removal diff (already correct) nor the still-configured WG
  apply (already reconciles addresses correctly via :880).
- No wire-protocol change, no userspace-dp change, no FRR change.
- Interaction with #1918 (merged, PR #1947): #1918 added `probeICMP`
  real-liveness to the **GRE keepalive** path (`keepaliveLoop`,
  `probeICMP` at :1024). WG tunnels never run keepalives
  (`applyWireguardTunLocked` never calls `startKeepalive`). So the #1918
  change does not interact with this fix; the rebase is clean (plan
  already branched off post-#1918 master @ ee3f336d3). No conflict.

---

## 3. Root cause (precise)

Two facts combine:

1. WG names are deliberately excluded from `ownedNames` and `desired`
   (`tunnel.go:172`), so the removal loop that prunes addresses for
   GRE/IPIP-style tunnels (via `delete(appliedAddrs,name)` + `LinkDel`)
   never fires for WG, AND
2. address reconciliation for WG happens *only* inside
   `applyWireguardTunLocked`, which is driven by the **current config
   list** (`tunnels` arg) — so a removed WG tunnel is simply never
   visited by any address-reconciling code again.

The persistent-device design (correct) and the address-reconcile-only-
when-configured design (correct for live tunnels) have a **gap exactly
at removal**: nobody owns "this WG device used to be configured, is now
gone from config, but the link must stay — strip its addresses."

The `appliedAddrs[name]` map is the key asset already in place: it
records exactly which addresses **this manager** applied to each device.
On removal we want to reconcile that device against an **empty desired
address set**, which `reconcileLinkAddrsLocked(link, name, nil,
appliedAddrs[name], …)` already does correctly (delete present-and-not-
wanted, respecting the link-local applied gate). We just need to *call*
it on removal and then drop the tracking entry.

---

## 4. Design — Path Options

The branch point is **how the manager detects "a WG tunnel was removed"
and how it prunes addresses while keeping the link**.

### Path A — Track previously-configured WG names; diff on removal (RECOMMENDED)

Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
to `ownedNames` but WG-only, and **never** feeding the `LinkDel` removal
loop). Each `Apply`:

1. Build `wgDesired` = set of `tc.Name` for current `Mode=="wireguard"`.
2. **Prune phase** (new), run alongside the existing GRE removal loop:
   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
   - look up the link (`LinkByName`); if found, call
     `reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name],
     "wireguard tun")` → strips manager-applied addresses (empty desired
     set), honoring the link-local applied gate (kernel autoconf fe80
     never touched).
   - **Keep the link** — never `LinkDel` (that is the #1432 invariant).
   - Optionally VRF-unbind (see §4a) — keep narrow for now.
   - `delete(t.appliedAddrs, name)` once pruned (idempotent: a second
     commit finds `name` no longer in old `wgConfigured`, so no-op).
   - If `LinkByName` fails (device already gone — manual `ip link del`),
     just `delete(t.appliedAddrs, name)` and drop tracking.
   - If `reconcileLinkAddrsLocked` leaves residual tracked addresses
     because an `AddrDel` failed, **retain** the name in the next
     `wgConfigured` so the next commit retries (mirrors GRE
     removal-retry at :197). Detect residual via the returned applied
     set being non-empty.
3. After the per-tunnel apply loop, set `t.wgConfigured = wgDesired`
   plus any retained-for-retry names.

**Pros**: symmetric with the existing `ownedNames` retry pattern; reuses
`reconcileLinkAddrsLocked` and `appliedAddrs` verbatim; idempotent;
link preserved; minimal new state (one map). Tested pattern in this file.

**Cons**: one more reconcile map to keep in sync across `clearLocked`
(must reset it too) and `ensureReconcileStateLocked` (must lazily init).

### Path B — Flush all addresses on any wgN that is up-but-unconfigured

On each `Apply`, enumerate kernel links, find TUN devices matching the
WG naming whose name is not in `wgDesired`, and flush manager-applied
addresses. Rejected: requires WG-name heuristics (no stable WG-only
marker on the netdev), risks touching foreign/adopted devices, and
duplicates the `appliedAddrs` bookkeeping Path A already has. Higher
blast radius, weaker safety.

### Path C — Tear the link too on removal

Rejected explicitly by #1432 S2a (AGY Hazard B): deleting wgN tears the
live peer/session and flaps the device. The issue itself says keep the
link. Out of scope; #1434 owns full teardown grammar.

### Recommendation

**Path A.** It is the minimal, symmetric, idempotent fix that reuses the
exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
already maintains, keeps the persistent link per #1432, and adds one
narrowly-scoped state map with the same retry discipline as the existing
GRE removal loop.

### 4a. VRF unbind on WG removal — scope decision

`applyWireguardTunLocked` VRF-binds at `:883-888` but does NOT use
`reconcileVRFClaimLocked`/`appliedRI` (it binds directly, no claim
tracked). So a removed WG tunnel that was VRF-bound leaves the link
enslaved to `vrf-<ri>`. Two choices:

- **A1 (recommended for this PR)**: prune **addresses only**; leave the
  VRF master as-is. Rationale: the link persists by design; its VRF
  membership is a property of the persistent device, not a leaked
  address; and there is no `appliedRI` claim to safely identity-gate an
  unbind (unbinding blind would risk stripping a master we do not own —
  the exact hazard `reconcileVRFClaimLocked` was built to avoid). Note
  this explicitly as a documented residual, tracked under #1434.
- **A2**: extend WG to use `appliedRI`/`reconcileVRFClaimLocked` so
  removal can identity-gated-unbind. Larger change; couples this fix to
  the VRF-claim machinery WG deliberately bypasses. Defer.

Decision: **A1** — addresses only, VRF residual documented. If a
reviewer demands VRF unbind, escalate to A2 as a follow-up, not this PR.

---

## 5. Detailed implementation sketch (Path A)

State (add to `tunnelManager`):
```go
// wgConfigured: WG tunnel names configured at the LAST Apply (plus
// names whose address prune left residual tracked addrs, retained for
// retry). NEVER feeds the LinkDel removal loop — WG links persist
// (#1432 S2a). Drives the WG address-prune-on-removal diff (#1919).
wgConfigured map[string]bool
```

`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.

`Apply`:
```go
wgDesired := map[string]bool{}
for _, tc := range tunnels {
    if tc.Mode == "wireguard" { wgDesired[tc.Name] = true }
}
oldWG := t.wgConfigured
nextWG := map[string]bool{}
for n := range wgDesired { nextWG[n] = true }
// prune phase
for name := range oldWG {
    if wgDesired[name] { continue }
    if link, err := t.ops.LinkByName(name); err == nil {
        remaining := t.reconcileLinkAddrsLocked(link, name, nil,
            t.appliedAddrs[name], "wireguard tun")
        if len(remaining) > 0 {
            t.appliedAddrs[name] = remaining
            nextWG[name] = true // AddrDel failed → retry next apply
            continue
        }
    }
    delete(t.appliedAddrs, name)
}
// ... existing GRE removal loop unchanged ...
// ... per-tunnel apply loop unchanged (still-configured WG re-tracked) ...
t.wgConfigured = nextWG
```

Note: `nextWG` is rebuilt from `wgDesired` at entry; the per-tunnel loop
already re-applies still-configured WG (no change there). The prune loop
runs against `oldWG` so it sees exactly the names that disappeared.

`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
ClearTunnels still does not delete WG links (unchanged) — but on a full
clear the operator intent is teardown; whether ClearTunnels should now
also flush WG addresses is a **secondary decision** (§7 open question).
Default: leave ClearTunnels behavior unchanged (it never managed WG
addresses before); only reset the tracking map so a post-Clear Apply
re-adopts cleanly.

Idempotency proof: after the prune commit, `oldWG` (next round) no longer
contains the removed name (we set `t.wgConfigured = nextWG` which only
carries retained-for-retry names). A clean prune drops the name entirely
→ next `Apply` sees it in neither `oldWG` nor `wgDesired` → no-op. A
failed-AddrDel prune keeps it in `nextWG` → retried until clean. ✔

---

## 6. Tests (new, in `tunnel_reconcile_test.go`)

Using the existing fake `linkOps` harness:

1. **`TestWireguardRemovedFromConfigPrunesAddresses`**: Apply with a WG
   tunnel carrying `172.16.0.1/30` (+ optional fe80 configured) → assert
   AddrAdd called. Apply again with empty tunnel list → assert
   (a) link is NOT deleted (no LinkDel for wgN), (b) AddrDel called for
   `172.16.0.1/30`, (c) configured fe80 deleted, kernel autoconf fe80
   untouched (reuse the link-local gate test fixtures at :349-435).
3. **`TestWireguardRemovalPruneIdempotent`**: third Apply (still empty)
   → assert NO further AddrDel / LinkByName churn for the pruned name
   (name dropped from tracking).
4. **`TestWireguardRemovalAddrDelFailureRetried`**: fake AddrDel returns
   error on first removal Apply → assert name retained, second removal
   Apply retries AddrDel.
5. **`TestWireguardRemovalDeviceAlreadyGone`**: LinkByName returns
   not-found on removal → assert no panic, tracking dropped, no-op next.
6. **`TestWireguardReAddAfterRemovalTracksFresh`**: add → remove (prune)
   → re-add same name with a NEW address → assert new addr applied and
   old addr not re-leaked (appliedAddrs correctly reset/repopulated).
7. **Regression guard**: existing `TestWireguardConfiguredLinkLocalRemoved`
   and friends must still pass (still-configured reconcile unchanged).

All tests assert via the fake's recorded `AddrAdd`/`AddrDel`/`LinkDel`
call logs. No live netlink.

---

## 7. Open questions / decisions for reviewer

1. **ClearTunnels + WG addresses**: should the explicit delete-everything
   path also flush WG addresses (and/or delete the WG link)? Current
   plan: NO change to ClearTunnels link behavior; only reset the new
   tracking map. Rationale: ClearTunnels never managed WG before; #1434
   owns teardown. Reviewer may want ClearTunnels to flush WG addresses
   for symmetry — call it.
2. **VRF unbind on WG removal** (§4a): A1 (addresses only) vs A2 (full
   VRF-claim adoption for WG). Plan: A1, residual documented.
3. **FRR routes** (§1a): plan asserts there is NO manager-owned FRR
   route for WG to withdraw and closes that sub-claim by clarification.
   Reviewer must produce a concrete WG→FRR-route code path to reopen it.
4. **Live peer/session**: removal keeps the link AND (per current code)
   the Rust wg_control thread keeps attached. Confirm intended:
   pruning the inner addresses while the peer stays attached means the
   device is up but unaddressed. Issue text says "keep the persistent
   wgN link (and the live peer/session if that's intended — clarify)".
   Plan position: keep link + peer attached (don't touch Rust); only
   strip the Go-managed kernel addresses. This matches #1432 S2a's
   "persistent device" intent and #1434's ownership of full teardown.

---

## 8. Risks & mitigations

- **R1 — pruning an address still in use by a live flow**: removing a WG
  tunnel from config IS the operator declaring it gone; stripping its
  addresses is the intended effect. Mitigation: only addresses in
  `appliedAddrs[name]` (manager-applied) are eligible; foreign/autoconf
  link-local is gated out by `reconcileLinkAddrsLocked`.
- **R2 — touching the wrong device** (Path B hazard): avoided by Path A
  keying off the exact tracked name set, not netdev heuristics.
- **R3 — retry storms on persistent AddrDel failure**: bounded by the
  same retain-and-retry pattern GRE removal uses; each Apply does at
  most one AddrDel attempt per residual address.
- **R4 — interaction with #1918**: none (WG has no keepalive). Verified.
- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
  while the daemon was DOWN is not in `oldWG` → not pruned by this fix.
  This is the **same restart-adoption limitation** the rest of the file
  has (the manager only prunes what it tracked applying). Document as a
  known boundary; full restart-time WG reconciliation is #1434 scope.
  (A reviewer may ask for a restart-time sweep — explicitly defer.)

---

## 9. Validation plan

- `make test` — Go unit tests (new + existing routing tests).
- `go test ./pkg/routing/...` focused run.
- `go vet ./pkg/routing/...`.
- No smoke required for a control-plane address-reconcile change with no
  dataplane/wire impact — but a manual incus check (configure WG tunnel
  with an address, `ip addr show wgN`, remove from config + commit,
  confirm address gone and link still present) is the acceptance demo
  for the PR description. (Optional at `/engineer` time.)

---

## 10. Module-doc updates (part of the contract)

- Update the `applyWireguardTunLocked` doc comment (`tunnel.go:784-797`)
  to remove/replace the "leaks until ip link del or daemon restart"
  S2a-limitation note (AGY M1) — it is now resolved for the
  config-removal-while-running case; restate the remaining boundaries
  (restart-time removal, VRF residual, link+peer kept).
- Update any `docs/` tunnel/wireguard module doc that states the leak as
  a known limitation. Grep `docs/` for "S2a", "wireguard", "AGY M1",
  "leak" during `/engineer`; if none reference it, say so in review notes.
- PR body: explicitly scope the "FRR routes" claim per §1a (clarified,
  not code-fixed) so the issue's title is fully addressed.

---

## 11. Reviewer ledger

See `reviewer-ids.md` for Codex / AGY task IDs per round. Convergence
target: all three (Claude SMR + Codex + AGY) PLAN-READY on the final rev.

---

## Appendix — verbatim key code

`Apply` WG exclusion (`tunnel.go:168-175`):
```go
desired := make(map[string]bool, len(tunnels))
for _, tc := range tunnels {
    if tc.Mode != "wireguard" {
        desired[tc.Name] = true
    }
}
```

WG apply branch (`tunnel.go:208-219`):
```go
for _, tc := range tunnels {
    if tc.Mode == "wireguard" {
        if err := t.applyWireguardTunLocked(tc); err != nil {
            slog.Warn("failed to apply wireguard tunnel", "name", tc.Name, "err", err)
        }
        continue
    }
    ...
}
```

WG address reconcile (the asset we reuse on removal) (`tunnel.go:880-881`):
```go
t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
    link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
```

Known-limitation comment to update (`tunnel.go:790-794`):
```go
// Known S2a limitation (AGY M1): because the device is untracked, a WG
// tunnel REMOVED from the config is not torn down by clearLocked and
// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
// accepts this in exchange for reload stability; multi-instance teardown
// is owned by the S6 grammar work (#1434).
```
