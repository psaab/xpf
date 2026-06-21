# Plan of action — #2197 proxy-ARP follow-ups

> Status: **PLAN-READY** (research only; no production code, no PR).
> Branch: `research/2197-proxyarp-followups`. Worktree:
> `.claude/worktrees/2197-research`. Drives three deferred refinements from
> the independent review of PR #2195 (#2160 static-NAT proxy-ARP).

Per-item verdict:

| Item | Sev | Verdict | One-line |
|------|-----|---------|----------|
| 1. v6 proxy-NDP pneigh table install | MEDIUM | **PLAN-READY** | mirror the v4 NTF_PROXY install in the AF_INET6 branch — clear win, the netlink lib already supports it |
| 2. re-assert proxy_arp after a non-commit link cycle | LOW | **PLAN-READY** | factor the apply-path reconcile into a daemon method, call it from the always-on periodic neighbor loop (standalone) + `reconcileRGState` (cluster) + post-`programRethMAC` |
| 3. narrow over-answer to per-address (Junos parity) | LOW-MED | **PLAN-DEFER** | the #2160 case is exactly the topology where the pneigh branch CANNOT answer (`rt.dst.dev == dev`) → the sysctl is load-bearing → cannot be dropped without breaking the very case #2160 fixed; ship a documented, opt-in narrowing only after a lab characterization |

---

## 1. Problem statement

PR #2195 (#2160) fixed static-NAT proxy-ARP: it installs an `NTF_PROXY`
neighbor entry for each configured IPv4 proxy address AND enables the
per-interface `net.ipv4.conf.<if>.proxy_arp` (or `proxy_ndp` for v6)
responder sysctl, so the kernel actually answers ARP/NDP. The independent
review accepted the fix and filed three deferred refinements:

1. **(MEDIUM) IPv6 proxy-NDP is Partial.** `proxyarp.go` enables
   `net.ipv6.conf.<if>.proxy_ndp` for a v6 proxy address but the AF_INET6
   branch `continue`s **before** installing a v6 proxy-neighbor table entry
   (the v6 analogue of `ip -6 neigh add proxy <addr> dev <if>`). Verified
   against `net/ipv6/ndisc.c` (`pndisc_is_router` / `pneigh_lookup`): the
   NDP-proxy reply requires forwarding **AND** `proxy_ndp` **AND** an
   existing v6 pneigh entry. Enabling the sysctl alone is a harmless no-op
   (no over-answer), but IPv6 static-NAT external proxy is **non-functional
   end-to-end** until the v6 pneigh entry is wired.

2. **(LOW) No re-assert after a non-commit link cycle.** `ReconcileProxyARP`
   runs only inside `applyConfigLocked` (a config apply, right after
   `networkd.Apply` resets per-interface sysctls). There is no periodic
   proxy-ARP reconcile. A kernel link DOWN/UP **outside** a config commit —
   an HA RETH member flap or `programRethMAC`'s link-cycle fallback —
   re-defaults `net.ipv4.conf.<if>.proxy_arp` to its parent/default value
   (typically 0), leaving the interface silent until the next operator
   commit.

3. **(LOW-MEDIUM) Over-answer breadth.** With the default `medium_id == 0`,
   `proxy_arp = 1` (the `arp_fwd_proxy` path, `net/ipv4/arp.c`) answers ARP
   for **any** target that routes out a *different* interface — broader than
   Junos `proxy-arp`, which proxies only the listed addresses. On a
   WAN/untrust interface this is a wider ARP-answering posture than intended.
   The review asks whether relying on the per-address `NTF_PROXY` pneigh
   entry alone (the `arp.c:863` branch — forwarding + `RTN_UNICAST` +
   `rt.dst.dev != dev`) could replace the sysctl where the topology allows.

---

## 2. Goals / non-goals

**Goals**

- Item 1: make IPv6 static-NAT / NAT64 external proxy work end-to-end
  (install the v6 pneigh entry), so `proxy-arp { interface … address <v6>; }`
  is functional, not Partial.
- Item 2: keep `proxy_arp`/`proxy_ndp` asserted across non-commit link
  cycles (HA RETH flap, `programRethMAC`) without an operator re-commit.
- Item 3: characterize when the sysctl is strictly required vs when the
  pneigh branch alone suffices, and decide whether Junos-parity narrowing is
  shippable.

**Non-goals**

- No new config grammar. `proxy-arp` already accepts an IPv6 address (the
  compiler stores it in `ProxyARPEntry.Addresses`); we do not add a separate
  `proxy-ndp` stanza. (Item 1 is a runtime wiring gap, not a config gap.)
- No change to the dataplane (userspace-dp / shim). Proxy-ARP/NDP is a
  kernel control-plane responder; the dataplane is uninvolved.
- No change to the GARP-on-add behavior (v6 uses unsolicited NA, out of
  scope — the v6 pneigh install is enough for the responder; an unsolicited
  NA "GARP equivalent" can be a follow-up if a same-L2 cache-poisoning need
  appears, but #2160's IPv4 GARP path is for fresh-takeover and is not
  required to make the responder work).

---

## 3. Current behavior (as-built, verified against source)

### 3.1 The v4 install path (`pkg/dataplane/proxyarp.go`)

`ReconcileProxyARP(cfg, ifaceMap)`:

1. Builds the desired set keyed by `{ifindex, netip.Addr}`. For each
   configured address it parses the CIDR. **IPv6 addresses are detected
   (`addr.Is6() && !addr.Is4In6()`) and `continue`d after only
   `recordFamily(ifindex, unix.AF_INET6)`** (proxyarp.go:163-171) — so an
   IPv6 address is added to `ifindexFamilies` (→ proxy_ndp sysctl) but is
   **never** added to `desired` and **never** gets a neighbor install.
2. Lists existing `NTF_PROXY` neighbors via `netlink.NeighList(idx,
   unix.AF_INET)` — IPv4 only.
3. Adds missing v4 entries via `netlink.NeighSet(&netlink.Neigh{Flags:
   NTF_PROXY, Family: AF_INET, IP: v4})` (proxyarp.go:211-219).
4. Removes stale v4 entries.
5. Resolves each ifindex → procfs name and calls `enableProxyResponders`,
   which writes `proxy_arp` (v4) / `proxy_ndp` (v6) per family present.

So the v6 path today: sysctl ON, pneigh entry ABSENT → kernel never answers
(item 1 confirmed against source).

### 3.2 netlink supports the v6 pneigh install (verified)

`neighHandle` (vishvananda/netlink v1.3.1, `neigh_linux.go`) uses
`neigh.Family` when `> 0`, serializes the IP as `To4()` else `To16()`, and
carries the `Flags` byte (NTF_PROXY). Setting `Family: unix.AF_INET6` + a
v6 `IP` + `Flags: NTF_PROXY` emits exactly the `RTM_NEWNEIGH` that
`ip -6 neigh add proxy <addr> dev <if>` does. No library gap. (`NeighList`
with `unix.AF_INET6` likewise lists v6 pneigh entries for the stale-removal
pass.)

### 3.3 Where the reconcile is invoked (item 2)

- **Only** in `daemon_apply.go:914-946` (step 2.6c of `applyConfigLocked`),
  guarded by `len(cfg.Security.NAT.ProxyARP) > 0`. It builds `ifaceMap`
  inline (resolving RETH→physical via `cfg.RethToPhysical()` +
  `config.LinuxIfName`), runs after `networkd.Apply`, and sends a GARP per
  added entry.
- `networkd.Apply` (`networkctl reconfigure`/reload) resets per-interface
  sysctls to their `.network`/default value — which is why the reconcile
  must run *after* it on every commit. The same reset happens on **any**
  kernel link DOWN/UP, not only `networkctl`.
- `programRethMAC` (`daemon_reth.go:170`) brings a RETH member DOWN→set
  MAC→UP **only** on the live-change fallback (`linkCycled == true`). That
  link cycle clears `proxy_arp` on that member. The post-MAC step today is
  `d.vrrpMgr.ReconcileVIPs()` (daemon_apply.go:877) — VIPs only; **no**
  proxy-ARP re-assert.

### 3.4 Periodic loops available as reassert hooks (item 2)

- `reconcileRGStateLoop` (`daemon_ha.go:461`, 2s ticker + `reconcileNowCh`)
  — **cluster only** (`reconcileRGState` returns early if `d.cluster == nil
  || d.vrrpMgr == nil`). Started only `if d.cluster != nil`
  (daemon_run.go:1098).
- `monitorLinkState` (`daemon_flow.go:316`) — a netlink `LinkSubscribe`
  watcher that already tracks per-ifindex oper up/down, but it is started
  **only when SNMP trap groups are configured**
  (`len(cfg.System.SNMP.TrapGroups) > 0`, daemon_run.go:1046). Not a
  reliable standalone hook.
- `runPeriodicNeighborResolution` (`daemon_run.go:1064`) — started
  **unconditionally** when `!NoDataplane && ActiveConfig != nil`. This is
  the one always-on periodic loop in **both** standalone and cluster modes.

### 3.5 Config / topology (item 3)

`ProxyARPEntry{Interface, Addresses}` is operator-authored
(`set security nat proxy-arp interface <if> address <addr>`). The #2160 case:
a static-NAT *external* address on the **same L2 subnet** as the proxy
interface (the route to that address stays on the ingress device →
`rt.dst.dev == dev`). The kernel pneigh reply branch (`arp.c:863`) requires
`rt.dst.dev != dev`, so it does **not** fire for that case; only the sysctl
(`arp_fwd_proxy`) answers. This is *the* topology #2160 needed.

---

## 4. Root cause

- **Item 1:** the AF_INET6 branch was deliberately scoped to sysctl-only in
  #2160 ("the kernel proxy-NDP table is managed separately") and the table
  install was deferred to this issue. Root cause = missing v6 pneigh
  install, nothing more.
- **Item 2:** the reconcile has exactly one trigger (config apply). The
  reset of `proxy_arp` is an effect of any link DOWN/UP; the trigger set
  does not cover non-commit link cycles. Root cause = trigger coverage gap.
- **Item 3:** two distinct kernel reply paths with different gates. The
  pneigh branch is narrow (per-entry) but topology-restricted
  (`rt.dst.dev != dev`); the sysctl is broad but topology-agnostic. There is
  no per-interface kernel knob to make the broad path answer *only* listed
  addresses (that is `medium_id` group semantics, which is not per-address).
  Root cause = kernel does not offer per-address narrowness on the
  same-subnet path.

---

## 5. Item 1 — v6 proxy-NDP pneigh install (design)

**Recommendation: PLAN-READY — implement. Clear MEDIUM win, low risk.**

Mirror the v4 install in the existing AF_INET6 branch. Concretely:

1. **Desired set is family-aware.** Replace the `desired` value-set keyed by
   `{ifindex, netip.Addr}` (already family-distinguishing because
   `netip.Addr` carries its family) — no struct change needed; just stop
   `continue`ing on v6. Add the v6 address to `desired` and
   `recordFamily(ifindex, AF_INET6)`.

   ```go
   if addr.Is6() && !addr.Is4In6() {
       desired[proxyKey{ifindex, addr}] = struct{}{}
       recordFamily(ifindex, unix.AF_INET6)
       continue
   }
   desired[proxyKey{ifindex, addr}] = struct{}{}
   recordFamily(ifindex, unix.AF_INET)
   ```

   (Both branches now just classify the family for the sysctl; the
   `desired` insert is common — can be hoisted.)

2. **List existing v6 pneigh too.** The existing-collection loop currently
   lists only `unix.AF_INET`. Add a parallel `netlink.NeighList(idx,
   unix.AF_INET6)` pass, building `existing` with the v6 addresses
   (`netip.AddrFromSlice(n.IP.To16())`, skipping anything that `To4()`
   succeeds on so a v4-mapped form is not double-counted). `netip.Addr`
   keys keep v4 and v6 disjoint automatically.

3. **Add/remove with the correct family.** In the add and stale-remove
   loops, derive `Family` from the key: `unix.AF_INET6` if `key.ip.Is6() &&
   !key.ip.Is4In6()`, else `unix.AF_INET`. Build the `netlink.Neigh` with
   `IP: key.ip.AsSlice()` (16 bytes for v6) and that family. NTF_PROXY flag
   is family-agnostic.

4. **GARP-on-add.** Leave the v4 GARP path as-is. For v6, do **not** emit a
   v4 GARP. Either skip the `added` GARP for v6 entries (the responder works
   without it) or — only if a future same-L2 cache-refresh need appears —
   add an unsolicited Neighbor Advertisement. **Recommendation: skip for now**
   (the issue scope is "make it functional"; an unsolicited NA is a separable
   enhancement). Mark v6 `ProxyARPAdded` entries so the caller's
   `cluster.SendGratuitousARP` (v4-only) is not called on a v6 IP — either
   omit v6 from the returned `added` slice, or add a `Family`/`IsV6` field to
   `ProxyARPAdded` and have the caller branch. **Cleanest: add `Family int`
   to `ProxyARPAdded` and skip GARP for AF_INET6** (keeps the return set
   complete for logging/metrics and avoids a silent v4 GARP on a v6 IP — see
   §10 risk R1).

5. **v6 is inherently per-address (no breadth problem).** Unlike v4 — where
   the broad `arp_fwd_proxy` path can answer without any pneigh entry — IPv6
   proxy-NDP is gated on the `pneigh_lookup` itself (`net/ipv6/ndisc.c`,
   per the kernel-verified issue): the kernel answers a v6 NS **only** if a
   matching v6 pneigh entry exists (plus forwarding + `proxy_ndp`). So the v6
   install is the necessary-AND-sufficient piece on the v6 side for each
   listed address, there is **no v6 over-answer breadth** (item 3 is v4-only),
   and item 1 is **monotonic** — it adds a required piece on top of an
   already-enabled `proxy_ndp` sysctl and can only improve the v6 state, never
   regress it. The live v6-NS test (§9) is the ground-truth completeness gate
   before the docs flip Partial→Done.

6. **Symmetry guard for the stale-removal pass.** The stale pass removes any
   `NTF_PROXY` entry on a managed interface not in `desired`. Now that v6 is
   listed, an operator-removed v6 proxy address is correctly torn down. This
   is desirable, but verify the managed-interface set still bounds the scope
   (it does — `managedSet` is built from `cfg.Security.NAT.ProxyARP`
   ifindexes only, so we never touch pneigh entries on unmanaged interfaces).

**Files:** `pkg/dataplane/proxyarp.go` (the install), `pkg/daemon/
daemon_apply.go` (GARP-skip for v6 if a `Family` field is added),
`pkg/dataplane/proxyarp_test.go` (v6 install assertions), docs
(`feature-gaps.md` Proxy NDP row Partial→Done; `phases.md`).

**No commit-time validation change needed** — the compiler already accepts a
v6 address; the only behavioral change is runtime. (Optionally add a schema
note, but not required.)

---

## 6. Item 2 — re-assert after a non-commit link cycle (design)

**Recommendation: PLAN-READY — implement. LOW but cheap and correct.**

The reconcile (`ReconcileProxyARP`) is **idempotent** (it diffs desired vs
existing and the sysctl write is a no-op when already set), so it is safe to
call repeatedly. The work is: (a) make it callable outside the apply path,
and (b) wire the triggers.

### 6.1 Factor a daemon method

Extract the `ifaceMap` construction (daemon_apply.go:916-934) + the
`ReconcileProxyARP` + GARP loop into a `func (d *Daemon)
reconcileProxyARP(cfg *config.Config)` (no-op when
`len(cfg.Security.NAT.ProxyARP) == 0`). The apply path calls it; the new
triggers call it with `d.store.ActiveConfig()`.

### 6.2 Trigger A — post-`programRethMAC` (the HA RETH flap)

In `daemon_apply.go`, the post-MAC block already calls
`d.vrrpMgr.ReconcileVIPs()` after a link cycle (the `needLinkCycleRecovery`
path, ~line 877). Add `d.reconcileProxyARP(cfg)` immediately after the VIP
reconcile in the **same** post-link-cycle block, gated on the same
"a member actually cycled" condition so we only pay the cost when a cycle
happened. This directly covers `programRethMAC`'s DOWN/UP fallback during a
commit. **Note:** the existing 2.6c call later in the same `applyConfig`
already re-runs the reconcile, so a commit-time link cycle is *already*
covered for the commit case — the real gap is a link cycle **outside** a
commit (Trigger B/C). Keep Trigger A only if there is a path where
`programRethMAC` cycles a link *without* a following 2.6c (audit: the
deferred-MAC `ApplyConfig` re-entry at line 905 does re-run 2.6c, so this
may be redundant; mark Trigger A **optional, verify-then-drop**).

### 6.3 Trigger B — periodic always-on reassert (standalone + cluster)

The only always-on periodic loop is `runPeriodicNeighborResolution`
(daemon_run.go:1064). Add a proxy-ARP reassert as one phase of that loop
(guarded by the per-phase goroutine pattern already used there per #1780),
OR add a dedicated low-frequency ticker. **Recommendation: a dedicated
ticker is cleaner** and avoids coupling proxy-ARP to neighbor-resolution
cadence/guards. Run it at a low rate (e.g. 30s — proxy-ARP is not latency
sensitive; a 30s worst-case re-assert after a flap is fine and keeps the
control-socket/netlink load trivial). The loop:

```go
func (d *Daemon) proxyARPReassertLoop(ctx context.Context) {
    t := time.NewTicker(30 * time.Second)
    defer t.Stop()
    for {
        select {
        case <-ctx.Done(): return
        case <-t.C:
            if cfg := d.store.ActiveConfig(); cfg != nil {
                d.reconcileProxyARP(cfg)
            }
        }
    }
}
```

Start it unconditionally when `!NoDataplane` (same gate as the neighbor
loop). The reconcile is a no-op when no proxy entries exist, so the loop is
cheap on configs that don't use proxy-ARP. **This is the load-bearing hook**
— it covers both standalone and cluster, and any non-commit link cycle, with
a bounded worst-case lag.

### 6.4 Trigger C — event-driven on link-up (optional, latency reducer)

To cut the worst-case lag from 30s to ~immediate, subscribe to netlink
link-up the way `monitorLinkState` does, and on an OPER-UP transition of an
interface that carries a proxy entry, call `reconcileProxyARP`. But:
`monitorLinkState` is SNMP-gated, so this needs its own always-on
subscription (or to fold proxy-ARP into a shared link watcher). **Given the
LOW severity, recommend deferring Trigger C** — the 30s periodic (Trigger B)
is sufficient for correctness; the event hook is a latency optimization that
can be a follow-up if a flap window proves operationally painful.

### 6.5 Net recommendation for item 2

Ship **Trigger B (periodic, 30s, always-on)** as the load-bearing fix.
**Default to NOT shipping Trigger A** — the SMR (F4) tightened this: the
commit-time 2.6c reconcile already re-covers a commit-time link cycle, so
Trigger A is presumed dead code unless the /engineer audit (§6.2) finds a
concrete `programRethMAC`-cycles-without-a-following-2.6c path. Defer
Trigger C (event-driven link-up) as a latency optimization. This is the
smallest change that closes the gap.

**Files:** `pkg/daemon/daemon_apply.go` (extract method), `pkg/daemon/
daemon_run.go` (start loop) + a new small file or `daemon_ha.go` for the
loop, tests in `pkg/daemon`.

---

## 7. Item 3 — narrow over-answer to per-address (feasibility)

**Recommendation: PLAN-DEFER (lab characterization required before any
narrowing ships). Do NOT drop the sysctl.**

### 7.1 The two kernel paths and their gates (re-derived)

`net/ipv4/arp.c`, `arp_process`:

- **pneigh branch (`arp.c` ~863):** fires when `IN_DEV_FORWARD(in_dev)` AND
  the target's `addr_type == RTN_UNICAST` AND `rt.dst.dev != dev` (the route
  to the target leaves a **different** device than the ARP arrived on) AND a
  matching `pneigh` (NTF_PROXY) entry exists. Per-address narrow. Does **not**
  consult `proxy_arp`.
- **`arp_fwd_proxy` path:** gated by `IN_DEV_PROXY_ARP(in_dev)` (the
  `proxy_arp` sysctl) with `medium_id == 0`; answers for **any** target that
  routes out a different interface. Broad.

### 7.2 The decisive observation (empirical, not a line-level trace)

The #2160 case is a static-NAT external address on the **same L2 subnet** as
the proxy interface (`rt.dst.dev == dev`). The DEFER verdict does **not**
depend on independently re-tracing the current-mainline `arp.c` branches
(the #2197 filer was kernel-source-verified and cites `arp.c:863`; I treat
those branch facts as given and consistent with the in-tree proxyarp.go
doc-comment). It rests on a stronger, **measured** fact from #2160:

> the per-address `NTF_PROXY` (pneigh) entry was **already installed** in the
> pre-#2160 code, and the same-subnet external address was **not** answered
> until the `proxy_arp` sysctl was turned on.

That is a direct empirical falsification of "pneigh-only answers the
same-subnet case," independent of which kernel branch does the work.

**Therefore:** in the exact topology #2160 fixed, the per-address pneigh
entry alone is **insufficient** — dropping the sysctl to gain Junos
narrowness would re-break #2160. This empirical falsification (not a
mechanism derivation) is the PLAN-DEFER kernel, and its robustness to my
mechanism uncertainty is *precisely why* shipping a speculative narrowing
(3B) on an unverified mechanism is the trap to avoid.

**v6 has no breadth problem.** Per §5.5, IPv6 proxy-NDP is `pneigh_lookup`-
gated (per-address by construction) — there is no v6 analogue of the broad
`arp_fwd_proxy` path, so the over-answer concern is **v4-only**. Item 3 does
not apply to v6 at all.

### 7.3 When pneigh-only *would* suffice

If the proxied external address routes out a **different** interface than
the proxy interface (`rt.dst.dev != dev`), the pneigh branch answers without
the sysctl, and the sysctl's only effect is the unwanted breadth. That is a
legitimate "narrow to pneigh-only" candidate — but it is a *different*
topology than #2160, and detecting it reliably at config-apply time requires
a route lookup for each proxied address against the live RIB (which is racy:
routes change post-commit; FRR may not have converged at apply time).

### 7.4 Options

- **3A (recommended): keep the sysctl, document the breadth, defer
  narrowing.** This is the status quo + a doc note (already present in
  feature-gaps.md / proxyarp.go). Zero risk. The breadth is operator-opted-in
  (they configured proxy-arp on the interface). **Recommended ship: nothing
  code-wise; the breadth note is already in the tree.**
- **3B: per-address route-aware narrowing.** At reconcile time, for each
  proxied address do a `netlink.RouteGet` and, **only if** `rt.dst.dev !=
  proxy-iface AND addr_type == RTN_UNICAST**, skip the sysctl for that
  interface (rely on pneigh). Keep the sysctl when *any* address on the
  interface is same-device. Problems: (i) racy vs RIB convergence; (ii) a
  per-interface sysctl is all-or-nothing — you cannot enable it for one
  address and not another on the same interface, so you would only narrow an
  interface where *every* proxied address is different-device, a narrow
  win; (iii) needs lab proof that pneigh-only actually answers in the
  target deployment (the same-subnet failure shows kernel behavior is
  subtler than the branch reading suggests). **Defer until a lab repro
  exists** that (a) reproduces the over-answer as a real operational problem
  and (b) confirms pneigh-only answers the different-device case.
- **3C (PLAN-KILL sub-option): `medium_id` groups.** The kernel's per-medium
  narrowing (`medium_id != 0`) groups interfaces, not addresses — it does
  not give per-listed-address narrowness. Not a fit. Killed.

### 7.5 Verdict

**PLAN-DEFER.** The over-answer is real but LOW-impact and operator-opted-in;
the only viable code path (3B) is racy, all-or-nothing per interface, and —
critically — must not be allowed to re-break the same-subnet #2160 case.
Ship nothing for item 3 now beyond the existing breadth documentation; revisit
3B only with a lab characterization (a real over-answer incident + a verified
pneigh-only different-device repro). Capture this as a parked follow-up.

---

## 8. Proposed implementation order (for the /engineer pass)

1. **PR-1 (item 1, MEDIUM):** v6 pneigh install in `proxyarp.go` + v6
   existing-list + family-correct add/remove + `ProxyARPAdded.Family` +
   GARP-skip-for-v6 in the caller + v6 unit tests + docs (Proxy NDP row
   Partial→Done). Self-contained, the clear win.
2. **PR-2 (item 2, LOW):** extract `reconcileProxyARP` daemon method +
   periodic reassert loop (Trigger B) started unconditionally + optional
   Trigger A (only if §6.2 audit finds a real gap) + tests. Independent of
   PR-1; can land in either order, but PR-1 first so the periodic loop also
   re-asserts the v6 entries.
3. **Item 3:** no PR — record PLAN-DEFER on the issue with the §7 rationale;
   keep the breadth doc note. Optionally file a parked follow-up issue for
   3B gated on a lab repro.

Sequencing rationale: PR-1 and PR-2 touch disjoint files
(`pkg/dataplane/proxyarp.go` vs `pkg/daemon/*`) except the shared
`ProxyARPAdded` type / caller GARP loop — do PR-1 first to settle that type,
then PR-2 reuses the extracted method.

---

## 9. Test / validation strategy

**Unit (both PRs, `go test ./pkg/dataplane/... ./pkg/daemon/...`):**

- Item 1: extend `proxyarp_test.go` — a v6 proxy entry must (a) record
  AF_INET6 in `ifaceFamilies` (already tested via `enableProxyResponders`)
  AND (b) produce a v6 `NTF_PROXY` neighbor install. Add a seam over the
  neighbor install (mirror `proxyARPSysctlSeam`) OR drive the loopback
  `TestReconcileProxyARP_EnablesSysctl` pattern with a `::1`-style v6 addr
  and assert a v6 `NeighList` entry (privileged-gated, `t.Skipf` on EPERM).
  Assert the v4 GARP is **not** called for a v6 added entry.
- Item 1 (SMR F1): a `::ffff:10.0.0.1` v4-mapped-literal proxy address MUST
  classify as **AF_INET** (the v4 desired/install path), never a v6
  `NeighSet` — explicit test.
- Item 2 (SMR F6): the extracted `reconcileProxyARP` must resolve a
  RETH-named proxy interface to the **physical** member ifindex (via
  `cfg.RethToPhysical()` + `config.LinuxIfName`) — assert the extracted
  method builds the identical `ifaceMap` the apply path did (regression
  guard against dropping the RETH resolution in the extraction).
- Item 2: a test that calls the extracted `reconcileProxyARP` twice and
  asserts idempotency (no duplicate install, sysctl re-written), and a test
  that the periodic loop calls the reconcile (inject a fake reconcile via a
  package seam / count invocations).

**Live (loss userspace cluster, the smoke env):**

- Item 1: configure `set security nat proxy-arp interface <reth.vlan>
  address <v6-external>/128`, commit, then from a host on the same L2 send
  an NDP solicitation for the external v6 and confirm the firewall answers
  (`tcpdump -i <if> icmp6 && ip -6 neigh show proxy`). Confirm v6 static-NAT
  to that external address now completes end-to-end (the #2160 v6 analogue).
- Item 2: after a commit, force a RETH member link cycle (`ip link set <if>
  down; up` or trigger a `programRethMAC` MAC change) **without** a commit;
  confirm `proxy_arp` returns to 1 within the periodic window (≤30s) and the
  proxied address is answered again. Compare against pre-fix (stays 0 until a
  commit).
- **Mandatory HA gate:** item 2 touches a daemon periodic loop + the
  post-`programRethMAC` path → run `make test-failover` (CLAUDE.md: any
  change touching cluster/VRRP/failover MUST pass). PR-1 is control-plane-only
  but a failover run is cheap insurance.

**Regression:** `go vet ./...`, full `make test`.

---

## 10. Blast radius

- **Item 1:** `pkg/dataplane/proxyarp.go` (v6 install) + the one caller in
  `daemon_apply.go` (GARP skip for v6). The stale-removal pass now also lists
  v6 pneigh on managed interfaces — bounded to interfaces named in
  `proxy-arp` config, so no risk to unrelated v6 neighbors. No dataplane, no
  config grammar, no gRPC/CLI surface.
- **Item 2:** a new always-on goroutine (one 30s ticker) + an extracted
  method. The reconcile is already idempotent and best-effort (never fatal),
  so a periodic re-run cannot regress a steady config. Touches the daemon
  run-loop wiring → exercise `make test-failover`.
- **Item 3:** none (no code).

---

## 11. Risks & mitigations

- **R1 — v4 GARP fired on a v6 IP.** If the v6 install is added to the
  returned `added` slice without a family tag, the caller's
  `cluster.SendGratuitousARP(a.Iface, a.IP, 1)` would be handed a v6 IP.
  *Mitigation:* add `Family int` to `ProxyARPAdded`, skip GARP for
  AF_INET6 (chosen in §5.4). Tested.
- **R2 — v6/v4-mapped double count.** `netip.AddrFromSlice(n.IP.To16())`
  on a v4 entry would mis-key. *Mitigation:* in the v6 existing-list pass,
  skip any neigh whose `IP.To4() != nil` (v4-mapped); rely on the separate
  v4 pass for those. The two passes use distinct families to `NeighList` so
  the kernel already separates them; the `netip.Addr` key keeps them disjoint.
- **R3 — periodic reassert vs DHCP/networkd ownership.** The reconcile writes
  `proxy_arp`/`proxy_ndp` per interface that has a proxy entry — it does not
  touch addresses or routes, so it cannot fight DHCP/networkd address
  reconciliation. *Mitigation:* scope unchanged (sysctl + pneigh only);
  no interaction.
- **R4 — periodic loop control-socket contention.** CLAUDE.md warns about
  >1/s control-socket callers. The reassert is netlink + procfs only (no
  helper control socket) at 1/30s — well under any contention threshold.
  *Mitigation:* keep it off the control socket (it is); 30s cadence.
- **R5 — item 3 narrowing re-breaks #2160.** The strongest reason for
  PLAN-DEFER. *Mitigation:* ship no narrowing without a lab repro proving
  pneigh-only answers the target topology AND that the topology is
  different-device; keep the sysctl as the default.
- **R6 — stale v6 pneigh removal is now active.** Once v6 is listed, an
  operator removing a v6 proxy address triggers a `NeighDel`. *Mitigation:*
  this is the desired symmetry with v4; bounded to managed interfaces;
  best-effort (logged, non-fatal). Covered by the idempotency test.

---

## Appendix — source anchors

- `pkg/dataplane/proxyarp.go:163-174` — v6 `continue` (item 1 gap).
- `pkg/dataplane/proxyarp.go:184-203` — v4-only existing-list (item 1).
- `pkg/dataplane/proxyarp.go:205-249` — v4-only add/remove (item 1).
- `pkg/daemon/daemon_apply.go:914-946` — sole reconcile call site (item 2).
- `pkg/daemon/daemon_apply.go:861-908` — post-`programRethMAC` /
  `ReconcileVIPs` block (item 2 Trigger A candidate).
- `pkg/daemon/daemon_reth.go:170-202` — `programRethMAC` link cycle (item 2).
- `pkg/daemon/daemon_ha.go:461-478` — `reconcileRGStateLoop` (cluster-only).
- `pkg/daemon/daemon_run.go:1059-1075` — always-on neighbor loop (item 2
  Trigger B home).
- `pkg/daemon/daemon_flow.go:316-369` — `monitorLinkState` (SNMP-gated; item
  2 Trigger C reference).
- netlink `neigh_linux.go` `neighHandle` — `Family`-aware, To4/To16 — v6
  pneigh install supported (item 1 feasibility).
- `docs/feature-gaps.md:173-174` — Proxy ARP Done / Proxy NDP Partial rows.
