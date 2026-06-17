Reading additional input from stdin...
OpenAI Codex v0.139.0
--------
workdir: /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
model: gpt-5.5
provider: openai
approval: never
sandbox: read-only
reasoning effort: xhigh
reasoning summaries: none
session id: 019ed4b5-253b-79c3-9a87-7e50054b5dee
--------
user
This is r3 of the plan at docs/research/1919-wg-addr-route-prune/plan.md. In your r2 review you returned PLAN-NEEDS-MAJOR with exactly ONE remaining finding: the AddrList-error fallback in pruneAppliedAddrsLocked returned only the 'applied' set, so when applied is empty AND AddrList transiently fails with a real stale address present, the helper returned empty -> caller dropped tracking -> leak with no retry.

r3 fixes this: pruneAppliedAddrsLocked now returns (failed map[string]bool, retry bool). retry is true whenever the device could NOT be proven clean — any AddrDel failed OR AddrList itself failed. On AddrList failure it returns (applied, true) unconditionally. The caller retains the name in nextWG when retry is true (NOT keyed on len(failed)>0 anymore). A new test §6.8 TestWireguardRemovalAddrListFailureRetained covers empty-applied + AddrList-failure.

Re-read the r3 §5 helper + caller and confirm your single r2 finding is resolved. Check for any NEW issue introduced by the (failed, retry) refactor. If clean, return PLAN-READY. Output one verdict: PLAN-READY / PLAN-READY-WITH-NITS / PLAN-NEEDS-MAJOR / PLAN-KILL with file:line for any remaining finding. Do not invent blockers without a source-grounded counterexample.
codex
I’ll re-read the r3 helper/caller text and the new test section, then I’ll check the refactor for a source-grounded counterexample rather than re-litigating the whole plan.
exec
/bin/bash -lc "rg -n \"pruneAppliedAddrsLocked|nextWG|AddrList|6\\.8|TestWireguardRemovalAddrListFailureRetained|retry\" docs/research/1919-wg-addr-route-prune/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
6:  AddrList-error fallback; fixed. r1 had 3 converged MAJORs, all resolved
208:       `pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])`
213:       `(failed, retry)`** — the all-family failed-`AddrDel` set, plus a
214:       `retry` bool that is true whenever the device could not be proven
215:       clean (any `AddrDel` failed, OR `AddrList` itself failed). **Keep
217:     - If `retry` is **true**: retain `t.appliedAddrs[name] = failed`
218:       (or the prior set on an `AddrList` failure) and `nextWG[name] =
219:       true` (retry next apply — mirrors GRE removal-retry at :194-198).
220:     - If `retry` is **false** (proven clean): `delete(t.appliedAddrs,
221:       name)` and DROP `name` from `nextWG`.
226:       RETAIN `nextWG[name] = true` and keep `appliedAddrs[name]` so the
231:3. After the per-tunnel apply loop, set `t.wgConfigured = nextWG`
232:   (= `wgDesired` ∪ retained-for-retry names).
234:#### r2 design note — why a dedicated `pruneAppliedAddrsLocked`, NOT `reconcileLinkAddrsLocked(…, nil, …)`
237:inferring "AddrDel failed, retry" from `len(remaining)>0` of
241:address returns an **empty** set, so the retry signal never fires and the
252:  `pruneAppliedAddrsLocked(link, name, applied) (failed map[string]bool)`
254:  1. `AddrList`s the device,
264:This makes the retry signal correct **by construction** for all families
267:**Pros**: symmetric with the existing `ownedNames` retry pattern; reuses
295:narrowly-scoped state map with the same retry discipline as the existing
357:// retry). NEVER feeds the LinkDel removal loop — WG links persist
365:r3 fix (Codex r2 MAJOR): the helper returns `(failed, retry)` where
366:`retry` is true whenever the prune could NOT prove the device is clean —
367:either an `AddrDel` failed OR `AddrList` itself failed (cannot enumerate
369:caller retains tracking on `retry`, NOT on `len(failed)>0` — decoupling
372:`AddrList` failure → r2 returned empty → caller dropped → leak).
375:// pruneAppliedAddrsLocked deletes the addresses this manager owns from a
379:// reconcileLinkAddrsLocked). Returns (failed, retry):
383://   - retry:  true if the device could not be proven clean this pass —
384://     any AddrDel failed OR AddrList itself failed. The caller retains
385://     the name in wgConfigured when retry is true.
387:func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) (map[string]bool, bool) {
388:    list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
392:        // next pass) and signal retry unconditionally — even if applied
394:        // address must still retry).
427:nextWG := map[string]bool{}
428:for n := range wgDesired { nextWG[n] = true }
436:            // transient lookup error: retain + retry (r1 Codex/AGY MAJOR)
437:            nextWG[name] = true
441:    failed, retry := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
442:    if retry {
443:        t.appliedAddrs[name] = failed // = old applied if AddrList failed
444:        nextWG[name] = true           // could not prove clean → retry
452:t.wgConfigured = nextWG
455:Note: `nextWG` starts as `wgDesired`; the per-tunnel loop already
459:`nextWG` → next `Apply` is a no-op for it (idempotent ✔). On AddrDel/
460:transient-lookup failure the name is retained in `nextWG` and retried.
471:contains the removed name (we set `t.wgConfigured = nextWG` which only
472:carries retained-for-retry names). A clean prune drops the name entirely
474:failed-AddrDel prune keeps it in `nextWG` → retried until clean. ✔
493:   (`172.16.0.1/30` — r1 review: the retry MUST be proven for the
508:8. **`TestWireguardRemovalAddrListFailureRetained`** (Codex r2 MAJOR):
509:   on removal, fake `AddrList` returns an error AND `appliedAddrs[name]`
510:   is empty (the edge case) → assert name RETAINED in tracking (retry),
511:   no panic; a subsequent Apply where AddrList succeeds prunes the
512:   address. Proves the `(failed, retry)` decoupling.
529:> r2 status: the three r1 MAJOR/MED findings (broken retry signal,
568:- **R3 — retry storms on persistent AddrDel failure**: bounded by the
569:  same retain-and-retry pattern GRE removal uses; each Apply does at

codex
The grep confirms r3 explicitly changed the contract to `(failed, retry)` and added the empty-applied `AddrList` failure test. I’m reading the surrounding pseudo-code now to make sure the caller’s state updates match that contract.
exec
/bin/bash -lc "sed -n '190,470p' docs/research/1919-wg-addr-route-prune/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
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
   - look up the link (`LinkByName`):
     - On **success**: call the **new dedicated prune helper**
       `pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])`
       (see design note below). It deletes every present non-link-
       local address (matching the steady-state reconcile's
       non-link-local semantics) plus configured/applied link-locals,
       honoring the same autoconf-fe80 gate, and **returns
       `(failed, retry)`** — the all-family failed-`AddrDel` set, plus a
       `retry` bool that is true whenever the device could not be proven
       clean (any `AddrDel` failed, OR `AddrList` itself failed). **Keep
       the link** — never `LinkDel` (#1432 invariant).
     - If `retry` is **true**: retain `t.appliedAddrs[name] = failed`
       (or the prior set on an `AddrList` failure) and `nextWG[name] =
       true` (retry next apply — mirrors GRE removal-retry at :194-198).
     - If `retry` is **false** (proven clean): `delete(t.appliedAddrs,
       name)` and DROP `name` from `nextWG`.
     - On **`LinkByName` error**: gate on `isLinkNotFound(err)`
       (`pkg/routing/vrf.go:151`). If **not-found** (device genuinely
       gone via manual `ip link del`): `delete(t.appliedAddrs, name)`
       and drop. If a **transient** error (EBUSY/netlink/timeout):
       RETAIN `nextWG[name] = true` and keep `appliedAddrs[name]` so the
       next apply retries — do NOT drop tracking on a transient lookup
       failure (r1 Codex/AGY MAJOR: dropping would forget a still-leaked
       address forever).
   - VRF residual: left as-is (see §4a A1).
3. After the per-tunnel apply loop, set `t.wgConfigured = nextWG`
   (= `wgDesired` ∪ retained-for-retry names).

#### r2 design note — why a dedicated `pruneAppliedAddrsLocked`, NOT `reconcileLinkAddrsLocked(…, nil, …)`

r1 review (all three reviewers, MAJOR) proved the original idea —
inferring "AddrDel failed, retry" from `len(remaining)>0` of
`reconcileLinkAddrsLocked` — is **broken**: that function only records a
failed delete into its returned `newApplied` when the address is
**link-local** (`tunnel.go:618`); a failed `AddrDel` of a regular v4/v6
address returns an **empty** set, so the retry signal never fires and the
leaked address is silently dropped from tracking and never retried.

Two ways to fix; r2 chooses (b):

- **(a)** change `reconcileLinkAddrsLocked` to also record non-link-local
  failed deletes — REJECTED: that function's return contract is consumed
  by the GRE/anchor/still-configured-WG callers and is carefully
  specified per #1884/#1905; widening its semantics risks rippling into
  those paths.
- **(b CHOSEN)** add a small, removal-only helper
  `pruneAppliedAddrsLocked(link, name, applied) (failed map[string]bool)`
  that:
  1. `AddrList`s the device,
  2. for each present address: skip autoconf/foreign link-local
     (`a.IP.IsLinkLocalUnicast() && (applied==nil || !applied[key])` —
     identical gate to `reconcileLinkAddrsLocked:611`), otherwise
     `AddrDel`,
  3. on `AddrDel` failure record `failed[key]=true` for **every** family
     (the fix — not just link-local),
  4. returns `failed`.
  `reconcileLinkAddrsLocked` is left **untouched** (frozen contract).

This makes the retry signal correct **by construction** for all families
and keeps the steady-state reconcile contract stable.

**Pros**: symmetric with the existing `ownedNames` retry pattern; reuses
`appliedAddrs` + the link-local gate; idempotent; link preserved; the new
helper is ~15 lines and isolates removal-prune failure tracking from the
steady-state reconcile contract.

**Cons**: one new small helper + one new reconcile map to keep in sync
across `clearLocked` (reset) and `ensureReconcileStateLocked` (lazy init).

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

### 4b. Prune scope — what addresses get deleted (r2 correction)

r1 review (all three) flagged that the plan said "manager-applied
addresses only". That is **wrong** and now corrected: the removal prune
deletes **every present non-link-local address** on the device
(`AddrDel` for all of them), and for **link-local** it deletes only the
configured/applied ones (autoconf/foreign fe80 gated out). The
`appliedAddrs[name]` set gates link-local deletion ONLY — it does NOT
restrict non-link-local deletion. This is **identical** to the
steady-state reconcile (`reconcileLinkAddrsLocked` deletes all present-
but-unwanted non-link-local addresses regardless of `applied`), so the
removal prune is consistent with how the manager already treats the
device while configured. Consequence to STATE in the PR + docs: if an
operator manually `ip addr add`'d a non-fe80 address to a configured wgN,
that address would also be removed on tunnel-removal prune — exactly as
it would be removed on any steady-state reconcile today. This is intended
"the manager owns the device's non-link-local address set" behavior, not
a new hazard. (If reviewers want strict applied-only deletion, the helper
can intersect with `applied`, but that would DIVERGE from steady-state
semantics and risk leaving a manager-applied address behind if it fell
out of `applied` tracking — not recommended.)

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

**r2 nit (AGY)**: a RELATED pre-existing gap to call out (NOT introduced
by this PR, NOT fixed by it): a WG tunnel that STAYS configured but has
its `routing-instance` removed also never unbinds (`applyWireguardTunLocked`
binds at `:883-888` but has no unbind-on-empty path). This is the same
root cause (WG bypasses `reconcileVRFClaimLocked`/`appliedRI`) and is in
scope for the A2 / #1434 VRF follow-up, not this address-leak fix.
Document both VRF residuals together so the follow-up has a clear target.

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

New helper (removal-only; leaves `reconcileLinkAddrsLocked` untouched).
r3 fix (Codex r2 MAJOR): the helper returns `(failed, retry)` where
`retry` is true whenever the prune could NOT prove the device is clean —
either an `AddrDel` failed OR `AddrList` itself failed (cannot enumerate
⇒ cannot conclude clean, regardless of whether `applied` is empty). The
caller retains tracking on `retry`, NOT on `len(failed)>0` — decoupling
the "enumerate failed" case from the "delete failed" set fixes the r2
counterexample (stale non-link-local present, `applied` empty, transient
`AddrList` failure → r2 returned empty → caller dropped → leak).

```go
// pruneAppliedAddrsLocked deletes the addresses this manager owns from a
// link being pruned (WG removal), keeping the link. Deletes every
// present non-link-local address, plus configured/applied link-locals;
// the kernel autoconf/foreign fe80 is never touched (same gate as
// reconcileLinkAddrsLocked). Returns (failed, retry):
//   - failed: addresses whose AddrDel FAILED, across ALL families
//     (carried forward as the new appliedAddrs[name] for the link-local
//     gate on the next attempt).
//   - retry:  true if the device could not be proven clean this pass —
//     any AddrDel failed OR AddrList itself failed. The caller retains
//     the name in wgConfigured when retry is true.
// Caller MUST hold mu.
func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) (map[string]bool, bool) {
    list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
    if err != nil {
        // Cannot enumerate ⇒ cannot conclude the device is clean. Keep
        // the existing tracked set (so the link-local gate stays correct
        // next pass) and signal retry unconditionally — even if applied
        // is empty (Codex r2 MAJOR: an empty applied with a real stale
        // address must still retry).
        slog.Warn("failed to list wireguard tun addresses for prune",
            "name", name, "err", err)
        return applied, true
    }
    failed := map[string]bool{}
    for i := range list {
        a := list[i]
        if a.IP == nil { continue } // unclassifiable: never delete
        key := a.IPNet.String()
        if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
            continue // kernel autoconf / foreign link-local: never delete
        }
        if delErr := t.ops.AddrDel(link, &a); delErr != nil {
            slog.Warn("failed to prune wireguard tun address",
                "name", name, "addr", key, "err", delErr)
            failed[key] = true // ALL families (the r1-MAJOR fix)
        } else {
            slog.Info("pruned wireguard tun address (removed from config)",
                "name", name, "addr", key)
        }
    }
    return failed, len(failed) > 0
}
```

`Apply` (prune phase + state, GRE loop & per-tunnel loop unchanged):
```go
wgDesired := map[string]bool{}
for _, tc := range tunnels {
    if tc.Mode == "wireguard" { wgDesired[tc.Name] = true }
}
oldWG := t.wgConfigured
nextWG := map[string]bool{}
for n := range wgDesired { nextWG[n] = true }
for name := range oldWG {
    if wgDesired[name] { continue }
    link, err := t.ops.LinkByName(name)
    if err != nil {
        if isLinkNotFound(err) {
            delete(t.appliedAddrs, name) // device genuinely gone; drop
        } else {
            // transient lookup error: retain + retry (r1 Codex/AGY MAJOR)
            nextWG[name] = true
        }
        continue
    }
    failed, retry := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
    if retry {
        t.appliedAddrs[name] = failed // = old applied if AddrList failed
        nextWG[name] = true           // could not prove clean → retry
        continue
    }
    delete(t.appliedAddrs, name) // proven clean; drop tracking
}
// ... existing GRE removal loop unchanged ...
// ... per-tunnel apply loop unchanged (still-configured WG re-tracked
//     via applyWireguardTunLocked → reconcileLinkAddrsLocked at :880) ...
t.wgConfigured = nextWG
```

Note: `nextWG` starts as `wgDesired`; the per-tunnel loop already
re-applies still-configured WG (no change there). The prune loop runs
against `oldWG` so it sees exactly the names that disappeared. On a clean
prune the name is in neither `wgDesired` nor retained → dropped from
`nextWG` → next `Apply` is a no-op for it (idempotent ✔). On AddrDel/
transient-lookup failure the name is retained in `nextWG` and retried.

`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
ClearTunnels still does not delete WG links (unchanged) — but on a full
clear the operator intent is teardown; whether ClearTunnels should now
also flush WG addresses is a **secondary decision** (§7 open question).
Default: leave ClearTunnels behavior unchanged (it never managed WG
addresses before); only reset the tracking map so a post-Clear Apply
re-adopts cleanly.

Idempotency proof: after the prune commit, `oldWG` (next round) no longer

exec
/bin/bash -lc "sed -n '470,520p' docs/research/1919-wg-addr-route-prune/plan.md" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
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
   error on first removal Apply for a **non-link-local** address
   (`172.16.0.1/30` — r1 review: the retry MUST be proven for the
   regular-address case, not only fe80) → assert name retained in
   tracking, second removal Apply retries AddrDel, third (success) drops
   it. This test is the direct regression guard for the r1 MAJOR.
5. **`TestWireguardRemovalDeviceNotFoundDropsTracking`**: LinkByName
   returns a not-found error on removal → assert no panic, tracking
   dropped, no-op next apply.
6. **`TestWireguardRemovalTransientLookupRetained`**: LinkByName returns
   a NON-not-found (transient) error on removal → assert name RETAINED
   in tracking and a subsequent Apply (link now resolvable) prunes the
   address. (Direct guard for r1 Codex/AGY MAJOR #2.) Requires the fake
   `linkOps` to support an injectable non-not-found LinkByName error.
7. **`TestWireguardReAddAfterRemovalTracksFresh`**: add → remove (prune)
   → re-add same name with a NEW address → assert new addr applied and
   old addr not re-leaked (appliedAddrs correctly reset/repopulated).
8. **`TestWireguardRemovalAddrListFailureRetained`** (Codex r2 MAJOR):
   on removal, fake `AddrList` returns an error AND `appliedAddrs[name]`
   is empty (the edge case) → assert name RETAINED in tracking (retry),
   no panic; a subsequent Apply where AddrList succeeds prunes the
   address. Proves the `(failed, retry)` decoupling.
9. **`TestWireguardRemovedWhileDaemonDownNotPruned`** (R5 boundary): on a
   FRESH manager (empty `wgConfigured`) with a wgN carrying addresses
   present in the kernel + an empty tunnel list → assert NO AddrDel
   (the manager only prunes what it tracked applying; restart-time
   removal is #1434 scope). Encodes the deferral.
10. **Regression guard**: existing `TestWireguardConfiguredLinkLocalRemoved`
   and friends must still pass (still-configured reconcile unchanged;
   `reconcileLinkAddrsLocked` is NOT modified).

exec
/bin/bash -lc "sed -n '350,455p' docs/research/1919-wg-addr-route-prune/plan.md | nl -ba -v 350" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   350	
   351	## 5. Detailed implementation sketch (Path A)
   352	
   353	State (add to `tunnelManager`):
   354	```go
   355	// wgConfigured: WG tunnel names configured at the LAST Apply (plus
   356	// names whose address prune left residual tracked addrs, retained for
   357	// retry). NEVER feeds the LinkDel removal loop — WG links persist
   358	// (#1432 S2a). Drives the WG address-prune-on-removal diff (#1919).
   359	wgConfigured map[string]bool
   360	```
   361	
   362	`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
   363	
   364	New helper (removal-only; leaves `reconcileLinkAddrsLocked` untouched).
   365	r3 fix (Codex r2 MAJOR): the helper returns `(failed, retry)` where
   366	`retry` is true whenever the prune could NOT prove the device is clean —
   367	either an `AddrDel` failed OR `AddrList` itself failed (cannot enumerate
   368	⇒ cannot conclude clean, regardless of whether `applied` is empty). The
   369	caller retains tracking on `retry`, NOT on `len(failed)>0` — decoupling
   370	the "enumerate failed" case from the "delete failed" set fixes the r2
   371	counterexample (stale non-link-local present, `applied` empty, transient
   372	`AddrList` failure → r2 returned empty → caller dropped → leak).
   373	
   374	```go
   375	// pruneAppliedAddrsLocked deletes the addresses this manager owns from a
   376	// link being pruned (WG removal), keeping the link. Deletes every
   377	// present non-link-local address, plus configured/applied link-locals;
   378	// the kernel autoconf/foreign fe80 is never touched (same gate as
   379	// reconcileLinkAddrsLocked). Returns (failed, retry):
   380	//   - failed: addresses whose AddrDel FAILED, across ALL families
   381	//     (carried forward as the new appliedAddrs[name] for the link-local
   382	//     gate on the next attempt).
   383	//   - retry:  true if the device could not be proven clean this pass —
   384	//     any AddrDel failed OR AddrList itself failed. The caller retains
   385	//     the name in wgConfigured when retry is true.
   386	// Caller MUST hold mu.
   387	func (t *tunnelManager) pruneAppliedAddrsLocked(link netlink.Link, name string, applied map[string]bool) (map[string]bool, bool) {
   388	    list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
   389	    if err != nil {
   390	        // Cannot enumerate ⇒ cannot conclude the device is clean. Keep
   391	        // the existing tracked set (so the link-local gate stays correct
   392	        // next pass) and signal retry unconditionally — even if applied
   393	        // is empty (Codex r2 MAJOR: an empty applied with a real stale
   394	        // address must still retry).
   395	        slog.Warn("failed to list wireguard tun addresses for prune",
   396	            "name", name, "err", err)
   397	        return applied, true
   398	    }
   399	    failed := map[string]bool{}
   400	    for i := range list {
   401	        a := list[i]
   402	        if a.IP == nil { continue } // unclassifiable: never delete
   403	        key := a.IPNet.String()
   404	        if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
   405	            continue // kernel autoconf / foreign link-local: never delete
   406	        }
   407	        if delErr := t.ops.AddrDel(link, &a); delErr != nil {
   408	            slog.Warn("failed to prune wireguard tun address",
   409	                "name", name, "addr", key, "err", delErr)
   410	            failed[key] = true // ALL families (the r1-MAJOR fix)
   411	        } else {
   412	            slog.Info("pruned wireguard tun address (removed from config)",
   413	                "name", name, "addr", key)
   414	        }
   415	    }
   416	    return failed, len(failed) > 0
   417	}
   418	```
   419	
   420	`Apply` (prune phase + state, GRE loop & per-tunnel loop unchanged):
   421	```go
   422	wgDesired := map[string]bool{}
   423	for _, tc := range tunnels {
   424	    if tc.Mode == "wireguard" { wgDesired[tc.Name] = true }
   425	}
   426	oldWG := t.wgConfigured
   427	nextWG := map[string]bool{}
   428	for n := range wgDesired { nextWG[n] = true }
   429	for name := range oldWG {
   430	    if wgDesired[name] { continue }
   431	    link, err := t.ops.LinkByName(name)
   432	    if err != nil {
   433	        if isLinkNotFound(err) {
   434	            delete(t.appliedAddrs, name) // device genuinely gone; drop
   435	        } else {
   436	            // transient lookup error: retain + retry (r1 Codex/AGY MAJOR)
   437	            nextWG[name] = true
   438	        }
   439	        continue
   440	    }
   441	    failed, retry := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
   442	    if retry {
   443	        t.appliedAddrs[name] = failed // = old applied if AddrList failed
   444	        nextWG[name] = true           // could not prove clean → retry
   445	        continue
   446	    }
   447	    delete(t.appliedAddrs, name) // proven clean; drop tracking
   448	}
   449	// ... existing GRE removal loop unchanged ...
   450	// ... per-tunnel apply loop unchanged (still-configured WG re-tracked
   451	//     via applyWireguardTunLocked → reconcileLinkAddrsLocked at :880) ...
   452	t.wgConfigured = nextWG
   453	```
   454	
   455	Note: `nextWG` starts as `wgDesired`; the per-tunnel loop already

codex
The caller is now keyed on `retry` at lines 441-445, and the `AddrList` error path returns `applied, true` at lines 388-397. I’m doing one pass against the existing reconcile semantics so I don’t miss a subtle regression from carrying `failed` back into `appliedAddrs`.
exec
/bin/bash -lc "rg -n \"func \\(t \\*tunnelManager\\).*reconcileLinkAddrsLocked|appliedAddrs|applyWireguardTunLocked|AddrList\\(\" -S ." in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
./pkg/ra/sender.go:376:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./pkg/ra/sender.go:407:		addrs, _ = netlink.AddrList(link, netlink.FAMILY_V6)
./pkg/routing/README.md:105:  deleted only if recorded in `appliedAddrs` (a configured fe80 we
./pkg/dataplane/compiler.go:641:func resolveAddrList(dp DataPlane, names []string, result *CompileResult) (uint32, error) {
./pkg/dataplane/compiler.go:809:			srcID, err := resolveAddrList(dp, pol.Match.SourceAddresses, result)
./pkg/dataplane/compiler.go:816:			dstID, err := resolveAddrList(dp, pol.Match.DestinationAddresses, result)
./pkg/dataplane/compiler.go:941:			srcID, err := resolveAddrList(dp, pol.Match.SourceAddresses, result)
./pkg/dataplane/compiler.go:947:			dstID, err := resolveAddrList(dp, pol.Match.DestinationAddresses, result)
./pkg/routing/iface_reuse_test.go:160:func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
./pkg/routing/tunnel_keepalive_test.go:92:func (o *kaOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
./pkg/routing/tunnel.go:33:	AddrList(netlink.Link, int) ([]netlink.Addr, error)
./pkg/routing/tunnel.go:177:	// appliedAddrs: per tunnel, the address set this manager itself
./pkg/routing/tunnel.go:182:	appliedAddrs map[string]map[string]bool
./pkg/routing/tunnel.go:200:	if t.appliedAddrs == nil {
./pkg/routing/tunnel.go:201:		t.appliedAddrs = map[string]map[string]bool{}
./pkg/routing/tunnel.go:291:		delete(t.appliedAddrs, name)
./pkg/routing/tunnel.go:300:		// its addresses + FRR routes every commit. applyWireguardTunLocked
./pkg/routing/tunnel.go:303:			if err := t.applyWireguardTunLocked(tc); err != nil {
./pkg/routing/tunnel.go:705:	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./pkg/routing/tunnel.go:706:		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], kind)
./pkg/routing/tunnel.go:724:func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./pkg/routing/tunnel.go:737:	if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./pkg/routing/tunnel.go:924:// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
./pkg/routing/tunnel.go:938:func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
./pkg/routing/tunnel.go:1017:	// see above), its appliedAddrs entry is retained with it so a later
./pkg/routing/tunnel.go:1020:	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./pkg/routing/tunnel.go:1021:		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./pkg/routing/tunnel.go:1392:	t.appliedAddrs = nil
./pkg/routing/tunnel.go:1437:		addrs, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./pkg/routing/tunnel_reconcile_test.go:300:	// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./pkg/routing/tunnel_reconcile_test.go:342:		t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./pkg/routing/tunnel_reconcile_test.go:430:		t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./pkg/cluster/reth.go:89:			addrs, err := rc.nlHandle.AddrList(link, netlink.FAMILY_ALL)
./pkg/cli/cli_show_interfaces.go:484:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/cli/cli_show_interfaces.go:958:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/grpcapi/server_show_interfaces_text.go:129:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/grpcapi/server_show_interfaces_text.go:218:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:69:    35	`applyWireguardTunLocked` (`tunnel.go:880`), which runs once per **still-
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:76:    42	        if err := t.applyWireguardTunLocked(tc); err != nil { ... }
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:86:    52	- `tc` for it is **absent** from `tunnels`, so `applyWireguardTunLocked`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:168:   134	| `pkg/routing/tunnel.go:188-204` removal loop | deletes non-WG tunnels gone from config; `delete(appliedAddrs,name)` |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:169:   135	| `pkg/routing/tunnel.go:208-230` per-tunnel loop | runs `applyWireguardTunLocked` ONLY for still-configured WG |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:170:   136	| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:172:   138	| `pkg/routing/tunnel.go:104-134` `tunnelManager` fields | `ownedNames`, `appliedAddrs[name]`, `appliedRI[name]` |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:191:   157	  (`applyWireguardTunLocked` never calls `startKeepalive`). So the #1918
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:203:   169	   GRE/IPIP-style tunnels (via `delete(appliedAddrs,name)` + `LinkDel`)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:206:   172	   `applyWireguardTunLocked`, which is driven by the **current config
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:215:   181	The `appliedAddrs[name]` map is the key asset already in place: it
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:219:   185	appliedAddrs[name], …)` already does correctly (delete present-and-not-
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:241:   207	       `pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:249:   215	       `t.appliedAddrs[name] = failedSet` and `nextWG[name] = true`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:251:   217	     - If the failed-set is empty (clean prune): `delete(t.appliedAddrs,
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:255:   221	       gone via manual `ip link del`): `delete(t.appliedAddrs, name)`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:257:   223	       RETAIN `nextWG[name] = true` and keep `appliedAddrs[name]` so the
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:371:./pkg/ra/sender.go:376:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:375:./pkg/ra/sender.go:407:		addrs, _ = netlink.AddrList(link, netlink.FAMILY_V6)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:388:./docs/userspace-xdp-pass-bootstrap-and-ipv6.md:61:**Fix:** `syncLocalAddressMapsLocked()` in `manager.go` now enumerates ALL kernel addresses via `netlink.AddrList(nil, family)`, including dynamically added VIPs. This runs periodically in the status update loop.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:494:./pkg/dataplane/compiler.go:641:func resolveAddrList(dp DataPlane, names []string, result *CompileResult) (uint32, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:495:./pkg/dataplane/compiler.go:809:			srcID, err := resolveAddrList(dp, pol.Match.SourceAddresses, result)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:496:./pkg/dataplane/compiler.go:816:			dstID, err := resolveAddrList(dp, pol.Match.DestinationAddresses, result)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:497:./pkg/dataplane/compiler.go:941:			srcID, err := resolveAddrList(dp, pol.Match.SourceAddresses, result)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:498:./pkg/dataplane/compiler.go:947:			dstID, err := resolveAddrList(dp, pol.Match.DestinationAddresses, result)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:570:./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:13:remaining := t.reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:585:./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:81:(`AddrList`), not by iterating `appliedAddrs[name]`. So the prune will
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:589:./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:116:`clearLocked` (`:1086-1113`) resets `ownedNames/appliedAddrs/appliedRI`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:626:./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:14:  remaining := t.reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:629:./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:30:* **Verdict**: **CONFIRMED (Broken)**. If `AddrDel` fails for a regular (non-link-local) address, `newApplied[key] = true` is skipped at line 618. The address is omitted from `newApplied` (which is returned as `remaining`). Consequently, `len(remaining)` will be `0` (unless a link-local delete also failed), and the prune loop will execute `delete(t.appliedAddrs, name)` and skip adding `name` to `nextWG`. The retry signal for regular addresses is broken.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:633:./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:41:* **Verdict**: **CONFIRMED (Defective)**. Any transient error (e.g. netlink buffer exhaustion, timeout) from `LinkByName` causes the code to jump to `delete(t.appliedAddrs, name)` and drop the tracking entry without retry. Because the persistent `wgN` link survives, the addresses survive on the interface but are forgotten by the daemon.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:822:./docs/research/1884-tunnel-flap/claude-smr-plan-r4.md:32:  appliedRI lifecycle (removal, clearLocked) now matches appliedAddrs
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:827:./docs/research/1884-tunnel-flap/agy-plan-r9.md:65:* **Defect**: If `LinkByName` returns a **transient** error (e.g. netlink busy or buffer overflow), `err == nil` is false. The code will skip the `LinkDel` attempt but will also **not** set `next[name] = true` and will delete the tracking maps for `appliedAddrs` and `appliedRI`. Consequently, the manager orphans the tunnel interface in the kernel and ceases tracking it.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:834:./docs/research/1884-tunnel-flap/codex-plan-r3.md:11:This needs a master-identity check before `LinkSetNoMaster`: only unbind if the current master is still the VRF that the tunnel manager previously bound. Also specify `appliedRI` cleanup on deletion/Clear; A.1 deletes `appliedAddrs` only ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:188)), and `clearLocked` cleanup names only `ownedNames`/`appliedAddrs` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:198)).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:840:./docs/research/1884-tunnel-flap/codex-plan-r2.md:13:4. `appliedAddrs` can forget a configured link-local that still exists. A.4 deletes stale link-local only if it is in `applied`, then updates `appliedAddrs[name]` to addresses “now ensured.” If `AddrDel` fails for a removed configured `fe80`, the address remains present but is no longer configured, so it drops out of `applied` and future applies skip it forever. Evidence: [plan.md:242](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:242), [plan.md:251](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:251), current best-effort delete pattern at [tunnel.go:453](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:453). Keep failed-delete applied LLs tracked until they are absent or deletion succeeds.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:841:./docs/research/1884-tunnel-flap/codex-plan-r2.md:33:2. Yes. `AddrDel` failure is the concrete hole; `AddrAdd` failure on introduction is acceptable if only successful adds enter `appliedAddrs`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:857:./docs/research/1884-tunnel-flap/claude-smr-plan-r3.md:27:- **appliedAddrs AddrDel-failure retention (F4) / ownedNames
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:896:./docs/research/1884-tunnel-flap/agy-plan-r3.md:48:*   **(F4) failed-AddrDel Retention:** Sound. Keeping failed-delete link-locals in `appliedAddrs` ensures they are cleaned up on a retry rather than orphaned.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:912:./docs/research/1884-tunnel-flap/agy-plan-r2.md:59:    *   **Analysis:** No issues found. Because `Apply` ([tunnel.go:94-310](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L94-L310)) does not return early on individual tunnel errors (it logs warnings and calls `continue`), `ownedNames` is guaranteed to be updated to the new `desired` set on every apply. When `Clear()` / `clearLocked()` is called, it correctly clears `ownedNames` and `appliedAddrs`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:915:./docs/research/1884-tunnel-flap/agy-plan-r2.md:79:*   **Q2: Any hole where a CONFIGURED fe80 is absent from `appliedAddrs` at removal time other than the documented daemon-restart residual? Is best-effort acceptable?**
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:967:./docs/research/1884-tunnel-flap/plan.md:347:Restart residual: `appliedAddrs` is not persisted; a configured fe80
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:985:./docs/research/1884-tunnel-flap/plan.md:617:   → deleted (in appliedAddrs); foreign/kernel fe80 never deleted;
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:986:./docs/research/1884-tunnel-flap/plan.md:618:   fe80 stale-delete failure → stays in appliedAddrs and is retried
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:993:./docs/research/1884-tunnel-flap/plan.md:692:  `appliedAddrs` link-local across restart. Separate issue if it bites.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1008:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:19:- pkg/routing/tunnel.go (Apply ~163, applyWireguardTunLocked ~798, reconcileLinkAddrsLocked ~584, clearLocked ~1086, tunnelManager fields ~104)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1029:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:473:   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1052:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:561:   430			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1056:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:714:   119	| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1065:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:784:   189	     `reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name],
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1073:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:803:   208	`reconcileLinkAddrsLocked` and `appliedAddrs` verbatim; idempotent;
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1076:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:827:   232	exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1082:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1004:   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1090:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1023:   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1091:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1036:   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1106:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1321:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1129:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1711:   379	  `appliedAddrs[name]` (manager-applied) are eligible; foreign/autoconf
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1133:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1719:   387	- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1140:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1791:   459	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1170:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5450:  1437			addrs, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1176:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5593:   105	  deleted only if recorded in `appliedAddrs` (a configured fe80 we
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1191:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5998:   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1203:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6033:   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1218:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6075:   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1243:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6297:   160	func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1247:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6372:   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1255:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6391:   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1256:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6404:   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1259:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6459:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1283:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6640:   189	     `reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name],
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1322:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6888:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1325:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6963:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1326:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6965:- **MEDIUM: The plan overclaims “manager-applied addresses only.”** `appliedAddrs` only gates stale link-local deletion. For non-link-local stale addresses, `reconcileLinkAddrsLocked` deletes them regardless of whether they are in `applied` ([tunnel.go:751](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751), [tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755)). That may match existing configured-WG behavior, but the plan should stop claiming the removal path is strictly applied-address scoped unless it adds an explicit filter.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1327:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6971:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1330:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6984:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1331:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6986:- **MEDIUM: The plan overclaims “manager-applied addresses only.”** `appliedAddrs` only gates stale link-local deletion. For non-link-local stale addresses, `reconcileLinkAddrsLocked` deletes them regardless of whether they are in `applied` ([tunnel.go:751](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751), [tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755)). That may match existing configured-WG behavior, but the plan should stop claiming the removal path is strictly applied-address scoped unless it adds an explicit filter.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1332:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6992:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1379:./docs/research/1919-wg-addr-route-prune/plan.md:136:| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1388:./docs/research/1919-wg-addr-route-prune/plan.md:207:       `pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1407:./docs/research/1919-wg-addr-route-prune/plan.md:265:`appliedAddrs` + the link-local gate; idempotent; link preserved; the new
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1409:./docs/research/1919-wg-addr-route-prune/plan.md:290:exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1413:./docs/research/1919-wg-addr-route-prune/plan.md:302:`appliedAddrs[name]` set gates link-local deletion ONLY — it does NOT
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1428:./docs/research/1919-wg-addr-route-prune/plan.md:372:    list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1434:./docs/research/1919-wg-addr-route-prune/plan.md:421:    failed := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1436:./docs/research/1919-wg-addr-route-prune/plan.md:431://     via applyWireguardTunLocked → reconcileLinkAddrsLocked at :880) ...
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1465:./docs/research/1919-wg-addr-route-prune/plan.md:547:- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1472:./docs/research/1919-wg-addr-route-prune/plan.md:619:t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1506:./_Log.md:5569:  **Action**: #1904 + #1905 combined /engineer lane (both filed from the #1884 research). #1904: shared riMemberLinuxName now resolves RI tunnel list members through cfg.TunnelNameMap() (compiler-assigned TunnelConfig.Name verbatim — exact device-name parity by construction), so unit>0 members like gr-0/0/0.1 bind the real uN device (gr-0-0-0u1); non-tunnel refs keep the literal transform byte-identically. #1905: applyWireguardTunLocked passes/stores t.appliedAddrs like the GRE branch, so a CONFIGURED fe80 removed from config reconciles away while kernel-autonomous fe80s are never touched. Live on loss userspace cluster: 10/10 PASS (gr-0-0-1u1 master vrf-vrf1904; configured fe80 removed, foreign fe80::beef + kernel stable-privacy LL survive). go build/test/-race clean.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1687:./pkg/dataplane/userspace/interfaces.go:453:	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1706:./pkg/dataplane/userspace/maps_sync.go:968:	// Use AddrList(nil, ...) to enumerate ALL addresses on the system.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1707:./pkg/dataplane/userspace/maps_sync.go:970:		addrs, err := netlink.AddrList(nil, family)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1730:./pkg/dataplane/compiler_iface.go:198:	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1739:./pkg/dataplane/compiler_iface.go:1175:		addrs, _ := netlink.AddrList(nl, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1879:./pkg/daemon/bootstrap.go:588:	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1881:./pkg/daemon/bootstrap.go:635:	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1885:./pkg/daemon/daemon_ha_fabric.go:114:	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2003:./pkg/daemon/daemon_reth.go:208:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2010:./pkg/daemon/daemon_reth.go:238:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2019:./pkg/daemon/daemon_reth.go:273:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2118:./pkg/cli/cli_show_interfaces.go:484:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2119:./pkg/cli/cli_show_interfaces.go:958:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2289:./pkg/grpcapi/server_show_interfaces_text.go:129:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2290:./pkg/grpcapi/server_show_interfaces_text.go:218:		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2359:./pkg/cluster/reth.go:89:			addrs, err := rc.nlHandle.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2463:./pkg/routing/README.md:105:  deleted only if recorded in `appliedAddrs` (a configured fe80 we
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2491:./pkg/routing/tunnel.go:33:	AddrList(netlink.Link, int) ([]netlink.Addr, error)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2512:./pkg/routing/tunnel.go:705:	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2520:./pkg/routing/tunnel.go:724:func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2521:./pkg/routing/tunnel.go:737:	if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2536:./pkg/routing/tunnel.go:1020:	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2545:./pkg/routing/tunnel.go:1437:		addrs, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2549:./pkg/routing/tunnel_reconcile_test.go:300:	// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2564:./pkg/routing/tunnel_reconcile_test.go:342:		t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2587:./pkg/routing/tunnel_reconcile_test.go:430:		t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2623:./pkg/routing/iface_reuse_test.go:160:func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2636:./pkg/routing/tunnel_keepalive_test.go:92:func (o *kaOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2714:./docs/pr/1904-routing-followups/plan.md:61:`applyWireguardTunLocked` calls the shared `reconcileLinkAddrsLocked`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2717:./docs/pr/1904-routing-followups/plan.md:75:t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2719:./docs/pr/1904-routing-followups/plan.md:83:- First apply after daemon restart (adoption): `appliedAddrs[wg0]` is
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3616:   177		// appliedAddrs: per tunnel, the address set this manager itself
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3621:   182		appliedAddrs map[string]map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3639:   200		if t.appliedAddrs == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3640:   201			t.appliedAddrs = map[string]map[string]bool{}
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3989:   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3990:   706			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], kind)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4008:   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4024:   265	`appliedAddrs` + the link-local gate; idempotent; link preserved; the new
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4037:   278	duplicates the `appliedAddrs` bookkeeping Path A already has. Higher
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4049:   290	exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4061:   302	`appliedAddrs[name]` set gates link-local deletion ONLY — it does NOT
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4078:   319	`applyWireguardTunLocked` VRF-binds at `:883-888` but does NOT use
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4099:   340	its `routing-instance` removed also never unbinds (`applyWireguardTunLocked`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4131:   372	    list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4173:   414	            delete(t.appliedAddrs, name) // device genuinely gone; drop
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4180:   421	    failed := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4182:   423	        t.appliedAddrs[name] = failed
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4186:   427	    delete(t.appliedAddrs, name) // clean prune; drop tracking
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4190:   431	//     via applyWireguardTunLocked → reconcileLinkAddrsLocked at :880) ...
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4246:   487	   old addr not re-leaked (appliedAddrs correctly reset/repopulated).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4306:   547	- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4444:   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4457:   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4573:   291			delete(t.appliedAddrs, name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4582:   300			// its addresses + FRR routes every commit. applyWireguardTunLocked
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4585:   303				if err := t.applyWireguardTunLocked(tc); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:5070:   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:5112:   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:5200:   430			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6028:  1392		t.appliedAddrs = nil
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6185:   924	// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6199:   938	func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6356:  1017		// see above), its appliedAddrs entry is retained with it so a later
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6359:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6360:  1021			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6547:pkg/routing/iface_reuse_test.go:160:func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6579:pkg/routing/tunnel_keepalive_test.go:92:func (o *kaOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6796:   160	func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6853:    33		AddrList(netlink.Link, int) ([]netlink.Addr, error)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6934:pkg/routing/tunnel.go:1021:		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7299:   145			// the dataplane snapshot, but applyWireguardTunLocked never ran,
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7448:207:       `pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7457:421:    failed := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7608:   572	- Update the `applyWireguardTunLocked` doc comment (`tunnel.go:784-797`)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7644:   608	        if err := t.applyWireguardTunLocked(tc); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7655:   619	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7656:   620	    link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:13:remaining := t.reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:14:if len(remaining) > 0 { t.appliedAddrs[name] = remaining; nextWG[name] = true; continue }
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:41:`delete(t.appliedAddrs, name)` runs and `name` is dropped from
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:56:  addresses (or have the prune compare `appliedAddrs[name]` before/after)
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:59:  ran against a found link and `appliedAddrs[name]` was non-empty going
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:77:## F2 (MINOR) — `appliedAddrs[name]` may be the WRONG eligibility set after a partial steady-state apply
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:79:`appliedAddrs[name]` records adds + present-and-wanted, but the prune
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:81:(`AddrList`), not by iterating `appliedAddrs[name]`. So the prune will
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:90:addresses present on the device, not only `appliedAddrs`-tracked ones —
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:110:WG-only netdev marker; `applyWireguardTunLocked` itself only knows a
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:116:`clearLocked` (`:1086-1113`) resets `ownedNames/appliedAddrs/appliedRI`
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:125:`applyWireguardTunLocked` (`:798-890`) never calls `startKeepalive`; the
./pkg/daemon/daemon_reth.go:208:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./pkg/daemon/daemon_reth.go:238:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./pkg/daemon/daemon_reth.go:273:	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:14:  remaining := t.reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:16:      t.appliedAddrs[name] = remaining
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:30:* **Verdict**: **CONFIRMED (Broken)**. If `AddrDel` fails for a regular (non-link-local) address, `newApplied[key] = true` is skipped at line 618. The address is omitted from `newApplied` (which is returned as `remaining`). Consequently, `len(remaining)` will be `0` (unless a link-local delete also failed), and the prune loop will execute `delete(t.appliedAddrs, name)` and skip adding `name` to `nextWG`. The retry signal for regular addresses is broken.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:38:  delete(t.appliedAddrs, name)
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:41:* **Verdict**: **CONFIRMED (Defective)**. Any transient error (e.g. netlink buffer exhaustion, timeout) from `LinkByName` causes the code to jump to `delete(t.appliedAddrs, name)` and drop the tracking entry without retry. Because the persistent `wgN` link survives, the addresses survive on the interface but are forgotten by the daemon.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:49:          delete(t.appliedAddrs, name)
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:58:  - §8 R1: "Mitigation: only addresses in `appliedAddrs[name]` (manager-applied) are eligible..."
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:75:* **Source Reality**: [pkg/routing/tunnel.go:883-888](file:///home/ps/git/bpfrx/pkg/routing/tunnel.go#L883-L888) (`applyWireguardTunLocked`) binds to VRF if `tc.RoutingInstance != ""`, but lacks any mechanism to unbind if the VRF config is removed while keeping the tunnel.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:76:* **Verdict**: **OK with Nit**. Deferring VRF unbind is acceptable, but the plan must explicitly note that changing a configured WG tunnel to have *no* routing instance will keep it bound to the old VRF in the kernel, as `applyWireguardTunLocked` does not unbind.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:85:* **Source Reality**: `applyWireguardTunLocked` does not configure keepalives. Only `applyKernelTunnelLocked` calls `startKeepalive`.
./pkg/daemon/bootstrap.go:588:	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/daemon/bootstrap.go:635:	addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/daemon/daemon_run.go:145:		// the dataplane snapshot, but applyWireguardTunLocked never ran,
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:19:- pkg/routing/tunnel.go (Apply ~163, applyWireguardTunLocked ~798, reconcileLinkAddrsLocked ~584, clearLocked ~1086, tunnelManager fields ~104)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:135:   177		// appliedAddrs: per tunnel, the address set this manager itself
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:140:   182		appliedAddrs map[string]map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:158:   200		if t.appliedAddrs == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:159:   201			t.appliedAddrs = map[string]map[string]bool{}
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:473:   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:561:   430			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:629:    34	`applyWireguardTunLocked` (`tunnel.go:880`), which runs once per **still-
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:636:    41	        if err := t.applyWireguardTunLocked(tc); err != nil { ... }
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:646:    51	- `tc` for it is **absent** from `tunnels`, so `applyWireguardTunLocked`
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:712:   117	| `pkg/routing/tunnel.go:188-204` removal loop | deletes non-WG tunnels gone from config; `delete(appliedAddrs,name)` |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:713:   118	| `pkg/routing/tunnel.go:208-230` per-tunnel loop | runs `applyWireguardTunLocked` ONLY for still-configured WG |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:714:   119	| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:716:   121	| `pkg/routing/tunnel.go:104-134` `tunnelManager` fields | `ownedNames`, `appliedAddrs[name]`, `appliedRI[name]` |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:735:   140	  (`applyWireguardTunLocked` never calls `startKeepalive`). So the #1918
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:747:   152	   GRE/IPIP-style tunnels (via `delete(appliedAddrs,name)` + `LinkDel`)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:750:   155	   `applyWireguardTunLocked`, which is driven by the **current config
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:759:   164	The `appliedAddrs[name]` map is the key asset already in place: it
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:763:   168	appliedAddrs[name], …)` already does correctly (delete present-and-not-
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:784:   189	     `reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name],
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:790:   195	   - `delete(t.appliedAddrs, name)` once pruned (idempotent: a second
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:793:   198	     just `delete(t.appliedAddrs, name)` and drop tracking.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:803:   208	`reconcileLinkAddrsLocked` and `appliedAddrs` verbatim; idempotent;
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:815:   220	duplicates the `appliedAddrs` bookkeeping Path A already has. Higher
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:827:   232	exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:834:   239	`applyWireguardTunLocked` VRF-binds at `:883-888` but does NOT use
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:929:   291			delete(t.appliedAddrs, name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:938:   300			// its addresses + FRR routes every commit. applyWireguardTunLocked
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:941:   303				if err := t.applyWireguardTunLocked(tc); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1004:   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1005:   706			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], kind)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1023:   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1036:   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1224:   924	// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1239:   938	func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1318:  1017		// see above), its appliedAddrs entry is retained with it so a later
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1321:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1322:  1021			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1619:   287	            t.appliedAddrs[name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1621:   289	            t.appliedAddrs[name] = remaining
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1626:   294	    delete(t.appliedAddrs, name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1673:   341	   old addr not re-leaked (appliedAddrs correctly reset/repopulated).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1711:   379	  `appliedAddrs[name]` (manager-applied) are eligible; foreign/autoconf
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1719:   387	- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1744:   412	- Update the `applyWireguardTunLocked` doc comment (`tunnel.go:784-797`)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1780:   448	        if err := t.applyWireguardTunLocked(tc); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1791:   459	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1792:   460	    link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2450:pkg/routing/tunnel.go:300:		// its addresses + FRR routes every commit. applyWireguardTunLocked
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2451:pkg/routing/tunnel.go:303:			if err := t.applyWireguardTunLocked(tc); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2465:pkg/routing/tunnel.go:924:// applyWireguardTunLocked creates (or reuses) the persistent wgN TUN
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2466:pkg/routing/tunnel.go:938:func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2550:pkg/daemon/daemon_run.go:145:		// the dataplane snapshot, but applyWireguardTunLocked never ran,
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:2628:pkg/routing/tunnel.go:1021:		link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:3174:   145			// the dataplane snapshot, but applyWireguardTunLocked never ran,
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5404:  1392		t.appliedAddrs = nil
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5450:  1437			addrs, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5593:   105	  deleted only if recorded in `appliedAddrs` (a configured fe80 we
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5998:   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6033:   300		// Apply with a CONFIGURED fe80 — recorded in appliedAddrs.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6075:   342			t.Fatal("failed-delete fe80 not retried (dropped from appliedAddrs)")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6297:   160	func (f *fakeLinkOps) AddrList(l netlink.Link, family int) ([]netlink.Addr, error) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6372:   705		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6373:   706			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], kind)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6391:   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6404:   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6459:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6460:  1021			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6511:   291			delete(t.appliedAddrs, name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6520:   300			// its addresses + FRR routes every commit. applyWireguardTunLocked
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6523:   303				if err := t.applyWireguardTunLocked(tc); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6640:   189	     `reconcileLinkAddrsLocked(link, name, nil, t.appliedAddrs[name],
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6646:   195	   - `delete(t.appliedAddrs, name)` once pruned (idempotent: a second
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6649:   198	     just `delete(t.appliedAddrs, name)` and drop tracking.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6671:   287	            t.appliedAddrs[name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6673:   289	            t.appliedAddrs[name] = remaining
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6678:   294	    delete(t.appliedAddrs, name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6736:   291			delete(t.appliedAddrs, name)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6817:   177		// appliedAddrs: per tunnel, the address set this manager itself
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6822:   182		appliedAddrs map[string]map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6888:  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6889:  1021			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6903:   239	`applyWireguardTunLocked` VRF-binds at `:883-888` but does NOT use
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6963:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6965:- **MEDIUM: The plan overclaims “manager-applied addresses only.”** `appliedAddrs` only gates stale link-local deletion. For non-link-local stale addresses, `reconcileLinkAddrsLocked` deletes them regardless of whether they are in `applied` ([tunnel.go:751](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751), [tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755)). That may match existing configured-WG behavior, but the plan should stop claiming the removal path is strictly applied-address scoped unless it adds an explicit filter.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6971:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6973:- **#1918 interaction claim is correct for Go tunnel keepalives.** `Apply` sends WG configs to `applyWireguardTunLocked` and `continue`s ([tunnel.go:297](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:297)); `startKeepalive` is only in the legacy non-WG path ([tunnel.go:664](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:664), [tunnel.go:682](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:682)). Minor wording nit: WG has protocol persistent keepalive fields, but that is Rust WG behavior, not the #1918 ICMP/link-admin keepalive.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6984:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6986:- **MEDIUM: The plan overclaims “manager-applied addresses only.”** `appliedAddrs` only gates stale link-local deletion. For non-link-local stale addresses, `reconcileLinkAddrsLocked` deletes them regardless of whether they are in `applied` ([tunnel.go:751](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751), [tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755)). That may match existing configured-WG behavior, but the plan should stop claiming the removal path is strictly applied-address scoped unless it adds an explicit filter.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6992:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6994:- **#1918 interaction claim is correct for Go tunnel keepalives.** `Apply` sends WG configs to `applyWireguardTunLocked` and `continue`s ([tunnel.go:297](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:297)); `startKeepalive` is only in the legacy non-WG path ([tunnel.go:664](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:664), [tunnel.go:682](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:682)). Minor wording nit: WG has protocol persistent keepalive fields, but that is Rust WG behavior, not the #1918 ICMP/link-admin keepalive.
./pkg/daemon/daemon_ha_fabric.go:114:	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/dataplane/userspace/interfaces.go:453:	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:22:  If `len(failed) > 0`, the `Apply` prune loop retains the failed addresses in `t.appliedAddrs[name]` and sets `nextWG[name] = true` so the removal and address deletion are retried on the next configuration apply.
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:46:          delete(t.appliedAddrs, name) // device genuinely gone; drop
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:67:   - `applyWireguardTunLocked` runs, applies address, and sets `t.appliedAddrs["wg0"] = {"10.0.0.1/24": true}`.
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:74:   - `delete(t.appliedAddrs, "wg0")` is called.
./pkg/dataplane/compiler_iface.go:198:	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
./pkg/dataplane/compiler_iface.go:1175:		addrs, _ := netlink.AddrList(nl, netlink.FAMILY_ALL)
./pkg/dataplane/userspace/maps_sync.go:968:	// Use AddrList(nil, ...) to enumerate ALL addresses on the system.
./pkg/dataplane/userspace/maps_sync.go:970:		addrs, err := netlink.AddrList(nil, family)
./docs/userspace-xdp-pass-bootstrap-and-ipv6.md:61:**Fix:** `syncLocalAddressMapsLocked()` in `manager.go` now enumerates ALL kernel addresses via `netlink.AddrList(nil, family)`, including dynamically added VIPs. This runs periodically in the status update loop.
./docs/research/1919-wg-addr-route-prune/plan.md:36:`applyWireguardTunLocked` (`tunnel.go:880`), which runs once per **still-
./docs/research/1919-wg-addr-route-prune/plan.md:43:        if err := t.applyWireguardTunLocked(tc); err != nil { ... }
./docs/research/1919-wg-addr-route-prune/plan.md:53:- `tc` for it is **absent** from `tunnels`, so `applyWireguardTunLocked`
./docs/research/1919-wg-addr-route-prune/plan.md:135:| `pkg/routing/tunnel.go:188-204` removal loop | deletes non-WG tunnels gone from config; `delete(appliedAddrs,name)` |
./docs/research/1919-wg-addr-route-prune/plan.md:136:| `pkg/routing/tunnel.go:208-230` per-tunnel loop | runs `applyWireguardTunLocked` ONLY for still-configured WG |
./docs/research/1919-wg-addr-route-prune/plan.md:137:| `pkg/routing/tunnel.go:798-890` `applyWireguardTunLocked` | create/reuse wgN; MTU; `reconcileLinkAddrsLocked`; VRF bind |
./docs/research/1919-wg-addr-route-prune/plan.md:139:| `pkg/routing/tunnel.go:104-134` `tunnelManager` fields | `ownedNames`, `appliedAddrs[name]`, `appliedRI[name]` |
./docs/research/1919-wg-addr-route-prune/plan.md:158:  (`applyWireguardTunLocked` never calls `startKeepalive`). So the #1918
./docs/research/1919-wg-addr-route-prune/plan.md:170:   GRE/IPIP-style tunnels (via `delete(appliedAddrs,name)` + `LinkDel`)
./docs/research/1919-wg-addr-route-prune/plan.md:173:   `applyWireguardTunLocked`, which is driven by the **current config
./docs/research/1919-wg-addr-route-prune/plan.md:182:The `appliedAddrs[name]` map is the key asset already in place: it
./docs/research/1919-wg-addr-route-prune/plan.md:186:appliedAddrs[name], …)` already does correctly (delete present-and-not-
./docs/research/1919-wg-addr-route-prune/plan.md:208:       `pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])`
./docs/research/1919-wg-addr-route-prune/plan.md:217:     - If `retry` is **true**: retain `t.appliedAddrs[name] = failed`
./docs/research/1919-wg-addr-route-prune/plan.md:220:     - If `retry` is **false** (proven clean): `delete(t.appliedAddrs,
./docs/research/1919-wg-addr-route-prune/plan.md:224:       gone via manual `ip link del`): `delete(t.appliedAddrs, name)`
./docs/research/1919-wg-addr-route-prune/plan.md:226:       RETAIN `nextWG[name] = true` and keep `appliedAddrs[name]` so the
./docs/research/1919-wg-addr-route-prune/plan.md:268:`appliedAddrs` + the link-local gate; idempotent; link preserved; the new
./docs/research/1919-wg-addr-route-prune/plan.md:281:duplicates the `appliedAddrs` bookkeeping Path A already has. Higher
./docs/research/1919-wg-addr-route-prune/plan.md:293:exact assets (`appliedAddrs`, `reconcileLinkAddrsLocked`) the manager
./docs/research/1919-wg-addr-route-prune/plan.md:305:`appliedAddrs[name]` set gates link-local deletion ONLY — it does NOT
./docs/research/1919-wg-addr-route-prune/plan.md:322:`applyWireguardTunLocked` VRF-binds at `:883-888` but does NOT use
./docs/research/1919-wg-addr-route-prune/plan.md:343:its `routing-instance` removed also never unbinds (`applyWireguardTunLocked`
./docs/research/1919-wg-addr-route-prune/plan.md:381://     (carried forward as the new appliedAddrs[name] for the link-local
./docs/research/1919-wg-addr-route-prune/plan.md:388:    list, err := t.ops.AddrList(link, netlink.FAMILY_ALL)
./docs/research/1919-wg-addr-route-prune/plan.md:434:            delete(t.appliedAddrs, name) // device genuinely gone; drop
./docs/research/1919-wg-addr-route-prune/plan.md:441:    failed, retry := t.pruneAppliedAddrsLocked(link, name, t.appliedAddrs[name])
./docs/research/1919-wg-addr-route-prune/plan.md:443:        t.appliedAddrs[name] = failed // = old applied if AddrList failed
./docs/research/1919-wg-addr-route-prune/plan.md:447:    delete(t.appliedAddrs, name) // proven clean; drop tracking
./docs/research/1919-wg-addr-route-prune/plan.md:451://     via applyWireguardTunLocked → reconcileLinkAddrsLocked at :880) ...
./docs/research/1919-wg-addr-route-prune/plan.md:507:   old addr not re-leaked (appliedAddrs correctly reset/repopulated).
./docs/research/1919-wg-addr-route-prune/plan.md:509:   on removal, fake `AddrList` returns an error AND `appliedAddrs[name]`
./docs/research/1919-wg-addr-route-prune/plan.md:572:- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
./docs/research/1919-wg-addr-route-prune/plan.md:597:- Update the `applyWireguardTunLocked` doc comment (`tunnel.go:784-797`)
./docs/research/1919-wg-addr-route-prune/plan.md:633:        if err := t.applyWireguardTunLocked(tc); err != nil {
./docs/research/1919-wg-addr-route-prune/plan.md:644:t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/research/1919-wg-addr-route-prune/plan.md:645:    link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./_Log.md:4967:    pkg/routing/tunnel.go (applyWireguardTunLocked persistent TUN, no flap)
./_Log.md:5428:  - **Action**: #1736 S2b — live kernel-WG interop: daemon collect-gate fix (WG tunnels have no GRE source and were dropped before applyWireguardTunLocked), interop harness + env, operator runbook, research plan carry.
./_Log.md:5569:  **Action**: #1904 + #1905 combined /engineer lane (both filed from the #1884 research). #1904: shared riMemberLinuxName now resolves RI tunnel list members through cfg.TunnelNameMap() (compiler-assigned TunnelConfig.Name verbatim — exact device-name parity by construction), so unit>0 members like gr-0/0/0.1 bind the real uN device (gr-0-0-0u1); non-tunnel refs keep the literal transform byte-identically. #1905: applyWireguardTunLocked passes/stores t.appliedAddrs like the GRE branch, so a CONFIGURED fe80 removed from config reconciles away while kernel-autonomous fe80s are never touched. Live on loss userspace cluster: 10/10 PASS (gr-0-0-1u1 master vrf-vrf1904; configured fe80 removed, foreign fe80::beef + kernel stable-privacy LL survive). go build/test/-race clean.
./docs/research/1884-tunnel-flap/claude-smr-plan-r4.md:32:  appliedRI lifecycle (removal, clearLocked) now matches appliedAddrs
./docs/research/1884-tunnel-flap/agy-plan-r9.md:65:* **Defect**: If `LinkByName` returns a **transient** error (e.g. netlink busy or buffer overflow), `err == nil` is false. The code will skip the `LinkDel` attempt but will also **not** set `next[name] = true` and will delete the tracking maps for `appliedAddrs` and `appliedRI`. Consequently, the manager orphans the tunnel interface in the kernel and ceases tracking it.
./docs/research/1884-tunnel-flap/codex-plan-r3.md:11:This needs a master-identity check before `LinkSetNoMaster`: only unbind if the current master is still the VRF that the tunnel manager previously bound. Also specify `appliedRI` cleanup on deletion/Clear; A.1 deletes `appliedAddrs` only ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:188)), and `clearLocked` cleanup names only `ownedNames`/`appliedAddrs` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:198)).
./docs/research/1884-tunnel-flap/codex-plan-r2.md:13:4. `appliedAddrs` can forget a configured link-local that still exists. A.4 deletes stale link-local only if it is in `applied`, then updates `appliedAddrs[name]` to addresses “now ensured.” If `AddrDel` fails for a removed configured `fe80`, the address remains present but is no longer configured, so it drops out of `applied` and future applies skip it forever. Evidence: [plan.md:242](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:242), [plan.md:251](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:251), current best-effort delete pattern at [tunnel.go:453](/home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go:453). Keep failed-delete applied LLs tracked until they are absent or deletion succeeds.
./docs/research/1884-tunnel-flap/codex-plan-r2.md:33:2. Yes. `AddrDel` failure is the concrete hole; `AddrAdd` failure on introduction is acceptable if only successful adds enter `appliedAddrs`.
./docs/research/1884-tunnel-flap/claude-smr-plan-r3.md:27:- **appliedAddrs AddrDel-failure retention (F4) / ownedNames
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:26:keepalive (no-op for anchors), LinkDel, clears appliedAddrs/appliedRI;
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:66:  retains via `next[name] = true`; appliedAddrs/appliedRI deleted only
./docs/research/1884-tunnel-flap/agy-plan-r2.md:59:    *   **Analysis:** No issues found. Because `Apply` ([tunnel.go:94-310](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L94-L310)) does not return early on individual tunnel errors (it logs warnings and calls `continue`), `ownedNames` is guaranteed to be updated to the new `desired` set on every apply. When `Clear()` / `clearLocked()` is called, it correctly clears `ownedNames` and `appliedAddrs`.
./docs/research/1884-tunnel-flap/agy-plan-r2.md:79:*   **Q2: Any hole where a CONFIGURED fe80 is absent from `appliedAddrs` at removal time other than the documented daemon-restart residual? Is best-effort acceptable?**
./docs/research/1884-tunnel-flap/agy-plan-r2.md:80:    *   **Answer:** Yes, best-effort is acceptable. The only other case where this happens is if `AddrAdd` transiently fails during the apply that introduced it. If `AddrAdd` failed, the address was never added to the kernel, so there is no kernel address to clean up anyway. On the next successful apply, the address will succeed and be registered in `appliedAddrs`.
./docs/research/1884-tunnel-flap/plan.md:47:#1432 (AGY Hazard B): `applyWireguardTunLocked` (tunnel.go:362-485)
./docs/research/1884-tunnel-flap/plan.md:72:- **#1432 S2a** — `applyWireguardTunLocked`: the proven reuse-in-place
./docs/research/1884-tunnel-flap/plan.md:194:    delete(t.appliedAddrs, name) // only once gone/deleted
./docs/research/1884-tunnel-flap/plan.md:206:additionally clears `ownedNames`/`appliedAddrs`); note
./docs/research/1884-tunnel-flap/plan.md:324:  `applied` — the per-link record `t.appliedAddrs[name]` of addresses
./docs/research/1884-tunnel-flap/plan.md:335:- update `t.appliedAddrs[name]` to: addresses now ensured (successful
./docs/research/1884-tunnel-flap/plan.md:347:Restart residual: `appliedAddrs` is not persisted; a configured fe80
./docs/research/1884-tunnel-flap/plan.md:462:`appliedAddrs`. Net effect: tunnel-stanza RI removal unbinds
./docs/research/1884-tunnel-flap/plan.md:550:gains `ownedNames`, `appliedAddrs`, `appliedRI`; `keepaliveRunner`
./docs/research/1884-tunnel-flap/plan.md:617:   → deleted (in appliedAddrs); foreign/kernel fe80 never deleted;
./docs/research/1884-tunnel-flap/plan.md:618:   fe80 stale-delete failure → stays in appliedAddrs and is retried
./docs/research/1884-tunnel-flap/plan.md:692:  `appliedAddrs` link-local across restart. Separate issue if it bites.
./docs/research/1884-tunnel-flap/plan.md:721:Settled r2: LinkSetUp skip keyed on runner-down; appliedAddrs
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:71:- **appliedAddrs lifecycle on recreate**: reset before reconcile on the
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:83:  from appliedAddrs AND absent from the kernel — there is nothing to
./docs/research/1884-tunnel-flap/agy-plan-r3.md:6:I will view the next segment of `pkg/routing/tunnel.go` to understand how the wireguard branch works and how `applyWireguardTunLocked` operates.
./docs/research/1884-tunnel-flap/agy-plan-r3.md:48:*   **(F4) failed-AddrDel Retention:** Sound. Keeping failed-delete link-locals in `appliedAddrs` ensures they are cleaned up on a retry rather than orphaned.
./docs/research/1884-tunnel-flap/agy-plan-r3.md:71:*   *Refinement Recommendation:* In A.1, alongside `delete(t.appliedAddrs, name)`, execute `delete(t.appliedRI, name)` to prevent a minor string map leak when a tunnel is entirely removed.
./docs/research/1884-tunnel-flap/agy-plan-r3.md:78:    4.  The map entry is deleted at `delete(t.appliedAddrs, name)` and `next[name]` is *not* written.
./docs/pr/1866-wg-teardown/plan.md:97:`pkg/routing/tunnel.go` `applyWireguardTunLocked`.)
./docs/pr/1904-routing-followups/plan.md:61:`applyWireguardTunLocked` calls the shared `reconcileLinkAddrsLocked`
./docs/pr/1904-routing-followups/plan.md:67:`appliedAddrs` record; the WG branch was deliberately left
./docs/pr/1904-routing-followups/plan.md:75:t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
./docs/pr/1904-routing-followups/plan.md:76:    link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
./docs/pr/1904-routing-followups/plan.md:83:- First apply after daemon restart (adoption): `appliedAddrs[wg0]` is
./docs/pr/1904-routing-followups/plan.md:93:  (device leaks until S6 teardown, #1434) extends to the appliedAddrs
./docs/pr/1904-routing-followups/plan.md:98:so `t.appliedAddrs` is always non-nil when the WG branch runs.
./docs/pr/1904-routing-followups/plan.md:121:(`riMemberLinuxName`, `applyWireguardTunLocked`,
./docs/pr/1736-wg-interop/plan.md:82:`applyWireguardTunLocked`, `wgTunMTUForEndpoint` = 1500 − overhead − pad ≈

exec
/bin/bash -lc "rg -n \"type tunnelManager|func \\(t \\*tunnelManager\\).*Apply|wgConfigured|ownedNames|isLinkNotFound|clearLocked\" -S ." in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
./pkg/ra/ra.go:36:		return m.clearLocked()
./pkg/ra/ra.go:181:	return m.clearLocked()
./pkg/ra/ra.go:184:func (m *Manager) clearLocked() error {
./pkg/routing/xfrm.go:27:	if err := x.clearLocked(); err != nil {
./pkg/routing/xfrm.go:104:	return x.clearLocked()
./pkg/routing/xfrm.go:107:// clearLocked is the lock-free body of Clear. Caller must hold mu.
./pkg/routing/xfrm.go:109:func (x *xfrmManager) clearLocked() error {
./pkg/routing/bond.go:28:	if err := b.clearLocked(); err != nil {
./pkg/routing/bond.go:110:	return b.clearLocked()
./pkg/routing/bond.go:113:// clearLocked is the lock-free body of Clear. Caller must hold mu.
./pkg/routing/bond.go:115:func (b *bondManager) clearLocked() error {
./pkg/routing/vrf.go:151:// isLinkNotFound reports whether err is a "link not found" error
./pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
./pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
./pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
./pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
./pkg/routing/README.md:86:set-diff against the previous DESIRED set (`ownedNames`, retained on a
./pkg/routing/tunnel.go:147:type tunnelManager struct {
./pkg/routing/tunnel.go:171:	// ownedNames: ALL non-WireGuard tunnel names from the LAST Apply's
./pkg/routing/tunnel.go:176:	ownedNames map[string]bool
./pkg/routing/tunnel.go:197:	if t.ownedNames == nil {
./pkg/routing/tunnel.go:198:		t.ownedNames = map[string]bool{}
./pkg/routing/tunnel.go:252:func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
./pkg/routing/tunnel.go:272:	oldOwned := t.ownedNames
./pkg/routing/tunnel.go:294:	t.ownedNames = next
./pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
./pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
./pkg/routing/tunnel.go:927:// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
./pkg/routing/tunnel.go:931:// tunnel REMOVED from the config is not torn down by clearLocked and
./pkg/routing/tunnel.go:1357:	return t.clearLocked()
./pkg/routing/tunnel.go:1360:// clearLocked is the lock-free body of Clear. Caller must hold mu.
./pkg/routing/tunnel.go:1364:// per-tunnel apply failure leaves the name in ownedNames but not in
./pkg/routing/tunnel.go:1368:func (t *tunnelManager) clearLocked() error {
./pkg/routing/tunnel.go:1370:	names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
./pkg/routing/tunnel.go:1374:	for name := range t.ownedNames {
./pkg/routing/tunnel.go:1391:	t.ownedNames = nil
./pkg/routing/tunnel.go:1394:	// clearLocked drains every keepalive runner first
./pkg/routing/tunnel_reconcile_test.go:120:	// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./pkg/routing/tunnel_reconcile_test.go:1023:	// whose LinkDel fails): it stays in ownedNames but never reaches
./pkg/routing/tunnel_reconcile_test.go:1034:	// t.tunnels and ownedNames, not the success list alone).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:18:2. r2 §5 now gates LinkByName failure on isLinkNotFound (pkg/routing/vrf.go:151): not-found drops tracking, transient retains+retries. Correct?
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:21:Also re-check: idempotency across add/remove/remove-again with the new nextWG logic; the clearLocked + ensureReconcileStateLocked wgConfigured wiring; tests §6 (non-link-local retry test #4, transient-lookup test #6, restart-boundary #8); FRR §1a connected-route nuance; VRF §4a A1 + the routing-instance-removed residual nit.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:53:    19	`wireguard`-mode tunnels from the `desired` set and from `ownedNames`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:88:    54	- It is **not in `ownedNames`**, so the `Apply` removal loop
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:172:   138	| `pkg/routing/tunnel.go:104-134` `tunnelManager` fields | `ownedNames`, `appliedAddrs[name]`, `appliedRI[name]` |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:174:   140	| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:201:   167	1. WG names are deliberately excluded from `ownedNames` and `desired`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:232:   198	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:233:   199	to `ownedNames` but WG-only, and **never** feeding the `LinkDel` removal
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:238:   204	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:253:   219	     - On **`LinkByName` error**: gate on `isLinkNotFound(err)`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:262:   228	3. After the per-tunnel apply loop, set `t.wgConfigured = nextWG`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:297:/bin/bash -lc 'rg -n "reconcileLinkAddrsLocked|pruneAppliedAddrsLocked|ensureReconcileStateLocked|clearLocked|wgConfigured|LinkByName|isLinkNotFound|routing-instance-removed|AddrDel|AddrList|autoconf|fe80|link-local|restart" .' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:379:./pkg/ra/ra.go:36:		return m.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:382:./pkg/ra/ra.go:181:	return m.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:383:./pkg/ra/ra.go:184:func (m *Manager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:589:./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:116:`clearLocked` (`:1086-1113`) resets `ownedNames/appliedAddrs/appliedRI`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:590:./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:117:to nil. The plan adds `wgConfigured=nil` there — required, else a
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:591:./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:120:`ensureReconcileStateLocked` (`:139-152`) must init `wgConfigured` — plan
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:593:./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:133:`wgConfigured` starts empty) is a real boundary. It is consistent with
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:632:./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:40:* **Source Reality**: [pkg/routing/vrf.go:155](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L155) provides `isLinkNotFound(err)` to isolate link absence.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:635:./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:46:      if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:639:./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:79:* **Plan Claim**: §8 R5: "on a fresh daemon, `wgConfigured` is empty... same restart-adoption limitation the rest of the file has."
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:822:./docs/research/1884-tunnel-flap/claude-smr-plan-r4.md:32:  appliedRI lifecycle (removal, clearLocked) now matches appliedAddrs
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:828:./docs/research/1884-tunnel-flap/agy-plan-r9.md:66:* **Fix**: Use `isLinkNotFound(err)` from [vrf.go:L155](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L155) to prune tracking only on explicit not-found or success:
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:830:./docs/research/1884-tunnel-flap/agy-plan-r9.md:75:  } else if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:834:./docs/research/1884-tunnel-flap/codex-plan-r3.md:11:This needs a master-identity check before `LinkSetNoMaster`: only unbind if the current master is still the VRF that the tunnel manager previously bound. Also specify `appliedRI` cleanup on deletion/Clear; A.1 deletes `appliedAddrs` only ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:188)), and `clearLocked` cleanup names only `ownedNames`/`appliedAddrs` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:198)).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:836:./docs/research/1884-tunnel-flap/codex-plan-r3.md:27:3. ownedNames growth is bounded. `next` starts as desired only, and a removed name is retained only when `LinkByName` succeeds and `LinkDel` fails ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:170)). If the link is gone on the next apply, no retention path fires, so `t.ownedNames = next` drops it ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:190)).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:837:./docs/research/1884-tunnel-flap/codex-plan-r3.md:29:5. No r1 closure is reopened by the MTU/AddrDel/ownedNames folds. The only blocker I found is the new `appliedRI` lifecycle hole above.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:839:./docs/research/1884-tunnel-flap/codex-plan-r2.md:7:1. A.3 adoption is broken if implemented literally. A.1 assigns `t.ownedNames = desired` before the per-tunnel loop, then A.3 defines adoption as `not in t.ownedNames`. That makes every desired tunnel “owned” before the anchor branch runs, so restart adoption, WG→GRE, and foreign-compatible TUN adoption do not trigger MTU normalization. Evidence: [plan.md:153](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:153), [plan.md:166](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:166), [plan.md:213](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:213), [plan.md:324](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:324). Fix: snapshot `oldOwned := t.ownedNames` before overwriting, and use `oldOwned` for adoption decisions.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:857:./docs/research/1884-tunnel-flap/claude-smr-plan-r3.md:27:- **appliedAddrs AddrDel-failure retention (F4) / ownedNames
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:868:./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:61:- **ownedNames vs Clear()**: `Apply → ClearTunnels → Apply` — clearLocked
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:869:./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:70:  identical to today's clearLocked-by-name behavior — no regression.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:873:./docs/research/1884-tunnel-flap/agy-plan-r1.md:62:#### Q1: Is removing `clearLocked()` from `Apply` safe for ALL callers?
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:874:./docs/research/1884-tunnel-flap/agy-plan-r1.md:65:* **Reasoning**: `clearLocked()` in [pkg/routing/tunnel.go:659-674](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L659-L674) only iterates over the `t.tunnels` tracked slice. It does not perform a wild kernel scan. 
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:875:./docs/research/1884-tunnel-flap/agy-plan-r1.md:67:  - For the CLI: `t.tunnels` is empty at startup, making `clearLocked()` a no-op anyway. 
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:904:./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:36:**T3 — daemon restart ⇒ adopted, not flapped.** ownedNames empty ⇒
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:907:./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:67:  after successful/no-op removal; clearLocked resets all three maps.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:912:./docs/research/1884-tunnel-flap/agy-plan-r2.md:59:    *   **Analysis:** No issues found. Because `Apply` ([tunnel.go:94-310](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L94-L310)) does not return early on individual tunnel errors (it logs warnings and calls `continue`), `ownedNames` is guaranteed to be updated to the new `desired` set on every apply. When `Clear()` / `clearLocked()` is called, it correctly clears `ownedNames` and `appliedAddrs`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:942:./docs/research/1884-tunnel-flap/plan.md:21:1. `clearLocked()` (tunnel.go:97) deletes EVERY tracked tunnel link and
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:943:./docs/research/1884-tunnel-flap/plan.md:49:symmetrically, and is deliberately untracked so `clearLocked` cannot
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:948:./docs/research/1884-tunnel-flap/plan.md:159:`Apply` no longer calls `clearLocked()`. The manager tracks
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:950:./docs/research/1884-tunnel-flap/plan.md:195:    delete(t.appliedRI, name)    // [r3] ditto; clearLocked clears both
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:951:./docs/research/1884-tunnel-flap/plan.md:203:between applies — identical to today's clearLocked-by-name behavior
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:952:./docs/research/1884-tunnel-flap/plan.md:205:`Clear()`/`clearLocked()` keep delete-everything semantics (clearLocked
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:969:./docs/research/1884-tunnel-flap/plan.md:454:  VRF device NOT-FOUND (`isLinkNotFound`-class, vrf.go:144-163 — the
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:971:./docs/research/1884-tunnel-flap/plan.md:461:`clearLocked` also `delete(t.appliedRI, name)` alongside
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:976:./docs/research/1884-tunnel-flap/plan.md:523:**A.8 — daemon-restart adoption falls out.** After restart `ownedNames`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:981:./docs/research/1884-tunnel-flap/plan.md:573:- **clearLocked semantics for explicit Clear()/shutdown unchanged**.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:994:./docs/research/1884-tunnel-flap/plan.md:722:best-effort + AddrDel-failure retention; A.6 field list; ownedNames
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1008:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:19:- pkg/routing/tunnel.go (Apply ~163, applyWireguardTunLocked ~798, reconcileLinkAddrsLocked ~584, clearLocked ~1086, tunnelManager fields ~104)
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1009:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:25:1. Is Path A's wgConfigured diff correct and idempotent? Walk the prune loop across 3 commits (add, remove, remove-again). Does it ever double-prune or strand tracking?
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1021:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:200:   571		case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1024:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:350:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1058:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:718:   123	| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1062:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:776:   181	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1063:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:782:   187	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1067:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:791:   196	     commit finds `name` no longer in old `wgConfigured`, so no-op).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1071:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:796:   201	     `wgConfigured` so the next commit retries (mirrors GRE
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1072:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:799:   204	3. After the per-tunnel apply loop, set `t.wgConfigured = wgDesired`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1074:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:806:   211	**Cons**: one more reconcile map to keep in sync across `clearLocked`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1095:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1140:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1097:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1227:   927	// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1098:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1232:   931	// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1109:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1596:   264	// wgConfigured: WG tunnel names configured at the LAST Apply (plus
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1110:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1600:   268	wgConfigured map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1111:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1603:   271	`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1112:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1611:   279	oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1116:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1630:   298	t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1117:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1637:   305	`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1118:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1646:   314	contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1134:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1720:   388	  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1141:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1798:   466	// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1161:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5344:/bin/bash -lc "rg -n \"func \\(t \\*tunnelManager\\) clearLocked|clearLocked\\(\" pkg/routing/tunnel.go" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1162:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5346:1357:	return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1163:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5347:1368:func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1164:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5369:  1357		return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1165:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5372:  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1166:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5380:  1368	func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1168:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5406:  1394		// clearLocked drains every keepalive runner first
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1171:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5532:  1357		return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1172:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5535:  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1173:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5543:  1368	func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1181:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5744:   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1182:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5745:   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1264:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6570:   571		case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1265:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6589:/bin/bash -lc "rg -n \"func isLinkNotFound|isLinkNotFound\\(\" pkg/routing -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1266:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6591:pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1267:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6592:pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1268:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6593:pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1269:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6594:pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1270:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6595:pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1271:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6596:pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1272:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6599:/bin/bash -lc 'rg --files pkg/routing | xargs rg -n "isLinkNotFound|not found|ErrNotFound"' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1273:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6601:pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1274:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6602:pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1275:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6610:pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1276:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6617:pkg/routing/vrf.go:151:// isLinkNotFound reports whether err is a "link not found" error
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1277:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6618:pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1278:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6619:pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1279:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6620:pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1280:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6632:   181	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1281:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6638:   187	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1285:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6647:   196	     commit finds `name` no longer in old `wgConfigured`, so no-op).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1289:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6652:   201	     `wgConfigured` so the next commit retries (mirrors GRE
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1290:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6655:   204	3. After the per-tunnel apply loop, set `t.wgConfigured = wgDesired`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1291:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6663:   279	oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1295:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6682:   298	t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1296:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6685:   314	contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1300:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6703:   151	// isLinkNotFound reports whether err is a "link not found" error
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1301:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6707:   155	func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1321:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6865:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1324:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6961:- **MAJOR: Path A’s retry signal is broken for regular addresses.** The plan’s removal sketch relies on `len(remaining)>0` after `reconcileLinkAddrsLocked(..., nil, ...)` to retain `wgConfigured` for retry ([plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285), [plan.md:288](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:288)). But source only re-adds a failed stale delete to `newApplied` if the address is link-local: `if a.IP.IsLinkLocalUnicast() { newApplied[key] = true }` ([tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755), [tunnel.go:758](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:758)). With empty desired addrs, a failed `AddrDel` for `172.16.0.1/30` returns an empty map, so Path A deletes tracking and does not retry ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:293)). The fake confirms failed `AddrDel` leaves the address present ([iface_reuse_test.go:143](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/iface_reuse_test.go:143)). This must be fixed before implementation. The proposed retry test must use a non-link-local address, not only `fe80`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1325:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6963:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1327:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6971:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1329:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6982:- **MAJOR: Path A’s retry signal is broken for regular addresses.** The plan’s removal sketch relies on `len(remaining)>0` after `reconcileLinkAddrsLocked(..., nil, ...)` to retain `wgConfigured` for retry ([plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285), [plan.md:288](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:288)). But source only re-adds a failed stale delete to `newApplied` if the address is link-local: `if a.IP.IsLinkLocalUnicast() { newApplied[key] = true }` ([tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755), [tunnel.go:758](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:758)). With empty desired addrs, a failed `AddrDel` for `172.16.0.1/30` returns an empty map, so Path A deletes tracking and does not retry ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:293)). The fake confirms failed `AddrDel` leaves the address present ([iface_reuse_test.go:143](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/iface_reuse_test.go:143)). This must be fixed before implementation. The proposed retry test must use a non-link-local address, not only `fe80`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1330:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6984:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1332:./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6992:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1381:./docs/research/1919-wg-addr-route-prune/plan.md:140:| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1385:./docs/research/1919-wg-addr-route-prune/plan.md:198:Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1386:./docs/research/1919-wg-addr-route-prune/plan.md:204:   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1392:./docs/research/1919-wg-addr-route-prune/plan.md:219:     - On **`LinkByName` error**: gate on `isLinkNotFound(err)`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1393:./docs/research/1919-wg-addr-route-prune/plan.md:228:3. After the per-tunnel apply loop, set `t.wgConfigured = nextWG`
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1408:./docs/research/1919-wg-addr-route-prune/plan.md:270:across `clearLocked` (reset) and `ensureReconcileStateLocked` (lazy init).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1419:./docs/research/1919-wg-addr-route-prune/plan.md:352:// wgConfigured: WG tunnel names configured at the LAST Apply (plus
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1420:./docs/research/1919-wg-addr-route-prune/plan.md:356:wgConfigured map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1421:./docs/research/1919-wg-addr-route-prune/plan.md:359:`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1431:./docs/research/1919-wg-addr-route-prune/plan.md:406:oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1433:./docs/research/1919-wg-addr-route-prune/plan.md:413:        if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1437:./docs/research/1919-wg-addr-route-prune/plan.md:432:t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1439:./docs/research/1919-wg-addr-route-prune/plan.md:442:`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1440:./docs/research/1919-wg-addr-route-prune/plan.md:451:contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1454:./docs/research/1919-wg-addr-route-prune/plan.md:489:   FRESH manager (empty `wgConfigured`) with a wgN carrying addresses
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1466:./docs/research/1919-wg-addr-route-prune/plan.md:548:  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:1473:./docs/research/1919-wg-addr-route-prune/plan.md:626:// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2398:./pkg/routing/bond.go:28:	if err := b.clearLocked(); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2402:./pkg/routing/bond.go:110:	return b.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2403:./pkg/routing/bond.go:113:// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2404:./pkg/routing/bond.go:115:func (b *bondManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2414:./pkg/routing/vrf.go:151:// isLinkNotFound reports whether err is a "link not found" error
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2415:./pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2419:./pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2421:./pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2440:./pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2507:./pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2525:./pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2527:./pkg/routing/tunnel.go:927:// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2528:./pkg/routing/tunnel.go:931:// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2539:./pkg/routing/tunnel.go:1357:	return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2540:./pkg/routing/tunnel.go:1360:// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2541:./pkg/routing/tunnel.go:1368:func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2543:./pkg/routing/tunnel.go:1394:	// clearLocked drains every keepalive runner first
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2547:./pkg/routing/tunnel_reconcile_test.go:120:	// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2651:./pkg/routing/xfrm.go:27:	if err := x.clearLocked(); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2655:./pkg/routing/xfrm.go:104:	return x.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2656:./pkg/routing/xfrm.go:107:// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:2657:./pkg/routing/xfrm.go:109:func (x *xfrmManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3586:   147	type tunnelManager struct {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3610:   171		// ownedNames: ALL non-WireGuard tunnel names from the LAST Apply's
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3615:   176		ownedNames map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3636:   197		if t.ownedNames == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3637:   198			t.ownedNames = map[string]bool{}
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3769:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:3855:   571		case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4023:   264	**Pros**: symmetric with the existing `ownedNames` retry pattern; reuses
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4029:   270	across `clearLocked` (reset) and `ensureReconcileStateLocked` (lazy init).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4111:   352	// wgConfigured: WG tunnel names configured at the LAST Apply (plus
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4115:   356	wgConfigured map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4118:   359	`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4165:   406	oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4172:   413	        if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4191:   432	t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4201:   442	`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4210:   451	contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4248:   489	   FRESH manager (empty `wgConfigured`) with a wgN carrying addresses
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4307:   548	  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4420:   151	// isLinkNotFound reports whether err is a "link not found" error
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4424:   155	func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4509:/bin/bash -lc "rg -n \"func \\(t \\*tunnelManager\\) clearLocked|clearLocked\\(\" pkg/routing/tunnel.go pkg/routing/*.go" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4511:pkg/routing/xfrm.go:27:	if err := x.clearLocked(); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4512:pkg/routing/xfrm.go:104:	return x.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4513:pkg/routing/xfrm.go:109:func (x *xfrmManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4514:pkg/routing/bond.go:28:	if err := b.clearLocked(); err != nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4515:pkg/routing/bond.go:110:	return b.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4516:pkg/routing/bond.go:115:func (b *bondManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4517:pkg/routing/tunnel.go:1357:	return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4518:pkg/routing/tunnel.go:1368:func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4519:pkg/routing/tunnel.go:1357:	return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4520:pkg/routing/tunnel.go:1368:func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4534:   252	func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4554:   272		oldOwned := t.ownedNames
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4576:   294		t.ownedNames = next
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:4890:   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:5954:  1023		// whose LinkDel fails): it stays in ownedNames but never reaches
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:5965:  1034		// t.tunnels and ownedNames, not the success list alone).
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:5993:  1357		return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:5996:  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6000:  1364	// per-tunnel apply failure leaves the name in ownedNames but not in
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6004:  1368	func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6006:  1370		names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6010:  1374		for name := range t.ownedNames {
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6027:  1391		t.ownedNames = nil
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6030:  1394		// clearLocked drains every keepalive runner first
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6188:   927	// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6192:   931	// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:6633:State wiring in the plan maps cleanly onto the current manager layout: `Apply` already has the old/next ownership pattern, `ensureReconcileStateLocked` is the lazy-init point, and `clearLocked` resets reconcile maps. I’m checking the fake harness and the FRR/VRF claims for any source-grounded residuals before choosing the verdict.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7447:140:| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7667:Remaining finding: `AddrList` error fallback is not sound under r2’s “delete all non-link-local” contract. The plan says prune deletes every present non-link-local address, not just `applied` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:295)), matching current reconcile where `applied` gates only link-local deletion ([tunnel.go](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:737), [tunnel.go](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751)). But on `AddrList` failure the helper returns only `applied`, and explicitly returns empty/drop when `applied` is empty ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:370), [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:421)). Counterexample: stale non-link-local exists on removed `wgN`, `applied` is empty, transient `AddrList` fails; caller drops `wgConfigured`, so no retry and the stale address remains.
./docs/research/1919-wg-addr-route-prune/codex-plan-r2.md:7672:Remaining finding: `AddrList` error fallback is not sound under r2’s “delete all non-link-local” contract. The plan says prune deletes every present non-link-local address, not just `applied` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:295)), matching current reconcile where `applied` gates only link-local deletion ([tunnel.go](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:737), [tunnel.go](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:751)). But on `AddrList` failure the helper returns only `applied`, and explicitly returns empty/drop when `applied` is empty ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:370), [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:421)). Counterexample: stale non-link-local exists on removed `wgN`, `applied` is empty, transient `AddrList` fails; caller drops `wgConfigured`, so no retry and the stale address remains.
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:116:`clearLocked` (`:1086-1113`) resets `ownedNames/appliedAddrs/appliedRI`
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:117:to nil. The plan adds `wgConfigured=nil` there — required, else a
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:120:`ensureReconcileStateLocked` (`:139-152`) must init `wgConfigured` — plan
./docs/research/1919-wg-addr-route-prune/claude-smr-plan-r1.md:133:`wgConfigured` starts empty) is a real boundary. It is consistent with
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:40:* **Source Reality**: [pkg/routing/vrf.go:155](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L155) provides `isLinkNotFound(err)` to isolate link absence.
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:46:      if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/agy-plan-r1.md:79:* **Plan Claim**: §8 R5: "on a fresh daemon, `wgConfigured` is empty... same restart-adoption limitation the rest of the file has."
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:16:Context: issue #1919 — when an operator removes a WireGuard tunnel from config, the persistent wgN device keeps its manager-applied kernel addresses (and the issue claims FRR routes) because WG is excluded from the ownedNames removal diff in pkg/routing/tunnel.go (#1432 S2a persistent-device invariant) and address reconcile runs only for still-configured WG tunnels.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:19:- pkg/routing/tunnel.go (Apply ~163, applyWireguardTunLocked ~798, reconcileLinkAddrsLocked ~584, clearLocked ~1086, tunnelManager fields ~104)
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:25:1. Is Path A's wgConfigured diff correct and idempotent? Walk the prune loop across 3 commits (add, remove, remove-again). Does it ever double-prune or strand tracking?
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:105:   147	type tunnelManager struct {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:129:   171		// ownedNames: ALL non-WireGuard tunnel names from the LAST Apply's
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:134:   176		ownedNames map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:155:   197		if t.ownedNames == nil {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:156:   198			t.ownedNames = map[string]bool{}
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:200:   571		case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:350:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:613:    18	`wireguard`-mode tunnels from the `desired` set and from `ownedNames`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:648:    53	- It is **not in `ownedNames`**, so the `Apply` removal loop
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:716:   121	| `pkg/routing/tunnel.go:104-134` `tunnelManager` fields | `ownedNames`, `appliedAddrs[name]`, `appliedRI[name]` |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:718:   123	| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:745:   150	1. WG names are deliberately excluded from `ownedNames` and `desired`
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:776:   181	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:777:   182	to `ownedNames` but WG-only, and **never** feeding the `LinkDel` removal
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:782:   187	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:791:   196	     commit finds `name` no longer in old `wgConfigured`, so no-op).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:796:   201	     `wgConfigured` so the next commit retries (mirrors GRE
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:799:   204	3. After the per-tunnel apply loop, set `t.wgConfigured = wgDesired`
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:802:   207	**Pros**: symmetric with the existing `ownedNames` retry pattern; reuses
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:806:   211	**Cons**: one more reconcile map to keep in sync across `clearLocked`
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:890:   252	func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:910:   272		oldOwned := t.ownedNames
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:932:   294		t.ownedNames = next
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1140:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1227:   927	// in t.tunnels: clearLocked must not delete it on reload (AGY Hazard B
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1232:   931	// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1596:   264	// wgConfigured: WG tunnel names configured at the LAST Apply (plus
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1600:   268	wgConfigured map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1603:   271	`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1611:   279	oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1630:   298	t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1637:   305	`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1646:   314	contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1720:   388	  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:1798:   466	// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5344:/bin/bash -lc "rg -n \"func \\(t \\*tunnelManager\\) clearLocked|clearLocked\\(\" pkg/routing/tunnel.go" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5346:1357:	return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5347:1368:func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5369:  1357		return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5372:  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5376:  1364	// per-tunnel apply failure leaves the name in ownedNames but not in
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5380:  1368	func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5382:  1370		names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5386:  1374		for name := range t.ownedNames {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5403:  1391		t.ownedNames = nil
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5406:  1394		// clearLocked drains every keepalive runner first
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5532:  1357		return t.clearLocked()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5535:  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5539:  1364	// per-tunnel apply failure leaves the name in ownedNames but not in
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5543:  1368	func (t *tunnelManager) clearLocked() error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5545:  1370		names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5549:  1374		for name := range t.ownedNames {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5574:    86	set-diff against the previous DESIRED set (`ownedNames`, retained on a
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5744:   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:5745:   120		// Fresh manager (ownedNames empty) = restart adoption; tc.MTU == 0
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6472:   252	func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6492:   272		oldOwned := t.ownedNames
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6514:   294		t.ownedNames = next
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6570:   571		case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6589:/bin/bash -lc "rg -n \"func isLinkNotFound|isLinkNotFound\\(\" pkg/routing -g'*.go'" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6591:pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6592:pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6593:pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6594:pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6595:pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6596:pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6599:/bin/bash -lc 'rg --files pkg/routing | xargs rg -n "isLinkNotFound|not found|ErrNotFound"' in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6601:pkg/routing/tunnel.go:571:	case isLinkNotFound(lookupErr):
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6602:pkg/routing/tunnel.go:840:		if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6610:pkg/routing/routing_test.go:39:	// Return the real netlink not-found error so isLinkNotFound()
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6617:pkg/routing/vrf.go:151:// isLinkNotFound reports whether err is a "link not found" error
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6618:pkg/routing/vrf.go:155:func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6619:pkg/routing/vrf.go:206:			if !isLinkNotFound(kerErr) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6620:pkg/routing/vrf.go:263:			if !isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6632:   181	Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6633:   182	to `ownedNames` but WG-only, and **never** feeding the `LinkDel` removal
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6638:   187	   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6647:   196	     commit finds `name` no longer in old `wgConfigured`, so no-op).
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6652:   201	     `wgConfigured` so the next commit retries (mirrors GRE
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6655:   204	3. After the per-tunnel apply loop, set `t.wgConfigured = wgDesired`
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6663:   279	oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6682:   298	t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6685:   314	contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6703:   151	// isLinkNotFound reports whether err is a "link not found" error
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6707:   155	func isLinkNotFound(err error) bool {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6816:   176		ownedNames map[string]bool
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6865:   840			if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6961:- **MAJOR: Path A’s retry signal is broken for regular addresses.** The plan’s removal sketch relies on `len(remaining)>0` after `reconcileLinkAddrsLocked(..., nil, ...)` to retain `wgConfigured` for retry ([plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285), [plan.md:288](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:288)). But source only re-adds a failed stale delete to `newApplied` if the address is link-local: `if a.IP.IsLinkLocalUnicast() { newApplied[key] = true }` ([tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755), [tunnel.go:758](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:758)). With empty desired addrs, a failed `AddrDel` for `172.16.0.1/30` returns an empty map, so Path A deletes tracking and does not retry ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:293)). The fake confirms failed `AddrDel` leaves the address present ([iface_reuse_test.go:143](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/iface_reuse_test.go:143)). This must be fixed before implementation. The proposed retry test must use a non-link-local address, not only `fe80`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6963:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6971:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6982:- **MAJOR: Path A’s retry signal is broken for regular addresses.** The plan’s removal sketch relies on `len(remaining)>0` after `reconcileLinkAddrsLocked(..., nil, ...)` to retain `wgConfigured` for retry ([plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285), [plan.md:288](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:288)). But source only re-adds a failed stale delete to `newApplied` if the address is link-local: `if a.IP.IsLinkLocalUnicast() { newApplied[key] = true }` ([tunnel.go:755](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:755), [tunnel.go:758](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:758)). With empty desired addrs, a failed `AddrDel` for `172.16.0.1/30` returns an empty map, so Path A deletes tracking and does not retry ([plan.md:293](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:293)). The fake confirms failed `AddrDel` leaves the address present ([iface_reuse_test.go:143](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/iface_reuse_test.go:143)). This must be fixed before implementation. The proposed retry test must use a non-link-local address, not only `fe80`.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6984:- **MAJOR/MEDIUM: Path A can also strand tracking on transient `LinkByName` failure.** The plan treats any lookup failure as “device already gone” and drops tracking ([plan.md:197](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:197), [plan.md:285](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:285)). Source explicitly says only not-found is absence; EBUSY/transport errors are transient and must not be treated as gone ([vrf.go:151](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/vrf.go:151), [tunnel.go:558](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:558)). For WG removal, a transient lookup error would drop `appliedAddrs` and `wgConfigured`, leaving stale addresses with no future retry.
./docs/research/1919-wg-addr-route-prune/codex-plan-r1.md:6992:- **Restart adoption boundary is acceptable to defer.** The proposed `wgConfigured` and existing `appliedAddrs` are in-memory reconcile state ([tunnel.go:176](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/pkg/routing/tunnel.go:176)). A daemon that restarts after config removal has no old WG membership to diff. That limitation is real, but consistent with the chosen tracked-only design.
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:41:  The r2 plan gates `LinkByName` lookup errors on [isLinkNotFound](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L151):
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:45:      if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:68:   - At the end of `Apply`, `t.wgConfigured = nextWG` (which is `{"wg0": true}`).
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:76:   - `t.wgConfigured` is set to `nextWG` (empty).
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:78:   - `wgDesired` is empty. `oldWG = t.wgConfigured` (empty).
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:87:  Successfully handles lazy initialization of `t.wgConfigured` so direct constructor callers (tests and CLI) are unaffected:
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:89:  if t.wgConfigured == nil {
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:90:      t.wgConfigured = map[string]bool{}
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:93:* **`clearLocked`**:
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:94:  Correctly resets `t.wgConfigured = nil` alongside other tracking maps on a full reset, ensuring adoption can happen cleanly post-clear.
./docs/research/1919-wg-addr-route-prune/agy-plan-r2.md:113:- `TestWireguardRemovalDeviceNotFoundDropsTracking`: Validates `isLinkNotFound` handling.
./docs/research/1919-wg-addr-route-prune/plan.md:20:`wireguard`-mode tunnels from the `desired` set and from `ownedNames`:
./docs/research/1919-wg-addr-route-prune/plan.md:55:- It is **not in `ownedNames`**, so the `Apply` removal loop
./docs/research/1919-wg-addr-route-prune/plan.md:139:| `pkg/routing/tunnel.go:104-134` `tunnelManager` fields | `ownedNames`, `appliedAddrs[name]`, `appliedRI[name]` |
./docs/research/1919-wg-addr-route-prune/plan.md:141:| `pkg/routing/tunnel.go:1086-1113` `clearLocked` | delete-everything path (ClearTunnels); does NOT delete WG (not in tunnels/ownedNames) |
./docs/research/1919-wg-addr-route-prune/plan.md:168:1. WG names are deliberately excluded from `ownedNames` and `desired`
./docs/research/1919-wg-addr-route-prune/plan.md:199:Add a dedicated WG ownership set `wgConfigured map[string]bool` (analogous
./docs/research/1919-wg-addr-route-prune/plan.md:200:to `ownedNames` but WG-only, and **never** feeding the `LinkDel` removal
./docs/research/1919-wg-addr-route-prune/plan.md:205:   for each `name` in the **old** `wgConfigured` not in `wgDesired`:
./docs/research/1919-wg-addr-route-prune/plan.md:222:     - On **`LinkByName` error**: gate on `isLinkNotFound(err)`
./docs/research/1919-wg-addr-route-prune/plan.md:231:3. After the per-tunnel apply loop, set `t.wgConfigured = nextWG`
./docs/research/1919-wg-addr-route-prune/plan.md:267:**Pros**: symmetric with the existing `ownedNames` retry pattern; reuses
./docs/research/1919-wg-addr-route-prune/plan.md:273:across `clearLocked` (reset) and `ensureReconcileStateLocked` (lazy init).
./docs/research/1919-wg-addr-route-prune/plan.md:355:// wgConfigured: WG tunnel names configured at the LAST Apply (plus
./docs/research/1919-wg-addr-route-prune/plan.md:359:wgConfigured map[string]bool
./docs/research/1919-wg-addr-route-prune/plan.md:362:`ensureReconcileStateLocked`: add `if t.wgConfigured == nil { … }`.
./docs/research/1919-wg-addr-route-prune/plan.md:385://     the name in wgConfigured when retry is true.
./docs/research/1919-wg-addr-route-prune/plan.md:426:oldWG := t.wgConfigured
./docs/research/1919-wg-addr-route-prune/plan.md:433:        if isLinkNotFound(err) {
./docs/research/1919-wg-addr-route-prune/plan.md:452:t.wgConfigured = nextWG
./docs/research/1919-wg-addr-route-prune/plan.md:462:`clearLocked`: add `t.wgConfigured = nil` to the reset block (:1109).
./docs/research/1919-wg-addr-route-prune/plan.md:471:contains the removed name (we set `t.wgConfigured = nextWG` which only
./docs/research/1919-wg-addr-route-prune/plan.md:514:   FRESH manager (empty `wgConfigured`) with a wgN carrying addresses
./docs/research/1919-wg-addr-route-prune/plan.md:573:  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
./docs/research/1919-wg-addr-route-prune/plan.md:651:// tunnel REMOVED from the config is not torn down by clearLocked and
./docs/research/1884-tunnel-flap/claude-smr-plan-r4.md:32:  appliedRI lifecycle (removal, clearLocked) now matches appliedAddrs
./docs/research/1884-tunnel-flap/agy-plan-r9.md:66:* **Fix**: Use `isLinkNotFound(err)` from [vrf.go:L155](file:///home/ps/git/bpfrx/pkg/routing/vrf.go#L155) to prune tracking only on explicit not-found or success:
./docs/research/1884-tunnel-flap/agy-plan-r9.md:75:  } else if !isLinkNotFound(err) {
./docs/research/1884-tunnel-flap/codex-plan-r3.md:11:This needs a master-identity check before `LinkSetNoMaster`: only unbind if the current master is still the VRF that the tunnel manager previously bound. Also specify `appliedRI` cleanup on deletion/Clear; A.1 deletes `appliedAddrs` only ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:188)), and `clearLocked` cleanup names only `ownedNames`/`appliedAddrs` ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:198)).
./docs/research/1884-tunnel-flap/codex-plan-r3.md:17:- F1: closed by “`oldOwned := t.ownedNames` ... `ADOPTION authority`” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:167)) and “`adopting := !oldOwned[tc.Name]`” ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:226)).
./docs/research/1884-tunnel-flap/codex-plan-r3.md:27:3. ownedNames growth is bounded. `next` starts as desired only, and a removed name is retained only when `LinkByName` succeeds and `LinkDel` fails ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:170)). If the link is gone on the next apply, no retention path fires, so `t.ownedNames = next` drops it ([plan.md](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:190)).
./docs/research/1884-tunnel-flap/codex-plan-r3.md:29:5. No r1 closure is reopened by the MTU/AddrDel/ownedNames folds. The only blocker I found is the new `appliedRI` lifecycle hole above.
./docs/research/1884-tunnel-flap/codex-plan-r2.md:7:1. A.3 adoption is broken if implemented literally. A.1 assigns `t.ownedNames = desired` before the per-tunnel loop, then A.3 defines adoption as `not in t.ownedNames`. That makes every desired tunnel “owned” before the anchor branch runs, so restart adoption, WG→GRE, and foreign-compatible TUN adoption do not trigger MTU normalization. Evidence: [plan.md:153](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:153), [plan.md:166](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:166), [plan.md:213](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:213), [plan.md:324](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:324). Fix: snapshot `oldOwned := t.ownedNames` before overwriting, and use `oldOwned` for adoption decisions.
./docs/research/1884-tunnel-flap/codex-plan-r2.md:15:5. Removed-link ownership is dropped on `LinkDel` failure. A.1 ignores removal errors and then sets `ownedNames` to `desired`, so a removed tunnel whose `LinkDel` transiently fails is orphaned and not retried on later applies. Evidence: [plan.md:158](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:158), [plan.md:163](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:163), [plan.md:166](/home/ps/git/bpfrx/.claude/worktrees/1884-research/docs/research/1884-tunnel-flap/plan.md:166). Retain ownership until delete succeeds or lookup returns not found.
./docs/research/1884-tunnel-flap/claude-smr-plan-r1.md:37:`GetStatus`, and add `t.ownedNames map[string]bool` = all non-WG names
./docs/research/1884-tunnel-flap/claude-smr-plan-r1.md:39:loop). A.1 deletes `ownedNames \ desired`. Restart bootstrap: empty
./docs/research/1884-tunnel-flap/claude-smr-plan-r1.md:40:ownedNames ⇒ deletes nothing, same adoption semantics.
./docs/research/1884-tunnel-flap/claude-smr-plan-r3.md:13:  pseudo-code snapshots `oldOwned := t.ownedNames` before building
./docs/research/1884-tunnel-flap/claude-smr-plan-r3.md:27:- **appliedAddrs AddrDel-failure retention (F4) / ownedNames
./docs/research/1884-tunnel-flap/claude-smr-plan-r3.md:53:3. **ownedNames growth bound**: retention happens only inside the
./docs/research/1884-tunnel-flap/agy-plan-r1.md:62:#### Q1: Is removing `clearLocked()` from `Apply` safe for ALL callers?
./docs/research/1884-tunnel-flap/agy-plan-r1.md:65:* **Reasoning**: `clearLocked()` in [pkg/routing/tunnel.go:659-674](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L659-L674) only iterates over the `t.tunnels` tracked slice. It does not perform a wild kernel scan. 
./docs/research/1884-tunnel-flap/agy-plan-r1.md:67:  - For the CLI: `t.tunnels` is empty at startup, making `clearLocked()` a no-op anyway. 
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:36:**T3 — daemon restart ⇒ adopted, not flapped.** ownedNames empty ⇒
./docs/research/1884-tunnel-flap/claude-smr-code-r1.md:67:  after successful/no-op removal; clearLocked resets all three maps.
./docs/research/1884-tunnel-flap/agy-plan-r2.md:58:*   **`ownedNames` desired-set diff (A.1):**
./docs/research/1884-tunnel-flap/agy-plan-r2.md:59:    *   **Analysis:** No issues found. Because `Apply` ([tunnel.go:94-310](file:///home/ps/git/bpfrx/.claude/worktrees/1884-research/pkg/routing/tunnel.go#L94-L310)) does not return early on individual tunnel errors (it logs warnings and calls `continue`), `ownedNames` is guaranteed to be updated to the new `desired` set on every apply. When `Clear()` / `clearLocked()` is called, it correctly clears `ownedNames` and `appliedAddrs`.
./docs/research/1884-tunnel-flap/agy-plan-r2.md:85:*   **Q4: Any caller sequence where `ownedNames` goes stale relative to the kernel in a way that deletes a link the manager should not own?**
./docs/research/1884-tunnel-flap/agy-plan-r2.md:86:    *   **Answer:** No. In the daemon path, `Apply` overwrites `ownedNames` with the desired set unconditionally at entry, and `Clear()` clears it completely. In the CLI standalone path, the manager is instantiated fresh each run, so `ownedNames` starts empty and deletes nothing.
./docs/research/1884-tunnel-flap/plan.md:21:1. `clearLocked()` (tunnel.go:97) deletes EVERY tracked tunnel link and
./docs/research/1884-tunnel-flap/plan.md:49:symmetrically, and is deliberately untracked so `clearLocked` cannot
./docs/research/1884-tunnel-flap/plan.md:159:`Apply` no longer calls `clearLocked()`. The manager tracks
./docs/research/1884-tunnel-flap/plan.md:160:`t.ownedNames map[string]bool` — ALL non-WG tunnel names from the LAST
./docs/research/1884-tunnel-flap/plan.md:173:oldOwned := t.ownedNames // [r2: Codex F1] entry-time snapshot — the
./docs/research/1884-tunnel-flap/plan.md:195:    delete(t.appliedRI, name)    // [r3] ditto; clearLocked clears both
./docs/research/1884-tunnel-flap/plan.md:197:t.ownedNames = next
./docs/research/1884-tunnel-flap/plan.md:201:Restart bootstrap: empty `ownedNames` ⇒ deletes nothing ⇒ adoption.
./docs/research/1884-tunnel-flap/plan.md:203:between applies — identical to today's clearLocked-by-name behavior
./docs/research/1884-tunnel-flap/plan.md:205:`Clear()`/`clearLocked()` keep delete-everything semantics (clearLocked
./docs/research/1884-tunnel-flap/plan.md:206:additionally clears `ownedNames`/`appliedAddrs`); note
./docs/research/1884-tunnel-flap/plan.md:234:// ownership snapshot — A.1 has already rewritten t.ownedNames by the
./docs/research/1884-tunnel-flap/plan.md:454:  VRF device NOT-FOUND (`isLinkNotFound`-class, vrf.go:144-163 — the
./docs/research/1884-tunnel-flap/plan.md:461:`clearLocked` also `delete(t.appliedRI, name)` alongside
./docs/research/1884-tunnel-flap/plan.md:523:**A.8 — daemon-restart adoption falls out.** After restart `ownedNames`
./docs/research/1884-tunnel-flap/plan.md:550:gains `ownedNames`, `appliedAddrs`, `appliedRI`; `keepaliveRunner`
./docs/research/1884-tunnel-flap/plan.md:573:- **clearLocked semantics for explicit Clear()/shutdown unchanged**.
./docs/research/1884-tunnel-flap/plan.md:613:   apply (ownedNames vs success-set) → still deleted; removal whose
./docs/research/1884-tunnel-flap/plan.md:614:   LinkDel FAILS → name retained in ownedNames and deletion retried
./docs/research/1884-tunnel-flap/plan.md:690:- Stale anchors orphaned while the daemon was down (not in `ownedNames`,
./docs/research/1884-tunnel-flap/plan.md:722:best-effort + AddrDel-failure retention; A.6 field list; ownedNames
./docs/research/1884-tunnel-flap/plan.md:729:String() explicit); ownedNames growth bounded (not-found path prunes);
./docs/research/1884-tunnel-flap/claude-smr-plan-r6.md:31:  and EEXIST handling (A.3), ownedNames (A.1) are untouched by v6.
./docs/research/1884-tunnel-flap/claude-smr-plan-r9.md:44:nothing else moved. MTU, address, keepalive, ownedNames, reuse-check,
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:7:reviewers') are genuinely closed by the v2 text: A.1's ownedNames diff
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:20:name WAS in `ownedNames` at entry (same-lifetime re-apply with a
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:26:ownedNames snapshot, used by BOTH reuse paths (plain reuse and EEXIST
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:61:- **ownedNames vs Clear()**: `Apply → ClearTunnels → Apply` — clearLocked
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:62:  clears ownedNames per A.1, so the post-Clear Apply adopts instead of
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:65:- **gre→wireguard same-name flip**: name in ownedNames, absent from
./docs/research/1884-tunnel-flap/claude-smr-plan-r2.md:70:  identical to today's clearLocked-by-name behavior — no regression.
./docs/research/1884-tunnel-flap/agy-plan-r3.md:45:*   **(F1) Entry-time `oldOwned` Snapshot:** Sound. By freezing the adoption authority in `oldOwned` at `Apply` entry, we ensure subsequent writes to `t.ownedNames` within the desired loop do not affect adoption status or cause transient MTU updates.
./docs/research/1884-tunnel-flap/agy-plan-r3.md:49:*   **(F5) failed-LinkDel Retention:** Sound. Leaving failed deletes in `ownedNames` ensures retry on subsequent applies.
./docs/research/1884-tunnel-flap/agy-plan-r3.md:75:    1.  If a stale link fails to delete, `next[name] = true` keeps it in `t.ownedNames` for the next apply.
./docs/research/1884-tunnel-flap/agy-plan-r3.md:79:*   **Verdict:** Sound. Stale entries whose links disappear out-of-band are cleanly pruned from `t.ownedNames` on the subsequent apply.
./docs/pr/1698-routing-domain-managers/plan.md:200:type tunnelManager struct {

codex
Existing `reconcileLinkAddrsLocked` already treats non-link-local addresses as manager-owned device state and uses `appliedAddrs` only for the link-local gate, which matches r3’s helper wording. I’m checking the exact current control flow around `Apply`/clear now; then I should be able to return the requested single verdict.
exec
/bin/bash -lc "sed -n '724,785p' pkg/routing/tunnel.go | nl -ba -v 724" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   724	func (t *tunnelManager) reconcileLinkAddrsLocked(link netlink.Link, name string, addrs []string, applied map[string]bool, kind string) map[string]bool {
   725		want := make(map[string]bool, len(addrs))
   726		for _, addrStr := range addrs {
   727			addr, parseErr := netlink.ParseAddr(addrStr)
   728			if parseErr != nil {
   729				slog.Warn("invalid "+kind+" address",
   730					"name", name, "addr", addrStr, "err", parseErr)
   731				continue
   732			}
   733			want[addr.IPNet.String()] = true
   734		}
   735		newApplied := make(map[string]bool, len(want))
   736		existing := map[string]bool{}
   737		if list, listErr := t.ops.AddrList(link, netlink.FAMILY_ALL); listErr == nil {
   738			for i := range list {
   739				a := list[i]
   740				key := a.IPNet.String()
   741				existing[key] = true
   742				if want[key] {
   743					continue
   744				}
   745				if a.IP == nil {
   746					// Defensive: the pre-#1884 WG block only deleted
   747					// addresses with a non-nil IP; keep that byte-identical
   748					// (and never delete something we cannot classify).
   749					continue
   750				}
   751				if a.IP.IsLinkLocalUnicast() && (applied == nil || !applied[key]) {
   752					// Kernel-managed or foreign link-local: never delete.
   753					continue
   754				}
   755				if delErr := t.ops.AddrDel(link, &a); delErr != nil {
   756					slog.Warn("failed to remove stale "+kind+" address",
   757						"name", name, "addr", key, "err", delErr)
   758					if a.IP != nil && a.IP.IsLinkLocalUnicast() {
   759						newApplied[key] = true // retry next apply
   760					}
   761				} else {
   762					slog.Info("removed stale "+kind+" address",
   763						"name", name, "addr", key)
   764				}
   765			}
   766		}
   767		for _, addrStr := range addrs {
   768			addr, parseErr := netlink.ParseAddr(addrStr)
   769			if parseErr != nil {
   770				continue
   771			}
   772			key := addr.IPNet.String()
   773			if existing[key] {
   774				newApplied[key] = true
   775				continue
   776			}
   777			if addErr := t.ops.AddrAdd(link, addr); addErr != nil {
   778				slog.Warn("failed to add "+kind+" address",
   779					"name", name, "addr", addrStr, "err", addErr)
   780			} else {
   781				newApplied[key] = true
   782			}
   783		}
   784		return newApplied
   785	}

exec
/bin/bash -lc "sed -n '147,310p' pkg/routing/tunnel.go | nl -ba -v 147" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   147	type tunnelManager struct {
   148		ops       linkOps
   149		vrfBinder vrfBinder
   150	
   151		// prober performs the keepalive ICMP echo. nil → the production
   152		// icmpProber (lazily resolved by keepaliveProber). Tests inject a
   153		// deterministic fake (#1918).
   154		prober tunnelProber
   155	
   156		mu         sync.Mutex
   157		tunnels    []string                    // tunnels successfully applied this round (GetStatus source)
   158		keepalives map[string]*keepaliveRunner // tunnel name -> runner
   159	
   160		// linkGen is the per-tunnel monotonic generation counter (#1918 §6
   161		// Axis D, defense-in-depth recreate guard). The MAP structure is
   162		// mutated only under mu (by Apply, via bumpLinkGenLocked); the counter
   163		// values are *atomic.Uint64 so a keepalive runner can Load() them
   164		// lock-free at tick time without ever taking mu (AGY r5 deadlock
   165		// note). Apply bumps the counter on a tunnel link create/recreate so a
   166		// stale runner captured at the old generation drops its LinkSet*.
   167		linkGen map[string]*atomic.Uint64
   168	
   169		// Reconcile-in-place state (#1884). All lazily initialized by Apply.
   170		//
   171		// ownedNames: ALL non-WireGuard tunnel names from the LAST Apply's
   172		// DESIRED set (plus names whose removal LinkDel failed, retained for
   173		// retry). The removal diff and the adoption decision both key off
   174		// this — NOT off the success-tracked t.tunnels, whose
   175		// failure-continue paths can leave a live kernel link untracked.
   176		ownedNames map[string]bool
   177		// appliedAddrs: per tunnel, the address set this manager itself
   178		// ensured (successful adds + present-and-wanted + link-local whose
   179		// stale-delete failed). Gates stale LINK-LOCAL deletion: a
   180		// configured fe80 we applied is removable; the kernel's autoconf
   181		// fe80 is never touched.
   182		appliedAddrs map[string]map[string]bool
   183		// appliedRI: per tunnel, the routing-instance whose VRF this
   184		// manager successfully bound — or directly OBSERVED as the link's
   185		// master for a step-0a `routing-instances <ri> interface` list
   186		// bind. Invariant (#1884 r6-r8): a claim is only ever written from
   187		// a successful bind or a master observation, never an intent.
   188		// Unbind on config-wants-none is identity-gated against
   189		// vrf-<claim>.
   190		appliedRI map[string]string
   191	}
   192	
   193	// ensureReconcileStateLocked lazily initializes the reconcile maps so
   194	// directly-constructed managers (tests, façade) need no constructor
   195	// changes. Caller MUST hold mu.
   196	func (t *tunnelManager) ensureReconcileStateLocked() {
   197		if t.ownedNames == nil {
   198			t.ownedNames = map[string]bool{}
   199		}
   200		if t.appliedAddrs == nil {
   201			t.appliedAddrs = map[string]map[string]bool{}
   202		}
   203		if t.appliedRI == nil {
   204			t.appliedRI = map[string]string{}
   205		}
   206		if t.keepalives == nil {
   207			t.keepalives = map[string]*keepaliveRunner{}
   208		}
   209		if t.linkGen == nil {
   210			t.linkGen = map[string]*atomic.Uint64{}
   211		}
   212	}
   213	
   214	// linkGenForLocked returns the (lazily created) generation counter for a
   215	// tunnel name. Caller MUST hold mu.
   216	func (t *tunnelManager) linkGenForLocked(name string) *atomic.Uint64 {
   217		g, ok := t.linkGen[name]
   218		if !ok {
   219			g = &atomic.Uint64{}
   220			t.linkGen[name] = g
   221		}
   222		return g
   223	}
   224	
   225	// bumpLinkGenLocked advances a tunnel's generation token. Called by
   226	// Apply whenever it CREATES or RECREATES the kernel link for a tunnel,
   227	// so any keepalive runner still holding the previous generation drops
   228	// its netlink op (#1918 §6 Axis D defense-in-depth). Caller MUST hold
   229	// mu.
   230	func (t *tunnelManager) bumpLinkGenLocked(name string) {
   231		t.linkGenForLocked(name).Add(1)
   232	}
   233	
   234	// keepaliveProber resolves the prober used by keepalive goroutines: the
   235	// injected test fake when set, else the production datagram-ICMP prober.
   236	func (t *tunnelManager) keepaliveProber() tunnelProber {
   237		if t.prober != nil {
   238			return t.prober
   239		}
   240		return icmpProber{}
   241	}
   242	
   243	// Apply reconciles the kernel tunnel devices against the desired
   244	// config WITHOUT the historical clear-all + delete-and-recreate
   245	// (#1884): an untouched tunnel keeps its netdev (stable ifindex — no
   246	// FRR route churn, no userspace-dp TUN-reader death per commit, see
   247	// #1881), tunnels removed from config are deleted via a set-diff
   248	// against the previous desired set, and a device is recreated only
   249	// when the existing kernel link is genuinely incompatible. Keepalive
   250	// probes (legacy non-anchor branch only) are reconciled by identity
   251	// instead of being restarted every apply.
   252	func (t *tunnelManager) Apply(tunnels []*config.TunnelConfig) error {
   253		t.mu.Lock()
   254		defer t.mu.Unlock()
   255		t.ensureReconcileStateLocked()
   256	
   257		desired := make(map[string]bool, len(tunnels))
   258		for _, tc := range tunnels {
   259			// WireGuard TUNs stay untracked/persistent (#1432 S2a, AGY
   260			// Hazard B) and are excluded from the removal diff.
   261			if tc.Mode != "wireguard" {
   262				desired[tc.Name] = true
   263			}
   264		}
   265	
   266		// oldOwned is the ENTRY-TIME ownership snapshot — the adoption
   267		// authority for the per-tunnel loop below (#1884 r2 Codex F1: the
   268		// rewritten set would mark every desired tunnel "owned" and make
   269		// adoption unreachable). next starts as the desired set; removal
   270		// failures retain their names so the next Apply retries instead of
   271		// orphaning a live link (r2 Codex F5).
   272		oldOwned := t.ownedNames
   273		next := make(map[string]bool, len(desired))
   274		for name := range desired {
   275			next[name] = true
   276		}
   277		for name := range oldOwned {
   278			if desired[name] {
   279				continue
   280			}
   281			t.stopKeepaliveLocked(name)
   282			if link, err := t.ops.LinkByName(name); err == nil {
   283				if delErr := t.ops.LinkDel(link); delErr != nil {
   284					slog.Warn("failed to delete removed tunnel",
   285						"name", name, "err", delErr)
   286					next[name] = true // retain ownership; retry next apply
   287					continue
   288				}
   289				slog.Info("tunnel removed", "name", name)
   290			}
   291			delete(t.appliedAddrs, name)
   292			delete(t.appliedRI, name)
   293		}
   294		t.ownedNames = next
   295		t.tunnels = nil // success-tracked (GetStatus); rebuilt below
   296	
   297		for _, tc := range tunnels {
   298			// WireGuard TUNs are persistent (#1432 S2a, AGY Hazard B): never
   299			// delete-and-recreate on reload — that would flap wgN and destroy
   300			// its addresses + FRR routes every commit. applyWireguardTunLocked
   301			// reuses an existing wgN in place.
   302			if tc.Mode == "wireguard" {
   303				if err := t.applyWireguardTunLocked(tc); err != nil {
   304					slog.Warn("failed to apply wireguard tunnel",
   305						"name", tc.Name, "err", err)
   306				}
   307				continue
   308			}
   309			// Adoption = this manager did NOT own the name at the last
   310			// apply (daemon restart, wireguard→gre same-name flip, foreign

exec
/bin/bash -lc "sed -n '938,1025p' pkg/routing/tunnel.go | nl -ba -v 938" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   938	func (t *tunnelManager) applyWireguardTunLocked(tc *config.TunnelConfig) error {
   939		mtu := wgTunMTUForEndpoint(tc)
   940		link, err := t.ops.LinkByName(tc.Name)
   941		// Copilot C3: only reuse an existing link if it is actually a TUN/TAP.
   942		// A name collision with some other interface type (e.g. a leftover
   943		// dummy) must be deleted and recreated, not mutated — otherwise we'd
   944		// bring up + address + VRF-bind the wrong device, and the Rust side's
   945		// open_tun on the same name would then fail.
   946		mustCreate := err != nil
   947		if err == nil {
   948			tt, isTuntap := link.(*netlink.Tuntap)
   949			if !isTuntap || tt.Mode != netlink.TUNTAP_MODE_TUN {
   950				// Not a TUN (a TAP, or some other type entirely). The Rust
   951				// side opens it with IFF_TUN, so a TAP would fail there;
   952				// delete + recreate as a TUN rather than mutate the wrong
   953				// device (Codex r3 MINOR).
   954				slog.Info("replacing non-TUN link before wireguard tun create",
   955					"name", tc.Name, "type", link.Type())
   956				if delErr := t.ops.LinkDel(link); delErr != nil {
   957					return fmt.Errorf("replace non-tun wireguard link %s: %w", tc.Name, delErr)
   958				}
   959				mustCreate = true
   960			}
   961		}
   962		if mustCreate {
   963			// Create a persistent TUN. NonPersist:false keeps the netdev
   964			// alive after the creating fd closes, so a reload that does not
   965			// touch this device leaves it (and its routes) intact.
   966			tun := &netlink.Tuntap{
   967				LinkAttrs:  netlink.LinkAttrs{Name: tc.Name, MTU: mtu},
   968				Mode:       netlink.TUNTAP_MODE_TUN,
   969				Flags:      netlink.TUNTAP_NO_PI,
   970				Queues:     1,
   971				NonPersist: false,
   972			}
   973			if addErr := t.ops.LinkAdd(tun); addErr != nil {
   974				return fmt.Errorf("create wireguard tun %s: %w", tc.Name, addErr)
   975			}
   976			closeTuntapFiles(tun.Fds)
   977			link = tun
   978			// vishvananda/netlink creates a TUN via TUNSETIFF and may return
   979			// before the generic LinkAttrs.MTU is applied, leaving the kernel
   980			// device at its default MTU on first apply (Codex r4 MAJOR).
   981			// Set the MTU explicitly after create so the inner cap is live
   982			// immediately, not only after a later reload.
   983			if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
   984				slog.Warn("failed to set wireguard tun mtu on create",
   985					"name", tc.Name, "mtu", mtu, "err", mtuErr)
   986			}
   987			slog.Info("wireguard tun created", "name", tc.Name, "mtu", mtu)
   988		} else {
   989			// Reuse in place; reconcile the MTU if the config changed it
   990			// (AGY M4 / Copilot C4 — a stale MTU on reuse, including a
   991			// pre-created device, would otherwise persist).
   992			if link.Attrs().MTU != mtu {
   993				if mtuErr := t.ops.LinkSetMTU(link, mtu); mtuErr != nil {
   994					slog.Warn("failed to update wireguard tun mtu",
   995						"name", tc.Name, "mtu", mtu, "err", mtuErr)
   996				} else {
   997					slog.Info("wireguard tun mtu updated", "name", tc.Name, "mtu", mtu)
   998				}
   999			}
  1000			slog.Debug("wireguard tun reused", "name", tc.Name)
  1001		}
  1002	
  1003		if err := t.ops.LinkSetUp(link); err != nil {
  1004			slog.Warn("failed to bring up wireguard tun", "name", tc.Name, "err", err)
  1005		}
  1006	
  1007		// Symmetric address reconciliation (Copilot C5): because the device
  1008		// is persistent and never recreated, addresses removed from the config
  1009		// would otherwise survive every reload and keep being routed. Shared
  1010		// helper (#1884) with the per-link applied-address record (#1905) —
  1011		// the same configured-vs-autoconf link-local split as the GRE/IPIP
  1012		// branch: a CONFIGURED fe80 later removed from config is deleted
  1013		// (this manager applied it), while the kernel's autoconf fe80 — and
  1014		// any fe80 already present before this daemon's first apply
  1015		// (restart adoption pass, applied == nil) — is never touched.
  1016		// Because the wgN device persists when removed from config (S2a,
  1017		// see above), its appliedAddrs entry is retained with it so a later
  1018		// re-add keeps accurate tracking; S6 teardown (#1434) owns deleting
  1019		// both.
  1020		t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
  1021			link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
  1022	
  1023		if tc.RoutingInstance != "" {
  1024			if bindErr := t.vrfBinder.BindInterfaceToVRF(tc.Name, tc.RoutingInstance); bindErr != nil {
  1025				slog.Warn("failed to bind wireguard tun to VRF",

exec
/bin/bash -lc "sed -n '1360,1396p' pkg/routing/tunnel.go | nl -ba -v 1360" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
  1360	// clearLocked is the lock-free body of Clear. Caller must hold mu.
  1361	// Apply no longer uses it (#1884 reconcile-in-place); it remains the
  1362	// explicit delete-everything path for ClearTunnels. It deletes the
  1363	// UNION of the success-tracked list and the ownership set: a
  1364	// per-tunnel apply failure leaves the name in ownedNames but not in
  1365	// t.tunnels (failure-continue before finishTunnelLocked), and the
  1366	// delete-everything contract must still cover that live link (Codex
  1367	// PR #1903 r1 MINOR).
  1368	func (t *tunnelManager) clearLocked() error {
  1369		t.stopAllKeepalivesLocked()
  1370		names := make(map[string]bool, len(t.tunnels)+len(t.ownedNames))
  1371		for _, name := range t.tunnels {
  1372			names[name] = true
  1373		}
  1374		for name := range t.ownedNames {
  1375			names[name] = true
  1376		}
  1377		for name := range names {
  1378			link, err := t.ops.LinkByName(name)
  1379			if err != nil {
  1380				continue // already gone
  1381			}
  1382			if err := t.ops.LinkDel(link); err != nil {
  1383				slog.Warn("failed to delete tunnel", "name", name, "err", err)
  1384			} else {
  1385				slog.Info("tunnel removed", "name", name)
  1386			}
  1387		}
  1388		t.tunnels = nil
  1389		// Reset the reconcile state with the devices: a post-Clear Apply
  1390		// adopts whatever survives instead of trusting stale ownership.
  1391		t.ownedNames = nil
  1392		t.appliedAddrs = nil
  1393		t.appliedRI = nil
  1394		// clearLocked drains every keepalive runner first
  1395		// (stopAllKeepalivesLocked above), so no live runner holds a stale
  1396		// linkGen pointer; dropping the map is safe and prevents removed names

codex
One detail I checked: carrying `failed` into `appliedAddrs` after an `AddrDel` failure is intentional for link-locals and harmless for non-link-locals because the helper enumerates the kernel again next pass and deletes all non-link-locals regardless of the applied set. That closes the original retry-signal trap.
exec
/bin/bash -lc "sed -n '560,610p' docs/research/1919-wg-addr-route-prune/plan.md | nl -ba -v 560" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   560	  tunnel from config IS the operator declaring it gone; stripping its
   561	  addresses is the intended effect. Scope (corrected per r1 review, §4b):
   562	  the prune deletes ALL present non-link-local addresses (the manager
   563	  owns the device's non-link-local set, same as steady-state reconcile),
   564	  and only configured/applied link-locals; the kernel autoconf/foreign
   565	  fe80 is gated out by the shared link-local check.
   566	- **R2 — touching the wrong device** (Path B hazard): avoided by Path A
   567	  keying off the exact tracked name set, not netdev heuristics.
   568	- **R3 — retry storms on persistent AddrDel failure**: bounded by the
   569	  same retain-and-retry pattern GRE removal uses; each Apply does at
   570	  most one AddrDel attempt per residual address.
   571	- **R4 — interaction with #1918**: none (WG has no keepalive). Verified.
   572	- **R5 — interaction with restart adoption** (`appliedAddrs == nil`):
   573	  on a fresh daemon, `wgConfigured` is empty, so a WG tunnel removed
   574	  while the daemon was DOWN is not in `oldWG` → not pruned by this fix.
   575	  This is the **same restart-adoption limitation** the rest of the file
   576	  has (the manager only prunes what it tracked applying). Document as a
   577	  known boundary; full restart-time WG reconciliation is #1434 scope.
   578	  (A reviewer may ask for a restart-time sweep — explicitly defer.)
   579	
   580	---
   581	
   582	## 9. Validation plan
   583	
   584	- `make test` — Go unit tests (new + existing routing tests).
   585	- `go test ./pkg/routing/...` focused run.
   586	- `go vet ./pkg/routing/...`.
   587	- No smoke required for a control-plane address-reconcile change with no
   588	  dataplane/wire impact — but a manual incus check (configure WG tunnel
   589	  with an address, `ip addr show wgN`, remove from config + commit,
   590	  confirm address gone and link still present) is the acceptance demo
   591	  for the PR description. (Optional at `/engineer` time.)
   592	
   593	---
   594	
   595	## 10. Module-doc updates (part of the contract)
   596	
   597	- Update the `applyWireguardTunLocked` doc comment (`tunnel.go:784-797`)
   598	  to remove/replace the "leaks until ip link del or daemon restart"
   599	  S2a-limitation note (AGY M1) — it is now resolved for the
   600	  config-removal-while-running case; restate the remaining boundaries
   601	  (restart-time removal, VRF residual, link+peer kept).
   602	- Update any `docs/` tunnel/wireguard module doc that states the leak as
   603	  a known limitation. Grep `docs/` for "S2a", "wireguard", "AGY M1",
   604	  "leak" during `/engineer`; if none reference it, say so in review notes.
   605	- PR body: explicitly scope the "FRR routes" claim per §1a (clarified,
   606	  not code-fixed) so the issue's title is fully addressed.
   607	
   608	---
   609	
   610	## 11. Reviewer ledger

exec
/bin/bash -lc "sed -n '620,655p' docs/research/1919-wg-addr-route-prune/plan.md | nl -ba -v 620" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   620	```go
   621	desired := make(map[string]bool, len(tunnels))
   622	for _, tc := range tunnels {
   623	    if tc.Mode != "wireguard" {
   624	        desired[tc.Name] = true
   625	    }
   626	}
   627	```
   628	
   629	WG apply branch (`tunnel.go:208-219`):
   630	```go
   631	for _, tc := range tunnels {
   632	    if tc.Mode == "wireguard" {
   633	        if err := t.applyWireguardTunLocked(tc); err != nil {
   634	            slog.Warn("failed to apply wireguard tunnel", "name", tc.Name, "err", err)
   635	        }
   636	        continue
   637	    }
   638	    ...
   639	}
   640	```
   641	
   642	WG address reconcile (the asset we reuse on removal) (`tunnel.go:880-881`):
   643	```go
   644	t.appliedAddrs[tc.Name] = t.reconcileLinkAddrsLocked(
   645	    link, tc.Name, tc.Addresses, t.appliedAddrs[tc.Name], "wireguard tun")
   646	```
   647	
   648	Known-limitation comment to update (`tunnel.go:790-794`):
   649	```go
   650	// Known S2a limitation (AGY M1): because the device is untracked, a WG
   651	// tunnel REMOVED from the config is not torn down by clearLocked and
   652	// leaks until `ip link del` or daemon restart. S2a single-tunnel scope
   653	// accepts this in exchange for reload stability; multi-instance teardown
   654	// is owned by the S6 grammar work (#1434).
   655	```

codex
I found no behavioral counterexample in the r3 §5 flow. There is one stale explanatory signature earlier in the document, but it does not contradict the detailed helper/caller sketch that implementation should follow.
exec
/bin/bash -lc "sed -n '1,20p' docs/research/1919-wg-addr-route-prune/plan.md | nl -ba -v 1" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
     1	# Plan-of-action — #1919: WireGuard tunnel removal leaks kernel addresses (+ FRR routes claim)
     2	
     3	- **Issue**: #1919 — routing: removing a WireGuard tunnel leaks its kernel
     4	  addresses + FRR routes (persistent wgN bypasses address reconcile)
     5	- **Revision**: r3 (post-r2 Codex re-review — one residual MAJOR on the
     6	  AddrList-error fallback; fixed. r1 had 3 converged MAJORs, all resolved
     7	  in r2; r3 closes the last edge case)
     8	- **Branch**: `research/1919-wg-addr-route-prune` off `origin/master`
     9	  @ `ee3f336d3` (post-#1918, post-#1947)
    10	- **Status**: PLAN DRAFT — research-only; STOP at PLAN-READY
    11	- **Contract**: `/research`, NOT `/engineer`. No PR, no production source
    12	  touched. Deliverable = converged plan + 3 verdicts + issue comment.
    13	
    14	---
    15	
    16	## 1. Problem statement
    17	
    18	WireGuard TUN devices are intentionally **persistent** (#1432 S2a). In
    19	`pkg/routing/tunnel.go`, the reconcile-in-place `Apply` excludes
    20	`wireguard`-mode tunnels from the `desired` set and from `ownedNames`:

exec
/bin/bash -lc "sed -n '246,258p' docs/research/1919-wg-addr-route-prune/plan.md | nl -ba -v 246" in /home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune
 succeeded in 0ms:
   246	- **(a)** change `reconcileLinkAddrsLocked` to also record non-link-local
   247	  failed deletes — REJECTED: that function's return contract is consumed
   248	  by the GRE/anchor/still-configured-WG callers and is carefully
   249	  specified per #1884/#1905; widening its semantics risks rippling into
   250	  those paths.
   251	- **(b CHOSEN)** add a small, removal-only helper
   252	  `pruneAppliedAddrsLocked(link, name, applied) (failed map[string]bool)`
   253	  that:
   254	  1. `AddrList`s the device,
   255	  2. for each present address: skip autoconf/foreign link-local
   256	     (`a.IP.IsLinkLocalUnicast() && (applied==nil || !applied[key])` —
   257	     identical gate to `reconcileLinkAddrsLocked:611`), otherwise
   258	     `AddrDel`,

codex
PLAN-READY-WITH-NITS: [plan.md:252](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:252) still shows the old one-return helper signature in the r2 design note. §5’s actual helper/caller correctly use `(failed, retry)` and resolve the r2 MAJOR; no behavioral counterexample found.
tokens used
96,190
PLAN-READY-WITH-NITS: [plan.md:252](/home/ps/git/bpfrx/.claude/worktrees/1919-research-wg-addr-route-prune/docs/research/1919-wg-addr-route-prune/plan.md:252) still shows the old one-return helper signature in the r2 design note. §5’s actual helper/caller correctly use `(failed, retry)` and resolve the r2 MAJOR; no behavioral counterexample found.
