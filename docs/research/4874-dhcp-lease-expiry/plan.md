# Research Plan — #4874 DHCP client lease-lifecycle: expired v4/v6-PD retention & terminal-cleanup route/RA staleness

- **Issue:** #4874 (label `bug`; Codex review 175 findings C175-HC-078, C175-HC-079)
- **Branch:** `research/4874-dhcp-lease-expiry`
- **Base:** origin/master @ `4047fd553`
- **Revision:** r4-final (Codex r1 BLOCKER accepted — A re-opened as A2; SMR
  r1 F1/F2/F3 folded; B refined per Codex F5/F6; Codex r2 LOW nits 1/2 folded)
- **Status:** PLAN-READY — CONVERGED 2-of-3 (Codex r2 + SMR r2; AGY infra-down).
  Fix A2 + B; keep A1 — see §6
- **Mode:** `/research` — stops at PLAN-READY. No PR, no production code touched here.

> Standing line (per task): *If reviewers conclude the current documented
> behavior is correct, PLAN-KILL is an acceptable verdict.* Applied honestly:
> the **timeout-retention (A1)** is correct and stays; the **terminal-cleanup
> route/RA staleness (A2)** and the **zero-lifetime IA_PD re-advertisement (B)**
> are genuine bugs and are PLAN-READY.

---

## 1. Problem statement

#4874 bundles two Codex-175 claims. Research splits Defect A into two distinct
sub-behaviors that the original plan (r1) wrongly lumped together:

- **A1 — timeout-retention (INTENTIONAL).** A v4 client / v6-PD that reaches T2,
  times out, and re-acquires keeps the address + default route + PD installed
  during the (default *unlimited*) re-acquisition. This is the deliberate #1844
  last-known-gateway retention, documented in `pkg/dhcp/README.md`.
- **A2 — terminal-cleanup route/RA staleness (BUG, found in Codex plan-review
  r1, confirmed firsthand).** On a client's *terminal* exit
  (`retransmission-attempt N` exhaustion → `finishClient`) or an explicit
  DHCPNAK (`abandonLeaseAfterNAK`), the code removes the **netlink address** and
  the **lease/PD map entries** and fires `onGatewayChange`, but does **not**
  fire `scheduleRecompile`. Because the FRR DHCP default route and the v6 RA
  prefix are compiled state re-rendered *only* by `applyConfig` (driven by
  `onAddressChange`/`scheduleRecompile`), they stay **stale** — the default
  route keeps pointing at the withdrawn gateway and the RA sender keeps
  advertising the withdrawn prefix — until some unrelated commit recompiles.
  This is exactly the issue's "stale default routes / incorrect RA" blast radius.
- **B — zero-lifetime IA_PD stored + re-advertised (BUG).** A DHCPv6 server that
  revokes an IA_PD by returning the prefix with **valid-lifetime 0** while
  renewing IA_NA has the revoked prefix stored, kept by `DelegatedPrefixesForRA`,
  and re-advertised with the RA sender's default **30-day valid / 7-day
  preferred** lifetimes.

---

## 2. Current behavior (quantified, read + verified at `4047fd553`)

### 2.1 A1 — timeout-retention (intentional #1844)

`runDHCPv4` (≈735-903) / `runDHCPv6` (≈1148-1310): on a renew/rebind **timeout**
the inner loop `break`s and the outer loop re-enters a fresh DORA/Solicit with
`committed` (+`committedPDs`) still non-nil — address, FRR default route (admin
distance 200), lease-map entry, and PD map stay installed. Under the default
`retransmission-attempt 0` (unlimited) the outer loop retries forever, so the
binding persists for the whole server-outage window.

Documented deliberate: `pkg/dhcp/README.md` ("Lease records are NOT expired by
the wall clock … deliberately diverges from RFC 2131 §4.4.5 for the timeout
case"). **KEEP.** RFC-correctness here is a WAN-availability regression (§4 Path
A). No new evidence #1844 was wrong.

### 2.2 A2 — terminal cleanup withdraws the address but not the route/RA (BUG)

Verified firsthand:

- `removeAddress` (`dhcp.go` ≈1783-1801) does **only** `AddrDel`; its own comment
  says *"Routes are cleaned up via FRR config removal."* It never touches routes.
- `finishClient` (`dhcp.go` ≈386-410): deletes `m.leases[key]`, deletes v6
  `m.delegatedPDs[iface]`, calls `removeAddress`, then `m.fireGatewayChange()`.
  **No `scheduleRecompile`.**
- `abandonLeaseAfterNAK` (`dhcp.go` ≈914-925): `removeAddress` + delete lease +
  `fireGatewayChange`. **No `scheduleRecompile`.**
- `fireGatewayChange` → the daemon's second DHCP callback →
  `d.ipmon.NotifyNextHopChange()` (`daemon_run.go` ≈1475-1478). That only marks
  the ip-monitoring **overlay** dirty, and *only if* a `PreferredRoute` with a
  `NextHopInterface` references it (`ipmon.go` ≈291-315). It does **not**
  re-render the base DHCP default route.
- The base DHCP default route + classless routes are rendered **only** by
  `applyConfig` → `collectDHCPRoutes`/`renderDHCPDefaults` reading `Leases()`
  (`frr/config_render.go` ≈262-270); the RA prefix **only** by `buildRAConfigs`
  reading `DelegatedPrefixesForRA()` (`daemon_ra.go` ≈28-31). Both run on
  recompile, which finishClient/abandonLeaseAfterNAK never trigger.

**Consequences:**
- **`retransmission-attempt N` exhaustion:** the run-loop goroutine self-exits
  (not from an `applyConfig`), so nothing recompiles → the FRR `ip route
  0.0.0.0/0 <gw> 200` and (v6) the RA prefix persist **indefinitely** until an
  unrelated commit. This is the finding's "a finite v4 retry count can return
  from the goroutine with it still installed" — **partially true**: the *address*
  is removed (my r1 was right on that), but the *route / RA binding* is not.
- **DHCPNAK:** the README advertises "deconfigures the interface immediately"
  (#3956), but only the address is immediate; the default route is not withdrawn
  until the next successful DORA (or commit). During a server flap this is a real
  stale-route/blackhole window and contradicts the documented promise.
- **Config-removal path is fine:** `reconcileDHCPClients` runs from within
  `applyConfigLocked`, so the surrounding `applyConfig` re-renders FRR after
  `finishClient` — no staleness there. The exposure is the *non-applyConfig*
  terminal exits above.

**Fix (A2):** couple lease-record **removal** to a recompile, mirroring how
lease **installation** couples to it (`commitLease` fires `scheduleRecompile`).
This is the natural extension of the documented **#1844 coupling rule** ("any
lease-record removal MUST route through a path that fires `onGatewayChange`") —
A2 adds "…and `scheduleRecompile`, so the FRR route + RA withdraw in lock-step,
not just the ipmon overlay." See §4 Path C.

### 2.3 B — zero-lifetime IA_PD stored + re-advertised (BUG)

Chain (verified, matches Codex F4): `extractDelegatedPrefixes` (≈1651-1680)
appends every prefix with no `ValidLifetime==0` filter → `runDHCPv6` `if
len(prefixes)>0 { committedPDs = prefixes }` (≈1259/1295) → `commitLease` `if
len(prefixes)>0 { m.delegatedPDs[iface]=prefixes }` (`commit.go` ≈138-142) →
`DelegatedPrefixesForRA` (≈274-290) returns it → `daemon_ra.go:43` `if
mapping.ValidLifetime>0` leaves `RAPrefix.ValidLifetime=0` → `sender.go:753` `if
validLife<=0 { validLife=defaultValidLifetime }` = **2592000 (30d)** / 604800
(7d). Revoked prefix re-advertised 30-day.

Internally inconsistent: `selectIANAAddress` (≈1454, #4383/F-264) already skips
`ValidLifetime==0` for IA_NA. The IA_PD path lacks the symmetric guard. **No
test pins the current store-zero-lifetime behavior** (`TestExtractDelegatedPrefixes`
covers single/none/multiple non-zero only). Safe to change.

---

## 3. What the finding wants vs. what #1844 protects

- **Wants (A1):** RFC 2131 §4.4.5 wall-clock expiry. **#1844 protects:** WAN
  self-uplink availability across a transient server outage. → keep retention.
- **Wants (A2):** the default route / RA prefix withdrawn when the binding is
  actually torn down. **#1844 does NOT protect** re-advertising a route/prefix
  after its owning lease was deleted — that is an unintended recompile-coupling
  gap, not a deliberate retention. → fix.
- **Wants (B):** treat valid-lifetime-0 IA_PD as a withdrawal. **#1844/README
  protects** only the *absent*-IA_PD retain rule, not re-advertising an
  explicitly-revoked prefix. → fix.

---

## 4. Multiple Path Options

### Path A — full RFC clock-expiry (A1 → expire on the wall clock)
Add a lease-lifetime timer; on expiry deconfigure address+route+PD and re-acquire.
- **RFC:** full. **WAN-availability risk: HIGH** — reverses #1844; a server reboot
  longer than the lease blackholes the firewall's own uplink + ip-monitoring +
  FRR default. **Blast radius:** largest (timers in both families, coupling rule).
- **Verdict:** rejected as default — overturns a documented, reviewed choice with
  no evidence it was wrong. (A knob remains a *possible* future issue, not #4874.)

### Path A′ (middle) — expire the ADDRESS but keep the ROUTE
- **Rejected for the current architecture, but not "impossible."** In xpf today
  the DHCP default route is rendered from the *lease* and resolves through the
  interface address's connected route; deleting the address removes the on-link
  foundation the route needs, and the route itself lives in FRR config, so a
  clean "address-gone / route-kept" split would need explicit onlink/host-route
  plumbing that does not exist. So A′ collapses into Path A or the retain default.
  (Softened per Codex F7: #1844 is a *current* tradeoff, not settled forever —
  the duplicate-allocation risk under unlimited retry is real; a future knob may
  revisit it. Out of scope for #4874.)

### Path B — do nothing / PLAN-KILL the whole issue
- Correct **only** for A1. Ignores A2 (real recompile-coupling bug affecting even
  the default NAK path) and B (real RFC 8415 bug). Rejected as the whole answer.

### Path C — Fix A2 + B, keep A1  ← RECOMMENDED
**A2 fix — couple removal to recompile.** Make the terminal removal paths
(`finishClient`, `abandonLeaseAfterNAK`, and the inner-loop `ctx.Done` inline
deletes) fire `scheduleRecompile` (the debounced `onAddressChange`) **in addition
to** `onGatewayChange`, so `applyConfig` re-renders FRR (withdraws the DHCP
default/classless routes) and rebuilds RA (drops the withdrawn PD). Symmetry
argument: installation already couples to `scheduleRecompile` via `commitLease`;
removal must too. Implementation notes for `/engineer`:
  - The 2 s debounce + the daemon's "recompile skips reconcile when the binding
    plan is unchanged" absorbs the redundant fire on the *config-removal*
    (Reconcile-driven) path, which is already inside `applyConfig` — so an extra
    scheduled recompile there coalesces to a cheap no-op and does **not**
    re-enter/deadlock `applySem` (scheduleRecompile only arms a timer; the
    callback runs on its own goroutine, not inline).
  - Preserve the #1844 coupling-rule ordering: address removed → maps deleted →
    `onGatewayChange` → `scheduleRecompile`.
  - Update `pkg/dhcp/README.md` to extend the coupling rule to recompile and to
    correct the "NAK deconfigures immediately" wording (route now withdrawn too).

**B fix — explicit-withdrawal semantics for IA_PD.** Partition each reply into
`live` (vlt>0) and `withdrawn` (vlt==0); carry a signal so `commitLease` applies
a **per-prefix** reconcile rather than a blunt clear-all (refined per Codex F5):

| Reply contents (IA_PD)                          | New stored PD set |
|-------------------------------------------------|-------------------|
| ≥1 live prefix                                   | `(prior \ withdrawn) ∪ live` → in practice = `live` (servers echo all held PDs on RENEW, `renew.go` ≈146-159) |
| 0 live, ≥1 explicitly withdrawn (vlt==0)         | `prior \ withdrawn` (remove only the zeroed prefixes; usually empties, but does **not** over-withdraw a co-held prefix the reply merely omitted) |
| 0 prefixes at all (absent / empty IA_PD)         | `prior` unchanged (retain — #1844 anti-outage) |

  - The signal is **"saw an explicit zero-lifetime prefix"**, not "any OptIAPD
    present": an empty IA_PD / NoPrefixAvail is ambiguous and stays on the retain
    path (Codex F5 + SMR F2).
  - **Acquire-path (Codex F6 + r2-nit-1):** on initial acquire, if the reply
    yields no IA_NA address AND no *live* prefix (only withdrawn PDs), it must be
    treated as an acquisition failure and retried — NOT settled into the default
    1 h lease (`dhcp.go` ≈1548). The guard must count *live* prefixes
    **regardless of `wantNA`**: a PD-only client has `wantNA=false`, so the
    current narrow `wantNA && !addr.IsValid() && wantPD && len(prefixes)==0`
    shape (≈1526) would let it fall through. Count live PDs whenever no IA_NA
    address is present, mirroring `selectIANAAddress`.
  - **Local PD state (Codex r2-nit-2):** `runDHCPv6` currently only refreshes
    `committedPDs` when `len(prefixes)>0` (≈1213/1259/1295). After a withdrawal
    reconcile it MUST update `committedPDs` to the *reconciled* set (which may be
    empty or smaller); otherwise the next RENEW echoes a withdrawn prefix via
    `renew.go` ≈147 and the server may re-grant it. Update `committedPDs` to the
    reconcile result on every commit, not only the non-empty case.
  - Clearing/withdrawing fires `scheduleRecompile` so RA reconverges (and A2's fix
    means a terminal exit also withdraws it).

- **RFC:** A2 + B fully conformant; A1 stays a documented deliberate divergence.
- **LAN/WAN risk:** correct-direction and bounded. A2 only withdraws bindings
  whose lease was *already* deleted (no new WAN exposure — it makes teardown
  match the address). B withdraws only on an *explicit* server statement.
- **Blast radius:** `pkg/dhcp` (`finishClient`, `abandonLeaseAfterNAK`, the
  ctx.Done deletes, `parseV6Reply`, `dhcpv6Result`, `commitLease`), `README.md`,
  tests. RA/daemon/FRR consumers unchanged (they already re-render on recompile).
- **Verdict:** ship.

---

## 5. Blast radius / affected files (Path C)

- `pkg/dhcp/dhcp.go` — A2: `finishClient`, `abandonLeaseAfterNAK`, inner-loop
  `ctx.Done` delete sites fire `scheduleRecompile`. B: `parseV6Reply` (partition
  `live`/`withdrawn` + `sawWithdrawal`), `dhcpv6Result` (add fields), `runDHCPv6`
  commit guards, acquire-path rejection.
- `pkg/dhcp/commit.go` — `commitLease` per-prefix PD reconcile (store live /
  remove withdrawn / retain on absent).
- `pkg/dhcp/README.md` — extend the #1844 coupling rule to `scheduleRecompile`;
  correct the "NAK deconfigures immediately" wording; document the zero-lifetime
  IA_PD withdrawal next to the #4383 IA_NA note.
- `pkg/dhcp/dhcp_test.go` / `commit_test.go` / `gateway_hook_test.go` — new tests
  (§7).
- **Unchanged:** `pkg/daemon/daemon_ra.go`, `pkg/ra/sender.go`,
  `pkg/frr/config_render.go`, `pkg/ipmon` — all already re-render on recompile;
  A2 makes the recompile fire.

---

## 6. Recommendation

**PLAN-READY (Path C).**
- **A1 — keep.** Timeout-retention is the deliberate #1844 last-known-gateway
  design. RFC clock-expiry (Path A) is a WAN-availability regression with no new
  evidence it is warranted.
- **A2 — fix.** Terminal-cleanup (`finishClient` max-attempts) and NAK
  (`abandonLeaseAfterNAK`) remove the address but leave the FRR default route and
  v6 RA prefix stale because they never `scheduleRecompile`. Couple removal to
  recompile (extend the #1844 coupling rule). This closes the issue's "stale
  default routes / incorrect RA" and makes the documented immediate-NAK claim
  true for the route.
- **B — fix.** Zero-valid-lifetime IA_PD is an RFC 8415 withdrawal; today it is
  stored and re-advertised 30-day. Add per-prefix withdrawal semantics
  (withdrawal-vs-silence) + the acquire-path all-withdrawn rejection.

This supersedes plan r1's "PLAN-KILL A" — Codex plan-review r1 correctly found
the A2 recompile-coupling gap my SMR r1 missed (self-correction recorded in
`claude-smr-plan-r2.md`).

---

## 7. Test plan (for `/engineer`)

A2 (unit, `pkg/dhcp`, no traffic — use the netlink/recompile seams):
- `retransmission-attempt 1`, acquire once, force the re-acquire to exhaust →
  goroutine exits → assert `scheduleRecompile`/`onAddressChange` fired (route/RA
  re-render requested), not just `onGatewayChange`.
- DHCPNAK in RENEWING → assert `onAddressChange` fired (route withdrawn), address
  removed, lease deleted (extends `gateway_hook_test.go`).
- Reconcile-removal path → still exactly one recompile (no double/no deadlock).

B (unit):
- IA_PD present, valid-lifetime 0 ⇒ 0 live + `sawWithdrawal`; `delegatedPDs`
  cleared; `DelegatedPrefixesForRA()` empty; recompile fired.
- No IA_PD option ⇒ prior PDs retained (anti-outage regression guard).
- Mixed {live /48, withdrawn /56} ⇒ only /48 retained.
- Multi-PD partial withdrawal: prior {/48,/56}; reply withdraws /56 only, omits
  /48 ⇒ result {/48} (per-prefix, not clear-all) — the Codex-F5 guard.
- Acquire with only withdrawn PDs + no IA_NA ⇒ acquisition failure/retry, no
  empty 1 h lease — **including a PD-only client (`wantNA=false`)** so the guard
  cannot fall through (Codex F6 + r2-nit-1).
- After a withdrawal reconcile, the NEXT RENEW must NOT echo the withdrawn prefix
  — assert `committedPDs`/the built RENEW IA_PD reflects the reconciled set, not
  the pre-withdrawal set (Codex r2-nit-2).
- `buildRAConfigs` with a withdrawn PD ⇒ no `RAPrefix` emitted (end-to-end).

No cluster smoke required — control-plane only; `make test` + new units suffice
for `/research`. `/engineer` decides final smoke scope.

---

## 8. Risks & mitigations

- **R1 (A2) — extra recompile churn.** Mitigation: debounced `scheduleRecompile`
  + "skip reconcile when binding plan unchanged" coalesces the redundant
  config-removal-path fire; timer-based, no inline `applySem` re-entry.
- **R2 (B) — over-withdraw on a co-held prefix the reply omitted.** Mitigation:
  per-prefix reconcile (`prior \ withdrawn`), never blunt clear-all (Codex F5).
- **R3 (B) — flapping server (vlt oscillates).** Accepted MINOR: RFC-correct to
  follow the server; strictly better than 30-day masking; recompile is debounced.
- **R4 (B) — acquire settles into empty lease.** Mitigation: reject all-withdrawn
  acquire (Codex F6); mirror `selectIANAAddress`.
- **R5 — scope creep into Path A (clock-expiry).** Out of scope; A1 retention
  stays. A2 is only teardown-coupling, not wall-clock expiry.

---

## 9. Rollback

Pure `git revert`. No persisted state or migration — PD/lease maps are in-memory,
FRR/RA re-render from live state on the next recompile.

---

## 10. Open questions for reviewers

1. A2 fix seam: is firing `scheduleRecompile` from the removal paths the right
   mechanism, or should a scoped route+RA withdrawal bypass a full recompile?
   (Recompile is simplest and matches installation's coupling; the debounce
   bounds churn.)
2. A2 scope: include the inner-loop `ctx.Done` inline-delete sites, or only the
   two non-applyConfig terminal owners (`finishClient`, `abandonLeaseAfterNAK`)?
3. B multi-PD reconcile: is `prior \ withdrawn ∪ live` the agreed rule, given
   servers echo all held PDs on RENEW (so `live` is usually authoritative)?

---

## 11. Reviewer verdicts (per round)

- **Round 1 — Claude SMR** (`claude-smr-plan-r1.md`): PLAN-READY-WITH-NITS; A=keep,
  B=fix. **Superseded** — missed the A2 recompile-coupling gap.
- **Round 1 — Codex** (`codex-plan-r1.md`): **PLAN-KILL** the r1 plan; A=fix/re-open
  (BLOCKER: terminal cleanup + NAK leave FRR route / RA prefix stale, no
  `scheduleRecompile`), B=fix. Findings F5 (per-prefix, not clear-all) + F6
  (acquire-path rejection) folded into r3.
- **Round 2 — Claude SMR** (`claude-smr-plan-r2.md`): **PLAN-READY** on r3;
  self-correction accepting A2. A1 keep, A2 fix, B fix.
- **Round 2 — Codex** (`codex-plan-r2.md`): **PLAN-READY-WITH-NITS** on r3. A1
  keep, A2 fix, B fix. Confirmed A2 closes the stale FRR/RA gap and
  `scheduleRecompile` (a `time.AfterFunc`, `dhcp.go` ≈1805) introduces no inline
  `applySem` re-entry; "found no remaining lease/PD delete path outside the r3 A2
  scope." Two LOW implementation nits (acquire guard counts live PDs regardless
  of `wantNA`; `runDHCPv6` updates `committedPDs` to the reconciled set) folded
  into §4/§7 for `/engineer` — neither is a plan blocker.
- **CONVERGED:** 2-of-3 PLAN-READY (Codex r2 + Claude SMR r2), identical
  per-defect verdicts (A1 keep / A2 fix / B fix). **AGY infra-down** for this run
  → 2-of-3 convergence per `feedback_codex_infra_must_retry` (AGY-alone-never;
  the two live reviewers are Codex + Claude SMR).
