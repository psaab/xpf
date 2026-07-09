# Claude SMR — hostile plan review, #4874 (round 1)

**Reviewer stance:** adversarial. Goal: break the plan, not bless it. I
re-read the source at `origin/master:4047fd553` independently rather than
trusting the plan's line cites.

**Overall verdict (r1): PLAN-READY-WITH-NITS.** The split recommendation
(KILL A / SHIP B) is correct in direction. Three findings must be folded into
r2 before I sign PLAN-READY clean: one substantive (the task-requested
"expire-address-retain-route" middle path is under-analyzed and must be
explicitly disposed of), one tightening the B fix seam, one minor.

Per-defect: **A → keep (PLAN-KILL).** **B → fix (PLAN-READY).**

---

## Independent verification of the load-bearing claims

### C1 — "finite-retry / cancel exits do NOT leak the binding" — CONFIRMED TRUE
Traced `Start` (`dhcp.go` ≈345-360): the goroutine runs
`defer close(dc.done)` then `defer m.finishClient(key, dc)`. On the
`runDHCPv4` maxAttempts branch (`attempt >= maxAttempts { return }`,
≈771-775), control returns and `finishClient` (≈386-410) runs. At that point
`m.leases[key]` still holds the last `committed` lease — the only sites that
`delete(m.leases,key)` are the inner-loop `ctx.Done` branches (which `return`
without reaching the acquire) and `abandonLeaseAfterNAK`; the T2-timeout `break`
does **not** delete. So `finishClient` reads a non-nil lease, calls
`removeAddress`, deletes `leases` + (v6) `delegatedPDs`, and fires
`onGatewayChange`. The finding's "a finite v4 retry count can even return from
the goroutine with it still installed" is **false**. Defect A's finite-retry
leak claim does not stand.

### C2 — Defect A's *substance* (retention during unlimited re-acquisition) is REAL but INTENTIONAL — CONFIRMED
The plan is honest here (§2.1 "Net Defect-A reality"). Under the default
`retransmission-attempt 0` the outer acquire loop retries forever with the old
address/route/lease-map installed. That is a real duplicate-allocation surface —
but it is precisely the documented #1844 last-known-gateway retention
(`README` "Lease records are NOT expired by the wall clock … deliberately
diverges from RFC 2131 §4.4.5 for the timeout case"). Not a bug; a reviewed
tradeoff. KILL-A holds.

### C3 — Defect B end-to-end — CONFIRMED REAL
`extractDelegatedPrefixes` (≈1651-1680) appends every prefix with no
`ValidLifetime==0` filter → `runDHCPv6` `if len(renewed.prefixes) > 0 {
committedPDs = renewed.prefixes }` (≈1258) replaces with the zero-lifetime
prefix → `commitLease` `if len(prefixes) > 0 { m.delegatedPDs[iface]=prefixes }`
stores it → `DelegatedPrefixesForRA` (≈274) returns it → `daemon_ra.go:43`
`if mapping.ValidLifetime > 0` is false so `RAPrefix.ValidLifetime` stays 0 →
`sender.go:753` `if validLife <= 0 { validLife = defaultValidLifetime }`
(2592000 = 30d). The revoked prefix IS re-advertised at 30-day valid / 7-day
preferred. No filter anywhere in the chain. Confirmed. And `selectIANAAddress`
(≈1454) already does `if iaaddr.ValidLifetime == 0 { continue }` for IA_NA
(#4383) — so the IA_PD omission is a real internal inconsistency, exactly as the
plan argues.

### C4 — "withdrawal vs silence" subtlety — CONFIRMED, and it is the crux
A naive `if p.ValidLifetime==0 { continue }` inside `extractDelegatedPrefixes`
turns a present-but-all-zero reply into `len==0`, which then hits the
`len(prefixes)>0`-guarded store as a **no-op** → the previously stored prefix is
**retained** → the withdrawal is silently ignored. So the plan is right that a
one-line filter is insufficient and a presence/withdrawal signal is required.

---

## Findings to fold into r2

### F1 (MAJOR) — the task's "expire-address-retain-route" middle path is not disposed of
The research task explicitly asked for a middle path "(e.g. expire the ADDRESS
but retain the gateway route, or a config knob)." The plan renamed the A/B/C
options and folded this into a hand-wave ("optionally expose an opt-in knob
later"). A hostile reader will call this dodging Defect A. **The plan must
explicitly analyze and reject (or accept) expire-address-retain-route on the
merits.** My analysis, which the plan should adopt:

> Removing the local interface address while keeping the default route is
> **technically incoherent** on Linux. The DHCP-learned default route resolves
> its next-hop through the on-link connected route that the interface address
> installs; drop the address and the connected route goes with it, so the
> gateway's link-layer resolution and ip-monitoring's next-hop reachability
> probe both break — you destroy the very route you tried to preserve. This is
> why #1844 retains the *whole* binding (address+route) rather than splitting
> them. The middle path is therefore rejected not for effort but for
> correctness: address and route cannot be cleanly decoupled here.

That *strengthens* KILL-A (full retention is the coherent choice), so folding it
in makes the plan more defensible, not less.

### F2 (MINOR→tightening) — the B signal should be "saw an explicit zero-lifetime prefix", not "iapdPresent"
`iapdPresent` (any OptIAPD in the reply) over-triggers: an IA_PD option carrying
**no** prefixes (e.g. a NoPrefixAvail status) is ambiguous and the conservative
current behavior (retain) is fine — it is NOT the Defect-B scenario. The precise,
lower-blast-radius signal is `sawWithdrawal := any IA_PD prefix with
ValidLifetime == 0`. Decision table for r2:

| Reply                                   | Action  |
|-----------------------------------------|---------|
| ≥1 live prefix (vlt>0)                   | store live (replaces; drops any co-reported withdrawn) |
| 0 live, ≥1 withdrawn (vlt==0)            | **clear** `m.delegatedPDs[iface]` (+ recompile) |
| 0 prefixes at all (absent / empty IA_PD) | retain (unchanged) |

This keeps the fix inside `parseV6Reply`/`commitLease` and never touches the
empty-IA_PD ambiguous case. Note the "≥1 live" row already handles partial
withdrawal (withdraw /56, keep /48) for free by storing only live prefixes.

### F3 (MINOR) — name RA-flap under a lifetime-oscillating server
If a broken server alternates vlt>0 / vlt==0 for the same prefix across renews,
the fix will advertise→withdraw→advertise on the LAN (RA churn). This is
RFC-correct (follow the server) and strictly better than masking a real
withdrawal for 30 days, but the plan should name it as an accepted minor and
note that a content-identical retain reply does not fire (the churn only tracks
genuine server oscillation). No debounce needed — RA reconvergence is cheap and
`scheduleRecompile` is already debounced upstream.

---

## Things I tried to break and could not

- **Session-sync / cluster blast radius for B:** `delegatedPDs` is per-node
  in-memory, rebuilt from replies; RA is per-node. No HA session-sync coupling.
  Clean.
- **Acquire-path regression from the B signal:** on initial acquire
  `committedPDs` is empty, so a "clear" branch is a no-op. Covered by the
  "absent IA_PD retains" test the plan already lists.
- **v4 scope creep:** B is v6-PD-only; no v4 code changes. Correct.
- **Rollback:** pure in-memory, `git revert` restores exactly. Correct.

---

## Verdict

**PLAN-READY-WITH-NITS.** Fold F1 (dispose of expire-address-retain-route on
correctness grounds), F2 (tighten the signal to `sawWithdrawal`), F3 (name the
RA-flap minor) into r2 and I sign **PLAN-READY**: **Defect A PLAN-KILL** (the
retention is intentional #1844 design and the finite-retry sub-claim is false),
**Defect B PLAN-READY** (fix the zero-valid-lifetime IA_PD withdrawal, preserving
the absent-IA_PD retain rule).
