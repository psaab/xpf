# Research Plan — #4874 DHCP client lease-lifecycle: expired v4/v6-PD retention vs. RFC expiry

- **Issue:** #4874 (label `bug`; Codex review 175 findings C175-HC-078, C175-HC-079)
- **Branch:** `research/4874-dhcp-lease-expiry`
- **Base:** origin/master @ `4047fd553`
- **Revision:** r2 (post round-1 Codex + Claude-SMR)
- **Status:** PLAN-READY (split verdict) — see §6
- **Mode:** `/research` — stops at PLAN-READY. No PR, no production code touched here.

> Standing line (per task): *If reviewers conclude the current documented
> behavior is correct, PLAN-KILL is an acceptable verdict.* This plan applies
> that literally: it PLAN-KILLs Defect A (documented, deliberate) and
> PLAN-READYs Defect B (a genuine, separable RFC-8415 conformance bug).

---

## 1. Problem statement

#4874 bundles two DHCP-client lease-lifecycle claims from Codex review 175:

- **Defect A (C175-HC-078):** a v4 client that reaches T2, gets no reply, and
  hits lease expiry restarts DORA/Solicit but "never first removes the old
  netlink address / default route, lease-map entry, or delegated-prefix map."
  The expired binding is retained and exposed "indefinitely"; the finding also
  asserts "a finite v4 retry count can even return from the goroutine with it
  still installed."

- **Defect B (C175-HC-079):** when a DHCPv6 server revokes an IA_PD by returning
  the prefix with **valid-lifetime 0** while renewing an IA_NA, the client stores
  the zero-lifetime prefix, `commitLease` replaces the prior (nonempty) PD slice,
  `DelegatedPrefixesForRA` keeps returning it, and the RA path re-advertises the
  revoked prefix with default **30-day valid / 7-day preferred** lifetimes.

The two are NOT the same class of problem. Defect A is a **deliberate,
documented WAN-availability design** (#1844). Defect B is a **genuine RFC 8415
conformance bug** that is *inconsistent with the code's own IA_NA handling*
(#4383). This plan researches both to a converged, differentiated verdict.

---

## 2. Current behavior (quantified, read at `4047fd553`)

### 2.1 Defect A — v4/v6 timeout-expiry retention (the #1844 design)

`pkg/dhcp/dhcp.go runDHCPv4` (≈735-903) and `runDHCPv6` (≈1148-1310):

- On a renew **NAK**, `abandonLeaseAfterNAK` removes the address, deletes the
  lease record, and fires `onGatewayChange` **immediately** (RFC 2131 §4.4.5,
  #3956). This path is correct and not in dispute.
- On a renew/rebind **TIMEOUT** (no reply), the inner renewal loop `break`s and
  the **outer `for` loop re-enters a fresh DORA/Solicit** with `committed`
  (v4) / `committed`+`committedPDs` (v6) **still non-nil** — i.e. the address,
  the FRR default route (admin distance 200), the lease-map entry, and the
  DHCPv6 delegated-PD map **stay installed** across the re-acquisition attempts.
- With `retransmission-attempt 0` (the DEFAULT — "unlimited"), the outer loop
  retries DORA forever with capped backoff, so the expired binding persists for
  the entire server-outage window. This is the finding's "indefinitely."

**Documented, deliberate (README `pkg/dhcp/README.md`):** *"Lease records are
NOT expired by the wall clock. During a timeout-driven failed re-acquisition …
the lease record and the kernel address intentionally persist until replaced —
consumers (FRR DHCP routes, ip-monitoring resolved next-hops) keep the
last-known gateway. This deliberately diverges from RFC 2131 §4.4.5 for the
timeout case."* The README also states the **Coupling rule (#1844):** any
lease-record removal MUST route through an `onGatewayChange`-firing path so the
ip-monitoring overlay withdraws its resolved next-hop in lock-step, and names
clock-expiry as future work *subject to that rule.*

**The finding's finite-retry sub-claim is FALSE.** On `retransmission-attempt N`
exhaustion the outer loop `return`s, and `Start`'s goroutine runs
`defer m.finishClient(key, dc)` on **every** exit path. `finishClient` reads
`lease := m.leases[key]` (still populated), calls `m.removeAddress`, deletes the
lease + delegated-PD map entries, and fires `onGatewayChange`. So a finite-retry
exit **does** deconfigure the binding — it does not "return with it still
installed." (v6 ctx-cancel branches also delete `leases`+`delegatedPDs` inline.)

**Net Defect-A reality:** the only real retention is the *unlimited-retry
timeout* window, which is exactly the #1844 last-known-gateway design. There is
no leak on the finite-retry / cancel paths.

### 2.2 Defect B — zero-lifetime IA_PD stored + re-advertised (genuine bug)

Trace, all at `4047fd553`:

1. `extractDelegatedPrefixes` (`dhcp.go` ≈1651) appends **every** IA_PD prefix,
   including `ValidLifetime == 0`. No zero-lifetime filter.
2. `runDHCPv6` renew/rebind commit: `if len(renewed.prefixes) > 0 {
   committedPDs = renewed.prefixes }`. A reply carrying one zero-lifetime prefix
   has `len == 1`, so `committedPDs` is **replaced** with the revoked prefix.
3. `commitLease` (`commit.go`): `if len(prefixes) > 0 { m.delegatedPDs[iface] =
   prefixes }` — stores the zero-lifetime prefix into the RA-source map.
4. `DelegatedPrefixesForRA` returns it unfiltered.
5. `daemon_ra.go:43` — `if mapping.ValidLifetime > 0 { pfx.ValidLifetime = … }`
   — the guard is false, so `RAPrefix.ValidLifetime` stays **0**.
6. `ra/sender.go:753` — `validLife := pfx.ValidLifetime; if validLife <= 0 {
   validLife = defaultValidLifetime }` → **`2592000` (30 days)**; preferred
   likewise defaults to `604800` (7 days).

**Result:** a prefix the server explicitly **revoked** (RFC 8415 §12.1 / §18.2.10
— valid-lifetime 0 = stop using now) is re-advertised to LAN hosts with a fresh
30-day valid / 7-day preferred lifetime, and keeps renewing off the *unrelated*
IA_NA lifetime. Downstream hosts keep a reclaimed prefix → overlap with another
subscriber, source-address policy failures, wrong-subscriber routing.

**This contradicts the code's own IA_NA behavior.** `selectIANAAddress`
(`dhcp.go` ≈1454, #4383/F-264) **already skips** any IAADDR with
`ValidLifetime == 0`. The IA_PD path is simply missing the symmetric guard.
There is **no test** pinning the current (store-zero-lifetime) IA_PD behavior —
`TestExtractDelegatedPrefixes` covers single/none/multiple non-zero prefixes
only. So Defect B is unpinned and safe to change.

**The one real subtlety** — and the reason B is *not* a one-line filter: the
`len(prefixes) > 0` guard is a **deliberate anti-outage** rule (README:
*"An IA_PD reply with no prefixes retains previously delegated prefixes"*). It
exists so a renew reply that merely **omits** IA_PD does not wipe the LAN prefix.
A naive "filter zero-lifetime inside `extractDelegatedPrefixes`" turns a
present-but-zero-lifetime **withdrawal** into an empty slice, which then hits the
retain guard and **keeps the revoked prefix** — the exact opposite of the intent.
The fix MUST distinguish three cases:

| Reply contents                    | Correct action        |
|-----------------------------------|-----------------------|
| IA_PD **absent** (silence)        | **Retain** prior PDs (anti-outage, #1844 spirit) |
| IA_PD present, valid-lifetime > 0  | Install/replace       |
| IA_PD present, **valid-lifetime 0**| **Withdraw** (drop from PD/RA set) |

That is exactly the v4 NAK vs. timeout distinction (#3956), applied to PD:
explicit withdrawal is honored immediately; silence retains.

---

## 3. What the finding actually wants vs. what #1844 protects

- **Wants (A):** RFC 2131 §4.4.5 wall-clock expiry — deconfigure the address +
  default route the moment the lease elapses, even mid-re-acquisition.
- **#1844 protects (A):** WAN self-uplink availability. A transient DHCP-server
  outage should not blackhole the firewall's own default route / ip-monitoring
  next-hop; the last-known gateway is retained until a replacement arrives. This
  was a reviewed, deliberate divergence, and clock-expiry was explicitly deferred
  to future work *with* the `onGatewayChange` coupling rule.
- **Wants (B):** treat a zero valid-lifetime IA_PD as a withdrawal — drop it from
  the RA/PD set instead of storing + defaulting it to 30 days.
- **#1844/README protects (B):** only the *absent*-IA_PD retain rule. It does
  **not** endorse re-advertising an explicitly-revoked prefix; that is an
  unintended consequence of `extractDelegatedPrefixes` lacking the zero-lifetime
  guard that `selectIANAAddress` already has.

---

## 4. Multiple Path Options

### Path A — Implement RFC clock-expiry with the #1844 `onGatewayChange` coupling
Add a wall-clock expiry timer (v4: `lease.LeaseTime` from grant; v6: IA_NA/PD
valid-lifetime). On expiry, deconfigure the address + default route + lease-map +
delegated-PD map through an `onGatewayChange`-firing path, then re-acquire.

- **RFC conformance:** full (both §4.4.5 and RFC 8415 §18.2.10).
- **WAN availability risk:** **HIGH.** Directly reverses the #1844 decision. A
  DHCP-server reboot longer than the lease now blackholes the firewall's own
  uplink + ip-monitoring overlay + FRR default route — the exact failure #1844
  was created to prevent. On a residential/SMB WAN this is a self-inflicted
  outage on every server maintenance window.
- **Blast radius:** run-loop timer plumbing in both families, `finishClient`
  ordering, ip-monitoring `NotifyNextHopChange`, FRR route withdrawal,
  `gateway_hook_test.go`, `renew_test.go` seams. Largest of the three.
- **Verdict lean:** rejected as the *default* — it overturns a documented,
  reviewed availability choice without new evidence that #1844 was wrong.

### Path B — Keep retention as-is; PLAN-KILL the finding as a misread
Document that Defect A is intentional #1844 design and that the finite-retry
sub-claim is factually wrong (finishClient cleans up), then close.

- **RFC conformance:** unchanged (deliberate §4.4.5 divergence for timeout).
- **Availability risk:** none.
- **Blast radius:** zero code.
- **Gap:** ignores **Defect B**, which is a *genuine* bug not covered by the
  #1844 retention rationale. Adopting Path B wholesale would wrongly bless the
  30-day re-advertisement of a revoked prefix. So Path B is correct **for A
  only**, not for the whole issue.

### Path C — Split: PLAN-KILL A (document), PLAN-READY B (fix the withdrawal)  ← RECOMMENDED
Treat the two defects on their merits:

- **A → PLAN-KILL/keep.** The retention is the #1844 design; the finite-retry
  leak claim is false. Optionally strengthen the README to name #4874 as the
  re-litigation and (if desired) expose an opt-in knob later — but no code is
  required now. A future clock-expiry, if ever wanted, still routes through the
  documented `onGatewayChange` coupling rule; that is a separate, larger issue.
- **B → PLAN-READY.** Add the zero-valid-lifetime withdrawal semantics for IA_PD,
  mirroring `selectIANAAddress` (#4383) and the v4 NAK/timeout split (#3956),
  while preserving the absent-IA_PD retain rule. Concretely, the smallest correct
  shape:
  1. In `parseV6Reply` (not blindly inside `extractDelegatedPrefixes`), detect
     whether **any** IA_PD option was present in the reply, and partition the
     extracted prefixes into `live` (valid-lifetime > 0) and `withdrawn`
     (valid-lifetime 0). `extractDelegatedPrefixes` may keep returning raw
     prefixes; the partition/decision belongs one level up so the "absent vs.
     present-but-zero" signal is not lost.
  2. Carry a small signal on `dhcpv6Result` (e.g. `iapdPresent bool` +
     `prefixes` already filtered to live) so the run loop / `commitLease` can
     distinguish "IA_PD absent → retain" from "IA_PD present, all withdrawn →
     delete `m.delegatedPDs[iface]`."
  3. Adjust the `len(prefixes) > 0` guard sites (`runDHCPv6` renew/rebind commit
     and `commitLease`) so an explicit all-withdrawn reply **clears** the stored
     PDs (and fires `scheduleRecompile` so RA reconverges), rather than being a
     no-op that retains them.
  4. RA path is then correct for free: with the prefix dropped,
     `DelegatedPrefixesForRA` no longer returns it, so `daemon_ra.go` /
     `sender.go` never see it. (No change needed to the sender's zero→default
     rule, which is correct for *configured* prefixes.)

- **RFC conformance:** B becomes fully RFC 8415-conformant; A stays a documented,
  deliberate §4.4.5 divergence.
- **LAN availability risk (B):** LOW-to-MEDIUM and *correct-direction*. Honoring a
  genuine withdrawal briefly removes the LAN prefix — but that is the RFC-mandated
  behavior and strictly better than advertising a reclaimed prefix for 30 days.
  Mitigation: only an **explicit valid-lifetime-0** prefix withdraws; a renew that
  merely omits IA_PD still retains (anti-flap). This matches the v4 NAK-vs-timeout
  asymmetry the project already ships.
- **Blast radius (B):** contained to `pkg/dhcp` (`parseV6Reply`,
  `dhcpv6Result`, the two `len(prefixes)>0` guard sites, `commitLease`) + one new
  test in `dhcp_test.go`/`commit_test.go`. RA/daemon code unchanged. No v4 change.
- **Verdict lean:** ship B, document/kill A.

---

## 5. Blast radius / affected files (Path C, B-only implementation)

- `pkg/dhcp/dhcp.go` — `parseV6Reply` (partition live/withdrawn + presence
  signal), `dhcpv6Result` (add signal field), `runDHCPv6` renew/rebind commit
  guards.
- `pkg/dhcp/commit.go` — `commitLease` PD store/clear branch (honor an explicit
  all-withdrawn as a delete).
- `pkg/dhcp/README.md` — document the zero-lifetime IA_PD withdrawal semantics
  next to the existing #4383 IA_NA note and the #1844 retention note; record
  #4874's A-verdict (retention is intentional) so this is not re-litigated.
- `pkg/dhcp/dhcp_test.go` / `commit_test.go` — new: zero-lifetime IA_PD present ⇒
  prefix dropped; IA_PD absent ⇒ prior prefix retained; mixed live+withdrawn ⇒
  only live kept.
- **Unchanged:** `pkg/daemon/daemon_ra.go`, `pkg/ra/sender.go`, all v4 paths,
  ip-monitoring. (A: no code change.)

---

## 6. Recommendation

**Split verdict:**

- **Defect A — PLAN-KILL / keep current behavior.** The timeout-retention is the
  deliberate, reviewed #1844 last-known-gateway design, documented in
  `pkg/dhcp/README.md` as an intentional RFC 2131 §4.4.5 divergence for the
  timeout case. The finding's material sub-claim ("a finite v4 retry count can
  return from the goroutine with it still installed") is **factually false** —
  `finishClient` deconfigures on every terminal exit and fires `onGatewayChange`.
  No code change; optionally a one-paragraph README note recording #4874.

- **Defect B — PLAN-READY (Path C, B-only).** The zero-valid-lifetime IA_PD
  storage + 30-day RA re-advertisement is a genuine RFC 8415 conformance bug,
  inconsistent with the code's own #4383 IA_NA zero-lifetime skip, unpinned by
  any test. Fix by adding explicit-withdrawal semantics that preserve the
  deliberate absent-IA_PD retain rule (the withdrawal-vs-silence distinction is
  load-bearing and is the whole reason this is not a one-liner).

The issue therefore closes as: **A documented as intended, B implemented under
`/engineer #4874`.**

---

## 7. Test plan (for `/engineer`, B-only)

Unit (no traffic, `pkg/dhcp`):
- `extractDelegatedPrefixes` / `parseV6Reply`: IA_PD present with valid-lifetime 0
  ⇒ zero live prefixes + `iapdPresent = true`.
- Renew reply {IA_NA renewed, IA_PD valid-lifetime 0} ⇒ `m.delegatedPDs[iface]`
  cleared; `DelegatedPrefixesForRA()` empty; `scheduleRecompile` fired.
- Renew reply with **no** IA_PD option ⇒ prior PDs retained (regression guard for
  the anti-outage rule).
- Mixed reply {live /48, withdrawn /56} ⇒ only the /48 retained.
- `delegatedPrefixesChanged` still fires on the retain→empty transition.

Integration (optional, cheap): `buildRAConfigs` with a withdrawn PD ⇒ no
`RAPrefix` emitted for it (proves the RA leak is closed end-to-end).

No cluster smoke required — DHCPv6 PD is control-plane, not dataplane-forwarding;
`make test` + the new unit tests are sufficient for a `/research` sign-off. (The
`/engineer` gate decides final smoke scope.)

---

## 8. Risks & mitigations

- **R1 — B over-withdraws on a flapping/buggy server that transiently sends
  valid-lifetime 0.** Mitigation: withdraw ONLY on an explicit present-but-zero
  IA_PD; absent IA_PD retains. Identical to the shipped v4 NAK-vs-timeout policy.
  A server sending valid-lifetime 0 is making an unambiguous RFC 8415 statement.
- **R2 — Signal plumbing (`iapdPresent`) accidentally changes the acquire path.**
  Mitigation: on initial acquire there is no prior PD to withdraw; the new branch
  is a no-op when `committedPDs` is empty. Cover with the "absent IA_PD" test.
- **R3 — Scope creep into Path A.** Mitigation: A is explicitly out of scope for
  code; only a README note. Clock-expiry stays a separate future issue bound to
  the `onGatewayChange` coupling rule.

---

## 9. Rollback

Pure `git revert` of the B PR. No persisted state, no migration: the PD map is
in-memory and rebuilt on the next reply. A revert restores the store-zero-lifetime
behavior exactly.

---

## 10. Open questions for reviewers

1. Do you agree A is a re-litigation of #1844 and the finite-retry sub-claim is
   false? If any reviewer finds a real path where a finite-retry / cancel exit
   leaves the binding installed, A re-opens.
2. For B, is `parseV6Reply`-level partition + a `dhcpv6Result.iapdPresent` signal
   the right seam, or should the withdrawal decision live entirely in
   `commitLease`? (Either is acceptable; the invariant is "absent ≠ present-zero".)
3. Should A additionally ship an opt-in `retain-expired-lease`/clock-expiry knob
   now, or defer entirely? (Recommend defer — no evidence #1844 default is wrong.)

---

## 11. Reviewer verdicts (filled per round)

- **Round 1 — Codex:** see `codex-plan-r1.md` (verbatim below at convergence).
- **Round 1 — Claude SMR:** see `claude-smr-plan-r1.md`.
- **AGY:** infra-down for this run → converge 2-of-3 (Codex + Claude SMR) per
  `feedback_codex_infra_must_retry` (AGY-alone-never-enough is satisfied; the two
  live reviewers are Codex + SMR).
