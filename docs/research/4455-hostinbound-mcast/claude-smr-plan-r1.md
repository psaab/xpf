# Claude SMR — hostile plan-review r1 (#4455 HI-1)

**Reviewer:** Claude SMR (self-review, adversarial). **Target:** plan.md r1 @
6e243a1d7f46. **Posture:** hostile — a first-pass soft PLAN-READY is a failure
mode this project has been bitten by; I am looking for structural defects.

**Verdict: PLAN-REVISE.** The architectural findings (F1–F4) are sound and
verified, but the r1 design has one real internal inconsistency, one unverified
load-bearing assumption, and a lockstep-guard gap. None is fatal; all are fixable
in r2. PLAN-KILL remains a legitimate convergent alternative pending Q1/Q2.

---

## Blocking issues (must fix in r2)

### B1 — the accept rules (§5.1a) are redundant and make the design incoherent
r1 says "emit an accept per admitted group (5.1a)" AND "drop only the
**un-admitted** dedicated groups (5.1b)" AND "no broad multicast catch-all in r1
(§9)". With `policy accept` on the chain and no broad multicast drop, an
**admitted** group is already accepted by policy fall-through — the explicit
accept in 5.1a matches nothing that would otherwise be dropped, so it is dead
weight. Accept rules are only necessary if a **broad** multicast drop exists to
protect against. r1 therefore conflates two mutually exclusive shapes:

- **Shape A (minimal, what r1 should be):** emit ONLY
  `iifname { I_Z } <fam> daddr { <un-admitted dedicated groups> } counter … drop`
  per zone. No accept rules, no broadcast handling. Admitted groups + shared
  groups + everything else stay at `policy accept`. This is the smallest correct
  change and removes the "is the accept redundant?" attack surface entirely.
- **Shape B (aggressive):** per-zone broad `iifname { I_Z } <fam> daddr
  <mcast-range> drop` after explicit per-group accepts. Fuller parity but
  reintroduces the MLD/IGMP/mDNS housekeeping risk r1 says it is avoiding.

**Required:** r2 must commit to **Shape A** for the recommended path, delete the
§5.1a accept rules and the §5.1 broadcast-accept paragraph (both redundant under
Shape A — DHCP broadcast stays at policy-accept with nothing to do), and move
Shape B to the aggressive-alternative bucket (§10 Q2/Q3). This also shrinks the
implementation to "per-zone un-admitted-dedicated-group drops behind an opt-in
knob," which materially sharpens the §3 value/PLAN-KILL calculus (the change is
even smaller than r1 implies).

### B2 — the iifname→kernel-netdev resolver assumes a helper that r1 never verified
§5.2 asserts "reuse the existing name-translation used by linksetup/networkd (do
not hand-roll slash→dash)" but points at no concrete function. The research did
NOT confirm a callable cfg-ref→kernel-netdev resolver exists; `linksetup.go`
writes `.link` files (rename side), which is not the same as a reusable
"given this config interface ref, return the kernel netdev name(s) a packet
ingresses on" lookup, and the VLAN-unit→sub-netdev + RETH cases are exactly where
a naive slash→dash breaks. If no such helper exists, §5.2 is materially more work
than r1 implies and the "Correctness" risk row is understated.

**Required:** r2 must either (a) cite the concrete existing function that yields
the kernel netdev name for a zone-interface unit (base, tagged VLAN, RETH), or
(b) explicitly scope building that resolver as first-class work with its own
unit-test matrix, and re-rate the Correctness risk from Med to Med-High until the
resolver is proven on the loss cluster (VLAN sub-netdev + RETH).

### B3 — the shim-diversion guard (§5.4) does not actually guard against the
### split-brain it claims to prevent
The guard asserts `should_fallback_early` keeps diverting multicast to the
kernel. That protects against multicast becoming *reachable* on the XSK, but it
does NOT detect the other split-brain direction: someone later adding a multicast
branch to `host_inbound_admits` / the forwarding classifier that admits or denies
a multicast dst **differently** from the kernel nft set. The invariant the
codebase actually enforces (#3486) is "the two surfaces agree on the token set" —
a shim-only tripwire is necessary but not sufficient.

**Required:** r2 must strengthen the guard to a two-sided assertion: (1) the shim
still diverts multicast (tripwire), AND (2) a Rust-side test asserting the
classifier makes NO independent multicast admission decision (multicast dst is
never classified as LocalDelivery / never reaches `host_inbound_admits`) so long
as (1) holds — i.e. the classifier's multicast behavior is provably a no-op, not
merely believed to be. Only then is "kernel-only enforcement" an honest
satisfaction of the lockstep contract rather than a documented hope.

---

## Non-blocking but must be addressed

### N1 — subnet-directed broadcast is punted, but the issue named it
§9 sends subnet-directed broadcast (10.0.1.255) out of scope because F1 does not
divert it to the kernel. That is a correct architectural distinction, but #4455's
title/body explicitly lists "subnet-directed" broadcast. r2 must state, in the
issue comment and the doc, WHY it is a genuinely different problem (it takes the
XSK/forwarding path, not the host-inbound input chain) so the deferral is a
reasoned scoping decision, not an omission — otherwise the "resolves the issue"
claim is overstated.

### N2 — §3/§11 undersell how small Shape-A actually is
Once B1 collapses the design to "per-zone un-admitted-dedicated-group drops behind
an opt-in-off knob, kernel-only, VRRP AF_PACKET-immune, Rust-unreachable," the
honest value statement is even thinner than r1 admits: the ONLY operators the
change protects are those who (a) enable the opt-in knob AND (b) run an FRR
routing protocol on a zone WITHOUT the matching token — a near-empty set, because
enabling the knob is a superset action of caring about the tokens. r2's §3 must
state this explicitly; it is the strongest single argument for PLAN-KILL and the
review must not bury it.

### N3 — counter name-scheme collision (Q7) should be pre-resolved, not left open
The #3361 scraper reverse-maps `xpfhi_<family>_<len>_<zone>`. A `<Z>_mcast_<fam>`
counter must not be parseable as a zone whose name ends in `_mcast`. r2 should
pick a scheme that is unambiguously non-colliding (e.g. a distinct prefix
`xpfhimc_…`) rather than leaving it as an open question, since it is a mechanical
decision with a known-correct answer.

---

## What is genuinely right in r1 (do not regress)

- F1 (shim diverts multicast to kernel), F2 (VRRP AF_PACKET-immune), F3 (FRR is
  the real risk), F4 (catalog already shipped) are all verified against real
  code with correct file:line citations. The kernel-as-sole-enforcement-point
  framing is correct.
- The shared-group carve-out (§5.3) is the right instinct — dropping
  224.0.0.1/2/22 broadly would be reckless. Keep it.
- The opt-in-off migration (M-i) is the correct default; enforce-by-default
  (M-iii) would silently break FRR adjacencies on upgrade.
- Making PLAN-KILL a first-class outcome with explicit criteria is correct and
  matches the honest value calculus.

---

## Convergence path

r2 fixes B1 (commit to Shape A, delete redundant accepts), B2 (cite or scope the
ifname resolver + re-rate risk), B3 (two-sided lockstep guard), N1–N3. On a clean
r2 I would move to **PLAN-READY for the narrow Shape-A scope**, with the standing
caveat that **PLAN-KILL is equally acceptable** if Codex/manual review judges the
Shape-A value (N2) too thin to justify the first-iifname-predicate correctness
burden. This is a design where "converged" may legitimately mean "converged on
PLAN-KILL."
