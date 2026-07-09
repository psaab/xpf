# Claude SMR — hostile plan-review r1 — #4146

Reviewer: Claude (self-model review, HOSTILE). Base origin/master `b4f2ddb2f`,
plan at `docs/research/4146-junos-host-direct-deny/plan.md` rev r1.

I read the plan against the actual code (lib.rs shim arms, daemon_nft.go
codegen, zones_host_inbound.go view builder, compiler_validate_warn.go #4168
helpers, policymatch resolveToken). This is not a synthesizer pass — I tried to
break the design.

## What I tried to break, and the result

### A. Premise: does the direct packet really never reach userspace-dp? — CONFIRMED
`userspace-xdp/src/lib.rs`: session-hit local → `PASS_TO_KERNEL` →
`cpumap_or_pass` (`:604`); session-miss local → `is_local_destination` →
`cpumap_or_pass` (`:632`). Both go to the kernel. `junos_host_local_policy`
runs only under `LocalDelivery` on the XSK path, which the direct-to-interface-IP
packet never reaches. The plan's premise holds; the kernel nft chain is the only
locus that sees the direct packet. The DRIVE-ROUND-5 "must reclaim shim budget"
framing is a genuine red herring — the fix does not belong in the shim at all.

### B. Availability posture — CONFIRMED
`drop_degraded_transit` returns `XDP_DROP` unconditionally (`lib.rs:1064,1070`);
the redirect-error arm is fail-closed, so direction (a) really would drop all
host-bound traffic to a withheld mgmt IP during a helper crash. Kernel nft
enforcement is helper-independent — the plan's core justification for (b) as the
Junos-parity locus is correct.

### C. Over-deny via app coarsening — CONFIRMED FORECLOSED
The representability gate (§6.3) emits a kernel rule only when the WHOLE match is
representable, so a custom/ALG app is never coarsened to a bare port. The gate is
all-or-nothing per term. Good. One caveat to make explicit (see FINDING-1).

### D. Feed staleness — CONFIRMED, with a nesting caveat
`resolveToken` (`policymatch.go:1306-1323`) treats feed-overlay names as book
references and merges live feed CIDRs, INCLUDING feed members nested inside a
static address-set (`expandBookName`… "feed-aware"). The plan already excludes
feed-backed sources, but must state that a static address-set that NESTS a
feed-bound member is also un-representable (not just a top-level feed name),
because its resolved CIDR set is runtime-mutable. The plan §6.2 parenthetical
("Static address-book members remain representable") is too loose — see
FINDING-2.

## Findings (must address before PLAN-READY)

### FINDING-1 (must-fix, documentation): daddr-scoping over-deny is real but safe-side — say so precisely
The plan scopes the deny by daddr (from-zone firewall-local addrs) not iifname.
I constructed the asymmetric case: firewall IP `W` in zone wan, IP `L` in zone
lan; `from-zone wan to-zone junos-host deny source BAD`. A packet from `BAD`
arriving on the LAN netdev but destined to `W` would be dropped by our
`daddr {W} saddr BAD drop` rule, whereas Junos (from-zone = lan by ingress)
would not apply the wan policy. So daddr-scoping CAN over-deny vs strict Junos
from-zone semantics.

Why this is acceptable and must be documented as such:
- The over-deny is **bounded to the explicitly-named bad source** — we never
  over-drop any source the operator did not name in a deny.
- For a DENY, dropping a spoofed/asymmetric packet from a named-bad source to a
  firewall IP is the **safe-side error**.
- It is **consistent with the existing chain**, which is already destination-
  scoped (daddr-only) by accepted design (#3718 Option B) — junos-host deny does
  not introduce a new class of imprecision.
Action: §11.1 must add the "bounded to the named source + safe-side for a deny +
consistent with the existing daddr-only chain" argument explicitly, and note
iifname as an optional future precision upgrade (not required).

### FINDING-2 (must-fix, correctness of the representability contract): nested-feed address-sets
§6 must state that a source token is un-representable if it OR ANY nested member
resolves through a live feed overlay (per `expandBookName` recursion), not only
when the top-level name is a feed. The implementation must reject the whole term
if `resolveToken` on any source token would pull in feed CIDRs. Otherwise a
static-looking address-set name could smuggle a feed member into a static nft set
that then goes stale.

### FINDING-3 (must-note, semantics): established-session survival
`ct state established,related accept` precedes the deny, so a session the bad
source established BEFORE the deny was committed survives until it closes (the
deny applies to NEW connections). This matches the existing per-zone chain and
Junos's practical behaviour, but the plan should state it as an expected,
documented property (§8/§10) so it is not read as a bypass. A source denied from
the start never forms an established state (its SYN is dropped), so there is no
exploitable bypass.

### FINDING-4 (scope, acceptable): source-restricted permit deferral
Deferring source-restricted `to-zone junos-host` permits to a follow-up (keeping
the #4168 warning for them) is acceptable scope control since the finding is
about DENY, but the plan must frame this as a TRACKED follow-up with the
identical `saddr !=` machinery — NOT another open-ended defer. §6.4 mostly does
this; tighten the wording to "tracked follow-up, same PR family" so it cannot be
read as re-deferring the issue.

## Non-findings (checked, no action)
- Ordering (deny after established/ND/ESP accepts, before service accepts) is
  correct: a denied source's new connection is dropped; ND/PMTUD/host-IPsec/
  established return survive — verified against `emitHostInboundZone` layout.
- Blanket `source any application any deny` correctly overrides the zone's own
  service admits (deny precedes the accepts) while ND/PMTUD survive — this is the
  intended Junos first-match behaviour and flips the #4168 `block-all` test from
  warn to enforced (plan §9.3 already flags the test update).
- SSOT: extends the existing "kernel primary + Rust secondary, both render from
  config" model (`daemon_nft.go:216-232`); not a #1319 violation.
- Fail-closed atomic nft load + counter declaration/reference discipline: the
  plan reuses the existing machinery correctly (§5.2, §7).
- v4+v6 handled via family split; `reject` maps to `reject with icmpx
  admin-prohibited` (generalising the existing `ident-reset` reject precedent).

## Verdict

**PLAN-REVISE** — the architecture is sound and this is NOT a PLAN-KILL: the
enforcement locus (kernel nft), the availability rationale, the over-deny
foreclosure, and the remainder decision (ii) are all correct and well-evidenced.
But three tightenings are required before PLAN-READY: FINDING-1 (document the
bounded, safe-side daddr over-deny), FINDING-2 (nested-feed address-sets are
un-representable), and FINDING-3 (established-session survival as a documented
property). FINDING-4 is a wording tightening. None touch the design; all are
precision/documentation. Address them and this converges to PLAN-READY.
