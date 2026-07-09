# Plan of Action — #4146 host-inbound: `to-zone junos-host` deny not enforced for direct host-bound traffic

- **Issue:** #4146
- **Branch:** `research/4146-junos-host-direct-deny`
- **Base:** origin/master `b4f2ddb2f`
- **Revision:** r7 (folds Codex r4: the fine-eligible-domain exclusion is by
  EFFECTIVE COARSE VERDICT — TCP/113 is excluded only when ident-reset's RST
  actually wins, NOT under `{all, ident-reset}` where the all-accept shadows it,
  closing a 113 fail-open). Builds on r6 (three-tier exact→from-any→global) + r5
  (DROP-only set-subtraction, fine-deny before ND/PMTUD, global-any scoped,
  tcp-rst unrepresentable).
- **Status:** seeking convergence (Codex + Claude SMR; AGY infra-down)
- **Disposition sought:** PLAN-READY, un-deferring the mislabeled `plan-deferred-operator`.

> This is `/research`, not `/engineer`. It stops at PLAN-READY (or PLAN-KILL).
> No production code is touched here; the deliverable is this doc + reviewer
> verdicts + issue comments.

---

## 0. TL;DR / decision resolved

The issue was parked `plan-deferred-operator` waiting on an "operator decision"
about handling junos-host policies nft cannot represent. **That is a design
question; this plan resolves it** rather than deferring again:

- **Enforce the `to-zone junos-host` DENY on the DIRECT host-bound path in the
  KERNEL nft `xpf_hostinbound` chain (direction b).** It is the only locus that
  (1) sees the packet — a direct host-bound packet is delivered by the kernel,
  never userspace-dp — and (2) is availability-preserving (helper-independent),
  matching where Junos enforces host-inbound (the RE control-plane filter).
  Go-only; **no Rust hot path**; independent of the #1864 shim verifier ceiling
  that blocked the previously-chased userspace-redirect approach (direction a).
  Both hostile reviewers confirmed the locus is correct.
- **Enforce by projecting the ORDERED per-ingress-scope junos-host policy list
  into an ordered nft subchain** (permit→accept short-circuit, deny→drop),
  scoped by **ingress interface (`iifname`)** not destination address, evaluated
  in the Rust SSOT's **coarse-admit-then-fine-policy** order. Emit a scope's
  subchain **only when the entire projected chain is representable**; otherwise
  emit nothing for that scope and keep the #4168 warning. This is the crux fix
  over r1/r2: representability and emission are decided on the **ordered decision
  program**, never per isolated deny term.
- **Representable subset:** action `deny` (silent drop); `match source-address`/
  `source-address-excluded` resolving entirely to *static* address-book CIDRs
  (recursively feed-untainted); `match application` reducing to simple
  proto + optional dst/src port + optional ICMP type/code (application-sets/lists
  OR-expanded to multiple rules); `match destination-address` resolving within
  the firewall-local set; **no** `scheduler-name`. `reject` and source-restricted
  `permit` (the "deny non-permitted" half) are tracked follow-ups in the same PR
  family (§6.5), not re-defers — the DENY slice un-defers the security bug.
- **Un-representable remainder (resolved operator decision, direction ii):**
  keep the shipped #4168 **commit WARNING** (suppressed only for policies that
  actually rendered an enforced rule), emit **no** partial/coarsened kernel rule
  (no over-/under-deny), and **do not** strict-reject the config (that would
  refuse legal Junos configs that userspace-dp *does* enforce on the XSK subset).
  The warned remainder is a **documented partial-coverage limitation**, not
  "Junos-correct."

Net: the security gap ("a configured `then deny` to the firewall's own host is
silently unenforced on the direct path") is closed for the representable ordered
class using the existing fail-closed kernel chain, with an honest warning for the
un-representable tail, verified by a **cross-language (nft vs Rust) parity
fixture**.

---

## 1. Problem statement & issue history

### The bug (security/correctness)
A `from-zone X to-zone junos-host { match source-address <bad>; then deny; }`
(or a global `match to-zone junos-host` deny) on a plain firewall interface IP is
**silently unenforced** for direct host-bound traffic: the management-plane DENY
reaches the host stack unfiltered and the policy hit counters stay zero. Labels:
`bug`, security, enforcement-gap, host-inbound, vsrx-parity.

### Why it kept getting deferred (issue thread)
1. **PLAN-DEFER:** rejected direction (a) (route through userspace-dp) — the
   shim redirect-error arm is fail-CLOSED (`drop_degraded_transit → XDP_DROP`),
   so a helper crash would drop *all* host-bound traffic to the mgmt IP,
   inverting "management always reachable." Shipped direction (c): commit WARNING
   (#4168) + docs. Left enforcement open.
2. **`plan-deferred-research → plan-deferred-operator`:** identified direction
   (b) as the parity-correct locus but deferred the "remainder contract."
3. **DRIVE-ROUND-5:** concluded "can't be enforced in userspace-dp … shim at the
   #1864 verifier ceiling," recommending a shim-budget-reclaim research.

### The reframing that un-defers it
DRIVE-ROUND-5 is right that the fix cannot live in **userspace-dp** — but that is
the wrong place. **The direct host-bound packet is delivered by the kernel, so
enforcement belongs in the kernel `xpf_hostinbound` nft chain** — the documented
PRIMARY host-inbound path (#3070), helper-independent, never touching the shim.
The remaining question was the enforcement *model*, resolved in §§3-6.

---

## 2. Verified root-cause chain (file:line, base `b4f2ddb2f`)

1. **Direct host-bound packets are shunted to the kernel, never reaching
   userspace-dp:** session-HIT local → `PASS_TO_KERNEL` → `cpumap_or_pass`
   (`userspace-xdp/src/lib.rs:589-604`); session-MISS local →
   `is_local_destination` → `cpumap_or_pass` (`:621-632`); `cpumap_or_pass`
   (`:1139`) redirects to cpumap else `XDP_PASS` — always the kernel.
2. **The fine junos-host gate is XSK-only.** `junos_host_local_policy` runs only
   under `ForwardingDisposition::LocalDelivery`
   (`userspace-dp/src/afxdp/poll_descriptor/mod.rs` ~2230, gated at `:2280`),
   reached only by the DNAT/static-NAT-to-self/embedded-ICMP/DNS subset. The
   coarse host-inbound admission (`host_inbound_gated_lo0_action`) runs FIRST
   (~`:2202`), the fine junos-host policy SECOND — the **coarse-then-fine** order
   this plan must reproduce.
3. **The kernel host-inbound chain has zero junos-host awareness.**
   `buildHostInboundFilterPayload` (`pkg/daemon/daemon_nft.go:501`) +
   `emitHostInboundZone` (`:656`) emit global `ct established,related accept` +
   ESP/AH + ND/PMTUD accepts, then per-zone **permit-by-service** accepts from
   any source, then a catch-all `<fam> daddr <zone-addrs> counter drop`. No
   source dimension, no per-application deny. `grep -rin junos.host pkg/daemon/`
   → nothing.

**Net:** the coarse permit-by-service gate admits the packet; the fine junos-host
deny (userspace-dp `LocalDelivery` only) never sees it. Distinct from #3019 (XSK
`LocalDelivery` arm) and #3292 (flowless arm).

---

## 3. Design space & the resolved decisions

### 3.1 Enforcement locus (a/b/c)
| Dir | Verdict |
|-----|---------|
| (a) Withhold junos-host IPs from `USERSPACE_LOCAL` → XSK path | **REJECTED.** Shim redirect-error arm fail-CLOSED (`lib.rs:1064,1070`) → helper crash drops all host-bound to the mgmt IP; inverts Junos availability. Also blocked by the #1864 verifier ceiling. |
| (b) KERNEL nft `xpf_hostinbound` DENY subchain | **CHOSEN.** Kernel = where the packet goes; helper-independent (Junos-parity locus); Go-only; no hot path; sidesteps the ceiling. Both reviewers confirm the locus. |
| (c) Commit warn + docs (#4168, shipped) | Complementary — retained for the un-representable remainder; not an enforcement fix alone. |

### 3.2 Enforcement MODEL (the r3 rework)
Junos evaluates `to-zone junos-host` as an **ordered first-match policy program**
scoped by **ingress zone**, layered on the coarse host-inbound admission. Three
corrections over r1/r2:
- **Ordered projection, not per-term.** A permit ahead of a broader deny carves
  an exception; mirroring a deny alone over-denies the carved-out sources.
  Project the whole ordered list (permit→accept, deny→drop) and gate emission on
  the **entire chain** being representable.
- **Ingress (`iifname`) scope, not `daddr`.** `daddr` scope both under-denies (a
  packet entering the from-zone but addressed to another zone's local IP evades
  the deny) and over-denies (a packet entering another zone but addressed to the
  from-zone's IP is wrongly dropped). #3718 does not prevent either (it only
  rejects duplicate local addresses with *differing* coarse service signatures,
  `pkg/config/dup_host_local_address.go:43`, and that file names
  ingress-interface matching as the correct model, `:32`). Scope by the
  from-zone's ingress interfaces.
- **Coarse-then-fine order.** Reproduce the Rust SSOT (coarse admit, then fine
  junos-host). For a `deny` (silent drop) this is a clean AND with the coarse
  gate; `reject` is deferred because reject-before-coarse-admit would turn a
  silent coarse drop into a RST (§6.5).

### 3.3 Remainder decision (i/ii/iii) — RESOLVED as (ii), redefined
- **(iii) leave userspace-only** — REJECTED (the status-quo bug).
- **(i) strict-reject the un-representable remainder** — considered and rejected
  as the *primary*, but its strongest form (Codex): the repo already
  strict-rejects new commits while warning on persisted/peer-loaded configs
  (`pkg/config/compiler.go:40`), so a strict-reject would not brick upgrades, and
  "accept-without-enforcement is not parity." We nonetheless keep **warn, not
  reject**, because these policies ARE enforced by userspace-dp on the XSK subset
  and a strict-reject refuses a legal, partially-enforced Junos config. (A
  strict-reject/lenient-warn hybrid is recorded as a future option in §11 if the
  operator later prefers it — but it is NOT required to un-defer the bug.)
- **(ii) enforce the representable ordered chain; warn on the remainder** —
  **CHOSEN**, with two hard constraints from review: representability is decided
  on the **complete ordered chain** (not per term), and the warning is
  **suppressed only when a rule is actually rendered** (a syntactically
  representable policy that scopes to only lifeline / no addresses emits no rule
  and MUST still warn). The warned remainder is a **documented partial-coverage
  limitation**, not labelled "Junos-correct."

---

## 4. Chosen approach (summary)

Extend the kernel host-inbound codegen with an **ordered, ingress-scoped,
coarse-gated, DROP-only junos-host DENY subchain**:

1. Build **one effective ordered program per (ingress zone, family)** in Rust's
   three-tier order = exact `from-zone Z to-zone junos-host` → from-any
   `from-zone any to-zone junos-host` (#3090) → applicable global `to-zone
   junos-host` terms.
2. **Gate emission on the WHOLE per-ingress program being representable** (§6); if
   any term (any tier) is not, emit nothing for that ingress and warn.
3. **Project DROP-only via set-subtraction:** deny→`drop`; a `permit` never emits
   a fine `accept` — it SUBTRACTS its set from every later deny (`saddr != …`),
   so the coarse gate stays the sole admit authority (§5.1, §6.1).
4. **Scope** each rule by `iifname { <Z's non-lifeline netdevs> }` — a global-any
   term is rendered per ingress zone with that zone's netdevs, NEVER unscoped —
   plus the representable source/dest/app matches.
5. **Order** the subchain to reproduce coarse-then-fine (§6.4): after ESP/AH +
   reply-direction established, BEFORE the ND/PMTUD/ICMP-error accepts and the
   coarse service accepts.
6. Attach a named counter per program/family (existing `HostInboundDenyCounterName`
   discipline) and a `xpf_host_inbound_junos_host_denies_total` metric — with an
   explicit note that this does NOT populate per-Junos-policy hit counters /
   `then count` / RT_FLOW deny attribution (§6.6).
7. Suppress the #4168 warning per-policy **only when that policy rendered a
   rule**; keep it otherwise. Update the docs matrix.
8. Guarantee kernel==Rust semantics with a **cross-language parity fixture**
   (§9.1).

---

## 5. Detailed implementation plan (for /engineer — not executed here)

**All Go. No Rust, no shim, no verifier interaction.**

### 5.1 Effective-program projection — `pkg/dataplane/userspace/junos_host_deny.go` (new)
The unit of representability + emission is the **single effective ordered
junos-host program per (ingress zone, family)** — NOT an isolated scope or term
(Codex r2). Rust evaluates one program in tier order (exact zone-pair →
from-any → global `to-zone junos-host`); the projection reproduces that.
- `type JunosHostDropRule struct { Family string; SrcMatch string /* saddr [!=] set, possibly with `saddr != <earlier-permit-set>` subtractions */; DstMatch string; L4 []string /* OR-expanded */; Counter string }`
- `type JunosHostProgram struct { Zone string; Family string; IngressIfnames []string /* non-empty, non-lifeline; global-any → union of ALL non-lifeline zoned netdevs */; DropRules []JunosHostDropRule; Representable bool; RenderedPolicies []string }`
- `func BuildJunosHostPrograms(cfg *config.Config, snap ...) []JunosHostProgram`:
  - For each configured (non-lifeline) security zone Z, assemble the **effective
    ordered term list** in Rust's exact THREE-tier order
    (`userspace-dp/src/policy.rs:2978,3014,3050`): (i) the `from-zone Z to-zone
    junos-host` EXACT zone-pair terms, then (ii) the `from-zone any to-zone
    junos-host` FROM-ANY wildcard-tier terms (#3090), then (iii) the applicable
    global `to-zone junos-host` terms (`IsHostToZoneScope`, `FromZones` includes Z
    or any). Omitting the middle FROM-ANY tier would let a `from-any permit any;
    global deny any` render the global drop while dropping the carve-out permit
    (Codex r3). All three tiers form the ONE per-ingress effective program.
  - **Whole-program representability gate:** if ANY term (any tier) in Z's
    effective program is unrepresentable (§6), mark the whole program
    `Representable=false`, emit NO rule for Z, and warn on the offending
    policy(ies). This closes the "omitted unrepresentable exact permit exposes a
    later rendered global deny" hole — a program is all-or-nothing per ingress.
  - **DENY-only emission via set-subtraction (no fine `accept` — Codex r2):**
    project the effective program to DROP rules only. A `permit` term never emits
    an `accept` (that would let a fine permit re-admit a service the coarse gate
    rejects — forbidden by Rust `poll_descriptor/mod.rs:138`); instead each later
    `deny` term's match SUBTRACTS every earlier permit term's matched set
    (`saddr != <permit-set>`, dest/app analogously). So a packet matching an
    earlier permit is simply not dropped by a later deny, and the **coarse gate
    remains the sole admit authority**. If a deny's post-subtraction match is not
    cleanly nft-representable (cross-dimension permit/deny overlap), the whole
    program is unrepresentable → warn.
  - Reject terms and source-restricted-permit-as-terminal programs are
    unrepresentable for this slice (§6.5) — the whole program warns, never a
    silent partial.
  - Resolve `IngressIfnames` from Z's `ZoneConfig.Interfaces` → kernel netdev
    names via the interface snapshot (`buildInterfaceSnapshots`), **including
    VLAN subunit and RETH member netdevs**, **excluding lifelines**
    (`hostInboundLifelineSet`). A **global-any** term contributes to EVERY zone's
    program (rendered once per ingress zone with that zone's netdevs), NEVER as an
    unscoped rule — so a global-any deny can never fire on a lifeline/unzoned
    ingress (Codex r2 inv-1 hole). A program resolving to no non-lifeline netdev
    emits nothing and still warns.
  - Resolve source/dest sets with STATIC-only address resolution (no feed
    overlay) + the recursive feed-taint check (§6.2); split by family with the
    cross-family excluded semantics of `matchAddr` (`policymatch.go:1282`).
  - Resolve applications via `ResolveApplication`/`ResolveApplicationSet` to
    OR-expanded L4 fragments including `SourcePort` (`types_security.go:1088`,
    `policymatch.go:1605`); an app that cannot fully reduce → unrepresentable.

### 5.2 Codegen — `pkg/daemon/daemon_nft.go`
- `buildHostInboundFilterPayload` takes `programs []dpuserspace.JunosHostProgram`.
- Counter pre-pass declares each rendered program's counter once (dedup on name);
  the test asserts **every counter reference is declared** (a program may emit
  multiple rules → multiple references, one declaration — matching the existing
  multi-reference contract at `daemon_nft.go:509`).
- **Chain order** — the CONCRETE DROP-only placement specified in §6.4: (1)
  ESP/AH accept; (2) `ct established,related ct direction reply accept`; (3) the
  NEW per-ingress-zone effective-program DROP rules (exact→from-any→global tiers),
  match restricted to the fine-eligible L4 domain (§6.7) —
  `iifname { <non-lifeline netdevs> } <fine-eligible-l4-exclusions> <fam> saddr [!=] <src-set> [saddr != <earlier-permit-set>] [<fam> daddr <dst-set>] [<l4-or-fragment>] counter name "<c>" drop`
  (NO fine `accept`); (4) ND/PMTUD/ICMP-error accepts; (5) residual
  `ct established,related accept` + per-zone coarse service accepts + catch-all
  drop (existing `emitHostInboundZone`) + unzoned catch-all drop.
- `hostInboundHasEnforceableView`/early-return: build the table when there is any
  **rendered** junos-host program OR any per-zone view OR unzoned addrs (guard on
  actually-emitted nonempty rules).

### 5.3 Reject / permit-restrict (follow-up, §6.5) — deferred rendering
When implemented, reject reuses the faithful pair already in the lo0 path
(`daemon_nft.go:1274`): `... meta l4proto 6 ... reject with tcp reset` +
`... reject with icmpx type admin-prohibited`, gated to coarse-admitted apps to
avoid the silent-drop-vs-reject divergence.

### 5.4 Metrics — `pkg/dataplane/userspace` (`xnft`) + `pkg/api`
- `HostInboundJunosHostDenyCounterName(scope, family)` + a
  `xpf_host_inbound_junos_host_denies_total{scope,family}` counter (scraped like
  #3361). Documented NOT to equal per-policy hit counters (§6.6).

### 5.5 Fail-closed apply
The junos-host deny rides `applyHostInboundFilter`'s atomic `nft -f -`. **Open
item for /engineer:** verify whether the host-inbound apply error actually fails
the commit or is a best-effort tail error (`daemon_apply.go` #4034 note treats
host-inbound nft errors as non-fatal-tail; `daemon_nft.go:234-243` claims it is
joined into the commit result). Adding a DENY means the retained-old-table on a
failed load is **less** restrictive, so a failed load must be surfaced (commit
warning/failure) rather than silently leaving the deny unenforced. Resolve this
explicitly; it is a correctness requirement, not optional.

### 5.6 Estimated size
~450-650 LOC Go across ~5 files + the parity fixture. No Rust/shim/hot-path
change.

---

## 6. Representability contract (per ordered chain)

A junos-host SCOPE is mirrored iff EVERY term in its ordered chain is
representable; otherwise the whole scope is left to the #4168 warning.

### 6.1 Representable term dimensions
- **Action:** `deny` → `drop`. `permit` is **never emitted as an nft `accept`**
  (that would let a fine permit bypass the coarse gate — Rust `mod.rs:138`);
  instead an earlier permit's matched set is SUBTRACTED from every later deny's
  match (§5.1 set-subtraction). A program whose net effect requires a terminal
  "deny everyone else" (a source-restricted permit with no following deny) is the
  §6.5 follow-up → warn.
- **Source:** every `source-address`/`source-address-excluded` token resolves —
  through the STATIC address book / static nested address-set — to a concrete
  commit-stable CIDR set (`any`/`any-ipv4`/`any-ipv6`/empty → match-all). Cross-
  family excluded handled per `matchAddr` (`policymatch.go:1282`): an excluded
  set present in only one family must not under-deny the other family.
- **Destination:** `destination-address`/`-excluded` resolves within the
  firewall-local set for the scope; `any` → the scope's firewall-local addrs. A
  destination naming a non-firewall address is unrepresentable (junos-host dest
  is the box).
- **Application:** `application`/application-set reduces (OR-expanded) to simple
  `Protocol` + optional `DestinationPort` (single/range) + optional `SourcePort`
  + optional ICMP type/code. Multiple members → multiple nft rules.

### 6.2 Un-representable (→ warn, no rule)
- **Feed-tainted source** — a token, OR ANY nested member, that resolves through
  the live feed overlay (`resolveToken`/`expandBookName` recurses,
  `policymatch.go:1306,1401`; a name can be simultaneously static and feed-backed,
  `policies_addrbook.go:361`). The implementation MUST inspect every node in the
  address closure against the feed bindings (resolving with an empty overlay
  alone is insufficient to detect same-name static+feed objects).
- **Multi-term / ALG-bearing applications**, application-sets not reducing to
  simple proto+port.
- **`SourcePort` that cannot be rendered** (rare) → term unrepresentable if not
  emitted.
- **Scheduler-gated policies** (`Policy.SchedulerName != ""`,
  `types_security.go:367`) — active only in time windows; a static nft rule is
  always-on and would over-enforce. Gate on `SchedulerName == ""`.
- **`tcp-rst` ingress zone** (`ZoneConfig.TCPRst`, `types_security.go:319`). With
  `tcp-rst`, Junos answers a TCP `deny` with a RST rather than a silent drop, so
  a silent-drop kernel rule would be a verdict-class divergence. A junos-host
  DENY program whose ingress zone has `tcp-rst` set is unrepresentable in the
  DENY (silent-drop) slice → warn; the reject follow-up (§6.5) renders the
  TCP-RST+ICMPx pair and lifts this.
- **Reject / source-restricted-permit-as-terminal programs** in the first slice
  (§6.5).
- Any future match dimension the nft input chain cannot express.

### 6.3 No over-/under-deny
A scope's rules are emitted only when the whole ordered chain is exactly
projectable; an unrepresentable term suppresses the scope's kernel enforcement
entirely (falls back to today's XSK-subset behaviour + warning), so no coarsened
or partially-ordered rule is ever emitted.

### 6.4 Coarse-then-fine ordering — CONCRETE DROP-only chain placement
Rust runs the coarse host-inbound admission then the fine junos-host policy
(`poll_descriptor/mod.rs:138,2285`), with ESP/AH genuinely fine-exempt (the
IPsec-passthrough stage returns before host-inbound) but ND/PMTUD/ICMP-error
merely COARSE-admitted (`host_inbound.rs:484`) — after which fine junos-host
STILL runs. The kernel chain reproduces this with this **exact rule order**
(specified, verified — not discovered — by the §9.1 fixture):

```
type filter hook input priority 10; policy accept;
# (1) ESP/AH — GENUINELY fine-exempt (IPsec-passthrough returns before fine).
meta l4proto { 50, 51 } accept
# (2) firewall-ORIGINATED reply traffic preserved (host-OUTBOUND flow return);
#     junos-host governs host-INBOUND original direction only.
ct state established,related ct direction reply accept
# (3) NEW junos-host DROP-ONLY subchain (per-ingress-zone effective program =
#     exact->from-any->global tiers, set-subtracted, ingress iifname-scoped; NO
#     fine accept ever emitted; match RESTRICTED to the fine-eligible L4 domain
#     per §6.7 — excludes ESP/AH, coarse-admitted IKE 500/4500, ident-reset 113).
#     Placed BEFORE the ND/PMTUD/ICMP-error accepts because those are COARSE
#     admissions after which Rust fine policy still runs, so a representable
#     `application any` deny MUST also drop the denied source's ND/PMTUD/ICMP-
#     error. Also before the residual established-accept + coarse service accepts,
#     so a denied source's NEW + original-direction-established inbound are
#     dropped (Rust per-hit re-eval/teardown, mod.rs:1291). Because NO fine accept
#     is emitted, a fine "permit" can NEVER re-admit a coarse-rejected service
#     (Rust mod.rs:138) — the coarse gate stays the sole admit authority.
<per-ingress-zone effective-program DROP rules (set-subtracted)>
# (4) ND/PMTUD/ICMP-error accepts for NON-denied sources.
icmpv6 type { 1,2,3,4 } ... accept ; icmpv6 type { 133..137 } ... accept
icmp  type { destination-unreachable, time-exceeded, parameter-problem } ... accept
# (5) residual established + coarse per-zone service accepts + catch-all drop
#     (existing emitHostInboundZone) + unzoned drop.
ct state established,related accept
<per-zone coarse accepts + catch-all drop>
<unzoned catch-all drop>
```

Notes: (i) DROP-only + set-subtraction is what makes this faithful — no fine
`accept` means a fine permit cannot bypass the coarse gate; permits only narrow
later denies. (ii) `application any`+`source any` deny is the extreme "lock down
all host-inbound from zone Z" case; lifelines are iifname-excluded so
management/ND on fxp0/em0/fab* is never affected. (iii) nft `drop` does not
delete conntrack state, but the rule (placed before the established-accept) drops
EVERY packet of the denied 5-tuple, so any lingering state is inert. The residual
established-accept (5) skipping a per-hit coarse recheck for NON-denied sources is
the EXISTING chain behaviour (pre-#4146), out of scope. (iv) A ground-truth on
whether Rust exempts pure ND (133-137) as adjacency vs subjecting it to fine
policy is a §9.1 fixture cell; if Rust exempts it, ND is hoisted to step (1).

### 6.5 Reject & source-restricted permit (tracked follow-ups, NOT re-defers)
`reject` (needs the TCP-RST+ICMPx pair gated to coarse-admitted apps, §5.3) and
the "deny non-permitted" half of a source-restricted `permit` (`saddr != S`) use
the IDENTICAL machinery and are tracked next slices in the same PR family. The
DENY slice alone un-defers the issue (the bug is a `then deny` unenforced). Until
then, scopes containing such terms are unrepresentable → warned.

### 6.7 Fine-eligible L4 domain — pre-fine terminal/exempt classes (Codex r3)
Rust runs certain classes BEFORE fine junos-host policy, so the fine DROP must
NOT touch them (else it converts a coarse-terminal verdict into a silent drop or
black-holes IPsec):
- **Raw ESP/AH (proto 50/51)** — IPsec passthrough (`poll_stages.rs` Stage 11)
  returns before fine. Exempt (already at chain step 1).
- **Coarse-admitted IKE / ESP-in-UDP NAT-T (UDP 500/4500)** — the same Stage 11
  passthrough covers IKE; it is reinjected to XFRM before fine when the ingress
  zone's host-inbound admits `ike`. A fine `application any` deny must NOT drop
  it.
- **`ident-reset` (TCP/113)** — a coarse-TERMINAL `reject with tcp reset`
  (`daemon_nft.go` ident-reset arm, #3310) when the ingress zone sets
  `system-services ident-reset`. Fine must not silence it into a drop.

**Rule:** the fine DROP subchain's match is restricted to the **fine-eligible L4
domain** — it excludes a class ONLY when that class's EFFECTIVE COARSE verdict is
a non-`accept` terminal/exempt (so excluding it does not create a fail-open):
- `meta l4proto {50,51}` (ESP/AH) — **always** excluded (Stage 11 passthrough is
  pre-fine, independent of the coarse token).
- `udp dport {500,4500}` (IKE/NAT-T) — excluded when the coarse gate admits IKE
  (`ike` token OR `all`/`any-service`); Stage 11 reinjects it to XFRM before fine.
  In a zone that admits neither, a NEW IKE is coarse-DROPPED regardless, so the
  exclusion is immaterial (drop either way) — no fail-open.
- `tcp dport 113` (ident-reset) — excluded **only when the effective coarse
  verdict is actually `reject with tcp reset`**: i.e. `ident-reset ∈ services`
  AND **NOT** `hostInboundAllowsAll(zone)` (Codex r4). In a `{ all, ident-reset }`
  / `any-service` zone the all-accept SHADOWS the ident-reset rule
  (`daemon_nft.go:661`, mirrored by Rust `forwarding.rs:399` short-circuiting on
  `all_services`), so 113 is coarse-ACCEPTED and MUST stay fine-eligible — else an
  `application any` deny would exempt 113 and then coarse-accept it, a silent
  rendered-policy fail-open. When neither ident-reset nor all applies, 113 is
  coarse-dropped, so the exclusion is immaterial.

Excluded classes fall through to their Rust-faithful coarse handling (ESP/AH
accept at step 1; coarse `ike` accept / passthrough; ident-reset RST). If a
junos-host deny's OWN application scope IS an exempt tuple (`then deny` on an
IKE/ident application), the program is **unrepresentable → warn** (the operator
is denying a class the IPsec/ident path owns; the DENY slice cannot faithfully
model it). Tests: `application any` deny in an `ike`-admitting zone does not drop
500/4500; in an `ident-reset` (NOT all) zone does not silence 113; in a
`{ all, ident-reset }` zone the deny DOES drop the denied source's 113 (no
fail-open); a deny scoped to an IKE/ident app warns.

### 6.6 Hit-counter honesty
The nft aggregate counter/metric does NOT populate per-Junos-policy hit counters,
`then count`, or RT_FLOW policy-deny attribution — the exact "counters stay zero"
symptom the issue reports for the direct path. nft cannot attribute a drop to a
Junos policy object. The implementation documents this explicitly (per-policy
attribution on the kernel path is out of scope; the userspace XSK path retains
its own attribution). This limitation is stated in the docs matrix.

---

## 7. Blast radius & risk analysis

- **Hot path?** No. Zero Rust; the shim and forwarding path are untouched; the
  #1864 ceiling is irrelevant.
- **Where it lands:** `pkg/daemon/daemon_nft.go`,
  `pkg/dataplane/userspace/junos_host_deny.go` (+ `zones_host_inbound.go` reuse),
  `xnft` counters, `pkg/api` collector, the #4168 warning suppression, docs, and
  the parity fixture. Control-plane only, evaluated at commit/config-apply.
- **Two-SSOT (#1319):** NOT a violation — that split is operational cmdtree vs
  config-mode schema (`docs/architecture.md:109`), not enforcement engines. The
  host-inbound design already has kernel-primary + Rust-secondary, both rendering
  from config. To guarantee they AGREE, the plan mandates a shared projection +
  cross-language parity fixtures (§9.1), addressing Codex's "sharing config alone
  does not prove semantic agreement."
- **Kernel/userspace agreement:** a direct packet hits exactly one path; the
  parity fixture pins identical verdicts for the representable subset.
- **Counter reset:** junos-host deny counters live in the atomically
  delete+recreated table → reset on rebuild like the existing per-zone counters
  (`rate()`-safe, documented).
- **Fail-closed apply:** §5.5 open item — a failed DENY load must be surfaced
  (retained old table is less restrictive).

---

## 8. Safety invariants (each gets a test)

1. **Lifeline never denied** — ingress `iifname` excludes fxp0/em0/fab*; a
   program resolving only to lifelines emits nothing (and warns). A **global-any**
   term is rendered per ingress zone with that zone's non-lifeline netdevs, NEVER
   as an unscoped rule, so it cannot fire on a lifeline/unzoned ingress.
2. **Ordered first-match fidelity via set-subtraction** — an earlier permit
   subtracts its set from every later deny's match (no fine `accept`, so a permit
   cannot bypass the coarse gate; no over-deny of carved-out sources).
3. **Single effective THREE-tier program per ingress** — exact zone-pair →
   from-any (#3090) → global tiers are gated + rendered as ONE program per ingress
   zone; an unrepresentable term in any contributing tier suppresses the whole
   program (no exposed global/from-any deny, no dropped carve-out permit).
4. **Ingress-scoped** — a deny fires only for traffic entering the from-zone's
   interfaces (no cross-zone under-/over-deny).
5. **Coarse gate is the sole admit authority** — no fine `accept` is emitted, so
   a fine permit can never re-admit a service the coarse host-inbound gate rejects
   (Rust `mod.rs:138`).
6. **Coarse-then-fine parity** — nft verdict == Rust `junos_host_local_policy`
   verdict across the fixture matrix (§9.1), including that an `application any`
   deny drops the denied source's ND/PMTUD/ICMP-error.
6b. **Fine-eligible L4 domain (§6.7)** — the DROP excludes a class only when its
   EFFECTIVE coarse verdict is a non-accept terminal/exempt: ESP/AH always;
   coarse-admitted IKE 500/4500; ident-reset 113 ONLY when its coarse verdict is
   the RST (ident-reset AND not `all`). A `{all, ident-reset}` zone keeps 113
   fine-eligible (no fail-open). A deny scoped to an exempt tuple warns.
7. **No transit impact** — the `input` hook sees only host-bound traffic;
   sustained iperf3 confirms zero forwarding regression.
8. **No over-deny** — whole-program representability gate (§6.3).
9. **Established-session parity — RESOLVED in §6.4 (SMR-F3 + Codex).** The
   concrete chain order accepts only `ct direction reply` established (firewall-
   ORIGINATED replies) ahead of the deny, then applies the deny to the denied
   source's NEW *and* original-direction-established inbound — matching Rust's
   per-LocalDelivery re-evaluation + session teardown
   (`poll_descriptor/mod.rs:1291`). Specified, not deferred. A source denied from
   its first packet never forms state.
10. **`tcp-rst` zone** — a junos-host deny program whose ingress zone has
    `tcp-rst` is unrepresentable in the DENY slice (silent-drop would diverge from
    Junos's RST); it warns (§6.2) until the reject follow-up.
11. **Deterministic payload** — ordered iteration over config slices.
12. **Warning suppressed only on rendered rules** — an unrepresentable /
    lifeline-only / no-address policy still warns (§6.3, §3.3).

---

## 9. Test plan

### 9.1 Cross-language parity fixture (the core guarantee — NEW)
A table-driven fixture feeds the SAME config + a matrix of synthetic packets
(ingress zone × source ∈ {denied, permitted-exception, other} × app ∈ {simple,
any} × family v4/v6 × {new, established, PMTUD/ICMP-error}) to BOTH:
- the nft projection (`BuildJunosHostPrograms` → rendered verdict), and
- the **authoritative** Rust `junos_host_local_policy` semantics — a Rust cargo
  test consuming the same config is the preferred oracle; the Go `policymatch`
  simulator may stand in ONLY where an existing contract test already pins it to
  the Rust path (do not invent a third semantics the fixture then validates
  against),
and asserts identical admit/deny verdicts for every representable cell, and that
every un-representable cell is warned + un-emitted.

### 9.2 Unit / golden (Go, `make test-go`)
- **Set-subtraction:** `permit source good` before `deny source 10/8` (good∈10/8)
  → a SINGLE `iifname{...} saddr 10/8 saddr != good ... drop` (NO fine `accept`
  emitted). Assert no `accept` line appears in a junos-host program.
- **Coarse gate sole authority:** a `permit application ssh` in a zone whose
  host-inbound-traffic omits ssh renders NO accept (ssh stays coarse-denied).
- **Effective THREE-tier composition:** exact → from-any → global assembled in
  order; a `from-any permit good` before a `global deny 10/8` renders
  `saddr 10/8 saddr != good drop` (the from-any carve-out is honored). An
  unrepresentable term in ANY tier suppresses the whole ingress program (assert
  the global/from-any deny is NOT rendered for that ingress).
- **Fine-eligible L4 domain (§6.7):** an `application any` deny in an
  ike-admitting zone does NOT drop UDP 500/4500; in an `ident-reset` (NOT all)
  zone does NOT silence TCP/113; in a **`{ all, ident-reset }`** zone DOES drop
  the denied source's 113 (no fail-open — the all-accept shadows the RST); never
  drops ESP/AH; a deny explicitly scoped to an IKE/ident application → NO rule +
  warning.
- iifname scope resolves VLAN subunit + RETH member netdevs, excludes lifelines.
- **global-any** deny renders per ingress zone with that zone's non-lifeline
  netdevs — assert it NEVER emits an unscoped rule and never matches a lifeline
  ingress.
- Under/over-deny guards: a deny scoped to from-zone wan matches only wan-ingress
  netdevs (assert via iifname, not daddr).
- source-address-excluded → `saddr != set`; cross-family excluded correctness.
- Applications: `junos-ssh` → `tcp dport 22`; app-set → multiple rules;
  `SourcePort` emitted; ICMP app → `icmp type…`; `any` → no L4.
- **ND/PMTUD placement:** an `application any source BAD deny` emits its drop
  BEFORE the ND/PMTUD/ICMP-error accepts (assert ordering), so BAD's PMTUD is
  dropped while another source's PMTUD is accepted.
- destination-address subset scoping; non-firewall dest → unrepresentable+warn.
- Representability gate: feed-tainted source (direct / nested / same-name
  static+feed), multi-term/ALG app, scheduler-gated, **tcp-rst ingress zone**,
  reject, source-restricted permit → NO rule + warning.
- Global `to-zone junos-host` with `FromZones` scope → iifname union; global-any
  → per-zone non-lifeline netdevs.
- Counter: every reference declared; early-return builds table only on rendered
  rules.
- Warning suppression keyed on rendered policies (lifeline-only / no-address
  representable policy still warns).
- nft payload parse-check (v1.1.6) for the new `iifname`/`saddr`/`daddr` lines.

### 9.3 Loss userspace cluster verification (required real-traffic proof)
Under the cluster lock (`./test/incus/with-cluster.sh`), on
`loss:xpf-userspace-fw0` (wan zone = reth0.50/reth0.80, admits `ping`,`gre`):
1. Baseline: `ping 172.16.50.8` from a WAN source SUCCEEDS.
2. Commit `set security address-book global address bad-host 172.16.80.200/32`
   + `from-zone wan to-zone junos-host policy block-bad match source-address
   bad-host; match application any; then deny`.
3. **MUST DROP:** host-bound packet from 172.16.80.200 to the WAN interface IP is
   dropped; `xpf_host_inbound_junos_host_denies_total` increments; no reply.
4. **MUST STILL ADMIT:** the same `ping` from a *different* WAN source succeeds.
5. **Ingress correctness:** a packet from 172.16.80.200 entering a DIFFERENT zone
   (e.g. lan) addressed to a lan IP is NOT dropped by the wan deny.
6. **No forwarding regression:** sustained iperf3 v4 + v6 (172.16.80.200) holds
   line rate.
7. Re-apply CoS after deploy.

### 9.4 Regression
- `make test` (Go + Rust cargo — the untouched Rust leg must stay green, #4006).
- Existing host-inbound tests + `compiler_junos_host_direct_warn_4146_test.go`
  updated: representable denies no longer warn (now enforced), un-representable
  ones still warn.
- Active/backup RETH/VIP host-inbound cases (Codex).

---

## 10. Documentation updates (part of the /engineer contract)

- `docs/host-inbound-service-matrix.md` §"`to-zone junos-host` … direct
  host-bound path (#4146)": record that the **representable ordered DENY class is
  now kernel-enforced (direction b)** with ingress-zone scope and coarse-then-fine
  order; describe the representability contract; state the un-representable tail
  as a **documented partial-coverage limitation** (NOT "Junos-correct"); state the
  hit-counter honesty note (§6.6) and the established-session parity decision
  (§8-inv-7).
- Update the #4168 warning prose to reflect suppression-on-render.
- `pkg/daemon/daemon_nft.go` head comment: the junos-host deny subchain, its
  ingress scope, and its coarse-then-fine placement.
- `_Log.md` per project rules.

---

## 11. Alternatives, PLAN-KILL analysis, rollout

### 11.1 Rejected alternatives
- **Direction (a) userspace redirect** — fail-closed posture inversion + verifier
  ceiling (§3.1).
- **daddr scoping** — under-/over-denies across zones; #3718 does not prevent it
  (§3.2). Replaced by iifname ingress scope.
- **Per-term deny emission** — ignores first-match ordering (§3.2). Replaced by
  the single per-ingress effective-program projection.
- **Fine `permit→accept` rules** — would let a fine permit re-admit a
  coarse-rejected service (Rust `mod.rs:138`). Replaced by DROP-only
  set-subtraction (a permit narrows later denies via `saddr !=`; no fine accept).
- **fine-before-coarse / silent-drop in a tcp-rst zone** — a tcp-rst zone answers
  a TCP deny with a RST; silent drop diverges, so such programs are
  unrepresentable in the DENY slice (§6.2) and reject is deferred (§6.5).
- **Strict-reject the remainder (i)** — refuses legal, XSK-enforced configs;
  recorded as a possible future hybrid (strict-reject-new / lenient-warn-loaded,
  per `compiler.go:40`) if the operator later prefers it.
- **Do nothing / keep deferring** — disallowed; the gap is real and the kernel
  locus is available.

### 11.2 PLAN-KILL analysis (why PLAN-READY, not PLAN-KILL)
Both hostile reviewers confirm the kernel-nft locus is correct and salvageable
and that direction (b) preserves helper-crash availability. The r1/r2 emission
bugs (ordering, daddr, coarse/fine) are corrected here into an ordered,
ingress-scoped, coarse-gated, parity-verified projection with a whole-chain
representability gate — a bounded, Go-only, well-specified fix. There is a real
fix that closes the security gap without a posture regression. PLAN-KILL is not
warranted.

### 11.3 Rollout / backout
- One PR (DENY slice) on the #4146 enforcement half; #4168 warning + docs remain
  the safety net for the tail; reject / source-restricted-permit slices follow in
  the same family.
- Backout is a pure `git revert` (control-plane only; no on-disk/Rust/ABI change).
- Config compatibility: existing configs keep loading; a previously-warned
  representable deny starts being enforced (the intended change), surfaced in
  commit output + docs.

---

## Appendix A — key code references (base `b4f2ddb2f`)
- Shim shunt: `userspace-xdp/src/lib.rs:589-604`, `:621-632`, `:1139`, `:1064`.
- Rust coarse-then-fine: `userspace-dp/src/afxdp/poll_descriptor/mod.rs` ~2202
  (coarse `host_inbound_gated_lo0_action`), ~2230/:2280 (fine
  `junos_host_local_policy`), `:1291` (session re-eval/teardown),
  `userspace-dp/src/policy.rs:2905`.
- Kernel codegen: `pkg/daemon/daemon_nft.go:244,501,656,450`; reject pair `:1274`;
  counter multi-ref `:509`.
- View/address/lifeline: `pkg/dataplane/userspace/zones_host_inbound.go:80,188,211,353`.
- Ingress-correct-model precedent: `pkg/config/dup_host_local_address.go:32,43`.
- Policy/app/address structs: `pkg/config/types_security.go:367` (SchedulerName),
  `:392` (PolicyMatch incl. Destination*), `:1088` (Application incl. SourcePort),
  `:1029` (Address).
- Resolution to reuse: `pkg/policymatch/policymatch.go:1244-1330` (matchAddr /
  resolveToken / cross-family excluded), `:1605` (SourcePort), `:1401` (recursive
  feed expand), `pkg/dataplane/userspace/policies_addrbook.go:361` (same-name
  static+feed); `pkg/config/predefined.go:190,207` (ResolveApplication[Set]).
- #4168 warning to adjust: `pkg/config/compiler_validate_warn.go:2191,2227`.
- Apply-error semantics: `pkg/daemon/daemon_apply.go` (#4034 tail), `daemon_nft.go:234-243`.
- Docs: `docs/host-inbound-service-matrix.md:526`.
