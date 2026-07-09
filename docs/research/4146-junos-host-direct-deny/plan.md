# Plan of Action — #4146 host-inbound: `to-zone junos-host` deny not enforced for direct host-bound traffic

- **Issue:** #4146
- **Branch:** `research/4146-junos-host-direct-deny`
- **Base:** origin/master `b4f2ddb2f`
- **Revision:** r2 (folds Claude SMR r1 findings F1-F4)
- **Status:** seeking convergence (Codex + Claude SMR; AGY infra-down)
- **Disposition sought:** PLAN-READY (a shippable enforcement fix), un-deferring the mislabeled `plan-deferred-operator`.

> This is `/research`, not `/engineer`. It stops at PLAN-READY (or PLAN-KILL).
> No production code is touched here; the deliverable is this doc + reviewer
> verdicts + issue comments.

---

## 0. TL;DR / decision resolved

The issue was parked as `plan-deferred-operator` waiting on an "operator
decision" about how to handle junos-host DENY policies that use match
dimensions nftables cannot represent. **That is a design question, and this
plan resolves it with a safe, Junos-parity-correct default** rather than
deferring again:

- **Enforce the junos-host DENY on the direct host-bound path in the KERNEL
  nft `xpf_hostinbound` chain (direction b).** This is the *only* locus that
  (1) actually sees the packet — a direct host-bound packet is delivered by the
  kernel, never by userspace-dp — and (2) is availability-preserving
  (helper-independent), exactly matching where Junos enforces host-inbound (the
  RE control-plane filter). It is **Go-only**, touches **no Rust hot path**, and
  is fully independent of the shim verifier ceiling that blocked the previously
  chased userspace-redirect approach (direction a).
- **Scope the kernel enforcement to the nft-representable subset**: action
  `deny`/`reject`, `match source-address`/`source-address-excluded` resolved to
  concrete CIDRs from the *static* address book, and `match application`
  reducible to a simple proto (+ optional port / ICMP type-code). This subset
  covers the entire security-motivating class ("deny a bad source to the box";
  the fable-164 scenario).
- **Remainder handling (the resolved operator decision): enforce the
  representable subset in the kernel; for a junos-host DENY carrying an
  UN-representable dimension (multi-term/ALG apps, dynamic-feed-backed
  sources), emit NO partial kernel rule (to avoid over-/under-deny) and keep the
  already-shipped #4168 commit WARNING.** We do **not** blanket-reject the
  config (that breaks vSRX config-load parity and refuses policies that
  userspace-dp *does* partially enforce on the XSK subset), and we do **not**
  leave everything userspace-only (that is the status quo bug).

Net: the primary security gap ("a configured deny to the firewall's own host is
silently unenforced") is closed for the representable class using the existing,
tested, fail-closed kernel chain; the honest #4168 warning remains for the
un-representable tail.

---

## 1. Problem statement & issue history

### The bug (security/correctness)
A `from-zone X to-zone junos-host { match source-address <bad>; then deny; }`
policy (or a global `match to-zone junos-host` deny) on a plain firewall
interface IP is **silently unenforced** for direct host-bound traffic. A
management-plane DENY that should stop a bad source from reaching the firewall's
own services reaches the host stack unfiltered; the policy hit counters stay
zero. Labels on the issue: `bug`, security, enforcement-gap, host-inbound,
vsrx-parity.

### Why it kept getting deferred (issue comments, verbatim thread)
1. **First research pass (PLAN-DEFER):** rejected direction (a) (route the
   packet through userspace-dp so its `LocalDelivery` gate enforces the deny)
   because the shim's XSK redirect-error arm is fail-CLOSED
   (`drop_degraded_transit → XDP_DROP`), so a helper crash would drop *all*
   host-bound traffic to the mgmt IP — inverting the "management always
   reachable" posture. Shipped direction (c): a commit-time WARNING (#4168) plus
   a docs note. Left the enforcement half open.
2. **Second pass (`plan-deferred-research → plan-deferred-operator`):**
   identified direction (b) (kernel nft mirror) as the Junos-parity-correct
   locus but deferred on the "remainder contract" — whether to reject/partial/
   leave-userspace policies whose match dimensions nft cannot represent, framed
   as an operator/product call.
3. **DRIVE-ROUND-5 (2026-07-08):** re-analysed and concluded "can't be enforced
   in userspace-dp … same shim-layer wall as #4478 … shim at the #1864 verifier
   ceiling 990,796/1M insns," recommending a shim-budget-reclaim research.

### Why the deferral is wrong — the reframing that un-defers it
The DRIVE-ROUND-5 conclusion is correct that the fix cannot go in
**userspace-dp** — but that is the wrong place to look. **The direct host-bound
packet is delivered by the Linux kernel, so the enforcement belongs in the
kernel `xpf_hostinbound` nft chain, which is already the documented PRIMARY
host-inbound enforcement path (#3070).** That path is availability-preserving
(helper-independent, mirrors Junos's RE control-plane filter), never touches the
shim, and is fully unblocked by the verifier ceiling. The only genuine open
question was the remainder contract — a design decision, resolved in §3.

---

## 2. Verified root-cause chain (file:line, at base `b4f2ddb2f`)

1. **Direct host-bound packets are shunted to the kernel by the shim, never
   reaching userspace-dp:**
   - Session-HIT local delivery: `userspace-xdp/src/lib.rs:589-604` —
     `USERSPACE_SESSION_ACTION_PASS_TO_KERNEL` arm → `cpumap_or_pass(ctrl)`
     (kernel).
   - Session-MISS local delivery: `userspace-xdp/src/lib.rs:621-632` —
     `if is_local_destination(&parsed) { … return Ok(cpumap_or_pass(ctrl)); }`
     (kernel).
   - `cpumap_or_pass` (`lib.rs:1139`) redirects to cpumap else `XDP_PASS` —
     **always the kernel stack, never the XSK**.
2. **The fine junos-host gate lives only on the XSK path.**
   `junos_host_local_policy` runs only under `ForwardingDisposition::
   LocalDelivery` (`userspace-dp/src/afxdp/poll_descriptor/mod.rs`, plus the
   #3292 flowless arm) — a disposition a direct-to-interface-IP packet never
   reaches because it was shunted at step 1. `LocalDelivery` is reached only by
   the narrow subset that stays on the XSK (DNAT/static-NAT-to-self, embedded
   ICMP, DNS edge cases), per `pkg/dataplane/userspace/zones_host_inbound.go:11-19`.
3. **The kernel host-inbound chain has zero junos-host awareness.**
   `buildHostInboundFilterPayload` (`pkg/daemon/daemon_nft.go:501`) +
   `emitHostInboundZone` (`:656`) emit, per zone/family: global
   `ct established,related accept` + ESP/AH + ND/PMTUD accepts, then per-zone
   **permit-by-service** accepts (`<fam> daddr <zone-addrs> <svc-match> accept`)
   from **any source**, then a catch-all `<fam> daddr <zone-addrs> counter drop`.
   There is **no source-address dimension and no per-application deny**.
   `grep -rin "junos.host" pkg/daemon/` returns nothing in the codegen.

**Net:** the coarse kernel permit-by-service gate admits the packet; the fine
junos-host deny (which lives only in userspace-dp `LocalDelivery`) never sees
it. Distinct from #3019 (wired the deny into the XSK `LocalDelivery` arm) and
#3292 (flowless arm) — this is the direct-to-interface path that never reaches
`LocalDelivery` at all.

---

## 3. Design space & the resolved operator decision

### 3.1 Enforcement locus (a/b/c)
| Dir | Mechanism | Verdict |
|-----|-----------|---------|
| (a) Withhold junos-host IPs from `USERSPACE_LOCAL` → force the XSK/`LocalDelivery` path | Route the packet through userspace-dp so its existing gate enforces the deny | **REJECTED.** Shim redirect-error arm is fail-CLOSED (`drop_degraded_transit`, `lib.rs:1064`), so a helper crash drops ALL host-bound traffic to the mgmt IP — inverts Junos's "management always reachable" posture. Also blocked by the #1864 shim verifier ceiling (~990k/1M insns) per DRIVE-ROUND-5. Wrong posture AND infeasible. |
| (b) Enforce junos-host DENY in the KERNEL nft `xpf_hostinbound` chain | Add source/app-scoped DENY rules ahead of the per-zone service accepts | **CHOSEN.** The kernel is where the packet actually goes; kernel enforcement is helper-independent (Junos-parity locus); Go-only; no Rust hot path; sidesteps the verifier ceiling entirely. |
| (c) Commit-time warn + docs | #4168 — already shipped | Complementary; retained for the un-representable remainder. Not an enforcement fix on its own. |

### 3.2 The remainder decision (i/ii/iii) — RESOLVED
The deferred "operator decision" is how to handle a junos-host DENY whose match
uses a dimension nft cannot represent:

- **(i) commit-REJECT the un-representable policy** — REJECTED. Breaks vSRX
  config-load parity (Junos accepts these), refuses policies that userspace-dp
  *does* enforce on the XSK subset, and can brick a previously-committed config
  on upgrade. Rejecting a legal config makes the box *less* usable without
  making traffic *more* secure.
- **(ii) enforce the representable subset in the kernel; warn on the
  remainder** — **CHOSEN.** Emit a kernel DENY rule *only* when the entire match
  is representable (so we can never over-deny by coarsening an app to its port,
  nor under-deny). For any policy with an un-representable dimension, emit no
  kernel rule and keep the shipped #4168 WARNING. Closes the gap for the whole
  security-critical representable class; stays honest (warned) for the tail;
  zero availability regression.
- **(iii) leave everything userspace-only** — REJECTED. That is the status quo
  bug: the primary "deny bad source to the box" case stays unenforced on the
  direct path.

### 3.3 Why (ii) is the safe/Junos-correct default (documented rationale)
- **Security:** closes the enforcement gap for the exact class the finding is
  about (source-scoped deny to a firewall service), using the fail-closed kernel
  chain that already carries ~100% of real host-bound traffic.
- **Availability:** kernel enforcement is helper-independent, so a dataplane
  crash never strands or over-blocks management — the property Junos guarantees
  by enforcing host-inbound in the RE control-plane filter.
- **No over-deny:** the representability gate means a coarsened rule is never
  emitted; an app that does not reduce to a simple proto+port is left to the
  warning, not mirrored as a broad port drop.
- **No parity regression:** legal Junos configs still load; the un-representable
  tail keeps working exactly as today (userspace-dp on the XSK subset + honest
  warning).

---

## 4. Chosen approach (summary)

Extend the existing kernel host-inbound codegen to honour `to-zone junos-host`
DENY/REJECT policies for the direct host-bound path:

1. Build a per-scope list of **junos-host deny terms** from the config
   (zone-pair `from-zone X to-zone junos-host` and global `match to-zone
   junos-host`), keeping only DENY/REJECT actions whose match is **fully
   nft-representable** (§6).
2. Resolve each term to an nft rule fragment: source-address set (or `!=` for
   `source-address-excluded`) + optional L4 proto/port (or ICMP type/code from
   the application), scoped to the from-zone's firewall-local addresses via the
   existing `BuildZoneHostInboundViews` daddr resolution (global terms scope to
   the union of all host-inbound addresses).
3. Emit these DENY rules in the `xpf_hostinbound` chain **after** the global
   `ct established,related` / ESP-AH / ND-PMTUD accepts and **before** the
   per-zone service accepts (Junos first-match ordering: the deny tightens the
   coarse service admit).
4. Attach a named counter (following the existing `HostInboundDenyCounterName`
   discipline) so the junos-host kernel denies are scrapeable, distinct from the
   per-zone catch-all deny counter.
5. Keep the #4168 warning firing for junos-host policies that are *not* mirrored
   (un-representable, or source-restricted permits deferred to a follow-up —
   §6.4), and refresh the docs matrix to say the representable DENY class is now
   kernel-enforced.

---

## 5. Detailed implementation plan (for /engineer — not executed here)

**All changes are Go. No Rust, no shim, no verifier interaction.**

### 5.1 New builder — `pkg/dataplane/userspace/zones_host_inbound.go` (or a sibling `junos_host_deny.go`)
- `type JunosHostDenyRule struct { Zone string; Family string; SrcSet []string; SrcExcluded bool; L4Match string; Action string /* drop | reject */; Counter string }`.
- `func BuildJunosHostDenyRules(cfg *config.Config) []JunosHostDenyRule`:
  - Iterate `cfg.Security.Policies` where `ToZone == "junos-host"` and each
    `p.Action ∈ {PolicyDeny, PolicyReject}`; iterate `cfg.Security.GlobalPolicies`
    where `IsHostToZoneScope(p.Match.ToZones)` and action deny/reject.
  - **Representability gate** (`junosHostDenyRepresentable`, §6): skip (leave to
    warning) any term whose source or application is not fully representable.
  - Resolve `SourceAddresses` (+`SourceAddressExcluded`) to concrete CIDRs using
    the *same static* address-book resolution the policy simulator uses
    (`resolveToken` semantics in `pkg/policymatch/policymatch.go:1306`, static
    path only — **no feed overlay**, since feeds are runtime-mutable §6.2). Split
    by family.
  - Resolve `Applications` to L4 fragments via `config.ResolveApplication`
    (`pkg/config/predefined.go:190`): `Protocol` + `DestinationPort` →
    `tcp dport <p>` / `udp dport <p>` / port-range; ICMP type/code → `icmp[v6]
    type <t> [code <c>]`; `any` → no L4 fragment.
  - Daddr scope: reuse `BuildZoneHostInboundViews(cfg)` addresses for the
    from-zone (zone-pair) or the union of all view addresses (global). This
    reuses the tested lifeline-exclusion + address-resolution machinery, so a
    junos-host deny inherits the same "never scope a lifeline address" safety.
- Emit per (rule, family) with a stable sort (config order) for deterministic
  payloads.

### 5.2 Codegen — `pkg/daemon/daemon_nft.go`
- `buildHostInboundFilterPayload` gains a `denyRules []dpuserspace.JunosHostDenyRule`
  parameter (built in `applyHostInboundFilter` alongside `views`).
- **Counter pre-pass:** declare each junos-host deny counter once (dedup on
  name), mirroring the existing per-zone counter discipline (`addCounter`).
- **Rule emission order** inside `chain input`:
  1. `type filter hook input priority 10; policy accept;`
  2. `ct state established,related accept`
  3. `meta l4proto { 50, 51 } accept` (ESP/AH)
  4. ICMP ND / error / PMTUD accepts
  5. **NEW: junos-host DENY rules** — one per term:
     `[<fam> daddr <zone-addrs>] <fam> saddr [!=] <src-set> [<l4-match>] counter name "<c>" <drop|reject with icmp/tcp>` .
  6. Per-zone service accepts + catch-all drop (existing `emitHostInboundZone`).
  7. Unzoned catch-all drop (existing).
  - Placing (5) after (2)-(4) means: a denied source's *new* connection (SYN /
    fresh datagram) hits the deny and is dropped; established return traffic for
    a firewall-*originated* flow, ND, PMTUD, and host-terminated IPsec are never
    collaterally dropped — the same discipline the existing chain uses.
- `reject` action → `reject` (Junos `then reject` sends an ICMP admin-prohibited
  / TCP RST; use nft `reject with icmpx type admin-prohibited` for v4/v6 parity,
  matching the existing `ident-reset` reject precedent at `daemon_nft.go:729`).
- Update `hostInboundHasEnforceableView`'s early-return guard so a config with
  *only* junos-host deny rules (no per-zone view) still builds the table.

### 5.3 Metrics — `pkg/dataplane/userspace` nft counter helpers (`xnft`)
- Add `HostInboundJunosHostDenyCounterName(scope, family)` and scrape it into a
  new `xpf_host_inbound_junos_host_denies_total{scope,family}` gauge/counter in
  the Prometheus collector (`pkg/api`), following the #3361 pattern. Reuses
  `ParseHostInboundDenyCounterName`-style readback.

### 5.4 Wiring
- `applyHostInboundFilter` builds `denyRules` and passes them to
  `buildHostInboundFilterPayload`; the fail-closed apply/teardown semantics are
  unchanged (the deny rides the same atomic `nft -f -` load).

### 5.5 Estimated size
~250-350 LOC Go across 3-4 files + tests. No change to any Rust crate, the
shim, the control socket, or the hot path.

---

## 6. Representability contract (precise — the crux of the remainder decision)

A junos-host DENY term is **mirrored to the kernel** iff EVERY dimension below
is representable; otherwise it is **left to the #4168 warning** (no kernel rule).

### 6.1 Representable
- **Action:** `then deny` → nft `drop`; `then reject` → nft `reject with icmpx
  admin-prohibited`.
- **Source:** `match source-address <a…>` / `source-address-excluded` where every
  named token resolves — through the *static* address book / address-set
  (nested static sets included) — to a concrete, commit-time-stable CIDR set.
  `any`/`any-ipv4`/`any-ipv6`/empty → match-all source (a blanket deny; still
  representable).
- **Application:** `match application <app>` where the app (or every member of an
  application-set) resolves via `ResolveApplication` to a **single simple
  form**: one `Protocol` with an optional `DestinationPort` (single or range)
  and optional ICMP type/code. `any` → no L4 constraint.

### 6.2 Un-representable (→ leave to warning, no kernel rule)
- **Dynamic-feed-backed source** (an address-name whose value comes from a live
  feed overlay). A static nft set would go stale as the feed updates; the feed
  path is a runtime overlay the userspace-dp enforces, not a commit-time
  constant. **This includes a static-looking address-SET that NESTS a feed-bound
  member** (SMR-F2): `resolveToken`/`expandBookName`
  (`pkg/policymatch/policymatch.go:1306-1323`) is feed-aware *recursively*, so a
  source token is un-representable if the token OR any nested member resolves
  through the feed overlay. The implementation MUST reject the whole term (leave
  to warning) whenever resolving any source token would pull in feed CIDRs —
  checked by resolving with an EMPTY feed overlay and separately confirming no
  token is feed-bound. Only tokens whose entire resolution is static
  address-book / static nested address-set are representable.
- **Multi-term custom applications**, **ALG-bearing** apps (the ALG semantics
  are not a port match), and application-sets that do not reduce to a single
  simple proto+port form.
- Any match dimension a future Junos construct adds that nft input-chain cannot
  express.

### 6.3 Why the gate prevents over-/under-deny
Because a kernel rule is emitted ONLY when the whole match is representable, we
never coarsen (e.g. never turn "deny custom-app-on-443-with-ALG" into "drop all
tcp/443") and never widen an excluded set incorrectly. An un-representable term
produces exactly the current behaviour + the honest warning — a strict superset
of today's safety.

### 6.4 Source-restricted PERMIT (scope note)
A `to-zone junos-host` *source-restricted permit* ("only source S may reach
service X") is representable as "deny X from `saddr != S`", but it flips the
default and interacts with the coarse per-service accept. **This plan's
must-ship scope is DENY/REJECT** (the finding's security case). Source-restricted
permits stay on the #4168 warning for now; enforcing them in the kernel is a
clean follow-up using the IDENTICAL machinery (`saddr !=` form) and is a
**TRACKED next slice in the same PR family, NOT a re-defer of #4146** (SMR-F4):
the security bug this issue names — a `then deny` silently unenforced — is closed
by the DENY/REJECT slice; the permit slice is an additive completeness item.
/engineer MAY fold it into the same PR if reviewers prefer, but the issue is
un-deferred by the DENY slice alone.

---

## 7. Blast radius & risk analysis

- **Hot path?** No. Zero Rust changes; the userspace-dp forwarding path and the
  shim are untouched. The #1864 verifier ceiling is irrelevant.
- **Where the change lands:** `pkg/daemon/daemon_nft.go`,
  `pkg/dataplane/userspace/zones_host_inbound.go` (+sibling),
  `pkg/dataplane/userspace` counter helpers, `pkg/api` collector, plus the
  #4168 warning tweak and docs. All Go control-plane, evaluated at commit /
  config-apply, not per packet.
- **Two-SSOT (#1319) concern:** NOT a violation. The config remains the single
  source of truth; both the kernel nft chain and the Rust classifier *render*
  from it — the host-inbound design already documents the kernel path as the
  PRIMARY enforcer and the Rust `LocalDelivery` as the secondary mirror
  (`daemon_nft.go:216-232`, `zones_host_inbound.go:11-19`,
  `hostInboundMatchSet` "Go/nftables MIRROR of the Rust classifier"). This
  extends the existing primary path with one more dimension it already should
  have honoured; it does not create a second SSOT.
- **Kernel/userspace agreement:** a direct host-bound packet goes to exactly one
  path (kernel), so there is no double-drop. For the XSK subset, userspace-dp's
  `junos_host_local_policy` already denies the same source — both render from the
  same config, so they agree; a golden test pins parity (§9).
- **Counter reset semantics:** the junos-host deny counters live in the same
  table that is atomically delete+recreated on every commit / lease change, so
  they reset on rebuild exactly like the existing per-zone deny counters
  (documented, `rate()`-safe).
- **Failure mode:** the deny rides the existing fail-closed atomic `nft -f -`
  load; a malformed payload rejects the WHOLE table (chain absent = the prior,
  equal-or-more-restrictive table is retained), and `applyConfigLocked`
  surfaces the error as commit FAILURE (`daemon_nft.go:234-243`). A junos-host
  deny that did not reach the kernel therefore reports failure, never silent
  success.

---

## 8. Safety invariants (must hold; each gets a test)

1. **Lifeline never denied.** Source/daddr scoping reuses
   `BuildZoneHostInboundViews`, which excludes fxp0 / em0 / fab* — a junos-host
   deny can never strand management or break HA.
2. **Established / ND / PMTUD / ESP-AH accepted before any junos-host deny** —
   the deny rules are emitted after those global accepts, so core L3/control and
   host-terminated IPsec are never collaterally dropped.
3. **No transit impact.** The nft `input` hook only sees host-bound (locally
   delivered) traffic; forwarded/transit packets never traverse this chain.
   Sustained iperf3 through the box confirms zero forwarding regression.
4. **No over-deny.** The representability gate (§6) guarantees a kernel rule is
   emitted only when the entire match is exactly representable.
5. **Deterministic payload.** Iteration over ordered policy slices → stable nft
   payload across commits (no map-iteration nondeterminism).
6. **Fail-closed load** preserved (§7).
7. **Established-session survival is expected, not a bypass (SMR-F3).** Because
   the deny rules sit after `ct state established,related accept`, a session the
   bad source established BEFORE the deny was committed survives until it closes
   — the deny applies to NEW connections, matching the existing per-zone chain
   and Junos's practical host-inbound behaviour. A source denied from the start
   never forms an established state (its SYN/first datagram is dropped), so there
   is no exploitable bypass. Documented in the docs matrix (§10).

---

## 9. Test plan

### 9.1 Unit / golden (Go, `make test-go`)
- `buildHostInboundFilterPayload` golden: a `from-zone wan to-zone junos-host`
  deny with a concrete source book-entry emits
  `ip saddr <cidr> ... counter name "<c>" drop` BEFORE the per-zone `ping`/`gre`
  accepts and AFTER the established/ND accepts.
- `source-address-excluded` → `saddr != <set>`.
- Application `junos-ssh` → `tcp dport 22`; ICMP app → `icmp type …`;
  application `any` → no L4 fragment.
- **Representability gate:** a deny whose source is a *feed-backed* address, or
  whose application is a multi-term/ALG app, emits **no** kernel rule AND still
  produces the #4168 warning (both asserted).
- Global `match to-zone junos-host` deny scopes to the union of host-inbound
  addresses.
- Counter declaration/reference agreement (declared once, referenced once) —
  extend the existing counter-agreement test.
- Lifeline-exclusion test: a junos-host deny cannot scope fxp0/em0/fab* addrs.
- nft payload parse-check (the existing `TestHostInboundFilter…PayloadParses`
  pattern) so v1.1.6 accepts the new `saddr`/`reject` lines.

### 9.2 Loss userspace cluster verification (the required real-traffic proof)
Run under the cluster lock (`./test/incus/with-cluster.sh`), on
`loss:xpf-userspace-fw0`:
1. Baseline: `ping 172.16.50.8` (wan zone admits `ping`) from a WAN-side source
   on VLAN 50/80 SUCCEEDS.
2. Commit:
   ```
   set security address-book global address bad-host 172.16.80.200/32
   set security policies from-zone wan to-zone junos-host policy block-bad match source-address bad-host
   set security policies from-zone wan to-zone junos-host policy block-bad match destination-address any
   set security policies from-zone wan to-zone junos-host policy block-bad match application any
   set security policies from-zone wan to-zone junos-host policy block-bad then deny
   ```
3. **MUST DROP:** a host-bound packet from 172.16.80.200 to the firewall's WAN
   interface IP (e.g. `ping`/TCP SYN to 172.16.50.8 or 172.16.80.8) is dropped;
   `xpf_host_inbound_junos_host_denies_total` increments; no reply.
4. **MUST STILL ADMIT:** the same `ping` from a *different* WAN source succeeds
   (coarse service gate unchanged for non-denied sources).
5. **No forwarding regression:** sustained iperf3 v4 + v6 through the box
   (172.16.80.200 target) holds line rate — the input-chain deny never touches
   transit.
6. Re-apply CoS after deploy (deploy wipes CoS).

### 9.3 Regression
- `make test` (Go + Rust cargo — the Rust leg must still pass even though it is
  untouched, per the #4006 gate).
- Existing host-inbound tests (`host_inbound_nft_test.go`,
  `nft_chain_priority_test.go`, `compiler_junos_host_direct_warn_4146_test.go`)
  stay green; the warning test is updated so representable denies no longer warn
  (they are now enforced) while un-representable ones still do.

---

## 10. Documentation updates (part of the /engineer contract)

- `docs/host-inbound-service-matrix.md` §"`to-zone junos-host` policy and the
  direct host-bound path (#4146)": change "Enforcement (directions a/b —
  deferred)" to record that the **representable DENY/REJECT class is now
  kernel-enforced (direction b)**; keep the availability rationale; describe the
  representability contract and the un-representable tail that keeps the warning.
- Adjust the #4168 warning prose so it no longer implies enforcement is fully
  deferred — it now warns only for the un-representable tail (and, until the
  §6.4 follow-up, source-restricted permits).
- Add a short design note to `pkg/daemon/daemon_nft.go` head comment describing
  the junos-host deny rule block and its ordering.
- Record in the docs matrix the two documented properties: (1) the deny applies
  to NEW connections (an established session predating the commit survives until
  it closes — SMR-F3), and (2) the bounded, safe-side daddr over-deny for a
  named-bad source arriving via an unexpected zone (SMR-F1).
- `_Log.md` per the project logging rules.

---

## 11. Alternatives considered, PLAN-KILL analysis, and rollout

### 11.1 Alternatives rejected
- **Direction (a) userspace redirect** — fail-closed posture inversion + shim
  verifier ceiling (§3.1). Rejected.
- **iifname (ingress-interface) scoping instead of daddr scoping** — Junos keys
  the from-zone on the ingress interface, so `iifname <from-zone netdevs>` is the
  literal parity. Rejected as the primary because (1) it adds VLAN-subunit /
  RETH netdev-name resolution fragility, and (2) it would make junos-host deny
  *more* precise than the rest of the chain, which is already destination-scoped
  (`daddr`) by accepted design (#3718 Option B). daddr-scoping reusing
  `BuildZoneHostInboundViews` reuses tested machinery and is exactly as
  destination-scoped as the existing chain.
  **The bounded over-deny, and why it is safe (SMR-F1):** daddr-scoping CAN
  differ from strict Junos from-zone semantics in an asymmetric-routing/spoofing
  case — a packet from the named-bad source arriving on a *different* zone's
  interface but destined to the from-zone's firewall IP is dropped by our
  `daddr {W} saddr BAD drop` rule, whereas Junos (from-zone = the ingress zone)
  would not apply the wan-zone policy. This over-deny is acceptable and safe
  because: (a) it is **bounded to the explicitly-named bad source** — no source
  the operator did not name in a deny is ever affected; (b) for a DENY,
  dropping a spoofed/asymmetric packet from a named-bad source to a firewall IP
  is the **safe-side error**; and (c) it is **consistent with the existing
  daddr-only chain** (#3718 Option B), introducing no new class of imprecision.
  The strict-commit gate already rejects the multi-zone-reachable-address
  *ambiguity*. iifname is an optional later precision upgrade if a concrete case
  ever demands strict from-zone semantics; it is not required.
- **Commit-REJECT the un-representable remainder (option i)** — breaks vSRX
  config-load parity and refuses partially-enforced configs (§3.2). Rejected.
- **Do nothing / keep deferring** — explicitly disallowed by the task; the
  security gap is real and the kernel locus is available.

### 11.2 PLAN-KILL analysis (why this is PLAN-READY, not PLAN-KILL)
The candidate kill arguments are all answered: (SSOT) it extends the existing
primary path, not a new source of truth; (over-deny) the representability gate
forecloses it; (availability) kernel enforcement is helper-independent, the
Junos posture; (complexity) ~300 LOC Go reusing tested resolution + chain
machinery, no hot path. There is a real, bounded, testable fix that closes the
security gap. PLAN-KILL is not warranted.

### 11.3 Rollout / backout
- Ships as one PR on the #4146 enforcement half; the #4168 warning + docs remain
  the safety net for the un-representable tail.
- Backout is a pure `git revert` (control-plane-only; no on-disk migration, no
  Rust/ABI change). On revert the chain returns to permit-by-service + the
  warning — the exact current state.
- Config compatibility: existing configs keep loading; a previously-warned
  representable deny simply starts being enforced (the intended behaviour
  change), surfaced in commit output and the docs.

---

## Appendix A — key code references (base `b4f2ddb2f`)
- Shim shunt: `userspace-xdp/src/lib.rs:589-604` (session-hit), `:621-632`
  (session-miss), `:1139` (`cpumap_or_pass`), `:1064` (`drop_degraded_transit`).
- Kernel host-inbound codegen: `pkg/daemon/daemon_nft.go:244`
  (`applyHostInboundFilter`), `:501` (`buildHostInboundFilterPayload`), `:656`
  (`emitHostInboundZone`), `:450` (`hostInboundHasEnforceableView`), `:729`
  (`hostInboundReject` precedent).
- View builder + address/lifeline resolution:
  `pkg/dataplane/userspace/zones_host_inbound.go:80`
  (`BuildZoneHostInboundViews`), `:353` (`BuildUnzonedHostInboundAddrs`).
- Policy structs: `pkg/config/types_security.go:392` (`PolicyMatch`), `:1088`
  (`Application`), `:1029` (`Address`).
- Address/app resolution to reuse: `pkg/policymatch/policymatch.go:1306`
  (`resolveToken`, static path), `pkg/config/predefined.go:190`
  (`ResolveApplication`).
- Existing #4146 warning to adjust:
  `pkg/config/compiler_validate_warn.go:2191`
  (`junosHostPolicyStricterThanCoarseGate`), `:2227`
  (`validateJunosHostDirectDeliveryWarnings`).
- Docs: `docs/host-inbound-service-matrix.md:526`.
