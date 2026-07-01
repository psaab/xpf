# #3611 — vSRX parity: junos-host self-zone policy (from-zone junos-host + global junos-host context)

## 1. Status

DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR).

Research base: origin/master `c18664f1b` (issue authored against `9419bbc2c`;
all findings re-verified file:line against `c18664f1b` in this run — see §3/§4:
policy.rs:2835-2838 indexed-but-not-consulted, compiler_validate_strict.go:
2715-2731 global reject, no `hook output`/`postrouting`/`forward` chain exists
anywhere in `pkg/`, `hostInboundLifelineSet` in `pkg/dataplane/userspace/
zones.go`, globals routed to `global_indices` and NOT consulted on the host
path at policy.rs:2249-2250).

Anticipated verdict: **PLAN-DEFER** (enforceable, but only in the kernel; high
self-DoS blast radius + partial fidelity + low demand). This is NOT works-as-
intended: the parity gap is real and a viable mechanism exists, so PLAN-KILL is
the wrong disposition. See §3 and §8.

## 2. Issue framing

The issue tracks two DOCUMENTED-but-untracked vSRX self-zone (`junos-host`)
parity follow-ups surfaced by Codex review-001 (H01 + M03):

1. **from-zone junos-host (host-ORIGINATED) not enforced (H01).**
   `to-zone junos-host` (host-INBOUND) security policy IS enforced today
   (`evaluate_junos_host_policy`, `userspace-dp/src/policy.rs`), on the XSK
   LocalDelivery path. But `from-zone junos-host` rules — traffic the firewall
   itself ORIGINATES (its own DNS/NTP/apt/IKE clients, etc.) — commit and are
   indexed by the same name resolution yet are never consulted, because
   locally-generated traffic does not traverse the ingress LocalDelivery path.
   A `from-zone junos-host ... then deny/reject` is silently inert.

2. **global-policy junos-host context rejected, not supported (M03).**
   `pkg/config/compiler_validate_strict.go:2711-2724` hard-rejects a global
   policy with `match from-zone junos-host` / `match to-zone junos-host` at
   commit (fail-closed, to keep commit and dataplane in sync). Operators must
   duplicate per-zone `to-zone junos-host` pairs; a missed zone is a management-
   plane hole.

Explicitly OUT OF SCOPE per the issue (deliberate, do not touch without a
separate design decision): no implicit default-deny for configured junos-host
zone-pairs (Codex M02, LIFELINE guarantee); `to-zone any` / `from-zone any
to-zone any` / global tiers deliberately NOT pulled into the host path (Codex
M01).

## 3. Honest scope/value framing — and the enforceability crux

**The crux question the issue asks (and the reason it was routed to /research):
can host-originated traffic even be gated in xpf's architecture, or is this
works-as-intended/document-only like #3620's premise-gate?**

Answer, verified against source:

- **The issue's premise is CORRECT.** Host-originated traffic does NOT traverse
  the AF_XDP userspace dataplane. The firewall's own sockets (systemd-resolved,
  chrony/NTP, apt/update clients, strongSwan IKE, the HA heartbeat, VRRP
  advertisements, the gRPC/HTTP/SSH management return path) emit via the
  **Linux kernel network stack**. XDP is an INGRESS/RX-only hook; there is no
  XDP egress hook, and the legacy TC egress path was retired in #1476
  (CLAUDE.md). `userspace-dp` only ever sees frames the XDP shim redirects to
  the XSK on RX. Therefore the userspace dataplane **fundamentally cannot** see
  or gate a locally-generated frame. `evaluate_junos_host_policy_l3_aware`
  consulting `from_any_index`/`zone_pair_index` for `from-zone junos-host` is
  impossible on the transit/LocalDelivery path — there is no such path for
  host-originated egress.

- **BUT this is NOT #3620.** #3620 was PLAN-KILLed because the premise was
  FALSE (SRX does not implicitly permit intrazone → no gap → nothing to build).
  Here the premise is TRUE, yet the FEATURE is a genuine parity gap: mainline
  Junos SRX/vSRX DOES subject host-outbound (RE-originated) self-traffic to
  `from-zone junos-host` security policy. And — critically — **a viable
  enforcement mechanism already exists in xpf**: the daemon renders kernel
  **nftables `type filter hook input`** base chains (`xpf_hostinbound`,
  `xpf_lo0`) for the SIBLING host-INBOUND direction (`pkg/daemon/daemon_nft.go`,
  `pkg/nftables`). The natural mirror for `from-zone junos-host` (host-OUTBOUND)
  is a kernel **`type filter hook output`** base chain that classifies a
  locally-generated frame by its egress interface's zone and applies the
  from-zone junos-host rules. All the plumbing — atomic `nft -f -` apply
  (`nftApplyPayload`), idempotent teardown (`nftDeleteTable`), per-zone
  interface+address views (`BuildZoneHostInboundViews`,
  `ZoneHostInboundView.{Interfaces,V4Addrs,V6Addrs}`), named-counter →
  Prometheus scrape (`xnft.HostInboundDenyCounterName`), and the lifeline
  exemption set (`hostInboundLifelineSet`) — already exists and is directly
  reusable.

- **Conclusion: enforceable, but ONLY in the kernel (nft OUTPUT chain), NOT in
  the userspace AF_XDP dataplane.** Because a real gap + a real mechanism both
  exist, the honest disposition is PLAN-DEFER (design captured, build deferred
  on risk/fidelity/demand), NOT PLAN-KILL. If reviewers conclude the self-DoS
  blast radius + the partial nft fidelity + the split-enforcement maintenance
  cost outweigh a niche parity win, **PLAN-KILL (document-only) is an acceptable
  verdict** — but the tie-breaker vs #3620 is that a working mechanism exists
  and Junos genuinely enforces this direction.

Value at absolute scale: this constrains the firewall's OWN outbound clients
(e.g. "the box may not open sessions to the untrust zone"). It is a hardening/
compliance parity feature, not a data-plane throughput feature. Demand is low;
the risk (bricking the box's own control plane) is high.

## 4. What's already shipped / partially batched

- **#3019** — `to-zone junos-host` security policy on the LocalDelivery path
  (`evaluate_junos_host_policy` / `_l3_aware`, `JUNOS_HOST_ZONE_ID = u16::MAX-1`,
  `JUNOS_HOST_ZONE_NAME = "junos-host"`, `has_junos_host_rules`). Strictly
  match-driven, NO implicit default-deny (the lifeline guarantee).
- **#3090** — `from-zone any to-zone junos-host` wildcard consulted on the host
  path (`from_any_index[JUNOS_HOST_ZONE_ID]`).
- **#3018 / #3148** — commit-time reject of an unsupported junos-host global
  context (`compiler_validate_strict.go`), the exact leaf M03 asks to lift.
- **#3070 / #3361 / #3362 / #3364** — the KERNEL nftables host-inbound path:
  `xpf_hostinbound` (`hook input` priority 10) + `xpf_lo0` (`hook input`
  priority 0), per-zone accept/deny scoped to zone addresses, named DROP
  counters scraped into `xpf_host_inbound_kernel_denies_total`. **This is the
  direct architectural template for a from-zone junos-host `hook output`
  chain.**
- **#3277 / #3172 / #3224 / #1960** — `hostInboundLifelineSet` (fxp0 +
  control/fabric interfaces never subject to a host-inbound deny). Directly
  reusable to protect the management/HA lifeline on the OUTPUT chain.
- **#3445 / #3392** — lo0 INPUT firewall filter mirrored to kernel nft; the
  `then` modifier subset nft can honor on a base chain is already characterized.
  Note: there is currently NO lo0 OUTPUT kernel mirror and NO `hook output`
  chain anywhere in xpf — so a from-zone junos-host output chain is genuinely
  new kernel infrastructure (built on existing helpers, but a new hook).

## 5. Concrete design

Two independently-shippable pieces. The plan RECOMMENDS deferring Piece A
(the large, risky one) and treats Piece B's to-zone half as a smaller optional
follow-up.

### Piece A — from-zone junos-host enforcement via a kernel nft OUTPUT chain (H01)

New base chain `xpf_hostout` (`type filter hook output priority <P>; policy
accept;`), rendered by a new `buildHostOutFilterPayload` in
`pkg/daemon/daemon_nft.go`, applied through the existing `nftApplyPayload` /
torn down through `nftDeleteTable`, wired into `applyConfigLocked` next to
`applyLo0Filter` / the host-inbound apply.

Classification: for a locally-generated frame, the egress interface determines
the to-zone. Reuse a per-zone view (extend/mirror `BuildZoneHostInboundViews`
into a `BuildZoneEgressViews` carrying `{Zone, Interfaces, V4Addrs, V6Addrs}`)
and emit, per configured `from-zone junos-host to-zone <zone>` rule:

```
chain output {
  type filter hook output priority <P>; policy accept;
  ct state established,related accept          # return/ongoing self-traffic
  meta l4proto { 50, 51 } accept               # ESP/AH (host-terminated IPsec)
  icmpv6 type { 1,2,3,4,133..137 } accept      # ND + PMTUD/error (mirror input)
  icmp  type { destination-unreachable, time-exceeded, parameter-problem } accept
  oifname { <lifeline ifaces> } accept         # fxp0 + control/fabric — NEVER deny
  # per matching from-zone junos-host to-zone <zone> rule (most-specific first):
  oifname <zone-if> ip  daddr <match> <l4proto>/<ports> counter name "<c>" <verdict>
  oifname <zone-if> ip6 daddr <match> <l4proto>/<ports> counter name "<c>" <verdict>
  # from-zone junos-host to-zone any wildcard: no oifname scoping (all egress)
}
```

- `<verdict>`: `then deny` → `drop`; `then reject` → nft `reject` (delivers
  ICMP/TCP-RST to the LOCAL socket — nft `reject` in the output chain is the
  correct primitive); `then permit` → `accept` (short-circuits later rules).
- **Strictly match-driven, `policy accept`, NO catch-all drop** — identical
  lifeline discipline to #3019/#3070: configuring some from-zone junos-host
  policy must NEVER silently brick the box's own outbound control plane.
- **Lifeline exemption FIRST** (`hostInboundLifelineSet` → oifname accept) so a
  broad `to-zone <wan> deny` cannot kill HA heartbeat / VRRP / management.
- Priority `<P>`: chosen so it does not shadow srcnat/masquerade or the
  conntrack hooks; a distinct pinned constant with an invariant test (mirroring
  `nftApplyPriorityInvariant`).

Go snapshot side: `from-zone junos-host` rules already reach the compiler and
the Rust snapshot (indexed via `resolve_policy_zone_id`); Piece A adds a Go-side
extraction of the from-zone junos-host rule set into the nft renderer. The Rust
`has_junos_host_rules` / `zone_pair_index` entries for from-zone junos-host
become informational (the runtime still cannot enforce them; kernel nft does).

### Piece B — global-policy junos-host context (M03)

Split by direction:

- **`to-zone junos-host` GLOBAL (host-INBOUND).** ENFORCEABLE in userspace-dp
  today: the to-zone junos-host direction DOES traverse LocalDelivery. Lift the
  `compiler_validate_strict.go` reject for `to-zone junos-host` globals AND
  index global-scoped junos-host rules into the host gate
  (`evaluate_junos_host_policy_l3_aware` consults `global_indices` filtered to a
  junos-host scope, most-specific-after-exact-and-from-any, before falling
  through). This is a bounded, self-contained userspace change — a candidate
  smaller standalone follow-up if the user wants partial parity without Piece A.
- **`from-zone junos-host` GLOBAL (host-OUTBOUND).** Same kernel-nft concern as
  Piece A; the OUTPUT chain would consult the global-scoped from-zone junos-host
  rules. Defers with Piece A.

## 6. Public API preservation

- No change to `evaluate_junos_host_policy` / `_l3_aware` signatures for Piece A
  (kernel-only). Piece B's to-zone-global half extends the internal host-gate
  evaluation to also walk global-scoped junos-host rules — additive, no
  signature change to the public wrapper.
- `resolve_policy_zone_id`, `JUNOS_HOST_ZONE_ID`, `JUNOS_HOST_ZONE_NAME`,
  `has_junos_host_rules` unchanged.
- `ZoneHostInboundView` unchanged; a new sibling view type (or a shared base) is
  added rather than mutating the existing one.
- Existing nft chains (`xpf_hostinbound`, `xpf_lo0`) untouched; `xpf_hostout` is
  a NEW table so it cannot regress host-inbound.

## 7. Hidden invariants the change must preserve

- **Lifeline guarantee (the #1 invariant).** No implicit default-deny on the
  output chain; `policy accept`; lifeline oifname-accept emitted BEFORE any deny;
  ESP/AH + ICMP ND/PMTUD/error exemptions mirrored from the input chain so the
  box's own IPsec/PMTUD/ND egress is never gated. A wrong rule must degrade to
  "no enforcement," never to "self-DoS."
- **Commit/dataplane parity.** M03's reject exists precisely so commit and the
  dataplane agree. Lifting it MUST be paired with real enforcement in the SAME
  change (Piece B to-zone in userspace-dp; from-zone via nft) — never lift the
  reject while leaving the rule inert (that re-opens the exact silent-never-
  match hole the reject closed).
- **Fidelity fail-closed (MANDATORY if Piece A is ever built).** The nft output
  chain can only express a SUBSET of the policy match grammar (l4proto + port
  ranges + address; NO multi-term / ALG application catalog, NO source-identity /
  dynamic-app). A `from-zone junos-host ... then deny application <x>` whose
  application term nft cannot represent MUST be **rejected at commit** (a new
  strict-validator gate, mirroring the M03 reject it replaces) — NEVER silently
  rendered as a looser rule (e.g. all-ports) or silently dropped. This converts
  the "silent partial security feature" footgun (operator believes an app-scoped
  deny protects them; an ALG app slips through) into a fail-closed commit error.
  This requirement is the direct answer to the issue's warning that "a wrong
  build here = a security feature that silently does nothing." It is also the
  single largest argument for KILL-document-only: if the representable subset is
  judged too narrow to be honestly useful, the feature is better *not* built.
- **Atomic nft apply / fail-closed teardown.** Reuse `nftApplyPayload` (atomic
  `-f -`, previous table retained on failure) and `nftDeleteTable` (idempotent,
  no `nft destroy` dependency — unversioned nftables floor). A failed output-
  chain apply must surface as commit failure (mirroring #3392/#3333) but must
  never leave a half-applied ruleset that could brick egress.
- **Counter declaration/reference agreement** (the #3578 quoting rule:
  declaration UNQUOTED, reference QUOTED; dedup declarations by name).
- **HA / config-sync portability.** The nft output chain is derived
  deterministically from committed config, so it re-renders identically on both
  nodes; no new synced runtime state. Must pass `make test-failover` (touches
  the control-plane egress path — heartbeat/VRRP are on the OUTPUT hook now).
- **Chain-priority determinism** (mirror `nft_chain_priority_test.go`): pin the
  output chain's priority with an invariant test.

## 8. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression (self-DoS blast radius) | **HIGH** | An nft `hook output` drop can brick the firewall's OWN control plane — HA heartbeat (em0), VRRP adverts, DHCP renewal, DNS/NTP dependencies, IKE/ESP to peers, gRPC/SSH management return path. Strictly-match-driven + lifeline oifname-accept + ESP/AH/ICMP exemptions are MANDATORY, not optional. This is the dominant reason to DEFER. |
| Fidelity / observability | **MED→HIGH** | nft cannot express the full app catalog (multi-term apps, ALG-dependent apps) — only l4proto + port ranges + addr. And nft can only `log prefix` → journald, NOT the structured RT_FLOW records the userspace deny path emits. So application matching + logging are a SUBSET of the to-zone (userspace) path — a documented parity asymmetry. |
| Architectural mismatch | **MED** | Split enforcement: to-zone junos-host in userspace-dp, from-zone junos-host in kernel nft. Two engines for one policy family = a maintenance + cross-engine parity-test burden. Not a dead-end (#961-style), but a real complexity tax. |
| Correctness of oif classification | **MED** | OUTPUT-hook `oifname` reflects the post-route-lookup egress device; must verify oif is reliably populated for the traffic classes in scope (esp. connected vs routed, VRF/l3mdev, and pre-vs-post reroute). Flagged as a verify item, not assumed. |
| Piece B to-zone-global (userspace) | **LOW→MED** | Bounded userspace-dp change; the only risk is precedence ordering of global-scoped junos-host rules vs exact/from-any, and re-checking the lifeline (no default-deny). Independently shippable and far lower-risk than Piece A. |

**Explicit PLAN-KILL-acceptable condition (per the issue):** if reviewers judge
the host-originated direction is not worth the self-DoS risk + partial fidelity
for a niche feature, downgrade to **document-only** (like #3620): keep the
commit-reject for from-zone junos-host globals, keep the current
"indexed-but-not-enforced" behavior, and add a docs paragraph stating the
architectural reason (host egress bypasses the AF_XDP dataplane; enforcement
would require a kernel nft output chain that is deliberately not built). The
plan's recommendation is DEFER (design captured) rather than KILL, because the
mechanism is real — but KILL-document-only is a defensible convergent outcome.

## 9. Test plan (for when/if Piece A or B is engineered)

- `cargo build` clean; full `cargo test` (userspace-dp) green; 5/5 named-test
  flake check on any touched policy test.
- `go build ./...` + `go test ./...` (30 Go packages), especially
  `pkg/daemon` (nft rendering + priority invariant + fail-closed apply/teardown)
  and `pkg/config` (strict-validator reject lift for M03).
- New unit tests: `buildHostOutFilterPayload` renders lifeline-accept first,
  strictly-match-driven, no catch-all drop, correct deny/reject/permit verdicts,
  counter declare/reference agreement, priority invariant.
- **Live enforcement (loss userspace cluster):**
  1. `from-zone junos-host to-zone untrust then deny` — from the firewall,
     originate a session to an untrust host (e.g. `curl`/`nc` from the box);
     confirm it is dropped, the named counter increments, and the Prometheus
     `..._denies_total` metric advances.
  2. `then reject` — confirm the local socket sees an ICMP/RST error promptly.
  3. `then permit` — confirm the session succeeds.
  4. **Lifeline regression (mandatory):** with a broad `to-zone <wan> deny`
     configured, confirm HA heartbeat, VRRP adverts, DHCP renewal, and SSH/gRPC
     management to the box are UNAFFECTED (lifeline oifname-accept holds).
  5. **`make test-failover`** — the OUTPUT hook now sits on the heartbeat/VRRP
     egress path; must pass 14/0 zero-drop with the chain installed.
- M03 to-zone-global: commit a `match to-zone junos-host` global with `then
  deny`; confirm it now commits AND is enforced on the LocalDelivery path
  (a matching host-inbound flow is denied); confirm a non-matching zone still
  falls through (lifeline).

## 10. Out of scope (explicitly)

- Implicit junos-host default-deny (Codex M02) — deliberate WONTFIX-by-design.
- `to-zone any` / `from-zone any to-zone any` / global tiers pulled into the
  host path (Codex M01).
- Structured RT_FLOW records from the kernel nft output chain (nft emits
  `log prefix` only; RT_FLOW parity for host-originated denies is a separate,
  larger observability item if ever needed).
- Full app-catalog (multi-term / ALG) fidelity on the nft output chain — scoped
  to protocol + port ranges + address matching only.
- A lo0 family inet/inet6 `filter output` kernel mirror (separate from the
  security-policy from-zone junos-host path).

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Is DEFER (not KILL) the right disposition?** The mechanism (nft output
   chain) is real and Junos genuinely enforces from-zone junos-host — but is a
   niche self-hardening feature with HIGH self-DoS risk + partial fidelity worth
   keeping "designed, deferred" rather than closing document-only like #3620?
2. **Is the nft `hook output` classification sound?** Does OUTPUT-hook
   `oifname` reliably reflect the egress zone for locally-generated frames
   across connected/routed/VRF(l3mdev)/reroute cases? If oif is unreliable at
   OUTPUT, is POSTROUTING (which loses `reject` toward the local socket) or a
   different hook required — and does that break the reject semantic?
3. **Is the split-enforcement model (to-zone in userspace-dp, from-zone in
   kernel nft) architecturally acceptable**, or does it create a parity/
   maintenance hazard severe enough to argue for KILL, or for moving BOTH
   directions to nft?
4. **Lifeline sufficiency.** Are `hostInboundLifelineSet` + ESP/AH + ICMP
   ND/PMTUD exemptions + strictly-match-driven/`policy accept` genuinely
   enough to guarantee the box can never self-DoS its control plane via a
   from-zone junos-host deny? What egress class is missed (e.g. DNS the box
   depends on for its own config, NTP, the update path during a rescue)?
5. **Should Piece B's to-zone-junos-host-GLOBAL half be split out NOW** as a
   small, low-risk userspace-dp follow-up (it needs no kernel work), while
   Piece A + the from-zone-global half defer together?
6. **Fidelity acceptability.** Is a from-zone junos-host enforcement that
   silently cannot honor multi-term/ALG applications and emits journald-only
   (not RT_FLOW) logs a PARTIAL parity that is worse than no feature (operator
   believes they're protected but an ALG app slips through)? Does that argue for
   KILL-document-only?
7. **Commit-reject lift coupling.** Is the invariant "never lift the M03 reject
   without shipping enforcement in the same change" correctly stated, and does
   the lenient/already-persisted-config path (warn-downgrade) stay fail-closed?
