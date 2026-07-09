# #4455 HI-1 — per-zone host-bound multicast/broadcast admission (plan of action)

- **Issue:** #4455 (HI-1, split from #4420, verified genuine in PR #4454, deferred)
- **Mode:** `/research` — plan only. STOP at PLAN-READY / PLAN-KILL. No PR, no
  production source changes.
- **Revision:** r2 (incorporates Codex r1 + Claude SMR r1 hostile findings)
- **Reviewers:** Codex (hostile) + Claude SMR (hostile self-review). AGY/gemini
  infra-down → 2-of-3 with documented Codex retries.
- **Converged recommendation (r2): PLAN-KILL — retain the shipped #4454 catalog +
  commit-time advisory as the operator-visible surface; do NOT build the
  per-zone multicast enforcement now.** The corrected, implementable design is
  preserved in §5–§8 as an appendix for a future `/engineer 4455` IF the operator
  explicitly wants the hardening despite the thin value; but on the merits below
  the honest convergent verdict is that the parity gain does not justify the
  HA/routing-critical multicast-drop risk and the first-`iifname`-predicate
  kernel-netdev-attribution fragility.

---

## 0. Round-1 review outcomes (why r2 converges on PLAN-KILL)

Both reviewers returned **PLAN-REVISE** on r1 with a strong PLAN-KILL case. The
eleven concrete findings (Codex C1–C8, SMR B1–B3/N1–N3) are addressed below; the
material ones that move the verdict:

- **C1 (Codex) — F1 is not universal.** Direct multicast hits
  `should_fallback_early`, but **native-GRE inner multicast does NOT**:
  `classify_native_gre_inner` (`userspace-xdp/src/lib.rs:646`) parses the inner
  v4/v6 header (`:767`/`:905`), checks only session/DNAT/local maps, returns `0`
  at `:857`/`:989`, and the packet is redirected to the **XSK** at `:724`. So a
  GRE-decapsulated inner packet addressed to a firewall-local multicast group
  CAN reach `host_inbound_admits`. "Kernel is the sole reachable enforcement
  point" is therefore false on the native-GRE decap path — the exact split-brain
  the lockstep contract exists to prevent.
- **C4 (Codex) + B2 (SMR) — the iifname source is address-scoped.**
  `ZoneHostInboundView.Interfaces` is "informational/test only"
  (`zones_host_inbound.go:28`); views/groups are created lazily on the FIRST
  address (`:97`) and interfaces are added only while iterating addresses
  (`:199`). An **addressless / DHCP-pending / routing-only** zone interface can
  therefore get **no** multicast `iifname` coverage → silent fail-open. A correct
  design must build the multicast interface set from zone/interface **membership**,
  independent of address presence — i.e. a NEW builder, not the existing view.
- **C5 + C6 (Codex) — the kernel-netdev resolver is fragile.** A resolver exists
  (`ResolveKernelIfName`, `pkg/config/types.go:208`) but (a) maps `reth0` to the
  **local physical member** (`types.go:98/146/178`, mirrored by
  `snapshotLinuxName` `interfaces.go:410/424`), directly contradicting r1's "RETH
  multicast arrives on a stable `reth` netdev" claim, and (b) **guesses** a
  slash→dash name for malformed/absent units (`:233`) instead of failing — so a
  naive "unresolved = skip" that trusts the returned string can silently install
  a drop on a non-existent or wrong interface. Getting the `iifname` wrong is
  either fail-open (never matches) or fail-**closed on the wrong interface**
  (drops legitimate traffic). This is the highest-severity correctness landmine.
- **C2 (Codex) — VRRP raw fallback is v4 AND v6.** r1 caveated only the v6 raw
  fallback; there is also a v4 `ip4:112` raw socket that joins 224.0.0.18
  (`pkg/vrrp/manager.go:799/834`) and a `receiver()` fallback started when
  `afPacketFD < 0` (`instance.go:1029`). Both raw fallbacks traverse
  `NF_INET_LOCAL_IN`, so the AF_PACKET-immunity argument only holds while
  AF_PACKET is available on both families.
- **C3 (Codex) — opt-in-off avoids upgrade breakage, not enable-time breakage.**
  xpf renders FRR OSPF/OSPFv3/RIP (`pkg/frr/policy_render.go:507/612/998`);
  enabling enforcement with a zone missing the token drops those daemons' hellos.
  A safe migration needs a strict-on-enable cross-check of managed
  OSPF/OSPFv3/RIP interfaces vs. zone tokens — and **PIM is unmanaged today**
  (`docs/feature-gaps.md:460`), so an external pimd cannot be auto-protected at
  all.
- **B1 (SMR) — the r1 accept rules were redundant.** With `policy accept` and no
  broad multicast drop, an admitted group is already accepted; the explicit
  accept matched nothing. The minimal correct design is "emit only the
  un-admitted dedicated-group drops" (Shape A). Folded into §5.1.
- Plus C7 (rsvp/pgm/sap in `protocols all` — document exclusion), C8/B3 (MLD
  negative test + two-sided lockstep guard), N1 (subnet-directed broadcast is a
  distinct forwarding-path problem), N2 (value is thinner than r1 admitted), N3
  (counter prefix `xpfhimc_` to avoid the #3361 reverse-map collision).

**Net:** none of the eleven is individually unfixable, and §5–§8 below are the
corrected design that fixes all of them. But the *accumulation* — a live-code
GRE-inner split-brain path, a demonstrably physical-member RETH resolver, an
address-lazy iifname source, and a name-guessing resolver — is a lot of
correctness surface for a change that (per §3) is opt-in-off, protects mainly
already-compliant operators, does not protect VRRP failover, and is otherwise
Rust-unreachable. Both reviewers' explicit conclusion: if GRE-inner and resolver
correctness cannot be nailed down with tests, **keep the shipped advisory and
kill enforcement.** r2 adopts that as the converged recommendation.

---

## 1. Status / framing

Host-bound **multicast** (224.0.0.0/4, ff00::/8) and **broadcast**
(255.255.255.255, subnet-directed) destined to the firewall itself bypass the
per-zone `host-inbound-traffic protocols` admission gate. The kernel
`xpf_hostinbound` `chain input` (`pkg/daemon/daemon_nft.go`,
`buildHostInboundFilterPayload`) matches **host-local unicast destination
addresses only**; a packet to a routing multicast group (OSPF 224.0.0.5/6, VRRP
224.0.0.18, PIM 224.0.0.13, RIP 224.0.0.9) matches no per-zone `daddr` set and
falls through `policy accept`. In Junos this is admitted per-zone via
`host-inbound-traffic protocols <x>`. **Fail-open-but-bounded, a parity gap, not
an open door.**

Verified architectural facts (corrected per round 1):

- **F1 (corrected).** The XDP shim `should_fallback_early`
  (`userspace-xdp/src/lib.rs:1340`, called `:565`) diverts **directly-addressed**
  host-bound multicast/broadcast/link-local (v4 255.255.255.255, 224.0.0.0/4,
  169.254/16; v6 ff00::/8, fe80::/10) to the kernel before the XSK, so
  `host_inbound_admits` never sees THOSE. **Exception (C1): native-GRE-decapsulated
  inner multicast reaches the XSK** (`lib.rs:646→724`). So the kernel nft chain is
  the sole reachable enforcement point for *non-GRE-decap* host-bound multicast
  only.
- **F2 (corrected).** Native VRRP reads via AF_PACKET SOCK_RAW ETH_P_ALL
  (`pkg/vrrp/manager.go:874`), which taps before `NF_INET_LOCAL_IN`, so an nft
  input DROP does not stop the primary VRRP receiver. **Caveat (C2): both the v4
  (`ip4:112`) and v6 (`ip6:112`) raw fallbacks traverse the input hook** and are
  used when AF_PACKET is unavailable.
- **F3.** The real risk surface is FRR (ospfd/ripd/pimd on normal kernel
  sockets) — a zone omitting the token loses adjacency on enable.
- **F4.** Prior art shipped in #4454: `hostInboundMulticastCatalog` (settled
  SSOT), `validateHostInboundMulticastWarnings` (commit advisory),
  `docs/host-inbound-multicast.md`. The catalog is inert design data today.

---

## 2. Problem statement (what a fix must resolve)

1. **iifname gate** keyed on the ingress interface's zone → its allowed
   `host-inbound-traffic protocols` (the chain has zero `iifname` predicates
   today — first consumer).
2. **Rust lockstep** with `host_inbound_admits` without split-brain — now known
   to include the native-GRE decap path (C1).
3. **Fail-closed + no-regression** — admit vrrp/ospf/etc. on their zones, drop
   un-admitted routing multicast, unicast host-inbound byte-identical.
4. **Blast radius** — nft chain + Rust classifier + iifname→kernel-netdev
   resolution + migration posture; VRRP/OSPF/PIM/IGMP correctness is
   HA/routing-critical.

---

## 3. Honest scope + value → the PLAN-KILL calculus

**Value:** strict Junos parity — make `host-inbound-traffic protocols`
authoritative for multicast, not just unicast.

**Why the value is thin (the decisive column):**
- **Bounded exposure.** Kernel delivers multicast only to joined groups; the
  always-on control set (ND/PMTUD/ESP-AH) is already globally accepted. No
  open-door to close — only a parity narrowing.
- **VRRP already safe (F2).** The change neither breaks failover nor protects it
  (primary receiver is AF_PACKET, before the hook).
- **Mostly Rust-unreachable (F1).** Enforcement is kernel-nft only except the
  exotic native-GRE-inner-multicast-to-self edge (C1), which is behind the
  NATIVE_GRE flag and vanishingly rare.
- **Opt-in-off reaches near-nobody (N2).** The only operators protected are those
  who (a) enable the knob AND (b) run an FRR protocol on a zone WITHOUT the
  matching token — a near-empty set, because enabling the knob is a superset
  action of caring about the tokens.

**Cost/risk (accumulated round-1 landmines):** first-ever `iifname` predicate; a
kernel-netdev resolver that maps RETH to a physical member and guesses on
malformed input (C5/C6); an address-lazy iifname source that fails open on
routing-only/DHCP-pending interfaces (C4); a native-GRE-inner split-brain path
(C1); enable-time FRR-adjacency breakage requiring a strict cross-check (C3); and
HA/routing-critical multicast where a wrong drop kills failover-fallback or an
OSPF/PIM adjacency.

**Converged verdict: the parity gain does not justify the risk now. PLAN-KILL —
retain the shipped #4454 advisory; do not enforce.** The advisory already makes
the gap operator-visible (names the zones/groups admitted packet-wide), which is
the right, safe stopping point for a bounded parity gap. §5–§8 preserve the
corrected design so a future `/engineer 4455` can pick it up unchanged if the
operator decides the hardening is worth the burden.

---

## 4. Already-shipped unicast host-inbound reference (what NOT to disturb)

```
table inet xpf_hostinbound {
  counter <per-zone/family deny counters> { }
  chain input {
    type filter hook input priority 10; policy accept;
    ct state established,related accept
    meta l4proto { 50, 51 } accept                                    # ESP/AH
    icmpv6 type { 1, 2, 3, 4 } counter … accept                        # v6 err/PMTUD
    icmpv6 type { 133, 134, 135, 136, 137 } counter … accept           # v6 ND
    icmp  type { destination-unreachable, time-exceeded, parameter-problem } counter … accept
    <per-zone>  <fam> daddr <zone-unicast-addrs> <l4-match> accept
    <per-zone>  <fam> daddr <zone-unicast-addrs> counter name "<z>_<fam>" drop
    <unzoned>   <fam> daddr <unzoned-addrs>       counter name "junos-host_<fam>" drop
  }
}
```

Built by `buildHostInboundFilterPayload(views, unzonedV4, unzonedV6)`; per-token
fragments render from the structured SSOT `config.HostInboundServiceMatch` /
`HostInboundProtocolMatch` (`[]L4Match`) via `renderHostInboundMatches`. Deny
counters `nftables.HostInboundDenyCounterName(zone, family)` scraped as
`xpf_host_inbound_kernel_denies_total{zone,family}` (#3361). The multicast gate
below is **purely additive** — multicast group addresses never overlap unicast
interface or unzoned addresses, so the rule families never interact and the
unicast golden-byte tests stay green unmodified.

---

## 5. Corrected design (appendix — implementable if the hardening is pursued)

### 5.1 nft: Shape A — un-admitted dedicated-group drops, iifname-scoped (kernel)

For each host-inbound-configured zone `Z` with **membership-derived** kernel
ingress interface set `I_Z` (§5.2) and admitted multicast-protocol set `M_Z`
(its `protocols` tokens ∩ `hostInboundMulticastCatalog`, `all`-expanded), and for
each family `fam ∈ {ip, ip6}`, emit ONLY the fail-closed drops for the
**dedicated** groups of protocols NOT in `M_Z`:

```
iifname { I_Z } <fam> daddr { <un-admitted dedicated groups, fam> } counter name "xpfhimc_<fam>_<Z>" drop
```

**No accept rules** (B1 — admitted groups reach the host via `policy accept`;
an explicit accept matches nothing). **No broad `224.0.0.0/4` / `ff00::/8` drop**
and **no broadcast handling** (255.255.255.255 stays at `policy accept`; DHCP is
unaffected). Placement: after the global accepts and the per-zone unicast rules,
before the unzoned deny.

Dedicated groups (gated by the drop when un-admitted): OSPF 224.0.0.5/6,
ff02::5/6; RIP 224.0.0.9 / RIPng ff02::9; VRRP 224.0.0.18 / ff02::12; PIM
224.0.0.13 / ff02::d; DVMRP 224.0.0.4. **Shared groups never dropped** (§5.3):
224.0.0.1, 224.0.0.2, 224.0.0.22 (igmp/router-discovery). Counter prefix
`xpfhimc_` is distinct from the #3361 `xpfhi_` scheme so the reverse-map cannot
misparse it (N3).

### 5.2 Membership-derived iifname → kernel-netdev resolution (C4/C5/C6)

- **Source (C4):** a NEW builder that walks zone → member interface refs (and
  #3362 per-interface overrides) from `cfg.Security.Zones` / `cfg.Interfaces`
  **independent of address presence** — NOT `ZoneHostInboundView.Interfaces`
  (which is address-lazy and would fail open on routing-only/DHCP-pending
  interfaces). Lifelines (fxp0/em0/fab*) excluded exactly as the address path
  excludes them.
- **Resolution (C5):** map each member ref+unit to the kernel netdev the packet
  ingresses on, using the SAME resolver the dataplane uses (`ResolveKernelIfName`
  / `snapshotLinuxName`) — which for `reth0` yields the **local physical member**,
  not a `reth` netdev. The design and tests MUST use the resolver's actual output
  (verified on the loss cluster: `ethtool`/`ip link` + a live `nft list ruleset`
  showing which `iifname` a 224.0.0.5 packet matches on a RETH VLAN unit), NOT an
  assumed name.
- **Fail-safe (C6):** `ResolveKernelIfName` GUESSES a slash→dash name on
  malformed/absent units. So a resolved name MUST be validated against the live
  netlink/snapshot netdev set before use; an unresolved/unvalidated interface
  yields **no** drop for that view (fail-open, never a guessed-interface drop),
  surfaced via a state-transition log + gauge (mirroring
  `AddresslessEnforcingZones` #3698).

### 5.3 Shared-group carve-out + MLD (C8)

`224.0.0.1/2/22` are multi-purpose; accept-when-admitted but **never** in the
drop set (igmp/router-discovery only ever loosened, never tightened). No broad
`ff00::/8` drop, so **MLD (ICMPv6 130/131/132/143 to ff02::1/ff02::16) is
untouched** — a REQUIRED negative test asserts no proposed drop matches those
types (C8/B3).

### 5.4 Rust lockstep — two-sided (C1/B3)

The kernel nft is authoritative for **directly-addressed** host-bound multicast.
The lockstep guard must be **two-sided**: (1) a shim tripwire asserting
`should_fallback_early` still diverts 224.0.0.0/4, ff00::/8, 255.255.255.255,
link-local (so directly-addressed multicast never becomes XSK-reachable without
tripping RED), AND (2) an explicit disposition for the **native-GRE inner
multicast** path (C1): either (a) scope it OUT of HI-1 with a test proving the
current behavior (inner multicast is forwarded/handled as-is, not host-inbound
gated) and document the residual, or (b) add a destination-group admission
dimension to `host_inbound_admits` for the decap path. Option (a) is preferred
(the decap-to-self-multicast edge is exotic and behind NATIVE_GRE); option (b) is
the only path that makes the lockstep claim literally true.

### 5.5 Protocol → multicast-group mapping table (settled catalog, F4)

| token | IPv4 group(s) | IPv6 group(s) | nft l4-match | gate class |
|---|---|---|---|---|
| `ospf`/`ospf3` | 224.0.0.5, 224.0.0.6 | ff02::5, ff02::6 | `meta l4proto 89` | dedicated |
| `rip`/`ripng` | 224.0.0.9 | ff02::9 | `udp dport 520/521` | dedicated |
| `pim` | 224.0.0.13 | ff02::d | `meta l4proto 103` | dedicated |
| `vrrp` | 224.0.0.18 | ff02::12 | `meta l4proto 112` | dedicated |
| `dvmrp` | 224.0.0.4 | — | `meta l4proto 2` | dedicated |
| `igmp` | 224.0.0.1, 224.0.0.22 | — | `meta l4proto 2` | shared (never drop) |
| `router-discovery` | 224.0.0.1, 224.0.0.2 | — (v6 = ND, global) | `icmp type {9,10}` | shared (never drop) |

**Excluded (C7):** `rsvp`(46)/`pgm`(113)/`sap`(UDP 9875) are in `protocols all`
and can be multicast (SAP → 224.2.127.254), but the shipped catalog deliberately
lists only protocols whose host-bound CONTROL rides a well-known link-local
group; these are left at `policy accept` with a documented residual packet-wide
gap rather than gated. `isis` is L2/non-IP (never on the IP input chain).

---

## 6. API / config-surface preservation

- Reuses existing `security zones <z> host-inbound-traffic protocols` leaves — no
  new protocol-token grammar. The only new surface is the **opt-in enable knob**
  (§7) which must round-trip `setSchema` + `SchemaValidate` and be documented in
  `docs/config-schema.md`.
- Unicast host-inbound unchanged (`renderHostInboundMatches` untouched;
  golden-byte + `host_inbound_nft_test.go` green unmodified).
- Metrics additive: `xpf_host_inbound_mcast_denies_total{zone,family}` (prefix
  `xpfhimc_`, N3). No RPC change.

---

## 7. Migration gating (C3, #1960)

- **M-i (only safe posture): opt-in, off-by-default enable knob** + strict-on-enable
  cross-check: reject the enable if any zone with a managed FRR OSPF/OSPFv3/RIP
  interface (`pkg/frr/policy_render.go`) lacks the matching
  `host-inbound-traffic protocols` token (validating the `commit confirmed`
  rollback target too). **PIM is unmanaged today** (`docs/feature-gaps.md:460`),
  so an external pimd cannot be auto-protected — documented residual.
- Lenient/tolerant load warns, never bricks (#1960). Existing configs are
  byte-identical until the operator enables.
- **This is exactly why the value is thin (N2):** the strict cross-check means an
  operator can only enable after already setting the tokens — the enforcement
  protects a near-empty population.

---

## 8. Hidden invariants

1. VRRP must-not-drop: admit vrrp groups on both families (C2 covers the raw
   fallbacks); the failover smoke is the empirical proof.
2. OSPF/PIM/RIP admitted ⇒ not dropped (Shape A never drops an admitted group).
3. nft ↔ Rust lockstep: two-sided guard (§5.4); GRE-inner disposition explicit.
4. Unicast + unzoned byte-identical (additive multicast block).
5. iifname resolution validated against live netdevs; unresolved ⇒ no drop
   (never guessed-interface, C6).
6. Lifelines never gated (membership set inherits the lifeline exclusion).
7. Atomic-load safety preserved (single unquoted counter decl + add/delete/recreate).

---

## 9. Risk table + test plan + out-of-scope

| Class | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| HA-critical | vrrp multicast wrongly dropped → failover regression | Low (F2; both raw fallbacks admitted) | Severe | Shape-A never drops admitted; failover smoke; C2 |
| Routing-critical | FRR OSPF/PIM/RIP adjacency dropped on enable | Med | Severe | Strict-on-enable cross-check; PIM residual documented |
| Correctness | iifname mis-resolution (RETH→phys member, guess-on-malformed, address-lazy source) | **Med-High** | Med-High | Membership source (C4); resolver validated vs live netdevs (C5/C6); loss-cluster verification |
| Split-brain | native-GRE inner multicast reaches XSK ungated | Low (NATIVE_GRE flag) | Med | §5.4 explicit disposition + test (C1) |

**Test plan:** RED-on-revert Go unit (`host_inbound_mcast_4455_test.go`) for the
un-admitted-dedicated drops + unicast/unzoned byte-identity; membership-source +
resolver unit (routing-only/DHCP-pending covered; RETH→resolver's actual name;
guessed name rejected vs live netdevs); nft parse-check; **shim two-sided guard
(C1) + MLD negative test (C8)**; loss-cluster smoke (mandatory, v4+v6): failover
MUST still work with enforce ON + vrrp-admitting zone (empirical F2 + C2 forced
AF_PACKET-failure), and a deny-multicast test (ospf-admitting zone keeps
adjacency; ospf-omitting zone drops 224.0.0.5 with counter increment; ND/unicast
unaffected). Re-apply CoS after deploy.

**Out of scope:** subnet-directed broadcast (N1 — F1 does NOT divert it; it takes
the XSK/forwarding path, a distinct problem); broad `224.0.0.0/4`/`ff00::/8`
drops; mDNS/LLMNR/SSDP (no token); rsvp/pgm/sap multicast (C7, documented
residual); enforce-by-default.

---

## 10. Open questions (each already answered toward PLAN-KILL)

- **Q1 (lockstep, C1).** Kernel-only + shim guard is honest ONLY if the
  native-GRE-inner path is explicitly scoped out with a test; a live Rust mirror
  is otherwise required for a path that almost never executes. → weight to KILL.
- **Q2 (migration, C3/N2).** M-i strict-on-enable is the only safe posture, and
  it protects a near-empty population. → strongest KILL argument.
- **Q3 (shared-group carve-out).** Accept-when-admitted/never-drop for
  igmp/router-discovery is safe partial parity; full gating reintroduces
  housekeeping risk. Settled toward the safe carve-out.
- **Q4 (knob surface).** `security forwarding-options host-inbound-multicast
  enforce` vs system/per-zone — deferred (moot under KILL).
- **Q5 (iifname RETH/VLAN, C5/C6).** The resolver maps RETH to a physical member
  and guesses on malformed input; correctness needs live-netdev validation +
  loss-cluster proof. High correctness burden. → weight to KILL.
- **Q6 (VRRP fallback, C2).** Both v4+v6 raw fallbacks are input-exposed; covered
  by admitting vrrp groups, but only while AF_PACKET is up.
- **Q7 (counter).** Resolved: distinct `xpfhimc_` prefix (N3).

---

## 11. Recommendation

**PLAN-KILL — retain the shipped #4454 protocol→group catalog + commit-time
advisory; do NOT build the per-zone multicast enforcement now.** The gap is a
bounded Junos-parity narrowing already surfaced to operators by the advisory;
enforcement is opt-in-off (protecting a near-empty population), does not protect
VRRP failover, is otherwise Rust-unreachable except an exotic native-GRE edge,
and carries real HA/routing-critical drop risk plus a demonstrably fragile
first-`iifname`-predicate kernel-netdev attribution (RETH→physical-member,
guess-on-malformed, address-lazy source). Both hostile reviewers reached the same
conclusion.

The corrected, implementable design (§5–§8) is preserved so that IF the operator
later decides the strict-parity hardening is worth the burden, `/engineer 4455`
can proceed from it directly — with the C1 GRE-inner test, the C4 membership
source, the C5/C6 live-netdev-validated resolver, and the C3 strict-on-enable
cross-check as mandatory acceptance criteria.

**This is `/research`. STOP at the converged verdict. No PR, no production source
changes.**
