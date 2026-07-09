# #4455 HI-1 — per-zone host-bound multicast/broadcast admission (plan of action)

- **Issue:** #4455 (HI-1, split from #4420, verified genuine in PR #4454, deferred)
- **Mode:** `/research` — plan only. STOP at PLAN-READY / PLAN-KILL. No PR, no
  production source changes.
- **Revision:** r1
- **Reviewers:** Codex (hostile plan-review) + Claude SMR (hostile self-review).
  AGY/gemini infra-down → proceed 2-of-3 with documented Codex retries.
- **Recommendation (r1, provisional):** PLAN-READY for a **narrow Option A**
  (catalog dedicated-groups only, housekeeping groups excluded, enforcement behind
  an opt-in off-by-default knob, **kernel-nft-only** enforcement plus a shim
  regression guard, **no live Rust admission change**). **PLAN-KILL is explicitly
  on the table** and a legitimate convergent outcome — see §3 and §10.

---

## 1. Status / framing

Host-bound **multicast** (224.0.0.0/4, ff00::/8) and **broadcast**
(255.255.255.255, subnet-directed) destined to the firewall itself bypass the
per-zone `host-inbound-traffic protocols` admission gate. The kernel
`xpf_hostinbound` `chain input` (`pkg/daemon/daemon_nft.go`,
`buildHostInboundFilterPayload`) matches **host-local unicast destination
addresses only** — every per-zone rule is `<fam> daddr <zone-unicast-addrs>
… accept / drop`. A packet addressed to a routing multicast group (OSPF
224.0.0.5/6, VRRP 224.0.0.18, PIM 224.0.0.13, RIP 224.0.0.9, …) matches no
per-zone `daddr` set and falls through the chain's `policy accept` to the host
stack with no per-zone scoping.

This is a **Junos-parity/hardening gap, not an open door**. In Junos, host-bound
routing multicast is admitted per-zone via `host-inbound-traffic protocols <x>`
on the ingress interface's zone. Here it is admitted **packet-wide** (on every
ingress interface, regardless of the zone's token set), bounded only by the fact
that the host kernel delivers multicast solely to groups a configured daemon
actually joined.

**Decisive architectural facts established during this research (verify-first on
current master):**

- **F1 — the XDP shim diverts classic multicast/broadcast to the kernel before
  the XSK.** `should_fallback_early` (`userspace-xdp/src/lib.rs:1340`, called at
  `lib.rs:565` on the normal path) returns `true` for v4 `255.255.255.255`,
  `224.0.0.0/4` (`is_ipv4_multicast`), `169.254.0.0/16` (link-local) and v6
  `ff00::/8` (`dst_addr[0]==0xff`) + `fe80::/10`, routing them to
  `pass_local_control → cpumap_or_pass → kernel`. **They never reach the XSK,
  so `host_inbound_admits` (`forwarding/host_inbound.rs:476`) never sees them.**
  The kernel nft `chain input` is therefore the **sole reachable enforcement
  point** for classic host-bound multicast/broadcast — exactly like the #4420
  HI-2 unzoned deny, which was deliberately kernel-only for the same reason.
- **F2 — native VRRP is architecturally immune to the nft input hook.** The
  xpf VRRPv3 receiver uses `AF_PACKET SOCK_RAW` with `ETH_P_ALL`
  (`pkg/vrrp/manager.go:874` `openAfPacketReceiver`, `instance.go:1380`
  `receiverAfPacket`), which taps at the link layer (`packet_rcv`) **before**
  `NF_INET_LOCAL_IN`. An nft `hook input` DROP of 224.0.0.18 / ff02::12 does
  **not** stop the AF_PACKET copy already delivered to xpf VRRP. The primary
  failover path survives a mis-scoped multicast drop. *Caveat:* the IPv6
  raw-socket fallback (`receiverIPv6`, `ip6:112`, used only when AF_PACKET is
  unavailable) DOES traverse the input hook.
- **F3 — the real risk surface is FRR.** ospfd/ripd/pimd/igmp receive multicast
  via normal kernel sockets, which **do** traverse `NF_INET_LOCAL_IN`. A zone
  running OSPF/PIM/RIP in FRR **without** the matching
  `host-inbound-traffic protocols` token relies today on `policy accept`;
  enforcing per-zone admission **drops its hellos → adjacency down**. This is
  the #1960 migration hazard.
- **F4 — prior art already shipped (PR #4454).** `hostInboundMulticastCatalog`
  (`pkg/config/host_inbound_multicast.go`) is the settled protocol→group SSOT;
  `validateHostInboundMulticastWarnings` (`pkg/config/compiler_validate_warn.go`)
  is a shipped commit-time WARN advisory; `docs/host-inbound-multicast.md`
  records the four coupled decisions. The catalog is **inert design data** —
  it makes no forwarding decision today. This plan turns decisions (1) iifname
  structure, (3) migration gating, (4) lockstep into a converged design;
  decision (2) the catalog is already settled.

---

## 2. Problem statement (what a fix must resolve)

1. **iifname gate.** Multicast has no per-zone unicast `daddr` to key on
   (destination is a group), so admission must key on the **ingress interface's
   zone → its allowed `host-inbound-traffic protocols`**. The chain has no
   `iifname` predicate today (grep: zero `iifname`/`oifname`/`pkttype` usages in
   `pkg/daemon`/`pkg/nftables`); this is the first consumer.
2. **Rust lockstep.** The codebase invariant is that the kernel nft host-inbound
   set and the Rust `host_inbound_admits` classifier agree (a divergence is a
   #1961-class control/dataplane split-brain). But F1 makes multicast unreachable
   on the Rust path — a live Rust mirror is dead code today. The plan must resolve
   this honestly (guard-test vs. live mirror).
3. **Fail-closed + no-regression.** Multicast that SHOULD be admitted (VRRP on a
   vrrp-zone, OSPF on an ospf-zone, IGMP, PIM, router-discovery) must still reach
   the host; un-admitted routing multicast must drop; existing **unicast**
   host-inbound must be byte-for-byte unchanged.
4. **Blast radius.** nft chain change + (maybe) Rust classifier change + the
   iifname→kernel-netdev resolution + the migration posture. VRRP/OSPF/PIM/IGMP
   correctness is HA/routing-critical.

---

## 3. Honest scope + value (PLAN-KILL is a live outcome)

**The case for the change (value):** strict Junos parity. A zone that does not
opt into a routing protocol should not have that protocol's host-bound multicast
silently admitted to the box. Closing this removes a "packet-wide admit" surface
and makes `host-inbound-traffic protocols` fully authoritative for multicast, not
just unicast.

**The case against / why the value is smaller than it looks:**

- **Bounded exposure.** The gap is fail-open-**but-bounded**: the kernel delivers
  multicast only to groups a joined daemon subscribed, and the always-on control
  set (ND, PMTUD/error ICMP, ESP/AH) is already globally accepted. There is no
  open-door fail-open to close — only a parity narrowing.
- **VRRP already safe (F2).** The headline HA risk ("a dropped VRRP advert breaks
  failover") is largely mitigated for the primary path because native VRRP reads
  via AF_PACKET before the input hook. So the change neither breaks failover nor
  is it the thing protecting failover.
- **Rust path unreachable (F1).** The "lockstep" requirement collapses to a
  parity-test/guard exercise, not a live dataplane change. The dataplane-side
  hardening people imagine is a no-op.
- **Safe migration is opt-in-off (F3, §7).** Because enforcement is fail-**closed**
  on revert of today's accept and can break FRR adjacencies the daemon cannot
  detect at commit, the only non-breaking rollout is an **opt-in, off-by-default**
  enforcement knob. But the operators who would enable it are precisely those who
  already set the `host-inbound-traffic protocols` token — so the marginal
  hardening for the population that needs it is thin.

**PLAN-KILL criterion (explicit).** If the reviewers judge that the parity gain
does not justify (a) introducing the first `iifname` predicate + its
kernel-netdev-resolution correctness burden, (b) the FRR-adjacency / IGMP-MLD
housekeeping drop risk, and (c) a kernel-only enforcement that cannot honestly
claim Rust lockstep — then **PLAN-KILL with "keep the shipped #4454 advisory as
the operator-visible surface; do not enforce"** is the correct convergent
outcome. This plan is written to make that decision cleanly reviewable, not to
force a build.

---

## 4. Already-shipped unicast host-inbound reference (what NOT to disturb)

The existing kernel `chain input` (unicast, must remain byte-identical):

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

- Emitted by `buildHostInboundFilterPayload(views, unzonedV4, unzonedV6)`.
- `views = BuildZoneHostInboundViews(cfg)` — one view per (zone, effective-token
  signature); each carries `Zone`, `Interfaces []string` (config refs, already
  populated, currently "informational/test only"), `SystemServices`, `Protocols`,
  `V4Addrs`, `V6Addrs`.
- Per-token nft match fragments render from the structured SSOT
  `config.HostInboundServiceMatch` / `HostInboundProtocolMatch` (`[]L4Match`) via
  `renderHostInboundMatches`. OSPF→`meta l4proto 89`, RIP→`udp dport 520`,
  VRRP→`meta l4proto 112`, PIM→`meta l4proto 103`, IGMP/DVMRP→`meta l4proto 2`,
  router-discovery→`icmp type { 9, 10 }`.
- Deny counters: `nftables.HostInboundDenyCounterName(zone, family)`, declared
  unquoted, referenced quoted (#3578); scraped as
  `xpf_host_inbound_kernel_denies_total{zone,family}` (#3361).
- Atomic replace idiom: `add table` / `delete table` / recreate.

**Invariant this plan preserves:** the multicast gate is **purely additive** —
new rules keyed on `iifname` + multicast `daddr` groups, inserted such that the
unicast `daddr`-scoped rules and the unzoned deny are unchanged. Multicast group
addresses never overlap unicast interface addresses or unzoned addresses, so the
two rule families never interact.

---

## 5. Concrete design

### 5.1 Recommended: Option A — catalog dedicated-groups, iifname-scoped, kernel-only

For each host-inbound-configured zone `Z` with kernel ingress interface set
`I_Z` and admitted multicast-protocol set `M_Z` (its `protocols` tokens ∩
`hostInboundMulticastCatalog`, with `all` expanded via
`HostInboundAllExpansionProtocols`), and for each family `fam ∈ {ip, ip6}`:

**(a) Admit rules** — for each `P ∈ M_Z` with catalog groups `G_P(fam) ≠ ∅`:

```
iifname { I_Z } <fam> daddr { G_P(fam) } <l4-match(P,fam)> accept
```

`<l4-match(P,fam)>` is the SAME fragment the unicast path renders
(`renderHostInboundMatches(HostInboundProtocolMatch(P, fam))`), so OSPF stays
`meta l4proto 89`, RIP stays `udp dport 520`, etc. The proto-match is retained
(not group-only) for precision and to disambiguate shared groups.

**(b) Fail-closed drops** — for the catalog groups of protocols **not** in `M_Z`,
restricted to **protocol-DEDICATED** groups only (see §5.3 shared-group carve-out):

```
iifname { I_Z } <fam> daddr { <un-admitted dedicated groups, fam> } counter name "<Z>_mcast_<fam>" drop
```

Dedicated groups gated by (a)/(b): OSPF `224.0.0.5`,`224.0.0.6` / `ff02::5`,`ff02::6`;
RIP `224.0.0.9` / RIPng `ff02::9`; VRRP `224.0.0.18` / `ff02::12`; PIM
`224.0.0.13` / `ff02::d`; DVMRP `224.0.0.4`. **Excluded from any drop** (accept
only when admitted, never dropped): the SHARED all-hosts/all-routers groups
`224.0.0.1`, `224.0.0.2`, `224.0.0.22` used by igmp/router-discovery (§5.3).

**Placement/ordering.** Emit the whole multicast block **after** the global
accepts (`ct established` / ESP-AH / ND / PMTUD) and **after** the per-zone
unicast rules, **before** the unzoned deny. Within a zone's block, all
`accept` rules precede the `drop`. Because multicast daddrs are disjoint from
unicast/unzoned daddrs, the relative order of the multicast block vs. the unicast
rules is immaterial for correctness; placing it after unicast keeps the unicast
golden-byte tests untouched.

**Broadcast.** v4 limited broadcast `255.255.255.255` (DHCP client, some
discovery) is diverted to the kernel by F1 and hits this chain. Gate DHCP
broadcast under the existing `dhcp`/`bootp` service token
(`udp dport { 67, 68 }`) — i.e. emit `iifname { I_Z } ip daddr 255.255.255.255
udp dport { 67, 68 } accept` when the zone admits dhcp, and otherwise leave
255.255.255.255 at `policy accept` (do NOT add a broadcast catch-all drop in r1 —
too broad; see §9 out-of-scope). Subnet-directed broadcast is out of scope (§9).

### 5.2 iifname → kernel-netdev resolution (the load-bearing new mechanism)

`ZoneHostInboundView.Interfaces` carries **config refs** (Junos-style, e.g.
`ge-0/0/2`, unit names like `ge-0/0/2.50`). The nft `iifname` predicate needs the
**kernel netdev name** a multicast packet actually ingresses on:

- Physical/vSRX names are renamed slash→dash (`ge-0/0/2` → `ge-0-0-2`) by
  `pkg/daemon/linksetup.go`.
- A **tagged** VLAN unit ingresses on the VLAN sub-netdev (`ge-0-0-2.50`), not the
  base device; an **untagged** unit (unit 0, no `vlan-id`) ingresses on the base
  device (`ge-0-0-2`).
- **RETH** members: multicast for a redundancy-group VIP arrives on the reth
  netdev / its VLAN sub-netdev; the physical member MAC alternates, but the
  netdev NAME the kernel presents to nft is stable — resolution must use the
  same netdev-name the kernel sees, verified on the loss cluster.

**Design:** add a resolver `hostInboundKernelIfnames(cfg, view)` (in
`pkg/dataplane/userspace`, beside `BuildZoneHostInboundViews`) that maps each
view interface ref to its kernel netdev name(s), reusing the existing
name-translation used by linksetup/networkd (do not hand-roll slash→dash).
Populate a new `KernelIfnames []string` field on the view (or return it
alongside), and have `buildHostInboundFilterPayload` consume it for the `iifname`
set. **Fail-safe rule:** if a view's kernel ifname set cannot be resolved
(empty), emit **no** multicast drop for that view (fail-open for that zone, never
fail-closed on an unknown interface) and surface it via a state-transition log +
gauge, mirroring the `AddresslessEnforcingZones` (#3698) pattern.

### 5.3 Shared-group carve-out (correctness, not optional)

`224.0.0.1` (all-hosts), `224.0.0.2` (all-routers), `224.0.0.22` (IGMPv3
reports) are **multi-purpose** groups. Dropping them because a zone omits `igmp`
would also drop general all-hosts traffic and could interfere with the host's own
IGMP membership maintenance. Therefore these groups are **accept-when-admitted
but never in the drop set** in r1. Consequence: `igmp` and `router-discovery`
multicast is only ever **loosened**, never **tightened** — partial parity. This
is a deliberate blast-radius bound and an open question (§10 Q3).

IPv6 ND (RS/RA/NS/NA/Redirect, types 133–137) is already globally accepted, so
v6 router-discovery needs nothing. **MLD** (ICMPv6 130/131/132/143 to `ff02::1` /
`ff02::16`) is NOT in the global ND accept set and NOT a host-inbound token; r1
does **not** drop any ff00::/8 beyond the dedicated groups, so MLD is untouched
(left at `policy accept`). Do not add a broad `ff00::/8` drop (§9).

### 5.4 Rust lockstep (decision 4) — recommended: guard, not live mirror

Because of F1 (multicast never reaches the XSK), a live
`host_inbound_admits` multicast dimension is **dead code today**. Recommended
resolution:

- **Kernel-nft is the authoritative + sole reachable enforcement point** for
  host-bound multicast/broadcast (documented as such, exactly like HI-2's
  kernel-only deny).
- **Add a shim-diversion regression guard** (Rust unit test in
  `userspace-xdp` and/or a Go assertion) that fails if `should_fallback_early`
  ever stops covering `224.0.0.0/4`, `ff00::/8`, `255.255.255.255`, or the
  link-local ranges — i.e. if any future change routes host-bound multicast to
  the XSK. That test is the tripwire that forces adding the Rust mirror **at the
  moment it becomes reachable**, preventing a silent split-brain.
- **No live `host_inbound_admits` change in r1.** Document the invariant in
  `host_inbound.rs` and `docs/host-inbound-multicast.md`.

**Alternative (if reviewers require live parity):** extend `ZoneHostInbound` with
a per-zone admitted-multicast-group set and consult it in `host_inbound_admits`
for a multicast `dst_addr`. This is honest lockstep but adds a destination-address
dimension the classifier lacks and is exercised by nothing until the shim
changes. Surfaced as §10 Q1.

### 5.5 Protocol → multicast-group mapping table (settled catalog, F4)

| `protocols` token | IPv4 group(s) | IPv6 group(s) | nft l4-match | gate class |
|---|---|---|---|---|
| `ospf`  | 224.0.0.5, 224.0.0.6 | — | `meta l4proto 89` | dedicated (accept+drop) |
| `ospf3` | — | ff02::5, ff02::6 | `meta l4proto 89` | dedicated |
| `rip`   | 224.0.0.9 | — | `udp dport 520` | dedicated |
| `ripng` | — | ff02::9 | `udp dport 521` | dedicated |
| `pim`   | 224.0.0.13 | ff02::d | `meta l4proto 103` | dedicated |
| `vrrp`  | 224.0.0.18 | ff02::12 | `meta l4proto 112` | dedicated |
| `dvmrp` | 224.0.0.4 | — | `meta l4proto 2` | dedicated |
| `igmp`  | 224.0.0.1, 224.0.0.22 | — | `meta l4proto 2` | **shared (accept-only, never drop)** |
| `router-discovery` | 224.0.0.1, 224.0.0.2 | — (v6 = ND, global) | `icmp type { 9, 10 }` | **shared (accept-only)** |

Source of truth stays `config.hostInboundMulticastCatalog`; the "gate class"
column is new metadata this plan adds (dedicated vs. shared) — proposed as a
field/predicate on the catalog so the nft builder and any future Rust mirror read
one table.

---

## 6. API / config-surface preservation

- **No new config grammar for the catalog** — it reuses the existing
  `security zones <z> host-inbound-traffic protocols <token>` leaves. No
  `setSchema` change for the protocol tokens.
- **New enforcement knob (§7).** The opt-in enable flag is the only new config
  surface. Proposed: `set security forwarding-options host-inbound-multicast
  enforce` (or a system-level flag) — exact spelling is §10 Q4. It must round-trip
  through `setSchema` + `SchemaValidate` and be documented in
  `docs/config-schema.md`.
- **Unicast host-inbound unchanged** — `renderHostInboundMatches` and the
  per-zone unicast rules are not touched; `TestHostInboundNftRenderGoldenByteIdentical`
  and the existing `host_inbound_nft_test.go` assertions stay green unmodified.
- **Metrics additive** — new `xpf_host_inbound_mcast_denies_total{zone,family}`
  (or fold into the existing kernel-deny counter with a distinct kind). Existing
  counters unchanged.
- **gRPC/REST** — no RPC change; the new counter surfaces through the existing
  metrics collector path.

---

## 7. Migration gating (decision 3, #1960)

Enforcement is fail-**closed** on revert of today's accept and can break an FRR
adjacency the daemon cannot detect at commit (F3). Options:

- **M-i (recommended r1): opt-in, off-by-default enforcement knob.** Existing
  configs are byte-identical until the operator explicitly enables enforcement.
  The already-shipped WARN advisory continues to nudge. On enable, the
  strict-on-commit path additionally validates that the enable knob is coherent;
  lenient/tolerant load only warns (never bricks a synced config, #1960).
- **M-ii: enforce-by-default (like HI-2).** Rejected for r1 — HI-2 closed a
  fail-open with no legitimate reliance; here there IS legitimate reliance
  (FRR-protocol-without-token), so default-on can silently break routing on
  upgrade.
- **M-iii: enforce-by-default but drop dedicated groups only + AF_PACKET-immune
  VRRP + housekeeping excluded.** Residual risk is real FRR OSPF/PIM/RIP adjacency
  loss for the omitted-token case. Held as the aggressive alternative (§10 Q2).

**Operator migration story (M-i):** doc in `docs/host-inbound-multicast.md` +
`pkg/daemon/README.md`: "before enabling `host-inbound-multicast enforce`, ensure
every zone running a routing protocol in FRR also lists the matching
`host-inbound-traffic protocols <x>`; the commit advisory lists the zones/groups
affected." The `commit confirmed` rollback target is validated the same way.

---

## 8. Hidden invariants

1. **VRRP must-not-drop (HA-critical).** Even though F2 makes native VRRP
   AF_PACKET-immune, the design MUST still admit `vrrp` groups on a vrrp-zone
   (224.0.0.18 / ff02::12) so the IPv6 raw-socket fallback and any kernel-path
   VRRP consumer keep working, and so the intent is explicit. The failover smoke
   (§9 test plan) is the empirical proof, not the AF_PACKET argument alone.
2. **OSPF/PIM/RIP must-not-drop when admitted.** A zone that lists the token must
   get its multicast admitted; the accept rule (5.1a) must precede the drop
   (5.1b) and reuse the exact unicast l4-match render.
3. **nft ↔ Rust exact parity (or documented divergence).** The lockstep contract
   requires either identical multicast admission on both surfaces OR a documented,
   test-guarded reason they cannot diverge (the F1 guard test, §5.4). A silent
   kernel-only change that *claims* parity is forbidden (#1961 class).
4. **Unicast + unzoned byte-identical.** The multicast block is additive; the
   unicast golden-byte and unzoned-deny tests must pass unmodified.
5. **iifname resolution fail-open, never fail-closed on unknown.** An unresolved
   kernel ifname yields no drop for that view (§5.2), never a drop on the wrong
   or a guessed interface.
6. **Lifelines never gated.** fxp0/em0/fab* are already excluded from the views;
   the multicast block must inherit that exclusion (build `I_Z` from the same
   lifeline-filtered interface set).
7. **Atomic-load safety.** New named counters declared once (unquoted) + the
   `add/delete/recreate` idiom preserved; a syntax error rejects the whole
   payload (fail closed-as-absent), so the multicast block cannot half-apply.

---

## 9. Risk table (4-class) + test plan + out-of-scope

### Risk table

| Class | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **HA-critical** | vrrp-zone multicast wrongly dropped → failover regression | Low (F2 AF_PACKET-immune; accept rule admits it) | Severe | Admit rule 5.1a; failover smoke MUST pass; IPv6 fallback covered |
| **Routing-critical** | FRR OSPF/PIM/RIP adjacency dropped when zone omits token | Med (exactly the #1960 case) | Severe | Opt-in off-by-default (M-i); advisory; migration doc |
| **Correctness** | iifname→kernel-netdev mis-resolution (VLAN/RETH slash-vs-dash) → fail-open or wrong-iface | Med | Med | Reuse linksetup translation; fail-open on unresolved; loss-cluster VLAN/RETH verification |
| **Housekeeping** | Broad multicast/MLD/IGMP drop breaks host membership | Low (r1 gates dedicated groups only; shared/MLD excluded) | Med | §5.3 carve-out; no ff00::/8 or broadcast catch-all in r1 |

### Test plan

- **Unit (RED-on-revert), Go** (`pkg/daemon/host_inbound_mcast_4455_test.go`,
  mirroring `host_inbound_unzoned_4420_test.go`): a fixture with a vrrp+ospf zone
  and a bare zone asserts (a) admitted-group accept rules present with the correct
  iifname + l4-match, (b) un-admitted dedicated-group drop present, (c) shared
  groups NEVER in a drop, (d) unicast rules + unzoned deny byte-identical.
  Neutering the multicast emitter turns it RED.
- **iifname resolution unit** (`pkg/dataplane/userspace`): VLAN sub-unit →
  `ge-0-0-2.50`, untagged → `ge-0-0-2`, RETH → reth netdev; unresolved → no drop.
- **nft parse-check**: the full payload with the multicast block parses on
  appliance nft (v1.1.6), extending `TestHostInboundFilter…PayloadParses`.
- **Shim guard** (Rust, `userspace-xdp`): assert `should_fallback_early` covers
  224.0.0.0/4, ff00::/8, 255.255.255.255, link-local — RED if multicast is ever
  routed to the XSK (the §5.4 tripwire).
- **Smoke on loss userspace cluster (MANDATORY, both v4+v6):**
  1. **Failover MUST still work** — `make test-failover` (iperf3 through the RG
     while cycling failovers) with the enforce knob ON and a vrrp-admitting zone:
     zero-drop failover, empirically confirming F2.
  2. **Deny-multicast test** — with the knob ON: a zone that admits `ospf` still
     forms/keeps an OSPF adjacency through the box's zone interface; a zone that
     does NOT admit `ospf` DROPS injected OSPF-group (224.0.0.5) packets (deny
     counter increments) while established unicast + ND + admitted protocols are
     unaffected.
  3. **Re-apply CoS after deploy** (`apply-cos-config.sh`) per the standing
     deploy-wipes-CoS rule.

### Out of scope (r1)

- **Subnet-directed broadcast** (e.g. 10.0.1.255) — F1 does NOT divert it to the
  kernel (it is not 255.255.255.255/224-4), so it takes the XSK/forwarding path
  and is a distinct problem; deferred.
- **A broad `ip daddr 224.0.0.0/4 drop` / `ip6 daddr ff00::/8 drop` catch-all** —
  too aggressive (MLD, mDNS, unknown groups, housekeeping); r1 gates only
  cataloged dedicated groups.
- **Live Rust `host_inbound_admits` multicast admission** — dead code under F1;
  deferred behind the guard test (§5.4).
- **mDNS/LLMNR/SSDP** — no host-inbound token exists; not admissible/gateable via
  `host-inbound-traffic` and left at policy-accept.
- **Enforce-by-default** — deferred pending §10 Q2 convergence.

---

## 10. Open questions (each invitable to PLAN-KILL)

- **Q1 (lockstep posture, PLAN-KILL fulcrum).** Is kernel-only enforcement +
  shim-diversion guard test an acceptable satisfaction of the "Rust lockstep"
  invariant, or must r1 ship a live (dead-code-today) `host_inbound_admits`
  multicast dimension? If reviewers demand live parity for a path that can never
  execute, the cost/benefit may tip to PLAN-KILL.
- **Q2 (migration posture, PLAN-KILL fulcrum).** Opt-in off-by-default (M-i) vs.
  enforce-by-default (M-iii)? If only M-i is safe, the hardening reaches only
  operators who already set the token — does that thin value justify building the
  iifname machinery at all, or is the shipped advisory (status quo) sufficient →
  PLAN-KILL?
- **Q3 (shared-group carve-out).** Is "accept-when-admitted, never-drop" for
  igmp/router-discovery shared groups (224.0.0.1/2/22) acceptable partial parity,
  or must those be gated too (accepting the housekeeping risk / a daddr+proto
  precise drop)?
- **Q4 (knob surface).** Where does the enable flag live — `security
  forwarding-options host-inbound-multicast enforce`, a `system` flag, or
  per-zone? Junos has no exact equivalent (it enforces unconditionally), so this
  is an xpf-specific migration affordance.
- **Q5 (iifname correctness on RETH/VLAN).** Can `iifname` be resolved reliably
  for every zone-interface shape (base, tagged VLAN unit, RETH member/VIP,
  VRF-bound) without a per-topology special case, given RETH member MAC
  alternation and VLAN sub-netdev naming? If resolution needs per-shape hacks,
  the correctness risk (fail-open on the wrong iface) may dominate.
- **Q6 (VRRP fallback path).** The IPv6 VRRP raw-socket fallback traverses the
  input hook — does admitting ff02::12 on vrrp-zones fully cover it, and is there
  any config where the fallback is the only receiver (AF_PACKET unavailable)?
- **Q7 (counter/metric).** New `xpf_host_inbound_mcast_denies_total` vs. folding
  into the existing kernel-deny counter — does a new label value collide with the
  #3361 scraper's `zone` reverse-mapping?

---

## 11. Recommendation

Adopt **Option A (narrow), kernel-only, opt-in off-by-default**, contingent on
reviewer convergence on Q1 and Q2. Concretely: iifname-scoped accept/drop for the
cataloged **dedicated** groups, shared-group carve-out, enforcement behind an
opt-in knob, kernel-nft as the sole enforcement point with a shim-diversion guard
test, and **no live Rust admission change**. If the reviewers judge (Q1/Q2) that
this cannot honestly claim lockstep and reaches only already-compliant operators,
**PLAN-KILL** (retain the shipped #4454 advisory; do not enforce) is the correct
convergent outcome — and is a fully acceptable result of this research.

**This is `/research`. STOP at PLAN-READY/PLAN-KILL. No PR, no production source
changes. `/engineer 4455` proceeds only after manual approval.**
