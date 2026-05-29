# #1651 — Native dataplane ARP/NDP active resolution — plan-of-action

**Status**: v2 — revised after 3-way round-1 (Codex 2C/2H/1M, AGY, Claude
SMR). v1 overstated "AF_PACKET RX cannot fix VLAN"; v2 retracts that, adds
the shim XSK-redirect path, and promotes the ifindex key-mismatch to the
lead §6 hypothesis. Three-way convergence on the ifindex-mismatch + Gate-M.
**Base SHA**: `0e5bb3812` (origin/master @ 2026-05-28).
**Research branch**: `research/1651-native-arp-resolution`. Docs only.
**Scope**: research-only. STOP at PLAN-READY/KILL. No code, no PR.
**Supersedes target**: #1648 (on-link warming) — only if this converges PLAN-READY.

---

## 0. TL;DR for reviewers (read this first)

The issue proposes building a native AF_PACKET ARP/NDP active resolver in
the dataplane to cut on-link cold-resolve from ~1.016s to <1ms, citing
`send_raw_frame` (AF_PACKET TX) at `neighbor.rs:29` as an existing
building block.

**Three of the issue's load-bearing premises are factually wrong against
`origin/master`, and the corrected facts point at a different bottleneck:**

1. **`send_raw_frame` does NOT exist.** `neighbor.rs:29` is a *dangling
   doc comment* with no function under it. AF_PACKET raw-frame TX was
   built, then **deleted** — see `docs/userspace-cold-start-resolution.md`
   §4 "AF_PACKET `send_raw_frame` Silently Drops on VLAN Sub-Interfaces."
   The issue cites a tombstone as a live primitive.

2. **The AF_PACKET RX path on VLAN is UNCERTAIN, not dead** (v1 overstated
   this; corrected per Codex CRITICAL-1). The cold-start doc §3/§4 evidence
   is about AF_PACKET **TX** failure and **XDP_PASS/cpumap IP-stack demux**
   failure — NOT AF_PACKET **RX with PROMISC**. In fact `docs/bugs.md:580,
   591` documents an in-tree working counter-example: the VRRP receiver uses
   `AF_PACKET SOCK_RAW + ETH_P_ALL + PACKET_MR_PROMISC + BPF filter` to
   RECEIVE multicast on VLAN sub-interfaces, precisely because raw IP
   sockets fail there (bugs.md:585: "AF_PACKET on VLAN sub-interfaces
   requires PACKET_MR_PROMISC to receive multicast from remote peers").
   **Caveat**: that VRRP path runs under *generic* XDP (`xdpgeneric`), where
   AF_PACKET ptype_all taps fire before generic XDP. The WAN smoke iface is
   *mlx5 native/zero-copy* XDP, where the program runs in the driver before
   the skb ptype_all hook. An XDP_PASS'd ARP reply DOES enter the skb stack
   and hit ptype_all, so an AF_PACKET PROMISC socket on the sub-iface MAY
   still see it even when the kernel can't demux it to the sub-iface IP
   stack — but this is genuinely unknown and is a Gate-M sub-measurement.

3. **The on-link smoke target `172.16.80.200` is on VLAN 80**
   (`ge-0-0-2.80` / `ge-7-0-2.80`), the *exact* sub-interface class where
   the historical AF_PACKET TX and ARP-reply-RX failures occurred.

The corrected bottleneck (per the #1636 cluster-validated timeline and the
cold-start doc) is **NOT raw kernel ARP RTT** — on-link the kernel resolves
in ~5ms (cold-start doc §6). The residual ~1.016s is the **D-timeout
drop → client TCP RTO #1** path, which fires because the on-link host is on
a VLAN sub-interface where the kernel ARP entry does NOT get learned in
time (or at all on the first probe) due to the ZC-VLAN-demux gap.

This reframes #1651. **The recommendation hinges on Gate-M** (§3, §11): the
lead hypothesis — converged on independently by all three reviewers (SMR
OQ-3, Codex HIGH-2, AGY §4) — is an **ifindex key-mismatch**: the kernel
learns the on-link neighbor in ~5ms but stores it (via netlink
`parse_neighbor_msg`) under the *physical parent* ifindex, while
`retry_pending_neigh` looks up under the *logical VLAN* `egress_ifindex`, so
the buffered SYN never finds the resolved MAC and drops at the 800ms
D-timeout → client TCP RTO #1 ≈ the observed 1.016s. If Gate-M confirms
this, the fix is a ~5-line parent-ifindex fallback in the retry lookup and
the native resolver is **unnecessary** (PLAN-KILL #1651-as-written, ship a
focused re-drive fix). The native paths (§4/§5) are only authorized if
Gate-M shows genuine kernel ARP latency on-link (the least likely outcome).

This doc designs the native resolver fully (so /engineer can proceed if the
measurement supports it), AND designs the measurement that gates it, AND
states the conditions under which it is PLAN-KILLED.

---

## 1. Problem statement (verified against code)

Cold-resolve path on first packet to an unresolved dst, as it exists today:

1. SYN arrives → XSK RX → session miss → policy permit → SNAT → FIB →
   neighbor lookup miss → `ForwardingDisposition::MissingNeighbor`
   (`poll_descriptor/mod.rs:2379`).
2. Session is created NOW (so the reverse SYN-ACK matches), then the SYN
   frame is buffered in `binding.pending_neigh`
   (`poll_descriptor/mod.rs:2652`, `queued_ns: now_ns`, `probe_attempts: 0`).
3. `trigger_kernel_arp_probe(&name, next_hop)` is fired
   (`poll_descriptor/mod.rs:2429`) — a **SOCK_RAW ICMP echo** with
   `SO_BINDTODEVICE` (`neighbor.rs:36`). This pokes the *kernel's* ARP/NDP
   stack; the dataplane does not craft ARP itself.
4. Kernel runs its own neighbor state machine (`mcast_solicit=3` ×
   `retrans_time_ms`). On reply, the kernel updates its table and emits a
   `RTM_NEWNEIGH` netlink multicast.
5. `neigh_monitor_thread` (`neighbor.rs:465`, RTMGRP_NEIGH) picks up the
   `RTM_NEWNEIGH`, `parse_neighbor_msg` updates `dynamic_neighbors`.
6. `retry_pending_neigh` (`neighbor_dispatch.rs:47`) runs every poll cycle
   — both the idle/`available==0` path (`worker/lifecycle.rs:135`) and the
   work path (`:296`) — finds the now-resolved MAC in `dynamic_neighbors`,
   rewrites the buffered SYN, and TXes it. The drop deadline is
   per-packet: `now_ns - pkt.queued_ns > pending_neigh_timeout_ns`
   (`neighbor_dispatch.rs:110`).

The userspace re-probe schedule (`PROBE_SCHEDULE_NS`,
`neighbor_dispatch.rs:33`) is **10/60/260 ms** (not the "250ms" the task
framing cites). `pending_neigh_timeout_ns` is the #1636 option-D value:
800ms when all interfaces read `retrans_time_ms ≤ 300ms`, else 2000ms
(`forwarding_build/mod.rs:401,443`).

The shim's ARP/NDP handling (verified `userspace-xdp/src/lib.rs`):
- ARP (non-IP L2) → `pass_non_ip_l2_direct()` → `XDP_PASS` (`:358,896`).
  Comment: "cpumap redirect breaks ARP neighbor resolution because the
  remote-CPU processing path does not drive the local L2 state machine."
- NDP (ICMPv6 type 133–137) → `cpumap_or_pass(ctrl)` (`:492`) → kernel via
  cpumap or `XDP_PASS`, **never the XSK**.

So in production, **ARP/NDP replies do NOT reach the XSK.** The XSK-side
ARP/NDP classifier `stage_link_layer_classify` (`poll_stages.rs:78`,
`classify_arp` / `parse_ndp_neighbor_advert`) only fires for frames that
*do* land on the XSK — e.g., a degraded-mode or non-VLAN host whose reply
got redirected. The issue's framing that this path "handles ARP replies on
the RX path" is true only for the non-production minority; the dominant
on-link VLAN case bypasses it.

### 1.1 Three corrected issue claims (evidence)

| Issue claim | Reality (origin/master) | Evidence |
|---|---|---|
| `send_raw_frame` via AF_PACKET at `neighbor.rs:29` is an existing primitive for raw ARP TX | No such function exists anywhere (`rg send_raw_frame` → only a dangling doc comment at `:29` + a stale mention at `:275`). It was built then **deleted**. | `rg -n send_raw_frame userspace-dp/`; cold-start doc §4 |
| AF_PACKET RX tap "likely safer, no shim change" | UNCERTAIN (v1 overstated as dead). AF_PACKET **TX** on VLAN failed; XDP_PASS/cpumap IP-stack demux failed. But AF_PACKET **RX + PROMISC** works on VLAN in-tree (VRRP receiver). The native-vs-generic-XDP ptype_all ordering for the smoke iface is a Gate-M question. | cold-start §3,§4 (TX); `docs/bugs.md:580,585,591` (RX counter-example) |
| Probe re-fire schedule is 250ms | Schedule is **10/60/260 ms** | `neighbor_dispatch.rs:33` |

---

## 2. The actual question this research must answer (measurement-first)

The whole design rests on **what dominates the on-link ~1.016s**. There are
two mutually-exclusive root causes with **opposite** fixes:

- **Root cause A — kernel resolves fast (~5ms) but the SYN is dropped
  before re-drive.** If the kernel learns the on-link neighbor in <10ms and
  emits `RTM_NEWNEIGH`, but the buffered SYN is still dropped at the
  800ms D-timeout and only succeeds on the client's TCP RTO #1 (~1000ms),
  then the bug is in the *re-drive coupling*, not in resolution speed.
  **Native ARP is unnecessary** — the fix is a small `pending_neigh`
  survival/timeout tweak (§6).

- **Root cause A′ — ifindex key-mismatch (the lead hypothesis).** A
  specialization of A. The kernel resolves the on-link neighbor in ~5ms and
  emits `RTM_NEWNEIGH`, but `parse_neighbor_msg` (`neighbor.rs:306,357`)
  single-inserts into `dynamic_neighbors` under the **kernel-reported
  ifindex**. For an XDP_PASS'd VLAN reply that the kernel demuxes to the
  *physical parent* (`ge-0-0-2`, ifindex e.g. 5), that is the parent
  ifindex — but `retry_pending_neigh` looks up `(egress_ifindex, hop)` with
  `egress_ifindex` = the *logical VLAN* sub-iface (e.g. 12)
  (`neighbor_dispatch.rs:118`). Miss → SYN waits → drops at 800ms → client
  RTO. Notably the **passive XSK learn** (`learn_dynamic_neighbor`:320)
  ALREADY dual-inserts the logical ifindex (`:328-344`), so the asymmetry is
  **netlink-path-only**. Fix candidate: dual-insert / parent-fallback in the
  netlink path or the retry lookup (~5 lines). **Native resolver
  unnecessary.** All three reviewers converged here.

- **Root cause B — kernel never learns at all (VLAN-demux delivery gap).**
  If the ARP/NDP reply is genuinely never delivered to the kernel L2 state
  machine for the sub-iface (cold-start §3), the kernel entry sticks
  `INCOMPLETE` and no `RTM_NEWNEIGH` fires. In this case a native path
  COULD help IF it can receive the reply where the kernel cannot —
  candidates: AF_PACKET PROMISC RX on the sub-iface (Path A, viability per
  §4 / Codex CRITICAL-1) or shim XSK-redirect (Path B, §4.3). v1's claim
  that "AF_PACKET cannot fix this" is RETRACTED — it is a Gate-M question.

The #1636 timeline (plan.md:165–178) and cold-start §6 ("ARP resolved in
~5ms") favor Root cause A′ (kernel resolves; userspace fails to find it).
Gate-M must distinguish A′ vs B by instrumenting **which ifindex the kernel
reports** and whether `RTM_NEWNEIGH` fires at all, on BOTH a plain and a
VLAN egress.

---

## 3. § Verified current bottleneck — measurement design (gating step)

**Hypothesis to test**: on-link 1.016s = D-timeout-drop(800ms) +
client-RTO-#1-delta(~216ms), i.e. the SYN is dropped before any successful
re-drive, regardless of whether the kernel resolved.

**Instrumentation** (read-only trace; no code merged — built on a scratch
branch only for the measurement run, discarded after):
- Timestamped event log (monotonic ns) at five points:
  - T0: SYN buffered in `pending_neigh` + initial `trigger_kernel_arp_probe`
    fired (`poll_descriptor/mod.rs:2429,2652`).
  - T1: `RTM_NEWNEIGH` for the target hop observed in
    `neigh_monitor_thread` / `parse_neighbor_msg` (`neighbor.rs:357`).
  - T2: `retry_pending_neigh` finds the MAC in `dynamic_neighbors` and TXes
    the buffered SYN (`neighbor_dispatch.rs:165`).
  - T3: D-timeout drop of the buffered SYN (`neighbor_dispatch.rs:111`).
  - T4: client iperf3 reports `connected`.
- Concurrent host-side captures on BOTH the firewall egress
  (`tcpdump -e -n -i ge-0-0-2.80 arp or icmp6` and the parent `ge-0-0-2`)
  and the target host, plus `ip -ts neigh show` polling at 1ms.
- **The ifindex instrumentation (decides A′)**: log the `ifindex` field
  the kernel reports in the `RTM_NEWNEIGH` for the resolved hop
  (`neighbor.rs:306`) AND the `egress_ifindex` the retry looks up
  (`neighbor_dispatch.rs:118`). If they differ for the VLAN case, A′ is
  confirmed and the fix is the dual-insert/fallback.
- **The AF_PACKET-PROMISC-RX probe (decides Path A viability for B)**:
  bind a throwaway `AF_PACKET SOCK_RAW + ETH_P_ALL + PACKET_MR_PROMISC` +
  ARP/ICMPv6-NA BPF filter to `ge-0-0-2.80` during the cold connect and
  count whether it receives the reply. This directly answers Codex
  CRITICAL-1 / the v1 retraction for the mlx5 native-XDP case.

**Two scenarios, post `ip neigh flush all` on client + firewall:**
- **S1 (VLAN egress)**: cold connect to `172.16.80.200` (VLAN 80) — the
  documented smoke case.
- **S2 (plain egress)**: cold connect to a non-VLAN on-link host on a
  plain `ge-0-0-x` interface (e.g. a `trust`/`untrust` bridge host). If the
  smoke env lacks one, add a host on `xpf-trust`.

**Decision matrix:**

| Observed | Root cause | Implied fix | #1651 verdict |
|---|---|---|---|
| S1: kernel `RTM_NEWNEIGH` lands <10ms but under a DIFFERENT ifindex than the retry lookup; SYN drops at 800ms | **A′ (ifindex key-mismatch)** | netlink dual-insert / retry parent-fallback (~5 lines, §6) | native resolver **unnecessary** → **PLAN-KILL**, ship key fix |
| S1: T1 lands <10ms, ifindex MATCHES, but T3 (drop) still precedes T2 (re-drive) | A (re-drive cadence) | event-driven wake on RTM_NEWNEIGH (§6) | native ARP **unnecessary** → KILL-as-overkill |
| S1: T1 never fires within 800ms AND the AF_PACKET-PROMISC-RX probe ALSO receives nothing | B (delivery gap, native-blocked) | shim/driver VLAN delivery (out of scope) | native AF_PACKET RX cannot help → KILL-as-wrong-layer |
| S1: T1 never fires BUT the AF_PACKET-PROMISC-RX probe DOES receive the reply | B (delivery gap, native-rescuable) | Path A (AF_PACKET PROMISC RX) or Path B (shim XSK-redirect) | native resolver **VIABLE** → conditional PLAN-READY for §4 |
| S2: kernel learn <10ms AND re-drive <15ms (already fast) | plain on-link already solved | none for plain; problem is VLAN-specific | confirms VLAN-specific |
| S1: kernel genuinely slow (>100ms) on-link even on parent capture | C (kernel ARP latency) | native resolver could help | supports #1651 as written |

Only the 4th and 6th rows support building the native resolver. Given
cold-start §6 "ARP resolved in ~5ms" and the #1636 timeline, **A′ is the
expected outcome** and the most likely verdict is PLAN-KILL-native +
ship-the-key-fix. **The measurement is a genuine kill-gate, not a
formality.**

---

## 4. § AF_PACKET active-resolver design (IPv4 ARP) — conditional on Gate-M

> Built out fully so /engineer can proceed IF AND ONLY IF Gate-M lands in
> the "row 4 / Root cause C" outcome. Otherwise this section is moot.

On `MissingNeighbor` with a resolved `next_hop`:

1. **Craft an ARP request** (the missing primitive). 42-byte frame:
   - L2: dst `ff:ff:ff:ff:ff:ff`, src = egress iface MAC
     (`forwarding.ifindex_to_mac` — verify this map exists; if not, read
     via `SIOCGIFHWADDR` once and cache per ifindex), ethertype `0x0806`
     (or `0x8100`+VLAN tag + `0x0806` for VLAN sub-ifaces — **see §4.1**).
   - ARP body: htype=1, ptype=0x0800, hlen=6, plen=4, op=1 (request),
     sender HW = iface MAC, sender proto = iface primary IPv4 on that
     subnet, target HW = `00:00:00:00:00:00`, target proto = `next_hop`.
2. **TX via AF_PACKET** `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`,
   `bind()` to the egress ifindex via `sockaddr_ll`, `send()`. **For VLAN
   sub-ifaces this is exactly what failed historically** (cold-start §4) —
   so this path is only viable on plain interfaces; VLAN egress MUST keep
   the kernel ICMP poke. (This already concedes the design cannot be a full
   replacement.)
3. **RX the reply** via a second AF_PACKET socket bound to the same
   ifindex with an attached BPF filter (`arp[6:2] = 2` for reply opcode,
   or cBPF compiled from `arp and arp[7]=2`), `MSG_DONTWAIT`, polled from
   the worker's idle path. On match, parse with the existing
   `classify_arp` (`parser.rs:80`) — already returns `ArpReply{sender_mac,
   sender_ip}`.
4. **Populate `dynamic_neighbors`** via `learn_dynamic_neighbor`
   (`neighbor_dispatch.rs:320`, with the multi-ifindex VLAN-logical insert)
   and forward the buffered SYN immediately on the next
   `retry_pending_neigh` sweep (already runs every 1ms).
5. **Optionally** `add_kernel_neighbor` (`neighbor.rs:214`, RTM_NEWNEIGH)
   to sync the kernel so subsequent kernel-path traffic resolves.

### 4.1 VLAN tagging hazard (the historical killer)

The cold-start doc §4 enumerates 5 failed attempts to TX ARP on a VLAN
sub-iface, including "insert 802.1Q tag + send on parent → TX offload
strips tag." **There is no demonstrated working AF_PACKET TX path on VLAN
sub-interfaces in this codebase.** Any §4 design MUST either (a) prove a
working VLAN AF_PACKET TX (new evidence, not in repo), or (b) restrict the
native path to plain interfaces and keep the kernel poke for VLAN — which
means the smoke target (VLAN 80) is NOT improved by this work, directly
contradicting the issue's acceptance criterion.

### 4.2 RX latency vs netlink

The claimed advantage is "RX the reply directly, no netlink on critical
path." But `neigh_monitor_thread` already delivers `RTM_NEWNEIGH` via
RTMGRP_NEIGH multicast "within microseconds of kernel resolution"
(cold-start §6, plan #1636 :186). An AF_PACKET RX socket polled from the
1ms worker idle path is **not faster** than a netlink multicast that wakes
on the same 1ms poll — both are bounded by the 1ms `retry_pending_neigh`
cadence, not by the delivery mechanism. The "no netlink" framing does not
buy measurable latency. **This is a core reason the design may not clear
its own bar.**

### 4.3 Path B — shim XSK-redirect (the AGY alternative)

Rather than an AF_PACKET socket, modify the shim (`lib.rs:358` for ARP,
`:492` for NDP) to **redirect** ARP replies / NDP NAs to the XSK ring
instead of `XDP_PASS`/`cpumap`. Frames arrive in the worker RX ring with
802.1Q tags intact; `classify_arp` / `parse_ndp_neighbor_advert`
(`parser.rs:80,130`) already parse tagged frames, and
`stage_link_layer_classify` (`poll_stages.rs:78`) already learns +
`add_kernel_neighbor`-syncs. This sidesteps the kernel L2 demux entirely.

**The serious objection (why this is not free):** the shim comment at
`lib.rs:898` warns cpumap-redirect of ARP "breaks ARP neighbor resolution
because the remote-CPU path does not drive the local L2 state machine."
XSK-redirect is a different action than cpumap but has the same
consequence — the **kernel never sees the reply**, so its neighbor table is
never populated and slow-path/cpumap-reinjected traffic (ESP, NDP RS/RA)
has no kernel entry. XDP has **no cheap clone** (`bpf_clone_redirect` is
TC-only), so keeping the kernel warm requires the dataplane to re-program
the kernel via `add_kernel_neighbor` RTM_NEWNEIGH after learning — which is
exactly what `poll_stages.rs:92` already does on the XSK learn path. So
Path B is workable (redirect → learn natively → netlink-sync the kernel),
but it is a shim change: it re-enters BPF-verifier + per-packet-cost review
(the redirect predicate runs on every non-IP / NDP frame) and must prove no
steady-state regression. Path B is the most promising native option IF
Gate-M shows Root cause B.

---

## 5. § IPv6 NDP design (full)

NDP is structurally harder than ARP and the historical evidence is worse
(VLAN demux affects ICMPv6 NDP identically). A complete design:

1. **Solicit**: Neighbor Solicitation (ICMPv6 type 135) to the
   **solicited-node multicast** `ff02::1:ffXX:XXXX` (low 24 bits of the
   target). L2 dst = `33:33:ff:XX:XX:XX`. Source = the egress iface's
   **link-local** (fe80::/10) address — must be discovered/cached per
   ifindex (`forwarding` must expose link-local; verify). Hop-limit = 255
   (mandatory per RFC 4861 §7.1.1, else the receiver MUST discard).
   ICMPv6 checksum over the pseudo-header (or `IPV6_CHECKSUM` sockopt on a
   raw socket, as `trigger_kernel_arp_probe` already does for the echo).
   NS options: Source Link-Layer Address (type 1) = iface MAC.
2. **RX the NA** (ICMPv6 type 136). The existing
   `parse_ndp_neighbor_advert` (`parser.rs:130`) already parses target IP +
   Target Link-Layer Address (option type 2). Reuse it.
3. **Validation** (anti-spoof, §9): hop-limit == 255 on receipt (RFC
   mandatory); target address matches the solicited address; Solicited
   flag set; if Override flag clear and an entry exists, do not overwrite
   (we only act on entries we solicited, so this is mostly moot).
4. **DAD interaction**: the firewall must NOT answer NS for the target's
   address (we are the solicitor, not the target). When the firewall sends
   NS *from* its own link-local, it must have completed DAD on that
   link-local already (it has, at link bring-up). No new DAD is introduced
   by sending NS for a *remote* target. RS/RA are untouched.
5. **Multicast group membership**: to RX the NA via AF_PACKET we do not
   need MLD membership (AF_PACKET is below the IP layer), but a *raw
   ICMPv6 socket* RX path WOULD need the solicited-node group joined.
   Decide RX mechanism (AF_PACKET vs raw ICMPv6) — AF_PACKET avoids MLD
   but inherits the VLAN-demux problem.

**Same VLAN-demux killer applies.** NDP on VLAN 80 (the IPv6 smoke target
`2001:559:8585:80::200`) faces identical ZC-VLAN-demux failure. There is no
evidence in-repo that an AF_PACKET NS TX or NA RX works on a VLAN
sub-iface. NDP is "where this gets real" precisely because it doubles the
surface with zero additional payoff over the kernel poke on the case that
matters (VLAN).

---

## 6. § Buffered-SYN survival + ifindex key-mismatch (the likely-actual fix)

**Lead hypothesis (3-way convergence — SMR OQ-3, Codex HIGH-2, AGY §4):
ifindex key-mismatch on the netlink learn path.**

Mechanism, verified against code:
- `parse_neighbor_msg` reads `ifindex` from the netlink body
  (`neighbor.rs:306`) and `update_dynamic_neighbor`s a **single** entry
  `(ifindex, ip)` (`:357`).
- For an on-link VLAN host whose ARP reply is XDP_PASS'd, the kernel
  resolves the entry on the **physical parent** (`ge-0-0-2`) because the
  ZC→skb path doesn't drive `vlan_do_receive()` for the sub-iface
  (cold-start §3) — so the `RTM_NEWNEIGH` carries the *parent* ifindex.
- `retry_pending_neigh` looks up `(egress_ifindex, hop)` where
  `egress_ifindex` is the **logical VLAN sub-iface** ifindex
  (`neighbor_dispatch.rs:118`). Parent ≠ logical → `dynamic_neighbors.get`
  misses → SYN stays queued → drops at the 800ms D-timeout → client TCP
  RTO #1 (~1000ms) re-drives. **This reproduces the observed 1.016s exactly
  and needs NO native resolver.**
- **Asymmetry evidence**: the *passive XSK learn* (`learn_dynamic_neighbor`,
  `:320`) ALREADY dual-inserts under both the ingress ifindex AND the
  resolved logical ifindex (`:328-344`, "#949 multi-ifindex insert"). The
  **netlink path does not** — it is single-insert. So the fix is to make the
  netlink path symmetric, OR add a parent-fallback in the retry lookup.

**Candidate fix (~5–15 lines, two options):**
1. *Retry-side parent-fallback* (AGY's sketch — **building blocks
   verified**): in `retry_pending_neigh`, after the `(egress_ifindex, hop)`
   miss, also try `(parent_ifindex, hop)` where
   `parent_ifindex = forwarding.egress.get(&egress_ifindex).bind_ifindex`.
   `ForwardingState.egress: FastMap<i32, EgressInterface>`
   (`types/forwarding.rs:36`) is keyed by the **logical** (VLAN sub-iface)
   ifindex, and `EgressInterface.bind_ifindex` (`:133`) is the **physical
   parent** the XSK binds to — exactly the ifindex the kernel reports for a
   VLAN-resolved entry. So the fallback compiles and is semantically
   correct.
2. *Netlink-side dual-insert*: in `parse_neighbor_msg`, when the resolved
   ifindex is a VLAN parent, also insert under the logical sub-iface(s) —
   reusing the `learn_dynamic_neighbor` multi-ifindex logic. Cleaner
   (symmetry with the passive path) but needs a parent→logical reverse map.

**GATE**: this fix is only correct if Gate-M's ifindex instrumentation
confirms the mismatch. If the ifindexes MATCH and the SYN still drops, the
residual is re-drive cadence (below).

**Secondary (only if ifindexes match):**
- **Event-driven re-drive**: on `RTM_NEWNEIGH` for a hop with a pending
  packet, wake the owning worker's retry instead of waiting for the 1ms
  poll. Marginal (<1ms); only worth it if Gate-M shows the poll cadence is
  the gap.
- **Do NOT lengthen D-timeout**: regresses the SYN#2 path (#1636 §5.1 —
  D=800ms is the tuned optimum vs kernel NUD_FAILED at ~750ms).

This section is the **most likely real deliverable** of #1651: a focused
~5–15-line ifindex/re-drive fix, NOT a native-resolver subsystem. If Gate-M
confirms A′, #1651-as-written is PLAN-KILL and this ships as a new
focused issue.

---

## 7. § HA per-RG

If a native resolver ships, it MUST gate on
`HAGroupRuntime::is_forwarding_active(now_secs)` exactly as the #1636
warmer does (`neighbor.rs:179`), checked immediately before any TX:
- Only the forwarding-active node for the owning RG sends ARP/NDP solicits.
- The standby never solicits (it would generate duplicate ARP on the wire
  and could blackhole if it learns and the active doesn't).
- On failover, the newly-active node re-solicits (the #1636 RG-promote
  warm pass already covers routed next-hops; on-link would piggyback).
- `make test-failover` MUST pass (per CLAUDE.md: any RG/VRRP/session-sync
  touch requires it). The owning RG for a `MissingNeighbor` resolution is
  `owner_rg_for_resolution` (`neighbor_dispatch.rs:357`).

But note: this HA surface is **only incurred if the native resolver is
built.** The §6 SYN-survival tweak touches no HA-relevant code (it operates
on already-RG-gated pending packets), so it has a far smaller HA blast
radius — another reason to prefer §6 if Gate-M permits.

---

## 8. § Fallback strategy

If native ships: **native primary + kernel/netlink fallback, never
replace.** The kernel poke (`trigger_kernel_arp_probe`) +
`neigh_monitor_thread` MUST stay because:
- VLAN sub-ifaces have no working native AF_PACKET TX (§4.1) — kernel poke
  is the only path there.
- The kernel table must stay populated for the slow-path/cpumap reinject
  traffic that does not transit the XSK.
- Idempotency: `learn_dynamic_neighbor` and `parse_neighbor_msg` both
  upsert into the same `ShardedNeighborMap`; double-learn (native RX +
  netlink) is a harmless idempotent overwrite of the same `(ifindex, ip) →
  mac`. `insert_if_changed` (`neighbor.rs:286`) already no-ops on
  identical values.

Replacing the kernel path is rejected outright.

---

## 9. § Anti-spoof validation

The dataplane already accepts ARP replies and NDP NAs it observes on the
RX path (`stage_link_layer_classify`, `poll_stages.rs:79–113`) with NO
validation today — it trusts any ARP reply / NA-with-TLLA on the ingress
ifindex (Codex MEDIUM-1 concurs). A native solicit-then-accept path
**MUST** add (mandatory, not optional); and these hardenings are
independently shippable against the existing passive path even if #1651 is
killed:
- **ARP**: accept only replies whose `sender_ip == solicited target` AND
  `sender_ip` is on the egress iface's configured subnet (on-link check).
  Drop replies for IPs we did not solicit (track outstanding solicits in a
  small per-worker set keyed `(ifindex, target_ip)`).
- **NDP**: hop-limit == 255 (RFC-mandatory, cheap, blocks off-link
  spoofing); target matches solicited; Solicited flag set.
- This is *stricter* than today's passive learn — a latent hardening win
  regardless of whether the native path ships, and could be applied to the
  existing passive learn at `poll_stages.rs` independently.

## 10. § Concurrency / idempotency

- `dynamic_neighbors` is a `ShardedNeighborMap` (`Arc`, interior mutability)
  written by: (a) netlink monitor thread (`parse_neighbor_msg`), (b) passive
  RX learn (`poll_stages.rs`, `learn_dynamic_neighbor_from_packet`), (c) the
  proposed native RX. All three use `insert`/`insert_if_changed`/
  `with_all_shards` which are already concurrency-safe. A native writer adds
  no new race class.
- `retry_pending_neigh` reads `dynamic_neighbors.get()` — a concurrent
  insert from any writer is observed on the next sweep. No coordination
  needed beyond what exists.
- The per-sweep probe dedup (`neighbor_dispatch.rs:92`) already prevents a
  probe storm; a native solicit would need the same dedup keyed
  `(egress_ifindex, next_hop)`.

---

## 11. § Acceptance, gates, and open questions

### Gate-M (measurement gate — BLOCKS everything)
Run §3 S1+S2 on the loss userspace cluster. Classify into the §3 decision
matrix. Only the "Root cause C / kernel ARP genuinely slow on-link" outcome
authorizes building §4/§5. Any other outcome → PLAN-KILL the native design
and pivot to §6 (or out-of-scope VLAN-demux).

### If native is authorized (unlikely per evidence)
- On-link cold connect (post flush) to plain AND VLAN host ≤ single-digit ms.
- IPv4 + IPv6 both covered (or VLAN explicitly carved out with rationale).
- `make test-failover` clean; per-RG gating verified on both nodes.
- No steady-state forwarding regression; AF_PACKET RX only on cold-resolve.
- Full smoke matrix (v4+v6 × push/-R × CoS-off/on) per project rules.

### Hostile open questions
1. **OQ-1**: Is there ANY working AF_PACKET TX path on a VLAN sub-interface
   in this kernel/driver combo? The repo says no (5 failed attempts). If
   not, the issue's primary acceptance criterion (VLAN-80 on-link ≤200ms
   via native) is unachievable by this design. **Must be answered before
   any code.**
2. **OQ-2**: Does the on-link 1.016s persist even when the kernel resolves
   the neighbor in <10ms (i.e., is the SYN dropped before re-drive)? If
   yes, native resolution provides ZERO benefit over a §6 tweak. (Gate-M
   T1-vs-T3 ordering.)
3. **OQ-3**: Is the netlink-learn → `retry_pending_neigh` re-drive keyed on
   the same ifindex the resolve populates? A physical-vs-logical (VLAN)
   ifindex key mismatch would make the kernel-resolved entry invisible to
   the retry — explaining a fast-kernel-resolve-but-still-1s outcome and
   pointing at a one-line key fix, not native ARP.
4. **OQ-4**: Does an AF_PACKET RX socket polled from the 1ms worker idle
   path beat RTMGRP_NEIGH multicast (also serviced on the same 1ms poll)?
   The claimed "no netlink on critical path" advantage appears to be ~0ms
   given both are poll-cadence-bound (§4.2). Quantify or retract.
5. **OQ-5**: The issue cites `send_raw_frame` as existing — it does not.
   What is the true cost of re-introducing AF_PACKET TX given it was
   deliberately deleted for VLAN unreliability? Is this re-litigating a
   settled decision?
6. **OQ-6**: For NDP, AF_PACKET RX of the NA avoids MLD but inherits VLAN
   demux; raw-ICMPv6 RX needs solicited-node group membership but might
   demux correctly. Which, and is either proven on VLAN?

---

## 12. Recommendation (provisional, pre-review)

**PLAN-KILL-leaning for the native resolver as written; PLAN-READY for the
Gate-M measurement + the §6 ifindex/re-drive fix.** Pending the one bounded
measurement. The evidence on `origin/master`:
- The headline primitive (`send_raw_frame`) does not exist; it was deleted.
  The issue cites a tombstone.
- The lead hypothesis (Root cause A′, 3-way convergence) is an **ifindex
  key-mismatch** on the netlink learn path that fully explains the 1.016s
  with NO native resolver. The fix is ~5–15 lines (§6).
- v1's "AF_PACKET RX cannot fix VLAN" is **retracted** (Codex CRITICAL-1):
  AF_PACKET PROMISC RX works on VLAN in-tree (VRRP), and the shim
  XSK-redirect (Path B, §4.3) is a real native alternative IF Gate-M shows
  a genuine delivery gap (Root cause B) rather than A′.

**The honest path: run Gate-M first** (one bounded cluster step). Expected
outcome (per cold-start §6 "ARP resolved in ~5ms" + the #1636 timeline):
A′ confirmed → **PLAN-KILL the native resolver**, open a focused issue for
the §6 ifindex/re-drive fix, and **do NOT close #1648 as superseded** (its
on-link warming is orthogonal; keep it as a separate mitigation track).
Only if Gate-M shows Root cause B-native-rescuable (row 4) or C (row 6)
does the §4 (Path A or B) / §5 native resolver earn its complexity — and
even then Path B (shim) is preferred over Path A (AF_PACKET) on the
VLAN case, with the kernel-warm-via-netlink-sync caveat.
