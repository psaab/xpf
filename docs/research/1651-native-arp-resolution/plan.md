# #1651 — Native dataplane ARP/NDP active resolution — plan-of-action

**Status**: DRAFT v1 — pending 3-way hostile review (Codex + AGY + Claude SMR).
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

2. **The proposed "AF_PACKET RX tap, no shim change" was already tried and
   abandoned** for the exact reason it is proposed (VLAN demux). See §3 +
   §4 + Key Learnings 1–2 of that same doc. cpumap/XDP_PASS of ARP/NDP
   replies on mlx5 zero-copy does not drive `vlan_do_receive()`, so the
   reply never matches the VLAN sub-interface and the kernel entry sticks
   in `INCOMPLETE`.

3. **The on-link smoke target `172.16.80.200` is on VLAN 80**
   (`ge-0-0-2.80` / `ge-7-0-2.80`), the *exact* sub-interface class where
   the historical AF_PACKET TX and ARP-reply-RX failures occurred.

The corrected bottleneck (per the #1636 cluster-validated timeline and the
cold-start doc) is **NOT raw kernel ARP RTT** — on-link the kernel resolves
in ~5ms (cold-start doc §6). The residual ~1.016s is the **D-timeout
drop → client TCP RTO #1** path, which fires because the on-link host is on
a VLAN sub-interface where the kernel ARP entry does NOT get learned in
time (or at all on the first probe) due to the ZC-VLAN-demux gap.

This reframes #1651 entirely. **This plan's recommendation hinges on a
single measurement** (§3, §11 Gate-M): does on-link cold-resolve in the
smoke env actually resolve in the kernel in <10ms (→ the SYN-survival /
re-drive logic is the fix, a small tweak — and native resolution is
**unnecessary**), or does it genuinely fail to resolve in the kernel
(→ the VLAN-demux gap is the fix, which AF_PACKET RX *cannot* solve, so the
native design as proposed is **PLAN-KILL** and the real fix is elsewhere)?

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
| AF_PACKET RX tap "likely safer, no shim change" | Tried and abandoned: ZC-VLAN-demux drops it; `send()`/`sendto()` report success but frames never reach the wire on VLAN sub-ifaces | cold-start doc §3, §4, Key Learnings 1–2 |
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

- **Root cause B — kernel never learns the on-link neighbor in time
  (VLAN-demux gap).** If the on-link host is on a VLAN sub-interface and the
  ARP/NDP reply is silently dropped by the ZC-VLAN-demux path (cold-start
  doc §3), the kernel entry sticks `INCOMPLETE`, no `RTM_NEWNEIGH` fires,
  the SYN drops at D-timeout, and the client RTO #1 re-drives (by which
  time a *second* kernel solicit + the warmer or retry has resolved it).
  **AF_PACKET RX cannot fix this** — the reply still does not reach an
  AF_PACKET socket on the VLAN sub-iface for the same kernel reason.
  Native resolution as proposed is then a **PLAN-KILL**; the real fix is
  the VLAN-demux delivery path (a shim/driver concern, out of #1651 scope).

The #1636 timeline (plan.md:165–178) and cold-start doc §6 ("ARP resolved
in ~5ms") strongly suggest a **hybrid**: kernel resolution is fast on a
*plain* interface, but the smoke target is on VLAN 80, so the smoke number
reflects the VLAN gap (Root cause B), while a non-VLAN on-link host would
already resolve fast (Root cause A path, already handled). The measurement
(§11 Gate-M) must distinguish these on BOTH a plain and a VLAN egress.

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

**Two scenarios, post `ip neigh flush all` on client + firewall:**
- **S1 (VLAN egress)**: cold connect to `172.16.80.200` (VLAN 80) — the
  documented smoke case.
- **S2 (plain egress)**: cold connect to a non-VLAN on-link host on a
  plain `ge-0-0-x` interface (e.g. a `trust`/`untrust` bridge host). If the
  smoke env lacks one, add a host on `xpf-trust`.

**Decision matrix:**

| Observed | Root cause | Implied fix | #1651 verdict |
|---|---|---|---|
| S1: T1 (kernel learn) lands <10ms, but T3 (drop) precedes T2 (re-drive); connect on RTO#1 | A (re-drive/timeout coupling) | §6 SYN-survival tweak ONLY | native ARP **unnecessary** → KILL-as-overkill |
| S1: T1 never fires (no RTM_NEWNEIGH) within 800ms; reply seen on parent but not sub-iface | B (VLAN-demux gap) | shim/driver VLAN delivery (out of scope) | native AF_PACKET RX **cannot fix** → KILL-as-wrong-layer |
| S2: kernel learn <10ms AND re-drive <15ms (already fast) | plain on-link already solved | none for plain; S1 is VLAN-specific | confirms problem is VLAN-only |
| S1: kernel genuinely slow (>100ms) to resolve on-link even on parent capture | C (kernel ARP latency) | native resolver *could* help | the ONLY case that supports #1651 as written |

Only the last row supports building the native resolver as proposed.
Given the cold-start doc's "ARP resolved in ~5ms" and the #1636 timeline,
the last row is the least likely outcome. **The measurement is therefore a
genuine kill-gate, not a formality.**

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

## 6. § Buffered-SYN survival (the likely-actual fix)

If Gate-M shows Root cause A (kernel resolves fast, SYN dropped early), the
fix is small and does NOT need native ARP:

- **The drop at `neighbor_dispatch.rs:110` recycles the frame at D-timeout
  (800ms).** If the kernel/native resolve lands at, say, 5ms but a *later*
  poll missed it, raising survival is about ensuring the re-drive sweep
  runs promptly after `RTM_NEWNEIGH` (it does, every 1ms) — so a true Root
  cause A would already forward at ~6ms. **If it doesn't, that's the
  bug to find** (e.g., the netlink learn updates `dynamic_neighbors` under
  the *logical* ifindex but `retry_pending_neigh` looks up under the
  *physical* egress ifindex, or vice versa — a key-mismatch). §11 Gate-M
  T1-vs-T2 gap pinpoints this.
- **Candidate tweak**: on `RTM_NEWNEIGH` for a hop that has a pending
  packet, proactively wake the owning worker's retry (event-driven
  re-drive) instead of relying on the 1ms poll. Marginal (<1ms) — only
  worth it if the poll cadence is shown to be the gap.
- **Do NOT lengthen D-timeout**: that regresses the SYN#2 path (#1636
  §5.1 analysis — D=800ms is already the tuned optimum vs the kernel
  NUD_FAILED at ~750ms).

This section is the **most likely real deliverable** of #1651, and it is a
~20-line change, not a native-resolver subsystem.

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
ifindex. A native solicit-then-accept path is **no worse** but should add:
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

**Provisional PLAN-KILL-leaning**, pending Gate-M. The evidence on
`origin/master` is that:
- The headline primitive (`send_raw_frame`) does not exist; it was deleted.
- The proposed AF_PACKET RX-tap approach was already tried and abandoned
  for the exact VLAN case that is the smoke target.
- The on-link bottleneck is almost certainly the D-timeout-drop → TCP-RTO
  path (Root cause A) or the VLAN-demux gap (Root cause B), neither of
  which native ARP resolution fixes — A is fixed by a small §6 tweak, B is
  a shim/driver layer concern outside #1651.

The honest path: **run Gate-M first.** If it confirms A/B (expected),
PLAN-KILL #1651 as written and either (a) open a focused §6 SYN-survival /
re-drive-key issue, or (b) confirm #1648's on-link warming is the pragmatic
mitigation after all (do NOT close #1648 as superseded). Only if Gate-M
shows genuine kernel ARP latency on-link (row 4) does the §4/§5 native
resolver earn its complexity.
