# Claude SMR hostile plan-review — #1651 r1

**Reviewer framing**: kernel-networking / AF_PACKET / ARP-NDP-protocol /
AF_XDP / HA domain expert. Hostile by mandate (no first-pass soft pass).
**Target**: `docs/research/1651-native-arp-resolution/plan.md` v1 @ `1bbe07b5b`.
**Verdict**: **PLAN-NEEDS-REVISION** (not yet PLAN-READY; not PLAN-KILL).

## Where v1 is right (verified independently against origin/master)

- **Claim 1 (`send_raw_frame` does not exist)**: VERIFIED. `rg send_raw_frame
  userspace-dp/` returns only the dangling doc comment at `neighbor.rs:29`
  and a stale mention at `:275`. The issue cites a tombstone. Codex + AGY
  concur.
- **Claim 3 (target on VLAN 80)**: VERIFIED. `docs/ha-cluster-userspace.conf`
  `unit 80 { vlan-id 80; address 172.16.80.8/24 }`; cold-start doc:179
  `next-hop 172.16.80.200 on ge-0-0-2.80`. Codex + AGY concur.
- **Claim 4 (bottleneck is D-drop+RTO, not kernel ARP RTT)**: VERIFIED as a
  hypothesis with strong support — cold-start doc:145 "ARP resolved in ~5ms
  but the retry didn't fire for another ~1195ms"; jit-design "1.016s B+D
  worst-case path." Still inferential without a live T0–T4 trace. All three
  reviewers agree it is plausible and that Gate-M is mandatory.
- **The ifindex key-mismatch (OQ-3)**: this is the standout. **Three-way
  convergence** — my OQ-3, Codex HIGH-2, and AGY §4 independently land on the
  same hypothesis: netlink learns the on-link neighbor under the *physical
  parent* ifindex (the XDP_PASS reply demuxes to `ge-0-0-2`, not
  `ge-0-0-2.80`), while `retry_pending_neigh` looks up under the *logical
  VLAN* `egress_ifindex` (`neighbor_dispatch.rs:118`,
  `neigh_key = (egress_ifindex, hop)`). A miss here strands the SYN until
  the D-timeout → exactly the observed 1.016s. AGY supplies a candidate
  parent-fallback fix. **This must be promoted from an open question to the
  primary investigation hypothesis in §6.**

## Where v1 is WRONG and must be corrected (self-correction)

- **Claim 2 was overstated, and I (SMR) wrote it that way.** v1 asserts the
  AF_PACKET RX tap "was already tried and abandoned" and "cannot fix" VLAN.
  Codex refutes this with `docs/bugs.md:580,591`: the VRRP receiver uses
  **AF_PACKET (SOCK_RAW + ETH_P_ALL + PACKET_MR_PROMISC + BPF filter) to
  RECEIVE on VLAN sub-interfaces**, precisely because raw IP sockets fail
  there. bugs.md:585 "AF_PACKET on VLAN sub-interfaces requires
  PACKET_MR_PROMISC to receive multicast from remote peers." The cold-start
  doc §3/§4 evidence is about **AF_PACKET TX** failure and **XDP_PASS/cpumap
  IP-stack demux** failure — NOT about AF_PACKET RX with PROMISC. **I
  conflated three distinct mechanisms.** The plan's "AF_PACKET RX cannot fix
  VLAN" is not proven and contradicts an in-tree working counter-example.

  *However*, AGY raises a real caveat that keeps this from being a clean
  refutation: bugs.md describes the working VRRP RX path on **generic XDP**
  (`xdpgeneric`), where AF_PACKET ptype_all taps fire *before* generic XDP
  in `__netif_receive_skb_core`. The WAN smoke iface is **mlx5 native /
  zero-copy XDP**, where the XDP program runs in the driver before the
  skb-based ptype_all hook. The open question is whether an **XDP_PASS'd**
  ARP reply (which DOES enter the skb stack and hit ptype_all) is visible to
  an AF_PACKET PROMISC socket on the sub-iface even though the kernel can't
  *demux it to the IP stack* of the sub-iface. These are different code
  paths and the answer is genuinely unknown from the repo. → **Gate-M must
  measure this directly** (does an AF_PACKET PROMISC socket on `ge-0-0-2.80`
  receive the XDP_PASS'd ARP reply?), not assert it dead.

- **The decision matrix is missing the AGY shim-redirect third path.** Both
  the issue and AGY propose redirecting ARP/NDP to the XSK at the shim
  (`lib.rs:358,492`), where VLAN tags arrive intact (parser.rs already
  handles tagged frames, poll_stages.rs:78 already learns from them). The
  shim comment warns cpumap-redirect breaks kernel resolution — but
  XSK-redirect is a *different* action than cpumap, and the plan should
  evaluate it as Path C, with the explicit cost: the shim must still PASS a
  *copy* (or re-inject) to keep the kernel table warm for slow-path traffic,
  which XDP cannot do cheaply (no clone primitive in XDP). This is the
  serious objection to Path C, not a hand-wave.

## Hostile findings the plan must resolve before PLAN-READY

- **SMR-1 (CRITICAL, self-correct)**: Rewrite §2/§3/§12 to STOP asserting
  AF_PACKET-RX-on-VLAN is dead. Reframe as: three candidate native paths —
  (A) AF_PACKET PROMISC RX on sub-iface, (B) shim XSK-redirect, (C) none /
  ifindex-fallback fix — and Gate-M decides. The bugs.md:591 counter-example
  makes the blanket "cannot fix" indefensible.

- **SMR-2 (CRITICAL)**: Promote the ifindex key-mismatch to §6's primary
  hypothesis. If Gate-M confirms netlink stores under the parent ifindex and
  the retry looks up under the logical, the fix is ~5 lines
  (`neighbor_dispatch.rs:117-126` parent-fallback) and #1651 is PLAN-KILL as
  written (native resolver unnecessary), with a focused follow-up issue
  shipping the key fix. Note: `learn_dynamic_neighbor` (`:320`) ALREADY
  dual-inserts the logical ifindex for the *XSK passive-learn* path — so the
  asymmetry is specifically in the *netlink* path (`parse_neighbor_msg` does
  a single insert under whatever ifindex the kernel reports). Verify which
  ifindex the kernel actually reports for a VLAN-resolved entry in Gate-M.

- **SMR-3 (HIGH)**: §4.2's "AF_PACKET RX is not faster than netlink" point
  is correct and is the quiet killer of the perf rationale: both are bounded
  by the 1ms `retry_pending_neigh` poll cadence
  (`worker/lifecycle.rs:135,296`). If the bottleneck is the poll cadence or
  the key-mismatch, NO resolution-delivery mechanism (native or kernel)
  helps — only fixing the re-drive does. This must be stated as a gating
  argument, not a sub-bullet.

- **SMR-4 (MEDIUM)**: Anti-spoof §9 should be mandatory and is independently
  shippable. The passive learn at `poll_stages.rs:79,100` accepts any ARP
  reply / NA-with-TLLA unconditionally. Codex MEDIUM-1 concurs. Even if
  #1651 is killed, harden the existing passive path.

- **SMR-5 (LOW)**: The plan's §4 VLAN-TX concession (native TX only works on
  plain ifaces) is correct and, combined with SMR-1, means a native design
  would be RX-native + TX-via-kernel-poke — a hybrid, not the clean "craft
  ARP, send, receive" the issue describes. State this hybrid explicitly.

## Recommendation

Revise to v2: (1) retract the AF_PACKET-RX-dead overclaim (SMR-1), (2) make
the ifindex-mismatch §6's lead hypothesis (SMR-2), (3) add the shim-redirect
Path C with its kernel-warm-copy objection, (4) keep Gate-M as the hard kill
gate but expand it to measure the AF_PACKET-PROMISC-RX-on-VLAN question and
the netlink-ifindex question directly. The most likely converged outcome
remains **PLAN-KILL the native resolver + ship the ifindex/re-drive fix**,
but v1 reached that conclusion via a partly-wrong argument and must reach it
via the right one.
