# Userspace Dataplane: ICMP Error NAT Reversal — Debugging Notes

Last updated: 2026-03-15 04:30 UTC

## Problem

`mtr` from `cluster-userspace-host` through the userspace firewall shows `???` for all intermediate hops but the final destination works:

```
HOST: cluster-userspace-host      Loss%   Snt
  1.|-- ???                       100.0
  ...
 11.|-- one.one.one.one            0.0%
```

## Root Cause

ICMP Time Exceeded (type 11) from intermediate routers arrives at the firewall's SNAT'd address (e.g. `172.16.80.8`). The userspace DP needs to:
1. Parse the embedded packet in the ICMP error
2. Find the matching forward session via NAT reverse index
3. Rewrite the outer ICMP destination from SNAT'd IP → original client IP
4. Rewrite the embedded packet's source from SNAT'd → original
5. Recompute all checksums (outer IP, outer ICMP, embedded IP)
6. Forward the rewritten ICMP error to the original client

### Destination reversal for DNAT / static-NAT (#3112)

Steps 3-4 above describe the SOURCE reversal that un-SNATs outbound flows.
The symmetric DESTINATION reversal handles INBOUND DNAT/static-NAT'd
servers. For a flow `client C -> public P` that the firewall DNATs to a
private server `S`, the ICMP error returns from `S` quoting a packet
addressed to `S` (and originating, on the outer header, from `S`). The
client opened its socket to `P`, so it silently discards an error that
quotes `S` — breaking PMTUD and traceroute to NAT'd servers.

When the matched forward session carries a destination NAT
(`NatDecision.rewrite_dst.is_some()`), the builders additionally:

- rewrite the **outer source** IP `S -> P` (the public address the client
  used), so the error appears to originate from `P`;
- rewrite the **embedded (quoted) destination** IP `S -> P`;
- rewrite the **embedded transport destination port** to the pre-DNAT
  public port (TCP/UDP only; ICMP echo carries no destination port);
- recompute the embedded IP-header checksum (IPv4) and the outer
  ICMP/ICMPv6 checksum (the ICMPv6 pseudo-header picks up the rewritten
  outer source automatically).

The pre-DNAT public destination + port are recovered from the forward
session key (`fwd.key.dst_ip` / `fwd.key.dst_port`), which holds the
ORIGINAL pre-NAT tuple, and are carried on `EmbeddedIcmpMatch` as
`original_dst` / `original_dst_port`. When the flow has **no** destination
NAT (SNAT-only or plain transit), these equal the embedded destination and
the rewrites are gated off — the output is byte-identical to the
source-only path, so transit/intermediate-router errors keep their real
outer source.

### Which ICMP error types are reversed (`is_icmp_error`)

The embedded-NAT reversal only runs for ICMP messages that quote the
offending datagram (an inner IP header + at least the first 8 bytes of its
transport header). `is_icmp_error` (`userspace-dp/src/afxdp/icmp.rs`) is the
single source of truth for that set, shared by all three gate sites
(`icmp_embed/mod.rs`, `icmp_embed/session_match.rs`,
`poll_descriptor/mod.rs`):

- **ICMPv4**: types **3** (Dest Unreachable), **4** (Source Quench),
  **5** (Redirect), **11** (Time Exceeded), **12** (Parameter Problem).
  All five share the RFC 792 8-byte ICMP header layout — the type-specific
  word (Redirect's gateway address; the unused word on the others) occupies
  bytes 4..8 — so the quoted IP header always begins at `l4 + 8` and the
  type-agnostic parser/builders need no per-type handling.
- **ICMPv6**: types **1** (Dest Unreachable), **2** (Packet Too Big),
  **3** (Time Exceeded), **4** (Parameter Problem).

**#2393** added ICMPv4 types 4 and 5. Before that the set was 3/11/12, so a
NAT44-transit Redirect (5) or Source Quench (4) was forwarded with its
quoted inner addresses left at the post-SNAT value (mismatched at the
host). Type 4 is deprecated (RFC 6633) and type 5 is normally link-scoped,
so a NATed transit instance is rare — but ICMP transit forwarding is
type-agnostic (no link-scope drop in the same-family path), so they *can*
reach this path. The set now matches the reject-suppression guard
(`reject_icmp_reply_suppressed`) and Linux netfilter conntrack's related-
ICMP `icmp_error` (3/4/5/11/12). Note this governs only **same-family**
embedded-NAT reversal; on the **NAT64** cross-family path Source Quench /
Redirect have no IPv6 analogue and are still dropped, not mistranslated
(RFC 7915, `nat64.rs`).

## What's Implemented (commit `d892376`)

### NAT Reversal Logic — WORKING (unit tested)

- `EmbeddedIcmpMatch` struct returns NAT info + original client IP + forwarding resolution
- `try_embedded_icmp_nat_match()` looks up session via NAT reverse index, resolves FIB toward original client
- `build_nat_reversed_icmp_error_v4()` — rewrites outer dst + embedded src/port, recomputes all checksums
- `build_nat_reversed_icmp_error_v6()` — same for IPv6/ICMPv6
- `PendingForwardRequest.prebuilt_frame` — carries pre-built frames for direct TX
- 5 unit tests passing (IPv4 TE, port SNAT, dest unreach, IPv6 TE, no-match)

### Live TX Path — NOT WORKING

The prebuilt ICMP error frames are being created but not transmitted. Evidence:
- slot 0 (ge-0-0-1 q0): rx=93, tx=0, miss=93, slow=93 — all going to slow-path
- slot 3 (ge-0-0-2 q3): rx=4, tx=42 — WAN transmits work fine
- LAN TX is zero — the reversed ICMP errors aren't reaching the wire

### Suspected Issue: Binding Selection for Prebuilt Frames

The `enqueue_pending_forwards()` function dispatches each `PendingForwardRequest` to the correct egress binding based on `target_ifindex`. For prebuilt frames, the binding selection may fail because:

1. The `target_ifindex` in the `PendingForwardRequest` might not match any binding's ifindex
2. The prebuilt frame path in `enqueue_pending_forwards` might skip the frame entirely
3. The TX ring on the LAN binding might not be available (fill ring exhaustion)

### How to Debug Next

1. Add `eprintln!` in `enqueue_pending_forwards()` when a `prebuilt_frame.is_some()` request arrives — log the target_ifindex and whether a matching binding was found
2. Check if the `EmbeddedIcmpMatch.resolution` has the correct `egress_ifindex` and `tx_ifindex` pointing to the LAN interface
3. Verify the prebuilt frame path in `enqueue_pending_forwards` actually writes to the TX ring
4. Check if the frame is being written but the TX completion isn't happening (sendto/kick needed)

## Separate Issue: GRE Tunnel Return Traffic (10.255.192.41)

The ping to `10.255.192.41` via the GRE tunnel fails because the **outer GRE reply packets never reach the firewall's physical NIC** (ge-0-0-2). The outbound GRE requests leave fine, but zero reply packets arrive on the wire. This is a network-level issue (upstream routing) — not a BPF or userspace DP bug.

Evidence:
- `tcpdump -i ge-0-0-2 "src host 2602:ffd3:0:2::7"` → 0 packets captured
- Remote tcpdump shows replies being sent
- Outbound GRE visible on ge-0-0-2

## Current State (c5cb982)

Historical note: this section predates #1473. The userspace runtime now keeps
`xdp_userspace_prog` attached and no longer swaps degraded helper/XSK states
back to `xdp_main_prog`. At the time of this capture, ICMP TE from intermediate
routers reached the userspace DP when armed and primary, but the session-miss
debug log (`/tmp/icmp_te_debug.log`) was never created. This meant either:

1. The ICMP TE packets hit an existing session (session hit path, bypass session-miss entirely)
2. The ICMP TE packets take a different code path before reaching the session-miss block
3. The Rust child process can't write to `/tmp/` (permissions/namespace issue)

Next debugging step: add debug logging to the session HIT path to see if ICMP TE matches an established session. Also verify `/tmp/` is writable from the Rust worker threads.

At the time of this capture, the key finding was that forwarding-disabled HA
secondaries ran `xdp_main_prog` and the eBPF embedded ICMP handler worked
correctly. When forwarding was armed, the userspace shim redirected ICMP TE to
userspace where the NAT reversal did not work (per-worker session isolation
plus cross-worker shared session lookup issue).

## Retired: `dnat_table` reverse-NAT steering (#17229)

The `dnat_table` / `dnat_table_v6` BPF steering maps and their publishers
were removed in #17229: the shim's `dnat_lookup_v4`/`_v6` readers were
deleted in 6f303c1cbc (#16241), so no packet's fate depended on those maps.
Embedded-ICMP reverse-NAT is handled from the helper's in-memory session
state. The `xpf_userspace_dnat_publish_errors_total` metric is also retired.

## XDP Shim Fixes Applied

1. **GRE/ESP XDP_PASS** (`7af4829`): GRE (proto 47) and ESP (proto 50) use `cpumap_or_pass()` directly instead of `fallback_to_main()` tail-call, which was silently failing (XDP_DROP fallthrough).

2. **Removed ICMP fallback** (`13241e7`): ICMP/ICMPv6 now goes to userspace DP natively instead of falling back to eBPF.

3. **Removed mid-stream TCP fallback** (gate-fixes merge): All TCP goes to userspace, not just SYN.

4. **Tail-call issue discovered**: the removed `fallback_to_main()` path used
   `USERSPACE_FALLBACK_PROGS.tail_call()` and could fail silently in the
   aya-ebpf framework, causing XDP_DROP instead of eBPF pipeline processing.
   The current shim bypasses that path entirely. Degraded helper/XSK states
   pass only proven local/control traffic and drop non-local transit.

## TC Conntrack Fix

`bpf/tc/tc_conntrack.c`: Added session creation for outer GRE/ESP tunnel-encapsulated packets (ingress_ifindex != 0 path). Previously these were passed through without session creation, preventing XDP ingress from matching the reverse entry. However, the XDP conntrack still shows 0 reverse-hit packets — this needs further investigation but is moot since GRE replies don't reach the NIC (network issue).

## ip rule Route Leaking

`pkg/dataplane/userspace/manager.go`: Added synthetic routes from `ip rule` entries to the userspace route snapshot. When `ip rule add to <prefix> lookup <table>` exists (from rib-group or next-table leaking), a `RouteSnapshot` with `NextTable` is added so the userspace FIB can cross-reference VRF tables.

## Tunnel Slow-Path Routing

`userspace-dp/src/afxdp.rs`: When FIB resolves to a tunnel interface (GRE/ip6gre/XFRM), the forwarding disposition is overridden to `MissingNeighbor` which routes through the kernel slow-path. The kernel handles GRE encapsulation; the userspace DP cannot TX directly to tunnel AF_XDP sockets.

## TCP RST reject reply: L2 group/broadcast guard (#3204)

The locally-generated **reject reply** has two legs that must agree on L2
suppression:

- **Non-TCP** rejects build an ICMP/ICMPv6 admin-prohibited unreachable. Its
  suppression gate `can_generate_icmp_error_reply`
  (`userspace-dp/src/afxdp/icmp.rs`) already refuses to reply to a frame whose
  L2 destination is group/broadcast, via the shared
  `l2_dst_is_group_or_broadcast` predicate
  (`userspace-dp/src/afxdp/frame/inspect.rs`, the I/G group bit of the first
  MAC octet, which also covers the all-ones broadcast).
- **TCP** rejects build a reflected RST (`build_reject_rst_frame`,
  `userspace-dp/src/afxdp/frame/tcp.rs`). The reply's source MAC is the inbound
  **destination** MAC (`write_reply_eth_header`: `out[6..12] = frame[0..6]`),
  so a RST built in response to a multicast/broadcast-addressed frame would
  egress with a group/broadcast **source** MAC — an IEEE 802.3 violation that
  poisons/flaps switch MAC tables and can reflect/loop traffic.

#3204 adds the SAME `l2_dst_is_group_or_broadcast` guard to
`build_reject_rst_frame` so the TCP leg matches the ICMP leg: a trigger frame
with a group/broadcast L2 destination yields `None`, and the caller
(`enqueue_reject_reply`, `poll_descriptor/reject_reply.rs`) fail-closes to the
silent drop it already performs. Because all three reject sources — policy
`then reject`, firewall-filter `then reject`, and zone `tcp-rst` — funnel
through `enqueue_reject_reply` → `build_reject_rst_frame`, the guard covers
every TCP reject leg in one place. A normal unicast trigger is unchanged: the
RST is still generated byte-for-byte as before.
