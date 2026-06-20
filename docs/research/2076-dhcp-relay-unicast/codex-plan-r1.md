# Codex Hostile Plan Review r1 (#2076)

Dispatched via codex-rescue subagent (agentId aee7c077e7bf66315), 2026-06-20.

## Verdict

**PLAN-NEEDS-REVISION**

## Findings (verbatim)

1. **BLOCKER — Raw fd close not idempotent.** Plan §255-257 closes the L2 fd in
   the watcher AND §276-277 in the defer. lldp.go:166-184 uses `closeOnce` for
   raw AF_PACKET fds. Double-closing an int fd can close an unrelated reused fd.
   Fix: `l2Sender.Close()` idempotent via `sync.Once`; both call only that.

2. **BLOCKER — Flat-set config parsing eats `overrides` as an interface.**
   compiler_services.go:1113-1116 stops interface parsing only at `interface` /
   `active-server-group`. `group g interface ge-0/0/0.0 overrides
   always-broadcast` would append `overrides`/`always-broadcast` to Interfaces.
   Fix: add `overrides` to the property-boundary set; parse inline + child shapes.

3. **MAJOR — htype guard dropped in detailed design.** §151-152 says htype==1,
   but §264-266 only requires len(chaddr)==6. dhcpv4 exposes `HWType`
   (dhcpv4.go:61); Ethernet is iana HWTypeEthernet. A non-Ethernet packet with a
   6-byte chaddr could be emitted as Ethernet. Fix: require
   `HWType==HWTypeEthernet && len(chaddr)==6`.

4. **MAJOR (hypothesis) — ciaddr ACK path missing.** Matrix keys only on flag +
   yiaddr; a clear-flag ACK with nonzero ciaddr + zero yiaddr would be broadcast.
   Fix: add a row for `flag0 && yiaddr==0 && ciaddr!=0` → unicast to ciaddr (UDP,
   client already has the IP).

5. **MAJOR — Fallback can't catch malformed-but-sent L2 frames.** Sendto only
   errors on syscall failure; bad checksum/source-IP/header bytes send fine and
   are dropped by the client with no fallback. Fix: narrow the risk claim; make
   frame-construction tests exhaustive.

6. **MAJOR — MTU unspecified.** relay.go:437 reads up to 1500 from the server;
   raw L2 send can't fragment. Fix: check `20+8+len(payload) <= iface.MTU`, else
   deliberately use UDP/broadcast fallback.

7. **MAJOR — Cached MAC/index unsafe across link/HA changes.** Sender holds one
   Index+MAC; after interface recreation or VRRP programRethMAC, raw replies use
   stale ifindex/source MAC. garp.go:27-35 looks up at send time. Fix: refresh on
   send errors / resolve per send.

8. **MAJOR — HA duplicate delivery is NOT an unchanged caveat.** README:73-78:
   VRRP-Backup relays duplicate requests; today the duplicate REPLIES are
   harmlessly lost on ARP failure. Fixing flag-clear delivery makes BOTH fw0 and
   fw1 actually deliver L2 unicasts → racing duplicates. Fix: explicitly
   analyze/test HA duplicate OFFER/ACK or gate relay on VRRP ownership.

9. **MINOR — RA AF_PACKET precedent factually wrong.** pkg/ra uses
   `mdlayher/ndp` (`ndp.Listen`), not AF_PACKET. Remove pkg/ra from the
   AF_PACKET evidence list (LLDP/GARP/VRRP still support the claim).
