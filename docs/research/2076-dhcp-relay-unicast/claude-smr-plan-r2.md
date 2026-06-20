# Claude SMR — Hostile Plan Review r2 (#2076)

**Posture:** hostile. Re-reviewing r2 against my r1 findings AND the
Codex/AGY r1 findings the plan claims to fold, plus hunting for NEW issues the
r2 edits introduced. Verified against source, not prose.

## My r1 findings — resolution check
- **F1 (malformed-frame masks the fallback):** RESOLVED. §7.2 narrows the risk
  claim explicitly ("Sendto-success-but-malformed silently dropped, fallback does
  NOT fire"); §8.2 promotes the live flag0 wire-capture to a PR gate that
  asserts a valid IPv4/UDP checksum on the wire; §9 restates the narrowed worst
  case. This is the correct defense (test coverage, not runtime).
- **F2 (VLAN sub-interface egress ifindex):** RESOLVED. §7.2 states the send uses
  the same netdev index the listener is BINDTODEVICE-bound to, per-send resolved,
  and §12 + §8.2 make the VLAN-tag-on-send a wire-capture confirmation. Acceptable
  — the Linux behavior is documented and the gate confirms it.
- **F3 (mdlayher vs hand-roll):** RESOLVED. §3 + §7.2 mandate the garp.go
  hand-roll; gopacket test-only.
- **F4 (source IP = saved giaddr, not the zeroed field):** RESOLVED. §7.1 + §7.2
  call out that pkt.GatewayIPAddr is zeroed at relay.go:478 and the L2 source IP
  must come from the saved runRelay:271 giaddr. Verified relay.go:478 does clear
  it; relay.go:271 computes the per-interface giaddr.
- **F5 (UDP csum decision):** RESOLVED. Q2 fixed to csum=0 (IPv4-legal) + IPv4
  header checksum computed.
- **F6 (VRRP-backup duplication note):** RESOLVED and ESCALATED — Codex#8 made
  this a full §7.6 with a test-failover gate, stronger than my r1 ask.

## Codex/AGY r1 BLOCKERs — independently verified as correctly folded
- **fd use-after-close (Codex#1/AGY#1):** §7.3 keeps the L2 fd OUT of the cancel
  watcher (it is TX-only, never blocks a read) and closes it via an idempotent
  `sync.Once` `l2Sender.Close()` from a `defer` that runs AFTER `wg.Wait()`.
  VERIFIED CORRECT against relay.go: the server-response goroutine
  (relay.go:322-327) is the only `sendReply` caller and is joined by
  `wg.Wait()` at relay.go:402; the main loop is also joined there. A
  `defer ...Close()` placed after the `wg.Wait()` call therefore runs strictly
  after the last possible `sendReply`. No use-after-close, no double-close.
- **flat-set `overrides` swallow (Codex#2):** §7.4 adds `overrides` to the inline
  property-boundary set. VERIFIED against compiler_services.go:1106-1124: the
  inline loop's ONLY recognized keywords are `interface` and
  `active-server-group`; the `interface` consumer (1113-1114) breaks on exactly
  those two, so without the fix `group g interface X overrides always-broadcast`
  appends `overrides`/`always-broadcast` to Interfaces. Adding `overrides` to
  both the boundary set AND a new `case "overrides"` (inline + children at
  1125-1145) is complete — there are no other group properties to collide with.

## New-issue hunt on the r2 edits

### N1 (MINOR) — ciaddr-via-UDP path: confirm it does not re-introduce an ARP failure.
§7.1's new row `flag0 && yiaddr==0 && ciaddr!=0 -> unicast to ciaddr via the
normal UDP socket`. This is safe ONLY because a client with a nonzero ciaddr is
in BOUND/RENEWING/REBINDING and HAS configured ciaddr, so it answers ARP. That
reasoning is correct and the plan states it. BUT: a relayed REBINDING reply
normally would not even reach the relay (RENEWING is unicast direct to server;
REBINDING is broadcast and CAN be relayed). The row is harmless and more correct
than broadcasting, but the plan should note this path is a low-frequency
correctness nicety, not the core fix — so a reviewer doesn't over-index on it.
Not blocking; the row is correct as written.

### N2 (MINOR) — per-send `InterfaceByName` cost / TOCTOU.
§7.2 resolves interface Index+MAC per send (garp.go precedent). DHCP reply
volume is low (a handful/sec even on a busy segment), so the extra syscall per
reply is negligible — correct tradeoff for staleness-safety. There is a tiny
TOCTOU (interface could change between resolve and Sendto) but the failure mode
is a Sendto error → broadcast fallback, which is safe. Acceptable. The plan could
note "resolve-per-send is fine because reply volume is low"; minor polish.

### N3 (MINOR) — MTU bound header arithmetic.
§7.2 uses `20 + 8 + len(payload) > iface.MTU` (IPv4+UDP+payload vs MTU). That is
the correct L3-vs-MTU comparison (MTU is the L3 payload limit, excludes the
14-byte Ethernet header). The changelog's parenthetical `14+20+8` is the full
frame size and is informational only; the operative check in §7.2 (`20+8+payload
> MTU`) is the right one. Consistent. No action needed beyond noting the two
numbers measure different things (frame vs L3) so the implementer uses the L3 one.

## Verdict

**PLAN-READY.** Every r1 finding from all three reviewers is correctly and
verifiably folded (the two BLOCKERs independently checked against
relay.go/compiler_services.go source). The three new observations (N1-N3) are all
MINOR polish, not gating — the mechanism (option d), the lifecycle handling, the
config plumbing fix, the destination matrix, and the HA/test-failover gate are
sound. The plan is implementation-ready; remaining items are implementer
judgment calls already flagged as such (§12). Recommend proceeding to /engineer.
