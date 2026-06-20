# Claude SMR — Hostile Plan Review r1 (#2076)

**Posture:** hostile. Goal is to fail the plan, not bless it. Verified claims
against source in the worktree, not against the plan's prose.

## Independent verification of the plan's load-bearing claims

- **Bug is real and as described.** relay.go:483-486: flag-clear + real yiaddr →
  `WriteTo(net.UDPAddr{IP: yiaddr, Port: 68})` on the plain udp4 client conn
  (relay.go:108-137, no AF_PACKET). ARP-to-unconfigured-yiaddr → undeliverable.
  CONFIRMED.
- **Relay has chaddr.** dhcpv4 lib field `ClientHWAddr net.HardwareAddr` present
  on the BOOTREPLY; relay logs it at relay.go:471. CONFIRMED.
- **CAP_NET_RAW already held + AF_PACKET template exists.** lldp.go:214-245
  (`unix.Socket(AF_PACKET,SOCK_RAW,...)`, `Sendto` w/ `SockaddrLinklayer`),
  garp.go (hand-rolled L2 frame + checksum), fail-soft open precedent in
  lldp.go:233-238 (socket setup fail → log + skip, not fatal). xpfd.service runs
  as root, no CapabilityBoundingSet. CONFIRMED — the "most code" con of option
  (a) is genuinely reduced by these templates.
- **No DHCPv6 relay exists.** grep for dhcpv6-relay/DHCPRelay6/RELAY-FORW finds
  nothing; only a DHCPv6 local server. The parity claim ("nothing to fix, and v6
  wouldn't have this bug") is CORRECT. CONFIRMED.
- **mdlayher/packet is a dep** (go.mod, indirect). CONFIRMED — but see F3: the
  plan should NOT use it; garp.go's hand-roll is the in-repo norm.
- **#1915 lifecycle invariants are real** (close-on-cancel watcher at
  relay.go:311-317 closes both conns; WaitGroup join at 402). The plan's
  "extend the watcher to close the L2 fd, keep wg.Wait() intact, fail-soft open"
  is the right shape. CONFIRMED.

## Findings

### F1 (MAJOR) — Default-on raw-L2 is a behavior change with a real-world failure surface the plan under-weights.
Today flag1 clients work and flag0 clients fail. The plan makes flag0 take a
**brand-new L2 path by default**. If the hand-rolled frame is subtly wrong
(checksum, length, VLAN-tagged egress interface, bridge/veth quirks in the incus
test env), flag0 goes from "fails via ARP" to "fails via malformed frame" — same
end state, but now with more code to be wrong in. The fallback mitigates this
ONLY if the failure is a *Sendto error*; a frame that `Sendto`-succeeds but is
malformed-on-wire (bad checksum) is silently dropped by the client and the
fallback never fires. **Required:** the test plan MUST include a wire-capture
assertion (tcpdump -e, verify IPv4+UDP checksums validate and the client actually
ACKs) before this is declared correct — not just "Sendto returned nil." The plan
has this in §8 integration but lists it as "manual / not gated"; for a
default-on path-change it should be a hard gate on the implementation PR (live
incus repro of a flag0 client acquiring a lease). Otherwise raise to BLOCKER.

### F2 (MAJOR) — Egress interface for the L2 send is under-specified for VLAN sub-interfaces.
The relay binds the client listener with `SO_BINDTODEVICE` to `ir.ifaceName`,
which may be a VLAN sub-interface (`ge-0/0/0.50` → a `.50` kernel netdev) or an
IRB. An AF_PACKET `SockaddrLinklayer{Ifindex}` send on the **sub-interface's**
ifindex will inject an already-tagged-or-untagged frame depending on kernel
behavior; sending on the **parent** ifindex would skip VLAN tagging entirely.
VRRP hit exactly this (instance.go comments: "AF_PACKET on VLAN sub-interfaces"
is special). The plan says "bound to the relay interface" but does not say
*which* ifindex for a `.N` sub-interface, nor whether the frame must carry an
802.1Q tag. **Required:** the design must state that the L2 send uses the same
netdev `net.InterfaceByName(ir.ifaceName).Index` the listener is bound to, and
must confirm (via the VRRP precedent or a capture) that the kernel applies VLAN
tagging for a sub-interface AF_PACKET send — or explicitly handle the tag. This
is the single most likely place the implementation silently produces an on-wire
frame that never reaches the client.

### F3 (MINOR) — "reuse mdlayher/ethernet+gopacket-free hand-roll" is contradictory; pick the hand-roll.
§7.2 hedges between `mdlayher/ethernet` and a hand-roll. garp.go is hand-rolled
and dependency-free and is the in-repo norm; `gopacket` is NOT a dep (only
`mdlayher/packet` indirect). Pulling in `gopacket` for frame *construction* would
add a direct dep for a 42-byte header. **Resolve:** mandate the garp.go-style
hand-roll for construction; `gopacket` may be used in *tests* only for decode
assertions (it's fine as a test dep if already vendored — verify, else hand-decode).

### F4 (MINOR) — Source-IP selection is named as a guard but not resolved.
§7.2 lists "srcIP (giaddr) valid IPv4" as a guard. giaddr was just *cleared* to
zero at relay.go:478 before forwarding to the client. The L2 frame's IPv4 source
must be the relay's interface address (the original giaddr we computed at
runRelay:271), NOT the now-zeroed pkt.GatewayIPAddr. The plan implicitly uses
"giaddr (our interface IP)" but the code clears pkt.GatewayIPAddr first — the
implementation must carry the interface IP separately into the L2 sender. Call
this out explicitly so the implementer doesn't read a zeroed field. (RFC: the
reply's IP source should be the relay's address on that segment; using yiaddr or
0.0.0.0 as source is wrong.)

### F5 (MINOR) — UDP checksum / Q2 should be decided in the plan, not left open.
UDP checksum=0 IS legal for IPv4 (RFC 768 — a zero checksum means "not computed";
only forbidden for IPv6). So csum=0 is a safe simplification and removes a whole
class of checksum bugs (F1's silent-drop risk). Recommend the plan *commit* to:
compute the IPv4 header checksum (mandatory, kernel/clients will drop a bad one),
and send UDP checksum=0 (legal, simpler, eliminates one bug surface). This
directly de-risks F1. Leaving it "open" invites the implementer to hand-roll a
UDP pseudo-header checksum that F1 warns about.

### F6 (MINOR) — VRRP-backup duplicate-relay interaction is acknowledged but the L2 path may worsen it.
README already notes a relay on a VRRP-Backup node duplicate-relays (DHCP
tolerates it). With broadcast that's benign (clients dedupe). With **unicast L2
to chaddr**, both master and backup may now deliver a *unicast* reply to the same
client — still tolerable (client dedupes on xid), but worth a one-line note that
the L2 change does not regress the existing accepted-interim behavior. Not a
blocker; just don't silently change the duplication characteristics without
saying so.

## Non-findings (hostile checks that PASSED)
- Option (b) rejection is justified: PERMANENT neigh entries for non-owned IPs
  collide with pkg/routing's neighbor resolver + HA, and cleanup is racy. Correct
  to reject.
- Option (c) as the *fallback/override* (not the default) is the right call —
  RFC-permitted, always-works, but broadcasts every reply, so it belongs behind
  a knob + as degradation, exactly as planned.
- Phasing (Phase 1 correctness / Phase 2 config) is sound; Phase 1 alone closes
  the issue.
- Dual-AST config handling (§7.4) correctly cites CLAUDE.md's
  ParseSetCommand+SetPath requirement and the existing inline-keys precedent in
  compileDHCPRelay.

## Verdict

**PLAN-NEEDS-REVISION.** The mechanism choice (option d) is correct and the
recommendation is sound. But two MAJOR gaps must be closed in the plan before it
is implementation-ready: **F1** (default-on path change demands a wire-capture /
live-flag0-lease gate, not just a Sendto-success check) and **F2** (VLAN
sub-interface egress ifindex + tagging is the most likely silent-failure point
and is under-specified). F4 (use the saved interface IP, not the zeroed giaddr)
and F5 (decide UDP csum=0) should be folded in to de-risk. Once the plan states
the egress-ifindex/VLAN behavior, the source-IP handling, the csum decision, and
promotes the live flag0 repro to a PR gate, this is PLAN-READY.
