# Plan: DHCP relay cannot unicast OFFER/ACK to broadcast-flag=0 clients (#2076)

- **Issue:** #2076 (audit, severity MEDIUM)
- **Revision:** r1 (initial draft)
- **Branch:** `research/2076-dhcp-relay-unicast`
- **Status:** DRAFT — awaiting 3-way hostile plan review (Codex + AGY + Claude SMR)
- **Scope:** `pkg/dhcprelay` only (DHCPv4 relay). No dataplane, no HA, no eBPF.

---

## 1. Problem statement

`pkg/dhcprelay/relay.go` relays server replies (OFFER/ACK) back to clients on
an **ordinary `udp4` PacketConn** (`defaultPacketConnFactory`, relay.go:108-137;
client conn opened at relay.go:279-280). When the server reply has the broadcast
flag **clear** and carries a real `YourIPAddr` (yiaddr), `handleServerResponses`
unicasts the datagram to `&net.UDPAddr{IP: pkt.YourIPAddr, Port: 68}`
(relay.go:483-486, `WriteTo` at 490):

```go
if pkt.IsBroadcast() || pkt.YourIPAddr == nil || pkt.YourIPAddr.Equal(net.IPv4zero) {
    dst = &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort}   // broadcast path: OK
} else {
    dst = &net.UDPAddr{IP: pkt.YourIPAddr, Port: clientPort}  // unicast to yiaddr: BROKEN
}
```

A UDP `WriteTo(yiaddr)` makes the kernel attempt to **ARP-resolve yiaddr** on the
client subnet. But a client in `SELECTING`/`REQUESTING` (RFC 2131 §4.3.1, §4.4.1)
has **not yet configured** the leased address — it has no IP bound and will not
answer ARP for yiaddr. The kernel's ARP request goes unanswered, the neighbor
entry stays `INCOMPLETE`, and the OFFER/ACK is silently dropped (or queued then
discarded). **The client never receives the reply and lease acquisition fails.**

### Who is affected
- Clients that **clear** the broadcast flag during initial acquisition,
  expecting a unicast reply to the offered address. RFC 2131 §4.1 explicitly
  permits this; some Linux (`dhclient` without `BOOTP_BROADCAST`), Windows, and
  embedded stacks do it.
- Clients that **set** the broadcast flag are fine (broadcast path at
  relay.go:483-484, `SO_BROADCAST` is set on the client conn).
- In-`RENEWING` unicast (client already has an address) goes **directly** to the
  server, **bypassing the relay** (giaddr=0, unicast to server IP) — not affected.

So the broken case is precisely **initial acquisition by broadcast-flag=0
clients**.

### Why the current code "works" in test
The test env clients all set the broadcast flag (or the kernel happens to have a
stale ARP entry), so the unicast-to-yiaddr path is rarely exercised. The audit
found it by reading source, not by a failing test.

---

## 2. RFC 2131 broadcast-flag semantics (the governing standard)

RFC 2131 §4.1 ("Constructing and sending DHCP messages"), the BROADCAST flag,
and the relay-agent delivery rules in §4.1 paragraph on `giaddr`:

> **If the broadcast bit is set ... the server (or relay) MUST broadcast.**
> If `giaddr` is nonzero, the server sends the reply to the relay at `giaddr`,
> port 67; the **relay** then delivers to the client per the BROADCAST flag and
> yiaddr/chaddr:
> - If `giaddr != 0` → server sends to relay; relay forwards to client.
> - At the relay, if the **BROADCAST flag is set**, forward as broadcast to
>   `255.255.255.255:68`.
> - If the **BROADCAST flag is clear**, the relay **SHOULD unicast** the reply
>   to the client's **hardware address (chaddr)** and **yiaddr**, building the
>   L2 frame directly — because the client cannot yet receive IP-routed traffic
>   to yiaddr (no ARP).

The key standard requirement: a relay that honors a clear broadcast flag **must
not rely on ARP**. It must address the L2 frame to `chaddr` and put yiaddr in the
IP/BOOTP fields. This is the canonical "raw L2 relay" behavior. RFC 2131 also
explicitly notes (§4.1) that an implementation **MAY** always set the broadcast
flag / always broadcast as a simpler alternative, accepting the cost that every
reply is broadcast on the segment.

### What the relay has available (on the reply packet `pkt`)
- `pkt.YourIPAddr` (yiaddr) — the offered/assigned IP. (relay.go:472, 483-486)
- `pkt.ClientHWAddr` (chaddr) — the client MAC, copied verbatim from the request
  into the reply by the server. **Present on every BOOTREPLY.** (dhcpv4 lib field
  `ClientHWAddr net.HardwareAddr`)
- `pkt.Flags` / `pkt.IsBroadcast()` / `pkt.SetBroadcast()` — the broadcast flag.
- `giaddr` — our interface IP (we set it on egress; cleared at relay.go:478
  before forwarding to the client).
- The receiving interface name (`ir.ifaceName`) and its `*net.Interface`
  (Index, HardwareAddr) — resolvable for the L2 send.

So the relay has **everything** needed to build an L2 frame to `chaddr` + yiaddr:
this is the determining fact for option viability.

---

## 3. Privilege / capability posture (determining fact for option a)

- `xpfd` runs as **root** under systemd (`test/incus/xpfd.service`: no `User=`,
  no `CapabilityBoundingSet`, no `NoNewPrivileges`; `LimitMEMLOCK=infinity`).
- **AF_PACKET (CAP_NET_RAW) is already used pervasively** in-repo:
  - `pkg/vrrp/instance.go` — `AF_PACKET`/`SOCK_RAW` VRRP RX/TX.
  - `pkg/lldp/lldp.go:214-245` — `unix.Socket(AF_PACKET, SOCK_RAW, htons(...))`,
    `Bind`/`Sendto` with `SockaddrLinklayer{Protocol, Ifindex}`.
  - `pkg/cluster/garp.go` — builds full L2 frames + ICMPv6 checksum, sends via
    AF_PACKET (GARP / unsolicited NA).
  - `pkg/ra/` — RA sender via raw socket.
- `mdlayher/packet v1.1.2` is already a (transitive) dependency in `go.mod`.

**Conclusion:** opening an AF_PACKET socket and crafting an L2 frame is an
**established, root-available pattern** in this daemon. There is no new privilege
requirement, no systemd-unit capability change, and a working in-repo template
(`pkg/lldp`, `pkg/cluster/garp.go`) to copy for frame construction + checksum.

---

## 4. IPv6 / DHCPv6 relay parity (determining fact for scope)

- There is **no DHCPv6 relay agent** in the codebase. `grep` for
  `dhcpv6-relay` / `DHCPRelay6` / RFC 6221/8415 RELAY-FORW finds nothing.
  `pkg/dhcprelay` is **DHCPv4-only**; the DHCPv6 references in `pkg/cli` are the
  DHCPv6 **local server** + client, not a relay.
- **DHCPv6 does not have this bug class at all.** DHCPv6 (RFC 8415) has no
  BOOTP broadcast flag; clients use a **link-local source address** and the
  relay replies to that link-local unicast (or `ff02::1:2`). There is no
  "reply to an unconfigured global address via ARP/ND" failure mode.
- **Scope decision:** this fix is **strictly DHCPv4**. No DHCPv6 work is in
  scope; the "parity" answer is "DHCPv6 relay does not exist and would not have
  this problem if it did." A one-line note in the README records this so a
  future DHCPv6 relay author does not re-litigate it.

---

## 5. Multiple Path Options (the design decision)

### Option (a) — Raw AF_PACKET L2 socket to chaddr + yiaddr  [RFC-correct]
Open an `AF_PACKET`/`SOCK_RAW` TX socket bound to the relay interface. For a
broadcast-flag=0 reply, build a full Ethernet+IPv4+UDP frame:
- **Ethernet dst** = `pkt.ClientHWAddr` (chaddr), **src** = interface MAC,
  ethertype `0x0800`.
- **IPv4 dst** = `yiaddr`, **src** = giaddr (our interface IP); proto 17.
- **UDP** dst 68 / src 67; payload = the BOOTP reply bytes (`pkt.ToBytes()`).
- Compute IPv4 header checksum + (optional but correct) UDP checksum, `Sendto`
  the frame on the AF_PACKET fd via `SockaddrLinklayer{Ifindex}`.

**Pros:** the canonical, RFC-correct relay behavior; honors the client's flag
exactly (unicast stays unicast — no segment-wide broadcast storm); identical to
ISC dhcrelay / Junos default. Reuses the existing `pkg/lldp` + `pkg/cluster/garp`
frame-build pattern. No ARP dependency.

**Cons:** most code (build + checksum L2/L3/L4 headers; new AF_PACKET fd
lifecycle alongside the existing UDP conns; new tests for frame construction).
Requires CAP_NET_RAW (already held). Must handle chaddr length / non-Ethernet
htype defensively (only build L2 for `htype==1`/6-byte MAC; otherwise fall back).

### Option (b) — Inject a temporary static ARP entry, then unicast via UDP
Before the UDP `WriteTo(yiaddr)`, push a static neighbor entry
`(yiaddr → chaddr, PERMANENT)` via netlink `RTM_NEWNEIGH` on the relay
interface, then unicast normally; remove/expire it afterward.

**Pros:** keeps the existing UDP send path; smaller frame-building surface.

**Cons:** **pollutes the kernel neighbor table** with entries for addresses the
host does not own; race/cleanup complexity (when to delete — the client may not
ACK; multiple in-flight clients; entry churn); a stale PERMANENT entry can
**break** later legitimate traffic to that IP; interacts badly with the
firewall's own neighbor-resolver subsystem and HA. Junos/ISC do **not** do this.
Considered an anti-pattern. **Rejected.**

### Option (c) — Always broadcast / always set the broadcast flag  [simplest fallback]
Drop the unicast branch: always send replies to `255.255.255.255:68` (the
`SO_BROADCAST` path that already works), optionally also `SetBroadcast()` on the
packet so downstream is consistent.

**Pros:** trivial (delete the else-branch), no new sockets, no capability
concerns, RFC-**permitted** (§4.1 MAY always-broadcast). Immediately fixes the
broken acquisition for flag=0 clients.

**Cons:** every reply is broadcast on the client segment — extra broadcast
traffic, every client NIC wakes for every other client's OFFER/ACK. On a busy
access segment this is real but bounded (DHCP reply volume is low). Does **not**
honor the client's stated preference; a security-conscious client that cleared
the flag to avoid broadcast still gets broadcast. It is the ISC `dhcrelay`
behavior **only** when explicitly forced; Junos exposes it as the explicit
`overrides always-broadcast` knob (opt-in), not the default.

### Option (d) — Hybrid: honor the flag, raw-L2 for flag=0, broadcast for flag=1, + an `overrides always-broadcast` config knob  [RECOMMENDED]
Default behavior = RFC-correct option (a) for the flag=0 unicast case + existing
broadcast for flag=1. Add an opt-in Junos-style config override
`forwarding-options dhcp-relay group <g> overrides always-broadcast;` that, when
set, forces the option-(c) always-broadcast behavior (operator escape hatch for
environments where the L2 path is undesirable or for diagnostic parity).

**Pros:** RFC-correct by default; matches Junos surface exactly (operators
already know `overrides always-broadcast`); gives an escape hatch without making
broadcast the default; the broadcast fallback is also the **graceful degradation
path** if AF_PACKET open fails (no CAP_NET_RAW in some future hardened unit) or
if `htype`/chaddr is unusable.

**Cons:** largest surface (option a's frame-building **plus** a config leaf
through the parser/compiler/schema/`DHCPRelayGroup` struct). But the config piece
is small and mechanical (one bool, mirroring existing `group` properties).

---

## 6. Recommendation

**Adopt Option (d): RFC-correct raw-L2 unicast by default + an opt-in
`overrides always-broadcast` knob, with broadcast as the automatic fallback when
the L2 path is unavailable.**

Rationale:
1. **Correctness:** option (a)'s raw-L2-to-chaddr is the only path that is RFC
   2131-correct AND does not broadcast every reply. It is what ISC dhcrelay and
   Junos do by default.
2. **No new privilege/dependency cost:** CAP_NET_RAW is already held; AF_PACKET
   frame-building is already done four places in this repo (`lldp`, `garp`,
   `ra`, `vrrp`) — there is a proven template, so the "most code" con of option
   (a) is materially reduced.
3. **Operator familiarity + safety valve:** the `overrides always-broadcast`
   knob is the exact Junos surface; it gives operators the option-(c) behavior
   on demand and doubles as the automatic degradation path (if AF_PACKET open
   fails or chaddr is non-Ethernet, fall back to broadcast and log once). This
   means the relay **never regresses to "undeliverable"** — worst case it
   broadcasts, which always works.
4. **Option (b) is rejected** outright (kernel neighbor-table pollution,
   cleanup races, conflicts with the firewall's neighbor resolver + HA).

### Phasing (so a smaller increment can ship first if review prefers)
- **Phase 1 (core fix, mandatory):** raw-L2 unicast path for flag=0 +
  automatic broadcast fallback on any L2 failure. This alone closes #2076.
- **Phase 2 (config knob):** `overrides always-broadcast` leaf
  (struct + compiler + schema + plumb to `Apply`). Pure opt-in; additive.

Phase 1 is the load-bearing correctness fix; Phase 2 is the Junos-parity polish.
Review may choose to ship Phase 1 alone and file Phase 2 as a follow-up, or ship
both together. **Default recommendation: ship both in one PR** (the config piece
is small and the README/parity story is cleaner as a unit).

---

## 7. Detailed design (Phase 1 + Phase 2)

### 7.1 Reply destination decision (relay.go `handleServerResponses`)
Replace the dst-selection block (relay.go:480-496) with:

```
flag1 (broadcast set) OR yiaddr unset/zero  -> broadcast (existing path)
flag0 (broadcast clear) AND yiaddr is real  -> raw-L2 unicast to chaddr+yiaddr
    on failure (no AF_PACKET fd / open error / chaddr unusable / Sendto error)
        -> fall back to broadcast + log-once
group has overrides.always-broadcast        -> broadcast (skip L2 entirely)
```

### 7.2 Raw-L2 sender (new file, e.g. `pkg/dhcprelay/l2send_linux.go`)
- A small `l2Sender` holding the AF_PACKET TX fd + interface Index + MAC,
  opened once per interface in `runRelay` (alongside the two UDP conns), closed
  by the same close-on-cancel watcher (extend the watcher to close the L2 fd
  too — keep the wg.Wait() liveness contract from #1915 intact).
- `func (s *l2Sender) sendReply(dstMAC net.HardwareAddr, srcIP, dstIP net.IP, payload []byte) error`
  builds Ethernet(0x0800)+IPv4(proto17, hdr csum)+UDP(67→68, csum)+payload and
  `unix.Sendto` on `SockaddrLinklayer{Ifindex}`. Mirror `pkg/cluster/garp.go`'s
  checksum helper style (or reuse `mdlayher/ethernet`+`gopacket`-free hand-roll;
  the garp.go pattern is hand-rolled and dependency-free — prefer that for
  consistency).
- **Guards:** only attempt L2 when `len(chaddr)==6` (Ethernet); `srcIP`
  (giaddr) and `dstIP` (yiaddr) are valid IPv4; interface MAC resolvable.
  Otherwise return an error → caller broadcasts.
- **CAP_NET_RAW absence:** `unix.Socket` returns `EPERM` → `l2Sender` open
  fails in `runRelay`; record `l2Sender == nil`; every flag0 reply then takes
  the broadcast fallback (logged once at WARN). Relay still functions.

### 7.3 Lifecycle integration (#1915 invariants are load-bearing)
- The L2 fd is opened **after** both UDP conns succeed and **before** the cancel
  watcher starts; the watcher closes all three fds; the L2 fd open is allowed to
  **fail soft** (nil sender, not a relay-fatal error) so a hardened/no-CAP_NET_RAW
  deployment still relays via broadcast.
- No change to the WaitGroup join structure — the L2 fd is not a goroutine, just
  an extra `Close()` in the existing watcher and the existing `defer`.

### 7.4 Config plumbing (Phase 2)
- `DHCPRelayGroup` gains `AlwaysBroadcast bool` (types_system.go:555-559).
- `compileDHCPRelay` (compiler_services.go:943-992) parses
  `overrides { always-broadcast; }` (block form) **and** the flat-set inline
  spelling `group <g> overrides always-broadcast` (dual-AST per the existing
  inline-keys handling at compiler_services.go:951-970). **Test both shapes via
  `ParseSetCommand()` + `tree.SetPath()`** per CLAUDE.md (never `NewParser()`
  for flat-set).
- Schema (schema_routing.go:282-285): add under `group`:
  `"overrides": {desc:"Relay overrides", children: {"always-broadcast": {desc:"Always broadcast replies"}}}`.
- `Apply`/`interfaceRelay`/`runRelay`/`handleServerResponses` thread the per-group
  `AlwaysBroadcast` bool down to the dst decision (store on `interfaceRelay`).

### 7.5 Counters / observability
- Add `repliesBroadcastFallback atomic.Uint64` (or a labeled counter) so the
  fallback-because-L2-failed case is visible in `show ... dhcp-relay` and/or
  Prometheus. Distinguish "broadcast because flag1" from "broadcast because L2
  failed" so operators can detect a CAP_NET_RAW/driver problem.

---

## 8. Test plan

Unit (no root, table-driven; `pkg/dhcprelay/relay_test.go` + a new
`l2send_test.go`):
1. **dst decision matrix:** flag1→broadcast; flag0+real-yiaddr→L2; flag0+zero
   yiaddr→broadcast; `AlwaysBroadcast`→broadcast even with flag0+yiaddr.
2. **L2 frame construction:** given chaddr/srcIP/dstIP/payload, assert the
   serialized Ethernet/IPv4/UDP header bytes + checksums (parse back with
   `gopacket` or hand-decode; assert IPv4 csum and UDP csum verify). chaddr
   non-6-byte → error (caller broadcasts).
3. **Fallback:** inject an `l2Sender` whose `sendReply` returns an error → assert
   the reply is re-sent via the broadcast conn and the fallback counter
   increments. `l2Sender == nil` (open failed) → broadcast path taken.
4. **Lifecycle (#1915 regression):** the L2 fd is closed on cancel; `Stop()`
   still joins deterministically; an L2-open failure does **not** make
   `runRelay` return early (relay stays up on broadcast).
5. **Config dual-AST:** `overrides always-broadcast` parses to
   `AlwaysBroadcast=true` from **both** block form and flat-set
   (`ParseSetCommand`+`SetPath`); absence → false.
6. **Schema completion:** `set forwarding-options dhcp-relay group g overrides ?`
   offers `always-broadcast`.

Integration (manual / incus, documented, not gated):
- A client configured to **clear** the broadcast flag (e.g.
  `dhclient -B`-off / a crafted DISCOVER with flags=0) on a relayed segment
  acquires a lease end-to-end. Capture with `tcpdump -e` on the client segment
  and confirm the OFFER/ACK is a **unicast L2 frame to the client MAC**
  (not a broadcast, not an ARP-stuck drop). This is the real-world proof the
  audit's failure mode is closed.

No `make test-failover` requirement (no cluster/VRRP/session-sync/failover code
touched) — but note the README's existing "VRRP-Backup duplicate relay" caveat
is unchanged by this work.

## 9. Risk / blast radius
- **Surface:** `pkg/dhcprelay` (relay.go dst block + new l2send file) + 4 small
  config touch points (types_system, compiler_services, schema_routing, README).
  No dataplane, no HA, no eBPF, no proto.
- **Worst case if L2 path is wrong:** a malformed frame is dropped by the client
  — but the broadcast fallback + (for flag1) existing broadcast path are
  unaffected, so a bug in the new path degrades to "no worse than today for
  flag0, still-working for flag1." With the fallback wired, even a total L2
  failure degrades to **broadcast (which always works)** — strictly better than
  the current undeliverable unicast.
- **Regression guard:** #1915 socket-lifecycle invariants (close-on-cancel
  watcher, WaitGroup join, fail-soft L2 open) are explicitly preserved and
  re-tested.

## 10. Documentation updates
- `pkg/dhcprelay/README.md`: document the reply-delivery model (flag1→broadcast,
  flag0→raw-L2-to-chaddr, fallback→broadcast), the `overrides always-broadcast`
  knob, the CAP_NET_RAW dependency (already held by the root daemon), and the
  **DHCPv6-relay-does-not-exist / would-not-have-this-bug** parity note.
- `docs/config-schema.md` (if it enumerates leaves): add the `overrides
  always-broadcast` leaf.

## 11. Open questions for reviewers
- **Q1.** Ship Phase 1 + Phase 2 together, or Phase 1 alone (file Phase 2)?
  (Recommendation: together — config piece is small.)
- **Q2.** UDP checksum: compute it (correct, ISC does) or send UDP csum=0
  (legal for IPv4, simpler)? Recommendation: compute it for correctness, but
  csum=0 is an acceptable simplification if it reduces risk.
- **Q3.** Should `always-broadcast` alone also `SetBroadcast()` on the wire so a
  downstream sniffer sees a consistent flag, or just choose the broadcast dst?
  (Junos forces broadcast delivery; the flag itself is cosmetic at the last hop.)
- **Q4.** Counter granularity: a single `repliesBroadcastFallback` vs. a labeled
  metric distinguishing flag1-broadcast / forced-always-broadcast / L2-fail
  fallback. (Recommendation: at least distinguish L2-fail so a CAP_NET_RAW/driver
  regression is observable.)
