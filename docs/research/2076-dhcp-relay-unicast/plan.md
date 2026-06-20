# Plan: DHCP relay cannot unicast OFFER/ACK to broadcast-flag=0 clients (#2076)

- **Issue:** #2076 (audit, severity MEDIUM)
- **Revision:** r2 (folds r1 review: Codex 2 BLOCKER/6 MAJOR/1 MINOR, AGY
  1 BLOCKER/5 MAJOR/1 MINOR, Claude SMR 2 MAJOR/4 MINOR — all three
  PLAN-NEEDS-REVISION, none PLAN-KILL; mechanism choice option (d) endorsed by
  all three)
- **Branch:** `research/2076-dhcp-relay-unicast`
- **Status:** revised — awaiting 3-way re-review (Codex + AGY + Claude SMR)
- **Scope:** `pkg/dhcprelay` (DHCPv4 relay) + 4 small `pkg/config` touch points.
  No dataplane, no eBPF, no proto. **Touches HA-relevant behavior** (see §7.6 —
  L2 delivery changes the VRRP-backup duplicate-relay characteristics, so a
  failover-aware test/gate is now in scope).

## Changelog r1 → r2 (review folds)
- **[BLOCKER, Codex#1 / AGY#1]** L2 fd is NOT closed in the cancel watcher. It is
  TX-only (never blocks a read), so it is closed with an **idempotent
  `l2Sender.Close()` (`sync.Once`)** called from a single `defer` that runs
  **after `wg.Wait()`** returns (all writers joined). Mirrors lldp.go
  `closeOnce`. See §7.3.
- **[BLOCKER, Codex#2]** Flat-set `overrides` would be swallowed into
  `Interfaces` (compiler_services.go:1113-1114 stops only at `interface` /
  `active-server-group`). Fix: add `overrides` to the property-boundary set +
  parse both inline-Keys and Children shapes. See §7.4.
- **[MAJOR, Codex#4 / AGY#5 / SMR]** Added the **ciaddr** destination row:
  `flag0 && yiaddr==0 && ciaddr!=0` → unicast to **ciaddr over the normal UDP
  socket** (client already has the IP; answers ARP). See §7.1.
- **[MAJOR, Codex#3]** htype guard restored to the detailed design: require
  `pkt.HWType == iana.HWTypeEthernet` **and** `len(chaddr)==6`. See §7.2.
- **[MAJOR, Codex#5 / AGY#2 / SMR-F1]** Malformed-but-sent frames `Sendto`-succeed
  and are silently dropped → fallback does NOT fire. Risk claim narrowed;
  exhaustive per-byte frame tests + a **live flag0-lease wire-capture gate** are
  mandatory (promoted from "manual" to a PR gate). UDP **checksum=0** chosen
  (legal IPv4, drops a bug class). See §7.2, §8.
- **[MAJOR, Codex#6 / AGY#4]** MTU: raw L2 can't fragment. If
  `14+20+8+len(payload) > iface.MTU` (L3 `20+8+payload > MTU`), deliberately use
  the UDP/broadcast fallback so the kernel fragments. See §7.2.
- **[MAJOR, Codex#7 / AGY#3 / SMR-F2]** Cached ifindex/MAC go stale on link flap
  / dynamic recreate / VRRP `programRethMAC`. Resolve interface attrs (index +
  MAC) **per send** (garp.go:27-35 precedent) — or reopen on interface-related
  Sendto errors. Source IP = the **saved interface giaddr** (the
  `pkt.GatewayIPAddr` field is zeroed at relay.go:478 before forwarding —
  must NOT read it). VLAN sub-interface egress uses the same netdev index the
  listener is bound to. See §7.2, §7.3.
- **[MAJOR, Codex#8]** HA duplicate delivery is NOT unchanged: today a backup's
  duplicate reply is lost on ARP failure; after the fix BOTH nodes deliver L2
  unicasts. Added §7.6 analysis + a `make test-failover` gate.
- **[MINOR, Codex#9]** Removed the factually-wrong `pkg/ra` AF_PACKET precedent
  (pkg/ra uses `mdlayher/ndp`, not AF_PACKET). LLDP/GARP/VRRP remain.
- **[MINOR, AGY#7]** Fixed schema citation: dhcp-relay is at
  schema_routing.go:**373-382**, not 282-285.
- **[MINOR, SMR-F3]** Mandate the garp.go-style dependency-free hand-roll for
  frame construction; `gopacket` only in tests (verify it's vendored, else
  hand-decode).

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
    `Bind`/`Sendto` with `SockaddrLinklayer{Protocol, Ifindex}`; fail-soft open
    (lldp.go:233-238: setup failure logs + skips, not fatal) and idempotent
    `closeOnce` (lldp.go:166-184) are the patterns to copy.
  - `pkg/cluster/garp.go` — builds full L2 frames + checksum, **resolves the
    interface MAC/index at send time** (garp.go:27-35), sends via AF_PACKET
    (GARP / unsolicited NA).
  - (`pkg/ra/` does NOT use AF_PACKET — it uses `mdlayher/ndp`; removed from this
    list per Codex#9. LLDP/GARP/VRRP still establish the precedent.)
- `mdlayher/packet v1.1.2` is already a (transitive) dependency in `go.mod`, but
  frame **construction** uses the garp.go-style hand-roll (dependency-free,
  in-repo norm). `gopacket` is not a dep; if used at all it is test-only.

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
Replace the dst-selection block (relay.go:480-496) with the **full** matrix
below. Note `pkt.GatewayIPAddr` was just zeroed at relay.go:478 — the L2 source
IP MUST come from the **saved interface giaddr** computed at runRelay:271, never
from the now-zeroed packet field (SMR-F4).

```
overrides.always-broadcast set              -> broadcast (skip L2 entirely)
flag1 (broadcast set)                       -> broadcast (existing path)
flag0 AND yiaddr is real                    -> raw-L2 unicast to chaddr + yiaddr
                                               (src IP = saved interface giaddr)
flag0 AND yiaddr==0 AND ciaddr!=0           -> UNICAST to ciaddr via the normal
                                               UDP socket (client already has the
                                               IP and answers ARP — DHCPINFORM /
                                               REBINDING ACK) [Codex#4/AGY#5]
flag0 AND yiaddr==0 AND ciaddr==0           -> broadcast (nothing routable)
L2 path fails (see §7.2 fail conditions)    -> broadcast fallback + log-once +
                                               increment l2-fallback counter
```

Decision precedence: `overrides.always-broadcast` is checked first (operator
override wins). `ciaddr` is `pkt.ClientIPAddr` (dhcpv4 lib field, confirmed at
dhcpv4.go:66). This matrix is the unit-test oracle in §8.1.

### 7.2 Raw-L2 sender (new file, e.g. `pkg/dhcprelay/l2send_linux.go`)
- A small `l2Sender` holding the AF_PACKET TX fd + the interface **name** (for
  per-send attribute re-resolution). `func newL2Sender(ifaceName string)
  (*l2Sender, error)` opens `unix.Socket(AF_PACKET, SOCK_RAW, ...)` and binds to
  the interface (lldp.go:214-245 template). Open is **fail-soft** — `EPERM`
  (no CAP_NET_RAW) or any error → return err; the caller records
  `l2Sender == nil` and every flag0 reply takes the broadcast fallback.
- `func (s *l2Sender) sendReply(dstMAC, srcMAC net.HardwareAddr, srcIP, dstIP net.IP, payload []byte) error`
  hand-rolls Ethernet(0x0800)+IPv4(proto17, **header checksum computed**)+
  UDP(67→68, **checksum=0**)+payload and `unix.Sendto` on
  `SockaddrLinklayer{Ifindex}`. **UDP csum=0 is legal for IPv4 (RFC 768)** and
  removes a whole hand-rolled-pseudo-header bug class [Codex#5/AGY#2/SMR-F5/Q2].
  Frame construction follows the dependency-free garp.go hand-roll; `gopacket`
  is test-only if used at all [SMR-F3].
- **Per-send interface re-resolution [Codex#7/AGY#3/SMR-F2]:** resolve the
  current `net.InterfaceByName(ifaceName)` → Index + HardwareAddr at send time
  (garp.go:27-35 precedent), so a link flap / dynamic recreate / VRRP
  `programRethMAC` MAC change does not leave a stale ifindex/source-MAC. The
  same netdev index the listener is `SO_BINDTODEVICE`-bound to is used (covers
  VLAN sub-interfaces; the kernel applies the sub-interface's VLAN tag on an
  AF_PACKET send to the `.N` netdev — confirm by capture, VRRP precedent
  comment).
- **Guards (return error → caller broadcasts):**
  - `pkt.HWType == iana.HWTypeEthernet` **and** `len(chaddr)==6` [Codex#3].
  - `srcIP` (saved giaddr) and `dstIP` (yiaddr) are valid IPv4.
  - interface resolvable + MAC present.
  - **MTU [Codex#6/AGY#4]:** if `20 + 8 + len(payload) > iface.MTU` (L3 size > MTU
    — the raw path cannot fragment), return error so the caller broadcasts /
    UDP-falls-back and the kernel fragments. (DHCP replies are normally well
    under 1500, but long classless-static-route / vendor option sets can exceed
    it.)
- **Malformed-but-sent risk [Codex#5/AGY#2/SMR-F1]:** `Sendto` only errors on a
  syscall failure; a frame with a bad IPv4 checksum / wrong bytes
  `Sendto`-succeeds and is silently dropped by the client, so the fallback does
  NOT fire. The risk claim in §9 is narrowed accordingly, and §8 mandates
  exhaustive per-byte construction tests + a **live flag0-lease wire-capture
  gate**.

### 7.3 Lifecycle integration (#1915 invariants are load-bearing)
- The L2 fd is opened **after** both UDP conns succeed and **before** the cancel
  watcher starts; open is **fail-soft** (nil sender, not relay-fatal).
- **The L2 fd is NOT closed in the cancel watcher [Codex#1/AGY#1 BLOCKER].** It
  is TX-only and never blocks a read, so it does not participate in the
  unblock-on-cancel contract. It is closed by a single **idempotent
  `l2Sender.Close()` (`sync.Once`, lldp.go:166-184 `closeOnce` precedent)**
  invoked from a `defer` that runs **after `wg.Wait()`** returns — i.e. after
  both the main loop and the server-response goroutine (the only `sendReply`
  callers) have joined. This eliminates the fd-reuse use-after-close race AGY/
  Codex flagged. The watcher continues to close ONLY the two UDP conns
  (unchanged from #1915).
- No change to the WaitGroup join structure — the L2 fd is not a goroutine.

### 7.4 Config plumbing (Phase 2)
- `DHCPRelayGroup` gains `AlwaysBroadcast bool` (types_system.go:555-559).
- `compileDHCPRelay` (compiler_services.go:919-996) parses
  `overrides { always-broadcast; }` (block form) **and** the flat-set inline
  spelling `group <g> overrides always-broadcast`. **[Codex#2 BLOCKER]** The
  inline `interface` consumer at compiler_services.go:1113-1114 currently stops
  only at `interface` / `active-server-group`; `overrides` MUST be added to that
  boundary set or it (and `always-broadcast`) get swallowed into `Interfaces`.
  Parse `overrides` from BOTH the inline `Keys` loop and the `Children` loop
  (`prop.FindChild("always-broadcast")` and `prop.Keys`) [AGY#6]. **Test both
  shapes via `ParseSetCommand()` + `tree.SetPath()`** per CLAUDE.md (never
  `NewParser()` for flat-set) and add a `dual_ast_differential_test.go` case.
- Schema (**schema_routing.go:373-382** [AGY#7]): add under `group`:
  `"overrides": {desc:"Relay overrides", children: {"always-broadcast": {desc:"Always broadcast replies"}}}`.
- `Apply`/`interfaceRelay`/`runRelay`/`handleServerResponses` thread the per-group
  `AlwaysBroadcast` bool down to the dst decision (store on `interfaceRelay`).

### 7.5 Counters / observability
- Distinguish broadcast reasons so a CAP_NET_RAW/driver/MTU regression is
  observable: `repliesBroadcastFlag1` (client asked), `repliesBroadcastForced`
  (overrides), `repliesL2Unicast` (success), `repliesBroadcastL2Fallback`
  (L2 failed — the one to alert on). Surface in `show ... dhcp-relay` /
  Prometheus [Q4 resolved → labeled].

### 7.6 HA / VRRP-backup duplicate delivery [Codex#8]
Today, the README (lines 73-78) notes a relay on a VRRP **Backup** node also
receives segment broadcasts and relays duplicate REQUESTs; the duplicate REPLY
to a flag0 client is **harmlessly lost on ARP failure** (the bug this issue
fixes). After this fix, a Backup node's L2 unicast to chaddr **actually
delivers**, so a flag0 client may now receive duplicate OFFER/ACK from both
nodes. DHCP clients dedupe on xid + chaddr, so this is tolerable, BUT it is a
**behavior change**, not "unchanged." Decision for the plan:
- **Acceptable interim (recommended):** rely on client xid dedupe, document the
  change in the README, and **gate the implementation PR on `make
  test-failover`** to prove no failover regression (the issue touches HA-adjacent
  behavior — CLAUDE.md requires test-failover for cluster/VRRP-adjacent changes).
- **Optional hardening (follow-up, not required for #2076):** suppress relay
  forwarding on a VRRP-Backup node (gate `Apply`/forwarding on VRRP ownership).
  This is the same deferred follow-up the README already names; this issue makes
  it slightly more salient but does not require it.

---

## 8. Test plan

### 8.1 Unit (no root, table-driven; `pkg/dhcprelay/relay_test.go` + new `l2send_test.go`)
1. **dst decision matrix (the §7.1 oracle):** every row — overrides→broadcast;
   flag1→broadcast; flag0+real-yiaddr→L2; flag0+yiaddr0+ciaddr!=0→UDP-unicast to
   ciaddr; flag0+yiaddr0+ciaddr0→broadcast; L2-fail→broadcast fallback.
2. **L2 frame construction (exhaustive per-byte) [Codex#5/AGY#2/SMR-F1]:** for
   given chaddr/srcMAC/srcIP/dstIP/payload, assert EVERY byte of the
   Ethernet/IPv4/UDP headers; assert the **IPv4 header checksum validates** and
   UDP checksum field == 0. Decode-back with a parser or hand-decode.
3. **Guards:** non-Ethernet htype → error; chaddr != 6 bytes → error;
   `20+8+len(payload) > MTU` → error (caller broadcasts); invalid src/dst IP →
   error. Each guard path increments the correct counter.
4. **Fallback:** an `l2Sender` whose `sendReply` returns error → reply re-sent on
   the broadcast conn + `repliesBroadcastL2Fallback` increments. `l2Sender == nil`
   (open failed) → broadcast path taken, relay stays up.
5. **Lifecycle (#1915 regression) [Codex#1/AGY#1]:** `l2Sender.Close()` is
   idempotent (double-call no-op via `sync.Once`); it is invoked only AFTER
   `wg.Wait()`; `Stop()` still joins deterministically; an L2-open failure does
   NOT make `runRelay` return early.
6. **Config dual-AST [Codex#2/AGY#6]:** `overrides always-broadcast` →
   `AlwaysBroadcast=true` from BOTH block form and flat-set
   (`ParseSetCommand`+`SetPath`); critically, `group g interface ge-0/0/0.0
   overrides always-broadcast` must NOT put `overrides`/`always-broadcast` in
   `Interfaces` (the swallow regression). Absence → false.
7. **Schema completion:** `set forwarding-options dhcp-relay group g overrides ?`
   offers `always-broadcast`.

### 8.2 Integration (live incus — PROMOTED TO A PR GATE [SMR-F1/AGY#2/Codex#5])
- A client that **clears** the broadcast flag (crafted DISCOVER with flags=0, or
  a client stack that does so) on a relayed segment acquires a lease end-to-end.
  `tcpdump -e` on the client segment MUST show the OFFER/ACK as a **unicast L2
  frame to the client MAC with a valid IPv4/UDP checksum** (not broadcast, not an
  ARP-stuck drop). A `Sendto`-success-but-malformed frame would FAIL this gate
  even though unit "fallback" tests pass — which is exactly why it is a gate, not
  manual.
- **`make test-failover` is a gate [Codex#8]:** prove the L2-delivery change does
  not regress failover and characterize HA duplicate OFFER/ACK behavior.

## 9. Risk / blast radius
- **Surface:** `pkg/dhcprelay` (relay.go dst block + new l2send file) + 4 small
  config touch points (types_system, compiler_services, schema_routing, README).
  No dataplane, no eBPF, no proto. **HA-adjacent** (§7.6) — `make test-failover`
  gated.
- **Worst case — the narrowed claim [Codex#5/AGY#2/SMR-F1]:** a `Sendto`-FAILURE
  degrades to broadcast (always works — strictly better than today). But a
  **`Sendto`-SUCCESS-but-malformed** frame (bad IPv4 checksum, wrong bytes) is
  silently dropped by the client and the fallback does NOT fire — that case is
  "no worse than today for flag0" but is NOT auto-recovered. This is why §8
  mandates exhaustive per-byte construction tests + the live wire-capture gate:
  the only defense against a silently-malformed frame is test coverage, not the
  runtime fallback.
- **Default-on behavior change:** flag0 replies move from the UDP path to a new
  L2 path by default. The `overrides always-broadcast` knob is the operator
  escape hatch; the automatic broadcast fallback covers `Sendto`-failure,
  no-CAP_NET_RAW, non-Ethernet htype, and over-MTU.
- **Regression guard:** #1915 socket-lifecycle invariants are preserved — the L2
  fd is explicitly kept OUT of the cancel watcher and closed idempotently after
  `wg.Wait()` (§7.3), and re-tested.

## 10. Documentation updates
- `pkg/dhcprelay/README.md`: document the reply-delivery model (flag1→broadcast,
  flag0→raw-L2-to-chaddr, fallback→broadcast), the `overrides always-broadcast`
  knob, the CAP_NET_RAW dependency (already held by the root daemon), and the
  **DHCPv6-relay-does-not-exist / would-not-have-this-bug** parity note.
- `docs/config-schema.md` (if it enumerates leaves): add the `overrides
  always-broadcast` leaf.

## 11. Open questions — resolved in r2
- **Q1 (ship phasing) — RESOLVED:** ship Phase 1 + Phase 2 together; the config
  piece is small and the README/parity story is cleaner as a unit.
- **Q2 (UDP checksum) — RESOLVED:** send UDP **checksum=0** (legal for IPv4 per
  RFC 768), compute the IPv4 **header** checksum (mandatory). Eliminates the
  hand-rolled pseudo-header checksum bug class that the malformed-frame risk
  (§7.2) warns about.
- **Q3 (SetBroadcast on the wire) — RESOLVED:** for the always-broadcast / fallback
  path, just choose the broadcast **destination**; do not mutate `pkt.Flags`. The
  flag is cosmetic at the last hop and mutating it would change the wire bytes
  the server set. (No reviewer objected.)
- **Q4 (counter granularity) — RESOLVED:** labeled counters per §7.5
  (`repliesBroadcastFlag1`, `repliesBroadcastForced`, `repliesL2Unicast`,
  `repliesBroadcastL2Fallback`) so an L2/CAP_NET_RAW/driver/MTU regression is
  observable in operations.

## 12. Remaining decision for the implementer (not a blocker)
- **VLAN-tag-on-AF_PACKET-send:** the design assumes the kernel applies the
  sub-interface's 802.1Q tag when `Sendto` targets the `.N` netdev index. This
  is the documented Linux behavior and matches the VRRP precedent, but the live
  wire-capture gate (§8.2) on a VLAN-tagged relay segment is the confirmation.
  If a future relay segment is a raw trunk where the relay must add the tag
  itself, that is an additive follow-up, not a change to this plan's mechanism.
