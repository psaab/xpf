# pkg/dhcprelay

RFC 3046 DHCPv4 relay agent. Forwards DHCP between clients on local
interfaces and remote servers, inserting Option 82 with `circuit-id` set
to the interface name.

## Entry points

- `Manager` — `relay.go`.
- `NewManager()` — `relay.go`.
- `Apply(ctx context.Context, cfg *config.DHCPRelayConfig)` — `relay.go`.
  Reconciles per-interface relay goroutines to the desired config (start
  added, stop removed, restart changed, leave unchanged). Called at boot
  AND on every day-2 commit (#2348). A nil `cfg` stops all relays.
- `Stats()` — `relay.go`. Per-interface counters.
- `RelayStats` — `relay.go`.
- `pendingTable` — `pending.go`. The bounded, expiring outstanding-request
  table that binds each relayed reply to a request the relay actually
  forwarded (#6562). Internal; reached through `interfaceRelay.pending`. See
  "Outstanding-request binding" below.
- `SetMasterGate(g)` — `relay.go`. Installs the per-interface HA master-state
  gate (#2456); the daemon passes `Daemon.relayMasterGateOpen`. nil = always
  relay (standalone). Read per packet, so failover is followed live.
- `SetIfNameResolver(fn)` — `relay.go`. Installs the authored-reference →
  Linux-device resolver the desired-set builder uses (#9406); the daemon passes
  `Config.ResolveKernelIfName` for the config being applied, immediately before
  `Apply`. nil = identity (the pre-#9406 behaviour). See "Interface identity vs
  bind name" below.

## Callers

`pkg/daemon`.

## Dependencies

`pkg/config`, `github.com/insomniacslk/dhcp`, and `golang.org/x/sys/unix`
(the last for the AF_PACKET raw-L2 reply socket — see "Reply delivery
model" below). No dependency on other `pkg/*` packages.

## Interface identity vs bind name (#9406)

A relay carries **two** interface names and they are not interchangeable.

| | value | who reads it |
|---|---|---|
| `ifaceName` | the AUTHORED config reference — `ge-0/0/0.0`, `reth0.0` | the #2348 `Apply` diff key, the `RelayStats` row, `shouldRelay`/the #2456 master gate, and `pkg/daemon`'s `relayInterfaceRG`, which parses it as a **Junos unit ref** to find the owning redundancy group |
| `kernelName` | the LINUX DEVICE — `ge-0-0-0`, `ge-0-0-0.180`, `ge-0-0-2` | `SO_BINDTODEVICE`, the giaddr address lookup, the #2347 ifindex drift check, the #2076 raw-L2 sender |

Before #9406 there was only the first, and it was used for both. Linux
`dev_valid_name()` forbids `/`, and a Junos unit suffix is not a device, so
under the canonical spelling `net.InterfaceByName("ge-0/0/0.0")` failed: **no
listener bound, no giaddr resolved, nothing was relayed** — on a commit that
`configstore.CheckText`, `CompileConfig`, `CompileConfigLenient` and
`SchemaValidate` all ACCEPT. The relay schema leaf is free-form (`args:1,
multi:true`, no `valueType`, no `validator`), and every relay test used the
dash form, so the defect lived exactly in the untested compiler-spelling →
runtime-bind seam.

This is the **#4049 class** — the same silent name mismatch fixed for LLDP —
but **not the #4049 remedy**. LLDP references are physical interfaces, so
`config.LinuxIfName` (slash→dash) sufficed there. A relay member is a LOGICAL
interface, and `LinuxIfName("ge-0/0/0.0")` is `ge-0-0-0.0`, which is still not
a device. The relay needs the canonical resolver's other two arms:

```
LinuxIfName("ge-0/0/0.0")          = "ge-0-0-0.0"    <- still not a device
ResolveKernelIfName("ge-0/0/0.0")  = "ge-0-0-0"      <- unit-0 collapse
ResolveKernelIfName("ge-0/0/0.80") = "ge-0-0-0.180"  <- .<vlan-id>, not .80
ResolveKernelIfName("reth0.0")     = "<local member>"
```

**Why the identity is not simply replaced by the kernel name.** It is the
tempting one-line fix and it silently breaks HA. `relayInterfaceRG`
(`pkg/daemon/daemon_dhcp.go`) strips the unit suffix and looks the base up in
`cfg.Interfaces.Interfaces` — a map keyed by the AUTHORED name. A kernel name
is not a key there, so every RETH-owned segment would resolve to RG 0, the
#2456 gate would read "not RG-owned → always relay", and **both** cluster nodes
would relay the same client broadcast upstream with different giaddrs.

`kernelName` is part of `relaySpec`, not a cached lookup beside it: retagging a
unit's `vlan-id`, or repointing a RETH at a different local member, changes the
device to bind without changing any other field, and `relaySpec.equal` is the
only thing that decides whether the reconcile rebinds.

`show services dhcp relay` prints the bound device beside the configured
interface. That is not cosmetic: every counter in `RelayStats` is a forwarding
counter, so a relay bound to nothing shows an all-zero row that is
indistinguishable from an idle segment — which is how this stayed invisible.
`config.validateDHCPRelayInterfaceRefWarnings` closes the other half at commit,
warning when a member names no configured interface or unit. Advisory, not a
gate, per #1960.

## Relayed client message types

The client→server forwarding loop (`runRelay`, gated by
`clientRequestRelayable`) relays every client-originated BOOTREQUEST that
carries server-bound options, per RFC 2131 §3.4:

| Message type | Relayed | Notes |
|--------------|---------|-------|
| `DISCOVER` | yes | lease acquisition |
| `REQUEST` | yes | lease selection / renewal / rebinding |
| `INFORM` | yes (#2153) | client already holds an address, asks only for supplemental parameters (DNS/domain/NTP) |
| `DECLINE` | yes (#2789) | client detected the offered address already in use (ARP probe) and broadcasts a DHCPDECLINE (RFC 2131 §3.1 step 4, §4.4.1); relayed so the originating server marks the address unavailable instead of re-offering it. Carries no server reply |
| `RELEASE` | no | unicast by the client directly to its bound server (RFC 2131 §4.4.4) — it routes without relay assistance and is never seen on the relay's client-facing broadcast socket |
| server reply types (`OFFER`/`ACK`/`NAK`/`FORCERENEW`) | n/a | not client-originated; the client→server gate never sees them. The reverse server→client path (`handleServerResponses`) forwards `OFFER`, `ACK` and `NAK` (#2606) **when they bind to an outstanding request** (#6562); `FORCERENEW` is **refused** (#6562, reversing #2645) — see the reply matrix below |

The `INFORM` reply (a server-issued `ACK` with no `yiaddr` but a real
`ciaddr`) is delivered by the matrix below via the "flag clear, `yiaddr==0`,
real `ciaddr`" UDP-unicast row — the client already owns and ARP-answers for
its address.

## Relay chaining — giaddr / Option 82 ownership (#5071, #5414)

The forward loop distinguishes a **first-hop** relay from an **intermediate**
relay in a chain by inspecting the inbound BOOTREQUEST's `giaddr`
(`GatewayIPAddr`), per RFC 1542 §4.1.1 / RFC 3046. Critically, a non-zero
`giaddr` is trusted as a genuine downstream-relay stamp **only on a trusted
relay uplink** (`overrides trust-option-82`, #5414); on the default untrusted
client-facing interface it is treated as client-forged and overwritten:

| Interface trust | Inbound `giaddr` | `giaddr` action | Option 82 action | `hops` |
|-----------------|------------------|-----------------|------------------|--------|
| any | `0.0.0.0` (first hop) | **stamp** this relay's interface IP | **insert** `circuit-id` = interface name | increment (after limit check) |
| **untrusted** (default) | non-zero (client-forged) | **overwrite** with this relay's IP | **strip + re-insert** this relay's `circuit-id` | increment (after limit check) |
| **trusted** (`trust-option-82`) | non-zero (downstream relay) | **preserve** untouched | **preserve** the downstream option untouched (no `Del`/overwrite) | increment (after limit check) |

The **first relay on the client segment owns both fields**: the server selects
the client's address pool from the `giaddr` it sees and unicasts its
`OFFER`/`ACK` back to `giaddr:67`, and the original `circuit-id` must survive so
the operator's per-port Option 82 policy still applies at the server. On a
**trusted** uplink an intermediate relay that overwrote `giaddr` would make the
server lease from the wrong pool and reply to the wrong relay; overwriting
Option 82 would destroy the downstream `circuit-id`. So on a trusted-chained
request this relay changes **only** the BOOTP `hops` field.

### RFC 3046 §2.1 anti-spoofing (#5414)

A DHCP relay listens on a **client-facing** interface, so any host on the client
segment can broadcast a BOOTREQUEST with a **forged** non-zero `giaddr` and a
crafted Option 82 to impersonate a downstream relay — steering the server's
pool/policy selection that keys on `circuit-id`/`remote-id`, or redirecting the
server's reply. RFC 3046 §2.1 requires the relay **not** to trust relay-agent
information from an untrusted source. xpf therefore treats an interface as
**untrusted by default** (matching vSRX): a non-zero inbound `giaddr` is assumed
client-forged and the relay resets it to its own address + re-stamps Option 82
(the first-hop path — `addOption82` `Del`s the forged option before inserting).
Only when the group is explicitly marked `overrides trust-option-82` (the
interface faces a real downstream relay) is a non-zero `giaddr` + Option 82
preserved. Each reset is counted in `RequestsUntrustedGiaddrReset` — a non-zero
value means a client-segment host attempted to spoof a downstream relay's
identity.

- The `chained` (trusted-preserve) and `forgedGiaddr` (untrusted-reset)
  conditions are captured **before** any mutation, gated on
  `ir.trustOption82`; a zero `giaddr` in either the 4-byte or 4-in-16 form reads
  as first-hop under both. See `TestRunRelay_UntrustedForgedGiaddrOverwritten`
  (reset) and `TestRunRelay_ChainedPreservesGiaddrAndOption82` (trusted
  preserve).
- The RFC 1542 §4.1.1 hop-limit check (`overrides maximum-hop-count`, default
  16, #4309) runs for **all** paths and **before** the reset counter increments,
  so a looping request dropped for `hops` is not miscounted as a reset — it is
  most load-bearing on a chained ring, where a misconfigured downstream relay
  loop would otherwise circulate a request forever (`RequestsDroppedMaxHops`).
- **Reply path.** A trusted-chained request's reply is unicast by the server
  directly to the preserved (downstream) `giaddr:67`, so it does not return
  through this relay's `giaddr:67`-bound server conn — the intermediate relay
  handles only the request direction, which is RFC-correct. The reply-path
  Option 82 strip + `giaddr` clear (below) therefore only fires for first-hop
  (and reset) leases this relay actually owns.
- **Trust is per relay group.** `trust-option-82` is a group-level override, so
  it applies to every interface in the group. Put downstream-relay uplinks in a
  trusted group and client segments in the default (untrusted) group.

## Reply delivery model (#2076)

Server replies (OFFER/ACK/NAK) that pass the source check (#4163) **and** bind
to an outstanding request (#6562) are delivered to clients honoring the RFC 2131
§4.1 broadcast flag:

| Condition | Delivery |
|-----------|----------|
| message type `DHCPNAK` (#2606) | **always broadcast** `255.255.255.255:68` (RFC 2131 §4.3.2; checked first, ignores the flag/yiaddr/ciaddr) |
| `overrides always-broadcast` set | broadcast `255.255.255.255:68` (operator override wins) |
| broadcast flag **set** | broadcast `255.255.255.255:68` |
| flag **clear**, real `yiaddr` | **raw-L2 unicast** to `chaddr` + `yiaddr` |
| flag **clear**, `yiaddr==0`, real `ciaddr` | UDP-unicast to `ciaddr` (client already owns the IP) |
| flag **clear**, no `yiaddr`/`ciaddr` | broadcast (nothing routable) |
| raw-L2 path unavailable/fails | broadcast fallback (always works) |

**DHCPNAK (#2606).** A server sends `DHCPNAK` to reject a client's `REQUEST`
(e.g. the requested address is already leased, or the client moved subnets).
On receiving it the client immediately abandons negotiation and restarts with
a fresh `DISCOVER`. Before #2606 `handleServerResponses` accepted only
`OFFER`/`ACK`, so NAKs were silently dropped and clients hung until their
retransmission timeout. The NAK is now forwarded, and it is **force-broadcast**
ahead of the matrix above: a NAK carries no binding (`yiaddr==0`), the client
has no usable address, and broadcasting also prevents a server that
erroneously echoes a stale `ciaddr` from steering the NAK into a UDP unicast to
an address the client does not own.

**DHCPFORCERENEW — REFUSED (#6562, reversing #2645).** A server sends
`DHCPFORCERENEW` (RFC 3203, message type 9 — defined in §4 "Message layout",
assigned in §5 "IANA Considerations") to a client that **already holds a lease**
to force it back into the `RENEWING` state ahead of its T1 timer. #2645 made the
relay forward it, on the reasoning that RFC 3118 authentication is end-to-end
between client and server and therefore out of scope for a relay. **That
reasoning was wrong, and the relay now refuses the message.**

RFC 3203 **§6** (Security Considerations — *not* §5, which is IANA
Considerations) makes the authentication mandatory, and says why:

> As in some network environments FORCERENEW can be used to snoop and spoof
> traffic, the FORCERENEW message MUST be authenticated using the procedures as
> described in [DHCP-AUTH]. FORCERENEW messages failing the authentication
> should be silently discarded by the client.

A relay **structurally cannot** discharge that MUST:

- RFC 3118 §5.2 defines the key as "K — a secret value shared between the
  **source and destination** of the message", and notes that "Delayed
  authentication requires a shared secret key for each client on each DHCP
  server". The relay is neither endpoint and holds no secret or secret-ID map.
- RFC 3118 §3 ("Interaction with Relay Agents") casts the relay purely as a
  transparent mutator whose `giaddr`/`hops`/Option-82 changes are **excluded**
  from the hash — it is not a party to the authentication.
- RFC 3118 §5.3 assigns validation to the receiver: "If the MAC computed by the
  **receiver** does not match the MAC contained in the authentication option,
  the receiver MUST discard the DHCP message."

Checking only that Option 90 is **present** would be theater: the off-path
attacker in this threat model already forges the server's source IP, so they can
equally attach a well-formed Option 90 with a bogus MAC — and since the relay
cannot check the MAC, a presence test admits exactly the attacker it is meant to
stop. Most deployed clients do not implement RFC 3118 at all, so nothing
downstream would catch it either.

**Refusing costs a conformant deployment nothing**, because a conformant
FORCERENEW never reaches this socket. RFC 3203 §2.2 opens:

> The DHCP server sends a unicast FORCERENEW message to the client.

A unicast addressed to the client's own leased address routes as ordinary
traffic and is never delivered to the relay's `giaddr:67` server socket at all.
The only FORCERENEW that can arrive *here* is one deliberately addressed to
`giaddr:67` — a non-conformant server, or the attacker §6 is about. Ordinary
leasing is untouched either way: clients still renew at T1/T2. The refusal is
**loud** — every one bumps `RepliesDroppedForceRenew` and the first per session
logs at `Warn`.

> Do **not** justify this by §2.2's retransmission sentence ("it should
> retransmit the FORCERENEW message using an exponential backoff algorithm").
> That describes recovery from *transient* loss. Here the loss is **permanent** —
> every retransmission hits the same refusal — and §2.2 itself bounds the
> attempts: "The amount of retransmissions should be limited." The backoff never
> converges, so it cannot carry the argument. The unicast sentence above can.

The refusal is also **belt-and-braces**: FORCERENEW is server-initiated, so its
xid matches no outstanding request and the binding gate below would drop it
regardless. The dedicated arm exists to give the refusal its own counter and
log, so an operator can tell it apart from an ordinary unbound reply.

There is deliberately **no opt-in knob** to re-enable forwarding. If a
deployment genuinely needs relayed FORCERENEW, that is a follow-up that should
come with a way to actually verify the message, not a flag that restores an
unverifiable forward.

**Why raw L2 (`l2send_linux.go`).** A client in SELECTING/REQUESTING that
clears the broadcast flag has **not yet configured** the offered address,
so it will not answer ARP for `yiaddr`. A normal UDP `WriteTo(yiaddr)`
forces the kernel to ARP-resolve `yiaddr`, the ARP goes unanswered, and the
reply is silently dropped — the client never acquires a lease. The relay
therefore builds a full Ethernet+IPv4+UDP frame addressed to the client's
`chaddr` and sends it on an `AF_PACKET`/`SOCK_RAW` socket (the
`pkg/cluster/garp.go` hand-roll pattern). The IPv4 source is the **saved
giaddr** (the same address the server saw in the relayed request); the IPv4
header checksum is computed and the UDP checksum is 0 (legal for IPv4 per
RFC 768).

- **`CAP_NET_RAW` dependency.** The AF_PACKET socket needs `CAP_NET_RAW`,
  already held by the root daemon (same as `pkg/vrrp`, `pkg/lldp`,
  `pkg/cluster/garp.go`). If the socket cannot be opened (e.g. a future
  hardened unit without the cap), the relay logs once and falls back to
  broadcast — it **never regresses to undeliverable**.
- **Guards → broadcast fallback.** Non-Ethernet `htype`, a non-6-byte
  `chaddr`, an over-MTU reply (`20 + 8 + len(payload) > iface.MTU` — the raw
  path cannot fragment), or any `Sendto` error fall back to broadcast.
- **Per-send interface re-resolution.** The ifindex + source MAC are
  re-resolved from `net.InterfaceByName` on every send (`garp.go`
  precedent), so a link flap / dynamic recreate / VRRP `programRethMAC` MAC
  change does not leave a stale ifindex or source MAC. VLAN sub-interface
  egress uses the same netdev index the listener is bound to (the kernel
  applies the `.N` 802.1Q tag).
- **Counters.** `Stats()` exposes a per-reason breakdown
  (`RepliesL2Unicast`, `RepliesUnicastCiaddr`, `RepliesBroadcastFlag1`,
  `RepliesBroadcastForced`, `RepliesBroadcastNoTarget`,
  `RepliesBroadcastL2Fallback`, `RepliesBroadcastNak`,
  `RepliesDroppedUnknownServer`, `RepliesDroppedNoRequest`,
  `RepliesDroppedForceRenew`, `PendingEvicted`).
  **`RepliesBroadcastL2Fallback` is the one
  to alert on** — it means the raw-L2 path failed (CAP_NET_RAW, driver, or
  MTU) and the relay degraded to broadcast. **`RepliesDroppedUnknownServer`
  (#4163)** counts replies dropped because their source IP was not a
  configured server — a non-zero value is a rogue-reply injection attempt (or
  a multi-homed server unicasting from an unlisted source IP); see "Reply
  source validation" below. **`RepliesDroppedNoRequest` (#6562)** counts
  replies dropped because they answered no outstanding relayed request —
  either an injection that passed the source check, **or a legitimate reply
  that missed the binding window**, which is a client-visible DHCP failure, so
  this one must be *watched*, not assumed hostile. **`PendingSize` /
  `PendingCapacity` (#6562)** are the outstanding-request table's occupancy and
  ceiling — the **leading** indicator: occupancy approaching capacity means
  bindings are about to be evicted. **`PendingEvicted` (#6562)** is coincident,
  not leading: it rises only once bindings are already being lost.
  **`RepliesDroppedForceRenew` (#6562)** counts refused DHCPFORCERENEW
  messages. See "Outstanding-request binding" below.
  **`RequestsDroppedRateLimit` (#5670)** counts
  client-facing datagrams dropped by the per-interface ingress rate limiter — a
  sustained nonzero value is a flood / amplification attempt (see "Ingress rate
  limit" below). `show ... dhcp-relay` prints this breakdown.

## Reply source validation (#4163)

`handleServerResponses` validates every server reply's **source IP against the
configured server set before parsing or forwarding it**. The server-facing
socket is *bound* to `giaddr:67` (see the socket-lifecycle notes below), not
`connect()`-ed, so the kernel delivers any datagram routed to `giaddr:67` —
from **any** source — up to the relay. Without a source check an off-path
attacker (or a compromised transit host) that can route a UDP datagram to
`giaddr:67` could inject a forged `OFFER`/`ACK` (steering the client to a
hostile gateway/DNS → MITM) or a forged `NAK` (forcing a client restart) and
the relay would deliver it. RFC 3046 relay practice is to forward replies only
from the relay's explicit, configured server list.

- The resolved server set (`[]*net.UDPAddr`, IP + port 67, from the group's
  active `server-group`) is threaded from `runRelaySession` into
  `handleServerResponses`, which builds an IP allow-set once. Each reply's
  source IP (from `ReadFrom`) is compared with `net.IP.Equal` (form-agnostic;
  the source **port** is not part of the trust decision). A reply from an
  unlisted source is **dropped before `dhcpv4.FromBytes`** and counted in
  `RepliesDroppedUnknownServer`.
- **Enforced by default** — there is no legitimate case for a relay forwarding
  a reply from a source outside its configured set. The drop is made **loud**:
  the first drop per session logs at `Warn` (subsequent ones at `Debug` so a
  forged-reply flood cannot spam the log) and every drop bumps the counter, so
  the one benign edge case — a strictly **multi-homed server** that unicasts
  its reply from a source IP different from the one the operator listed — is
  diagnosable from `RepliesDroppedUnknownServer` (and the `Warn`) rather than
  presenting as a silent black-hole. If a real deployment needs that, a
  follow-up can add an explicit extra-reply-source allow-list knob; it is not
  needed to close the injection hole.
- Source-set membership is necessary but **not sufficient** — a source IP is
  spoofable. Since #6562 it is the *first* of two checks; see
  "Outstanding-request binding" immediately below. (`giaddr`-echo and Option-82
  correlation remain out of scope: Option 82 is stripped on the reply but not
  echo-validated.) This is DHCPv4-only (there is no DHCPv6 relay — see below).

## Outstanding-request binding (#6562)

The #4163 source check above stops an attacker who cannot forge a source
address. It does **not** stop one who can: an off-path attacker who spoofs a
configured server's IP passes it, and the relay would then forward a forged
`OFFER`/`ACK` (hostile gateway/DNS) or `NAK` (forced client restart) to the
client. So every reply must additionally **bind to a request the relay actually
forwarded**.

`pending.go` holds a bounded, expiring table of outstanding transactions. The
client-facing loop inserts an entry for each request it relays upstream
(*before* the upstream write — the reply loop is a different goroutine, and a
fast server can answer before a post-send insert would have run); the
server-facing loop forwards a reply only if `pendingTable.matches` hits.

**Key — `xid` + `chaddr`.** RFC 2131 §4.1 gives the xid's purpose ("The 'xid'
field is used by the client to match incoming DHCP messages with pending
requests"), and its §4.3.1 Table 3 requires a server to copy **both** `xid` and
`chaddr` from the client's message into `DHCPOFFER`/`DHCPACK`/`DHCPNAK` — so
both halves are present on the request and echoed on the reply. The relay's own
mutations (`hops`, `giaddr`, Option 82) touch neither, so the key is stable
across stamping. Option 61 (client-identifier) is **deliberately excluded**
even though it is a stronger identity: RFC 2131 told servers they MUST NOT echo
it and only RFC 6842 §3 (2013) reversed that to a MUST, so keying on it would
drop every reply from a pre-RFC-6842 server — a silent, segment-wide outage. The
ingress interface is not keyed either: each relay interface owns its own table.

**Bounded — capacity is derived from `maximum-packet-rate`, evict-oldest.**
Steady-state occupancy is `rate × TTL`, and the fill rate is the configurable
#5670 limit — so capacity **must** track it. `pendingCapacityFor` sizes the
table at `rate × pendingTTL + relayBurstFor(rate)` (the sustained window plus
the token bucket's 2-second burst allowance), clamped to
`[4096, 131072]`. `maxPacketRate` participates in `relaySpec.equal()`, so a
day-2 rate change restarts the session and re-derives it.

> A **fixed** capacity is a trap, and this originally shipped as a hardcoded
> 8192. Above ~273 pps the table became cap-bound and the binding window
> silently collapsed from 30 s to `8192/rate` seconds — while the
> "Ingress rate limit" section below *recommends raising*
> `maximum-packet-rate` on a busy segment. A segment provisioned at 3000 pps
> had a 2.7 s window; a boot storm against a server whose RTT exceeded that had
> every reply dropped at the relay, turning a storm that previously completed
> into a permanent retry storm. `TestPendingCapacity_TracksMaxPacketRate` pins
> the property (a reply arriving one server RTT later still binds), not the
> number.

The **ceiling** is mandatory in the other direction: the schema allows up to
1000000 pps, and an unclamped derivation would be ~3×10⁷ entries — gigabytes,
i.e. the memory-exhaustion vector this table exists not to be. Above ~4096 pps
the ceiling binds and the effective window is `capacity/rate` seconds; that is
unavoidable (window × rate *is* memory) but it is made explicit rather than
emergent — `Apply` logs a startup `Warn` naming the reduced window, and
`PendingSize`/`PendingCapacity` show the runtime truth.

At capacity the table reaps expired slots first, then evicts the **oldest** — it
does **not** refuse the new request. Refusing new requests would let an attacker
who fills the table lock out every new client (a total segment outage); evicting
the oldest degrades gracefully, and the choice trades away no security, because
eviction can only cause a legitimate reply to be *dropped*, never an unsolicited
reply to be *accepted*. Every eviction bumps `PendingEvicted`.

**Amortized O(1) at capacity.** Expiry and eviction go through a fixed-size ring
of insertions, not a scan. This works because every entry carries the *same*
TTL, so insertion order **is** expiry order and the oldest is always at the ring
head. The original implementation ranged the whole map for the minimum expiry —
two full `O(capacity)` scans per admitted packet once full, on the single
client-facing read goroutine, which saturates a core in exactly the overload the
table is meant to survive.

Per-insert reclaim work is **bounded by a constant**, via two mechanisms that
cover different cases:

- The *wholly expired* ring — the first insert after a long idle period — is
  taken in constant time by a fast path: because the ring is expiry-ordered, one
  probe of the newest slot proves the whole ring is dead, so `head`/`count` reset
  to zero and the map is replaced wholesale rather than deleted key by key.
- The *mixed* ring — most slots expired but the newest still live, which is a
  quiet period followed by a single late request — cannot use that probe, so the
  head drain is capped at `maxDrainPerInsert` (64) slots per call. Without the
  cap this case popped ~`capacity` (up to 131071) slots one at a time, each with
  a map lookup and delete, under the mutex on the client-facing packet path: the
  same multi-millisecond stall as before, just behind a narrower trigger.

`insert` needs exactly one free slot, so reclaiming more per call buys nothing.
Leftover expired slots are inert — `matches` re-checks the expiry and
`PendingSize` excludes them — and later inserts clear the backlog at a net 63
slots per admitted packet (64 drained, one added; the eviction loop cannot run
after a positive drain, because `count < capacity` by then). `TestPendingTable_FullDrainIsConstantTime` and
`TestPendingTable_PartialDrainIsBounded` pin the two cases by counting slots
examined; the latter must **stagger** expiries, because a frozen clock makes
every slot expire together and the mixed case unconstructible.

Because both reclaim steps always free room before the at-capacity eviction loop
can run, that loop only ever displaces an *unexpired* binding — so counting each
pop as cap pressure is exact, and `PendingEvicted` cannot fire on a relay that is
merely idle. `insert` carries the proof.

A key re-inserted before its old slot expires (a retransmission, or the
SELECTING REQUEST reusing the DISCOVER's xid) simply gets a new slot; the older
one is stale and is discarded for free at the head. Slot identity is an explicit
**generation counter**, not the expiry: two inserts of the same key can carry
identical expiries (nothing guarantees `time.Now()` advances between two calls),
and matching on expiry would pop the older slot and delete a binding the newer
slot still owns. Because a slot is always freed before a push,
`len(entries) ≤ count ≤ capacity` — the ring bounds the map, so duplicate
inserts cannot grow either structure.
`TestPendingTable_AtCapInsertIsConstantTime` pins the cost by counting ring
slots examined (deterministic, no timing), with a **lower** bound as well as an
upper one so an implementation that bypasses the ring cannot pass by reporting
zero.

**Memory.** A `pendingSlot` is 48 bytes on amd64, so the ring is a fixed
`48 × capacity` (6 MiB at the 131072 ceiling) plus the Go map, ~18 MiB per
interface at full occupancy on a ceiling-sized table. That is bounded per
interface but **multiplicative across relay interfaces**: a chassis with many
high-rate relay segments should size `maximum-packet-rate` per segment rather
than setting it high everywhere.

**Bindings survive a config reload.** Every field in `relaySpec` — servers,
always-broadcast, hop count, trust-option-82, packet rate — participates in
`equal()`, so any day-2 change to a group stops the relay and builds a
replacement. The replacement rebinds the *same* `giaddr:67`, so replies for
pre-reload requests still arrive; without migration they would hit the binding
gate and be dropped, which pre-#6562 would have been forwarded. `Apply` therefore
snapshots the old table's live bindings and adopts them into the replacement,
**after** the old relay's goroutines are joined (so the snapshot is complete)
and **before** the new one launches (so nothing races the destination).

This matters most for `maximum-packet-rate`, whose documented remedy is to raise
it on a busy segment: without migration, an operator following that advice
*during* a boot storm would flush every in-flight binding and cause the retry
storm this table exists to prevent. Adopted entries keep their **original
expiry** — a reload must not refresh the TTL, which would widen the attacker's
xid-guessing window every time the config was touched. If the replacement is
*smaller* (the rate was lowered), the oldest excess bindings are dropped and
**counted** in `PendingEvicted` rather than discarded silently.

`adopt` **requires an empty destination**, and asserts it. It appends rather than
merging, so migrated expiries landing after a destination's later ones would
destroy the expiry ordering everything else depends on: the full-drain probe
would read a newer-but-expired tail slot, conclude the whole ring was dead, and
wipe live bindings, while the head drain and `PendingSize`'s binary search would
mis-locate the boundary. The sole production caller adopts into a table built
moments earlier and never launched, so the assertion cannot fire in the live
path — it exists so a future second caller fails loudly instead of silently
corrupting the structure that decides which replies reach clients. An ordered
merge would generalise it, but no caller needs one.

**TTL — 30s.** This bounds the window in which a guessed xid would be accepted,
while covering realistic server latency. RFC 2131 §4.1's retransmission schedule
is 4s, then 8s, doubling to a 64s maximum, so 30s spans the first three
retransmissions. A too-short TTL is self-healing rather than fatal: the client's
retransmission traverses the relay and arms a fresh entry, and this holds
whichever xid it uses — §4.1 leaves that open ("A client may choose to reuse the
same 'xid' or select a new 'xid' for each retransmitted message") — because the
server's answer echoes whatever xid the retransmission carried.

**A match does not consume the entry.** The relay fans each request out to
*every* server in the group, so an N-server group answers one `DISCOVER` with N
`OFFER`s; and RFC 2131 §4.4.1 has the SELECTING `DHCPREQUEST` reuse the
`DHCPOFFER`'s xid, so the same binding must also admit the `ACK`/`NAK`.
Consuming on first match would silently break multi-server redundancy.

**Fail direction.** A binding that is too strict silently breaks DHCP for real
clients, which is a worse outage than the injection it prevents. Every drop is
therefore counted (`RepliesDroppedNoRequest`) and logged warn-once-then-`Debug`.

The **leading** indicator is `PendingSize`/`PendingCapacity`: occupancy climbing
toward capacity means the relay is about to start evicting bindings, and it is
visible *before* any reply is lost. `PendingEvicted` is **coincident**, not
leading — an eviction is what *causes* the subsequent drop, so its lead time is
one server RTT (tens of ms to a couple of seconds). Alert on the
size/capacity ratio; treat a rising `PendingEvicted` as damage already in
progress.

`PendingSize` reports **unexpired ring slots**. Neither of the two obvious
alternatives is correct:

- the map's key count reads *low*, because duplicate inserts consume ring slots
  without adding keys — a capacity-4 ring holding `A,B,B,B` has two keys but
  evicts live `A` on the very next insert, so the gauge would show a comfortable
  `2/4` at the exact moment eviction began;
- the raw ring count reads *high*, because expired slots stay counted until some
  later insert reclaims them — an idle full table would report
  `capacity/capacity` even though the next insert reclaims the lot and evicts
  nothing, paging an operator over a relay that is simply quiet.

Expired slots form a contiguous prefix (the ring is expiry-ordered), so the
boundary is found by binary search — `O(log capacity)` under the mutex, which
matters because `Stats()` reads this while the packet path is running.

These counters are currently surfaced only by the **on-box console CLI**
(`show services dhcp relay`) — there is no gRPC RPC or Prometheus collector for
`RelayStats`, so the remote `cli` and external alerting do not see them. That
gap is pre-existing and tracked separately; it does bound "visible" to the
console today.

A nil table fails **closed** (it
admits nothing), matching the #4163 empty-allow-set posture, so a wiring
regression is a loud counted outage rather than a silent loss of the control;
`TestManagerRelay_HasPendingTable` guards the production wiring.

**Table lifetime.** The table lives on `interfaceRelay`, not on the session, so
a session rebuild (#2347 ifindex drift, #3960 re-address) does not wipe
in-flight bindings and strand a client mid-transaction.

**HA note (#2456).** Entries are per-node. If a client's transaction spans a
failover, the newly-active node has no binding for the in-flight reply and drops
it; the client's normal retransmission then re-arms the new node. The window is
bounded by one client retransmission, and the drop is visible in
`RepliesDroppedNoRequest`. (A BACKUP node never inserts, because the master gate
drops the request before it is forwarded.)

### `overrides always-broadcast` config

```
set forwarding-options dhcp-relay group <g> overrides always-broadcast
```

Mirrors the Junos knob: forces every reply to broadcast even for
flag-clear clients (the raw-L2 socket is not opened at all when set). This
is the operator escape hatch for environments where the L2 path is
undesirable. Both the block form (`overrides { always-broadcast; }`) and
the flat-set form compile to `DHCPRelayGroup.AlwaysBroadcast`; the flat-set
inline-interface consumer treats `overrides` as a property boundary so it
is not swallowed into the interface list (#2076 / dual-AST harness case
`forwarding-options-dhcp-relay-overrides`).

### Additional overrides (#4309)

```
set forwarding-options dhcp-relay group <g> overrides maximum-hop-count <1..16>
set forwarding-options dhcp-relay group <g> overrides forward-only
set forwarding-options dhcp-relay group <g> overrides relay-agent-option
```

- **`maximum-hop-count` — ENFORCED.** The relay drops a client request
  whose BOOTP `hops` field has reached this value (RFC 1542 §4.1.1 loop
  protection), and increments `RelayStats.RequestsDroppedMaxHops`.
  Previously the limit was hardcoded at 16; that stays the default when
  the override is unset (`resolveMaxHopCount`). Compiles to
  `DHCPRelayGroup.MaximumHopCount` and flows into `relaySpec.maxHopCount`
  (a change restarts the per-interface relay).
- **`forward-only` — accepted-only.** The xpf relay already forwards
  statelessly (no persistent per-client binding), so this matches the
  default behavior. Typed + compiled so it stops silently vanishing; a
  commit-time advisory (`validateDHCPRelayParityWarnings`) notes it is
  accepted and inert.
- **`relay-agent-option` — accepted-only.** The relay ALWAYS inserts
  Option 82 (`circuit-id`); this knob is accepted and matches the
  default, with the same accepted-only advisory.

### Ingress rate limit (#5670)

```
set forwarding-options dhcp-relay group <g> overrides maximum-packet-rate <pps>
```

- **`maximum-packet-rate` — ENFORCED (DoS hardening).** The relay admits at
  most this many client-facing datagrams per second **per interface**, via a
  per-interface token bucket (`tokenBucket` in `relay.go`) checked in the main
  read loop **before** `dhcpv4.FromBytes`. Without it an untrusted client
  segment can flood `:67`: each admitted packet costs a variable-length TLV
  parse, an Option 82 allocation, and a **fan-out send to EVERY configured
  server** — a 1→N amplification that can also make the real servers rate-limit
  legitimate clients. The bound is applied at the cheapest point (before the
  parse) so a flood is dropped without doing the work.
- **Default 100 pps** when unset (`resolveMaxPacketRate`). DHCP relay traffic is
  inherently low-rate (a handful of packets per lease, renewals on the order of
  hours), so 100 pps sustained is generous for legitimate use. The bucket starts
  **full** with a **2-second burst** (`relayBurstFor` = `2×rate`), so a
  simultaneous-boot spike up to `2×rate` packets is admitted instantly before
  the sustained rate throttles a persistent flood. Set a high value
  (schema range `1..1000000`) to effectively disable the bound on a segment that
  legitimately needs it.
  - **Raising this also resizes the #6562 outstanding-request table**, whose
    capacity is derived as `rate × 30s + 2×rate` — that is deliberate, so the
    reply-binding window does not collapse on a segment you just told the relay
    to expect more traffic from. Above **~4096 pps** the table's memory ceiling
    (131072 entries) binds instead, the effective binding window becomes
    `capacity/rate` seconds rather than 30 s, and the relay logs a startup
    `Warn` naming the reduced window. Watch `PendingSize`/`PendingCapacity` on
    such a segment. See "Outstanding-request binding" above.
- **Counted + throttled log.** Every dropped datagram bumps
  `RelayStats.RequestsDroppedRateLimit`; the log is warn-once-per-session then
  `Debug` (never per packet, per the project logging rules). A sustained
  nonzero counter means the segment is exceeding its pps bound — a flood /
  amplification attempt or a segment that should raise `maximum-packet-rate`
  (which resizes the #6562 binding table with it — see the sub-bullet above).
- Compiles to `DHCPRelayGroup.MaximumPacketRate` and flows into
  `relaySpec.maxPacketRate` (a change resizes the bucket, so it restarts the
  per-interface relay). All three parse shapes (flat-set, merged-Keys, block
  form) are covered; the flat-set consumer treats `overrides` as a property
  boundary so the value token is not swallowed into the interface list. The
  token-bucket refill semantics are unit-tested deterministically with an
  injected clock (`TestTokenBucket_BurstThenRefill`); the end-to-end flood-drop
  is `TestRunRelay_RateLimit_5670` / `TestRunRelay_RateLimit_DefaultBound`.

### Trust override (#5414)

```
set forwarding-options dhcp-relay group <g> overrides trust-option-82
```

- **`trust-option-82` — ENFORCED (RFC 3046 §2.1).** Marks the group's
  interfaces as **trusted relay uplinks** that face a downstream relay, so
  an inbound non-zero `giaddr` + Option 82 is preserved (the RFC 1542 §4.1
  intermediate-relay behavior). When **unset (the default)** the interface
  is an untrusted client-facing segment: a non-zero `giaddr` is assumed
  client-forged and the relay overwrites it with its own address +
  re-stamps Option 82, counting the event in
  `RelayStats.RequestsUntrustedGiaddrReset`. Compiles to
  `DHCPRelayGroup.TrustOption82` and flows into `relaySpec.trustOption82`
  (a change restarts the per-interface relay). All three parse shapes
  (flat-set, merged-Keys, block form) are covered; the flat-set consumer
  treats `overrides` as a property boundary so the keyword is not swallowed
  into the interface list. See the "RFC 3046 §2.1 anti-spoofing" section
  above.

### IPv6 / DHCPv6 parity

There is **no DHCPv6 relay agent** in the codebase, and DHCPv6 (RFC 8415)
does not have this bug class: it has no BOOTP broadcast flag — clients use a
link-local source and the relay replies to that link-local unicast (or
`ff02::1:2`), so there is no "reply to an unconfigured global address via
ND" failure mode. This fix is strictly DHCPv4.

**Authoring the Junos DHCPv6 relay stanza is refused (#9411).** Before #9411,
`forwarding-options dhcp-relay dhcpv6 { … }` committed clean on every config
channel and was either discarded or — in the elided spelling
`dhcp-relay dhcpv6 { group g6 { … } }` — compiled AS A DHCPv4 relay group, which
also hid a real DHCPv4 relay block authored after it. The config compiler now
refuses the stanza at commit (warning on the tolerant load / peer-sync path) and
never reads the dhcpv6 spelling as this package's DHCPv4 relay; see
`docs/config-schema.md`. An RFC 8415 relay agent is separate, larger work.

### HA master-state gate (#2456)

On a chassis cluster a shared client segment is reachable from BOTH the
MASTER and the BACKUP node, so both nodes' listeners receive the client
DISCOVER/REQUEST broadcast. Without a gate both relay it upstream, so the
server sees **duplicate** relayed requests (and duplicate relay state with
different per-node `giaddr`s). #2456 couples the upstream relay-forward to
this node's VRRP/cluster MASTER state for the relay interface's redundancy
group:

- The Manager carries a `masterGate` seam, installed by the daemon via
  `Manager.SetMasterGate` (`daemon_run.go`). The gate closure is
  `Daemon.relayMasterGateOpen` (`daemon_dhcp.go`).
- The gate is read **per packet** in the relay's main read loop (after the
  packet is parsed and confirmed relayable, before `giaddr`/forward). A
  BACKUP node **drops** the request (bumping `RequestsDroppedBackup`); a
  MASTER node relays as before.
- The decision mirrors the DDNS per-RG writer gate
  (`ddnsReconcileOptions`): standalone (no cluster) always relays; a
  non-RG-owned relay interface (RG 0) always relays (not a duplicate
  hazard); an RG-owned interface relays IFF this node is MASTER for that RG.
  `relayInterfaceRG` resolves the relay interface name (e.g. `reth0.0`) to
  its RG by stripping the unit suffix and reading the config interface's
  `redundant-ether-options redundancy-group` (same shape as `rgForInterfaces`,
  #2664).
- Because the gate reads the same live `rgStateMachine` the DHCP server and
  DDNS gates read — via the stricter `isRethMasterState` → `AllVRRPMaster()`
  accessor (all the RG's VRRP instances MASTER), not the looser `IsActive()`
  (`rg_active = clusterPri || allVrrpMaster` in non-strict mode) those gates
  use — a backup that **becomes** master on VRRP failover starts relaying
  immediately, no relay restart and no cached-at-startup staleness. The
  tighter all-VRRP-master criterion is deliberate: it avoids two nodes both
  relaying during the cluster-primary-but-not-yet-VRRP-master convergence
  window, which is the duplicate-relay hazard this gate closes.
- A nil gate (the `NewManager` default, or any non-cluster build) is
  fail-open: every request is relayed (correct standalone behavior).

Changes touching this path must pass `make test-failover`.

Note (#2076): the *reply* path on Backup is a separate concern. Before #2076
a Backup's duplicate flag-clear reply was harmlessly lost on ARP failure;
now that the flag-clear path actually delivers (raw L2 to `chaddr`), a
flag-clear client could receive duplicate OFFER/ACK. With the #2456 gate the
Backup no longer relays the *request* upstream, so it never produces an
OFFER/ACK to forward in the first place; clients still dedupe on
`xid` + `chaddr` for any residual cross-node delivery.

## Socket / lifecycle model (#1915)

- **Per-interface listener on `0.0.0.0:67`.** Each interface in a relay
  group gets its own client-facing UDP listener bound to the wildcard
  `0.0.0.0:67`. Multiple listeners coexist via `SO_REUSEADDR` +
  `SO_REUSEPORT` set **before** `bind(2)` (idiomatic
  `net.ListenConfig.Control`, mirroring `pkg/cluster` `vrfListenConfig`).
  Without REUSEPORT the second interface's bind would fail `EADDRINUSE`
  and only the first interface would be served.
- **`SO_BINDTODEVICE` is a hard invariant on every client listener.** The
  kernel discards BINDTODEVICE-mismatched sockets *before* the REUSEPORT
  load-balancing fanout, so each listener only receives its own
  interface's ingress traffic — REUSEPORT does **not** cause duplicate or
  cross-interface relaying. A client listener without BINDTODEVICE would
  join the REUSEPORT group unfiltered and steal other interfaces' packets.
- **`SO_BROADCAST` on the client listener** so broadcast OFFER/ACK replies
  to `255.255.255.255:68` are delivered (Linux returns `EACCES` on a
  limited-broadcast `sendto` without it). The server conn does not set
  `SO_BROADCAST` (server replies to the relay are unicast) or
  `SO_BINDTODEVICE` (the routed reply may arrive via the WAN path, not the
  client interface).
- **Server-facing socket binds `giaddr:67` (BOOTPS), not an ephemeral port
  (#2888).** RFC 2131 §4.1 specifies a server unicasts its reply back to the
  relay agent at the `giaddr` it saw in the relayed request, destination port
  `67` (BOOTPS) — **not** the relay's source port. A strict-RFC server
  therefore sends `OFFER`/`ACK` to `giaddr:67`; if the relay's server conn sat
  on an ephemeral port (`giaddr:0`, the pre-#2888 behavior) nothing listened on
  `giaddr:67` and the reply was dropped, so a relayed lease never completed with
  a strict server. The server conn now binds `giaddr:67` and sets
  `SO_REUSEADDR` + `SO_REUSEPORT` — **required**, because the client listener
  already holds `0.0.0.0:67`; a second `:67` bind (even to the distinct,
  specific `giaddr`) would otherwise fail `EADDRINUSE`. The two sockets do not
  steal each other's traffic: the client listener is `SO_BINDTODEVICE`-pinned to
  the LAN interface and the server conn binds the **specific** unicast `giaddr`,
  so the kernel delivers a unicast datagram destined to `giaddr:67` to the
  address-specific socket in preference to the wildcard listener.
- **Read buffer sized to the UDP/IP maximum (#3012).** Both the
  client-facing (`runRelay`) and server-facing (`handleServerResponses`)
  loops read into a `readBufSize` (= 65535) buffer. `net.PacketConn.ReadFrom`
  on a UDP socket copies only the first `len(buf)` bytes of a datagram and
  silently discards the tail (`MSG_TRUNC`); a truncated DHCP datagram corrupts
  the trailing option block, so `dhcpv4.FromBytes` fails and the packet is
  dropped. DHCP imposes no 1500-byte limit (the Maximum DHCP Message Size
  option is a `uint16`, and a UDP datagram can carry up to 65535 bytes), so a
  datagram can legitimately exceed 1500 bytes — large option sets (classless
  static routes, many search domains, Option 82, vendor/PXE options) or a
  jumbo-MTU link delivering the whole datagram in one frame. Sizing the buffer
  to the UDP maximum ensures the buffer is never the truncation point. (A
  fixed 64 KiB buffer is fine here — the relay read path is not hot.)
- **Bounded, deterministic `Stop()`.** Reads use the blocking
  `net.PacketConn.ReadFrom`; a close-on-cancel watcher (started after both
  conns exist) closes BOTH conns when the relay context is cancelled, so a
  blocked read returns `net.ErrClosed` immediately. The server-response
  goroutine is tracked with a `WaitGroup` and joined before the relay's
  `done` channel closes, so `Stop()` (and the `Stop()` inside `Apply()`) is
  a true join with no packet-dependent wait and no goroutine leak across
  `Apply`/`Stop` cycles. Both loops cancel the shared context on exit so a
  one-sided error cannot wedge the join.
- **Day-2 reconcile (#2348).** `Apply` is invoked at boot (`daemon_run.go`)
  AND on every commit through `daemon.reconcileDHCPRelay` in the
  `applyConfigLocked` pipeline (`daemon_apply.go`, step 16c) — the relay
  Manager is created at boot regardless of whether a relay was configured
  then, so a relay added later starts and a relay removed later stops.
  `Apply` diffs the desired set (`computeDesired`) against the running
  `relays` map **per interface** and:
  - starts an interface present in desired but not running;
  - stops (bounded `cancel()`+`<-done`) an interface running but no longer
    desired (or when the whole block is deleted: a nil `cfg` stops all);
  - restarts an interface whose **spec changed** — a `relaySpec` is the
    resolved server list (config order) plus the `always-broadcast` flag;
    a change in either tears the old session down and binds a fresh one;
  - leaves an unchanged interface's session running untouched (idempotent —
    a no-op commit causes **no churn**, no socket reopen).
  The stop/restart teardown reuses the same `Stop()` mechanism (the #2347
  supervisor + #1915 close-on-cancel + `WaitGroup` join), and the old
  listener is fully closed before any replacement binds, so a restart never
  races `EADDRINUSE` and never hangs. The teardown joins run **outside**
  `m.mu` so a blocked relay's `<-done` does not stall `Stats()` or a
  concurrent `Apply`.
- **Startup readiness retry.** When `Apply` starts a relay (boot or a day-2
  add) and the interface is not yet ready (no IPv4 address, or a dynamic
  VLAN/tunnel not yet created), the relay retries resolving the interface +
  giaddr on a bounded, `ctx`-cancelable interval instead of dying
  permanently. The interface is re-looked-up every attempt (no stale cached
  index).
- **Socket bind/listen retry (#2787).** A *transient* failure to open the
  client listener (`0.0.0.0:67`) or the `giaddr:67` server conn — interface not
  yet up, its IPv4 not yet bound, or port 67 momentarily busy on a quick reload —
  is **not terminal**. `runRelaySession` returns `sessionRetry`, and the
  supervisor (`runRelay`) waits the same bounded, `ctx`-cancelable
  `retryInterval` and rebuilds, so the relay recovers on that interface once
  the condition clears. Before #2787 a bind failure returned `false`/terminal
  and the per-interface supervisor goroutine exited permanently — the relay
  went deaf on that segment until a daemon restart or operator re-commit. Only
  a *cancelled* session context (`Stop()`) on a bind failure is terminal
  (`sessionStop`), so teardown stays prompt and never spins past shutdown.
- **ifindex-drift detection (#2347).** `SO_BINDTODEVICE` pins the client
  listener to the interface's kernel **ifindex** at `bind(2)`. If the
  interface is deleted+recreated or renamed at runtime under unchanged config
  (VLAN delete/recreate, tunnel rebuild, device reset) it gets a NEW ifindex
  and the kernel stops delivering DHCP client requests to the stale-bound
  socket — the relay goes permanently **deaf** on that segment until a daemon
  restart. (Note: the raw-L2 reply path is unaffected — it re-resolves the
  ifindex per send; only the listener is at risk.) Each per-interface relay is
  now a **supervisor**: `runRelay` runs one `runRelaySession` under a child
  context and rebuilds it when the session tears down due to drift.
  `runRelaySession` captures the live ifindex when it opens the listener and
  runs a periodic (`ifindexCheckInterval`, 5s) watcher that re-resolves the
  name to the live ifindex; on a real, differing index it records drift and
  cancels the **session** context, reusing the existing #1915 close-on-cancel
  + `WaitGroup` teardown (no new teardown path, no `EADDRINUSE` — the stale
  socket is fully closed before the rebind, no `Stop()`-hang risk). The probe
  is **tolerant**: a resolve failure is treated as "no drift" so a transient
  netlink hiccup or mid-rename window never tears down a working listener, and
  it is **idempotent** (unchanged ifindex => no rebind). A failed baseline
  capture (`boundIfindex==0`) adopts the first real reading as the baseline
  rather than triggering a spurious rebind. Drift detection is per-interface,
  so a rebind on one segment never drops relays on the others. This mirrors
  the #2294 VRRP instance-restart-on-ifindex-drift fix for the relay listener.
- **giaddr re-resolution on a same-ifindex readdress (#3960).** The `giaddr`
  is the relay's own interface address — the source the upstream server
  unicasts its `OFFER`/`ACK` back to (`giaddr:67`, above). It is resolved
  **once** at session start and consumed in three places: the server conn's
  `giaddr:67` bind, the per-packet `GatewayIPAddr` stamp, and the raw-L2 reply
  source IP. If the interface's **primary IPv4 changes while its ifindex stays
  the same** (a DHCP-learned lease renewing to a different IP, a static
  readdress, or an HA VIP move on the same netdev), all three go **stale**: the
  relay keeps stamping the old `giaddr`, the server replies to the old
  (now-invalid) address, and even a corrected stamp would not help because the
  server conn is still bound to the old `giaddr:67` — the reply is
  **blackholed** and relayed clients silently stop getting leases. The
  ifindex-drift watcher above now **also** re-resolves the primary IPv4 on each
  tick and compares it against the `giaddr` the session bound at start; on a
  real, differing address it records a **readdress** (`sessionReaddr`) and
  cancels the session context, reusing the same #1915 teardown. The rebuild
  re-resolves the `giaddr`, **rebinds the server conn** to the new
  `giaddr:67`, and makes the new main loop stamp the current address — fixing
  all three consumers atomically. Like the ifindex probe it is **tolerant**: a
  momentarily unaddressed interface (resolve failure) keeps the last-known-good
  `giaddr` and never tears down a working listener or stamps a bogus `giaddr`,
  and it is **idempotent** (unchanged address => no rebuild).

## Gotchas

- The interface must have an IPv4 address — that's what fills `giaddr`. If
  it is missing at boot the relay retries (see above) rather than failing.
- **Primary-vs-secondary giaddr selection (#2849).** When an interface
  carries a primary address plus secondary subnet aliases, the kernel returns
  them in netlink maintenance order — NOT guaranteed primary-first.
  `defaultIfaceResolver` therefore selects the **PRIMARY** IPv4, not the first
  one: on Linux it enumerates addresses via `netlink.AddrList`
  (`relay_giaddr_linux.go`), records each address's `IFA_F_SECONDARY` flag,
  and `selectPrimaryIPv4` (`relay.go`) prefers the first non-secondary
  address. `net.Interface.Addrs()` drops the secondary flag, so a portable
  fallback (used only when netlink fails, and on non-Linux) cannot distinguish
  them and reports every address as primary — preserving the historical
  first-address behavior. Picking a secondary alias as `giaddr` would make the
  upstream server lease from the wrong subnet pool. If netlink enumeration
  fails the resolver falls back to the portable lister rather than failing
  closed (a transient netlink hiccup must not strand a relay).
- Option 82 sub-option 1 (`circuit-id`) is set to the interface name **on
  first-hop requests only** (inbound `giaddr==0`); a chained request's
  downstream Option 82 is preserved untouched (#5071, see "Relay chaining"
  above). On the reply path Option 82 is stripped before forwarding to the
  client.
- Server addresses must be **literal IPs**. `Apply()` calls
  `net.ParseIP` and rejects hostnames; there is no DNS resolution
  path. To target a hostname, the operator must resolve it externally
  and put the IP in the config.
- **Kea / dhcp-relay coexistence on `:67`.** The Kea DHCP server
  (`pkg/dhcpserver`) and this relay are operationally mutually exclusive on
  a given interface's `:67` — Kea does not set REUSEPORT/BINDTODEVICE, so
  configuring both to bind the same port leaves one failing to bind. A
  commit-check that rejects this is a deferred follow-up.
- **VRRP-Backup duplicate relay (HA) — gated since #2456.** On a chassis
  cluster a relay on a VRRP **Backup** node also receives segment broadcasts;
  before #2456 both nodes relayed duplicate requests upstream. The per-packet
  `masterGate` (`Daemon.relayMasterGateOpen`, installed via
  `Manager.SetMasterGate`) now drops the client request on a node that is
  BACKUP for the relay interface's redundancy group, so only the MASTER
  relays — see "HA master-state gate (#2456)" above. Standalone and
  non-RG-owned interfaces still always relay. Changes here must pass
  `make test-failover`.
