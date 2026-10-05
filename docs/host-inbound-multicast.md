# Host-bound routing multicast admission (#4455, HI-1)

This document records the active host-bound **multicast** admission behavior,
the protocol→multicast-group catalog, and the managed-routing migration gate.
The catalog is an enforcement input shared by the Go/kernel nft builders and
the Rust AF_XDP classifier; this is no longer a deferred design artifact or an
advisory-only feature.

## Enforcement behavior

The Go text oracle and netlink installer enforce the same per-ingress rule:
catalog multicast is admitted only when the packet arrives on an unambiguous
zone interface whose effective `host-inbound-traffic protocols` set includes
the token that owns the exact destination group and protocol tuple. Interface
overrides replace the zone-level protocol set. Matching is independent of
firewall-local unicast addresses, so an addressless but configured ingress is
still gated.

Each catalog group has a default-deny rule. A wrong group, family, IP protocol,
ICMP type, or transport is denied; catalog traffic on unzoned or ambiguous
ingress is denied as well. Non-catalog destinations retain their existing
host-inbound behavior. The userspace classifier receives the actual destination
IP at host-delivery decisions, including the GRE outer path, and applies the
same group/family/protocol/token decision.

Explicit `to-zone junos-host` fine-policy denies run before the coarse multicast
gate, while the multicast guard itself precedes the residual established /
related accept so conntrack cannot bypass the current zone decision. Existing
global ND, PMTUD/error, and ESP/AH exceptions and the explicit
`system-services any-service` wildcard retain their established behavior.

The gate applies to the catalog below; it does not change DHCP, which uses a
different destination and delivery path (see the DHCP sibling section).
Host-bound routing multicast is therefore no longer packet-wide via the
input-chain `policy accept` fall-through.

## Managed-routing commit gate

The strict compiler gate cross-checks the interfaces xpf renders into FRR for
OSPFv2, OSPFv3, and RIP (global and routing-instance protocols) against the
effective `host-inbound-traffic protocols` set for each interface in a
security zone. A strict commit is rejected when that set omits the matching
token (`ospf`, `ospf3`, or `rip`); `all` and an effective interface override
that includes the token satisfy the gate. The error identifies the interface
and zone and directs the operator to add the missing admission.

Tolerant load / peer-sync follows the #1960 no-brick path: it keeps the
configuration bootable and records a warning, but the packet remains
default-denied until the protocol is explicitly admitted. This avoids silently
breaking a managed routing daemon on strict commit without re-opening the
multicast path on tolerant loads.

Zone attribution and effective-token resolution reuse the dataplane's existing
helpers (`zoneIfaceLogicalKeys` and
`ZoneConfig.InterfaceHostInboundEffective`), including bare-member unit
expansion, interface-override replacement, and physical-parent inheritance.
There is no longer a packet-wide multicast advisory for compliant zones.
BGP/LDP/MSDP are unicast and PIM is unmanaged, so those protocols have no
managed FRR interface source for this cross-check; their catalog groups are
still enforced by the dataplane gate.

## The DHCP-server sibling (#6460)

The DHCP server remains a separate #6460 admission issue. The managed-routing
gate cross-checks routing-protocol tokens against FRR, while the DHCP server is
neither a routing protocol nor rendered into FRR. A separate advisory
(`validateDHCPServerHostInboundBypassWarnings`,
`pkg/config/compiler_validate_warn_dhcp_hostinbound.go`) warns when a DHCP
server binds an interface whose zone's effective `host-inbound-traffic
system-services` set omits `dhcp` / `dhcpv6`.

The two DHCP families bypass enforcement for **different** reasons, and the
message names the relevant path:

| Family | Why the zone token does not bound it |
|---|---|
| DHCPv4 (`dhcp`) | **Two planes, both bypassed (#7489).** (1) A client addresses its DISCOVER/REQUEST to the **255.255.255.255 broadcast**, and `should_fallback_early` (`userspace-xdp/src/lib.rs`) hands `dst_v4 == 0xffff_ffff` straight to the kernel — the request never enters the AF_XDP userspace dataplane or its host-inbound gate. (2) xpf renders Kea's `Dhcp4` with **no** `dhcp-socket-type` key (`pkg/dhcpserver/dhcpserver.go` emits `interfaces-config` with an `interfaces` list and nothing else), so Kea's default `raw` applies and the server receives on an **AF_PACKET** socket, delivered **before** the netfilter input hook. |
| DHCPv6 (`dhcpv6`) | Kea's `Dhcp6` has no raw mode, but a client addresses the server at **ff02::1:2**. This DHCP group is not in the routing-multicast catalog, so the routing group gate does not match it; it retains the separate DHCPv6 path and advisory described above. |

The remedy in the message deliberately leads with **removing the interface from
the group**, not with adding the token: adding the token cannot enforce anything
on the DHCP server's request path (both planes above are bypassed), so presenting
it as *the fix* would restate the same false signal in a new place. The token is
offered only as a way to record that the segment is meant to be served.

### Scope of the bypass argument — do not generalise it (#7489)

"The AF_PACKET tap is upstream of netfilter" is an argument about **one** plane,
and it does **not** establish that a host-inbound token is inert for v4 traffic
at large. The AF_XDP userspace dataplane enforces host-inbound itself,
**fail-closed**, on the local-delivery path (`host_inbound_gated_lo0_action`,
`userspace-dp/src/afxdp/poll_descriptor/filter.rs`), and a packet dropped there
never reaches the kernel on any device — so an AF_PACKET tap cannot see it.

**Measured** on the loss userspace cluster: 20 unicast datagrams to an
interface-mode-SNAT address, on a port the arrival zone did not admit, produced
**+22 host-inbound denies and ZERO packets on `tcpdump -ni any`**, with a
same-host ping (which the zone *does* admit) answering normally.

What decides which plane applies is the **destination**, not the port. On a
session miss the shim steers on address alone — `should_fallback_early`, then
`is_local_destination`, which deliberately returns false for an address in
`USERSPACE_INTERFACE_NAT_V4` ("the common WAN case"). So:

| v4 destination | plane | host-inbound token |
|---|---|---|
| `255.255.255.255` (DHCP DISCOVER) | kernel, via the shim's early fallback | inert — this advisory's subject |
| ordinary local unicast | kernel, via `is_local_destination` | inert on the userspace plane |
| unicast to an **interface-mode-SNAT** address | **redirected to the AF_XDP dataplane** | **load-bearing, fail-closed** |
| **subnet-directed broadcast** (`192.168.1.255`) | redirected to the AF_XDP dataplane, then **dropped** — never locally delivered | inert: the packet never reaches the gate |

**The fourth row is the #8061 asymmetry, and it is deliberate.** A
subnet-directed broadcast is none of `should_fallback_early`'s three classes
(`0xffff_ffff`, multicast, link-local), so unlike the limited broadcast it is
NOT handed to the kernel — it enters the AF_XDP dataplane. It does not,
however, reach local delivery: every `LocalDelivery` return site is gated on
membership the address cannot have. `fib.rs`'s arm requires `local_tables_v4` /
`local_nat_any_table_v4`, populated from each interface's HOST address
(`forwarding_build/interfaces.rs`, `local_v4.insert(v4.addr())`);
`forwarding/local_delivery.rs` requires `iface.primary_v4 == Some(ip)`;
`poll_stages.rs`'s site is the IPsec passthrough decision and is not
address-derived. The only residual path is an operator configuring the
directed broadcast as a **DNAT external**, which is a deliberate act.

So the consequence chain one would expect — L2-less delivery on `xpf-usp0`,
invisible to an `AF_PACKET` consumer on the physical NIC, and subject to the
fail-closed host-inbound gate — **does not occur**: the packet is dropped
before local delivery, so the gate is never consulted.

Nor is there a consumer to harm. The product's three `AF_PACKET` consumers each
take a different class: the DHCP client (`pkg/dhcp`, nclient4/nclient6) uses the
limited broadcast, which early-falls-back; VRRP (`pkg/vrrp`) uses multicast
224.0.0.18 / ff02::12, likewise; and the HA ARP probe is EtherType 0x0806, which
never reaches the AF_INET arm at all.

This is not an oversight but the **advertised** state of a knob. `family inet
targeted-broadcast` — Junos's directed-broadcast forwarding — is a real config
leaf that is ACCEPTED-ONLY and not enforced by the runtime (#4308), and a
commit-time advisory tells the operator so: *"configured but accepted-only —
typed and stored but not enforced by the runtime yet (parity, #4308)"*, guarded
by `TestInterfaceParityKnobsAdvisory_4308`. An operator who wants directed
broadcasts forwarded is told at commit that they are not.

The third row is not this advisory's subject, but the sentence above was being
read as covering it. A DHCP **client** on such an interface receives its
RENEWING-state ACK as a unicast to that address; whether that specific frame
loses its lease when the token is absent was **not** measured and is not claimed
here.

### The userspace gate is DENY-ONLY for an AF_PACKET consumer (#7318)

A ceiling worth stating before someone designs into it. The AF_XDP gate looks
like a general enforcement point for host-bound traffic, and for a service that
reads from a kernel **socket** it is. For a service that taps the **physical
device** with `AF_PACKET` — Kea's Dhcp4 on the default `raw` is exactly this —
it can only ever DENY.

The asymmetry is in the delivery mechanism, not the gate. A DENIED packet is
dropped in the worker and reaches the kernel on no device, so an AF_PACKET tap
cannot see it (the measurement above: +22 denies, zero on `tcpdump -ni any`).
But an ADMITTED packet is not passed through on its ingress NIC — local delivery
is a `write()` into the TUN device `xpf-usp0`, opened `IFF_TUN | IFF_NO_PI`,
carrying a **bare L3 packet with the Ethernet header stripped**
(`userspace-dp/src/afxdp/tx/dispatch/slow_path.rs`, `userspace-dp/src/slowpath.rs`).
A raw-socket consumer bound to `ge-0-0-1` therefore never sees it: wrong device
for `packet_rcv`'s filter, and no L2 header for a filter that reads the
ethertype at offset 12 — which Kea's LPF does, as its first test.

The practical consequence: routing DHCPv4 into the dataplane so the gate can
*admit* it would not gate DHCP, it would take the server off the air. Any
proposal to enforce host-inbound for a raw-socket service has to be a
deny-side-only change, leaving the admit path exactly as it is.

The DHCP warning continues to use the same zone-attribution and effective-
admission helpers, but it remains WARN-only because DHCP's delivery paths are
not governed by the routing-multicast gate. The #1960 no-brick treatment for
managed routing is implemented separately by the strict-commit / tolerant-load
gate above.

**The DHCP server's bypass is not repaired by routing-multicast enforcement.**
The v6 leg's `ff02::1:2` group is not a catalog entry. The v4 leg reaches Kea's
default `raw` socket through the broadcast / AF_PACKET path before the netfilter
input hook; an input-chain drop cannot constrain a consumer that receives on
that earlier path (#7318 measured the INPUT drop while Kea still answered).

#7318 shipped the opt-in half: `system services dhcp-local-server
dhcp-socket-type udp` moves Dhcp4 onto a UDP socket that does traverse the
input hook, at which point the per-zone `dhcp` token governs the server path
with no Component A required — because on UDP Kea does not receive broadcast
at all, so the broadcast-specific accept fall-through has no DHCP listener
behind it. The DEFAULT is unchanged (`raw`), because udp serves relayed and
renewing clients only and stops serving directly-attached address-less clients;
that is a deployment choice, not a bug fix. Whether the default should ever flip
is still open and deliberately unprejudiced.

## Protocol → multicast-group catalog

The single source of truth is `hostInboundMulticastCatalog` in
`pkg/config/host_inbound_multicast.go`. Only protocols whose host-bound **control
traffic** rides a well-known multicast group are listed; unicast routing control
(BGP TCP/179, LDP, MSDP, BFD to a peer address) and L2/non-IP protocols (IS-IS)
are deliberately absent. Family split mirrors `HostInboundProtocolFamily`.

| `protocols` token | IPv4 group(s) | IPv6 group(s) | Notes |
|---|---|---|---|
| `ospf`  | `224.0.0.5`, `224.0.0.6` | — | OSPFv2 AllSPFRouters / AllDRouters (IP proto 89) |
| `ospf3` | — | `ff02::5`, `ff02::6` | OSPFv3 (IP proto 89, IPv6) |
| `rip`   | `224.0.0.9` | — | RIPv2 (UDP 520) |
| `ripng` | — | `ff02::9` | RIPng (UDP 521) |
| `pim`   | `224.0.0.13` | `ff02::d` | ALL-PIM-ROUTERS (IP proto 103), dual-family |
| `igmp`  | `224.0.0.1`, `224.0.0.22` | — | all-hosts / IGMPv3 reports (IP proto 2), IPv4 only |
| `dvmrp` | `224.0.0.4` | — | ALL-DVMRP-ROUTERS, carried inside IGMP (IP proto 2), IPv4 only |
| `vrrp`  | `224.0.0.18` | `ff02::12` | VRRP (IP proto 112), dual-family |
| `router-discovery` | `224.0.0.1`, `224.0.0.2` | — | IRDP advertisements / solicitations (IPv4); the IPv6 equivalent is ND RS/RA, already in the always-accepted set |

`protocols all` expands (via `HostInboundAllExpansionProtocols`, #3199) to the
routing-protocol set including every catalog member above. Those tokens produce
the corresponding group/protocol tuples, so `all` admits only the catalog
groups belonging to its expanded protocols.

## Enforcement contract (#11571)

1. **Ingress-zone scope.** Kernel rules use the ingress `iifname` (or the
   equivalent VRF slave scope) together with the catalog group and protocol
   tuple. Zone-level and interface-override rules use their effective protocol
   set; ambiguous and unzoned ingress has no allow rule and falls into the
   catalog-group deny.

2. **Default-deny catalog groups.** For every catalog group, only the exact
   family/group/protocol tuple admitted by that ingress zone is accepted.
   Addressless ingress views are still included. Non-catalog traffic keeps its
   existing behavior; explicit global control exceptions and the documented
   `any-service` wildcard are preserved.

3. **Policy and conntrack ordering.** Explicit `to-zone junos-host` fine-policy
   decisions run before multicast admission. The multicast accept/drop rules
   run before residual established/related accepts so an old conntrack entry
   cannot bypass a changed zone decision.

4. **Failure paths.** A cold-boot host-inbound fence denies catalog multicast
   when the main table is unavailable. Persistent DHCP backstops are limited to
   `meta pkttype host`, so they cannot shadow MLD, other multicast, broadcast,
   or non-unicast fall-through. The additive coverage-gap fence likewise leaves
   retained-main-table multicast policy authoritative; it adds no broad ACCEPT.

5. **Kernel/Rust lockstep.** The Go catalog
   (`pkg/config/host_inbound_multicast.go`), zone-view construction
   (`pkg/dataplane/userspace/zones_host_inbound.go`), nft text/netlink builders,
   and Rust destination-aware classifier
   (`userspace-dp/src/afxdp/forwarding/host_inbound.rs`) enforce the same
   catalog tuples. Regression tests cover both families, overrides, default
   denies, and builder ordering.

## See also

- `docs/host-inbound-service-matrix.md` — the per-token service/protocol matrix
  and the sibling #3226 `system-services all` SCOPING advisory (which warns
  that `all` stopped admitting packet-wide).
- `pkg/config/host_inbound_tokens.go` — the recognized-token allowlist, family
  maps, and per-tuple L4 match SSOT.
- `pkg/config/compiler_validate_warn_dhcp_hostinbound.go` — the #6460
  DHCP-server sibling advisory described above.
- `pkg/dhcpserver/README.md` — the Kea render, including the AF_PACKET
  socket-type default that leg turns on.
