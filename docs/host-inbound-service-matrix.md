# Host-Inbound Service-Port Matrix

Authoritative, operator-facing map of every `security zones <zone>
host-inbound-traffic { system-services ...; protocols ...; }` token to the exact
ports / protocols it opens on the firewall, across all three enforcement
surfaces. This is the single reference so future audits stop re-deriving the
port sets from source (folds codex-review-002 M07/M08 and L02/L03/L07/L16/L19;
issue #3619).

## The three surfaces

Host-inbound admission is enforced (and validated) in three independent places
that MUST agree on the token set:

1. **Go SSOT — recognized-token allowlist + address family + structured
   token→tuple table.** The set of meaningful tokens, their address-family
   scoping, and (since #3627 B1a) their structured `(proto, ports, icmp-type)`
   tuples. Commit-time validation hard-rejects any token outside it (#3200).
   - `config.KnownHostInboundSystemServices` — `pkg/config/host_inbound_tokens.go`
   - `config.KnownHostInboundProtocols` — same file
   - `config.HostInboundServiceFamily` / `config.HostInboundProtocolFamily` —
     family scoping (`ip` = IPv4-only, `ip6` = IPv6-only, absent = dual)
   - `config.HostInboundL2Protocols` / `config.HostInboundAllExpansionProtocols()`
     — `protocols all` expansion minus L2/non-IP tokens
   - `config.HostInboundServiceMatch` / `config.HostInboundProtocolMatch`
     (`[]config.L4Match{Proto, Ports, ICMPType, Reject}`) — the STRUCTURED
     token→tuple SSOT added in #3627 B1a. The nft kernel mirror (surface 2) now
     RENDERS its match fragments from this table rather than carrying a parallel
     hard-coded copy, and the `request security match-policies` host-inbound
     classifier (surface 4) MATCHES queries against it. Before #3627 the Go SSOT
     declared only the token allowlist and family, and the port sets lived only
     on surfaces 2 and 3 as hand-mirrors; now surface 2 is a render of this
     table, and surface 3 (Rust) remains a hand-mirror pending the deferred
     per-tuple parity test.

2. **nft kernel mirror — PRIMARY enforcement.** Host-bound traffic to a
   firewall interface IP / VRRP VIP is shunted to the kernel by the XDP shim
   before it reaches userspace-dp, so the nftables `inet xpf_hostinbound` chain
   carries ~100% of real host-inbound traffic. Since #3627 B1a the per-token
   match fragments are RENDERED from the surface-1 structured SSOT
   (`renderHostInboundMatches`), byte-identical to the pre-#3627 strings
   (`TestHostInboundNftRenderGoldenByteIdentical`).
   - `hostInboundServiceMatches` — `pkg/daemon/daemon_nft.go` (services; renders
     `config.HostInboundServiceMatch`)
   - `hostInboundProtocolMatches` — same file (protocols; renders
     `config.HostInboundProtocolMatch`)
   - `hostInboundServiceAction` — same file (ident-reset reject verdict)
   - global always-accepts — `buildHostInboundFilterPayload`, same file

3. **Rust AF_XDP classifier — SECONDARY enforcement.** The XSK
   local-delivery path, reached only by the subset of host-bound traffic that
   arrives on the AF_XDP fast path (e.g. DNAT/static-NAT to a firewall-local
   address). The IPsec passthrough stage (`stage_ipsec_passthrough_check`) is
   likewise scoped to a firewall-local destination since #5620: it claims the
   kernel-XFRM passthrough short-circuit ONLY when `flow.dst_ip` is an address
   the firewall owns (`owns_configured_ip`), so a TRANSIT ESP/AH/IKE packet
   routed to a remote host falls through to transit zone policy instead of
   being reinjected to the local XFRM stack (codex-review-181 M03).
   - `classify_system_service` / `classify_protocol` —
     `userspace-dp/src/afxdp/forwarding/host_inbound.rs`
   - `is_icmp_host_inbound_global_accept` — same file (global ICMP/ND accepts)

4. **match-policies host-inbound classifier — DIAGNOSTIC (not enforcement).**
   The `request security match-policies` simulator names WHICH host-inbound token
   admits a queried host-bound tuple (#3627 B1a). It does not enforce; it reads
   the surface-1 structured SSOT and mirrors the surface-2 global accepts so its
   report cannot drift from what the kernel opens.
   - `ClassifyHostInbound` / `hostInboundGlobalAccept` —
     `pkg/dataplane/userspace/host_inbound_classify.go`
   - wired into `pkg/policymatch` as `Result.HostInbound`

**Drift guards.** The token *sets* are pinned in lockstep by
`config.TestHostInboundRustClassifierMatchesGoSSOT` (`pkg/config/host_inbound_rust_parity_test.go`,
#3486 — parses the Rust source and asserts its match arms equal the Go SSOT) and
`TestHostInboundNftMatchesKnownTokens` (`pkg/daemon/host_inbound_parity_test.go`,
#3200 — asserts the nft matcher's domain equals the SSOT). The *port sets* for
deliberately-narrow tokens (sip, tftp, traceroute, bfd, the #3341 routing
protocols) are additionally pinned by fail-on-revert assertions in
`pkg/daemon/host_inbound_parity_test.go` so an accidental widen turns RED. Since
#3627 B1a the nft match fragments are RENDERED from surface 1 and pinned
byte-identical by `TestHostInboundNftRenderGoldenByteIdentical`
(`pkg/daemon/host_inbound_ssot_render_3627_test.go`); the structured tuples
themselves are pinned by `config.TestHostInboundServiceMatchTuples` /
`TestHostInboundProtocolMatchTuples`. A per-tuple parity test between the Rust
classifier (surface 3) and the structured SSOT (surface 1) is a deferred
follow-up; until it lands, surface 3 stays a hand-mirror held by the set-level
`TestHostInboundRustClassifierMatchesGoSSOT`.

## system-services matrix

| Token (aliases) | nft match (`daemon_nft.go`) | Rust admit (`host_inbound.rs`) | Family | Notes |
|---|---|---|---|---|
| `all` | union of every row in this table EXCEPT `gre` and `r-exec`/`rexec` | same union (`system_service_all_expansion`) | per expanded token | **#3226:** expands to the named system-services — NOT a packet-wide admit and NOT a full-admit boolean. The zone keeps its catch-all drop, so raw IP protocols (GRE/OSPF/PIM/VRRP/future proto numbers) and unlisted ports are DENIED unless listed explicitly. ESP/AH are the exception: they keep an unconditional global accept (see the ESP/AH row), so they are NOT denied by this change. The expanded `ident-reset` keeps its RESET verdict. See [`system-services all` is the named-service union](#system-services-all-is-the-named-service-union-3226). |
| `any-service` | full admit | `all_services = true` | dual | Blanket accept for the zone — a **packet-wide** admit of EVERY IP protocol/port. Junos defines `any-service` as "all system services on an entire port range including the system services that are not defined"; xpf reads it as the (wider) packet-wide superset. `config.HostInboundFullAdmitService` is the SSOT; `ValidateConfig` emits a commit-time advisory naming the zone/interface. See [`system-services all` is the named-service union](#system-services-all-is-the-named-service-union-3226). |
| `ssh` | tcp 22 | tcp 22 | dual | |
| `telnet` | tcp 23 | tcp 23 | dual | |
| `ftp` | tcp 21 | tcp 21 | dual | Control port only; FTP data is an ALG/transit concern. |
| `http` / `webapi-clear-text` | tcp 80 | tcp 80 | dual | Web-management HTTP. The admit port is the canonical Junos J-Web port (`webmgmt.HTTPPort` = 80) and EQUALS the actual listener bind (#5715): `resolveAPIBinds` binds an explicitly-configured `web-management http` on TCP/80, not the pre-#5715 8080. Listener↔admit are one contract (`webmgmt` SSOT), guarded by `TestWebMgmtListenerMatchesHostInboundAdmit_5715` + the Go/Rust port-parity `TestHostInboundRustWebPortsMatchSSOT_5715`. |
| `https` / `webapi-ssl` | tcp 443 | tcp 443 | dual | Web-management HTTPS. Admit port = `webmgmt.HTTPSPort` = 443 = the listener bind (#5715, was 8443). Same contract as `http` above. |
| `ping` | icmp/icmpv6 echo-request | ICMP type 8 (v4) / 128 (v6) | dual | Echo-request only; ICMP errors are global-accepted (see below). |
| `dns` | udp 53, tcp 53 | udp 53, tcp 53 | dual | |
| `dhcp` / `bootp` | udp {67, 68} | udp 67, 68 | **ip (v4)** | DHCPv4; must not open on v6 (#3225). **Junos accepts these two per INTERFACE only**; since #7490 a zone-level token is WITHHELD from a DHCP server/relay interface and retained elsewhere — see [DHCP and BOOTP are per-interface only in Junos (#6519)](#dhcp-and-bootp-are-per-interface-only-in-junos-6519). |
| `dhcpv6` | udp {546, 547} | udp 546, 547 | **ip6** | DHCPv6; v6-only (#3225). |
| `ntp` | udp 123 | udp 123 | dual | |
| `snmp` | udp 161 | udp 161 | dual | |
| `snmp-trap` | udp 162 | udp 162 | dual | |
| `ike` / `ipsec` | udp {500, 4500} | udp 500, 4500 | dual | `ipsec` is an ALIAS of `ike` (L03). Raw ESP(50)/AH(51) are global-accepted (nft) / handled by `stage_ipsec_passthrough_check` (Rust), so `ipsec` is effectively a superset of `ike`. |
| `tftp` | udp 69 | udp 69 | dual | **UDP 69 only (M08). Data ports are ALG/transit, not host-inbound — matches vSRX.** See disposition. |
| `netconf` | tcp 830 | tcp 830 | dual | |
| `ssh-netconf` / `netconf-ssh` | tcp {22, 830} | tcp 22, 830 | dual | |
| `finger` | tcp 79 | tcp 79 | dual | |
| `ident-reset` | tcp 113 → **reject with tcp reset** | **drop** (no admit) | dual | **Cross-surface divergence (#3310):** nft actively RESETs TCP/113; the AF_XDP secondary path drops it. See divergences. |
| `lsping` | udp 3503 | udp 3503 | dual | |
| `sip` | udp 5060, tcp 5060 | udp 5060, tcp 5060 | dual | **UDP+TCP 5060 only (M07). SIP-over-TLS (TCP 5061) is NOT admitted — matches vSRX.** See disposition. |
| `r-login` / `rlogin` | tcp 513 | tcp 513 | dual | |
| `r-sh` / `rsh` | tcp 514 | tcp 514 | dual | |
| `r-exec` / `rexec` | tcp 512 | tcp 512 | dual | **xpf EXTENSION — excluded from `all` (#3226).** Juniper's host-inbound service list (zone-level and interface-level) documents `rlogin` and `rsh` but NOT rexec, and unlike the port-neutral xpf spellings (`webapi-*` → the http/https ports, `ssh-netconf` → ssh ∪ netconf) tcp/512 is opened by no other token — so folding it into `all` widened the union past the Junos meaning. Listed explicitly it still opens 512. Member of `config.HostInboundNonJunosSystemServices`. |
| `reverse-telnet` | tcp 2900 | tcp 2900 | dual | Console-server reverse Telnet. 2900 is a PLATFORM DEFAULT: `junos-es-conf-system` 24.4R2 `[edit system services reverse telnet] port` carries an explicit YANG `default "2900"`. #3226 fold. |
| `reverse-ssh` | tcp 2901 | tcp 2901 | dual | Console-server reverse SSH. 2901 is a PLATFORM DEFAULT: same module, `[edit system services reverse ssh] port`, YANG `default "2901"`. #3226 fold. |
| `lsselfping` | udp 8503 | udp 8503 | dual | LSP Self-Ping (RFC 7746). Port is STANDARDS-ASSIGNED: §3 "The UDP Destination Port MUST be lsp-self-ping (8503)", §6 records the IANA assignment. Distinct from `lsping` (udp 3503, MPLS echo) despite the similar name. #3226 fold. |
| `r2cp` | *(none)* | *(none)* | dual | Radio-Router Control Protocol. no admit tuple — see [Junos services xpf admits nothing for](#junos-services-xpf-admits-nothing-for). #3226 fold. |
| `rpm` | *(none)* | *(none)* | dual | Real-time Performance Monitoring probe RECEIVER. no admit tuple — see [Junos services xpf admits nothing for](#junos-services-xpf-admits-nothing-for). #3226 fold. |
| `tcp-encap` | *(none)* | *(none)* | dual | TCP encapsulation for IPsec (Juniper Secure Connect). no admit tuple — see [Junos services xpf admits nothing for](#junos-services-xpf-admits-nothing-for). #3226 fold. |
| `appqoe` | *(none)* | *(none)* | dual | AppQoE ACTIVE probe (SD-WAN SLA measurement). no admit tuple — see [Junos services xpf admits nothing for](#junos-services-xpf-admits-nothing-for). #3226 fold. |
| `high-availability` | *(none)* | *(none)* | dual | Multinode High Availability (MNHA) inter-node control over the interchassis link. no admit tuple — see [Junos services xpf admits nothing for](#junos-services-xpf-admits-nothing-for). #3226 fold. |
| `xnm-clear-text` | tcp 3221 | tcp 3221 | dual | JUNOScript clear-text. |
| `xnm-ssl` | tcp 3220 | tcp 3220 | dual | JUNOScript over SSL. |
| `traceroute` | udp 33434-33523 | udp 33434..=33523 | dual | **UDP probe range only (L07/L16).** UDP-only per #3368; ICMP time-exceeded replies ride the global ICMP-error accept. |
| `gre` | meta l4proto 47 | ip protocol 47 | dual | GRE listed as a system-service by some configs (repo HA cluster wan zone). |

## protocols (routing) matrix

| Token | nft match (`daemon_nft.go`) | Rust admit (`host_inbound.rs`) | Family | Notes |
|---|---|---|---|---|
| `all` | expansion (routing set minus L2) | `routing_protocol_all_expansion()` | dual | Expands to every routing protocol EXCEPT L2 (IS-IS). NOT a blanket accept — does NOT open system-services (#3199). |
| `ospf` | meta l4proto 89 | ip proto 89 | **ip** | OSPFv2, IPv4 (#3225). |
| `ospf3` | meta l4proto 89 | ip proto 89 | **ip6** | OSPFv3, IPv6 (#3225). Same proto 89, different family. |
| `bgp` | tcp 179 | tcp 179 | dual | |
| `rip` | udp 520 | udp 520 | **ip** | RIPv2, IPv4 (#3225). |
| `ripng` | udp 521 | udp 521 | **ip6** | RIPng, IPv6 (#3225). |
| `igmp` | meta l4proto 2 | ip proto 2 | **ip** | IPv4 group membership; v6 equivalent is MLD over the global ND accept (#3225). |
| `pim` | meta l4proto 103 | ip proto 103 | dual | |
| `vrrp` | meta l4proto 112 | ip proto 112 | dual | |
| `bfd` | udp {3784, 3785, 4784} | udp 3784, 3785, 4784 | dual | Single-hop control (3784) + echo (3785) + multi-hop control (4784, RFC 5883) (#3299). |
| `ldp` | tcp 646, udp 646 | tcp 646, udp 646 | dual | |
| `msdp` | tcp 639 | tcp 639 | dual | |
| `nhrp` | meta l4proto 54 | ip proto 54 | dual | |
| `rsvp` | meta l4proto 46 | ip proto 46 | dual | #3341. |
| `pgm` | meta l4proto 113 | ip proto 113 | dual | #3341. Distinct from ident-reset's `tcp dport 113` (this is IP protocol 113). |
| `sap` | udp 9875 | udp 9875 | dual | #3341. |
| `dvmrp` | meta l4proto 2 | ip proto 2 | **ip** | #3341. Carried inside IGMP; IPv4-only, like `igmp`. |
| `isis` | (none) | (none) | **L2/none** | Recognized but no IP match on either surface (L2/OSI-CLNP). Kernel hands IS-IS PDUs to FRR's isisd via an LLC socket, outside the IP host-inbound filter. Excluded from `protocols all` (#3311). |
| `router-discovery` | v4: `icmp type { 9, 10 }`; **v6: (none)** | v4 ICMP types 9, 10 | v4 per-zone; **v6 global** | **L02:** on IPv6, RS/RA (133/134) ride the always-accepted ND global set, so this token carries NOTHING on v6 — correct kernel parity, but a CLI/doc trap. |

## `system-services all` is the named-service union (#3226)

`system-services any-service` is now the ONLY `system-services` token that is
not a per-tuple match. It sets one boolean (`all_services` in `host_inbound.rs`;
`hostInboundAllowsAll` in `daemon_nft.go`) that short-circuits admission to
accept EVERY IP protocol and port destined to the zone's local firewall
addresses — GRE, ESP/AH, OSPF, PIM, VRRP, and any future protocol number — with
**no** catch-all drop. `config.HostInboundFullAdmitService`
(`pkg/config/host_inbound_tokens.go`) is the SSOT for which tokens are
full-admit; since #3226 it matches `any-service` alone.

### What `all` means now

Junos defines the two tokens differently, and xpf follows that split:

| Token | Junos definition (`system-services`, Security Zones Host Inbound Traffic) | xpf behaviour |
|---|---|---|
| `all` | "Traffic from the defined system services available on the Routing Engine." | Expands to the union of the **named** system-services in the matrix above (`config.HostInboundAllExpansionServices` / Rust `system_service_all_expansion`), then falls through to the per-match path — so the zone keeps its **catch-all drop**. |
| `any-service` | "All system services on an entire port range including the system services that are not defined." | Packet-wide full admit (a superset of the Junos entire-port-range reading — the fail-safe direction for a token whose purpose is to over-admit). |

Junos's documented system-service list contains **no raw IP protocol**:
GRE/OSPF/PIM/VRRP are reached through `protocols`, or not at all. So a
Junos-correct `all` never opens a bare protocol number. Before #3226 xpf aliased
`all` to the packet-wide admit, which accepted every IP protocol to a zoned
firewall address and emitted no deny at all — a fail-OPEN relative to Junos that
could mask a missing explicit `protocols` entry.

This mirrors exactly what #3199 did to the sibling `protocols all` (scoped to
the routing-protocol set rather than a blanket accept), and reuses the same
mechanism: an SSOT expansion list plus a load-bearing exclusion set.

### `any-service` is a deliberate superset — narrowing it was rejected (#6618)

**Decision: xpf KEEPS the packet-wide reading of `any-service`.** #6618 proposed
narrowing it to the Junos reading (widen the TCP/UDP port range only; leave raw
IP protocols to `protocols`). That was considered and rejected. This section
records the decision so the question is not re-asked, and
`pkg/nftables/host_inbound_any_service_verdict_6618_test.go` binds it: the
single rule an `any-service` zone renders on the live netlink path carries no L4
discriminator and no drop behind it, so a narrowing turns that test RED and has
to be an explicit, reviewed flip rather than a quiet edit.

**What the vendor actually says.** Two statement pages, quoted verbatim:

| Statement | Juniper's words |
|---|---|
| `system-services any-service` | "All system services on an entire port range including the system services that are not defined." |
| `protocols all` | "Enable traffic from all possible protocols available. Use the except option to disallow specific protocols." |

Read carefully, the `any-service` sentence is **silent on IP protocols**, not
contradictory: its subject is "system services" — a vocabulary that is entirely
TCP/UDP/ICMP — and its widener is a *port* range. The claim that Junos DENIES
OSPF under `any-service` is therefore an inference from structure, not a quoted
rationale that reaches the case: Junos carries protocol traffic on a separate
`protocols` knob, whose own blanket token means the enumerated protocol list
(`bfd bgp dvmrp igmp ldp msdp nhrp ospf ospf3 pgm pim rip ripng
router-discovery rsvp sap vrrp`), so a `system-services` token that admitted
every protocol number would make the protocol-specific knob unreachable. The
inference is sound, and the direction of xpf's divergence — over-admit on an
opt-in token — is the fail-safe one. But it is an inference, and the disposition
below does not need it to be more.

**Why narrowing was rejected.**

- **It removes the only remaining escape, and nothing replaces it.** Junos
  itself has no way to admit an arbitrary IP protocol number host-inbound:
  `protocols all` means that enumerated list, and neither knob reaches SCTP,
  IPIP/6in4, L2TPv3, or a future protocol number. xpf already diverged
  deliberately once for this reason (the xpf-only `gre` system-service, see the
  two xpf-only carve-outs above) *because operator configs list it there*. Under
  a narrowed `any-service`, a zone terminating any other raw protocol on the
  firewall would have no token at all — and, as
  [The only escape is `any-service`](#the-only-escape-is-any-service) proves, an
  lo0 input filter cannot rescue a host-inbound deny on either enforcement path.
  A hard, unremediable blackhole is a worse outcome than an announced superset.
- **It retracts #3226's own migration path one release later.** The `all`
  scoping advisory tells the operator, in as many words, to `use "any-service"
  for the previous packet-wide admit`. Narrowing `any-service` next would break
  the same population a second time, and the second time with no remedy left.
- **The breadth is opt-in and already announced.** An operator must write the
  token, and `fullAdmitAdvice` (`pkg/config/compiler_validate_warn_host_inbound.go`) emits a
  commit-time advisory naming the stanza and the exact blast radius
  ("EVERY IP protocol/port (GRE/ESP/AH/OSPF/PIM/VRRP/future proto numbers) …
  a superset of Junos's per-service union"). The surprise #6618 is concerned
  with — an operator who reads the Junos page and expects port-range semantics —
  is what that advisory exists to prevent.

**What would reopen it.** A token (or an explicit `protocols` extension) that
gives a raw IP protocol its own admission path. With one, narrowing `any-service`
costs an operator nothing and should be revisited; without one, it only converts
an announced over-admission into a silent, unfixable denial.

### The union must equal Juniper's defined-service set — both directions

Scoping `all` to the recognized-token union is only Junos-correct if that union
is neither NARROWER nor WIDER than the set Juniper defines. Both directions are
enforced by `TestHostInboundAllUnionMatchesJunosSchema_3226`
(`pkg/config/host_inbound_tokens_test.go`).

#### The oracle is Juniper's YANG schema, not its prose pages

This union was wrong **three times** while the oracle was a list hand-copied out
of Juniper's `system-services` reference pages. Those pages are individually
incomplete and mutually inconsistent — between them they omit `lsping`, `sip`,
`appqoe`, `tcp-encap`, `lsselfping` and `high-availability` — so a test that
claimed to carry the list "verbatim" was in fact asserting against a set that had
never been the real one.

A fourth revision replaced that with a hand-copied list of tokens *extracted*
from the YANG. That was no better in kind — still a literal nobody could check,
and deleting a token from it (and from the implementation) stayed green.

So the module itself is **vendored whole** and the test does the extraction:

| | |
|---|---|
| Module | `junos-es-conf-security@2024-01-01.yang` (`junos-es` = the SRX/vSRX family) |
| Revision | `2024-01-01`, description `"Junos: 24.4R2.25"` |
| Groupings | `zone-system-services-object-type` and `interface-system-services-object-type` |
| Upstream | <https://github.com/Juniper/yang> |
| Vendored | `pkg/config/testdata/junos-es-conf-security@2024-01-01.yang.gz` (97 KB gzipped, 975 KB raw) |
| Parsed by | `pkg/config/host_inbound_tokens_test.go` |

Three gates make the derivation real rather than asserted:

1. **SHA-256 pin.** The decompressed module must hash to
   `3d03d81b…5d3bd70e`, byte-identical to the file Juniper publishes. Any edit
   to the vendored copy — including deleting a single `enum` — REDs. The pin is
   checkable by hand against upstream (`curl … | sha256sum`).
2. **Real extraction.** The test brace-matches the grouping body and reads its
   `enum` statements. Nothing is transcribed.
3. **Count pin.** The enumeration size (37) is pinned independently, so a
   deletion still REDs even if the hash pin were re-baselined in the same edit.

The zone-level / per-interface agreement is now **enforced** rather than
recorded in a comment: the test parses both groupings and fails if they differ,
which is what licenses one oracle to govern both surfaces. Release cross-checks
performed when the module was vendored: 25.4R1 enumerates the same 37 tokens;
20.4R1 enumerates 36 — identical except that `lsselfping` had not yet been
added. Nothing was ever removed.

**Narrower — the missing services.** `r2cp`, `reverse-ssh`, `reverse-telnet`,
`rpm`, `lsselfping`, `tcp-encap`, `appqoe` and `high-availability` are all in
Juniper's enumeration but were absent from xpf's recognized-token allowlist
entirely. That was a #3200-class parity gap on its own (a valid vSRX stanza was
hard-rejected at commit), and #3226 made it load-bearing: once `all` is the
recognized-token union, a service missing from that union is neither admitted by
`all` NOR nameable as an escape — strict validation rejects any token outside the
same allowlist — so its traffic is denied with no in-grammar remedy short of the
packet-wide `any-service`. All eight are now recognized and in the union.

The fail-OPEN direction is stated over **atomic (proto, port) openings**, not
over token names, so it survives a rename and catches any future xpf-only token
that opens something of its own. That is what keeps `r-exec`/`rexec` (tcp/512)
and `gre` (IP protocol 47) out while leaving the port-neutral aliases in.

### Junos services xpf admits nothing for

Five services in Juniper's enumeration are recognized (a valid vSRX stanza must
commit) and stay in the `all` union, but synthesize **no admission tuple** on any
enforcement surface — for two because Junos documents the port as
operator-chosen, for three because we could not find it. Those are different
statements and the doc keeps them apart. `config.HostInboundUnportedSystemServices` is the SSOT;
`HOST_INBOUND_UNPORTED_SERVICES` is the Rust mirror, held equal by the #3486
parity test.

#### This is a choice, not an inference

An earlier revision justified this by arguing that Juniper's YANG records a
`default` wherever a platform default exists, so its absence proved there was
none. **That generalization is false and has been withdrawn.** `[edit system
services telnet]` has no port leaf and no default either, yet telnet plainly has
a fixed wire tuple — and this very matrix maps it to TCP/23. The absence of a
configuration leaf says nothing about whether a service has a fixed listening
port.

What is actually true is narrower: for each service below we looked and did not
find an authoritative host-inbound listening tuple. That is a gap in our
knowledge. Under that gap there are two options:

- **Guess a port.** If wrong, it is wrong in *both* directions at once — it opens
  a port with no listener (real attack surface on every `all` zone) *and* still
  denies the port actually in use. Neither half is visible to the operator.
- **Open nothing.** Wrong in *one* direction — traffic Junos would admit is
  denied — but the failure is announced at commit, is recoverable without a code
  change, and never silently widens the host's exposure.

**xpf chooses to open nothing**, because that failure mode is one-directional,
visible and recoverable, and because a firewall is the wrong place to guess. If
an authoritative tuple is found for any service below, moving it out of this set
with the source recorded is a strict improvement and is expected.

These five are **not one class**, and the code does not pretend otherwise:
`config.HostInboundNoAdmitReason` labels each token, the two sets are held in
bijection by test, and the commit advisory words itself differently for each —
because the operator's situation differs.

#### Class 1 — operator-configured port (`HostInboundNoPortOperatorConfigured`)

Junos **documents** the listening port as chosen by the operator, over a range,
with no platform default. There is no "correct port" for xpf to admit — not
because we failed to find it, but because the service does not have one until the
operator configures it. **Restoring a port is not an available option here**; the
only choice is between a guess and nothing.

| Service | What it is | Evidence |
|---|---|---|
| `rpm` | RPM probe RECEIVER | **Best-evidenced member.** `[edit services rpm probe-server] tcp\|udp port` (`junos-es-conf-services` 24.4R2) is "Port number 7 through 65535", and Juniper's RPM receiver documentation describes the port as explicitly configured. The container is `presence`-gated, so with no configuration nothing listens. The port is genuinely per-deployment, not merely unfound. An earlier revision admitted tcp+udp/7 — the range FLOOR, not a default. |
| `r2cp` | Radio-Router Control Protocol | `[edit protocols r2cp] server-port` (`junos-es-conf-protocols` 24.4R2) is `range "1 .. 65535"`, i.e. operator-chosen. Transport is UDP by the sibling `client-port port-number` description ("UDP port number for R2CP clients") — *indirect*. **Not sourced:** a default listening port. udp/28762 appears only in `draft-dubois-r2cp-00`, which calls it a value prototypes *suggested*; Juniper adopts it nowhere. |

#### Class 2 — no authoritative tuple found (`HostInboundNoPortUnsourced`)

xpf could **not** find an authoritative host-inbound listening tuple. This is an
admission of ignorance, not a finding: the service may well have a fixed port we
did not locate. If one is found, moving the token out of the no-admit set with
the source recorded is a strict improvement and is expected.

| Service | What it is | Evidence, and what is NOT sourced |
|---|---|---|
| `tcp-encap` | IPsec-in-TCP (Juniper Secure Connect) | Transport is TCP. **Not sourced:** a default listening port. The closest Juniper evidence is the sample output of `show security tcp-encap connection detail`, whose "Local Gateway" (the SRX side) is `10.4.0.2:443` in one session and `10.4.0.2:500` in another — the vendor's own example shows **two** listening ports, and its Output Fields table never documents the port component. `[edit security tcp-encap]` exposes only `profile`/`ssl-profile`/`log`/`traceoptions`; `services ssl termination profile` has no port option and no default either (an earlier revision inferred the port from that profile — withdrawn). TCP/443 is *convention*: the NCP Path Finder **client** guide describes falling back to "TCP encapsulation of IPsec with SSL header (via port 443)", but that is the client vendor describing client behaviour, and Juniper's own Secure Connect guide never mentions 443. A sample plus a third-party convention is not a default. **Operator note:** TCP/443 is already in the `all` union via `https`/`webapi-ssl`, so the observable gap is the non-443 case (e.g. the TCP/500 the same sample shows). |
| `appqoe` | AppQoE ACTIVE probe | **Not sourced:** transport or port. Juniper describes the active probe only as *"custom packets are sent between spoke and hub points on all the multiple routes"*; `active-probe-params` exposes probe-count, probe-interval, data-fill, data-size, dscp-code-points, enable-sla-export, per-packet-loss-timeout, forwarding-class and loss-priority — no port, no transport — and `show … sla active-probe-statistics` reports addresses and timings with no port column. **Decoy:** udp/36000 is the only port on the AppQoE page and belongs to the *passive* probe; the Limitations section says *"An input firewall filter is required at the non-WAN interfaces to discard UDP packets with UDP destination port 36000."* That is TRANSIT traffic Juniper tells operators to DISCARD — admitting it host-inbound would be doubly wrong. |
| `high-availability` | Multinode HA (MNHA) inter-node control over the ICL | **Juniper explicitly acknowledges a protocol and port exist and declines to publish them.** The MNHA preparation guidance says the ICL *"path uses (whether the ICL is encrypted or not) IP address, protocol, and port details. You must ensure that this communication is allowed between the nodes if any firewall or other inspection is in place."* That is the entire published statement — no numbers appear anywhere. A sweep of the full Junos High Availability User Guide found 12 config examples using this token and not one port; every TCP/UDP port in the book belongs to the generic BFD chapters, not MNHA. `show chassis high-availability information`/`peer-info` carry peer IP, interface, routing-instance and encryption state — no port field. **Do not attribute udp/500+4500 or ESP here:** those belong to the *optional* `ha-link-encryption` and are admitted through the separate `ike` token Juniper's own examples configure alongside this one. *Mitigation:* xpf does not implement MNHA. Its own inter-node HA control plane (heartbeat on the cluster control interface, session/config sync over the fabric) rides LIFELINE interfaces — `fxp0`, `em0`, `fab<N>`, plus any configured `control-interface` / `fabric-interface` (`HostInboundLifelineSet`, #3277) — which `BuildZoneHostInboundViews` removes before generating host-inbound deny sets. So an unported `high-availability` cannot break xpf's own HA. **Stated plainly: xpf does not implement the MNHA ICL, so naming this token is a no-op for xpf** — it governs a feature xpf does not have. It bites only an operator porting a Junos MNHA config onto a non-lifeline zone, who gets the commit advisory. |

#### The only escape is `any-service`

`system-services any-service` is the **only** remedy, on either enforcement
surface. An lo0 input filter does not help. Two earlier revisions of this fold
claimed otherwise and both were wrong; the history is kept because the second
error is easy to re-derive.

<!-- REFUTED-REMEDY:BEGIN
     Everything between these fences DESCRIBES the lo0-filter remedy in order to
     REFUTE it. TestHostInboundMatrixDocDoesNotAdviseTheRefutedRemedy
     (pkg/config) asserts the refuted phrasing appears ONLY inside this block —
     so a future edit cannot reintroduce it as live operator advice, which is
     exactly how it survived two withdrawals. If you are editing this block,
     keep it refutational; if you need to state the remedy works, you first need
     the bypass mechanism described at the end of the block. -->

| Revision | Claim | Why it is false |
|---|---|---|
| r3 | "admit the real port with a firewall filter" | False on AF_XDP: #3485 deliberately runs the host-inbound gate FIRST so a denied packet incurs none of the lo0 filter's side-effects (counter, log, reject reply, session teardown). On a deny the filter is never evaluated at all. |
| r4 | "…on the kernel path only" | The **priorities are right** — `xpf_lo0` is hook-input priority 0, `xpf_hostinbound` is 10 — but the **inference is wrong**. In nftables `accept` ends the current *base chain*, not the hook. |

The nftables man page is explicit:

> An **accept** verdict (including an implicit one via the base chain's policy)
> ends the evaluation of the current base chain. […] The packet advances to the
> next base chain.

versus

> A **drop** verdict (including an implicit one via the base chain's policy)
> immediately ends the evaluation of the whole ruleset. No further chains of any
> hook are consulted.

So an `accept` in `xpf_lo0` at priority 0 does **not** stop the packet reaching
`xpf_hostinbound` at priority 10, where the catch-all drop terminates it. Only
`drop` is terminal for the hook. There is no mark, no return-path exclusion and
no bypass wiring between the two chains:

```
xpf_lo0        priority  0 :  accept
       |  (packet advances to the next base chain)
       v
xpf_hostinbound priority 10 :  catch-all drop   <- packet dies here
```

Making a filter work would mean building a **real bypass** — an explicit mark set
in `xpf_lo0` and tested in `xpf_hostinbound`, or merging the two chains. That is
a new security mechanism that deliberately lets an lo0 filter override the zone
host-inbound default-deny, so it needs its own design and threat review; and it
would still not help on the AF_XDP path without also reordering #3485, which
would reopen codex-review-118 M1. Both are out of scope for this fold.

<!-- REFUTED-REMEDY:END -->

Why `any-service` genuinely works: it is a full-admit token, so the nft builder
emits a bare `accept` and **no catch-all drop at all** for the zone (there is
nothing left at priority 10 to kill the packet), and the AF_XDP classifier
short-circuits `admits()` to true. That property — not the wording of the
advisory — is what the tests bind.

**Operator consequence — a known, deliberate, fail-closed divergence from
Junos.** A zone that actually terminates one of these services must use
`system-services any-service`. That is the only remedy: as shown above, an lo0
input filter cannot rescue a host-inbound deny on either enforcement path.
Naming one of these tokens explicitly draws a
commit-time advisory (`unportedAdvice`,
`compiler_validate_warn_host_inbound.go`) that says exactly this, so the
gap is announced rather than discovered as a silent blackhole. `system-services
all` does **not** draw the advisory: it covers these services (contributing
nothing), and warning there would fire on a large fraction of commits — every
lifeline-only HA `control` zone included — while telling the operator nothing
they asked about.

**Wider — the two xpf-only carve-outs.** `config.HostInboundNonJunosSystemServices`
(Rust mirror: `HOST_INBOUND_NON_JUNOS_SERVICES`) holds the tokens xpf accepts
that Juniper's list does not define, and excludes them from the expansion:

- **`gre`** — xpf accepts it under `system-services` because operator configs
  list it there, mapping it to IP protocol 47. Junos has no raw-IP-protocol
  system-service, so folding it into `all` would open a protocol Junos's `all`
  never opens.
- **`r-exec` / `rexec`** — Juniper documents `rlogin` and `rsh` but not rexec.
  Unlike the other xpf-only spellings this one is not a port-neutral alias:
  `webapi-clear-text`/`webapi-ssl` resolve to the http/https ports and
  `ssh-netconf`/`netconf-ssh` to ssh ∪ netconf, so including them widens
  nothing, whereas tcp/512 is opened by no other token.

`sip` is deliberately NOT in this set: it is a vSRX ALG service with its own
#3619 disposition and a fail-on-revert port pin
(`TestHostInboundSipTftpNarrowPortSet`).

Both carve-out tokens stay fully usable — they just have to be listed
**explicitly**. This is the service-side twin of `HostInboundL2Protocols`
excluding `isis` from `protocols all` (#3311), and the #3486 parity test asserts
the Go and Rust exclusion sets are equal.

### `ident-reset` inside the expansion

`all` expands to a set that includes `ident-reset`, whose Junos semantics are to
**RESET** inbound ident (TCP/113), not to admit it (#3310). Both nft builders
(`hostInboundMatchSet` in `pkg/daemon/daemon_nft.go` and
`hostInboundMatchFragments` in `pkg/nftables/netlink_hostinbound.go`) therefore
take the verdict from the **expanded** token via
`config.HostInboundServiceTokenExpansion`, never from the authored one — keying
it on the authored token would render `tcp dport 113 accept` and silently admit
ident probes that the per-token form resets. The Rust classifier keeps the
documented #3310 divergence (its `ident-reset` arm is a no-op, so the rare
AF_XDP-reached ident packet is dropped rather than reset).

### Upgrade behaviour and the commit-time advisory

The narrowing is a **no-op on every shipped config**: each one places
`system-services all` on the lifeline-only `control` zone
(`docs/ha-cluster-userspace.conf`, `examples/deploy/ha-pair.conf`,
`test/incus/xpf-cluster-fw0.conf`), and lifeline interfaces are excluded from
the host-inbound deny address sets by `BuildZoneHostInboundViews` (#3277), so
such a zone emits no rules at all and `all` vs the expansion is
indistinguishable there. HA heartbeat / session-sync / config-sync / fabric ride
strictly the control + fabric interfaces and never reach this filter.

`ValidateConfig` (via `validateHostInboundStanzaWarnings`,
`pkg/config/compiler_validate_warn_host_inbound.go`) emits two WARN-only
advisories, for each zone-level stanza AND each per-interface override (#3362):

- **`any-service`** → the packet-wide-full-admit breadth advisory.
- **`all`** → a scoping/upgrade advisory naming what is now denied and pointing
  at `any-service` as the one-token way to restore the previous behaviour. It is
  **gated on the zone (or overridden interface) owning at least one non-lifeline
  interface**, because the narrowing cannot change enforcement anywhere else —
  without the gate every cluster commit would warn forever about a guaranteed
  no-op.

Neither is ever a hard reject: both tokens are legal Junos.

## Host-bound routing multicast is admitted packet-wide (#4455)

The per-zone rules above match host-local **unicast** `daddr` only, so host-bound
**multicast** (OSPF `224.0.0.5/6`, VRRP `224.0.0.18`, PIM `224.0.0.13`, …) falls
through the input chain's `policy accept` **without** per-zone
`host-inbound-traffic protocols` scoping — admitted packet-wide on every ingress
interface, not scoped to the opting-in zone. This is fail-open-but-bounded (the
host delivers only to groups a joined daemon subscribed), a Junos-parity gap.
`ValidateConfig` emits a WARN-only commit-time advisory for a zone admitting a
multicast routing protocol; the per-zone `iifname` enforcement is deferred. Full
protocol→group catalog and the deferred four-decision plan:
[`docs/host-inbound-multicast.md`](host-inbound-multicast.md).

## Global always-accepts (independent of the zone token set)

These are accepted on EVERY host-inbound-configured zone regardless of its
`system-services` / `protocols` set, so enforcement never breaks core L3
operation or session return traffic. nft: `buildHostInboundFilterPayload`; Rust:
`is_icmp_host_inbound_global_accept` + `stage_ipsec_passthrough_check`.

| Class | nft | Rust | Rationale |
|---|---|---|---|
| Established/related | `ct state established,related accept` | conntrack fast path | Return / ongoing host traffic. **On a tightening the kernel entry is reconciled — see "Stale kernel authorization on a tightening (#5566)" below.** |
| Raw IPsec ESP/AH | `meta l4proto { 50, 51 } accept` | `stage_ipsec_passthrough_check` (before `host_inbound_admits`) | Kernel XFRM decrypts host-terminated IPsec; makes `ike`/`ipsec` a working superset. |
| ICMPv4 errors/PMTUD | `icmp type { destination-unreachable, time-exceeded, parameter-problem }` | proto 1 **on IPv4** types 3, 11, 12 | PMTUD / unreachable / traceroute-to-self signalling. Echo-request is NOT here (gated on `ping`). |
| ICMPv6 errors + ND | `icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 }` | proto 58 **on IPv6** types 1-4, 133-137 | v6 error/PMTUD (1-4) + Neighbor Discovery (133-137). Echo-request (128) is NOT here (gated on `ping`). |

### The protocol number is paired with the IP FAMILY (#7520)

`is_icmp_host_inbound_global_accept` used to switch on the protocol number
**alone**, and the two arms mean different things on different families. So:

| packet | old verdict |
|---|---|
| **IPv4**, protocol byte 58, type 1/2/3/4/133..137 | took the ICMPv6 arm → **globally ADMITTED** |
| **IPv6**, next-header 1, type 3/11/12 | took the ICMPv4 arm → **globally ADMITTED** |

This predicate returns **before** the zone lookup, so a match admits a packet
the zone's `host-inbound-traffic` set never permitted — a **fail-open**, not a
fail-closed narrowing.

The type numbers cannot disambiguate it, which is why the family has to be part
of the key: ICMPv6 destination-unreachable is type **1**, and 1 is a perfectly
legal ICMPv4 type number; ICMPv4 time-exceeded is **11**, which is nothing in
ICMPv6's error range. A `(protocol, type)` pair alone genuinely cannot tell the
two apart.

An unknown or neither-family packet now admits nothing — the fall-through is
`false`, so a packet whose address family the parser could not determine stays
gated on the zone set rather than exempted.

**Why it survived #3171 and #3292:** those implemented the two halves of this
admission and neither tested their **composition**. Each half is correct in
isolation; the defect is only visible when you ask what happens to a packet
whose protocol byte belongs to the other family.

The nft side was never affected: `icmp type` and `icmpv6 type` are
family-scoped matchers by construction, so the two surfaces had silently
diverged.

## Stale kernel authorization on a tightening (#5566)

The `ct state established,related accept` above is the FIRST rule in the chain
(and, in the `to-zone junos-host` program branch, the residual established accept
follows the fine DROP but still precedes the per-zone coarse drops). Replacing the
`xpf_hostinbound` table does **not** flush Linux netfilter conntrack. So an
EXISTING direct-kernel host connection admitted under a looser prior config — an
SSH / HTTPS / SNMP session to a firewall-local address — kept riding that leading
established-accept after the operator REMOVED the service: the new per-zone
catch-all DROP never saw the flow's original-direction packets. That was a
host-inbound false-allow confined to the direct-kernel delivery path; the Rust
userspace local-delivery path already re-checks the effective host-inbound set on
every session hit and tears a now-denied session down
(`userspace-dp/src/afxdp/poll_descriptor/mod.rs`), but the kernel path had no
equivalent teardown.

**Fix — conntrack reconcile after every successful apply**
(`pkg/daemon/host_inbound_conntrack_flush.go`, wired at the tail of
`applyHostInboundFilter`). After the real `xpf_hostinbound` table loads, the
daemon deletes every established/related **kernel** conntrack entry whose
original-direction destination is a **covered** firewall-local host-inbound
address (an address that carries a default-deny — the same `desiredDrop` set as
#5789) and whose `(proto, dport)` the CURRENT coarse rules no longer admit. The
next original-direction packet is then re-evaluated and dropped by the per-zone
catch-all instead of short-circuiting on the established-accept. Properties:

- **Reconcile, not a delta.** The flush condition is "not admitted by the CURRENT
  config", derived from the SAME structured SSOT the nft chain renders from
  (`config.HostInboundServiceMatch` / `HostInboundProtocolMatch`), so the admit
  decision cannot drift from the chain's per-zone accepts. No prior-config
  snapshot is persisted; the sweep is a no-op on loosening / unchanged commits
  because still-permitted flows are kept. A service that stays configured is never
  flushed (no connection-reset regression).
- **Lifeline-safe.** Only addresses in the covered default-deny set are eligible;
  management / cluster-control lifelines (fxp0 / em0 / fab<N>) are excluded from the
  host-inbound views, so their conntrack is never flushed. Addressed-but-unzoned
  addresses (#4420 HI-2) are covered with an empty admit set (fully denied except
  the global exemptions below).
- **Global exemptions preserved.** ESP/AH (proto 50/51), ICMP ND/PMTUD/error, and
  the configured WireGuard listen port (#5582) are never flushed, mirroring the
  chain's global accepts. ICMP echo conntrack is short-lived and left to age out.
- **Not a commit failure — but it IS retried and IS visible (#6802).** The nft
  table is already applied, so enforcement for NEW connections holds regardless,
  and failing the commit would roll back correct enforcement over a transient
  conntrack-subsystem error. That rationale is unchanged. What #6802 corrected is
  the rest of it: before #6802 the flush returned nothing, set no dirty flag,
  bumped no counter, published no metric, and no ticker re-ran it — every ticker
  under `pkg/daemon` was enumerated and none re-drives `applyConfig`,
  `applyHostInboundFilter` or the flush, so the only re-attempt was the next
  externally-triggered apply. See "Revocation failure is retried" below.

Kernel netfilter conntrack on this appliance tracks only host-terminated /
kernel-forwarded flows (transit forwarding runs through userspace-dp's own session
table), so the swept table is small. Fail-on-revert proofs:
`pkg/daemon/host_inbound_conntrack_flush_5566_test.go`.

### Revocation failure is retried, counted, and published (#6802)

The failure direction is what made "best effort" a defect rather than a
tradeoff. A stale entry rides the chain's **leading**
`ct state established,related accept`, so a failed revocation fails **OPEN**: a
host service the operator has just REMOVED keeps being served on every
already-established direct-kernel connection. Before #6802 that persisted until
the flow closed or timed out, with nothing to notice it and nothing to re-drive
it.

`flushDeniedHostInboundConntrack` now returns whether every family's delete
succeeded, and the call site records the outcome as **retry debt**:

- **The debt retains the exact request** — the `views` / `unzonedV4` /
  `unzonedV6` / `wgListenPorts` the failed flush was called with — not a set
  re-derived at retry time. A retry that re-derived from the current config would
  attempt a *different* revocation than the one that failed, and the two diverge
  exactly when a commit landed in between.
- **A failure of one family does not abandon the other.** The loop `continue`s so
  the second family is still swept; the failure is carried out in the return
  value rather than swallowed.
- **`hostInboundConntrackReassertLoop` is the retry owner**, started
  unconditionally in `Run` alongside `proxyARPReassertLoop`,
  `raDeadSenderReassertLoop` (#6793) and `fabricIPVLANReassertLoop` (#6791), at
  the same 30s cadence. The gate is a single atomic pointer load, so it is free
  on a node whose revocations have all succeeded. Like its siblings it takes
  `applySem` **before** acting (#4001) — an in-flight apply must not race a
  revocation against a half-applied host-inbound set — and re-reads the debt
  **inside** the semaphore, because the commit it queued behind may already have
  flushed successfully.
- **A later successful flush clears the debt.** The filter is built from the
  desired set, so a current successful revocation subsumes an older failed one;
  retaining stale debt would make the owner re-drive a revocation whose target no
  longer exists.

Operator-visible surface — both emitted even when the dataplane is not loaded,
because the daemon rebuilds the kernel table in config-only mode too:

| Series | Meaning |
|---|---|
| `xpf_host_inbound_conntrack_revocation_pending` | `1` while a revocation has failed and not yet been re-driven. While set, a now-denied host service may still be reachable on an established kernel connection. |
| `xpf_host_inbound_conntrack_revocation_failures_total` | Every failed attempt, retries included. Climbing while the gauge stays `1` means the retry owner is running but not converging. |

Both are omitted entirely — not published as `0` — on a server that has not wired
the accessors, so an unwired node cannot be mistaken for a converged one (the
#6828 absent-vs-zero distinction). Fail-on-revert proofs:
`pkg/daemon/host_inbound_conntrack_retry_6802_test.go` and
`pkg/api/metrics_hostinbound_conntrack_revoke_6802_test.go`.

## Fail-closed invariant for a nil / configured=false known zone (#3705)

Every zone the control plane KNOWS about — a zone present in the snapshot with a
valid, addressable id — is host-inbound **enforcing** (default-deny at minimum),
and the two layers agree:

- **Go builder (`buildZoneSnapshots`, `pkg/dataplane/userspace/zones.go`).** A
  tolerant / HA-loaded config can carry a NIL zone value
  (`Security.Zones[name] == nil`, the #3493 shape). `HostInboundConfigured` is
  set UNCONDITIONALLY, so a nil zone ships `host_inbound_configured=true` with
  EMPTY token sets — default-deny, identical to a no-stanza zone (#3405). Before
  #3705 the flag was gated on `zone != nil`, so a nil zone shipped a valid
  name+id but `configured=false`.
- **Rust build path (`forwarding_build::zones::populate_zones`).** The
  `zone_host_inbound` insert is NOT gated on `host_inbound_configured`: every
  known zone gets an entry (an empty `ZoneHostInbound` when the flag is false /
  tokens are empty → default-deny). This is the dataplane fail-closed backstop
  for a mismatched-version control plane (e.g. an old pre-#3405 Go binary that
  omits the flag). `host_inbound_configured` now selects only WHICH tokens a
  zone admits, never WHETHER it is enforced.

Without both, a KNOWN configured zone with `configured=false` was left absent
from `zone_host_inbound` and hit the `None => true` admit-all arm in
`host_inbound_admits` — reopening the #3405 default-deny on the nil-object shape
(a management-plane fail-open on the exact tolerant-load / HA-sync path where nil
zones arise). `None` now means only a genuinely unknown / global ingress zone
(id 0, never in the table), which keeps the admit default; lifeline interfaces
(fxp0/em0/fab<N>) never reach the AF_XDP classifier (#3682).

## Deliberate narrowings & the one cross-surface divergence

These are intentional and match vSRX / Junos semantics. Documented here so future
audits do not re-file them.

- **`sip` — UDP+TCP 5060 only, no SIP-TLS (M07).** The Junos `junos-sip`
  predefined application is UDP and TCP destination-port 5060, and the SRX SIP
  ALG supports SIP signaling on port 5060 (UDP by default, TCP added in
  12.3X48-D25 / 17.3R1). Junos ships **no** predefined SIP-over-TLS (SIPS)
  application on port 5061; SIPS/5061 requires a **custom** application/service.
  xpf therefore opens UDP 5060 + TCP 5060 on both surfaces and does not admit
  5061 — working as intended. An operator terminating SIPS on the firewall must
  add a custom host-inbound service (there is no `sip` widen).
- **`tftp` — UDP 69 only (M08).** The Junos `junos-tftp` predefined application
  is UDP port 69. TFTP data transfers use ephemeral ports negotiated
  dynamically; for host-bound TFTP that is an ALG/transit concern, not a
  host-inbound listener. xpf opens UDP 69 only on both surfaces — matches vSRX.
- **`traceroute` — UDP 33434-33523 only (L07/L16).** UDP probe range only, per
  the #3368 disposition. The ICMP time-exceeded replies traceroute relies on ride
  the global ICMP-error accept.
- **`router-discovery` carries nothing on IPv6 (L02).** v6 RS/RA (types 133/134)
  are admitted unconditionally as part of the ND global-accept set
  (#3171/#3201/#3240), so the per-zone token adds nothing on v6 — correct kernel
  parity, but note it in operator docs.
- **`ipsec` is an alias of `ike` (L03).** Both open IKE (UDP 500 / NAT-T 4500).
  Raw ESP/AH is governed by the XFRM passthrough / global ESP-AH accept, so
  `ipsec` is effectively a superset of `ike`.
- **`isis` is a recognized no-op (#3311).** Valid at commit for vSRX parity but
  produces no IP match on either surface (rides L2/OSI-CLNP; delivered to FRR
  isisd over an LLC socket). Excluded from the `protocols all` IP expansion.
- **`ident-reset` — the one true cross-surface divergence (#3310).** On the nft
  (primary) path `system-services ident-reset` emits `reject with tcp reset` for
  TCP/113 (Junos actively resets ident probes). The AF_XDP (secondary) path does
  not synthesize an RST — it simply **drops** TCP/113 (the classifier arm
  contributes nothing to the admit set). This is a documented divergence on the
  near-nonexistent DNAT/static-NAT-to-113 path; both layers stop the prior
  plain-admit of 113.

## Addressless-zone fail-open window (#3698)

Host-inbound default-deny is scoped to a zone's firewall-local **addresses** —
the nft chain matches `<fam> daddr <zone-addrs> ... drop`. A configured,
host-inbound-enforcing zone whose non-lifeline interfaces have **no resolvable
address yet** (a DHCP WAN before its first lease, a backup node before VIP
install, or an interface the operator has not addressed) yields an EMPTY address
set, so `BuildZoneHostInboundViews` emits no deny for it and
`applyHostInboundFilter` scopes nothing. During that window, host-bound packets
to a freshly-usable address on that interface can reach the kernel input path
without the intended zone default-deny — a transient fail-open on a security
boundary. Address appearance makes the address available to a later snapshot;
it does not itself prove that host-inbound re-rendered or reached the kernel. A
later applicable full apply must reach host authorization and complete the nft
transaction (VRRP VIPs remain resolved from config, so a VIP-scoped zone is not
addressless even on the backup node). An address-scoped nft deny cannot be
rendered without an address, so #3698 makes the window **observable** rather
than silent.

The SSOT for "which configured enforcing zones are currently in the window" is
`dpuserspace.AddresslessEnforcingZones` (`pkg/dataplane/userspace/zones.go`). It
reads the scoped/unscoped decision back from `BuildZoneHostInboundViews` — the
same builder that drives the nft payload — so the signal describes the same
address snapshot, not whether the later nft transaction succeeded. It reports a
zone iff it has at least one **non-lifeline**
interface assigned yet resolves no address; zones that are scoped, whose only
interfaces are management/cluster-control lifelines (fxp0 / em0 / fab<N>), or that
have no interfaces are deliberately NOT reported (low-noise).

Two observability surfaces consume it:

- **State-transition log** (`daemon_nft.go`, `logHostInboundAddresslessTransitions`).
  A `WARN` is logged when a zone ENTERS the window and an `INFO` when it LEAVES
  (an address appears). These transitions describe the snapshot built before nft
  success and are not installation proof. A zone that stays addressless across
  repeated commits / DHCP renewals is logged once, not every apply.
- **Prometheus gauge** `xpf_host_inbound_addressless_zones{zone}` (`pkg/api`).
  Value `1` per zone currently in the window; the series is absent when the zone
  is enforced. Emitted BEFORE the dataplane gate (config-derived, so it stays
  visible in a config-only / degraded boot). Alert with e.g.
  `max_over_time(xpf_host_inbound_addressless_zones[1h]) > 0`.

## Lifeline exclusion is by address VALUE, in the fence and the real table

**What the builders subtract.** `BuildZoneHostInboundViews` and
`BuildUnzonedHostInboundAddrs` skip a snapshot whose *interface* is a lifeline
(`hostInboundLifelineInterface` — fxp0 / em0 / fab<N> plus the configured
chassis-cluster control and fabric links, #3277), **and** withhold any address
*value* that lives on a lifeline (`hostInboundLifelineSharedAddrs`, #7284). The
value half matters because the interface check answers "is the snapshot I am
walking a lifeline", while a destination-only drop rule poses a different
question: "is this address also reachable as a management address".

Until #7284 only the interface check existed on the real-table side. If the same
firewall-local address was ALSO configured on a non-lifeline interface, that
interface's snapshot contributed it and the address landed in the drop set. The
fence had partitioned per address value since #6492; the two disagreed, and that
divergence WAS the defect. Both now derive the lifeline address set from one
walk (`forEachFirewallLocalAddr`).

**Why it reaches management.** The destination-address rules carry no `iifname`
qualifier (#3718). A drop scoped to a shared management address therefore applies
to traffic arriving on the lifeline too — the rule cannot tell the two ingress
paths apart. That is why the fix is a subtraction and not an ingress qualifier.
The #9637 ingress-zone rules (see "Ingress-zone judgement (#9637)") do not change
this. A lifeline netdev is never in a view's ingress scope, so traffic arriving on
the lifeline still meets only the destination-address rules.

**The topology is one the commit gate accepts.**
`validateDuplicateHostLocalAddressStrict` permits a management address shared
onto a non-lifeline interface (`pkg/config/dup_host_local_address_3718_test.go`,
`TestDupHostLocalLifelineExcluded`), so this could never have been closed by
tightening the gate — the configuration is legal and the enforcement has to
handle it. Three variants, all verified by driving the real builders:

| Shared onto | Real table for the shared address | New mgmt connection | Established mgmt session |
|---|---|---|---|
| a zone that **admits** the service | `daddr <ip> tcp dport 22 accept` then `daddr <ip> … drop` | survives (accept precedes) | survives (#5566 admits tcp/22) |
| a zone with **no `host-inbound-traffic` stanza** (#3405) | address withheld — no rule for it | survives | survives (not in the covered set) |
| an **unzoned** interface (#4420 HI-2) | address withheld — no rule for it | survives | survives (not in the covered set) |

**Row 1 is deliberately left alone**, and that is the reason the subtraction is
scoped to EMPTY-admit views rather than applied like the fence's. A view that
admits something emits its `accept` before the catch-all drop, so management
already survives there, and the drop still expresses a real policy for every
OTHER service on that address. Withholding the address from that view would
delete the accept and the deny together, leaving every host service reachable on
it — a far wider hole than the lockout being fixed. An empty-admit view has no
such policy to preserve: its only possible outcome for the address is a drop with
no accept.

**This is a widening of a drop set, deliberately.** Rows 2-3 previously denied
the shared address; they no longer do. #6492 blessed the same trade for the
fence. The bound on it is that only an address ACTUALLY on a lifeline is
withheld — an address that is not is still denied by the #3405 default-deny and
still in the #4420 HI-2 unzoned set, so neither fail-open is reopened. That
boundary is the one the tests exist to hold.

**Both halves move together.** `daemon_nft.go` builds one `views` /
`unzonedV4` / `unzonedV6` triple and passes it to BOTH `toNftHostInboundSpec`
(the rules) and `flushDeniedHostInboundConntrack` (the #5566 reconcile), so
withholding at the builders removes the address from the covered set as well as
from the chain. Fixing only the rule emission would have stopped NEW management
connections being dropped and still torn down the operator's CURRENT session on
the next apply.

**What the FENCE does about it.** A fence is the real table with every
per-service ACCEPT removed, so it would collapse row 1 into rows 2-3 for the
fence window — that was #6492 Finding A. #6492 fixes it by giving the fence its
own drop scope, which WITHHOLDS any address shared with a lifeline interface, so
a fence never drops a shared management address on any render (see "Fence drop
scope is not the real ruleset's scope"). The guarantee is narrower than
"management is safe": an address the operator manages the box on that is NOT
shared with a lifeline is fenced like any other for the fence window. The global
mandatory admits (`ct established,related`, raw ESP/AH, IPv6 ND, v4/v6 PMTUD)
precede every drop, so an already-established session survives the chain.

**What is still true.** A lifeline address that is NOT shared onto any
non-lifeline interface never enters a view or the unzoned set. That is the case
the exclusion was originally written for, and it is the overwhelmingly common
one.

## Cold-boot fail-closed install fence (#5644, M37)

`applyHostInboundFilter` loads the chain with `nft -f -`, which is **atomic**:
on a load failure the kernel keeps the exact PREVIOUS `inet xpf_hostinbound`
generation untouched, if one exists. That generation protects only rules and
destinations already represented in it; it does not cover a newly appeared
address (#5789). **On a COLD BOOT both nft tables are absent, so a failed install
has no prior generation to retain.** A boot apply that reaches
`applyHostInboundFilter` does so through `applyConfig`, which only **logs and
discards** the returned error
(a boot apply must not brick startup), so a cold-boot install failure would leave
the host input path with **no** `xpf_hostinbound` chain — every host-bound service
to a firewall-local address reachable with no host-inbound default-deny
(fail-open) — while the daemon proceeds to publish host service / VIP / HA-ready.

To close that window when the rendered snapshot has addresses, a cold-boot
install failure attempts a **fail-closed fallback** before returning the error.
That fallback is DENY-ALL for every address in the snapshot; an addressless
snapshot produces a zero-drop table shell:

- `d.hostInboundEnforced` (a `Daemon` atomic bool) is a process-local historical
  fallback gate. A successful real load stores true, including a program-only
  generation; a successful fallback stores true only when that exact fallback
  contains an address-scoped DROP. Repeated successful zero-drop fallbacks leave
  false. A successful **no-enforcement teardown** (nothing is enforceable, so the
  `xpf_hostinbound` table is deleted) stores **false** (#5790): with no table
  installed the "a protecting table exists" premise is gone, so a later
  enforceable generation whose first real load fails must take this cold-boot
  fence path rather than assume a retained table (the pre-fix sticky-true skipped
  the fence and left newly reachable addresses fail-open). A teardown **failure**
  (a table the delete could not remove may still be installed) does **not** clear
  it. True still proves neither current table presence nor coverage of current
  addresses — the DAY-2 COVERAGE gap is tracked separately (#5789, below). All
  Stores are serialized under `applySem`; nft completion and the following Go
  Store are ordered but not one atomic publication.
- `d.hostInboundCoveredAddrs` (a `Daemon` set, keyed `"<fam>|<addr>"`) is the
  #5789 COVERAGE discriminator that the sticky boolean alone cannot provide.
  `hostInboundEnforced=true` proves only that SOME protecting table loaded at SOME
  earlier generation, NOT that the RETAINED (atomic-untouched) generation covers
  the CURRENT desired destination set. Two fail-open paths otherwise remain: (1) a
  previously-addressed zone gains another static/DHCP/SLAAC address and the next
  real render fails — atomic nft retention keeps the OLD generation, which has no
  deny for the new address; (2) a successful addressless program-only install
  stores `enforced=true` with ZERO covered addresses, and an address later appears
  before a failed rerender. `hostInboundCoveredAddrs` records the destination set
  the currently-retained enforcement (last successful real load OR address-scoped
  cold-boot fence) drops. On a failed rerender while `enforced=true`, the desired
  drop set is diffed against it (`hostInboundUncoveredDropAddrs`); any UNCOVERED
  destination gets an ADDITIVE gap fence (below). It is set to the desired set on a
  successful real load / address-scoped fence, left UNCHANGED on any failure
  (atomic retention keeps the old generation, so its coverage claim stands), and
  CLEARED on a successful teardown (#5790 — no table covers nothing). `applySem`
  serialized, like the `hostInboundFailOpen` maps.
- `installHostInboundGapFence` / `buildHostInboundGapFencePayload` (#5789) build
  the ADDITIVE gap fence: a SEPARATE `inet xpf_hostinbound_gap` base chain at
  `nftHostInboundGapPriority` (11) — STRICTLY AFTER the main `xpf_hostinbound`
  table (10), which is strictly after `xpf_lo0` (0); the three distinct
  strictly-increasing hook-input priorities are pinned by
  `nft_chain_priority_test.go`. It denies ONLY the uncovered addresses (with the
  SAME mandatory L3 / return admits as the cold-boot fence, via the shared
  `hostInboundFenceMandatoryAdmits`) and, unlike the whole-table cold-boot fence,
  does NOT replace `xpf_hostinbound` — so the retained generation's per-service
  ACCEPTS for already-covered addresses stay intact (the issue's "do not weaken
  retained valid rules"). A newly-appeared uncovered address falls through the main
  chain's `policy accept` (a `drop` is terminal, an `accept` is not, so an already
  service-accepted or catch-all-dropped covered address keeps its main-table
  verdict) and is dropped by the gap. The uncovered lists derive from the same
  lifeline-subtracted views/unzoned sets, so the gap never fences management /
  cluster-control traffic. A gap install failure JOINS the commit error
  (fail-closed); the gap is torn down by the next successful real install (best
  effort — a lingering gap fences only, never opens) and on a successful teardown.
- `installHostInboundColdBootFence` / `buildHostInboundFencePayload`
  (`daemon_nft.go`) build the fence: the same atomic-replace `xpf_hostinbound`
  table reduced to the global mandatory admits (`ct established,related`, raw
  ESP/AH, IPv6 ND, v4/v6 PMTUD+error, the configured WireGuard listen port) and a
  catch-all `<fam> daddr <addrs> drop` for **every** firewall-local address the
  real ruleset would scope (the per-zone views + the addressed-but-unzoned set).
  It carries **no per-service accept and no named counters** — it is strictly the
  real table with every service ACCEPT removed, so during the fence window even a
  `system-services all` zone is denied (maximally fail-closed). The address sets
  exclude lifeline INTERFACES (fxp0 / em0 / fab<N>) via
  `BuildZoneHostInboundViews` / `BuildUnzonedHostInboundAddrs` — but **not**
  lifeline address VALUES. A management address also configured on a non-lifeline
  interface IS in the fence's drop set, and the drop carries no `iifname`, so the
  fence drops new management connections to it for the whole fence window (#6492
  Finding A). See "Lifeline exclusion is by address VALUE, in the fence and the real table".
- The requested apply still **fails** (`applyHostInboundFilter` returns the
  wrapped real nft error, joined with a fallback error when fallback also fails).
  A later full apply seeing an address gets another fallback opportunity only if
  it reaches host authorization, the real load fails, and state remains false.
  There is no host-inbound retry loop.
- A DHCP/DHCPv6 lease callback classified for full recompile runs serialized
  `applyConfig`, but classification does not prove host-inbound ran. A required
  protocol-gate error returns before `applyTailReconciles` and receives no
  cancellation closeout, leaving retry/re-render to a later applicable successful
  reconcile that reaches the tail. **#5791 (fixed):** the callback's
  management-only skip is now gated on the config-derived host-inbound LIFELINE
  set (`config.HostInboundLifelineSet` / `HostInboundLifelineInterface` — the SAME
  authority that lifeline-excludes these address sets), not the broad
  management-VRF name class (fxp*/fab<N>/em*). So a zoned NON-lifeline DHCP interface
  (a standalone `fxp1`) is classified for the full recompile that builds its
  address-scoped fence; only a true lifeline (fxp0/em0/fab<N>/configured
  control-interface) keeps the management-only fast path. The skip decision and
  this fence now share one classifier and cannot drift.
- If the fence **also** fails to load (nft itself broken), both errors are joined
  and an `ERROR`-level `COLD-BOOT FAIL-OPEN GUARD` log fires; `hostInboundEnforced`
  stays false. That is the irreducible catastrophic case — the daemon has done all
  it can short of holding forwarding.

Relationship to the addressless window above: at the first cold-boot apply an
interface may have no address yet, so both the real ruleset and fallback can
contain zero address-scoped DROPs. A successful zero-drop fallback leaves
`hostInboundEnforced` false. Address appearance alone does not re-run this path;
a later applicable full apply must reach host authorization, and a failed real
load while state is false then renders another fallback from that invocation's
snapshot. This is scoped to the **direct-host nft input authority** only; the
AF_XDP transit arm / attach readiness is owned separately by #5275.
Fail-on-revert proofs:
`pkg/daemon/host_inbound_coldboot_fence_5644_test.go`; for the
teardown-clears-the-gate ordering (#5790),
`pkg/daemon/host_inbound_teardown_enforced_5790_test.go`; and for the day-2
coverage gap + additive gap fence (#5789),
`pkg/daemon/host_inbound_coverage_gap_5789_test.go` (both the address-added and
the program-only-then-address paths) plus the three-chain priority invariant in
`pkg/daemon/nft_chain_priority_test.go`.

### lo0 RE-protection cold-boot fence (#6476)

The operator's `interfaces lo0 unit 0 family inet filter input <name>`
(the Junos protect-RE pattern) lowers to the `inet xpf_lo0` input chain — the
authoritative, operator-authored control-plane firewall, evaluated at hook-input
priority 0 (strictly BEFORE the `xpf_hostinbound` backstop at 10). Before #6476
it had the SAME cold-boot fail-open the host-inbound table closed in #5644: on a
COLD BOOT no prior `xpf_lo0` table exists to retain, and the boot apply reaches
`applyLo0Filter` through `applyConfig` (which only logs+discards the error), so a
failed `InstallLo0` left the RE input path with **no** lo0 filter and only a WARN,
while host service / VIP / HA-ready were published. Host-inbound (priority 10) may
still gate, so exposure is partial — but any service protected ONLY via the lo0
filter is unenforced.

The fix mirrors the host-inbound cold-boot fence for the lo0 table:

- `installLo0ColdBootFence` / `buildLo0FencePayload` (`daemon_nft.go`) build the
  fence from the SAME fence-only address scope as the host-inbound cold-boot
  fence (`dpuserspace.BuildFenceAddrSets`, #6492 — lifeline INTERFACES excluded
  and lifeline-shared address VALUES withheld; see "Fence drop scope is not the
  real ruleset's scope" and "Lifeline exclusion is by INTERFACE, not by address
  value") and the SAME
  `buildFenceTablePayload` body as the host-inbound cold-boot fence — mandatory L3
  / return admits (`ct established,related`, raw ESP/AH, IPv6 ND, v4/v6
  PMTUD+error, the configured WireGuard listen port) then a catch-all
  `<fam> daddr <addrs> drop`, no per-service accept and no named counters — but
  rendered into the `xpf_lo0` table at priority 0, the same slot the real lo0
  filter occupies, so a later successful `InstallLo0` **atomically replaces** it.
  Netlink install is `Installer.InstallLo0ColdBootFence` (T1 parity gate:
  `lo0_cold_boot_fence`).
- **The gate keys on `d.lo0Enforced` — "is the live `xpf_lo0` table a REAL
  operator filter" — NOT "does any protecting table exist" (#6489).** A failed
  `InstallLo0` installs (or re-installs) a fence UNLESS a real filter is currently
  loaded. It is true ONLY after a successful real `InstallLo0` **that rendered at
  least one kernel rule** (#6529, below); a FENCE deliberately
  does **not** set it (a fence is not a real filter — its chain is `policy accept`
  and drops only the addresses in the snapshot it was rendered from — so it stays
  false across a fence). A successful no-filter TEARDOWN stores false (the table is
  deleted); a teardown FAILURE does not clear it. `applySem`-serialized.
- **Why it must not key on "any table exists".** The earlier design set a single
  `lo0Enforced` bool true on BOTH a real load AND a scoped fence, so this sequence
  FAILED OPEN: cold-boot real install fails → fence(snapshot A) installed → gate
  true → a new local address **B** appears + real install fails again → the gate
  skips re-fencing → the retained table is the OLD FENCE (`policy accept` + drops
  for A only), so **B** falls through `policy accept` → the RE input path is open
  for B. Keying on `lo0Enforced` instead RE-RENDERS the whole-table fence
  from the CURRENT snapshot on every day-2 failure while no real filter is loaded,
  so B is covered.
- **No day-2 gap fence (the deliberate divergence from #5789) — but only once a
  REAL filter is loaded.** When `lo0Enforced` is true, a day-2 failure
  installs no fence: the atomic `replaceTable` retains the operator's filter, which
  — unlike the auto-generated, per-destination-address-scoped `xpf_hostinbound`
  table — is hand-authored and NOT per-destination scoped (its terms, typically
  ending in a catch-all `discard`, govern every firewall-local address, including
  one that appears later). So lo0 needs neither a per-address coverage set nor an
  additive gap table; the whole-table re-render (fence path) and retain-the-real-
  filter (real-filter path) together close the gap.
- **A VACATED filter does not claim enforcement (#6529).** `Installer.InstallLo0`
  reports the RENDERED rule count (from `nlPlan.rules`, the actual build) alongside
  its error, and a successful install that rendered **zero** rules Stores
  `lo0Enforced` **false**. Such an install leaves an empty `policy accept` shell
  that enforces nothing, and one boolean cannot tell "a real filter governing every
  local address" from "a real filter that compiled to nothing" — so the pre-#6529
  unconditional `Store(true)` on any successful install permanently suppressed this
  fence and left the host input path open. Zero rules is reachable through three
  doors, none of them distinguishable by counting TERMS: a filter NAME that resolves
  to no filter (`toNftLo0Spec`'s map lookup silently yields no terms), a filter with
  no terms, and a filter whose every term lowers to zero rules (a Junos
  match-nothing scope, e.g. an unresolved `from source-prefix-list`). All three
  arrive through `opts.lenientFirewallRefs` on `Store.Load` at boot or
  `Store.SyncApply` on HA peer-sync, which downgrades the dangling-firewall-ref
  reject to a warning. It Stores **false** rather than merely skipping the Store,
  because a peer-synced vacated generation atomically REPLACES a live real filter
  (#5790 teardown parity). It does NOT install a fence: fencing on a SUCCESSFUL
  install would deny host-bound traffic on a clean commit; the gate being false is
  what matters, and the next failed install fences from the current snapshot.
  Fail-on-revert: `pkg/daemon/lo0_vacated_enforced_6529_test.go` (four cases plus
  the anti-over-fix `TestRealLo0FilterStillEnforces6529`, which pins that a real
  filter still skips the day-2 fence) and
  `pkg/nftables/netlink_lo0_zero_render_6529_test.go` (a spec WITH terms really can
  render zero rules — the case a term-count gate misses).
- A zero-drop fence (an addressless boot snapshot) is likewise not a real filter,
  so it leaves `lo0Enforced` false and a later failed real invocation
  re-fences from a possibly-now-addressed snapshot; a catastrophic double-failure
  (real load AND fence both fail) joins both errors, fires the `COLD-BOOT
  FAIL-OPEN GUARD` ERROR log, and leaves `lo0Enforced` false.

**Pre-existing residuals (NOT introduced or addressed by #6476/#6489, tracked
separately):**

- A retained REAL lo0 filter with **no catch-all term** is a valid config
  (`compiler_filter_nocatchall_3295_test`); such a filter need not itself cover a
  new day-2 address. That is the lo0 filter's own coverage semantics, independent
  of this boot fence — the fence only guarantees the RE path is not left fully
  open when NO real filter is loaded.
- The two shared-mechanism behaviours #6492 filed against this fence body — a
  management IP shared onto a non-lifeline interface picking up a global `daddr`
  drop, and a zone-less router yielding empty address sets → an accept-all fence
  shell — are **fixed**; see "Fence drop scope is not the real ruleset's scope"
  below.

### Fence drop scope is not the real ruleset's scope (#6492)

A fence is the real table with **every per-service ACCEPT removed**, so it cannot
reuse the real ruleset's address scope unchanged. `dpuserspace.BuildFenceAddrSets`
(`pkg/dataplane/userspace/zones_host_inbound.go`) derives the fence-only scope and
is called by BOTH fence sites (`installHostInboundColdBootFence`,
`installLo0ColdBootFence`). It differs from `BuildZoneHostInboundViews` +
`BuildUnzonedHostInboundAddrs` in two directions:

- **Narrower — lifeline-shared addresses are WITHHELD (Finding A).** The view
  builders exclude lifeline INTERFACES (fxp0 / em0 / fab* / the configured
  control+fabric links), not lifeline address VALUES. If the SAME IP is also
  configured on a non-lifeline interface — a topology xpf explicitly accepts,
  `pkg/config/dup_host_local_address_3718_test.go` — that snapshot re-adds it, and
  the fence's drop rule carries **no `iifname` qualifier**, so it renders as a bare
  `ip daddr <mgmt-ip> drop` that kills every NEW management connection to it for
  the whole fence window. Such addresses are removed from the fence's drop set and
  reported at WARN (`logFenceWithheld`: `withheld_v4` / `withheld_v6`). This is
  fence-only: the REAL table keeps denying them, because its per-service accepts
  (the mgmt zone's `system-services ssh`) precede its catch-all DROP and still
  admit the session. Withholding them in the view builder instead would relax the
  real table's default-deny — a fail-open.
- **Wider — every firewall-local address is covered, zones or not (Finding B).**
  Both view builders return nothing when the config declares no security zone,
  because the real host-inbound default-deny is a zone-model construct. But
  host-inbound / lo0 filters are independently valid without zones
  (`pkg/config/compiler_filter_ref_3296_test.go`), so on a zone-less-but-addressed
  router a failed cold-boot lo0 install produced an accept-policy fence shell with
  **ZERO drops** — fail-OPEN, defeating the fence's whole purpose. The fence's drop
  set is therefore derived from the firewall-local ADDRESSES (every non-lifeline
  interface address from the canonical snapshot builder, plus every configured VRRP
  virtual address — a VIP is live only on the RG master, so the backup node's
  snapshot misses it, #3172), not from zone membership. There is no
  "are there zones?" branch: the address walk is identical either way and simply
  yields more than the zone views do when zones are absent or incomplete. It also
  closes the smaller same-shape hole in a ZONED config — a VRRP VIP on an unzoned
  interface, which neither view builder collected.

  This reaches production through `applyLo0Filter` only: `applyHostInboundFilter`
  returns on its teardown branch before the install when nothing is enforceable, so
  a zone-less router never reaches the host-inbound fence.

Because the fence's coverage now differs from the real ruleset's desired-drop set
in both directions, `installHostInboundColdBootFence` records
`hostInboundCoveredAddrs` from the **fence's own** sets, not from the real
ruleset's `desiredDrop` — the #5789 day-2 gap check must describe what the
retained enforcement actually drops.

Fail-on-revert proof: `pkg/daemon/host_inbound_fence_scope_6492_test.go` —
`TestFenceWithholdsLifelineSharedAddress6492` (which also asserts the REAL views
still carry the shared address, so an over-fix in the view builder goes RED) and
`TestFenceCoversZonelessRouter6492`, both driven through the production
`applyLo0Filter` → `installLo0ColdBootFence` path with an injected install
failure.

Fail-on-revert proof: `pkg/daemon/lo0_coldboot_fence_6476_test.go` —
`TestColdBootLo0FenceThenNewAddressReFences` pins the #6489 fence→fail→re-fence
sequence (RED if a fence marks a real filter loaded). The lo0-first-then-host-
inbound priority ordering (0 < 10) is pinned by
`pkg/daemon/nft_chain_priority_test.go`; the fence's netlink/exec-nft parity by
the `lo0_cold_boot_fence` case in `daemon_nft_netlink_parity_test.go`.

### Per-interface / per-family refinement (#3710)

The zone-level signal above **collapses**: `AddresslessEnforcingZones` marks a
zone "scoped" (and stays silent) the moment ANY of its interfaces resolves an
address in EITHER family. But host-inbound ENFORCEMENT is per-destination-address
and per-family — the kernel chain emits `<fam> daddr <set> ... drop` separately
for `inet` and `inet6` — so a **MIXED** zone can still carry a real fail-open
window the zone-level view cannot express:

- **Mixed-interface zone**: `trust` has `ge-0-0-0.0` (static `192.0.2.1`) and
  `ge-0-0-1.0` (DHCP WAN, lease pending). The addressed sibling makes the zone
  scoped, so #3698 never surfaces `ge-0-0-1.0`'s window.
- **Mixed-family interface**: `ge-0-0-2.0` has a static/DHCP v4 address but its v6
  lease (DHCPv6) has not landed. `len(v.V4Addrs) > 0` marks the zone scoped, so
  the IPv6 side entering the same window is invisible — dual-stack edges commonly
  bring the two families up at different times.

`dpuserspace.AddresslessEnforcingInterfaces` (`pkg/dataplane/userspace/zones.go`)
surfaces the window at `{zone, interface-unit, family}` granularity. It reports a
non-lifeline logical unit assigned to a configured enforcing zone when, for a
family, the unit has a **DHCP / DHCPv6 client** configured (`family inet { dhcp; }`
/ `family inet6 { dhcpv6; }` / `dhcpv6-client`) but currently resolves **no
address** in that family — using the same static / live-kernel address resolution
plus configured VRRP VIPs that `BuildZoneHostInboundViews` scopes the deny with.

Only the `dhcp-pending` reason is reported: a static address or a VRRP VIP is
injected into the enforced deny from config regardless of link/lease state, so it
never opens a per-interface window. Gating on a configured DHCP client (rather
than "any family with no address") keeps the signal low-noise — an IPv4-only
interface is **not** flagged as addressless in `inet6`, because it never intends
to acquire a v6 address. A landed lease changes the next address snapshot; nft
enforcement still depends on a later applicable reconcile reaching host
authorization and completing its transaction.

Two observability surfaces consume it (mirroring #3698):

- **State-transition log** (`daemon_nft.go`,
  `logHostInboundAddresslessIfaceTransitions`). A `WARN` on ENTRY, an `INFO` on
  RECOVERY, transitions only.
- **Prometheus gauge**
  `xpf_host_inbound_addressless_interfaces{zone,interface,family,reason}`
  (`pkg/api`). Value `1` per open window; absent when the family is enforced.
  Emitted BEFORE the dataplane gate. The zone-level
  `xpf_host_inbound_addressless_zones` remains as a coarser compatibility
  aggregate — this per-interface series is strictly more sensitive and is exported
  alongside it, not in place of it.

## Per-interface override precedence (#3362, #3720, #6515)

Host-inbound-traffic can be authored at three granularities:

1. **zone-level** — `security zones <z> host-inbound-traffic { ... }`, applies to
   every interface in the zone **that does not declare its own stanza**;
2. **physical-interface-level** — `security zones <z> interfaces <ifN>
   host-inbound-traffic { ... }` (a bare interface ref), applies to every
   configured unit of that physical interface;
3. **unit-level** — `security zones <z> interfaces <ifN.M>
   host-inbound-traffic { ... }`, applies only to that logical unit.

Levels 2 and 3 are both the **interface level** and they UNION with each other.
The interface level as a whole **REPLACES** the zone level:

```
effective(ifN.M) = physical(ifN) ∪ unit(ifN.M)     if either is declared
                 = zone                             otherwise
```

`config.EffectiveHostInboundTokens` is the SSOT for that outer choice and
`config.UnionHostInboundTokens` for the inner merge; every surface that resolves
an interface's admission routes through the former — the kernel nft view builder
(`BuildZoneHostInboundViews`), the per-interface classifier
(`ClassifyHostInboundForInterface`), the commit-time advisories, the
duplicate-host-address gate, and all six display surfaces.

`UnionHostInboundTokens` dedups on the CASE-FOLDED token and emits the token as
the operator authored it (#7171). Service tokens are matched case-insensitively
everywhere downstream, so a zone spelling a service `ssh` and an interface
spelling it `SSH` describe one admission, not two; keying the dedup on the raw
token rendered both and made the display disagree with the single service
actually admitted. Folding the key without folding the value keeps the authored
case these surfaces are meant to echo back. This is deliberately NOT shared with
the case-fold in `junos_host_deny.go`: that one folds to MATCH enforcement
(#5557), while this one folds only to DEDUP and must preserve the spelling.

### The advisory consumes the enforcer's view, it does not model it (#6640)

`config.EffectiveHostInboundTokens` settles the zone-vs-interface choice, but it
takes an interface's override as an ARGUMENT — it does not resolve one. The
resolution (the #3720 physical→unit merge, the #3720 M01 / #5489 cross-zone
quarantines, the #5878 canonicalisation) lives in
`config.ResolveInterfaceHostInbound`, and the enforcement builders in
`pkg/dataplane/userspace` (`buildInterfaceHostInboundMap`,
`buildInterfaceZoneMap`, `mergeHostInboundTraffic`) are one-line delegations to
it.

That move is #6640, and the reason is that the commit-time advisory could not
reach the old location — `pkg/dataplane/userspace` imports `pkg/config`, not the
other way round — so it re-derived an approximation instead: a union of the zone
stanza with each **raw** interface stanza, modelling no physical→unit layer at
all. The advisory and the enforcer were therefore describing different objects,
and the advisory emitted FALSE denial warnings on configurations that
full-admit:

| authored | effective (enforced) | old advisory |
|---|---|---|
| physical `any-service` + unit `rpm` | `{any-service, rpm}` — full admit | "rpm is DENIED; add `any-service`" |
| physical `rpm` + unit `any-service` | `{rpm, any-service}` — full admit | same, at the physical stanza |
| lifeline-only zone (`fxp0.0`) | not enforced at all (#3277) | same, at the zone |
| `fxp0.0` interface override | not enforced at all (#3277) | same, at the interface |

Three separate rounds (#3226, #6616, #6640) each fixed one more advisory case by
copying one more enforcement rule into the advisory. The general shape, stated
once: **the advisory must not maintain its own model of enforcement semantics.**
Every divergence found so far has been a place where enforcement grew a rule the
advisory did not copy, so the advisory now calls the same function instead.

Two rules follow from that, and they are separate:

- **Observability comes from the EFFECTIVE view.** An advisory fires only where
  the dataplane acts: for an interface stanza, on the enforcement KEYS that ref
  governs (a physical interface with units is never itself a key — its units
  are), skipping lifeline keys, and only when at least one such key does not
  full-admit once resolved. For the zone stanza, only when at least one
  non-lifeline key in the zone still resolves to NO interface override, so the
  zone-level tokens actually reach something. A zone with no interfaces yet keeps
  warning: the stanza governs nothing, but the advisory is about what the
  operator authored.
- **The named TOKENS come from the AUTHORED stanza.** The resolved set on a unit
  also carries tokens inherited from its physical parent, and naming those at the
  unit's own stanza would report a service that stanza never accepted — the same
  cry-wolf failure in a new place, with one denial drawing two advisories.

The lifeline exemption (#3277) now covers the unported-service advisory as well
as the scoping one; before #6640 it was applied to the latter only.

Gate: `pkg/config/host_inbound_advisory_effective_view_6640_test.go` (four false
shapes silent, three real denials still warning) plus
`pkg/dataplane/userspace/host_inbound_shared_view_6640_test.go` (the same fixture
observed through the classifier). Breaking `ResolveInterfaceHostInbound` must red
BOTH files; if only the advisory reds, they are not sharing it.

### Replace, not union (#6515) — UPGRADE NOTE

> **This is an admission NARROWING. Read it before upgrading if any of your
> configs author a per-interface `host-inbound-traffic` stanza.**

Junos, [Security Zones](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-zone-configuration.html):
"You can configure these parameters at the zone level, in which case they affect
all interfaces of the zone, or at the interface level. **(Interface configuration
overrides that of the zone.)**"

Before #6515 xpf UNIONed the two levels and asserted "Junos additive semantics"
in-tree, so an interface stanza could only ever WIDEN admission and never narrow
it: a zone admitting `protocols ospf` with an interface stanza admitting only
`ping` still admitted OSPF on that interface, where Junos denies it. #6515 makes
the interface stanza replace the zone stanza on the interfaces that declare one.

**Presence, not emptiness.** An explicit `host-inbound-traffic { }` on an
interface is a **deny-all** override, not a fallback to the zone set.
`parseHostInboundNode` compiles a present-but-empty stanza to a non-nil empty
struct precisely so the two are distinguishable.

**The WHOLE stanza replaces, not each leaf.** An interface stanza that declares
only `protocols` also drops the zone's `system-services`. That is the literal
reading of the sentence above, and the community consensus states it the same way
("if you configure anything under specific interface level, then zone-specific
configuration doesn't apply to this interface anymore"). No vendor text was found
describing a per-leaf inheritance, so none is implemented — a per-leaf rule would
be a guess, and a guess that silently widens admission.

**Junos's own narrowing idiom is `except`, which xpf does not implement.** The
worked example in the Juniper topic narrows a second interface with
`system-services all` plus `ftp except` / `http except`. xpf's schema has no
`except` keyword, so the only way to narrow an interface here is to author the
narrower token list directly. That is a separate parity gap, not a consequence of
this change.

**What upgrading takes away.** For every interface that declares a stanza, the
lost set is the zone-level tokens the interface stanza does not repeat (after
`all`-expansion). The services most likely to disappear are exactly the ones that
hurt: `ssh`, `https`/webmgmt, `ike` (ESP/AH keep their global accept, but IKE
udp/500,4500 is token-gated, so tunnels stop rekeying), and unicast `bgp`/`ospf`
to the interface address.

**It is not only new connections.** The #5566 conntrack reconcile
(`buildHostInboundConntrackFlushFilter`) rebuilds its admit set from these same
views and DELETES established kernel conntrack entries to a covered
firewall-local address that the new set no longer admits. A narrowing commit
therefore drops LIVE sessions to a removed service, not merely refuses new ones.

**What is structurally out of scope.** Lifeline interfaces (`fxp0` / `em0` /
`fab*` and the configured control + fabric links) are excluded from host-inbound
deny scoping by INTERFACE, so management over `fxp0` and the HA control plane are
unaffected by this flip. Since #7284 the exclusion is also by address VALUE: a
management address additionally configured on a zoned or unzoned interface is
withheld from any drop set that would deny it with no accept (see "Lifeline
exclusion is by address VALUE, in the fence and the real table"). VRRP advertisements
are unaffected because the views scope drops to unicast interface addresses plus
VRRP VIPs only, and 224.0.0.18 is never in that scope.

**Migration.** `validateHostInboundOverrideReplaceWarnings`
(`pkg/config/compiler_validate_warn_host_inbound.go`) emits a commit-time
advisory naming every `(zone, interface, lost tokens)` triple, so `commit check`
shows the loss BEFORE the commit that would cause it. The remedy is mechanical:
repeat the zone-level tokens in the interface stanza. It is WARN-only — the new
behaviour is the Junos behaviour, and rejecting the config would refuse something
Junos accepts. Lifeline interfaces and effective sets that full-admit
(`any-service`) are skipped: nothing is lost there, and an advisory that fires on
configs losing nothing is one operators learn to ignore.

### Physical∪unit merge (#3720)

A more-specific unit override never *replaces* a physical override — they are
merged, because both are interface-level statements. Before #3720 the resolver
(`buildInterfaceHostInboundMap`, `pkg/dataplane/userspace/zones.go`) walked refs
in sorted order and wrote each key first-writer-wins; a bare physical ref sorts
before (is a prefix of) its units, so it filled `out["ifN.M"]` first and the
later exact unit override was **dropped** — the less-specific physical ref
silently shadowed the more-specific unit ref (fail-open, admitting a service the
unit did not open, or fail-closed, denying one it did). The fix MERGES (unions)
the two levels instead.

**Cross-zone quarantine (#3720 M01, #5489).** A host-inbound override must
contribute to a unit's effective set ONLY from the unit's authoritative zone
owner. On the lenient / peer-synced load path an ownership conflict is downgraded
to a warning (`compiler_validate_strict.go`) and `buildInterfaceZoneMap` resolves
the owner as the **first sorted zone** that claims the unit, so two zones can
both name the same `ifN.M` while only one owns it. Both branches of
`buildInterfaceHostInboundMap` (`pkg/dataplane/userspace/zones_override.go`)
enforce the owner predicate `zoneByIface[ref] == zn`:

- **physical→unit expansion (#3720 M01)** does NOT apply a physical `ifN`
  override owned by zone trust onto `ifN.M` owned by zone guest — it skips any
  unit whose resolved zone differs from the override's zone.
- **exact unit-level ref (#5489)** does NOT merge a `ifN.M` override authored by
  a **non-owner** zone into `out["ifN.M"]`. Before #5489 the exact-unit branch
  unioned every zone's override unconditionally, so a losing zone's admission
  token (e.g. `ssh`) bled into the winning zone's `InterfaceSnapshot` /
  `ZoneHostInboundView` — a cross-zone host-inbound admission escalation. The
  quarantine mirrors the physical branch exactly (same `z != "" && z != zn`
  predicate, same skip), so a unit's effective tokens come only from its
  authoritative owner. Single-owner (non-conflict) configs are unchanged.

**Presentation parity (#3720 H05).** `ZoneConfig.InterfaceHostInboundEffective`
(`pkg/config/host_inbound_view.go`) — used by `show interfaces <unit>`, `show
security zones`, and the gRPC interface diagnostic — folds the physical-parent
override into a unit ref's effective set with the same within-level union rule
(and then replaces the zone level with it, #6515), so the operator diagnostic
agrees with what the dataplane admits. Before #3720 it read
only the exact ref and reported "no override / default-deny" for a unit that in
fact inherited a physical override.

**Base-vs-unit-0 single-address reconciliation (#5699).** A non-VLAN unit 0
collapses onto the base netdev (`ge-0/0/0.0` → Linux `ge-0-0-0`), so the base
interface snapshot and the unit-0 snapshot (`buildInterfaceSnapshots`) enumerate
the IDENTICAL live kernel address through `buildLinkSnapshot`. `BuildZoneHostInboundViews`
groups addresses by `(zone, effective-token signature)`, and the base ref keys
its copy under `overrideByIface[ifN]` (physical-level override only) while unit 0
keys the same address under `overrideByIface[ifN.0]` (the base ∪ unit-0 merged
override above). A per-interface override on the **unit-0** ref therefore made
the two signatures diverge, emitting the SINGLE live address into TWO
host-inbound views with conflicting admit sets. Because the kernel
`xpf_hostinbound` destination-address rules carry no ingress-interface
predicate, whichever view's rule block sorts first decides — a deterministic
false-deny (the base view's narrower set drops a service the unit-0 override
opened). The fix skips the base (physical) snapshot's host-inbound address
contribution when unit 0 is configured: unit 0's snapshot is the authoritative
carrier (its merged override matches enforcement and `InterfaceHostInboundEffective`),
so the address resolves to ONE view carrying the `physical ∪ unit-0` admit set
(which post-#6515 replaces the zone level; before #6515 it was `zone ∪ physical ∪
unit-0`). The skip is gated on the ACTUAL same-netdev collapse
(`snapshotLinuxName(base, unit0) == snapshotLinuxName(base, nil)`), NOT merely
"unit 0 exists": a VLAN unit 0 (`VlanID > 0` → Linux `<base>.<vlan>`) or a
tunnel-mapped unit 0 resolves to a DISTINCT netdev, so the base and unit-0
snapshots enumerate DISJOINT addresses — skipping the base there would drop the
base netdev's own live address from every view and the kernel input chain would
fall through to `policy accept` (FAIL-OPEN). The base snapshot is kept as the
sole carrier both for a VLAN/tunnel unit 0 (distinct netdev) and for an
interface with no unit 0 at all (rare bootstrap / DHCP-on-raw-netdev), so an
address is never dropped from the deny scope.

**Gate alignment.** The commit-time duplicate-address gate
(`buildHostInboundOverrideMapLocal` +
`validateDuplicateHostLocalAddressStrict`, `pkg/config/dup_host_local_address.go`)
mirrors the same resolution and quarantine — `effectiveHostInboundSigLocal`
delegates to `EffectiveHostInboundTokens` — so the
`CanonicalHostInboundTokenSig` it compares equals the runtime's effective set.
That matters here specifically: the gate rejects two zones claiming one
firewall-local address with DIFFERING admission, so a signature built from a
different combination rule than enforcement uses would compare the wrong sets.

## DHCP and BOOTP are per-interface only in Junos (#6519)

Juniper, [Security Zones](https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-zone-configuration.html):

> "All services (except DHCP and BOOTP) can be configured either per zone or per
> interface. A DHCP server is configured only per interface because the incoming
> interface must be known by the server to be able to send out DHCP replies."

`dhcp` and `bootp` are therefore the two `system-services` tokens Junos does NOT
accept at the zone level. xpf accepts them there, and a zone-level token
authorizes udp/67-68 on the firewall-local addresses of every member interface —
an over-authorization relative to Junos, which would make the operator admit the
service interface by interface.

**Status: ENFORCED for the server/relay role since #7490; a deliberate
deviation everywhere else.** A zone-level `dhcp` / `bootp` no longer authorizes
udp/67-68 on a member interface that runs a DHCP **server or relay**. It still
does on every other interface — the firewall's own DHCP **client**, an
interface that is both, and one running neither.

**That per-role asymmetry is an xpf invention, not a Junos behaviour.** Junos
does not accept these two tokens at the zone level for **any** role. An operator
who observes that a zone-level `dhcp` works for a client and not for a server,
and concludes that is what Junos does, will carry that belief somewhere it is
false. The reasoning is in "Why only the server role" below; the code is
`pkg/config/host_inbound_dhcp_flip_7490.go`.

`validateHostInboundZoneLevelDHCPWarnings`
(`pkg/config/host_inbound_dhcp_scope_6519.go`) still emits one commit-time
advisory per zone, and after #7490 it says one of two things per interface:

| the interface is | the advisory says |
|---|---|
| **withheld** (DHCP server/relay) | the token **no longer authorizes** here; client DISCOVER is DENIED until you add `interfaces <if> host-inbound-traffic system-services dhcp`. This half is an **upgrade notice**, not a parity nicety |
| **retained** (client, both, or idle) | the token still authorizes here, which Junos would not accept — and keeping it is an xpf deviation |

The advisory deliberately asks the **unfiltered** question ("does the zone-level
stanza name this token for this interface") rather than reading the effective
set. Reading the effective set would make it go **silent on exactly the
interfaces the flip just narrowed**, so the operator whose DHCP server stopped
receiving DISCOVER would be told nothing.

Three details that matter:

- **A zone-level `all` counts.** `all` expands to the named-service union, which
  contains `dhcp` and `bootp` (`HostInboundAllExpansionServices`), so a zone-level
  `all` authorizes them on every member exactly as a named token would. The
  advisory reports that case explicitly, marked "via `all`", because the edit that
  fixes it is a different edit. An advisory that reported only the named token
  would have left the `all` case as a silent deviation.
- **`dhcpv6` is deliberately NOT covered.** The vendor sentence names DHCP and
  BOOTP. Extending it to the v6 token would be an inference, not a citation.
- **An interface that authorized the service ITSELF is not named.** The advisory
  fires for an interface whose EFFECTIVE set admits the token while its OWN
  interface-level stanza does not — i.e. the zone-level token is the authorizer.
  Stating the predicate that way keeps it correct both while the two levels union
  and after #6515 makes the interface level replace the zone level, without
  asserting which rule is in force.

### The advisory names the DHCP ROLE on each interface (stage 1.5)

The advisory annotates every interface it reports with WHY the zone-level token
is load-bearing there, because that role is exactly the discriminator the
deferred enforcement flip turns on:

| label | source | what a flip would mean there |
|---|---|---|
| `DHCP server` | a `dhcp-local-server` / `dhcpv6-local-server` group member, or a `dhcp-relay` group member | The case the vendor sentence covers — the server must know the incoming interface. Migrating to the interface stanza **matches Junos**. |
| `DHCP client` | the unit runs `family inet { dhcp; }` | The case the vendor sentence does **not** reach. The token is holding up the interface's **address**, not merely a service: a flip that dropped it would cost that interface its lease renewals. Move the token; do not drop it. |
| `no DHCP configured` | neither of the above | Pure over-admission — the token opens udp/67-68 for nothing. **Removing it narrows nothing in use, today, at no risk.** |

A relay counts as the server role because it too receives client DISCOVER on
udp/67 and must know the incoming interface to send the reply back.

Role matching treats a bare physical ref and a unit under it as the same
interface (the #3720 physical/unit relationship, `reth1` ↔ `reth1.0`) but keeps
two DIFFERENT units distinct (`reth1.0` vs `reth1.50`) — basing both sides on the
physical would leak a sibling unit's DHCP role onto an interface that has none,
and label an idle interface as vendor-backed for migration when it is not.

Only the v4 client is consulted: the tokens this advisory covers open udp/67-68,
and `dhcpv6` is deliberately outside the vendor sentence (above).

### The remedy accounts for #6515 replace semantics

Stage 1's remedy said "move the token to `interfaces <if> host-inbound-traffic
system-services ...`". Under #6515, a per-interface stanza **REPLACES** the zone
stanza on that interface, so following that verbatim drops every OTHER service
the zone admitted there — a zone admitting `ping ssh dhcp` narrows to `dhcp`
alone on the migrated interface. The sibling #6515 advisory does catch it and
names the lost tokens, but only on a LATER commit, after the narrowing has
already been authored. The message now carries the caveat up front.

### Why only the server role (#7490)

Junos accepts neither token at the zone level for any role, so withholding for
every role would be the more faithful change. #7490 declined it, and the reason
is the sentence the whole parity claim rests on:

> "A DHCP server is configured only per interface because the incoming interface
> must be known by the server to be able to send out DHCP replies."

That is an argument about a **server** needing ingress identity. It says nothing
about a client. Applying the rule past its own stated justification is an error
`docs/engineering-style.md` names, and here the penalty is not a wrong warning:

- **#7489 established the token is load-bearing.** The AF_XDP userspace
  dataplane enforces host-inbound on its local-delivery path, **fail-closed** —
  the earlier "AF_PACKET is upstream of netfilter" reasoning covered only one of
  two enforcement planes.
- So a zoned, non-lifeline interface running the firewall's **own DHCPv4
  client** would lose udp/68, and with it its unicast lease renewals, and with
  those its **address** — on a box whose recovery path may be a console.

Hence: withhold where the vendor's reasoning reaches, and decline to extend it
where it does not. Flipping every role remains available if strict parity is
later judged worth an upgrade break; taking it **after** this change is a
smaller step than taking it now, because the server/relay half has already
moved.

**An interface that is BOTH** a server/relay member and the firewall's own
client is **retained**, not withheld. The predicate is `server AND NOT client`,
and the conjunction is the point rather than an optimisation: on such an
interface the client half is what holds up the address, so withholding on
`server` alone would take the address from exactly the configuration the client
carve-out exists to protect.

**Lifelines are never withheld from.** They are excluded from host-inbound deny
scoping entirely, so filtering their token list would change what the
diagnostics render without changing what is admitted — inventing a divergence
rather than closing one.

### What the flip touches, and the one case it cannot express

The withholding decision is derived **once per commit**
(`stampZoneDHCPScopeWithheld`, run from the P5 `resolveDerivedConfig` phase) and
stamped on each `ZoneConfig` as `DHCPScopeWithheld`. That is what lets
`InterfaceHostInboundEffective` — the shared resolver every diagnostic surface
and the nft view builder reach — apply it with no signature change, so
enforcement and every description of it move together. It runs **last** of the
P5 sub-steps because the lifeline set reads the cluster fabric interfaces that
an earlier sub-step auto-populates.

Two planes need explicit handling:

- **nft (primary).** `BuildZoneHostInboundViews` groups by resolved token
  signature, so a withheld interface simply lands in its own group.
- **Rust AF_XDP (secondary).** Its picker consults the per-interface table first
  and **falls back** to the zone-keyed table when the interface has no entry.
  So `buildInterfaceSnapshots` now stamps a per-interface set for a withheld
  interface even when it declares no stanza of its own; without that the flip
  would be silently half-done on this plane only.

**A zone-level `all` is expanded on a withheld interface.** `all` stands for the
named-service union, which contains `dhcp` and `bootp`, and every plane expands
it at the admission predicate rather than in the token list — so leaving it
verbatim would re-authorize both through the back door. There is no token
spelling for "all except dhcp", so the union is materialised and the rendered
set for that interface reads as the expansion rather than `all`. That is the
truthful rendering: `all` is no longer what the interface admits.

**Uncovered residual: `any-service`.** The full-admit token is not a per-service
union and is not expanded, so a zone-level `any-service` still admits udp/67-68
on a withheld interface. The #6519 advisory has the same blind spot, and the two
share one predicate deliberately — an enforcement gate that disagreed with the
advice would tell an operator to migrate one set of interfaces and withhold on
another. Closing it is a separate change to both.

### What the flip does NOT mean: the server's request path was never gated

Withholding this token from a `dhcp-local-server` interface is expected to
change **nothing an operator can observe on the server's request path**, and
saying otherwise is a documented defect in this repo's history (#8060).
Measured on hardware (#6460, #7489, #8060):

- a DHCPv4 **DISCOVER/REQUEST** is addressed to `255.255.255.255`; the XDP shim
  hands that destination straight to the kernel, and Kea's `Dhcp4` runs in `raw`
  mode so it receives on an **AF_PACKET** socket delivered *before* the
  netfilter input hook. An nft INPUT drop **counted** the packet and Kea
  answered anyway. The same holds for a unicast to the interface's own address,
  because Kea's LPF admits both.
- a DHCPv6 **SOLICIT** is addressed to `ff02::1:2`, and every per-zone rule is
  scoped `<fam> daddr <zone unicast addrs>`, so a multicast destination matches
  nothing and falls through to the base chain's `policy accept`.

So the value of the flip is **parity and the removal of an over-authorization**
— a zone-level token opening udp/67-68 on the firewall-local addresses of every
member — not the prevention of an exposure that was live. What the bypass
argument does **not** cover, and what the advisory therefore names: a DHCP
relay's unicast leg, and the firewall's own DHCP client, whose RENEW **unicast**
to a zone address *is* daddr-matched. Those are why the token still has to be
expressible per interface.

### The shipped configs were migrated with the flip

`test/incus/xpf-cluster-fw{0,1}.conf`, `docs/ha-cluster.conf`,
`docs/ha-cluster-loss.conf` and `docs/ha-cluster-userspace.conf` all authored a
zone-level `dhcp` on a `lan` zone whose only member, `reth1`, runs the
`dhcp-local-server`. Each now **also** admits `dhcp` on `reth1` through a
per-interface stanza, restating the zone's other tokens because a per-interface
stanza REPLACES the zone stanza (#6515). The effective set on `reth1` is
unchanged, and a test walks all five to prove it — two of them are what
`make test-failover` deploys, and the cluster LAN host gets its lease from that
server.

The **zone-level tokens were kept**, not deleted. #8060's non-goal is explicit
that removing `dhcp` from that zone would be worse than the wrong comment it
replaced, and keeping it costs nothing: `reth1` now resolves from its own
stanza, and the zone level still covers any future member that declares none.

The `mgmt` zone's zone-level `dhcp` in the `xpf-cluster-fw*` files was **not**
touched: `fxp0` is a lifeline and runs the firewall's own client, so it is
retained on both counts.

## Multi-member bracket body applies to every member (#6391) — UPGRADE NOTE

> **This is an admission WIDENING. Read it before upgrading if any of your
> configs are hand-authored or loaded with `load override`.**

A per-interface `host-inbound-traffic` body authored ON a bracketed interface
membership now applies to EVERY member of that bracket. Before #6391 it applied
to the FIRST member only, and the remaining members silently fell back to the
zone-level set.

```
security {
    zones {
        security-zone trust {
            interfaces {
                [ ge-0/0/0 ge-0/0/1 ] {
                    host-inbound-traffic {
                        system-services { ssh; }
                    }
                }
            }
        }
    }
}
```

- **Before #6391:** ssh admitted on `ge-0/0/0` only. `ge-0/0/1` fell back to the
  zone-level host-inbound set.
- **After #6391:** ssh admitted on `ge-0/0/0` AND `ge-0/0/1` — what the config
  says.

So on upgrade, an interface that is a non-first member of a bracket carrying a
host-inbound body **newly admits** the services and protocols in that body. If
you were relying on the old under-application (deliberately or not), split the
stanza into per-interface statements before upgrading:

```
set security zones security-zone trust interfaces [ ge-0/0/0 ge-0/0/1 ]
set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services ssh
```

That flat-set form is scoped to `ge-0/0/0` alone and is UNAFFECTED by this change
— see below.

**Who is affected: essentially no one authoring via `set`.** The multi-member
shape is only reachable from a hierarchical parse — `load override` or a
hand-edited config file. A `set`-authored bracket list cannot produce it (the
schema models the interface name as a wildcard container, so `SetPath` nests the
bracket tail under the first member rather than widening its key). **No config in
this repository uses the shape**: the `.conf` fixtures under `docs/`,
`test/incus/` and `examples/deploy/` contain zero bracketed zone memberships.

**What did NOT change — the single-scoped guarantee.** A service authored under
ONE named interface via its own statement is scoped to that interface and never
appears on a sibling, including a sibling it shares a bracket with. That
invariant is unconditional and permanently pinned; PR #6389 broke it and was
closed unmerged. The two cases are distinguishable in the compiled AST (a
multi-member body is one container whose `Keys` carry both names; the flat-set
form is a container keyed on one name with the sibling as a membership CHILD),
which is what makes applying the body to every member safe here. Full mechanism:
`docs/config-schema.md`, "A per-interface `host-inbound-traffic` override is
scoped by the KEYS of the node it is authored on".

**Round-trip (#6668, fixed).** The multi-member shape survives config
persistence, HA config sync, `show | display set` → `load set`, and `load merge`
of a hierarchical file. Before #6668 the display-set form flattened into a
container keyed on the first member with the second demoted to a leaf keyword,
which failed to compile on reload; the same replay ran inside the daemon on the
`load merge` path, so a merge could rewrite the candidate. `display set` now
re-emits the authored `[ ... ]` group and the replay reconstructs it. See
`docs/config-schema.md`, "Round-trip: fixed in #6668".

**Revoking a grant made this way needs care.** A bracket-body grant has no
targeted `delete`: because the admission was authored on the multi-member node
rather than on either interface, there is no per-interface path to remove it
from just one member. The revocation that does work —
`delete security zones security-zone <z> interfaces [ a b ]` — deletes the
whole node, which also removes `a` and `b` from the zone entirely. That is
almost never what an operator wants, and on a zone-based firewall dropping a
zone membership is a much larger change than dropping a service.

The safe pattern, and the one to prefer when a grant may later need narrowing:
author per-interface statements instead of a bracket body. Two statements
granting `ssh` to `a` and to `b` are individually revocable; one bracket body
granting it to both is not. If you already have a bracket body and need to
revoke for one member, rewrite it as per-interface statements in the same commit
as the delete, so the zone membership is never actually lost.

## Repeated host-inbound-traffic blocks merge (#4544)

Junos MERGES two literal `host-inbound-traffic { ... }` blocks authored under
one `security-zone` (or one interface) into a single effective stanza — the
union of their `system-services` / `protocols`. xpf now matches that at both
the zone level and the #3362 per-interface level.

Where this bites is **`load override`** of a hand-authored file. The three
config-arrival paths differ in how they treat two same-key blocks:

- **flat-set** (`set ... host-inbound-traffic system-services ssh` then
  `... protocols ospf`) — `ConfigTree.SetPath` reuses the existing same-key
  container, so the two lines land under ONE node. Structurally immune.
- **`load merge`** — routes through `FormatSet` (a flat-set round-trip), so it
  merges for the same reason.
- **`load override`** (`store_command.go`, `s.candidate = tree`) — splices the
  RAW hierarchical parse straight into the candidate and commits it with no
  FormatSet round-trip. The hierarchical parser (`parseStatements`) keeps two
  literal `host-inbound-traffic { ... }` blocks as **separate same-key
  siblings** — it does not merge them — and there is no duplicate-block schema
  rejection.

Before #4544 the compiler dropped every block but one on the load-override path:
the zone-level `case "host-inbound-traffic"` OVERWROTE (`zone.HostInboundTraffic
= parseHostInboundNode(prop)`, last block wins) and the interface-level reader
used `FindChild` (first block wins). Either way the operator's authored
admission set silently narrowed — a service DoS — or fail-opened if the dropped
block was the restrictive one. A Junos-EXPORTED config always shows one already-
merged block, so the trigger is a hand-authored duplicate + `load override`.

The fix (`mergeHostInbound`, `pkg/config/compiler_security_zones.go`) accumulates
across **all** `FindChildren("host-inbound-traffic")` at both levels and unions
their token sets, deduplicated (first-seen order). A **single** block is
byte-identical to the pre-#4544 behaviour — the first parse is returned
unchanged, with no dedup, so a single block keeps its exact token multiset;
dedup applies only when a second block is actually merged. RED-on-revert guards:
`pkg/config/host_inbound_dup_block_4544_test.go`.

This is orthogonal to the "Per-interface override precedence (#3362, #3720,
#6515)" section above, which resolves host-inbound authored at DIFFERENT
granularities (`physical ∪ unit`, then REPLACING the zone level). #4544 merges
repeated blocks at the SAME granularity.

**#4818 extends this merge one level UP.** #4544 merges repeated
`host-inbound-traffic {}` blocks *within one* `security-zone <name> {}`
instance. It did not help if the DUPLICATE was the outer instance itself — a
`load override` with two literal top-level `security-zone trust { ... }`
siblings (one carrying `interfaces`, the other carrying
`host-inbound-traffic`) still lost the first instance wholesale, because
`compileZones` allocated a brand new `ZoneConfig` per instance and the #4544
merge logic never got a chance to run against the discarded first instance's
properties. #4818 makes `compileZones` find-or-create the `ZoneConfig` by
name across instances too, so `mergeHostInbound` now unions
host-inbound-traffic both *within* one instance (#4544) and *across* sibling
instances of the same zone name (#4818) — and the per-interface
`InterfaceHostInbound` map merges the same way when two instances both
declare host-inbound-traffic on the same interface name. See
`docs/config-schema.md`'s "#4818/#4820/#4821" duplicate-block-registry entry
for the two sibling fixes (`services rpm probe`, `security ssh-known-hosts
host`) that share this exact root cause at the named-instance level.
RED-on-revert guards: `pkg/config/zone_dup_block_4818_test.go`.

## Ingress-zone judgement (#9637)

Junos admits host-inbound traffic by the zone of the interface it **arrives on**.
The destination-address rules judged it by the zone that **owns the address it
names**, and the two disagree whenever those zones differ:

- **Exposure.** A client on a zone that denies ssh reached ssh on another zone's
  address.
- **Over-refusal.** A zone that admits ssh was refused on another zone's address.
  This was measured on the loss cluster on 2026-09-11: from `lan`, which admits
  ssh, TCP/22 to the `wan` and `sfmix` addresses timed out while ping answered.

The `xpf_hostinbound` chain now carries two rule sets, in this order, after the
global accepts:

1. **Ingress-zone rules** (`emitHostInboundZoneIngress`,
   `pkg/daemon/host_inbound_ingress_9637.go`, mirrored rule-for-rule by
   `emitHostInboundZoneIngressNetlink`). Each view, in each family, emits
   `iifname <view netdevs> <fam> daddr <every judged address> <match> accept` for
   each listed service or protocol, then the same scope with the zone's deny
   counter and `drop`. "Every judged address" is every view's addresses plus the
   addressed-but-unzoned set (#4420), which is exactly the set rule set 2 judges.
   A packet on a view's netdev is decided here, whichever of those addresses it
   names.
2. **Destination-address rules**, unchanged. A packet on a netdev no view claims
   meets only these, exactly as before #9637.

Both rule sets judge the same destination addresses, so no packet reaches the
chain's accept policy that did not before. A netdev left out of every scope loses
coverage, but it never admits anything it did not admit before.

**Which netdevs a view claims** is decided by `hostInboundViewIngressNetdevs`
(`pkg/dataplane/userspace/zones_host_inbound.go`). A view claims the netdevs of
its own interface **units**, by the snapshot `LinuxName` the dataplane uses. A
RETH unit therefore resolves to its member netdev on the node (`reth1.0` →
`ge-0-0-1` on node 0), and a VLAN unit to `<parent>.<vlan>`. It does not claim:

- a physical row's netdev. That is either a trunk parent, whose tagged frames
  arrive on the subunit netdevs, or the netdev its unit 0 collapses onto, which
  that unit claims.
- a netdev claimed by more than one (zone, token-set) view. Whichever view's
  rules came first would decide it.
- a lifeline netdev (fxp0 / em0 / fab*), so management and cluster control are
  never judged by a data zone.
- a netdev enslaved to an l3mdev VRF (#6619,
  `config.HostInboundVRFEnslavedNetdevs`), because at LOCAL_IN `iifname` names
  the VRF master. A routing-instance member zone, such as `sfmix` on the loss
  cluster, therefore stays judged by destination address.

**What an operator can observe.**

- Cross-zone host-inbound follows the ingress zone **for a packet the kernel
  receives on its ingress netdev**. A zone that does not admit ssh is refused on
  every such address, including one owned by a zone that admits ssh (the
  exposure). Measured on the loss cluster: TCP/22 from the WAN VLAN 80 segment to
  the LAN VIP went from admitted to dropped, while ping answered.
- **Residual over-refusal (measured, not closed by #9637).** The XDP shim does not
  pass every host-bound packet to the kernel on its ingress netdev.
  - A destination owned by interface-mode source NAT is reported non-local by
    `is_local_destination`, so its reverse-NAT repair can run (#290). Such a
    packet goes to the userspace dataplane.
  - The userspace dataplane applies its own ingress-zone host-inbound check, then
    reinjects the packet through `xpf-usp0`.
  - The kernel chain sees `iifname xpf-usp0`, which no view claims, so the
    destination-address rules judge it by the address's owner.
  - On the loss cluster the `lan-to-wan` rule is `source-nat interface`, so TCP/22
    from the LAN host to the `wan` addresses is still refused. A capture on fw0
    showed those SYNs arriving on `xpf-usp0`, while a SYN to the LAN VIP arrived
    on `ge-0-0-1`. Closing this needs the reinject path to carry the ingress zone
    to the kernel chain.
- The per-zone deny counters (#3361) count the drop under the ingress zone.
- The fences (#5644 cold-boot, #5789 gap) are unchanged. They drop by destination
  address, with no per-service accepts, over the same address set.
- `make test-host-inbound` probes from the LAN host. Its `wan` ssh cells remain
  DENY, because those addresses are interface-NAT addresses and take the reinject
  path above. The smoke says so beside the cells, which flip to ADMIT once the
  residual is closed.

Pinned by:

- `TestHostInboundIngressZoneVerdictsOnRealKernel9637`. Three client namespaces
  reach a listener through the rendered ruleset. The destination-only ruleset
  reproduces both directions of the defect, the ingress-scoped one inverts both,
  and an unclaimed netdev is still judged by destination.
- `TestHostInboundIngressRulesShape9637` and
  `TestZoneHostInboundViewIngressNetdevs9637`.
- The T1 parity fixture (`TestNftNetlinkParity`), which gives `IngressNetdevs` to
  every rendering branch.

## Duplicate host-local-address ambiguity (#3718, Option B)

The kernel host-inbound chain's destination-address rules match on
**destination address only**. Each is `<fam> daddr <zone-addrs> ...`, with **no**
ingress-interface / VRF / zone predicate, in a **single global**
`inet xpf_hostinbound` input chain (`emitHostInboundZone`,
`pkg/daemon/daemon_nft.go`). Since #9637 the ingress-zone rules come before them
and decide every packet that arrives on a netdev some view claims. What follows
describes the destination-address rules, which still decide every other packet.
So when two security zones
resolve the **same** firewall-local address — a duplicated interface address, a
duplicated VRRP VIP, or the same address reused across routing-instances (a zone
is not VRF-scoped in xpf, so overlapping-VRF reuse surfaces as the cross-zone
case) — they emit two rule blocks keyed on the same `daddr`, in zone-sort order,
and the **earlier-sorting zone decides the packet** regardless of which zone /
interface the traffic actually ingresses. A zero-service zone emits only a
terminal catch-all `drop` for the address, so if it sorts first it drops every
host-bound service the other zone opened (or the inverse admits what the owning
zone denied). Worse, the userspace-dp secondary path (`host_inbound_admits`,
`forwarding/host_inbound.rs`) is **already ingress-zone scoped**, so the kernel
`daddr` path and the userspace path can render **opposite** verdicts on the same
packet — a kernel/userspace split-brain.

This is caught fail-closed at commit and surfaced at runtime:

- **Commit-time gate** `config.validateDuplicateHostLocalAddressStrict`
  (`pkg/config/dup_host_local_address.go`) hard-rejects a config where the same
  `(family, host address)` — an interface address OR a VRRP VIP — is
  host-inbound-reachable from **more than one distinct effective host-inbound
  token set**. It keys on differing token sets, NOT merely ">1 zone", so it does
  **not** false-positive on a deliberate duplicate: the same address in two zones
  with **identical** host-inbound service sets renders the same block twice
  (order-independent, both paths agree) and is allowed; only a differing set (two
  zones with different `host-inbound-traffic`, or one zone with differing #3362
  per-interface overrides) is rejected. Covers IPv4 (H01), IPv6 (M02), VRRP VIPs
  (M03), and the cross-zone subset of same-address-across-routing-instances
  (M04). Management / cluster-control lifeline interfaces (fxp0 / em0 / fab<N>) are
  excluded, mirroring the deny scoping. On the tolerant load / peer-sync path the
  rejection is downgraded to a `cfg.Warnings` entry (`lenientDuplicateHostLocalAddress`)
  so an already-persisted or peer-synced config an older binary accepted still
  boots (#1960 no-brick).
- **Runtime SSOT** `dpuserspace.AmbiguousHostInboundAddresses`
  (`pkg/dataplane/userspace/zones.go`) reads the scopes back from
  `BuildZoneHostInboundViews` (the same builder that drives nft emission), using
  the shared `config.CanonicalHostInboundTokenSig` so it can never disagree with
  the commit gate on what counts as a differing set. Unlike the addressless
  window above, an ambiguity is **NOT self-healing** — it stands until the config
  is fixed.
- **State-transition log** (`daemon_nft.go`,
  `logHostInboundAmbiguousTransitions`): a `WARN` on ENTRY, an `INFO` on RECOVERY,
  logged once per transition (not every apply).
- **Prometheus gauge** `xpf_host_inbound_ambiguous_addresses{address,family}`
  (`pkg/api`), value `1` per ambiguous address, emitted BEFORE the dataplane gate
  so it stays visible in a config-only / degraded boot. Alert with
  `max_over_time(xpf_host_inbound_ambiguous_addresses[1h]) > 0`.

### Deferred follow-ons

Option B rejects the ambiguity fail-closed; it does **not** yet make the kernel
path ingress-scoped. Two follow-ons are tracked on #3718:

- **Option A — kernel `iifname` ingress-scope**: emit host-inbound rules with an
  `iifname` predicate, so the ingress zone disambiguates the `daddr`.
  **Delivered by #9637 for every netdev a view claims.**
  - It was deferred because an ingress rule set must enumerate every ingress
    netdev, or a legitimate management packet fails closed. #9637 avoids that
    requirement rather than meeting it: the ingress-zone rules come first, and
    the destination-address rules stay behind them as the judge for any netdev
    the scope leaves out.
  - Those netdevs are VRF members, `lo`, lifelines, trunk parents, and netdevs
    claimed by two views. An incomplete enumeration therefore costs coverage,
    never admission, and a packet on a left-out netdev keeps its pre-#9637
    verdict.
  - VRF-member zones are the remaining gap. They stay destination-judged
    (#6619).
- **Option C — per-VRF host-inbound chains**: separate per-routing-instance input
  chains so the same address can be **intentionally** reused across VRFs with
  distinct host-inbound policies (which Option B rejects). A larger architectural
  fork; deferred until there is demand.

## `to-zone junos-host` policy and the direct host-bound path (#4146)

vSRX layers management-plane admission in two places: the coarse
`host-inbound-traffic system-services <svc>` port gate above, PLUS a fine
`security policies from-zone <z> to-zone junos-host` (or a global
`match to-zone junos-host`) policy that can restrict the source or application
and can `then deny`. On xpf the **representable ordered `then deny` class is now
kernel-enforced on the direct host-bound path** (direction (b), #4146 below); an
un-representable remainder (feed-tainted source, multi-term/ALG application,
scheduler-gated policy, `tcp-rst` ingress zone, `reject`, and the "deny
non-permitted" half of a source-restricted `permit`) is a documented
partial-coverage limitation that keeps the commit warning.

### The gap

Ordinary traffic to a firewall interface IP is delivered by the **Linux kernel**,
not the userspace dataplane. On a session miss the XDP shim's `is_local_destination`
(`userspace-xdp/src/lib.rs`) returns true for any address in the local set and
shunts the packet to the kernel (`cpumap_or_pass`). The nft `xpf_hostinbound`
chain — the PRIMARY enforcement surface documented above — is **permit-by-service
only**: it admits configured `system-services`/`protocols` to a firewall-local
address from **any** source, with **no per-source and no per-application deny**.
The fine `to-zone junos-host` policy runs **only** on the userspace AF_XDP
`LocalDelivery` path (`junos_host_local_policy`), which is reached only by the
subset of host-bound traffic that arrives on the XSK fast path (e.g. DNAT /
static-NAT to a firewall-local address) — never by a direct-to-interface-IP
packet, which was already shunted to the kernel. Net: a
`from-zone X to-zone junos-host { match source-address ...; then deny; }` (or a
source-scoped permit) on a plain interface IP is silently unenforced for the
direct path; hit counters stay zero. This is distinct from #3019 (which wired the
deny into the XSK `LocalDelivery` arm) and #3292 (the flowless arm): those are the
XSK paths that DO enforce it.

### Enforcement (direction b — shipped, #4146)

The representable `to-zone junos-host` DENY class is enforced on the direct
host-bound path by a DROP-only subchain in the kernel `xpf_hostinbound` chain —
the availability-preserving locus (the kernel delivers the packet; the userspace
helper never sees it, so a helper crash cannot lock management out).

- **Projection SSOT (`config.BuildJunosHostDenyProjection`,
  `pkg/config/junos_host_deny.go`).** Per ingress zone, the effective ordered
  program is assembled in Junos's exact three tiers — exact `from-zone Z to-zone
  junos-host` → `from-zone any to-zone junos-host` (#3090) → applicable global
  `match to-zone junos-host` — mirroring `policymatch.matchJunosHost` /
  userspace-dp `evaluate_junos_host_policy`. The projection is decided on the
  **whole ordered program**: if any contributing term is un-representable the
  program emits nothing (no coarsened / partial rule) and its policies keep the
  warning.
- **FIRST-MATCH, never a fine accept (#9504).** Each ingress zone's program
  renders, in authored order, into its own nft chain that the `xpf_hostinbound`
  input chain enters with an `iifname`-scoped `jump`. A `deny` drops (answering
  TCP with a RST on a `tcp-rst` zone), a `reject` answers (TCP RST, else ICMP
  administratively prohibited), and a `permit` RETURNS from the subchain, so the
  coarse host-inbound gate still decides. A permit NEVER emits a fine `accept`
  (that would let it re-admit a coarse-rejected service — Rust
  `poll_descriptor/mod.rs:138`); `return` leaves the fine program without
  admitting anything.

  A packet that matches no rule returns as well. **xpf applies no implicit
  junos-host default-deny on any path** — `evaluate_junos_host_policy_l3_aware`
  (policy.rs) and `policymatch.matchJunosHost` both deliver on no match, which is
  the management-lifeline guarantee — so the kernel program must not invent one
  either. The consequence for an operator is stated under the warning below: a
  restricted `permit` alone restricts nothing, on any path.

  Before #9504 a permit could be projected only as a `saddr !=` SUBTRACTION of
  later denies. That cannot express a carve narrowed on any other dimension, so a
  narrow-application, source-excluded or destination-scoped permit made the WHOLE
  program un-representable — which silently disabled kernel enforcement of every
  other junos-host deny on that ingress zone, including the canonical management
  ACL (`permit <mgmt-net> junos-ssh` followed by `deny any`).
- **Ingress `iifname` scope, never `daddr` as the ZONE scope.** The DROP is scoped
  by the from-zone's kernel netdev names
  (`pkg/dataplane/userspace/BuildJunosHostPrograms`), excluding lifelines
  (fxp0/em0/fab<N>) — a daddr-derived zone scope would both under- and over-deny
  across zones. A global-any term renders per ingress zone with that zone's
  netdevs, never unscoped. An EXPLICIT `match destination-address` adds a
  narrowing `daddr` predicate ON TOP of that iifname scope (see the destination
  slice below); it never replaces it. Because the scope is the ingress netdev, a
  destination-scoped deny on a data zone can never suppress management ingress on
  a lifeline, whichever firewall address it names.
- **An l3mdev VRF netdev cannot be an `iifname` scope (#6619).** The daemon
  enslaves every interface member of every routing instance whose
  `instance-type` is not `forwarding` to `vrf-<name>`
  (`pkg/daemon/daemon_apply_interfaces.go` → `BindInterfaceToVRF` →
  `LinkSetMaster`). At the netfilter LOCAL_IN hook the l3mdev receive handler has
  already replaced `skb->dev` with the VRF device, so `meta iifname` names the
  **master**, never the enslaved interface, and `iifname "ge-0-0-1" … drop`
  matches nothing. Measured firsthand at the exact hook and priority
  `xpf_hostinbound` installs (inet base chain, hook `input`, priority 10) on the
  kernel floor this project targets: `c_slave(veth1)=0  c_master(vrf-t)=3
  c_any=3` — and `c_any=3` for three packets proves the hook runs **exactly
  once**, so the zero is "it does not happen", not "a second pass was missed".
  Such a netdev is therefore dropped from the scope. Before #6619 it was kept:
  the zone emitted a representable program whose rules never matched AND, being
  representable, suppressed its own #4168 warning — config commits clean, rules
  present in the ruleset, nothing enforced.

  **Not the same finding as #4455 Component A**, which is PLAN-KILLed. That
  proposed to ADD a first-ever `iifname` predicate for *multicast admission*, and
  was killed on reachability plus three attribution fragilities —
  RETH→physical-member resolution, guess-on-malformed input, an address-lazy
  interface source. l3mdev/VRF is in none of them, and this is a gate that
  already shipped (#4932/#4146) on a different feature.

  **Do not "fix" this by scoping on the VRF master name instead.** That rule
  would match every interface in the VRF, including unzoned ones and any lifeline
  bound to the same VRF — management stranding of the #7284 shape, where lifeline
  exclusion is by INTERFACE and not by address value. Making it safe would need
  full VRF-membership attribution including tunnel interfaces bound through
  `pkg/routing/tunnel.go`'s `tc.RoutingInstance`, which is the fragile-attribution
  territory #4455 Component A died in. Enforcement under VRF, if ever wanted,
  needs its own design with that as the acceptance gate.

- **Scope resolution is a COVERAGE question, not an existence one (#6564
  member 8).** Two decisions come out of the resolved scope and they are
  deliberately not one boolean:

  - **Emit rules** when at least one candidate resolved. Protection that works is
    never withdrawn — a zone that resolved some of its ingress netdevs still gets
    a kernel deny on those.
  - **Suppress the #4168 warning** only when every OWN candidate resolved. A zone
    that resolved *some* is not enforcing the policy on every ingress path, and
    `len(netdevs) > 0` cannot tell that from full coverage — it reported such a
    zone as fully enforced.

  A zone with NO candidates at all (lifeline-only, or no interfaces) is a third
  state and must stay distinct: there is nothing to enforce, so it must not block
  suppression. The distinction is exactly `len(Unscopable) > 0` — the zone HAD
  candidates and could not use them all.

- **Representable is not enforced — a deny that projects NO rule keeps its
  warning (#6705).** The suppression asks whether the kernel gate enforces the
  deny, so it gates on the deny having actually EMITTED a rule, not on the
  program having been representable. A deny term can pass every representability
  check and still project nothing:

  - an application-any permit for **every** source ahead of it — `junosHostBuildRule`'s
    `permitAll` arm drops the deny because nothing is left to drop;
  - its application resolves entirely to the OTHER family (an ICMPv6 app on the
    inet chain);
  - its address match is the #5828 degenerate `any` + `*-excluded` empty set.

  Before #6705 all three produced an empty DROP program whose deny still counted
  as rendered, so the operator got neither the enforcement nor the diagnostic —
  the same failure shape as the l3mdev case above, reached without any scoping
  problem at all. `junosHostProjectProgram` now reports which term keys
  contributed at least one rule, and a deny that contributed none blocks its own
  suppression exactly as an un-representable program does. The two families are
  recorded per family (v4 and v6 separately), so an IPv6-only deny is rendered on
  its own.

  **What #6705 is NOT.** It was filed as a valueless-or-omitted `match` dimension
  erasing the program through a clean strict commit. Measured against the real
  compiler, that vector does not exist: an omitted dimension is rejected by the
  #3044 required-match gate, a valueless one by the #6526 no-operand gate (both
  in the zone-pair and global-policy spellings), and an unresolvable address-set
  by #3149. The reachable input is a fully authored `source-address any` permit —
  legitimate configuration, which is precisely why it carried no flag. Tests pin
  both rejections so relaxing either gate cannot silently re-open the path.

  **The tolerant channel DID reach it (#9572).** Those two gates guard the strict
  commit only. The tolerant compile (`CompileConfigLenient`, used on the
  persisted-load and HA peer-sync paths) downgrades both rejections to warnings.
  It then compiles the policy with the dropped dimension left EMPTY, flagged
  `LenientContentDropped` (#5575). The userspace snapshot builder refuses such a
  policy.

  The kernel projection used to read the empty dimension as `any`. So an omitted
  or valueless `application` became an application-any permit, and an omitted or
  valueless `source-address` became a permit for every source. Either one erased
  every later deny from the program. The daemon still installs this program from
  the config the helper refused, and on the host-bound path it is the
  enforcement. A poisoned permit also blocked the deny that followed it
  (narrow-application poison) whenever its application was narrow.

  `junosHostProjectTerm` now marks a poisoned PERMIT, and
  `junosHostProjectProgram` skips it. Its real carve cannot be recovered from
  dropped content, so later denies render as authored. That can only drop MORE
  host-bound traffic than configured, never admit traffic a deny names. A
  poisoned DENY is unchanged: its empty dimension widens a DROP, which is the
  fail-closed direction.

  Covered by `pkg/config/junos_host_poisoned_permit_9572_test.go` and the
  rendered-nft cell in `pkg/daemon/host_inbound_junos_host_4146_test.go`.

  **Only an OWN netdev counts toward the gap.** A VLAN subunit contributes its
  physical parent as an extra candidate for the bondless-RETH case where frames
  may ride the member. On a plain 802.1Q trunk the parent is never where the
  subunit's frames arrive, so losing it costs that zone nothing. Counting a
  dropped parent as a coverage gap would warn on every trunk carrying an untagged
  unit-0 in one zone and tagged subunits in others — an ordinary correct config,
  and an advisory that fires on those stops being read at all.
  `TestJunosHostCrossZoneAmbiguousTrunkKeepsWarning` (pkg/config) and the
  parent-superset row of
  `pkg/dataplane/userspace/junos_host_vrf_scope_6619_test.go` both hold this
  line.

  **No packet changes verdict.** Dropping an enslaved netdev removes only rules
  that provably never matched, and partially-resolved zones keep every rule they
  had. The whole behaviour change is commit-time warnings that were previously
  suppressed.

- **Coarse-then-fine order (`pkg/daemon/daemon_nft.go`).** The fine DROP runs after
  ESP/AH accept + the firewall-originated reply-direction established accept, but
  BEFORE the ND/PMTUD accepts and the residual full established accept, so a denied
  source's NEW *and* original-direction-established inbound (including its
  ND/PMTUD) are dropped — matching Rust's per-hit re-eval/teardown. ESP/AH (proto
  50/51) are always exempt; IKE 500/4500 is shielded when the ingress interface
  coarse-admits `ike`; ident-reset TCP/113 keeps its RST when the interface's
  effective coarse verdict is the RST (ident-reset set AND not `any-service`).
  #3226: `all` no longer shadows ident-reset — it EXPANDS to a set containing
  ident-reset, so the kernel chain really does emit the reject rule and the
  shield must carve TCP/113 out (`HostInboundServiceTokenExpansion`).
  - **Per-interface scope of the IKE / ident shield (#5565).** The shield is
    scoped to the SPECIFIC netdevs whose EFFECTIVE per-interface host-inbound set
    (`InterfaceHostInboundEffective`: the interface override where declared,
    else the zone-level set — #6515) admits the
    exemption — `JunosHostDenyProgram.IKEExemptNetdevs` / `IdentResetNetdevs`,
    each a subset of the program's `IngressNetdevs`. A per-INTERFACE `ike` /
    `ident-reset` override therefore shields only the interface(s) that configured
    it (`iifname "<that-netdev>" ...`), never the whole zone iifname set — a
    least-privilege override on one interface is not widened to a sibling that did
    not configure it. A genuinely ZONE-LEVEL exception (authored on the zone's own
    `host-inbound-traffic`) is folded into every interface's effective set, so its
    subset equals `IngressNetdevs` and the shield stays zone-wide (no regression).
    The zone-wide `application any` DROP itself is unaffected — the deny is a zone
    policy and still scopes by the full zone iifname set; only the ACCEPT/RST
    exemption ahead of it is narrowed. Before #5565 the shield used a single
    zone-wide `CoarseAdmitsIKE` / `CoarseIdentResets` bit derived by unioning
    every per-interface override, so one interface's `ike` falsely admitted IKE
    on every interface in the zone.
  - **Operator note — exempt tuples survive an `application any` deny.** On an
    **IKE-admitting** zone, `from-zone Z to-zone junos-host { match source-address
    BAD; match application any; then deny; }` does **NOT** stop BAD's IKE / IPsec
    NAT-T (UDP 500/4500): the userspace IPsec-passthrough stage returns BEFORE the
    fine junos-host policy, and the kernel decrypts host-terminated IPsec before
    any deny — so 500/4500 is admitted regardless of the deny. Likewise on an
    **ident-resetting** zone (`system-services ident-reset`, not `all`) the same
    deny still answers BAD's TCP/113 with a RST, not a silent drop. This is
    faithful to the Rust runtime (Stage-11 passthrough / the coarse ident-reset
    terminal both run pre-fine), not a bug. To actually deny IKE/ident from a
    source, remove the coarse admission (drop `ike` / `ident-reset` from the
    zone's `host-inbound-traffic`) rather than relying on a junos-host `deny`.
- **Observability.** `xpf_host_inbound_junos_host_denies_total{scope,family}`
  (nft named counters, distinct from the coarse
  `xpf_host_inbound_kernel_denies_total`). This does **not** populate per-Junos-
  policy hit counters / `then count` / RT_FLOW deny attribution — nft cannot
  attribute a drop to a policy object; that is the one "counters stay zero" symptom
  the direct path retains. The userspace XSK path keeps its own attribution.

**Representable subset:** action `deny`, `reject` or `permit` (#9504); `match
source-address` / `source-address-excluded` **and** `match destination-address` /
`destination-address-excluded` resolving entirely to *static* address-book CIDRs
(recursively feed-untainted); `match application` reducing to simple
proto + optional dst/src port + optional ICMP type/code (application-sets
OR-expanded to multiple rules); **no** `scheduler-name`. A `tcp-rst` ingress zone
is representable: its denies render as a TCP `reject with tcp reset` ahead of the
drop for everything else, which is what `enqueue_deny_reply` (reject_reply.rs)
does at runtime.

**Address-match semantics (source AND destination).** Both dimensions route
through ONE projection formula (`junosHostProjectAddrMatch`,
`pkg/config/junos_host_deny.go`) so they cannot drift, and both mirror Junos
`matchAddr`:
- A **constrained** set (e.g. `source-address 10.0.0.0/8` + excluded) drops
  every source EXCEPT the set on the family that carries a prefix (IPv4:
  `saddr != 10.0.0.0/8`), and — because the set has no prefix of the *other*
  family — drops **ALL** of that other family (IPv6 here): "everything except
  10/8" is all IPv6. This match-all-of-opposite-family behavior is intentional.
- The **wildcard** case `any` (or the family-scoped `any-ipv4` / `any-ipv6`) +
  excluded is the degenerate "every address EXCEPT every address" = the **empty
  set**: it matches NOTHING and projects **no drop rule** for the affected
  family. `any` suppresses both families; `any-ipv4` / `any-ipv6` suppress only
  their own. Emitting an unconditional drop here (the #5828 bug — the old
  `len(src)==0 => SrcAny` classification) would invert the authored domain and
  could lock out **all** direct host-bound traffic on the ingress zone. A plain
  `source-address any` + `then deny` with **no** exclusion is unaffected — that
  is a legitimate drop-all deny and still emits the unconditional drop.
- A **constrained positive** set with no prefix of a family matches nothing on
  that family and emits no rule there (Junos empty-positive-set semantic).

**`match destination-address` on a DENY (#4146 destination slice).** The kernel
`xpf_hostinbound` chain hooks the INPUT path, so every packet it evaluates is
already host-destined; an explicit destination therefore renders as a narrowing
`<fam> daddr <set>` / `daddr != <set>` predicate **on top of** the `iifname`
zone scope — never as a replacement for it. A destination naming no firewall
address simply matches nothing in the chain, exactly as the Rust /
`policymatch` evaluation of that policy matches nothing, so the live
firewall-local address set is **not** needed to render it. Rust already matched
this dimension on the junos-host path (`rule_l3_matches(rule, state, src_ip,
dst_ip)` in `evaluate_junos_host_policy_l3_aware`); the kernel projection was
the only surface dropping it, which made a `from-zone X to-zone junos-host {
match destination-address <fw-ip>; then deny; }` silently unenforced — and,
because the representability gate is whole-program, silently disabled kernel
enforcement of **every other** junos-host deny on that ingress zone.

A destination-scoped **`permit`** stays un-representable: a permit is projected
only as a `saddr !=` SUBTRACTION of later denies (see DROP-only above), which
cannot express a carve that is also destination-scoped. The whole program then
emits nothing and every one of its policies keeps the warning — never a deny
widened past the permit's destination scope.

**Un-representable remainder (keeps the commit warning below):** feed-tainted
source **or destination**, a **MIXED direct+term** or ALG-bearing application, an
application scoped to an IPsec/ident exempt tuple, and a scheduler-gated policy
(time-windowed: rendered as an always-on rule it would carve or drop outside its
own window). A zone whose ingress netdevs cannot all be scoped (#6564, #6619) and
a lifeline-only zone keep the warning for their own reasons, above. No
partial/coarsened kernel rule is ever emitted for the remainder.

**Not in the remainder, and not enforced anywhere: the "deny non-permitted" half
of a restricted `permit`.** It is not a kernel-vs-userspace gap — xpf has no
implicit junos-host default-deny on either path — so the fix for an operator who
wants it is an explicit `then deny` policy after the permit, which the kernel
chain now enforces. The commit warning for a restricted permit says exactly that
(#9504); it previously said the restriction held on the userspace path, which was
false.

A **pure multi-term** application is NOT in that remainder, contrary to earlier
revisions of this paragraph. A `term`-bearing application with no direct match
body compiles to an implicit application-SET — the parent struct is discarded and
each term is stored as its own application (`compiler_applications.go`) — so
`junosHostResolveApplications` takes the application-set branch and OR-expands
every term into its own L4 fragment, exactly as the representable subset above
describes for application-sets. The deny IS enforced, so the hazard on this row
is the inverse of the one previously documented: a PARTIAL expansion would render
a kernel deny **silently narrower** than authored. Only a MIXED direct+term
application is un-representable (`MixedDirectTermApps`), and the strict structure
gate hard-rejects that at commit before it can reach the projection.

**Each member of this remainder owes BOTH halves.** "No kernel rule is rendered"
AND "the #4168 warning fires naming the policy" — either alone is satisfiable by
a bug, and a policy that renders nothing while saying nothing is the silent
failure this projection exists to avoid.
`pkg/dataplane/userspace/junos_host_residual_6612_test.go` asserts both halves per
class, and gives every row a FLIP (the same fixture with the residual attribute
neutralised) so a row cannot pass because the fixture was broken in some other
way. Covered today: scheduler-gated deny, feed-bound source, feed-bound
destination, `reject`, `tcp-rst` zone, ALG application, IKE-exempt-tuple
application, source-restricted permit.

A destination-scoped `permit` was silent on BOTH halves until #6612: it rendered
nothing and produced **zero warnings of any kind**. The projection correctly
refused to render it (`junosHostProjectTerm`: `p.Action != PolicyDeny &&
(junosHostAddrScoped(dest) || DestinationAddressExcluded)`), but
`junosHostPolicyStricterThanCoarseGate`
(`pkg/config/compiler_validate_warn_host_inbound.go`) admitted a permit as
stricter-than-coarse only through `junosHostPolicySourceScoped`, which inspects
the SOURCE dimension alone. One system held both beliefs: the projection knew it
could not enforce the policy, and the advisory never said so. The warning now
keys on the SAME expression the projection applies — deliberately not a second
copy of the condition, because a divergence between the two is always a bug.
`destination-address-excluded` is covered as its own disjunct, so a config using
the inverted form is not left with a residual of the bug's own shape.

**Worse than silence — the shape to remember.** A destination-scoped permit
followed by a deny emitted exactly ONE warning, and it named the **deny**. An
operator saw output, reasonably concluded the config had been checked, and the
policy that silently enforced nothing was not the one named. A partial signal
that points at the wrong policy is more dangerous than no signal, which at least
invites suspicion.

**Why this class needs two fixtures.** The two halves cannot be made
gate-sensitive by one config, and the reason is structural. For the RULES half to
red when the projection's destination gate is removed, the permit needs a
CONCRETE source — with `source-address any` it sets `permitAllV4` and shadows
every later deny outright, so nothing renders either way. For the WARNING half to
red when the advisory clause is removed, the permit must NOT be source-scoped, or
it warns through the source predicate and proves nothing about the destination
dimension. The two requirements are mutually exclusive, so the class is bound by a
table row (source `any`, pinning the advisory clause) plus
`TestJunosHostDestinationScopedPermitDoesNotWidenALaterDeny6612` (concrete source
ahead of a deny, pinning the projection gate).

The third dimension, an APPLICATION-scoped permit, has the same silent shape and
is tracked separately in #7374: it needs a comparison against the zone's
EFFECTIVE admit set rather than a token test, because a syntactic
"application != any" rule would warn on configs that have no gap at all.

### Commit-time warning (direction c — shipped; now suppressed on render)

`config.validateJunosHostDirectDeliveryWarnings`
(`pkg/config/compiler_validate_warn_host_inbound.go`,
run inside `ValidateConfig`) emits a WARN-only commit message for each `to-zone
junos-host` policy — zone-pair or global — that is **stricter than the coarse
gate** (a `then deny`/`then reject`, or a source-restricted `then permit`) AND is
**not** enforced by the direction-(b) projection above. A representable DENY that
renders an enforced kernel rule in every enforceable ingress zone it applies to
has its warning **suppressed** (`BuildJunosHostDenyProjection().RenderedPolicyKeys`);
an un-representable / lifeline-only / unenforceable policy still warns. The trigger
is deliberately conservative — a plain `permit`-from-any to junos-host only mirrors
the coarse permit-by-service gate and does **not** warn. It is **never a hard
reject**: the config is legal Junos and a reject would brick a previously committed
config. The warning names the policy and points here.

### Historical alternatives (rejected)

- **(a) Withhold junos-host-policy'd interface IPs from the local set** so the
  packet falls through to the XSK `LocalDelivery` junos-host gate. Rejected: the
  XSK redirect-error arm is fail-CLOSED (`drop_degraded_transit` → `XDP_DROP`,
  `lib.rs`), so a withheld IP is **dropped** while the helper is down — inverting
  "management always reachable". Also blocked by the #1864 shim verifier ceiling.
- Enforcing the fine restriction inside **userspace-dp** — wrong locus: a direct
  host-bound packet never reaches the helper (the kernel delivers it).

## Non-handshake TCP first packet on the LocalDelivery session-miss install (#2151 / #4487 / #4539)

The XSK `LocalDelivery` arm may CACHE a firewall-local session on a session
miss so subsequent established packets bypass userspace and return straight to
the kernel (`should_cache_local_delivery_session_on_miss` →
`install_helper_local_session_on_miss`, `userspace-dp/src/afxdp/forwarding/local_delivery.rs`).
That install is gated so a **TCP** session is seeded only off the handshake — a
first packet that carries **SYN** (an initial SYN, or the SYN|ACK inbound leg of
a firewall-originated flow). The gate is a **single positive predicate**:
`crate::tcp_flags::has_syn(tcp_flags)`. Non-TCP (ICMP / UDP) LocalDelivery is
unaffected — the `has_syn` gate is TCP-only and those protocols always cache.

That single `has_syn` predicate (#4539) subsumes two earlier NARROW
decline-gates and closes the residual they left open:

- **#2151** declined to cache off a bare/established **ACK** (`has_ack &&
  !has_syn`, ACK set / SYN clear). Still declined — it is a `!has_syn` case.
- **#4487** declined a **bare RST or bare FIN with no ACK bit** (`is_closing &&
  !has_syn`). Still declined — also `!has_syn`. Without it a RST/FIN flood to a
  firewall interface IP churns the per-worker session table (a cheap host-IP
  session-table DoS) and a later real SYN would HIT the immediately-`closing`
  seed instead of being re-evaluated by the host-inbound / junos-host gates (a
  policy-evaluation skip).
- **#4539** (gate-consistency hardening, LOW) closes the residual the two
  decline-gates missed: a non-handshake anomalous / crafted first packet that is
  **neither ACK-set nor closing** — **pure PSH (0x08), a null segment (0x00),
  pure URG (0x20), or an ECE/CWR-only** segment. Under the old two-gate form
  these fell through to the default `true` and seeded a 300s host-local session
  (`is_initial_syn` false at install → `established = true`). Aligning on
  `has_syn` matches the gate to its stated "only off the handshake" intent.

The `!has_syn` decline is the **same predicate** the transit strict-syn-check
applies (#4400, `strict_syn_check_drops_new_flow`), but the **action differs by
disposition**, exactly as #4400 chose. Transit dispositions (ForwardCandidate /
MissingNeighbor) **DROP** the packet. Host-inbound `LocalDelivery` must **NOT**
drop it: a peer RST/FIN tearing down a firewall-**originated** TCP flow
(BGP-active, syslog-TCP/TLS, feed/RPM fetches, DNS-over-TCP), or a
connection-refused RST for the firewall's own outbound SYN whose dataplane
session was already GC'd, arrives as a session MISS and must still reach the
local stack so the kernel socket tears down promptly (the #4400 LocalDelivery
drop-exemption). So the guard here only declines to **cache**; the
`LocalDelivery` disposition still delivers the declined packet to the host via
the reinject chokepoint. An established-session packet is a session HIT and
never consults this miss-only gate; and any later real SYN is re-evaluated by
the `to-zone junos-host` mandatory-teardown gate that runs on EVERY
LocalDelivery session hit (`poll_descriptor`), so declining to cache never skips
policy.

## On-wire coverage: what a compile-side test structurally cannot show (#6936)

Everything above is enforced by `pkg/config` / `pkg/daemon` / `userspace-dp`
tests that inspect what the compiler **produced**. None of them can show what
the box **admitted**. `test/incus/test-host-inbound.sh` closes the two on-wire
legs #6936 named — host-inbound resolved on a **tagged VLAN sub-unit**, and
admission **unchanged across an HA failover** — against the loss userspace
cluster.

It commits nothing. It reads the already-committed config in `display set`
form, derives its probe targets from it, and refuses to run if the zone posture
its expectations depend on has changed. A shared cluster's config is not the
smoke's to own, and an expectation table that has silently gone stale reports a
clean pass while asserting the wrong thing.

### The matrix on `loss:xpf-userspace-fw0`

`lan` admits `ssh` + `ping`. `wan` admits `ping` + `gre` and owns the two tagged
sub-units `reth0.50` / `reth0.80`. Every probe comes from `cluster-userspace-host`,
so every probe **arrives on `lan`** (`reth1`). Since #9637, host-inbound is judged
by the zone a packet arrives on, whichever address it names, so the smoke scores
lan's own addresses against `lan`'s posture, and the `wan`
sub-units against the reinject-path residual:

| target | interface | owning zone | tcp/22 | tcp/23 | icmp |
|---|---|---|---|---|---|
| `10.0.61.1` | `reth1.0` (untagged) | lan | RST → **admitted** | timeout → denied | reply |
| `2001:559:8585:ef00::1` | `reth1.0` (untagged) | lan | RST → **admitted** | timeout → denied | reply |
| `172.16.50.8` | `reth0.50` (**VLAN 50**) | wan | timeout → **denied** | timeout → denied | reply |
| `2001:559:8585:50::8` | `reth0.50` (**VLAN 50**) | wan | timeout → **denied** | timeout → denied | reply |
| `172.16.80.8` | `reth0.80` (**VLAN 80**) | wan | timeout → **denied** | timeout → denied | reply |
| `2001:559:8585:80::8` | `reth0.80` (**VLAN 80**) | wan | timeout → **denied** | timeout → denied | reply |

The four `wan` rows deny tcp/22 although every probe arrives on `lan`, which
admits ssh. That is the residual over-refusal #9637 measured and did not close.
These are interface-NAT addresses, so the userspace dataplane reinjects the SYN
through `xpf-usp0`, where the kernel chain still judges by the address's owner
(§ "Ingress-zone judgement (#9637)"). The cells stay
load-bearing through the tcp/22 and tcp/23 pair at the *same address*: one port
answers and the other does not, which no routing or reachability story explains.
A posture check asserts that `lan` owns `reth1.0`, the prober's ingress interface,
so the ssh cells cannot quietly be scored against the wrong zone.

This prober cannot see the other direction: a client arriving on `wan` that names
a `lan` address. The #9637 lab gate measured that direction separately, from the
WAN-side `xpf-mouse-target` (`docs/log/9637.md`).

### Why the RST matters

`xpfd` binds its own listeners (gRPC 50051, HTTP 8080) on `127.0.0.1` only, so
a probe of a non-listening port on a firewall-local address comes back as an
**RST** if host-inbound admitted it and as **nothing at all** if host-inbound
dropped it. Collapsing those two — which is what a bare `nc -z` exit status
does — would make every negative cell in the smoke unfalsifiable. The prober
(`host_inbound_probe.py`) therefore reports `OPEN` / `REFUSED` / `TIMEOUT` /
`ERROR` as a raw observation, and `host-inbound-lib.sh` maps them onto
`ADMITTED` / `SILENT` / `UNREACHED` / `BLIND`.

Note the vocabulary has no state called `DENIED`. **A probe cannot observe a
deny.** It observes silence, and "the firewall dropped it" and "my prober never
reached the firewall" are the same reading. Silence is promoted to a deny only
by a positive control at the **same address, same family, same run, same
prober** — the ICMP cell at that address. A same-family-but-different-address
control would not do: a route that stopped reaching one VLAN address would make
every deny cell at it pass for the wrong reason. `make test-host-inbound-lib`
drives that middle row (identical expectation, identical observation, only the
control differs) hermetically.

### The failover leg asserts a diff, not a pass

`--with-failover` moves RG1 (WAN/`reth0`) and RG2 (LAN/`reth1`) to node1,
re-runs the matrix, fails back, and re-runs it again. The assertion is that the
matrix is **identical**, not that it still passes: a run in which every
admission silently died still satisfies every DENY cell, so re-scoring alone
cannot see the regression this leg exists for. `hi_matrix_stable_verdict` also
fails an empty run rather than reading it as "unchanged".

Failing back is explicit. `request chassis cluster failover reset` only clears
the manual latch; with preempt disabled the current master keeps the group, so
a reset alone leaves the shared cluster inverted for the next lane.

### What is still not covered on the wire, and why

The duplicate-host-local-address leg #6936 also listed has **no reachable
venue**, and the reason is the product's own gate rather than the lab's: the
ambiguous topology is hard-rejected at commit and commit-check by
`validateDuplicateHostLocalAddressStrict` (§ "Duplicate host-local-address
ambiguity (#3718, Option B)"). A smoke cannot apply the config it would need to
observe. The state is reachable only through the tolerant `load` / peer-sync
path — a deliberate #1960 no-brick concession — and that path's runtime surface
is already covered where it is observable, by
`pkg/daemon/host_inbound_ambiguous_3718_test.go` and
`pkg/api/metrics_host_inbound_ambiguous_3718_test.go`. Reaching it on the wire
would mean writing the rejected config straight into the config DB and
restarting, which measures a state the product refuses to enter rather than one
an operator can reach.

## Adding a new host-inbound service

Adding or changing a token is a coordinated edit across all three surfaces so the
drift guards stay green:

1. Add the token to `config.KnownHostInboundSystemServices` /
   `config.KnownHostInboundProtocols` (and a family map if it is v4/v6-only, and
   `config.HostInboundL2Protocols` if it rides L2).
2. Add the port/protocol match to `hostInboundServiceMatches` /
   `hostInboundProtocolMatches` in `pkg/daemon/daemon_nft.go`.
3. Add the matching arm to `classify_system_service` / `classify_protocol` in
   `userspace-dp/src/afxdp/forwarding/host_inbound.rs` (and
   `KNOWN_ROUTING_PROTOCOL_TOKENS` for a routing protocol).
4. Update this matrix, and add a fail-on-revert port assertion in
   `pkg/daemon/host_inbound_parity_test.go` for any deliberately-narrow set.

The port sets on surfaces 2 and 3 have **no** automated cross-check of the exact
port numbers (only the token set is guarded by #3486) — the fail-on-revert
assertions in `host_inbound_parity_test.go` plus this matrix are the contract
that keeps the nft and Rust port numbers aligned.

## WireGuard listen port: a dynamic exception, NOT a token (#5582)

WireGuard is deliberately **not** a `system-services` token. Its UDP listen port
is operator-configured (`interfaces <wg> tunnel wireguard listen-port <n>`), so
it does not fit the static token→port SSOT above (a token like `ssh` maps to a
fixed port on all three surfaces). Instead, the kernel host-inbound builder emits
an **automatic, dynamic** `udp dport <configured-wg-port(s)> accept` on the input
hook whenever a WG tunnel is configured (`emitHostInboundWireGuardAccept`,
`pkg/daemon/daemon_nft.go`; port set from `config.WireGuardListenPorts()`). This
mirrors the shim's steer-to-kernel of that exact port so a fresh passive handshake
to a restricted zoned address is admitted rather than dropped. See
`docs/wireguard-interop.md` → "Host-inbound admission of the WG listen port". Do
NOT add a `wireguard` token to `KnownHostInboundSystemServices` — the port is
dynamic and the automatic exception already covers it.

## Junos references

- SIP ALG — default SIP signaling on port 5060; TCP support added in
  12.3X48-D25 / 17.3R1:
  <https://www.juniper.net/documentation/us/en/software/junos/alg/topics/topic-map/security-sip-alg.html>
- Predefined policy applications (junos-sip = UDP+TCP 5060; junos-tftp = UDP 69):
  <https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/policy-predefined-applications.html>
- system-services (security zones host-inbound-traffic):
  <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-system-service-zone-host-inbound-traffic.html>
- protocols (security zones host-inbound-traffic):
  <https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-protocols-zone-host-inbound-traffic.html>
