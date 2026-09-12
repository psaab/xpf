//! #3070: host-inbound-traffic admission for host-bound (local-delivery)
//! traffic.
//!
//! `security zones <z> host-inbound-traffic { system-services ...; protocols
//! ...; }` is parsed and modeled in the Go control plane but, before #3070,
//! never reached the dataplane: host-bound traffic (SSH, ping, routing
//! protocols destined to a firewall-local interface IP) was admitted
//! regardless of the configured set. This module classifies the raw Junos
//! tokens carried on `ZoneSnapshot` into a `ZoneHostInbound` admission set and
//! provides the per-packet admit check used on the local-delivery path.
//!
//! Default posture (#3405 — Junos/vSRX default-deny parity): EVERY configured
//! security zone is enforced. The Go control plane marks every zone
//! `host_inbound_configured == true` (`ZoneSnapshot::host_inbound_configured`),
//! so a zone with NO `host-inbound-traffic` stanza arrives with EMPTY token
//! sets and is inserted into `ForwardingState::zone_host_inbound` with an empty
//! [`ZoneHostInbound`] — `admits()` then returns false for every
//! service/protocol, i.e. default-deny, identical to an empty
//! `host-inbound-traffic { }` stanza. Before #3405 a no-stanza zone was absent
//! from the map and `host_inbound_admits` returned admit (`None => true`), a
//! permit-all management-plane exposure on any zone the operator never locked
//! down. The `None => true` arm now applies ONLY to a genuinely unknown / global
//! ingress zone (e.g. id 0), never to a configured zone. The global
//! ICMP/ND/PMTUD accepts (`is_icmp_host_inbound_global_accept`, #3171) still
//! precede the per-zone deny, and lifeline interfaces (fxp0/em0/fab*) never
//! reach this AF_XDP local-delivery classifier (their host-bound traffic is
//! served by the kernel, which excludes them from the deny address sets), so the
//! default-deny cannot strand management or break HA.
//!
//! The authoritative operator-facing token->port matrix across all three
//! surfaces (the Go SSOT allowlist, the nft kernel mirror, and this Rust
//! classifier) -- including the deliberate narrowings (sip UDP+TCP 5060 only,
//! tftp UDP 69 only, traceroute UDP-only, router-discovery v6 global,
//! ipsec=ike alias) and the ident-reset divergence -- lives in
//! docs/host-inbound-service-matrix.md (#3619).

use super::*;

// #3201/#3240: ICMP type numbers carried per-zone for subtype-specific
// host-inbound admission. These mirror the nft chain's named-type matches
// (`pkg/daemon/daemon_nft.go`): `ping` → echo-request, IPv4 `router-discovery`
// → router-advertisement/solicitation (types 9/10). Error/PMTUD and IPv6 ND
// subtypes are admitted globally instead (see `is_icmp_host_inbound_global_accept`).
const ICMP4_ECHO_REQUEST: u8 = 8;
const ICMP4_ROUTER_ADVERTISEMENT: u8 = 9;
const ICMP4_ROUTER_SOLICITATION: u8 = 10;
const ICMP6_ECHO_REQUEST: u8 = 128;

/// Build the per-zone host-inbound admission table from the snapshot. Since
/// #3722 `populate_zones` inserts an entry for EVERY known security zone
/// regardless of `host_inbound_configured` — a no-stanza / nil / unconfigured
/// zone arrives with empty token sets -> empty `ZoneHostInbound` -> default-deny
/// (fail-closed). `host_inbound_configured` now only selects WHICH tokens a zone
/// admits (the #3405 no-stanza-vs-configured distinction), never WHETHER the
/// zone is enforced — a missing table entry means only a genuinely unknown /
/// global (id 0) ingress zone, which the classifier admits by design. The zone
/// id used as the key MUST be the same validated id `populate_zones` accepted
/// (caller passes it), so the two maps stay aligned.
pub(in crate::afxdp) fn zone_host_inbound_from_snapshot(zone: &ZoneSnapshot) -> ZoneHostInbound {
    zone_host_inbound_from_tokens(
        &zone.host_inbound_system_services,
        &zone.host_inbound_protocols,
    )
}

/// #3362: build a [`ZoneHostInbound`] from raw Junos host-inbound token slices.
/// Shared by the zone-level path ([`zone_host_inbound_from_snapshot`]) and the
/// per-interface OVERRIDE path (`InterfaceSnapshot.host_inbound_*`), so the two
/// classify identically. The interface-level token set carried on the wire is
/// already the EFFECTIVE set computed in Go — the interface stanza REPLACES the
/// zone one (#6515) — so this just classifies it as-is.
pub(in crate::afxdp) fn zone_host_inbound_from_tokens(
    services: &[String],
    protocols: &[String],
) -> ZoneHostInbound {
    let mut hi = ZoneHostInbound::default();
    for svc in services {
        classify_system_service(svc.trim().to_ascii_lowercase().as_str(), &mut hi);
    }
    for proto in protocols {
        classify_protocol(proto.trim().to_ascii_lowercase().as_str(), &mut hi);
    }
    hi
}

/// Every recognized `system-services` token that names a CONCRETE service
/// (mirror of the Go SSOT config.KnownHostInboundSystemServices minus the two
/// meta tokens `all` and `any-service`). The `system-services all` expansion is
/// derived from this list MINUS the xpf-only extension set
/// (HOST_INBOUND_NON_JUNOS_SERVICES) — see `system_service_all_expansion`.
/// Listing `gre` here (and excluding it via the non-Junos set) is what makes
/// that set load-bearing on this surface (#3226), mirroring how listing `isis`
/// in KNOWN_ROUTING_PROTOCOL_TOKENS makes HOST_INBOUND_L2_PROTOCOLS
/// load-bearing for `protocols all` (#3311).
const KNOWN_SYSTEM_SERVICE_TOKENS: &[&str] = &[
    "ssh",
    "telnet",
    "ftp",
    "http",
    "webapi-clear-text",
    "https",
    "webapi-ssl",
    "ping",
    "dns",
    "dhcp",
    "bootp",
    "dhcpv6",
    "ntp",
    "snmp",
    "snmp-trap",
    "ike",
    "ipsec",
    "tftp",
    "netconf",
    "ssh-netconf",
    "netconf-ssh",
    "finger",
    "ident-reset",
    "lsping",
    "sip",
    "r-login",
    "rlogin",
    "r-sh",
    "rsh",
    // #3226: `r-exec`/`rexec` (tcp/512) is an xpf-only spelling — Juniper's
    // host-inbound service list documents rlogin and rsh but NOT rexec — and
    // unlike the other xpf spellings it is not a port-neutral alias, so it is
    // EXCLUDED from the `all` expansion below via
    // HOST_INBOUND_NON_JUNOS_SERVICES.
    "r-exec",
    "rexec",
    "xnm-clear-text",
    "xnm-ssl",
    "traceroute",
    // #3226 fold: Junos host-inbound services xpf previously did not recognize
    // at all. Membership is derived from Juniper's published YANG schema
    // (pkg/config/testdata/junos-es-conf-security@2024-01-01.yang.gz), not
    // from prose reference pages — those were incomplete and had this set wrong
    // three times. Mirror of config.KnownHostInboundSystemServices.
    //
    // Only reverse-telnet (tcp/2900) and reverse-ssh (tcp/2901) carry a
    // PLATFORM-DEFAULT port (explicit YANG `default` statements), and
    // lsselfping carries a STANDARDS-ASSIGNED one (RFC 7746, udp/8503). The
    // rest are listed in HOST_INBOUND_UNPORTED_SERVICES below: recognized, but
    // no admit tuple, because xpf has no authoritative port to admit for them.
    "r2cp",
    "reverse-ssh",
    "reverse-telnet",
    "rpm",
    "lsselfping",
    "tcp-encap",
    "appqoe",
    "high-availability",
    // #3226: `gre` is an xpf EXTENSION (Junos has no raw-IP-protocol
    // system-service), so it is EXCLUDED from the `all` expansion below via
    // HOST_INBOUND_NON_JUNOS_SERVICES.
    "gre",
];

/// xpf-only `system-services` tokens — the Rust mirror of the Go SSOT
/// config.HostInboundNonJunosSystemServices (#3226). Junos scopes
/// `system-services all` to the DEFINED system services, and its service list
/// carries no raw IP protocol; xpf additionally accepts `gre` (IP protocol 47)
/// because operator configs list it there, and `r-exec`/`rexec` (tcp/512),
/// which Juniper's host-inbound list does not document at all and which — unlike
/// the port-neutral xpf spellings webapi-*/netconf-ssh — opens a port no other
/// token opens. Folding an xpf-only token into the `all` expansion would make
/// `all` open a protocol or port Junos's `all` never opens, so these are
/// excluded from the expansion and must be listed explicitly. Keep in lockstep
/// with the Go set (the #3486 parity test guards this).
const HOST_INBOUND_NON_JUNOS_SERVICES: &[&str] = &["gre", "r-exec", "rexec"];

/// Recognized JUNOS `system-services` tokens xpf has no authoritative listening
/// tuple to admit for — the Rust mirror of the Go SSOT
/// config.HostInboundUnportedSystemServices (#3226 fold). Unlike
/// HOST_INBOUND_NON_JUNOS_SERVICES these are NOT xpf extensions: they are in
/// Juniper's published schema, so they stay recognized and stay in the
/// `system-services all` union. They simply contribute NO admit tuple: for rpm
/// and r2cp Junos documents the port as operator-chosen, and for the rest xpf
/// could not find an authoritative one. Those are DIFFERENT statements and the
/// Go set records which applies per token.
///
/// This is a deliberate CHOICE under uncertainty, not an inference. For each of
/// these tokens xpf looked for an authoritative host-inbound listening tuple and
/// did not find one. (An earlier revision argued the absence of a YANG `default`
/// PROVED there was no fixed port; that generalization is false — `[edit system
/// services telnet]` has no port leaf either, yet telnet is TCP/23 — and has
/// been withdrawn.) Faced with the gap, guessing a port is wrong in BOTH
/// directions at once: it opens a port nothing listens on while still denying
/// the port actually in use, invisibly. Opening nothing is wrong in one
/// direction only, is announced to the operator at commit, and never silently
/// widens the host's exposure.
///
/// The five are NOT one class, and the Go side labels them
/// (config.HostInboundNoAdmitReason): `rpm` and `r2cp` have an
/// OPERATOR-CONFIGURED port that Junos documents as a range with no default — so
/// there is no correct port to admit, and restoring one is not even an available
/// option; `tcp-encap`, `appqoe` and `high-availability` are UNSOURCED — we did
/// not find the tuple, which is an admission, not a finding. This surface does
/// not need the distinction (both classes admit nothing), so the mirror stays a
/// single array; the labelling lives with the evidence, on the Go set. The
/// operator-facing consequence, and which escape hatch works on which surface,
/// is in docs/host-inbound-service-matrix.md.
///
/// Keep in lockstep with the Go set — the #3486 parity test asserts equality,
/// and `unported_services_admit_nothing_3226` asserts the behavior, so this
/// const is load-bearing rather than decorative.
const HOST_INBOUND_UNPORTED_SERVICES: &[&str] =
    &["r2cp", "rpm", "tcp-encap", "appqoe", "high-availability"];

/// True if `token` is an xpf-only (non-Junos) system-service, and so excluded
/// from the `system-services all` expansion. #3226.
fn is_non_junos_system_service(token: &str) -> bool {
    HOST_INBOUND_NON_JUNOS_SERVICES.contains(&token)
}

/// The system-service tokens that `system-services all` expands to (#3226),
/// derived from KNOWN_SYSTEM_SERVICE_TOKENS MINUS the xpf-only extension set.
/// In Junos `host-inbound-traffic system-services all` admits "traffic from the
/// defined system services available on the Routing Engine" — NOT every IP
/// protocol and NOT a blanket bypass. Expanding to a concrete admit set (rather
/// than the pre-#3226 `all_services` short-circuit) keeps an `all` zone from
/// accepting GRE/ESP/AH/OSPF/PIM/VRRP and arbitrary future protocol numbers on
/// its local addresses, and re-arms the per-zone default deny for everything
/// the named set does not cover. Aliases (http/webapi-clear-text, ike/ipsec,
/// ...) resolve to the same ports; the admit sets dedup.
fn system_service_all_expansion() -> impl Iterator<Item = &'static str> {
    KNOWN_SYSTEM_SERVICE_TOKENS
        .iter()
        .copied()
        .filter(|t| !is_non_junos_system_service(t))
}

/// Classify one Junos `system-services` token into the admission set.
/// Unrecognised tokens are intentionally ignored (fail-closed: they do not
/// broaden admit). Covers the common Junos service set; the repo configs use
/// {all, ssh, ping, dhcp, dhcpv6, gre} and this is a comprehensive superset.
///
/// The recognized token set here is a SECURITY allowlist and MUST stay in
/// lockstep with the Go SSOT config.KnownHostInboundSystemServices (#3200). A
/// Go parity test (config.TestHostInboundRustClassifierMatchesGoSSOT, #3486)
/// parses these match arms and fails the build if a token is added/removed on
/// only one side. Adding a service here without adding it to the Go SSOT (or
/// vice versa) turns that test RED.
fn classify_system_service(token: &str, hi: &mut ZoneHostInbound) {
    match token {
        // #3226: `system-services all` admits only the DEFINED system-service
        // set (Junos: "traffic from the defined system services available on
        // the Routing Engine") — it expands to every recognized service EXCEPT
        // the xpf-only extensions (gre), via system_service_all_expansion
        // (= KNOWN_SYSTEM_SERVICE_TOKENS minus HOST_INBOUND_NON_JUNOS_SERVICES),
        // NOT a blanket accept. The expansion never yields "all", so this
        // recursion terminates. Mirrors the Go SSOT `all` case in
        // config.HostInboundServiceMatch, which derives the same exclusion from
        // config.HostInboundAllExpansionServices().
        "all" => {
            for tok in system_service_all_expansion() {
                classify_system_service(tok, hi);
            }
        }
        // `any-service` REMAINS the packet-wide full admit (#3226): Junos
        // defines it as "all system services on an entire port range including
        // the system services that are not defined", i.e. the explicit escape
        // hatch for traffic the named set does not cover. xpf reads it as a
        // superset (every IP protocol, not just the TCP/UDP port range) — the
        // fail-safe direction for a token whose purpose is to over-admit, and
        // the one-token migration for a config that relied on the pre-#3226
        // breadth of `all`. Commit-warned in compiler_validate_warn.go.
        "any-service" => hi.all_services = true,
        "ssh" => {
            hi.tcp_ports.insert(22);
        }
        "telnet" => {
            hi.tcp_ports.insert(23);
        }
        "ftp" => {
            hi.tcp_ports.insert(21);
        }
        "http" | "webapi-clear-text" => {
            hi.tcp_ports.insert(80);
        }
        "https" | "webapi-ssl" => {
            hi.tcp_ports.insert(443);
        }
        // #3201/#3240: `ping` admits ICMP echo-request ONLY (v4 type 8, v6 type
        // 128), matching the nft chain (`hostInboundServiceMatches`:
        // `icmp/icmpv6 type echo-request`) — NOT the whole ICMP protocol. ICMP
        // error/PMTUD subtypes are admitted separately + globally (#3171).
        "ping" => {
            hi.icmp_types_v4.insert(ICMP4_ECHO_REQUEST);
            hi.icmp_types_v6.insert(ICMP6_ECHO_REQUEST);
        }
        "dns" => {
            hi.udp_ports.insert(53);
            hi.tcp_ports.insert(53);
        }
        // dhcp server listens on udp/67; client replies arrive on udp/68. Admit
        // both so a `dhcp-local-server` on the zone interface works. #3225:
        // DHCPv4 is IPv4-only — these ports must NOT open on the v6 path (the
        // family map config.HostInboundServiceFamily is the cross-layer SSOT).
        "dhcp" | "bootp" => {
            hi.udp_ports_v4.insert(67);
            hi.udp_ports_v4.insert(68);
        }
        // #3225: DHCPv6 is IPv6-only — these ports stay off the v4 path.
        "dhcpv6" => {
            hi.udp_ports_v6.insert(546);
            hi.udp_ports_v6.insert(547);
        }
        "ntp" => {
            hi.udp_ports.insert(123);
        }
        "snmp" => {
            hi.udp_ports.insert(161);
        }
        "snmp-trap" => {
            hi.udp_ports.insert(162);
        }
        // `ipsec` is the Junos system-service that permits host-terminated
        // IPsec. It opens IKE (udp 500 / NAT-T 4500); the raw ESP/AH data plane
        // is handled by the kernel XFRM stack / stage_ipsec_passthrough_check
        // before host-inbound enforcement, so `ipsec` is effectively a superset
        // of `ike`. Aliased to keep parity with the nft mirror + the #3200 SSOT.
        //
        // #3616/#4323: this admit set gates IKE on BOTH host-inbound paths. On
        // the PRIMARY kernel nftables path (`pkg/daemon/daemon_nft.go`) it opens
        // udp 500/4500 per zone. On the SECONDARY AF_XDP path
        // (`stage_ipsec_passthrough_check`, #4323 Option B) the same udp-500/4500
        // admit is consulted for a NEW inbound IKE initiation (an ISAKMP header
        // with an all-zero Responder SPI) via `host_inbound_admits_iface`: a zone
        // omitting `ike`/`ipsec` drops it before it reaches the local IKE daemon.
        // Raw ESP/AH stays EXEMPT on that path (ratified #3616 Option A) — the
        // SA is the authorization; established/reply IKE is exempt only while a
        // live seeded exchange matches (#6471 secondary path, see
        // forwarding/ipsec.rs).
        "ike" | "ipsec" => {
            hi.udp_ports.insert(500);
            hi.udp_ports.insert(4500);
        }
        "tftp" => {
            hi.udp_ports.insert(69);
        }
        "netconf" => {
            hi.tcp_ports.insert(830);
        }
        "ssh-netconf" | "netconf-ssh" => {
            hi.tcp_ports.insert(830);
            hi.tcp_ports.insert(22);
        }
        "finger" => {
            hi.tcp_ports.insert(79);
        }
        // #3310: Junos `system-services ident-reset` does NOT permit the ident
        // (auth/TCP-113) service — it actively RESETS inbound ident probes. The
        // PRIMARY enforcement path for direct host-bound traffic to an interface
        // IP / VRRP VIP is the kernel nft chain (the XDP shim shunts such
        // traffic to the kernel before userspace-dp sees it), which emits a
        // `reject with tcp reset` for TCP/113 (`hostInboundServiceAction`,
        // pkg/daemon/daemon_nft.go). This AF_XDP local-delivery classifier is
        // the SECONDARY edge-case path (reached only by DNAT/static-NAT-to-113,
        // an edge of an edge). It must NOT admit 113 — so this arm contributes
        // NOTHING to the admit set, and `admits()` returns false for TCP/113,
        // dropping the rare AF_XDP-reached ident packet (a documented
        // divergence from the kernel reset; strictly better than the prior plain
        // admit). The explicit arm is kept (rather than falling into `_ => {}`)
        // so the token stays recognized by the Go<->Rust parity test
        // (config.TestHostInboundRustClassifierMatchesGoSSOT) and so a future
        // secondary-path RST upgrade (plan Option A) has an obvious home.
        "ident-reset" => {}
        "lsping" => {
            hi.udp_ports.insert(3503);
        }
        "sip" => {
            hi.udp_ports.insert(5060);
            hi.tcp_ports.insert(5060);
        }
        "r-login" | "rlogin" => {
            hi.tcp_ports.insert(513);
        }
        "r-sh" | "rsh" => {
            hi.tcp_ports.insert(514);
        }
        "r-exec" | "rexec" => {
            hi.tcp_ports.insert(512);
        }
        // #3226 fold — Junos host-inbound services at a port Juniper actually
        // fixes. Mirror of config.HostInboundServiceMatch; the port values are
        // pinned on this surface by
        // system_services_all_admits_documented_junos_services_3226 and on the
        // Go side by TestHostInboundDocumentedJunosServiceTokensCommit_3226 +
        // the nft golden TestHostInboundNftRenderGoldenByteIdentical.
        //
        // `[edit system services reverse telnet|ssh] port` carry explicit YANG
        // `default` statements of 2900 / 2901 (junos-es-conf-system 24.4R2).
        "reverse-telnet" => {
            hi.tcp_ports.insert(2900);
        }
        "reverse-ssh" => {
            hi.tcp_ports.insert(2901);
        }
        // RFC 7746 §3: "The UDP Destination Port MUST be lsp-self-ping (8503)";
        // §6 records the IANA assignment. Distinct from `lsping` (udp/3503, the
        // MPLS echo port) despite the similar name — they are different
        // protocols, so this must NOT be folded into the lsping arm.
        "lsselfping" => {
            hi.udp_ports.insert(8503);
        }
        // #3226 fold — recognized Junos services with no authoritative tuple
        // (HOST_INBOUND_UNPORTED_SERVICES). This arm must stay EMPTY: xpf has no
        // authoritative port for them, so any value inserted here would be a guess
        // that opens an unused port while still denying the one in use. They
        // remain recognized (a valid vSRX stanza must commit, #3200) and remain
        // in the `all` union, contributing nothing. Mirror of the
        // config.HostInboundUnportedSystemServices gate in
        // config.HostInboundServiceMatch; `unported_services_admit_nothing_3226`
        // is the RED-on-revert guard.
        "r2cp" | "rpm" | "tcp-encap" | "appqoe" | "high-availability" => {}
        "xnm-clear-text" => {
            hi.tcp_ports.insert(3221);
        }
        "xnm-ssl" => {
            hi.tcp_ports.insert(3220);
        }
        "traceroute" => {
            // UDP probes land in the 33434..33523 range; admit it as a small
            // explicit set (kept short to avoid bloating the per-zone set).
            for p in 33434u16..=33523 {
                hi.udp_ports.insert(p);
            }
        }
        // Some operators list `gre` under system-services (see the repo
        // ha-cluster config wan zone). Treat it as IP protocol 47.
        "gre" => {
            hi.ip_protocols.insert(47);
        }
        // Unknown / unmapped service token: ignore (fail-closed).
        _ => {}
    }
}

/// Every recognized `protocols` token (mirror of the Go SSOT
/// config.KnownHostInboundProtocols minus the `all` meta-token). The
/// `protocols all` expansion is derived from this list MINUS the L2/non-IP set
/// (HOST_INBOUND_L2_PROTOCOLS) — see `routing_protocol_all_expansion`. Listing
/// IS-IS here (and excluding it via the L2 set) is what makes the L2 set
/// load-bearing on this surface (#3311): adding a new L2 protocol means adding
/// it to both lists, after which it is automatically kept out of the IP `all`
/// expansion with no edit to the expansion logic.
const KNOWN_ROUTING_PROTOCOL_TOKENS: &[&str] = &[
    // #3225: ospf (OSPFv2, IPv4) and ospf3 (OSPFv3, IPv6) are BOTH listed so
    // `protocols all` admits proto 89 on each family; classify_protocol scopes
    // each to its own family.
    "ospf",
    "ospf3",
    "bgp",
    "rip",
    "ripng",
    "igmp",
    "pim",
    "vrrp",
    "bfd",
    "ldp",
    "msdp",
    "nhrp",
    "router-discovery",
    // #3341: additional Junos/vSRX routing-control protocols. All ride IP, so
    // each contributes a concrete IP admit in classify_protocol: rsvp (proto 46,
    // dual), pgm (proto 113, dual), sap (UDP/9875, dual), dvmrp (proto 2 / IGMP,
    // IPv4-only). Mirror of config.KnownHostInboundProtocols.
    "rsvp",
    "pgm",
    "sap",
    "dvmrp",
    // #3311: IS-IS is a recognized protocol but rides L2 (OSI/CLNP), so it is
    // EXCLUDED from the IP `all` expansion below via HOST_INBOUND_L2_PROTOCOLS.
    "isis",
];

/// L2/non-IP host-inbound protocols — the Rust mirror of the Go SSOT
/// config.HostInboundL2Protocols (#3311). These ride directly over L2
/// (OSI/CLNP / LLC) and cannot be expressed as an IP host-inbound match, so
/// they are excluded from the `protocols all` IP expansion and contribute no
/// per-token IP admit. Keep in lockstep with the Go set (a Go parity intent +
/// the protocols_all_excludes_l2 test below guard this).
const HOST_INBOUND_L2_PROTOCOLS: &[&str] = &["isis"];

/// True if `token` is an L2/non-IP host-inbound protocol (excluded from the IP
/// `protocols all` expansion). #3311.
fn is_host_inbound_l2_protocol(token: &str) -> bool {
    HOST_INBOUND_L2_PROTOCOLS.contains(&token)
}

/// The routing-protocol tokens that `protocols all` expands to (#3199), derived
/// from KNOWN_ROUTING_PROTOCOL_TOKENS MINUS the L2/non-IP set (#3311). In Junos
/// `host-inbound-traffic protocols all` admits every supported ROUTING protocol
/// — NOT every system-service and NOT a blanket bypass. Expanding to a concrete
/// IP set (rather than a short-circuit admit) keeps a `protocols all` zone from
/// opening SSH/HTTPS/SNMP/NETCONF on the box; excluding L2 protocols keeps it
/// from listing a token that can produce no IP admit. ospf3 aliases ospf; the
/// caller dedups.
fn routing_protocol_all_expansion() -> impl Iterator<Item = &'static str> {
    KNOWN_ROUTING_PROTOCOL_TOKENS
        .iter()
        .copied()
        .filter(|t| !is_host_inbound_l2_protocol(t))
}

/// Classify one Junos `protocols` (routing-protocol) token. Port-based
/// protocols (bgp/ldp/msdp/rip) contribute TCP/UDP ports; IP-protocol-based
/// ones (ospf/pim/igmp/vrrp) contribute a protocol number; router-discovery is
/// ICMP/ICMPv6.
fn classify_protocol(token: &str, hi: &mut ZoneHostInbound) {
    match token {
        // `protocols all` admits only the routing-protocol set (#3199) — it
        // expands to every recognized routing protocol EXCEPT L2/non-IP ones
        // (IS-IS), via routing_protocol_all_expansion (= KNOWN_ROUTING_PROTOCOL_
        // TOKENS minus HOST_INBOUND_L2_PROTOCOLS, #3311), NOT system services
        // and NOT a blanket accept. The expansion never yields "all", so this
        // recursion terminates. Mirrors the Go nft `all` case, which derives the
        // same exclusion from config.HostInboundAllExpansionProtocols().
        "all" => {
            for tok in routing_protocol_all_expansion() {
                classify_protocol(tok, hi);
            }
        }
        // #3225: OSPFv2 (ospf) is IPv4-only, OSPFv3 (ospf3) is IPv6-only — both
        // ride IP protocol 89 but on different families (SSOT:
        // config.HostInboundProtocolFamily).
        "ospf" => {
            hi.ip_protocols_v4.insert(89);
        }
        "ospf3" => {
            hi.ip_protocols_v6.insert(89);
        }
        "bgp" => {
            hi.tcp_ports.insert(179);
        }
        // #3225: RIPv2 is IPv4-only, RIPng is IPv6-only.
        "rip" => {
            hi.udp_ports_v4.insert(520);
        }
        "ripng" => {
            hi.udp_ports_v6.insert(521);
        }
        // #3225: IGMP is IPv4 group membership; the IPv6 equivalent is MLD over
        // ICMPv6 (the always-accepted ND set), so igmp is IPv4-only here.
        "igmp" => {
            hi.ip_protocols_v4.insert(2);
        }
        "pim" => {
            hi.ip_protocols.insert(103);
        }
        "vrrp" => {
            hi.ip_protocols.insert(112);
        }
        // #3299: BFD admits single-hop control (3784) + echo (3785) AND
        // multi-hop control (4784, RFC 5883). Multi-hop is control-only; echo
        // stays single-hop on 3785. Keep this set in lockstep with the nft
        // host-inbound rule (`hostInboundProtocolMatches`, pkg/daemon).
        "bfd" => {
            hi.udp_ports.insert(3784);
            hi.udp_ports.insert(3785);
            hi.udp_ports.insert(4784);
        }
        "ldp" => {
            hi.tcp_ports.insert(646);
            hi.udp_ports.insert(646);
        }
        "msdp" => {
            hi.tcp_ports.insert(639);
        }
        "nhrp" => {
            hi.ip_protocols.insert(54);
        }
        // #3341: RSVP rides directly over IP, protocol 46 (dual-family).
        "rsvp" => {
            hi.ip_protocols.insert(46);
        }
        // #3341: PGM (Pragmatic General Multicast) rides over IP, protocol 113
        // (dual-family).
        "pgm" => {
            hi.ip_protocols.insert(113);
        }
        // #3341: SAP (Session Announcement Protocol) is UDP/9875 (dual-family).
        "sap" => {
            hi.udp_ports.insert(9875);
        }
        // #3341: DVMRP is carried inside IGMP (IP protocol 2) and is an IPv4-only
        // multicast routing protocol (SSOT: config.HostInboundProtocolFamily
        // ["dvmrp"]="ip"), so it admits proto 2 on v4 only — matching igmp.
        "dvmrp" => {
            hi.ip_protocols_v4.insert(2);
        }
        // #3311: IS-IS rides OSI/CLNP directly over L2 (LLC-encapsulated, NOT
        // IP), so it cannot be expressed in this IP-keyed admit model (proto
        // number / TCP-UDP port / ICMP type). It is a recognized-but-no-op
        // host-inbound token (Go SSOT: config.HostInboundL2Protocols; Rust
        // mirror: HOST_INBOUND_L2_PROTOCOLS): the kernel delivers IS-IS PDUs to
        // FRR's isisd via an LLC packet socket, outside the IP host-inbound
        // filter (and the AF_XDP local-delivery path only ever classifies IP
        // packets). This explicit arm is DOCUMENTARY — the catch-all `_ => {}`
        // would no-op identically. The L2 set's load-bearing job is the
        // `protocols all` exclusion above (routing_protocol_all_expansion),
        // which is what the protocols_all_excludes_l2 test guards.
        "isis" => {}
        // #3201/#3240: router-discovery admits ICMPv4 router-advertisement (9)
        // and router-solicitation (10) ONLY — matching the nft chain
        // (`hostInboundProtocolMatches`: `icmp type { 9, 10 }`). On v6, RS/RA
        // are part of the always-accepted ND set (types 133-137) handled
        // globally by `is_icmp_host_inbound_global_accept`, so router-discovery
        // contributes nothing per-zone on v6 — exactly as the nft chain returns
        // nil for v6 router-discovery and relies on the global ND accept.
        "router-discovery" => {
            hi.icmp_types_v4.insert(ICMP4_ROUTER_ADVERTISEMENT);
            hi.icmp_types_v4.insert(ICMP4_ROUTER_SOLICITATION);
        }
        // Unknown / unmapped protocol token: ignore (fail-closed).
        _ => {}
    }
}

/// #3171/#3201/#3240: ICMP/ICMPv6 subtypes that the host-inbound layer admits
/// UNCONDITIONALLY — regardless of which services/protocols the ingress zone
/// lists — so the userspace LocalDelivery classifier matches the kernel
/// host-inbound chain's GLOBAL accepts at the top of the chain
/// (`pkg/daemon/daemon_nft.go` `buildHostInboundFilterPayload`):
/// `icmp type { destination-unreachable, time-exceeded, parameter-problem }`
/// and `icmpv6 type { 1, 2, 3, 4, 133, 134, 135, 136, 137 }`.
///
/// Two categories ride this global accept:
///   1. ERROR / PMTUD control messages (#3171) — destination-unreachable,
///      packet-too-big, time-exceeded, parameter-problem — which carry PMTUD /
///      unreachable / traceroute-to-self signalling that must reach a
///      firewall-local address (e.g. a DNAT-to-self embedded ICMP error landing
///      on the XSK) even on a configured ping-less zone.
///   2. IPv6 Neighbor Discovery (#3201/#3240) — RS (133), RA (134), NS (135),
///      NA (136), Redirect (137). ND is core L3 operation, accepted globally by
///      the nft chain (never a per-service exposure). Admitting it here is what
///      lets the per-zone `router-discovery` token carry NOTHING on v6 while
///      still matching nft — i.e. v6 RS/RA reach the host via this global ND
///      accept on any host-inbound-configured zone, exactly as nft does.
///
/// The ICMPv4 set is deliberately NARROWER than `icmp::is_icmp_error` (the
/// embedded-NAT reversal set, which also includes v4 Source Quench (4) and
/// Redirect (5)): Source Quench is deprecated (RFC 6633) and v4 Redirect is
/// link-scoped — neither is a control message we admit to the host, and neither
/// is in the nft v4 global accept. ECHO REQUEST (v4 type 8 / v6 type 128) is NOT
/// here: it stays gated on the `ping` system-service (per-zone `icmp_types_*`),
/// so a ping-less zone still drops echo. IPv4 router-advertisement/solicitation
/// (9/10) are likewise NOT global — they are gated on `router-discovery` per
/// zone (nft `icmp type { 9, 10 }`).
///
/// Keep this set in lock-step with the kernel chain in
/// `pkg/daemon/daemon_nft.go` and its
/// `TestHostInboundFilterExemptsIPsecAndV6Errors` accept assertions.
/// #7520: expose the predicate to the family-pairing test. A `for_test`
/// accessor rather than widening the function itself — the test needs to CALL
/// it, not to make it part of the module's surface.
#[cfg(test)]
pub(super) fn is_icmp_host_inbound_global_accept_for_test(
    protocol: u8,
    is_v6: bool,
    icmp_type: u8,
) -> bool {
    is_icmp_host_inbound_global_accept(protocol, is_v6, icmp_type)
}

fn is_icmp_host_inbound_global_accept(protocol: u8, is_v6: bool, icmp_type: u8) -> bool {
    // #7520: the protocol number is paired with the IP FAMILY, not read alone.
    //
    // Switching on `protocol` by itself is family-blind, and the two arms mean
    // different things on different families. An IPv4 packet whose protocol
    // byte is 58 took the ICMPv6 arm and was globally admitted for type 1/2/3/4
    // or 133..137 — bypassing zone admission entirely — even though 58 is not
    // ICMPv6 on IPv4. Symmetrically an IPv6 packet with next-header 1 took the
    // ICMPv4 arm. Both are fail-OPEN: this predicate returns early, BEFORE the
    // zone lookup, so a match here admits a packet the zone's
    // `host-inbound-traffic` set never permitted.
    //
    // The type numbers do not disambiguate it either — they overlap. ICMPv6
    // destination-unreachable is 1, and 1 is a legal (if unassigned-to-error)
    // ICMPv4 type; ICMPv4 time-exceeded is 11, which is nothing in ICMPv6's
    // error range. A `(protocol, type)` pair alone cannot tell the two apart,
    // which is why the family has to be part of the key.
    //
    // An unknown / neither-family packet admits nothing: the fall-through is
    // false, so a packet whose address family the parser could not determine
    // stays gated on the zone set rather than exempted.
    match (protocol, is_v6) {
        // ICMPv4 on IPv4: destination-unreachable (3, also carries PMTUD
        // "fragmentation needed" as code 4), time-exceeded (11),
        // parameter-problem (12).
        (1, false) => matches!(icmp_type, 3 | 11 | 12),
        // ICMPv6 on IPv6 errors: destination-unreachable (1), packet-too-big
        // (2, PMTUD), time-exceeded (3), parameter-problem (4); PLUS the ND
        // set: RS (133), RA (134), NS (135), NA (136), Redirect (137).
        (58, true) => matches!(icmp_type, 1 | 2 | 3 | 4 | 133 | 134 | 135 | 136 | 137),
        _ => false,
    }
}

/// Per-packet host-inbound admit check for a host-bound (local-delivery)
/// packet ingressing `ingress_zone_id`. Returns true (admit) when the packet is
/// an ICMP/ICMPv6 error/PMTUD control message (#3171 — always exempt, mirroring
/// the kernel chain), when the ingress zone is genuinely unknown / global (id
/// not in the table — see below), or when the packet's service/protocol is in
/// the zone's admission set. Returns false (deny) when the zone IS configured
/// and the packet matches nothing — which, since #3405, includes every
/// configured security zone with no `host-inbound-traffic` stanza (it arrives
/// with an empty set -> default-deny). `icmp_type` is the first L4 byte for
/// ICMP/ICMPv6 packets and is ignored for every other protocol (pass 0).
pub(in crate::afxdp) fn host_inbound_admits(
    state: &ForwardingState,
    ingress_zone_id: u16,
    protocol: u8,
    dst_port: u16,
    is_v6: bool,
    icmp_type: u8,
) -> bool {
    // #3171/#3201/#3240: error/PMTUD control messages AND the IPv6 ND set are
    // admitted before the zone lookup so PMTUD / unreachable / traceroute-to-self
    // and v6 RS/RA work on a configured zone that omits `ping` / scopes
    // router-discovery, matching the kernel host-inbound chain's global accepts.
    // Echo-request and IPv4 router-advert/solicit are NOT in this set, so they
    // stay gated on the `ping` / `router-discovery` tokens below.
    if is_icmp_host_inbound_global_accept(protocol, is_v6, icmp_type) {
        return true;
    }
    match state.zone_host_inbound.get(&ingress_zone_id) {
        // #3405: every configured security zone is in the table (the Go control
        // plane marks them all `host_inbound_configured`), so `None` is now only
        // a genuinely unknown / global ingress zone (e.g. id 0, no resolved
        // security zone). Such traffic keeps the admit default — narrowing it is
        // out of scope for the configured-zone default-deny fix and risks
        // breaking ND / control delivery on the global context.
        //
        // #5659: an ADDRESSED interface with an EMPTY security-zone also resolves
        // to id 0 here, but its host-inbound is denied WITHOUT touching this
        // global admit arm — `populate_interfaces` inserts an empty
        // `ZoneHostInbound` sentinel into `ifindex_host_inbound` keyed by that
        // interface's ifindex, so the ingress-interface-keyed
        // `host_inbound_admits_iface` denies it while this zone-only path (and a
        // legitimately-zoneless NON-addressed control interface) keeps admit.
        //
        // #6873: WHAT THIS ARM DOES NOT SETTLE. The two citations above narrow
        // WHICH ingress contexts reach `None`; neither says anything about the
        // table being EMPTY, and an empty table sends EVERY zone id here. That
        // is a real fail-open — `cold_forwarding_state_admits_every_host_inbound
        // _service_6873` demonstrates a default `ForwardingState` admitting ssh,
        // https, v6 DNS and raw GRE — so the question "can a reader observe the
        // empty table?" is load-bearing and is answered here rather than left to
        // the next audit to re-derive.
        //
        // It cannot, and the reason is worker LIFECYCLE ORDERING, not a flag:
        //
        //   - `bring_up_workers` is the only worker spawn path (README:133
        //     forbids a bare `std::thread::spawn` for a worker), and reconcile
        //     runs `tear_down` -> `apply_snapshot` (publishes a snapshot-derived
        //     forwarding state) -> `bring_up_workers`. A worker is spawned only
        //     after a real state is published.
        //   - `reconcile(None, ..)` takes its early exit AFTER `tear_down`
        //     (coordinator/reconcile/mod.rs), so "no snapshot" means "no
        //     workers", never "workers on an empty table".
        //   - `stop_inner` JOINS every worker via `workers.stop_and_clear(..)`
        //     BEFORE `self.forwarding = ForwardingState::default()` (#6592), so
        //     the reset is never visible to a live reader.
        //
        // A `snapshot_installed` check here would therefore be dead code: it
        // would gate a state no reader can reach, and bury the invariant that
        // actually protects this arm one layer deeper. The invariant is pinned
        // instead, by `no_snapshot_reconcile_leaves_no_reader_for_the_empty
        // _table_6873` (coordinator/tests.rs) — an ordering invariant with no
        // test is one refactor from being false.
        //
        // TWO SURFACES, TWO DIFFERENT ANSWERS — and the difference is why this
        // arm keeps getting re-audited. host-inbound is enforced BOTH here and
        // by the kernel nft chain, and the cold-boot question resolves
        // oppositely on each:
        //
        //   - KERNEL nft chain: the window IS reachable. A boot apply can fail
        //     with no prior table to retain, leaving the host path with no
        //     chain at all, so it needs a real gate — `installHostInboundCold
        //     BootFence` (#5644, and its lo0 analogue #6476), guarded by
        //     `TestColdBootHostInboundInstallFailureInstallsFence`.
        //   - HERE (userspace AF_XDP classifier): unreachable, by the worker
        //     lifecycle above. There is no failed-apply equivalent, because a
        //     worker only exists once a state has been published.
        //
        // So "the host-inbound cold-boot fail-open was closed in #5644" is true
        // of the kernel surface and says nothing about this one. Reading that
        // sentence next to this arm is what makes an auditor expect a fence
        // here and file the absence of one — twice so far.
        //
        // So, precisely: this arm is settled for CONFIGURED zones (#3405) and
        // for addressed empty-zone interfaces (#5659); it deliberately keeps
        // admit for a legitimately zoneless NON-addressed control interface; and
        // the empty-table case is unreachable by the ordering above rather than
        // by anything this function does.
        None => true,
        // A configured zone — including one with no `host-inbound-traffic` stanza
        // (empty set) — denies anything its set does not admit (#3405).
        Some(hi) => hi.admits(protocol, dst_port, is_v6, icmp_type),
    }
}

/// #3362: per-packet host-inbound admit keyed by INGRESS INTERFACE first. When
/// the ingress interface carries a per-interface host-inbound OVERRIDE
/// (`state.ifindex_host_inbound`), the packet is matched against that interface's
/// EFFECTIVE admission set (resolved in Go: the interface stanza REPLACES the
/// zone one, #6515); otherwise it
/// falls back to the zone-keyed [`host_inbound_admits`]. The global
/// ICMP/PMTUD/ND accept (#3171) is applied first in BOTH branches so error / ND
/// delivery is never broken by a scoped override. This is the entry point the
/// local-delivery poll path uses; `host_inbound_admits` stays the zone-only
/// primitive (and the direct test target).
#[allow(clippy::too_many_arguments)]
pub(in crate::afxdp) fn host_inbound_admits_iface(
    state: &ForwardingState,
    ingress_ifindex: i32,
    ingress_zone_id: u16,
    protocol: u8,
    dst_port: u16,
    is_v6: bool,
    icmp_type: u8,
) -> bool {
    if let Some(hi) = state.ifindex_host_inbound.get(&ingress_ifindex) {
        if is_icmp_host_inbound_global_accept(protocol, is_v6, icmp_type) {
            return true;
        }
        return hi.admits(protocol, dst_port, is_v6, icmp_type);
    }
    host_inbound_admits(state, ingress_zone_id, protocol, dst_port, is_v6, icmp_type)
}

#[cfg(test)]
#[path = "host_inbound_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "unzoned_tunnel_host_inbound_9941_tests.rs"]
mod unzoned_tunnel_9941_tests;
