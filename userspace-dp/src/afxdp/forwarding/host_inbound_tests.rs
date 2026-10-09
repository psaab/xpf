use super::*;

// #3405: a CONFIGURED zone with an EMPTY admission set (the on-wire shape of a
// security zone that declared no `host-inbound-traffic` stanza — the Go
// control plane now marks every zone host_inbound_configured) must
// default-DENY every host-bound service/protocol, while the global
// ICMP/ND/PMTUD accept still admits error/PMTUD control. This pins the
// load-bearing Rust half of the #3405 default-deny: `Some(empty) => deny`,
// NOT the pre-#3405 admit. Fail-on-revert: change the `Some(hi)` arm of
// host_inbound_admits to admit when the set is empty (or special-case an
// empty zone back to admit) and the SSH assertion below flips RED.
#[test]
fn empty_configured_zone_default_denies() {
    const TCP: u8 = 6;
    const ZONE: u16 = 7;

    let mut state = ForwardingState::default();
    // A configured zone with NO tokens = the no-stanza / empty-stanza shape.
    state
        .zone_host_inbound
        .insert(ZONE, zone_host_inbound_from_tokens(&[], &[]));

    // SSH (tcp/22) to the host on this zone is DENIED — the zone opened
    // nothing. (Pre-#3405 a no-stanza zone was absent from the table and this
    // returned admit via `None => true`.)
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 22, false, 0),
        "empty configured zone must deny ssh (tcp/22) — #3405 default-deny",
    );
    // HTTPS (tcp/443) and an arbitrary UDP service are likewise denied.
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 443, false, 0),
        "empty configured zone must deny https (tcp/443)",
    );
    assert!(
        !host_inbound_admits(&state, ZONE, 17, 53, true, 0),
        "empty configured zone must deny udp/53 on v6",
    );

    // The global ICMP error/PMTUD accept (#3171) still fires: v4
    // destination-unreachable (type 3) and v6 packet-too-big (type 2) reach
    // the host even on a default-deny zone, so PMTUD is never black-holed.
    assert!(
        host_inbound_admits(&state, ZONE, 1, 0, false, 3),
        "ICMPv4 destination-unreachable must stay globally admitted",
    );
    assert!(
        host_inbound_admits(&state, ZONE, 58, 0, true, 2),
        "ICMPv6 packet-too-big (PMTUD) must stay globally admitted",
    );

    // A genuinely unknown / global ingress zone (id not in the table) keeps
    // the admit default — #3405 is scoped to configured zones only.
    assert!(
        host_inbound_admits(&state, 999, TCP, 22, false, 0),
        "unknown/global zone (absent from table) keeps the admit default",
    );
}

// #12053: this shared fixture is the concrete system-service list emitted by
// the Go compiler for `all; ssh except`. A Go regression asserts byte-for-byte
// that it still matches compiler output; feeding that exact list through the
// Rust classifier must not re-open TCP/22, while `netconf` keeps TCP/830.
#[test]
fn all_except_ssh_emitted_services_do_not_admit_tcp22_12053() {
    let emitted_services: Vec<String> = serde_json::from_str(include_str!(
        "host_inbound_all_except_ssh_12053.json"
    ))
    .expect("shared Go compiler emission fixture is valid JSON");
    let hi = zone_host_inbound_from_tokens(&emitted_services, &[]);

    assert!(
        !hi.admits(6, 22, false, 0),
        "effective `all; ssh except` list must not re-admit TCP/22 through an alias",
    );
    assert!(
        !hi.admits(6, 22, true, 0),
        "effective `all; ssh except` list must not re-admit TCP/22 on IPv6",
    );
    assert!(
        hi.admits(6, 830, false, 0),
        "excluding SSH must preserve the independent `netconf` TCP/830 service",
    );
}

// #3310: `system-services ident-reset` must NOT admit TCP/113 on the AF_XDP
// secondary path — Junos ident-reset resets ident probes, it does not permit
// the service. The kernel nft chain emits the actual `reject with tcp reset`
// (primary path); this classifier just stops admitting 113 so the rare
// AF_XDP-reached ident packet (DNAT/static-NAT-to-113) is dropped. Co-declared
// services on the SAME zone (ssh/http) must still admit (no over-removal), and
// UDP/113 (not ident) is likewise not admitted. Fail-on-revert: restore
// `hi.tcp_ports.insert(113)` in the ident-reset classifier arm and the
// tcp/113-denied assertion flips RED.
#[test]
fn ident_reset_does_not_admit_113() {
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const ZONE: u16 = 11;

    let mut state = ForwardingState::default();
    // A zone that declares ident-reset ALONGSIDE ssh + http (so the test
    // proves ident-reset removes ONLY 113, not the co-declared services —
    // ssh/http admit only from their own classifier arms).
    state.zone_host_inbound.insert(
        ZONE,
        zone_host_inbound_from_tokens(
            &[
                "ident-reset".to_string(),
                "ssh".to_string(),
                "http".to_string(),
            ],
            &[],
        ),
    );

    // TCP/113 is NOT admitted (dropped on the secondary path), v4 and v6.
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 113, false, 0),
        "ident-reset must NOT admit TCP/113 on v4 (#3310) — it resets, not permits",
    );
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 113, true, 0),
        "ident-reset must NOT admit TCP/113 on v6 (#3310)",
    );
    // UDP/113 (not ident) is not admitted either.
    assert!(
        !host_inbound_admits(&state, ZONE, UDP, 113, false, 0),
        "UDP/113 must not be admitted (ident is TCP-only)",
    );
    // The co-declared services on the same zone still admit (no over-removal).
    assert!(
        host_inbound_admits(&state, ZONE, TCP, 22, false, 0),
        "co-declared ssh (tcp/22) must still admit",
    );
    assert!(
        host_inbound_admits(&state, ZONE, TCP, 80, false, 0),
        "co-declared http (tcp/80) must still admit",
    );
}

// #3311: the `protocols all` expansion must EXCLUDE every L2/non-IP protocol
// (IS-IS) — they cannot produce an IP host-inbound admit and are handled by
// FRR over L2. This guards the SSOT-driven exclusion
// (routing_protocol_all_expansion = KNOWN_ROUTING_PROTOCOL_TOKENS minus
// HOST_INBOUND_L2_PROTOCOLS), the load-bearing job of the L2 set on this
// surface. Fail-on-revert: remove "isis" from HOST_INBOUND_L2_PROTOCOLS and
// isis (still in KNOWN_ROUTING_PROTOCOL_TOKENS) reappears in the expansion,
// turning the exclusion assertion RED. Mirrors the Go
// TestHostInboundProtocolsAllExcludesL2.
#[test]
fn protocols_all_excludes_l2() {
    let expansion: Vec<&str> = routing_protocol_all_expansion().collect();

    // Every L2 protocol is excluded from the IP `all` expansion.
    for l2 in HOST_INBOUND_L2_PROTOCOLS {
        assert!(
            !expansion.contains(l2),
            "L2 protocol {l2:?} must be excluded from the `protocols all` IP expansion",
        );
    }
    // IS-IS specifically: a recognized routing token that is nonetheless
    // kept out of the expansion BECAUSE it is in the L2 set.
    assert!(
        KNOWN_ROUTING_PROTOCOL_TOKENS.contains(&"isis"),
        "isis must be a recognized routing token (so the exclusion is meaningful)",
    );
    assert!(
        !expansion.contains(&"isis"),
        "isis (L2) must not appear in the `protocols all` IP expansion",
    );
    // Sanity: real IP routing protocols still expand.
    for p in ["ospf", "ospf3", "bgp", "bfd", "router-discovery"] {
        assert!(
            expansion.contains(&p),
            "IP routing protocol {p:?} must remain in the `protocols all` expansion",
        );
    }
}

// #3362: the per-interface host-inbound OVERRIDE keys the admit check by
// ingress ifindex. An interface with an override is matched against ITS
// effective set; an interface without one falls back to the from-zone set.
// Fail-on-revert: make host_inbound_admits_iface ignore ifindex_host_inbound
// (i.e. always defer to the zone) and the override-scoped assertions flip.
#[test]
fn per_interface_override_keys_by_ifindex() {
    const TCP: u8 = 6;
    const IFINDEX_UPLINK: i32 = 100; // ssh override
    const IFINDEX_OTHER: i32 = 200; // no override (zone fallback)
    const ZONE: u16 = 5; // zone-keyed set = ping only

    let mut state = ForwardingState::default();
    // Zone-level set: ping (ICMP echo) only — NO ssh.
    state.zone_host_inbound.insert(
        ZONE,
        zone_host_inbound_from_tokens(&["ping".to_string()], &[]),
    );
    // Per-interface override on the uplink: ssh only.
    state.ifindex_host_inbound.insert(
        IFINDEX_UPLINK,
        zone_host_inbound_from_tokens(&["ssh".to_string()], &[]),
    );

    // Uplink (override present): admits ssh, denies https, and does NOT
    // inherit the zone's ping (the override REPLACES the zone set on this
    // interface — #6515 — and the carried set is already resolved in Go).
    assert!(
        host_inbound_admits_iface(&state, IFINDEX_UPLINK, ZONE, TCP, 22, false, 0),
        "uplink override must admit ssh (tcp/22)",
    );
    assert!(
        !host_inbound_admits_iface(&state, IFINDEX_UPLINK, ZONE, TCP, 443, false, 0),
        "uplink override (ssh only) must deny https (tcp/443)",
    );

    // Other interface (no override): falls back to the zone set — denies ssh,
    // admits the zone's ping echo-request (icmp v4 type 8).
    assert!(
        !host_inbound_admits_iface(&state, IFINDEX_OTHER, ZONE, TCP, 22, false, 0),
        "non-overridden interface must fall back to the zone set (no ssh)",
    );
    assert!(
        host_inbound_admits_iface(&state, IFINDEX_OTHER, ZONE, 1, 0, false, 8),
        "non-overridden interface must inherit the zone's ping admit",
    );

    // Global ICMP error/PMTUD accept (#3171) still applies on the override
    // path: destination-unreachable (v4 type 3) is admitted even though the
    // override set is ssh-only.
    assert!(
        host_inbound_admits_iface(&state, IFINDEX_UPLINK, ZONE, 1, 0, false, 3),
        "ICMP error/PMTUD must stay globally admitted on the override path",
    );
}

// #3311: a zone with `protocols all` must NOT admit IS-IS as an IP protocol
// (proto 124, integrated IS-IS-over-IP), proving the L2 exclusion holds end
// to end through classify_protocol. It must still admit a real expanded IP
// protocol (OSPF, proto 89). Fail-on-revert: remove isis from
// HOST_INBOUND_L2_PROTOCOLS — isis enters the expansion, but its
// classify_protocol arm is a no-op, so this stays green; the
// protocols_all_excludes_l2 token test above is the real RED-on-revert guard.
// #3341: the routing-control tokens rsvp/pgm/sap/dvmrp must each classify to
// the correct IP admit with the correct family scoping, mirroring the nft
// matcher (hostInboundProtocolMatches) and the Go SSOT. Fail-on-revert:
// before #3341 these hit the catch-all `_ => {}` no-op arm, so every admit
// assertion below goes RED.
#[test]
fn routing_control_protocol_tokens_classify() {
    // rsvp — IP proto 46, dual-family.
    let mut hi = ZoneHostInbound::default();
    classify_protocol("rsvp", &mut hi);
    assert!(hi.admits(46, 0, false, 0), "rsvp must admit proto 46 on v4");
    assert!(
        hi.admits(46, 0, true, 0),
        "rsvp must admit proto 46 on v6 (dual)"
    );

    // pgm — IP proto 113, dual-family.
    let mut hi = ZoneHostInbound::default();
    classify_protocol("pgm", &mut hi);
    assert!(
        hi.admits(113, 0, false, 0),
        "pgm must admit proto 113 on v4"
    );
    assert!(
        hi.admits(113, 0, true, 0),
        "pgm must admit proto 113 on v6 (dual)"
    );

    // sap — UDP/9875, dual-family.
    let mut hi = ZoneHostInbound::default();
    classify_protocol("sap", &mut hi);
    assert!(
        hi.admits(17, 9875, false, 0),
        "sap must admit udp/9875 on v4"
    );
    assert!(
        hi.admits(17, 9875, true, 0),
        "sap must admit udp/9875 on v6 (dual)"
    );

    // dvmrp — IGMP-encapsulated (proto 2), IPv4-only.
    let mut hi = ZoneHostInbound::default();
    classify_protocol("dvmrp", &mut hi);
    assert!(
        hi.admits(2, 0, false, 0),
        "dvmrp must admit proto 2 (IGMP) on v4"
    );
    assert!(
        !hi.admits(2, 0, true, 0),
        "dvmrp must NOT admit proto 2 on v6 (IPv4-only)",
    );

    // All four are recognized routing tokens (so `protocols all` covers them)
    // and none are L2.
    for tok in ["rsvp", "pgm", "sap", "dvmrp"] {
        assert!(
            KNOWN_ROUTING_PROTOCOL_TOKENS.contains(&tok),
            "{tok} must be a recognized routing token",
        );
        assert!(
            !is_host_inbound_l2_protocol(tok),
            "{tok} rides IP, must not be an L2 protocol",
        );
    }
}

#[test]
fn protocols_all_admits_ip_routing_not_l2() {
    let mut hi = ZoneHostInbound::default();
    classify_protocol("all", &mut hi);
    // OSPFv2 (proto 89) admitted on v4 via the expansion.
    assert!(
        hi.admits(89, 0, false, 0),
        "`protocols all` must admit OSPF (proto 89) on v4",
    );
    // Integrated IS-IS-over-IP (proto 124) is NOT admitted — isis is L2.
    assert!(
        !hi.admits(124, 0, false, 0),
        "`protocols all` must not admit IS-IS (proto 124) — L2/OSI, handled by FRR",
    );
}

// #3226: `system-services all` is the union of the DEFINED system services
// (Junos: "traffic from the defined system services available on the Routing
// Engine"), NOT a packet-wide admit. Before #3226 the `all` arm set
// `all_services = true`, which short-circuits `ZoneHostInbound::admits` to
// `true` for EVERY protocol/port — so an `all` zone accepted GRE/ESP/AH/OSPF/
// PIM/VRRP and any future protocol number on its local addresses. This asserts
// the per-packet VERDICT on the AF_XDP classifier, the mirror of the Go
// TestClassifyHostInboundSystemServicesAllScopedToNamedServices and the nft
// TestHostInboundNftSystemServicesAllIsScopedNotBlanket.
//
// FAIL-ON-REVERT: fold `all` back into the `any-service` arm (or make
// system_service_all_expansion yield nothing) and the DENIED assertions flip.
#[test]
fn system_services_all_is_scoped_not_packet_wide() {
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const ZONE: u16 = 11;

    let mut state = ForwardingState::default();
    state
        .zone_host_inbound
        .insert(ZONE, zone_host_inbound_from_tokens(&["all".to_string()], &[]));

    // ADMITTED: the named system-service union `all` stands for.
    for (name, proto, port) in [
        ("ssh", TCP, 22u16),
        ("https", TCP, 443),
        ("telnet", TCP, 23),
        ("snmp", UDP, 161),
        ("ntp", UDP, 123),
        ("ike", UDP, 500),
        ("netconf", TCP, 830),
    ] {
        assert!(
            host_inbound_admits(&state, ZONE, proto, port, false, 0),
            "`system-services all` must admit {name} ({proto}/{port}) — it expands to the named service union",
        );
    }

    // DENIED: raw IP protocols Junos's `all` never opens. ESP(50)/AH(51) are
    // deliberately omitted — they carry an unconditional host-terminated-IPsec
    // accept upstream of this classifier, so they prove nothing here.
    for (name, proto) in [
        ("ospf", 89u8),
        ("gre", 47),
        ("vrrp", 112),
        ("pim", 103),
        ("nhrp", 54),
        ("future-proto-253", 253),
    ] {
        assert!(
            !host_inbound_admits(&state, ZONE, proto, 0, false, 0),
            "`system-services all` must DENY raw IP protocol {name} ({proto}) — it is not a packet-wide admit (#3226)",
        );
    }

    // DENIED: an unlisted TCP port — the per-zone default deny is re-armed.
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 9999, false, 0),
        "`system-services all` must DENY an unlisted tcp/9999 (#3226)",
    );

    // The v6 family behaves identically for the dual-family services.
    assert!(
        host_inbound_admits(&state, ZONE, TCP, 22, true, 0),
        "`system-services all` must admit ssh on IPv6 too",
    );
    assert!(
        !host_inbound_admits(&state, ZONE, 89, 0, true, 0),
        "`system-services all` must DENY ospf3/proto-89 on IPv6 too (#3226)",
    );
}

// #3226 over-reach guard: `any-service` REMAINS the packet-wide escape hatch
// (Junos: "all system services on an entire port range including the system
// services that are not defined"). If the narrowing were mistakenly applied to
// `any-service` as well, every assertion here flips.
#[test]
fn any_service_remains_full_admit() {
    const ZONE: u16 = 12;

    let mut state = ForwardingState::default();
    state.zone_host_inbound.insert(
        ZONE,
        zone_host_inbound_from_tokens(&["any-service".to_string()], &[]),
    );

    for (name, proto, port) in [
        ("ospf", 89u8, 0u16),
        ("gre", 47, 0),
        ("vrrp", 112, 0),
        ("unlisted tcp/9999", 6, 9999),
    ] {
        assert!(
            host_inbound_admits(&state, ZONE, proto, port, false, 0),
            "`any-service` must remain a full admit for {name} — it is the documented escape hatch (#3226)",
        );
    }
}

// #3226: the `system-services all` expansion EXCLUDES the xpf-only extension
// tokens (HOST_INBOUND_NON_JUNOS_SERVICES) — the load-bearing job of that set
// on this surface, mirroring HOST_INBOUND_L2_PROTOCOLS for `protocols all`.
// `gre` is a recognized xpf system-service (so the exclusion is meaningful) but
// is NOT a Junos system service, so folding it into `all` would make `all` open
// IP protocol 47 that Junos's `all` never opens.
//
// FAIL-ON-REVERT: remove "gre" from HOST_INBOUND_NON_JUNOS_SERVICES and it
// reappears in the expansion, turning the exclusion assertion RED.
#[test]
fn system_services_all_excludes_non_junos_extensions() {
    let expansion: Vec<&str> = system_service_all_expansion().collect();

    for x in HOST_INBOUND_NON_JUNOS_SERVICES {
        assert!(
            !expansion.contains(x),
            "xpf-only service {x:?} must be excluded from the `system-services all` expansion",
        );
    }
    assert!(
        KNOWN_SYSTEM_SERVICE_TOKENS.contains(&"gre"),
        "gre must be a recognized system-service token (so the exclusion is meaningful)",
    );
    assert!(
        !expansion.contains(&"gre"),
        "gre (xpf extension) must not appear in the `system-services all` expansion",
    );
    // The two meta tokens must never appear — `all` would recurse forever.
    for meta in ["all", "any-service"] {
        assert!(
            !expansion.contains(&meta),
            "meta token {meta:?} must not appear in the `system-services all` expansion (recursion / semantics)",
        );
    }
    // Sanity: real Junos system services still expand.
    for s in ["ssh", "https", "snmp", "ping", "ntp", "ident-reset"] {
        assert!(
            expansion.contains(&s),
            "Junos system service {s:?} must remain in the `system-services all` expansion",
        );
    }
}

// #3226 fold, fail-CLOSED half: scoping `all` to the recognized-token union
// only preserves Junos semantics if that union CONTAINS every service Juniper
// defines. Several did not exist on either surface, so an authored `all`
// stopped admitting them with no in-grammar way to restore them (the Go strict
// validator rejects any token outside the same allowlist).
//
// The set is derived from Juniper's published YANG schema, extracted into
// pkg/config/testdata/junos-es-conf-security@2024-01-01.yang.gz — NOT from
// the prose reference pages, which are individually incomplete and had this
// union wrong three times.
//
// This test covers only the tokens with a port Juniper actually FIXES:
//
//   reverse-telnet tcp/2900, reverse-ssh tcp/2901
//       explicit YANG `default` statements on
//       `[edit system services reverse telnet|ssh] port`.
//   lsselfping udp/8503
//       RFC 7746 §3/§6 (IANA `lsp-self-ping`). NOT 3503 — that is `lsping`.
//
// The remaining Junos services in the union have no authoritative tuple xpf can
// admit and are
// covered by `unported_services_admit_nothing_3226` instead.
//
// Rust mirror of the Go TestClassifyHostInboundAllAdmitsDocumentedJunosServices
// and the nft golden TestHostInboundNftRenderGoldenByteIdentical.
//
// FAIL-ON-REVERT: drop a token from KNOWN_SYSTEM_SERVICE_TOKENS or its
// classify_system_service arm and its rows flip to denied.
#[test]
fn system_services_all_admits_documented_junos_services_3226() {
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const ZONE: u16 = 14;

    let mut state = ForwardingState::default();
    state
        .zone_host_inbound
        .insert(ZONE, zone_host_inbound_from_tokens(&["all".to_string()], &[]));

    for (name, token, proto, port) in [
        ("reverse-telnet", "reverse-telnet", TCP, 2900u16),
        ("reverse-ssh", "reverse-ssh", TCP, 2901),
        ("lsselfping", "lsselfping", UDP, 8503),
    ] {
        // Reached through the `all` union, on both families.
        for v6 in [false, true] {
            assert!(
                host_inbound_admits(&state, ZONE, proto, port, v6, 0),
                "`system-services all` must admit {name} ({proto}/{port}, v6={v6}) — it is a documented Junos system-service",
            );
        }
        // And reachable by NAMING the service, which is what makes the union
        // restorable rather than a dead end.
        let mut named = ForwardingState::default();
        named
            .zone_host_inbound
            .insert(ZONE, zone_host_inbound_from_tokens(&[token.to_string()], &[]));
        assert!(
            host_inbound_admits(&named, ZONE, proto, port, false, 0),
            "an explicit `system-services {token}` must admit {name} ({proto}/{port})",
        );
    }
}

// #3226 fold, unverified-port half: the Junos services xpf has no authoritative
// listening port for (HOST_INBOUND_UNPORTED_SERVICES) must contribute NOTHING to
// the admit set — whether reached through `all` or named explicitly.
//
// Earlier revisions of this fold synthesized a port for two of them from
// circumstantial evidence: r2cp udp/28762 (a value draft-dubois-r2cp-00 merely
// SUGGESTS for prototypes, which Juniper adopts nowhere) and rpm tcp+udp/7 (the
// FLOOR of the configurable `[edit services rpm probe-server] port` range, not a
// default — the container is presence-gated, so with no configuration nothing
// listens at all). Both opened a port on every `all` zone that in the ordinary
// case has no listener, while still failing to open whatever port the operator
// actually configured. An unverified port is wrong in BOTH directions at once,
// which is why the correct model is no tuple plus a commit advisory.
//
// The basis is a deliberate CHOICE under uncertainty, NOT an inference from the
// schema. (An earlier revision argued the absence of a YANG `default` proved
// there was no fixed port; that is false — `[edit system services telnet]` has
// no port leaf either, yet telnet is TCP/23 — and has been withdrawn.) No
// authoritative host-inbound tuple was found for these tokens, and under that
// gap opening nothing fails in one direction and visibly, whereas a guess fails
// in both directions and silently.
//
// FAIL-ON-REVERT: hand any of these tokens a port (in classify_system_service or
// by dropping it from HOST_INBOUND_UNPORTED_SERVICES while adding an insert) and
// the sweep below flips to admitted. The two historical guesses are probed by
// name so a literal revert of the previous revision is caught precisely.
#[test]
fn unported_services_admit_nothing_3226() {
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const ZONE: u16 = 21;

    // A representative sweep: the two historical guesses, plus ports that would
    // plausibly be reached for these services, plus a raw IP protocol.
    let probes: [(u8, u16); 10] = [
        (UDP, 28762), // the r2cp guess (draft "suggested", never Junos)
        (TCP, 7),     // the rpm guess (range floor, not a default)
        (UDP, 7),
        (TCP, 443),   // a tcp-encap port in Juniper's own sample output
        (TCP, 9500),  // another port from that sample (remote gateway side)
        (UDP, 36000), // the appqoe PASSIVE probe — transit, Juniper says DISCARD
        (UDP, 500),   // MNHA examples admit IKE via its OWN `ike` token
        (TCP, 22),    // ...and SSH via its OWN `ssh` token
        (UDP, 3503),  // lsping's port must not leak to an unported token
        (TCP, 830),
    ];

    for token in HOST_INBOUND_UNPORTED_SERVICES {
        let mut named = ForwardingState::default();
        named.zone_host_inbound.insert(
            ZONE,
            zone_host_inbound_from_tokens(&[(*token).to_string()], &[]),
        );
        for (proto, port) in probes {
            for v6 in [false, true] {
                assert!(
                    !host_inbound_admits(&named, ZONE, proto, port, v6, 0),
                    "`system-services {token}` must admit NOTHING ({proto}/{port}, v6={v6}) — \
                     xpf has no authoritative listening port for it, so any admit here is a guess (#3226)",
                );
            }
        }
        // The token must still be RECOGNIZED (it is a real Junos service and a
        // valid vSRX stanza must commit) — assert it is in the known set, so
        // "admits nothing" can never be satisfied by deleting the token.
        assert!(
            KNOWN_SYSTEM_SERVICE_TOKENS.contains(token),
            "{token} must stay a recognized system-service — the no-port model \
             narrows what it admits, it does not remove the token",
        );
        // ...and it must NOT be an xpf-only extension: these are genuine Junos
        // services, so `all` still covers them (contributing nothing).
        assert!(
            !HOST_INBOUND_NON_JUNOS_SERVICES.contains(token),
            "{token} is a Junos service, not an xpf extension — it must stay in the `all` union",
        );
    }

    // Reached through `all`, the same ports stay denied: the union inherits the
    // no-tuple model rather than re-opening the guesses.
    let mut all = ForwardingState::default();
    all.zone_host_inbound
        .insert(ZONE, zone_host_inbound_from_tokens(&["all".to_string()], &[]));
    for (proto, port) in [(UDP, 28762u16), (TCP, 7), (UDP, 7), (UDP, 36000)] {
        assert!(
            !host_inbound_admits(&all, ZONE, proto, port, false, 0),
            "`system-services all` must DENY {proto}/{port} — it expands to the Junos service \
             union, and no service in that union fixes this port (#3226)",
        );
    }
    // Guard against the sweep going vacuously green: `all` must still admit the
    // services that DO carry a fixed port.
    for (proto, port) in [(TCP, 2900u16), (TCP, 2901), (UDP, 8503), (TCP, 22)] {
        assert!(
            host_inbound_admits(&all, ZONE, proto, port, false, 0),
            "`system-services all` must still admit {proto}/{port} — otherwise the deny \
             assertions above prove nothing",
        );
    }
}

// #3226 fold, over-admit half: `r-exec`/`rexec` (tcp/512) is absent from
// Juniper's documented host-inbound service list — zone-level and
// interface-level both document rlogin and rsh but not rexec — so a
// Junos-correct `all` never opens 512. Unlike the port-neutral xpf spellings
// (webapi-* resolve to the http/https ports, ssh-netconf to ssh ∪ netconf) 512
// is opened by no other token, so including it widened `all` past the meaning
// #3226 restores.
//
// FAIL-ON-REVERT: remove "r-exec"/"rexec" from HOST_INBOUND_NON_JUNOS_SERVICES
// and the first assertion flips to admitted.
#[test]
fn system_services_all_excludes_rexec_3226() {
    const TCP: u8 = 6;
    const ZONE: u16 = 15;

    let mut state = ForwardingState::default();
    state
        .zone_host_inbound
        .insert(ZONE, zone_host_inbound_from_tokens(&["all".to_string()], &[]));
    assert!(
        !host_inbound_admits(&state, ZONE, TCP, 512, false, 0),
        "`system-services all` must DENY rexec tcp/512 — it is not a documented Junos system-service (#3226)",
    );

    // Both spellings stay fully usable when listed EXPLICITLY.
    for token in ["r-exec", "rexec"] {
        let mut named = ForwardingState::default();
        named
            .zone_host_inbound
            .insert(ZONE, zone_host_inbound_from_tokens(&[token.to_string()], &[]));
        assert!(
            host_inbound_admits(&named, ZONE, TCP, 512, false, 0),
            "an explicit `system-services {token}` must still admit tcp/512 — the carve-out narrows `all`, it does not remove the token",
        );
    }
}

// #3226: an EXPLICIT `system-services gre` still admits IP protocol 47. The
// carve-out narrows the `all` meta-token; it does not remove the token. Without
// this the exclusion above could be "fixed" by deleting the gre arm entirely.
#[test]
fn explicit_gre_service_still_admits_proto_47() {
    const ZONE: u16 = 13;

    let mut state = ForwardingState::default();
    state
        .zone_host_inbound
        .insert(ZONE, zone_host_inbound_from_tokens(&["gre".to_string()], &[]));

    assert!(
        host_inbound_admits(&state, ZONE, 47, 0, false, 0),
        "an explicit `system-services gre` must still admit IP protocol 47",
    );
}

// #6873 STEP 1 — the PAYLOAD PROOF for the ordering guard in
// `coordinator/tests.rs`.
//
// An empty `zone_host_inbound` admits every host-bound packet: every zone id
// misses the table, so every lookup takes the `None => true` arm. That is the
// hazard #6873 describes, and it is real — this cell demonstrates it rather
// than assuming it.
//
// It exists because the companion cell asserts an ABSENCE (no worker thread is
// ever live while the table is empty), and an absence assertion is only worth
// as much as the demonstrated ability of that state to cause harm. Without
// this cell, `no_snapshot_reconcile_leaves_no_reader_for_the_empty_table_6873`
// would be guarding against a danger nobody had shown exists.
//
// Driven through `host_inbound_admits_iface` — the entry point the
// local-delivery poll path actually calls (`poll_stages.rs`) — not the
// zone-only primitive, so it cannot pass by binding a helper the production
// path does not reach.
#[test]
fn cold_forwarding_state_admits_every_host_inbound_service_6873() {
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    const GRE: u8 = 47;
    const IFINDEX: i32 = 10;
    const ZONE: u16 = 7;

    // A cold state: exactly what `ForwardingState::default()` produces before
    // any snapshot is applied, and what `stop_inner` resets to on teardown.
    let cold = ForwardingState::default();
    assert!(
        cold.zone_host_inbound.is_empty() && cold.ifindex_host_inbound.is_empty(),
        "fixture broken: a cold ForwardingState must carry NO host-inbound entries — \
         this cell is about the empty table, so a populated one would prove nothing"
    );

    // Every one of these is admitted, on a zone that admits nothing when the
    // table is populated. None of them is ICMP, so none can reach admit via
    // the #3171/#3201 global error/ND accept — the admit here is the
    // `None => true` arm and nothing else.
    for (proto, port, v6, what) in [
        (TCP, 22u16, false, "ssh"),
        (TCP, 443, false, "https"),
        (UDP, 53, true, "dns over v6"),
        (GRE, 0, false, "raw GRE"),
    ] {
        assert!(
            host_inbound_admits_iface(&cold, IFINDEX, ZONE, proto, port, v6, 0),
            "a cold (empty) forwarding state admits {what} — this is the fail-open \
             #6873 is about, and it is why nothing may observe this state"
        );
    }

    // THE CONTROL. The same packets on the same zone id are DENIED once the
    // zone is in the table. Without this, the loop above would pass equally
    // against a build that admitted everything unconditionally, and would say
    // nothing about emptiness being the cause.
    let mut warm = ForwardingState::default();
    warm.zone_host_inbound
        .insert(ZONE, zone_host_inbound_from_tokens(&[], &[]));
    for (proto, port, v6, what) in [
        (TCP, 22u16, false, "ssh"),
        (TCP, 443, false, "https"),
        (UDP, 53, true, "dns over v6"),
        (GRE, 0, false, "raw GRE"),
    ] {
        assert!(
            !host_inbound_admits_iface(&warm, IFINDEX, ZONE, proto, port, v6, 0),
            "with the zone PRESENT and admitting nothing, {what} must be denied — \
             it is the table being EMPTY that admits, not the admit path being open"
        );
    }
}

// #11571: catalog destinations require the exact protocol token, family,
// group, and transport tuple. OSPFv2/v3 both use IP protocol 89, so a
// transport-only admit would confuse family-specific groups and let an OSPF
// zone receive traffic for another routing protocol's multicast destination.
#[test]
fn ospf_multicast_is_scoped_to_exact_group_family_and_token_11571() {
    const ZONE: u16 = 51;
    let mut v4 = ForwardingState::default();
    v4.zone_host_inbound.insert(
        ZONE,
        zone_host_inbound_from_tokens(&[], &["ospf".to_string()]),
    );
    assert!(
        host_inbound_admits_for_destination(
            &v4,
            ZONE,
            89,
            0,
            false,
            0,
            "224.0.0.5".parse().unwrap(),
        ),
        "OSPFv2 on AllSPFRouters must be admitted by protocols ospf",
    );
    assert!(
        host_inbound_admits_for_destination(
            &v4,
            ZONE,
            89,
            0,
            false,
            0,
            "224.0.0.6".parse().unwrap(),
        ),
        "OSPFv2 on AllDRouters must be admitted by protocols ospf",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &v4,
            ZONE,
            89,
            0,
            false,
            0,
            "224.0.0.9".parse().unwrap(),
        ),
        "the shared protocol number must not admit the RIP multicast group",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &v4,
            ZONE,
            112,
            0,
            false,
            0,
            "224.0.0.5".parse().unwrap(),
        ),
        "OSPF groups must reject packets with the wrong IP protocol",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &v4,
            ZONE,
            89,
            0,
            true,
            0,
            "224.0.0.5".parse().unwrap(),
        ),
        "a catalog destination with a mismatched family marker must fail closed",
    );
    assert!(
        host_inbound_admits_for_destination(
            &v4,
            ZONE,
            89,
            0,
            false,
            0,
            "192.0.2.5".parse().unwrap(),
        ),
        "non-catalog OSPF destinations retain the existing protocol-token behavior",
    );

    let mut v6 = ForwardingState::default();
    v6.zone_host_inbound.insert(
        ZONE,
        zone_host_inbound_from_tokens(&[], &["ospf3".to_string()]),
    );
    assert!(
        host_inbound_admits_for_destination(
            &v6,
            ZONE,
            89,
            0,
            true,
            0,
            "ff02::5".parse().unwrap(),
        ),
        "OSPFv3 on AllSPFRouters must be admitted by protocols ospf3",
    );
    assert!(
        host_inbound_admits_for_destination(
            &v6,
            ZONE,
            89,
            0,
            true,
            0,
            "ff02::6".parse().unwrap(),
        ),
        "OSPFv3 on AllDRouters must be admitted by protocols ospf3",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &v6,
            ZONE,
            89,
            0,
            true,
            0,
            "ff02::12".parse().unwrap(),
        ),
        "OSPFv3 token must not admit the VRRP multicast group",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &v6,
            ZONE,
            112,
            0,
            true,
            0,
            "ff02::5".parse().unwrap(),
        ),
        "OSPFv3 groups must reject packets with the wrong IP protocol",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &v6,
            ZONE,
            89,
            0,
            true,
            0,
            "224.0.0.5".parse().unwrap(),
        ),
        "protocols ospf3 must not admit an IPv4 OSPF group",
    );
}

// #11571: VRRP has exact family-specific groups, and an interface-level
// effective set replaces (rather than unions with) its zone's protocol tokens.
#[test]
fn vrrp_multicast_is_dual_family_default_deny_and_override_scoped_11571() {
    const ZONE: u16 = 52;
    const OVERRIDE_IFINDEX: i32 = 520;
    let mut state = ForwardingState::default();
    state.zone_host_inbound.insert(
        ZONE,
        zone_host_inbound_from_tokens(&[], &["VRRP".to_string()]),
    );
    assert!(
        host_inbound_admits_for_destination(
            &state,
            ZONE,
            112,
            0,
            false,
            0,
            "224.0.0.18".parse().unwrap(),
        ),
        "VRRPv4 must admit its 224.0.0.18 group",
    );
    assert!(
        host_inbound_admits_for_destination(
            &state,
            ZONE,
            112,
            0,
            true,
            0,
            "ff02::12".parse().unwrap(),
        ),
        "VRRPv6 must admit its ff02::12 group",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &state,
            ZONE,
            112,
            0,
            false,
            0,
            "224.0.0.5".parse().unwrap(),
        ),
        "VRRP token must not admit the OSPFv2 group",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &state,
            ZONE,
            112,
            0,
            true,
            0,
            "ff02::5".parse().unwrap(),
        ),
        "VRRP token must not admit the OSPFv3 group",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &state,
            ZONE,
            89,
            0,
            false,
            0,
            "224.0.0.18".parse().unwrap(),
        ),
        "VRRP group must reject OSPF's protocol number",
    );

    let empty_zone = zone_host_inbound_from_tokens(&[], &[]);
    let mut closed = ForwardingState::default();
    closed.zone_host_inbound.insert(ZONE, empty_zone);
    assert!(
        !host_inbound_admits_for_destination(
            &closed,
            ZONE,
            112,
            0,
            false,
            0,
            "224.0.0.18".parse().unwrap(),
        ),
        "an empty configured zone must default-deny a catalog group",
    );
    assert!(
        !host_inbound_admits_for_destination(
            &closed,
            0,
            112,
            0,
            true,
            0,
            "ff02::12".parse().unwrap(),
        ),
        "an absent/unzoned ingress must default-deny a catalog group",
    );

    // The interface's effective override is authoritative, not unioned with
    // the zone tokens. A different interface still uses the zone fallback.
    state.ifindex_host_inbound.insert(
        OVERRIDE_IFINDEX,
        zone_host_inbound_from_tokens(&[], &["ospf".to_string()]),
    );
    assert!(
        host_inbound_admits_iface_for_destination(
            &state,
            OVERRIDE_IFINDEX,
            ZONE,
            89,
            0,
            false,
            0,
            "224.0.0.5".parse().unwrap(),
        ),
        "an OSPF interface override must admit its exact group",
    );
    assert!(
        !host_inbound_admits_iface_for_destination(
            &state,
            OVERRIDE_IFINDEX,
            ZONE,
            112,
            0,
            false,
            0,
            "224.0.0.18".parse().unwrap(),
        ),
        "the OSPF override must replace the zone's VRRP token",
    );
    assert!(
        host_inbound_admits_iface_for_destination(
            &state,
            OVERRIDE_IFINDEX + 1,
            ZONE,
            112,
            0,
            false,
            0,
            "224.0.0.18".parse().unwrap(),
        ),
        "an interface without an override must retain zone VRRP admission",
    );

    let mut wildcard = ForwardingState::default();
    wildcard.zone_host_inbound.insert(
        ZONE,
        zone_host_inbound_from_tokens(&["any-service".to_string()], &[]),
    );
    assert!(
        host_inbound_admits_for_destination(
            &wildcard,
            ZONE,
            253,
            0,
            false,
            0,
            "224.0.0.18".parse().unwrap(),
        ),
        "the explicit any-service wildcard must retain its full-admit semantics",
    );
}
