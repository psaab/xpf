//! #16055: PPTP data-channel resolve domain tests.
//!
//! The association table is domain-keyed. The production resolve used the
//! ingress-derived domain (fabric zone override only, no ambiguous zone),
//! while stage 9b immediately re-keys the resulting flow to the claimed
//! identity's domain (`ingress_zone_override.or(ambiguous_zone)`). On an
//! ambiguous fabric arrival those differ by construction: the claimed
//! zone has no `zone_routing_domain` row, so stage 9b keys the flow in
//! the per-zone quarantine band `AMBIGUOUS_FABRIC_DOMAIN_BASE | zone`,
//! while the pre-fix resolve looked the association up in the fabric
//! link's own domain (domain 0 here — the link is in no routing
//! instance). Consequences, both pinned below:
//!
//! - a same-call-ID association installed in the claimed (quarantine)
//!   domain was never found: the packet stayed flowless and no session
//!   was claimed in the domain it was re-keyed to;
//! - a same-call-ID association in the WRONG (ingress) domain WAS
//!   found and idle-refreshed (`resolve_and_touch`), so tenant B's
//!   traffic kept tenant A's association alive — the wrong-domain
//!   refresh the issue names.
//!
//! The fix derives the resolve domain from the same claimed identity
//! used for re-keying (`pptp_resolve_routing_domain`), and fails closed
//! to domain 0 on a fabric arrival with no claimed zone.
//!
//! Mutation discipline: reverting the helper's fabric arm to the pre-fix
//! expression (`ingress_zone_override` only, fabric-link fallthrough)
//! reds every cell in this file; the gre_discriminator domain-scoping
//! cell (#13681) stays green under that revert because it bypasses the
//! poll-loop derivation entirely.

use super::*;
use std::net::{IpAddr, Ipv4Addr};

const FABRIC_IFINDEX: i32 = 21;
const TENANT_ZONE: u32 = 7;
const CLAIMED_DOMAIN: u32 = crate::session::AMBIGUOUS_FABRIC_DOMAIN_BASE | TENANT_ZONE as u32;

fn peer_a() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}
fn peer_b() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
}

/// Fabric-link ingress (ifindex 21, in NO routing instance), claimed
/// zone 7 spanning instances so it has NO `zone_routing_domain` row —
/// the ambiguous shape stage 9b quarantines.
fn ambiguous_fabric_forwarding() -> ForwardingState {
    let mut forwarding = ForwardingState::default();
    forwarding.has_routing_domains = true;
    // Deliberately NO zone_routing_domain row for TENANT_ZONE and NO
    // ifindex_to_routing_domain row for the fabric link: the claimed
    // zone resolves to the quarantine band, the fabric link to 0.
    forwarding
}

/// Install the SAME endpoint pair + SAME call IDs in two domains:
/// the claimed (quarantine) domain and the wrong ingress (0) domain.
/// Returns (claimed_handle, wrong_handle, sessions).
fn install_same_call_id_across_domains() -> (u32, u32, crate::session::SessionTable) {
    let mut sessions = crate::session::SessionTable::new();
    let (a, b) = (peer_a(), peer_b());
    let claimed_call = crate::session::pptp::PptpCall::new_in_domain(CLAIMED_DOMAIN, a, 100, b, 200);
    let claimed_control =
        crate::session::pptp::ControlChannelId::new_in_domain(CLAIMED_DOMAIN, a, 49_152, b, 1723);
    let claimed_handle = sessions
        .pptp_mut()
        .install(claimed_call, claimed_control, 1_000)
        .expect("claimed-domain association installs");
    let wrong_call = crate::session::pptp::PptpCall::new_in_domain(0, a, 100, b, 200);
    let wrong_control =
        crate::session::pptp::ControlChannelId::new_in_domain(0, a, 49_152, b, 1723);
    let wrong_handle = sessions
        .pptp_mut()
        .install(wrong_call, wrong_control, 1_000)
        .expect("wrong-domain association installs");
    assert_ne!(claimed_handle, wrong_handle, "fixture: domains must yield distinct handles");
    (claimed_handle, wrong_handle, sessions)
}

/// A version-1 PPTP GRE frame A->B carrying B's call ID (200), shaped
/// like the gre_discriminator fixture so `pptp_data_session_flow_in_domain`
/// parses it identically.
fn pptp_frame_a_to_b() -> (Vec<u8>, UserspaceDpMeta) {
    let (src, dst) = ([10u8, 0, 0, 1], [10u8, 0, 0, 2]);
    let mut f = vec![0u8; 20];
    f[0] = 0x45;
    f[9] = crate::ip_proto::PROTO_GRE;
    f[12..16].copy_from_slice(&src);
    f[16..20].copy_from_slice(&dst);
    f.extend_from_slice(&(0x2000u16 | 0x0001).to_be_bytes()); // Key set, version 1
    f.extend_from_slice(&0x880Bu16.to_be_bytes()); // PPP
    f.extend_from_slice(&0x05DCu16.to_be_bytes()); // payload length
    f.extend_from_slice(&200u16.to_be_bytes()); // call ID allocated by B
    let total = f.len() as u16;
    f[2..4].copy_from_slice(&total.to_be_bytes());
    let mut meta = UserspaceDpMeta {
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_GRE,
        l3_offset: 0,
        l4_offset: 20,
        ..Default::default()
    };
    meta.flow_src_addr[..4].copy_from_slice(&src);
    meta.flow_dst_addr[..4].copy_from_slice(&dst);
    (f, meta)
}

/// The domain stage 9b will re-key this packet's flow to — the claimed
/// identity expression, spelled out so the test asserts resolve==rekey
/// rather than trusting either side alone.
fn stage9b_domain(forwarding: &ForwardingState) -> u32 {
    crate::afxdp::forwarding::ingress_routing_domain(
        forwarding,
        FABRIC_IFINDEX,
        0,
        Some(TENANT_ZONE),
    )
}

#[test]
fn pptp_resolve_domain_uses_claimed_ambiguous_zone_not_fabric_link_16055() {
    let forwarding = ambiguous_fabric_forwarding();
    assert_eq!(
        stage9b_domain(&forwarding),
        CLAIMED_DOMAIN,
        "fixture: claimed ambiguous zone must quarantine (no zone_routing_domain row)"
    );
    // Pre-fix expression, for contrast: fabric override only.
    let prefix_domain = crate::afxdp::forwarding::ingress_routing_domain(
        &forwarding,
        FABRIC_IFINDEX,
        0,
        None,
    );
    assert_eq!(prefix_domain, 0, "fixture: fabric link itself is in domain 0");
    assert_ne!(prefix_domain, CLAIMED_DOMAIN, "fixture: the two derivations must differ");

    let resolve_domain = pptp_resolve_routing_domain(
        &forwarding,
        FABRIC_IFINDEX,
        0,
        true,           // packet_fabric_ingress
        None,           // ingress_zone_override (ambiguous stamps carry none)
        Some(TENANT_ZONE), // ambiguous_zone: the claimed identity
        false,          // absent_fabric_ingress_suspect
    );
    assert_eq!(
        resolve_domain, CLAIMED_DOMAIN,
        "resolve must use the claimed ambiguous zone's domain — the same \
         domain stage 9b re-keys the flow to (#16055)"
    );
    assert_eq!(resolve_domain, stage9b_domain(&forwarding), "resolve domain must equal re-key domain");
}

#[test]
fn pptp_resolve_domain_validated_override_and_nonfabric_unchanged_16055() {
    let mut forwarding = ambiguous_fabric_forwarding();
    let tenant_domain = 42u32;
    forwarding.zone_routing_domain.insert(TENANT_ZONE, tenant_domain);
    forwarding.ifindex_to_routing_domain.insert(99, 5);
    forwarding.ingress_logical_ifindex.insert((99, 0), 99);

    // Validated fabric stamp: resolve in the zone's real domain.
    assert_eq!(
        pptp_resolve_routing_domain(&forwarding, FABRIC_IFINDEX, 0, true, Some(TENANT_ZONE), None, false),
        tenant_domain,
        "validated claimed zone must resolve in its mapped domain"
    );
    // Non-fabric arrival: physical ingress derivation, claimed zones ignored.
    assert_eq!(
        pptp_resolve_routing_domain(&forwarding, 99, 0, false, Some(TENANT_ZONE), Some(TENANT_ZONE), false),
        5,
        "non-fabric arrivals keep the ingress-interface domain"
    );
}

#[test]
fn pptp_resolve_domain_fails_closed_without_claimed_zone_16055() {
    let mut forwarding = ambiguous_fabric_forwarding();
    // Even if the fabric link WERE in a tenant domain, an unencoded
    // fabric arrival claims no identity and must not resolve there.
    forwarding.ifindex_to_routing_domain.insert(FABRIC_IFINDEX, 42);
    forwarding.ingress_logical_ifindex.insert((FABRIC_IFINDEX, 0), FABRIC_IFINDEX);
    assert_eq!(
        pptp_resolve_routing_domain(&forwarding, FABRIC_IFINDEX, 0, true, None, None, false),
        0,
        "fabric arrival with no claimed zone must fail closed to domain 0, \
         never the fabric link's own domain (#16055)"
    );
    // Suspect arm stays domain 0 regardless of any claimed zone.
    assert_eq!(
        pptp_resolve_routing_domain(&forwarding, FABRIC_IFINDEX, 0, true, Some(TENANT_ZONE), None, true),
        0,
        "absent-stamp suspect arrivals resolve in domain 0 (suspect arm owns re-keying)"
    );
    assert_eq!(
        pptp_resolve_routing_domain(&forwarding, FABRIC_IFINDEX, 0, false, None, None, true),
        0,
        "suspect gate precedes the non-fabric derivation too"
    );
}

/// THE decisive regression check from #16055: same PPTP call ID across
/// domains — association refresh lands in the correct (claimed) domain
/// and no cross-tenant session is claimed.
#[test]
fn pptp_same_call_id_across_domains_refreshes_only_claimed_domain_16055() {
    let forwarding = ambiguous_fabric_forwarding();
    let (claimed_handle, wrong_handle, mut sessions) = install_same_call_id_across_domains();
    let (frame, meta) = pptp_frame_a_to_b();

    let resolve_domain = pptp_resolve_routing_domain(
        &forwarding,
        FABRIC_IFINDEX,
        0,
        true,
        None,
        Some(TENANT_ZONE),
        false,
    );
    let flow = crate::afxdp::gre_discriminator::pptp_data_session_flow_in_domain(
        &frame,
        meta,
        &mut sessions,
        resolve_domain,
        2_000,
    )
    .expect("the claimed domain's association must resolve on a fabric arrival");
    assert_eq!(flow.forward_key.routing_domain, CLAIMED_DOMAIN);
    assert_eq!(
        flow.forward_key.discriminator,
        crate::session::TunnelDiscriminator::Pptp(claimed_handle),
        "must claim the claimed tenant's session, not the same-call-ID \
         association in the ingress domain"
    );
    assert_ne!(
        flow.forward_key.discriminator,
        crate::session::TunnelDiscriminator::Pptp(wrong_handle),
    );

    // Idle-refresh landed ONLY in the claimed domain: advance past the
    // idle timeout from install (1_000) but not from the resolve
    // (2_000). The claimed association survives; the wrong-domain one,
    // never refreshed, expires.
    let probe = 2_000 + crate::session::pptp::ASSOCIATION_IDLE_TIMEOUT_NS - 1;
    // At `probe`, claimed age = timeout-1 (alive), wrong age = timeout+999 (dead).
    let expired = sessions.pptp_mut().expire_idle(probe, crate::session::pptp::ASSOCIATION_IDLE_TIMEOUT_NS);
    assert_eq!(expired, 1, "exactly the un-refreshed wrong-domain association must expire");
    assert_eq!(
        sessions.pptp().resolve_in_domain(CLAIMED_DOMAIN, peer_b(), 200),
        Some(claimed_handle),
        "claimed-domain association refreshed by its own tenant's traffic"
    );
    assert_eq!(
        sessions.pptp().resolve_in_domain(0, peer_b(), 200),
        None,
        "wrong-domain association must NOT be refreshed by claimed-domain traffic"
    );
    let _ = wrong_handle;
}

/// Negative control for the fixture above: resolving in the pre-fix
/// (ingress) domain DOES claim and refresh the wrong tenant — proving
/// the fixture can distinguish the defect.
#[test]
fn pptp_same_call_id_prefix_domain_would_claim_wrong_tenant_16055() {
    let (_claimed_handle, wrong_handle, mut sessions) = install_same_call_id_across_domains();
    let (frame, meta) = pptp_frame_a_to_b();
    let flow = crate::afxdp::gre_discriminator::pptp_data_session_flow_in_domain(
        &frame,
        meta,
        &mut sessions,
        0, // pre-fix ingress-derived domain on this fixture
        2_000,
    )
    .expect("pre-fix domain resolves (to the wrong tenant)");
    assert_eq!(
        flow.forward_key.discriminator,
        crate::session::TunnelDiscriminator::Pptp(wrong_handle),
        "control: the ingress domain claims the wrong-domain association"
    );
}
