use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::native_gre_snapshot;

/// #9941: a decapped inner packet addressed to an RE-local address, arriving on
/// an UNZONED and UNNUMBERED tunnel, must not reach host services.
///
/// `logical_ingress` resolves the tunnel's LOGICAL ifindex through
/// `ifindex_to_zone_id` with `unwrap_or_default()`, and an unzoned unit is never
/// inserted there (the insert is gated on `row_zone_id != 0`), so it resolves to
/// zone **0**. Zone 0 is not a deny sentinel on this path: `host_inbound_admits`
/// takes the `None => true` global-zone admit arm. The #5659 backstop that
/// covers an ADDRESSED unzoned interface does not fire here, because its scope
/// guard is `registered_local` — and its own comment says an "address-less
/// interface is not" an exposure. That is true for an ordinary interface and
/// FALSE for a tunnel: a decap re-ingress delivers to local addresses that
/// OTHER interfaces registered, so the tunnel never needs one of its own.
///
/// The positive control in the same run is the zoned tunnel, which must keep
/// being judged by its zone rather than denied wholesale.
fn gre_state(zone: &str, addressed: bool) -> ForwardingState {
    let mut snapshot = native_gre_snapshot(false);
    for iface in &mut snapshot.interfaces {
        if iface.tunnel {
            iface.zone = zone.to_string();
            if !addressed {
                iface.addresses.clear();
            }
        }
    }
    // The zone the tunnel names must exist, or the build refuses the snapshot.
    build_forwarding_state(&snapshot)
}

/// The tunnel unit's logical ifindex in `native_gre_snapshot`.
const GRE_LOGICAL_IFINDEX: i32 = 362;
const TCP: u8 = 6;

#[test]
fn unzoned_unnumbered_tunnel_decap_does_not_admit_host_services_9941() {
    let state = gre_state("", false);

    // Premise 1: the unzoned unit really is absent from the zone map, so
    // logical_ingress resolves it to zone 0.
    assert!(
        !state.ifindex_to_zone_id.contains_key(&GRE_LOGICAL_IFINDEX),
        "premise: an unzoned tunnel unit must be absent from ifindex_to_zone_id",
    );
    let resolved_zone = state
        .ifindex_to_zone_id
        .get(&GRE_LOGICAL_IFINDEX)
        .copied()
        .unwrap_or_default();
    assert_eq!(resolved_zone, 0, "premise: it resolves to zone 0");

    // The defect: SSH to a firewall-local address, decapped from this tunnel.
    assert!(
        !host_inbound_admits_iface(&state, GRE_LOGICAL_IFINDEX, resolved_zone, TCP, 22, false, 0),
        "#9941: a decapped inner packet from an UNZONED, UNNUMBERED tunnel was admitted to ssh \
         (tcp/22) on a firewall-local address. Zone 0 is not a deny sentinel on the host-inbound \
         path, and the #5659 backstop does not cover an address-less ingress — but a tunnel \
         delivers to local addresses that OTHER interfaces registered, so it is an exposure \
         without being addressed itself",
    );
    assert!(
        !host_inbound_admits_iface(&state, GRE_LOGICAL_IFINDEX, resolved_zone, TCP, 830, false, 0),
        "#9941: NETCONF (tcp/830) likewise",
    );

    // Control, in the SAME run: ICMP error / PMTUD stays globally admitted, so
    // the fix cannot have worked by denying everything.
    assert!(
        host_inbound_admits_iface(&state, GRE_LOGICAL_IFINDEX, resolved_zone, 1, 0, false, 3),
        "control: ICMP destination-unreachable must stay admitted (#3171 global accept)",
    );
}

#[test]
fn a_zoned_tunnel_is_still_judged_by_its_zone_9941() {
    // POSITIVE CONTROL for the fix: the zoned tunnel keeps its zone identity and
    // is adjudicated by the zone set, not denied wholesale.
    let state = gre_state("sfmix", true);
    assert!(
        state.ifindex_to_zone_id.contains_key(&GRE_LOGICAL_IFINDEX),
        "control: a ZONED tunnel unit must carry a zone id",
    );
    let zone = state.ifindex_to_zone_id[&GRE_LOGICAL_IFINDEX];
    assert_ne!(zone, 0, "control: the zoned tunnel must not resolve to 0");
    // The fixture's zone declares no host-inbound tokens, so the #3405
    // default-deny governs — the point is that it is the ZONE deciding, and the
    // interface carries no blanket deny sentinel of its own.
    assert!(
        !state.ifindex_host_inbound.contains_key(&GRE_LOGICAL_IFINDEX),
        "control: a zoned tunnel must NOT get an interface-keyed deny sentinel — its zone decides",
    );
}
