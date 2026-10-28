//! #17031: the consolidated admission gate cells.
//!
//! Before #17031 the #6458 V2 owner-RG gate plus the #15916 ambiguous-
//! stamp promotion were open-coded at every session-miss site, and the
//! NoRoute, zone-counter and flow-cache-seed copies never promoted an
//! ambiguous stamp at all. These cells pin the ONE rule in
//! `admission_zone_override` / `promoted_zone_override`, the shared
//! post-translation destination helpers, and — structurally — that no
//! production copy of the gate/promote chain survives outside
//! `transit_policy.rs` (plus the definitions in `forwarding::fabric`).

use super::*;
use crate::afxdp::forwarding_build::build_forwarding_state;
use crate::afxdp::test_fixtures::{nat_snapshot, nat_snapshot_with_fabric};
use crate::test_zone_ids::{TEST_LAN_ZONE_ID, TEST_WAN_ZONE_ID};
use std::collections::BTreeMap;

fn wan_egress_resolution() -> ForwardingResolution {
    // Egress 12 is reth0.80: zone `wan`, redundancy group 1 (fixture).
    ForwardingResolution {
        disposition: ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: 12,
        tx_ifindex: 12,
        tunnel_endpoint_id: 0,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
        source_ifindex: 0,
        route_mtu: 0,
        transport_route_mtu: 0,
    }
}

fn active_rg1(now_secs: u64) -> BTreeMap<i32, HAGroupRuntime> {
    BTreeMap::from([(
        1,
        HAGroupRuntime {
            active: true,
            watchdog_timestamp: now_secs,
            lease: HAGroupRuntime::active_lease_until(now_secs, now_secs),
        },
    )])
}

/// Table: (raw, ambiguous, rg1_active, expected).
/// FAIL-ON-REVERT: dropping the promotion (passing `raw` alone to the
/// owner-RG gate, the pre-#17031 NoRoute/counter/seed shape) reds the
/// two promoted rows; dropping the gate reds the inactive rows.
#[test]
fn admission_zone_override_is_the_one_from_zone_rule_17031() {
    let state = build_forwarding_state(&nat_snapshot_with_fabric());
    let now_ns = crate::afxdp::monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let resolution = wan_egress_resolution();
    let active = active_rg1(now_secs);
    let inactive: BTreeMap<i32, HAGroupRuntime> = BTreeMap::new();

    let cases: &[(Option<u32>, Option<u32>, bool, Option<u32>)] = &[
        // Proved punt, owner active -> honored.
        (Some(TEST_LAN_ZONE_ID), None, true, Some(TEST_LAN_ZONE_ID)),
        // Proved punt, owner inactive -> stripped (fabric zone governs).
        (Some(TEST_LAN_ZONE_ID), None, false, None),
        // Ambiguous claim, owner active -> PROMOTED (the #17031 fix for
        // NoRoute/counters/seed, which never promoted before).
        (None, Some(TEST_LAN_ZONE_ID), true, Some(TEST_LAN_ZONE_ID)),
        // Ambiguous claim, owner inactive -> stays withheld.
        (None, Some(TEST_LAN_ZONE_ID), false, None),
        // Raw wins over ambiguous when both are present.
        (
            Some(TEST_WAN_ZONE_ID),
            Some(TEST_LAN_ZONE_ID),
            true,
            Some(TEST_WAN_ZONE_ID),
        ),
        // No claim at all.
        (None, None, true, None),
    ];
    for (raw, ambiguous, rg_active, expected) in cases {
        let ha = if *rg_active { &active } else { &inactive };
        assert_eq!(
            admission_zone_override(&state, ha, now_secs, *raw, *ambiguous, resolution),
            *expected,
            "raw={raw:?} ambiguous={ambiguous:?} rg_active={rg_active}"
        );
        // The ungated half agrees whenever a claim exists and differs
        // exactly by the gate: promoted-or-raw, never gated away.
        if raw.is_some() || ambiguous.is_some() {
            assert_eq!(
                promoted_zone_override(&state, ha, now_secs, *raw, *ambiguous, resolution),
                raw.or(*ambiguous).filter(|_| {
                    // promote() itself is owner-gated, so an inactive
                    // owner yields no promoted value either.
                    *rg_active || raw.is_some()
                }),
                "promoted half: raw={raw:?} ambiguous={ambiguous:?} rg_active={rg_active}"
            );
        }
    }

    // Base resolution (egress 0 -> owner RG 0): neither claim survives,
    // even with RG 1 active — the fail-closed base-NoRoute shape.
    let base = ForwardingResolution {
        egress_ifindex: 0,
        tx_ifindex: 0,
        ..wan_egress_resolution()
    };
    assert_eq!(
        admission_zone_override(
            &state,
            &active,
            now_secs,
            None,
            Some(TEST_LAN_ZONE_ID),
            base
        ),
        None
    );
    // The judged from-zone for a promoted claim is the claimed zone:
    // this is the pair the counters and the seed must credit (#12865
    // parity — counter from-zone == judged from-zone).
    let (gated, from_zone, to_zone) = transit_zone_pair(
        &state,
        &active,
        now_secs,
        21, // fabric parent, carries no zone of its own
        None,
        Some(TEST_LAN_ZONE_ID),
        resolution,
    );
    assert_eq!(gated, Some(TEST_LAN_ZONE_ID));
    assert_eq!(from_zone, TEST_LAN_ZONE_ID);
    assert_eq!(to_zone, TEST_WAN_ZONE_ID);
}

/// The shared post-translation destination: NAT64 dest-only re-classify
/// plus the rewrite/wire collapse, in one place.
/// FAIL-ON-REVERT: judging the wire IPv6 destination (pre-#12906) reds
/// the NAT64 row; skipping the rewrite-port collapse reds the DNAT row.
#[test]
fn post_translation_policy_dst_is_shared_17031() {
    // NAT64 needs a configured Pref64 — use the fabric snapshot plus a
    // NAT64 rule (mirrors the #12906 NAT64 cell's fixture).
    let mut snap = nat_snapshot();
    snap.nat64_rules = vec![crate::NAT64RuleSnapshot {
        name: "nat64".to_string(),
        prefix: "64:ff9b::/96".to_string(),
        pool_addresses: vec!["198.51.100.1".to_string()],
        no_v6_frag_header: false,
        ..Default::default()
    }];
    let state = build_forwarding_state(&snap);
    let no_nat = crate::nat::NatDecision::default();
    let wire_v6: IpAddr = "64:ff9b::198.18.2.9".parse().expect("nat64 dst");
    let extracted: IpAddr = "198.18.2.9".parse().expect("extracted dst");

    // NAT64: dest-only re-classify extracts the IPv4 destination.
    let nat64_v4 = nat64_dest_only_v4(&state, &no_nat, wire_v6);
    assert_eq!(
        nat64_v4.map(IpAddr::V4),
        Some(extracted),
        "Pref64 destination must re-classify to its embedded IPv4 host"
    );
    assert_eq!(
        post_translation_policy_dst(nat64_v4, &no_nat, wire_v6, 443),
        (extracted, 443)
    );

    // A same-family rewrite suppresses the re-classify and wins.
    let dnat = crate::nat::NatDecision {
        rewrite_dst: Some("198.18.0.50".parse().expect("dnat dst")),
        rewrite_dst_port: Some(8443),
        ..Default::default()
    };
    assert_eq!(nat64_dest_only_v4(&state, &dnat, wire_v6), None);
    let wire_v4: IpAddr = "203.0.113.9".parse().expect("wire dst");
    assert_eq!(
        post_translation_policy_dst(None, &dnat, wire_v4, 443),
        ("198.18.0.50".parse::<IpAddr>().expect("dnat dst"), 8443)
    );

    // Untranslated: wire tuple verbatim; IPv4 never re-classifies.
    assert_eq!(nat64_dest_only_v4(&state, &no_nat, wire_v4), None);
    assert_eq!(
        post_translation_policy_dst(None, &no_nat, wire_v4, 443),
        (wire_v4, 443)
    );
}

/// Parity through the consolidated NoRoute adjudication: the SAME
/// ambiguous-stamp + DNAT fixture that the #12906 cells judge with a
/// proved stamp must judge identically when the stamp arrives as a
/// withheld ambiguous claim and the owner RG is active — and must NOT
/// judge on the claimed pair when the owner RG is inactive.
/// FAIL-ON-REVERT: removing the `ambiguous_zone` parameter (the
/// pre-#17031 caller passed the raw stamp alone) reds the active half.
#[test]
fn noroute_ambiguous_stamp_promotes_through_transit_policy_17031() {
    let mut snap = nat_snapshot_with_fabric();
    snap.default_policy = "permit".to_string();
    snap.policies = vec![crate::PolicyRuleSnapshot {
        name: "deny-translated-server".to_string(),
        policy_id: 4242,
        from_zone: "lan".to_string(),
        to_zone: "wan".to_string(),
        source_addresses: vec!["any".to_string()],
        destination_addresses: vec!["198.18.0.50/32".to_string()],
        applications: vec!["any".to_string()],
        application_terms: Vec::new(),
        action: "deny".to_string(),
        ..Default::default()
    }];
    let state = build_forwarding_state(&snap);
    let now_ns = crate::afxdp::monotonic_nanos();
    let now_secs = now_ns / 1_000_000_000;
    let src: IpAddr = "10.0.61.100".parse().expect("src");
    let dst: IpAddr = "203.0.113.9".parse().expect("dst");
    let flow = SessionFlow {
        src_ip: src,
        dst_ip: dst,
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: src,
            dst_ip: dst,
            src_port: 40000,
            dst_port: 443,
            discriminator: Default::default(),
            routing_domain: 0,
        },
    };
    let nat = crate::nat::NatDecision {
        rewrite_dst: Some("198.18.0.50".parse().expect("translated dst")),
        rewrite_dst_port: Some(8443),
        ..Default::default()
    };
    let resolution = ForwardingResolution {
        disposition: ForwardingDisposition::NoRoute,
        egress_ifindex: 12,
        tx_ifindex: 12,
        ..wan_egress_resolution()
    };

    // Owner RG active: the ambiguous claim promotes and the translated
    // deny lands on the claimed pair — identical to a proved stamp.
    let promoted = transit_policy_adjudication(
        &state,
        &active_rg1(now_secs),
        now_secs,
        21,
        None,
        Some(TEST_LAN_ZONE_ID),
        resolution,
        nat,
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert_eq!(promoted.gated_ingress_zone_override, Some(TEST_LAN_ZONE_ID));
    assert_eq!(promoted.from_zone_id, TEST_LAN_ZONE_ID);
    assert_eq!(promoted.to_zone_id, TEST_WAN_ZONE_ID);
    assert_eq!(
        promoted
            .denial
            .expect("promoted NoRoute must deny on the translated tuple")
            .policy_id,
        4242
    );

    // Owner RG inactive: the claim stays withheld, the fabric zone
    // governs, and the claimed pair's rule does NOT fire.
    let withheld = transit_policy_adjudication(
        &state,
        &BTreeMap::new(),
        now_secs,
        21,
        None,
        Some(TEST_LAN_ZONE_ID),
        resolution,
        nat,
        true,
        &flow,
        6,
        true,
        None,
        64,
        now_ns,
    );
    assert_eq!(withheld.gated_ingress_zone_override, None);
    assert_eq!(withheld.from_zone_id, 0);
    assert!(
        withheld.denial.is_none() || withheld.denial.as_ref().map(|d| d.policy_id) != Some(4242),
        "an unpromoted claim must not buy the claimed pair's verdict"
    );
}

/// Structural guard: the gate/promote chain has ONE production home.
/// Any new open-coded copy outside `transit_policy.rs` (the gate's
/// definition in `forwarding/fabric.rs` excepted) reds this cell —
/// that is the recurrence #17031 exists to prevent.
#[test]
fn gate_and_promotion_have_one_production_home_17031() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let poll_dir = manifest.join("src/afxdp/poll_descriptor");
    let mut gate_offenders = Vec::new();
    let mut promote_offenders = Vec::new();
    let mut stack = vec![poll_dir];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read poll_descriptor dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if name.contains("test") || name == "transit_policy.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("read source");
            if text.contains("gate_fabric_zone_override_on_owner_rg(") {
                gate_offenders.push(name.clone());
            }
            if text.contains("promote_ambiguous_fabric_zone(") {
                promote_offenders.push(name);
            }
        }
    }
    assert!(
        gate_offenders.is_empty(),
        "owner-RG gate called outside transit_policy.rs: {gate_offenders:?} \
         (#17031: route it through admission_zone_override)"
    );
    assert!(
        promote_offenders.is_empty(),
        "ambiguous promotion called outside transit_policy.rs: {promote_offenders:?} \
         (#17031: route it through admission_zone_override/promoted_zone_override)"
    );
}
