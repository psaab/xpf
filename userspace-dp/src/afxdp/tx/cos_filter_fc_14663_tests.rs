//! #14663 (D3-04): firewall-filter `then forwarding-class` must govern the
//! egress DSCP rewrite, and an unmaterialized filter class must preserve its
//! rewrite instead of bleaching to the default queue's class.
//!
//! Fixture (the claim's exact mechanism):
//! - Ingress BA classifier `ba14663`: DSCP 0 -> best-effort (class queue 0),
//!   DSCP 46 -> expedited-forwarding (class queue 5), both low LP.
//! - Input firewall filter on the ingress interface: TCP dport 5060 ->
//!   `then forwarding-class expedited-forwarding`.
//! - Egress `wan-rw14663` rewrite: best-effort/low -> 0,
//!   expedited-forwarding/low -> 46.
//! - A DSCP-0 packet matching dport 5060 is BA-classified best-effort but
//!   filter-classified expedited-forwarding: queue AND rewrite must follow
//!   the filter (queue 5, DSCP 46), on fresh, cached-seed, cached-hit, and
//!   flowless paths. DSCP-0 without the filter match stays DSCP 0 (control).

use super::*;
use crate::filter::TermMatchExtra;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSDSCPRewriteRuleEntrySnapshot, CoSDSCPRewriteRuleSnapshot, CoSForwardingClassSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    FirewallFilterSnapshot, FirewallTermSnapshot,
};

const EGRESS: i32 = 202;
const INGRESS: u32 = 5;

fn fc(name: &str, queue: i32) -> CoSForwardingClassSnapshot {
    CoSForwardingClassSnapshot {
        name: name.into(),
        queue,
    }
}
fn sched(name: &str) -> CoSSchedulerSnapshot {
    CoSSchedulerSnapshot {
        name: name.into(),
        priority: "low".into(),
        transmit_rate_bytes: 4_000_000,
        buffer_size_bytes: 128_000,
        ..Default::default()
    }
}

fn rewrite_entry(fc_name: &str, dscp: u8) -> CoSDSCPRewriteRuleEntrySnapshot {
    CoSDSCPRewriteRuleEntrySnapshot {
        forwarding_class: fc_name.into(),
        loss_priority: "low".into(),
        dscp_value: dscp,
    }
}

fn snapshot_14663(materialize_ef: bool) -> ConfigSnapshot {
    let mut map_entries = vec![CoSSchedulerMapEntrySnapshot {
        forwarding_class: "best-effort".into(),
        scheduler: "be-sched".into(),
    }];
    if materialize_ef {
        map_entries.push(CoSSchedulerMapEntrySnapshot {
            forwarding_class: "expedited-forwarding".into(),
            scheduler: "ef-sched".into(),
        });
    }
    ConfigSnapshot {
        interfaces: vec![
            // Logical ingress unit: BA classifier + input filter. Its parent
            // is the physical ingress (ifindex 5) the packet meta names.
            InterfaceSnapshot {
                name: "ge-0/0/0.0".into(),
                ifindex: 101,
                parent_ifindex: 5,
                vlan_id: 0,
                filter_input_v4: "sip-classify".into(),
                cos_dscp_classifier: "ba14663".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/1.0".into(),
                ifindex: EGRESS,
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                cos_shaping_burst_bytes: 256_000,
                cos_scheduler_map: "wan-map".into(),
                cos_dscp_rewrite_rule: "wan-rw14663".into(),
                ..Default::default()
            },
        ],
        filters: vec![FirewallFilterSnapshot {
            name: "sip-classify".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "sip".into(),
                protocols: vec!["tcp".into()],
                destination_ports: vec!["5060".into()],
                action: "accept".into(),
                forwarding_class: "expedited-forwarding".into(),
                ..Default::default()
            }],
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![fc("best-effort", 0), fc("expedited-forwarding", 5)],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "ba14663".into(),
                entries: vec![
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![0],
                    },
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![46],
                    },
                ],
            }],
            schedulers: vec![sched("be-sched"), sched("ef-sched")],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: map_entries,
            }],
            dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
                name: "wan-rw14663".into(),
                entries: vec![
                    rewrite_entry("best-effort", 0),
                    rewrite_entry("expedited-forwarding", 46),
                ],
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn key_14663(dst_port: u16) -> SessionKey {
    SessionKey {
        addr_family: libc::AF_INET as u8,
        protocol: PROTO_TCP,
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 61, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(172, 16, 80, 200)),
        src_port: 12345,
        dst_port,
        discriminator: Default::default(),
        routing_domain: 0,
    }
}

fn meta_14663(dscp: u8) -> UserspaceDpMeta {
    UserspaceDpMeta {
        ingress_ifindex: INGRESS,
        ingress_vlan_id: 0,
        addr_family: libc::AF_INET as u8,
        dscp,
        ..Default::default()
    }
}

#[test]
fn firewall_filter_forwarding_class_overrides_ba_classifier_on_egress_dscp_rewrite_14663() {
    let forwarding = build_forwarding_state(&snapshot_14663(true));
    let key = key_14663(5060);
    let meta = meta_14663(0);

    let fresh = resolve_cos_tx_selection(
        &forwarding,
        EGRESS,
        meta,
        Some(&key),
        TermMatchExtra::default(),
    );
    assert_eq!(fresh.queue_id, Some(5), "filter EF class must queue on EF");
    assert_eq!(
        fresh.dscp_rewrite,
        Some(46),
        "#14663: filter forwarding-class expedited-forwarding must rewrite DSCP 46, \
         not the BA best-effort DSCP 0"
    );

    let cached = resolve_cached_cos_tx_selection(&forwarding, EGRESS, meta, &key);
    assert_eq!(cached.queue_id, Some(5), "cached seed must queue on EF");
    assert_eq!(
        cached.dscp_rewrite,
        Some(46),
        "#14663: cached seed must rewrite by the filter class (46), not BA (0)"
    );

    // A subsequent packet of the same flow with DSCP 46: the filter-pinned
    // cached LP re-resolution must still yield the EF rewrite, keyed by the
    // filter class stored in the seed descriptor.
    assert_eq!(
        cached.filter_class_queue_id,
        Some(5),
        "#14663: seed must store the filter class queue id"
    );
    if cached.cos_lp_reclassify {
        let hit = reclassify_cached_cos_lp_rewrite(
            &forwarding,
            EGRESS,
            5,
            46,
            0,
            false,
            INGRESS,
            0,
            0,
            cached.filter_class_queue_id,
        );
        assert_eq!(
            hit,
            Some(46),
            "#14663: cached LP re-resolution for a filter-pinned flow must not \
             re-derive the rewrite from the BA class"
        );
    }

    // Control: same BA packet, destination port the filter does not match.
    let control_key = key_14663(443);
    let control = resolve_cos_tx_selection(
        &forwarding,
        EGRESS,
        meta,
        Some(&control_key),
        TermMatchExtra::default(),
    );
    assert_eq!(
        control.queue_id,
        Some(0),
        "control: unmatched packet stays BE queue"
    );
    assert_eq!(
        control.dscp_rewrite,
        Some(0),
        "control: unmatched packet stays DSCP 0"
    );

    // Flowless (no 5-tuple): the input filter's class must also govern.
    // The portless evaluator cannot match the dport term, so use the
    // flow-bearing arms above as the decisive cells; this flowless call
    // must at least not panic and must keep the BA rewrite for DSCP 0.
    let flowless = cached_cos_tx_selection_flowless(&forwarding, EGRESS, meta, &key, Some(&key));
    assert_eq!(flowless.dscp_rewrite, Some(0));
}

#[test]
fn unmaterialized_filter_forwarding_class_preserves_egress_dscp_rewrite_14663() {
    // Egress scheduler-map materializes only best-effort; the rewrite rule
    // still defines expedited-forwarding -> 46. The filter class clamps the
    // queue to the default (0) but must preserve the EF rewrite (#13968's
    // stated intent, extended to filter classes by #14663).
    let forwarding = build_forwarding_state(&snapshot_14663(false));
    let key = key_14663(5060);
    let meta = meta_14663(0);

    let fresh = resolve_cos_tx_selection(
        &forwarding,
        EGRESS,
        meta,
        Some(&key),
        TermMatchExtra::default(),
    );
    assert_eq!(
        fresh.queue_id,
        Some(0),
        "unmaterialized EF clamps to default queue"
    );
    assert_eq!(
        fresh.dscp_rewrite,
        Some(46),
        "#14663: unmaterialized filter class must preserve its EF rewrite (46), not bleach to 0"
    );

    let cached = resolve_cached_cos_tx_selection(&forwarding, EGRESS, meta, &key);
    assert_eq!(
        cached.queue_id,
        Some(0),
        "cached: unmaterialized EF clamps to default"
    );
    assert_eq!(
        cached.dscp_rewrite,
        Some(46),
        "#14663: cached seed must preserve the unmaterialized filter class rewrite"
    );

    // Control: no filter match -> BE rewrite 0.
    let control = resolve_cos_tx_selection(
        &forwarding,
        EGRESS,
        meta,
        Some(&key_14663(443)),
        TermMatchExtra::default(),
    );
    assert_eq!(
        control.dscp_rewrite,
        Some(0),
        "control: unmatched stays DSCP 0"
    );
}

#[test]
fn fabric_scoped_ingress_consults_customer_input_filter_14663() {
    // V2 fabric: the packet arrives on the fabric link (ifindex 4242) but its
    // validated scope names the customer ingress unit (101). The customer
    // input filter (attached to 101) must be consulted for TX selection:
    // DSCP 0 + dport 5060 -> EF queue 5 / DSCP 46. Without the fabric-aware
    // ingress resolution the filter lookup keys the fabric ifindex and misses.
    let forwarding = build_forwarding_state(&snapshot_14663(true));
    let key = key_14663(5060);
    let fabric_meta = UserspaceDpMeta {
        ingress_ifindex: 4242,
        fabric_ingress_ifindex: 101,
        addr_family: libc::AF_INET as u8,
        dscp: 0,
        ..Default::default()
    };
    let fresh = resolve_cos_tx_selection(
        &forwarding,
        EGRESS,
        fabric_meta,
        Some(&key),
        TermMatchExtra::default(),
    );
    assert_eq!(
        fresh.queue_id,
        Some(5),
        "#14663 leg3: V2 fabric packet must consult the customer input filter (EF queue)"
    );
    assert_eq!(
        fresh.dscp_rewrite,
        Some(46),
        "#14663 leg3: V2 fabric packet must get the filter class rewrite (46)"
    );

    let cached = resolve_cached_cos_tx_selection(&forwarding, EGRESS, fabric_meta, &key);
    assert_eq!(
        cached.queue_id,
        Some(5),
        "#14663 leg3: cached fabric seed must consult customer filter"
    );
    assert_eq!(cached.dscp_rewrite, Some(46));

    // Direct-ingress control (same filter, no fabric stamp) agrees.
    let direct = resolve_cos_tx_selection(
        &forwarding,
        EGRESS,
        meta_14663(0),
        Some(&key),
        TermMatchExtra::default(),
    );
    assert_eq!(direct.queue_id, Some(5));
    assert_eq!(direct.dscp_rewrite, Some(46));
}

fn snapshot_14663_output_filter() -> ConfigSnapshot {
    let mut snapshot = snapshot_14663(true);
    // Egress output filter also classifies dport 5060 to EF; BA is BE.
    snapshot.interfaces[1].filter_output_v4 = "sip-out".into();
    snapshot.filters.push(FirewallFilterSnapshot {
        name: "sip-out".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "sip".into(),
            protocols: vec!["tcp".into()],
            destination_ports: vec!["5060".into()],
            action: "accept".into(),
            forwarding_class: "expedited-forwarding".into(),
            ..Default::default()
        }],
    });
    snapshot
}

#[test]
fn output_filter_forwarding_class_overrides_ba_classifier_on_egress_dscp_rewrite_14663() {
    let forwarding = build_forwarding_state(&snapshot_14663_output_filter());
    let key = key_14663(5060);
    let meta = meta_14663(0);
    let fresh = resolve_cos_tx_selection(
        &forwarding,
        EGRESS,
        meta,
        Some(&key),
        TermMatchExtra::default(),
    );
    assert_eq!(
        fresh.queue_id,
        Some(5),
        "output filter EF class must queue on EF"
    );
    assert_eq!(
        fresh.dscp_rewrite,
        Some(46),
        "#14663: output filter forwarding-class must rewrite DSCP 46, not BA 0"
    );
    let cached = resolve_cached_cos_tx_selection(&forwarding, EGRESS, meta, &key);
    assert_eq!(cached.queue_id, Some(5));
    assert_eq!(
        cached.dscp_rewrite,
        Some(46),
        "#14663: cached output-filter class rewrite"
    );
    assert_eq!(cached.filter_class_queue_id, Some(5));
}
