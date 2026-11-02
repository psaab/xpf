// #18728: the Junos implicit final discard, measured on the Go builder wire.
//
// The Go snapshot builder (pkg/dataplane/userspace/filters.go,
// appendImplicitDiscard) ends every filter that has no terminal catch-all
// term with a synthetic, unconstrained, counted `implicit-discard` term. The
// helper compiles it like any authored final discard; this module proves the
// evaluators that matter actually discard with it, and that the paths that
// must NOT change (no filter bound, family mismatch, the #6835 routing-
// instance defer, catch-all filters) still accept.
//
// The snapshots are not transcribed: they are the JSON the Go builder emits,
// pinned in testdata/firewall_implicit_discard_18728.json by
// TestImplicitDiscardSnapshotFixtureFresh18728. A Go-side regression that
// stopped appending the term reds that Go cell (stale fixture) and, once the
// fixture is regenerated, the discard cells here.
//
// Loaded as a sibling submodule via `#[path]` from filter/mod.rs.

use super::*;
use crate::ip_proto::{PROTO_TCP, PROTO_UDP};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const WIRE: &str = include_str!("../../../testdata/firewall_implicit_discard_18728.json");

const IF_IN: i32 = 7; // input v4 allow-ssh-v4, input v6 allow-ssh-v6
const IF_OUT: i32 = 8; // output v4 allow-ssh-v4, output v6 allow-ssh-v6
const IF_RI: i32 = 9; // input v4 ri-steer (no v6 filter: family mismatch)
const IF_NONE: i32 = 10; // no filter bound
const IF_PERMIT: i32 = 11; // input v4 permit-explicit
const IF_MODIFIER: i32 = 12; // input v4 modifier-catch
const IF_RI_CATCH: i32 = 13; // input v4 ri-catch
const IF_COUNT_NEXT: i32 = 14; // input v4 count-next
const IF_EMPTY: i32 = 15; // input v4 empty
const IF_WEB_OUT: i32 = 16; // output v4 allow-web-v4 (pure accept, no count)

const SRC4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
const STEERED4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
const DST4: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
const SRC6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 10));
const DST6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 20));

fn go_filters() -> Vec<FirewallFilterSnapshot> {
    serde_json::from_str(WIRE).expect("Go-built filter snapshots decode")
}

fn iface(ifindex: i32) -> crate::InterfaceSnapshot {
    crate::InterfaceSnapshot {
        ifindex,
        ..Default::default()
    }
}

/// One FilterState binding the Go filters to interfaces and lo0. A fresh state
/// per cell keeps the counter assertions independent.
fn state() -> FilterState {
    let interfaces = vec![
        crate::InterfaceSnapshot {
            filter_input_v4: "allow-ssh-v4".into(),
            filter_input_v6: "allow-ssh-v6".into(),
            ..iface(IF_IN)
        },
        crate::InterfaceSnapshot {
            filter_output_v4: "allow-ssh-v4".into(),
            filter_output_v6: "allow-ssh-v6".into(),
            ..iface(IF_OUT)
        },
        crate::InterfaceSnapshot {
            filter_input_v4: "ri-steer".into(),
            ..iface(IF_RI)
        },
        iface(IF_NONE),
        crate::InterfaceSnapshot {
            filter_input_v4: "permit-explicit".into(),
            ..iface(IF_PERMIT)
        },
        crate::InterfaceSnapshot {
            filter_input_v4: "modifier-catch".into(),
            ..iface(IF_MODIFIER)
        },
        crate::InterfaceSnapshot {
            filter_input_v4: "ri-catch".into(),
            ..iface(IF_RI_CATCH)
        },
        crate::InterfaceSnapshot {
            filter_input_v4: "count-next".into(),
            ..iface(IF_COUNT_NEXT)
        },
        crate::InterfaceSnapshot {
            filter_input_v4: "empty".into(),
            ..iface(IF_EMPTY)
        },
        crate::InterfaceSnapshot {
            filter_output_v4: "allow-web-v4".into(),
            ..iface(IF_WEB_OUT)
        },
    ];
    parse_filter_state(
        &go_filters(),
        &[],
        &interfaces,
        "allow-ssh-v4",
        "allow-ssh-v6",
    )
    .expect("Go-built filter snapshots compile")
}

fn input(
    state: &FilterState,
    ifindex: i32,
    src: IpAddr,
    dst: IpAddr,
    proto: u8,
    dport: u16,
) -> FilterResult {
    evaluate_interface_filter_non_routing_counted(
        state,
        ifindex,
        src.is_ipv6(),
        src,
        dst,
        proto,
        49152,
        dport,
        0,
        TermMatchExtra::default(),
        100,
        NonRoutingCountPolicy::Always,
        None,
    )
}

/// `(packets, bytes)` of every term of `key`, in term order.
fn counters(state: &FilterState, key: &str) -> Vec<(u64, u64)> {
    crate::filter::flush_recorded_filter_counters();
    state.filters[key]
        .terms
        .iter()
        .map(|t| {
            (
                t.counter.packets.load(Ordering::Relaxed),
                t.counter.bytes.load(Ordering::Relaxed),
            )
        })
        .collect()
}

/// The fixture carries what the Go cells say it does: the synthetic term is
/// the last term of exactly the no-catch-all filters, named and counted.
#[test]
fn go_fixture_carries_the_synthetic_term_only_without_a_catch_all_18728() {
    let mut with = Vec::new();
    for snap in go_filters() {
        let last = snap.terms.last();
        let synthetic = last.is_some_and(|t| t.name == "implicit-discard");
        if synthetic {
            let t = last.unwrap();
            assert_eq!(
                t.action, "discard",
                "{}: synthetic term must discard",
                snap.name
            );
            assert_eq!(
                t.count, "implicit-discard",
                "{}: synthetic term must count",
                snap.name
            );
            assert!(
                !t.next_term && t.routing_instance.is_empty(),
                "{}: must terminate",
                snap.name
            );
            with.push(format!("{}:{}", snap.family, snap.name));
        }
    }
    with.sort();
    assert_eq!(
        with,
        vec![
            "inet6:allow-ssh-v6",
            "inet:allow-ssh-v4",
            "inet:allow-web-v4",
            "inet:count-next",
            "inet:empty",
            "inet:ri-steer",
        ]
    );
}

/// Input, IPv4 and IPv6: the authored accept still wins; everything else is
/// discarded by the implicit term and charged to ITS counter only.
#[test]
fn input_filter_discards_unmatched_v4_and_v6_18728() {
    for (src, dst, key) in [
        (SRC4, DST4, "inet:allow-ssh-v4"),
        (SRC6, DST6, "inet6:allow-ssh-v6"),
    ] {
        let st = state();
        assert_eq!(
            input(&st, IF_IN, src, dst, PROTO_TCP, 22).action,
            FilterAction::Accept,
            "{key}: ssh"
        );
        assert_eq!(
            input(&st, IF_IN, src, dst, PROTO_TCP, 443).action,
            FilterAction::Discard,
            "{key}: tcp/443"
        );
        assert_eq!(
            input(&st, IF_IN, src, dst, PROTO_UDP, 53).action,
            FilterAction::Discard,
            "{key}: udp/53"
        );
        assert_eq!(
            counters(&st, key),
            vec![(1, 100), (2, 200)],
            "{key}: ssh counted once, the two unmatched packets on implicit-discard"
        );
    }
}

/// Output, live TX selection (cos_classify) and the cached TX replay: both
/// legs discard what the output allowlist does not name.
#[test]
fn output_filter_discards_unmatched_on_live_and_cached_tx_18728() {
    let st = state();
    for (src, dst, v6) in [(SRC4, DST4, false), (SRC6, DST6, true)] {
        let live = |dport| {
            evaluate_interface_output_filter_tx_selection_counted(
                &st,
                IF_OUT,
                v6,
                src,
                dst,
                PROTO_TCP,
                49152,
                dport,
                0,
                TermMatchExtra::default(),
                100,
            )
            .action
        };
        assert_eq!(live(22), FilterAction::Accept, "v6={v6}: live ssh");
        assert_eq!(live(443), FilterAction::Discard, "v6={v6}: live tcp/443");
        let filter = interface_output_filter_needing_tx_eval(&st, IF_OUT, v6)
            .expect("an output filter ending in a counted discard needs TX evaluation");
        let cached = |dport| {
            evaluate_filter_ref_tx_selection_cached(filter, src, dst, PROTO_TCP, 49152, dport, 0)
                .action
        };
        assert_eq!(cached(22), FilterAction::Accept, "v6={v6}: cached ssh");
        assert_eq!(
            cached(443),
            FilterAction::Discard,
            "v6={v6}: cached tcp/443"
        );
    }
}

/// A pure-accept output allowlist (no count/log/class) needed no TX
/// evaluation before #18728, so its output binding never ran. With the
/// synthetic counted discard it must, or the output implicit discard is
/// dead code.
#[test]
fn pure_accept_output_allowlist_now_needs_tx_eval_18728() {
    let st = state();
    let filter = interface_output_filter_needing_tx_eval(&st, IF_WEB_OUT, false)
        .expect("allow-web-v4 must need TX evaluation once it ends in the implicit discard");
    assert_eq!(
        evaluate_filter_ref_tx_selection_cached(filter, SRC4, DST4, PROTO_TCP, 49152, 22, 0).action,
        FilterAction::Discard
    );
    assert_eq!(
        evaluate_filter_ref_tx_selection_cached(filter, SRC4, DST4, PROTO_TCP, 49152, 443, 0)
            .action,
        FilterAction::Accept
    );
}

/// lo0 host-bound: both the unmetered and the metered (Some(now)) walks.
#[test]
fn lo0_filter_discards_unmatched_v4_and_v6_18728() {
    let st = state();
    for (src, dst) in [(SRC4, DST4), (SRC6, DST6)] {
        let v6 = src.is_ipv6();
        let plain = |dport| {
            evaluate_lo0_filter(
                &st,
                v6,
                src,
                dst,
                PROTO_TCP,
                49152,
                dport,
                0,
                TermMatchExtra::default(),
            )
            .action
        };
        assert_eq!(plain(22), FilterAction::Accept, "v6={v6}: lo0 ssh");
        assert_eq!(plain(179), FilterAction::Discard, "v6={v6}: lo0 tcp/179");
        let metered = evaluate_lo0_filter_counted(
            &st,
            v6,
            src,
            dst,
            PROTO_UDP,
            49152,
            123,
            0,
            TermMatchExtra::default(),
            100,
            Some(1),
        );
        assert_eq!(
            metered.action,
            FilterAction::Discard,
            "v6={v6}: metered lo0 udp/123"
        );
    }
}

/// #7212: an established session whose input filter now ends in the implicit
/// discard is revoked like one hitting an authored static discard: the static
/// verdict is Discard and the deny is flow-invariant.
#[test]
fn implicit_discard_is_a_flow_invariant_static_deny_18728() {
    let st = state();
    let filter = &st.iface_filter_v4_fast[&IF_IN];
    let verdict = |dport| {
        filter_ref_static_verdict(
            filter,
            SRC4,
            DST4,
            PROTO_TCP,
            49152,
            dport,
            0,
            TermMatchExtra::default(),
        )
    };
    assert_eq!(verdict(22), FilterAction::Accept);
    assert_eq!(verdict(443), FilterAction::Discard);
    assert!(filter_ref_deny_is_flow_invariant(
        filter,
        SRC4,
        DST4,
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default()
    ));
    assert_eq!(
        counters(&st, "inet:allow-ssh-v4"),
        vec![(0, 0), (0, 0)],
        "the static verdict charges nothing (#7212)"
    );
}

/// #6835: a matched routing-instance term on the non-routing walk DEFERS
/// (Accept + deferred_at_routing_term) before reaching the implicit discard;
/// traffic outside its scope is discarded.
#[test]
fn routing_instance_defer_is_unchanged_and_unscoped_traffic_is_discarded_18728() {
    let st = state();
    let steered = input(&st, IF_RI, STEERED4, DST4, PROTO_TCP, 443);
    assert_eq!(steered.action, FilterAction::Accept);
    assert_eq!(
        steered.deferred_at_routing_term,
        Some(0),
        "the defer must still fire at the RI term"
    );
    let other = input(&st, IF_RI, SRC4, DST4, PROTO_TCP, 443);
    assert_eq!(other.action, FilterAction::Discard);
    assert_eq!(other.deferred_at_routing_term, None);
}

/// Paths #18728 must not change: no filter bound, a family with no filter on
/// the interface, an unknown key — all still the default Accept.
#[test]
fn no_filter_and_family_mismatch_defaults_unchanged_18728() {
    let st = state();
    assert_eq!(
        input(&st, IF_NONE, SRC4, DST4, PROTO_TCP, 443),
        FilterResult::default()
    );
    assert_eq!(
        input(&st, IF_NONE, SRC6, DST6, PROTO_TCP, 443),
        FilterResult::default()
    );
    // IF_RI binds only an inet filter; an IPv6 packet sees no filter.
    assert_eq!(
        input(&st, IF_RI, SRC6, DST6, PROTO_TCP, 443),
        FilterResult::default()
    );
    assert_eq!(
        evaluate_filter(
            &st,
            "inet:does-not-exist",
            SRC4,
            DST4,
            PROTO_TCP,
            49152,
            443,
            0,
            TermMatchExtra::default()
        ),
        FilterResult::default()
    );
    // No output filter on IF_IN: TX selection leaves it alone.
    assert!(interface_output_filter_needing_tx_eval(&st, IF_IN, false).is_none());
}

/// Filters with a terminal catch-all get no synthetic term, so unmatched
/// traffic is NOT discarded: explicit `then accept`, an unconstrained
/// modifier-only term (implicit accept, #14632), and an unconstrained
/// routing-instance term (defers on this walk).
#[test]
fn catch_all_filters_still_accept_unmatched_18728() {
    let st = state();
    for ifindex in [IF_PERMIT, IF_MODIFIER, IF_RI_CATCH] {
        assert_eq!(
            input(&st, ifindex, SRC4, DST4, PROTO_UDP, 5353).action,
            FilterAction::Accept,
            "ifindex {ifindex}"
        );
    }
}

/// `then { count; next term; }` falls through to the implicit discard: the
/// fall-through counter AND the implicit counter both move.
#[test]
fn count_next_term_falls_through_to_the_implicit_discard_18728() {
    let st = state();
    assert_eq!(
        input(&st, IF_COUNT_NEXT, SRC4, DST4, PROTO_TCP, 22).action,
        FilterAction::Discard
    );
    assert_eq!(counters(&st, "inet:count-next"), vec![(1, 100), (1, 100)]);
}

/// The Junos empty filter discards everything.
#[test]
fn empty_filter_discards_everything_18728() {
    let st = state();
    for (proto, dport) in [(PROTO_TCP, 22), (PROTO_UDP, 53)] {
        assert_eq!(
            input(&st, IF_EMPTY, SRC4, DST4, proto, dport).action,
            FilterAction::Discard
        );
    }
    assert_eq!(counters(&st, "inet:empty"), vec![(2, 200)]);
}
