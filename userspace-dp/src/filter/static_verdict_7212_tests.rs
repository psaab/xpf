// #7212: the SIDE-EFFECT-FREE static input-filter verdict
// (`NonRoutingCountPolicy::Never` / `filter_ref_static_verdict`).
//
// The established-session-hit revalidation re-derives an ALREADY-ADMITTED
// session's input-filter verdict once per config generation. That packet is not
// a new arrival at the filter, so the re-derivation must charge nothing: a
// counting re-derivation would inflate every matched `then count` term by one
// packet per PERMITTED session per commit, which is the common case and would
// be silent.
//
// Loaded as a sibling submodule via `#[path]` from filter/mod.rs.

use super::*;
use crate::ip_proto::PROTO_TCP;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn state_with(filters: &[FirewallFilterSnapshot], ifindex: i32, v6: bool) -> FilterState {
    let name = filters[0].name.clone();
    let iface = if v6 {
        crate::InterfaceSnapshot {
            ifindex,
            filter_input_v6: name,
            ..Default::default()
        }
    } else {
        crate::InterfaceSnapshot {
            ifindex,
            filter_input_v4: name,
            ..Default::default()
        }
    };
    parse_filter_state(filters, &[], &[iface], "", "").expect("filter state compiles")
}

fn term(name: &str, action: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        name: name.into(),
        action: action.into(),
        syslog: false,
        reject_message_type: String::new(),
        ..Default::default()
    }
}

fn counted_term(name: &str, action: &str, counter: &str) -> FirewallTermSnapshot {
    FirewallTermSnapshot {
        count: counter.into(),
        ..term(name, action)
    }
}

/// Every counter on `filter`, in term order, as `(packets, bytes)`.
fn counters(state: &FilterState, key: &str) -> Vec<(u64, u64)> {
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

const SRC4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 50));
const DST4: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

/// The filter population the equivalence + suppression cells sweep. Each entry
/// exercises a DIFFERENT exit of the walk, because `Never` has to be silent on
/// all of them — an equivalence proved on the Accept exit alone would say
/// nothing about the terminal-DENY replay arm, which is the one #7212 actually
/// takes when it revokes.
fn walk_shapes() -> Vec<(&'static str, Vec<FirewallTermSnapshot>)> {
    vec![
        // Implicit-Accept exit: nothing matches.
        (
            "no-match",
            vec![FirewallTermSnapshot {
                destination_ports: vec!["8443".into()],
                ..counted_term("other", "discard", "c-other")
            }],
        ),
        // Terminal-ACCEPT exit on a counted term.
        (
            "terminal-accept",
            vec![counted_term("permit-web", "accept", "c-permit")],
        ),
        // Terminal-DISCARD exit on a counted term — the replay arm.
        (
            "terminal-discard",
            vec![counted_term("deny-web", "discard", "c-deny")],
        ),
        // Terminal-REJECT exit.
        (
            "terminal-reject",
            vec![counted_term("reject-web", "reject", "c-reject")],
        ),
        // A `then { count; next term; }` fall-through AHEAD of a terminal
        // discard. Under `Always` both counters move; under
        // `OnlyTerminalNonAccept` the replay walks both. `Never` must move
        // neither, and this is the shape where a replay leak is visible as a
        // count on a term the terminal exit did not itself match.
        (
            "fallthrough-then-discard",
            vec![
                // #5142/#2544: a fall-through term is one with an EMPTY
                // action. A `next_term` bit on a term that carries a real
                // terminating action is a contradiction the compiler resolves
                // in favour of the action, so `action: "accept", next_term:
                // true` would TERMINATE and the deny below would be
                // unreachable — the fixture would then prove nothing about the
                // replay arm.
                counted_term("mark", "", "c-mark"),
                counted_term("deny", "discard", "c-deny2"),
            ],
        ),
        // A matched routing-instance term: the non-routing walk DEFERS and
        // returns the default Accept without counting on any policy.
        (
            "routing-instance-defer",
            vec![FirewallTermSnapshot {
                routing_instance: "blue".into(),
                ..counted_term("pbr", "accept", "c-pbr")
            }],
        ),
        // `except` inversion — an address the term excludes, so the deny does
        // NOT apply and the walk falls to the implicit Accept.
        (
            "source-except-misses",
            vec![counted_term("deny-except", "discard", "c-except")],
        ),
    ]
}

fn shape_state(name: &str, terms: Vec<FirewallTermSnapshot>) -> FilterState {
    let mut terms = terms;
    if name == "source-except-misses" {
        // `from source-address 10.0.1.50/32 except` — the address the packet
        // HAS is the one excluded, so the deny term does not match it and the
        // walk falls through to the implicit Accept.
        terms[0].source_addresses = vec!["10.0.1.50/32".into()];
        terms[0].source_except = true;
    }
    state_with(
        &[FirewallFilterSnapshot {
            name: "edge-in".into(),
            family: "inet".into(),
            terms,
        }],
        7,
        false,
    )
}

/// `Never` returns EXACTLY the action `Always` returns, on every exit of the
/// walk. It is the same walk with counting suppressed, so this is a fact rather
/// than a coincidence — but suppressing the count on the wrong arm (returning
/// the default `FilterResult` early, say) would change the action too, and this
/// is the cell that would red.
#[test]
fn static_verdict_agrees_with_the_counted_walk_on_every_exit_7212() {
    for (name, terms) in walk_shapes() {
        let always_state = shape_state(name, terms.clone());
        let never_state = shape_state(name, terms);
        let always = evaluate_interface_filter_non_routing_counted(
            &always_state,
            7,
            false,
            SRC4,
            DST4,
            PROTO_TCP,
            49152,
            443,
            0,
            TermMatchExtra::default(),
            1500,
            NonRoutingCountPolicy::Always,
            None,
        )
        .action;
        let never = filter_ref_static_verdict(
            &never_state.iface_filter_v4_fast[&7],
            SRC4,
            DST4,
            PROTO_TCP,
            49152,
            443,
            0,
            TermMatchExtra::default(),
        );
        assert_eq!(never, always, "shape {name}: static verdict must equal the counted walk's action");
    }
}

/// The point of the policy. `Always` moves counters; `Never` moves NONE — on
/// every exit, including the terminal-DENY exit whose replay arm is a separate
/// code path from the in-walk count.
///
/// The `Always` half is not decoration: without it a shape whose terms simply
/// never match would report "Never counted nothing" for the wrong reason, and
/// the whole table would pass vacuously. Each row asserts BOTH that the counted
/// walk moved something and that the uncounted walk did not.
#[test]
fn static_verdict_charges_no_counter_on_any_exit_7212() {
    let mut shapes_that_counted = 0usize;
    for (name, terms) in walk_shapes() {
        let always_state = shape_state(name, terms.clone());
        let never_state = shape_state(name, terms);
        crate::filter::flush_recorded_filter_counters();
        crate::policy::flush_recorded_policy_hit_counters();
        let before = counters(&never_state, "inet:edge-in");

        let _ = evaluate_interface_filter_non_routing_counted(
            &always_state,
            7,
            false,
            SRC4,
            DST4,
            PROTO_TCP,
            49152,
            443,
            0,
            TermMatchExtra::default(),
            1500,
            NonRoutingCountPolicy::Always,
            None,
        );
        let _ = filter_ref_static_verdict(
            &never_state.iface_filter_v4_fast[&7],
            SRC4,
            DST4,
            PROTO_TCP,
            49152,
            443,
            0,
            TermMatchExtra::default(),
        );

        crate::filter::flush_recorded_filter_counters();
        crate::policy::flush_recorded_policy_hit_counters();
        let always_after = counters(&always_state, "inet:edge-in");
        crate::filter::flush_recorded_filter_counters();
        crate::policy::flush_recorded_policy_hit_counters();
        let never_after = counters(&never_state, "inet:edge-in");
        assert_eq!(
            never_after, before,
            "shape {name}: the static verdict must charge no counter"
        );
        if always_after.iter().any(|(p, _)| *p > 0) {
            shapes_that_counted += 1;
        }
    }
    // Three shapes have no counting exit BY CONSTRUCTION and must not be read as
    // evidence: `no-match` matches nothing, `routing-instance-defer` returns
    // before the count, and `source-except-misses` is excluded by its own
    // `except`. The other four DO count under `Always`, which is what makes
    // their `Never` rows meaningful.
    assert_eq!(
        shapes_that_counted, 4,
        "the counted walk must actually move counters on the shapes whose \
         Never rows are supposed to prove suppression"
    );
    // #14656: counters are coalesced per-thread in every build; flush before asserting.
}

/// The specific mutation the `counting()` refactor guards. The replay arm used
/// to be gated on `!always_count`, which a third variant inherits — so a
/// `Never` walk landing on a terminal `discard` would have REPLAYED every
/// matched term's counter, on exactly the exit #7212 takes to revoke a session.
/// This is the fall-through shape, where the replay is visible on a term the
/// terminal exit did not itself match.
#[test]
fn static_verdict_does_not_replay_counters_on_the_terminal_deny_exit_7212() {
    let state = shape_state(
        "fallthrough-then-discard",
        vec![
            counted_term("mark", "", "c-mark"),
            counted_term("deny", "discard", "c-deny2"),
        ],
    );
    let verdict = filter_ref_static_verdict(
        &state.iface_filter_v4_fast[&7],
        SRC4,
        DST4,
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(
        verdict,
        FilterAction::Discard,
        "the fixture must actually reach the terminal-deny exit, or the replay \
         arm is never entered and this cell proves nothing"
    );
    assert_eq!(
        counters(&state, "inet:edge-in"),
        vec![(0, 0), (0, 0)],
        "neither the fall-through nor the terminal term may be replayed"
    );
}

/// `OnlyTerminalNonAccept` still replays on the terminal-deny exit. Without
/// this, deleting the replay arm outright would leave the `Never` cells above
/// green and silently zero the #2620 counters.
#[test]
fn only_terminal_non_accept_still_replays_after_the_never_split_7212() {
    let state = shape_state(
        "fallthrough-then-discard",
        vec![
            counted_term("mark", "", "c-mark"),
            counted_term("deny", "discard", "c-deny2"),
        ],
    );
    let result = evaluate_interface_filter_non_routing_counted(
        &state,
        7,
        false,
        SRC4,
        DST4,
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
        1500,
        NonRoutingCountPolicy::OnlyTerminalNonAccept,
        None,
    );
    assert_eq!(result.action, FilterAction::Discard);
    assert_eq!(
        counters(&state, "inet:edge-in"),
        vec![(1, 1500), (1, 1500)],
        "#2620: the terminal-deny exit is the sole counter and must replay both \
         matched terms"
    );
}

/// v6 parity — the walk has separate v4 and v6 leaves and the `Never` guard had
/// to be applied to both. A v4-only cell would leave the v6 leaf free to keep
/// counting.
#[test]
fn static_verdict_charges_no_counter_on_the_v6_leaf_7212() {
    let state = state_with(
        &[FirewallFilterSnapshot {
            name: "edge-in6".into(),
            family: "inet6".into(),
            terms: vec![
                counted_term("mark", "", "c-mark6"),
                counted_term("deny", "discard", "c-deny6"),
            ],
        }],
        9,
        true,
    );
    let src = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0x50));
    let dst = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0x20));
    let verdict = filter_ref_static_verdict(
        &state.iface_filter_v6_fast[&9],
        src,
        dst,
        PROTO_TCP,
        49152,
        443,
        0,
        TermMatchExtra::default(),
    );
    assert_eq!(verdict, FilterAction::Discard);
    assert_eq!(counters(&state, "inet6:edge-in6"), vec![(0, 0), (0, 0)]);
}

/// The `counting()` classification itself, so a future variant cannot silently
/// inherit a behaviour. This is the fail-on-revert pin for the exhaustive
/// `match`: flipping any cell reds here.
#[test]
fn non_routing_count_policy_classification_7212() {
    assert_eq!(NonRoutingCountPolicy::Always.counting(), (true, false));
    assert_eq!(
        NonRoutingCountPolicy::OnlyTerminalNonAccept.counting(),
        (false, true)
    );
    assert_eq!(NonRoutingCountPolicy::Never.counting(), (false, false));
}
