// Tests for afxdp/forwarding_build/. Moved from
// afxdp/forwarding_build_tests.rs to the directory-module
// colocated path in #1342 (split forwarding_build.rs by entity
// kind). Loaded as a sibling sub-module via `#[cfg(test)] mod
// tests;` in forwarding_build/mod.rs (no `#[path]` attribute).

use super::*;
use crate::filter::TermMatchExtra;
use crate::filter::evaluate_filter_ref_tx_selection_runtime_counted;
use crate::{
    ClassOfServiceSnapshot, CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot,
    CoSDSCPRewriteRuleEntrySnapshot, CoSDSCPRewriteRuleSnapshot, CoSForwardingClassSnapshot,
    CoSIEEE8021ClassifierEntrySnapshot, CoSIEEE8021ClassifierSnapshot,
    CoSINetPrecedenceClassifierEntrySnapshot, CoSINetPrecedenceClassifierSnapshot,
    CoSSchedulerMapEntrySnapshot, CoSSchedulerMapSnapshot, CoSSchedulerSnapshot,
    FirewallFilterSnapshot, FirewallTermSnapshot, ThreeColorPolicerSnapshot,
};
use std::net::{IpAddr, Ipv4Addr};

fn three_color_snapshot(burst: u64) -> ConfigSnapshot {
    ConfigSnapshot {
        filters: vec![FirewallFilterSnapshot {
            name: "policed".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "meter".into(),
                action: "accept".into(),
                policer: "stable-pol".into(),
                ..Default::default()
            }],
        }],
        three_color_policers: vec![ThreeColorPolicerSnapshot {
            name: "stable-pol".into(),
            mode: "single-rate".into(),
            color_blind: true,
            committed_rate_bytes_per_sec: 1,
            committed_burst_bytes: burst,
            peak_or_excess_burst_bytes: 50,
            then_action: "discard".into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn parse_syn_cookie_master_key_accepts_exact_hex_key() {
    assert_eq!(
        parse_syn_cookie_master_key("00112233445566778899aabbccddeeff"),
        Some([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    );
}

#[test]
fn parse_syn_cookie_master_key_rejects_malformed_keys() {
    for key in [
        "",
        "00112233445566778899aabbccddee",
        "00112233445566778899aabbccddeeff00",
        "00112233445566778899aabbccddeefg",
    ] {
        assert_eq!(
            parse_syn_cookie_master_key(key),
            None,
            "key {key:?} should fail closed"
        );
    }
}

// #3909: the SYN-cookie master key is `skip_serializing` (kept out of the
// world-readable state.json), but it is STILL delivered on the control socket
// via `apply_snapshot` and must reach the dataplane so source validation
// functions. This asserts that a snapshot carrying the key (the control-plane
// delivery path — i.e. the post-restart re-push) produces a live
// `syn_cookie_master_key` in the forwarding state. A valid key present here is
// what makes the SYN-cookie source-validation check work.
#[test]
fn syn_cookie_master_key_from_snapshot_reaches_forwarding_state() {
    let snapshot = ConfigSnapshot {
        syn_cookie_master_key: "00112233445566778899aabbccddeeff".into(),
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        state.syn_cookie_master_key.0,
        Some([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]),
        "control-plane-delivered key must reach the dataplane for source validation"
    );
}

// #4484 L-7: `ForwardingState` derives `Debug`; the SYN-cookie master key
// must never render in cleartext through it. The `SynCookieMasterKey`
// wrapper redacts in `Debug` (`Some(<redacted>)` / `None`). Fail-on-revert:
// drop the manual `Debug` impl (deriving `Debug` on the newtype) and the raw
// bytes reappear (`Some([171, 171, ...])`), so both asserts below FAIL.
#[test]
fn syn_cookie_master_key_debug_redacts_the_secret_in_forwarding_state() {
    let mut state = ForwardingState::default();
    state.syn_cookie_master_key = SynCookieMasterKey(Some([0xab; 16]));
    let rendered = format!("{state:?}");
    // The secret bytes never appear (0xab = 171 decimal in the derived form).
    assert!(
        !rendered.contains("171"),
        "raw SYN-cookie key byte leaked into Debug output: {rendered}"
    );
    // The field renders with the redaction marker instead.
    assert!(
        rendered.contains("syn_cookie_master_key: Some(<redacted>)"),
        "expected redacted marker, got: {rendered}"
    );
    // Guard: sibling fields still render (Debug is not wholesale suppressed).
    assert!(
        rendered.contains("local_v4"),
        "other fields must still render in Debug: {rendered}"
    );
    // A None key renders plainly (no phantom marker).
    let none = ForwardingState::default();
    assert!(
        format!("{none:?}").contains("syn_cookie_master_key: None"),
        "unset key must render as None"
    );
}

#[test]
fn forwarding_state_refresh_preserves_three_color_runtime_state() {
    let policy_counters = PolicyCounterStore::default();
    let snapshot = three_color_snapshot(100);
    let state = build_forwarding_state_with_policy_counters(&snapshot, &policy_counters);
    let refreshed = build_forwarding_state_with_policy_counters_and_previous(
        &snapshot,
        &policy_counters,
        &crate::nat::NatCounterStore::default(),
        Some(&state),
    )
    .expect("test snapshot must not produce integrity error");
    assert!(std::sync::Arc::ptr_eq(
        &state.filter_state.three_color_policers[0],
        &refreshed.filter_state.three_color_policers[0]
    ));

    let filter = state.filter_state.filters.get("inet:policed").unwrap();
    let first = evaluate_filter_ref_tx_selection_runtime_counted(
        filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        100,
        0,
    );
    assert!(!first.policer_drop);

    let refreshed_filter = refreshed.filter_state.filters.get("inet:policed").unwrap();
    let second = evaluate_filter_ref_tx_selection_runtime_counted(
        refreshed_filter,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        PROTO_UDP,
        12345,
        5000,
        0,
        TermMatchExtra::default(),
        51,
        0,
    );

    assert!(
        second.policer_drop,
        "production refresh must share runtime state during publication"
    );
    let status = refreshed.filter_state.three_color_policer_statuses();
    assert_eq!(status[0].green_packets, 1);
    assert_eq!(status[0].red_packets, 1);
    assert_eq!(status[0].drop_packets, 1);
}

#[test]
fn build_cos_state_translates_scheduler_map_entries() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "expedited-forwarding".into(),
                    queue: 1,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be-sched".into(),
                    transmit_rate_bytes: 3_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 128_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "ef-sched".into(),
                    transmit_rate_bytes: 7_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: true,
                    priority: "strict-high".into(),
                    buffer_size_bytes: 64_000,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "expedited-forwarding".into(),
                        scheduler: "ef-sched".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be-sched".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert_eq!(iface.shaping_rate_bytes, 10_000_000);
    assert_eq!(iface.burst_bytes, 256_000);
    assert_eq!(iface.default_queue, 0);
    assert_eq!(iface.queues.len(), 2);
    assert_eq!(iface.queues[0].queue_id, 0);
    assert_eq!(iface.queues[0].forwarding_class, "best-effort");
    assert_eq!(iface.queues[0].priority, 5);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 3_000_000);
    assert!(iface.queues[0].guarantee_enabled);
    assert!(!iface.queues[0].exact);
    assert_eq!(iface.queues[0].surplus_weight, 5);
    assert_eq!(iface.queues[0].buffer_bytes, 128_000);
    assert_eq!(iface.queues[1].queue_id, 1);
    assert_eq!(iface.queues[1].forwarding_class, "expedited-forwarding");
    assert_eq!(iface.queues[1].priority, 0);
    assert_eq!(iface.queues[1].transmit_rate_bytes, 7_000_000);
    assert!(iface.queues[1].guarantee_enabled);
    assert!(iface.queues[1].exact);
    assert_eq!(iface.queues[1].surplus_weight, 12);
    assert_eq!(iface.queues[1].buffer_bytes, 64_000);
}

#[test]
fn build_cos_state_resolves_percent_buffer_size_from_interface_burst_pool() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 3_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 10.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert_eq!(iface.burst_bytes, 256_000);
    assert_eq!(
        iface.queues[0].buffer_bytes, 25_600,
        "10% of the resolved interface CoS burst pool must not compile to zero"
    );

    let runtime = crate::afxdp::cos::builders::build_cos_interface_runtime(iface, 0);
    assert!(
        runtime.queues[0].config.buffer_bytes >= crate::afxdp::cos::COS_MIN_BURST_BYTES,
        "runtime queue buffer must retain a non-zero capacity after the queue floor"
    );
}

// #4228 Gap 2: a `transmit-rate percent <n>` scheduler resolves to an absolute
// byte/sec rate against the bound interface's shaping-rate — the SAME
// interface-shaping base family buffer-size percent uses. RED on revert: with
// the percent left inert the queue takes `explicit_transmit_rate_bytes = None`,
// so its rate collapses to the whole interface shaping-rate (10_000_000, not
// 0.5x) and `guarantee_enabled` stays false.
#[test]
fn build_cos_state_resolves_transmit_rate_percent_against_interface_shaping_rate() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 0,
                transmit_rate_percent: 50.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert_eq!(
        iface.queues[0].transmit_rate_bytes, 5_000_000,
        "transmit-rate percent 50 must resolve to 50% of the 10_000_000 B/s interface shaping-rate"
    );
    assert!(
        iface.queues[0].guarantee_enabled,
        "a resolved percent transmit-rate must enable the queue guarantee (no longer inert)"
    );
}

// #4228 Gap 2: a percent transmit-rate on an interface with NO root
// shaping-rate (transparent root) has no base to resolve against; it stays
// inert — no fabricated guarantee — matching the buffer-size None->default path.
#[test]
fn build_cos_state_transmit_rate_percent_no_shaping_rate_stays_inert() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 0,
                transmit_rate_percent: 50.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert!(
        !iface.queues[0].guarantee_enabled,
        "a percent with no interface shaping-rate has no base and must not fabricate a guarantee"
    );
}

// #6846 F5 — the remainder CALL SITE, not the resolver.
//
// Every cell in `cos::remainder_temporal_tests_6846` calls
// `cos_remainder_rate_bytes` directly with its own shaping argument, so none of
// them exercises `build_cos_iface_config`'s pre-pass. A review measured the
// hole: swapping `iface.cos_shaping_rate_bytes_per_sec` for `burst_bytes` at
// that call site changes every remainder queue's rate on every interface and
// left the whole crate GREEN (4775 tests, 0 failed). Both operands are `u64`
// and the crate has no `deny(warnings)`, so it compiles silently.
//
// That is the same hazard `temporal_call_site_uses_the_queue_rate_not_the_
// interface_burst` exists to catch for the sibling form, one line above. These
// three cells bind the wiring: the argument the pre-pass is handed, the
// precedence the main path applies, and the value the CONSUMER ends up with.

/// Forwarding classes for the #6846 builder cells: three classes so a
/// remainder queue always has resolved siblings to be a remainder OF.
fn remainder_forwarding_classes_6846() -> Vec<CoSForwardingClassSnapshot> {
    vec![
        CoSForwardingClassSnapshot {
            name: "be".into(),
            queue: 0,
        },
        CoSForwardingClassSnapshot {
            name: "ef".into(),
            queue: 1,
        },
        CoSForwardingClassSnapshot {
            name: "af".into(),
            queue: 2,
        },
    ]
}

/// A shaped interface (ifindex 42) bound to `wan-map`, carrying `schedulers`
/// and one map entry per `(forwarding_class, scheduler)` pair.
///
/// The shaping rate and the burst are DELIBERATELY different orders of
/// magnitude (10_000_000 vs 256_000) so that handing the pre-pass the wrong one
/// cannot produce the expected rate by coincidence.
fn remainder_snapshot_6846(
    schedulers: Vec<CoSSchedulerSnapshot>,
    entries: &[(&str, &str)],
) -> ConfigSnapshot {
    ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: remainder_forwarding_classes_6846(),
            schedulers,
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: entries
                    .iter()
                    .map(|(fc, sched)| CoSSchedulerMapEntrySnapshot {
                        forwarding_class: (*fc).into(),
                        scheduler: (*sched).into(),
                    })
                    .collect(),
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    }
}

/// A scheduler with `transmit-rate remainder` and nothing else.
fn remainder_scheduler_6846(name: &str) -> CoSSchedulerSnapshot {
    CoSSchedulerSnapshot {
        name: name.into(),
        transmit_rate_remainder: true,
        ..Default::default()
    }
}

/// The queue materialized for `fc`, by forwarding-class rather than by index —
/// index would silently follow scheduler-map iteration order.
fn queue_for_class_6846<'a>(iface: &'a CoSInterfaceConfig, fc: &str) -> &'a CoSQueueConfig {
    iface
        .queues
        .iter()
        .find(|q| q.forwarding_class == fc)
        .unwrap_or_else(|| panic!("no queue materialized for forwarding-class {fc}"))
}

// #6846: the pre-pass must be handed the interface SHAPING RATE. RED on the
// measured escape (`burst_bytes` in place of
// `iface.cos_shaping_rate_bytes_per_sec`): the absolute sibling alone claims
// 1_000_000 > the 256_000 burst, so the leftover saturates to nothing, the
// remainder stops resolving, and the queue falls back to the whole 10_000_000
// interface rate with no guarantee.
#[test]
fn build_cos_state_remainder_pre_pass_takes_the_interface_shaping_rate() {
    let snapshot = remainder_snapshot_6846(
        vec![
            CoSSchedulerSnapshot {
                name: "abs-sched".into(),
                transmit_rate_bytes: 1_000_000,
                ..Default::default()
            },
            CoSSchedulerSnapshot {
                name: "pct-sched".into(),
                transmit_rate_percent: 30.0,
                ..Default::default()
            },
            remainder_scheduler_6846("rem-sched"),
        ],
        &[
            ("ef", "abs-sched"),
            ("af", "pct-sched"),
            ("be", "rem-sched"),
        ],
    );

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");

    // The siblings first: a wrong sibling rate would move the leftover, so
    // asserting the remainder alone could pass on two compensating errors.
    assert_eq!(
        queue_for_class_6846(iface, "ef").transmit_rate_bytes,
        1_000_000,
        "the absolute sibling keeps its own rate"
    );
    assert_eq!(
        queue_for_class_6846(iface, "af").transmit_rate_bytes,
        3_000_000,
        "percent 30 of the 10_000_000 B/s interface shaping-rate"
    );

    let rem = queue_for_class_6846(iface, "be");
    assert_eq!(
        rem.transmit_rate_bytes, 6_000_000,
        "the remainder queue takes 10_000_000 - (1_000_000 + 3_000_000). \
         10_000_000 means it did not resolve at all and fell back to the whole \
         interface rate; anything derived from 256_000 means the pre-pass was \
         handed the interface BURST instead of its shaping rate"
    );
    assert!(
        rem.guarantee_enabled,
        "a resolved remainder is a real rate and must enable the queue guarantee"
    );
}

// #6846 R4: the pre-pass and the main path must agree about WHICH queues are
// remainder queues. The main path prefers an absolute rate
// (`cos_effective_transmit_rate_bytes` before the `.or_else`), so a scheduler
// carrying BOTH an absolute rate and `remainder` — reachable on the lenient
// load / peer-sync path, since the strict commit gate rejects it — must not be
// counted in the divisor.
//
// This binds both halves at the builder, which the resolver-level cells cannot:
// counting the both-forms queue in the divisor makes the real remainder queue
// 5_000_000 instead of 8_000_000, and inverting the main path's `.or_else` so
// remainder beats absolute makes the both-forms queue 8_000_000 instead of
// 2_000_000. Either one reds exactly one assertion below and names itself.
#[test]
fn build_cos_state_remainder_pre_pass_and_main_path_agree_on_the_divisor() {
    let snapshot = remainder_snapshot_6846(
        vec![
            CoSSchedulerSnapshot {
                name: "both-sched".into(),
                transmit_rate_bytes: 2_000_000,
                transmit_rate_remainder: true,
                ..Default::default()
            },
            remainder_scheduler_6846("rem-sched"),
        ],
        &[("ef", "both-sched"), ("be", "rem-sched")],
    );

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");

    assert_eq!(
        queue_for_class_6846(iface, "ef").transmit_rate_bytes,
        2_000_000,
        "absolute beats remainder on the SAME scheduler — 8_000_000 here means \
         the main path resolved it as a remainder queue instead"
    );
    assert_eq!(
        queue_for_class_6846(iface, "be").transmit_rate_bytes,
        8_000_000,
        "the ONE real remainder queue takes the whole 10_000_000 - 2_000_000 \
         leftover — 5_000_000 means the pre-pass counted the both-forms \
         scheduler in the divisor while the main path did not, halving every \
         real remainder queue's share"
    );
}

// #6846 F1, asserted AT THE CONSUMER. A resolver that can return a legal zero
// needs its assertion where the zero is CONSUMED, because `Some(0)` is
// indistinguishable from healthy where it is produced: it only collides with a
// sentinel one layer up.
//
// `CoSQueueConfig` states the sentinel itself ("transparent zero-rate queues use
// that value to mean unshaped/full bucket", types/cos.rs) and cos/token_bucket.rs
// reads it. So `guarantee_enabled = true` alongside `transmit_rate_bytes = 0`
// would promote the queue into guarantee service AND leave it uncapped — the
// inverse of the starved queue the form is meant to describe. `percent 60` +
// `percent 40` + `remainder` reaches it with no over-subscription at all.
#[test]
fn build_cos_state_zero_remainder_leftover_never_guarantees_the_unshaped_sentinel() {
    let snapshot = remainder_snapshot_6846(
        vec![
            CoSSchedulerSnapshot {
                name: "p60".into(),
                transmit_rate_percent: 60.0,
                ..Default::default()
            },
            CoSSchedulerSnapshot {
                name: "p40".into(),
                transmit_rate_percent: 40.0,
                ..Default::default()
            },
            remainder_scheduler_6846("rem-sched"),
        ],
        &[("ef", "p60"), ("af", "p40"), ("be", "rem-sched")],
    );

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");

    // Guard the fixture: if the siblings ever stopped claiming the whole rate
    // there would BE a leftover, and every assertion below would pass over a
    // case that never arose.
    assert_eq!(
        queue_for_class_6846(iface, "ef").transmit_rate_bytes
            + queue_for_class_6846(iface, "af").transmit_rate_bytes,
        10_000_000,
        "fixture broken: the two percent siblings must claim the WHOLE shaping \
         rate, or the remainder leftover is not zero"
    );

    let rem = queue_for_class_6846(iface, "be");
    assert!(
        !(rem.guarantee_enabled && rem.transmit_rate_bytes == 0),
        "a guarantee on the zero/unshaped sentinel is the fail-open state: the \
         token bucket reads transmit_rate_bytes == 0 as `full bucket`, so this \
         queue would be promoted into guarantee service AND run uncapped"
    );
    assert!(
        !rem.guarantee_enabled,
        "a leftover of nothing is not a resolution — the form stays inert and \
         keeps the historical no-guarantee fallback"
    );
    assert_eq!(
        rem.transmit_rate_bytes, 10_000_000,
        "the inert fallback is the interface shaping-rate, unchanged from \
         before remainder existed"
    );
}

#[test]
fn build_cos_state_prefers_legacy_byte_buffer_when_both_fields_present() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 3_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 128_000,
                buffer_size_percent: 10.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert_eq!(
        iface.queues[0].buffer_bytes, 128_000,
        "legacy buffer_size_bytes must keep precedence for additive protocol compatibility"
    );
}

// #915 (Copilot code-review #3): regression test that
// `build_cos_state` correctly propagates the snapshot
// `surplus_sharing` flag into the runtime `CoSQueueConfig`.
// The builders test alone is insufficient because it starts from
// a hand-built `CoSQueueConfig`, so a regression that stops
// `build_cos_state` from copying the snapshot field would not
// show up there. This test starts from a `CoSSchedulerSnapshot`
// with `surplus_sharing=true` and verifies the field arrives at
// `CoSQueueConfig.surplus_sharing`.
#[test]
fn build_cos_state_propagates_surplus_sharing_from_snapshot() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "iperf-a".into(),
                    queue: 4,
                },
                CoSForwardingClassSnapshot {
                    name: "iperf-b".into(),
                    queue: 5,
                },
            ],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "iperf-a".into(),
                    transmit_rate_bytes: 1_000_000_000 / 8,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128 * 1024,
                    buffer_size_percent: 0.0,
                    surplus_sharing: true, // opt-in
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "iperf-b".into(),
                    transmit_rate_bytes: 10_000_000_000 / 8,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: true,
                    priority: "low".into(),
                    buffer_size_bytes: 128 * 1024,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false, // explicit hard-cap
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-a".into(),
                        scheduler: "iperf-a".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "iperf-b".into(),
                        scheduler: "iperf-b".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    let q4 = iface.queues.iter().find(|q| q.queue_id == 4).unwrap();
    let q5 = iface.queues.iter().find(|q| q.queue_id == 5).unwrap();
    assert!(
        q4.surplus_sharing,
        "snapshot scheduler iperf-a (surplus_sharing=true) must reach \
         CoSQueueConfig.surplus_sharing on queue 4"
    );
    assert!(
        !q5.surplus_sharing,
        "snapshot scheduler iperf-b (surplus_sharing=false) must reach \
         CoSQueueConfig.surplus_sharing=false on queue 5"
    );
    // Sanity: both still exact (so the strip-on-non-exact rule wouldn't have
    // fired even if it had been at this layer).
    assert!(q4.exact && q5.exact);
}

#[test]
fn build_cos_state_propagates_equal_flow_target_policy_gated_on_enforcement() {
    // #1746: the policy string reaches CoSQueueConfig only when the
    // scheduler is actually equal-flow-enforcing; otherwise the queue
    // carries the byte-unchanged default `Slowest`. #2458: an unknown
    // NON-EMPTY policy on an active equal-flow scheduler now fails the
    // snapshot closed (see the dedicated fail-closed test below); the
    // empty/unset string still decodes to `Slowest`.
    let make_sched = |name: &str, enforcement: bool, policy: &str| CoSSchedulerSnapshot {
        name: name.into(),
        transmit_rate_bytes: 1_000_000_000 / 8,
        transmit_rate_percent: 0.0,
        transmit_rate_exact: true,
        priority: "low".into(),
        buffer_size_bytes: 128 * 1024,
        buffer_size_percent: 0.0,
        surplus_sharing: false,
        equal_flow_enforcement: enforcement,
        equal_flow_target_policy: policy.into(),
        codel_target_ns: 0,
        ..Default::default()
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "fc-mean".into(),
                    queue: 4,
                },
                CoSForwardingClassSnapshot {
                    name: "fc-ungated".into(),
                    queue: 5,
                },
                CoSForwardingClassSnapshot {
                    name: "fc-ideal".into(),
                    queue: 6,
                },
                CoSForwardingClassSnapshot {
                    name: "fc-empty".into(),
                    queue: 7,
                },
            ],
            schedulers: vec![
                make_sched("s-mean", true, "mean"),
                // Policy set but enforcement absent: must stay Slowest.
                make_sched("s-ungated", false, "mean"),
                make_sched("s-ideal", true, "ideal-share"),
                // #2458: empty/unset policy on an active equal-flow
                // scheduler is the legacy default and decodes to Slowest.
                make_sched("s-empty", true, ""),
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "fc-mean".into(),
                        scheduler: "s-mean".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "fc-ungated".into(),
                        scheduler: "s-ungated".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "fc-ideal".into(),
                        scheduler: "s-ideal".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "fc-empty".into(),
                        scheduler: "s-empty".into(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    let policy_of = |queue_id: u8| {
        iface
            .queues
            .iter()
            .find(|q| q.queue_id == queue_id)
            .unwrap_or_else(|| panic!("queue {queue_id} present"))
            .equal_flow_target_policy
    };
    assert_eq!(policy_of(4), EqualFlowTargetPolicy::Mean);
    assert_eq!(
        policy_of(5),
        EqualFlowTargetPolicy::Slowest,
        "policy without equal-flow-enforcement must stay at the default"
    );
    assert_eq!(policy_of(6), EqualFlowTargetPolicy::IdealShare);
    assert_eq!(
        policy_of(7),
        EqualFlowTargetPolicy::Slowest,
        "empty/unset policy string must decode to the byte-unchanged default"
    );
}

#[test]
fn build_cos_state_fails_closed_on_unknown_equal_flow_target_policy() {
    // #2458: an active equal-flow scheduler carrying a NON-EMPTY policy
    // string that is not one of slowest|mean|ideal-share fails the
    // snapshot CLOSED (the helper-boundary backstop for a typo or a
    // version-drifted snapshot) rather than silently mapping it to the
    // `Slowest` default and changing queue fairness with no failure
    // surfaced. The Go commit-time gate (#1746/#2458) is the primary
    // defense; this proves the Rust backstop names the offending value.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "fc-bad".into(),
                queue: 4,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "s-bad".into(),
                transmit_rate_bytes: 1_000_000_000 / 8,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: true,
                priority: "low".into(),
                buffer_size_bytes: 128 * 1024,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: true,
                equal_flow_target_policy: "bogus-policy".into(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "fc-bad".into(),
                    scheduler: "s-bad".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    // Call the fallible production orchestrator directly (the `super::*`
    // `build_cos_state` test wrapper `.expect()`s a clean snapshot).
    match super::cos::build_cos_state(&snapshot) {
        Err(crate::policy::SnapshotIntegrityError::CosUnknownEqualFlowTargetPolicy {
            forwarding_class,
            target_policy,
        }) => {
            assert_eq!(forwarding_class, "fc-bad");
            assert_eq!(target_policy, "bogus-policy");
        }
        Err(other) => panic!("wrong integrity error: {other}"),
        Ok(_) => panic!("unknown equal-flow-target-policy must fail the snapshot closed"),
    }
}

#[test]
fn build_cos_state_fails_closed_on_unknown_scheduler_priority() {
    // #6849 added the `medium` case. `hgh` is an operator typo; `medium` is
    // the more interesting one, because until #6849 removed its match arm it
    // resolved to a REAL rank (3) and silently placed the class between
    // medium-high and medium-low instead of failing. A unit test on
    // cos_priority_rank alone would not catch that arm coming back: the
    // caller has to actually consult it, which is what this drives.
    for bad_priority in ["hgh", "medium"] {
        build_cos_state_rejects_priority_6849(bad_priority);
    }
}

fn build_cos_state_rejects_priority_6849(bad_priority: &str) {
    // #hb166 T-7: a scheduler carrying a NON-EMPTY `priority` string that
    // is not a known Junos scheduler priority fails the snapshot CLOSED
    // (the helper-boundary backstop for a typo / version-drifted snapshot)
    // rather than silently ranking it lowest ("low") — mirroring the #2458
    // equal-flow-policy backstop a few fields over. RED-on-revert: the
    // pre-fix `_ => 5` catch-all returned `Ok` with the class demoted to
    // rank 5.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "fc-bad".into(),
                queue: 4,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "s-bad".into(),
                transmit_rate_bytes: 1_000_000_000 / 8,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: true,
                priority: bad_priority.into(),
                buffer_size_bytes: 128 * 1024,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "fc-bad".into(),
                    scheduler: "s-bad".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    match super::cos::build_cos_state(&snapshot) {
        Err(crate::policy::SnapshotIntegrityError::CosUnknownSchedulerPriority {
            forwarding_class,
            priority,
        }) => {
            assert_eq!(forwarding_class, "fc-bad");
            assert_eq!(priority, bad_priority);
        }
        Err(other) => panic!("wrong integrity error: {other}"),
        Ok(_) => panic!(
            "#6849: scheduler priority {bad_priority:?} must fail the snapshot CLOSED, not \
             resolve to a rank"
        ),
    }
}

#[test]
fn build_cos_state_falls_back_to_default_best_effort_queue() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 7,
            cos_shaping_rate_bytes_per_sec: 1_000_000,
            cos_scheduler_map: "missing-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot::default()),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state
        .interfaces
        .get(&7)
        .expect("missing fallback CoS interface");
    assert_eq!(iface.shaping_rate_bytes, 1_000_000);
    assert_eq!(iface.burst_bytes, default_cos_burst_bytes(1_000_000));
    assert_eq!(iface.default_queue, 0);
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].queue_id, 0);
    assert_eq!(iface.queues[0].forwarding_class, "best-effort");
    assert_eq!(iface.queues[0].priority, 5);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 1_000_000);
    assert!(iface.queues[0].guarantee_enabled);
    assert!(!iface.queues[0].exact);
    assert_eq!(iface.queues[0].surplus_weight, 1);
    assert_eq!(
        iface.queues[0].buffer_bytes,
        default_cos_burst_bytes(1_000_000)
    );
}

#[test]
fn build_cos_state_derives_exact_queue_default_burst_from_queue_rate() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 25_000_000_000 / 8,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 100_000_000 / 8,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: true,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");

    assert_eq!(iface.shaping_rate_bytes, 25_000_000_000 / 8);
    assert_eq!(
        iface.burst_bytes,
        default_cos_burst_bytes(25_000_000_000 / 8),
        "interface burst should still derive from the parent shaper"
    );
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 100_000_000 / 8);
    assert!(iface.queues[0].exact);
    assert_eq!(
        iface.queues[0].buffer_bytes,
        default_cos_burst_bytes(100_000_000 / 8),
        "exact queue burst must derive from the scheduler rate, not the 25 Gb/s parent shaper"
    );
}

#[test]
fn build_cos_state_uses_effective_transmit_rate_for_surplus_weight() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 9,
            cos_shaping_rate_bytes_per_sec: 1_000_000,
            cos_scheduler_map: "test-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 0,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "test-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&9).expect("missing CoS interface");
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 1_000_000);
    assert!(
        !iface.queues[0].guarantee_enabled,
        "zero scheduler transmit-rate inherits an effective rate for surplus sizing only"
    );
    assert_eq!(iface.queues[0].surplus_weight, 16);
}

#[test]
fn build_cos_state_marks_no_rate_scheduler_map_queue_residual_only() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 9,
            cos_shaping_rate_bytes_per_sec: 1_000_000,
            cos_scheduler_map: "test-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 0,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "test-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&9).expect("missing CoS interface");
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].transmit_rate_bytes, 1_000_000);
    assert!(
        !iface.queues[0].guarantee_enabled,
        "scheduler-map queue without explicit transmit-rate must not become a root-rate guarantee"
    );
    assert!(!iface.queues[0].exact);
}

#[test]
fn build_cos_state_dangling_scheduler_reference_uses_safe_best_effort_default() {
    // A scheduler-map entry naming a scheduler that is NOT defined (a
    // commit-time typo, hard-rejected on the strict path but downgraded
    // to a warning on the lenient load / peer-sync path, so it can still
    // reach the dataplane) must fail SAFE, not OPEN. Before the fix the
    // unresolved reference fell through to `transmit_rate_bytes = the
    // whole interface shaping rate`, deriving `surplus_weight = 16` (the
    // maximum) — the class did not merely lose its guarantee, it won the
    // LARGEST best-effort surplus share. The queue must stay materialized
    // (so a classifier steering traffic to its queue still forwards) but
    // be pinned to the minimal best-effort surplus weight, with no
    // guarantee and no fabricated priority.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 9,
            cos_shaping_rate_bytes_per_sec: 1_000_000,
            cos_scheduler_map: "test-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "ef".into(),
                queue: 1,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            // The referenced scheduler "ef-typo" is intentionally absent.
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "test-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "ef".into(),
                    scheduler: "ef-typo".into(),
                }],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&9).expect("missing CoS interface");
    // Queue stays materialized under its real queue id / class.
    assert_eq!(iface.queues.len(), 1);
    assert_eq!(iface.queues[0].queue_id, 1);
    assert_eq!(iface.queues[0].forwarding_class, "ef");
    // SAFE default: minimal best-effort surplus share, NOT the fail-open
    // maximum (16) the whole-interface effective rate would have derived.
    assert_eq!(
        iface.queues[0].surplus_weight, 1,
        "dangling scheduler reference must fail SAFE to the minimal best-effort surplus weight, not fail OPEN to the max"
    );
    // No guarantee, no exact, priority stays "low" (rank 5) — nothing is
    // fabricated for the unresolved reference.
    assert!(!iface.queues[0].guarantee_enabled);
    assert!(!iface.queues[0].exact);
    assert_eq!(iface.queues[0].priority, 5, "low priority rank");
}

#[test]
fn build_cos_state_binds_dscp_classifier_to_usable_interface_queue_ids() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            cos_dscp_classifier: "wan-classifier".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            cos_dscp_rewrite_rule: "wan-rewrite".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
            ],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan-classifier".into(),
                entries: vec![
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![46],
                    },
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![0],
                    },
                ],
            }],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    code_points: vec![5],
                }],
            }],
            dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
                name: "wan-rewrite".into(),
                entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    dscp_value: 46,
                }],
            }],
            schedulers: vec![
                CoSSchedulerSnapshot {
                    name: "be".into(),
                    transmit_rate_bytes: 1_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "low".into(),
                    buffer_size_bytes: 0,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
                CoSSchedulerSnapshot {
                    name: "voice".into(),
                    transmit_rate_bytes: 2_000_000,
                    transmit_rate_percent: 0.0,
                    transmit_rate_exact: false,
                    priority: "high".into(),
                    buffer_size_bytes: 0,
                    buffer_size_percent: 0.0,
                    surplus_sharing: false,
                    equal_flow_enforcement: false,
                    equal_flow_target_policy: String::new(),
                    codel_target_ns: 0,
                    ..Default::default()
                },
            ],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        scheduler: "be".into(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "voice".into(),
                        scheduler: "voice".into(),
                    },
                ],
            }],
            ..Default::default()
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    assert_eq!(iface.dscp_classifier, "wan-classifier");
    assert_eq!(iface.ieee8021_classifier, "wan-pcp");
    // #3995: a single (voice, low) rewrite is loss-priority-DIFFERENTIATED
    // (only LOW is set), so it is NOT baked into the per-queue drain fallback
    // (which is uniform-only); it resolves per-flow via `lp_rewrite` instead.
    assert_eq!(
        iface
            .queues
            .iter()
            .find(|queue| queue.queue_id == 5)
            .and_then(|queue| queue.dscp_rewrite),
        None
    );
    assert!(iface.queues.iter().any(|queue| queue.queue_id == 5));
    // #3995: voice (queue 5) is classified LOW (index 0) for DSCP 46, and the
    // rewrite-rule maps (voice, low) -> 46, so the loss-priority matrix carries
    // (queue 5, low) -> 46.
    let lp_rewrite = state
        .lp_rewrite
        .get(&42)
        .expect("missing lp_rewrite for CoS interface");
    assert_eq!(lp_rewrite.dscp_rewrite_by_queue_lp.get(&(5, 0)), Some(&46));
    assert_eq!(lp_rewrite.dscp_lp_by_dscp[46], 0);
    assert_eq!(lp_rewrite.dscp_lp_by_dscp[0], 0);
    let classifier = state
        .dscp_classifiers
        .get("wan-classifier")
        .expect("missing classifier");
    assert_eq!(classifier.queue_by_dscp.get(&46), Some(&5));
    assert_eq!(classifier.queue_by_dscp.get(&0), Some(&0));
    let pcp_classifier = state
        .ieee8021_classifiers
        .get("wan-pcp")
        .expect("missing 802.1p classifier");
    assert_eq!(pcp_classifier.queue_by_pcp.get(&5), Some(&5));
}

#[test]
fn build_forwarding_state_prefers_logical_unit_for_ingress_lookup() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0-0-1".into(),
                ifindex: 10,
                hardware_addr: "02:00:00:00:00:10".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0-0-1.0".into(),
                ifindex: 11,
                parent_ifindex: 10,
                vlan_id: 0,
                hardware_addr: "02:00:00:00:00:10".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.ingress_logical_ifindex.get(&(10, 0)), Some(&11));
}

#[test]
fn build_forwarding_state_keeps_parent_bound_vlan_units_distinct() {
    use crate::ZoneSnapshot;

    let snapshot = ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "wan".into(),
                id: 11,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "dmz".into(),
                id: 12,
                ..Default::default()
            },
        ],
        interfaces: vec![
            InterfaceSnapshot {
                name: "reth0.80".into(),
                zone: "wan".into(),
                ifindex: 20080,
                parent_ifindex: 6,
                vlan_id: 80,
                hardware_addr: "02:00:00:00:00:06".into(),
                cos_shaping_rate_bytes_per_sec: 10_000_000,
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "reth0.81".into(),
                zone: "dmz".into(),
                ifindex: 20081,
                parent_ifindex: 6,
                vlan_id: 81,
                hardware_addr: "02:00:00:00:00:06".into(),
                cos_shaping_rate_bytes_per_sec: 20_000_000,
                ..Default::default()
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot::default()),
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    assert_eq!(state.ingress_logical_ifindex.get(&(6, 80)), Some(&20080));
    assert_eq!(state.ingress_logical_ifindex.get(&(6, 81)), Some(&20081));
    assert_eq!(state.ifindex_to_zone_id.get(&20080).copied(), Some(11));
    assert_eq!(state.ifindex_to_zone_id.get(&20081).copied(), Some(12));
    assert_eq!(
        state.egress.get(&20080).expect("wan egress").bind_ifindex,
        6
    );
    assert_eq!(
        state.egress.get(&20081).expect("dmz egress").bind_ifindex,
        6
    );
    assert!(state.cos.interfaces.contains_key(&20080));
    assert!(state.cos.interfaces.contains_key(&20081));
}

// #3070: host-inbound-traffic enforcement. A configured zone admits only its
// listed system-services / protocols for host-bound (local-delivery) traffic;
// an unconfigured zone admits everything (admit-all default). Reverting the
// enforcement (treating every zone as admit-all) turns the deny assertions RED.
#[test]
fn build_forwarding_state_enforces_host_inbound_traffic() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::host_inbound_admits;

    let snapshot = ConfigSnapshot {
        zones: vec![
            // wan: ping + gre + router-discovery (mirrors the repo cluster cfg).
            ZoneSnapshot {
                name: "wan".into(),
                id: 11,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ping".into(), "gre".into()],
                host_inbound_protocols: vec!["router-discovery".into()],
                ..Default::default()
            },
            // lan: ssh + ping only.
            ZoneSnapshot {
                name: "lan".into(),
                id: 12,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ssh".into(), "ping".into()],
                host_inbound_protocols: vec![],
                ..Default::default()
            },
            // control: `system-services all` — the heartbeat zone as every
            // shipped HA config authors it. #3226: `all` is the union of the
            // named system-services, NOT a packet-wide admit, so this zone is
            // open to ssh/https/snmp/... but NOT to raw IP protocols. (In a
            // real cluster the control zone is lifeline-only, so it never even
            // contributes host-inbound addresses — see
            // pkg/dataplane/userspace.BuildZoneHostInboundViews.)
            ZoneSnapshot {
                name: "control".into(),
                id: 13,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["all".into()],
                host_inbound_protocols: vec![],
                ..Default::default()
            },
            // #3705: a KNOWN zone in the snapshot with host_inbound_configured=false
            // (the tolerant / HA nil-zone shape, or an old pre-#3405 Go control
            // plane that omits the flag) is now default-DENY, NOT admit-all. It
            // still enters the table (with an empty ZoneHostInbound) so the
            // classifier fails closed instead of falling into `None => true`.
            ZoneSnapshot {
                name: "legacy".into(),
                id: 14,
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    // #3705: EVERY known zone populates the table — including the legacy
    // configured=false zone (id 14). Before #3705 id 14 was absent (admit-all);
    // it is now present with an empty default-deny ZoneHostInbound.
    assert!(state.zone_host_inbound.contains_key(&11));
    assert!(state.zone_host_inbound.contains_key(&12));
    assert!(state.zone_host_inbound.contains_key(&13));
    assert!(state.zone_host_inbound.contains_key(&14));

    // wan (id 11): ping echo-request (icmp type 8) admitted, gre (proto 47)
    // admitted, ssh (tcp/22) DENIED, ospf (proto 89) DENIED. #3201: a non-echo
    // ICMP type (13 = timestamp-request) is DENIED — `ping` no longer opens the
    // whole ICMP protocol.
    assert!(host_inbound_admits(&state, 11, 1, 0, false, 8), "wan ping echo");
    assert!(
        !host_inbound_admits(&state, 11, 1, 0, false, 13),
        "wan ping does NOT admit timestamp-request"
    );
    assert!(host_inbound_admits(&state, 11, 47, 0, false, 0), "wan gre");
    assert!(
        !host_inbound_admits(&state, 11, 6, 22, false, 0),
        "wan ssh deny"
    );
    assert!(
        !host_inbound_admits(&state, 11, 89, 0, false, 0),
        "wan ospf deny"
    );

    // lan (id 12): ssh (tcp/22) admitted, ping admitted, telnet (tcp/23)
    // DENIED, dhcp (udp/67) DENIED (not listed).
    assert!(host_inbound_admits(&state, 12, 6, 22, false, 0), "lan ssh");
    assert!(host_inbound_admits(&state, 12, 1, 0, false, 8), "lan ping echo");
    assert!(
        !host_inbound_admits(&state, 12, 6, 23, false, 0),
        "lan telnet deny"
    );
    assert!(
        !host_inbound_admits(&state, 12, 17, 67, false, 0),
        "lan dhcp deny"
    );

    // control (id 13): `all` → the named system-service union (#3226). SSH and
    // SNMP are admitted; an arbitrary port and a raw IP protocol are DENIED.
    // Before #3226 `all` short-circuited to a packet-wide admit, so both of the
    // deny assertions below were admits.
    assert!(
        host_inbound_admits(&state, 13, 6, 22, false, 0),
        "control all ssh (named system-service)"
    );
    assert!(
        host_inbound_admits(&state, 13, 17, 161, false, 0),
        "control all snmp (named system-service)"
    );
    assert!(
        !host_inbound_admits(&state, 13, 6, 12345, false, 0),
        "control all must DENY an unlisted tcp port (#3226 — `all` is not packet-wide)"
    );
    assert!(
        !host_inbound_admits(&state, 13, 89, 0, false, 0),
        "control all must DENY ospf/proto-89 (#3226 — a routing protocol needs a `protocols` entry)"
    );

    // #3705: legacy (id 14) is a KNOWN configured=false zone → now default-DENY,
    // NOT admit-all. ssh (tcp/22) and ospf (proto 89) are both denied because its
    // empty ZoneHostInbound admits nothing. Fail-on-revert: re-gate the insert in
    // forwarding_build::zones on `zone.host_inbound_configured` and id 14 falls
    // back to `None => true` admit-all, flipping these two assertions RED.
    assert!(
        !host_inbound_admits(&state, 14, 6, 22, false, 0),
        "legacy configured=false zone must default-DENY ssh (#3705 fail-closed)"
    );
    assert!(
        !host_inbound_admits(&state, 14, 89, 0, false, 0),
        "legacy configured=false zone must default-DENY ospf (#3705 fail-closed)"
    );
    // The global ICMP error/PMTUD accept still fires even on the default-deny
    // legacy zone (PMTUD is never black-holed).
    assert!(
        host_inbound_admits(&state, 14, 1, 0, false, 3),
        "ICMPv4 destination-unreachable stays globally admitted on the legacy zone"
    );
    // A zone id that does NOT exist in the snapshot at all (genuinely unknown /
    // global ingress zone) still admits — the `None => true` arm is preserved for
    // id-not-in-table, which #3405 deliberately kept as the admit default.
    assert!(
        host_inbound_admits(&state, 99, 6, 22, false, 0),
        "unknown/global zone (absent from snapshot) keeps the admit default"
    );
}

// #3705: a KNOWN zone that reaches the dataplane with host_inbound_configured=false
// — the tolerant / HA nil-zone shape (Security.Zones[name] == nil ships a valid
// name+id but configured=false; #3493), or an old pre-#3405 Go control plane that
// omits the flag — must default-DENY host-bound traffic, NOT admit-all. This is
// the Rust half of the #3705 fix and the defense-in-depth backstop for a
// mismatched-version control plane (the Go builder now also ships configured=true
// for a nil zone). The build path inserts an empty ZoneHostInbound for the known
// zone so the classifier fails closed instead of hitting `None => true`.
//
// Fail-on-revert: re-gate the insert in forwarding_build::zones on
// `zone.host_inbound_configured` and the nil zone (id 21) is left absent from the
// table -> `None => true` admit-all -> the ssh/https deny assertions flip RED.
#[test]
fn build_forwarding_state_nil_zone_default_denies() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::host_inbound_admits;

    let snapshot = ConfigSnapshot {
        zones: vec![
            // The nil-zone shape: a known zone (valid name + id) that arrives with
            // host_inbound_configured=false and NO tokens.
            ZoneSnapshot {
                name: "nil-zone".into(),
                id: 21,
                host_inbound_configured: false,
                host_inbound_system_services: vec![],
                host_inbound_protocols: vec![],
                ..Default::default()
            },
            // A normal configured zone to prove the fix does not disturb legit
            // admit sets.
            ZoneSnapshot {
                name: "trust".into(),
                id: 22,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ssh".into()],
                host_inbound_protocols: vec![],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    // #3705: the nil zone is PRESENT in the table (fail-closed), not absent.
    assert!(
        state.zone_host_inbound.contains_key(&21),
        "nil / configured=false known zone must enter the host-inbound table (#3705)"
    );

    // The nil zone default-DENIES every host-bound service — ssh (tcp/22), https
    // (tcp/443), and an arbitrary UDP service on v6 are all denied.
    assert!(
        !host_inbound_admits(&state, 21, 6, 22, false, 0),
        "nil zone must deny ssh (tcp/22) — #3705 fail-closed default-deny"
    );
    assert!(
        !host_inbound_admits(&state, 21, 6, 443, false, 0),
        "nil zone must deny https (tcp/443)"
    );
    assert!(
        !host_inbound_admits(&state, 21, 17, 53, true, 0),
        "nil zone must deny udp/53 on v6"
    );
    // The global ICMP error/PMTUD accept (#3171) still fires on the nil zone, so
    // PMTUD / unreachable control is never black-holed by the default-deny.
    assert!(
        host_inbound_admits(&state, 21, 1, 0, false, 3),
        "ICMPv4 destination-unreachable stays globally admitted on the nil zone"
    );

    // The normal configured zone still admits its configured set (no over-removal).
    assert!(
        host_inbound_admits(&state, 22, 6, 22, false, 0),
        "configured trust zone must still admit ssh (tcp/22)"
    );
    assert!(
        !host_inbound_admits(&state, 22, 6, 443, false, 0),
        "configured trust zone (ssh only) must still deny https (tcp/443)"
    );

    // A genuinely unknown / global ingress zone (id not in the snapshot at all)
    // keeps the admit default — the `None => true` arm is preserved for id-not-in-
    // table (#3405 deliberately scoped it to configured zones only). Lifeline
    // interfaces (fxp0/em0/fab*) never reach this classifier (#3682).
    assert!(
        host_inbound_admits(&state, 900, 6, 22, false, 0),
        "unknown/global zone (absent from snapshot) keeps the admit default"
    );
}

// #5659: an ADDRESSED interface with an EMPTY security-zone string registers its
// IP into local_v4/local_v6 (a local-delivery target) but is skipped by the
// #2391 zone-id backstop (guarded by `!iface.zone.is_empty()`), so it resolves to
// zone_id 0. Without the empty-zone fail-closed sentinel, the ingress-interface-
// keyed `host_inbound_admits_iface` falls back to `host_inbound_admits(0)` which
// hits the `None => true` global-zone admit arm and would admit EVERY host-bound
// service on that interface. The fix inserts an empty `ZoneHostInbound` sentinel
// keyed by the interface's ifindex so host-bound services are DENIED there.
//
// Fail-on-revert: removing the sentinel insert in `populate_interfaces`
// (forwarding_build/interfaces.rs) makes `host_inbound_admits_iface(unzoned)`
// admit SSH/BGP again -> the deny assertions below turn RED. The ICMP/ND accepts
// and the genuinely-global zone_id 0 path (no ifindex override) stay untouched,
// and the em0 lifeline keeps its unconditional admit -> those anti-over-reject
// assertions guard the fix's scope.
#[test]
fn empty_zone_addressed_interface_denies_host_inbound() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::{host_inbound_admits, host_inbound_admits_iface};
    use crate::protocol::snapshot::InterfaceAddressSnapshot;

    const UNZONED_IFINDEX: i32 = 80;
    const EM0_IFINDEX: i32 = 81;
    const TRUST_IFINDEX: i32 = 82;
    const LO0_IFINDEX: i32 = 83;
    const PROTO_TCP: u8 = 6;
    const PROTO_ICMP: u8 = 1;
    const PROTO_ICMP6: u8 = 58;

    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 22,
            host_inbound_configured: true,
            host_inbound_system_services: vec!["ssh".into()],
            ..Default::default()
        }],
        interfaces: vec![
            // The gap: an ADDRESSED interface with NO security-zone.
            InterfaceSnapshot {
                name: "ge-0/0/9".into(),
                zone: String::new(),
                ifindex: UNZONED_IFINDEX,
                hardware_addr: "02:00:00:00:00:80".into(),
                addresses: vec![
                    InterfaceAddressSnapshot {
                        family: "inet".into(),
                        address: "10.0.99.1/24".into(),
                        ..Default::default()
                    },
                    InterfaceAddressSnapshot {
                        family: "inet6".into(),
                        address: "2001:db8:99::1/64".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            // A zoneless-addressed LIFELINE (em0) must NOT get a deny sentinel —
            // its host traffic is served unconditionally.
            InterfaceSnapshot {
                name: "em0".into(),
                zone: String::new(),
                ifindex: EM0_IFINDEX,
                hardware_addr: "02:00:00:00:00:81".into(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "10.99.0.1/24".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            // #5659 fold: a zoneless-addressed lo0 loopback (router-id / BGP
            // update-source) is a LIFELINE and must NOT get a deny sentinel —
            // the earlier fxp0/em0-only predicate missed lo0 and would have
            // stranded BGP-to-loopback the moment a future change bound it.
            InterfaceSnapshot {
                name: "lo0".into(),
                zone: String::new(),
                ifindex: LO0_IFINDEX,
                hardware_addr: "02:00:00:00:00:83".into(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "10.255.0.1/32".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            // A normally-zoned addressed interface — unaffected.
            InterfaceSnapshot {
                name: "ge-0/0/8".into(),
                zone: "trust".into(),
                ifindex: TRUST_IFINDEX,
                hardware_addr: "02:00:00:00:00:82".into(),
                addresses: vec![InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "10.0.61.1/24".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    // Precondition: the unzoned interface's IPs ARE registered as local-delivery
    // targets (the exposure the sentinel closes), and it resolved to zone_id 0
    // (no ifindex_to_zone_id entry).
    assert!(
        state.local_v4.contains(&"10.0.99.1".parse::<Ipv4Addr>().unwrap()),
        "unzoned interface v4 IP must be a local-delivery target"
    );
    assert!(
        state
            .local_v6
            .contains(&"2001:db8:99::1".parse::<std::net::Ipv6Addr>().unwrap()),
        "unzoned interface v6 IP must be a local-delivery target"
    );
    assert!(
        !state.ifindex_to_zone_id.contains_key(&UNZONED_IFINDEX),
        "unzoned interface must resolve to zone_id 0 (no zone-id entry)"
    );

    // The FIX: a host-bound service ingressing on the unzoned interface is DENIED
    // (empty sentinel), even though its resolved zone id is the global 0.
    assert!(
        !host_inbound_admits_iface(&state, UNZONED_IFINDEX, 0, PROTO_TCP, 22, false, 0),
        "empty-zone addressed interface must DENY host-bound ssh (tcp/22) — #5659"
    );
    assert!(
        !host_inbound_admits_iface(&state, UNZONED_IFINDEX, 0, PROTO_TCP, 179, false, 0),
        "empty-zone addressed interface must DENY host-bound bgp (tcp/179) — #5659"
    );

    // ICMP error/PMTUD (v4 type 3) and IPv6 ND (type 135) STILL admitted globally
    // on the unzoned interface — the sentinel must not black-hole control traffic.
    assert!(
        host_inbound_admits_iface(&state, UNZONED_IFINDEX, 0, PROTO_ICMP, 0, false, 3),
        "ICMPv4 destination-unreachable stays globally admitted on the unzoned interface"
    );
    assert!(
        host_inbound_admits_iface(&state, UNZONED_IFINDEX, 0, PROTO_ICMP6, 0, true, 135),
        "IPv6 Neighbor Solicitation stays globally admitted on the unzoned interface"
    );

    // Scope guard 1: the genuinely-global zone_id 0 path (no ifindex override)
    // KEEPS its admit default — a legitimately-zoneless NON-addressed control
    // interface is not affected. This is why the sentinel is keyed by ifindex, not
    // inserted into zone_host_inbound at id 0.
    assert!(
        host_inbound_admits(&state, 0, PROTO_TCP, 22, false, 0),
        "global zone_id 0 (zone-only path) keeps the admit default — not broken by #5659"
    );

    // Scope guard 2: the em0 lifeline is zoneless+addressed but must NOT get a
    // deny sentinel — its host traffic is served unconditionally.
    assert!(
        !state.ifindex_host_inbound.contains_key(&EM0_IFINDEX),
        "em0 lifeline must not get an empty-zone deny sentinel (#5659 scope)"
    );
    assert!(
        host_inbound_admits_iface(&state, EM0_IFINDEX, 0, PROTO_TCP, 22, false, 0),
        "em0 lifeline keeps its unconditional admit"
    );

    // Scope guard 3 (#5659 fold): lo0 is zoneless+addressed but is a lifeline
    // per the widened predicate (mirrors `userspaceSkipsIngressInterface`), so it
    // must NOT get a deny sentinel and must keep admitting host-bound bgp — the
    // earlier fxp0/em0-only predicate would have armed a strand-management deny.
    assert!(
        !state.ifindex_host_inbound.contains_key(&LO0_IFINDEX),
        "lo0 loopback lifeline must not get an empty-zone deny sentinel (#5659 fold)"
    );
    assert!(
        host_inbound_admits_iface(&state, LO0_IFINDEX, 0, PROTO_TCP, 179, false, 0),
        "lo0 loopback keeps host-bound bgp admit (router-id / update-source)"
    );

    // Anti-over-reject: the normal trust zone still admits its configured ssh.
    assert!(
        host_inbound_admits_iface(&state, TRUST_IFINDEX, 22, PROTO_TCP, 22, false, 0),
        "configured trust zone still admits ssh (tcp/22)"
    );
    assert!(
        !host_inbound_admits_iface(&state, TRUST_IFINDEX, 22, PROTO_TCP, 179, false, 0),
        "configured trust zone (ssh only) still denies bgp (tcp/179)"
    );
}

// #3299: `host-inbound-traffic protocols bfd` must admit multi-hop BFD control
// (UDP 4784, RFC 5883) in addition to single-hop control (3784) + echo (3785).
// Multi-hop BFD (for multi-hop BGP / BFD over multi-hop static routes) carries
// control packets on UDP/4784; before this fix the "bfd" arm inserted only
// 3784/3785 so 4784 was denied by host-inbound admission. Fail-on-revert:
// removing `hi.udp_ports.insert(4784)` from the "bfd" arm in host_inbound.rs
// turns the 4784-admit assertion RED. Keep in lockstep with the nft rule
// (`hostInboundProtocolMatches` "bfd", pkg/daemon/daemon_nft.go).
#[test]
fn build_forwarding_state_bfd_admits_multihop_control() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::host_inbound_admits;

    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".into(),
            id: 41,
            host_inbound_configured: true,
            host_inbound_system_services: vec![],
            host_inbound_protocols: vec!["bfd".into()],
            ..Default::default()
        }],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    assert!(state.zone_host_inbound.contains_key(&41));

    // Single-hop control (3784) + echo (3785) still admitted.
    assert!(
        host_inbound_admits(&state, 41, 17, 3784, false, 0),
        "bfd single-hop control udp/3784 admitted"
    );
    assert!(
        host_inbound_admits(&state, 41, 17, 3785, false, 0),
        "bfd echo udp/3785 admitted"
    );
    // Multi-hop control (4784, RFC 5883) admitted — the #3299 fix.
    assert!(
        host_inbound_admits(&state, 41, 17, 4784, false, 0),
        "bfd multi-hop control udp/4784 (RFC 5883) admitted"
    );
    // Also admitted on IPv6 (BFD runs over both families).
    assert!(
        host_inbound_admits(&state, 41, 17, 4784, true, 0),
        "bfd multi-hop control udp/4784 admitted on v6"
    );
    // A non-BFD UDP port stays DENIED (the arm did not open all of UDP).
    assert!(
        !host_inbound_admits(&state, 41, 17, 4783, false, 0),
        "bfd zone does not admit unrelated udp/4783"
    );
}

// #3311: `host-inbound-traffic protocols isis` must COMPILE into forwarding
// state and produce NO IP host-inbound admit on the AF_XDP local-delivery path.
// IS-IS rides OSI/CLNP directly over L2 (LLC-encapsulated, NOT IP), so it cannot
// be expressed in the IP-keyed admit model; it is a recognized-but-no-op token
// (Go SSOT config.HostInboundL2Protocols) handled by FRR over an LLC socket,
// outside this filter. The zone is still host-inbound-CONFIGURED, so a
// non-admitted IP service (e.g. SSH) stays DENIED — proving the isis arm did
// not accidentally fall open. Kept in lockstep with the nft mirror's isis
// no-op case (hostInboundProtocolMatches, pkg/daemon/daemon_nft.go).
//
// Scope note: this guards that the isis arm admits NOTHING — giving the "isis"
// arm any IP admit (e.g. `hi.ip_protocols.insert(124)`) turns the proto-124
// assertion RED. It does NOT guard the arm's existence (deleting `"isis" => {}`
// falls through to `_ => {}`, also a no-op). The SSOT-driven `protocols all`
// EXCLUSION is the genuinely-testable contract for HOST_INBOUND_L2_PROTOCOLS —
// see `protocols_all_excludes_l2` in afxdp::forwarding::host_inbound (RED when
// isis is removed from the L2 set), the real fail-on-revert guard.
#[test]
fn build_forwarding_state_isis_is_l2_noop() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::host_inbound_admits;

    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "core".into(),
            id: 51,
            host_inbound_configured: true,
            host_inbound_system_services: vec![],
            host_inbound_protocols: vec!["isis".into()],
            ..Default::default()
        }],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    // The zone compiles into the host-inbound table (config accepted).
    assert!(
        state.zone_host_inbound.contains_key(&51),
        "isis-only zone is host-inbound-configured and present in the table"
    );

    // isis admits NOTHING on the IP path: no TCP/UDP port, no IP protocol.
    assert!(
        !host_inbound_admits(&state, 51, 6, 22, false, 0),
        "isis zone must not admit ssh (no IP fall-open)"
    );
    assert!(
        !host_inbound_admits(&state, 51, 17, 520, false, 0),
        "isis zone must not admit an unrelated UDP port"
    );
    // Junos uses IP protocol 124 for integrated IS-IS-over-IP in some stacks;
    // assert no IP-protocol admit landed either (the arm is a true no-op).
    assert!(
        !host_inbound_admits(&state, 51, 124, 0, false, 0),
        "isis zone must not admit any IP protocol (L2/OSI, handled by FRR)"
    );
    // ICMP error/PMTUD still rides the global accept (unchanged), but plain
    // echo-request stays denied because `ping` was not configured.
    assert!(
        !host_inbound_admits(&state, 51, 1, 0, false, 8),
        "isis-only zone still denies ICMP echo-request (ping not configured)"
    );
}

// #3171: a CONFIGURED ping-less zone must still admit ICMP/ICMPv6 ERROR /
// PMTUD control messages (destination-unreachable, packet-too-big, time-
// exceeded, parameter-problem) reaching the XSK LocalDelivery path — mirroring
// the kernel host-inbound chain's global ICMP-error accept — while still
// DENYING ICMP echo-request when `ping` is not configured. A zone WITH `ping`
// still admits echo-request.
//
// Fail-on-revert: deleting the `is_icmp_host_inbound_global_accept` early-return
// in `host_inbound_admits` (the blanket ICMP-drop behaviour) turns the
// "admits dest-unreachable" assertions RED while the "drops echo without ping"
// assertions stay GREEN.
#[test]
fn build_forwarding_state_admits_icmp_errors_on_pingless_zone() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::host_inbound_admits;

    let snapshot = ConfigSnapshot {
        zones: vec![
            // ping-less zone: ssh only, NO ping.
            ZoneSnapshot {
                name: "wan-noping".into(),
                id: 31,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ssh".into()],
                host_inbound_protocols: vec![],
                ..Default::default()
            },
            // ping zone: echo-request must still be admitted.
            ZoneSnapshot {
                name: "lan-ping".into(),
                id: 32,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ping".into()],
                host_inbound_protocols: vec![],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    // ping-less zone (id 31) ADMITS ICMPv4 error / PMTUD control messages even
    // though it lists no `ping`: destination-unreachable (3), time-exceeded
    // (11), parameter-problem (12).
    assert!(
        host_inbound_admits(&state, 31, 1, 0, false, 3),
        "ping-less zone admits icmp destination-unreachable (PMTUD)"
    );
    assert!(
        host_inbound_admits(&state, 31, 1, 0, false, 11),
        "ping-less zone admits icmp time-exceeded (traceroute)"
    );
    assert!(
        host_inbound_admits(&state, 31, 1, 0, false, 12),
        "ping-less zone admits icmp parameter-problem"
    );
    // ...and ICMPv6 destination-unreachable (1) + packet-too-big (2, PMTUD).
    assert!(
        host_inbound_admits(&state, 31, 58, 0, true, 1),
        "ping-less zone admits icmpv6 destination-unreachable"
    );
    assert!(
        host_inbound_admits(&state, 31, 58, 0, true, 2),
        "ping-less zone admits icmpv6 packet-too-big (PMTUD)"
    );

    // ...but echo-request (v4 type 8 / v6 type 128) is STILL DENIED — it is
    // gated on the `ping` system-service, which this zone does not list.
    assert!(
        !host_inbound_admits(&state, 31, 1, 0, false, 8),
        "ping-less zone DENIES icmp echo-request"
    );
    assert!(
        !host_inbound_admits(&state, 31, 58, 0, true, 128),
        "ping-less zone DENIES icmpv6 echo-request"
    );

    // ping zone (id 32) admits echo-request on both families.
    assert!(
        host_inbound_admits(&state, 32, 1, 0, false, 8),
        "ping zone admits icmp echo-request"
    );
    assert!(
        host_inbound_admits(&state, 32, 58, 0, true, 128),
        "ping zone admits icmpv6 echo-request"
    );
}

// #3201/#3240: host-inbound ICMP admission is SUBTYPE-specific and matches the
// nft chain (`pkg/daemon/daemon_nft.go`) exactly — a service admits ONLY the
// ICMP types it implies, not the whole ICMP/ICMPv6 protocol:
//   ping            → echo-request (v4 8 / v6 128)
//   router-discovery → IPv4 router-advert/solicit (9/10); v6 via global ND
// Error/PMTUD (#3171) and IPv6 ND (133-137) ride the global accept on any
// configured zone.
//
// Fail-on-revert: restoring the protocol-wide `icmp = true` (admitting ANY
// ICMP type whenever `ping`/`router-discovery` is set) turns the
// "ping drops timestamp-request" and "router-discovery drops echo" assertions
// RED (they would over-admit), while every admit assertion stays GREEN.
#[test]
fn build_forwarding_state_host_inbound_icmp_subtype_parity() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::host_inbound_admits;

    let snapshot = ConfigSnapshot {
        zones: vec![
            // ping zone: echo-request only.
            ZoneSnapshot {
                name: "ping-zone".into(),
                id: 51,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ping".into()],
                host_inbound_protocols: vec![],
                ..Default::default()
            },
            // router-discovery zone: IPv4 types 9/10 only; NO ping.
            ZoneSnapshot {
                name: "rd-zone".into(),
                id: 52,
                host_inbound_configured: true,
                host_inbound_system_services: vec![],
                host_inbound_protocols: vec!["router-discovery".into()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    // ping zone (51): admits echo-request (8 v4 / 128 v6) ...
    assert!(
        host_inbound_admits(&state, 51, 1, 0, false, 8),
        "ping admits icmp echo-request"
    );
    assert!(
        host_inbound_admits(&state, 51, 58, 0, true, 128),
        "ping admits icmpv6 echo-request"
    );
    // ... but DROPS a random non-echo ICMP type (13 = timestamp-request) — the
    // #3201 over-admission the protocol-wide `icmp=true` allowed.
    assert!(
        !host_inbound_admits(&state, 51, 1, 0, false, 13),
        "ping DROPS icmp timestamp-request"
    );
    // ... and DROPS IPv4 router-advertisement (9) — that is router-discovery's
    // subtype, not ping's.
    assert!(
        !host_inbound_admits(&state, 51, 1, 0, false, 9),
        "ping DROPS icmp router-advertisement"
    );
    // ICMP errors (#3171) are still globally admitted on the ping zone.
    assert!(
        host_inbound_admits(&state, 51, 1, 0, false, 3),
        "ping zone still admits icmp destination-unreachable (global)"
    );

    // router-discovery zone (52): admits IPv4 router-advert (9) + solicit (10) ...
    assert!(
        host_inbound_admits(&state, 52, 1, 0, false, 9),
        "router-discovery admits icmp router-advertisement (9)"
    );
    assert!(
        host_inbound_admits(&state, 52, 1, 0, false, 10),
        "router-discovery admits icmp router-solicitation (10)"
    );
    // ... but DROPS echo-request (8) — that is ping's subtype, not
    // router-discovery's (the #3240 over-admission).
    assert!(
        !host_inbound_admits(&state, 52, 1, 0, false, 8),
        "router-discovery DROPS icmp echo-request (#3240)"
    );
    assert!(
        !host_inbound_admits(&state, 52, 58, 0, true, 128),
        "router-discovery DROPS icmpv6 echo-request"
    );
    // v6 RS/RA (133/134) reach the host via the global ND accept on ANY
    // configured zone — matching nft, which returns nil for v6 router-discovery
    // and relies on the global ND accept.
    assert!(
        host_inbound_admits(&state, 52, 58, 0, true, 133),
        "router-discovery zone admits icmpv6 router-solicitation (global ND)"
    );
    assert!(
        host_inbound_admits(&state, 52, 58, 0, true, 134),
        "router-discovery zone admits icmpv6 router-advertisement (global ND)"
    );

    // A service NOT configured drops its ICMP types: a router-discovery-only
    // zone does not admit echo (asserted above); a ping-only zone does not admit
    // router-advert (asserted above). Neither zone is `all`, so a non-listed
    // ICMP type is denied — defense-in-depth parity with the nft type set.
    assert!(
        !host_inbound_admits(&state, 52, 1, 0, false, 13),
        "router-discovery DROPS icmp timestamp-request"
    );
}

// #3199: `host-inbound-traffic protocols all` admits only the ROUTING-protocol
// set — it must NOT open system-services (SSH/HTTPS/SNMP/...) on the box. This
// is the Junos meaning of `protocols all` (all entries under the `protocols`
// stanza), not a blanket bypass of the host-inbound gate.
//
// Fail-on-revert: restoring the old `"all" => hi.all_protocols = true` classifier
// + the `|| self.all_protocols` short-circuit in `ZoneHostInbound::admits`
// turns the "protocols-all ssh deny" assertions RED (the zone admits everything
// again).
#[test]
fn build_forwarding_state_protocols_all_admits_routing_not_system_services() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::host_inbound_admits;

    let snapshot = ConfigSnapshot {
        zones: vec![
            // routing zone: `protocols all`, NO system-services.
            ZoneSnapshot {
                name: "routing".into(),
                id: 21,
                host_inbound_configured: true,
                host_inbound_system_services: vec![],
                host_inbound_protocols: vec!["all".into()],
                ..Default::default()
            },
            // mgmt zone: explicit `system-services ssh` — regression guard.
            ZoneSnapshot {
                name: "mgmt".into(),
                id: 22,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ssh".into()],
                host_inbound_protocols: vec![],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    // routing (id 21): `protocols all` admits routing protocols of every kind.
    assert!(
        host_inbound_admits(&state, 21, 89, 0, false, 0),
        "protocols all admits ospf (proto 89)"
    );
    assert!(
        host_inbound_admits(&state, 21, 6, 179, false, 0),
        "protocols all admits bgp (tcp/179)"
    );
    assert!(
        host_inbound_admits(&state, 21, 112, 0, false, 0),
        "protocols all admits vrrp (proto 112)"
    );
    assert!(
        host_inbound_admits(&state, 21, 17, 520, false, 0),
        "protocols all admits rip (udp/520)"
    );
    // ...but NOT system-services: SSH, HTTPS, SNMP must be DENIED.
    assert!(
        !host_inbound_admits(&state, 21, 6, 22, false, 0),
        "protocols all must NOT admit ssh (tcp/22)"
    );
    assert!(
        !host_inbound_admits(&state, 21, 6, 443, false, 0),
        "protocols all must NOT admit https (tcp/443)"
    );
    assert!(
        !host_inbound_admits(&state, 21, 17, 161, false, 0),
        "protocols all must NOT admit snmp (udp/161)"
    );

    // mgmt (id 22): explicit ssh still admits ssh (regression), denies https.
    assert!(
        host_inbound_admits(&state, 22, 6, 22, false, 0),
        "system-services ssh admits ssh"
    );
    assert!(
        !host_inbound_admits(&state, 22, 6, 443, false, 0),
        "system-services ssh does not admit https"
    );
}

// #3225: host-inbound service/protocol matches must be ADDRESS-FAMILY AWARE. A
// v4-only service (dhcp) must admit its ports on IPv4 but DROP the same ports on
// IPv6; a v6-only service (dhcpv6) / protocol (ripng, ospf3) must admit on IPv6
// and DROP on IPv4; a dual-family service (ssh) admits on BOTH. Before #3225 the
// admit sets were family-neutral, so a v4-only `dhcp` opened udp/67-68 on the
// IPv6 path and `ripng` opened udp/521 on IPv4 — wrong-family host exposure.
//
// Fail-on-revert: restore the family-neutral classifier (insert dhcp into the
// shared `udp_ports`, ospf/ospf3 into the shared `ip_protocols`, etc.) and the
// "v4-only service drops on v6" / "v6-only drops on v4" assertions go RED (the
// zone admits the wrong family again); the dual-service ssh assertions stay
// GREEN.
#[test]
fn build_forwarding_state_host_inbound_is_address_family_aware() {
    use crate::ZoneSnapshot;
    use crate::afxdp::forwarding::host_inbound_admits;

    let snapshot = ConfigSnapshot {
        zones: vec![
            // v4-only services + v4-only routing protocols.
            ZoneSnapshot {
                name: "v4svc".into(),
                id: 41,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["dhcp".into()],
                host_inbound_protocols: vec!["rip".into(), "ospf".into()],
                ..Default::default()
            },
            // v6-only services + v6-only routing protocols.
            ZoneSnapshot {
                name: "v6svc".into(),
                id: 42,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["dhcpv6".into()],
                host_inbound_protocols: vec!["ripng".into(), "ospf3".into()],
                ..Default::default()
            },
            // dual-family service (ssh) — admits on BOTH families.
            ZoneSnapshot {
                name: "dual".into(),
                id: 43,
                host_inbound_configured: true,
                host_inbound_system_services: vec!["ssh".into()],
                host_inbound_protocols: vec![],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    // v4svc (id 41): dhcp udp/67-68 + rip udp/520 + ospf proto 89 admit on IPv4.
    assert!(
        host_inbound_admits(&state, 41, 17, 67, false, 0),
        "dhcp admits udp/67 on IPv4"
    );
    assert!(
        host_inbound_admits(&state, 41, 17, 520, false, 0),
        "rip admits udp/520 on IPv4"
    );
    assert!(
        host_inbound_admits(&state, 41, 89, 0, false, 0),
        "ospf admits proto 89 on IPv4"
    );
    // ...but the SAME ports/proto must be DENIED on IPv6 (wrong family).
    assert!(
        !host_inbound_admits(&state, 41, 17, 67, true, 0),
        "dhcp (v4-only) must NOT admit udp/67 on IPv6"
    );
    assert!(
        !host_inbound_admits(&state, 41, 17, 520, true, 0),
        "rip (v4-only) must NOT admit udp/520 on IPv6"
    );
    assert!(
        !host_inbound_admits(&state, 41, 89, 0, true, 0),
        "ospf (v4-only OSPFv2) must NOT admit proto 89 on IPv6"
    );

    // v6svc (id 42): dhcpv6 udp/546-547 + ripng udp/521 + ospf3 proto 89 admit
    // on IPv6.
    assert!(
        host_inbound_admits(&state, 42, 17, 546, true, 0),
        "dhcpv6 admits udp/546 on IPv6"
    );
    assert!(
        host_inbound_admits(&state, 42, 17, 521, true, 0),
        "ripng admits udp/521 on IPv6"
    );
    assert!(
        host_inbound_admits(&state, 42, 89, 0, true, 0),
        "ospf3 admits proto 89 on IPv6"
    );
    // ...but DENIED on IPv4.
    assert!(
        !host_inbound_admits(&state, 42, 17, 546, false, 0),
        "dhcpv6 (v6-only) must NOT admit udp/546 on IPv4"
    );
    assert!(
        !host_inbound_admits(&state, 42, 17, 521, false, 0),
        "ripng (v6-only) must NOT admit udp/521 on IPv4"
    );
    assert!(
        !host_inbound_admits(&state, 42, 89, 0, false, 0),
        "ospf3 (v6-only OSPFv3) must NOT admit proto 89 on IPv4"
    );

    // dual (id 43): ssh admits on BOTH families (unchanged dual-family).
    assert!(
        host_inbound_admits(&state, 43, 6, 22, false, 0),
        "ssh admits tcp/22 on IPv4"
    );
    assert!(
        host_inbound_admits(&state, 43, 6, 22, true, 0),
        "ssh admits tcp/22 on IPv6"
    );
}

#[test]
fn build_forwarding_state_disables_tx_selection_when_no_cos_or_filters_exist() {
    let state = build_forwarding_state(&ConfigSnapshot::default());
    assert!(!state.tx_selection_enabled_v4);
    assert!(!state.tx_selection_enabled_v6);
}

#[test]
fn build_forwarding_state_enables_tx_selection_when_cos_interfaces_exist() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be-sched".into(),
                transmit_rate_bytes: 10_000_000,
                transmit_rate_percent: 0.0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be-sched".into(),
                }],
            }],
            ..Default::default()
        }),
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    assert!(state.tx_selection_enabled_v4);
    assert!(state.tx_selection_enabled_v6);
}

/// #6236 PR-2A parent-RED: a counter-only OUTPUT filter (no CoS interface, no
/// input filter, no `then forwarding-class`/`dscp`, no terminal action) MUST
/// still enable the family-wide TX gate, because `Filter::needs_tx_eval()`
/// covers `then count`. The rewritten gate reads the `has_output_needs_tx_eval_*`
/// aggregate = `values().any(needs_tx_eval)` over the FINAL output fast map.
///
/// Drop `has_counter_terms` from `Filter::needs_tx_eval()` and this fails RED:
/// the aggregate clears, the gate disables, and this counter-only filter's
/// `then count` would silently stop being enforced on the TX path. It also pins
/// that the new single aggregate subsumes the OLD two-clause gate — the old
/// `affects_tx_selection` clause is `false` here (counter-only), so only the
/// `needs_tx_eval` superset keeps the gate armed.
#[test]
fn build_forwarding_state_enables_tx_selection_for_counter_only_output_filter() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 7,
            filter_output_v4: "wan-count".into(),
            ..Default::default()
        }],
        filters: vec![FirewallFilterSnapshot {
            name: "wan-count".into(),
            family: "inet".into(),
            terms: vec![FirewallTermSnapshot {
                name: "tally".into(),
                action: "accept".into(),
                count: "wan-bytes".into(),
                ..Default::default()
            }],
        }],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    // affects_tx_selection is false (no forwarding-class / dscp-rewrite), so the
    // OLD has_output_tx_selection clause does NOT arm the gate — only the
    // needs_tx_eval superset (which covers `then count`) does.
    // #6236 PR-2B: `has_output_tx_selection_v4` is deleted; read the
    // `affects_tx_selection` flag off the output fast-map filter to make the
    // same point — a counter-only filter does not affect tx-selection.
    assert!(
        !state
            .filter_state
            .iface_filter_out_v4_fast
            .get(&7)
            .is_some_and(|f| f.affects_tx_selection),
        "counter-only filter does not affect tx-selection"
    );
    assert!(
        state.filter_state.has_output_needs_tx_eval_v4,
        "counter-only output filter needs a TX-path walk"
    );
    assert!(
        state.tx_selection_enabled_v4,
        "global TX gate must stay armed for a counter-only output filter"
    );
    // v6 has no output filter → the gate stays disabled (no fail-open on the
    // other family).
    assert!(!state.tx_selection_enabled_v6);
}

/// #6236 PR-2A/2B equivalence: on a NORMAL (unique-ifindex) compiled state the
/// `has_output_needs_tx_eval_*` aggregate is bit-equivalent to the OLD two-clause
/// gate it replaced — `has_output_tx_selection_* OR !needs_tx_eval-set.is_empty()`.
/// PR-2B deleted both `has_output_tx_selection_*` and the
/// `iface_filter_out_*_needs_tx_eval` sets, so the two original clauses are
/// reconstructed here independently from the retained output fast maps (an
/// `affects_tx_selection` scan for the first clause, a `needs_tx_eval()` scan for
/// the second). Exercises a mix of output-filter shapes (tx-selection,
/// counter-only, terminal-only, and plain accept).
#[test]
fn has_output_needs_tx_eval_matches_old_two_clause_gate() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                ifindex: 10,
                filter_output_v4: "cos".into(),
                filter_output_v6: "count6".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                ifindex: 11,
                filter_output_v4: "deny".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                ifindex: 12,
                filter_output_v4: "plain".into(),
                filter_output_v6: "plain6".into(),
                ..Default::default()
            },
        ],
        filters: vec![
            FirewallFilterSnapshot {
                name: "cos".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "mark".into(),
                    action: "accept".into(),
                    forwarding_class: "expedited".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "count6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "tally".into(),
                    action: "accept".into(),
                    count: "c6".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "deny".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "drop".into(),
                    action: "discard".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "plain".into(),
                family: "inet".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "ok".into(),
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
            FirewallFilterSnapshot {
                name: "plain6".into(),
                family: "inet6".into(),
                terms: vec![FirewallTermSnapshot {
                    name: "ok".into(),
                    action: "accept".into(),
                    ..Default::default()
                }],
            },
        ],
        ..Default::default()
    };

    let fs = build_forwarding_state(&snapshot).filter_state;
    // #6236 PR-2B: reconstruct the two original clauses from the retained output
    // fast maps — clause 1 = old `has_output_tx_selection_*` (any output filter
    // affects tx-selection); clause 2 = old `!needs_tx_eval-set.is_empty()` (any
    // output filter needs a TX walk).
    let old_gate_v4 = fs
        .iface_filter_out_v4_fast
        .values()
        .any(|f| f.affects_tx_selection)
        || fs
            .iface_filter_out_v4_fast
            .values()
            .any(|f| f.needs_tx_eval());
    let old_gate_v6 = fs
        .iface_filter_out_v6_fast
        .values()
        .any(|f| f.affects_tx_selection)
        || fs
            .iface_filter_out_v6_fast
            .values()
            .any(|f| f.needs_tx_eval());
    assert_eq!(
        fs.has_output_needs_tx_eval_v4, old_gate_v4,
        "new v4 aggregate must equal the old two-clause gate"
    );
    assert_eq!(
        fs.has_output_needs_tx_eval_v6, old_gate_v6,
        "new v6 aggregate must equal the old two-clause gate"
    );
    // Sanity: the mix actually exercises a true aggregate on both families
    // (a tx-selection filter on v4, a counter-only filter on v6).
    assert!(fs.has_output_needs_tx_eval_v4);
    assert!(fs.has_output_needs_tx_eval_v6);
}

/// #3075 fail-on-revert: a stable name-hash zone id > 255 (the common case) MUST
/// be admitted to the forwarding zone table now that the event-stream wire is
/// u16 — the former >u8::MAX skip is retired. Restoring that skip drops the zone
/// from zone_name_to_id / zone_id_to_name and this fails RED. The reserved-range
/// reject (next test) is unaffected.
#[test]
fn build_forwarding_state_admits_zone_id_above_255() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            // The stable name-hash of "trust" (config.StableZoneID) is 50675.
            name: "trust".into(),
            id: 50675,
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.zone_name_to_id.get("trust").copied(), Some(50675));
    assert_eq!(
        state.zone_id_to_name.get(&50675).map(String::as_str),
        Some("trust")
    );
}

/// #919/#922: any zone with id ≥ ZONE_ID_RESERVED_MIN must be
/// dropped at config-build time so a hostile/buggy snapshot cannot
/// collide with the JUNOS_GLOBAL_ZONE_ID sentinel (u16::MAX).
#[test]
fn build_forwarding_state_rejects_reserved_zone_ids() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "ok".into(),
                id: 5,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "reserved-edge".into(),
                id: crate::policy::ZONE_ID_RESERVED_MIN,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "global-sentinel".into(),
                id: crate::policy::JUNOS_GLOBAL_ZONE_ID,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.zone_name_to_id.get("ok").copied(), Some(5));
    assert!(state.zone_name_to_id.get("reserved-edge").is_none());
    assert!(state.zone_name_to_id.get("global-sentinel").is_none());
    assert!(
        state
            .zone_id_to_name
            .get(&crate::policy::ZONE_ID_RESERVED_MIN)
            .is_none()
    );
    assert!(
        state
            .zone_id_to_name
            .get(&crate::policy::JUNOS_GLOBAL_ZONE_ID)
            .is_none()
    );
}

/// #3719 (H03/L04): two DIFFERENT zones carrying the same nonzero non-reserved
/// id must fail the snapshot CLOSED before any id-keyed map is populated —
/// otherwise populate_zones lets the later zone overwrite the earlier's
/// zone_id_to_name / host-inbound / tcp-rst entries, merging two security zones.
/// The Go control plane quarantines the collision before the wire; this is the
/// helper-boundary backstop. Removing reject_duplicate_zone_ids (or its call in
/// build_forwarding_state) turns this RED — the build succeeds and one id maps
/// to a single merged zone.
#[test]
fn build_forwarding_state_rejects_duplicate_zone_ids() {
    use crate::ZoneSnapshot;
    // z174 and z214 both fold to config.StableZoneID 53547 (the verified
    // collision pair); here we stamp the shared id explicitly.
    let snapshot = ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "z174".into(),
                id: 53547,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "z214".into(),
                id: 53547,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("two zones sharing a numeric id must fail closed");
    match err {
        crate::policy::SnapshotIntegrityError::DuplicateZoneId { id, first, second } => {
            assert_eq!(id, 53547);
            assert_eq!(first, "z174");
            assert_eq!(second, "z214");
        }
        other => panic!("expected DuplicateZoneId, got {other:?}"),
    }
}

/// #3719: a zone id repeated only within the RESERVED range (or with id 0) is
/// skipped by populate_zones and must NOT be treated as a collision — the gate
/// mirrors populate_zones' skip set, so it must not over-reject.
#[test]
fn build_forwarding_state_reserved_duplicate_ids_are_not_collisions() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "resv-a".into(),
                id: crate::policy::ZONE_ID_RESERVED_MIN,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "resv-b".into(),
                id: crate::policy::ZONE_ID_RESERVED_MIN,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "ok".into(),
                id: 7,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    // Both reserved zones are skipped (never installed); "ok" builds cleanly.
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.zone_name_to_id.get("ok").copied(), Some(7));
    assert!(state.zone_name_to_id.get("resv-a").is_none());
    assert!(state.zone_name_to_id.get("resv-b").is_none());
}

/// #3719 review MAJOR: a scoped `junos-global` policy carries its concrete
/// match-zone out-of-band in `match_from_zone`/`match_to_zone`. If the Go
/// quarantine's match-zone scrub were reverted, a global policy referencing the
/// QUARANTINED (dropped) zone would reach the helper with a dangling match-zone;
/// `build_global_zone_scope` resolves it against the published zone table, misses,
/// and returns `UnresolvableZoneReference` (#3402), which propagates via `?` and
/// rejects the WHOLE snapshot — a fresh-boot brick, the exact failure the
/// quarantine exists to prevent. This pins that boundary behavior: the Go scrub
/// MUST drop such a policy so this dangling reference never reaches the wire.
#[test]
fn build_forwarding_state_global_policy_with_unresolvable_match_zone_bricks() {
    let snapshot = ConfigSnapshot {
        // z214 was quarantined/dropped; only the survivor z174 is published.
        zones: vec![crate::ZoneSnapshot {
            name: "z174".into(),
            id: 53547,
            ..Default::default()
        }],
        policies: vec![crate::PolicyRuleSnapshot {
            name: "g-scoped-quarantined".into(),
            from_zone: "junos-global".into(),
            to_zone: "junos-global".into(),
            match_from_zone: "z214".into(), // dangling — not in the zone table
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            action: "permit".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("a dangling global match-zone must fail the snapshot closed");
    match err {
        crate::policy::SnapshotIntegrityError::UnresolvableZoneReference { zone, .. } => {
            assert_eq!(zone, "z214");
        }
        other => panic!("expected UnresolvableZoneReference, got {other:?}"),
    }
}

/// The clean post-quarantine shape: the z214-scoped global policy was dropped by
/// the Go quarantine, leaving only a global policy scoped to the SURVIVING zone
/// z174. `build_forwarding_state` resolves it and builds with no
/// `SnapshotIntegrityError` — no brick. Together with the test above this is the
/// end-to-end guard: the scrubbed snapshot builds; the un-scrubbed one rejects.
#[test]
fn build_forwarding_state_global_policy_scoped_to_published_zone_builds() {
    let snapshot = ConfigSnapshot {
        zones: vec![crate::ZoneSnapshot {
            name: "z174".into(),
            id: 53547,
            ..Default::default()
        }],
        policies: vec![crate::PolicyRuleSnapshot {
            name: "g-scoped-survivor".into(),
            from_zone: "junos-global".into(),
            to_zone: "junos-global".into(),
            match_from_zone: "z174".into(),
            source_addresses: vec!["any".into()],
            destination_addresses: vec!["any".into()],
            applications: vec!["any".into()],
            action: "permit".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect("a global policy scoped to a published zone must build without a brick");
    assert_eq!(state.zone_name_to_id.get("z174").copied(), Some(53547));
}

/// #921: ifindex_to_zone_id is populated at config build time
/// from the snapshot's per-interface zone NAME via zone_name_to_id.
#[test]
fn ifindex_to_zone_id_populated_from_snapshot_at_build_time() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 7,
            ..Default::default()
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/0".into(),
            zone: "trust".into(),
            ifindex: 42,
            hardware_addr: "02:00:00:00:00:42".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.ifindex_to_zone_id.get(&42).copied(), Some(7));
}

/// #7025: `EgressInterface::zone_id` is a MIRROR of
/// `ifindex_unambiguous_zone_id`, and must stay one.
///
/// The field has no production reader in a default build — deleting it yields
/// seven `E0609` reads, all in test files; `--features debug-log` adds exactly
/// one, the `FWD_STATE: egress[..]` dump. It is retained so that debug line is
/// self-describing, and this cell is what stops it from becoming the "stale
/// copy that looks like a second opinion" #7025 was filed about: a future edit
/// that sources it from anywhere but the ledger reds here.
///
/// THE TABLE NEEDS BOTH ROWS. A fixture whose interfaces all resolve to zone 0
/// cannot distinguish a correct mirror from a field hardcoded to 0 — every
/// comparison passes. So the snapshot carries a ZONED interface (non-zero) and
/// an UNZONED one (zero), and the cell asserts both cases occur before
/// comparing.
///
/// WHAT IT CATCHES, MEASURED — and what it does NOT, which matters more.
///
/// Severing the mirror (`zone_id` hardcoded to 0) reds this cell. It also reds
/// FOUR pre-existing tests, so on that mutation this cell is not the only guard.
///
/// Re-pointing `populate_egress` at the row-derived `ifindex_to_zone_id` — the
/// map #6722 replaced, and the realistic regression — reds two pre-existing
/// tests (`unzoned_iface_tunnel_unit_does_not_inherit_a_siblings_zone_via_egress_row_6722`
/// and `unzoned_interface_with_egress_row_stays_zone_zero_6713`) and does NOT
/// red this one. That is a property of the FIXTURE: the two maps agree for both
/// interfaces here, so the mutation is a no-op on this input. An earlier
/// revision of this comment claimed the opposite; it was measured and was
/// wrong, and it is recorded rather than quietly corrected because a guard's
/// stated scope is a claim like any other.
///
/// So what this cell adds is not extra coverage of those two mutations — it is
/// the STRUCTURAL invariant, asserted over every egress row rather than over a
/// fixture's expected zone values. The pre-existing tests pin what specific
/// interfaces should resolve to; this pins that the field and
/// `egress_zone_id()` can never disagree, which is the property the doc on the
/// field promises a reader.
#[test]
fn egress_zone_id_mirrors_the_unambiguous_ledger_7025() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".into(),
            id: 11,
            ..Default::default()
        }],
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/1".into(),
                zone: "wan".into(),
                egress_zone: "wan".into(),
                ifindex: 99,
                hardware_addr: "02:00:00:00:00:99".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/2".into(),
                ifindex: 77,
                hardware_addr: "02:00:00:00:00:77".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);

    // Precondition: BOTH cases are present, or the comparison below is
    // satisfied by everything being zero.
    let zoned = state.egress.get(&99).expect("zoned egress row");
    let unzoned = state.egress.get(&77).expect("unzoned egress row");
    assert_ne!(
        zoned.zone_id, 0,
        "fixture invalid: the zoned interface resolved to zone 0, so this cell \
         would compare 0 against 0 for every row and pass against a field \
         hardcoded to 0 (#7025)"
    );
    assert_eq!(
        unzoned.zone_id, 0,
        "fixture invalid: the unzoned interface must resolve to 0, so the table \
         covers both sides of the mirror"
    );

    for (ifidx, eg) in &state.egress {
        assert_eq!(
            eg.zone_id,
            state.egress_zone_id(*ifidx),
            "EgressInterface::zone_id for ifindex {ifidx} disagrees with \
             ForwardingState::egress_zone_id. The field is a DEBUG-ONLY MIRROR of \
             ifindex_unambiguous_zone_id (#7025) and the debug dump renders a \
             zone name from it — a divergence prints a zone the dataplane is not \
             using, which is worse than printing nothing"
        );
    }
}

/// #921: EgressInterface.zone_id is set from the snapshot at
/// config build time.
#[test]
fn egress_interface_zone_id_set_from_snapshot() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "wan".into(),
            id: 11,
            ..Default::default()
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/1".into(),
            zone: "wan".into(),
            // #6722: the EGRESS zone is decided by the Go builder and carried
            // here; the helper does not re-derive it from `zone`. A snapshot
            // that omits it is one the v5 contract cannot carry.
            egress_zone: "wan".into(),
            ifindex: 99,
            hardware_addr: "02:00:00:00:00:99".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let eg = state.egress.get(&99).expect("egress");
    assert_eq!(eg.zone_id, 11);
}

/// #2391: an interface whose zone snapshot field references a zone that was
/// DROPPED at config build time (reserved id) must FAIL CLOSED — the forwarding
/// build returns InterfaceUnknownZone instead of silently collapsing the
/// interface to zone_id == 0 (which would bypass every zone-pair policy).
/// fail-on-revert: restoring the `unwrap_or(0)` collapse makes this red.
/// (#3075 retired the separate >u8::MAX drop; the reserved-range drop remains.)
#[test]
fn interface_pointing_at_skipped_zone_fails_closed() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "reserved".into(),
            id: crate::policy::ZONE_ID_RESERVED_MIN, // dropped at populate_zones
            ..Default::default()
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/2".into(),
            zone: "reserved".into(),
            ifindex: 23,
            hardware_addr: "02:00:00:00:00:23".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("interface referencing a dropped zone must fail closed");
    match err {
        crate::policy::SnapshotIntegrityError::InterfaceUnknownZone { interface, zone } => {
            assert_eq!(interface, "ge-0/0/2");
            assert_eq!(zone, "reserved");
        }
        other => panic!("expected InterfaceUnknownZone, got {other:?}"),
    }
}

/// #2391: an interface whose snapshot zone string isn't in the zones list at all
/// (a typo / version-drifted snapshot) fails CLOSED rather than collapsing the
/// EgressInterface to zone_id == 0.
#[test]
fn interface_with_unknown_zone_name_fails_closed() {
    use crate::ZoneSnapshot;
    let snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 3,
            ..Default::default()
        }],
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/3".into(),
            zone: "ghost".into(), // not in zones
            ifindex: 56,
            hardware_addr: "02:00:00:00:00:56".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("interface referencing an unknown zone must fail closed");
    assert!(matches!(
        err,
        crate::policy::SnapshotIntegrityError::InterfaceUnknownZone { .. }
    ));
}

/// #2391 anti-over-reject: an interface with NO zone (empty string) is the
/// legitimate "unzoned" case and must still build, mapping to zone_id == 0.
#[test]
fn interface_with_empty_zone_builds_with_zone_zero() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/4".into(),
            zone: String::new(), // unzoned
            ifindex: 77,
            hardware_addr: "02:00:00:00:00:77".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    let eg = state.egress.get(&77).expect("egress");
    assert_eq!(eg.zone_id, 0);
    // unzoned interfaces are not inserted into ifindex_to_zone_id
    assert!(state.ifindex_to_zone_id.get(&77).is_none());
}

// ---------------------------------------------------------------------
// #3771: route / neighbor wire-struct integrity guards. A route whose
// `family` contradicts its destination prefix (M4), a route with a
// negative preference (L1), and a neighbor whose `family` contradicts its
// IP (M11) all fail the snapshot CLOSED; a neighbor with an unknown state
// (M12) is skipped + counted rather than installed.
// ---------------------------------------------------------------------

/// #3771 (M4): a route declaring family="inet6" with an IPv4 destination fails
/// the snapshot CLOSED via `RouteFamilyMismatch`. fail-on-revert: restoring the
/// parse-only `populate_routes` installs it into routes_v4 (ignoring `family`)
/// and the build succeeds, making this `expect_err` red.
#[test]
fn route_family_contradicts_destination_fails_closed() {
    let snapshot = ConfigSnapshot {
        routes: vec![crate::RouteSnapshot {
            table: "inet6.0".into(),
            family: "inet6".into(),           // claims IPv6
            destination: "10.0.0.0/8".into(), // ...but is IPv4
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("route family/destination mismatch must fail closed");
    match err {
        crate::policy::SnapshotIntegrityError::RouteFamilyMismatch {
            table,
            destination,
            family,
        } => {
            assert_eq!(table, "inet6.0");
            assert_eq!(destination, "10.0.0.0/8");
            assert_eq!(family, "inet6");
        }
        other => panic!("expected RouteFamilyMismatch, got {other:?}"),
    }

    // The symmetric case: family="inet" with an IPv6 destination.
    let snapshot_v6 = ConfigSnapshot {
        routes: vec![crate::RouteSnapshot {
            table: "inet.0".into(),
            family: "inet".into(),               // claims IPv4
            destination: "2001:db8::/32".into(), // ...but is IPv6
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(matches!(
        try_build_forwarding_state_with_policy_counters(
            &snapshot_v6,
            &crate::policy::PolicyCounterStore::default(),
        ),
        Err(crate::policy::SnapshotIntegrityError::RouteFamilyMismatch { .. })
    ));
}

/// #6568 (member 1): a route whose destination parses as NEITHER family fails
/// the snapshot CLOSED via `RouteDestinationUnparseable`.
///
/// This was a SILENT skip — no Err, no counter, no log — at a boundary whose
/// whole #2409/#2410/#3771 contract is "no silent skips". The cohort filed it
/// as a low-materiality residual with "no traffic fail-open"; measured, both
/// halves are wrong. `ipnet`'s parsers REQUIRE a prefix length, so a bare host
/// address is exactly the input that vanished — and for a `discard`/`reject`
/// route the vanishing is a FAIL-OPEN: with no blackhole entry the packet
/// longest-prefix matches a LESS-SPECIFIC route (typically the default) and is
/// FORWARDED where the operator asked for it to be dropped.
///
/// fail-on-revert: restore the fall-through (delete the trailing `return
/// Err(...)`) and the build succeeds, making these `expect_err`s red.
#[test]
fn route_destination_unparseable_fails_closed() {
    // A BARE HOST ADDRESS: legal-looking operator input, no prefix length.
    for (table, dest) in [
        ("inet.0", "10.0.0.1"),
        ("inet6.0", "2001:db8::1"),
        // The Junos `default` keyword, which the Go config compiler accepts
        // verbatim as a destination.
        ("inet.0", "default"),
        ("inet.0", "not-an-address"),
    ] {
        let snapshot = ConfigSnapshot {
            routes: vec![crate::RouteSnapshot {
                table: table.into(),
                destination: dest.into(),
                discard: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = try_build_forwarding_state_with_policy_counters(
            &snapshot,
            &crate::policy::PolicyCounterStore::default(),
        )
        .expect_err("an unparseable destination must fail the snapshot CLOSED");
        match err {
            crate::policy::SnapshotIntegrityError::RouteDestinationUnparseable {
                table: got_table,
                destination,
            } => {
                assert_eq!(got_table, table);
                assert_eq!(destination, dest);
            }
            other => panic!("destination {dest:?}: expected RouteDestinationUnparseable, got {other:?}"),
        }
    }
}

/// #6568 (member 1) anti-over-reject: every destination shape the Go producer
/// can legitimately emit still builds. Without this, a gate that rejected
/// EVERYTHING would satisfy the fail-closed test above while breaking all
/// forwarding.
#[test]
fn route_destination_valid_prefixes_still_build() {
    let snapshot = ConfigSnapshot {
        routes: vec![
            crate::RouteSnapshot {
                table: "inet.0".into(),
                destination: "10.9.0.0/16".into(),
                ..Default::default()
            },
            crate::RouteSnapshot {
                table: "inet.0".into(),
                destination: "0.0.0.0/0".into(),
                ..Default::default()
            },
            crate::RouteSnapshot {
                table: "inet.0".into(),
                // The /32 host prefix the Go producer now emits for a bare
                // host address — the shape that replaces the silent drop.
                destination: "10.0.0.1/32".into(),
                discard: true,
                ..Default::default()
            },
            crate::RouteSnapshot {
                table: "inet6.0".into(),
                destination: "2001:db8::/64".into(),
                ..Default::default()
            },
            crate::RouteSnapshot {
                table: "inet6.0".into(),
                destination: "2001:db8::1/128".into(),
                discard: true,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect("every valid prefix shape must still build");
}

/// #3771 (M4) anti-over-reject: a route whose `family` AGREES with its
/// destination builds, and an EMPTY `family` (older / omitted producer) is
/// unconstrained and also builds (parse-only, the pre-fix behaviour).
#[test]
fn route_family_matching_or_empty_builds() {
    let snapshot = ConfigSnapshot {
        routes: vec![
            crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "10.0.0.0/8".into(),
                next_hops: vec!["192.0.2.1".into()],
                ..Default::default()
            },
            crate::RouteSnapshot {
                table: "inet6.0".into(),
                family: "inet6".into(),
                destination: "2001:db8::/32".into(),
                next_hops: vec!["2001:db8::1".into()],
                ..Default::default()
            },
            // Empty family — unconstrained, must not be rejected.
            crate::RouteSnapshot {
                table: "inet.0".into(),
                family: String::new(),
                destination: "172.16.0.0/12".into(),
                next_hops: vec!["192.0.2.2".into()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect("matching / empty family routes must build");
    let v4 = state.routes_v4.get("inet.0").expect("v4 table");
    assert_eq!(v4.len(), 2, "both v4 routes install");
    let v6 = state.routes_v6.get("inet6.0").expect("v6 table");
    assert_eq!(v6.len(), 1, "the v6 route installs");
}

/// #3771 (L1): a route with a NEGATIVE preference fails the snapshot CLOSED via
/// `RoutePreferenceOutOfRange`. fail-on-revert: removing the preference guard
/// installs the route with i32::MIN preference (sorting ahead of every route)
/// and the build succeeds, making this `expect_err` red.
#[test]
fn route_negative_preference_fails_closed() {
    let snapshot = ConfigSnapshot {
        routes: vec![crate::RouteSnapshot {
            table: "inet.0".into(),
            family: "inet".into(),
            destination: "0.0.0.0/0".into(),
            next_hops: vec!["192.0.2.1".into()],
            preference: i32::MIN,
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("a negative route preference must fail closed");
    match err {
        crate::policy::SnapshotIntegrityError::RoutePreferenceOutOfRange {
            destination,
            preference,
            ..
        } => {
            assert_eq!(destination, "0.0.0.0/0");
            assert_eq!(preference, i32::MIN);
        }
        other => panic!("expected RoutePreferenceOutOfRange, got {other:?}"),
    }
}

/// #3771 (L1) anti-over-reject: preference 0 (the most-preferred value) and a
/// normal positive preference both build.
#[test]
fn route_nonnegative_preference_builds() {
    let snapshot = ConfigSnapshot {
        routes: vec![
            crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "10.0.0.0/8".into(),
                next_hops: vec!["192.0.2.1".into()],
                preference: 0,
                ..Default::default()
            },
            crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "172.16.0.0/12".into(),
                next_hops: vec!["192.0.2.2".into()],
                preference: 100,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect("non-negative preferences must build");
}

// ---------------------------------------------------------------------
// #4446: static bare-gateway next-hop ifindex inference is table-scoped.
// A bare-gateway static route infers its egress ifindex ONLY from a
// connected prefix in the route's OWN routing-instance table, never a
// different instance's overlapping connected prefix. Reverting the fix
// restores the GLOBAL connected scan, which binds the first
// prefix.contains() match regardless of table -> cross-VRF wrong egress.
// ---------------------------------------------------------------------

/// #4446: two routing instances ("red", "blue") own the SAME connected
/// subnet 192.168.0.0/24 on different interfaces (a normal reason to use
/// VRFs). A bare-gateway static route in each instance resolves its gateway
/// to its OWN instance's interface at FIB-build time.
///
/// RED-on-revert: the pre-#4446 global `connected_v4` scan returns the FIRST
/// `prefix.contains()` match. "blue" is inserted first, so the global scan
/// binds blue's ifindex (102) into red's route — this `assert_eq!(101)`
/// goes red. The single-table case is unaffected (each route already
/// resolves to the sole in-table connected interface); only the
/// overlapping-VRF case regresses.
#[test]
fn static_bare_gateway_infers_ifindex_in_own_table_v4() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            // BLUE inserted FIRST so its connected prefix LEADS the global
            // scan order — the pre-fix global inference would bind it to
            // red's route. The table-scoped fix filters it out for red.
            InterfaceSnapshot {
                name: "ge-0-0-2".into(),
                ifindex: 102,
                routing_instance: "blue".into(),
                hardware_addr: "02:00:00:00:00:02".into(),
                addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "192.168.0.2/24".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0-0-1".into(),
                ifindex: 101,
                routing_instance: "red".into(),
                hardware_addr: "02:00:00:00:00:01".into(),
                addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                    family: "inet".into(),
                    address: "192.168.0.1/24".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        routes: vec![
            // Bare-gateway static route in RED; gateway 192.168.0.254 is in
            // BOTH instances' overlapping 192.168.0.0/24.
            crate::RouteSnapshot {
                table: "red.inet.0".into(),
                family: "inet".into(),
                destination: "10.0.0.0/8".into(),
                next_hops: vec!["192.168.0.254".into()],
                ..Default::default()
            },
            // ...and in BLUE, same gateway, different instance.
            crate::RouteSnapshot {
                table: "blue.inet.0".into(),
                family: "inet".into(),
                destination: "10.0.0.0/8".into(),
                next_hops: vec!["192.168.0.254".into()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    let red = state.routes_v4.get("red.inet.0").expect("red.inet.0 table");
    assert_eq!(
        red[0].next_hops[0].ifindex, 101,
        "red's bare-gateway route must egress red's interface, not blue's overlapping prefix"
    );

    let blue = state
        .routes_v4
        .get("blue.inet.0")
        .expect("blue.inet.0 table");
    assert_eq!(
        blue[0].next_hops[0].ifindex, 102,
        "blue's bare-gateway route must egress blue's interface"
    );
}

/// #4446: v6 twin — the same table-scoped inference for IPv6 bare-gateway
/// routes (`infer_connected_route_target_v6`). "blue" leads the global scan;
/// red's route must still bind red's ifindex.
#[test]
fn static_bare_gateway_infers_ifindex_in_own_table_v6() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0-0-2".into(),
                ifindex: 102,
                routing_instance: "blue".into(),
                hardware_addr: "02:00:00:00:00:02".into(),
                addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                    family: "inet6".into(),
                    address: "2001:db8::2/64".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0-0-1".into(),
                ifindex: 101,
                routing_instance: "red".into(),
                hardware_addr: "02:00:00:00:00:01".into(),
                addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                    family: "inet6".into(),
                    address: "2001:db8::1/64".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        routes: vec![
            crate::RouteSnapshot {
                table: "red.inet6.0".into(),
                family: "inet6".into(),
                destination: "2001:db8:beef::/48".into(),
                next_hops: vec!["2001:db8::254".into()],
                ..Default::default()
            },
            crate::RouteSnapshot {
                table: "blue.inet6.0".into(),
                family: "inet6".into(),
                destination: "2001:db8:beef::/48".into(),
                next_hops: vec!["2001:db8::254".into()],
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);

    let red = state
        .routes_v6
        .get("red.inet6.0")
        .expect("red.inet6.0 table");
    assert_eq!(
        red[0].next_hops[0].ifindex, 101,
        "red's v6 bare-gateway route must egress red's interface"
    );

    let blue = state
        .routes_v6
        .get("blue.inet6.0")
        .expect("blue.inet6.0 table");
    assert_eq!(
        blue[0].next_hops[0].ifindex, 102,
        "blue's v6 bare-gateway route must egress blue's interface"
    );
}

/// #4446 anti-regression: the common single-table (default-instance) case is
/// unaffected — a bare-gateway static route still resolves its gateway to the
/// sole connected interface. A legitimate cross-table reach is expressed as a
/// `next-table` route (no forwarding next-hop, so it never touches this
/// inference) and is likewise unaffected: its `next_hops` stay empty.
#[test]
fn static_bare_gateway_single_table_still_resolves() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0-0-1".into(),
            ifindex: 201,
            hardware_addr: "02:00:00:00:02:01".into(),
            addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "192.168.0.1/24".into(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        routes: vec![
            crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "10.0.0.0/8".into(),
                next_hops: vec!["192.168.0.254".into()],
                ..Default::default()
            },
            // A next-table leak: no forwarding next-hop, so the inference is
            // never exercised and `next_hops` stays empty.
            crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "172.16.0.0/12".into(),
                next_table: "blue.inet.0".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };

    let state = build_forwarding_state(&snapshot);
    let table = state.routes_v4.get("inet.0").expect("inet.0 table");
    let bare = table
        .iter()
        .find(|r| r.prefix.contains("10.0.0.0".parse().unwrap()))
        .expect("bare-gateway route");
    assert_eq!(
        bare.next_hops[0].ifindex, 201,
        "single-table bare-gateway route still resolves to its connected interface"
    );
    let leak = table
        .iter()
        .find(|r| !r.next_table.is_empty())
        .expect("next-table route");
    assert!(
        leak.next_hops.is_empty(),
        "a next-table leak carries no forwarding next-hop (inference untouched)"
    );
}

/// #3771 (M11): a neighbor declaring family="inet" with an IPv6 IP fails the
/// snapshot CLOSED via `NeighborFamilyMismatch`. fail-on-revert: restoring the
/// family-ignoring `populate_neighbors` installs the neighbor and the build
/// succeeds, making this `expect_err` red.
#[test]
fn neighbor_family_contradicts_ip_fails_closed() {
    let snapshot = ConfigSnapshot {
        neighbors: vec![crate::NeighborSnapshot {
            interface: "ge-0/0/0".into(),
            ifindex: 10,
            family: "inet".into(),           // claims IPv4
            ip: "2001:db8::1".into(),        // ...but is IPv6
            mac: "aa:bb:cc:dd:ee:01".into(),
            state: "reachable".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("neighbor family/IP mismatch must fail closed");
    match err {
        crate::policy::SnapshotIntegrityError::NeighborFamilyMismatch {
            interface,
            ip,
            family,
        } => {
            assert_eq!(interface, "ge-0/0/0");
            assert_eq!(ip, "2001:db8::1");
            assert_eq!(family, "inet");
        }
        other => panic!("expected NeighborFamilyMismatch, got {other:?}"),
    }
}

/// #3771 (M11) anti-over-reject: a neighbor whose `family` matches its IP, and a
/// neighbor with an EMPTY `family` (older producer), both build and install.
#[test]
fn neighbor_family_matching_or_empty_installs() {
    let snapshot = ConfigSnapshot {
        neighbors: vec![
            crate::NeighborSnapshot {
                interface: "ge-0/0/0".into(),
                ifindex: 10,
                family: "inet".into(),
                ip: "10.0.0.1".into(),
                mac: "aa:bb:cc:dd:ee:01".into(),
                state: "reachable".into(),
                ..Default::default()
            },
            crate::NeighborSnapshot {
                interface: "ge-0/0/0".into(),
                ifindex: 10,
                family: String::new(), // unconstrained
                ip: "2001:db8::2".into(),
                mac: "aa:bb:cc:dd:ee:02".into(),
                state: "stale".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect("matching / empty family neighbors must build");
    assert_eq!(state.neighbors.len(), 2, "both neighbors install");
}

/// #3771 (M12): a neighbor with an UNKNOWN state (`none`) is NOT installed and
/// the diagnostic counter bumps. fail-on-revert: the denylist treats `none` as
/// usable and installs it, so the `is_empty` assertion (race-free) goes red.
#[test]
fn neighbor_unknown_state_is_skipped_and_counted() {
    let before = crate::afxdp::forwarding::NEIGHBOR_UNKNOWN_STATE_SKIPPED
        .load(std::sync::atomic::Ordering::Relaxed);
    let snapshot = ConfigSnapshot {
        neighbors: vec![crate::NeighborSnapshot {
            interface: "ge-0/0/0".into(),
            ifindex: 10,
            family: "inet".into(),
            ip: "10.0.0.9".into(),
            mac: "aa:bb:cc:dd:ee:09".into(),
            state: "none".into(), // pre-fix denylist treated this as usable
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.neighbors.is_empty(),
        "an unknown-state neighbor must not be installed into the FIB"
    );
    let after = crate::afxdp::forwarding::NEIGHBOR_UNKNOWN_STATE_SKIPPED
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        after > before,
        "an unknown-state neighbor must bump NEIGHBOR_UNKNOWN_STATE_SKIPPED"
    );
}

/// #3771 (M12): a `failed` neighbor is still skipped under the new allowlist
/// (regression against the pre-fix denylist). The "failed does not bump the
/// unknown-state counter" property is proven deterministically by
/// `classify_neighbor_state_is_an_allowlist` (KnownUnusable) — asserting on the
/// process-global counter here would be flaky under parallel test execution.
#[test]
fn neighbor_failed_state_is_not_installed() {
    let snapshot = ConfigSnapshot {
        neighbors: vec![crate::NeighborSnapshot {
            interface: "ge-0/0/0".into(),
            ifindex: 10,
            family: "inet".into(),
            ip: "10.0.0.4".into(),
            mac: String::new(),
            state: "failed".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.neighbors.is_empty(),
        "a failed neighbor is not installed"
    );
}

// ---------------------------------------------------------------------
// #2410: validated narrowing newtypes — out-of-range VLAN / TTL / queue
// fail the snapshot CLOSED instead of wrapping (VLAN/TTL) or silently
// dropping (queue). #2409: malformed interface address fails closed.
// ---------------------------------------------------------------------

/// #2410: a VLAN id > 65535 fails the snapshot CLOSED via
/// `InterfaceVlanOutOfRange`. fail-on-revert: restoring
/// `iface.vlan_id.max(0) as u16` wraps 65537 → VLAN 1 and the build
/// succeeds, making this `expect_err` red.
#[test]
fn interface_vlan_id_out_of_range_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/2".into(),
            ifindex: 23,
            parent_ifindex: 22,
            vlan_id: 65_537, // wraps to VLAN 1 under the old `as u16` cast
            hardware_addr: "02:00:00:00:00:23".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("an out-of-range VLAN id must fail closed, not wrap to a different VLAN");
    match err {
        crate::policy::SnapshotIntegrityError::InterfaceVlanOutOfRange { interface, vlan_id } => {
            assert_eq!(interface, "ge-0/0/2");
            assert_eq!(vlan_id, 65_537);
        }
        other => panic!("expected InterfaceVlanOutOfRange, got {other:?}"),
    }
}

/// #8597 K39: the 4096..=65535 gap #2410 left open. A VLAN in that band fits a
/// `u16`, so the old bound accepted it — and `TxVlanTag::from` then masks it
/// with `0x0fff`, emitting the frame on a DIFFERENT, live VLAN.
///
/// fail-on-revert: restoring the bound to `u16::MAX` makes both `expect_err`s
/// below red, because 4097 and 4096 are perfectly representable as `u16`.
#[test]
fn interface_vlan_id_above_the_12_bit_field_fails_closed_8597_k39() {
    // 4097 & 0x0fff == 1. Not a large VLAN downstream — VLAN 1, which on most
    // switches is a live L2 domain the operator never named.
    let err = vlan_snapshot_err_8597_k39(4097);
    match err {
        crate::policy::SnapshotIntegrityError::InterfaceVlanOutOfRange { interface, vlan_id } => {
            assert_eq!(interface, "ge-0/0/2");
            assert_eq!(vlan_id, 4097);
        }
        other => panic!("expected InterfaceVlanOutOfRange, got {other:?}"),
    }

    // 4096 is the worse one, and it is a DIFFERENT harm class rather than a
    // bigger version of the same. 4096 & 0x0fff == 0, and `TxVlanTag::from`
    // computes `present: vid > 0`, so `present` is false, `header_len()`
    // returns 14, and the frame is emitted with NO TAG on an interface
    // configured as tagged — landing in the native VLAN or dropped by the
    // switch, not merely mis-delivered.
    match vlan_snapshot_err_8597_k39(4096) {
        crate::policy::SnapshotIntegrityError::InterfaceVlanOutOfRange { vlan_id, .. } => {
            assert_eq!(vlan_id, 4096);
        }
        other => panic!("expected InterfaceVlanOutOfRange for 4096, got {other:?}"),
    }
}

/// #8597 K39 ANTI-OVER-REJECT, and it is the assertion that decides whether the
/// bound is right rather than merely tight.
///
/// The commit gate is `ValidateInteger(1, 4094)`
/// (`pkg/config/schema_interfaces.go`), so no committed config reaches either
/// boundary — this guards the tolerant load path. 4095 is accepted because it
/// is REPRESENTABLE in the 12-bit field and does not alias; rejecting it would
/// make this boundary stricter than the wire, which is a different claim from
/// the one K39 is about (#6773: the boundary admits exactly the
/// wire-representable range).
#[test]
fn interface_vlan_id_at_the_12_bit_boundary_is_accepted_8597_k39() {
    for vlan in [1, 50, 4094, 4095] {
        let snapshot = ConfigSnapshot {
            interfaces: vec![InterfaceSnapshot {
                name: "ge-0/0/2".into(),
                ifindex: 23,
                parent_ifindex: 22,
                vlan_id: vlan,
                hardware_addr: "02:00:00:00:00:23".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        try_build_forwarding_state_with_policy_counters(
            &snapshot,
            &crate::policy::PolicyCounterStore::default(),
        )
        .unwrap_or_else(|e| {
            panic!("VLAN {vlan} is representable in the 12-bit field and must be \
                    accepted; the bound must not over-reject what the commit gate \
                    permits (max 4094). got {e:?}")
        });
    }
}

fn vlan_snapshot_err_8597_k39(vlan_id: i32) -> crate::policy::SnapshotIntegrityError {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/2".into(),
            ifindex: 23,
            parent_ifindex: 22,
            vlan_id,
            hardware_addr: "02:00:00:00:00:23".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("a VLAN outside the 12-bit field must fail closed, not be masked")
}

/// #2410 anti-over-reject: an in-range VLAN (and the negative "no VLAN"
/// sentinel) still build, byte-identical to the old `.max(0) as u16`.
#[test]
fn interface_vlan_id_in_range_builds_exactly() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/3".into(),
                ifindex: 30,
                parent_ifindex: 29,
                vlan_id: 4094, // top of the legal 802.1Q range
                hardware_addr: "02:00:00:00:00:30".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/4".into(),
                ifindex: 31,
                vlan_id: -1, // legitimate "no VLAN" sentinel → 0 (untagged)
                hardware_addr: "02:00:00:00:00:31".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.egress.get(&30).expect("egress 30").vlan_id, 4094);
    assert_eq!(state.egress.get(&31).expect("egress 31").vlan_id, 0);
}

/// #2706: a NEGATIVE interface MTU fails the snapshot CLOSED via
/// `InterfaceMtuInvalid`. fail-on-revert: restoring `iface.mtu.max(0) as
/// usize` silently collapses -1 → 0, the egress MTU guard then treats 0 as
/// "unknown; forward" (PTB/drop enforcement disabled), the build succeeds,
/// and this `expect_err` goes red.
#[test]
fn interface_negative_mtu_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/2".into(),
            ifindex: 40,
            mtu: -1, // collapses to 0 (enforcement off) under the old `.max(0)` cast
            hardware_addr: "02:00:00:00:00:40".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("a negative interface MTU must fail closed, not collapse to 0 (enforcement off)");
    match err {
        crate::policy::SnapshotIntegrityError::InterfaceMtuInvalid { interface, mtu } => {
            assert_eq!(interface, "ge-0/0/2");
            assert_eq!(mtu, -1);
        }
        other => panic!("expected InterfaceMtuInvalid, got {other:?}"),
    }
}

/// #2706 anti-over-reject: a positive MTU builds through unchanged, and the
/// legitimate 0 "unknown MTU" sentinel is preserved as 0 (the permissive
/// "forward; MTU unknown" case the egress guard relies on) — byte-identical
/// to the old `.max(0) as usize`. This guards against the #2696
/// over-rejection dual-risk (rejecting a legit 0 would break deploy-boot of
/// any interface whose link MTU could not be resolved).
#[test]
fn interface_mtu_positive_and_zero_build_exactly() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                name: "ge-0/0/3".into(),
                ifindex: 41,
                mtu: 9000, // jumbo — passes through unchanged
                hardware_addr: "02:00:00:00:00:41".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                name: "ge-0/0/4".into(),
                ifindex: 42,
                mtu: 0, // legitimate "unknown MTU" sentinel → stays 0 (permissive)
                hardware_addr: "02:00:00:00:00:42".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.egress.get(&41).expect("egress 41").mtu, 9000);
    assert_eq!(state.egress.get(&42).expect("egress 42").mtu, 0);
}

/// #2410: a tunnel TTL > 255 fails the snapshot CLOSED via
/// `TunnelTtlOutOfRange`. fail-on-revert: restoring
/// `endpoint.ttl.max(0) as u8` wraps 256 → 0 (a blackholed tunnel) and
/// the build succeeds, making this `expect_err` red.
#[test]
fn tunnel_ttl_out_of_range_fails_closed() {
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 9,
            interface: "gr-0/0/0".into(),
            ifindex: 50,
            mode: "gre".into(),
            source: "203.0.113.1".into(),
            destination: "198.51.100.1".into(),
            ttl: 256, // wraps to 0 under the old `as u8` cast
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("an out-of-range tunnel TTL must fail closed, not wrap to 0");
    match err {
        crate::policy::SnapshotIntegrityError::TunnelTtlOutOfRange { tunnel_id, ttl } => {
            assert_eq!(tunnel_id, 9);
            assert_eq!(ttl, 256);
        }
        other => panic!("expected TunnelTtlOutOfRange, got {other:?}"),
    }
}

/// #5193 (A1-b7-F1): two tunnel-endpoint rows sharing one nonzero id fail the
/// snapshot CLOSED via `TunnelEndpointDuplicateId`. Pre-fix, `tunnel_endpoints`
/// (keyed by id) kept only the LAST row while `tunnel_endpoint_by_ifindex`
/// pointed BOTH interfaces at that id — so traffic on the losing interface
/// encapsulated with the winner's outer source/destination/key.
///
/// FAIL-ON-REVERT: drop the preflight and the build succeeds with exactly one
/// endpoint and two aliasing ifindex rows, making this `expect_err` red.
#[test]
fn tunnel_duplicate_endpoint_id_fails_closed_5193() {
    let dup = |ifindex: i32, dest: &str| crate::protocol::snapshot::TunnelEndpointSnapshot {
        id: 21,
        interface: format!("gr-0/0/{ifindex}"),
        ifindex,
        mode: "gre".into(),
        source: "203.0.113.1".into(),
        destination: dest.into(),
        ttl: 64,
        ..Default::default()
    };
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![dup(60, "198.51.100.1"), dup(61, "198.51.100.2")],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("two endpoints sharing id 21 must fail the snapshot closed, not alias");
    match err {
        crate::policy::SnapshotIntegrityError::TunnelEndpointDuplicateId { tunnel_id, ifindex } => {
            assert_eq!(tunnel_id, 21);
            assert_eq!(ifindex, 61, "the error names the SECOND row's ifindex");
        }
        other => panic!("expected TunnelEndpointDuplicateId, got {other:?}"),
    }
}

/// #5193 anti-over-reject: distinct ids still build, and an id of 0 (the
/// skipped placeholder row) does not count as a duplicate no matter how often
/// it appears.
#[test]
fn tunnel_distinct_and_zero_endpoint_ids_still_build_5193() {
    let ep = |id: u16, ifindex: i32| crate::protocol::snapshot::TunnelEndpointSnapshot {
        id,
        interface: format!("gr-0/0/{ifindex}"),
        ifindex,
        mode: "gre".into(),
        source: "203.0.113.1".into(),
        destination: "198.51.100.1".into(),
        ttl: 64,
        ..Default::default()
    };
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![ep(22, 62), ep(23, 63), ep(0, 64), ep(0, 65)],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(state.tunnel_endpoints.contains_key(&22));
    assert!(state.tunnel_endpoints.contains_key(&23));
    assert_eq!(state.tunnel_endpoint_by_ifindex.get(&62).copied(), Some(22));
    assert_eq!(state.tunnel_endpoint_by_ifindex.get(&63).copied(), Some(23));
}

/// #5193 (A1-b7-F7): a CoS DSCP REWRITE-RULE code-point outside the 6-bit DSCP
/// domain fails the snapshot CLOSED via `CosDscpRewriteCodePointOutOfRange`.
/// The classifier builders have failed closed since #2447, but the rewrite
/// ingest stored the value unchecked and the transmit path masks it
/// (`dscp & 0x3f`), so a rule written as 110 marked egress packets DSCP 46 —
/// a different PHB than configured.
///
/// FAIL-ON-REVERT: remove the bound check and the build succeeds, installing
/// the rule that the TX mask turns into DSCP 46.
#[test]
fn cos_dscp_rewrite_out_of_range_code_point_fails_closed_5193() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 81,
            cos_shaping_rate_bytes_per_sec: 1,
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "voice".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![crate::CoSDSCPRewriteRuleSnapshot {
                name: "wan-rewrite".into(),
                entries: vec![crate::CoSDSCPRewriteRuleEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    dscp_value: 110, // > 63 — the TX mask turns this into 46
                }],
            }],
            schedulers: vec![],
            scheduler_maps: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot)
        .expect_err("an out-of-range rewrite code-point must fail closed, not mask to DSCP 46");
    match err {
        crate::policy::SnapshotIntegrityError::CosDscpRewriteCodePointOutOfRange {
            rule,
            forwarding_class,
            dscp,
        } => {
            assert_eq!(rule, "wan-rewrite");
            assert_eq!(forwarding_class, "voice");
            assert_eq!(dscp, 110);
        }
        other => panic!("expected CosDscpRewriteCodePointOutOfRange, got {other:?}"),
    }
}

/// #5193 anti-over-reject: the top of the legal DSCP range (63) still builds,
/// so the new bound cannot be a blanket rejection.
#[test]
fn cos_dscp_rewrite_max_code_point_still_builds_5193() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 82,
            cos_shaping_rate_bytes_per_sec: 1,
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "voice".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![crate::CoSDSCPRewriteRuleSnapshot {
                name: "wan-rewrite".into(),
                entries: vec![crate::CoSDSCPRewriteRuleEntrySnapshot {
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    dscp_value: 63,
                }],
            }],
            schedulers: vec![],
            scheduler_maps: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let state = super::cos::build_cos_state(&snapshot)
        .expect("an in-range rewrite code-point must build");
    assert!(
        state.dscp_rewrite_rules.contains_key("wan-rewrite"),
        "the in-range rewrite rule must still be installed"
    );
}

/// #2410 anti-over-reject: an in-range TTL still builds exactly.
#[test]
fn tunnel_ttl_in_range_builds_exactly() {
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 10,
            interface: "gr-0/0/0".into(),
            ifindex: 51,
            mode: "gre".into(),
            source: "203.0.113.1".into(),
            destination: "198.51.100.1".into(),
            ttl: 255, // top of the legal range
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(state.tunnel_endpoints.get(&10).expect("endpoint").ttl, 255);
}

/// #2703: a NEGATIVE tunnel TTL (a corrupt / mixed-version snapshot
/// field) maps to the documented default 64, NOT 0. fail-on-revert:
/// restoring `TunnelTtl(0)` for negatives writes outer TTL 0 and
/// blackholes the tunnel — the exact failure the Go-side 0→64 default
/// guards against — making this assertion red.
#[test]
fn tunnel_ttl_negative_maps_to_default_not_zero() {
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 11,
            interface: "gr-0/0/0".into(),
            ifindex: 52,
            mode: "gre".into(),
            source: "203.0.113.1".into(),
            destination: "198.51.100.1".into(),
            ttl: -1, // corrupt / mixed-version: must NOT become 0
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        state.tunnel_endpoints.get(&11).expect("endpoint").ttl,
        64,
        "a negative snapshot TTL must map to the default 64, not 0 (blackhole)"
    );
}

/// #5162: a non-WireGuard tunnel whose outer source and destination are
/// DIFFERENT address families (v4 source + v6 destination) is skipped by
/// `populate_tunnel_endpoints` — a helper-boundary backstop for a
/// mixed-version peer-sync / corrupt snapshot the Go commit gate
/// (`validateTunnelOuterFamilyStrict`) did not reject. Before the fix such
/// a row was tagged `inet6` (Go picks inet6 if EITHER endpoint is v6) and
/// installed, then silently dropped every encap in the GRE AF_INET6 arm.
/// fail-on-revert: removing the family-mismatch skip installs the endpoint
/// and this `assert!(!contains_key)` goes red.
#[test]
fn tunnel_mixed_outer_family_is_skipped() {
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 12,
            interface: "gr-0/0/0".into(),
            ifindex: 53,
            mode: "gre".into(),
            // Go would tag this `inet6` (destination is v6); the source is v4.
            outer_family: "inet6".into(),
            source: "203.0.113.1".into(),
            destination: "2001:db8::1".into(),
            ttl: 64,
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        !state.tunnel_endpoints.contains_key(&12),
        "a mixed-family (v4 src / v6 dst) GRE endpoint must be skipped, not installed"
    );
    // And it must not be indexed for GRE decap either.
    assert!(
        !state
            .gre_decap_index
            .values()
            .any(|ids| ids.contains(&12)),
        "a skipped mixed-family endpoint must not enter the GRE decap index"
    );
}

/// #5162 anti-over-reject: a same-family (v4 src / v4 dst) GRE tunnel still
/// installs exactly. Guards the family-mismatch skip from swallowing a
/// legitimate same-family tunnel.
#[test]
fn tunnel_same_outer_family_builds_exactly() {
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 13,
            interface: "gr-0/0/0".into(),
            ifindex: 54,
            mode: "gre".into(),
            outer_family: "inet".into(),
            source: "203.0.113.1".into(),
            destination: "198.51.100.1".into(),
            ttl: 64,
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.tunnel_endpoints.contains_key(&13),
        "a same-family v4/v4 GRE endpoint must install"
    );
}

/// #5162 anti-over-reject: a same-family (v6 src / v6 dst) GRE tunnel still
/// installs exactly.
#[test]
fn tunnel_same_outer_family_v6_builds_exactly() {
    let snapshot = ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 14,
            interface: "gr-0/0/0".into(),
            ifindex: 55,
            mode: "gre".into(),
            outer_family: "inet6".into(),
            source: "2001:db8::1".into(),
            destination: "2001:db8::2".into(),
            ttl: 64,
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.tunnel_endpoints.contains_key(&14),
        "a same-family v6/v6 GRE endpoint must install"
    );
}

/// #2410: a CoS forwarding-class queue id outside 0..=255 fails the
/// snapshot CLOSED via `CosQueueIdOutOfRange`. fail-on-revert: restoring
/// the `filter_map` range check silently DROPS the class, the build
/// succeeds, and this `expect_err` is red.
#[test]
fn cos_forwarding_class_queue_out_of_range_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 60,
            cos_shaping_rate_bytes_per_sec: 1,
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "voice".into(),
                queue: 256, // outside u8 range — pre-fix: silently dropped
            }],
            schedulers: vec![],
            scheduler_maps: vec![],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot)
        .expect_err("an out-of-range CoS queue id must fail closed, not silently drop the class");
    match err {
        crate::policy::SnapshotIntegrityError::CosQueueIdOutOfRange {
            forwarding_class,
            queue,
        } => {
            assert_eq!(forwarding_class, "voice");
            assert_eq!(queue, 256);
        }
        other => panic!("expected CosQueueIdOutOfRange, got {other:?}"),
    }
}

/// #2410 anti-over-reject: an in-range queue id still maps, and an EMPTY
/// class name is still skipped (the legitimate placeholder case) without
/// erroring.
#[test]
fn cos_forwarding_class_in_range_queue_builds_and_empty_name_skipped() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 61,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "m".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5, // in-range
                },
                CoSForwardingClassSnapshot {
                    name: String::new(), // placeholder — skipped, not an error
                    queue: 999,
                },
            ],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "m".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "voice".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let state = super::cos::build_cos_state(&snapshot).expect("in-range queue id must build");
    let cfg = state.interfaces.get(&61).expect("iface 61 cos");
    assert_eq!(cfg.queue_by_forwarding_class.get("voice").copied(), Some(5));
}

/// #2447: a DSCP classifier code-point outside the 6-bit DSCP domain
/// (0..=63) fails the snapshot CLOSED via `CosDscpCodePointOutOfRange`. The
/// pre-fix builder masked the index `dscp & 0x3f`, so 110 silently built the
/// classifier for DSCP 46 — a DIFFERENT traffic class. fail-on-revert:
/// restore `usize::from(dscp & 0x3f)` and `table[idx] = queue_id` and the
/// build succeeds (installing the aliased entry), making this `expect_err`
/// red.
#[test]
fn cos_dscp_classifier_out_of_range_code_point_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 80,
            cos_shaping_rate_bytes_per_sec: 1,
            cos_dscp_classifier: "wan".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan".into(),
                entries: vec![CoSDSCPClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    dscp_values: vec![110], // > 63 — pre-fix masked to 46
                }],
            }],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![],
            scheduler_maps: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot)
        .expect_err("an out-of-range DSCP code-point must fail closed, not alias into queue 46");
    match err {
        crate::policy::SnapshotIntegrityError::CosDscpCodePointOutOfRange { classifier, dscp } => {
            assert_eq!(classifier, "wan");
            assert_eq!(dscp, 110);
        }
        other => panic!("expected CosDscpCodePointOutOfRange, got {other:?}"),
    }
}

/// #2447: an 802.1p classifier code-point outside the 3-bit PCP domain
/// (0..=7) fails closed via `CosIeee8021CodePointOutOfRange` (pre-fix
/// `pcp.min(7)` clamped 9 into queue 7).
#[test]
fn cos_ieee8021_classifier_out_of_range_code_point_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 81,
            cos_shaping_rate_bytes_per_sec: 1,
            cos_ieee8021_classifier: "wan-pcp".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    code_points: vec![9], // > 7 — pre-fix clamped to 7
                }],
            }],
            dscp_rewrite_rules: vec![],
            schedulers: vec![],
            scheduler_maps: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot)
        .expect_err("an out-of-range PCP code-point must fail closed, not clamp into queue 7");
    match err {
        crate::policy::SnapshotIntegrityError::CosIeee8021CodePointOutOfRange { classifier, pcp } => {
            assert_eq!(classifier, "wan-pcp");
            assert_eq!(pcp, 9);
        }
        other => panic!("expected CosIeee8021CodePointOutOfRange, got {other:?}"),
    }
}

/// #2447 anti-over-reject: in-range boundary code-points (DSCP 63, PCP 7)
/// still build the classifier table at the expected indices.
#[test]
fn cos_classifier_in_range_boundary_code_points_build() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 82,
            cos_shaping_rate_bytes_per_sec: 1,
            cos_dscp_classifier: "wan".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan".into(),
                entries: vec![CoSDSCPClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    dscp_values: vec![63], // max in-range
                }],
            }],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    code_points: vec![7], // max in-range
                }],
            }],
            dscp_rewrite_rules: vec![],
            schedulers: vec![],
            scheduler_maps: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let state = super::cos::build_cos_state(&snapshot)
        .expect("in-range boundary code-points must build");
    let iface = state.interfaces.get(&82).expect("iface 82 cos");
    assert_eq!(iface.dscp_queue_by_dscp[63], 0, "DSCP 63 must map to queue 0");
    assert_eq!(iface.ieee8021_queue_by_pcp[7], 0, "PCP 7 must map to queue 0");
}

/// #2409: an interface address that does not parse as an `IpNet` fails the
/// snapshot CLOSED via `InterfaceAddressUnparseable`. fail-on-revert:
/// restoring the `else { continue; }` silently drops the address (losing
/// the connected route) and the build succeeds, making this red.
#[test]
fn interface_malformed_address_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/5".into(),
            ifindex: 70,
            hardware_addr: "02:00:00:00:00:70".into(),
            addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "10.0.0.0/33".into(), // not a parseable CIDR
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot,
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err("a malformed interface address must fail closed, not silently drop the route");
    match err {
        crate::policy::SnapshotIntegrityError::InterfaceAddressUnparseable { interface, address } => {
            assert_eq!(interface, "ge-0/0/5");
            assert_eq!(address, "10.0.0.0/33");
        }
        other => panic!("expected InterfaceAddressUnparseable, got {other:?}"),
    }
}

/// #2409 anti-over-reject: a valid interface address still installs its
/// connected route.
#[test]
fn interface_valid_address_builds_connected_route() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            name: "ge-0/0/6".into(),
            ifindex: 71,
            hardware_addr: "02:00:00:00:00:71".into(),
            addresses: vec![crate::protocol::snapshot::InterfaceAddressSnapshot {
                family: "inet".into(),
                address: "10.0.61.1/24".into(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.connected_v4.iter().any(|r| r.ifindex == 71),
        "valid address must produce a connected route"
    );
    assert!(state.local_v4.contains(&"10.0.61.1".parse().unwrap()));
}

// ---------------------------------------------------------------------
// #916: zero-shaping-rate (transparent root) tests.
// ---------------------------------------------------------------------

#[test]
fn build_cos_state_includes_zero_shaping_rate_interface() {
    // Pre-#916, an interface with `cos_shaping_rate_bytes_per_sec == 0`
    // was silently dropped by `build_cos_state`'s upstream skip,
    // which masked the runtime deadlock by suppressing the entire
    // CoS runtime. The bug surface for the operator was "CoS
    // classifier doesn't apply on this interface". The fix permits
    // the interface through; the runtime handles transparent-root
    // semantics.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 0, // <- the case under test
            cos_shaping_burst_bytes: 0,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        state.interfaces.contains_key(&42),
        "zero-shaping-rate interface must be included in CoSState (transparent root)"
    );
    let iface = &state.interfaces[&42];
    assert_eq!(iface.shaping_rate_bytes, 0);
    // burst_bytes falls back to default_cos_burst_bytes(0) which floors
    // at COS_MIN_BURST_BYTES (96 KB).
    assert!(iface.burst_bytes >= 64 * 1500);
}

#[test]
fn build_cos_state_zero_shaping_rate_queue_inherits_transparent() {
    // When the scheduler has no transmit-rate AND the interface has
    // no shaping-rate, the queue's effective rate falls through to
    // 0. Verify the queue config carries `transmit_rate_bytes == 0`
    // (the runtime build path will pre-fill tokens to the buffer cap
    // and the queue-service will bypass the cos_refill_ns_until check).
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "iperf-a".into(),
                queue: 4,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "no-rate".into(),
                transmit_rate_bytes: 0, // <- fallback chains to 0
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "iperf-a".into(),
                    scheduler: "no-rate".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    let iface = state
        .interfaces
        .get(&42)
        .expect("transparent iface present");
    let queue = iface
        .queues
        .iter()
        .find(|q| q.queue_id == 4)
        .expect("iperf-a queue present");
    assert_eq!(
        queue.transmit_rate_bytes, 0,
        "transparent root + no scheduler rate → transparent queue (rate 0)"
    );
    assert!(
        !queue.guarantee_enabled,
        "no scheduler rate means surplus-only even when the effective rate is transparent"
    );
}

#[test]
fn build_cos_state_no_rate_exact_surplus_equal_flow_is_residual_only() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 42,
            cos_shaping_rate_bytes_per_sec: 25_000_000_000 / 8,
            cos_scheduler_map: "wan-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "iperf-a".into(),
                queue: 4,
            }],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "no-rate-exact".into(),
                transmit_rate_bytes: 0,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: true,
                priority: "high".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: true,
                equal_flow_enforcement: true,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "iperf-a".into(),
                    scheduler: "no-rate-exact".into(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let queue = state
        .interfaces
        .get(&42)
        .expect("shaped iface present")
        .queues
        .iter()
        .find(|q| q.queue_id == 4)
        .expect("iperf-a queue present");

    assert_eq!(queue.transmit_rate_bytes, 25_000_000_000 / 8);
    assert!(!queue.guarantee_enabled);
    assert!(!queue.exact);
    assert!(!queue.surplus_sharing);
    assert!(!queue.equal_flow_enforcement);
}

#[test]
fn build_cos_state_mixed_zero_and_nonzero_shaping_rate() {
    // Two interfaces in the same snapshot — one with shaping-rate
    // configured, one without. Both must produce CoSState entries
    // with the correct semantics.
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            InterfaceSnapshot {
                ifindex: 42,
                cos_shaping_rate_bytes_per_sec: 25_000_000_000 / 8,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
            InterfaceSnapshot {
                ifindex: 43,
                cos_shaping_rate_bytes_per_sec: 0,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    let shaped = state.interfaces.get(&42).expect("shaped iface in CoSState");
    let transparent = state
        .interfaces
        .get(&43)
        .expect("transparent iface in CoSState");
    assert_eq!(shaped.shaping_rate_bytes, 25_000_000_000 / 8);
    assert_eq!(transparent.shaping_rate_bytes, 0);
    // Both must have at least one queue.
    assert!(!shaped.queues.is_empty());
    assert!(!transparent.queues.is_empty());
}

#[test]
fn build_cos_state_skips_interface_with_no_cos_config() {
    // An interface that is NOT participating in CoS (no scheduler-map,
    // no classifier, no rewrite-rule, no shaping-rate) must NOT receive
    // a CoSState entry — otherwise the per-interface owner-worker
    // dispatch funnels every TX into one worker, collapsing throughput
    // (regression hunted in iperf3 -P 12 -R: 22 Gbps → 2 Gbps until
    // this gate was reinstated).
    let snapshot = ConfigSnapshot {
        interfaces: vec![
            // Forwarding-only LAN egress with no CoS at all.
            InterfaceSnapshot {
                ifindex: 100,
                cos_shaping_rate_bytes_per_sec: 0,
                cos_shaping_burst_bytes: 0,
                cos_scheduler_map: String::new(),
                cos_dscp_classifier: String::new(),
                cos_ieee8021_classifier: String::new(),
                cos_dscp_rewrite_rule: String::new(),
                ..Default::default()
            },
            // Sibling that DOES participate in CoS — must still appear.
            InterfaceSnapshot {
                ifindex: 101,
                cos_shaping_rate_bytes_per_sec: 0,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "wan-map".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: String::new(),
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&100),
        "interface with no CoS config must NOT be added to CoSState"
    );
    assert!(
        state.interfaces.contains_key(&101),
        "interface with scheduler-map but no shaping-rate must still appear (transparent root)"
    );
}

#[test]
fn build_cos_state_admits_each_cos_field_in_isolation() {
    // The skip predicate is an OR over five arms (rate, scheduler-map,
    // DSCP classifier, 802.1p classifier, DSCP rewrite). Pin every arm so
    // a future refactor can't silently drop one — Codex review on
    // PR #1183 flagged this as coverage debt (Q5). The sixth `InterfaceSnapshot`
    // CoS field, `cos_shaping_burst_bytes`, is intentionally NOT a
    // standalone arm; see the dedicated burst-only-skip test below and
    // the gate comment in `forwarding_build/cos.rs::build_cos_iface_config`
    // for rationale.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![CoSSchedulerMapEntrySnapshot {
                forwarding_class: "best-effort".into(),
                scheduler: String::new(),
            }],
        }],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "dscp-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_values: vec![0],
            }],
        }],
        ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
            name: "p8021-cls".into(),
            entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                code_points: vec![0],
            }],
        }],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "dscp-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_value: 0,
            }],
        }],
        inet_precedence_classifiers: vec![],
    };
    let cases: &[(i32, &str, InterfaceSnapshot)] = &[
        (
            201,
            "shaping-rate only",
            InterfaceSnapshot {
                ifindex: 201,
                cos_shaping_rate_bytes_per_sec: 1_000_000,
                ..Default::default()
            },
        ),
        (
            203,
            "scheduler-map only",
            InterfaceSnapshot {
                ifindex: 203,
                cos_scheduler_map: "wan-map".into(),
                ..Default::default()
            },
        ),
        (
            204,
            "DSCP classifier only",
            InterfaceSnapshot {
                ifindex: 204,
                cos_dscp_classifier: "dscp-cls".into(),
                ..Default::default()
            },
        ),
        (
            205,
            "802.1p classifier only",
            InterfaceSnapshot {
                ifindex: 205,
                cos_ieee8021_classifier: "p8021-cls".into(),
                ..Default::default()
            },
        ),
        (
            206,
            "DSCP rewrite-rule only",
            InterfaceSnapshot {
                ifindex: 206,
                cos_dscp_rewrite_rule: "dscp-rw".into(),
                ..Default::default()
            },
        ),
    ];
    for (ifindex, label, iface) in cases {
        let snapshot = ConfigSnapshot {
            interfaces: vec![iface.clone()],
            class_of_service: Some(cos.clone()),
            ..Default::default()
        };
        let state = build_cos_state(&snapshot);
        assert!(
            state.interfaces.contains_key(ifindex),
            "{label}: interface must be admitted to CoSState (ifindex {ifindex})"
        );
    }
}

#[test]
fn build_cos_state_skips_interface_with_burst_only_no_other_cos_knobs() {
    // The Go compiler permits a committed config to carry
    // `BurstSizeBytes > 0` independently of `ShapingRateBytes`
    // (`pkg/config/compiler_class_of_service.go:285-312`), so this
    // snapshot shape IS reachable from real config. We deliberately
    // skip it anyway: pre-f0e364d7 also skipped burst-only (the old
    // `shaping_rate == 0` skip caught it), and admitting it would
    // install the cross-binding owner-worker redirect that PR #1183
    // exists to remove. The buffer-cap admission effect that admission
    // would unlock has never been observable in production.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 250,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_shaping_burst_bytes: 256_000,
            cos_scheduler_map: String::new(),
            cos_dscp_classifier: String::new(),
            cos_ieee8021_classifier: String::new(),
            cos_dscp_rewrite_rule: String::new(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot::default()),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&250),
        "interface with burst-only (no rate, no classes, no rewrite) must NOT be in CoSState"
    );
}

#[test]
fn build_cos_state_skips_interface_with_unresolvable_named_references() {
    // A typo'd scheduler-map / classifier / rewrite-rule name is
    // non-empty but does not resolve to any entry in the CoS config.
    // Pre-fix, an is-non-empty gate would admit such an interface and
    // build only a default best-effort queue with rate=0, re-triggering
    // the owner-worker redirect collapse for an interface with no
    // effective CoS policy. The predicate must require named references
    // to actually resolve.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![CoSSchedulerMapSnapshot {
            name: "wan-map".into(),
            entries: vec![CoSSchedulerMapEntrySnapshot {
                forwarding_class: "best-effort".into(),
                scheduler: String::new(),
            }],
        }],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "dscp-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_values: vec![0],
            }],
        }],
        ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
            name: "p8021-cls".into(),
            entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                code_points: vec![0],
            }],
        }],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "dscp-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_value: 0,
            }],
        }],
        inet_precedence_classifiers: vec![],
    };
    // Each typo'd reference (one CoS field non-empty but unresolvable)
    // must NOT admit the interface to CoSState.
    let cases: &[(i32, &str, InterfaceSnapshot)] = &[
        (
            301,
            "typo'd scheduler-map",
            InterfaceSnapshot {
                ifindex: 301,
                cos_scheduler_map: "wan-mapp".into(),
                ..Default::default()
            },
        ),
        (
            302,
            "typo'd DSCP classifier",
            InterfaceSnapshot {
                ifindex: 302,
                cos_dscp_classifier: "dscp-cls-typo".into(),
                ..Default::default()
            },
        ),
        (
            303,
            "typo'd 802.1p classifier",
            InterfaceSnapshot {
                ifindex: 303,
                cos_ieee8021_classifier: "p8021-cls-typo".into(),
                ..Default::default()
            },
        ),
        (
            304,
            "typo'd DSCP rewrite-rule",
            InterfaceSnapshot {
                ifindex: 304,
                cos_dscp_rewrite_rule: "dscp-rw-typo".into(),
                ..Default::default()
            },
        ),
    ];
    for (ifindex, label, iface) in cases {
        let snapshot = ConfigSnapshot {
            interfaces: vec![iface.clone()],
            class_of_service: Some(cos.clone()),
            ..Default::default()
        };
        let state = build_cos_state(&snapshot);
        assert!(
            !state.interfaces.contains_key(ifindex),
            "{label}: unresolvable name must NOT admit interface to CoSState (ifindex {ifindex})"
        );
    }
}

#[test]
fn build_cos_state_skips_interface_with_resolvable_but_empty_scheduler_map() {
    // Copilot review on PR #1183 caught this: `compileClassOfService`
    // keeps a named scheduler-map even when it has zero entries, so
    // a `contains_key` admission check would let a config like
    // `set class-of-service interfaces ifd unit X scheduler-map empty-map`
    // (with `empty-map` declared but no entries) pass the gate, then
    // collapse downstream to a synthetic best-effort default queue —
    // re-triggering the owner-worker redirect collapse for an interface
    // with no effective CoS policy.
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 401,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "empty-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "empty-map".into(),
                entries: vec![], // <- the critical case: declared but empty
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&401),
        "interface attached to a resolvable but empty scheduler-map must NOT enter CoSState"
    );
}

/// #2409: at the RUST helper boundary, a scheduler-map entry referencing a
/// forwarding-class absent from the class-to-queue table fails the snapshot
/// CLOSED. This is a true NEVER-FIRES DRIFT BACKSTOP: an undefined-class
/// scheduler-map entry is a SUPPORTED, committable config shape on the Go
/// side (warning-only at commit, `compiler_validate_warn.go`), so the Go
/// snapshot emitter (`pkg/dataplane/userspace/cos.go`,
/// `buildClassOfServiceSnapshot`) now DEGRADES VISIBLY — it filters the
/// undefined entry with a `slog.Warn` and never puts it on the wire (see
/// `TestBuildClassOfServiceSnapshotSkipsUndefinedSchedulerMapClass`). This
/// hard-error therefore only fires on a version/snapshot-drifted helper that
/// receives an entry the emitter would have filtered — making it consistent
/// with the VLAN/TTL/queue/address sites (corruption a valid config never
/// produces) and with the #2391/#2212/#2240 precedents (all have a Go gate
/// upstream so their Rust backstop never fires on a fresh operator config).
///
/// #8442: that "never fires on a fresh operator config" claim was FALSE when it
/// was written, and an ordinary commit reached this error. `forwarding-classes
/// queue 5 ""` committed green; the emitter kept the empty class AND its
/// scheduler-map entry; `build_cos_classifier_tables` skipped the empty name
/// building `class_to_queue`; and the entry's lookup landed here, refusing the
/// whole snapshot. The claim is true again only because #8442 added the missing
/// Go gate — which is the upstream half the sentence above assumed already
/// existed. See `an_empty_forwarding_class_refuses_the_whole_snapshot_8442`,
/// which pins the blast radius that made it worth fixing rather than the one
/// bad entry.
///
/// fail-on-revert: restoring the `continue` at the `class_to_queue.get`
/// lookup makes the build succeed (silently dropping the entry) and this
/// `expect_err` red.
#[test]
fn build_cos_state_fails_closed_on_scheduler_map_undefined_forwarding_class() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 402,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "broken-map".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            // forwarding_classes intentionally does NOT include the
            // class names referenced by `broken-map` below, so the first
            // entry's `class_to_queue.get(&entry.forwarding_class)` misses.
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "broken-map".into(),
                entries: vec![
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "missing-class-a".into(),
                        scheduler: String::new(),
                    },
                    CoSSchedulerMapEntrySnapshot {
                        forwarding_class: "missing-class-b".into(),
                        scheduler: String::new(),
                    },
                ],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot)
        .expect_err("scheduler-map referencing an undefined class must fail closed");
    match err {
        crate::policy::SnapshotIntegrityError::SchedulerMapUnknownClass {
            scheduler_map,
            forwarding_class,
        } => {
            assert_eq!(scheduler_map, "broken-map");
            assert_eq!(forwarding_class, "missing-class-a");
        }
        other => panic!("expected SchedulerMapUnknownClass, got {other:?}"),
    }
}

#[test]
fn build_cos_state_skips_classifier_only_mapping_to_unmaterialized_queue() {
    // An interface attaches a DSCP classifier whose entries map to
    // forwarding-class `voice` (queue 5). The interface has NO
    // scheduler-map, so the only queue it would materialize is the
    // synthetic default best-effort (queue 0). The classifier maps to
    // queue 5, which the interface won't have at runtime — packets
    // matching the classifier would land in `resolve_cos_queue_idx`
    // and get dropped, while the interface still installs the
    // owner-worker redirect. Gate must skip such interfaces.
    // (Copilot review on PR #1183 caught this.)
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![
            CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            },
            CoSForwardingClassSnapshot {
                name: "voice".into(),
                queue: 5,
            },
        ],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "voice-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "voice".into(), // queue 5
                loss_priority: String::new(),
                dscp_values: vec![0x2e],
            }],
        }],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
        inet_precedence_classifiers: vec![],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 501,
            cos_dscp_classifier: "voice-cls".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&501),
        "DSCP classifier mapping to queue the interface won't materialize (no scheduler-map) must NOT admit"
    );
}

#[test]
fn build_cos_state_admits_classifier_mapping_to_materialized_queue() {
    // The opposite of the previous test: a DSCP classifier mapping to
    // queue 0 is OK on an interface with no scheduler-map, because the
    // synthetic default best-effort queue IS queue 0. Packets land
    // there and the classifier IS observable, so the interface
    // legitimately needs to be in CoSState.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
            name: "be-cls".into(),
            entries: vec![CoSDSCPClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(), // queue 0
                loss_priority: String::new(),
                dscp_values: vec![0x10],
            }],
        }],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![],
        inet_precedence_classifiers: vec![],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 502,
            cos_dscp_classifier: "be-cls".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        state.interfaces.contains_key(&502),
        "DSCP classifier mapping to materialized queue must admit interface"
    );
}

#[test]
fn build_cos_state_skips_rewrite_only_mapping_to_unmaterialized_class() {
    // A DSCP rewrite-rule whose ONLY entry is for forwarding-class
    // `voice` is attached to an interface with no scheduler-map. The
    // interface only has the synthetic default best-effort class —
    // the `voice` rewrite has no queue to attach to, so no packet can
    // ever observe it. Gate must skip.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![
            CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            },
            CoSForwardingClassSnapshot {
                name: "voice".into(),
                queue: 5,
            },
        ],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "voice-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "voice".into(),
                loss_priority: String::new(),
                dscp_value: 0x2e,
            }],
        }],
        inet_precedence_classifiers: vec![],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 503,
            cos_dscp_rewrite_rule: "voice-rw".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        !state.interfaces.contains_key(&503),
        "DSCP rewrite-rule for class the interface won't materialize must NOT admit"
    );
}

#[test]
fn build_cos_state_admits_rewrite_only_mapping_to_materialized_class() {
    // A DSCP rewrite-rule with a `best-effort` entry is observable on
    // an interface with no scheduler-map, because the synthetic default
    // best-effort queue IS the materialized class. Packets in that
    // queue can carry the rewrite — interface should be admitted.
    let cos = ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "best-effort".into(),
            queue: 0,
        }],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        dscp_rewrite_rules: vec![CoSDSCPRewriteRuleSnapshot {
            name: "be-rw".into(),
            entries: vec![CoSDSCPRewriteRuleEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                dscp_value: 0,
            }],
        }],
        inet_precedence_classifiers: vec![],
    };
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 504,
            cos_dscp_rewrite_rule: "be-rw".into(),
            ..Default::default()
        }],
        class_of_service: Some(cos),
        ..Default::default()
    };
    let state = build_cos_state(&snapshot);
    assert!(
        state.interfaces.contains_key(&504),
        "DSCP rewrite-rule for the materialized best-effort class must admit"
    );
}

// ---------------------------------------------------------------------------
// #1636 option D: compute_pending_neigh_timeout_ns tests.
// ---------------------------------------------------------------------------

/// Fake sysctl reader: maps a path to a u32, or None to simulate a read
/// failure (missing file / permission / parse error).
struct FakeSysctl {
    values: std::collections::HashMap<String, Option<u32>>,
    default_value: Option<u32>,
}

impl FakeSysctl {
    fn all(v: u32) -> Self {
        Self {
            values: std::collections::HashMap::new(),
            default_value: Some(v),
        }
    }
    fn set(mut self, path: &str, v: Option<u32>) -> Self {
        self.values.insert(path.to_string(), v);
        self
    }
}

impl SysctlReader for FakeSysctl {
    fn read_u32(&self, path: &str) -> Option<u32> {
        if let Some(v) = self.values.get(path) {
            return *v;
        }
        self.default_value
    }
}

fn one_iface_map() -> FastMap<i32, String> {
    let mut m = FastMap::default();
    m.insert(80, "ge-0-0-2".to_string());
    m
}

#[test]
fn pending_neigh_timeout_fast_when_all_retrans_le_250() {
    let reader = FakeSysctl::all(250);
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, PENDING_NEIGH_TIMEOUT_FAST_NS);
}

#[test]
fn pending_neigh_timeout_fallback_when_iface_retrans_too_high() {
    // Default is 250 (fast) but the v4 per-iface table is 1000ms.
    let reader = FakeSysctl::all(250).set(
        "/proc/sys/net/ipv4/neigh/ge-0-0-2/retrans_time_ms",
        Some(1000),
    );
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, super::super::PENDING_NEIGH_TIMEOUT_NS);
}

#[test]
fn pending_neigh_timeout_fallback_when_v6_too_high() {
    let reader = FakeSysctl::all(250).set(
        "/proc/sys/net/ipv6/neigh/ge-0-0-2/retrans_time_ms",
        Some(900),
    );
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, super::super::PENDING_NEIGH_TIMEOUT_NS);
}

#[test]
fn pending_neigh_timeout_fallback_when_default_template_too_high() {
    // Per-iface tables fast, but the `default` template is still 1000ms
    // (an interface created after the snapshot would inherit it).
    let reader = FakeSysctl::all(250).set(
        "/proc/sys/net/ipv4/neigh/default/retrans_time_ms",
        Some(1000),
    );
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, super::super::PENDING_NEIGH_TIMEOUT_NS);
}

#[test]
fn pending_neigh_timeout_fails_closed_on_read_error() {
    // A read failure (None) on any checked path must fail closed to the
    // 2000ms default rather than optimistically assuming fast.
    let reader =
        FakeSysctl::all(250).set("/proc/sys/net/ipv4/neigh/ge-0-0-2/retrans_time_ms", None);
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, super::super::PENDING_NEIGH_TIMEOUT_NS);
}

#[test]
fn pending_neigh_timeout_fast_with_no_dataplane_interfaces() {
    // Empty iface map: only the `default` template is checked. If it is
    // fast, the timeout is fast.
    let reader = FakeSysctl::all(250);
    let got = compute_pending_neigh_timeout_ns(&FastMap::default(), &reader);
    assert_eq!(got, PENDING_NEIGH_TIMEOUT_FAST_NS);
}

#[test]
fn pending_neigh_timeout_fast_with_jiffy_rounded_252() {
    // The daemon writes 250 but the kernel rounds retrans_time_ms to its
    // internal jiffy resolution and reads back 252 on HZ=100 hosts. The
    // 300ms threshold must still admit the fast 800ms timeout.
    let reader = FakeSysctl::all(252);
    let got = compute_pending_neigh_timeout_ns(&one_iface_map(), &reader);
    assert_eq!(got, PENDING_NEIGH_TIMEOUT_FAST_NS);
}

// ---------------------------------------------------------------------
// #1432 S2a — WireGuard endpoint hydration + engine reload stability.
// ---------------------------------------------------------------------

const WG_TEST_PRIVKEY_HEX: &str =
    "a01010101010101010101010101010101010101010101010101010101010101a";
const WG_TEST_PEERKEY_HEX: &str =
    "b02020202020202020202020202020202020202020202020202020202020202b";

fn wg_snapshot(listen_port: u16, allowed: &[&str], endpoint: &str) -> ConfigSnapshot {
    ConfigSnapshot {
        tunnel_endpoints: vec![crate::protocol::snapshot::TunnelEndpointSnapshot {
            id: 7,
            interface: "wg0".into(),
            linux_name: "wg0".into(),
            ifindex: 42,
            mode: "wireguard".into(),
            wg_listen_port: listen_port,
            wg_local_privkey_hex: WG_TEST_PRIVKEY_HEX.into(),
            wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
                wg_peer_pubkey_hex: WG_TEST_PEERKEY_HEX.into(),
                wg_allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
                wg_endpoint: endpoint.into(),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn wg_endpoint_hydrates_runtime_tunnel_endpoint() {
    let snap = wg_snapshot(51820, &["10.0.0.0/24"], "203.0.113.1:51820");
    let state = build_forwarding_state(&snap);
    assert!(state.has_wg_tunnels, "WG endpoint sets has_wg_tunnels");
    let ep = state.tunnel_endpoints.get(&7).expect("WG endpoint present");
    assert_eq!(ep.mode, "wireguard");
    assert_eq!(ep.wg_listen_port, 51820);
    assert_eq!(ep.wg_peers.len(), 1);
    assert_eq!(ep.wg_peers[0].allowed_ips.len(), 1);
    assert_eq!(
        ep.wg_peers[0].endpoint,
        Some("203.0.113.1:51820".parse().unwrap())
    );
    // Engine instantiated and keyed by endpoint id.
    assert!(state.wg_engines.contains_key(&7), "engine instantiated");
    assert_eq!(state.wg_engines.get(&7).unwrap().listen_port(), 51820);
}

#[test]
fn wg_endpoint_with_malformed_key_is_dropped() {
    let mut snap = wg_snapshot(51820, &[], "");
    snap.tunnel_endpoints[0].wg_local_privkey_hex = "deadbeef".into(); // wrong length
    let state = build_forwarding_state(&snap);
    assert!(
        !state.tunnel_endpoints.contains_key(&7),
        "endpoint with malformed key must be dropped, not half-installed"
    );
    assert!(!state.has_wg_tunnels);
}

#[test]
fn wg_reload_reuses_engine_when_identity_unchanged() {
    let snap = wg_snapshot(51820, &["10.0.0.0/24"], "203.0.113.1:51820");
    let prev = build_forwarding_state(&snap);
    let prev_engine = prev.wg_engines.get(&7).unwrap().clone();
    // Rebuild with the SAME config, threading `previous`.
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();
    let next_engine = next.wg_engines.get(&7).unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&prev_engine, next_engine),
        "unchanged WG identity must reuse the same engine Arc (no reconcile)"
    );
}

#[test]
fn wg_reload_seeds_high_water_on_identity_change() {
    let snap = wg_snapshot(51820, &["10.0.0.0/24"], "203.0.113.1:51820");
    let prev = build_forwarding_state(&snap);
    // Advance the prior engine's TAI64N clock via an initiation.
    let prev_engine = prev.wg_engines.get(&7).unwrap();
    let peer_pub = prev_engine.first_peer_pubkey().unwrap();
    let mut out = [0u8; crate::afxdp::wg::WG_MSG_INIT_LEN];
    prev_engine.create_initiation(&peer_pub, &mut out).unwrap();
    let prev_hw = prev_engine.tai64n_high_water().expect("clock advanced");

    // Change the identity (different listen port) so a fresh engine is built.
    let snap2 = wg_snapshot(51821, &["10.0.0.0/24"], "203.0.113.1:51820");
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap2,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();
    let next_engine = next.wg_engines.get(&7).unwrap();
    assert!(
        !std::sync::Arc::ptr_eq(prev_engine, next_engine),
        "changed identity must build a fresh engine"
    );
    assert_eq!(next_engine.listen_port(), 51821);
    let next_hw = next_engine.tai64n_high_water().expect("seeded from prior");
    assert!(
        next_hw >= prev_hw,
        "fresh engine TAI64N high-water must be seeded >= the prior engine's"
    );
}

#[test]
fn wg_endpoint_v6_bracketed_hydrates_initiator_capable() {
    // A standard IPv6 endpoint `[addr]:port` must hydrate to
    // Some(SocketAddr) with the authored port so the peer can INITIATE
    // handshakes/keepalives — not None (responder-only) (#5182).
    let snap = wg_snapshot(51820, &["10.0.0.0/24"], "[2001:db8::1]:51820");
    let state = build_forwarding_state(&snap);
    let ep = state.tunnel_endpoints.get(&7).expect("WG endpoint present");
    assert_eq!(ep.wg_peers.len(), 1);
    let want: std::net::SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
    assert_eq!(
        ep.wg_peers[0].endpoint,
        Some(want),
        "bracketed IPv6 endpoint must hydrate initiator-capable with its port"
    );
}

#[test]
fn wg_endpoint_nonempty_unparseable_drops_row() {
    // A non-empty endpoint that does not parse to a concrete SocketAddr
    // (here a port-stripped bare host — exactly the #5182 tokenizer bug's
    // output) must fail the ROW closed, NOT silently degrade the peer to
    // responder-only. FAIL-ON-REVERT: the pre-fix `.parse().ok()` coerced
    // this to None and KEPT the row, so it would still contain key 7.
    let snap = wg_snapshot(51820, &["10.0.0.0/24"], "2001:db8::1");
    let state = build_forwarding_state(&snap);
    assert!(
        !state.tunnel_endpoints.contains_key(&7),
        "non-empty unparseable WG endpoint must drop the row, not hydrate responder-only"
    );
    assert!(!state.has_wg_tunnels);
}

#[test]
fn wg_endpoint_with_zero_listen_port_is_dropped() {
    // A WG tunnel with no listen port cannot bind a socket and is
    // invisible to the shim gate; it must be dropped, not installed as a
    // half-dead tunnel binding port 0 (Codex MAJOR).
    let snap = wg_snapshot(0, &["10.0.0.0/24"], "203.0.113.1:51820");
    let state = build_forwarding_state(&snap);
    assert!(
        !state.tunnel_endpoints.contains_key(&7),
        "WG endpoint with listen_port 0 must be dropped"
    );
    assert!(!state.has_wg_tunnels);
    assert!(!state.wg_engines.contains_key(&7));
}

// ---------------------------------------------------------------------
// #1873 — stable-id contract: removing one tunnel preserves the OTHER
// tunnels' engines + remap purge-set computation.
// ---------------------------------------------------------------------

fn two_tunnel_snapshot() -> ConfigSnapshot {
    ConfigSnapshot {
        tunnel_endpoints: vec![
            crate::protocol::snapshot::TunnelEndpointSnapshot {
                id: 824,
                interface: "gr-0/0/0.0".into(),
                linux_name: "gr-0-0-0".into(),
                ifindex: 41,
                mode: "gre".into(),
                source: "172.16.80.8".into(),
                destination: "203.0.113.9".into(),
                transport_table: "inet.0".into(),
                ttl: 64,
                ..Default::default()
            },
            crate::protocol::snapshot::TunnelEndpointSnapshot {
                id: 7,
                interface: "wg0".into(),
                linux_name: "wg0".into(),
                ifindex: 42,
                mode: "wireguard".into(),
                wg_listen_port: 51820,
                wg_local_privkey_hex: WG_TEST_PRIVKEY_HEX.into(),
                wg_peers: vec![crate::protocol::snapshot::TunnelWgPeerSnapshot {
                    wg_peer_pubkey_hex: WG_TEST_PEERKEY_HEX.into(),
                    wg_allowed_ips: vec!["10.0.0.0/24".into()],
                    wg_endpoint: "203.0.113.1:51820".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

/// #1873 contract pin: with stable (Go-side content-derived) ids, a
/// snapshot that removes one tunnel keeps the OTHER tunnel's id, so
/// `populate_wg_engines` reuses the survivor's engine Arc verbatim —
/// no rebuild, no session reset, no TAI64N reseed. Under the retired
/// positional allocator the survivor's id shifted and this test's
/// Arc::ptr_eq assertion is exactly what broke.
#[test]
fn wg_engine_survives_unrelated_tunnel_removal() {
    let snap = two_tunnel_snapshot();
    let prev = build_forwarding_state(&snap);
    let prev_engine = prev.wg_engines.get(&7).unwrap().clone();

    // Remove the GRE tunnel; the WG row is byte-identical (same id —
    // the Go allocator guarantees this since #1873).
    let mut snap2 = two_tunnel_snapshot();
    snap2.tunnel_endpoints.retain(|ep| ep.id == 7);
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap2,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();
    let next_engine = next.wg_engines.get(&7).unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&prev_engine, next_engine),
        "removing an unrelated tunnel must not rebuild the WG engine (#1873)"
    );
}

/// #4103: a routine WG config change (here: adding an allowed-ip to a
/// peer) forces an identity-change engine rebuild via `WgEngine::new`,
/// which starts from an empty peer table and gives every peer a fresh
/// `Peer::new` with `greatest_tai64n = [0; 12]`. The #4092 responder
/// anti-replay high-water for each SURVIVING peer must be carried forward
/// across that rebuild, else a benign commit silently disarms the
/// anti-replay (an attacker could replay a captured type-1 initiation).
/// This pins `populate_wg_engines`' `seed_greatest_tai64n` carry-over:
/// reverting it leaves the fresh peer at `[0; 12]` and this assert goes
/// RED.
#[test]
fn wg_responder_high_water_survives_config_change_rebuild() {
    let prev = build_forwarding_state(&wg_snapshot(51820, &["10.0.0.0/24"], "203.0.113.1:51820"));
    let prev_engine = prev.wg_engines.get(&7).expect("prev WG engine").clone();

    // Simulate a valid accepted type-1 initiation advancing this peer's
    // responder high-water (as `check_and_update_tai64n` would on a real
    // handshake). Key by the peer's own pubkey (read back from the engine).
    let pubkey = prev_engine.greatest_tai64n_by_pubkey()[0].0;
    let t_last: [u8; 12] = [0x40, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    prev_engine.seed_greatest_tai64n(&[(pubkey, t_last)]);
    assert_eq!(prev_engine.greatest_tai64n_by_pubkey(), vec![(pubkey, t_last)]);

    // Add an allowed-ip — a benign change that flips `wg_peers_eq` and so
    // rebuilds the whole engine.
    let snap2 = wg_snapshot(51820, &["10.0.0.0/24", "192.168.0.0/24"], "203.0.113.1:51820");
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap2,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();
    let next_engine = next.wg_engines.get(&7).expect("next WG engine");

    // The engine was genuinely rebuilt (different Arc) — this is the case
    // that resets the high-water without the #4103 carry-over.
    assert!(
        !std::sync::Arc::ptr_eq(&prev_engine, next_engine),
        "adding an allowed-ip must rebuild the WG engine (identity change)"
    );
    // #4103: the surviving peer's responder high-water is carried forward,
    // NOT reset to [0; 12] — so a replayed type-1 (recovered TAI64N
    // `<= t_last`) still fails `check_and_update_tai64n`.
    assert_eq!(
        next_engine.greatest_tai64n_by_pubkey(),
        vec![(pubkey, t_last)],
        "responder anti-replay high-water must survive an identity-change rebuild (#4103)"
    );
}

/// #1873 R-D purge-set pins: (a) vanished id purged, (b) owner-name
/// change purged, (c) cosmetic linux_name change NOT purged,
/// (d) untouched ids NOT purged.
#[test]
fn tunnel_remap_purge_ids_owner_change_semantics() {
    use crate::afxdp::coordinator::tunnel_remap_purge_ids;
    let prev = build_forwarding_state(&two_tunnel_snapshot());

    // (a) vanished: remove the GRE row.
    let mut snap_removed = two_tunnel_snapshot();
    snap_removed.tunnel_endpoints.retain(|ep| ep.id == 7);
    let next = build_forwarding_state(&snap_removed);
    assert_eq!(tunnel_remap_purge_ids(&prev, &next, true), vec![824]);

    // (b) owner change: id 824 now belongs to a DIFFERENT logical name
    // (temporal hash reuse).
    let mut snap_reused = two_tunnel_snapshot();
    snap_reused.tunnel_endpoints[0].interface = "gr-9/9/9.0".into();
    let next = build_forwarding_state(&snap_reused);
    assert_eq!(tunnel_remap_purge_ids(&prev, &next, true), vec![824]);

    // (c) cosmetic linux_name rename, logical name unchanged: NO purge.
    let mut snap_renamed = two_tunnel_snapshot();
    snap_renamed.tunnel_endpoints[0].linux_name = "gre-renamed".into();
    let next = build_forwarding_state(&snap_renamed);
    assert!(tunnel_remap_purge_ids(&prev, &next, true).is_empty());

    // (d) identical set: NO purge.
    let next = build_forwarding_state(&two_tunnel_snapshot());
    assert!(tunnel_remap_purge_ids(&prev, &next, true).is_empty());
}

/// #1873 owner-check pins (Codex code r2 — replaces the unsound r1
/// defer + rotation-barrier design): a re-owned id installs
/// IMMEDIATELY (no defer), the unrelated WG endpoint's engine Arc is
/// reused verbatim, and the purge set plus the per-packet owner check
/// (not apply-time timing) carry the correctness burden.
#[test]
fn reowned_tunnel_id_installs_immediately_with_engine_reuse() {
    let prev = build_forwarding_state(&two_tunnel_snapshot());

    // Same snapshot, id 824 re-owned by a different logical name.
    let mut snap_reused = two_tunnel_snapshot();
    snap_reused.tunnel_endpoints[0].interface = "gr-9/9/9.0".into();
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap_reused,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();
    let ep = next
        .tunnel_endpoints
        .get(&824)
        .expect("new owner installed");
    assert_eq!(ep.interface, "gr-9/9/9.0");
    // The unrelated WG endpoint keeps its engine Arc across the apply.
    assert!(next.tunnel_endpoints.contains_key(&7));
    assert!(std::sync::Arc::ptr_eq(
        prev.wg_engines.get(&7).expect("prev engine"),
        next.wg_engines.get(&7).expect("next engine"),
    ));
}

/// #1873 purge-set pin (Codex code r2): an id NEWLY APPEARING in
/// `next` (absent in `previous`) is purged when
/// `include_new_appearances` is set — any entry still storing it
/// (e.g. a synced copy installed with an unresolvable id during HA
/// config skew) predates `previous` and must die before the new
/// owner's row is reachable. The first-apply arm (flag false) skips
/// it so boot-time synced sessions survive.
#[test]
fn newly_appearing_tunnel_id_is_purged_after_first_apply() {
    use crate::afxdp::coordinator::tunnel_remap_purge_ids;
    // previous has only the WG endpoint; next adds the GRE row (824).
    let mut snap_wg_only = two_tunnel_snapshot();
    snap_wg_only.tunnel_endpoints.retain(|ep| ep.id == 7);
    let prev = build_forwarding_state(&snap_wg_only);
    let next = build_forwarding_state(&two_tunnel_snapshot());
    assert_eq!(tunnel_remap_purge_ids(&prev, &next, true), vec![824]);
    assert!(tunnel_remap_purge_ids(&prev, &next, false).is_empty());
}

/// #1873 owner check (Codex code r2): a stale session whose stored
/// tunnel resolution was created against a DIFFERENT owning netdev of
/// the same id must NEVER adopt the new owner at re-resolution — the
/// stored egress_ifindex (= the owner's logical_ifindex at resolve
/// time) is the discriminator, independent of purge timing, worker
/// rotation, or which forwarding state the worker held at create.
#[test]
fn stale_session_never_adopts_reowned_tunnel_id() {
    use crate::afxdp::ShardedNeighborMap;
    use crate::afxdp::session_glue::lookup_forwarding_resolution_for_session;

    let state = build_forwarding_state(&two_tunnel_snapshot());
    let row_ifindex = state
        .tunnel_endpoints
        .get(&824)
        .expect("gre row")
        .logical_ifindex;
    let flow = crate::afxdp::SessionFlow {
        src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 61, 102)),
        dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
        forward_key: crate::session::SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 6,
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 61, 102)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
            src_port: 55068,
            dst_port: 5201,
                    discriminator: Default::default(),
                    routing_domain: 0,
        },
    };
    let stale_decision = crate::session::SessionDecision {
        resolution: crate::afxdp::ForwardingResolution {
            disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
            local_ifindex: 0,
            // The OLD owner's netdev ifindex — different from the
            // current row's.
            egress_ifindex: row_ifindex + 1000,
            tx_ifindex: 3,
            tunnel_endpoint_id: 824,
            next_hop: None,
            neighbor_mac: Some([2, 0, 0, 0, 0, 9]),
            src_mac: Some([2, 0, 0, 0, 0, 1]),
            tx_vlan_id: 0,
        },
        nat: crate::nat::NatDecision::default(),
    };
    let resolved = lookup_forwarding_resolution_for_session(
        &state,
        &std::sync::Arc::new(ShardedNeighborMap::new()),
        &flow,
        stale_decision,
    );
    assert_eq!(
        resolved.disposition,
        crate::afxdp::ForwardingDisposition::NoRoute,
        "stale owner must be gated, never re-resolved into the new owner"
    );
    assert_eq!(
        resolved.tunnel_endpoint_id, 824,
        "the gated resolution stays tunnel-marked so the R-C gate drops it"
    );
    assert_eq!(
        resolved.egress_ifindex,
        row_ifindex + 1000,
        "the stale egress_ifindex survives write-back so the gate stays sticky"
    );

    // Control: a session created against the CURRENT owner re-resolves
    // normally (the cached ForwardCandidate fallback applies when the
    // outer route is unresolvable in this fixture).
    let mut fresh_decision = stale_decision;
    fresh_decision.resolution.egress_ifindex = row_ifindex;
    let resolved = lookup_forwarding_resolution_for_session(
        &state,
        &std::sync::Arc::new(ShardedNeighborMap::new()),
        &flow,
        fresh_decision,
    );
    assert_ne!(
        (resolved.disposition, resolved.egress_ifindex),
        (crate::afxdp::ForwardingDisposition::NoRoute, 0),
        "matching owner must not be gated"
    );
}

/// #1873 owner-RG attribution pin (Codex code r3 MAJOR 2): a stale
/// tunnel resolution (stored egress_ifindex != the current row's
/// logical_ifindex) must NOT inherit the NEW owner's redundancy group
/// — owner_rg_for_resolution returns 0 (unknown) so HA metadata and
/// owner-RG indexes keep their existing attribution.
#[test]
fn stale_owner_resolution_does_not_inherit_new_owner_rg() {
    use crate::afxdp::owner_rg_for_resolution;
    let mut snap = two_tunnel_snapshot();
    snap.tunnel_endpoints[0].redundancy_group = 2;
    let state = build_forwarding_state(&snap);
    let row_ifindex = state
        .tunnel_endpoints
        .get(&824)
        .expect("gre row")
        .logical_ifindex;
    let mut resolution = crate::afxdp::ForwardingResolution {
        disposition: crate::afxdp::ForwardingDisposition::ForwardCandidate,
        local_ifindex: 0,
        egress_ifindex: row_ifindex,
        tx_ifindex: 3,
        tunnel_endpoint_id: 824,
        next_hop: None,
        neighbor_mac: None,
        src_mac: None,
        tx_vlan_id: 0,
    };
    assert_eq!(owner_rg_for_resolution(&state, resolution), 2);
    // Stale owner: a different netdev owned this id when the session
    // resolved — never attribute the new owner's RG.
    resolution.egress_ifindex = row_ifindex + 1000;
    assert_eq!(owner_rg_for_resolution(&state, resolution), 0);
    // Synced entries installed with an unresolvable id (egress 0)
    // keep the current-row attribution (no discriminator to check).
    resolution.egress_ifindex = 0;
    assert_eq!(owner_rg_for_resolution(&state, resolution), 2);
}

/// #1873 reconcile-boundary purge pin (AGY code r3 / Codex code r3):
/// the reconcile path diffs against the tunnel-owner map captured
/// BEFORE teardown defaults coord.forwarding — the owners-list flavor
/// must implement all three arms, and the new-appearance arm must be
/// skippable for the genuine first apply.
#[test]
fn tunnel_remap_purge_ids_from_owners_semantics() {
    use crate::afxdp::coordinator::tunnel_remap_purge_ids_from_owners;
    let next = build_forwarding_state(&two_tunnel_snapshot());

    // Vanished id.
    let owners = vec![
        (824u16, "gr-0/0/0.0".to_string()),
        (7u16, "wg0".to_string()),
        (901u16, "gr-1/1/1.0".to_string()),
    ];
    assert_eq!(
        tunnel_remap_purge_ids_from_owners(&owners, &next, true),
        vec![901]
    );

    // Owner change at a surviving id.
    let owners = vec![
        (824u16, "gr-old/0/0.0".to_string()),
        (7u16, "wg0".to_string()),
    ];
    assert_eq!(
        tunnel_remap_purge_ids_from_owners(&owners, &next, true),
        vec![824]
    );

    // New appearance: id 824 absent from the prior owners.
    let owners = vec![(7u16, "wg0".to_string())];
    assert_eq!(
        tunnel_remap_purge_ids_from_owners(&owners, &next, true),
        vec![824]
    );
    assert!(tunnel_remap_purge_ids_from_owners(&owners, &next, false).is_empty());

    // Pristine first apply (empty owners + flag false): nothing purged.
    assert!(tunnel_remap_purge_ids_from_owners(&[], &next, false).is_empty());
}

// #2008 H3/H4: pin the snapshot -> runtime read of the ALG-disable
// bitfield in forwarding_build/mod.rs (`state.alg_disable_flags =
// snapshot.flow.alg_disable_flags`). Without this assertion the wire
// plumbing is untested end to end: the Go-packing tests and the pure
// `alg_type_for_session` tests both stay green even if the build step
// is reverted to a hardcoded 0, so the flag would silently never reach
// the conntrack publisher. MUTATION-VERIFY: hardcoding line 175 to 0
// (or dropping the assignment) must fail this test.
#[test]
fn build_forwarding_state_carries_alg_disable_flags() {
    // DNS (0x01) + FTP (0x02) disabled.
    let flags: u8 = 0x01 | 0x02;
    let snapshot = ConfigSnapshot {
        flow: crate::FlowSnapshot {
            alg_disable_flags: flags,
            ..Default::default()
        },
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        state.alg_disable_flags, flags,
        "ForwardingState.alg_disable_flags must equal snapshot.flow.alg_disable_flags"
    );
}

// #2008 H14: pin the snapshot -> runtime read of `power_mode_disable` in
// forwarding_build/mod.rs (`state.power_mode_disable =
// snapshot.flow.power_mode_disable`). MUTATION-VERIFY: dropping that
// assignment (leaving the ForwardingState default of false) must fail this
// test.
#[test]
fn build_forwarding_state_carries_power_mode_disable() {
    let snapshot = ConfigSnapshot {
        flow: crate::FlowSnapshot {
            power_mode_disable: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.power_mode_disable,
        "ForwardingState.power_mode_disable must equal snapshot.flow.power_mode_disable"
    );
}

// #3360: pin the snapshot -> runtime read of `gre_acceleration` in
// forwarding_build/mod.rs (`state.gre_acceleration =
// snapshot.flow.gre_acceleration`). MUTATION-VERIFY: dropping that assignment
// (leaving the ForwardingState default of false) must fail this test. Before
// #3360 the field was deserialized and shown in `show security flow` but never
// assigned into runtime state — a silent config-truth gap.
#[test]
fn build_forwarding_state_carries_gre_acceleration() {
    let snapshot = ConfigSnapshot {
        flow: crate::FlowSnapshot {
            gre_acceleration: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.gre_acceleration,
        "ForwardingState.gre_acceleration must equal snapshot.flow.gre_acceleration"
    );
}

// #hb166 T-4: an admitted interface whose scheduler-map materializes ONLY
// best-effort (queue 0) but whose DSCP classifier steers a code-point to
// `voice` (queue 5, NOT materialized) must NOT write the unmaterialized queue
// id into the per-interface table — that id has no queue at runtime and the
// enqueue path DROPS every packet of that code-point (a 100% silent
// blackhole). It must fail SAFE: fall back to the interface default queue so
// the traffic forwards on best-effort.
//
// FAIL-ON-REVERT: dropping the materialized-queue filter in
// build_cos_dscp_queue_table (writing `queue_id` verbatim) makes
// dscp_queue_by_dscp[46] == 5 again, reproducing the blackhole.
#[test]
fn build_cos_state_classifier_unmaterialized_queue_falls_back_to_default() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 77,
            cos_shaping_rate_bytes_per_sec: 10_000_000,
            cos_scheduler_map: "be-only".into(),
            cos_dscp_classifier: "wan-classifier".into(),
            cos_ieee8021_classifier: "wan-pcp".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![
                CoSForwardingClassSnapshot {
                    name: "best-effort".into(),
                    queue: 0,
                },
                CoSForwardingClassSnapshot {
                    name: "voice".into(),
                    queue: 5,
                },
            ],
            dscp_classifiers: vec![CoSDSCPClassifierSnapshot {
                name: "wan-classifier".into(),
                entries: vec![
                    // DSCP 46 -> voice (queue 5) is NOT materialized by the
                    // scheduler-map -> must fall back to default queue 0.
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "voice".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![46],
                    },
                    // DSCP 0 -> best-effort (queue 0) IS materialized -> admits
                    // the interface and stays queue 0.
                    CoSDSCPClassifierEntrySnapshot {
                        forwarding_class: "best-effort".into(),
                        loss_priority: "low".into(),
                        dscp_values: vec![0],
                    },
                ],
            }],
            ieee8021_classifiers: vec![CoSIEEE8021ClassifierSnapshot {
                name: "wan-pcp".into(),
                entries: vec![CoSIEEE8021ClassifierEntrySnapshot {
                    // PCP 5 -> voice (queue 5) unmaterialized -> default 0.
                    forwarding_class: "voice".into(),
                    loss_priority: "low".into(),
                    code_points: vec![5],
                }],
            }],
            dscp_rewrite_rules: vec![],
            schedulers: vec![CoSSchedulerSnapshot {
                name: "be".into(),
                transmit_rate_bytes: 1_000_000,
                transmit_rate_percent: 0.0,
                transmit_rate_exact: false,
                priority: "low".into(),
                buffer_size_bytes: 0,
                buffer_size_percent: 0.0,
                surplus_sharing: false,
                equal_flow_enforcement: false,
                equal_flow_target_policy: String::new(),
                codel_target_ns: 0,
                ..Default::default()
            }],
            // Materializes ONLY best-effort (queue 0). voice/queue 5 is never
            // built on this interface.
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "be-only".into(),
                entries: vec![CoSSchedulerMapEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    scheduler: "be".into(),
                }],
            }],
            inet_precedence_classifiers: vec![],
        }),
        ..Default::default()
    };

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&77).expect("missing CoS interface");
    // The interface materializes only queue 0.
    assert!(
        iface.queues.iter().all(|queue| queue.queue_id == 0),
        "scheduler-map materializes only best-effort (queue 0)"
    );
    assert_eq!(iface.default_queue, 0);
    // The blackhole code-points now resolve to the default queue, NOT the
    // unmaterialized queue 5.
    assert_eq!(
        iface.dscp_queue_by_dscp[46], 0,
        "DSCP 46 -> unmaterialized queue 5 must fall back to default queue 0 (no blackhole)"
    );
    assert_eq!(
        iface.ieee8021_queue_by_pcp[5], 0,
        "PCP 5 -> unmaterialized queue 5 must fall back to default queue 0 (no blackhole)"
    );
    // The materialized best-effort code-point is unchanged.
    assert_eq!(iface.dscp_queue_by_dscp[0], 0);
}

/// #3651 gate F1: bind the CONFIG-APPLY block that produces BOTH per-zone
/// counter families.
///
/// `forwarding_build` is the only place `zone_counter_slot_map` /
/// `zone_counter_store` and `flood_counter_slot_map` / `flood_counter_store`
/// are populated from a `ConfigSnapshot`. Before this test, every other test
/// reference to those fields was a HAND-ASSIGNMENT — so deleting either build
/// block verbatim left the whole cargo suite green (measured: `4256 passed;
/// 0 failed` with the flood block gone, and the same with the already-merged
/// traffic block gone).
///
/// The undetected runtime consequence is total: an unbuilt slot map is
/// `empty()`, so every zone resolves to slot 0, `record_zone_flood_drop` /
/// `record_zone_traffic` return at their `slot == 0` guard for every packet on
/// every zone, nothing is ever published, and every read surface reports
/// `ErrCounterNotPopulated`. That is bit-for-bit the pre-#3651 state the
/// populate work exists to close — reachable with a fully green suite.
///
/// Covers BOTH families deliberately: the traffic half is an inherited gap of
/// the same shape, and one test closes both cells.
///
/// Second leg binds the CARRY-FORWARD half: `previous`-threaded totals must
/// survive a re-apply, which is what makes counters survive a config commit.
#[test]
fn config_apply_builds_both_per_zone_counter_slot_maps_3651() {
    use crate::afxdp::flood_counters::{flush_recorded_flood_counters, record_zone_flood_drop};
    use crate::afxdp::zone_counters::{flush_recorded_zone_counters, record_zone_traffic};

    const TRUST: u16 = 50675; // config::StableZoneID("trust")
    const UNTRUST: u16 = 20665; // config::StableZoneID("untrust")

    let mut snapshot = ConfigSnapshot::default();
    snapshot.zones = vec![
        ZoneSnapshot {
            name: "trust".to_string(),
            id: TRUST,
            ..Default::default()
        },
        ZoneSnapshot {
            name: "untrust".to_string(),
            id: UNTRUST,
            ..Default::default()
        },
    ];

    let first = build_forwarding_state(&snapshot);

    // Leg 1: BOTH slot maps must come back built from the snapshot's zone set.
    // Deleting either build block leaves that family's map `empty()`, so every
    // zone resolves to slot 0 and the assertion below fires.
    for (label, slotted) in [
        ("flood", first.flood_counter_slot_map.slot_of(TRUST)),
        ("traffic", first.zone_counter_slot_map.slot_of(TRUST)),
    ] {
        assert_ne!(
            slotted, 0,
            "config apply did not build the {label} slot map: zone TRUST resolves to \
             slot 0, so every packet on it takes the `slot == 0` early return and the \
             zone can never publish -- the pre-#3651 not-populated state, with a \
             green suite"
        );
    }
    for (label, slotted) in [
        ("flood", first.flood_counter_slot_map.slot_of(UNTRUST)),
        ("traffic", first.zone_counter_slot_map.slot_of(UNTRUST)),
    ] {
        assert_ne!(
            slotted, 0,
            "config apply did not build the {label} slot map for the SECOND zone: a \
             one-zone assertion could pass on an off-by-one that still slots only one"
        );
    }
    // Neither family may claim overflow on a two-zone config -- that would mean
    // the build ran with the wrong id set.
    assert!(!first.flood_counter_slot_map.overflow_active);
    assert!(!first.zone_counter_slot_map.overflow_active);

    // Leg 2: totals must SURVIVE a re-apply through the `previous` thread. This
    // is what makes per-zone counters survive a config commit; without the
    // carry-forward the store is recreated empty and every count resets to 0 on
    // every commit.
    record_zone_flood_drop(&first.flood_counter_slot_map, TRUST, "syn-flood");
    flush_recorded_flood_counters(&first.flood_counter_store, &first.flood_counter_slot_map);
    record_zone_traffic(&first.zone_counter_slot_map, TRUST, UNTRUST, 1500);
    flush_recorded_zone_counters(&first.zone_counter_store, &first.zone_counter_slot_map);

    let second = build_forwarding_state_with_policy_counters_and_previous(
        &snapshot,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&first),
    )
    .expect("re-apply of a clean snapshot must build");

    let flood = second.flood_counter_store.snapshot();
    let trust_flood = flood
        .iter()
        .find(|r| r.zone_id == TRUST)
        .expect("flood totals must survive the re-apply (previous store carried forward)");
    assert_eq!(
        trust_flood.syn_flood_events, 1,
        "flood count reset across a config apply: the carry-forward is what makes \
         per-zone counters survive a commit"
    );

    let traffic = second.zone_counter_store.snapshot();
    let trust_traffic = traffic
        .iter()
        .find(|r| r.zone_id == TRUST)
        .expect("traffic totals must survive the re-apply (previous store carried forward)");
    assert_eq!(trust_traffic.ingress_packets, 1);
    assert_eq!(trust_traffic.ingress_bytes, 1500);

    // And the rebuilt maps are still live, not left empty by the re-apply.
    assert_ne!(second.flood_counter_slot_map.slot_of(TRUST), 0);
    assert_ne!(second.zone_counter_slot_map.slot_of(TRUST), 0);
}

/// #6847: an inet-precedence classifier code-point outside the 3-bit
/// IP-precedence domain (0..=7) fails the snapshot CLOSED via
/// `CosInetPrecedenceCodePointOutOfRange`, mirroring the #2447 dscp / 802.1p
/// backstops. Masking it (`& 0x7`) would install the classifier for a DIFFERENT
/// traffic class — 9 aliases onto precedence 1 — with no apply failure.
///
/// The Go commit gate (`collectCoSINetPrecedenceCodePoints`) rejects this
/// first; this guards helper-boundary version/snapshot drift, where the
/// producer is not necessarily the Go binary that was validated.
///
/// SCOPE — the check exists at TWO sites, and they are redundant for this
/// input: `build_cos_inet_precedence_queue_table` (over `queue_by_prec`) and
/// `build_cos_inet_precedence_lp_table` (over `lp_by_prec`). Those two maps are
/// filled in the same loop from the same entries, so their key sets are always
/// identical and no snapshot can reach one check without the other. Mutating
/// either site alone therefore leaves this test GREEN — measured, not assumed.
/// Both are kept because each is the natural bounds check for its own table and
/// neither should silently start depending on the other.
///
/// FAIL-ON-REVERT: replace BOTH `table.get_mut(usize::from(precedence))` bounds
/// checks with a masked `table[usize::from(precedence & 0x7)]` write and the
/// build succeeds, so the `expect_err` goes red.
#[test]
fn cos_inet_precedence_classifier_out_of_range_code_point_fails_closed() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 82,
            cos_shaping_rate_bytes_per_sec: 1,
            cos_inet_precedence_classifier: "wan-prec".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            inet_precedence_classifiers: vec![CoSINetPrecedenceClassifierSnapshot {
                name: "wan-prec".into(),
                entries: vec![CoSINetPrecedenceClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    precedences: vec![9], // > 7 — masking would alias onto 1
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![],
            scheduler_maps: vec![],
        }),
        ..Default::default()
    };
    let err = super::cos::build_cos_state(&snapshot).expect_err(
        "an out-of-range IP-precedence code-point must fail closed, not alias onto precedence 1",
    );
    match err {
        crate::policy::SnapshotIntegrityError::CosInetPrecedenceCodePointOutOfRange {
            classifier,
            precedence,
        } => {
            assert_eq!(classifier, "wan-prec");
            assert_eq!(precedence, 9);
        }
        other => panic!("expected CosInetPrecedenceCodePointOutOfRange, got {other:?}"),
    }
}

/// #6847: an interface whose ONLY CoS state is an inet-precedence classifier is
/// ADMITTED to `CoSState`.
///
/// The #1183 `useful_cos_state` gate skips interfaces that contribute no usable
/// CoS state. Omitting the inet-precedence arm from that gate would drop
/// exactly the plain `set class-of-service interfaces <if> unit 0 classifiers
/// inet-precedence <name>` config this issue is about — no shaping-rate, no
/// scheduler-map, no other classifier — so the classify arm would be
/// unreachable for the common case while every other test still passed.
///
/// FAIL-ON-REVERT: drop `|| inet_precedence_classifier_targets_iface_queue`
/// from `contributes_usable_cos_state` and `state.interfaces` is empty here.
#[test]
fn cos_inet_precedence_classifier_alone_admits_the_interface() {
    let snapshot = ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 83,
            cos_inet_precedence_classifier: "wan-prec".into(),
            ..Default::default()
        }],
        class_of_service: Some(ClassOfServiceSnapshot {
            forwarding_classes: vec![CoSForwardingClassSnapshot {
                name: "best-effort".into(),
                queue: 0,
            }],
            inet_precedence_classifiers: vec![CoSINetPrecedenceClassifierSnapshot {
                name: "wan-prec".into(),
                entries: vec![CoSINetPrecedenceClassifierEntrySnapshot {
                    forwarding_class: "best-effort".into(),
                    loss_priority: "low".into(),
                    precedences: vec![5],
                }],
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            schedulers: vec![],
            scheduler_maps: vec![],
        }),
        ..Default::default()
    };
    let state = super::cos::build_cos_state(&snapshot).expect("classifier-only snapshot must build");
    let cfg = state
        .interfaces
        .get(&83)
        .expect("an inet-precedence classifier alone must admit the interface to CoSState");
    assert_eq!(cfg.inet_precedence_classifier, "wan-prec");
    // precedence 5 -> best-effort -> queue 0; every other code-point stays
    // u8::MAX (unclassified).
    assert_eq!(cfg.inet_precedence_queue_by_prec[5], 0);
    assert_eq!(cfg.inet_precedence_queue_by_prec[4], u8::MAX);
}

// ── #5716: a rejected build must not prune the LIVE zone counters ─────
//
// `build_forwarding_state_with_policy_counters_and_previous` carries the
// previous state's `ZoneCounterStore` forward. That store is `Arc`-backed,
// so the carry-forward `clone()` is a handle on the SAME map the running
// workers fold into — not a copy. Pre-#5716 the build ran the destructive
// `reconcile()` (a `retain` to the incoming snapshot's zone set) in the
// middle of the builder, ahead of the fallible `filter_state` and `cos`
// steps. A snapshot that failed one of those was rejected by the
// reconcile/refresh preflight ("keeping previous forwarding state") — but
// the live store had already lost the removed zones' cumulative totals, so
// an operator's `show security zones` traffic counters silently reset on a
// commit that was never applied.
//
// Where the prune lives now, corrected twice. r1's shape — "the last statement
// before `Ok(state)`" — was replaced in r2 by the structural split, and that
// sentence survived here describing a tree that no longer existed: after r2 the
// prune was one of THREE statements in `attach_zone_counters`, with the
// slot-map construction and the store assignment following it. r5 moved it out
// of the build entirely, to `forwarding_build::commit_zone_counter_prune`,
// which each apply path calls at its own commit point. What remains in the
// build is additive only.

/// Live state for the two tests below: zones 100 and 200 configured, with
/// traffic folded into the shared store.
fn zone_counter_prev_state() -> ForwardingState {
    use crate::afxdp::zone_counters::{flush_recorded_zone_counters, record_zone_traffic};
    let prev_snapshot = ConfigSnapshot {
        zones: vec![
            ZoneSnapshot {
                name: "trust".into(),
                id: 100,
                ..Default::default()
            },
            ZoneSnapshot {
                name: "untrust".into(),
                id: 200,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let prev = build_forwarding_state(&prev_snapshot);
    record_zone_traffic(&prev.zone_counter_slot_map, 100, 200, 64);
    flush_recorded_zone_counters(&prev.zone_counter_store, &prev.zone_counter_slot_map);
    assert_eq!(
        prev.zone_counter_store.snapshot().len(),
        2,
        "both zones must be counting before the build under test"
    );
    prev
}

/// A snapshot with the given zone set and an extra defect, used to trip one
/// named fallible integrity belt.
fn zone_counter_snapshot_with_zones(zone_ids: &[u16]) -> ConfigSnapshot {
    ConfigSnapshot {
        zones: zone_ids
            .iter()
            .map(|&id| ZoneSnapshot {
                name: format!("zone{id}"),
                id,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

/// The candidate zone set every rejection row below builds on: it DROPS live
/// zone 200 and ADDS a brand-new zone 300, so one drive exercises both live-store
/// mutations a rejected build must not make — the destructive `reconcile` prune
/// of 200, and the `ZoneCounterSlotMap::build` get-or-create of 300.
const ZONE_COUNTER_CANDIDATE_ZONES: [u16; 2] = [100, 300];

/// FOUR of the inner builder's ten fallible integrity belts, chosen by
/// POSITION: a snapshot carrying the candidate zone set plus that belt's
/// defect, and the error it must raise. Deliberately not one row per belt —
/// the reason the four are the four is below.
///
/// The SPAN is what matters, not the count. #3719 duplicate-zone-id is the
/// builder's FIRST fallible step and #2410 CoS queue-id its LAST (nothing
/// fallible follows it), with #2240 NPTv6 and #3367/#2505 filter in between.
/// Every STRAIGHT-LINE statement position the zone-counter work could be
/// relocated to and still be a DEFECT is a position with a `?` below it — and
/// every one of those is above the LAST belt, so the CoS row observes the
/// relocation wherever it lands. That is the row that binds the ordering
/// invariant. (Straight-line is the quantifier's real scope: a relocation into
/// a conditionally-evaluated closure a given row's snapshot never enters would
/// escape that row — see the builder's doc comment.) The dup-zone row is what
/// makes "the last belt" a checkable bracket instead of an arbitrary pick: it
/// pins where the fallible region begins, and reds under a hoist above it.
///
/// A single-belt fixture binds neither: a fallible step relocated below the
/// zone-counter work leaves it green (measured — moving the NPTv6 step below
/// the prune left 4280 of 4281 tests passing). That second, weaker defect
/// class — one BELT moved below the binding rather than the binding moved up —
/// is caught only by that belt's OWN row, so the table covers it for these
/// four belts and not for the other six. Adding the six would buy only more of
/// that class; it would not strengthen the ordering bind above.
fn zone_counter_rejection_rows() -> Vec<(
    &'static str,
    ConfigSnapshot,
    fn(&crate::policy::SnapshotIntegrityError) -> bool,
)> {
    let mut dup_zone = zone_counter_snapshot_with_zones(&ZONE_COUNTER_CANDIDATE_ZONES);
    // #3719: a second zone re-using id 300. The FIRST fallible step in the
    // builder. Its job is to pin where the fallible region BEGINS, so "the
    // last belt" names a bracketed region rather than one arbitrary belt.
    //
    // Polarity, stated exactly, because an earlier round overshot it: this row
    // stays green only for a relocation strictly BELOW it — it rejects before
    // the relocated block could run — and those are precisely the relocations
    // the CoS row catches. A hoist ABOVE it, to the top of
    // `build_fallible_forwarding_state`, reds THIS row in both zone tests
    // (measured, #6832 fold r4: `left: 1, right: 2` on the prune test and
    // `left: [100, 300], right: [100, 200]` on the create test, both reported
    // against this row's label).
    dup_zone.zones.push(ZoneSnapshot {
        name: "clash".into(),
        id: 300,
        ..Default::default()
    });

    let mut nptv6 = zone_counter_snapshot_with_zones(&ZONE_COUNTER_CANDIDATE_ZONES);
    // #2240: an unparseable internal prefix.
    nptv6.nptv6_rules = vec![crate::Nptv6RuleSnapshot {
        name: "bad-parse".into(),
        from_zone: String::new(),
        internal_prefix: "not-a-prefix".into(),
        external_prefix: "2001:db8:9::/48".into(),
    }];

    let mut filter = zone_counter_snapshot_with_zones(&ZONE_COUNTER_CANDIDATE_ZONES);
    // #3367: the Go side could not parse the term's tcp-flags expression, so
    // the helper-side belt rejects rather than installing an unconstrained term.
    filter.filters = vec![FirewallFilterSnapshot {
        name: "f".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "t".into(),
            action: "discard".into(),
            tcp_flags_unparseable: true,
            ..Default::default()
        }],
    }];

    let mut cos = zone_counter_snapshot_with_zones(&ZONE_COUNTER_CANDIDATE_ZONES);
    // #2410: a forwarding-class queue id outside 0..=255. The LAST fallible
    // step in the builder.
    cos.interfaces = vec![InterfaceSnapshot {
        ifindex: 60,
        cos_shaping_rate_bytes_per_sec: 1,
        ..Default::default()
    }];
    cos.class_of_service = Some(ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "voice".into(),
            queue: 256,
        }],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        // #6847: this literal is exhaustive, so the new BA-classifier list
        // has to be named here. Empty keeps the fixture's meaning — the case
        // under test is the queue-id overflow on `forwarding_classes`.
        inet_precedence_classifiers: vec![],
        dscp_rewrite_rules: vec![],
    });

    vec![
        ("#3719 duplicate zone id (first fallible step)", dup_zone, {
            |e: &crate::policy::SnapshotIntegrityError| {
                matches!(
                    e,
                    crate::policy::SnapshotIntegrityError::DuplicateZoneId { .. }
                )
            }
        }),
        ("#2240 NPTv6 unparseable rule", nptv6, {
            |e: &crate::policy::SnapshotIntegrityError| {
                matches!(
                    e,
                    crate::policy::SnapshotIntegrityError::Nptv6UnparseableRule { .. }
                )
            }
        }),
        ("#3367 filter unparseable tcp-flags", filter, {
            |e: &crate::policy::SnapshotIntegrityError| {
                matches!(
                    e,
                    crate::policy::SnapshotIntegrityError::UnrepresentableFilterTCPFlags { .. }
                )
            }
        }),
        ("#2410 CoS queue id (last fallible step)", cos, {
            |e: &crate::policy::SnapshotIntegrityError| {
                matches!(
                    e,
                    crate::policy::SnapshotIntegrityError::CosQueueIdOutOfRange { .. }
                )
            }
        }),
    ]
}

/// One EXTRA rejection row, used ONLY by
/// `rejected_build_leaves_the_zone_store_clean_against_live_sibling_stores`
/// and deliberately NOT folded into [`zone_counter_rejection_rows`], whose
/// four rows are chosen by a different argument (span over the fallible
/// region) that this row would blur.
///
/// #6832 fold r7, review M1. That test asserts two residue facts — one about
/// the live POLICY store, one about the live NAT store — and each one's
/// expected value depends on where the row's belt sits relative to a
/// DIFFERENT call site in `build_fallible_forwarding_state`: the policy parse
/// (`parse_policy_state_with_counters`) and the source-NAT parse
/// (`parse_source_nat_rules_with_previous`), about sixty lines below it. Over
/// the four shared rows the two predicates are the SAME expression, because
/// every one of the four sits either ABOVE both parses (#3719) or BELOW both
/// (NPTv6 / filter / CoS). That is correct today only by coincidence of the
/// current builder layout: a belt landing anywhere in the region BETWEEN the
/// two parses makes one of the two assertions wrong, and no row in the shared
/// four can tell the difference.
///
/// This row is a belt in that region. #3402's unresolvable-zone reject fires
/// INSIDE the policy parse's rule loop, downstream of the per-rule
/// `counter_store.rule_hit_counter(&rule_id)` that resolves the probe rule's
/// counter (`policy.rs`) and upstream of the source-NAT parse. So it is the
/// one row with policy residue PRESENT and NAT residue ABSENT, and the two
/// predicates can no longer be written as one expression without a row
/// contradicting them.
///
/// The row supplies only the DEFECT rule. The caller inserts its probe rule at
/// index 0, so the probe's counter is resolved before this rule rejects.
fn policy_parse_interior_rejection_row() -> (
    &'static str,
    ConfigSnapshot,
    fn(&crate::policy::SnapshotIntegrityError) -> bool,
) {
    let mut snapshot = zone_counter_snapshot_with_zones(&ZONE_COUNTER_CANDIDATE_ZONES);
    snapshot.policies = vec![crate::protocol::PolicyRuleSnapshot {
        name: "unresolvable-to-zone".into(),
        from_zone: "zone100".into(),
        to_zone: "no-such-zone".into(),
        action: "permit".into(),
        ..Default::default()
    }];
    (
        "#3402 unresolvable policy zone (inside the policy parse)",
        snapshot,
        |e: &crate::policy::SnapshotIntegrityError| {
            matches!(
                e,
                crate::policy::SnapshotIntegrityError::UnresolvableZoneReference { .. }
            )
        },
    )
}

/// #6995: the three fallible belts that fire AFTER both the policy-counter and
/// NAT-counter bindings, each carrying rules that create a block in each store.
///
/// Deliberately NOT reusing `zone_counter_rejection_rows()` wholesale. That
/// table's first row (#3719 duplicate zone id) rejects at the builder's FIRST
/// fallible step — ABOVE `parse_policy_state_with_counters` and the NAT
/// reconcilers — so it produces no residue whether the rollback exists or not.
/// Including it would add a row that is green for the wrong reason and dilute
/// the matrix. The three below bracket the region that matters: every
/// straight-line position where the counter bindings sit has one of these `?`s
/// beneath it.
fn counter_residue_rejection_rows() -> Vec<(
    &'static str,
    ConfigSnapshot,
    fn(&crate::policy::SnapshotIntegrityError) -> bool,
)> {
    fn base() -> ConfigSnapshot {
        let mut snap = zone_counter_snapshot_with_zones(&ZONE_COUNTER_CANDIDATE_ZONES);
        // A candidate-only policy rule: its stable rule id is not in the live
        // store, so `rule_hit_counter` GET-CREATES a block for it.
        snap.policies = vec![crate::PolicyRuleSnapshot {
            name: "probe-rule".into(),
            from_zone: "zone100".into(),
            to_zone: "zone300".into(),
            action: "permit".into(),
            ..Default::default()
        }];
        // A candidate-only static-NAT rule with a counter id the live store has
        // never seen, so `rule_counter` GET-INSERTS a row for it. Addresses must
        // PARSE: `StaticNatTable::from_snapshots` `continue`s past an
        // unparseable rule before it ever reaches the counter, which would make
        // the NAT half of every assertion below pass for free.
        snap.static_nat_rules = vec![crate::StaticNATRuleSnapshot {
            name: "probe-static".into(),
            counter_id: COUNTER_RESIDUE_CANDIDATE_NAT_ID,
            external_ip: "198.51.100.7".into(),
            internal_ip: "10.9.9.7".into(),
            ..Default::default()
        }];
        snap
    }

    let mut nptv6 = base();
    // #2240: unparseable internal prefix — the FIRST belt below the bindings.
    nptv6.nptv6_rules = vec![crate::Nptv6RuleSnapshot {
        name: "bad-parse".into(),
        from_zone: String::new(),
        internal_prefix: "not-a-prefix".into(),
        external_prefix: "2001:db8:9::/48".into(),
    }];

    let mut filter = base();
    // #3367: the Go side could not parse the term's tcp-flags expression.
    filter.filters = vec![FirewallFilterSnapshot {
        name: "f".into(),
        family: "inet".into(),
        terms: vec![FirewallTermSnapshot {
            name: "t".into(),
            action: "discard".into(),
            tcp_flags_unparseable: true,
            ..Default::default()
        }],
    }];

    let mut cos = base();
    // #2410: a forwarding-class queue id outside 0..=255. The LAST fallible
    // step — nothing fallible follows it, so this row observes a relocation of
    // the counter bindings to ANY position in the builder.
    cos.interfaces = vec![InterfaceSnapshot {
        ifindex: 60,
        cos_shaping_rate_bytes_per_sec: 1,
        ..Default::default()
    }];
    cos.class_of_service = Some(ClassOfServiceSnapshot {
        forwarding_classes: vec![CoSForwardingClassSnapshot {
            name: "voice".into(),
            queue: 256,
        }],
        schedulers: vec![],
        scheduler_maps: vec![],
        dscp_classifiers: vec![],
        ieee8021_classifiers: vec![],
        inet_precedence_classifiers: vec![],
        dscp_rewrite_rules: vec![],
    });

    vec![
        ("#2240 NPTv6 unparseable rule", nptv6, {
            |e: &crate::policy::SnapshotIntegrityError| {
                matches!(
                    e,
                    crate::policy::SnapshotIntegrityError::Nptv6UnparseableRule { .. }
                )
            }
        }),
        ("#3367 filter tcp-flags unparseable", filter, {
            |e: &crate::policy::SnapshotIntegrityError| {
                matches!(
                    e,
                    crate::policy::SnapshotIntegrityError::UnrepresentableFilterTCPFlags { .. }
                )
            }
        }),
        ("#2410 CoS queue id out of range (last fallible step)", cos, {
            |e: &crate::policy::SnapshotIntegrityError| {
                matches!(
                    e,
                    crate::policy::SnapshotIntegrityError::CosQueueIdOutOfRange { .. }
                )
            }
        }),
    ]
}

/// The NAT counter id only the CANDIDATE carries.
const COUNTER_RESIDUE_CANDIDATE_NAT_ID: u32 = 4242;
/// The NAT counter id the LIVE store is already carrying when the rejected
/// build runs. It must SURVIVE — see the tests.
const COUNTER_RESIDUE_LIVE_NAT_ID: u32 = 7;
/// The policy rule id the LIVE store is already carrying. Must SURVIVE.
const COUNTER_RESIDUE_LIVE_POLICY_ID: &str = "live-zone-a->live-zone-b/live-rule";

/// Seed both live stores so a rejected build has something to DESTROY as well
/// as something to create.
///
/// This is the half that makes the two tests below distinguish a rollback from
/// a `clear()`. A test that only asserted "the candidate id is absent" would
/// pass against a fix that emptied the store outright — which would reset the
/// running configuration's cumulative hit counts on a commit that never
/// applied, i.e. the #5716 defect reintroduced in a new store.
fn seed_live_counter_stores() -> (PolicyCounterStore, crate::nat::NatCounterStore) {
    let policy = PolicyCounterStore::default();
    let nat = crate::nat::NatCounterStore::default();
    // Reach the private get-or-create through the public parse entry point the
    // production builder uses, so the seeding path is the production path.
    let live_rules = vec![crate::PolicyRuleSnapshot {
        name: "live-rule".into(),
        from_zone: "live-zone-a".into(),
        to_zone: "live-zone-b".into(),
        action: "permit".into(),
        ..Default::default()
    }];
    let mut zone_map = rustc_hash::FxHashMap::default();
    zone_map.insert("live-zone-a".to_string(), 100u16);
    zone_map.insert("live-zone-b".to_string(), 200u16);
    crate::policy::parse_policy_state_with_counters(
        "deny",
        &live_rules,
        &zone_map,
        &[],
        &policy,
    )
    .expect("the live seed policy must parse");
    let _ = nat.rule_counter(COUNTER_RESIDUE_LIVE_NAT_ID);
    assert!(
        policy
            .tracked_rule_ids()
            .iter()
            .any(|id| id == COUNTER_RESIDUE_LIVE_POLICY_ID),
        "fixture: the live policy rule id must be seeded, or 'it survived' is \
         vacuous. Got {:?}",
        policy.tracked_rule_ids()
    );
    assert_eq!(
        nat.tracked_ids(),
        vec![COUNTER_RESIDUE_LIVE_NAT_ID],
        "fixture: the live NAT counter id must be seeded"
    );
    (policy, nat)
}

/// #6995 PROPERTY 1 (the STORE): a rejected build must leave no block behind in
/// the live `PolicyCounterStore`, and must not disturb the ones already there.
///
/// `PolicyCounterStore::rule_hit_counter` GET-OR-CREATES out of the live,
/// `Arc`-shared store, and it runs inside `build_fallible_forwarding_state`
/// ahead of the NPTv6, filter and CoS belts. Before the rollback, a build those
/// belts rejected left one block per candidate-only rule — plus the reserved
/// default-policy id — in a store the discarded build's caller never asked to
/// mutate.
///
/// This half is memory-only: `Coordinator::policy_rule_counters` reads the
/// PUBLISHED forwarding state, not the store, so the residue is invisible to
/// operators. It is bound anyway because "invisible" is a property of today's
/// readers, not of the store — and because the NAT sibling proves the same
/// mechanism does reach an operator surface.
#[test]
fn rejected_build_does_not_leave_policy_blocks_in_the_live_store_6995() {
    for (label, snapshot, expected) in counter_residue_rejection_rows() {
        let (policy, nat) = seed_live_counter_stores();
        let before = policy.tracked_rule_ids();

        let err = match build_forwarding_state_with_policy_counters_and_previous(
            &snapshot,
            &policy,
            &nat,
            Some(&zone_counter_prev_state()),
        ) {
            Ok(_) => panic!("{label}: this snapshot must be rejected"),
            Err(e) => e,
        };
        assert!(
            expected(&err),
            "{label}: rejected through a different belt than the row names \
             ({err:?}) — the row is no longer exercising the belt it is here for"
        );

        assert_eq!(
            policy.tracked_rule_ids(),
            before,
            "{label}: a REJECTED build changed the live policy-counter registry. \
             Extra ids are residue keyed by the refused snapshot's own rules; \
             MISSING ids mean the rollback destroyed a running rule's cumulative \
             hit count on a commit that never applied"
        );
    }
}

/// #6995 PROPERTY 1 (the STORE), NAT half.
///
/// Same mechanism through `NatCounterStore::rule_counter`, which GET-OR-INSERTS
/// one row per NAT rule from the source / static / destination reconcilers.
#[test]
fn rejected_build_does_not_leave_nat_rows_in_the_live_store_6995() {
    for (label, snapshot, expected) in counter_residue_rejection_rows() {
        let (policy, nat) = seed_live_counter_stores();

        let err = match build_forwarding_state_with_policy_counters_and_previous(
            &snapshot,
            &policy,
            &nat,
            Some(&zone_counter_prev_state()),
        ) {
            Ok(_) => panic!("{label}: this snapshot must be rejected"),
            Err(e) => e,
        };
        assert!(expected(&err), "{label}: wrong belt ({err:?})");

        assert_eq!(
            nat.tracked_ids(),
            vec![COUNTER_RESIDUE_LIVE_NAT_ID],
            "{label}: a REJECTED build changed the live NAT-counter registry. \
             Id {COUNTER_RESIDUE_CANDIDATE_NAT_ID} belongs to a rule the build \
             refused and never installed; id {COUNTER_RESIDUE_LIVE_NAT_ID} is \
             the running configuration's and must survive"
        );
    }
}

/// #6995 PROPERTY 2 (the OPERATOR SURFACE): a rejected build must put no
/// phantom row on `ProcessStatus.nat_rule_counters`.
///
/// This is a SEPARATE property from the store assertion above, and it is bound
/// separately on purpose. `NatCounterStore::snapshots()` emits one row per
/// stored id *regardless of whether its packet/byte value is zero*, and that
/// feeds `server/helpers/status.rs` -> `ProcessStatus.nat_rule_counters` -> Go
/// `NATRuleCounters`. So the NAT half of this residue was operator-visible: a
/// refused commit put rows for a configuration that was never installed on the
/// status surface until the next successful commit evicted them.
///
/// The two assertions are not interchangeable. A "fix" that filtered
/// zero-valued rows out of `snapshots()` would satisfy THIS test while leaving
/// the store dirty — and would also hide legitimately-zero rows for rules that
/// really are installed. Binding the store first is what makes this one a
/// consequence rather than the whole claim.
#[test]
fn rejected_build_leaves_no_phantom_rows_on_the_nat_status_surface_6995() {
    for (label, snapshot, expected) in counter_residue_rejection_rows() {
        let (policy, nat) = seed_live_counter_stores();

        let err = match build_forwarding_state_with_policy_counters_and_previous(
            &snapshot,
            &policy,
            &nat,
            Some(&zone_counter_prev_state()),
        ) {
            Ok(_) => panic!("{label}: this snapshot must be rejected"),
            Err(e) => e,
        };
        assert!(expected(&err), "{label}: wrong belt ({err:?})");

        let rows = nat.snapshots();
        assert!(
            rows.iter()
                .all(|r| r.counter_id != COUNTER_RESIDUE_CANDIDATE_NAT_ID),
            "{label}: the status surface carries a NAT rule-counter row for id \
             {COUNTER_RESIDUE_CANDIDATE_NAT_ID}, which belongs to a commit that \
             was REFUSED and never installed. Rows: {rows:?}"
        );
        assert!(
            rows.iter()
                .any(|r| r.counter_id == COUNTER_RESIDUE_LIVE_NAT_ID),
            "{label}: the running configuration's NAT rule-counter row \
             disappeared from the status surface after a build that was \
             rejected. Rows: {rows:?}"
        );
    }
}

#[test]
fn rejected_build_does_not_prune_live_zone_counters() {
    // `ZoneCounterStore` is `Arc`-backed, so the build's carry-forward
    // `clone()` is a handle on the SAME map the running workers fold into —
    // not a copy. Pre-#5716 the build ran the destructive `reconcile()` (a
    // `retain` to the incoming snapshot's zone set) in the middle of the
    // builder, ahead of the fallible `filter_state` and `cos` steps. A
    // snapshot that failed one of those was rejected by the reconcile/refresh
    // preflight ("keeping previous forwarding state") — but the live store had
    // already lost the removed zones' cumulative totals, so an operator's
    // `show security zones` traffic counters silently reset on a commit that
    // was never applied.
    for (label, snapshot, expected) in zone_counter_rejection_rows() {
        let prev = zone_counter_prev_state();
        let err = match build_forwarding_state_with_policy_counters_and_previous(
            &snapshot,
            &PolicyCounterStore::default(),
            &crate::nat::NatCounterStore::default(),
            Some(&prev),
        ) {
            Ok(_) => panic!("{label}: this snapshot must be rejected"),
            Err(e) => e,
        };
        assert!(
            expected(&err),
            "{label}: rejected through a different belt than the row names              ({err:?}) — the row is no longer exercising the belt it is here for"
        );

        let live = prev.zone_counter_store.snapshot();
        assert_eq!(
            live.len(),
            2,
            "{label}: a REJECTED build pruned the live zone-counter store;              `show security zones` totals reset on a commit that never applied"
        );
        assert!(
            live.iter().any(|z| z.zone_id == 200),
            "{label}: zone 200's totals were dropped by a build that was rejected"
        );
    }
}

#[test]
fn rejected_build_does_not_create_zone_blocks_in_the_live_store() {
    // The mirror image of the prune, and the half the sparse snapshot hides.
    // `ZoneCounterSlotMap::build` GET-OR-CREATES one atomic block per
    // SLOT-ASSIGNED zone — a subset of the configured set, since it skips zone
    // id 0 and stops at `ZONE_COUNTER_ASSIGNABLE_SLOTS` — resolved out of the
    // store it is handed — and that is
    // the carried-forward, `Arc`-shared, LIVE store. So a candidate that
    // introduces a zone and is then REJECTED used to leave a zero-valued block
    // for that zone behind in the live map. `snapshot()` omits all-zero rows,
    // so operator-visible counts stay correct and nothing looks wrong; the map
    // just grows by one orphaned block per rejected commit that adds or
    // renumbers a zone, raising the cost of every snapshot, clear and
    // reconcile. Assert on the block set, not the snapshot.
    for (label, snapshot, expected) in zone_counter_rejection_rows() {
        let prev = zone_counter_prev_state();
        assert_eq!(
            prev.zone_counter_store.tracked_zone_ids_for_test(),
            vec![100, 200],
            "{label}: fixture must start with exactly the two live zones"
        );

        let err = match build_forwarding_state_with_policy_counters_and_previous(
            &snapshot,
            &PolicyCounterStore::default(),
            &crate::nat::NatCounterStore::default(),
            Some(&prev),
        ) {
            Ok(_) => panic!("{label}: this snapshot must be rejected"),
            Err(e) => e,
        };
        assert!(
            expected(&err),
            "{label}: rejected through a different belt than the row names ({err:?})"
        );

        assert_eq!(
            prev.zone_counter_store.tracked_zone_ids_for_test(),
            vec![100, 200],
            "{label}: a REJECTED build created a block for candidate-only zone \
             300 in the LIVE store — runtime state the discarded build's caller \
             never asked for, invisible to the sparse snapshot, and accumulating \
             one block per rejected commit"
        );
    }
}

#[test]
fn rejected_build_leaves_the_zone_store_clean_against_live_sibling_stores() {
    // #6832 fold r5. The two tests above pass a FRESH `PolicyCounterStore` and
    // `NatCounterStore` into every row. That is not neutral: those two stores
    // are also `Arc`-shared and are also written by the inner builder, ABOVE
    // the last three belts, so a rejected build leaves get-or-create residue in
    // each. Measured on this branch, with a candidate SNAT rule carrying a
    // fresh `counter_id` and a malformed NPTv6 rule to reject the build:
    //
    //   nat_residue  = [4242]        <- pre-existing, tracked as #6995
    //   zone_residue = [100, 200]    <- correct, this is what #6832 fixes
    //
    // Two things follow, and this test exists for the second. First, the
    // #6995 residue is real and out of scope here — neither introduced nor
    // fixed by this PR, and cross-referenced from `forwarding_build/mod.rs`
    // and `docs/userspace-dataplane-gaps.md`. Second, and the reason the fresh
    // stores are worth replacing in at least one row: a zone guarantee proved
    // only against EMPTY sibling stores is a guarantee about a configuration
    // that never happens in production, where all three arrive live and
    // populated off the same coordinator. This row runs the same four
    // rejection belts with all three stores live and asserts the zone half
    // still holds.
    //
    // #6832 fold r7 (review M1): plus a FIFTH belt the shared four do not
    // carry. The two residue predicates below are facts about two different
    // builder call sites — the policy parse and the source-NAT parse — and
    // over the shared four they collapse to the same expression, because all
    // four sit above both parses or below both. `#3402` rejects BETWEEN them,
    // so the set can now distinguish the two positions instead of merely
    // asserting them. See `policy_parse_interior_rejection_row`.
    for (label, snapshot, expected) in zone_counter_rejection_rows()
        .into_iter()
        .chain(std::iter::once(policy_parse_interior_rejection_row()))
    {
        let prev = zone_counter_prev_state();
        // Live siblings, pre-populated the way a running coordinator's are.
        // BOTH of them: r5 seeded only the NAT store and left `live_policy` a
        // bare `default()`, so the policy half of this row was still exactly
        // the empty neighbour the test exists to stop relying on, and the
        // gaps-doc claim that residue in BOTH stores is asserted was true of
        // one. The policy store is seeded through the PRODUCTION path — a
        // clean build, which get-or-creates the reserved default-policy
        // counter — rather than by poking the registry, so what it holds is
        // what a running coordinator's holds.
        let live_policy = PolicyCounterStore::default();
        let live_nat = crate::nat::NatCounterStore::default();
        let _ = live_nat.rule_counter(7777);
        build_forwarding_state_with_policy_counters_and_previous(
            &ConfigSnapshot::default(),
            &live_policy,
            &live_nat,
            None,
        )
        .expect("the empty seed snapshot must build");
        let policy_seed = live_policy.tracked_rule_ids_for_test();
        assert!(
            !policy_seed.is_empty(),
            "{label}: fixture precondition — the policy store must be LIVE \
             (non-empty) before the rejected build, or this row proves the \
             zone guarantee against an empty neighbour again"
        );
        let mut snapshot = snapshot;
        snapshot.source_nat_rules = vec![crate::protocol::SourceNATRuleSnapshot {
            name: "candidate-snat".into(),
            counter_id: 4242,
            ..Default::default()
        }];
        // A candidate-only POLICY rule, so the policy residue is
        // distinguishable from the seed the way `4242` is distinguishable from
        // `7777` on the NAT side. Without it the rejected build's policy
        // residue equals the seed (both just the reserved default-policy
        // counter) and no assertion here could tell a #6995 policy-side fix
        // from the status quo.
        //
        // INSERTED at index 0, not assigned over: the four shared rows carry
        // no policies, so for them this is still exactly `[probe-rule]` — but
        // the #3402 row's defect IS a policy rule, and it must survive AND
        // stay after the probe, so the probe's `rule_hit_counter` is resolved
        // before the defect rejects (#6832 fold r7).
        snapshot.policies.insert(
            0,
            crate::protocol::PolicyRuleSnapshot {
                name: "probe-rule".into(),
                from_zone: "zone100".into(),
                to_zone: "zone300".into(),
                action: "permit".into(),
                ..Default::default()
            },
        );

        let err = match build_forwarding_state_with_policy_counters_and_previous(
            &snapshot,
            &live_policy,
            &live_nat,
            Some(&prev),
        ) {
            Ok(_) => panic!("{label}: this snapshot must be rejected"),
            Err(e) => e,
        };
        assert!(
            expected(&err),
            "{label}: rejected through a different belt than the row names ({err:?})"
        );

        assert_eq!(
            prev.zone_counter_store.tracked_zone_ids_for_test(),
            vec![100, 200],
            "{label}: a REJECTED build mutated the live ZONE-counter store when \
             the sibling policy/NAT stores were also live — the zone guarantee \
             must not depend on its neighbours being empty"
        );
        // The scope boundary, asserted rather than only described: the NAT
        // store IS touched, and this is #6995's residue, not a #6832
        // regression. If a later change fixes #6995, this assertion is the one
        // that says so out loud instead of going quietly stale.
        //
        // It is row-dependent, and that dependence is itself the useful part.
        // The NAT rule parse sits in the MIDDLE of the fallible builder, so a
        // belt ABOVE it rejects before any NAT counter is resolved and a belt
        // BELOW it does not. TWO rows reject above it: #3719 duplicate-zone-id,
        // the builder's first fallible step, and #3402, which rejects inside
        // the policy parse — itself upstream of the NAT parse. NPTv6, filter
        // and CoS all follow it. So this pins the relative order of those two
        // belts and the NAT parse as well as the residue itself — hoist the
        // NAT parse above the policy parse and the #3402 row reds
        // (`left: [4242, 7777], right: [7777]`, measured #6832 fold r7).
        let rejected_above_the_nat_parse =
            label.starts_with("#3719") || label.starts_with("#3402");
        // NOT the same expression as the NAT predicate, and that is the point.
        // Only #3719 rejects above the POLICY parse; #3402 rejects INSIDE it,
        // downstream of the probe rule's `rule_hit_counter`, so the policy
        // residue is present for that row while the NAT residue is not.
        // Before #6832 fold r7 both predicates read `starts_with("#3719")` and
        // no row in the set could contradict either one — a belt relocated
        // into the roughly sixty lines between the two parses would have made
        // one of them silently wrong.
        let rejected_above_the_policy_parse = label.starts_with("#3719");
        // #6995 CLOSED — and this is the assertion that says so out loud,
        // exactly as the comment below predicted when it was written.
        //
        // The two predicates that follow used to be evaluated HERE, against the
        // stores the public entry point was handed, and they asserted the
        // residue was PRESENT. It no longer is: the caller
        // (`build_forwarding_state_with_policy_counters_and_previous`) now
        // captures both registries before the fallible build and retains them
        // back on `Err`.
        //
        // The ordering property they encode is NOT discarded, because it is a
        // real property and it is still true — it is just a property of the
        // INNER builder rather than of the caller. So it moves down one layer,
        // to `build_fallible_forwarding_state`, which is where the get-or-create
        // actually happens and which does not roll back. Deleting the
        // predicates instead would have removed the only bind on the relative
        // order of the policy parse, the NAT parse and the belts, and #6832
        // fold r7 exists precisely because an earlier round let those two
        // predicates collapse into one expression no row could contradict.
        let policy_ids = live_policy.tracked_rule_ids_for_test();
        let mut nat_ids: Vec<u32> = live_nat.snapshots().iter().map(|s| s.counter_id).collect();
        nat_ids.sort_unstable();
        assert_eq!(
            policy_ids, policy_seed,
            "{label}: a REJECTED build left the live POLICY-counter registry \
             changed. Extra ids are #6995 residue keyed by the refused \
             snapshot's own rules; MISSING ids are the DESTRUCTIVE class \
             (#7010), where the rollback ate a running rule's totals"
        );
        assert_eq!(
            nat_ids,
            vec![7777],
            "{label}: a REJECTED build left the live NAT-counter registry \
             changed. Id 4242 belongs to a candidate-only rule the build \
             refused; 7777 is the running configuration's and must survive. \
             This row is what makes the #6995 rollback hold with the ZONE \
             store live alongside it, not just against empty neighbours"
        );

        // The ordering bind, re-anchored at the layer that owns it. Same
        // predicates, same rows, same reasoning — run against the inner builder
        // on its own live-seeded stores, where the residue is still observable
        // because nothing has rolled it back yet.
        let inner_policy = PolicyCounterStore::default();
        let inner_nat = crate::nat::NatCounterStore::default();
        let _ = inner_nat.rule_counter(7777);
        build_forwarding_state_with_policy_counters_and_previous(
            &ConfigSnapshot::default(),
            &inner_policy,
            &inner_nat,
            None,
        )
        .expect("the empty seed snapshot must build");
        let inner_policy_seed = inner_policy.tracked_rule_ids_for_test();
        assert!(
            !inner_policy_seed.is_empty(),
            "{label}: fixture precondition — the inner-builder policy store \
             must be LIVE before the rejected build"
        );
        let inner_err =
            build_fallible_forwarding_state(&snapshot, &inner_policy, &inner_nat, Some(&prev))
                .err()
                .unwrap_or_else(|| panic!("{label}: the inner builder must reject this snapshot"));
        assert!(
            expected(&inner_err),
            "{label}: the inner builder rejected through a different belt than \
             the row names ({inner_err:?})"
        );
        let mut inner_nat_ids: Vec<u32> =
            inner_nat.snapshots().iter().map(|s| s.counter_id).collect();
        inner_nat_ids.sort_unstable();
        let expected_nat_ids: Vec<u32> = if rejected_above_the_nat_parse {
            vec![7777]
        } else {
            vec![4242, 7777]
        };
        let inner_policy_ids = inner_policy.tracked_rule_ids_for_test();
        assert!(
            inner_policy_seed.iter().all(|id| inner_policy_ids.contains(id)),
            "{label}: the inner builder EVICTED a live policy counter. It is \
             ADDITIVE by construction; losing a seeded id would be the \
             DESTRUCTIVE class, which is #7010, not this one. \
             seed={inner_policy_seed:?} after={inner_policy_ids:?}"
        );
        // The policy half of the ordering boundary: the candidate-only rule's
        // counter IS resolved by the inner builder for a belt BELOW the policy
        // parse and is not for a belt above it. #3402 is the row that separates
        // this predicate from the NAT one — it is BELOW the probe rule's
        // counter (residue expected) and ABOVE the NAT parse (no NAT residue).
        let policy_residue_expected = !rejected_above_the_policy_parse;
        assert_eq!(
            inner_policy_ids.iter().any(|id| id.contains("probe-rule")),
            policy_residue_expected,
            "{label}: the policy-side ordering boundary moved. A belt BELOW the \
             probe rule's per-rule counter resolution leaves that rule's \
             counter in the store the inner builder was handed, and a belt \
             ABOVE it does not. after={inner_policy_ids:?}"
        );
        assert_eq!(
            inner_nat_ids, expected_nat_ids,
            "{label}: the NAT-side ordering boundary moved. A belt BELOW the \
             NAT rule parse leaves the candidate's counter_id behind in the \
             store the INNER builder was handed, and a belt ABOVE it does not. \
             Hoisting the NAT parse above the policy parse reds the #3402 row \
             here (measured, #6832 fold r7). The caller undoes this on `Err` \
             (#6995) — that is asserted above, at the caller's layer"
        );
    }
}

#[test]
fn accepted_build_defers_the_prune_to_the_commit_point() {
    // #6832 fold r5. A clean BUILD no longer prunes, and that is the fix, not
    // an omission: the build succeeding is not the apply committing. Worker
    // bring-up can still reject the apply afterwards (#4952 spawn, #5143 bind),
    // and pruning here destroyed a removed zone's cumulative totals for a
    // configuration that never ran a worker — measured in
    // `rejected_apply_does_not_prune_live_zone_counters_6832`.
    //
    // Anti-over-fix control, in the same test so the two halves cannot drift:
    // the prune is DEFERRED, not deleted. `commit_zone_counter_prune` still
    // drops the removed zone, and the survivor still keeps its carried-forward
    // totals rather than resetting.
    let prev = zone_counter_prev_state();
    let good_snapshot = ConfigSnapshot {
        zones: vec![ZoneSnapshot {
            name: "trust".into(),
            id: 100,
            ..Default::default()
        }],
        ..Default::default()
    };
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &good_snapshot,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .expect("a clean snapshot must build");

    // Half 1 — the build itself is now ADDITIVE ONLY. Zone 200 is absent from
    // this snapshot and its totals are still here, because no apply has
    // committed yet.
    let mut after_build: Vec<u16> = next
        .zone_counter_store
        .snapshot()
        .iter()
        .map(|r| r.zone_id)
        .collect();
    after_build.sort_unstable();
    assert_eq!(
        after_build,
        vec![100, 200],
        "a clean BUILD must not prune: the apply it belongs to can still be \
         rejected by worker bring-up, and the prune is unrecoverable"
    );

    // Half 2 — the commit point still prunes. This is the anti-over-fix
    // control: reverting `commit_zone_counter_prune` to a no-op (rather than
    // moving it) reds here, and every rejected-apply assertion stays green.
    commit_zone_counter_prune(&next, &good_snapshot);

    let live = next.zone_counter_store.snapshot();
    assert_eq!(
        live.len(),
        1,
        "a COMMITTED apply must still prune the removed zone's totals"
    );
    assert_eq!(live[0].zone_id, 100);
    assert!(
        live[0].ingress_packets > 0,
        "the surviving zone must keep its carried-forward totals"
    );
    // The prune is on the shared store, so the previous state's handle
    // observes it too (same Arc).
    assert_eq!(prev.zone_counter_store.snapshot().len(), 1);
}

// ── #3651 flood half of the #5716/#6832 rejected-build guarantee ──────
//
// The flood-event store is the traffic store's exact sibling: `Arc`-backed,
// carried forward through the SAME `previous` handle, get-or-created per
// slot-assigned zone by `FloodCounterSlotMap::build`, and pruned by the same
// `reconcile`. #6938 therefore binds it inside `attach_zone_counters` and
// prunes it inside `commit_zone_counter_prune` rather than giving it its own
// pair, so it inherits the ordering structurally.
//
// These two rows check that the inheritance is REAL rather than assumed.
// Master's `rejected_build_does_not_prune_live_zone_counters` and
// `accepted_build_defers_the_prune_to_the_commit_point` read
// `zone_counter_store` and nothing else, so they stay green with the flood
// prune moved back inside the fallible builder — which is precisely the shape
// this branch's pre-merge code had, and precisely the defect #5716/#6832
// removed for the traffic family.

/// Live state for the two flood rows: zones 100 and 200 configured, each with
/// a recorded SYN-flood event so both produce a row in the sparse store
/// snapshot (which omits all-zero rows by design).
fn flood_counter_prev_state() -> ForwardingState {
    use crate::afxdp::flood_counters::{flush_recorded_flood_counters, record_zone_flood_drop};
    let prev = zone_counter_prev_state();
    record_zone_flood_drop(&prev.flood_counter_slot_map, 100, "syn-flood");
    record_zone_flood_drop(&prev.flood_counter_slot_map, 200, "syn-flood");
    flush_recorded_flood_counters(&prev.flood_counter_store, &prev.flood_counter_slot_map);
    assert_eq!(
        flood_store_zone_ids(&prev),
        vec![100, 200],
        "both zones must be counting flood events before the build under test"
    );
    prev
}

/// Sorted zone ids currently tracked by a state's flood store.
fn flood_store_zone_ids(state: &ForwardingState) -> Vec<u16> {
    let mut ids: Vec<u16> = state
        .flood_counter_store
        .snapshot()
        .iter()
        .map(|r| r.zone_id)
        .collect();
    ids.sort_unstable();
    ids
}

/// A build the integrity belts REJECT must leave the live flood store intact.
///
/// Same four belts, same candidate zone set (`ZONE_COUNTER_CANDIDATE_ZONES`
/// drops live zone 200 and adds a new zone 300) as the traffic rows, so a
/// relocation of the flood work into the fallible region is caught wherever it
/// lands: every straight-line position that is still a defect has a `?` below
/// it, hence sits above the LAST belt.
#[test]
fn rejected_build_does_not_prune_live_flood_counters_3651() {
    let prev = flood_counter_prev_state();
    for (label, snapshot, is_expected) in zone_counter_rejection_rows() {
        let err = build_forwarding_state_with_policy_counters_and_previous(
            &snapshot,
            &PolicyCounterStore::default(),
            &crate::nat::NatCounterStore::default(),
            Some(&prev),
        )
        .expect_err(&format!("{label}: this snapshot must be rejected"));
        assert!(
            is_expected(&err),
            "{label}: rejected for the wrong reason ({err:?}) — the row would \
             then prove nothing about where the flood binding sits"
        );
        assert_eq!(
            flood_store_zone_ids(&prev),
            vec![100, 200],
            "{label}: the REJECTED build pruned zone 200's cumulative flood \
             counts out of the LIVE, Arc-shared flood store. The apply never \
             happened — zone 200 is still configured — so `show security screen \
             ids-option statistics` now reads \"not available\" for it forever \
             (#3651 flood half of #5716/#6832)"
        );
    }
}

/// The flood prune is DEFERRED to the commit point, not deleted.
///
/// Anti-over-fix control for the row above, and the row that reds if
/// `commit_zone_counter_prune` prunes only the traffic store: without the
/// flood `reconcile` there, a removed zone's flood blocks would be retained
/// forever while its traffic blocks were dropped, so the two per-zone surfaces
/// would disagree about which zones exist.
#[test]
fn accepted_build_defers_the_flood_prune_to_the_commit_point_3651() {
    let prev = flood_counter_prev_state();
    let good_snapshot = zone_counter_snapshot_with_zones(&[100]);
    let next = build_forwarding_state_with_policy_counters_and_previous(
        &good_snapshot,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .expect("a clean snapshot must build");

    // Half 1 — a clean BUILD is additive only for the flood family too. This
    // is also the precondition that stops half 2 passing vacuously: if the
    // build had already pruned, half 2's post-commit assertion would hold for
    // the wrong reason.
    assert_eq!(
        flood_store_zone_ids(&next),
        vec![100, 200],
        "a clean BUILD must not prune the flood store: the apply it belongs to \
         can still be rejected by worker bring-up (#4952 spawn, #5143 bind), \
         and the prune is unrecoverable"
    );

    // Half 2 — the commit point prunes BOTH families.
    commit_zone_counter_prune(&next, &good_snapshot);
    assert_eq!(
        flood_store_zone_ids(&next),
        vec![100],
        "a COMMITTED apply must prune the removed zone from the FLOOD store as \
         well as the traffic store — commit_zone_counter_prune reconciles both"
    );
    // The survivor keeps its carried-forward count rather than resetting.
    let live = next.flood_counter_store.snapshot();
    assert_eq!(live[0].zone_id, 100);
    assert!(
        live[0].syn_flood_events > 0,
        "the surviving zone must keep its carried-forward flood totals"
    );
    // Shared Arc: the previous state's handle observes the same prune.
    assert_eq!(flood_store_zone_ids(&prev), vec![100]);
}

/// #5619: the secure-tunnel unit's ifindex is what decides whether a
/// LAN->tunnel route resolves `NoRoute` or `MissingNeighbor`, and the two
/// dispositions are NOT interchangeable.
///
/// This pins the FIB half of a claim made in the Go control plane
/// (`snapshotLinuxName`, pkg/dataplane/userspace/interfaces.go): resolving a
/// secure-tunnel unit to the netdev that actually exists admits the tunnel's
/// connected prefix here, which moves the disposition. Without this test the
/// Go-side comment and the PR that documents the behaviour change could rot
/// silently against a later FIB edit.
///
/// Both rows are otherwise byte-identical; ONLY `ifindex` differs, which is
/// exactly the field the Go fix changes.
///
/// `NoRoute` and `MissingNeighbor` are both slow-path eligible, so the
/// difference is not "delivered vs dropped" at this layer — it is that the
/// `MissingNeighbor` arm in `poll_descriptor` evaluates zone policy before the
/// reinject gate and the `NoRoute` arm does not.
#[test]
fn secure_tunnel_unit_ifindex_decides_route_disposition() {
    fn snapshot(st_unit_ifindex: i32) -> ConfigSnapshot {
        let addr = |a: &str| crate::InterfaceAddressSnapshot {
            family: "inet".into(),
            address: a.into(),
            scope: 0,
        };
        ConfigSnapshot {
            zones: vec![
                ZoneSnapshot {
                    name: "trust".into(),
                    id: 1,
                    ..Default::default()
                },
                ZoneSnapshot {
                    name: "vpn".into(),
                    id: 2,
                    ..Default::default()
                },
            ],
            interfaces: vec![
                InterfaceSnapshot {
                    name: "ge-0/0/0.0".into(),
                    zone: "trust".into(),
                    linux_name: "ge-0-0-0".into(),
                    ifindex: 11,
                    mtu: 1500,
                    addresses: vec![addr("10.0.1.1/24")],
                    ..Default::default()
                },
                InterfaceSnapshot {
                    name: "st0.0".into(),
                    zone: "vpn".into(),
                    linux_name: "st0.0".into(),
                    ifindex: st_unit_ifindex,
                    mtu: 1400,
                    addresses: vec![addr("10.5.5.1/30")],
                    ..Default::default()
                },
            ],
            routes: vec![crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "192.168.99.0/24".into(),
                next_hops: vec!["10.5.5.2".into()],
                preference: 5,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    let dst = Ipv4Addr::new(192, 168, 99, 5);

    // Unresolved unit (the pre-#5619 `st0.0` -> nonexistent `st0` lookup):
    // the row is skipped by populate_interfaces, so the gateway 10.5.5.2 has
    // no connected prefix to infer an egress ifindex from.
    let unresolved = build_forwarding_state(&snapshot(0));
    assert!(
        !unresolved
            .connected_v4
            .iter()
            .any(|c| c.prefix.contains(Ipv4Addr::new(10, 5, 5, 2))),
        "premise broken: an ifindex-0 tunnel row must contribute no connected prefix"
    );
    let r0 = lookup_forwarding_resolution_v4(&unresolved, None, dst, "inet.0", 0, true, None);
    assert_eq!(
        r0.disposition,
        ForwardingDisposition::NoRoute,
        "an unresolved secure-tunnel unit must leave the route unresolvable"
    );
    assert_eq!(r0.egress_ifindex, 0);

    // Resolved unit (post-#5619): the connected prefix exists, the gateway
    // infers ifindex 42, and the xfrmi has no neighbor to resolve against.
    let resolved = build_forwarding_state(&snapshot(42));
    assert!(
        resolved
            .connected_v4
            .iter()
            .any(|c| c.prefix.contains(Ipv4Addr::new(10, 5, 5, 2)) && c.ifindex == 42),
        "premise broken: a resolved tunnel row must contribute its connected prefix"
    );
    let r42 = lookup_forwarding_resolution_v4(&resolved, None, dst, "inet.0", 0, true, None);
    assert_eq!(
        r42.disposition,
        ForwardingDisposition::MissingNeighbor,
        "a resolved secure-tunnel unit must claim the route on the MissingNeighbor arm, \
         which is the arm that evaluates zone policy before the reinject gate"
    );
    assert_eq!(r42.egress_ifindex, 42);

    // The two arms differ in policy handling, not in slow-path eligibility —
    // state that here so a future reader does not misread the change as
    // "delivered becomes dropped unconditionally".
    assert!(r0.disposition.is_slow_path_eligible());
    assert!(r42.disposition.is_slow_path_eligible());
}

/// #6664: a genuine inter-VRF next-table CYCLE resolves to
/// `NextTableUnsupported` through the real recursion, and that disposition is
/// not slow-path eligible.
///
/// The chain is built rather than simulated: `inet.0` leaks 172.16/12 into
/// `blue.inet.0`, which leaks the same prefix back. The walk pushes "inet.0"
/// onto the visited set, recurses, and the second hop trips
/// `visited.contains(next_table_name)` — the production cycle check in
/// `fib.rs`, reached the way a packet reaches it. Passing `depth =
/// MAX_NEXT_TABLE_DEPTH` directly would land on the same disposition by a
/// different door and would keep passing if the cycle check were deleted.
///
/// Honest scope note. No config can currently put this state into the FIB:
/// every `next_table`-bearing route the snapshot publishes lives in the GLOBAL
/// table (`pkg/dataplane/userspace/routes.go` — the global static pass and the
/// synthetic ip-rule leak pass are the only two producers), and a next-table
/// authored UNDER a routing-instance is hard-rejected at commit (#5830) and
/// dropped from the snapshot even on the tolerant load / peer-sync path. So the
/// recursion is at most one hop, global -> instance, and terminates there. This
/// test therefore pins DEFENSE-IN-DEPTH, not a live exposure: the safety above
/// is an emergent property of two guards in another language and package, and
/// a third producer or one relaxed guard would reopen the bypass silently.
#[test]
fn next_table_cycle_resolves_unsupported_and_is_not_slow_path_eligible_6664() {
    let snapshot = ConfigSnapshot {
        routes: vec![
            crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "172.16.0.0/12".into(),
                next_table: "blue.inet.0".into(),
                ..Default::default()
            },
            crate::RouteSnapshot {
                table: "blue.inet.0".into(),
                family: "inet".into(),
                destination: "172.16.0.0/12".into(),
                next_table: "inet.0".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);

    // Premise: both legs of the cycle are actually present. Without this a
    // snapshot that silently dropped one leg would still reach
    // NextTableUnsupported — via NoRoute-shaped termination — and the test
    // would pass for the wrong reason.
    assert!(
        state
            .routes_v4
            .get("inet.0")
            .is_some_and(|t| t.iter().any(|r| r.next_table == "blue.inet.0")),
        "premise broken: the global leg of the cycle is missing"
    );
    assert!(
        state
            .routes_v4
            .get("blue.inet.0")
            .is_some_and(|t| t.iter().any(|r| r.next_table == "inet.0")),
        "premise broken: the return leg of the cycle is missing"
    );

    let dst = Ipv4Addr::new(172, 16, 5, 5);
    let cycled = lookup_forwarding_resolution_v4(&state, None, dst, "inet.0", 0, true, None);
    assert_eq!(
        cycled.disposition,
        ForwardingDisposition::NextTableUnsupported,
        "an A->B->A next-table cycle must resolve NextTableUnsupported"
    );
    assert_eq!(
        cycled.egress_ifindex, 0,
        "NextTableUnsupported carries no egress interface — which is why a \
         zone-PAIR adjudication cannot be computed for it and #6664 fails it \
         closed instead"
    );
    assert!(
        !cycled.disposition.is_slow_path_eligible(),
        "a cyclic next-table chain must NOT be handed to the kernel FIB, which \
         would forward it with no zone policy, session, NAT or screen (#6664)"
    );

    // Positive control: a destination with no route at all still resolves
    // NoRoute and REMAINS delegable. Without this, deleting the whole
    // next-table arm would satisfy the assertions above.
    let unrouted = lookup_forwarding_resolution_v4(
        &state,
        None,
        Ipv4Addr::new(203, 0, 113, 7),
        "inet.0",
        0,
        true,
        None,
    );
    assert_eq!(
        unrouted.disposition,
        ForwardingDisposition::NoRoute,
        "premise broken: an unrouted destination must resolve NoRoute"
    );
    assert!(
        unrouted.disposition.is_slow_path_eligible(),
        "NoRoute must STILL delegate to the kernel — it is transient and #7409 \
         forbids black-holing a destination the kernel can still reach"
    );
}

/// #6710 — THE MEASUREMENT. The issue was filed as an OPEN QUESTION, read from
/// source with the worker loop never executed, and asks first whether the
/// interaction occurs at all. It does, and this is the half of the chain that
/// can be executed here: what a LAN→xfrmi egress actually RESOLVES to, and
/// which properties of that resolution decide whether the dead-host negative
/// cache can be armed against it.
///
/// `secure_tunnel_unit_ifindex_decides_route_disposition` above already
/// establishes `MissingNeighbor`; what #6710 turns on are two further facts it
/// does not assert, and each is load-bearing in a different direction:
///
///   * `next_hop` is `Some(..)` — the negative cache is keyed
///     `(egress_ifindex, next_hop)`, and the arming site in
///     `neighbor_dispatch.rs` is inside `if let Some(next_hop)`. No next hop,
///     no key, no interaction.
///   * `tunnel_endpoint_id == 0` — this is the discriminator against #1912,
///     which states that "tunnel-marked decisions are NEVER buffered in
///     pending_neigh ... so for an unresolved OUTER hop the top-of-arm neg
///     fast-fail can never arm". That exclusion is real, and it is exactly why
///     a GRE outer hop is safe and an xfrmi is not: an xfrmi egress is a
///     CONNECTED route to an ordinary ifindex, not a tunnel endpoint, so it
///     takes the buffered path and the cache CAN arm.
///
/// The third fact — that an armed entry then recycles the frame before the
/// slow-path reinject — is control flow inside
/// `poll_binding_process_descriptor`, which no test in this crate can drive
/// (it needs a live binding, UMEM and descriptor ring). It is stated in the
/// PR body with its line references rather than asserted here, and the
/// behavioural guard for the fix lives at the arming site instead, where it
/// IS executable: `lan_to_xfrmi_timeout_does_not_arm_the_dead_host_cache_6710`
/// in neighbor_dispatch.rs.
#[test]
fn xfrmi_egress_resolves_a_negative_cache_key_6710() {
    fn snapshot(secure_tunnel: bool) -> ConfigSnapshot {
        let addr = |a: &str| crate::InterfaceAddressSnapshot {
            family: "inet".into(),
            address: a.into(),
            scope: 0,
        };
        ConfigSnapshot {
            zones: vec![
                ZoneSnapshot {
                    name: "trust".into(),
                    id: 1,
                    ..Default::default()
                },
                ZoneSnapshot {
                    name: "vpn".into(),
                    id: 2,
                    ..Default::default()
                },
            ],
            interfaces: vec![
                crate::InterfaceSnapshot {
                    name: "ge-0/0/1.0".into(),
                    zone: "trust".into(),
                    linux_name: "ge-0-0-1.0".into(),
                    ifindex: 11,
                    mtu: 1500,
                    addresses: vec![addr("10.0.1.1/24")],
                    ..Default::default()
                },
                crate::InterfaceSnapshot {
                    name: "st0.0".into(),
                    zone: "vpn".into(),
                    linux_name: "st0.0".into(),
                    ifindex: 42,
                    mtu: 1400,
                    addresses: vec![addr("10.5.5.1/30")],
                    secure_tunnel,
                    ..Default::default()
                },
            ],
            routes: vec![crate::RouteSnapshot {
                table: "inet.0".into(),
                family: "inet".into(),
                destination: "192.168.99.0/24".into(),
                next_hops: vec!["10.5.5.2".into()],
                preference: 5,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    let state = build_forwarding_state(&snapshot(true));
    let dst = Ipv4Addr::new(192, 168, 99, 5);
    let r = lookup_forwarding_resolution_v4(&state, None, dst, "inet.0", 0, true, None);

    assert_eq!(
        r.disposition,
        ForwardingDisposition::MissingNeighbor,
        "premise: a LAN→xfrmi packet must take the cold MissingNeighbor arm — \
         an xfrmi has no lladdr, so lookup_neighbor_entry can never hit"
    );
    assert_eq!(r.egress_ifindex, 42);
    assert!(
        r.next_hop.is_some(),
        "the negative cache is keyed (egress_ifindex, next_hop) and the arming \
         site is inside `if let Some(next_hop)`; with no next hop there is no \
         key and #6710's interaction cannot occur at all"
    );
    assert_eq!(
        r.tunnel_endpoint_id, 0,
        "THE #1912 DISCRIMINATOR. A tunnel-marked decision is never buffered in \
         pending_neigh, so its hop can never arm the cache — that is why a GRE \
         outer hop is safe. An xfrmi egress is a CONNECTED route to an ordinary \
         ifindex, carries no endpoint id, takes the buffered path, and therefore \
         CAN arm it. If this ever becomes non-zero, #6710 stops applying and \
         this test should say so rather than being deleted"
    );
    assert!(
        r.disposition.is_slow_path_eligible(),
        "the intended fate of this packet is the slow-path reinject — an xfrmi \
         gets no AF_XDP binding, so the kernel XFRM stack is the ONLY way it is \
         ever encrypted. A negative-cache fast-fail recycles it before that."
    );

    // The fix is keyed on the shipped `secure_tunnel` flag, not on a name
    // grammar. Assert both directions so the set cannot silently become
    // "everything" or "nothing".
    assert!(
        state.lladdrless_egress.contains(&42),
        "the xfrmi ifindex must be recorded as lladdr-less so the dead-host \
         cache is not armed against a device that has nothing to answer with"
    );
    assert!(
        !state.lladdrless_egress.contains(&11),
        "an ordinary LAN interface must NOT be recorded lladdr-less; the #1651 \
         dead-host protection has to keep working everywhere else"
    );
    let plain = build_forwarding_state(&snapshot(false));
    assert!(
        plain.lladdrless_egress.is_empty(),
        "with secure_tunnel unset the set must be empty — the flag is the only \
         input, so an older control plane that omits it changes nothing"
    );
}

/// #6751 PR 2/3: the interface-mode SNAT identity registry is NODE-lifetime and
/// must be CARRIED across an apply, not rebuilt.
///
/// Two assertions, because the pointer alone is not the property. `ptr_eq`
/// pins that the same instance was carried; the second half pins what that
/// buys — the occupancy of a session minted BEFORE the apply still forces the
/// post-apply collider to PAT. Rebuild the registry per apply and a commit
/// silently returns the node to the #6751 ambiguity for every live session.
#[test]
fn interface_snat_identity_registry_survives_apply_6751() {
    let snap = ConfigSnapshot {
        source_nat_rules: vec![crate::SourceNATRuleSnapshot {
            name: "iface-snat".into(),
            from_zone: "lan".into(),
            to_zone: "wan".into(),
            source_addresses: vec!["0.0.0.0/0".into()],
            interface_mode: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let prev = build_forwarding_state(&snap);

    // Mint an identity through the REAL admission path against `prev`.
    let egress: IpAddr = "172.16.80.8".parse().unwrap();
    let server: IpAddr = "172.16.80.200".parse().unwrap();
    let mut counter = None;
    let first = crate::nat::match_source_nat_result_for_tuple(
        &prev.iface_nat_allocators,
        &prev.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.101".parse().unwrap(),
        server,
        Some(6),
        5555,
        80,
        Some("172.16.80.8".parse().unwrap()),
        None,
        1_000,
        false,
        false,
        crate::nat::NatHolder::Untracked,
        &mut counter,
    );
    match first {
        crate::nat::SourceNatLookup::Matched(d) => {
            assert_eq!(d.rewrite_src, Some(egress));
            assert_eq!(d.rewrite_src_port, None, "first flow preserves");
        }
        other => panic!("expected a matched interface SNAT decision, got {other:?}"),
    }

    let next = build_forwarding_state_with_policy_counters_and_previous(
        &snap,
        &PolicyCounterStore::default(),
        &crate::nat::NatCounterStore::default(),
        Some(&prev),
    )
    .unwrap();

    assert!(
        std::sync::Arc::ptr_eq(&prev.iface_nat_allocators, &next.iface_nat_allocators),
        "the identity registry must be carried, never rebuilt, across an apply"
    );

    // The property that carry-over buys: the pre-apply occupancy still binds.
    let mut counter2 = None;
    let second = crate::nat::match_source_nat_result_for_tuple(
        &next.iface_nat_allocators,
        &next.source_nat_rules,
        &crate::nat::NatScopeCtx::default(),
        "lan",
        "wan",
        "10.0.61.102".parse().unwrap(),
        server,
        Some(6),
        5555,
        80,
        Some("172.16.80.8".parse().unwrap()),
        None,
        2_000,
        false,
        false,
        crate::nat::NatHolder::Untracked,
        &mut counter2,
    );
    match second {
        crate::nat::SourceNatLookup::Matched(d) => assert!(
            d.rewrite_src_port.is_some(),
            "a post-apply collider must still see the pre-apply occupancy"
        ),
        other => panic!("expected a matched interface SNAT decision, got {other:?}"),
    }
}

/// #6849: `medium` is not a Junos scheduler priority and must fail CLOSED.
///
/// The dead `"medium" => Some(3)` arm predated the T-7 fail-closed work —
/// the original function was a six-level ladder ending in `_ => 5`, and T-7
/// mechanically rewrote every arm to `Some(n)` while changing the signature,
/// carrying `medium` along with it. No version of the Go producer has ever
/// emitted it: the schema's `priority` enum accepts only the five below.
///
/// This is a fail-OPEN removal in the sense that matters — with the arm
/// present, a `medium` string from a typo or a drifting snapshot resolved to
/// a real rank and silently placed the class between `medium-high` and
/// `medium-low`, rather than surfacing `CosUnknownSchedulerPriority`.
#[test]
fn cos_priority_rank_rejects_medium_and_pins_the_five_real_ranks_6849() {
    assert_eq!(
        super::cos::cos_priority_rank_for_test("medium"),
        None,
        "#6849: `medium` is not a Junos scheduler priority — it must fail CLOSED so the \
         caller raises CosUnknownSchedulerPriority, not resolve to a rank between \
         medium-high and medium-low"
    );

    // The five REAL priorities, with their ranks pinned to the exact values
    // they have always had. This is the other half of #6849: the ranks were
    // deliberately NOT renumbered when rank 3 became vacant, because a large
    // number of CoS tests construct queues with a literal `priority: 5`
    // meaning "low" and would silently mean something else. If a later change
    // closes the gap to 0..=4, this cell reds and points at those literals.
    for (name, want) in [
        ("strict-high", 0u8),
        ("high", 1),
        ("medium-high", 2),
        ("medium-low", 4),
        ("low", 5),
    ] {
        assert_eq!(
            super::cos::cos_priority_rank_for_test(name),
            Some(want),
            "#6849: rank of {name:?} must stay {want} — renumbering silently reinterprets \
             every hardcoded `priority:` literal in the CoS tests"
        );
    }

    // Rank 3 is vacant, and COS_PRIORITY_LEVELS is sized for the highest LIVE
    // rank (low = 5), so six slots is correct rather than off by one. Without
    // this the constant looks like a stale leftover and an unrelated tidy-up
    // would shrink it to 5 and truncate `low`.
    assert!(
        crate::afxdp::types::COS_PRIORITY_LEVELS
            > usize::from(
                super::cos::cos_priority_rank_for_test("low").expect("low is a known priority")
            ),
        "#6849: COS_PRIORITY_LEVELS must exceed the highest live rank, or indexing by the \
         rank of `low` is out of bounds"
    );
}

// #6846: `buffer-size temporal` converts against the queue's DRAIN rate, and
// that is not the same question as whether the queue has a resolvable
// transmit-rate.
//
// `transmit_rate_bytes` at the call site is
// `explicit_transmit_rate_bytes.unwrap_or(iface.cos_shaping_rate_bytes_per_sec)`,
// so a queue with no guarantee of its own still drains at the interface shaping
// rate and its microsecond target still has a byte value. Measured: this
// scheduler carries ONLY a temporal target — no absolute rate, no percent, no
// remainder — and one second of drain comes out as the full 10_000_000, not the
// 100_000 that `default_cos_burst_bytes(10_000_000)` would give.
//
// The Go commit advisory depends on exactly this fact. An earlier revision
// warned that temporal "has no effect" whenever the RATE did not resolve, which
// is a strictly stronger condition — it told operators a knob does nothing when
// it does. `cosSchedulerTemporalResolves` (pkg/config) is the narrowed
// predicate; this cell is what makes it checkable rather than asserted.
#[test]
fn build_cos_state_temporal_converts_against_the_fallback_drain_rate() {
    let snapshot = remainder_snapshot_6846(
        vec![CoSSchedulerSnapshot {
            name: "no-rate".into(),
            buffer_size_temporal_us: 1_000_000, // one second of drain
            ..Default::default()
        }],
        &[("be", "no-rate")],
    );

    let state = build_cos_state(&snapshot);
    let iface = state.interfaces.get(&42).expect("missing CoS interface");
    let q = queue_for_class_6846(iface, "be");

    // Guard the fixture: the queue must genuinely have NO guarantee, or this
    // cell would be measuring the ordinary resolved-rate path.
    assert!(
        !q.guarantee_enabled,
        "fixture broken: a scheduler with no transmit-rate must not carry a guarantee"
    );
    assert_eq!(
        q.buffer_bytes, 10_000_000,
        "one second of drain at the 10_000_000 B/s interface shaping-rate. \
         100_000 would mean the buffer fell back to default_cos_burst_bytes and \
         temporal really was inert here — which is what the commit advisory used \
         to claim"
    );
}

// #7015: bind the counter-prune OBLIGATION — "on the `is_ok()` branch, this
// call happens" — which nothing enforced.
//
// WHY NOT THE RECEIPT THE ISSUE PREFERS. #7015 ranks a prune-debt receipt first:
// `attach_zone_counters` records "prune owed for generation N", and "a new
// build's additive half finding a prior generation's debt still outstanding IS
// the defect". That is UNSOUND as specified, and the reason is the very path
// #6832 created. A rejected apply legitimately leaves the debt outstanding —
// that is the whole point of deferring the prune past `bring_up_workers` — and
// the next build then finds it. So the receipt fires on every
// rejected-apply-then-retry sequence, which is a normal operator flow, not a
// defect. `rejected_apply_then_retry_is_a_reachable_sequence_7015` below
// demonstrates that sequence is reachable rather than hypothetical.
//
// So this is the issue's option (2), the structural guard — with the weakness
// it was ranked down for removed. #7015 objects that option (2) "needs an
// exemption list", and this board has been bitten by lists going stale. This
// guard has no per-call-site list: it DISCOVERS the prune families from the
// definitions and requires each to be called from the same two apply commit
// points. A family added later is picked up with no edit — which matters
// immediately, because #7010 adds a second one.
//
// The one pinned population is the set of forwarding-state PUBLISH sites, and
// it is pinned by exact content rather than by count so a stale entry cannot
// hide behind a coincidental total. That pin is the half that detects the third
// apply path: a new one either calls the prunes (the family assertion fires,
// naming what to update) or it does not (this pin fires, naming the new site).

/// Every `pub(in crate::afxdp) fn commit_*_prune(` defined in
/// `forwarding_build/mod.rs`, discovered rather than listed.
fn discovered_prune_families() -> Vec<String> {
    prune_families_in(include_str!("mod.rs"))
}

/// The discovery itself, over arbitrary source, so its own behaviour can be
/// measured rather than argued.
fn prune_families_in(src: &str) -> Vec<String> {
    let cleaned = crate::afxdp::worker_queue::tests::blank_comments_and_strings(src);
    let mut out = Vec::new();
    for line in cleaned.lines() {
        // Keyed on `fn NAME(`, NOT on the visibility modifier in front of it.
        // An earlier revision matched the exact `pub(in crate::afxdp) fn `
        // prefix, which meant a routine visibility widening would drop a family
        // out of discovery silently — and with two families present the
        // anti-vacuity floor below would still pass, leaving the widened one
        // unguarded. That is the "fails to a value indistinguishable from
        // healthy" shape this guard exists to avoid, so the needle does not
        // depend on a spelling that has no bearing on the obligation.
        let Some(idx) = line.find("fn ") else {
            continue;
        };
        let Some(name) = line[idx + 3..].split('(').next() else {
            continue;
        };
        let name = name.trim();
        if name.starts_with("commit_") && name.ends_with("_prune") {
            out.push(name.to_string());
        }
    }
    out.sort();
    out
}

/// The discovery must not depend on a spelling that has no bearing on the
/// obligation.
///
/// An earlier revision keyed on the exact `pub(in crate::afxdp) fn ` prefix. A
/// routine visibility widening would then have dropped a family out of
/// discovery SILENTLY — and with two families present (as of #7010) the
/// anti-vacuity floor still passes, so the widened one goes unguarded while the
/// guard reports clean. This measures the property instead of asserting it.
#[test]
fn prune_family_discovery_is_independent_of_visibility_7015() {
    const SPELLINGS: &str = r#"
pub(in crate::afxdp) fn commit_zone_counter_prune(a: u8) {}
pub(crate) fn commit_rule_counter_prune(a: u8) {}
fn commit_private_counter_prune(a: u8) {}
pub fn not_a_prune_family(a: u8) {}
fn commit_something_else(a: u8) {}
"#;
    let mut got = prune_families_in(SPELLINGS);
    got.sort();
    assert_eq!(
        got,
        vec![
            "commit_private_counter_prune".to_string(),
            "commit_rule_counter_prune".to_string(),
            "commit_zone_counter_prune".to_string(),
        ],
        "discovery must find every `commit_*_prune` regardless of visibility, and \
         must not claim functions that are neither (#7015)"
    );

    // ...and it must still be blinded by comments, so a doc comment naming a
    // family cannot conjure one that does not exist.
    assert!(
        prune_families_in("// fn commit_ghost_counter_prune(a: u8) {}\n").is_empty(),
        "a COMMENTED-OUT definition was discovered as a real family; the scan is \
         not blanking comments and a doc comment could satisfy it (#7015)"
    );
}

/// Production `.rs` files under `src/afxdp`, with comments and string bodies
/// blanked so a doc comment quoting a call cannot satisfy the scan.
fn afxdp_production_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/afxdp");
    let mut files = Vec::new();
    crate::afxdp::worker_queue::tests::afxdp_rs_files(&root, &mut files);
    let mut out = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .expect("under src/afxdp")
            .to_string_lossy()
            .replace('\\', "/");
        if crate::afxdp::worker_queue::tests::is_fixture(&root, &rel) {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read source");
        out.push((
            rel,
            crate::afxdp::worker_queue::tests::blank_comments_and_strings(&src),
        ));
    }
    out
}

/// The two apply paths that commit a snapshot, and therefore the two files a
/// counter prune must be called from.
const APPLY_COMMIT_POINT_FILES: &[&str] =
    &["coordinator/reconcile/mod.rs", "coordinator/snapshot_refresh.rs"];

#[test]
fn every_commit_counter_prune_is_called_from_both_apply_commit_points_7015() {
    let families = discovered_prune_families();
    assert!(
        !families.is_empty(),
        "the scan discovered NO commit_*_prune family in forwarding_build/mod.rs. \
         Either the naming convention changed or the comment-blanking ate the \
         definitions — either way this guard would pass while checking nothing (#7015)"
    );

    let sources = afxdp_production_sources();
    assert!(
        sources.len() >= 40,
        "only {} production sources under src/afxdp were scanned; the walk or the \
         fixture filter is broken and every absence below is vacuous",
        sources.len()
    );

    for family in &families {
        let needle = format!("{family}(");
        let mut callers: Vec<String> = Vec::new();
        for (rel, cleaned) in &sources {
            // The definition itself is not a call site.
            let defines = cleaned.contains(&format!("fn {needle}"));
            let mentions = cleaned.matches(&needle).count();
            let calls = mentions - usize::from(defines);
            if calls > 0 {
                callers.push(rel.clone());
            }
        }
        callers.sort();
        let want: Vec<String> = APPLY_COMMIT_POINT_FILES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(
            callers, want,
            "`{family}` is called from {callers:?}, want exactly {want:?}.\n\
             The destructive half of a counter reconcile must run at EVERY apply \
             path's own commit point and nowhere else: earlier than that and a \
             build whose workers fail to come up destroys live totals for a \
             configuration that never forwarded (#6832/#7010); missing from one \
             and that path leaks removed rows forever. If you added an apply \
             path, call every discovered prune family at its commit point and \
             add its file to APPLY_COMMIT_POINT_FILES (#7015)"
        );
    }
}

#[test]
fn forwarding_publish_population_is_pinned_7015() {
    // The half that DETECTS a third apply path. Pinned by content, not by
    // count: a stale entry cannot hide behind a coincidental total.
    let want: &[(&str, usize)] = &[
        // Teardown reset — not an apply, publishes nothing to commit.
        ("coordinator/mod.rs", 1),
        // Builder staging into the fds carrier — not an apply publish.
        ("coordinator/reconcile/mod.rs", 1),
        // THE RECONCILE APPLY's publish. Its commit point is in reconcile/mod.rs,
        // after bring_up_workers — deliberately not here.
        ("coordinator/reconcile/snapshot.rs", 1),
        // THE REFRESH APPLY's publish, which IS its own commit point.
        ("coordinator/snapshot_refresh.rs", 1),
    ];

    let mut got: Vec<(String, usize)> = Vec::new();
    for (rel, cleaned) in afxdp_production_sources() {
        let n = cleaned.matches(".forwarding = ").count();
        if n > 0 {
            got.push((rel, n));
        }
    }
    got.sort();
    let want_owned: Vec<(String, usize)> =
        want.iter().map(|(f, n)| ((*f).to_string(), *n)).collect();
    assert_eq!(
        got, want_owned,
        "the set of forwarding-state assignment sites under src/afxdp changed.\n\
         If a new APPLY path appeared, it must call every commit_*_prune family \
         at its own commit point (see \
         every_commit_counter_prune_is_called_from_both_apply_commit_points_7015) \
         — the obligation is control-flow-shaped and nothing else enforces it. \
         If the new site is not an apply, add it here with a note saying why \
         (#7015)"
    );
}

/// The refutation of #7015's preferred mechanism, made concrete.
///
/// A prune-debt receipt would treat "a prior generation's debt is still
/// outstanding when the next build runs" as the defect. This shows that
/// sequence is an ordinary one: a rejected apply leaves the prune legitimately
/// undone — that is what #6832 deferred it FOR — and the retry that follows is
/// a normal operator response, not a bug. A receipt keyed on outstanding debt
/// fires here.
#[test]
fn rejected_apply_then_retry_is_a_reachable_sequence_7015() {
    // Both directions already exist as behavioural cells in coordinator/tests.rs
    // (`rejected_apply_does_not_prune_live_zone_counters_6832` and
    // `committed_reconcile_prunes_zone_counters_for_removed_zones_6832`), so
    // what this pins is that the project treats them as ONE sequence rather than
    // two unrelated states — i.e. that the rejected state is a resting place a
    // retry departs from.
    let src = include_str!("../coordinator/tests.rs");
    let cleaned = crate::afxdp::worker_queue::tests::blank_comments_and_strings(src);
    for needle in [
        "fn rejected_apply_does_not_prune_live_zone_counters_6832(",
        "fn committed_reconcile_prunes_zone_counters_for_removed_zones_6832(",
    ] {
        assert!(
            cleaned.contains(needle),
            "{needle} is gone. The #7015 argument against a prune-debt receipt \
             rests on the rejected-apply state being reachable AND survivable; \
             if that cell no longer exists, re-derive the argument before \
             relying on it"
        );
    }
}

/// #7342: each `security flow tcp-session` window on the wire lands in ITS OWN
/// `SessionTimeouts` field.
///
/// This binds the WIRING — the struct-literal assignment in
/// `build_forwarding_state` — not the function it calls.
/// `with_tcp_session_windows` is tested directly in
/// `session/tcp_close_state_7342_tests.rs`, and that test passes with the two
/// close fields transposed here, because it never reads `snapshot.flow`. The
/// four values are deliberately distinct from each other and from every
/// default, so a transposition is named by the value rather than merely
/// unequal — and closing vs time-wait is the pair that would transpose
/// silently, being adjacent, same-typed, and different only by which state
/// they govern.
#[test]
fn each_tcp_session_timeout_lands_in_its_own_session_timeout_field_7342() {
    let mut snapshot = ConfigSnapshot::default();
    snapshot.flow.tcp_session_timeout = 611;
    snapshot.flow.tcp_initial_timeout = 47;
    snapshot.flow.tcp_closing_timeout = 13;
    snapshot.flow.tcp_time_wait_timeout = 149;
    snapshot.flow.udp_session_timeout = 71;
    snapshot.flow.icmp_session_timeout = 23;

    let state = build_forwarding_state(&snapshot);
    let t = state.session_timeouts;
    for (label, got, want_secs) in [
        ("established", t.tcp_established_ns, 611u64),
        ("initial", t.tcp_opening_ns, 47),
        ("closing", t.tcp_closing_ns, 13),
        ("time_wait", t.tcp_time_wait_ns, 149),
        ("udp", t.udp_ns, 71),
        ("icmp", t.icmp_ns, 23),
    ] {
        assert_eq!(
            got,
            want_secs * 1_000_000_000,
            "the {label} window did not come from its own wire field — two \
             adjacent same-typed seconds values are transposed"
        );
    }
}

/// The same wiring with the three #7342 fields ABSENT: every window must hold
/// its dataplane default.
///
/// This is the skew case — a Go binary that predates #7342 omits the fields, so
/// `serde(default)` gives 0 — and it is what makes "an existing config reaps
/// exactly as before" true rather than merely intended. Without it the cell
/// above would pass an implementation that treated 0 as a literal zero window,
/// which reaps every session instantly.
#[test]
fn absent_tcp_session_timeout_fields_keep_the_dataplane_defaults_7342() {
    let state = build_forwarding_state(&ConfigSnapshot::default());
    let t = state.session_timeouts;
    let base = crate::session::SessionTimeouts::default();
    assert_eq!(t.tcp_established_ns, base.tcp_established_ns);
    assert_eq!(t.tcp_opening_ns, base.tcp_opening_ns);
    assert_eq!(t.tcp_closing_ns, base.tcp_closing_ns);
    assert_eq!(t.tcp_time_wait_ns, base.tcp_time_wait_ns);
    // ...and the two close windows are the same, so a pre-#7342 peer's
    // sessions reap exactly where they did before the state was split.
    assert_eq!(t.tcp_closing_ns, t.tcp_time_wait_ns);
}

// ---------------------------------------------------------------------------
// #7888: the inert set has to survive the trip from the wire into the
// forwarding state. This is the Rust half of the wiring guard — the Go half
// (`TestScreenInertProfilesReachTheWire_7888`) proves the field is EMITTED;
// this proves it is CONSUMED.
//
// RED on revert: delete `state.screen_inert_profiles = build_screen_inert_profiles(snapshot)`
// and the map is empty, which is the pre-#7888 behaviour — the field arrives on
// the wire and is dropped on the floor, so every inert zone still gets a bare
// Pass. A cell that called `build_screen_inert_profiles` directly would stay
// green through that revert, which is precisely the mistake this issue is about:
// the builder was never the broken part.
// ---------------------------------------------------------------------------
#[test]
fn inert_screen_profiles_reach_the_forwarding_state_7888() {
    let snapshot = ConfigSnapshot {
        screen_inert_profile_zones: vec![crate::ScreenMissingProfileRef {
            zone: "trust".into(),
            profile: "p".into(),
            alarm_without_drop: false,
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        state
            .screen_inert_profiles
            .get("trust")
            .map(|r| r.profile.as_str()),
        Some("p"),
        "the inert set must reach the forwarding state with its profile name intact — the \
         runtime WARN names the profile, and a WARN that cannot name it sends the operator \
         nowhere"
    );
    assert!(
        state.screen_missing_profiles.is_empty(),
        "an inert zone must NOT land in the undefined map — they select different WARN \
         texts, and merging them reintroduces the defect one layer down"
    );
}

// The mirror direction: an UNDEFINED ref must not leak into the inert map. Two
// cells, because a single implementation that wrote both wire fields into one
// map would satisfy either one alone.
#[test]
fn undefined_screen_profiles_do_not_leak_into_the_inert_map_7888() {
    let snapshot = ConfigSnapshot {
        screen_missing_profile_zones: vec![crate::ScreenMissingProfileRef {
            zone: "trust".into(),
            profile: "ghost".into(),
            alarm_without_drop: false,
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert_eq!(
        state.screen_missing_profiles.get("trust").map(String::as_str),
        Some("ghost")
    );
    assert!(
        state.screen_inert_profiles.is_empty(),
        "an undefined ref must not appear in the inert map"
    );
}

// #8442 — THE BLAST RADIUS. An empty forwarding-class name does not break one
// class; it refuses the ENTIRE snapshot, so every forwarding change in the same
// commit silently fails to apply while the CLI reports success.
//
// The Go emitter keeps an empty class (in `forwarding_classes` AND in the
// scheduler-map entries); `build_cos_classifier_tables` deliberately SKIPS an
// empty name when building `class_to_queue`. Each side is reasonable alone —
// the disagreement is the fault.
//
// This cell is deliberately at the FORWARDING-STATE level rather than
// `build_cos_state`, because the value of the #8442 gate is not "one CoS entry
// is wrong". It is that an unrelated neighbour in the same commit does not
// reach the dataplane either. A `build_cos_state`-level cell cannot say that.
#[test]
fn an_empty_forwarding_class_refuses_the_whole_snapshot_8442() {
    // One CoS stanza carrying an empty class, and ONE completely unrelated
    // forwarding change: a neighbour. The neighbour is the witness.
    let unrelated_neighbor = || crate::NeighborSnapshot {
        interface: "ge-0/0/0".into(),
        ifindex: 402,
        family: "inet".into(),
        ip: "10.0.1.2".into(),
        mac: "aa:bb:cc:dd:ee:02".into(),
        state: "reachable".into(),
        ..Default::default()
    };
    let cos = |include_empty: bool| {
        let mut forwarding_classes = vec![CoSForwardingClassSnapshot {
            name: "realfc".into(),
            queue: 6,
        }];
        let mut entries = vec![CoSSchedulerMapEntrySnapshot {
            forwarding_class: "realfc".into(),
            scheduler: String::new(),
        }];
        if include_empty {
            // Exactly what the Go emitter produced for `queue 5 ""` before the
            // commit gate — measured, not imagined.
            forwarding_classes.insert(
                0,
                CoSForwardingClassSnapshot {
                    name: String::new(),
                    queue: 5,
                },
            );
            entries.insert(
                0,
                CoSSchedulerMapEntrySnapshot {
                    forwarding_class: String::new(),
                    scheduler: String::new(),
                },
            );
        }
        ClassOfServiceSnapshot {
            forwarding_classes,
            schedulers: vec![],
            scheduler_maps: vec![CoSSchedulerMapSnapshot {
                name: "sm1".into(),
                entries,
            }],
            dscp_classifiers: vec![],
            ieee8021_classifiers: vec![],
            dscp_rewrite_rules: vec![],
            inet_precedence_classifiers: vec![],
        }
    };
    let snapshot = |include_empty: bool| ConfigSnapshot {
        interfaces: vec![InterfaceSnapshot {
            ifindex: 402,
            cos_shaping_rate_bytes_per_sec: 0,
            cos_scheduler_map: "sm1".into(),
            ..Default::default()
        }],
        neighbors: vec![unrelated_neighbor()],
        class_of_service: Some(cos(include_empty)),
        ..Default::default()
    };

    // CONTROL FIRST, so a failure below cannot be blamed on the fixture: with no
    // empty class the identical snapshot builds AND the unrelated neighbour is
    // installed.
    let ok_state = try_build_forwarding_state_with_policy_counters(
        &snapshot(false),
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect("control: the same snapshot without the empty class must build");
    assert!(
        !ok_state.neighbors.is_empty(),
        "control: the unrelated neighbour must be installed when the CoS stanza \
         is clean — if it is not, this cell cannot show that the empty class is \
         what removes it"
    );

    // THE DEFECT: one empty class name, and the WHOLE build is refused.
    let err = try_build_forwarding_state_with_policy_counters(
        &snapshot(true),
        &crate::policy::PolicyCounterStore::default(),
    )
    .expect_err(
        "an empty forwarding-class name must refuse the snapshot — if this builds, \
         the Go/Rust set disagreement has been closed on the Rust side and the \
         #8442 commit gate's rationale needs re-reading",
    );
    match err {
        crate::policy::SnapshotIntegrityError::SchedulerMapUnknownClass {
            ref scheduler_map,
            ref forwarding_class,
        } => {
            assert_eq!(scheduler_map, "sm1");
            assert_eq!(
                forwarding_class, "",
                "the refusal must be attributed to the EMPTY class — any other \
                 name means this cell is measuring a different miss"
            );
        }
        other => panic!("expected SchedulerMapUnknownClass, got {other:?}"),
    }
    // And that is the whole point: the refusal is snapshot-wide. There is no
    // partially-applied state to inspect — the caller keeps the PREVIOUS live
    // forwarding state, so the neighbour that the control proved installable is
    // simply not installed, and nothing tells the operator.
}

/// #9425: the inert reference's AUDIT MODIFIER must survive the decode.
///
/// `inert_screen_profiles_reach_the_forwarding_state_7888` proves the zone and
/// its profile name arrive. It says nothing about the flag, so dropping
/// `alarm_without_drop: r.alarm_without_drop` from `build_screen_inert_profiles`
/// left the ENTIRE Rust suite green while the shipped helper hard-dropped every
/// substituted default for a zone that asked for audit mode — the defect #9425
/// exists to fix, reinstated one layer down in the decode.
///
/// Both rows, because a builder that hard-codes either value passes the other
/// one alone.
#[test]
fn inert_screen_profile_audit_flag_survives_the_decode_9425() {
    for audit in [true, false] {
        let snapshot = ConfigSnapshot {
            screen_inert_profile_zones: vec![crate::ScreenMissingProfileRef {
                zone: "trust".into(),
                profile: "p".into(),
                alarm_without_drop: audit,
            }],
            ..Default::default()
        };
        let state = build_forwarding_state(&snapshot);
        let got = state
            .screen_inert_profiles
            .get("trust")
            .unwrap_or_else(|| panic!("POSITIVE CONTROL: the inert ref must decode at all"));
        assert_eq!(
            got.alarm_without_drop, audit,
            "the audit modifier must travel with the inert reference (audit={audit}); it is \
             the ONLY channel by which an inert zone's alarm-without-drop can reach the \
             helper, because such a zone gets no `screens` entry"
        );
        assert_eq!(got.profile, "p", "the profile name must still arrive (#7888)");
    }
}

/// The mirror control: an UNDEFINED reference must never carry the flag into the
/// helper. The wire struct is shared by both sets, so a decoder that read the
/// field on the undefined path would let that set inherit the inert set's
/// meaning.
#[test]
fn undefined_screen_profile_never_carries_an_audit_flag_9425() {
    let snapshot = ConfigSnapshot {
        screen_missing_profile_zones: vec![crate::ScreenMissingProfileRef {
            zone: "trust".into(),
            profile: "ghost".into(),
            // Even if a malformed or hostile sender sets it, the undefined path
            // has no field to put it in and the zone must keep hard-dropping.
            alarm_without_drop: true,
        }],
        ..Default::default()
    };
    let state = build_forwarding_state(&snapshot);
    assert!(
        state.screen_inert_profiles.is_empty(),
        "an undefined reference must not materialise an inert entry, which is the only \
         place an audit flag could be honoured"
    );
    assert!(
        state.screen_missing_profiles.contains_key("trust"),
        "POSITIVE CONTROL: the undefined reference itself must still decode"
    );
}

/// #9512: kernel-learned IPv6 routes whose next hop is the SAME link-local
/// address on different links. The Go importer publishes each leg as
/// `gateway@<netdev>`; the helper must bind each leg to its own link, and the
/// answer must not depend on snapshot interface order. Before #9512 the leg was
/// scope-less, and the connected-prefix scan bound whichever interface's
/// `fe80::/64` came first. The last route is the negative control: a
/// scope-less GLOBAL gateway still infers its link from the connected prefix.
#[test]
fn learned_link_local_next_hop_binds_its_own_link_in_any_order_9512() {
    fn iface(name: &str, linux: &str, ifindex: i32, global: &str, link_local: &str) -> InterfaceSnapshot {
        InterfaceSnapshot {
            name: name.into(),
            linux_name: linux.into(),
            ifindex,
            hardware_addr: format!("02:00:00:00:95:{:02x}", ifindex & 0xff),
            addresses: vec![
                crate::protocol::snapshot::InterfaceAddressSnapshot {
                    family: "inet6".into(),
                    address: global.into(),
                    ..Default::default()
                },
                crate::protocol::snapshot::InterfaceAddressSnapshot {
                    family: "inet6".into(),
                    address: link_local.into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }
    let route = |dst: &str, hops: &[&str]| crate::RouteSnapshot {
        table: "inet6.0".into(),
        family: "inet6".into(),
        destination: dst.into(),
        next_hops: hops.iter().map(|h| h.to_string()).collect(),
        ..Default::default()
    };
    let one = iface("ge-0/0/1.0", "ge-0-0-1", 101, "2001:db8:1::1/64", "fe80::1/64");
    let two = iface("ge-0/0/2.0", "ge-0-0-2", 102, "2001:db8:2::1/64", "fe80::2/64");
    let routes = vec![
        route("2001:db8:beef::/48", &["fe80::254@ge-0-0-2"]),
        route("2001:db8:cafe::/48", &["fe80::254@ge-0-0-1"]),
        route("2001:db8:ec::/48", &["fe80::254@ge-0-0-1", "fe80::254@ge-0-0-2"]),
        route("2001:db8:ab::/48", &["2001:db8:2::254"]),
    ];

    for (label, interfaces) in [
        ("ge-0-0-1 first", vec![one.clone(), two.clone()]),
        ("ge-0-0-2 first", vec![two.clone(), one.clone()]),
    ] {
        let snapshot = ConfigSnapshot {
            interfaces,
            routes: routes.clone(),
            ..Default::default()
        };
        let state = build_forwarding_state(&snapshot);
        let table = state.routes_v6.get("inet6.0").expect("inet6.0 table");
        let legs = |dst: &str| -> Vec<i32> {
            let prefix: Ipv6Addr = dst.split('/').next().unwrap().parse().unwrap();
            table
                .iter()
                .find(|r| r.prefix.contains(prefix))
                .unwrap_or_else(|| panic!("{label}: no route for {dst}"))
                .next_hops
                .iter()
                .map(|nh| nh.ifindex)
                .collect()
        };
        assert_eq!(legs("2001:db8:beef::"), vec![102], "{label}: fe80::254@ge-0-0-2 must bind ge-0-0-2");
        assert_eq!(legs("2001:db8:cafe::"), vec![101], "{label}: fe80::254@ge-0-0-1 must bind ge-0-0-1");
        assert_eq!(legs("2001:db8:ec::"), vec![101, 102], "{label}: each ECMP leg binds its own link");
        assert_eq!(legs("2001:db8:ab::"), vec![102], "{label}: a scope-less global gateway still infers its connected link");
    }
}

// #9173: the published key-ring bases reach the forwarding state, and one
// malformed base leaves the ring present with no base, so it fails closed.
#[test]
fn syn_cookie_key_ring_from_snapshot_reaches_forwarding_state_9173() {
    const PRIMARY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const OLD: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
    let base = |hex: &str, accept_only: bool| crate::protocol::SynCookieKeyBaseSnapshot {
        base: hex.into(),
        accept_only,
    };
    let ring = |bases| {
        Some(crate::protocol::SynCookieKeyRingSnapshot {
            period_secs: 56 * 64,
            bases,
        })
    };
    let snapshot = ConfigSnapshot {
        syn_cookie_master_key: "00112233445566778899aabbccddeeff".into(),
        syn_cookie_key_ring: ring(vec![base(PRIMARY, false), base(OLD, true)]),
        ..Default::default()
    };
    let rendered = format!("{:?}", build_forwarding_state(&snapshot).syn_cookie_key_ring);
    assert!(
        rendered.contains("present: true")
            && rendered.contains("period_epochs: 56")
            && rendered.contains("bases: 2 <redacted>"),
        "{rendered}"
    );

    // Non-hex, and a 32-hex key where a 64-hex base belongs, are both malformed.
    for bad in ["not-hex", "00112233445566778899aabbccddeeff"] {
        let state = build_forwarding_state(&ConfigSnapshot {
            syn_cookie_master_key: "00112233445566778899aabbccddeeff".into(),
            syn_cookie_key_ring: ring(vec![base(PRIMARY, false), base(bad, false)]),
            ..Default::default()
        });
        let rendered = format!("{:?}", state.syn_cookie_key_ring);
        assert!(
            rendered.contains("present: true") && rendered.contains("bases: 0 <redacted>"),
            "a malformed base {bad:?} must leave the ring present with no base, which fails \
             closed, not absent, which would fall back to the legacy key: {rendered}"
        );
        assert!(
            state.syn_cookie_master_key.0.is_some(),
            "the legacy key itself still parses"
        );
    }

    // A snapshot from an older control plane carries no ring at all.
    let absent = build_forwarding_state(&ConfigSnapshot {
        syn_cookie_master_key: "00112233445566778899aabbccddeeff".into(),
        ..Default::default()
    });
    let rendered = format!("{:?}", absent.syn_cookie_key_ring);
    assert!(
        rendered.contains("present: false"),
        "a snapshot without a ring must read as absent: {rendered}"
    );

    // A PRESENT but empty ring is a published ring with no usable base.
    let empty = build_forwarding_state(&ConfigSnapshot {
        syn_cookie_master_key: "00112233445566778899aabbccddeeff".into(),
        syn_cookie_key_ring: Some(crate::protocol::SynCookieKeyRingSnapshot::default()),
        ..Default::default()
    });
    let rendered = format!("{:?}", empty.syn_cookie_key_ring);
    assert!(
        rendered.contains("present: true") && rendered.contains("bases: 0 <redacted>"),
        "an explicit empty ring must fail closed, not fall back to the legacy key: {rendered}"
    );
}

// #9173: BIND THE WIRING. The ring only reaches the dataplane through the two
// worker sites that hand forwarding state to `ScreenState`. A site still calling
// `update_syn_cookie_master_key` would leave that worker on the legacy key with
// every screen-level cell green, so both are pinned here.
#[test]
fn worker_sites_publish_the_syn_cookie_key_ring_9173() {
    fn code(src: &str) -> String {
        src.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .flat_map(|line| line.chars().filter(|c| !c.is_whitespace()))
            .collect()
    }
    for (site, src, call) in [
        (
            "worker/loop_body/setup.rs",
            code(include_str!("../worker/loop_body/setup.rs")),
            "update_syn_cookie_keys(forwarding.syn_cookie_master_key.0,forwarding.syn_cookie_key_ring.clone()",
        ),
        (
            "worker/loop_body/mod.rs",
            code(include_str!("../worker/loop_body/mod.rs")),
            "update_syn_cookie_keys(new_forwarding.syn_cookie_master_key.0,new_forwarding.syn_cookie_key_ring.clone()",
        ),
    ] {
        assert!(
            src.contains(call),
            "{site} must publish the SYN-cookie key ring with the key"
        );
        assert!(
            !src.contains("update_syn_cookie_master_key("),
            "{site} must not publish the key without the ring"
        );
    }
}
