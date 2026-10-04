//! #7337 cells for [`super::dangling_cos_interface_refs`].
//!
//! Split out of `cos.rs` for the same reason as
//! `remainder_temporal_tests_6846` — keeping that file under the 1500 LOC
//! modularity WATCH floor. Loaded as a child module of `cos`, so `use super::*`
//! still reaches the private builder these cells pin.
//!
//! What these assert is that a dangling reference becomes OBSERVABLE. They
//! deliberately do NOT assert that it is rejected: the applied behaviour was
//! already correct (#1183's skip, and #1960's lenient path), and silence was
//! the whole defect. `build_cos_state_skips_interface_with_unresolvable_named_references`
//! in `forwarding_build/tests.rs` still pins the applied half, unchanged.
use super::*;
use crate::{
    CoSDSCPClassifierEntrySnapshot, CoSDSCPClassifierSnapshot, CoSDSCPRewriteRuleEntrySnapshot,
    CoSDSCPRewriteRuleSnapshot, CoSForwardingClassSnapshot, CoSIEEE8021ClassifierEntrySnapshot,
    CoSIEEE8021ClassifierSnapshot, CoSINetPrecedenceClassifierEntrySnapshot,
    CoSINetPrecedenceClassifierSnapshot, CoSSchedulerMapEntrySnapshot,
};

/// One CoS snapshot defining exactly one entity of each referable kind, so a
/// test can name either the real one (resolves) or a typo (does not).
fn cos_with_one_of_each() -> ClassOfServiceSnapshot {
    ClassOfServiceSnapshot {
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
        inet_precedence_classifiers: vec![CoSINetPrecedenceClassifierSnapshot {
            name: "prec-cls".into(),
            entries: vec![CoSINetPrecedenceClassifierEntrySnapshot {
                forwarding_class: "best-effort".into(),
                loss_priority: String::new(),
                precedences: vec![0],
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
    }
}

/// Every referable kind, as (label the builder emits, a setter putting `name`
/// into the matching interface field, the name that DOES resolve).
///
/// One row per kind is what makes the five-way enumeration explicit; the
/// census cell below is what forces a SIXTH field to arrive here rather than
/// being quietly unchecked, which is the drift this issue already suffered
/// once (`cos_inet_precedence_classifier` was added by #6847 after filing and
/// leaked identically).
#[allow(clippy::type_complexity)]
fn ref_kinds() -> Vec<(&'static str, fn(&mut InterfaceSnapshot, &str), &'static str)> {
    vec![
        (
            "scheduler-map",
            (|i, n| i.cos_scheduler_map = n.to_string()) as fn(&mut InterfaceSnapshot, &str),
            "wan-map",
        ),
        (
            "dscp classifier",
            |i, n| i.cos_dscp_classifier = n.to_string(),
            "dscp-cls",
        ),
        (
            "ieee-802.1 classifier",
            |i, n| i.cos_ieee8021_classifier = n.to_string(),
            "p8021-cls",
        ),
        (
            "inet-precedence classifier",
            |i, n| i.cos_inet_precedence_classifier = n.to_string(),
            "prec-cls",
        ),
        (
            "dscp rewrite-rule",
            |i, n| i.cos_dscp_rewrite_rule = n.to_string(),
            "dscp-rw",
        ),
    ]
}

#[test]
fn every_reference_kind_reports_when_it_dangles() {
    let cos = cos_with_one_of_each();
    let tables = build_cos_classifier_tables(&cos).expect("tables build");
    for (label, set, _resolving) in ref_kinds() {
        let mut iface = InterfaceSnapshot {
            ifindex: 301,
            ..Default::default()
        };
        set(&mut iface, "typo-name");
        let got = dangling_cos_interface_refs(&iface, &tables);
        assert_eq!(
            got,
            vec![(label, "typo-name".to_string())],
            "a dangling {label} must be reported, and reported as exactly that kind"
        );
    }
}

#[test]
fn a_reference_that_resolves_reports_nothing() {
    let cos = cos_with_one_of_each();
    let tables = build_cos_classifier_tables(&cos).expect("tables build");
    for (label, set, resolving) in ref_kinds() {
        let mut iface = InterfaceSnapshot {
            ifindex: 302,
            ..Default::default()
        };
        set(&mut iface, resolving);
        assert!(
            dangling_cos_interface_refs(&iface, &tables).is_empty(),
            "{label} {resolving:?} resolves, so it must NOT be reported — a warning on a \
             correct config is worse than none, operators stop reading them"
        );
    }
}

#[test]
fn an_unset_reference_reports_nothing() {
    let cos = cos_with_one_of_each();
    let tables = build_cos_classifier_tables(&cos).expect("tables build");
    // The overwhelmingly common interface: no CoS configured at all. Empty is
    // not dangling, and if this ever reported, every plain forwarding interface
    // on the box would emit five warnings per apply.
    let iface = InterfaceSnapshot {
        ifindex: 303,
        ..Default::default()
    };
    assert!(dangling_cos_interface_refs(&iface, &tables).is_empty());
}

#[test]
fn an_admitted_interface_still_reports_its_dangling_reference() {
    // The shape that makes this worth fixing at the reference level rather
    // than on the skip path. A shaping rate admits the interface to CoSState
    // on its own, so #1183's gate never drops it; the typo'd classifier then
    // resolves to nothing inside build_cos_dscp_queue_table and installs an
    // unset table. The operator sees CoS active on the interface and has no
    // way to learn that the classifier is inert. A skip-path-only report would
    // say nothing here.
    let cos = cos_with_one_of_each();
    let tables = build_cos_classifier_tables(&cos).expect("tables build");
    let iface = InterfaceSnapshot {
        ifindex: 304,
        cos_shaping_rate_bytes_per_sec: 1_000_000,
        cos_dscp_classifier: "dscp-clsss".into(),
        ..Default::default()
    };
    assert!(
        build_cos_iface_config(
            &iface,
            &tables,
            CoSIngressClassifierBindings::default(),
        )
        .expect("builds")
        .is_some(),
        "precondition: the shaping rate must admit this interface, or this cell is \
         measuring the skip path instead of the admitted path"
    );
    assert_eq!(
        dangling_cos_interface_refs(&iface, &tables),
        vec![("dscp classifier", "dscp-clsss".to_string())]
    );
}

#[test]
fn several_dangling_references_are_all_reported() {
    let cos = cos_with_one_of_each();
    let tables = build_cos_classifier_tables(&cos).expect("tables build");
    let iface = InterfaceSnapshot {
        ifindex: 305,
        cos_scheduler_map: "nope-map".into(),
        cos_dscp_rewrite_rule: "nope-rw".into(),
        ..Default::default()
    };
    // Reporting only the first would leave an operator fixing one typo,
    // re-applying, and finding another — the report has to be complete.
    assert_eq!(
        dangling_cos_interface_refs(&iface, &tables),
        vec![
            ("scheduler-map", "nope-map".to_string()),
            ("dscp rewrite-rule", "nope-rw".to_string()),
        ]
    );
}

#[test]
fn every_cos_string_field_is_classified_as_reference_or_value() {
    // A census over the SNAPSHOT, which is the population that actually grows.
    // This issue's own field count went 4 -> 5 when #6847 added
    // `cos_inet_precedence_classifier`, and nothing noticed until someone
    // counted by hand — so a new String field must be forced to a decision
    // here rather than silently joining the unchecked set.
    //
    // What this proves: the field SET is accounted for. What it does not
    // prove: that `dangling_cos_interface_refs` checks each one — that is what
    // `every_reference_kind_reports_when_it_dangles` enumerates. Adding a
    // reference field therefore reds THIS cell, and the fix is to add it to
    // both this list and `ref_kinds`.
    const REFERENCES: &[&str] = &[
        "cos_scheduler_map",
        "cos_dscp_classifier",
        "cos_ieee8021_classifier",
        "cos_inet_precedence_classifier",
        "cos_dscp_rewrite_rule",
    ];
    // Not a reference: an enumerated VALUE parsed by match in
    // build_cos_iface_config, naming no other CoS entity, so it cannot dangle.
    const VALUES: &[&str] = &["cos_oversubscription_policy"];

    let src = include_str!("../../../protocol/snapshot.rs");
    let mut found: Vec<&str> = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("pub cos_") else {
            continue;
        };
        let Some((name, ty)) = rest.split_once(':') else {
            continue;
        };
        if ty.trim().trim_end_matches(',') == "String" {
            found.push(name.trim());
        }
    }
    assert!(
        !found.is_empty(),
        "the census parsed ZERO cos_* String fields out of snapshot.rs — the shape it greps \
         for changed and this cell is now vacuous, which looks identical to a clean pass"
    );
    for name in &found {
        let full = format!("cos_{name}");
        assert!(
            REFERENCES.contains(&full.as_str()) || VALUES.contains(&full.as_str()),
            "InterfaceSnapshot::{full} is a cos_* String field that is neither declared a NAMED \
             REFERENCE nor a VALUE. If it names another CoS entity, add it to REFERENCES and to \
             ref_kinds() so a dangling one is reported; if it is an enumerated value, add it to \
             VALUES with the reason."
        );
    }
    assert_eq!(
        found.len(),
        REFERENCES.len() + VALUES.len(),
        "census counted {} cos_* String fields but {} are declared; a field was removed from \
         snapshot.rs and left declared here, which reads as coverage it no longer has",
        found.len(),
        REFERENCES.len() + VALUES.len()
    );
}
