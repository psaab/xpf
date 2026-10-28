//! #17228 parity cells for the consolidated CoS code-point table
//! builder.
//!
//! Before #17228 the DSCP and 802.1p table builders were separate
//! copies, and they had already diverged once: pre-#2447 the DSCP copy
//! masked out-of-range code-points (`dscp & 0x3f`, 110 → 46) while the
//! PCP copy clamped (`pcp.min(7)`, 9 → 7). All six builders now route
//! through the single `build_code_point_table` body, so these cells pin
//! the SHARED contract uniformly for every family: an empty classifier
//! name and a missing classifier both yield the all-`u8::MAX`
//! unclassified table, and a retained out-of-range code-point fails
//! CLOSED on both the queue and the loss-priority table of its family
//! instead of aliasing into an in-range slot. A future copy-pasted
//! seventh builder that reintroduced mask/clamp aliasing would fail
//! these cells for its family.

// `use super::*`: child module of cos.rs — the private builders, the
// shared `build_code_point_table`, and the `FastMap` alias re-exported
// via cos.rs's `super::super::*` are the surface under test.
use super::*;

/// One named classifier map: `{name: classifier}`.
fn one_classifier<C>(name: &str, classifier: C) -> FastMap<String, C> {
    let mut classifiers = FastMap::default();
    classifiers.insert(name.to_string(), classifier);
    classifiers
}

/// Every family's queue AND loss-priority table rejects its retained
/// out-of-range code-point with that family's error variant, carrying
/// the classifier name and the untouched code-point value. This is the
/// anti-divergence pin for #2447: 110 must not land in DSCP slot 46
/// (mask) and 9 must not land in PCP slot 7 (clamp) — in ANY family.
#[test]
fn cos_all_families_reject_out_of_range_code_point_fail_closed_17228() {
    let materialized = [0u8, 5];
    let dscp = one_classifier(
        "wan",
        CoSDSCPClassifierConfig {
            invalid_dscp: Some(110),
            ..Default::default()
        },
    );
    match build_cos_dscp_queue_table("wan", &dscp, &materialized, 0) {
        Err(crate::policy::SnapshotIntegrityError::CosDscpCodePointOutOfRange {
            classifier,
            dscp,
        }) => {
            assert_eq!(classifier, "wan");
            assert_eq!(dscp, 110);
        }
        other => panic!("DSCP queue table must fail closed on 110, got {other:?}"),
    }
    match build_cos_dscp_lp_table("wan", &dscp) {
        Err(crate::policy::SnapshotIntegrityError::CosDscpCodePointOutOfRange {
            classifier,
            dscp,
        }) => {
            assert_eq!(classifier, "wan");
            assert_eq!(dscp, 110);
        }
        other => panic!("DSCP LP table must fail closed on 110, got {other:?}"),
    }

    let ieee = one_classifier(
        "wan-pcp",
        CoSIEEE8021ClassifierConfig {
            invalid_pcp: Some(9),
            ..Default::default()
        },
    );
    match build_cos_ieee8021_queue_table("wan-pcp", &ieee, &materialized, 0) {
        Err(crate::policy::SnapshotIntegrityError::CosIeee8021CodePointOutOfRange {
            classifier,
            pcp,
        }) => {
            assert_eq!(classifier, "wan-pcp");
            assert_eq!(pcp, 9);
        }
        other => panic!("802.1p queue table must fail closed on 9, got {other:?}"),
    }
    match build_cos_ieee8021_lp_table("wan-pcp", &ieee) {
        Err(crate::policy::SnapshotIntegrityError::CosIeee8021CodePointOutOfRange {
            classifier,
            pcp,
        }) => {
            assert_eq!(classifier, "wan-pcp");
            assert_eq!(pcp, 9);
        }
        other => panic!("802.1p LP table must fail closed on 9, got {other:?}"),
    }

    let precedence = one_classifier(
        "wan-prec",
        CoSINetPrecedenceClassifierConfig {
            invalid_precedence: Some(9),
            ..Default::default()
        },
    );
    match build_cos_inet_precedence_queue_table("wan-prec", &precedence, &materialized, 0) {
        Err(crate::policy::SnapshotIntegrityError::CosInetPrecedenceCodePointOutOfRange {
            classifier,
            precedence,
        }) => {
            assert_eq!(classifier, "wan-prec");
            assert_eq!(precedence, 9);
        }
        other => panic!("inet-prec queue table must fail closed on 9, got {other:?}"),
    }
    match build_cos_inet_precedence_lp_table("wan-prec", &precedence) {
        Err(crate::policy::SnapshotIntegrityError::CosInetPrecedenceCodePointOutOfRange {
            classifier,
            precedence,
        }) => {
            assert_eq!(classifier, "wan-prec");
            assert_eq!(precedence, 9);
        }
        other => panic!("inet-prec LP table must fail closed on 9, got {other:?}"),
    }
}

/// The shared early-return contract, once per family: an empty
/// classifier name yields the all-`u8::MAX` table even when a
/// classifier under the empty name retains an invalid code-point, and
/// a name with no matching classifier yields the same table. Queue
/// tables substitute the default queue only for a materialized-map
/// miss, and LP tables copy classified values verbatim.
#[test]
fn cos_all_families_share_empty_missing_and_fill_contract_17228() {
    let materialized = [0u8, 5];

    let mut dscp_classifier = CoSDSCPClassifierConfig {
        invalid_dscp: Some(110),
        ..Default::default()
    };
    dscp_classifier.queue_by_dscp[46] = Some(5);
    dscp_classifier.queue_by_dscp[10] = Some(2); // not materialized → default 0
    dscp_classifier.lp_by_dscp[46] = 3;
    let dscp = one_classifier("", dscp_classifier);
    assert_eq!(
        build_cos_dscp_queue_table("", &dscp, &materialized, 0).expect("empty name builds"),
        [u8::MAX; 64],
        "empty DSCP name must skip the invalid code-point check"
    );
    assert_eq!(
        build_cos_dscp_lp_table("", &dscp).expect("empty name builds"),
        [u8::MAX; 64]
    );
    let dscp_named = one_classifier("wan", {
        let mut c = CoSDSCPClassifierConfig::default();
        c.queue_by_dscp[46] = Some(5);
        c.queue_by_dscp[10] = Some(2);
        c.lp_by_dscp[46] = 3;
        c
    });
    assert_eq!(
        build_cos_dscp_queue_table("absent", &dscp_named, &materialized, 0)
            .expect("missing classifier builds"),
        [u8::MAX; 64]
    );
    let dscp_queue =
        build_cos_dscp_queue_table("wan", &dscp_named, &materialized, 0).expect("DSCP builds");
    assert_eq!(dscp_queue[46], 5, "materialized queue is kept");
    assert_eq!(
        dscp_queue[10], 0,
        "unmaterialized queue falls back to default"
    );
    assert_eq!(dscp_queue[0], u8::MAX, "unclassified code-point stays MAX");
    let dscp_lp = build_cos_dscp_lp_table("wan", &dscp_named).expect("DSCP LP builds");
    assert_eq!(dscp_lp[46], 3);
    assert_eq!(dscp_lp[10], u8::MAX);

    let ieee = one_classifier("wan-pcp", {
        let mut c = CoSIEEE8021ClassifierConfig::default();
        c.queue_by_pcp[7] = Some(5);
        c.lp_by_pcp[7] = 2;
        c
    });
    assert_eq!(
        build_cos_ieee8021_queue_table("", &ieee, &materialized, 0).expect("empty name builds"),
        [u8::MAX; 8]
    );
    assert_eq!(
        build_cos_ieee8021_queue_table("absent", &ieee, &materialized, 0)
            .expect("missing classifier builds"),
        [u8::MAX; 8]
    );
    let ieee_queue =
        build_cos_ieee8021_queue_table("wan-pcp", &ieee, &materialized, 0).expect("PCP builds");
    assert_eq!(ieee_queue[7], 5);
    assert_eq!(ieee_queue[0], u8::MAX);
    let ieee_lp = build_cos_ieee8021_lp_table("wan-pcp", &ieee).expect("PCP LP builds");
    assert_eq!(ieee_lp[7], 2);
    assert_eq!(ieee_lp[0], u8::MAX);

    let precedence = one_classifier("wan-prec", {
        let mut c = CoSINetPrecedenceClassifierConfig::default();
        c.queue_by_prec[6] = Some(5);
        c.lp_by_prec[6] = 1;
        c
    });
    assert_eq!(
        build_cos_inet_precedence_queue_table("", &precedence, &materialized, 0)
            .expect("empty name builds"),
        [u8::MAX; 8]
    );
    assert_eq!(
        build_cos_inet_precedence_queue_table("absent", &precedence, &materialized, 0)
            .expect("missing classifier builds"),
        [u8::MAX; 8]
    );
    let prec_queue =
        build_cos_inet_precedence_queue_table("wan-prec", &precedence, &materialized, 0)
            .expect("precedence builds");
    assert_eq!(prec_queue[6], 5);
    assert_eq!(prec_queue[0], u8::MAX);
    let prec_lp =
        build_cos_inet_precedence_lp_table("wan-prec", &precedence).expect("precedence LP builds");
    assert_eq!(prec_lp[6], 1);
    assert_eq!(prec_lp[0], u8::MAX);
}
