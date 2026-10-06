use super::run_before_pmech_deadline;

#[test]
fn expired_p2_descriptor_is_refused_before_adjudication_9506() {
    let (mut refused, mut adjudicated) = (0, 0);
    let decision = run_before_pmech_deadline(
        10,
        10,
        || refused += 1,
        || {
            adjudicated += 1;
            ()
        },
    );

    assert!(decision.is_none(), "expired descriptor reached adjudication");
    assert_eq!(refused, 1, "expired descriptor refusal was not counted");
    assert_eq!(adjudicated, 0, "expired descriptor was adjudicated");
}

#[test]
fn deadline_gate_fails_closed_on_zero_clock_and_admits_live_descriptor_9506() {
    let (mut refused, mut adjudicated) = (0, 0);
    let zero_clock = run_before_pmech_deadline(
        11,
        0,
        || refused += 1,
        || {
            adjudicated += 1;
        },
    );
    assert!(zero_clock.is_none(), "zero clock sample was not refused");
    assert_eq!(refused, 1, "zero clock refusal was not counted");
    assert_eq!(adjudicated, 0, "zero clock descriptor was adjudicated");

    let live = run_before_pmech_deadline(
        11,
        10,
        || refused += 1,
        || {
            adjudicated += 1;
            42
        },
    );
    assert_eq!(live, Some(42), "live descriptor did not reach adjudication");
    assert_eq!(refused, 1, "live descriptor was refused");
    assert_eq!(adjudicated, 1, "live descriptor was not adjudicated once");
}
