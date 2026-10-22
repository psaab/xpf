//! #7560 residual: the report GATE, not the counters.
//!
//! #8235 shipped the lease counters and a note for them, and left the gate
//! alone. The gate was already wrong at two of the three `reseed_retained_from`
//! call sites:
//!
//!   - `nat64.rs` gated on `reseeded || skipped_out_of_range || refused` and
//!     omitted `skipped_address_only` ENTIRELY, so a pass that skipped only
//!     address-only tokens counted them and then printed nothing;
//!   - the #6979 rename site always printed a line but left that count out of
//!     the message.
//!
//! Both are the same shape: the condition and the text are restated at each
//! caller, so a field added to `ReseedOutcome` has to be added in three places,
//! and was not — twice. Correcting the two sites would leave three places to
//! forget next time. `needs_report()` derives the gate from the struct so a
//! silently-ungated population is unrepresentable.
//!
//! These cells are about the GATE. The counters and the note are #8235's and
//! are tested there; nothing here re-tests them.

use super::allocator::ReseedOutcome;

/// #7560 residual PRIMARY: a pass whose ONLY non-carried population is
/// address-only tokens must still report.
///
/// This is precisely the NAT64 omission, reproduced against the derived gate.
///
/// FAIL-ON-REVERT: drop `self.skipped_address_only > 0` from `needs_report` and
/// this reds — the exact field the NAT64 condition was missing.
#[test]
fn a_pass_that_only_skipped_address_only_tokens_still_reports_7560() {
    let only_address_only = ReseedOutcome {
        skipped_address_only: 4,
        ..ReseedOutcome::default()
    };
    assert!(
        only_address_only.needs_report(),
        "a pass whose only effect was skipping four address-only tokens reported nothing. \
         That is the nat64.rs gate omission: the population was counted and then swallowed \
         by a condition that did not mention it",
    );
}

/// Every non-carried population must open the gate on its own. Asserting them
/// one at a time rather than together is what makes this catch a SINGLE
/// omission — a combined fixture with all three set passes even if two of the
/// three disjuncts are missing.
#[test]
fn each_non_carried_population_opens_the_gate_alone_7560() {
    for (label, outcome) in [
        (
            "skipped_out_of_range",
            ReseedOutcome { skipped_out_of_range: 1, ..ReseedOutcome::default() },
        ),
        (
            "skipped_address_only",
            ReseedOutcome { skipped_address_only: 1, ..ReseedOutcome::default() },
        ),
        ("refused", ReseedOutcome { refused: 1, ..ReseedOutcome::default() }),
    ] {
        assert!(
            outcome.needs_report(),
            "{label} alone did not open the report gate; a pass whose only lost population \
             is {label} would print nothing",
        );
    }
}

/// CONTROL: an outcome with nothing lost must NOT report.
///
/// Without this the primary is satisfied by `fn needs_report() -> bool { true }`,
/// which prints a line on every ordinary apply — noise an operator learns to
/// skip, reintroducing the invisibility by a different route. That is the
/// failure mode `dropped_persistent_lease_note` documents for its own silence,
/// and the gate owes the same discipline.
#[test]
fn a_pass_that_lost_nothing_does_not_report_7560() {
    assert!(
        !ReseedOutcome::default().needs_report(),
        "an empty outcome must not produce a line",
    );
    // A pass that carried everything and lost nothing is the EXPECTED case and
    // must stay silent too — `reseeded` is not a reason to report.
    let clean = ReseedOutcome { reseeded: 12, ..ReseedOutcome::default() };
    assert!(
        !clean.needs_report(),
        "a fully successful carry opened the report gate; the carry succeeding is the \
         expected case and reporting it every time is the noise this gate exists to avoid",
    );
}

/// The gate deliberately does NOT cover dropped leases: they have their own
/// note and their own condition (`dropped_persistent_lease_note`), so folding
/// them in here would print a "0 not carried, 0 skipped, 0 refused" line on a
/// lease-only drop.
///
/// This pins that separation so a later change does not "simplify" the two
/// conditions into one and reintroduce exactly that noise.
#[test]
fn dropped_leases_are_not_this_gates_population_7560() {
    let leases_only = ReseedOutcome {
        dropped_persistent_on_retained: 9,
        dropped_persistent_on_removed: 3,
        ..ReseedOutcome::default()
    };
    assert!(
        !leases_only.needs_report(),
        "the carried/skipped gate opened for a lease-only drop. Leases are reported by \
         dropped_persistent_lease_note, which has its own condition; opening this gate too \
         emits a line whose every counter is zero",
    );
    // And the note DOES fire for it, so the population is not lost between the
    // two conditions — the gap this cell would otherwise create.
    assert!(
        super::source::dropped_persistent_lease_note("p", &leases_only).is_some(),
        "a lease-only drop must still be reported by the lease note; if neither condition \
         fires, splitting them has silently dropped the population",
    );
}

/// The destructure in `needs_report` must stay EXHAUSTIVE.
///
/// This guards the guard, and it is not paranoia: when a new field breaks the
/// build, rustc's own help text offers *"or always ignore missing fields here"*
/// — i.e. add `..`. Taking that suggestion silences the compiler and restores
/// exactly the defect the destructure exists to prevent, and it does so while
/// looking like following the compiler's advice.
///
/// A runtime test cannot observe a compile-time property, so this reads the
/// source. That is the same shape as the repo's existing `*_doc_guard` tests.
///
/// FAIL-ON-REVERT: add `..` to the `let Self { ... } = *self;` pattern in
/// `needs_report` and this reds, while every other cell in this file stays
/// green — because with `..` the gate still behaves correctly TODAY and only
/// fails the next time someone adds a field.
#[test]
fn the_report_gate_destructure_stays_exhaustive_7560() {
    let src = include_str!("allocator/mod.rs");
    let at = src
        .find("pub(crate) fn needs_report")
        .expect("needs_report must exist; the gate is what this file is about");
    // Bound the check to the PATTERN ITSELF, not the function body. A first
    // version searched the whole body and red on its own doc comment, which
    // says "no `..` rest pattern" — the instrument was matching prose rather
    // than code, and would equally have missed a `..` sitting outside the
    // pattern.
    let body_end = src[at..]
        .find("\n    }\n")
        .expect("needs_report must have a closing brace");
    let body = &src[at..at + body_end];
    let pat_start = body.find("let Self {");
    let pattern = pat_start.map(|i| {
        let rest = &body[i..];
        let end = rest.find("} = *self;").expect("the destructure must be assigned from *self");
        &rest[..end]
    });

    assert!(
        pattern.is_some(),
        "needs_report no longer destructures ReseedOutcome. Without the destructure a new \
         population is silently ungated — the gate becomes one hand-written disjunction that \
         a new field slips past exactly as it slipped past three per-site conditions",
    );
    assert!(
        !pattern.unwrap_or("..").contains(".."),
        "needs_report's destructure has a `..` rest pattern. That silences the compile error \
         a new field is supposed to cause — which is rustc's own suggested fix and the wrong \
         one. With `..` the gate still works today and starts failing silently the next time \
         someone adds a field to ReseedOutcome",
    );
}
