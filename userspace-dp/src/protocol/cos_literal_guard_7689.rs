//! #7689: keep additive-wire struct literals non-exhaustive.
//!
//! Two cells. The first pins `CoSSchedulerSnapshot` at ZERO exhaustive
//! literals — it was the tree's outlier at 97% and the struct that paid #6846's
//! 71-literal toll. The second is a per-struct RATCHET over the whole
//! additive-wire population, added when the same shape turned up in four
//! structs in a single session. Its header explains why the obvious
//! generalisation of that observation is wrong.
//!
//! An ADDITIVE wire field — one carrying `#[serde(default)]`, designed to be
//! invisible to older peers — is a compile break at every **exhaustive** struct
//! literal, i.e. every literal with no `..Default::default()` tail. Those
//! literals do not care about the new field; they break only because they
//! enumerate.
//!
//! `CoSSchedulerSnapshot` was the tree's outlier: 72 of 74 literals enumerated
//! (97%), against 1 of 402 for `InterfaceSnapshot` and 12 of 330 for
//! `FirewallTermSnapshot`. #6846 paid that toll — two new fields broke 71
//! literals across five files — and #7689 converted them. This is the second
//! half of #7689's acceptance: the cell that stops the pattern coming back,
//! because the habit is what regrows it.
//!
//! Deliberately NOT `#[non_exhaustive]`. That would force the tail at compile
//! time, but it also blocks exhaustive construction outside the defining crate
//! and changes the type's public contract to solve a test-hygiene problem.

use crate::afxdp::worker_queue::tests::{afxdp_rs_files, blank_comments_and_strings};

/// Split a struct-literal body on its DEPTH-0 commas.
///
/// The struct-update tail is `..expr` occupying the position a field name would
/// occupy, so it is the segment test that identifies it — not a substring
/// search for `..`, which also matches a range inside a field value
/// (`foo: 0..3`) and would score an exhaustive literal as guarded.
fn depth0_segments(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for ch in body.chars() {
        match ch {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth -= 1,
            _ => {}
        }
        if ch == ',' && depth == 0 {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    out.push(cur);
    out
}

/// True when the literal body carries a `..` struct-update tail.
fn has_update_tail(body: &str) -> bool {
    depth0_segments(body)
        .iter()
        .any(|s| s.trim_start().starts_with(".."))
}

#[test]
fn cos_scheduler_snapshot_literals_carry_an_update_tail_7689() {
    // The whole crate source, not just `src/afxdp`: `src/protocol/` holds 15 of
    // these literals, and a scan rooted at the afxdp subtree would report a
    // clean tree while never reading them. (`afxdp_rs_files` is a generic
    // recursive `.rs` walker despite its name.)
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    afxdp_rs_files(&root, &mut files);

    let mut literals = 0usize;
    let mut skipped_non_literal = 0usize;
    let mut exhaustive: Vec<String> = Vec::new();

    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        let raw = std::fs::read_to_string(path).expect("read source");

        // Comments and string bodies are blanked BEFORE any brace or comma
        // arithmetic. This is not defensive dressing: a literal whose tail is
        // written `field: 1, // note\n ..Default::default()` puts the comment
        // at the head of the final depth-0 segment, so an unblanked scan reads
        // that segment as starting with `//` and reports a guarded literal as
        // exhaustive. Measured on this tree — it produced a false positive at
        // forwarding_build/tests.rs before blanking was added. The shared
        // helper is reused rather than re-implemented for exactly the reason
        // `afxdp/worker_queue.rs` gives where it widens the visibility: "a
        // second copy of comment-blanking is exactly where a source-scanning
        // gate quietly stops seeing what it is meant to."
        let src = blank_comments_and_strings(&raw);

        let mut from = 0usize;
        while let Some(hit) = src[from..].find("CoSSchedulerSnapshot") {
            let start = from + hit;
            from = start + "CoSSchedulerSnapshot".len();

            // Require the identifier to be whole, then an optional run of
            // whitespace, then `{`. Anything else is a mention, not a literal.
            let after = src[from..].trim_start();
            if !after.starts_with('{') {
                continue;
            }
            let brace = from + src[from..].find('{').expect("checked above");

            // `struct X {`, `impl ... for X {` and `-> X {` all match the
            // identifier-then-brace shape and are NOT literals. The return-type
            // case is the one that bites: a constructor helper
            // `fn f(..) -> CoSSchedulerSnapshot {` would otherwise have its
            // whole FUNCTION BODY brace-matched as a literal body, which
            // contains no depth-0 `..` segment and so scores as exhaustive.
            // Measured: 4 such helpers in this tree, all false positives
            // before this guard was added.
            let pre = src[..start].trim_end();
            if pre.ends_with("->")
                || pre.ends_with("struct")
                || pre.ends_with("impl")
                || pre.ends_with("for")
            {
                skipped_non_literal += 1;
                continue;
            }

            // Brace-match the literal body.
            let bytes = src.as_bytes();
            let mut i = brace + 1;
            let mut depth = 1i32;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            if depth != 0 {
                continue; // unbalanced: not a literal we can judge
            }
            let body = &src[brace + 1..i - 1];

            literals += 1;
            if !has_update_tail(body) {
                let line = src[..start].matches('\n').count() + 1;
                exhaustive.push(format!("{rel}:{line}"));
            }
        }
    }

    // NON-VACUITY. The assertion below is an ABSENCE, so it passes for two very
    // different reasons: the literals all carry a tail, or the scan found no
    // literals at all. A rename of the struct, a move of these files, or a
    // regression in the match shape would each silently produce a clean report.
    // Both populations are floored so a scan that reached nothing FAILS instead.
    assert!(
        files.len() >= 200,
        "scan read only {} .rs files under src — the walk is broken, so the \
         exhaustive-literal assertion below would pass vacuously",
        files.len()
    );
    assert!(
        literals >= 70,
        "found only {literals} CoSSchedulerSnapshot literals (expected ~83). \
         Either the struct was renamed or the match shape stopped matching — \
         either way this cell is no longer measuring what it names, and a \
         green result here would mean nothing"
    );

    assert!(
        exhaustive.is_empty(),
        "{} CoSSchedulerSnapshot literal(s) enumerate every field with no \
         `..Default::default()` tail, so the next additive wire field breaks \
         them:\n  {}\n\nAdd `..Default::default()` and keep only the fields the \
         test asserts on. If a literal must enumerate DELIBERATELY (to force a \
         compile break when a field is added), say so at the site and raise \
         this ceiling with the reason — do not delete the assertion.",
        exhaustive.len(),
        exhaustive.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// #7689 GENERALISED: the same tax, measured across the whole additive-wire
// population rather than the one struct that paid it loudest.
// ---------------------------------------------------------------------------
//
// WHY THE OBVIOUS GENERALISATION IS WRONG, measured before building this.
//
// The prompt for this was four structs needing `..Default::default()` in one
// session: `CoSSchedulerSnapshot`, `StageSeed`, `ProcessStatus` and
// `WorkerRuntimeCounters`. Four instances looks like a class. It is two.
//
//   CoSSchedulerSnapshot  13 fields  serde(default)  -> additive WIRE type
//   ProcessStatus        153 fields  serde(default)  -> additive WIRE type
//   StageSeed              4 fields  no derives      -> test-harness struct
//   WorkerRuntimeCounters 20 fields  no serde at all -> internal counters
//
// The tax #7689 describes is specific: an ADDITIVE wire field carries
// `#[serde(default)]` precisely so an older peer never sees it, so a test
// literal breaking on it is pure friction with no review value. For a
// NON-wire struct the opposite holds — adding a field is an ordinary breaking
// change, and the compile error at each site is review pressure worth keeping.
// Forcing `..Default::default()` onto `WorkerRuntimeCounters` would REMOVE a
// signal rather than remove a cost.
//
// So a guard scoped to all four would be scoped to a class that does not
// exist, and would actively weaken review on two of them.
//
// AND THE NAIVE POPULATION IS UNSHIPPABLE. "Every struct with a Default impl"
// is 240 structs, 130 of which have at least one exhaustive literal, totalling
// **1497** literals. Most are harmless: `FirewallFilterSnapshot` is 276 of 276
// exhaustive and costs nothing, because it has three fields and does not grow.
// Exhaustiveness is only a tax on a struct that GAINS fields.
//
// The population below is therefore: a Default impl, at least one
// `#[serde(default)]` field, and >= 8 fields. That is 124 literals across 23
// structs — tractable, and every one of them is a type designed to grow.
//
// WHY A RATCHET RATHER THAN AN ASSERTION OF ZERO. Converting 124 literals now
// is a mechanical change across 23 structs and five subsystems, with real
// conflict surface against every lane. The ceiling table records today's count
// per struct and only ever goes DOWN: a struct drifting back toward
// `CoSSchedulerSnapshot`'s 97% reds immediately, while the existing backlog
// stays visible and shrinkable. Same shape as #7484's coverage ratchet.
// #8537 tightened seven of these after fixing a scan defect that counted
// PATH-QUALIFIED TYPE POSITIONS as struct literals. ConfigSnapshot's ceiling of
// 15 was 15 miscounts, one for one: the tree contains exactly 15
// `-> crate::ConfigSnapshot {` return types and, measured, every qualified
// occurrence in EXPRESSION position already carried `..Default::default()`. So
// no real literal was lost when the number went to 0 — the ceiling had simply
// been holding room for a miscount, which is the specific way a ratchet decays
// into permission.
const ADDITIVE_WIRE_EXHAUSTIVE_CEILING: &[(&str, usize)] = &[
    // #16242: tightened 2 -> 0. The two exhaustive main_tests literals
    // gained `..Default::default()` tails when the tx_batch_*/
    // tx_kick_batch_* fields landed, so no exhaustive literal remains;
    // the ceiling holds that ground instead of decaying into permission.
    ("BindingCountersSnapshot", 0),
    ("ConfigSnapshot", 0),
    ("DestinationNATRuleSnapshot", 3),
    ("ExceptionStatus", 1),
    ("FabricSnapshot", 7),
    ("FirewallTermSnapshot", 12),
    ("FlowWorkerStatus", 1),
    ("InjectPacketRequest", 1),
    ("InterfaceSnapshot", 0),
    ("MapPins", 0),
    ("NAT64RuleSnapshot", 3),
    ("NeighborSnapshot", 26),
    ("PacketResolution", 1),
    ("ProcessStatus", 1),
    ("SessionDeltaInfo", 1),
    ("SlowPathStatus", 1),
    ("SourceNATRuleSnapshot", 0),
    ("SourceNatPoolStatus", 1),
    ("StaticNATRuleSnapshot", 34),
    ("ThreeColorPolicerSnapshot", 2),
    ("ThreeColorPolicerStatus", 1),
    ("WgTunnelStatus", 2),
    ("WorkerRuntimeStatus", 1),
];

/// Count exhaustive literals of `name` across the crate, using the same
/// detection the CoSSchedulerSnapshot cell above proved out: comments and
/// strings blanked first, non-literal matches (`-> X {`, `struct X {`) skipped,
/// and the update tail identified by DEPTH-0 SEGMENT rather than by a `..`
/// substring.
fn exhaustive_literal_count(files: &[std::path::PathBuf], name: &str) -> usize {
    let mut exhaustive = 0usize;
    for path in files {
        let raw = std::fs::read_to_string(path).expect("read source");
        exhaustive += exhaustive_literal_count_in_source(&raw, name);
    }
    exhaustive
}

/// #8537: walk backwards from `start` over any `ident::` segments and return
/// the index where the whole PATH begins (`crate::a::Name` -> index of
/// `crate`). `start` is returned unchanged when the name is not qualified.
fn path_start(bytes: &[u8], start: usize) -> usize {
    let mut at = start;
    loop {
        if at < 2 || bytes[at - 1] != b':' || bytes[at - 2] != b':' {
            return at;
        }
        let sep = at - 2;
        let mut i = sep;
        while i > 0 {
            let c = bytes[i - 1];
            if c == b'_' || c.is_ascii_alphanumeric() {
                i -= 1;
            } else {
                break;
            }
        }
        if i == sep {
            // `::` with no identifier before it (a leading `::Name`). The path
            // begins at the separator.
            return sep;
        }
        at = i;
    }
}

/// The source-level half of the scan, split out (#8537) so both directions can
/// be tested against a fixture instead of against the tree — a cell that can
/// only assert "the false positive is gone" would also pass against deleting
/// the guard.
fn exhaustive_literal_count_in_source(raw: &str, name: &str) -> usize {
    let mut exhaustive = 0usize;
    {
        let src = blank_comments_and_strings(raw);
        let mut from = 0usize;
        while let Some(hit) = src[from..].find(name) {
            let start = from + hit;
            from = start + name.len();
            // whole-identifier match only
            if start > 0 {
                let prev = src.as_bytes()[start - 1];
                if prev == b'_' || prev.is_ascii_alphanumeric() {
                    continue;
                }
            }
            let after = src[from..].trim_start();
            if !after.starts_with('{') {
                continue;
            }
            let brace = from + src[from..].find('{').expect("checked");
            // #8537: the arms below inspect the text immediately BEFORE the
            // name, so a PATH-QUALIFIED occurrence used to defeat every one of
            // them: for `-> crate::ConfigSnapshot {` the preceding text ends
            // with `::`, not `->`, and a RETURN TYPE was counted as an
            // exhaustive literal. The #8138 branch tripped the ratchet on a
            // test helper that contained no literal at all.
            //
            // Strip the qualifier and apply the same arms to what precedes the
            // WHOLE path. Skipping every `::`-preceded hit instead would trade
            // this false positive for a false NEGATIVE: `crate::Name { .. }` in
            // expression position is a real exhaustive literal and must still
            // count.
            let name_start = path_start(src.as_bytes(), start);
            let pre = src[..name_start].trim_end();
            if pre.ends_with("->")
                || pre.ends_with("struct")
                || pre.ends_with("impl")
                || pre.ends_with("for")
                || pre.ends_with("enum")
            {
                continue;
            }
            let bytes = src.as_bytes();
            let mut i = brace + 1;
            let mut depth = 1i32;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'{' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            if depth != 0 {
                continue;
            }
            if !has_update_tail(&src[brace + 1..i - 1]) {
                exhaustive += 1;
            }
        }
    }
    exhaustive
}

/// #8537 both-directions fixture for the literal scan.
///
/// The bug this fixes was a FALSE POSITIVE — a path-qualified return type
/// counted as an exhaustive struct literal. The obvious repair, "skip any hit
/// preceded by `::`", trades it for a false NEGATIVE, because
/// `crate::Name { .. }` in EXPRESSION position is a real exhaustive literal.
/// So every row below pins one side or the other, and the rows are in one cell
/// deliberately: a fix that satisfies only the false-positive rows would also
/// satisfy deleting the guard.
#[test]
fn literal_scan_distinguishes_qualified_types_from_qualified_literals_8537() {
    // (source, expected count, why)
    let cases: &[(&str, usize, &str)] = &[
        // --- MUST NOT COUNT: type positions, qualified and bare ---
        ("fn f() -> Wire { Wire::default() }", 0, "bare return type"),
        (
            "fn f() -> crate::Wire { crate::Wire::default() }",
            0,
            "#8537: PATH-QUALIFIED return type — the regression this fixes",
        ),
        (
            "fn f() -> crate::a::b::Wire { todo!() }",
            0,
            "deeply qualified return type",
        ),
        ("struct Wire { a: u8 }", 0, "struct definition"),
        ("impl Wire { fn n() {} }", 0, "bare impl header"),
        ("impl crate::Wire { fn n() {} }", 0, "qualified impl header"),
        (
            "impl Default for crate::Wire { fn default() -> Self { todo!() } }",
            0,
            "qualified trait-impl header",
        ),
        // --- MUST COUNT: real exhaustive literals, qualified and bare ---
        ("let w = Wire { a: 1, b: 2 };", 1, "bare exhaustive literal"),
        (
            "let w = crate::Wire { a: 1, b: 2 };",
            1,
            "#8537 the other direction: a QUALIFIED literal is still a literal",
        ),
        (
            "let w = crate::proto::Wire { a: 1 };",
            1,
            "deeply qualified literal",
        ),
        // --- MUST NOT COUNT: literals that carry the update tail ---
        (
            "let w = Wire { a: 1, ..Default::default() };",
            0,
            "bare literal with update tail",
        ),
        (
            "let w = crate::Wire { a: 1, ..Default::default() };",
            0,
            "qualified literal with update tail",
        ),
        // --- whole-identifier matching must survive the change ---
        (
            "let w = MyWire { a: 1 };",
            0,
            "a longer identifier ENDING in the name is not the name",
        ),
    ];

    for (src, want, why) in cases {
        let got = exhaustive_literal_count_in_source(src, "Wire");
        assert_eq!(
            got, *want,
            "exhaustive_literal_count_in_source({src:?}) = {got}, want {want} — {why}"
        );
    }

    // NON-VACUITY: the scan must be capable of returning both answers, or the
    // table above could be satisfied by a function that always returns 0.
    assert_eq!(
        exhaustive_literal_count_in_source("let w = Wire { a: 1 };", "Wire"),
        1,
        "the scan never returns a nonzero count — it cannot be measuring anything"
    );
    assert_eq!(
        exhaustive_literal_count_in_source("fn f() -> crate::Wire { todo!() }", "Wire"),
        0,
        "the scan never returns zero — it cannot be excluding anything"
    );
}

/// The ratchet: no struct in the additive-wire population may gain exhaustive
/// literals.
///
/// FAIL-ON-REVERT: strip `..Default::default()` from any literal of a listed
/// struct and its row reds with both numbers.
#[test]
fn additive_wire_exhaustive_literals_only_ever_decrease_7689() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    afxdp_rs_files(&root, &mut files);

    // NON-VACUITY. Both floors, for the same reason as the sibling cell: a scan
    // that read nothing would report every count as 0, which is <= every
    // ceiling, and the ratchet would certify a tree it never opened.
    assert!(
        files.len() >= 200,
        "scan read only {} .rs files under src; the walk is broken and every \
         count below would pass as 0",
        files.len()
    );

    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let mut total = 0usize;
    for (name, ceiling) in ADDITIVE_WIRE_EXHAUSTIVE_CEILING {
        let actual = exhaustive_literal_count(&files, name);
        total += actual;
        if actual > *ceiling {
            regressions.push(format!(
                "{name}: {actual} exhaustive literals, ceiling {ceiling} (+{})",
                actual - ceiling
            ));
        } else if actual < *ceiling {
            improvements.push(format!("{name}: {actual}, ceiling {ceiling}"));
        }
    }

    // The second floor: the population must still be FOUND. If every struct
    // were renamed or moved, every count would be 0 and the ratchet would read
    // as a clean tree rather than a broken scan.
    assert!(
        total >= 80,
        "found only {total} exhaustive literals across the whole population \
         (expected ~124). The structs were renamed or the detection stopped \
         matching, so this ratchet is measuring nothing"
    );

    assert!(
        regressions.is_empty(),
        "{} struct(s) in the additive-wire population GAINED exhaustive \
         literals:\n  {}\n\nAn additive `#[serde(default)]` field is designed to \
         be invisible to an older peer, so a literal that breaks on one breaks \
         for no reason but its own enumeration. Add `..Default::default()` and \
         keep only the fields the test asserts on. #6846 paid this toll at 71 \
         literals in one change.",
        regressions.len(),
        regressions.join("\n  ")
    );

    // Improvements are not a failure, but the ceiling must be tightened or the
    // ratchet silently stops ratcheting.
    assert!(
        improvements.is_empty(),
        "{} struct(s) now have FEWER exhaustive literals than their ceiling. \
         That is the fix working — tighten the ceiling in \
         ADDITIVE_WIRE_EXHAUSTIVE_CEILING to the new numbers so the ground \
         gained is held:\n  {}",
        improvements.len(),
        improvements.join("\n  ")
    );
}
