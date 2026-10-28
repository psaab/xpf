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
// The population below is therefore: a `Default` impl, at least one
// `#[serde(default)]` field, and >= 8 fields — tractable, and every one of
// them is a type designed to grow.
//
// #17147: that population used to be HAND-KEPT in the table below, and
// nothing checked the table against its own rule. `ControlResponse`
// (30 fields) and `ControlRequest` qualified for years while absent, and
// the dispatcher's one exhaustive 30-field all-default literal in
// `server/handlers/mod.rs` took a forced edit for every new field. The
// population is now DERIVED mechanically by
// `qualifying_additive_wire_structs` (scan of `src/protocol/*.rs` for the
// stated rule), `CoSSchedulerSnapshot` is folded into the table at its
// pinned 0 (the dedicated cell above keeps its literal-count floor), and
// the ratchet asserts every qualifying struct has a row — a qualifying
// struct without one FAILS instead of escaping silently. The scan is
// scoped to `src/protocol` because that is where the wire types live
// (`protocol/mod.rs`: "All types are pub(crate)"); a wire struct defined
// elsewhere is out of the stated population by construction, the same
// deliberate scoping as the wire/non-wire split above.
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
    // #17147: ceilings for the rows the mechanical census added (every
    // previously-absent qualifier, plus CoSSchedulerSnapshot folded in
    // from its dedicated cell), each at the count the ratchet measured on
    // this tree; ControlResponse is 0 because its one exhaustive literal
    // (the dispatcher) gained the update tail in the same change.
    ("BindingCountersSnapshot", 0),
    ("BindingStatus", 0),
    ("CoSInterfaceStatus", 0),
    ("CoSQueueStatus", 0),
    ("CoSSchedulerSnapshot", 0),
    ("ConfigSnapshot", 0),
    ("ControlRequest", 0),
    ("ControlResponse", 0),
    ("DestinationNATRuleSnapshot", 3),
    ("DisplayLeaseWire", 2),
    ("ExceptionStatus", 1),
    ("FabricSnapshot", 7),
    ("FibRouteWire", 3),
    ("FirewallTermSnapshot", 12),
    ("FlowSnapshot", 0),
    ("FlowWorkerStatus", 1),
    ("IdleLeaseWire", 4),
    ("InjectPacketRequest", 1),
    ("InterfaceSnapshot", 0),
    ("IpsecPMechTunnelRowSnapshot", 7),
    ("MapPins", 0),
    // #16267: tightened 3 -> 0. Already 0 on master (the #15678/#15930-
    // #16049 scope fields made every literal carry a tail); the stale
    // ceiling was holding room for literals that no longer exist.
    ("NAT64RuleSnapshot", 0),
    ("NeighborSnapshot", 26),
    ("PacketResolution", 1),
    ("PolicyRenameAncestry", 15),
    ("PolicyRuleSnapshot", 0),
    ("PolicySessionRebind", 4),
    ("ProcessStatus", 1),
    ("RouteSnapshot", 94),
    ("S5ReinjectProvenance", 3),
    ("S5ReinjectStatus", 0),
    ("ScreenProfileSnapshot", 0),
    ("SessionCounterRowWire", 3),
    ("SessionDeltaInfo", 1),
    ("SessionPolicyMatch", 3),
    ("SessionPolicyTuple", 4),
    ("SessionSyncRequest", 0),
    ("SlowPathStatus", 1),
    ("SourceNATRuleSnapshot", 0),
    ("SourceNatPoolStatus", 1),
    // #16267: tightened 34/2 -> 0. Every exhaustive literal of both
    // structs gained a `..Default::default()` tail (only default-valued
    // fields were dropped), so no exhaustive literal remains; the
    // ceilings hold that ground instead of decaying into permission.
    ("StaticNATRuleSnapshot", 0),
    ("ThreeColorPolicerSnapshot", 0),
    ("ThreeColorPolicerStatus", 1),
    ("TunnelEndpointSnapshot", 0),
    ("WgTunnelStatus", 2),
    ("WorkerRuntimeStatus", 1),
    ("ZoneSnapshot", 0),
];

/// #17147: one struct definition found by the mechanical population census.
#[derive(Debug, PartialEq, Eq)]
struct AdditiveWireStruct {
    name: String,
    field_count: usize,
    has_default: bool,
    has_serde_default_field: bool,
}

/// The census rule, applied to one struct: a `Default` impl, at least one
/// `#[serde(default)]` field, and >= 8 fields.
fn qualifies_as_additive_wire(s: &AdditiveWireStruct) -> bool {
    s.has_default && s.has_serde_default_field && s.field_count >= 8
}

/// Brace-match the block opened at `open` (index of `{` in `src`); returns
/// the index just past the matching `}`.
fn matching_brace(src: &str, open: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Count NAMED fields in a struct body: depth-0 comma segments carrying a
/// `name:` head. Angle depth is tracked so the comma in `Vec<A, B>` does
/// not split a field, and segments holding only attributes do not count.
fn named_field_count(body: &str) -> usize {
    let mut segments = Vec::new();
    let mut cur = String::new();
    let (mut depth, mut angle) = (0i32, 0i32);
    for ch in body.chars() {
        match ch {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth -= 1,
            '<' => angle += 1,
            '>' => angle -= 1,
            _ => {}
        }
        if ch == ',' && depth == 0 && angle == 0 {
            segments.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    segments.push(cur);
    segments
        .iter()
        .filter(|seg| {
            let mut text = seg.as_str();
            loop {
                let t = text.trim_start();
                let Some(rest) = t.strip_prefix("#[") else {
                    break;
                };
                match rest.find(']') {
                    Some(at) => text = &rest[at + 1..],
                    None => return false,
                }
            }
            let text = text.trim_start();
            let text = text
                .strip_prefix("pub(crate)")
                .or_else(|| text.strip_prefix("pub(super)"))
                .or_else(|| text.strip_prefix("pub"))
                .unwrap_or(text)
                .trim_start();
            let Some(colon) = text.find(':') else {
                return false;
            };
            let head = text[..colon].trim();
            !head.is_empty()
                && head.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
                && head
                    .chars()
                    .next()
                    .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        })
        .count()
}

/// Parse every named-field struct definition in one source file (already
/// blanked of comments/strings) into census rows. A struct counts as
/// having `Default` when its attribute block derives it, or the file
/// carries a manual `impl Default for Name`.
fn additive_wire_structs_in_source(src: &str) -> Vec<AdditiveWireStruct> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(hit) = src[from..].find("struct ") {
        let kw = from + hit;
        if kw > 0 && (bytes[kw - 1] == b'_' || bytes[kw - 1].is_ascii_alphanumeric()) {
            from = kw + 1;
            continue;
        }
        let name_start = kw + "struct ".len();
        let mut name_end = name_start;
        while name_end < bytes.len()
            && (bytes[name_end] == b'_' || bytes[name_end].is_ascii_alphanumeric())
        {
            name_end += 1;
        }
        if name_end == name_start {
            from = kw + 1;
            continue;
        }
        let name = &src[name_start..name_end];
        let rest = &src[name_end..];
        let mut open = None;
        for (off, ch) in rest.char_indices() {
            match ch {
                '{' => {
                    open = Some(name_end + off);
                    break;
                }
                '(' | ';' => break,
                _ => {}
            }
        }
        let Some(open) = open else {
            from = name_end;
            continue;
        };
        let Some(end) = matching_brace(src, open) else {
            from = name_end;
            continue;
        };
        // Walk backwards from the keyword over the contiguous attribute
        // groups (and any visibility) that attach to this struct. All
        // indices stay in the ORIGINAL string: `pre_end` is the byte index
        // where the not-yet-consumed prefix ends.
        let mut block_start = kw;
        loop {
            let mut pre_end = block_start;
            while pre_end > 0 && bytes[pre_end - 1].is_ascii_whitespace() {
                pre_end -= 1;
            }
            for vis in ["pub(crate)", "pub(super)", "pub"] {
                if pre_end >= vis.len() && &src[pre_end - vis.len()..pre_end] == vis {
                    pre_end -= vis.len();
                    while pre_end > 0 && bytes[pre_end - 1].is_ascii_whitespace() {
                        pre_end -= 1;
                    }
                    break;
                }
            }
            if pre_end == 0 || bytes[pre_end - 1] != b']' {
                block_start = pre_end;
                break;
            }
            // Walk back over the balanced `#[...]` group ending at pre_end.
            let mut depth = 0i32;
            let mut i = pre_end;
            let mut group_start = None;
            while i > 0 {
                i -= 1;
                match bytes[i] {
                    b']' => depth += 1,
                    b'[' => {
                        depth -= 1;
                        if depth == 0 {
                            group_start = Some(i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(gs) = group_start else {
                block_start = pre_end;
                break;
            };
            if gs == 0 || bytes[gs - 1] != b'#' {
                block_start = pre_end;
                break;
            }
            block_start = gs - 1;
        }
        let attrs = &src[block_start..kw];
        let derives_default = attrs.match_indices("#[derive(").any(|(at, _)| {
            let inner_start = at + "#[derive(".len();
            match attrs[inner_start..].find(')') {
                Some(close) => attrs[inner_start..inner_start + close]
                    .split(',')
                    .any(|part| part.trim() == "Default"),
                None => false,
            }
        });
        let manual_default = src.contains(&format!("Default for {name}"))
            || src.contains(&format!("Default for crate::protocol::{name}"));
        let body = &src[open + 1..end - 1];
        out.push(AdditiveWireStruct {
            name: name.to_string(),
            field_count: named_field_count(body),
            has_default: derives_default || manual_default,
            has_serde_default_field: body.match_indices("#[serde(").any(|(at, _)| {
                let inner_start = at + "#[serde(".len();
                let mut depth = 1i32;
                let mut i = inner_start;
                let b = body.as_bytes();
                while i < b.len() && depth > 0 {
                    match b[i] {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                body[inner_start..i.saturating_sub(1).max(inner_start)]
                    .split(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
                    .any(|word| word == "default")
            }),
        });
        from = end;
    }
    out
}

/// Derive the additive-wire population mechanically: every struct in
/// `src/protocol/*.rs` meeting the stated rule (Default impl, at least
/// one `#[serde(default)]` field, >= 8 fields), sorted by name.
/// Known limitation, stated plainly: generic parameters are not
/// specially parsed — a simple `struct Wire<T> {` IS counted (the
/// search for the opening brace walks over `<T>`), but a generic
/// parameter containing `(` (for example `struct Wire<F: Fn(u8)> {`)
/// trips the tuple/unit early exit and is skipped. No qualifying wire
/// struct carries such parameters today. Renamed re-exports of a
/// qualifying struct under a second name are counted under their
/// definition name only. Both are outside the stated rule as written;
/// the census fixture and the population-size floor keep the
/// derivation itself honest.
fn qualifying_additive_wire_structs(
    protocol_files: &[std::path::PathBuf],
) -> Vec<AdditiveWireStruct> {
    let mut out = Vec::new();
    for path in protocol_files {
        let raw = std::fs::read_to_string(path).expect("read protocol source");
        let src = blank_comments_and_strings(&raw);
        out.extend(additive_wire_structs_in_source(&src));
    }
    out.retain(qualifies_as_additive_wire);
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Both-directions fixture for the mechanical census (#17147), mirroring
/// the #8537 fixture's discipline: a parser that always qualifies (or
/// never does) would pass a one-sided table, so rows pin each rule leg
/// independently — Default derivation, serde-default presence, the
/// >= 8 field floor, named-field-only counting, and manual Default.
#[test]
fn additive_wire_census_applies_the_stated_rule_17147() {
    let cases: &[(&str, &[&str], &str)] = &[
        (
            "#[derive(Default)] struct Wire { #[serde(default)] a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8 }",
            &["Wire"],
            "8 fields, derived Default, one serde-default field: qualifies",
        ),
        (
            "#[derive(Default)] struct Wire { #[serde(default)] a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8 }",
            &[],
            "7 fields is below the >= 8 floor",
        ),
        (
            "#[derive(Clone)] struct Wire { #[serde(default)] a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8 }",
            &[],
            "no Default impl: the exhaustive-literal tax cannot be paid with ..Default::default()",
        ),
        (
            "#[derive(Default)] struct Wire { a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8 }",
            &[],
            "no serde-default field: not an additive wire type",
        ),
        (
            "#[derive(Default)] struct Wire { #[serde(rename = \"x\")] a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: Vec<u8, u8> }",
            &[],
            "rename alone is not default, and the comma inside Vec<A, B> must not mint a ninth field",
        ),
        (
            "#[derive(Default)] struct Wire { #[serde(default)] a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: Vec<u8, u8> }",
            &[],
            "7 fields with a Vec<A, B> field is below the floor: the angle comma must not mint an eighth field (isolates the angle leg — serde-default is present and Default is derived, unlike the rename case above)",
        ),
        (
            "struct Wire { #[serde(default)] a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8 } impl Default for Wire { fn default() -> Self { todo!() } }",
            &["Wire"],
            "a manual Default impl qualifies like a derived one",
        ),
        (
            "#[derive(Default)] struct Wire(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8, pub u8, #[serde(default)] pub u8);",
            &[],
            "tuple structs have no named fields to enumerate",
        ),
    ];
    for (src, want, why) in cases {
        let blanked = blank_comments_and_strings(src);
        let got: Vec<String> = additive_wire_structs_in_source(&blanked)
            .into_iter()
            .filter(qualifies_as_additive_wire)
            .map(|s| s.name)
            .collect();
        assert_eq!(
            got, *want,
            "census({src:?}) = {got:?}, want {want:?} — {why}"
        );
    }
    let blanked = blank_comments_and_strings(
        "#[derive(Default)] struct Wire { #[serde(default)] a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8 }",
    );
    assert_eq!(
        additive_wire_structs_in_source(&blanked)
            .into_iter()
            .filter(qualifies_as_additive_wire)
            .count(),
        1,
        "the census never qualifies anything — it cannot be measuring the rule"
    );
}

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
/// literals, and (#17147) every struct the mechanical census derives must
/// have a ceiling row.
///
/// FAIL-ON-REVERT: strip `..Default::default()` from any literal of a listed
/// struct and its row reds with both numbers; delete a qualifying struct's
/// ceiling row (or add a qualifying struct without one) and the population
/// assertion reds naming it.
#[test]
fn additive_wire_exhaustive_literals_only_ever_decrease_7689() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    afxdp_rs_files(&root, &mut files);

    // #17147 POPULATION COMPLETENESS. Derive the population from the stated
    // rule (scan of src/protocol/*.rs) and assert it equals the ceiling
    // table's row set — a qualifying struct without a row FAILS here instead
    // of escaping the ratchet until someone remembers to list it, and a
    // stale row for a struct that no longer qualifies fails the other way.
    // This guard file is excluded: its fixtures name qualifying shapes.
    let protocol_dir = root.join("protocol");
    let mut protocol_files = Vec::new();
    afxdp_rs_files(&protocol_dir, &mut protocol_files);
    protocol_files.retain(|f| {
        f.file_name()
            .is_some_and(|n| n != "cos_literal_guard_7689.rs")
    });
    assert!(
        protocol_files.len() >= 10,
        "census read only {} protocol files; the population derivation is          broken and the completeness assertion below would compare empties",
        protocol_files.len()
    );
    let derived = qualifying_additive_wire_structs(&protocol_files);
    assert!(
        derived.len() >= 40,
        "census derived only {} qualifying structs (expected 47 on this          tree); the parser stopped matching, so completeness would certify          a population it never derived",
        derived.len()
    );
    let derived_names: Vec<&str> = derived.iter().map(|s| s.name.as_str()).collect();
    let table_names: Vec<&str> = ADDITIVE_WIRE_EXHAUSTIVE_CEILING
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let missing: Vec<&str> = derived_names
        .iter()
        .copied()
        .filter(|n| !table_names.contains(n))
        .collect();
    let stale: Vec<&str> = table_names
        .iter()
        .copied()
        .filter(|n| !derived_names.contains(n))
        .collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "additive-wire ceiling table does not match the mechanically          derived population:\n  qualifying structs with NO ceiling row          (add one at the measured count): {missing:?}\n  ceiling rows for          structs that no longer qualify (remove the row): {stale:?}"
    );

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
    // as a clean tree rather than a broken scan. #16267: lowered 80 -> 25.
    // #17147: the census widened the population from 22 hand-kept rows to
    // the full derived set, so the floor is re-measured in this change and
    // recorded in docs/log/17147.md; it still reds if the scan or the
    // population disappears.
    assert!(
        total >= 25,
        "found only {total} exhaustive literals across the whole population. \
         The structs were renamed or the detection stopped matching, so \
         this ratchet is measuring nothing"
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
