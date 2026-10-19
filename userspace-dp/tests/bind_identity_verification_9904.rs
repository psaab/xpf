//! F-151 (#9904) TRIPWIRE: post-bind identity verification call site.
//!
//! Explicitly a source tripwire, not a behavioral test: driving
//! `try_open_bind` to the mismatch needs a real AF_XDP bind (hardware),
//! so the invocation ordering is pinned here while the logic it invokes
//! is covered behaviorally — `verify_bind_identity_*` by
//! `bind_identity_9904_tests` (mock resolver: match/mismatch/unresolvable)
//! and the mismatch teardown by `bind_mismatch_teardown_9904_tests`
//! (hermetic fixtures, terminal planned-vs-observed error). What this pins
//! is that the check is INVOKED on the create path AFTER socket creation
//! and BEFORE the fill prime, with its `Err` arm failing the bind: a dead
//! `fn verify_bind_identity` alone, or a call placed after the prime,
//! does not satisfy this.

use std::path::Path;

/// #15255 (A84-02): strip `//` line comments so prose mentioning the
/// call/teardown cannot satisfy the tripwire. Block comments are not
/// stripped: the production window contains none, and a naive block
/// stripper would eat string literals containing `/*`.
fn strip_line_comments_15255(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// #15255 (A84-02): the fail-closed window — the code of the
/// `if let Err(mismatch) = verify_bind_identity(..)` statement starting
/// at `start`, bounded by brace balance. Returns None if the statement
/// never opens a block or never closes.
fn mismatch_window_15255(text: &str, start: usize) -> Option<&str> {
    let rest = text.get(start..)?;
    let open = rest.find('{')?;
    let mut depth = 0i32;
    for (i, ch) in rest.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 && i >= open {
                    return rest.get(..=i);
                }
            }
            _ => {}
        }
    }
    None
}

/// #15255 (A84-02): evaluate the tripwire against bind.rs source.
/// Returns Err(message) exactly when the call-site fail-closed
/// behaviour is not pinned: no invocation, invocation not guarded by
/// `if let Err`, no `return Err(fail_identity_mismatched_bind(` inside
/// that guard's window, or the call landing after the fill prime.
fn bind_identity_violation_15255(raw: &str) -> Result<(), String> {
    let text = strip_line_comments_15255(raw);
    let call = "verify_bind_identity(info.ifindex(), &bound_ifname)";
    let call_pos = text.find(call).ok_or_else(|| {
        "F-151 (#9904) RED: src/afxdp/bind.rs never invokes post-bind \
         identity verification on the socket-create path; a rename in \
         the ifindex->name->bind window can silently bind the wrong \
         interface's queue — see issue psaab/xpf#9904"
            .to_string()
    })?;
    let prime_pos = text
        .find("prime_fill_ring_offsets(&mut device")
        .ok_or_else(|| "tripwire stale: fill-prime call site moved; update this pin".to_string())?;
    if call_pos >= prime_pos {
        return Err(format!(
            "F-151 (#9904) RED: identity verification must precede the fill \
             prime (call at {call_pos}, prime at {prime_pos})"
        ));
    }
    // Anchor to the call window (#15255): the `if let Err` guard must
    // immediately govern THIS call, and its block must return the
    // teardown error. The old whole-file `contains` was satisfied by
    // the teardown's own definition and its cfg(test) caller even
    // after the call site was degraded to `let _ = ...;`.
    let guard = "if let Err(mismatch) =";
    let guard_pos = text[..call_pos].rfind(guard).ok_or_else(|| {
        "F-151 (#9904) RED: the verify_bind_identity call is not guarded by \
         `if let Err(mismatch) = ...`; a discarded result (`let _ =`) binds \
         the wrong interface silently"
            .to_string()
    })?;
    if !text[guard_pos + guard.len()..call_pos].trim().is_empty()
        && !text[guard_pos + guard.len()..call_pos]
            .trim()
            .starts_with("verify_bind_identity")
    {
        // The guard found above must belong to this call: only the call
        // expression itself may sit between `=` and the call substring.
        return Err(
            "F-151 (#9904) RED: the nearest `if let Err` guard does not govern \
             the verify_bind_identity call"
                .to_string(),
        );
    }
    let window = mismatch_window_15255(&text, guard_pos).ok_or_else(|| {
        "F-151 (#9904) RED: the `if let Err(mismatch)` block never closes; \
         cannot pin its fail-closed arm"
            .to_string()
    })?;
    if !window.contains("return Err(fail_identity_mismatched_bind(") {
        return Err(
            "F-151 (#9904) RED: mismatch arm must `return Err(fail_identity_mismatched_bind(...))` \
             inside the `if let Err` block following the verify call (ordered \
             device-first teardown fails the bind closed)"
                .to_string(),
        );
    }
    Ok(())
}

#[test]
fn bind_performs_post_bind_identity_verification_9904() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let bind_rs = Path::new(manifest_dir).join("src/afxdp/bind.rs");
    let text = std::fs::read_to_string(&bind_rs)
        .unwrap_or_else(|e| panic!("read {}: {e}", bind_rs.display()));
    if let Err(e) = bind_identity_violation_15255(&text) {
        panic!("{e}");
    }
}

/// #15255: the tripwire must be CAPABLE of failing. The pre-fix shape
/// (`text.contains("fail_identity_mismatched_bind(")` over the whole
/// file) stayed green when the call site's Err arm was removed,
/// because the definition and the cfg(test) caller satisfy the
/// substring. Each mutant below is that degradation, applied to the
/// REAL bind.rs, and each must be reported.
#[test]
fn bind_identity_tripwire_reds_on_discarded_result_15255() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let bind_rs = Path::new(manifest_dir).join("src/afxdp/bind.rs");
    let text = std::fs::read_to_string(&bind_rs)
        .unwrap_or_else(|e| panic!("read {}: {e}", bind_rs.display()));
    assert!(
        bind_identity_violation_15255(&text).is_ok(),
        "control: the real bind.rs must satisfy the tripwire"
    );

    // Mutant 1 (the #15255 acceptance mutant): discard the result.
    // The teardown fn and its test caller remain in the file, so the
    // old whole-file substring check stayed green on exactly this.
    let discarded = text.replacen(
        "if let Err(mismatch) = verify_bind_identity(info.ifindex(), &bound_ifname) {",
        "let _ = verify_bind_identity(info.ifindex(), &bound_ifname); if false {",
        1,
    );
    assert_ne!(discarded, text, "mutant 1 anchor must exist in bind.rs");
    assert!(
        bind_identity_violation_15255(&discarded).is_err(),
        "RED expected: `let _ = verify_bind_identity(..)` must fail the tripwire"
    );

    // Mutant 2: keep the guard, drop the fail-closed return.
    let swallowed = text.replacen(
        "return Err(fail_identity_mismatched_bind(",
        "let _ = fail_identity_mismatched_bind(",
        1,
    );
    assert_ne!(swallowed, text, "mutant 2 anchor must exist in bind.rs");
    assert!(
        bind_identity_violation_15255(&swallowed).is_err(),
        "RED expected: a mismatch arm that does not return the teardown error must fail"
    );

    // Mutant 3: the invocation survives only in a comment.
    let commented = text.replacen(
        "if let Err(mismatch) = verify_bind_identity(info.ifindex(), &bound_ifname) {",
        "// if let Err(mismatch) = verify_bind_identity(info.ifindex(), &bound_ifname) {",
        1,
    );
    assert_ne!(commented, text, "mutant 3 anchor must exist in bind.rs");
    assert!(
        bind_identity_violation_15255(&commented).is_err(),
        "RED expected: a commented-out invocation must fail the tripwire"
    );
}
