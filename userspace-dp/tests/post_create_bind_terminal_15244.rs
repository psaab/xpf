//! #15244 (A61-03) TRIPWIRE: post-create bind failures are terminal
//! for the flag/strategy ladder in `open_binding_worker_rings`.
//!
//! Explicitly a source tripwire, not a behavioural test: forcing a
//! real identity mismatch after a successful `xsk_socket__create`
//! needs a bound AF_XDP socket on hardware, so the wiring is pinned
//! here while the decisions it invokes are covered behaviourally —
//! `is_post_create_bind_error` / `post_create_bind_error` and the
//! tagged mismatch teardown by `bind_post_create_terminal_15244_tests`
//! in `src/afxdp/bind.rs`. What this pins is that the mechanisms are
//! WIRED on the production path: every post-create arm of
//! `try_open_bind` (identity mismatch, fill-prime failure,
//! non-zerocopy) returns a tagged error, and the ladder checks the
//! tag BEFORE overwriting `last_err`. Removing the tag, an arm, or
//! the ladder check — so a forced identity mismatch again surfaces
//! as the follow-on create's "Bad address" — does not satisfy this.
//!
//! #16437: the tag check is anchored per arm, inside `try_open_bind`'s
//! body with comments stripped: the fill-prime `Err` window and the
//! `requires_zerocopy()` window must each carry
//! `return Err(post_create_bind_error(`. The pre-#16437 shape counted
//! `post_create_bind_error(` file-wide against a floor of 3 — a floor
//! met by the tag definition, the `is_` predicate and the ladder gate
//! alone, so un-tagging either inline arm kept the tripwire green.

use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// #16437: strip `//` line comments so prose mentioning the tag or
/// the arms cannot satisfy the anchored window checks (the #15255
/// precedent in bind_identity_verification_9904.rs). Safe here:
/// bind.rs's `//` occurrences are comments only — no URL or
/// `//`-in-string literals — and any future `//` string literal
/// would trip the staleness anchors below rather than pass silently.
fn strip_line_comments_16437(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// #16437: slice from `start` through its brace-balanced window: the
/// first `{` at or after `start`, to the `}` that closes it. Returns
/// None if the window never opens or never closes. Brace counting
/// also counts braces inside string literals (the `format!` arms
/// carry none extra; a stray would unbalance and read as stale).
fn brace_window_16437(text: &str, start: usize) -> Option<&str> {
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

/// #16437: evaluate the tripwire against bind.rs source. Returns
/// Err(message) exactly when the production wiring is not pinned:
/// ladder-gate ordering, the identity-mismatch cause text, or a
/// tagged `return Err(post_create_bind_error(` inside either inline
/// post-create arm of `try_open_bind` (fill-prime `Err` window,
/// `requires_zerocopy()` window). The tag definition and the `is_`
/// predicate live outside `try_open_bind` and cannot satisfy these
/// per-arm window checks, and the definition's
/// `pub(super) fn post_create_bind_error(` never matches the
/// `return Err(post_create_bind_error(` needle.
fn post_create_violation_16437(raw: &str) -> Result<(), String> {
    let text = strip_line_comments_16437(raw);

    // The ladder must consult the tag.
    let gate = "is_post_create_bind_error(err.as_ref())";
    let gate_pos = text.find(gate).ok_or_else(|| {
        "#15244 RED: open_binding_worker_rings never consults \
         is_post_create_bind_error; a post-create failure (identity \
         mismatch / prime / non-zerocopy) falls through to the next \
         candidate on a UMEM libxdp already unmapped, and last_err \
         becomes the follow-on create's Bad address instead of the \
         true cause — see psaab/xpf#15244"
            .to_string()
    })?;

    // The terminal return must precede the last_err overwrite, so the
    // true cause is what surfaces.
    let overwrite_pos = text
        .find("last_err = Some(err);")
        .ok_or("tripwire stale: last_err overwrite moved; update this pin".to_string())?;
    if gate_pos >= overwrite_pos {
        return Err(format!(
            "#15244 RED: the post-create gate must precede the last_err \
             overwrite (gate at {gate_pos}, overwrite at {overwrite_pos}); \
             otherwise the true cause is replaced before it can surface"
        ));
    }
    if !text[gate_pos..overwrite_pos].contains("return Err(err)") {
        return Err(
            "#15244 RED: the post-create gate must return the tagged error \
             immediately, not log-and-continue the ladder"
                .to_string(),
        );
    }

    if !text.contains("bind identity mismatch: {mismatch}") {
        return Err(
            "#15244 RED: the identity-mismatch cause text must be preserved \
             verbatim so a forced mismatch surfaces as bind identity mismatch"
                .to_string(),
        );
    }

    // Anchor to try_open_bind's body only.
    let body_start = text.find("fn try_open_bind(").ok_or_else(|| {
        "tripwire stale (#16437): fn try_open_bind( not found; update this pin".to_string()
    })?;
    let body = brace_window_16437(&text, body_start).ok_or_else(|| {
        "tripwire stale (#16437): try_open_bind body never closes; update this pin".to_string()
    })?;

    let needle = "return Err(post_create_bind_error(";

    // Fill-prime arm: the `Err(err) =>` window inside the
    // prime_fill_ring_offsets match must return the tagged error.
    let prime_pos = body
        .find("prime_fill_ring_offsets(&mut device, offsets)")
        .ok_or_else(|| {
            "tripwire stale (#16437): fill-prime call site moved; update this pin".to_string()
        })?;
    let err_arm_pos = body[prime_pos..]
        .find("Err(err) =>")
        .map(|i| prime_pos + i)
        .ok_or_else(|| {
            "tripwire stale (#16437): fill-prime Err arm moved; update this pin".to_string()
        })?;
    let prime_window = brace_window_16437(body, err_arm_pos).ok_or_else(|| {
        "tripwire stale (#16437): fill-prime Err window never closes; update this pin".to_string()
    })?;
    if !prime_window.contains(needle) {
        return Err("#15244/#16437 RED: the fill-prime post-create arm in \
             try_open_bind must `return Err(post_create_bind_error(...))`; \
             an untagged arm re-enters the ladder on an unmapped UMEM and \
             last_err becomes the follow-on create's Bad address"
            .to_string());
    }

    // Non-zerocopy arm: the requires_zerocopy() window must return
    // the tagged error.
    let zc_pos = body.find("requires_zerocopy()").ok_or_else(|| {
        "tripwire stale (#16437): requires_zerocopy() block moved; update this pin".to_string()
    })?;
    let zc_window = brace_window_16437(body, zc_pos).ok_or_else(|| {
        "tripwire stale (#16437): requires_zerocopy() window never closes; update this pin"
            .to_string()
    })?;
    if !zc_window.contains(needle) {
        return Err("#15244/#16437 RED: the non-zerocopy post-create arm in \
             try_open_bind must `return Err(post_create_bind_error(...))`; \
             an untagged arm re-enters the ladder on an unmapped UMEM and \
             last_err becomes the follow-on create's Bad address"
            .to_string());
    }

    // Identity-mismatch arm: try_open_bind must keep returning the
    // tagged teardown helper's result. `fail_identity_mismatched_bind`
    // is itself a plain `fn` whose definition never matches the
    // `return Err(fail_identity_mismatched_bind(` needle.
    if !body.contains("return Err(fail_identity_mismatched_bind(") {
        return Err(
            "#15244 RED: try_open_bind must `return Err(fail_identity_mismatched_bind(...))` \
             so the identity-mismatch arm stays post-create tagged"
                .to_string(),
        );
    }
    Ok(())
}

#[test]
fn post_create_bind_failures_exit_the_ladder_with_true_cause_15244() {
    let bind_rs = read("src/afxdp/bind.rs");
    if let Err(e) = post_create_violation_16437(&bind_rs) {
        panic!("{e}");
    }
}

/// #16437: the tripwire must be CAPABLE of failing per arm. The
/// pre-fix shape (`matches("post_create_bind_error(").count() >= 3`
/// over the whole file) stayed green when either inline arm lost its
/// tag, because the definition, the `is_` predicate and the ladder
/// gate alone meet the floor. Each mutant below is that degradation,
/// applied to the REAL bind.rs, and each must be reported; the
/// comment-only pair also proves comment stripping.
#[test]
fn post_create_tripwire_reds_on_untagged_inline_arms_16437() {
    let bind_rs = read("src/afxdp/bind.rs");
    assert!(
        post_create_violation_16437(&bind_rs).is_ok(),
        "control: the real bind.rs must satisfy the tripwire"
    );

    // Mutant 1 (#16437 acceptance M1): untag the fill-prime arm.
    let untagged_prime = bind_rs.replacen(
        r#"return Err(post_create_bind_error(format!(
                                "prime fill ring after socket create: {err}""#,
        r#"return Err(format!(
                                "prime fill ring after socket create: {err}"#,
        1,
    );
    assert_ne!(
        untagged_prime, bind_rs,
        "mutant 1 anchor must exist in bind.rs"
    );
    assert!(
        post_create_violation_16437(&untagged_prime).is_err(),
        "RED expected: an untagged fill-prime arm must fail the tripwire"
    );

    // Mutant 2 (#16437 acceptance M2): untag the zero-copy arm.
    let untagged_zc = bind_rs.replacen(
        r#"return Err(post_create_bind_error(format!(
                        "{} bind(fd={}) did not report XDP_OPTIONS_ZEROCOPY after bind""#,
        r#"return Err(format!(
                        "{} bind(fd={}) did not report XDP_OPTIONS_ZEROCOPY after bind""#,
        1,
    );
    assert_ne!(
        untagged_zc, bind_rs,
        "mutant 2 anchor must exist in bind.rs"
    );
    assert!(
        post_create_violation_16437(&untagged_zc).is_err(),
        "RED expected: an untagged non-zerocopy arm must fail the tripwire"
    );

    // Mutant 3: only a comment inside the fill-prime arm mentions the
    // tag; comment stripping must keep the tripwire red.
    let commented_prime = bind_rs.replacen(
        r#"return Err(post_create_bind_error(format!(
                                "prime fill ring after socket create: {err}""#,
        r#"return Err(format!(
                                "prime fill ring after socket create: {err}")); // post_create_bind_error("#,
        1,
    );
    assert_ne!(
        commented_prime, bind_rs,
        "mutant 3 anchor must exist in bind.rs"
    );
    assert!(
        post_create_violation_16437(&commented_prime).is_err(),
        "RED expected: a comment mentioning the tag must not rescue an untagged fill-prime arm"
    );

    // Mutant 4: the same for the zero-copy arm.
    let commented_zc = bind_rs.replacen(
        r#"return Err(post_create_bind_error(format!(
                        "{} bind(fd={}) did not report XDP_OPTIONS_ZEROCOPY after bind""#,
        r#"return Err(format!(
                        "{} bind(fd={}) did not report XDP_OPTIONS_ZEROCOPY after bind")); // post_create_bind_error("#,
        1,
    );
    assert_ne!(
        commented_zc, bind_rs,
        "mutant 4 anchor must exist in bind.rs"
    );
    assert!(
        post_create_violation_16437(&commented_zc).is_err(),
        "RED expected: a comment mentioning the tag must not rescue an untagged non-zerocopy arm"
    );
}
