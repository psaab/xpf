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

use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn post_create_bind_failures_exit_the_ladder_with_true_cause_15244() {
    let bind_rs = read("src/afxdp/bind.rs");

    // The ladder must consult the tag.
    let gate = "is_post_create_bind_error(err.as_ref())";
    let gate_pos = bind_rs.find(gate).unwrap_or_else(|| {
        panic!(
            "#15244 RED: open_binding_worker_rings never consults \
             is_post_create_bind_error; a post-create failure (identity \
             mismatch / prime / non-zerocopy) falls through to the next \
             candidate on a UMEM libxdp already unmapped, and last_err \
             becomes the follow-on create's Bad address instead of the \
             true cause — see psaab/xpf#15244"
        )
    });

    // The terminal return must precede the last_err overwrite, so the
    // true cause is what surfaces.
    let overwrite_pos = bind_rs
        .find("last_err = Some(err);")
        .expect("tripwire stale: last_err overwrite moved; update this pin");
    assert!(
        gate_pos < overwrite_pos,
        "#15244 RED: the post-create gate must precede the last_err \
         overwrite (gate at {gate_pos}, overwrite at {overwrite_pos}); \
         otherwise the true cause is replaced before it can surface"
    );
    assert!(
        bind_rs[gate_pos..overwrite_pos].contains("return Err(err)"),
        "#15244 RED: the post-create gate must return the tagged error \
         immediately, not log-and-continue the ladder"
    );

    // All three post-create arms must be tagged: the identity
    // mismatch teardown, the fill-prime failure, and the
    // non-zerocopy rejection. (The mismatch helper's body carries
    // the first; the other two are inline in try_open_bind.)
    let tagged = bind_rs.matches("post_create_bind_error(").count();
    assert!(
        tagged >= 3,
        "#15244 RED: expected at least 3 post_create_bind_error tag \
         sites (identity mismatch, fill prime, non-zerocopy), found {tagged}; \
         an untagged post-create arm re-enters the ladder on an unmapped UMEM"
    );
    assert!(
        bind_rs.contains("bind identity mismatch: {mismatch}"),
        "#15244 RED: the identity-mismatch cause text must be preserved \
         verbatim so a forced mismatch surfaces as bind identity mismatch"
    );
}
