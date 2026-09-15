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

#[test]
fn bind_performs_post_bind_identity_verification_9904() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let bind_rs = Path::new(manifest_dir).join("src/afxdp/bind.rs");
    let text = std::fs::read_to_string(&bind_rs)
        .unwrap_or_else(|e| panic!("read {}: {e}", bind_rs.display()));
    let call = "verify_bind_identity(info.ifindex(), &bound_ifname)";
    let call_pos = text.find(call).unwrap_or_else(|| {
        panic!(
            "F-151 (#9904) RED: src/afxdp/bind.rs never invokes post-bind \
             identity verification on the socket-create path; a rename in \
             the ifindex->name->bind window can silently bind the wrong \
             interface's queue — see issue psaab/xpf#9904"
        )
    });
    // Ordering: the check must run after socket creation and before the
    // fill prime, so a mismatch fails before any frame is primed.
    let prime_pos = text.find("prime_fill_ring_offsets(&mut device").unwrap_or_else(|| {
        panic!("tripwire stale: fill-prime call site moved; update this pin")
    });
    assert!(
        call_pos < prime_pos,
        "F-151 (#9904) RED: identity verification must precede the fill \
         prime (call at {call_pos}, prime at {prime_pos})"
    );
    // Result handling: the mismatch arm must route through the ordered
    // teardown that fails the bind closed.
    assert!(
        text.contains("fail_identity_mismatched_bind("),
        "F-151 (#9904) RED: mismatch arm must tear down via \
         `fail_identity_mismatched_bind` (ordered device-first drops)"
    );
}
