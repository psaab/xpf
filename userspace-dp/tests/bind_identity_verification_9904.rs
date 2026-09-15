//! F-151 (#9904): post-bind identity re-verification must exist.
//!
//! STEP-0 repro: bind resolves ifindex->name with `if_indextoname` and then
//! creates the socket BY NAME, so a concurrent rename in the window can bind
//! another interface's queue, and nothing downstream re-checks. The rename
//! actor is the product itself (xpf renames interfaces at startup). This
//! cell REDs until `src/afxdp/bind.rs` performs a post-bind re-resolve
//! (name->ifindex) and fails the bind on planned-vs-observed mismatch.

use std::path::Path;

#[test]
fn bind_performs_post_bind_identity_verification_9904() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let bind_rs = Path::new(manifest_dir).join("src/afxdp/bind.rs");
    let text = std::fs::read_to_string(&bind_rs)
        .unwrap_or_else(|e| panic!("read {}: {e}", bind_rs.display()));
    // Call-site pin, not a mere substring: the check must be INVOKED on the
    // create path (in `try_open_bind` before the fill prime), not just
    // defined. A dead `fn verify_bind_identity` alone does not satisfy this.
    assert!(
        text.contains("verify_bind_identity(info.ifindex(), &bound_ifname)"),
        "F-151 (#9904) RED: src/afxdp/bind.rs does not invoke post-bind \
         identity verification on the socket-create path; a rename in the \
         ifindex->name->bind window can silently bind the wrong \
         interface's queue — see issue psaab/xpf#9904"
    );
}
