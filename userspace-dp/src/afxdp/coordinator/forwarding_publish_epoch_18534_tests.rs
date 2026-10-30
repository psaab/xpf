//! #18534: every forwarding snapshot a worker can adopt carries a distinct,
//! nonzero `ForwardingState::publish_epoch`, and a validation-only republish
//! (same forwarding `Arc`) keeps it. The flow cache memoises the
//! destination-owner RG per epoch, so a publish that reused an epoch for
//! different tables would let a stale memo stand; an unstamped (0) publish
//! would silently turn the memo off in production.

use super::*;

#[test]
fn each_forwarding_publish_carries_a_fresh_nonzero_epoch_18534() {
    let mut coord = Coordinator::new();
    coord.publish_runtime_view();
    let first = coord.ha.runtime.load().forwarding().publish_epoch;
    assert_ne!(first, 0, "a published forwarding snapshot must be stamped");
    coord.publish_runtime_view();
    let second = coord.ha.runtime.load().forwarding().publish_epoch;
    assert!(second > first, "a new forwarding Arc needs a new epoch: {first} then {second}");
    // Validation-only republish: same tables, same Arc, same epoch.
    let published = coord.ha.runtime.load().forwarding().clone();
    coord.republish_runtime_validation();
    let view = coord.ha.runtime.load();
    assert!(Arc::ptr_eq(view.forwarding(), &published), "premise: the forwarding Arc is reused");
    assert_eq!(view.forwarding().publish_epoch, second);
}
