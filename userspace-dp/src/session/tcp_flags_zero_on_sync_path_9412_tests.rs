//! #9412 — pin that the production HA import path carries NO TCP flags, so the
//! comment describing them cannot drift back into implying a re-derivation.
//!
//! WHY A GUARD AND NOT PROSE. `session/install.rs` used to document the synced
//! `tcp_flags` as "the install-time flags (the opening SYN for a SYN-created
//! flow)", which reads as though real flags arrive and #3152 declines to trust
//! them. They do not arrive: `server/helpers/session_sync.rs` hardcodes
//! `tcp_flags: 0` on the only production constructor for a synced entry. An
//! external review read that comment and concluded the import "re-derives
//! close-state from the carried tcp_flags" — a mechanism that does not exist —
//! and prose is not falsifiable, so nothing could have caught that.
//!
//! WHAT IT ASSERTS. The imported entry's `tcp_flags` stay a hard zero, so the
//! close bits install.rs derives FROM `tcp_flags` are all false. That was #9412's
//! mechanism. #9412 is now implemented WITHOUT touching this: close state rides
//! its own wire field, `SessionSyncRequest.tcp_close_class`, and
//! `upsert_synced_with_origin` applies it (see
//! `close_state_sync_9412_acceptance_tests.rs`). Adding a field instead of
//! redefining one is the decision this cell now defends. If `tcp_flags` ever
//! starts carrying real flags on this path, close state would have two carriers
//! that can disagree, and this cell fails, naming itself.
//!
//! It drives the REAL constructor, `build_synced_session_entry`, rather than
//! asserting a literal of my own. A cell that compared a local `const
//! PRODUCTION_SYNC_TCP_FLAGS: u8 = 0` against the derivation would be a statement
//! about my own constant: changing `session_sync.rs` to carry real flags would
//! leave it green, which is exactly the drift it exists to catch.

use crate::server::helpers::build_synced_session_entry;
use crate::session::{has_fin, has_rst, is_closing};
use crate::test_zone_ids::*;
use crate::SessionSyncRequest;

/// A minimal TCP peer-sync record. It states no close class, so this cell sees
/// only the `tcp_flags` carrier. #9412's own carrier is `tcp_close_class`.
fn tcp_sync_req() -> SessionSyncRequest {
    SessionSyncRequest {
        operation: "upsert".to_string(),
        addr_family: libc::AF_INET as u8,
        protocol: crate::ip_proto::PROTO_TCP,
        src_ip: "10.0.61.102".to_string(),
        dst_ip: "172.16.80.200".to_string(),
        src_port: 54321,
        dst_port: 5201,
        ingress_zone_id: TEST_TRUST_ZONE_ID,
        egress_zone_id: TEST_UNTRUST_ZONE_ID,
        ..SessionSyncRequest::default()
    }
}

#[test]
fn production_sync_import_carries_no_tcp_flags_9412() {
    let zones = rustc_hash::FxHashMap::default();
    let entry = build_synced_session_entry(&tcp_sync_req(), &zones, 0)
        .expect("FIXTURE FAILED: a plain TCP sync record must import");

    assert_eq!(
        entry.tcp_flags, 0,
        "#9412: the production sync-import constructor must still be carrying \
         tcp_flags: 0 for this cell's claim to hold. If this FAILS, #9412 has been \
         implemented or the constructor changed: close-state may now cross the \
         wire, the derivation below is no longer vacuous, and BOTH this cell and \
         the #3152 comment block in session/install.rs must be updated to describe \
         the new carrier instead of the hard zero."
    );

    // The consequence, derived exactly the way install.rs derives it from the
    // entry's tcp_flags.
    let (closing, reset, fin_own) = (
        is_closing(entry.tcp_flags),
        has_rst(entry.tcp_flags),
        has_fin(entry.tcp_flags),
    );
    assert!(
        !closing && !reset && !fin_own,
        "#9412: the close bits derived from `tcp_flags` must stay false on the sync \
         path. Close state crosses on `tcp_close_class` instead, so a set bit here \
         means a second, competing carrier. closing={closing} reset={reset} fin_own={fin_own}"
    );
}

/// POSITIVE CONTROL. Without it the cell above is satisfied by a broken
/// derivation — predicates that returned false for every input would pass it, and
/// the assertion would then be about the predicates rather than about the hard
/// zero. Real flags must produce real bits.
#[test]
fn the_close_bit_derivation_itself_works_9412() {
    use crate::tcp_flags::{TCP_FIN, TCP_RST};

    assert!(
        is_closing(TCP_FIN) && has_fin(TCP_FIN) && !has_rst(TCP_FIN),
        "a FIN must derive CLOSING + fin_own"
    );
    assert!(
        is_closing(TCP_RST) && has_rst(TCP_RST) && !has_fin(TCP_RST),
        "a RST must derive CLOSING + reset"
    );
    assert!(
        !is_closing(0x10 /* ACK */),
        "a bare ACK must not derive CLOSING"
    );
}
