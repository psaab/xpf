//! #15770 TRIPWIRE: owed kernel-neighbor bindings are per-bucket, not a
//! single table-wide slot.
//!
//! Explicitly a source tripwire, not a behavioural test: the decision
//! logic is covered behaviourally by
//! `hot_bucket_multi_victim_owed_not_overwritten_15770` and
//! `owned_way_rate_limited_mac_change_survives_eviction_15770` in
//! `src/afxdp/neighbor_program_limiter.rs`. What this pins is that the
//! production limiter no longer carries the single newest-wins `owed`
//! slot whose overwrite lost hot-bucket victims (#15770).

use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn limiter_has_no_single_table_wide_owed_slot_15770() {
    let src = read("src/afxdp/neighbor_program_limiter.rs");
    assert!(
        !src.contains("owed: Option<((i32, IpAddr), [u8; 6])>"),
        "#15770 RED: the limiter again carries a single table-wide \
         newest-wins owed slot; a second hot-bucket refusal overwrites \
         the first victim, whose unchanged re-advert is then skipped"
    );
    assert!(
        src.contains("desired_key: Option<(i32, IpAddr)>"),
        "#15770 RED: owed state must live per way (desired_key/desired_mac) \
         so a bucket retains multiple owed bindings and an owed binding \
         survives eviction of its owner's way"
    );
    assert!(
        src.contains("fn record_owed("),
        "#15770 RED: refusals and in-owned-way rate-limited changes must \
         record owed per bucket via record_owed"
    );
}
