//! #13081 structural regression for the per-batch PMech replay stage.

#[test]
fn pmech_replay_drain_is_a_sibling_stage_13081() {
    let source = include_str!("mod.rs");
    assert!(
        source.contains("pmech_replay::drain_pending_pmech_replays(")
            && source.contains("&mut binding.pending_pmech_reverse")
            && source.contains("&mut binding.pending_pmech_replay"),
        "the poll loop delegates pending PMech reverse replay to its sibling stage"
    );
    assert!(
        !source.contains("match pmech_directory.probe_token(held.token)")
            && !source.contains("for _ in 0..pmech_scan_len"),
        "the large poll function must not inline PMech replay-stage control flow"
    );
}
