// #16242 descriptors-per-commit / per-kick histogram tests.

use super::*;

#[test]
fn tx_batch_bucket_layout_pin() {
    // Exact sizes 1..=7 occupy buckets 0..=6.
    for n in 1..=7u32 {
        assert_eq!(tx_batch_bucket(n), (n - 1) as usize, "size {n}");
    }
    // Power-of-two bands above that.
    assert_eq!(tx_batch_bucket(8), 7);
    assert_eq!(tx_batch_bucket(15), 7);
    assert_eq!(tx_batch_bucket(16), 8);
    assert_eq!(tx_batch_bucket(31), 8);
    assert_eq!(tx_batch_bucket(32), 9);
    assert_eq!(tx_batch_bucket(63), 9);
    // A full TX_BATCH_SIZE commit, and anything larger (multi-commit
    // per-kick accumulation), saturates in the top bucket.
    assert_eq!(tx_batch_bucket(64), TX_BATCH_BUCKETS - 1);
    assert_eq!(tx_batch_bucket(128), TX_BATCH_BUCKETS - 1);
    assert_eq!(tx_batch_bucket(u32::MAX), TX_BATCH_BUCKETS - 1);
}

#[test]
fn tx_batch_snapshot_propagates_hist_and_scalars() {
    let live = BindingLiveState::new();
    let owner = &live.owner_profile_owner;
    owner.tx_batch_hist[2].store(5, Ordering::Relaxed);
    owner.tx_batch_hist[TX_BATCH_BUCKETS - 1].store(7, Ordering::Relaxed);
    owner.tx_batch_commits.store(12, Ordering::Relaxed);
    owner.tx_batch_descriptors.store(300, Ordering::Relaxed);
    owner.tx_kick_batch_hist[9].store(3, Ordering::Relaxed);
    owner.tx_kick_batch_kicks.store(3, Ordering::Relaxed);
    owner.tx_kick_batch_descriptors.store(150, Ordering::Relaxed);

    let snap = live.snapshot();
    assert_eq!(snap.tx_batch_hist[2], 5);
    assert_eq!(snap.tx_batch_hist[TX_BATCH_BUCKETS - 1], 7);
    assert_eq!(snap.tx_batch_commits, 12);
    assert_eq!(snap.tx_batch_descriptors, 300);
    assert_eq!(snap.tx_kick_batch_hist[9], 3);
    assert_eq!(snap.tx_kick_batch_kicks, 3);
    assert_eq!(snap.tx_kick_batch_descriptors, 150);
    // Invariant the operator reading relies on: buckets sum to commits.
    assert_eq!(snap.tx_batch_hist.iter().sum::<u64>(), snap.tx_batch_commits);
    assert_eq!(
        snap.tx_kick_batch_hist.iter().sum::<u64>(),
        snap.tx_kick_batch_kicks
    );
}
