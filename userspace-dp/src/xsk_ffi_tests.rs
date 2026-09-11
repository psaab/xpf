use super::*;

#[test]
fn private_constructor_rings_borrow_umem_ring_boxes() {
    let mut umem_fill: Box<XskRingProd> = Box::new(unsafe { core::mem::zeroed() });
    let mut umem_comp: Box<XskRingCons> = Box::new(unsafe { core::mem::zeroed() });
    let socket_fill: Box<XskRingProd> = Box::new(unsafe { core::mem::zeroed() });
    let socket_comp: Box<XskRingCons> = Box::new(unsafe { core::mem::zeroed() });
    let umem_fill_addr = (&*umem_fill) as *const XskRingProd;
    let umem_comp_addr = (&*umem_comp) as *const XskRingCons;
    let socket_fill_addr = (&*socket_fill) as *const XskRingProd;
    let socket_comp_addr = (&*socket_comp) as *const XskRingCons;

    let rings = device_queue_rings_for_create(
        Some((&mut umem_fill, &mut umem_comp)),
        socket_fill,
        socket_comp,
    );

    assert_eq!(rings.fill() as *const XskRingProd, umem_fill_addr);
    assert_eq!(rings.comp() as *const XskRingCons, umem_comp_addr);
    assert_ne!(rings.fill() as *const XskRingProd, socket_fill_addr);
    assert_ne!(rings.comp() as *const XskRingCons, socket_comp_addr);
    assert_eq!((&*umem_fill) as *const XskRingProd, umem_fill_addr);
    assert_eq!((&*umem_comp) as *const XskRingCons, umem_comp_addr);
}

// ── Producer-ring append safety (#2383) ──────────────────────────
//
// `WriteTx::insert` / `WriteFill::insert` must place the k-th total
// item of a reservation at `base_idx + written + n` so a second
// `insert()` APPENDS after the first instead of overwriting it.
// These tests fail-on-revert: reverting the index to `base_idx + n`
// makes the second insert clobber slot base+0.

/// Read TX descriptor slot `i` from the leaked test ring backing.
/// The bridge writes through libxdp at `idx & mask`, so reading the
/// raw ring buffer at `i & mask` observes what `insert` wrote.
fn tx_slot(ring: &XskRingProd, i: u32) -> XdpDesc {
    let idx = (i & ring.mask) as usize;
    unsafe { *(ring.ring as *const XdpDesc).add(idx) }
}

fn fill_slot(ring: &XskRingProd, i: u32) -> u64 {
    let idx = (i & ring.mask) as usize;
    unsafe { *(ring.ring as *const u64).add(idx) }
}

fn desc(addr: u64) -> XdpDesc {
    XdpDesc {
        addr,
        len: addr as u32,
        options: 0,
    }
}

#[test]
fn write_tx_two_inserts_append_not_overwrite() {
    let mut tx = RingTx::new_for_test(-1, 8);
    let base;
    {
        let mut w = tx.transmit(4);
        base = w.base_idx;
        assert_eq!(w.reserved, 4);
        // First insert: one descriptor at base+0.
        assert_eq!(w.insert([desc(0xA0)].into_iter()), 1);
        assert_eq!(w.written, 1);
        // Second insert: must APPEND at base+1, base+2 (NOT base+0).
        assert_eq!(w.insert([desc(0xB1), desc(0xC2)].into_iter()), 2);
        assert_eq!(w.written, 3);
        w.commit();
    }
    // All three distinct slots hold the items in insertion order.
    assert_eq!(tx_slot(&tx.ring, base).addr, 0xA0);
    assert_eq!(tx_slot(&tx.ring, base.wrapping_add(1)).addr, 0xB1);
    assert_eq!(tx_slot(&tx.ring, base.wrapping_add(2)).addr, 0xC2);
}

#[test]
fn write_tx_single_insert_writes_base() {
    let mut tx = RingTx::new_for_test(-1, 8);
    let base;
    {
        let mut w = tx.transmit(4);
        base = w.base_idx;
        assert_eq!(w.insert([desc(0x11), desc(0x22)].into_iter()), 2);
        assert_eq!(w.written, 2);
        w.commit();
    }
    assert_eq!(tx_slot(&tx.ring, base).addr, 0x11);
    assert_eq!(tx_slot(&tx.ring, base.wrapping_add(1)).addr, 0x22);
}

#[test]
fn write_tx_insert_bounded_by_remaining_reservation() {
    let mut tx = RingTx::new_for_test(-1, 8);
    {
        let mut w = tx.transmit(2);
        assert_eq!(w.reserved, 2);
        // First insert fills the reservation.
        assert_eq!(w.insert([desc(1), desc(2)].into_iter()), 2);
        assert_eq!(w.written, 2);
        // Second insert has zero remaining capacity — inserts nothing,
        // does not write past the reservation.
        assert_eq!(w.insert([desc(3), desc(4)].into_iter()), 0);
        assert_eq!(w.written, 2);
        // A single oversized insert is also capped at the reservation.
        w.commit();
    }
    let mut tx2 = RingTx::new_for_test(-1, 8);
    {
        let mut w = tx2.transmit(2);
        assert_eq!(w.insert((0..10).map(desc)), 2);
        assert_eq!(w.written, 2);
        w.commit();
    }
}

#[test]
fn write_fill_two_inserts_append_not_overwrite() {
    let mut dq = DeviceQueue::new_for_test(-1, 8);
    let base;
    {
        let mut w = dq.fill(4);
        base = w.base_idx;
        assert_eq!(w.reserved, 4);
        assert_eq!(w.insert([0xA0u64].into_iter()), 1);
        assert_eq!(w.written, 1);
        assert_eq!(w.insert([0xB1u64, 0xC2u64].into_iter()), 2);
        assert_eq!(w.written, 3);
        w.commit();
    }
    let ring = dq.rings.fill();
    assert_eq!(fill_slot(ring, base), 0xA0);
    assert_eq!(fill_slot(ring, base.wrapping_add(1)), 0xB1);
    assert_eq!(fill_slot(ring, base.wrapping_add(2)), 0xC2);
}

#[test]
fn write_fill_single_insert_writes_base() {
    let mut dq = DeviceQueue::new_for_test(-1, 8);
    let base;
    {
        let mut w = dq.fill(4);
        base = w.base_idx;
        assert_eq!(w.insert([0x11u64, 0x22u64].into_iter()), 2);
        assert_eq!(w.written, 2);
        w.commit();
    }
    let ring = dq.rings.fill();
    assert_eq!(fill_slot(ring, base), 0x11);
    assert_eq!(fill_slot(ring, base.wrapping_add(1)), 0x22);
}

#[test]
fn write_fill_insert_bounded_by_remaining_reservation() {
    let mut dq = DeviceQueue::new_for_test(-1, 8);
    {
        let mut w = dq.fill(2);
        assert_eq!(w.reserved, 2);
        assert_eq!(w.insert([1u64, 2u64].into_iter()), 2);
        assert_eq!(w.written, 2);
        assert_eq!(w.insert([3u64, 4u64].into_iter()), 0);
        assert_eq!(w.written, 2);
        w.commit();
    }
    let mut dq2 = DeviceQueue::new_for_test(-1, 8);
    {
        let mut w = dq2.fill(2);
        assert_eq!(w.insert(0..10u64), 2);
        assert_eq!(w.written, 2);
        w.commit();
    }
}

// ── RX consumer-ring release safety (#4997) ──────────────────────
//
// `ReadRx` now holds `ring: &'a mut XskRingCons` (it was a shared
// `&'a XskRingCons` plus a `*const -> *mut` cast in `release()`/drop —
// writing the consumer ring through a pointer derived from `&T` with no
// `UnsafeCell` is UB under Stacked/Tree Borrows, which Miri flags). The
// `release()`/drop calls must still advance the real kernel-facing
// `consumer` pointer through that `&mut`.
//
// This drives the exact production `receive` -> `read` -> `release`
// path on a hermetic test ring and asserts (a) the descriptors read
// back in order and (b) the `consumer` pointer advanced by the released
// count — i.e. `release()` genuinely wrote through the reference.
//
// Fail-on-revert: reverting the field to `&XskRingCons` no longer
// compiles — `bridge_xsk_ring_cons_release` takes `*mut XskRingCons`
// and a `&T` does not coerce to `*mut T` without the removed const
// cast — so the type change is itself compile-pinned; this test
// additionally pins the release/cancel behavior. Miri cannot drive it
// (the libxdp C bridge is `extern "C"` FFI, unsupported under Miri), so
// there is no Miri-gated variant — the `&mut` type + this behavioral
// test are the pins.
#[test]
fn read_rx_release_advances_consumer_through_mut_ref() {
    let mut rx = RingRx::new_for_test(-1, 8);
    rx.push_for_test(desc(0xAA));
    rx.push_for_test(desc(0xBB));

    // consumer pointer starts at 0 (nothing released yet).
    assert_eq!(unsafe { *rx.ring.consumer }, 0);

    {
        let mut r = rx.receive(4);
        let d0 = r.read().expect("first descriptor available");
        let d1 = r.read().expect("second descriptor available");
        assert_eq!(d0.addr, 0xAA);
        assert_eq!(d1.addr, 0xBB);
        assert!(r.read().is_none(), "only two descriptors were pushed");
        r.release();
    }

    // release() must have written through the &mut: the kernel-facing
    // consumer pointer advanced by the two released descriptors.
    assert_eq!(unsafe { *rx.ring.consumer }, 2);
}

// ── Terminal-op base-cursor advance (#5716) ──────────────────────
//
// All four ring guards stay usable after their terminal op
// (`WriteTx::commit` / `WriteFill::commit` / `ReadRx::release` /
// `ReadComplete::release`). Pre-#5716 none of them advanced `base_idx`
// past the slots the terminal op had handed to the kernel, so a reused
// guard silently aliased them:
//
//   * producers restarted at `base_idx + 0` and OVERWROTE the
//     just-submitted descriptors / fill offsets;
//   * `ReadComplete` restarted at `base_idx + 0` and RE-READ completion
//     addresses it had already reaped;
//   * `ReadRx` kept its positional cursor but sealed itself with a sticky
//     `released` flag, so the post-release reads could never be released
//     and `Drop`'s cancel under-counted — permanently leaking those RX
//     ring slots (`cached_cons` stuck ahead of `*consumer`).
//
// No production caller crosses a terminal op today (every site is
// `create -> insert/read* -> commit/release -> drop`), so these are
// API-hardening guards: they pin the reuse contract before a caller
// relies on it. The single-use path is unchanged and still covered by
// the #2383/#4997 tests above.
//
// Two different producibility questions, with two different answers,
// because someone will ask:
//
//   * The BATCH SIZES below are producible exactly as written. Every
//     production insert passes a variable-length slice
//     (`scratch_prepared_tx.len()` in tx/transmit/write.rs and four sites
//     in cos/queue_service/service.rs, `scratch_fill.len()` in
//     tx/rings.rs, `offsets.len()` plus an arbitrary retry suffix in
//     bind.rs), and every release releases whatever its
//     `while let Some(..) = read()` loop consumed (tx/rings.rs,
//     poll_descriptor/mod.rs). Nothing caps a batch at one or two slots,
//     so a three-slot batch is an ordinary shape rather than one invented
//     for the fixture.
//   * The REUSE ITSELF -- insert -> commit -> insert on one guard -- is
//     NOT producible today. That is the point: it is the forward-looking
//     contract this change states, so a fixture for it tests the stated
//     contract rather than inventing a shape. If a future caller starts
//     streaming through one guard, these are the tests that hold the line.

/// Seed a producer ring so the next reservation begins at `at`. Lets a test
/// place the guard's base cursor at the `u32` wrap boundary instead of only
/// at 0 (libxdp masks the index, so a ring index legitimately wraps `u32`).
fn seed_prod_at(ring: &mut XskRingProd, at: u32) {
    ring.cached_prod = at;
    ring.cached_cons = at.wrapping_add(ring.size);
    unsafe {
        *ring.producer = at;
        *ring.consumer = at;
    }
}

/// Seed a consumer ring so the next peek begins at `at`. Same purpose as
/// [`seed_prod_at`], for the RX / completion side.
fn seed_cons_at(ring: &mut XskRingCons, at: u32) {
    ring.cached_prod = at;
    ring.cached_cons = at;
    unsafe {
        *ring.producer = at;
        *ring.consumer = at;
    }
}

/// The two cursor origins every reuse test runs at: mid-range (0) and the
/// `u32` wrap boundary. At `u32::MAX - 1` the reservation straddles the wrap,
/// so the terminal op's `wrapping_add` advance crosses `u32::MAX` mid guard —
/// the edge of the class these guards claim to cover. With [`REUSE_BATCHES`]
/// the wrap lands *inside* the second batch (indices `u32::MAX`, 0, 1) rather
/// than between two guards.
const CURSOR_ORIGINS: [u32; 2] = [0, u32::MAX - 1];

/// Slot count of the hermetic rings the reuse fixtures run on.
const REUSE_RING_CAPACITY: u32 = 8;

/// The batch sizes each reuse fixture drives through its guard, in order.
///
/// What actually rejects a constant advance is the PER-OPERATION checkpoint,
/// not the number of distinct sizes. With a cursor assertion after every
/// terminal op, two distinct sizes already suffice: a batch of 1 rejects every
/// constant except 1, and a following batch of 3 rejects the constant 1
/// (cumulative 4 against 2). Three sizes are what the fixtures happen to use;
/// they are not load-bearing, and a later reshape to two distinct sizes would
/// keep the guard intact. What is NOT safe is collapsing to a single repeated
/// size, or dropping the intermediate checkpoints — see below.
///
/// The intermediate checkpoints are the load-bearing part. Three applications
/// of `+= 2` land on the same FINAL cursor as the correct advance
/// (2+2+2 == 1+3+2), so a constant is invisible to an end-state-only check.
/// Delete the checkpoints and the guard is gone while still looking like a
/// guard. The last checkpoint specifically is redundant — the first two have
/// already rejected every constant by the time it runs — but it is cheap and
/// states the end state explicitly.
///
/// DETECTED is not BOUND, and that is why this reshape was necessary rather
/// than tidy. The constants that *did* red before this change red on
/// **payload** assertions, never on a cursor one — a re-read descriptor came
/// back with the wrong address (`read_rx` caught `left: 0xBB` against
/// `right: 0xCC`). Measured on the pre-#6832 fixtures, each of the four guards
/// admitted exactly one constant — `WriteTx`/`WriteFill` passed `+= 1`,
/// `ReadRx`/`ReadComplete` passed `+= 2`. So the cursor advance was not
/// half-covered by the old fixtures; it was covered nowhere and merely
/// *detected* in two of the four, through the data a wrong cursor happened to
/// corrupt. That detection survives only while the aliased slots hold
/// distinguishable payloads, and it says nothing whatever about the two guards
/// whose surviving constant left the data intact. The per-batch checkpoints
/// below are the first assertions in this file to bind the advance itself.
const REUSE_BATCHES: [u32; 3] = [1, 3, 3];

/// Total slots a reuse fixture reserves / peeks: the sum of [`REUSE_BATCHES`].
const REUSE_TOTAL: u32 = REUSE_BATCHES[0] + REUSE_BATCHES[1] + REUSE_BATCHES[2];

// FIXTURE SELF-CHECKS, not coverage. All three of these are assertions over
// test constants alone, so no production edit can make any of them fail and
// none belongs in a count of what this file binds. They exist to fail the
// BUILD if a later edit to the constants above quietly invalidates the
// fixtures that consume them.
//
// #6832 fold r6 — these guards are now stated over the positions each loop
// ACTUALLY EXECUTES, because twice running a guard phrased over the whole array
// was satisfied by a triple its consuming loop could not distinguish.
//
// The rule the two escapes share: **a self-check must quantify over the same
// values its fixture drives.** `[0, 2, 2]` passed a distinctness disjunction via
// a zero that executes no operation at all. `[1, 1, 3]` passed the same
// disjunction via `B[1] != B[2]`, while the Drop fixtures' explicit loop runs
// only `B[0]` and `B[1]` — both 1. Each time the constraint MOVED rather than
// closed, and a neighbouring triple took the dead one's place; a fifth conjunct
// would move it again. So the arrays below ARE the loops' iterands: each fixture
// iterates the same const its guard asserts over, which makes "the guard names
// something the loop never executes" unstateable rather than merely
// currently-false.

// (1) Every reuse batch NON-ZERO — a zero batch executes no terminal operation,
// so it contributes no executed size. Measured: with `[0, 2, 2]` and this
// conjunct absent, the file compiled and all 17 XSK tests passed.
const _: () = assert!(
    REUSE_BATCHES[0] > 0 && REUSE_BATCHES[1] > 0 && REUSE_BATCHES[2] > 0,
    "every reuse batch must be NON-ZERO: a zero batch executes no terminal op, \
     so it cannot contribute a distinct executed size and a constant advance \
     survives"
);

// (2) The ORDINARY reuse fixtures drive all three batches with a checkpoint
// after each (`for n in REUSE_BATCHES`), so two distinct sizes anywhere in the
// triple do suffice for them. This assertion is correct FOR THEM and was never
// the hole — it is simply not the Drop fixtures' precondition.
const _: () = assert!(
    REUSE_BATCHES[0] != REUSE_BATCHES[1]
        || REUSE_BATCHES[1] != REUSE_BATCHES[2]
        || REUSE_BATCHES[0] != REUSE_BATCHES[2],
    "the ordinary reuse fixtures need at least two DISTINCT sizes among the \
     three they execute, to reject a constant advance"
);

/// The batches every **Drop** fixture drives to an EXPLICIT terminal op before
/// leaving the final one partly done. The fixtures iterate THIS, and guard (3)
/// asserts over THIS, so the two cannot drift apart.
const EXPLICIT_BATCHES: [u32; 2] = [REUSE_BATCHES[0], REUSE_BATCHES[1]];

// (3) The Drop fixtures' explicit loop executes ONLY these two, so rejecting a
// constant advance there needs THESE TWO distinct — not merely two distinct
// somewhere in the triple. `[1, 1, 3]` satisfies (2) and fails here: measured,
// it compiled, passed 17/17, and greened all four Drop fixtures under a constant
// `base_idx` advance that reds 4 of 4 at `[1, 3, 3]`.
const _: () = assert!(
    EXPLICIT_BATCHES[0] != EXPLICIT_BATCHES[1],
    "the Drop fixtures explicitly execute only REUSE_BATCHES[0] and [1], so \
     THOSE TWO must differ; distinct sizes elsewhere in the triple cannot help \
     a loop that never runs them"
);

/// How much of the final batch each Drop fixture consumes before letting `Drop`
/// finish it. Every entry is one drive, so `Drop` runs at
/// `(terminal, cancel) = (p, REUSE_BATCHES[2] - p)` for each `p`.
///
/// Driving MORE THAN ONE is what binds the cancel argument, and its absence was
/// a live hole. At a single pinned partial both counts are fixed across all four
/// fixtures and both cursor origins, so a `Drop` hardcoding either position is
/// indistinguishable. Measured at the r5 shape (`p` pinned to
/// `REUSE_BATCHES[2] - 1`): hardcoding ONLY the cancel argument to `1` left the
/// suite at **4266 passed, 0 failed** — identical to baseline. The r5 evidence
/// (constants `1` and `2` failing at different assertions) proved only that
/// those two JOINT substitutions fail; it could not speak to the cancel
/// position, which never varied.
const DROP_PARTIALS: [u32; 2] = [1, 2];

// (4) Each partial leaves BOTH halves of `Drop` real work: `p` to
// submit/release and `REUSE_BATCHES[2] - p` to cancel, both non-zero.
const _: () = assert!(
    DROP_PARTIALS[0] >= 1
        && DROP_PARTIALS[1] >= 1
        && DROP_PARTIALS[0] < REUSE_BATCHES[2]
        && DROP_PARTIALS[1] < REUSE_BATCHES[2],
    "every drop partial must lie in 1..REUSE_BATCHES[2] so Drop has a non-zero \
     terminal count AND a non-zero cancel count"
);

// (5) The partials must DIFFER, so the terminal count varies across drives —
// and since cancel is `REUSE_BATCHES[2] - p`, the cancel count varies too,
// INVERSELY. That inverse pairing is what leaves no constant satisfying either
// position: whatever value a constant picks is right for at most one drive.
//
// The old `REUSE_BATCHES[2] >= 3` floor is now DERIVED from (4)+(5) rather than
// asserted as its own magic number: two distinct partials both inside
// `1..B[2]` cannot exist below 3. A floor that follows from the property it
// serves cannot drift away from it, which is exactly how the previous floor
// came to be true-but-insufficient.
const _: () = assert!(
    DROP_PARTIALS[0] != DROP_PARTIALS[1],
    "the drop partials must DIFFER, or the terminal and cancel counts are the \
     same in every drive and a hardcoded constant survives in both positions"
);
// Each slot of a run must land in its own ring slot; otherwise a misplaced
// write could alias onto the very value it was supposed to corrupt.
const _: () = assert!(REUSE_TOTAL <= REUSE_RING_CAPACITY);
/// Distinct non-zero payload for the `j`-th slot of a reuse run. Monotone in
/// `j`, and never 0 (the test ring backing is zero-initialised), so a write
/// that lands on the wrong slot is detectable both at the slot it corrupted
/// and at the slot it skipped.
fn reuse_payload(j: u32) -> u64 {
    0xA000 + j as u64
}

#[test]
fn write_tx_insert_after_commit_appends_past_the_committed_slots() {
    for origin in CURSOR_ORIGINS {
        let mut tx = RingTx::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_prod_at(&mut tx.ring, origin);
        let producer = tx.ring.producer;
        let base;
        {
            let mut w = tx.transmit(REUSE_TOTAL);
            base = w.base_idx;
            assert_eq!(base, origin, "reservation must start at the seeded cursor");
            assert_eq!(
                w.reserved, REUSE_TOTAL,
                "the fixture needs the whole reservation up front — a short \
                 reserve would silently shrink the batches below"
            );
            let mut submitted = 0u32;
            for n in REUSE_BATCHES {
                let first = submitted;
                assert_eq!(
                    w.insert((0..n).map(|k| desc(reuse_payload(first + k)))),
                    n,
                    "origin {origin}: a {n}-descriptor batch did not fit the \
                     remaining reservation"
                );
                w.commit();
                submitted += n;
                // The commit handed `n` slots to the kernel, so the cursor must
                // move by exactly `n`. Asserted after EVERY commit: a constant
                // advance is invisible at the end (2+2+2 == 1+3+2) and shows up
                // only here.
                assert_eq!(
                    w.base_idx,
                    base.wrapping_add(submitted),
                    "origin {origin}: after commits summing to {submitted} slots \
                     the base cursor did not advance by the committed count"
                );
                assert_eq!(
                    w.reserved,
                    REUSE_TOTAL - submitted,
                    "origin {origin}: commit must consume the submitted slots"
                );
                // #6832 fold r2: asserted per commit, not only in aggregate.
                // Three submits of a constant 2 reach the same TOTAL as the
                // correct 1/3/2, so an aggregate-only check cannot see a commit
                // that hands the kernel the wrong NUMBER of slots — which
                // publishes descriptors the caller has not written yet, or
                // strands ones it has.
                assert_eq!(
                    unsafe { *producer },
                    base.wrapping_add(submitted),
                    "origin {origin}: after commits summing to {submitted} slots \
                     the kernel-facing producer did not advance by the \
                     committed count"
                );
            }
        }
        // Every slot holds its own descriptor: no batch overwrote a predecessor
        // the kernel already owns, and none skipped a slot.
        for j in 0..REUSE_TOTAL {
            assert_eq!(
                tx_slot(&tx.ring, base.wrapping_add(j)).addr,
                reuse_payload(j),
                "origin {origin}: slot {j} does not hold its own descriptor. \
                 The shape this guards: a post-commit insert landing on the \
                 wrong slot, corrupting a descriptor already submitted to the \
                 kernel"
            );
        }
        // The drop-time cancel left cached_prod exactly on the producer (no
        // leaked slots). NB: this pair binds the terminal op's
        // `reserved -= written` bookkeeping, NOT the cursor advance — `Drop`
        // cancels `reserved - written`, so a commit that moved the cursor but
        // left the reservation unshrunk cancels slots the kernel already owns.
        // A wrong *cursor* leaves both equalities intact (measured: `+= 1` here
        // was GREEN before #6832), which is why the per-batch checkpoints above
        // are the ones that bind it. The producer equality below is an end-state
        // restatement of those checkpoints, which are what bind the per-commit
        // submission count.
        assert_eq!(unsafe { *producer }, base.wrapping_add(REUSE_TOTAL));
        assert_eq!(tx.ring.cached_prod, unsafe { *producer });
    }
}

#[test]
fn write_fill_insert_after_commit_appends_past_the_committed_slots() {
    for origin in CURSOR_ORIGINS {
        let mut dq = DeviceQueue::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_prod_at(dq.rings.fill_mut(), origin);
        let producer = dq.rings.fill().producer;
        let base;
        {
            let mut w = dq.fill(REUSE_TOTAL);
            base = w.base_idx;
            assert_eq!(base, origin, "reservation must start at the seeded cursor");
            assert_eq!(
                w.reserved, REUSE_TOTAL,
                "the fixture needs the whole reservation up front — a short \
                 reserve would silently shrink the batches below"
            );
            let mut submitted = 0u32;
            for n in REUSE_BATCHES {
                let first = submitted;
                assert_eq!(
                    w.insert((0..n).map(|k| reuse_payload(first + k))),
                    n,
                    "origin {origin}: a {n}-offset batch did not fit the \
                     remaining reservation"
                );
                w.commit();
                submitted += n;
                // Asserted after EVERY commit — see the note in the WriteTx
                // sibling: a constant advance survives an end-state-only check.
                assert_eq!(
                    w.base_idx,
                    base.wrapping_add(submitted),
                    "origin {origin}: after commits summing to {submitted} slots \
                     the base cursor did not advance by the committed count"
                );
                assert_eq!(
                    w.reserved,
                    REUSE_TOTAL - submitted,
                    "origin {origin}: commit must consume the submitted slots"
                );
                // Per commit, not only in aggregate — see the `WriteTx` sibling.
                assert_eq!(
                    unsafe { *producer },
                    base.wrapping_add(submitted),
                    "origin {origin}: after commits summing to {submitted} slots \
                     the kernel-facing producer did not advance by the \
                     committed count"
                );
            }
        }
        let ring = dq.rings.fill();
        for j in 0..REUSE_TOTAL {
            assert_eq!(
                fill_slot(ring, base.wrapping_add(j)),
                reuse_payload(j),
                "origin {origin}: slot {j} does not hold its own fill offset. \
                 The shape this guards: a post-commit insert overwriting an \
                 offset already submitted to the kernel, leaving two RX slots \
                 aliasing one UMEM frame"
            );
        }
        assert_eq!(unsafe { *producer }, base.wrapping_add(REUSE_TOTAL));
        assert_eq!(ring.cached_prod, unsafe { *producer });
    }
}

#[test]
fn read_complete_read_after_release_does_not_re_reap_released_entries() {
    for origin in CURSOR_ORIGINS {
        let mut dq = DeviceQueue::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_cons_at(dq.rings.comp_mut(), origin);
        for j in 0..REUSE_TOTAL {
            dq.push_comp_for_test(reuse_payload(j));
        }
        // Raw pointer captured before the guard borrows the ring (it models
        // kernel-owned mmap state, exactly as `test_cons_ring` sets it up).
        let consumer = dq.rings.comp().consumer;
        assert_eq!(unsafe { *consumer }, origin);
        {
            let mut r = dq.complete(REUSE_TOTAL);
            assert_eq!(r.base_idx, origin, "peek must start at the seeded cursor");
            // Pin the window size at its source. `read()` has no error path —
            // its only `None` is the `read_count >= peeked` bounds check — so
            // the sole alternative cause of an early `None` is a short peek.
            // With `peeked` pinned here, the terminal `None` below means
            // exhaustion and nothing else.
            assert_eq!(
                r.peeked, REUSE_TOTAL,
                "peek must cover every pushed completion entry"
            );
            let mut released = 0u32;
            for n in REUSE_BATCHES {
                for k in 0..n {
                    // A reused reader must continue past what it released.
                    // Handing an address back twice would recycle one UMEM
                    // frame into the fill ring twice.
                    assert_eq!(
                        r.read(),
                        Some(reuse_payload(released + k)),
                        "origin {origin}: entry {} was not reaped in order. \
                         The shape this guards: a reused reader re-reading an \
                         already-released completion address",
                        released + k
                    );
                }
                r.release();
                released += n;
                assert_eq!(
                    r.base_idx,
                    origin.wrapping_add(released),
                    "origin {origin}: after releases summing to {released} entries \
                     the base cursor did not advance by the released count"
                );
                assert_eq!(
                    unsafe { *consumer },
                    origin.wrapping_add(released),
                    "origin {origin}: the kernel-facing consumer is not at the \
                     released count. The shape this guards: a release that does \
                     not reach the shared consumer pointer"
                );
            }
            assert_eq!(
                r.read(),
                None,
                "origin {origin}: the peek window was pinned at {} entries above \
                 and all of them have been read, so the guard must report \
                 exhaustion",
                REUSE_TOTAL
            );
        }
        // Nothing peeked-but-unread survives: cached_cons matches the real
        // consumer, so no completion-ring slots were leaked.
        assert_eq!(dq.rings.comp().cached_cons, unsafe { *consumer });
    }
}

#[test]
fn read_rx_read_after_release_stays_releasable() {
    for origin in CURSOR_ORIGINS {
        let mut rx = RingRx::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_cons_at(&mut rx.ring, origin);
        for j in 0..REUSE_TOTAL {
            rx.push_for_test(desc(reuse_payload(j)));
        }
        let consumer = rx.ring.consumer;
        {
            let mut r = rx.receive(REUSE_TOTAL);
            assert_eq!(r.base_idx, origin, "peek must start at the seeded cursor");
            // Same reasoning as the `read_complete_...` sibling: `ReadRx::read`
            // has no error path either, so pinning `peeked` at its source is
            // what lets the terminal `is_none()` below mean exhaustion rather
            // than a short peek.
            assert_eq!(
                r.peeked, REUSE_TOTAL,
                "peek must cover every pushed descriptor"
            );
            let mut released = 0u32;
            for n in REUSE_BATCHES {
                for k in 0..n {
                    assert_eq!(
                        r.read()
                            .expect("descriptor inside the pinned peek window")
                            .addr,
                        reuse_payload(released + k),
                        "origin {origin}: descriptor {} was not read in order",
                        released + k
                    );
                }
                r.release();
                released += n;
                // Two independent failure modes are pinned here, and they are
                // caught by different assertions. The base cursor catches an
                // advance that is not the released count. The consumer pointer
                // catches the pre-#5716 sticky `released` flag, which swallowed
                // every release after the first and leaked those slots for the
                // life of the socket — the descriptor reads above do NOT catch
                // that one, because the positional cursor stayed correct under
                // it.
                assert_eq!(
                    r.base_idx,
                    origin.wrapping_add(released),
                    "origin {origin}: after releases summing to {released} \
                     descriptors the base cursor did not advance by the \
                     released count"
                );
                assert_eq!(
                    unsafe { *consumer },
                    origin.wrapping_add(released),
                    "origin {origin}: the consumer is not at the released \
                     count. The shape this guards: the sticky-flag release, \
                     which swallowed every release after the first and left \
                     those descriptors permanently unreleasable"
                );
            }
            assert!(
                r.read().is_none(),
                "origin {origin}: the peek window was pinned at {} descriptors \
                 above and all of them have been read, so the guard must report \
                 exhaustion",
                REUSE_TOTAL
            );
        }
        // Drop must land cached_cons on the real consumer. A leak shows up
        // here as cached_cons > *consumer.
        assert_eq!(
            rx.ring.cached_cons,
            unsafe { *consumer },
            "origin {origin}: cached_cons is not on the kernel consumer. The \
             shape this guards: cached_cons drifting AHEAD, which leaks those \
             RX ring slots for the life of the socket"
        );
    }
}

#[test]
fn read_rx_drop_releases_a_batch_read_after_an_explicit_release() {
    // B3 (#6832 fold r2): the `Drop` condition itself changed — it was
    // `!self.released && self.read_count > 0` and is now `self.read_count > 0`
    // — and no fixture drove it. The sibling above always releases everything
    // it reads, so it leaves `read_count == 0` at drop and never enters the
    // branch.
    //
    // This one does: it releases the first two batches explicitly, then reads
    // PART of the third and lets `Drop` finish. That is the shape the sticky
    // flag broke. Pre-#5716 `Drop` saw `released == true`, skipped the release
    // entirely, and cancelled `peeked - read_count` against an unshrunk
    // `peeked` — so `cached_cons` ended AHEAD of `*consumer` and those RX ring
    // slots were leaked for the life of the socket. Post-#5716 the release
    // reaches the kernel and the cancel covers exactly the peeked-but-unread
    // remainder.
    for dropped_read in DROP_PARTIALS {
    for origin in CURSOR_ORIGINS {
        let mut rx = RingRx::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_cons_at(&mut rx.ring, origin);
        for j in 0..REUSE_TOTAL {
            rx.push_for_test(desc(reuse_payload(j)));
        }
        let consumer = rx.ring.consumer;

        // Read part of the final batch and leave the rest peeked-but-unread,
        // so the drop has BOTH a release and a non-zero cancel to do.
        let released_explicitly = EXPLICIT_BATCHES[0] + EXPLICIT_BATCHES[1];
        
        assert!(
            dropped_read > 0 && dropped_read < REUSE_BATCHES[2],
            "fixture: the final batch must be partly read so drop does both a \
             release and a cancel"
        );
        {
            let mut r = rx.receive(REUSE_TOTAL);
            let mut read_so_far = 0u32;
            for n in EXPLICIT_BATCHES {
                for _ in 0..n {
                    r.read().expect("descriptor inside the peek window");
                }
                r.release();
                read_so_far += n;
                // PER-OPERATION checkpoint, not an aggregate. The explicit
                // releases — one per EXPLICIT_BATCHES entry, whatever that
                // array's arity — sum to `released_explicitly`, and a constant
                // advance can reach the same total by a different route
                // (2+2 == 1+3), so an end-of-loop check alone admits it.
                // Checking after EACH release rejects it at the first batch
                // (#6832 fold r5).
                assert_eq!(
                    unsafe { *consumer },
                    origin.wrapping_add(read_so_far),
                    "origin {origin}: the consumer is not at {read_so_far} after \
                     the explicit release of a {n}-descriptor batch — the release \
                     advanced by something other than what it was handed"
                );
            }
            assert_eq!(
                unsafe { *consumer },
                origin.wrapping_add(released_explicitly),
                "origin {origin}: fixture precondition — EVERY explicit release \
                 the loop above performed must already have reached the \
                 kernel. The quantifier is over EXPLICIT_BATCHES, which the \
                 loop iterates generally; `released_explicitly` is its \
                 arity-2 sum, so growing the array without changing that sum \
                 reds HERE rather than passing vacuously — measured (#6832 \
                 fold r7): at arity 3 all four Drop fixtures red at this \
                 precondition, left 7 right 4"
            );
            for k in 0..dropped_read {
                assert_eq!(
                    r.read()
                        .expect("descriptor inside the peek window")
                        .addr,
                    reuse_payload(read_so_far + k),
                    "origin {origin}: descriptor {} was not read in order after \
                     a release",
                    read_so_far + k
                );
            }
            // No second `release()` — `Drop` owns this batch.
        }
        assert_eq!(
            unsafe { *consumer },
            origin.wrapping_add(released_explicitly + dropped_read),
            "origin {origin}: the consumer is not at \
             {released_explicitly}+{dropped_read}. The shape this guards: a \
             drop that skips the descriptors read after an explicit release, \
             leaving them unreleasable and leaking their RX slots"
        );
        assert_eq!(
            rx.ring.cached_cons,
            unsafe { *consumer },
            "origin {origin}: cached_cons is not on the kernel consumer. The \
             shape this guards: a drop-time cancel that does not cover exactly \
             the peeked-but-unread remainder"
        );
    }
    }
}
// ── Terminal-op-then-Drop, for the other three guards ────────────
//
// #6832 fold r3. The fixture above closed the `read -> release -> read ->
// drop` shape for `ReadRx` because r2 had found it unbound there. It did not
// ask whether the three SIBLING guards had the same hole. They did.
//
// Precisely, measured on this branch — the two halves of a guard's `Drop` are
// not equally uncovered, so stating it as "the body never ran" would be false:
//
//   * The submit/release half — `if self.written > 0 { submit }` and
//     `if self.read_count > 0 { release }` — never executed AT ALL for these
//     three guards. Every pre-existing fixture commits or releases everything
//     it wrote or read before the guard leaves scope, so each reaches drop
//     with `written`/`read_count` at 0.
//   * The cancel half DOES run in `write_tx_two_inserts_append_not_overwrite`
//     and `write_tx_single_insert_writes_base` (and their `write_fill`
//     twins), which leave part of the reservation unused. Each of those four
//     does assert after the guard drops — but only on RING SLOT CONTENTS,
//     written during `insert` and untouched by the drop. None reads
//     `cached_prod` or `*producer` post-drop, so nothing they assert can
//     OBSERVE the drop's effects: sever the cancel and all four stay green.
//     In the reuse fixtures the reservation is fully consumed, which makes
//     their post-drop `cached_prod == *producer` pair a check on a `Drop` that
//     did nothing.
//
// The three fixtures below are the same shape as the `ReadRx` one, one per
// remaining guard: run the first two batches to the terminal op explicitly,
// leave the third PARTLY done, and let `Drop` finish. That gives the drop both
// halves of its job at once — a submit/release AND a non-zero cancel.
//
// "So a drop that does either wrongly is observable" is what r3 wrote here, and
// at the batch sizes r3 chose it was FALSE. With a final batch of 2 the drop's
// two counts were both 1, so a `Drop` hardcoding its bridge arguments to the
// literal 1 produced byte-identical ring state — measured: all 17 XSK tests
// passed under exactly that mutation. r5's `>= 3` floor separated the two
// counts and left the CANCEL count invariant at 1 across every fixture, so a
// cancel-only constant still survived — measured again: 4266 passed, 0 failed.
//
// What makes the claim true now is not a size but a QUANTIFIER: each fixture
// drives `DROP_PARTIALS`, so `Drop` runs at `(terminal, cancel) = (p, B[2] - p)`
// for more than one `p`, and both coordinates take more than one value. A
// constant is right for at most one drive whichever position it occupies.
// Guards (4) and (5) hold that; the `>= 3` floor they replaced is now a
// consequence rather than a separate assertion, so do not cite it here.
//
// This paragraph deliberately names no literal counts. r6 found that the
// version which did had gone stale against its own round's change — it cited a
// self-check that had just been derived away, and a fixed submit-2/cancel-1
// that the partials had just made variable. A comment that restates values the
// consts already carry is a third copy of the invariant with no guard on it.
//
// Each is comparative: reverting its production line reds it while the
// pre-existing tests in this file stay green (see `_Log.md` for the matrix).

#[test]
fn read_complete_drop_releases_a_batch_read_after_an_explicit_release() {
    // Twin of `read_rx_drop_releases_a_batch_read_after_an_explicit_release`.
    // `ReadComplete::Drop` releases `read_count` and cancels the peeked-but-
    // unread remainder; the sibling reuse fixture releases everything it reads,
    // so it reaches drop with `read_count == 0` AND `peeked == 0` and the whole
    // body is skipped. A drop that skipped the release here would leave those
    // completion entries unreleasable — the kernel never learns the TX frames
    // were reaped, so the completion ring loses those slots for the life of the
    // socket.
    for dropped_read in DROP_PARTIALS {
    for origin in CURSOR_ORIGINS {
        let mut dq = DeviceQueue::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_cons_at(dq.rings.comp_mut(), origin);
        for j in 0..REUSE_TOTAL {
            dq.push_comp_for_test(reuse_payload(j));
        }
        let consumer = dq.rings.comp().consumer;

        let released_explicitly = EXPLICIT_BATCHES[0] + EXPLICIT_BATCHES[1];
        
        assert!(
            dropped_read > 0 && dropped_read < REUSE_BATCHES[2],
            "fixture: the final batch must be partly read so drop does both a \
             release and a cancel"
        );
        {
            let mut r = dq.complete(REUSE_TOTAL);
            let mut read_so_far = 0u32;
            for n in EXPLICIT_BATCHES {
                for _ in 0..n {
                    r.read().expect("entry inside the peek window");
                }
                r.release();
                read_so_far += n;
                // PER-OPERATION checkpoint, not an aggregate. The explicit
                // releases — one per EXPLICIT_BATCHES entry, whatever that
                // array's arity — sum to `released_explicitly`, and a constant
                // advance can reach the same total by a different route
                // (2+2 == 1+3), so an end-of-loop check alone admits it.
                // Checking after EACH release rejects it at the first batch
                // (#6832 fold r5).
                assert_eq!(
                    unsafe { *consumer },
                    origin.wrapping_add(read_so_far),
                    "origin {origin}: the consumer is not at {read_so_far} after \
                     the explicit release of a {n}-descriptor batch — the release \
                     advanced by something other than what it was handed"
                );
            }
            assert_eq!(
                unsafe { *consumer },
                origin.wrapping_add(released_explicitly),
                "origin {origin}: fixture precondition — EVERY explicit release \
                 the loop above performed must already have reached the \
                 kernel. The quantifier is over EXPLICIT_BATCHES, which the \
                 loop iterates generally; `released_explicitly` is its \
                 arity-2 sum, so growing the array without changing that sum \
                 reds HERE rather than passing vacuously — measured (#6832 \
                 fold r7): at arity 3 all four Drop fixtures red at this \
                 precondition, left 7 right 4"
            );
            for k in 0..dropped_read {
                assert_eq!(
                    r.read(),
                    Some(reuse_payload(read_so_far + k)),
                    "origin {origin}: entry {} was not reaped in order after a \
                     release",
                    read_so_far + k
                );
            }
            // No second `release()` — `Drop` owns this batch.
        }
        assert_eq!(
            unsafe { *consumer },
            origin.wrapping_add(released_explicitly + dropped_read),
            "origin {origin}: the consumer is not at \
             {released_explicitly}+{dropped_read}. The shape this guards: a \
             drop that skips the completion entries read after an explicit \
             release, leaving them unreleasable and leaking their slots"
        );
        assert_eq!(
            dq.rings.comp().cached_cons,
            unsafe { *consumer },
            "origin {origin}: cached_cons is not on the kernel consumer. The \
             shape this guards: a drop-time cancel that does not cover exactly \
             the peeked-but-unread remainder"
        );
    }
    }
}
#[test]
fn write_tx_drop_submits_a_batch_inserted_after_an_explicit_commit() {
    // The producer counterpart. `WriteTx::Drop` submits `written` and cancels
    // `reserved - written`.
    //
    // What the pre-existing fixtures leave for that drop, stated exactly —
    // an earlier round wrote "every pre-existing fixture commits its whole
    // reservation, so it drops with `written == 0` and `reserved == 0` and the
    // body does nothing", and that is false in its second half and contradicts
    // the block 90 lines above, which had it right. `commit()` zeroes `written`
    // and subtracts it from `reserved`, so a fixture that commits everything it
    // INSERTED still drops with `reserved` at whatever it over-reserved:
    // `write_tx_two_inserts_append_not_overwrite` reserves 4 and inserts 3,
    // `write_tx_single_insert_writes_base` reserves 4 and inserts 2. Both drop
    // with `written == 0` — so the SUBMIT half is genuinely never exercised,
    // which is what this fixture is for — but with `reserved` at 1 and 2, so
    // the CANCEL half does run there. It is unobserved rather than unexecuted:
    // neither reads `cached_prod` or `*producer` after the guard drops.
    //
    // A drop that skipped the submit would silently DISCARD descriptors the
    // caller had already inserted — frames the caller believes it queued for TX
    // are never handed to the kernel.
    for dropped_written in DROP_PARTIALS {
    for origin in CURSOR_ORIGINS {
        let mut tx = RingTx::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_prod_at(&mut tx.ring, origin);
        let producer = tx.ring.producer;

        let committed = EXPLICIT_BATCHES[0] + EXPLICIT_BATCHES[1];
        
        assert!(
            dropped_written > 0 && dropped_written < REUSE_BATCHES[2],
            "fixture: the final batch must be partly inserted so drop does both \
             a submit and a cancel"
        );
        let base;
        {
            let mut w = tx.transmit(REUSE_TOTAL);
            base = w.base_idx;
            assert_eq!(base, origin, "reservation must start at the seeded cursor");
            let mut submitted = 0u32;
            for n in EXPLICIT_BATCHES {
                let first = submitted;
                assert_eq!(
                    w.insert((0..n).map(|k| desc(reuse_payload(first + k)))),
                    n,
                    "origin {origin}: a {n}-descriptor batch did not fit the \
                     remaining reservation"
                );
                w.commit();
                submitted += n;
                // PER-OPERATION checkpoint — see the RX twin above for why an
                // aggregate is not enough (#6832 fold r5).
                assert_eq!(
                    unsafe { *producer },
                    base.wrapping_add(submitted),
                    "origin {origin}: the producer is not at {submitted} after \
                     the explicit commit of a {n}-descriptor batch — the commit \
                     advanced by something other than what it was handed"
                );
            }
            assert_eq!(
                unsafe { *producer },
                base.wrapping_add(committed),
                "origin {origin}: fixture precondition — EVERY explicit commit \
                 the loop above performed must already have reached the \
                 kernel. The quantifier is over EXPLICIT_BATCHES, which the \
                 loop iterates generally; `committed` is its arity-2 sum, so \
                 growing the array without changing that sum reds HERE rather \
                 than passing vacuously — measured (#6832 fold r7): at arity 3 \
                 all four Drop fixtures red at this precondition"
            );
            let first = submitted;
            assert_eq!(
                w.insert((0..dropped_written).map(|k| desc(reuse_payload(first + k)))),
                dropped_written,
                "origin {origin}: the post-commit batch did not fit the \
                 remaining reservation"
            );
            // No second `commit()` — `Drop` owns this batch.
        }
        assert_eq!(
            unsafe { *producer },
            base.wrapping_add(committed + dropped_written),
            "origin {origin}: the producer is not at {committed}+\
             {dropped_written}. The shape this guards: a drop that discards \
             descriptors inserted after an explicit commit, so frames the \
             caller queued are never handed to the kernel"
        );
        assert_eq!(
            tx.ring.cached_prod,
            unsafe { *producer },
            "origin {origin}: cached_prod is not on the kernel producer. The \
             shape this guards: a drop-time cancel that does not cover exactly \
             the unused remainder of the reservation"
        );
        // The drop-submitted descriptor landed in its OWN slot, past the ones
        // the kernel already owns — the same append property the commit path
        // has, on the path where `Drop` rather than `commit` publishes it.
        for j in 0..committed + dropped_written {
            assert_eq!(
                tx_slot(&tx.ring, base.wrapping_add(j)).addr,
                reuse_payload(j),
                "origin {origin}: slot {j} does not hold its own descriptor"
            );
        }
    }
    }
}
#[test]
fn write_fill_drop_submits_a_batch_inserted_after_an_explicit_commit() {
    // Twin of the `WriteTx` fixture above. A fill-ring drop that skipped the
    // submit would strand UMEM frames: the caller has handed them to the fill
    // writer and will not re-post them, but the kernel never sees them, so
    // those RX buffers are lost for the life of the socket.
    for dropped_written in DROP_PARTIALS {
    for origin in CURSOR_ORIGINS {
        let mut dq = DeviceQueue::new_for_test(-1, REUSE_RING_CAPACITY);
        seed_prod_at(dq.rings.fill_mut(), origin);
        let producer = dq.rings.fill().producer;

        let committed = EXPLICIT_BATCHES[0] + EXPLICIT_BATCHES[1];
        
        assert!(
            dropped_written > 0 && dropped_written < REUSE_BATCHES[2],
            "fixture: the final batch must be partly inserted so drop does both \
             a submit and a cancel"
        );
        let base;
        {
            let mut w = dq.fill(REUSE_TOTAL);
            base = w.base_idx;
            assert_eq!(base, origin, "reservation must start at the seeded cursor");
            let mut submitted = 0u32;
            for n in EXPLICIT_BATCHES {
                let first = submitted;
                assert_eq!(
                    w.insert((0..n).map(|k| reuse_payload(first + k))),
                    n,
                    "origin {origin}: a {n}-offset batch did not fit the \
                     remaining reservation"
                );
                w.commit();
                submitted += n;
                // PER-OPERATION checkpoint — see the RX twin above for why an
                // aggregate is not enough (#6832 fold r5).
                assert_eq!(
                    unsafe { *producer },
                    base.wrapping_add(submitted),
                    "origin {origin}: the producer is not at {submitted} after \
                     the explicit commit of a {n}-descriptor batch — the commit \
                     advanced by something other than what it was handed"
                );
            }
            assert_eq!(
                unsafe { *producer },
                base.wrapping_add(committed),
                "origin {origin}: fixture precondition — EVERY explicit commit \
                 the loop above performed must already have reached the \
                 kernel. The quantifier is over EXPLICIT_BATCHES, which the \
                 loop iterates generally; `committed` is its arity-2 sum, so \
                 growing the array without changing that sum reds HERE rather \
                 than passing vacuously — measured (#6832 fold r7): at arity 3 \
                 all four Drop fixtures red at this precondition"
            );
            let first = submitted;
            assert_eq!(
                w.insert((0..dropped_written).map(|k| reuse_payload(first + k))),
                dropped_written,
                "origin {origin}: the post-commit batch did not fit the \
                 remaining reservation"
            );
            // No second `commit()` — `Drop` owns this batch.
        }
        let ring = dq.rings.fill();
        assert_eq!(
            unsafe { *producer },
            base.wrapping_add(committed + dropped_written),
            "origin {origin}: the producer is not at {committed}+\
             {dropped_written}. The shape this guards: a drop that discards \
             fill offsets inserted after an explicit commit, stranding those \
             UMEM frames for the life of the socket"
        );
        assert_eq!(
            ring.cached_prod,
            unsafe { *producer },
            "origin {origin}: cached_prod is not on the kernel producer. The \
             shape this guards: a drop-time cancel that does not cover exactly \
             the unused remainder of the reservation"
        );
        for j in 0..committed + dropped_written {
            assert_eq!(
                fill_slot(ring, base.wrapping_add(j)),
                reuse_payload(j),
                "origin {origin}: slot {j} does not hold its own fill offset"
            );
        }
    }
    }
}
// ── libxdp ring ABI contract (#4976) ─────────────────────────────
//
// The authoritative guard is the `const _` block in `xsk_ffi.rs` (fails
// the build on drift) plus the `_Static_assert`s in `csrc/xsk_bridge.c`
// (fail the build if the *installed* libxdp layout drifts). This runtime
// test restates the same contract as a named, discoverable check: if the
// Rust mirror is ever re-laid-out without updating the contract, the const
// block already refuses to compile this crate — but this test also gives a
// human-readable failure naming the exact field that moved.
#[test]
fn xsk_ring_abi_matches_libxdp_contract() {
    use core::mem::{align_of, offset_of, size_of};

    // 64-bit pointer width underpins the fixed pointer-field offsets.
    assert_eq!(size_of::<*const u32>(), 8, "AF_XDP dataplane is 64-bit only");

    for (name, sz, al) in [
        ("XskRingProd", size_of::<XskRingProd>(), align_of::<XskRingProd>()),
        ("XskRingCons", size_of::<XskRingCons>(), align_of::<XskRingCons>()),
    ] {
        assert_eq!(sz, 48, "{name} size drift vs libxdp DEFINE_XSK_RING");
        assert_eq!(al, 8, "{name} align drift vs libxdp DEFINE_XSK_RING");
    }

    // Field offsets — must match libxdp's `DEFINE_XSK_RING` in xsk.h and
    // the `_Static_assert`s in csrc/xsk_bridge.c.
    assert_eq!(offset_of!(XskRingProd, cached_prod), 0, "prod.cached_prod");
    assert_eq!(offset_of!(XskRingProd, cached_cons), 4, "prod.cached_cons");
    assert_eq!(offset_of!(XskRingProd, mask), 8, "prod.mask");
    assert_eq!(offset_of!(XskRingProd, size), 12, "prod.size");
    assert_eq!(offset_of!(XskRingProd, producer), 16, "prod.producer");
    assert_eq!(offset_of!(XskRingProd, consumer), 24, "prod.consumer");
    assert_eq!(offset_of!(XskRingProd, ring), 32, "prod.ring");
    assert_eq!(offset_of!(XskRingProd, flags), 40, "prod.flags");

    assert_eq!(offset_of!(XskRingCons, cached_prod), 0, "cons.cached_prod");
    assert_eq!(offset_of!(XskRingCons, cached_cons), 4, "cons.cached_cons");
    assert_eq!(offset_of!(XskRingCons, mask), 8, "cons.mask");
    assert_eq!(offset_of!(XskRingCons, size), 12, "cons.size");
    assert_eq!(offset_of!(XskRingCons, producer), 16, "cons.producer");
    assert_eq!(offset_of!(XskRingCons, consumer), 24, "cons.consumer");
    assert_eq!(offset_of!(XskRingCons, ring), 32, "cons.ring");
    assert_eq!(offset_of!(XskRingCons, flags), 40, "cons.flags");
}

// #9726: the helper attaches its own XDP program, so every socket config the
// bridge hands libxdp must carry the header's INHIBIT_PROG_LOAD. The bridge's
// test-only seam routes both create functions to captures that sit where libxdp's
// functions would, record the libxdp_flags of the config they were passed, and
// return -EINVAL without creating a socket. So a create function that passes 0,
// another flag, or a config its fill did not set reds this cell.
#[test]
fn socket_create_passes_inhibit_prog_load_to_libxdp_9726() {
    use core::ptr::null_mut;
    type CreateFn = unsafe extern "C" fn(
        *mut *mut XskSocketOpaque,
        *const c_char,
        u32,
        *mut XskUmemOpaque,
        *mut XskRingCons,
        *mut XskRingProd,
        *mut XskRingProd,
        *mut XskRingCons,
        u32,
        u32,
        u16,
    ) -> c_int;
    let creates: [(&str, CreateFn); 2] = [
        ("private", bridge_xsk_socket_create_private),
        ("shared", bridge_xsk_socket_create_shared),
    ];

    let header = unsafe { bridge_xsk_libxdp_inhibit_prog_load_flag() } as u32;
    let captured: Vec<(&str, c_int, u32)> = creates
        .into_iter()
        .map(|(name, create)| {
            let mut xsk: *mut XskSocketOpaque = null_mut();
            // Enabling resets the captured flags, so each read belongs to this call.
            unsafe { bridge_xsk_capture_socket_create_for_test(1) };
            let rc = unsafe {
                create(
                    &mut xsk,
                    c"xpf-9726-capture".as_ptr(),
                    0,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    0,
                    0,
                    0,
                )
            };
            (name, rc, unsafe { bridge_xsk_captured_libxdp_flags() })
        })
        .collect();
    // Restore libxdp's functions before an assertion can unwind past this cell.
    unsafe { bridge_xsk_capture_socket_create_for_test(0) };

    for (name, rc, flags) in captured {
        assert_eq!(
            rc,
            -libc::EINVAL,
            "the {name} create did not reach libxdp through the capture seam"
        );
        assert_ne!(
            flags, 0,
            "the {name} create lets libxdp load its own XDP program"
        );
        assert_eq!(
            flags, header,
            "the {name} create passes libxdp_flags {flags:#x}, not INHIBIT_PROG_LOAD {header:#x}"
        );
    }
}
