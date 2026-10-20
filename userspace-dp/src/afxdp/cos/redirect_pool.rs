// #6310: per-worker copy-buffer pool for the cross-worker CoS
// prepared-redirect path.
//
// The two cross-binding prepared-redirect sites in `cross_binding.rs`
// (`redirect_prepared_cos_request_to_owner{,_binding}`) must hand OWNED
// bytes to the owner worker: the source UMEM frame is recycled the
// instant the request is enqueued (see
// `recycle_prepared_immediately_with_shared`), but the owner worker
// consumes the bytes ASYNCHRONOUSLY on its own thread — it drains the
// per-binding `pending_tx` MPSC inbox, re-ingests the request into a CoS
// queue, and only copies the bytes into a UMEM TX frame at drain/settle
// time (`copy_from_slice(&req.bytes)`). The copy is therefore genuinely
// required (a shared scratch reused per-packet would be overwritten
// before the owner reads it, and shared-UMEM is not universal, so an
// offset hand-off is not always sound). Before this fix each redirect
// paid a fresh `frame.to_vec()` heap allocation at packet rate on the
// cross-worker arm — the same warmed-path allocation class as the CoS
// cohort #4972 / #4973 / #5189, but these two sites were never
// enumerated there.
//
// The pool is a bounded, per-worker THREAD-LOCAL free-list of byte
// buffers. `checkout` copies a source frame into a reusable allocation;
// `checkout_with_capacity` gives builders empty owned storage to fill.
// `recycle` returns a buffer only after it is dead: forwarded NAT64
// buffers are returned after TX copies them into UMEM, while CoS local-TX
// and cross-worker redirect buffers are returned at their existing settle
// points. The pool caps retained buffers and allocates on a cold/depleted
// checkout; warmed workers reuse completed packet storage.
//
// Soundness of the cross-worker hand-off: the pool is thread-local, so
// no two workers ever touch the same pool. A checked-out buffer is
// MOVED into the `TxRequest` and travels to the owner inside the
// single-owner MPSC inbox; the owner later MOVES its bytes into its OWN
// thread-local pool at settle. Ownership is always exclusive (Rust move
// semantics + the inbox single-consumer invariant): no aliasing, no
// data race, no use-after-free. Buffers migrate from redirect sources to
// owners; under the symmetric cross-worker CoS spread this fix targets
// (every worker both sources redirects and owns shaped queues) each
// worker's pool stays replenished and the warmed redirect path is
// allocation-free. A pathologically asymmetric pattern just falls back
// to allocating on the depleted side and caps the buffer count on the
// other — bounded and self-healing, never incorrect.

use std::cell::RefCell;

/// Upper bound on pooled buffers per worker thread. At ~MTU each this
/// caps the pool at a couple of MB per worker; excess buffers are
/// dropped (freed) rather than retained.
const MAX_POOLED_BUFFERS: usize = 1024;

thread_local! {
    static POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Check out a buffer holding a fresh copy of `src`. Reuses a pooled
/// allocation (retained capacity) when the per-worker pool is non-empty,
/// otherwise allocates. The result is byte-for-byte and length-identical
/// to `src.to_vec()` and never aliases `src`.
#[inline]
pub(in crate::afxdp) fn checkout(src: &[u8]) -> Vec<u8> {
    let mut buf = checkout_with_capacity(src.len());
    buf.extend_from_slice(src);
    buf
}

/// Check out a reusable empty buffer with at least `capacity` bytes available.
/// It is intended for builders that write directly into owned queued storage.
#[inline]
pub(in crate::afxdp) fn checkout_with_capacity(capacity: usize) -> Vec<u8> {
    POOL.with(|pool| {
        let mut buf = pool.borrow_mut().pop().unwrap_or_default();
        buf.clear();
        if buf.capacity() < capacity {
            buf.reserve_exact(capacity);
        }
        buf
    })
}

/// #15956: publish `capacity` bytes of a pooled checkout's spare capacity
/// as the Vec's length WITHOUT the `resize(capacity, 0)` zero-fill pass,
/// for reused-buffer builders that overwrite the bytes they publish.
///
/// Contract with the caller (the NAT64 build sites in `frame/mod.rs` and
/// `poll_descriptor/nat64_icmp_error.rs`): the builder is one of the
/// `crate::nat64::build_*_frame_into` family. Each writes the Ethernet
/// header and every L3 byte in `0..written` (header fields first, payload
/// copy, then checksums computed over bytes it just wrote — no translator
/// reads `dst` before writing the byte it later checksums), and returns
/// `Some(written)` with `written <= capacity` or `None`. This helper only
/// changes how `0..capacity` becomes addressable: instead of zero-filling
/// the whole window, it exposes the already-owned spare capacity. The
/// caller then `truncate`s to `written`, so bytes in `written..capacity`
/// are never read as Vec elements, and on `None` the caller recycles the
/// Vec (whose next checkout `clear()`s it) without publishing anything.
///
/// Soundness rests on that contract, pinned by the fail-on-revert corpus
/// in `tests_nat_rewrite.rs`: forward / reverse / non-first / ICMP-error
/// NAT64 builds over a `0xEE`-poisoned tail must stay byte-identical to
/// the zero-filled build. If a future translator ever read an unwritten
/// byte of `dst`, that corpus — not this comment — is what catches it.
///
/// `buf` must come from [`checkout_with_capacity`] with the same
/// `capacity` (length 0, capacity >= `capacity`).
#[inline]
pub(in crate::afxdp) fn extend_pooled_for_build(buf: &mut Vec<u8>, capacity: usize) {
    debug_assert_eq!(buf.len(), 0, "build checkout must start empty");
    debug_assert!(buf.capacity() >= capacity, "checkout under capacity");
    let spare_len = buf.spare_capacity_mut().len();
    assert!(
        spare_len >= capacity,
        "pooled checkout spare capacity below build capacity"
    );
    // SAFETY: `spare_capacity_mut()[..capacity]` is owned, writable spare
    // capacity of `buf`. Per the contract above the consuming builder
    // initializes every byte in `0..written` before the caller truncates
    // to `written` and publishes the Vec; bytes beyond `written` are
    // never read, and the failure path recycles without publishing.
    unsafe {
        buf.set_len(capacity);
    }
}

/// Return a finished local-TX buffer to the per-worker pool for reuse.
/// The caller MUST be done with `buf` — its bytes already copied into a
/// UMEM TX frame — so the buffer is dead. Drops the buffer if the pool
/// is at its cap.
#[inline]
pub(in crate::afxdp) fn recycle(buf: Vec<u8>) {
    POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if pool.len() < MAX_POOLED_BUFFERS {
            pool.push(buf);
        }
    });
}

#[cfg(test)]
pub(in crate::afxdp) fn clear_for_test() {
    POOL.with(|pool| pool.borrow_mut().clear());
}

#[cfg(test)]
pub(in crate::afxdp) fn len_for_test() -> usize {
    POOL.with(|pool| pool.borrow().len())
}
