//! Preallocated per-worker scratch buffers for the WG hot path.
//!
//! No `vec![]` in encap/decap. The buffers are sized once at
//! worker init and reused for every packet. Capacity is taken
//! from the worker's max-frame size — the UMEM frame is
//! `UMEM_FRAME_SIZE` (4096) in `afxdp/mod.rs:175`; the WG module
//! takes the size as an explicit `max_frame: usize` parameter so it
//! does not have to import the rest of `afxdp/`. The integration PR
//! will wire `WgWorkerScratch::new(UMEM_FRAME_SIZE as usize)` (or a
//! smaller worker-specific cap) from the dispatch side.

use std::cell::RefCell;

/// One-per-worker scratch. Holds buffers used by `try_encap` and
/// `try_decap`. The cells are entered exclusively per packet
/// (worker is single-threaded inside its poll loop), so `RefCell`
/// is sufficient and avoids any `unsafe`.
pub(crate) struct WgWorkerScratch {
    /// Output buffer for `try_encap`. Sized to `max_frame`.
    #[expect(dead_code, reason = "test-only encap buffer; production encap writes caller buffers (#17212)")]
    pub(crate) encap_out: RefCell<Vec<u8>>,
    /// Output buffer for `try_decap` (decrypted plaintext). Sized
    /// to `max_frame` (decap output is strictly smaller than the
    /// input, but a single sizing keeps the allocator quiet).
    pub(crate) decap_out: RefCell<Vec<u8>>,
}

impl WgWorkerScratch {
    pub(crate) fn new(max_frame: usize) -> Self {
        Self {
            encap_out: RefCell::new(vec![0u8; max_frame]),
            decap_out: RefCell::new(vec![0u8; max_frame]),
        }
    }
}

#[cfg(test)]
mod scratch_tests {
    use super::*;

    #[test]
    fn sizes_match_max_frame() {
        let s = WgWorkerScratch::new(2048);
        assert_eq!(s.encap_out.borrow().len(), 2048);
        assert_eq!(s.decap_out.borrow().len(), 2048);
    }

    #[test]
    fn reuse_does_not_reallocate() {
        // The contract is that we never reallocate. We verify by
        // capturing the buffer's pointer and checking it after a
        // sequence of in-place writes — if the Vec ever grew via
        // a reallocation, the pointer would change.
        let s = WgWorkerScratch::new(1500);
        let initial_ptr = s.encap_out.borrow().as_ptr();
        for _ in 0..32 {
            let mut buf = s.encap_out.borrow_mut();
            buf[0] = 0xaa;
            buf[1499] = 0xbb;
        }
        let after_ptr = s.encap_out.borrow().as_ptr();
        assert_eq!(initial_ptr, after_ptr);
    }
}
