// #16184: the Rc-clone `UmemAreaHandle` keeps the mmap'd area alive
// and byte-identical after the owning `WorkerUmem` is dropped.
//
// Before the handle existed this path threaded a raw area pointer
// cast out of `binding.umem`; soundness rested only on a comment
// contract. The handle makes the lifetime structural: it owns an
// `Rc<WorkerUmemInner>` clone, so dropping every other handle can
// never unmap the region while a handle holder is still reading it.
//
// Fail-on-revert: replace `UmemAreaHandle { umem: WorkerUmem }`
// with a raw-pointer field (or drop the clone in `from_umem`) and
// the drop-then-read cell below dereferences an unmapped region;
// make `area()` mint from any other allocation and the pointer
// identity / slice-byte assertions fail.

use super::*;

#[test]
fn area_handle_clone_shares_the_same_allocation_16184() {
    let umem = WorkerUmem::new_for_test(64).expect("build hermetic worker umem");
    let handle = UmemAreaHandle::from_umem(&umem);
    let clone = handle.clone();
    // Same `Rc<WorkerUmemInner>` allocation, addressed identically
    // through the owning handle and through both handle clones.
    assert!(std::ptr::eq(handle.area(), umem.area()));
    assert!(std::ptr::eq(clone.area(), umem.area()));
    assert!(handle.umem.shares_allocation_with(&umem));
    assert!(clone.umem.shares_allocation_with(&handle.umem));
}

#[test]
fn area_handle_outlives_the_owning_umem_16184() {
    let handle = {
        let umem = WorkerUmem::new_for_test(64).expect("build hermetic worker umem");
        let handle = UmemAreaHandle::from_umem(&umem);
        // Write a marker through the owner's area while it lives.
        let marker = [0xA5u8; 8];
        unsafe {
            umem.area()
                .slice_mut_unchecked(0, marker.len())
                .expect("marker slice")
                .copy_from_slice(&marker);
        }
        // `umem` (the last non-handle owner) drops here. With the
        // raw-pointer form the region would now rely on an unstated
        // outlives contract; the handle's Rc clone keeps the
        // `WorkerUmemInner` — and therefore the mmap — alive.
        handle
    };
    // Fresh frame at offset 4096 must be readable (zeros) and the
    // marker frame must still read back byte-identical.
    let first = handle
        .area()
        .slice(0, 8)
        .expect("marker frame must survive the owner drop");
    assert_eq!(first, &[0xA5u8; 8]);
    let second = handle
        .area()
        .slice(4096, 8)
        .expect("second frame must be mapped through the handle");
    assert_eq!(second, &[0u8; 8]);
}
