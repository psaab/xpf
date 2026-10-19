// #15730: a `WorkerUmem` whose `Rc` is shared must not panic in
// `umem_mut()`.
//
// The shared-UMEM group builder (`create_shared_binding_group`) clones
// one `WorkerUmem` for every member binding. The OWNER binding then
// creates its socket through `create_xsk_binding_shared_owner(&mut Umem)`
// (and the private fallback through `create_xsk_binding_private`), both
// of which reached the UMEM through `WorkerUmem::umem_mut`. Before the
// fix that accessor was `Rc::get_mut(..).expect("single-owner umem")`,
// which is `None` the moment a second clone exists — so the owner bind
// panicked deterministically under the default CrossNic shared-UMEM
// policy (after the zero-copy attempt reported EINVAL, so the copy-mode
// fallback never ran) and the helper never armed. `new_for_test` builds
// a hermetic UMEM (null libxdp handle, no kernel socket), so these cells
// exercise the exact accessor on the exact cloned shape the group
// builder produces, without CAP_NET_ADMIN or AF_XDP hardware.

use super::*;

#[test]
fn shared_clone_umem_mut_does_not_panic_15730() {
    // Mutable bindings so this cell panics rather than merely failing to
    // compile when the pre-fix `&mut self` + `Rc::get_mut` accessor is
    // restored: fail-on-revert is the panic, not a type error.
    let mut owner = WorkerUmem::new_for_test(64).expect("build hermetic worker umem");
    let mut secondary = owner.clone();
    let mut tertiary = owner.clone();
    assert!(owner.shares_allocation_with(&secondary));
    assert!(owner.shares_allocation_with(&tertiary));

    // The exact step that panicked at umem/mod.rs:106. Through a clone
    // (the secondary's handle), through the owner, and through the
    // original — every shared handle must be able to run the bind-time
    // create, in sequence, as the group builder does.
    {
        let mut guard = secondary.umem_mut();
        let _ = guard.fill_comp_rings_mut();
    }
    {
        let mut guard = owner.umem_mut();
        let _ = guard.fill_comp_rings_mut();
    }
    {
        let mut guard = tertiary.umem_mut();
        let _ = guard.fill_comp_rings_mut();
    }

    // Non-mutating reads through the same shared handles still work
    // (the pool builder's `umem().frame(..)` enumeration).
    assert!(owner.umem().frame(BufIdx(0)).is_some());
    assert!(secondary.umem().frame(BufIdx(1)).is_some());
    // The secondary create's raw pointer is readable from any clone.
    let _ = secondary.as_raw_umem_ptr();
}

#[test]
fn umem_mut_overlap_is_a_loud_panic_not_an_alias_15730() {
    let mut umem = WorkerUmem::new_for_test(64).expect("build hermetic worker umem");
    let mut clone = umem.clone();

    // Two simultaneously-live `&mut Umem` would alias the libxdp ring
    // state. The fix must keep that a loud (RefCell) panic — it must not
    // succeed by handing out a second mutable borrow, which would be UB
    // at the FFI boundary.
    let first = umem.umem_mut();
    let overlap = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _second = clone.umem_mut();
    }));
    drop(first);
    assert!(
        overlap.is_err(),
        "#15730: a second umem_mut while one is live must panic (RefCell \
         exclusion), never alias the UMEM ring state"
    );

    // After the first borrow is released, a fresh one succeeds — the
    // sequential private-bind pattern (zero-copy attempt, then copy
    // attempt on the same UMEM).
    let mut guard = clone.umem_mut();
    let _ = guard.fill_comp_rings_mut();
}
