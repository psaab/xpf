//! #15730 TRIPWIRE: the shared-UMEM owner bind must not route through a
//! single-owner-only accessor.
//!
//! Explicitly a source tripwire, not a behavioural test: reaching the
//! real owner create needs a bound AF_XDP socket on hardware. The
//! decision it guards is covered behaviourally by
//! `shared_clone_umem_mut_does_not_panic_15730` /
//! `umem_mut_overlap_is_a_loud_panic_not_an_alias_15730` in
//! `src/afxdp/umem/tests/shared_clone_15730.rs`. What this pins is the
//! wiring on the production path: the accessor is shared-safe, and the
//! owner/private creates reach it through a shared handle. Restoring
//! the single-owner gate in the bind path does not satisfy this.

use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn shared_owner_umem_mut_has_no_single_owner_gate_15730() {
    let umem_rs = read("src/afxdp/umem/mod.rs");

    // The production gate was a call on the UMEM accessor:
    //   Rc::get_mut(&mut self.inner).expect("single-owner umem")
    // Reintroducing that call reintroduces the panic. (Doc comments in
    // umem/mod.rs quote the removed call; the call itself is the gate,
    // so the pin is on the call, not the quoted text.)
    assert!(
        !umem_rs.contains("Rc::get_mut(&mut self.inner"),
        "#15730 RED: WorkerUmem::umem_mut again gates the UMEM on \
         Rc::get_mut; the group builder clones the UMEM before the \
         owner bind, so the gate can never pass for a shared group"
    );
    assert!(
        umem_rs.contains("pub(super) fn umem_mut(&self)"),
        "#15730 RED: umem_mut must take &self so the cloned owner and \
         private-fallback handles can run their bind-time creates; \
         an &mut-self accessor cannot be reached through a shared clone"
    );
}

#[test]
fn owner_and_private_creates_reach_the_umem_through_a_shared_handle_15730() {
    let bind_rs = read("src/afxdp/bind.rs");
    assert!(
        bind_rs.contains("create_xsk_binding_shared_owner("),
        "#15730 RED: the shared owner no longer dispatches to its \
         owner create (wiring regression)"
    );
    assert!(
        bind_rs.contains("&mut worker_umem.umem_mut()"),
        "#15730 RED: the owner/private creates must borrow the UMEM \
         through WorkerUmem::umem_mut on a shared (&self) handle; \
         reverting to an exclusive handle reintroduces the panic"
    );
}
