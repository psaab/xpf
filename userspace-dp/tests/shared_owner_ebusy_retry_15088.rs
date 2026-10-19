//! #15088 (A61-02) TRIPWIRE: shared-owner EBUSY handling.
//!
//! Explicitly a source tripwire, not a behavioural test: forcing a real
//! `-EBUSY` from the kernel's deferred XSK pool release needs a bound
//! AF_XDP socket on hardware, so the wiring is pinned here while the
//! decisions it invokes are covered behaviourally —
//! `ebusy_retry_allowed` / `create_mode` by `bind_owner_retry_15088_tests`
//! in `src/afxdp/bind.rs`, the NULL fill/comp hand-off by
//! `shared_owner_bridge_passes_null_fill_comp_15088` in
//! `src/xsk_ffi_tests.rs` (through the #9726 capture seam), and the
//! borrowed ring ownership by
//! `shared_owner_rings_borrow_umem_secondary_rings_owned_15088`.
//! What this pins is that the mechanisms are WIRED on the production
//! path: the owner dispatches to the owner create, and the EBUSY retry
//! is gated on the role. Deleting the gate (retrying every role again)
//! or merging the owner back into the secondary create does not satisfy
//! this.

use std::path::Path;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn shared_owner_never_retries_ebusy_on_same_umem_15088() {
    let bind_rs = read("src/afxdp/bind.rs");

    // The owner role must dispatch to the dedicated owner create.
    assert!(
        bind_rs.contains("create_xsk_binding_shared_owner("),
        "#15088 RED: src/afxdp/bind.rs never dispatches the shared owner \
         to create_xsk_binding_shared_owner; the owner would again be \
         created with per-socket fill/comp structs whose failure path \
         munmaps the UMEM's only FILL/COMP mapping — see psaab/xpf#15088"
    );

    // The EBUSY retry must be gated on the role, not unconditional.
    assert!(
        bind_rs.contains("ebusy_retry_allowed(socket_role)"),
        "#15088 RED: try_open_bind retries EBUSY without consulting \
         ebusy_retry_allowed(socket_role); a failed owner create would \
         again be retried on the same (unmapped) UMEM"
    );
    let gate_pos = bind_rs
        .find("ebusy_retry_allowed(socket_role)")
        .expect("gate call present (asserted above)");
    let busy_pos = bind_rs
        .find("\"Device or resource busy\"")
        .expect("tripwire stale: EBUSY string moved; update this pin");
    assert!(
        gate_pos < busy_pos,
        "#15088 RED: the role gate must precede the EBUSY retry decision \
         (gate at {gate_pos}, busy check at {busy_pos})"
    );
}

#[test]
fn shared_owner_create_passes_null_fill_comp_to_libxdp_15088() {
    let bridge_c = read("csrc/xsk_bridge.c");
    assert!(
        bridge_c.contains("bridge_xsk_socket_create_shared_owner"),
        "#15088 RED: csrc/xsk_bridge.c has no owner bridge; libxdp would \
         again receive per-socket fill/comp structs for the owner"
    );
    assert!(
        bridge_c.contains("rx, tx, NULL, NULL, &cfg)"),
        "#15088 RED: the owner bridge must pass NULL fill/comp so libxdp \
         substitutes the UMEM's fill_save/comp_save and takes the \
         unmap == false error path on a failed create"
    );

    let bind_rs = read("src/afxdp/bind.rs");
    assert!(
        bind_rs.contains("SharedOwner => xsk_ffi::XskCreateMode::SharedOwnerUmem"),
        "#15088 RED: SharedOwner no longer maps to SharedOwnerUmem; the \
         owner would again share the secondary's per-socket create mode"
    );
}
