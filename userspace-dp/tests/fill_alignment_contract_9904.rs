//! F-069 (#9904) TRIPWIRE: fill-alignment contract cited beside the code.
//!
//! Explicitly a doc tripwire, and the fix IS the doc: the AF_XDP core
//! aligned-chunk masking contract (`xp_check_aligned` — the kernel masks
//! FILL-ring addresses to the chunk base in aligned mode) is load-bearing
//! for the RX-recycle path (which pushes headroom-shifted `desc.addr`
//! verbatim) but was nowhere written down. This cell REDs until
//! `afxdp/umem/README.md` cites it. The `flags == 0` precondition the
//! citation rests on is pinned in code by
//! `umem::create_flags_9904_tests`.

use std::path::Path;

#[test]
fn umem_readme_cites_fill_alignment_contract_9904() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let readme = Path::new(manifest_dir).join("src/afxdp/umem/README.md");
    let text = std::fs::read_to_string(&readme)
        .unwrap_or_else(|e| panic!("read {}: {e}", readme.display()));
    assert!(
        text.contains("xp_check_aligned"),
        "F-069 (#9904) RED: src/afxdp/umem/README.md does not cite the \
         AF_XDP core alignment contract (`xp_check_aligned`) that the \
         headroom-shifted RX-recycle path relies on; see issue psaab/xpf#9904"
    );
}
