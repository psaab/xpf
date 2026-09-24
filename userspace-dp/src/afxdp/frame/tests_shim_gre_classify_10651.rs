// #10651: the shim's native-GRE kernel-pass decision, EXECUTED.
//
// The native-GRE arm classifies the INNER packet and, on an inner-tuple
// `PASS_TO_KERNEL` steering hit, used to hand the OUTER GRE frame to the
// kernel with no outer-destination predicate — so a GRE frame addressed
// to a host beyond this firewall was kernel-forwarded with no zone policy
// while the inner was never adjudicated.
//
// WHY THIS FILE INCLUDES THE SHIM'S SOURCE AND RUNS IT: same shape as
// `tests_shim_wg_classify_8274.rs` — the shim is `no_std` for
// `bpfel-unknown-none` and cannot be executed by a host test, and modeled
// tests leak to ordinary edits (the ext-parity record). The verdict lives
// in the `core`-only `gre_classify` module the shim calls; this file pulls
// that file in by source and runs the full truth table.
#[path = "../../../../userspace-xdp/src/gre_classify.rs"]
mod shim_gre;

use shim_gre::native_gre_inner_pass_steers_to_kernel;

/// The full 2x2: only (local outer, PASS inner) steers to the kernel.
/// Every other combination stays on the userspace path for decap and
/// adjudication. Deleting the outer conjunct (the pre-fix shape) flips
/// the second row green-to-red.
#[test]
fn native_gre_kernel_pass_requires_a_local_outer_10651() {
    // (outer local, inner PASS, steers to kernel, why)
    let cases = [
        (
            true,
            true,
            true,
            "local outer + inner PASS: the only shape that reaches the kernel",
        ),
        (
            false,
            true,
            false,
            "non-local outer + inner PASS: must stay for decap/adjudication (#10651)",
        ),
        (
            true,
            false,
            false,
            "local outer + inner REDIRECT/miss: userspace owns the inner",
        ),
        (
            false,
            false,
            false,
            "non-local outer + inner REDIRECT/miss: userspace path",
        ),
    ];
    for (outer_local, inner_pass, steers, why) in cases {
        assert_eq!(
            native_gre_inner_pass_steers_to_kernel(outer_local, inner_pass),
            steers,
            "{why}"
        );
    }
}
