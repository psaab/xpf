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
//
// #10865 scoped redirect-only note: the shim's
// `classify_native_gre_inner` currently reads only the 4-byte, unflagged GRE
// header and returns a classifier miss when C/K/S flags are present. Those
// keyed / checksummed / sequenced packets are therefore NOT shim-classified
// for kernel delivery; the native-GRE arm's miss path continues to XSK for
// userspace decap and policy. The following executed truth table pins that
// all non-PASS results (including that flag-induced miss) stay userspace.
#[path = "../../../../userspace-xdp/src/gre_classify.rs"]
mod shim_gre;

use shim_gre::{
    InnerSessionAction, OuterDestinationLocal, degraded_general_local_pass_applies,
    native_gre_inner_pass_steers_to_kernel, native_gre_inner_pass_steers_to_kernel_typed,
};

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
            "local outer + keyed-GRE classifier miss: stays on XSK redirect path",
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

/// #14327: the degraded path's general local pass must not claim a
/// native-GRE frame before the #10651 inner gate runs.
///
/// This composes the two host-executed predicates exactly as
/// `is_degraded_local_or_control` does after its early/NDP arms: the
/// general local pass first (via `degraded_general_local_pass_applies`),
/// then, for native GRE, the typed inner gate. The pre-fix shim returned
/// `true` from the unconditional `if destination_is_local` arm, so every
/// outer-local row below steered to the kernel regardless of the inner
/// action; reverting the guard to `destination_is_local` alone flips the
/// first two rows red.
///
/// Session actions mirror the shim's constants: 0 = classifier miss,
/// 1 = REDIRECT, 2 = PASS_TO_KERNEL.
#[test]
fn degraded_native_gre_local_outer_requires_inner_pass_14327() {
    fn degraded_passes(
        is_native_gre: bool,
        destination_is_local: bool,
        inner_action: u8,
    ) -> bool {
        if degraded_general_local_pass_applies(is_native_gre, destination_is_local) {
            return true;
        }
        if is_native_gre {
            return native_gre_inner_pass_steers_to_kernel_typed(
                OuterDestinationLocal::from_is_local_destination(destination_is_local),
                InnerSessionAction::from_classifier_action(inner_action),
            );
        }
        false
    }

    // (native GRE, outer local, inner action, passes to kernel, why)
    let cases = [
        (
            true,
            true,
            0,
            false,
            "native GRE, local outer, inner miss: must drop, not kernel-pass (#14327)",
        ),
        (
            true,
            true,
            1,
            false,
            "native GRE, local outer, inner REDIRECT: inner stays in userspace (#14327)",
        ),
        (
            true,
            true,
            2,
            true,
            "native GRE, local outer, inner PASS_TO_KERNEL: proven local delivery passes",
        ),
        (
            true,
            false,
            2,
            false,
            "native GRE, non-local outer, inner PASS: #10651 outer gate still refuses",
        ),
        (
            true,
            false,
            0,
            false,
            "native GRE, non-local outer, inner miss: drops",
        ),
        (
            false,
            true,
            0,
            true,
            "non-native-GRE local packet: degraded general local pass unchanged",
        ),
        (
            false,
            false,
            0,
            false,
            "non-native-GRE transit packet: no degraded pass",
        ),
    ];
    for (native, local, inner, passes, why) in cases {
        assert_eq!(degraded_passes(native, local, inner), passes, "{why}");
    }
}
