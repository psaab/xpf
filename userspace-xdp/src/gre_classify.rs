//! #10651: the shim's native-GRE kernel-pass decision.
//!
//! The native-GRE arm classifies the INNER packet and, on an inner-tuple
//! `PASS_TO_KERNEL` steering hit — a peer-synced LocalDelivery row under HA —
//! hands the OUTER GRE frame to the kernel. Before this fix it did so with no
//! outer-destination predicate, so a GRE frame addressed to a host BEYOND this
//! firewall was kernel-forwarded with no zone policy while the inner was never
//! adjudicated. #304 gave the non-native arms destination predicates; the
//! native arm never got one.
//!
//! The fix: the outer frame reaches the kernel only when the OUTER destination
//! is itself local. A non-local outer stays on the userspace path for decap
//! and adjudication, whatever the inner classified to.
//!
//! # Why this is a module and not one line inside the GRE arm
//!
//! The shim cannot be executed by a host test: it is `no_std`, built for
//! `bpfel-unknown-none`. `tests_shim_ext_parity.rs` records what happens when a
//! shim property is guarded by a test that MODELS the shim from source text
//! instead — five successive models, each leaking to a more ordinary edit than
//! the last, including one that accepted the deletion of a security property.
//! Its resolution was to move the walk into a `core`-only module
//! (`ipv6_ext_walk.rs`) that the shim calls and a host test pulls in BY SOURCE
//! PATH and RUNS. (Described, not spelled: the #5173 confinement refusal walks
//! this directory for the attribute token itself, and prose that spells it is a
//! false red — the convention this file follows is the one stated at the top of
//! `ipv6_ext_walk.rs`.)
//!
//! This module is that shape, for the same reason. The decision below is the
//! security boundary of #10651 — it is what decides whether a non-local outer
//! frame is forwarded by the kernel with no adjudication at all — so it is
//! executed by the host test, on the real truth table, rather than asserted
//! about.

/// Must the OUTER GRE frame be handed to the kernel?
///
/// Both inputs are load-bearing and refer to different packets: outer
/// destination locality comes from the GRE frame, while the session action
/// comes from classifying its inner tuple. A peer-synced inner
/// `PASS_TO_KERNEL` row does not authorize kernel forwarding of a non-local
/// outer frame.
pub const USERSPACE_SESSION_ACTION_PASS_TO_KERNEL: u8 = 2;

/// The output of the shim's OUTER packet locality check.
///
/// Distinct from `InnerSessionAction` so a caller cannot silently exchange
/// the two inputs at the GRE dispatch boundary.
#[derive(Clone, Copy)]
pub struct OuterDestinationLocal(bool);

impl OuterDestinationLocal {
    #[inline(always)]
    pub fn from_is_local_destination(is_local: bool) -> Self {
        Self(is_local)
    }
}

/// The result of classifying the GRE INNER tuple.
///
/// This carries the classifier's action, not a caller-provided `true` from
/// the `PASS_TO_KERNEL` match arm. Keeping the action distinct from outer
/// locality makes a swapped dispatch argument a compile error.
#[derive(Clone, Copy)]
pub struct InnerSessionAction(u8);

impl InnerSessionAction {
    #[inline(always)]
    pub fn from_classifier_action(action: u8) -> Self {
        Self(action)
    }
}

/// The core truth-table predicate, retained for its host-executed module test.
#[inline(always)]
pub fn native_gre_inner_pass_steers_to_kernel(
    outer_is_local_destination: bool,
    inner_is_pass_to_kernel: bool,
) -> bool {
    outer_is_local_destination && inner_is_pass_to_kernel
}

/// The production dispatch boundary. Distinct argument types reject a
/// swapped outer-locality / inner-action call at compile time.
#[inline(always)]
pub fn native_gre_inner_pass_steers_to_kernel_typed(
    outer_is_local_destination: OuterDestinationLocal,
    inner_action: InnerSessionAction,
) -> bool {
    native_gre_inner_pass_steers_to_kernel(
        outer_is_local_destination.0,
        inner_action.0 == USERSPACE_SESSION_ACTION_PASS_TO_KERNEL,
    )
}
