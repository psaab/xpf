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

/// #14327: may the degraded path's general local-destination arm pass
/// this packet to the kernel without consulting the native-GRE gate?
///
/// `is_degraded_local_or_control` passes genuinely local traffic to the
/// kernel during a degraded window. But a native-GRE frame's OUTER
/// destination is the local tunnel endpoint by construction, so an
/// unconditional local pass hands the outer frame to the kernel before
/// the #10651 arm can classify the INNER packet: inner transit the
/// healthy path would keep in userspace (inner action != PASS_TO_KERNEL)
/// is decapsulated and forwarded by the kernel with no zone policy.
///
/// Native-GRE frames therefore decline the general local pass here and
/// fall through to the #10651 typed gate, which reaches the kernel only
/// when the inner action is PASS_TO_KERNEL. Every non-native-GRE local
/// packet keeps the degraded local pass exactly as before. Non-native
/// GRE (native flag clear) is not userspace-owned, so it also keeps the
/// general pass; kernel termination remains its disposition.
///
/// Both inputs are caller-computed scalars: `is_native_gre` is
/// `protocol == PROTO_GRE && (ctrl.flags & NATIVE_GRE) != 0` and
/// `destination_is_local` is the shim's exact `is_local_destination`
/// verdict. This module owns only the conjunction, per the module shape
/// above, so the host test executes the real decision.
#[inline(always)]
pub fn degraded_general_local_pass_applies(
    is_native_gre: bool,
    destination_is_local: bool,
) -> bool {
    destination_is_local && !is_native_gre
}

/// #14645: must a native-GRE outer fragment be kept on the userspace (XSK)
/// path instead of a kernel pass? `protocol`/`wire_protocol` are the parsed
/// and pre-substitution protocols; `is_fragment` separates a fragmented
/// datagram from a whole one (a whole GRE packet keeps its ordinary
/// disposition and is never buffered). A non-first fragment carries the
/// #7494 sentinel (255) with the wire protocol still GRE; a first fragment
/// keeps GRE. For both, the answer is yes when native GRE is armed: a local
/// tail has no kernel GRE terminator (the tunnel netdev is a TUN anchor),
/// and an interface-NAT tail must follow its head into the helper, which
/// reassembles before decap. Host-executed by the userspace-dp test.
#[inline(always)]
pub fn native_gre_fragment_stays_on_helper(
    protocol: u8,
    wire_protocol: u8,
    is_fragment: bool,
    native_gre_armed: bool,
) -> bool {
    native_gre_armed
        && is_fragment
        && ((protocol == 47 && wire_protocol == 47) || (protocol == 255 && wire_protocol == 47))
}

/// #15102: must a WireGuard outer fragment be kept on the userspace (XSK)
/// path instead of a kernel pass? `protocol`/`wire_protocol` are the parsed
/// and pre-substitution protocols; `is_fragment` separates a fragmented
/// datagram from a whole one. A first fragment keeps UDP (and, when it is a
/// transport-data record to a steered listener, `wg_worker_claim` already
/// claims it); this predicate's load-bearing row is the TAIL: protocol 255
/// with wire protocol UDP. The tail carries no port and no record type, so
/// the shim cannot prove it is WG — it keeps EVERY UDP tail on the helper,
/// where the worker buffers it only if the head was already admitted to a
/// configured listener (see `is_wg_fragment_candidate`); every other UDP
/// tail is then adjudicated as an ordinary fragment by downstream stages,
/// never kernel-passed merely for being a tail. `wg_rx_armed` is the
/// `USERSPACE_CTRL_FLAG_WG_RX` state: with no WG tunnel configured there
/// is no listener to reassemble for and tails keep today's disposition.
/// Host-executed by the userspace-dp test.
#[inline(always)]
pub fn wg_fragment_stays_on_helper(
    protocol: u8,
    wire_protocol: u8,
    is_fragment: bool,
    wg_rx_armed: bool,
) -> bool {
    wg_rx_armed
        && is_fragment
        && ((protocol == 17 && wire_protocol == 17) || (protocol == 255 && wire_protocol == 17))
}

/// #14954: may the native-GRE inner classifier build a session key from
/// this inner packet, or must it miss (return 0, stay in userspace)?
///
/// The classifier runs BEFORE the worker decapsulates: a hit can steer
/// the OUTER frame to the kernel (`PASS_TO_KERNEL`) or to the helper
/// (`REDIRECT`) without the inner ever being adjudicated, so every
/// property the worker would enforce on the inner must be enforced
/// here first. Three fail-open gaps are closed together because they
/// share one verdict:
///
/// * FRAGMENTED inner — an IPv4 fragment field with MF set or a
///   non-zero offset, or an IPv6 chain that sighted a non-atomic
///   Fragment header (offset != 0 or M set), has no complete L4 header
///   in this packet; ports read from it are payload bytes.
/// * DECLARED LENGTH — the readable L4 span must lie inside the inner
///   datagram's declared end (`total_len` for v4, `40 + payload_len`
///   for v6, measured from the inner L3 start). Slack past it is
///   Ethernet pad / outer trailer promoted by the outer trim, not
///   inner bytes. A declared end past the capture (lying-long) is
///   bounded by the capture reads themselves, exactly as the shim's
///   outer parsers treat it.
/// * LAND — inner src == inner dst. The healthy/degraded outer LAND
///   drops compare the OUTER addresses; a GRE inner with equal
///   addresses rides a `PASS_TO_KERNEL` hit to the kernel decapsulated
///   with no screen ever seeing the inner.
///
/// `inner_is_fragment` is caller-computed: v4 from the fragment field,
/// v6 from the shared walk (`fragment_seen` excludes atomic headers, so
/// a whole datagram carrying an atomic Fragment header still classifies
/// — the worker's `packet_trimmed_len`/`parse_inner_protocol_and_offsets`
/// treat it the same way). `l4_span_start`/`l4_span_len` are the span
/// the caller is about to read for the tuple (0 length = no L4 read for
/// this protocol, so the length gate is vacuous for the span — the
/// header itself was already read inside the declared minimums the
/// caller checked). Address slices are the fixed 16-byte shim shape
/// (v4 in the first 4 bytes, zero-padded), family-correct for one
/// comparison.
#[inline(always)]
pub fn gre_inner_classify_allowed(
    inner_is_fragment: bool,
    inner_src_addr: &[u8; 16],
    inner_dst_addr: &[u8; 16],
    inner_l3_offset: usize,
    declared_end: usize,
    l4_span_start: usize,
    l4_span_len: usize,
) -> bool {
    if inner_src_addr == inner_dst_addr {
        return false;
    }
    !gre_inner_fragment_or_length_rejected(
        inner_is_fragment,
        inner_l3_offset,
        declared_end,
        l4_span_start,
        l4_span_len,
    )
}

/// #14954 scalar half of [`gre_inner_classify_allowed`]: the fragment and
/// declared-length verdicts without the address comparison.
///
/// The shim's call sites judge LAND separately (a direct address
/// comparison on the key they just built) and call this half for the
/// fragment/length verdicts with inner-L3-relative offsets, so no
/// packet-derived absolute offset crosses into the comparison. The
/// combined wrapper above is exactly LAND + this half, and the host
/// test executes both.
#[inline(always)]
pub fn gre_inner_fragment_or_length_rejected(
    inner_is_fragment: bool,
    inner_l3_offset: usize,
    declared_end: usize,
    l4_span_start: usize,
    l4_span_len: usize,
) -> bool {
    if inner_is_fragment {
        return true;
    }
    if l4_span_len == 0 {
        return false;
    }
    // rejected iff the span ends past the declared end (or the declared
    // end does not even cover the header). One subtraction chain rather
    // than checked_add + two compares — same verdict for every input,
    // including span overflow (start+len wraps past usize::MAX only
    // when len > 0 and start is huge, which the wrapping form still
    // reports as past any real declared end).
    declared_end < inner_l3_offset
        || l4_span_start > declared_end
        || l4_span_len > declared_end - l4_span_start
}
