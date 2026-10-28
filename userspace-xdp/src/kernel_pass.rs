//! #17223: the shim's kernel-pass arm predicates, in a module that
//! compiles for the HOST as well as for `bpfel-unknown-none`.
//!
//! The two paths used to restate every kernel-pass disposition by hand.
//! Four times in 30 days the copies diverged into correctness defects
//! that were each fixed by another hand mirror: #10863 (fail-open NDP),
//! #14327 (fail-open native-GRE inner), #15946 (missing degraded twins)
//! and #16438 (degraded drop of fragmented host UDP). The copies were
//! linked only by line-number prose that had already rotted.
//!
//! What is actually shared, per predicate (no broader claim is made):
//!
//! * `wg_tail_fragment` is called by BOTH the healthy dispatch and the
//!   degraded path (which computes its `wg_tail_excluded` fact with it).
//! * `wg_steer_passes_to_kernel` is called ONLY by the healthy dispatch.
//!   The degraded WG arm is a declared `Narrowed` twin (see
//!   `DEGRADED_TWIN`): it does not call this predicate and does not
//!   exclude a session-REDIRECT-owned candidate.
//! * `session_pass_to_kernel` and `zero_hop_limit_vetoes_local_pass` are
//!   called ONLY by the degraded composition below. The healthy session
//!   arms decide by matching the session action and by calling
//!   `zero_hop_limit_local_drop_shim` directly under their own locality
//!   gates; they do not call either predicate. Their `Same`/`Narrowed`
//!   rows declare verdict correspondence, not a shared call.
//! * `degraded_local_or_control` is the degraded composition itself.
//!   The shim's `is_degraded_local_or_control` executes exactly its
//!   decomposition — head, then prefix, then mid, then the native-GRE
//!   gate — resolving each stage's facts only on the previous stage's
//!   fall-through, and the host cell executes this full function plus
//!   the staged split equivalence.
//!
//! Map-touching lookups stay at the call sites; every input here is a
//! scalar or a caller-computed bool (a map verdict the caller already
//! resolved), so no `aya`, BPF map or `std` dependency is needed and
//! the host test in userspace-dp pulls this file in by source and RUNS
//! it.
//!
//! The deliberate healthy/degraded differences are declared in
//! `DEGRADED_TWIN` below, keyed by the shim's branch-arm index, so a
//! deliberate `Narrowed`/`Absent` row and an accidental omission no
//! longer look identical in source. The agreement test derives the
//! kernel-pass arm set from the shim source (every
//! `USERSPACE_BRANCH_ARM_*` constant plus its return disposition) and
//! fails when a `cpumap_or_pass` arm has no row.
//!
//! Nothing in here may take a dependency on `aya`, on a BPF map, or on
//! `std` — that is what keeps it host-compilable, and it is the whole
//! point.

/// Branch-arm indices, mirrored from the shim root's
/// `USERSPACE_BRANCH_ARM_*` constants for the same host-compilation
/// reason as the `PROTO_*` mirrors in `tunnel_frag.rs`: importing would
/// couple this host-compiled module to the `no_std` crate root it must
/// stay independent of. The agreement test pins these equal to the
/// shim's constants by index and name, so the mirror cannot drift.
pub const ARM_L2_PARSE_FAIL: u32 = 0;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_NON_ADJUDICATED_PASS: u32 = 4;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_WG_STEER: u32 = 9;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_EARLY_FILTER: u32 = 10;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_SESSION_HIT_PASS_KERNEL: u32 = 12;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_SESSION_MISS_NAT_NDP: u32 = 13;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_SESSION_MISS_ICMP_NAT_LOCAL: u32 = 14;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_SESSION_MISS_LOCAL: u32 = 15;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_SESSION_MISS_IFNAT_KERNEL_TUNNEL: u32 = 16;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_GRE_INNER_PASS_KERNEL: u32 = 19;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_CTRL_DISABLED_LOCAL: u32 = 26;
/// See [`ARM_L2_PARSE_FAIL`].
pub const ARM_SESSION_MISS_PROXY_NDP: u32 = 27;

/// How the degraded composition treats one healthy kernel-pass arm.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DegradedTwin {
    /// The degraded path reaches the same kernel-pass verdict on the
    /// same facts (through `degraded_local_or_control`). This declares
    /// verdict correspondence only; it does not claim the healthy and
    /// degraded paths call the same predicate function.
    Same,
    /// The degraded path deliberately decides differently; the reason
    /// names the predicate or gate responsible for the difference.
    Narrowed(&'static str),
    /// The degraded path has no twin for this arm; the reason names
    /// why the healthy disposition cannot occur or must not pass when
    /// degraded.
    Absent(&'static str),
}

/// #17223: the declared degraded twin of every kernel-pass arm, keyed
/// by `USERSPACE_BRANCH_ARM_*` index. A row exists for every arm whose
/// shim return disposition is a kernel pass via `cpumap_or_pass` (or
/// `pass_local_control`, which wraps it) — including the L2-parse-fail
/// and non-adjudicated passes, whose degraded twins are declared
/// `Absent`. Redirect, drop and direct-`XDP_PASS` arms are not
/// `cpumap_or_pass` arms and carry no row. The host agreement test
/// DERIVES that set from the shim source (it parses every
/// `USERSPACE_BRANCH_ARM_*` constant and the return disposition
/// following each arm's branch-stat site), requires exactly this
/// table to cover it, and requires every row to name a real arm — it
/// does not consult a hardcoded name list, so a new `cpumap_or_pass`
/// arm without a row fails the test.
pub const DEGRADED_TWIN: &[(u32, DegradedTwin)] = &[
    (
        ARM_L2_PARSE_FAIL,
        DegradedTwin::Absent(
            "the degraded composition is only reached with a parsed packet; the \
             ctrl-disabled degraded entry drops an L2 parse failure instead of passing it",
        ),
    ),
    (
        ARM_NON_ADJUDICATED_PASS,
        DegradedTwin::Absent(
            "a non-adjudicated ifindex never reaches the degraded composition: the \
             ctrl-disabled degraded entry drops it and the binding-degraded path sits \
             behind the healthy adjudicated gate, so degraded never passes it",
        ),
    ),
    (
        ARM_WG_STEER,
        DegradedTwin::Narrowed(
            "degraded does not call wg_steer_passes_to_kernel: it tests the session \
             PASS arm independently first and then passes any WG steer candidate, so a \
             candidate with a live REDIRECT session kernel-passes degraded but not \
             healthy; pre-existing divergence, declared here rather than shared",
        ),
    ),
    (ARM_EARLY_FILTER, DegradedTwin::Same),
    (ARM_SESSION_HIT_PASS_KERNEL, DegradedTwin::Same),
    (ARM_SESSION_MISS_NAT_NDP, DegradedTwin::Same),
    (ARM_SESSION_MISS_ICMP_NAT_LOCAL, DegradedTwin::Same),
    (
        ARM_SESSION_MISS_LOCAL,
        DegradedTwin::Narrowed(
            "degraded folds the healthy local arm into degraded_general_local_pass_applies \
             (native GRE declines) plus the ESP/interface-NAT and native-GRE inner gates; \
             the zero-hop-limit veto applies before the session/WG arms instead of inside the arm",
        ),
    ),
    (
        ARM_SESSION_MISS_IFNAT_KERNEL_TUNNEL,
        DegradedTwin::Narrowed(
            "degraded_interface_nat_esp_passes_to_kernel: ESP-only; a non-native GRE head \
             drops by design on the degraded path, so its tail drops beside it",
        ),
    ),
    (ARM_GRE_INNER_PASS_KERNEL, DegradedTwin::Same),
    (
        ARM_CTRL_DISABLED_LOCAL,
        DegradedTwin::Narrowed(
            "not a healthy arm: the ctrl-disabled disposition over the degraded composition \
             verdict; it has no healthy twin by construction",
        ),
    ),
    (ARM_SESSION_MISS_PROXY_NDP, DegradedTwin::Same),
];

/// The `cpumap_or_pass`-disposition arm indices, in dispatch order. The
/// agreement test derives this set from the shim source and requires
/// `DEGRADED_TWIN` (and this list) to cover exactly it.
pub const KERNEL_PASS_ARMS: &[u32] = &[
    ARM_L2_PARSE_FAIL,
    ARM_NON_ADJUDICATED_PASS,
    ARM_WG_STEER,
    ARM_EARLY_FILTER,
    ARM_SESSION_HIT_PASS_KERNEL,
    ARM_SESSION_MISS_NAT_NDP,
    ARM_SESSION_MISS_ICMP_NAT_LOCAL,
    ARM_SESSION_MISS_LOCAL,
    ARM_SESSION_MISS_IFNAT_KERNEL_TUNNEL,
    ARM_GRE_INNER_PASS_KERNEL,
    ARM_CTRL_DISABLED_LOCAL,
    ARM_SESSION_MISS_PROXY_NDP,
];

/// Look up the declared degraded twin of a branch arm.
#[inline(always)]
pub fn degraded_twin(arm: u32) -> Option<DegradedTwin> {
    let mut i = 0;
    while i < DEGRADED_TWIN.len() {
        if DEGRADED_TWIN[i].0 == arm {
            return Some(DEGRADED_TWIN[i].1);
        }
        i += 1;
    }
    None
}

/// Healthy WG-steer arm (healthy dispatch only): a WG steer candidate
/// passes to the kernel unless a live session already owns the packet
/// (REDIRECT stays in userspace, PASS_TO_KERNEL is decided by its own
/// arm below). `session_action` mirrors the shim's action values
/// (1 = REDIRECT, 2 = PASS_TO_KERNEL). The degraded path does NOT call
/// this predicate — that deliberate difference is the `ARM_WG_STEER`
/// `Narrowed` row in `DEGRADED_TWIN`.
#[inline(always)]
pub fn wg_steer_passes_to_kernel(
    wg_steer_candidate: bool,
    session_action_is_redirect: bool,
    session_action_is_pass_to_kernel: bool,
) -> bool {
    wg_steer_candidate && !session_action_is_redirect && !session_action_is_pass_to_kernel
}

/// The WG-fragment narrowing shared by both paths (#15102/#16438):
/// only a fragmented TAIL (parsed protocol is the no-L4 sentinel) is
/// kept on the helper by the WG arm. A head keeps UDP and carries a
/// port, so it is not provably WG and must reach the local/control and
/// session arms. Previously the healthy call site spelled the tail-only
/// conjunct inline while the degraded path used a separate helper;
/// both now call this one predicate.
#[inline(always)]
pub fn wg_tail_fragment(parsed_protocol: u8, no_l4_sentinel: u8) -> bool {
    parsed_protocol == no_l4_sentinel
}

/// The degraded composition's session test: a live session row with
/// the PASS_TO_KERNEL action passes to the kernel while degraded.
/// Called only by `degraded_local_or_control`; the healthy session
/// arms match the session action directly and do not call this.
#[inline(always)]
pub fn session_pass_to_kernel(session_action_is_pass_to_kernel: bool) -> bool {
    session_action_is_pass_to_kernel
}

/// The zero-hop-limit veto (#16841) as the degraded composition applies
/// it: a local destination whose hop-limit-0 packet the knob rejects
/// must not pass via any arm below the veto point. Called only by
/// `degraded_local_or_control`; the healthy local/session arms call
/// `zero_hop_limit_local_drop_shim` directly under their own gates.
#[inline(always)]
pub fn zero_hop_limit_vetoes_local_pass(
    destination_is_local: bool,
    zero_hop_limit_drop: bool,
) -> bool {
    destination_is_local && zero_hop_limit_drop
}

/// The degraded prefix composition: every arm before the
/// zero-hop-limit veto. Returns `Some(verdict)` when a prefix arm
/// decides, `None` when the packet falls through to the veto and the
/// arms below it. `degraded_local_or_control` begins with this, and
/// the shim calls it after the head stage, resolving the tail facts
/// only on the fall-through — so reordering a prefix veto changes the
/// executed verdict, not just the tested shape.
#[inline(always)]
pub fn degraded_local_or_control_prefix(
    native_gre_fragment_on_helper: bool,
    wg_tail_excluded: bool,
    unresolved_ext_chain: bool,
    early_pass: bool,
    icmp_to_interface_nat_local: bool,
    local_ndp_control: bool,
    nat_external_ndp_control: bool,
    proxy_ndp_control: bool,
) -> Option<bool> {
    if native_gre_fragment_on_helper {
        return Some(false);
    }
    if wg_tail_excluded {
        return Some(false);
    }
    if unresolved_ext_chain {
        return Some(false);
    }
    if early_pass {
        return Some(true);
    }
    if icmp_to_interface_nat_local {
        return Some(true);
    }
    if local_ndp_control {
        return Some(true);
    }
    if nat_external_ndp_control {
        return Some(true);
    }
    if proxy_ndp_control {
        return Some(true);
    }
    None
}

/// #17223: the degraded local/control composition over caller-resolved
/// facts, in the degraded path's evaluation order, as separate bool
/// parameters (inlined; no aggregate crosses into the composition, so
/// the verifier state shape matches the hand-ordered arms it replaces).
/// This is the single composition the host cell executes, and the
/// shim's `is_degraded_local_or_control` executes exactly this
/// decomposition — head, then prefix, then mid, then the native-GRE
/// gate — resolving each part's facts only after the previous part
/// falls through, so the order and the vetoes cannot drift from the
/// tested shape and every map lookup stays lazy in the original
/// order. Returns true iff the packet passes to the kernel as
/// local/control while degraded. The fully resolved host form and
/// the shim's staged form return the identical verdict at every
/// point (the host cell proves the split exhaustively).
#[inline(always)]
pub fn degraded_local_or_control(
    native_gre_fragment_on_helper: bool,
    wg_tail_excluded: bool,
    unresolved_ext_chain: bool,
    early_pass: bool,
    icmp_to_interface_nat_local: bool,
    local_ndp_control: bool,
    nat_external_ndp_control: bool,
    proxy_ndp_control: bool,
    destination_is_local: bool,
    zero_hop_limit_drop: bool,
    session_is_pass_to_kernel: bool,
    wg_steer_candidate: bool,
    general_local_pass: bool,
    interface_nat_esp_pass: bool,
    native_gre: bool,
    gre_inner_pass: bool,
) -> bool {
    if let Some(verdict) = degraded_local_or_control_prefix(
        native_gre_fragment_on_helper,
        wg_tail_excluded,
        unresolved_ext_chain,
        early_pass,
        icmp_to_interface_nat_local,
        local_ndp_control,
        nat_external_ndp_control,
        proxy_ndp_control,
    ) {
        return verdict;
    }
    degraded_local_or_control_tail(
        destination_is_local,
        zero_hop_limit_drop,
        session_is_pass_to_kernel,
        wg_steer_candidate,
        general_local_pass,
        interface_nat_esp_pass,
        native_gre,
        gre_inner_pass,
    )
}

/// The degraded tail composition: the zero-hop-limit veto and the arms
/// below it, in the degraded path's evaluation order, ending at the
/// native-GRE gate. Expressed through `degraded_local_or_control_mid`
/// so the shim's staged execution and this fully resolved form share
/// the same tail decision. Called by `degraded_local_or_control`.
#[inline(always)]
pub fn degraded_local_or_control_tail(
    destination_is_local: bool,
    zero_hop_limit_drop: bool,
    session_is_pass_to_kernel: bool,
    wg_steer_candidate: bool,
    general_local_pass: bool,
    interface_nat_esp_pass: bool,
    native_gre: bool,
    gre_inner_pass: bool,
) -> bool {
    match degraded_local_or_control_mid(
        destination_is_local,
        zero_hop_limit_drop,
        session_is_pass_to_kernel,
        wg_steer_candidate,
        general_local_pass,
        interface_nat_esp_pass,
        native_gre,
    ) {
        Some(verdict) => verdict,
        None => gre_inner_pass,
    }
}

/// The degraded mid composition: the tail arms before the native-GRE
/// gate. Returns `Some(verdict)` when the zero-hop-limit veto or a
/// pass arm decides, `None` when only the native-GRE gate remains.
/// The shim calls this after computing `gre_inner_pass` (guarded by
/// `native_gre`) but before the mid call, so the read-only GRE inner
/// session lookup runs even when mid decides; no verdict changes.
#[inline(always)]
pub fn degraded_local_or_control_mid(
    destination_is_local: bool,
    zero_hop_limit_drop: bool,
    session_is_pass_to_kernel: bool,
    wg_steer_candidate: bool,
    general_local_pass: bool,
    interface_nat_esp_pass: bool,
    native_gre: bool,
) -> Option<bool> {
    if zero_hop_limit_vetoes_local_pass(destination_is_local, zero_hop_limit_drop) {
        return Some(false);
    }
    if session_pass_to_kernel(session_is_pass_to_kernel) {
        return Some(true);
    }
    if wg_steer_candidate {
        return Some(true);
    }
    if general_local_pass {
        return Some(true);
    }
    if interface_nat_esp_pass {
        return Some(true);
    }
    if native_gre {
        return None;
    }
    Some(false)
}

/// The degraded head composition: the fragment/unresolved vetoes and
/// the early pass, before any NDP fact is resolved. Returns
/// `Some(verdict)` when a head arm decides, `None` on fall-through.
#[inline(always)]
pub fn degraded_local_or_control_head(
    native_gre_fragment_on_helper: bool,
    wg_tail_excluded: bool,
    unresolved_ext_chain: bool,
    early_pass: bool,
) -> Option<bool> {
    if native_gre_fragment_on_helper {
        return Some(false);
    }
    if wg_tail_excluded {
        return Some(false);
    }
    if unresolved_ext_chain {
        return Some(false);
    }
    if early_pass {
        return Some(true);
    }
    None
}
