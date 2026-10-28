//! #17223: the shim's kernel-pass arm predicates, shared by the healthy
//! dispatch (`try_xdp_userspace`) and the degraded composition
//! (`is_degraded_local_or_control`), in a module that compiles for the
//! HOST as well as for `bpfel-unknown-none`.
//!
//! The two paths used to restate every kernel-pass disposition by hand.
//! Four times in 30 days the copies diverged into correctness defects
//! that were each fixed by another hand mirror: #10863 (fail-open NDP),
//! #14327 (fail-open native-GRE inner), #15946 (missing degraded twins)
//! and #16438 (degraded drop of fragmented host UDP). The copies were
//! linked only by line-number prose that had already rotted.
//!
//! This module owns the PURE predicates: every input is a scalar or a
//! caller-computed bool (a map verdict the caller already resolved), so
//! no `aya`, BPF map or `std` dependency is needed and the host test in
//! userspace-dp pulls this file in by source and RUNS it. Map-touching
//! lookups stay at the call sites; what is shared is the decision each
//! arm makes from those verdicts, including call-site narrowings such
//! as the healthy WG tail-only conjunct.
//!
//! The deliberate healthy/degraded differences are declared in
//! `DEGRADED_TWIN` below, keyed by the shim's branch-arm index, so a
//! deliberate `Narrowed`/`Absent` row and an accidental omission no
//! longer look identical in source. The agreement test fails when a
//! kernel-pass arm has no row.
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
pub const ARM_WG_STEER: u32 = 9;
/// See [`ARM_WG_STEER`].
pub const ARM_EARLY_FILTER: u32 = 10;
/// See [`ARM_WG_STEER`].
pub const ARM_SESSION_HIT_PASS_KERNEL: u32 = 12;
/// See [`ARM_WG_STEER`].
pub const ARM_SESSION_MISS_NAT_NDP: u32 = 13;
/// See [`ARM_WG_STEER`].
pub const ARM_SESSION_MISS_ICMP_NAT_LOCAL: u32 = 14;
/// See [`ARM_WG_STEER`].
pub const ARM_SESSION_MISS_LOCAL: u32 = 15;
/// See [`ARM_WG_STEER`].
pub const ARM_SESSION_MISS_IFNAT_KERNEL_TUNNEL: u32 = 16;
/// See [`ARM_WG_STEER`].
pub const ARM_GRE_INNER_PASS_KERNEL: u32 = 19;
/// See [`ARM_WG_STEER`].
pub const ARM_CTRL_DISABLED_LOCAL: u32 = 26;
/// See [`ARM_WG_STEER`].
pub const ARM_SESSION_MISS_PROXY_NDP: u32 = 27;

/// How the degraded composition treats one healthy kernel-pass arm.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DegradedTwin {
    /// The degraded path calls the same shared predicate with the same
    /// facts; a true verdict passes to the kernel in both modes.
    Same,
    /// The degraded path deliberately decides differently; the reason
    /// names the shared predicate or gate that narrows it.
    Narrowed(&'static str),
    /// The degraded path has no twin for this arm; the reason names
    /// why the healthy disposition cannot occur or must not pass when
    /// degraded.
    Absent(&'static str),
}

/// #17223: the declared degraded twin of every kernel-pass arm, keyed
/// by `USERSPACE_BRANCH_ARM_*` index. A row exists for every arm whose
/// healthy disposition is `cpumap_or_pass` (a kernel pass); redirect,
/// drop and parse-failure arms are not kernel-pass arms and carry no
/// row. The host agreement test parses the shim's arm constants,
/// requires every kernel-pass arm listed in `KERNEL_PASS_ARMS` to have
/// a row here, and requires every row to name a real arm.
pub const DEGRADED_TWIN: &[(u32, DegradedTwin)] = &[
    (ARM_WG_STEER, DegradedTwin::Same),
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

/// The kernel-pass arm indices, in dispatch order. The agreement test
/// requires `DEGRADED_TWIN` to cover exactly this set.
pub const KERNEL_PASS_ARMS: &[u32] = &[
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

/// Healthy WG-steer arm: a WG steer candidate passes to the kernel
/// unless a live session already owns the packet (REDIRECT stays in
/// userspace, PASS_TO_KERNEL is decided by its own arm below).
/// `session_action` mirrors the shim's action values (1 = REDIRECT,
/// 2 = PASS_TO_KERNEL). The degraded twin has no session-steer
/// interaction: it tests the session arm and the steer independently,
/// which composes to the same kernel-pass verdict.
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

/// Session PASS_TO_KERNEL arm: a live session row with the
/// PASS_TO_KERNEL action passes to the kernel in both modes.
#[inline(always)]
pub fn session_pass_to_kernel(session_action_is_pass_to_kernel: bool) -> bool {
    session_action_is_pass_to_kernel
}

/// The zero-hop-limit veto (#16841) as the degraded composition applies
/// it: a local destination whose hop-limit-0 packet the knob rejects
/// must not pass via any arm below the veto point.
#[inline(always)]
pub fn zero_hop_limit_vetoes_local_pass(
    destination_is_local: bool,
    zero_hop_limit_drop: bool,
) -> bool {
    destination_is_local && zero_hop_limit_drop
}

/// #17223: the degraded local/control composition over caller-resolved
/// facts, in the degraded path's evaluation order, as separate bool
/// parameters (inlined; no aggregate crosses into the composition, so
/// the verifier state shape matches the hand-ordered arms it replaces).
/// This is the single composition both the shim's
/// `is_degraded_local_or_control` and the host cell execute, so the
/// order and the vetoes cannot drift from the tested shape. Returns
/// true iff the packet passes to the kernel as local/control while
/// degraded. The shim resolves each fact lazily in this order and
/// returns at the same points; it calls this function for the final
/// native-GRE gate with the already-decided prefix encoded as
/// false/true facts.
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
    if native_gre_fragment_on_helper {
        return false;
    }
    if wg_tail_excluded {
        return false;
    }
    if unresolved_ext_chain {
        return false;
    }
    if early_pass {
        return true;
    }
    if icmp_to_interface_nat_local {
        return true;
    }
    if local_ndp_control {
        return true;
    }
    if nat_external_ndp_control {
        return true;
    }
    if proxy_ndp_control {
        return true;
    }
    if zero_hop_limit_vetoes_local_pass(destination_is_local, zero_hop_limit_drop) {
        return false;
    }
    if session_pass_to_kernel(session_is_pass_to_kernel) {
        return true;
    }
    if wg_steer_candidate {
        return true;
    }
    if general_local_pass {
        return true;
    }
    if interface_nat_esp_pass {
        return true;
    }
    if native_gre {
        return gre_inner_pass;
    }
    false
}
