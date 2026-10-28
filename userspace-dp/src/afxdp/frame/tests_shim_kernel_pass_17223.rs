// #17223: the shim's kernel-pass predicates and degraded composition,
// EXECUTED on the host.
//
// The healthy dispatch and the degraded composition used to restate
// every kernel-pass arm by hand; the copies diverged four times
// (#10863, #14327, #15946, #16438). The pure predicates and the
// degraded composition now live in the `core`-only `kernel_pass`
// module the shim calls; this file pulls that file in by source and
// runs it over fact tuples. The `DEGRADED_TWIN` agreement below
// DERIVES the kernel-pass arm set from the shim source: it parses
// every `USERSPACE_BRANCH_ARM_*` constant and the return disposition
// after each arm's branch-stat site (`cpumap_or_pass` /
// `pass_local_control`, which wraps it), with no hardcoded arm-name
// list — adding a `cpumap_or_pass` arm without a twin row fails here.
#[path = "../../../../userspace-xdp/src/kernel_pass.rs"]
mod shim_kernel_pass;

use shim_kernel_pass::DegradedTwin;

#[test]
fn degraded_composition_vetoes_precede_pass_arms_17223() {
    use shim_kernel_pass::degraded_local_or_control as comp;
    // (frag, tail, unresolved, early, icmp_nat, local_ndp, nat_ndp, proxy_ndp,
    //  is_local, zero_hop, session, wg_steer, general_local, ifnat_esp, native_gre, gre_inner)
    // Fragment gates and the unresolved-chain veto beat every pass arm.
    assert!(!comp(
        true, false, false, true, false, false, false, false, false, false, true, false, true,
        false, false, false
    ));
    assert!(!comp(
        false, true, false, true, false, false, false, false, false, false, true, false, true,
        false, false, false
    ));
    assert!(!comp(
        false, false, true, true, false, false, false, false, false, false, true, false, true,
        false, false, false
    ));
    // The zero-hop-limit veto beats the session/WG arms below it, but
    // only for a local destination.
    assert!(!comp(
        false, false, false, false, false, false, false, false, true, true, true, true, false,
        false, false, false
    ));
    assert!(comp(
        false, false, false, false, false, false, false, false, false, true, true, false, false,
        false, false, false
    ));
    // A pre-veto arm (NDP) passes even when the veto would fire.
    assert!(comp(
        false, false, false, false, false, true, false, false, true, true, false, false, false,
        false, false, false
    ));
}

#[test]
fn degraded_prefix_tail_split_matches_full_composition_17223() {
    // The shim executes the composition staged (head, then prefix, then
    // mid, then the native-GRE gate); the staged form must agree with
    // the full composition on every fact vector. Exhaustive over the
    // 16 facts.
    for bits in 0u32..(1 << 16) {
        let f = |i: u32| bits & (1 << i) != 0;
        let full = shim_kernel_pass::degraded_local_or_control(
            f(0),
            f(1),
            f(2),
            f(3),
            f(4),
            f(5),
            f(6),
            f(7),
            f(8),
            f(9),
            f(10),
            f(11),
            f(12),
            f(13),
            f(14),
            f(15),
        );
        let staged = staged_17223(&f);
        assert_eq!(full, staged, "fact vector {bits:#018b} diverged");
    }
}

// The shim's staged execution, fact-for-fact: head decides the
// fragment/unresolved/early facts, prefix decides the remaining
// pre-veto arms, mid decides the veto and post-veto pass arms, and
// only the native-GRE fall-through consults the inner gate.
fn staged_17223(f: &dyn Fn(u32) -> bool) -> bool {
    if let Some(verdict) = shim_kernel_pass::degraded_local_or_control_head(f(0), f(1), f(2), f(3))
    {
        return verdict;
    }
    if let Some(verdict) = shim_kernel_pass::degraded_local_or_control_prefix(
        f(0),
        f(1),
        f(2),
        f(3),
        f(4),
        f(5),
        f(6),
        f(7),
    ) {
        return verdict;
    }
    if let Some(verdict) = shim_kernel_pass::degraded_local_or_control_mid(
        f(8),
        f(9),
        f(10),
        f(11),
        f(12),
        f(13),
        f(14),
    ) {
        return verdict;
    }
    f(15)
}

#[test]
fn degraded_composition_pass_arms_17223() {
    use shim_kernel_pass::degraded_local_or_control as comp;
    // Each pass arm alone passes (positions as in the veto test).
    assert!(
        comp(
            false, false, false, true, false, false, false, false, false, false, false, false,
            false, false, false, false
        ),
        "early"
    );
    assert!(
        comp(
            false, false, false, false, true, false, false, false, false, false, false, false,
            false, false, false, false
        ),
        "icmp_nat_local"
    );
    assert!(
        comp(
            false, false, false, false, false, true, false, false, false, false, false, false,
            false, false, false, false
        ),
        "local_ndp"
    );
    assert!(
        comp(
            false, false, false, false, false, false, true, false, false, false, false, false,
            false, false, false, false
        ),
        "nat_ndp"
    );
    assert!(
        comp(
            false, false, false, false, false, false, false, true, false, false, false, false,
            false, false, false, false
        ),
        "proxy_ndp"
    );
    assert!(
        comp(
            false, false, false, false, false, false, false, false, false, false, true, false,
            false, false, false, false
        ),
        "session"
    );
    assert!(
        comp(
            false, false, false, false, false, false, false, false, false, false, false, true,
            false, false, false, false
        ),
        "wg_steer"
    );
    assert!(
        comp(
            false, false, false, false, false, false, false, false, false, false, false, false,
            true, false, false, false
        ),
        "general_local"
    );
    assert!(
        comp(
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, true, false, false
        ),
        "ifnat_esp"
    );
    // Nothing set: drops (fail-closed transit).
    assert!(!comp(
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false
    ));
    // #14327 shape: native GRE reaches the kernel only through the inner gate.
    assert!(!comp(
        false, false, false, false, false, false, false, false, true, false, false, false, false,
        false, true, false
    ));
    assert!(comp(
        false, false, false, false, false, false, false, false, true, false, false, false, false,
        false, true, true
    ));
    // A non-GRE packet never consults the inner gate.
    assert!(!comp(
        false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, true
    ));
}

#[test]
fn wg_tail_fragment_is_the_shared_narrowing_17223() {
    // #16438/#15102: the tail (255) is the only WG-fragment narrowing;
    // a UDP head (17) is not narrowed on either path.
    assert!(shim_kernel_pass::wg_tail_fragment(255, 255));
    assert!(!shim_kernel_pass::wg_tail_fragment(17, 255));
    assert!(!shim_kernel_pass::wg_tail_fragment(47, 255));
}

#[test]
fn wg_steer_and_session_predicates_17223() {
    // WG steer passes only when no session owns the packet.
    assert!(shim_kernel_pass::wg_steer_passes_to_kernel(
        true, false, false
    ));
    assert!(!shim_kernel_pass::wg_steer_passes_to_kernel(
        true, true, false
    ));
    assert!(!shim_kernel_pass::wg_steer_passes_to_kernel(
        true, false, true
    ));
    assert!(!shim_kernel_pass::wg_steer_passes_to_kernel(
        false, false, false
    ));
    assert!(shim_kernel_pass::session_pass_to_kernel(true));
    assert!(!shim_kernel_pass::session_pass_to_kernel(false));
    assert!(shim_kernel_pass::zero_hop_limit_vetoes_local_pass(
        true, true
    ));
    assert!(!shim_kernel_pass::zero_hop_limit_vetoes_local_pass(
        false, true
    ));
    assert!(!shim_kernel_pass::zero_hop_limit_vetoes_local_pass(
        true, false
    ));
}

#[test]
fn degraded_twin_covers_every_kernel_pass_arm_17223() {
    // Derive the arm set from the shim source. Parse every
    // `USERSPACE_BRANCH_ARM_*` constant, then for each constant's
    // branch-stat site find the return disposition that follows it.
    // An arm is a kernel-pass arm iff that disposition is
    // `cpumap_or_pass` (reached directly or through `pass_local_control`,
    // which wraps it, including via a tail expression without `return`).
    // There is deliberately NO hardcoded arm-name list in this guard:
    // a new `cpumap_or_pass` arm without a DEGRADED_TWIN row fails.
    let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("userspace-xdp/src/lib.rs");
    let src = std::fs::read_to_string(&lib).expect("read shim lib.rs");
    let mut arm_index: std::collections::BTreeMap<String, u32> = Default::default();
    let mut max: Option<u32> = None;
    for line in src.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("const USERSPACE_BRANCH_ARM_") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": u32 = ") else {
            continue;
        };
        let value: u32 = value
            .strip_suffix(';')
            .expect("branch arm value ends with ';'")
            .parse()
            .expect("branch arm value is numeric");
        if name == "MAX" {
            max = Some(value);
            continue;
        }
        arm_index.insert(name.to_ascii_lowercase(), value);
    }
    let max = max.expect("USERSPACE_BRANCH_ARM_MAX not found in the shim source");
    assert!(
        arm_index.len() >= 20,
        "parsed only {} branch arms — the scan is broken",
        arm_index.len()
    );
    assert_eq!(
        arm_index.len() as u32,
        max,
        "branch-arm constants are not a dense 0..MAX set — the scan is broken"
    );
    // Derived kernel-pass set: name -> index for every arm whose
    // branch-stat site returns through cpumap_or_pass.
    let lines: Vec<&str> = src.lines().collect();
    let mut derived: std::collections::BTreeMap<String, u32> = Default::default();
    for (i, raw) in lines.iter().enumerate() {
        let Some(at) = raw.find("USERSPACE_BRANCH_ARM_") else {
            continue;
        };
        if !raw.contains("incr_branch_stat(") {
            continue;
        }
        let suffix = &raw[at + "USERSPACE_BRANCH_ARM_".len()..];
        let end = suffix
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(suffix.len());
        let name = suffix[..end].to_ascii_lowercase();
        if name == "max" || !arm_index.contains_key(&name) {
            continue;
        }
        // Branch-stat sites can share a line (l2 parse failure), so the
        // scan starts on the marker line itself, then up to 16 lines on
        // (record_trace calls can sit between the stat and its return).
        let window: String = lines[i..(i + 16).min(lines.len())].join("\n");
        if window.contains("cpumap_or_pass(") || window.contains("pass_local_control(") {
            derived.insert(name.clone(), arm_index[&name]);
        }
    }
    // The ctrl-disabled local arm's pass is a tail expression one line
    // after its branch-stat site; it is inside the window above. The
    // derived set must at least contain the two previously missing
    // Absent arms, or the derivation itself is broken.
    for required in ["l2_parse_fail", "non_adjudicated_pass", "wg_steer"] {
        assert!(
            derived.contains_key(required),
            "derived kernel-pass set is missing {required} — the derivation is broken: {derived:?}"
        );
    }
    // Every derived kernel-pass arm has exactly one twin row, and a
    // Narrowed/Absent row must declare a non-empty reason.
    let mut twin_count: std::collections::BTreeMap<u32, usize> = Default::default();
    for &(idx, twin) in shim_kernel_pass::DEGRADED_TWIN {
        *twin_count.entry(idx).or_default() += 1;
        if let DegradedTwin::Narrowed(reason) | DegradedTwin::Absent(reason) = twin {
            assert!(
                !reason.is_empty(),
                "arm index {idx}: a Narrowed/Absent twin must declare its reason"
            );
        }
    }
    for (name, idx) in &derived {
        assert_eq!(
            twin_count.get(idx).copied().unwrap_or(0),
            1,
            "kernel-pass arm {name} (index {idx}) must have exactly one DEGRADED_TWIN row"
        );
    }
    // No row names a non-kernel-pass (redirect/drop/direct-pass) arm.
    let derived_indices: std::collections::BTreeSet<u32> = derived.values().copied().collect();
    for &(idx, _) in shim_kernel_pass::DEGRADED_TWIN {
        assert!(
            derived_indices.contains(&idx),
            "DEGRADED_TWIN row for index {idx} is not a derived cpumap_or_pass arm"
        );
    }
    // KERNEL_PASS_ARMS covers exactly the derived set.
    let listed: std::collections::BTreeSet<u32> =
        shim_kernel_pass::KERNEL_PASS_ARMS.iter().copied().collect();
    assert_eq!(
        listed, derived_indices,
        "KERNEL_PASS_ARMS diverged from the shim-derived cpumap_or_pass set"
    );
    assert_eq!(
        shim_kernel_pass::DEGRADED_TWIN.len(),
        derived.len(),
        "DEGRADED_TWIN must have exactly one row per derived kernel-pass arm"
    );
    // The mirrored indices in kernel_pass.rs match the shim's constants
    // for every derived arm.
    let mirrors: [(&str, u32); 12] = [
        ("l2_parse_fail", shim_kernel_pass::ARM_L2_PARSE_FAIL),
        (
            "non_adjudicated_pass",
            shim_kernel_pass::ARM_NON_ADJUDICATED_PASS,
        ),
        ("wg_steer", shim_kernel_pass::ARM_WG_STEER),
        ("early_filter", shim_kernel_pass::ARM_EARLY_FILTER),
        (
            "session_hit_pass_kernel",
            shim_kernel_pass::ARM_SESSION_HIT_PASS_KERNEL,
        ),
        (
            "session_miss_nat_ndp",
            shim_kernel_pass::ARM_SESSION_MISS_NAT_NDP,
        ),
        (
            "session_miss_icmp_nat_local",
            shim_kernel_pass::ARM_SESSION_MISS_ICMP_NAT_LOCAL,
        ),
        (
            "session_miss_local",
            shim_kernel_pass::ARM_SESSION_MISS_LOCAL,
        ),
        (
            "session_miss_ifnat_kernel_tunnel",
            shim_kernel_pass::ARM_SESSION_MISS_IFNAT_KERNEL_TUNNEL,
        ),
        (
            "gre_inner_pass_kernel",
            shim_kernel_pass::ARM_GRE_INNER_PASS_KERNEL,
        ),
        (
            "ctrl_disabled_local",
            shim_kernel_pass::ARM_CTRL_DISABLED_LOCAL,
        ),
        (
            "session_miss_proxy_ndp",
            shim_kernel_pass::ARM_SESSION_MISS_PROXY_NDP,
        ),
    ];
    for (name, mirror) in mirrors {
        assert!(
            derived.contains_key(name),
            "mirror {name} is not in the derived kernel-pass set"
        );
        assert_eq!(
            Some(&mirror),
            arm_index.get(name),
            "kernel_pass mirror for {name} drifted from the shim constant"
        );
    }
    // The two previously missing arms declare Absent; the WG arm
    // declares its Narrowed divergence.
    assert!(
        matches!(
            shim_kernel_pass::degraded_twin(shim_kernel_pass::ARM_L2_PARSE_FAIL),
            Some(DegradedTwin::Absent(_))
        ),
        "l2_parse_fail must declare an Absent degraded twin"
    );
    assert!(
        matches!(
            shim_kernel_pass::degraded_twin(shim_kernel_pass::ARM_NON_ADJUDICATED_PASS),
            Some(DegradedTwin::Absent(_))
        ),
        "non_adjudicated_pass must declare an Absent degraded twin"
    );
    assert!(
        matches!(
            shim_kernel_pass::degraded_twin(shim_kernel_pass::ARM_WG_STEER),
            Some(DegradedTwin::Narrowed(_))
        ),
        "wg_steer must declare its Narrowed degraded twin"
    );
    // The shim source no longer carries line-number prose linking the
    // two copies, and both paths call the shared WG-tail predicate.
    assert!(
        !src.contains("(:1077)") && !src.contains("(healthy :"),
        "line-number twin prose remains in the shim"
    );
    assert!(
        src.matches("kernel_pass::wg_tail_fragment").count() >= 2,
        "healthy and degraded paths must both call kernel_pass::wg_tail_fragment"
    );
    // The degraded path executes the shared composition staged:
    // exactly one head, prefix and mid call exist in the shim (the
    // former hand-written arm chain is gone), and the native-GRE gate
    // is the staged fall-through.
    for stage in [
        "kernel_pass::degraded_local_or_control_head(",
        "kernel_pass::degraded_local_or_control_prefix(",
        "kernel_pass::degraded_local_or_control_mid(",
    ] {
        assert_eq!(
            src.matches(stage).count(),
            1,
            "the degraded path must call {stage} exactly once"
        );
    }
}
