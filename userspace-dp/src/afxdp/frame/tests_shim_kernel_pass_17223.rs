// #17223: the shim's kernel-pass predicates and degraded composition,
// EXECUTED on the host.
//
// The healthy dispatch and the degraded composition used to restate
// every kernel-pass arm by hand; the copies diverged four times
// (#10863, #14327, #15946, #16438). The pure predicates and the
// degraded composition now live in the `core`-only `kernel_pass`
// module the shim calls; this file pulls that file in by source and
// runs it over fact tuples, and pins the `DEGRADED_TWIN` table against
// the shim's `USERSPACE_BRANCH_ARM_*` constants in the #16241 style:
// adding a kernel-pass arm without a twin row fails here.
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
    // #16241 style: parse the shim's USERSPACE_BRANCH_ARM_* constants
    // and require every kernel-pass arm to have a DEGRADED_TWIN row.
    // The kernel-pass set is the shim's cpumap_or_pass dispositions;
    // it is enumerated here by arm name so a renamed or added arm that
    // the shim counts as a kernel pass must be enrolled (or this list
    // updated with its twin row) to keep the build green.
    let lib = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("userspace-xdp/src/lib.rs");
    let src = std::fs::read_to_string(&lib).expect("read shim lib.rs");
    let mut arm_index: std::collections::BTreeMap<String, u32> = Default::default();
    for line in src.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("const USERSPACE_BRANCH_ARM_") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": u32 = ") else {
            continue;
        };
        if name == "MAX" {
            continue;
        }
        let value: u32 = value
            .strip_suffix(';')
            .expect("branch arm value ends with ';'")
            .parse()
            .expect("branch arm value is numeric");
        arm_index.insert(name.to_ascii_lowercase(), value);
    }
    assert!(
        arm_index.len() >= 20,
        "parsed only {} branch arms — the scan is broken",
        arm_index.len()
    );
    // The kernel-pass arms (healthy cpumap_or_pass dispositions, plus
    // the ctrl-disabled local pass which is the degraded composition's
    // own disposition).
    let kernel_pass_names = [
        "wg_steer",
        "early_filter",
        "session_hit_pass_kernel",
        "session_miss_nat_ndp",
        "session_miss_icmp_nat_local",
        "session_miss_local",
        "session_miss_ifnat_kernel_tunnel",
        "gre_inner_pass_kernel",
        "ctrl_disabled_local",
        "session_miss_proxy_ndp",
    ];
    // Every kernel-pass arm has a twin row, keyed by its shim index.
    for name in kernel_pass_names {
        let idx = *arm_index
            .get(name)
            .unwrap_or_else(|| panic!("shim has no USERSPACE_BRANCH_ARM_{name}"));
        let twin = shim_kernel_pass::degraded_twin(idx).unwrap_or_else(|| {
            panic!("kernel-pass arm {name} (index {idx}) has no DEGRADED_TWIN row")
        });
        if let DegradedTwin::Narrowed(reason) | DegradedTwin::Absent(reason) = twin {
            assert!(
                !reason.is_empty(),
                "arm {name}: a Narrowed/Absent twin must declare its reason"
            );
        }
    }
    // The table covers exactly the kernel-pass set: no missing row, no
    // row for a non-kernel-pass (redirect/drop) arm, no duplicate.
    assert_eq!(
        shim_kernel_pass::KERNEL_PASS_ARMS.len(),
        kernel_pass_names.len(),
        "KERNEL_PASS_ARMS and the test's kernel-pass list diverged"
    );
    let mut seen = std::collections::BTreeSet::new();
    for &arm in shim_kernel_pass::KERNEL_PASS_ARMS {
        assert!(seen.insert(arm), "duplicate KERNEL_PASS_ARMS row {arm}");
        assert!(
            shim_kernel_pass::degraded_twin(arm).is_some(),
            "KERNEL_PASS_ARMS entry {arm} has no DEGRADED_TWIN row"
        );
    }
    assert_eq!(
        shim_kernel_pass::DEGRADED_TWIN.len(),
        shim_kernel_pass::KERNEL_PASS_ARMS.len(),
        "DEGRADED_TWIN must have exactly one row per kernel-pass arm"
    );
    // The mirrored indices in kernel_pass.rs match the shim's constants.
    let mirrors: [(&str, u32); 10] = [
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
        assert_eq!(
            Some(&mirror),
            arm_index.get(name),
            "kernel_pass mirror for {name} drifted from the shim constant"
        );
    }
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
    assert!(
        src.contains("kernel_pass::degraded_local_or_control("),
        "the degraded path must call the shared composition"
    );
}
