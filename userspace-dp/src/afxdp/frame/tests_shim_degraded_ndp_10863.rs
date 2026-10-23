// #10863: execute the degraded shim's NDP destination predicate on the host.
//
// The healthy path has an early-filter host test, but the degraded path used a
// separate type-only NDP predicate. Pull the degraded predicate in by source so
// the behavior that distinguishes local from transit NDP is directly executed.
#[path = "../../../../userspace-xdp/src/degraded_ndp.rs"]
mod shim_degraded_ndp;

#[test]
fn degraded_ndp_kernel_pass_requires_a_local_destination_10863() {
    for icmp_type in 133..=137 {
        assert!(
            shim_degraded_ndp::is_local_ndp_control(icmp_type, 255, true),
            "local NDP type {icmp_type} must remain eligible for kernel delivery"
        );
        assert!(
            !shim_degraded_ndp::is_local_ndp_control(icmp_type, 255, false),
            "transit NDP type {icmp_type} must not pass to the kernel"
        );
        // #15946: hop-limit <255 is not on-link proof.
        assert!(
            !shim_degraded_ndp::is_local_ndp_control(icmp_type, 64, true),
            "local NDP type {icmp_type} hop<255 must not pass"
        );
        assert!(
            shim_degraded_ndp::is_nat_external_ndp_control(icmp_type, 255, true),
            "NAT-external NDP type {icmp_type} hop255 must pass (degraded arm)"
        );
        assert!(
            !shim_degraded_ndp::is_nat_external_ndp_control(icmp_type, 64, true)
        );
    }
    for icmp_type in [0, 1, 4, 128, 129, 132, 138, 255] {
        assert!(
            !shim_degraded_ndp::is_local_ndp_control(icmp_type, 255, true),
            "non-NDP ICMPv6 type {icmp_type} must not use the NDP control arm"
        );
    }
}
