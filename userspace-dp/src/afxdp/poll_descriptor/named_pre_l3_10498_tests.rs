#[test]
fn named_pre_l3_poll_arms_keep_recycle_and_counter_wiring_10498() {
    let source = include_str!("mod.rs");

    let umem_start = source
        .find("let Some(raw_frame)")
        .expect("UMEM-slice arm must remain in poll head");
    let umem_end = source[umem_start..]
        .find("// #10313")
        .map(|offset| umem_start + offset)
        .expect("UMEM arm must precede VLAN guard");
    let umem = &source[umem_start..umem_end];
    assert!(umem.contains("telemetry.counters.touched = true;"));
    assert!(umem.contains("telemetry.counters.umem_slice_dropped += 1;"));
    assert!(umem.contains("binding.scratch.scratch_recycle.push(desc.addr);"));
    assert!(umem.contains("continue;"));

    let vlan_start = source
        .find("if meta.ingress_vlan_present != 0")
        .expect("unknown-VLAN guard must remain in poll head");
    let vlan_end = source[vlan_start..]
        .find("// #10314")
        .map(|offset| vlan_start + offset)
        .expect("VLAN guard must precede destination-MAC guard");
    let vlan = &source[vlan_start..vlan_end];
    assert!(vlan.contains("telemetry.counters.touched = true;"));
    assert!(vlan.contains("telemetry.counters.unknown_vlan_dropped += 1;"));
    assert!(vlan.contains("binding.scratch.scratch_recycle.push(desc.addr);"));
    assert!(vlan.contains("continue;"));

    let mac_start = source
        .find("if !ingress_destination_mac_accepted(")
        .expect("destination-MAC guard must remain in poll head");
    let mac_end = source[mac_start..]
        .find("// #946 Phase 1 stage 5")
        .map(|offset| mac_start + offset)
        .expect("destination-MAC guard must precede L2 classification");
    let mac = &source[mac_start..mac_end];
    assert!(mac.contains("telemetry.counters.touched = true;"));
    assert!(mac.contains("telemetry.counters.dst_mac_dropped += 1;"));
    assert!(mac.contains("binding.scratch.scratch_recycle.push(desc.addr);"));
    assert!(mac.contains("continue;"));
}
