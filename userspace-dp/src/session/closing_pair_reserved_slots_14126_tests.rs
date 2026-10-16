use super::tests::{decision, key_v4, metadata};
use super::*;
use crate::tcp_flags::{TCP_ACK, TCP_FIN, TCP_SYN};
use std::net::{IpAddr, Ipv4Addr};

fn filler_key(port: u16) -> SessionKey {
    SessionKey {
        src_port: port,
        ..key_v4()
    }
}

fn install_single(table: &mut SessionTable, key: &SessionKey, now_ns: u64, tcp_flags: u8) {
    assert!(table.install_with_protocol(
        key.clone(),
        decision(),
        metadata(),
        now_ns,
        PROTO_TCP,
        tcp_flags,
    ));
}

/// #14126 decisive check: max=10, len=8, reserved=2, one local closing
/// half, needed=2. Correct: 8-1+2+2=11 > 10 must refuse; buggy preflight
/// computes 8-1+2=9 and admits (then evicts the closing row and the
/// reverse install fails against the reservation).
#[test]
fn closing_pair_preflight_counts_reserved_ipsec_slots_14126() {
    let now = 1_000_000_000u64;
    let mut table = SessionTable::new();

    // Install the closing pair (2 rows), then delete the reverse half so
    // only ONE local closing row remains. This is legitimate: the
    // companion may live on a peer / have been reaped first.
    let forward = key_v4();
    let _reverse = super::tests::install_forward_reverse_pair(&mut table, &forward, now, TCP_ACK);
    // Drive into closing via a FIN on the forward half (propagates closing
    // to both halves).
    assert!(table.lookup(&forward, now + 1_000_000, TCP_FIN).is_some());
    assert!(table.entry_by_key(&forward).expect("fwd").closing);
    let reverse_key = reverse_session_key(&forward, NatDecision::default());
    // Remove only the reverse half; forward closing row stays.
    table.delete(&reverse_key);
    assert!(table.entry_by_key(&forward).is_some());
    assert!(table.entry_by_key(&reverse_key).is_none());
    assert_eq!(table.len(), 1);

    // Reserve two IPsec slots BEFORE capping/filling, in production order:
    // reserve_ipsec_install refuses unless can_admit(2) passes.
    let mut ipsec_key = key_v4();
    ipsec_key.src_ip = IpAddr::V4(Ipv4Addr::new(10, 141, 26, 1));
    ipsec_key.dst_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 141));
    ipsec_key.src_port = 50141;
    ipsec_key.dst_port = 443;
    ipsec_key.discriminator = TunnelDiscriminator::Ipsec(141_260);
    let token = table
        .reserve_ipsec_install(PMechInstallPlan {
            forward_key: ipsec_key.clone(),
            decision: decision(),
            metadata: metadata(),
            owner_worker: 7,
            owner_generation: 141_260,
            plan_expiry_ns: 10_000_000_000,
        })
        .expect("IPsec two-slot reservation at low occupancy");

    // Fill to len=8 with filler singles (max will be 10).
    // Reserved slots consume admission headroom: len + 2 + needed <= max.
    table.set_max_sessions_for_test(10);
    for port in 60_000u16..60_007 {
        install_single(&mut table, &filler_key(port), now, TCP_ACK);
    }
    assert_eq!(table.len(), 8);
    // Sanity: reserved slots are really held.
    assert!(!table.can_admit(1), "len 8 + reserved 2 + 1 > 10");

    // Positive control: with reserved=2, even reclaiming BOTH closing
    // halves would not help here (only one is local), and reclaiming
    // the one local half: 8 - 1 + 2 needed = 9 raw, +2 reserved = 11.
    assert!(
        !table.can_admit_after_closing_tcp_pair_for_syn(2, &forward, TCP_SYN),
        "closing-pair preflight must count reserved IPsec slots: \
         len=8, reclaimed=1, needed=2, reserved=2, max=10 does not fit"
    );
    // The closing row must NOT be evicted by a read-only preflight.
    assert!(
        table.entry_by_key(&forward).is_some(),
        "preflight must not evict the closing row"
    );

    // Positive control: once the reservation is released, the same reuse
    // DOES fit (8 - 1 + 2 = 9 <= 10) — proving the refusal above is due
    // to the reservation, not the tuple shape.
    assert!(table.cancel_ipsec_install(token, 7, 141_260));
    assert!(
        table.can_admit_after_closing_tcp_pair_for_syn(2, &forward, TCP_SYN),
        "after reservation release, reclaiming 1 for 2 needed at len 8/10 fits"
    );
}
