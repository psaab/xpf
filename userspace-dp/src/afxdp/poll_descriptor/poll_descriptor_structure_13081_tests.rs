//! #13081 structural regression for the per-batch PMech replay stage.

#[test]
fn pmech_replay_drain_is_a_sibling_stage_13081() {
    let source = include_str!("mod.rs");
    assert!(
        source.contains("pmech_replay::drain_pending_pmech_replays(")
            && source.contains("&mut binding.pending_pmech_reverse")
            && source.contains("&mut binding.pending_pmech_replay"),
        "the poll loop delegates pending PMech reverse replay to its sibling stage"
    );
    assert!(
        !source.contains("match pmech_directory.probe_token(held.token)")
            && !source.contains("for _ in 0..pmech_scan_len"),
        "the large poll function must not inline PMech replay-stage control flow"
    );
}

// #13766: behavioral drain coverage for the #13636 TX-pool return.
//
// Drive the real `drain_pending_pmech_replays` with fresh directories (never
// `PMechSessionDirectory::global()`) and assert the actual destination deques.
// Test both terminal reasons: an expired token becomes Absent, and a held
// packet's owner generation can mismatch a newer token owner generation. Each
// reason is exercised for both injected TX-pool frames and native RX frames.
// Reverting, swapping, or removing the `is_injected` branch must fail these
// assertions even though no source-string check is involved.
mod pmech_drain_13766 {
    use super::super::pmech_replay::drain_pending_pmech_replays;
    use crate::afxdp::types::{PendingPMechReversePacket, UserspaceDpMeta};
    use crate::session::{
        PMechClaimKind, PMechClaimSpec, PMechDirection, PMechSessionDirectory, PMechWaiterRef,
        SessionKey, TunnelDiscriminator,
    };
    use crate::xsk_ffi::xdp::XdpDesc;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};

    const GEN: u64 = 7;

    fn test_key() -> SessionKey {
        SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: crate::ip_proto::PROTO_UDP,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 137, 66, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 137)),
            src_port: 13_766,
            dst_port: 443,
            discriminator: TunnelDiscriminator::Ipsec(137_066),
            routing_domain: 7,
        }
    }

    fn reserve_pending(directory: &PMechSessionDirectory, owner_generation: u64) -> u64 {
        directory
            .reserve_claims(
                owner_generation,
                u64::MAX,
                &[PMechClaimSpec::new(
                    test_key(),
                    PMechClaimKind::Pending,
                    PMechDirection::Reverse,
                )],
            )
            .expect("reserve test pmech claim")
    }

    fn held(
        is_injected: bool,
        token: u64,
        owner_generation: u64,
        addr: u64,
    ) -> PendingPMechReversePacket {
        PendingPMechReversePacket {
            desc: XdpDesc {
                addr,
                len: 64,
                options: 0,
            },
            meta: UserspaceDpMeta::default(),
            waiter: PMechWaiterRef {
                arrival_worker_id: 137,
                defer_id: addr,
            },
            token,
            owner_generation,
            is_injected,
        }
    }

    fn run_drain(
        directory: &PMechSessionDirectory,
        pending_reverse: &mut VecDeque<PendingPMechReversePacket>,
    ) -> (Vec<u64>, Vec<u64>) {
        let mut pending_replay = VecDeque::new();
        let mut scratch_recycle = Vec::new();
        let mut tx_recycle = VecDeque::new();
        drain_pending_pmech_replays(
            directory,
            pending_reverse,
            &mut pending_replay,
            &mut scratch_recycle,
            &mut tx_recycle,
        );
        assert!(
            pending_replay.is_empty(),
            "terminal probes must not enqueue packets for replay"
        );
        assert!(
            pending_reverse.is_empty(),
            "terminal probes must drain every held packet"
        );
        (scratch_recycle, tx_recycle.into_iter().collect())
    }

    fn assert_routing(is_injected: bool, addr: u64, scratch: &[u64], tx: &[u64]) {
        if is_injected {
            assert_eq!(
                tx,
                &[addr],
                "injected (WireGuard plaintext) frame descriptor addr {addr} came from the TX pool and MUST return to tx_recycle"
            );
            assert!(
                scratch.is_empty(),
                "injected frame addr {addr} must never land in scratch_recycle (RX fill ring): got {scratch:?}"
            );
        } else {
            assert_eq!(
                scratch,
                &[addr],
                "native RX frame descriptor addr {addr} MUST return to scratch_recycle"
            );
            assert!(
                tx.is_empty(),
                "native RX addr {addr} must never land in tx_recycle (TX pool): got {tx:?}"
            );
        }
    }

    #[test]
    fn expired_token_recycles_injected_to_tx_and_native_to_scratch_13766() {
        for is_injected in [true, false] {
            let directory = PMechSessionDirectory::new();
            let token = reserve_pending(&directory, GEN);
            assert!(
                directory.mark_uncertain(token, GEN, 100),
                "fixture: reserved token must become uncertain-denied"
            );
            assert_eq!(directory.expire_uncertain(100), 1);
            let addr = if is_injected { 0xA001 } else { 0xA002 };
            let mut pending: VecDeque<_> = [held(is_injected, token, GEN, addr)].into();
            let (scratch, tx) = run_drain(&directory, &mut pending);
            assert_routing(is_injected, addr, &scratch, &tx);
        }
    }

    #[test]
    fn changed_generation_recycles_injected_to_tx_and_native_to_scratch_13766() {
        // A Live token belonging to a newer owner generation is not replayable
        // by a packet held under the old generation, and must be recycled.
        for is_injected in [true, false] {
            let directory = PMechSessionDirectory::new();
            let live_gen = GEN + 1;
            let token = reserve_pending(&directory, live_gen);
            assert!(
                directory.mark_live(token, live_gen, 1, 2),
                "fixture: reserved token must become live"
            );
            let addr = if is_injected { 0xB001 } else { 0xB002 };
            let mut pending: VecDeque<_> = [held(is_injected, token, GEN, addr)].into();
            let (scratch, tx) = run_drain(&directory, &mut pending);
            assert_routing(is_injected, addr, &scratch, &tx);
        }
    }

    #[test]
    fn mixed_batch_routes_each_frame_to_its_own_pool_13766() {
        let directory = PMechSessionDirectory::new();
        let mut pending: VecDeque<_> = [
            held(true, 0xDEAD, GEN, 0xC001),
            held(false, 0xDEAD, GEN, 0xC002),
        ]
        .into();
        let (scratch, tx) = run_drain(&directory, &mut pending);
        assert_eq!(
            tx,
            vec![0xC001],
            "the single injected frame returns to tx_recycle exactly once"
        );
        assert_eq!(
            scratch,
            vec![0xC002],
            "the single native RX frame returns to scratch_recycle exactly once"
        );
    }
}
