// #18640 (review V): bring-up gives every worker of the set a unique rank and the
// set's width, so each fanned-out HA copy is charged on exactly ONE worker.
use super::*;
use crate::session::{SessionKey, SessionOrigin, SessionTable};

#[test]
fn bring_up_charges_each_key_on_exactly_one_worker_18640() {
    // Sparse ids, as bring-up can produce after a queue is skipped.
    let ids = [0u32, 1, 2, 5, 9, 11];
    let shards = session_limit_shards(ids.iter().copied());
    let mut ranks: Vec<u32> = shards.values().map(|(rank, _)| *rank).collect();
    ranks.sort_unstable();
    assert_eq!(ranks, (0..ids.len() as u32).collect::<Vec<_>>(), "ranks are unique and dense");
    assert!(
        shards.values().all(|(_, width)| *width == ids.len() as u32),
        "every worker's width is the set size: {shards:?}"
    );
    let plans: Vec<WorkerLaunchPlan> = ids
        .iter()
        .map(|id| worker_launch_plan(*id, 0, Vec::new(), crate::PollMode::BusyPoll, &shards))
        .collect();
    for (id, plan) in ids.iter().zip(&plans) {
        assert_eq!(plan.session_limit_shard, shards[id], "worker {id}'s launch plan carries its slot");
    }
    let tables: Vec<SessionTable> = plans
        .iter()
        .map(|plan| {
            let mut table = SessionTable::new();
            table.set_session_limit_shard(plan.session_limit_shard.0, plan.session_limit_shard.1);
            table
        })
        .collect();
    for port in 0..512u16 {
        let key = SessionKey {
            addr_family: libc::AF_INET as u8,
            protocol: 17,
            src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 62, 102)),
            dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 80, 210)),
            src_port: 20000 + port,
            dst_port: 9,
            discriminator: Default::default(),
            routing_domain: 0,
        };
        let charged = tables
            .iter()
            .filter(|table| table.session_limit_counted(&key, SessionOrigin::SyncImport, false))
            .count();
        assert_eq!(charged, 1, "key {port} must be charged on exactly one worker, got {charged}");
    }
}
