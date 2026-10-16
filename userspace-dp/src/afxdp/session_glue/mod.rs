use super::*;
use crate::session::ForwardingGenerationStamp;
use std::sync::atomic::{AtomicU64, Ordering};

pub(in crate::afxdp) mod commands;
mod delete_drop_sweep;
mod install_table_purge;
mod promote;

pub(in crate::afxdp) use delete_drop_sweep::{DELETE_DROP_SWEEP_BUDGET, DeleteDropSweep};
pub(in crate::afxdp) use install_table_purge::{
    INSTALL_TABLE_PURGE_BUDGET, InstallTablePurge, install_table_purge_predicate,
};
pub(in crate::afxdp) use promote::{
    SharedSessionRefs, maybe_promote_synced_session, maybe_promote_synced_session_with_conntrack,
    SessionHitVerdict,
};
/// #10507 Cell 5a test seam: command-driven Demote/Refresh funnels for
/// cross-module poll tests (unshared map, no BPF). Production `handle_*`
/// stay `pub(in session_glue)`; these `#[cfg(test)]` delegates widen
/// nothing outside tests.
#[cfg(test)]
pub(crate) fn handle_demote_owner_rgs_for_test(
    sessions: &mut crate::session::SessionTable,
    session_map: crate::afxdp::bpf_map::SteeringMap<'_>,
    conntrack_v4_fd: libc::c_int,
    conntrack_v6_fd: libc::c_int,
    forwarding: &crate::afxdp::ForwardingState,
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::HAGroupRuntime>,
    dynamic_neighbors: &std::sync::Arc<crate::afxdp::sharded_neighbor::ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
    cancelled_keys: &mut Vec<crate::session::SessionKey>,
    cancelled_keys_seen: &mut rustc_hash::FxHashSet<crate::session::SessionKey>,
) -> bool {
    commands::handle_demote_owner_rgs(
        sessions, session_map, conntrack_v4_fd, conntrack_v6_fd, forwarding,
        ha_state, dynamic_neighbors, owner_rgs, now_ns, now_secs,
        cancelled_keys, cancelled_keys_seen,
    )
}
#[cfg(test)]
pub(crate) fn handle_refresh_owner_rgs_for_test(
    sessions: &mut crate::session::SessionTable,
    session_map: crate::afxdp::bpf_map::SteeringMap<'_>,
    forwarding: &crate::afxdp::ForwardingState,
    ha_state: &std::collections::BTreeMap<i32, crate::afxdp::HAGroupRuntime>,
    dynamic_neighbors: &std::sync::Arc<crate::afxdp::sharded_neighbor::ShardedNeighborMap>,
    owner_rgs: Vec<i32>,
    now_ns: u64,
    now_secs: u64,
) -> bool {
    commands::handle_refresh_owner_rgs(
        sessions, session_map, forwarding, ha_state, dynamic_neighbors,
        owner_rgs, now_ns, now_secs,
    )
}
#[cfg(test)]
use promote::purge_translated_synced_hit;
use promote::should_keep_synced_hit_transient;

mod resolution;
mod worker_commands;
mod revalidation;
mod tx_cancel;
mod resolve;
#[cfg(test)]
mod modularity_13082_tests;
pub(super) use resolution::*;
pub(super) use worker_commands::*;
pub(super) use revalidation::*;
pub(super) use tx_cancel::*;
pub(super) use resolve::*;
pub(crate) use resolution::{INSTALL_TABLE_PURGE_NEEDED, policy_id_for_list_request};
pub(crate) use revalidation::{
    forward_export_candidates_for_owner_rgs, publish_worker_session_map_entry,
};
#[cfg(test)]
pub(crate) use revalidation::export_forward_sessions_for_owner_rgs;
pub(crate) use worker_commands::{
    PEER_DELETE_REFUSED_LOCAL_OWNED, SESSION_DELETE_DROP_EPOCH,
    SESSION_DELETE_REPLICA_DROPPED, SESSION_DELETE_REPLICA_DROP_REPAIRED,
    SESSION_REPLICATION_ENQUEUED, SESSION_REPLICATION_LOCK_CONTENDED,
    SESSION_REPLICATION_QUEUE_DEPTH_MAX, SESSION_REPLICATION_QUEUE_DEPTH_SUM,
    SESSION_REPLICATION_UPSERTS, session_delete_drop_epoch,
};
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[path = "deleted_first_policy_purge_9526_tests.rs"]
mod deleted_first_policy_purge_9526_tests;
#[cfg(test)]
#[path = "pbr_install_table_9752_tests.rs"]
mod pbr_install_table_9752_tests;
// #4800: publish + sibling-replication contention accounting for the
// new-flow-install ceiling harness. Kept in its own file rather than
// appended to `tests.rs` (already ~7k lines).
#[cfg(test)]
#[path = "newflow_contention_tests.rs"]
mod newflow_contention_tests;
// #9951: established-session routing revocation regression and controls.
#[cfg(test)]
#[path = "leak_revoke_9951_tests.rs"]
mod leak_revoke_9951_tests;
// #9517: the worker publish path's routing-domain WIRING, driven against the
// `bpf_map` write recorder. Its own file for the same reason as the one above.
#[cfg(test)]
#[path = "routing_domain_publish_9517_tests.rs"]
mod routing_domain_publish_9517_tests;
// #9560: the steering map's shared-row DELETE, driven against the same recorder.
#[cfg(test)]
#[path = "steering_row_owners_9560_tests.rs"]
mod steering_row_owners_9560_tests;

// #6600: the coordinator's pre-publish NAT reservation resolves the synced zone
// pair through the SAME helper the worker-side upsert uses, so the two cannot
// land on different allocators.
pub(in crate::afxdp) use commands::upsert_synced::synced_source_nat_zone_pair;

/// #7919: one worker's answer to a `QuerySessionCounters` request.
///
/// `found` is carried separately from the counters because "I hold this session
/// and it has no traffic" and "I do not hold this session" are different facts,
/// and the query exists to tell them apart. A single zeroed row would collapse
/// them and answer neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionCounterAnswer {
    pub sequence: u64,
    pub found: bool,
    /// True when the held entry is a peer-synced/replica origin. A replica
    /// reporting VOLUME would falsify the premise the investigation rests on —
    /// that replicas are created at zero and cannot advance — so the answer
    /// carries what it would take to notice that.
    pub replica: bool,
    pub fwd_packets: u64,
    pub fwd_bytes: u64,
    pub rev_packets: u64,
    pub rev_bytes: u64,
}
