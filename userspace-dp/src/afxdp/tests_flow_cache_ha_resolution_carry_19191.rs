// #19191: a split-RG / active-active NON-OWNER keeps its cached redirected
// flows across the periodic primary-liveness re-imports (#19173 option A).
//
// On such a node the HA import handler stores the raw local candidate
// (`ForwardCandidate`) unenforced, and the slow path persists the HA-derived
// `FabricRedirect` into the row on its first packet (#12265 Owner-persist).
// Under #19173's rule (option B) every liveness re-import then differed from
// the row by that judgment alone, minted a new install epoch, and the next
// packet of every cached redirected flow was refused (`Replaced`, counted as
// no-record) and re-seeded: N cached flows cost N slow-path packets per
// liveness interval. #19191 lets the import keep the row's resolution, its
// forwarding stamp and its epoch when it differs from the row ONLY by this
// node's own current HA judgment (`ha_resolution_carry_applies`).
//
// Every packet goes through the production poll function and every import
// and HA transition through the production worker-command dispatcher. The
// RG epoch array persists across packets here (`txn_run_multi_binding_with_
// rg_epochs`), so the flow cache's own epoch fence is what an HA transition
// trips, as in production (`ha/state.rs` bumps before it publishes).
#![allow(unused_imports)]

use super::test_fixtures::*;
use super::tests_flow_cache_reimport_churn_19173::{
    Round, split_forward, split_pair, split_rg_churn, upsert_local_churn,
};
use super::tests_split_rg_failback_18531::{
    DPORT, FABRIC, LAN, LAN_HOST, LAN_IFINDEX, SPORT, TCP_ACK, WAN, WAN_HOST, WAN_UNIT_IFINDEX,
    apply_commands, bindings, fw1_owner_forwarding, owner_ha, split_ha,
};
use super::tests_support::*;
use super::*;
use crate::afxdp::flow_cache::FlowCacheEvictionArm as Arm;
use crate::afxdp::session_glue::commands::upsert_synced::HaResolutionCarryDisabledForTest;
use crate::session::{
    ForwardingGenerationStamp, SessionDecision, SessionKey, SessionOrigin, SessionTable,
};
use std::sync::atomic::{AtomicU32, Ordering};

const FLOWS: u16 = 64;
const ROUNDS: usize = 5;

fn replaced_this_thread() -> u64 {
    crate::afxdp::flow_cache::FLOW_CACHE_REPLACED_EVICTIONS_THIS_THREAD.with(|count| count.get())
}

/// THE measurement as a cell (docs/log/19191.md): 64 cached flows, five
/// rounds. Split-RG non-owner: every round re-imports every pair as a
/// primary-liveness frame (same wire id, same content) and sends one LAN
/// packet per flow; UpsertLocal: every round refreshes every row with no wire
/// id. Every round must keep every flow on the cache: 64 hits, no eviction on
/// any arm, no replaced refusal. Option (B) (the #19173 rule) measured 64
/// no-record evictions per split-RG round; MR2 (never carry a resolution
/// difference) reds this cell.
#[test]
fn liveness_reimports_keep_every_cached_redirect_19191() {
    let replaced_before = replaced_this_thread();
    let (control, rounds) = split_rg_churn(FLOWS, ROUNDS);
    assert_eq!(control.hits, u64::from(FLOWS), "premise: control round: {control:?}");
    for (n, round) in rounds.iter().enumerate() {
        assert_eq!(
            (round.packets, round.hits, round.no_record_evictions, round.evictions),
            (u64::from(FLOWS), u64::from(FLOWS), 0, 0),
            "split_rg round {n}: every redirected flow must stay cached across the \
             liveness re-import: {round:?}"
        );
    }
    assert_eq!(replaced_this_thread(), replaced_before, "split_rg: nothing refused as Replaced");
    let (control, rounds) = upsert_local_churn(FLOWS, ROUNDS);
    assert_eq!(control.hits, u64::from(FLOWS), "premise: control round: {control:?}");
    for (n, round) in rounds.iter().enumerate() {
        assert_eq!(
            (round.packets, round.hits, round.no_record_evictions, round.evictions),
            (u64::from(FLOWS), u64::from(FLOWS), 0, 0),
            "upsert_local round {n}: {round:?}"
        );
    }
    assert_eq!(replaced_this_thread(), replaced_before, "upsert_local: nothing refused");
}

/// The TRUE twin of the cell above: the same procedure with the handler's HA
/// judgment switched off (test builds only), which is exactly the #19173
/// option (B) install. Every split-RG round now refuses every cached flow
/// once (64 no-record evictions, 64 replaced refusals, 0 hits), so the cell
/// above can tell the carry from its absence.
#[test]
fn twin_without_the_carry_evicts_every_cached_redirect_19191() {
    let _off = HaResolutionCarryDisabledForTest::new();
    let replaced_before = replaced_this_thread();
    let (control, rounds) = split_rg_churn(FLOWS, ROUNDS);
    assert_eq!(control.hits, u64::from(FLOWS), "premise: control round: {control:?}");
    for (n, round) in rounds.iter().enumerate() {
        assert_eq!(
            (round.hits, round.no_record_evictions, round.evictions),
            (0, u64::from(FLOWS), u64::from(FLOWS)),
            "twin round {n}: option (B) re-seeds every flow once per re-import: {round:?}"
        );
    }
    assert_eq!(
        replaced_this_thread() - replaced_before,
        u64::from(FLOWS) * ROUNDS as u64,
        "twin: every eviction was a Replaced refusal"
    );
}

// ---------------------------------------------------------------------------
// A split-RG fixture whose flow cache AND RG epochs persist across packets.
// ---------------------------------------------------------------------------

/// What one LAN packet did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sent {
    cache_hit: bool,
    /// Per-binding TX deltas, indexed WAN / FABRIC / LAN.
    tx: [u64; 3],
}

const VIA_FABRIC: [u64; 3] = [0, 1, 0];
const VIA_WAN: [u64; 3] = [1, 0, 0];

struct Split {
    forwarding: ForwardingState,
    sessions: SessionTable,
    bindings: Vec<BindingWorker>,
    rg_epochs: [AtomicU32; MAX_RG_EPOCHS],
    /// The config generation the next packet's pass runs under.
    config_generation: u64,
    flows: u16,
}

impl Split {
    /// `flows` SNAT flows imported from the WAN owner on fw1 holding the LAN
    /// RG only (`split_ha`), each seeded into the LAN binding's cache by one
    /// fabric-redirected packet.
    fn seeded(flows: u16) -> Self {
        let forwarding = fw1_owner_forwarding();
        let mut sessions = SessionTable::new();
        sessions.set_forwarding_revalidation_gen(7, 9);
        let mut fx = Split {
            forwarding,
            sessions,
            bindings: bindings(),
            rg_epochs: std::array::from_fn(|_| AtomicU32::new(0)),
            config_generation: 7,
            flows,
        };
        fx.reimport(&split(), SessionOrigin::SyncImport);
        assert_eq!(fx.sessions.len(), 2 * flows as usize, "fixture: every pair imported");
        for i in 0..flows {
            assert_eq!(
                fx.send(&split(), i),
                Sent { cache_hit: false, tx: VIA_FABRIC },
                "premise: flow {i}'s first packet is fabric-redirected and seeds"
            );
            assert_eq!(
                fx.send(&split(), i),
                Sent { cache_hit: true, tx: VIA_FABRIC },
                "premise: flow {i} is cache-served"
            );
        }
        fx
    }

    /// Re-import every pair through the production dispatcher under `ha`.
    fn reimport(&mut self, ha: &BTreeMap<i32, HAGroupRuntime>, origin: SessionOrigin) {
        let mut commands = Vec::new();
        for i in 0..self.flows {
            commands.extend(split_pair(&self.forwarding, ha, i, origin));
        }
        apply_commands(
            &mut self.sessions,
            &self.forwarding,
            ha,
            commands.into_iter().map(WorkerCommand::UpsertSynced).collect(),
        );
    }

    /// One mid-stream LAN -> WAN ACK of flow `i`, persistent cache and epochs.
    fn send(&mut self, ha: &BTreeMap<i32, HAGroupRuntime>, i: u16) -> Sent {
        let sport = SPORT + i;
        let frame = build_txn_tcp_syn_frame_v4(
            LAN_HOST,
            WAN_HOST,
            sport,
            DPORT,
            TCP_ACK,
            [0x02, 0xbf, 0x72, 0x16, 0x02, 0x03],
        );
        let mut meta = txn_meta_v4(LAN_IFINDEX as u32, TCP_ACK, frame.len() as u16);
        meta.flow_src_addr[..4].copy_from_slice(&LAN_HOST.octets());
        meta.flow_dst_addr[..4].copy_from_slice(&WAN_HOST.octets());
        meta.flow_src_port = sport;
        meta.flow_dst_port = DPORT;
        meta.config_generation = self.config_generation;
        let tx = |bindings: &Vec<BindingWorker>| -> [u64; 3] {
            [WAN, FABRIC, LAN].map(|b| bindings[b].live.tx_packets.load(Ordering::Relaxed))
        };
        let hits_before = self.bindings[LAN].flow.flow_cache.hits;
        let tx_before = tx(&self.bindings);
        let shared = Arc::new(Mutex::new(FastMap::default()));
        let (_batch, dbg, _egress) = txn_run_multi_binding_with_rg_epochs(
            &mut self.bindings,
            LAN,
            &mut self.sessions,
            &self.forwarding,
            ha,
            &frame,
            meta,
            &shared,
            &Arc::new(Mutex::new(FastMap::default())),
            &Arc::new(Mutex::new(FastMap::default())),
            &SharedSessionOwnerRgIndexes::default(),
            self.config_generation,
            0,
            Some(&self.rg_epochs),
        );
        assert_eq!(dbg.rx, 1, "anti-vacuity: the descriptor reached the poll body");
        let tx_after = tx(&self.bindings);
        Sent {
            cache_hit: self.bindings[LAN].flow.flow_cache.hits > hits_before,
            tx: [0, 1, 2].map(|b| tx_after[b] - tx_before[b]),
        }
    }

    fn key(&self, i: u16) -> SessionKey {
        split_forward(&self.forwarding, i).key
    }

    /// Flow `i`'s forward row: decision, install epoch, forwarding stamp.
    fn row(&self, i: u16) -> (SessionDecision, u64, ForwardingGenerationStamp) {
        let key = self.key(i);
        let (decision, _, _, stamp) = self
            .sessions
            .entry_with_origin_and_forwarding_generation(&key)
            .expect("forward row");
        let epoch = self
            .sessions
            .backing_install_epoch_for_cache_hit(&key, monotonic_nanos())
            .expect("forward row epoch");
        (decision, epoch, stamp)
    }

    fn epochs(&self) -> Vec<u64> {
        (0..self.flows).map(|i| self.row(i).1).collect()
    }

    /// The HA transition order of `ha/state.rs`: the RG's epoch (and, on an
    /// activation, the node-level slot 0) moves BEFORE the new HA state is
    /// visible, then the worker command follows.
    fn bump_rg1_epoch(&self, activation: bool) {
        self.rg_epochs[1].fetch_add(1, Ordering::Release);
        if activation {
            self.rg_epochs[0].fetch_add(1, Ordering::Release);
        }
    }
}

fn now_secs() -> u64 {
    monotonic_nanos() / 1_000_000_000
}

fn split() -> BTreeMap<i32, HAGroupRuntime> {
    split_ha(now_secs())
}

fn owner() -> BTreeMap<i32, HAGroupRuntime> {
    owner_ha(now_secs())
}

/// The premise every HA cell starts from: a liveness re-import on the split
/// node carried every row (same epoch, the persisted redirect and its fresh
/// stamp kept) and the flows stay on the cache.
fn carried(fx: &mut Split) {
    let before: Vec<_> = (0..fx.flows).map(|i| fx.row(i)).collect();
    fx.reimport(&split(), SessionOrigin::SyncLiveness);
    for i in 0..fx.flows {
        let (decision, epoch, stamp) = fx.row(i);
        assert_eq!(
            decision.resolution.disposition,
            ForwardingDisposition::FabricRedirect,
            "premise: flow {i}'s persisted redirect is kept"
        );
        assert_eq!((decision, epoch, stamp), before[i as usize], "premise: flow {i} carried");
        assert!(stamp.valid, "premise: flow {i}'s kept stamp is a validated one");
        assert_eq!(
            fx.send(&split(), i),
            Sent { cache_hit: true, tx: VIA_FABRIC },
            "premise: flow {i} stays cached across the carry"
        );
    }
}

/// A carried row whose RG then ACTIVATES on this node: the cached redirect is
/// fenced (the RG epoch moved before the new HA state became visible), the
/// RefreshOwnerRGS rewrite makes the row a local WAN candidate, and the first
/// packet re-derives the new HA judgment: it leaves on the WAN, never the
/// fabric, and re-seeds a WAN entry that the next packet hits.
#[test]
fn activation_fences_a_carried_redirect_and_forwards_locally_19191() {
    let mut fx = Split::seeded(4);
    carried(&mut fx);
    fx.bump_rg1_epoch(true);
    apply_commands(
        &mut fx.sessions,
        &fx.forwarding,
        &owner(),
        vec![WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] }],
    );
    for i in 0..fx.flows {
        let (decision, _, stamp) = fx.row(i);
        assert_eq!(
            (decision.resolution.disposition, decision.resolution.egress_ifindex),
            (ForwardingDisposition::ForwardCandidate, WAN_UNIT_IFINDEX),
            "flow {i}: the activation refresh rewrites the carried redirect to the WAN"
        );
        assert!(stamp.valid, "flow {i}: the refresh stamps its own derivation");
    }
    let evictions_before: u64 = fx.bindings[LAN].flow.flow_cache.evictions_by_arm.iter().sum();
    for i in 0..fx.flows {
        assert_eq!(
            fx.send(&owner(), i),
            Sent { cache_hit: false, tx: VIA_WAN },
            "flow {i}: the cached redirect is fenced and the slow path forwards locally"
        );
    }
    let arms = fx.bindings[LAN].flow.flow_cache.evictions_by_arm;
    assert_eq!(
        arms.iter().sum::<u64>() - evictions_before,
        u64::from(fx.flows),
        "one fence per carried entry: {arms:?}"
    );
    for i in 0..fx.flows {
        assert_eq!(
            fx.send(&owner(), i),
            Sent { cache_hit: true, tx: VIA_WAN },
            "flow {i}: the re-seeded entry is the local WAN candidate"
        );
    }
}

/// The same activation with RefreshOwnerRGS not yet applied (the coordinator
/// pushes it after publishing the new state, `ha/state.rs`): the carried row
/// still holds the redirect with a validated stamp. The epoch fence sends the
/// first packet to the slow path, which re-judges HA on every pass: the
/// stored redirect takes the #15958b/#16524 rehome-or-retain verdict, and
/// with the WAN host's connected owner (RG1) now active here and the fresh
/// route reaching it, the flow re-homes onto the WAN and re-seeds there.
#[test]
fn activation_before_refresh_rehomes_a_carried_redirect_19191() {
    let mut fx = Split::seeded(4);
    carried(&mut fx);
    fx.bump_rg1_epoch(true);
    for i in 0..fx.flows {
        assert_eq!(
            fx.send(&owner(), i),
            Sent { cache_hit: false, tx: VIA_WAN },
            "flow {i}: fenced, and the slow path re-homes the carried redirect"
        );
        assert_eq!(
            fx.send(&owner(), i),
            Sent { cache_hit: true, tx: VIA_WAN },
            "flow {i}: the re-seeded entry is the local WAN candidate"
        );
    }
}

/// HA safety of the carry condition itself: a liveness re-import that lands
/// AFTER this node's activation became visible but BEFORE RefreshOwnerRGS ran
/// must not keep the redirect. The handler now runs on the active path
/// (owner RG forwarding-active here), states no judgment and installs the
/// HA-enforced local candidate; the import mints. MR1 (carry any resolution
/// difference) keeps the redirect in the row here: a node that owns the RG
/// would hold a stored redirect, which the #15958b rehome-or-retain verdict
/// keeps on a transient FIB lag.
#[test]
fn import_after_activation_installs_the_local_candidate_19191() {
    let mut fx = Split::seeded(4);
    carried(&mut fx);
    let carried_epochs = fx.epochs();
    fx.bump_rg1_epoch(true);
    fx.reimport(&owner(), SessionOrigin::SyncLiveness);
    for i in 0..fx.flows {
        let (decision, epoch, stamp) = fx.row(i);
        assert_eq!(
            (decision.resolution.disposition, decision.resolution.egress_ifindex),
            (ForwardingDisposition::ForwardCandidate, WAN_UNIT_IFINDEX),
            "flow {i}: the import on the RG owner installs the local candidate"
        );
        assert_ne!(epoch, carried_epochs[i as usize], "flow {i}: a new incarnation");
        assert_eq!(stamp, ForwardingGenerationStamp::default(), "flow {i}: unvalidated");
    }
    for i in 0..fx.flows {
        assert_eq!(
            fx.send(&owner(), i),
            Sent { cache_hit: false, tx: VIA_WAN },
            "flow {i}: the first post-activation packet forwards locally"
        );
    }
}

/// A full cycle back: from the activated, locally forwarding state the RG
/// DEMOTES again. The cached WAN entries are fenced, DemoteOwnerRGS
/// re-resolves the rows to the redirect, the packets go back to the fabric,
/// and a later liveness re-import on the split node carries again (the
/// demote's refresh stamped the redirect as this node's own derivation).
#[test]
fn demote_redirects_again_and_the_next_reimport_carries_19191() {
    let mut fx = Split::seeded(4);
    carried(&mut fx);
    fx.bump_rg1_epoch(true);
    apply_commands(
        &mut fx.sessions,
        &fx.forwarding,
        &owner(),
        vec![WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] }],
    );
    for i in 0..fx.flows {
        assert_eq!(fx.send(&owner(), i).tx, VIA_WAN, "premise: flow {i} forwards locally");
        assert_eq!(fx.send(&owner(), i), Sent { cache_hit: true, tx: VIA_WAN });
    }
    fx.bump_rg1_epoch(false);
    apply_commands(
        &mut fx.sessions,
        &fx.forwarding,
        &split(),
        vec![WorkerCommand::DemoteOwnerRGS { owner_rgs: vec![1] }],
    );
    for i in 0..fx.flows {
        assert_eq!(
            fx.send(&split(), i),
            Sent { cache_hit: false, tx: VIA_FABRIC },
            "flow {i}: the cached WAN entry is fenced and the flow redirects again"
        );
        assert_eq!(fx.send(&split(), i), Sent { cache_hit: true, tx: VIA_FABRIC });
    }
    carried(&mut fx);
}

/// The kept forwarding stamp cannot outlive a generation change: after a
/// carry, a new config generation fences every cached entry (generation
/// arm), the slow path finds the kept stamp stale, re-resolves and persists
/// under the new generation, and the next liveness re-import carries again
/// under that generation.
#[test]
fn a_generation_change_revalidates_the_kept_row_19191() {
    let mut fx = Split::seeded(4);
    carried(&mut fx);
    let (_, _, old_stamp) = fx.row(0);
    fx.config_generation = 8;
    let generation_before = fx.bindings[LAN].flow.flow_cache.evictions_by_arm
        [Arm::LookupGeneration as usize];
    for i in 0..fx.flows {
        assert_eq!(
            fx.send(&split(), i),
            Sent { cache_hit: false, tx: VIA_FABRIC },
            "flow {i}: a new generation fences the entry"
        );
        let (decision, _, stamp) = fx.row(i);
        assert_eq!(decision.resolution.disposition, ForwardingDisposition::FabricRedirect);
        assert!(stamp.valid && stamp != old_stamp, "flow {i}: re-persisted under the new generation");
        assert_eq!(stamp.config_generation, 8, "flow {i}");
    }
    assert_eq!(
        fx.bindings[LAN].flow.flow_cache.evictions_by_arm[Arm::LookupGeneration as usize]
            - generation_before,
        u64::from(fx.flows),
        "the generation fence fired once per entry"
    );
    carried(&mut fx);
}

/// A re-import that changes a non-HA forwarding field (the SNAT port) while
/// also differing from the row in disposition mints, and the import's
/// decision wins: the row holds the new translation and the unenforced
/// candidate, unvalidated, and the cached entry (seeded with the old
/// translation) is refused on its next hit. MR4 (drop the NAT/table equality)
/// reds it.
#[test]
fn non_ha_change_with_a_disposition_difference_mints_19191() {
    let mut fx = Split::seeded(2);
    carried(&mut fx);
    let (before, epoch_before, _) = fx.row(0);
    let mut forward = split_forward(&fx.forwarding, 0);
    forward.origin = SessionOrigin::SyncLiveness;
    forward.decision.nat.rewrite_src_port = Some(40123);
    assert_ne!(forward.decision.nat, before.nat, "premise: a NAT change");
    apply_commands(
        &mut fx.sessions,
        &fx.forwarding,
        &split(),
        vec![WorkerCommand::UpsertSynced(forward)],
    );
    let (decision, epoch, stamp) = fx.row(0);
    assert_eq!(decision.nat.rewrite_src_port, Some(40123), "the import's NAT wins");
    assert_eq!(
        decision.resolution.disposition,
        ForwardingDisposition::ForwardCandidate,
        "the import's own (unenforced) resolution is installed"
    );
    assert_ne!(epoch, epoch_before, "a new incarnation");
    assert_eq!(stamp, ForwardingGenerationStamp::default(), "unvalidated");
    let replaced_before = replaced_this_thread();
    let sent = fx.send(&split(), 0);
    assert!(!sent.cache_hit, "the entry seeded with the old translation is not served");
    assert_eq!(replaced_this_thread() - replaced_before, 1, "refused as Replaced");
    // The unchanged flow still carries and stays cached.
    assert_eq!(fx.send(&split(), 1), Sent { cache_hit: true, tx: VIA_FABRIC });
}
