// #18705: a reply that arrives between the RG-activation HA store and this
// worker's `RefreshOwnerRGS` must not be source-NAT judged on the stale line.
//
// `update_ha_state` bumps the node-level activation epoch, stores the
// activated view, and only then pushes `RefreshOwnerRGS` to each worker. A
// worker that polls under the activated view before its refresh lands judges
// a reverse hit against the local forward companion's STORED line; on the
// LAN owner of an RG split that line is the split-FIB default via reth0.50,
// and the reth0.80 translation does not match it: StaleSourceNat, full-pair
// teardown, mid-failover. The fix declines that revocation while this
// table's refresh for the current activation epoch is pending (bounded), and
// loads the command-dispatch view after the queue drain so the refresh
// itself cannot run under the pre-activation view.
//
// The cells reuse the #18531 poll harness and the #18691 LAN-owner import.
// The fixture shapes the live flow; see `tests_lan_owner_idle_import_18691.rs`.
// The cells that drive the coordinator and the worker's production command
// phase are in `tests_refresh_pending_pipeline_18705.rs`.
use super::tests_lan_owner_idle_import_18691::*;
use super::tests_split_rg_failback_18531::*;
use super::tests_support::*;
use super::*;

/// The translation no rule produces (as if the owner had readdressed
/// reth0.80): what a genuinely withdrawn translation looks like here.
const READDRESSED: Ipv4Addr = Ipv4Addr::new(172, 16, 80, 99);

/// A WAN reply on reth0.80 addressed to `translated`.
fn wan_reply_to(translated: Ipv4Addr) -> (Vec<u8>, UserspaceDpMeta) {
    let wan_mac = [0x02, 0xbf, 0x72, 0x16, 0x01, 0x01];
    let frame =
        build_txn_tcp_syn_frame_v4(WAN_HOST, translated, DPORT, SPORT, TCP_ACK, wan_mac);
    let mut meta = txn_meta_v4(WAN_UNIT_IFINDEX as u32, TCP_ACK, frame.len() as u16);
    meta.ingress_vlan_id = 80;
    set_flow(
        &mut meta,
        IpAddr::V4(WAN_HOST),
        IpAddr::V4(translated),
        DPORT,
        SPORT,
    );
    (frame, meta)
}

/// The LAN owner's import of a flow whose translation no rule produces,
/// under the split FIB, with no carried traffic (the #16217 established
/// reverse guard must not be what decides these cells).
fn lan_owner_import_withdrawn(now_secs: u64) -> SessionTable {
    import_pair(
        &rg_taking_node_forwarding(),
        &split_ha(now_secs),
        Family::V4,
        false,
        Numbering::Peer,
        Some(IpAddr::V4(READDRESSED)),
        None,
    )
}

/// Dispatch `commands` under a caller-fixed view whose published activation
/// epoch is `view_epoch0`, through the production dispatcher.
fn apply_at_view_epoch(
    sessions: &mut SessionTable,
    forwarding: &ForwardingState,
    ha: &BTreeMap<i32, HAGroupRuntime>,
    view_epoch0: u32,
    commands: Vec<WorkerCommand>,
) {
    let queue = Arc::new(Mutex::new(VecDeque::from(commands)));
    crate::afxdp::session_glue::apply_worker_commands_at_view_epoch(
        &queue,
        sessions,
        crate::afxdp::bpf_map::SteeringMap::unshared_for_test(-1),
        -1,
        -1,
        forwarding,
        ha,
        Some(view_epoch0),
        &Arc::new(ShardedNeighborMap::default()),
        0,
        &mut VecDeque::new(),
    );
}

/// The withdrawn translation across the window: kept while the refresh is
/// pending (the stored line is no evidence either way), revoked at the first
/// reply after the refresh, whose `refresh_for_ha_transition` cleared the
/// judgment and re-resolved the line onto reth0.80. The keep defers the
/// revocation by one refresh; it never forgives it.
#[test]
fn withdrawn_translation_kept_while_refresh_pending_revoked_after_18705() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let owner_forwarding = fw1_owner_forwarding();
    let mut sessions = lan_owner_import_withdrawn(now_secs);
    let epoch0 = wire_epoch_reader_18705(&mut sessions);
    epoch0.fetch_add(1, Ordering::Relaxed);
    let reply = |sessions: &mut SessionTable| {
        let (frame, meta) = wan_reply_to(READDRESSED);
        drive(sessions, &owner_forwarding, &owner_ha(now_secs), WAN, &frame, meta, 1)
    };
    let pending = reply(&mut sessions);
    assert_eq!(pending.session_hit, 1, "the reply must hit the reverse row");
    assert_eq!(
        (pending.snat_revoked, pending.closes, sessions.len()),
        (0, 0, 2),
        "while the refresh is pending the stored line is no ground to revoke"
    );
    apply_at_view_epoch(
        &mut sessions,
        &owner_forwarding,
        &owner_ha(now_secs),
        epoch0.load(Ordering::Relaxed),
        vec![WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![1] }],
    );
    let key = exported_forward(&owner_forwarding, Family::V4).key;
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_UNIT_IFINDEX,
        "premise: the refresh re-resolves the line onto reth0.80"
    );
    let refreshed = reply(&mut sessions);
    assert_eq!(refreshed.session_hit, 1, "the reply must hit the reverse row");
    assert_eq!(
        (refreshed.snat_revoked, refreshed.closes, sessions.len()),
        (1, 1, 0),
        "after the refresh a translation no rule produces is revoked"
    );
}

/// The keep is reverse-only. While the refresh is pending, a reply is
/// declined, and the flow's next FORWARD slow-path hit is still judged on
/// its live re-resolution (reth0.80) and revokes the withdrawn translation.
/// If forward hits declined too, it would be kept. (This cell does not see a
/// decline that marks the row judged; mutant M2 survived it. That is
/// consistent with the forward hit on the new owner promoting the
/// peer-synced row: `update_session` clears the mark in
/// `refresh_in_place`. The withdrawn and bound cells see M2.)
#[test]
fn forward_hit_while_refresh_pending_still_revokes_18705() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let owner_forwarding = fw1_owner_forwarding();
    let mut sessions = lan_owner_import_withdrawn(now_secs);
    let epoch0 = wire_epoch_reader_18705(&mut sessions);
    epoch0.fetch_add(1, Ordering::Relaxed);
    let (frame, meta) = wan_reply_to(READDRESSED);
    let reply = drive(
        &mut sessions,
        &owner_forwarding,
        &owner_ha(now_secs),
        WAN,
        &frame,
        meta,
        1,
    );
    assert_eq!(
        (reply.session_hit, reply.snat_revoked, sessions.len()),
        (1, 0, 2),
        "the pending refresh keeps the reply"
    );
    let forward = lan_ack(&mut sessions, &owner_forwarding, &owner_ha(now_secs), 1);
    assert_eq!(forward.session_hit, 1, "the LAN packet must hit the forward row");
    assert_eq!(
        (forward.snat_revoked, sessions.len()),
        (1, 0),
        "a forward hit is judged on its live line while the refresh is pending"
    );
}

/// (B) The keep is bounded. With no refresh ever reaching the table (the
/// stamp-less paths: a superseded debt refresh, a worker registered after
/// the fan-out snapshot), the decline stops `OWNER_RG_REFRESH_PENDING_KEEP_NS`
/// after its first use for that epoch, and the withdrawn translation is
/// judged and revoked as before #18705.
#[test]
fn refresh_pending_keep_is_bounded_18705() {
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let owner_forwarding = fw1_owner_forwarding();
    let mut sessions = lan_owner_import_withdrawn(now_secs);
    let epoch0 = wire_epoch_reader_18705(&mut sessions);
    epoch0.fetch_add(1, Ordering::Relaxed);
    let reply = |sessions: &mut SessionTable| {
        let (frame, meta) = wan_reply_to(READDRESSED);
        drive(sessions, &owner_forwarding, &owner_ha(now_secs), WAN, &frame, meta, 1)
    };
    let within = reply(&mut sessions);
    assert_eq!(
        (within.session_hit, within.snat_revoked, sessions.len()),
        (1, 0, 2),
        "within the bound the pending refresh keeps the reply"
    );
    sessions.backdate_owner_rg_refresh_pending_for_test(
        2 * crate::session::OWNER_RG_REFRESH_PENDING_KEEP_NS,
    );
    let past = reply(&mut sessions);
    assert_eq!(past.session_hit, 1, "the reply must hit the reverse row");
    assert_eq!(
        (past.snat_revoked, past.closes, sessions.len()),
        (1, 1, 0),
        "past the bound the judgment runs and revokes, with no refresh"
    );
}

/// Control: a wired reader alone opens no keep. The owner imported the flow
/// under its own view, no activation is pending, and the withdrawn
/// translation still revokes at the first reply, exactly as
/// `owner_readdressed_translation_still_revokes_18691` does with no reader.
/// A table whose stamp were not seeded from its reader would read as
/// pending from birth and keep it.
#[test]
fn reader_without_pending_activation_still_revokes_18705() {
    let forwarding = fw1_owner_forwarding();
    let now_secs = monotonic_nanos() / 1_000_000_000;
    let mut sessions = import_pair(
        &forwarding,
        &owner_ha(now_secs),
        Family::V4,
        false,
        Numbering::Peer,
        Some(IpAddr::V4(READDRESSED)),
        None,
    );
    let _epoch0 = wire_epoch_reader_18705(&mut sessions);
    let (frame, meta) = wan_reply_to(READDRESSED);
    let out = drive(&mut sessions, &forwarding, &owner_ha(now_secs), WAN, &frame, meta, 1);
    assert_eq!(out.session_hit, 1, "the WAN reply must hit the reverse row");
    assert_eq!(
        (out.snat_revoked, sessions.len()),
        (1, 0),
        "no pending activation: the owner revokes on the reply"
    );
}

/// (A) Stamp provenance: a refresh stamps the epoch its VIEW showed, never
/// the reader's epoch at dispatch time. Two activations land close together:
/// RG0 (epoch 8, published, its view loaded by this worker) and then RG1
/// (epoch 9, bumped after that view was loaded). The RG0 refresh is
/// dispatched under the epoch-8 view; it re-resolves nothing for RG1, and
/// the stored line is still the split-FIB line. The table must stay pending
/// for epoch 9, so the reply is kept. Stamping the reader's 9 at dispatch
/// would read "refreshed", and the reply would be judged on the stale line
/// and revoked: the #18705 window, reopened by a too-new stamp.
///
/// (A refresh dispatched under the pre-activation view for RG1 itself is no
/// sharper here: under this split view it re-resolves the forward line to
/// `FabricRedirect`, which IS rewritten, and the #16215 redirect decline then
/// holds the reply whatever the stamp. The view-after-drain change keeps that
/// from happening; see `tests_refresh_pending_pipeline_18705.rs`.)
#[test]
fn refresh_stamps_its_views_epoch_not_a_later_activation_18705() {
    let (mut sessions, split_forwarding, now_secs) = lan_owner_import(Family::V4, false);
    let key = exported_forward(&split_forwarding, Family::V4).key;
    let epoch0 = wire_epoch_reader_18705(&mut sessions);
    // Activation k (RG0): bumped and published; this worker loads its view.
    let view_epoch0 = epoch0.fetch_add(1, Ordering::Relaxed) + 1;
    // Activation k+1 (RG1): bumped after that view was loaded.
    epoch0.fetch_add(1, Ordering::Relaxed);
    apply_at_view_epoch(
        &mut sessions,
        &split_forwarding,
        &split_ha(now_secs),
        view_epoch0,
        vec![WorkerCommand::RefreshOwnerRGS { owner_rgs: vec![0] }],
    );
    assert_eq!(
        stored_forward_line(&sessions, &key).egress_ifindex,
        WAN_GATEWAY_UNIT_IFINDEX,
        "premise: the RG0 refresh re-resolves no owner-RG line"
    );
    let owner_forwarding = fw1_owner_forwarding();
    let (frame, meta) = wan_reply_frame_for(Family::V4);
    let out = drive(
        &mut sessions,
        &owner_forwarding,
        &owner_ha(now_secs),
        WAN,
        &frame,
        meta,
        1,
    );
    assert_eq!(out.session_hit, 1, "the reply must hit the reverse row");
    assert_eq!(
        (out.snat_revoked, out.closes, sessions.len()),
        (0, 0, 2),
        "a refresh whose view predates the RG1 activation does not end its keep"
    );
}
