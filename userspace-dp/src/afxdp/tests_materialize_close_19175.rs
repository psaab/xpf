// #19175: a FIN or RST that materializes a session half from the shared map
// must carry its close to the rest of the flow, exactly as the same packet on
// a row already in the worker table does.
//
// Before #19175 the materialize installed the row WITH the packet's flags
// (`upsert_synced_with_origin` derives closing/reset/fin_own from them). That
// install ran outside the local-hit state machine, so none of the steps that
// carry a close onward ran: the companion propagation (#4109 F17), the HA
// Update (#9412), the cross-worker close relay (#18520) and the #16489
// closing-counter baseline. A shared hit carries `authority_deferred: false`,
// so the poll site's #13938 Owner replay did not run either, and had it run,
// `stamp_tcp_close` would have seen no progress on the already-closed row.
// The typical victim is the forward half F of a flow whose server RST lands on
// a worker lacking the reverse half R: F stayed on the established window.
//
// The fix installs the row with its carried close state and replays the
// packet through the poll site's Owner replay, after the promotion, as for a
// local hit (`session_glue::apply_deferred_shared_materialization`).
//
// Every cell drives the production poll body (fresh bindings per packet, so
// every packet takes the slow path) on the captured loss fw1 snapshot with
// fw1 owning both RGs: the #18531/#18552 harness. The flow is the imported
// SNAT pair (SyncImport, Established, session id from the peer), published to
// the shared maps as the HA import publishes it.
//
// - (a)/(b) a server RST, or FIN, on a worker holding F but not R;
// - (c) the true twin: the same packet with R in the worker table already,
//   which must leave the same rows, deltas and relays;
// - (d) the same with F a locally authored `ForwardFlow` (R promoted alone);
// - (e) a second RST on the now-local R changes nothing;
// - (f) a FIN or RST whose materialize classifies `Drop` closes nothing;
// - (g) the forward direction: a client FIN materializing F, with its twin,
//   and a translated fabric FIN through the shared wire alias (the fabric
//   wire placeholder arm), which must relay and announce the close.
//
// Fold 1 (codex-d's review):
// - (i) the close reaches the SHARED maps (canonical rows and F's aliases),
//   so a same-tuple SYN on ANOTHER worker takes the closing-incarnation path
//   instead of resolving and reusing the old incarnation;
// - (ii) on the wire placeholder arm, a retransmitted FIN or RST that
//   re-materializes F never moves the companion's fixed close deadline;
// - (iii) every close cell asserts the shared classes, which the old twin
//   compared as (0, 0) against (0, 0);
// - (iv)/(v) a reverse FIN/RST on an established flow whose R crossed its
//   idle deadline goes through reverse synthesis: R gets its own FIN
//   (`fin_own`), F gets the close through F17, the Update is queued, shared
//   is closed (#19186 folded in); (vi) its true twin, a forward install's
//   companion, still records the forward FIN as `fin_peer`;
// - a newer incarnation published between the close and its publication
//   keeps its own (open) class.
//
// (h), the FabricRedirect interaction, needs a hand-built resolution and lives
// with the #18552 deferred-effects harness:
// `tests_promote_permit_18552.rs::fabric_redirect_materialize_replays_like_a_local_hit_19175`.

use super::tests_split_rg_failback_18531 as rg;
use super::tests_split_rg_failback_18531::Family;
use super::tests_support::{
    build_txn_tcp_syn_frame_v4, txn_meta_v4, txn_run_multi_binding_with_shared_maps,
};
use super::*;
use crate::session::{
    HandshakeRelay, HandshakeRelayStage, RELAY_CLOSE_FIN_FORWARD, RELAY_CLOSE_FIN_REVERSE,
    RELAY_CLOSE_RESET, SessionDeltaKind, TcpCloseClass,
};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::Ordering;

type SharedMap = Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>;
type CloseState = (bool, bool, bool, bool, u64);

const RST_ACK: u8 = crate::tcp_flags::TCP_RST | crate::tcp_flags::TCP_ACK;
const FIN_ACK: u8 = crate::tcp_flags::TCP_FIN | crate::tcp_flags::TCP_ACK;

struct Fx {
    forwarding: ForwardingState,
    ha: BTreeMap<i32, HAGroupRuntime>,
    sessions: SessionTable,
    shared: SharedMap,
    shared_nat: SharedMap,
    shared_wire: SharedMap,
    shared_indexes: SharedSessionOwnerRgIndexes,
    forward: SyncedSessionEntry,
    reverse: SyncedSessionEntry,
}

/// Which rows this worker's table holds before the packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// F as the HA import installs it (`SyncImport`), R only in shared.
    ForwardOnly,
    /// R as the HA import installs it, F only in shared.
    ReverseOnly,
    /// Both, as the HA import installs them: the twin of either.
    Both,
    /// F as a locally authored `ForwardFlow` (same tuple, decision and id),
    /// R only in shared.
    LocalForwardOnly,
    /// Fold 1: the locally authored pair, F `ForwardFlow` and R its
    /// `ReverseFlow` companion carrying F's id (#18718).
    LocalPair,
}

impl Fx {
    /// fw1 after the crash takeover, owning both RGs: the fw0-originated pair
    /// in the shared maps (`SyncImport`, reverse from production reverse
    /// synthesis) and the rows `held` in this worker's table.
    fn imported(held: Held) -> Self {
        let forwarding = rg::fw1_owner_forwarding();
        let now_ns = monotonic_nanos();
        let now_secs = now_ns / 1_000_000_000;
        let ha = rg::owner_ha(now_secs);
        let forward =
            rg::imported_pair_entry(&forwarding, rg::forward_key(), IpAddr::V4(rg::SNAT_IP));
        let reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
            &forwarding,
            &ha,
            &Arc::new(ShardedNeighborMap::default()),
            &forward,
            now_secs,
        )
        .expect("production reverse synthesis must produce the companion");
        assert_ne!(forward.session_id, 0, "premise: the import carries a session id");
        assert_eq!(
            (forward.tcp_close_class, reverse.tcp_close_class),
            (0, 0),
            "premise: the imported pair is open"
        );
        let mut sessions = SessionTable::new();
        match held {
            Held::ForwardOnly => import(&mut sessions, &forward, now_ns),
            Held::ReverseOnly => import(&mut sessions, &reverse, now_ns),
            Held::Both => {
                import(&mut sessions, &forward, now_ns);
                import(&mut sessions, &reverse, now_ns);
            }
            Held::LocalForwardOnly | Held::LocalPair => {
                assert!(
                    sessions.install_with_protocol_with_origin_and_source_nat_with_session_id(
                        forward.key.clone(),
                        forward.decision,
                        forward.metadata.clone(),
                        SessionOrigin::ForwardFlow,
                        now_ns,
                        PROTO_TCP,
                        rg::TCP_ACK,
                        forward.source_nat_static,
                        forward.session_id,
                    ),
                    "fixture: the local forward must install"
                );
                if held == Held::LocalPair {
                    assert!(
                        sessions.install_with_protocol_with_origin_and_source_nat_with_session_id(
                            reverse.key.clone(),
                            reverse.decision,
                            reverse.metadata.clone(),
                            SessionOrigin::ReverseFlow,
                            now_ns,
                            PROTO_TCP,
                            rg::TCP_ACK,
                            reverse.source_nat_static,
                            forward.session_id,
                        ),
                        "fixture: the local reverse companion must install"
                    );
                }
            }
        }
        sessions.set_forwarding_revalidation_gen(7, 9);
        let _ = sessions.drain_deltas(64);
        sessions.drain_handshake_relays_into(&mut Vec::new());
        let fx = Self {
            forwarding,
            ha,
            sessions,
            shared: Arc::new(Mutex::new(FastMap::default())),
            shared_nat: Arc::new(Mutex::new(FastMap::default())),
            shared_wire: Arc::new(Mutex::new(FastMap::default())),
            shared_indexes: SharedSessionOwnerRgIndexes::default(),
            forward,
            reverse,
        };
        fx.publish(&fx.forward);
        fx.publish(&fx.reverse);
        fx
    }

    fn publish(&self, entry: &SyncedSessionEntry) {
        crate::afxdp::shared_ops::publish_shared_session(
            &self.shared,
            &self.shared_nat,
            &self.shared_wire,
            &self.shared_indexes,
            entry,
        );
    }

    fn drive(&mut self, ingress: usize, frame: &[u8], meta: UserspaceDpMeta) -> Observed {
        let mut bindings = rg::bindings();
        let (_batch, dbg, _egress) = txn_run_multi_binding_with_shared_maps(
            &mut bindings,
            ingress,
            &mut self.sessions,
            &self.forwarding,
            &self.ha,
            frame,
            meta,
            &self.shared,
            &self.shared_nat,
            &self.shared_wire,
            &self.shared_indexes,
            7,
            0,
        );
        assert_eq!(dbg.rx, 1, "anti-vacuity: the descriptor must reach the poll body");
        let tx = |b: &BindingWorker| b.live.tx_packets.load(Ordering::Relaxed);
        let deltas = self
            .sessions
            .drain_deltas(64)
            .into_iter()
            .map(|delta| (delta.kind, delta.key, delta.tcp_close_class, delta.session_id))
            .collect();
        let mut relays = Vec::new();
        self.sessions.drain_handshake_relays_into(&mut relays);
        let (forward_key, reverse_key) = (&self.forward.key, &self.reverse.key);
        Observed {
            session_hit: dbg.session_hit,
            tx: [
                tx(&bindings[rg::WAN]),
                tx(&bindings[rg::FABRIC]),
                tx(&bindings[rg::LAN]),
            ],
            forward: self.sessions.close_state_for_test(forward_key),
            reverse: self.sessions.close_state_for_test(reverse_key),
            origins: [
                self.sessions.entry_with_origin(forward_key).map(|(_, _, o)| o),
                self.sessions.entry_with_origin(reverse_key).map(|(_, _, o)| o),
            ],
            forward_baseline: self.sessions.closing_counters_seen_for_test(forward_key),
            deltas,
            relays,
        }
    }

    /// One WAN -> LAN reply of the flow (the reverse half's tuple) carrying
    /// `flags`, on the WAN unit.
    fn wan_reply(&mut self, flags: u8) -> Observed {
        let (frame, meta) = with_flags(rg::wan_reply_frame_for(Family::V4), flags);
        self.drive(rg::WAN, &frame, meta)
    }

    /// One LAN -> WAN packet of the flow (the forward half's tuple) carrying
    /// `flags`, on the LAN binding.
    fn lan_packet(&mut self, flags: u8) -> Observed {
        let frame = build_txn_tcp_syn_frame_v4(
            rg::LAN_HOST,
            rg::WAN_HOST,
            rg::SPORT,
            rg::DPORT,
            flags,
            [0x02, 0xbf, 0x72, 0x16, 0x02, 0x03],
        );
        let mut meta = txn_meta_v4(rg::LAN_IFINDEX as u32, flags, frame.len() as u16);
        meta.flow_src_addr[..4].copy_from_slice(&rg::LAN_HOST.octets());
        meta.flow_dst_addr[..4].copy_from_slice(&rg::WAN_HOST.octets());
        meta.flow_src_port = rg::SPORT;
        meta.flow_dst_port = rg::DPORT;
        meta.config_generation = 7;
        self.drive(rg::LAN, &frame, meta)
    }

    fn shared_close_classes(&self) -> (Option<u8>, Option<u8>) {
        let shared = crate::afxdp::shared_ops::lock_shared_recover(&self.shared);
        (
            shared.get(&self.forward.key).map(|entry| entry.tcp_close_class),
            shared.get(&self.reverse.key).map(|entry| entry.tcp_close_class),
        )
    }

    /// Fold 1: (session id, close class) of every shared copy of the pair,
    /// `None` where absent: [F, R, F under its reply wire alias, F under its
    /// canonical reply alias (both `shared_nat_sessions`), F under its
    /// forward-wire alias (`shared_forward_wire_sessions`)].
    fn shared_copies(&self) -> [Option<(u64, u8)>; 5] {
        let nat = self.forward.decision.nat;
        let reply_wire = crate::session::reverse_session_key(&self.forward.key, nat);
        let reply_canonical = crate::session::reverse_canonical_key(&self.forward.key, nat);
        let forward_wire = crate::session::forward_wire_key(&self.forward.key, nat);
        assert!(
            reply_wire != reply_canonical && forward_wire != self.forward.key,
            "fixture: the SNAT pair has distinct NAT and forward-wire aliases"
        );
        let read = |map: &SharedMap, key: &SessionKey| {
            crate::afxdp::shared_ops::lock_shared_recover(map)
                .get(key)
                .map(|entry| (entry.session_id, entry.tcp_close_class))
        };
        [
            read(&self.shared, &self.forward.key),
            read(&self.shared, &self.reverse.key),
            read(&self.shared_nat, &reply_wire),
            read(&self.shared_nat, &reply_canonical),
            read(&self.shared_wire, &forward_wire),
        ]
    }

    /// Fold 1: every shared copy (canonical rows and F's aliases) is present
    /// and carries `class`.
    fn shared_all_closed(&self, class: TcpCloseClass) -> bool {
        self.shared_copies()
            .iter()
            .all(|copy| copy.is_some_and(|(_, wire)| wire == class.to_wire()))
    }

    /// Drive one packet on ANOTHER worker's table `other` sharing these
    /// shared maps (the tables are swapped in and back).
    fn on_worker(&mut self, other: &mut SessionTable, packet: impl FnOnce(&mut Self) -> Observed) -> Observed {
        std::mem::swap(&mut self.sessions, other);
        let seen = packet(self);
        std::mem::swap(&mut self.sessions, other);
        seen
    }

    /// The fabric wire placeholder arm of (g2): worker A promoted a SNAT flow
    /// on a fabric arrival and published it (`SharedPromote`, fabric
    /// ingress); this table is worker B's, empty, or (`with_reverse`)
    /// holding R as A's replica (`WorkerLocalImport`, the sibling
    /// `UpsertSynced` shape).
    fn wire_arm(with_reverse: bool) -> Self {
        let forwarding = rg::fw1_owner_forwarding();
        let now_ns = monotonic_nanos();
        let ha = rg::owner_ha(now_ns / 1_000_000_000);
        let mut forward = rg::exported_forward(&forwarding, Family::V4);
        forward.origin = SessionOrigin::SharedPromote;
        forward.metadata.fabric_ingress = true;
        let mut reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
            &forwarding,
            &ha,
            &Arc::new(ShardedNeighborMap::default()),
            &forward,
            now_ns / 1_000_000_000,
        )
        .expect("production reverse synthesis must produce the companion");
        reverse.origin = SessionOrigin::SharedPromote;
        assert!(
            crate::afxdp::shared_ops::is_fabric_wire_placeholder(
                forward.metadata.fabric_ingress,
                forward.metadata.is_reverse,
                forward.decision,
            ),
            "premise: the forward row is a fabric wire placeholder"
        );
        let mut sessions = SessionTable::new();
        if with_reverse {
            import_as(&mut sessions, &reverse, SessionOrigin::WorkerLocalImport, now_ns);
        }
        sessions.set_forwarding_revalidation_gen(7, 9);
        let _ = sessions.drain_deltas(64);
        sessions.drain_handshake_relays_into(&mut Vec::new());
        let fx = Self {
            forwarding,
            ha,
            sessions,
            shared: Arc::new(Mutex::new(FastMap::default())),
            shared_nat: Arc::new(Mutex::new(FastMap::default())),
            shared_wire: Arc::new(Mutex::new(FastMap::default())),
            shared_indexes: SharedSessionOwnerRgIndexes::default(),
            forward,
            reverse,
        };
        fx.publish(&fx.forward);
        fx.publish(&fx.reverse);
        fx
    }

    /// One translated client packet redirected over the fabric (the wire
    /// placeholder arm's packet), carrying `flags`.
    fn fabric_packet(&mut self, flags: u8) -> Observed {
        let (frame, meta) = with_flags(rg::fabric_forward_frame(&self.forwarding, Family::V4), flags);
        self.drive(rg::FABRIC, &frame, meta)
    }

    /// R's absolute close deadline (last seen + idle window), `None` if absent.
    fn reverse_deadline(&self) -> Option<u64> {
        let last_seen = self.sessions.last_seen_ns(&self.reverse.key)?;
        let (_, _, _, _, expires) = self.sessions.close_state_for_test(&self.reverse.key)?;
        Some(last_seen + expires)
    }
}

/// Install `entry` into the worker table as the HA import does (`SyncImport`,
/// open, the carried handshake stage and packet counts).
fn import(sessions: &mut SessionTable, entry: &SyncedSessionEntry, now_ns: u64) {
    import_as(sessions, entry, SessionOrigin::SyncImport, now_ns);
}

/// [`import`] under `origin` (fold 1: `WorkerLocalImport`, a sibling's
/// `UpsertSynced` replica of a locally owned row).
fn import_as(sessions: &mut SessionTable, entry: &SyncedSessionEntry, origin: SessionOrigin, now_ns: u64) {
    assert!(
        sessions.upsert_synced_with_origin(
            crate::session::SessionInstall {
                key: entry.key.clone(),
                decision: entry.decision,
                metadata: entry.metadata.clone(),
                source_nat_static: entry.source_nat_static,
                origin,
                now_ns,
                protocol: PROTO_TCP,
                tcp_flags: rg::TCP_ACK,
                session_id: entry.session_id,
                tcp_close_class: 0,
                tcp_handshake_state: entry.tcp_handshake_state,
                persistent_lease_hold: None,
                fwd_packets: entry.fwd_packets,
                rev_packets: entry.rev_packets,
            },
            false,
        ),
        "fixture: the HA import must install {:?}",
        entry.key
    );
}

/// Rewrite a builder's TCP flags (the frame byte and the descriptor meta) and
/// put it on the fixture's config generation.
fn with_flags((mut frame, mut meta): (Vec<u8>, UserspaceDpMeta), flags: u8) -> (Vec<u8>, UserspaceDpMeta) {
    frame[meta.l4_offset as usize + 13] = flags;
    meta.tcp_flags = flags;
    meta.config_generation = 7;
    (frame, meta)
}

/// What one packet left behind: the poll's counters, both halves' close state
/// (closing, reset, fin_own, fin_peer, idle window) and origin, F's #16489
/// baseline, every delta and every relay it queued.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Observed {
    session_hit: u64,
    /// Packets sent out [WAN, FABRIC, LAN].
    tx: [u64; 3],
    forward: Option<CloseState>,
    reverse: Option<CloseState>,
    /// Worker [F, R] origins.
    origins: [Option<SessionOrigin>; 2],
    forward_baseline: Option<u64>,
    deltas: Vec<(SessionDeltaKind, SessionKey, u8, u64)>,
    relays: Vec<HandshakeRelay>,
}

impl Observed {
    fn updates(&self) -> Vec<&(SessionDeltaKind, SessionKey, u8, u64)> {
        self.deltas
            .iter()
            .filter(|(kind, ..)| *kind == SessionDeltaKind::Update)
            .collect()
    }

    fn closed_relays(&self) -> Vec<&HandshakeRelay> {
        self.relays
            .iter()
            .filter(|relay| relay.stage == HandshakeRelayStage::Closed)
            .collect()
    }
}

/// The fixed-close-window part of a close state: (closing, reset, fin_own,
/// fin_peer) and the idle window in whole seconds.
fn close_bits(state: Option<CloseState>) -> Option<(bool, bool, bool, bool, u64)> {
    state.map(|(closing, reset, fin_own, fin_peer, expires)| {
        (closing, reset, fin_own, fin_peer, expires / 1_000_000_000)
    })
}

/// Report every broken leg together, so a red run names each one.
fn assert_legs(cell: &str, legs: &[(bool, &str)]) {
    let failed: Vec<&str> = legs
        .iter()
        .filter(|(held, _)| !held)
        .map(|(_, leg)| *leg)
        .collect();
    assert!(failed.is_empty(), "{cell}: broken legs: {failed:#?}");
}

/// Fold 1: [`assert_legs`] over several cases at once, so a red run names
/// every broken case (and a mutant's kill can be attributed per case).
fn assert_cases(cell: &str, cases: Vec<(String, Vec<(bool, &'static str)>)>) {
    let failed: Vec<(String, Vec<&str>)> = cases
        .into_iter()
        .filter_map(|(case, legs)| {
            let broken: Vec<&str> = legs
                .iter()
                .filter(|(held, _)| !held)
                .map(|(_, leg)| *leg)
                .collect();
            (!broken.is_empty()).then_some((case, broken))
        })
        .collect();
    assert!(failed.is_empty(), "{cell}: broken cases: {failed:#?}");
}

/// The legs a reverse-direction close owes, whichever row it landed on: F
/// closed through F17, exactly one HA Update for F carrying `class`, one close
/// relay for F with `relay_bits`, and F's #16489 baseline seeded. The baseline
/// is seeded with F's packet total, so it is observable only for an F that
/// carries packets (the import's counts); a fresh local F seeds 0.
fn reverse_close_legs(
    fx: &Fx,
    seen: &Observed,
    forward_bits: (bool, bool, bool, bool, u64),
    class: TcpCloseClass,
    relay_bits: u8,
) -> Vec<(bool, &'static str)> {
    let updates = seen.updates();
    let relays = seen.closed_relays();
    let carries_packets = fx.forward.fwd_packets + fx.forward.rev_packets > 0
        && seen.origins[0] != Some(SessionOrigin::ForwardFlow);
    vec![
        (seen.session_hit == 1, "premise: the reply must hit the flow"),
        (seen.tx[rg::LAN] == 1, "premise: the reply must be forwarded to the LAN"),
        (
            close_bits(seen.forward) == Some(forward_bits),
            "F17: F does not carry the reply's close on its close window",
        ),
        (
            updates.len() == 1
                && updates[0].1 == fx.forward.key
                && updates[0].2 == class.to_wire()
                && updates[0].3 == fx.forward.session_id,
            "#9412: not exactly one HA Update for F carrying the close class",
        ),
        (
            relays.len() == 1
                && relays[0].forward_key == fx.forward.key
                && relays[0].session_id == fx.forward.session_id
                && relays[0].close_bits == relay_bits,
            "#18520: the close relay for F is not pending with the close bits",
        ),
        (
            !carries_packets || seen.forward_baseline.is_some_and(|seen| seen > 0),
            "#16489: F's closing-counter baseline was not seeded",
        ),
        (
            fx.shared_all_closed(class),
            "fold 1: a shared copy of F or R (canonical row or F's NAT/wire alias) \
             does not carry the close class",
        ),
    ]
}

/// (a) The defect cell. A server RST|ACK lands on a worker that holds F but
/// not R; shared R is the imported `SyncImport` row. R is materialized,
/// promoted with F (#18552 B1), and the Owner replay applies the RST: R and F
/// reset on the 2 s window, one Update for F with the Reset class, the close
/// relay pending, F's baseline seeded. RED before #19175: R was reset at
/// install, F stayed Established, no Update, no relay, baseline 0.
#[test]
fn materialized_reverse_rst_closes_and_announces_the_forward_19175() {
    let mut fx = Fx::imported(Held::ForwardOnly);
    let seen = fx.wan_reply(RST_ACK);
    let mut legs = reverse_close_legs(
        &fx,
        &seen,
        (true, true, false, false, 2),
        TcpCloseClass::Reset,
        RELAY_CLOSE_RESET,
    );
    legs.extend([
        (
            close_bits(seen.reverse) == Some((true, true, false, false, 2)),
            "R: the materialized R is not reset on the 2 s window",
        ),
        (
            seen.origins == [Some(SessionOrigin::SharedPromote); 2],
            "premise: the reply did not materialize R and promote the pair",
        ),
    ]);
    assert_legs(&format!("materialized reverse RST ({seen:?})"), &legs);
}

/// (b) The FIN|ACK twin of (a): R's own FIN is `fin_own` on R and F's PEER FIN
/// (`fin_peer`) on F, both CLOSING on the 30 s window; the Update carries the
/// Closing class and the relay the reverse-FIN bit.
#[test]
fn materialized_reverse_fin_marks_the_forwards_peer_fin_19175() {
    let mut fx = Fx::imported(Held::ForwardOnly);
    let seen = fx.wan_reply(FIN_ACK);
    let mut legs = reverse_close_legs(
        &fx,
        &seen,
        (true, false, false, true, 30),
        TcpCloseClass::Closing,
        RELAY_CLOSE_FIN_REVERSE,
    );
    legs.push((
        close_bits(seen.reverse) == Some((true, false, true, false, 30)),
        "R: the materialized R does not carry its own FIN (fin_own) on the close window",
    ));
    assert_legs(&format!("materialized reverse FIN ({seen:?})"), &legs);
}

/// (c) The true twin: the same packet on a worker that holds R already (an
/// ordinary local hit, replayed by the poll site's #13938 Owner replay) must
/// leave exactly what the materialized arm leaves: both halves' close state
/// and origin, F's baseline, every delta and every relay. That is the "one
/// place" claim. RST and FIN.
#[test]
fn materialized_close_equals_the_local_hit_close_19175() {
    for flags in [RST_ACK, FIN_ACK] {
        let mut materialized = Fx::imported(Held::ForwardOnly);
        let mut local = Fx::imported(Held::Both);
        let got = materialized.wan_reply(flags);
        let twin = local.wan_reply(flags);
        assert_legs(
            &format!("flags {flags:#04x}: materialized {got:?} vs local hit {twin:?}"),
            &[
                (
                    twin.updates().len() == 1 && twin.closed_relays().len() == 1,
                    "twin premise: the local-hit close is not announced and relayed",
                ),
                (
                    close_bits(got.forward) == close_bits(twin.forward)
                        && close_bits(got.reverse) == close_bits(twin.reverse),
                    "the close state of F or R differs from the local hit's",
                ),
                (got.origins == twin.origins, "the origins differ from the local hit's"),
                (
                    got.forward_baseline == twin.forward_baseline,
                    "F's #16489 baseline differs from the local hit's",
                ),
                (got.deltas == twin.deltas, "the delta stream differs from the local hit's"),
                (got.relays == twin.relays, "the relays differ from the local hit's"),
                (
                    (got.session_hit, got.tx) == (twin.session_hit, twin.tx),
                    "the packet's handling differs from the local hit's",
                ),
                (
                    materialized.shared_copies() == local.shared_copies(),
                    "the shared rows' close classes differ from the local hit's",
                ),
                // Fold 1 (iii): before fold 1 both arms left every shared
                // copy at class 0, so the equality above held while shared
                // still named the open flow (Codex P2-1).
                (
                    local.shared_all_closed(expected_class(flags))
                        && materialized.shared_all_closed(expected_class(flags)),
                    "fold 1: a shared copy of F or R does not carry the close class",
                ),
            ],
        );
    }
}

/// The close class one FIN or RST leaves on a pair that was open.
fn expected_class(flags: u8) -> TcpCloseClass {
    if crate::tcp_flags::has_rst(flags) {
        TcpCloseClass::Reset
    } else {
        TcpCloseClass::Closing
    }
}

/// (d) F authored by this worker (`ForwardFlow`, not promotable, so R is
/// promoted alone) and R only in shared as the imported `SyncImport` row: the
/// issue's recipe. The materialized RST reaches F, F announces it (a locally
/// authored row is not peer-synced) and the relay is pending (R is
/// `SharedPromote`, so the pair is split across workers).
#[test]
fn materialized_reverse_rst_closes_a_local_forward_flow_19175() {
    let mut fx = Fx::imported(Held::LocalForwardOnly);
    let seen = fx.wan_reply(RST_ACK);
    let mut legs = reverse_close_legs(
        &fx,
        &seen,
        (true, true, false, false, 2),
        TcpCloseClass::Reset,
        RELAY_CLOSE_RESET,
    );
    legs.push((
        seen.origins == [Some(SessionOrigin::ForwardFlow), Some(SessionOrigin::SharedPromote)],
        "premise: R was not materialized and promoted alone beside the local F",
    ));
    assert_legs(&format!("local forward, materialized reverse RST ({seen:?})"), &legs);
}

/// (e) The progress predicate. After (a), R is in the worker table, reset. A
/// second RST is an ordinary local hit whose replay sees no progress
/// (`stamp_tcp_close`): no second propagation (F's close state and last-seen
/// unchanged), no second Update, no second relay.
#[test]
fn a_second_rst_after_the_materialized_close_changes_nothing_19175() {
    let mut fx = Fx::imported(Held::ForwardOnly);
    let first = fx.wan_reply(RST_ACK);
    assert_legs(
        &format!("first RST ({first:?})"),
        &reverse_close_legs(
            &fx,
            &first,
            (true, true, false, false, 2),
            TcpCloseClass::Reset,
            RELAY_CLOSE_RESET,
        ),
    );
    let forward_last_seen = fx.sessions.last_seen_ns(&fx.forward.key);
    let second = fx.wan_reply(RST_ACK);
    assert_legs(
        &format!("second RST ({second:?})"),
        &[
            (second.session_hit == 1, "premise: the second RST must hit R"),
            (
                second.origins == first.origins,
                "premise: the second RST must be a local hit on the promoted pair",
            ),
            (second.forward == first.forward, "F's close state changed"),
            (
                fx.sessions.last_seen_ns(&fx.forward.key) == forward_last_seen,
                "F was refreshed again (a second propagation)",
            ),
            (second.reverse == first.reverse, "R's close state changed"),
            (second.updates().is_empty(), "a second HA Update was queued"),
            (second.closed_relays().is_empty(), "a second close relay was queued"),
            // Not compared: F's #16489 baseline. `account_packet` folds every
            // accounted closing packet into it by design (the closing packet
            // must not read as post-close activity), for a local hit too.
        ],
    );
}

/// (f) #19153 Drop interplay. Shared R is replaced between the resolve's
/// capture and the materialize's claim (session-close logging toggled: a
/// compared field the #10612 zone fence does not read), so the materialize
/// installs the current row clean and the packet is dropped. A dropped
/// packet's FIN or RST applies NO close anywhere: R installed open, F
/// untouched, no delta, no relay, the shared rows open. Unchanged by #19175.
#[test]
fn a_dropped_materialize_applies_no_close_19175() {
    for flags in [RST_ACK, FIN_ACK] {
        let mut fx = Fx::imported(Held::ForwardOnly);
        let forward_before = fx.sessions.close_state_for_test(&fx.forward.key);
        let mut replacement = fx.reverse.clone();
        replacement.metadata.log_session_close = !replacement.metadata.log_session_close;
        let (shared, nat, wire, indexes) = (
            Arc::clone(&fx.shared),
            Arc::clone(&fx.shared_nat),
            Arc::clone(&fx.shared_wire),
            fx.shared_indexes.clone(),
        );
        let published = replacement.clone();
        crate::afxdp::session_glue::set_materialize_before_claim_hook_for_test(move || {
            crate::afxdp::shared_ops::publish_shared_session(
                &shared, &nat, &wire, &indexes, &published,
            );
        });
        let drops_before = crate::afxdp::session_glue::MATERIALIZE_DIVERGENCE_DROPS
            .load(Ordering::Relaxed);
        let seen = fx.wan_reply(flags);
        let drops_after = crate::afxdp::session_glue::MATERIALIZE_DIVERGENCE_DROPS
            .load(Ordering::Relaxed);
        let installed_logging = fx
            .sessions
            .entry_with_origin(&fx.reverse.key)
            .map(|(_, metadata, _)| metadata.log_session_close);
        assert_legs(
            &format!(
                "flags {flags:#04x}: dropped materialize ({seen:?}, R close logging \
                 {installed_logging:?})"
            ),
            &[
                (seen.session_hit == 1, "premise: the reply must hit the shared row"),
                (seen.tx == [0, 0, 0], "the packet was forwarded"),
                (drops_after > drops_before, "the drop was not counted"),
                (
                    installed_logging == Some(replacement.metadata.log_session_close),
                    "premise: the current row was not installed",
                ),
                (
                    seen.reverse.is_some_and(|(closing, reset, fin_own, fin_peer, _)| {
                        !closing && !reset && !fin_own && !fin_peer
                    }),
                    "the dropped packet closed R",
                ),
                (seen.forward == forward_before, "the dropped packet changed F"),
                (seen.forward_baseline == Some(0), "F's baseline was seeded"),
                (seen.deltas.is_empty(), "the dropped packet queued a delta"),
                (seen.relays.is_empty(), "the dropped packet queued a relay"),
                (
                    fx.shared_close_classes() == (Some(0), Some(0)),
                    "a shared row took a close",
                ),
            ],
        );
    }
}

/// (g) The forward direction: a client FIN|ACK on a worker that holds R but
/// not F materializes F (promoted, a forward hit promotes no partner) and the
/// replay carries the FIN to R as R's PEER FIN, announces it and relays it.
/// It equals the twin with F already in the table. RED before #19175: F was
/// closed at install and R, the HA peer and the siblings never learned it.
#[test]
fn materialized_forward_fin_reaches_the_reverse_19175() {
    let mut fx = Fx::imported(Held::ReverseOnly);
    let seen = fx.lan_packet(FIN_ACK);
    let mut twin_fx = Fx::imported(Held::Both);
    let twin = twin_fx.lan_packet(FIN_ACK);
    let updates = seen.updates();
    let relays = seen.closed_relays();
    assert_legs(
        &format!("materialized forward FIN ({seen:?}) vs local hit ({twin:?})"),
        &[
            (seen.session_hit == 1, "premise: the FIN must hit the flow"),
            (seen.tx[rg::WAN] == 1, "premise: the FIN must be forwarded to the WAN"),
            (
                close_bits(seen.forward) == Some((true, false, true, false, 30)),
                "F: the materialized F does not carry its own FIN",
            ),
            (
                close_bits(seen.reverse) == Some((true, false, false, true, 30)),
                "F17: R does not carry F's FIN as its peer FIN",
            ),
            (
                updates.len() == 1
                    && updates[0].1 == fx.forward.key
                    && updates[0].2 == TcpCloseClass::Closing.to_wire(),
                "#9412: not exactly one HA Update for F carrying the Closing class",
            ),
            (
                relays.len() == 1 && relays[0].close_bits == RELAY_CLOSE_FIN_FORWARD,
                "#18520: the close relay for F is not pending with the forward FIN",
            ),
            (
                seen.forward_baseline.is_some_and(|seen| seen > 0),
                "#16489: F's closing-counter baseline was not seeded",
            ),
            (
                close_bits(seen.forward) == close_bits(twin.forward)
                    && close_bits(seen.reverse) == close_bits(twin.reverse)
                    && seen.origins == twin.origins
                    && seen.forward_baseline == twin.forward_baseline
                    && seen.deltas == twin.deltas
                    && seen.relays == twin.relays,
                "twin: the materialized close differs from the local hit's",
            ),
            (
                fx.shared_all_closed(TcpCloseClass::Closing)
                    && twin_fx.shared_all_closed(TcpCloseClass::Closing),
                "fold 1 (iii): a shared copy of F or R does not carry CLOSING",
            ),
        ],
    );
}

/// (g) The fabric wire placeholder arm (`shared_ops/lookup.rs`): worker A
/// promoted a SNAT flow on a fabric arrival and published it; worker B (this
/// table, empty) takes the translated client FIN redirected over the fabric.
/// It resolves through the shared wire alias and installs A's canonical row
/// as a `WorkerLocalImport` replica. The replay must relay the close to A
/// (#18520: B alone saw it) and announce it under A's carried id (#9582).
/// RED before #19175: the FIN closed B's replica at install and nothing else.
#[test]
fn wire_alias_fin_relays_and_announces_the_close_19175() {
    let mut fx = Fx::wire_arm(false);
    let seen = fx.fabric_packet(FIN_ACK);
    let copies = fx.shared_copies();
    let updates = seen.updates();
    let relays = seen.closed_relays();
    assert_legs(
        &format!("wire-alias FIN ({seen:?})"),
        &[
            (seen.session_hit == 1, "premise: the FIN must hit the shared alias"),
            (seen.tx[rg::WAN] == 1, "premise: the FIN must be forwarded to the WAN"),
            (
                seen.origins[0] == Some(SessionOrigin::WorkerLocalImport),
                "premise: B did not install A's canonical row as a worker replica",
            ),
            (
                close_bits(seen.forward).is_some_and(|(closing, reset, fin_own, _, _)| {
                    closing && fin_own && !reset
                }),
                "B's replica does not carry the FIN",
            ),
            (
                relays.len() == 1
                    && relays[0].forward_key == fx.forward.key
                    && relays[0].session_id == fx.forward.session_id
                    && relays[0].close_bits == RELAY_CLOSE_FIN_FORWARD,
                "#18520: the close relay to A is not pending",
            ),
            (
                updates.len() == 1
                    && updates[0].1 == fx.forward.key
                    && updates[0].2 == TcpCloseClass::Closing.to_wire()
                    && updates[0].3 == fx.forward.session_id,
                "#9582: the replica did not announce the close under A's id",
            ),
            // Fold 1: B publishes the close of the row it closed (F, under
            // A's id, and its aliases). B holds no R, so shared R is not
            // B's to close; A applies the relay to its table.
            (
                [copies[0], copies[2], copies[3], copies[4]].iter().all(|copy| {
                    *copy == Some((fx.forward.session_id, TcpCloseClass::Closing.to_wire()))
                }),
                "fold 1: shared F or one of its aliases does not carry CLOSING",
            ),
            (
                copies[1].is_some_and(|(_, class)| class == 0),
                "B closed shared R, a row it does not hold",
            ),
        ],
    );
}

/// Fold 1 (i), Codex P2-1. A reverse RST or FIN materializes R on worker A
/// and closes the pair there; then a same-tuple SYN (the client reusing the
/// tuple) arrives on worker B, whose table is empty. The close must have
/// reached the shared maps, every copy (canonical F and R, F's NAT and
/// forward-wire aliases), so B's closing-incarnation probe
/// (`probe_closing_syn_candidate`, keyed on a nonzero shared class) sends
/// the SYN down the owner's new-flow path. RED before fold 1: the replay
/// left every shared copy at class 0, B resolved the old incarnation as a
/// session hit and materialized it, so the SYN rode the old session and NAT.
#[test]
fn a_same_tuple_syn_on_another_worker_takes_the_closing_incarnation_path_19175() {
    let mut cases = Vec::new();
    for flags in [RST_ACK, FIN_ACK] {
        let mut fx = Fx::imported(Held::ForwardOnly);
        let old_id = fx.forward.session_id;
        let close = fx.wan_reply(flags);
        let copies = fx.shared_copies();
        let shared_closed = fx.shared_all_closed(expected_class(flags));
        let mut worker_b = SessionTable::new();
        worker_b.set_forwarding_revalidation_gen(7, 9);
        let syn = fx.on_worker(&mut worker_b, |fx| fx.lan_packet(crate::tcp_flags::TCP_SYN));
        let b_row = worker_b
            .entry_with_origin(&fx.forward.key)
            .map(|(_, _, origin)| (worker_b.session_id_for(&fx.forward.key), origin));
        cases.push((
            format!(
                "flags {flags:#04x}: close on A ({close:?}), shared {copies:?}, SYN on B \
                 ({syn:?}), B's row {b_row:?}"
            ),
            vec![
                (
                    close.session_hit == 1 && close.origins == [Some(SessionOrigin::SharedPromote); 2],
                    "premise: the close did not materialize R and promote the pair on A",
                ),
                (
                    shared_closed,
                    "fold 1: a shared copy of the closed pair does not carry its close class",
                ),
                (
                    syn.session_hit == 0,
                    "the SYN on B resolved the closed pair as a session hit instead of \
                     taking the closing-incarnation path",
                ),
                (
                    b_row.is_none_or(|(id, _)| id != old_id),
                    "B holds the old incarnation (its session id) for the SYN's tuple: \
                     the old session and NAT were reused",
                ),
            ],
        ));
    }
    assert_cases("same-tuple SYN on another worker", cases);
}

/// Fold 1 (ii), Codex P2-2. On the fabric wire placeholder arm every
/// translated client packet re-materializes worker B's replica of F from
/// the shared row. Worker B also holds R. After the first close, a
/// retransmitted FIN or RST must not read as new progress on the
/// re-installed F: R's absolute deadline (its fixed RST fuse, its TIME_WAIT
/// window, or its CLOSING window from the first FIN) must not move, and no
/// second Update or relay may be queued.
///
/// The cases: a FIN retransmit; Codex's reverse RST, then a forward FIN
/// inside R's 2 s fuse; both FINs (TIME_WAIT), then a FIN retransmit; and a
/// retransmitted forward RST. RED before fold 1: the re-install took the
/// stale open shared row, so each retransmit re-closed F and F17 re-armed R.
/// The single-FIN cases also need the same-incarnation carry
/// (`same_incarnation_close_progress`): a CLOSING shared class does not say
/// which direction FINed, so the shared publication alone leaves F's own
/// FIN off the re-installed row.
#[test]
fn wire_placeholder_retransmits_never_move_the_companion_deadline_19175() {
    #[derive(Clone, Copy, Debug)]
    enum Arrival {
        /// A translated client packet on the fabric (the wire arm).
        Fabric(u8),
        /// A server reply on the WAN, a local hit on B's R.
        Reply(u8),
    }
    use Arrival::{Fabric, Reply};
    let cases: [(&str, &[Arrival], Arrival); 4] = [
        ("FIN, then a retransmitted FIN", &[Fabric(FIN_ACK)], Fabric(FIN_ACK)),
        (
            "an ACK, a reverse RST, then a forward FIN inside the RST fuse",
            &[Fabric(rg::TCP_ACK), Reply(RST_ACK)],
            Fabric(FIN_ACK),
        ),
        (
            "both FINs (TIME_WAIT), then a retransmitted forward FIN",
            &[Fabric(FIN_ACK), Reply(FIN_ACK)],
            Fabric(FIN_ACK),
        ),
        ("a forward RST, then a retransmitted RST", &[Fabric(RST_ACK)], Fabric(RST_ACK)),
    ];
    let mut results = Vec::new();
    for (case, setup, retransmit) in cases {
        let mut fx = Fx::wire_arm(true);
        let drive = |fx: &mut Fx, arrival: Arrival| match arrival {
            Fabric(flags) => fx.fabric_packet(flags),
            Reply(flags) => fx.wan_reply(flags),
        };
        let mut setup_seen = Vec::new();
        for arrival in setup {
            setup_seen.push(drive(&mut fx, *arrival));
        }
        let reverse_before = fx.sessions.close_state_for_test(&fx.reverse.key);
        let forward_before = close_bits(fx.sessions.close_state_for_test(&fx.forward.key));
        let deadline_before = fx.reverse_deadline();
        let seen = drive(&mut fx, retransmit);
        let reverse_after = fx.sessions.close_state_for_test(&fx.reverse.key);
        results.push((
            format!(
                "{case}: setup {setup_seen:?}; retransmit {seen:?}; R {reverse_before:?} -> \
                 {reverse_after:?}; R deadline {deadline_before:?} -> {:?}",
                fx.reverse_deadline()
            ),
            vec![
                (
                    reverse_before.is_some_and(|(closing, ..)| closing),
                    "premise: the setup did not close B's R",
                ),
                (
                    seen.session_hit == 1 && seen.tx.iter().sum::<u64>() == 1,
                    "premise: the retransmit was not forwarded as a session hit",
                ),
                (
                    seen.origins[0] == Some(SessionOrigin::WorkerLocalImport),
                    "premise: B's F is not A's re-materialized replica",
                ),
                (
                    fx.reverse_deadline() == deadline_before,
                    "R's close deadline moved: the retransmit re-applied F17",
                ),
                (reverse_after == reverse_before, "R's close state changed"),
                // A retransmitted FIN still ORs F's own FIN bit into a reset
                // F, as on a local hit (`stamp_tcp_close`), so the bits are
                // compared as "none lost", not for equality.
                (
                    match (forward_before, close_bits(seen.forward)) {
                        (Some(was), Some(now)) => {
                            now.0 && (now.1 || !was.1) && (now.2 || !was.2) && (now.3 || !was.3)
                        }
                        _ => false,
                    },
                    "the re-installed F lost close state it had before the retransmit",
                ),
                (seen.updates().is_empty(), "the retransmit queued another HA Update"),
                (seen.closed_relays().is_empty(), "the retransmit queued another close relay"),
            ],
        ));
    }
    assert_cases("wire-arm retransmits", results);
}

/// Fold 1 (iv)/(v): the shared drive. F is the locally authored, live,
/// established forward; R its local companion, past its strict idle
/// deadline (one-direction activity refreshes only the hit half) but not yet
/// reaped. The reply's lookup reads `IdleCrossed`, which the shared-ops
/// lookup turns into a miss, so the resolver synthesizes R from F's NAT
/// match (`install_reverse_session_from_forward_match`).
fn idle_crossed_reverse_close(flags: u8) -> (Fx, Observed) {
    let mut fx = Fx::imported(Held::LocalPair);
    assert!(
        fx.sessions.idle_cross_for_test(&fx.reverse.key, monotonic_nanos()),
        "fixture: R must be in the table to idle-cross"
    );
    let seen = fx.wan_reply(flags);
    (fx, seen)
}

/// The legs both (iv) and (v) owe: the reply is synthesized and forwarded,
/// R carries the close as its OWN (`fin_own` for a FIN), F takes it through
/// F17, one HA Update announces F's close, and every shared copy carries it.
fn synthesized_close_legs(
    fx: &Fx,
    seen: &Observed,
    reverse_bits: (bool, bool, bool, bool, u64),
    forward_bits: (bool, bool, bool, bool, u64),
    class: TcpCloseClass,
) -> Vec<(bool, &'static str)> {
    let updates = seen.updates();
    vec![
        (seen.session_hit == 1, "premise: the reply did not resolve"),
        (seen.tx[rg::LAN] == 1, "premise: the reply was not forwarded to the LAN"),
        (
            seen.origins == [Some(SessionOrigin::ForwardFlow), Some(SessionOrigin::ReverseFlow)],
            "premise: R was not re-synthesized beside the local F",
        ),
        (
            close_bits(seen.reverse) == Some(reverse_bits),
            "R does not carry the reply's close as its own on the close window \
             (#19186: a FIN recorded as fin_peer)",
        ),
        (
            close_bits(seen.forward) == Some(forward_bits),
            "F17: the established F did not take the reply's close",
        ),
        (
            updates.len() == 1
                && updates[0].1 == fx.forward.key
                && updates[0].2 == class.to_wire()
                && updates[0].3 == fx.forward.session_id,
            "#9412: not exactly one HA Update for F carrying the close class",
        ),
        (
            fx.shared_all_closed(class),
            "fold 1: a shared copy of F or R does not carry the close class",
        ),
    ]
}

/// Fold 1 (iv), Codex P2-3 / #19186: a server FIN on an ESTABLISHED flow
/// whose R crossed its idle deadline. RED before fold 1: the synthesis
/// stamped the FIN at install as R's `fin_peer` (the constructor's forward
/// inference), F stayed established, no Update, shared open.
#[test]
fn idle_crossed_reverse_fin_closes_both_halves_through_the_replay_19175() {
    let (fx, seen) = idle_crossed_reverse_close(FIN_ACK);
    let legs = synthesized_close_legs(
        &fx,
        &seen,
        (true, false, true, false, 30),
        (true, false, false, true, 30),
        TcpCloseClass::Closing,
    );
    assert_legs(&format!("idle-crossed reverse FIN ({seen:?})"), &legs);
}

/// Fold 1 (v): the RST of (iv). RED before fold 1: R reset at install, F
/// still established on its long window, no Update, shared open.
#[test]
fn idle_crossed_reverse_rst_resets_both_halves_through_the_replay_19175() {
    let (fx, seen) = idle_crossed_reverse_close(RST_ACK);
    let legs = synthesized_close_legs(
        &fx,
        &seen,
        (true, true, false, false, 2),
        (true, true, false, false, 2),
        TcpCloseClass::Reset,
    );
    assert_legs(&format!("idle-crossed reverse RST ({seen:?})"), &legs);
}

/// Fold 1 (vi), the true twin of (iv) for #19186: the row constructor's FIN
/// direction rule is unchanged. A forward install and its reverse companion
/// built from the FORWARD packet (the session-miss shape: both take the
/// packet's flags) record that FIN as F's own and as R's PEER FIN. Only the
/// synthesis caller, whose packet is the reply, stopped passing a FIN there.
#[test]
fn a_forward_install_companion_still_records_the_forward_fin_as_peer_fin_19186() {
    let fx = Fx::imported(Held::ForwardOnly);
    let mut table = SessionTable::new();
    let now_ns = monotonic_nanos();
    for (entry, origin) in [
        (&fx.forward, SessionOrigin::ForwardFlow),
        (&fx.reverse, SessionOrigin::ReverseFlow),
    ] {
        assert!(
            table.install_with_protocol_with_origin_and_source_nat_with_session_id(
                entry.key.clone(),
                entry.decision,
                entry.metadata.clone(),
                origin,
                now_ns,
                PROTO_TCP,
                FIN_ACK,
                entry.source_nat_static,
                fx.forward.session_id,
            ),
            "fixture: the {origin:?} row must install"
        );
    }
    let forward = close_bits(table.close_state_for_test(&fx.forward.key));
    let reverse = close_bits(table.close_state_for_test(&fx.reverse.key));
    assert_legs(
        &format!("forward install F {forward:?}, companion R {reverse:?}"),
        &[
            (
                forward.is_some_and(|(closing, reset, fin_own, fin_peer, _)| {
                    closing && !reset && fin_own && !fin_peer
                }),
                "F does not record the forward FIN as its own",
            ),
            (
                reverse.is_some_and(|(closing, reset, fin_own, fin_peer, _)| {
                    closing && !reset && !fin_own && fin_peer
                }),
                "the companion R does not record the forward FIN as its peer FIN",
            ),
        ],
    );
}

/// Fold 1 (MS8's cell): the shared publication is incarnation-safe. A newer
/// incarnation of the pair (same tuples and NAT, another session id) is
/// published between the replay's close and its shared publication
/// (`set_close_publish_hook_for_test`). The old incarnation's close must
/// not land on it: every shared copy keeps the new id at class 0.
#[test]
fn a_newer_incarnation_published_mid_close_keeps_its_open_class_19175() {
    let mut fx = Fx::imported(Held::ForwardOnly);
    let new_id = (1u64 << 48) | 99;
    assert_ne!(new_id, fx.forward.session_id, "fixture: a different incarnation");
    let mut forward_b = fx.forward.clone();
    forward_b.session_id = new_id;
    let mut reverse_b = fx.reverse.clone();
    reverse_b.session_id = new_id;
    let ran = Rc::new(Cell::new(false));
    let hook_ran = Rc::clone(&ran);
    let (shared, nat, wire, indexes) = (
        Arc::clone(&fx.shared),
        Arc::clone(&fx.shared_nat),
        Arc::clone(&fx.shared_wire),
        fx.shared_indexes.clone(),
    );
    crate::afxdp::session_glue::set_close_publish_hook_for_test(move || {
        for entry in [&forward_b, &reverse_b] {
            crate::afxdp::shared_ops::publish_shared_session(&shared, &nat, &wire, &indexes, entry);
        }
        hook_ran.set(true);
    });
    let seen = fx.wan_reply(RST_ACK);
    let copies = fx.shared_copies();
    assert_legs(
        &format!("replacement mid-close ({seen:?}), shared {copies:?}"),
        &[
            (ran.get(), "premise: no close was published (the hook never ran)"),
            (
                close_bits(seen.reverse) == Some((true, true, false, false, 2))
                    && close_bits(seen.forward) == Some((true, true, false, false, 2)),
                "premise: the RST did not close the old pair in the worker table",
            ),
            (
                copies.iter().all(|copy| *copy == Some((new_id, 0))),
                "the old incarnation's close landed on the newer incarnation's shared copies",
            ),
        ],
    );
}
