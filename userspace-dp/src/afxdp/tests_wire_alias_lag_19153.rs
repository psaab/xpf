// #19153 fold 3 (Codex re-check of fold 2, P2): a translated fabric packet
// that resolves through the shared forward-wire ALIAS must not be dropped
// because the alias lags its canonical row.
//
// The shape is the review's interleaving. Worker A serves a SNAT flow that it
// promoted on a fabric arrival (`promote.rs` sets `fabric_ingress`), so
// shared holds A's `SharedPromote` canonical row and its wire alias. A then
// advances the canonical row and is descheduled before it advances the alias:
// - the handshake: the ct-slice restamps the canonical stage Established
//   (`ct_slice.rs`, `restamp_shared_handshakes_established`), then the counts,
//   then the alias (`restamp_shared_forward_wire_established`);
// - the policy rebind: `restamp_shared_policy_entries` writes the canonical
//   row in one lock section and the wire alias in a later one;
// - a republish: `publish_shared_session` of a new incarnation under the same
//   tuple and translation (a new session id) writes the canonical row first
//   and the wire alias last.
// Worker B (this table, empty) takes translated forward packets redirected
// over the fabric. The first misses B's table and resolves the alias. The row
// it installs is a fabric wire placeholder (fabric ingress, SNAT only), so
// every later packet resolves the alias again (`lookup.rs`, the local-hit
// arms).
//
// At 4bb6adc3dd the capture was the alias. The materialize re-read the
// canonical row, classified the lagged field as a divergence and dropped the
// packet, and it did so for every packet until A's alias write. Fold 3
// captures the canonical row itself (`lookup_shared_forward_wire_capture`), so
// the capture and the re-read agree and no packet drops.
//
// The lag is the canonical half of each production writer, called on its
// own: `restamp_shared_handshakes_established` alone (nothing between it and
// the alias restamp in `ct_slice.rs` writes the handshake byte: the count
// restamps write counters and clocks only), and `restamp_shared_policy_entries`
// and `publish_shared_session` against throwaway NAT and wire maps (only their
// canonical lock sections land).
// That is the shared state at the pause point, held for as long as the cell
// sends packets, without a second thread.
//
// Each packet runs on fresh bindings (a fresh flow cache, as `rg::drive`), so
// every packet takes the slow path and the real lookup and materialize.

use super::tests_split_rg_failback_18531 as rg;
use super::tests_split_rg_failback_18531::Family;
use super::tests_support::txn_run_multi_binding_with_shared_maps;
use super::*;
use crate::session::TcpHandshakeState;
use std::sync::atomic::Ordering;

/// Packets per cell: more than one, so a repeated drop is visible.
const PACKETS: usize = 3;

/// The policy a rebind renames the flow's admitting policy to.
const REBOUND_POLICY_ID: u32 = 0x1915_3;

/// A republished incarnation's session id is the original's plus this.
const REPUBLISHED_ID_STEP: u64 = 1;

type SharedMap = Arc<Mutex<FastMap<SessionKey, SyncedSessionEntry>>>;

struct AliasFixture {
    forwarding: ForwardingState,
    ha: BTreeMap<i32, HAGroupRuntime>,
    family: Family,
    sessions: crate::session::SessionTable,
    shared: SharedMap,
    shared_nat: SharedMap,
    shared_wire: SharedMap,
    shared_indexes: SharedSessionOwnerRgIndexes,
    /// The canonical forward row as worker A published it.
    forward: SyncedSessionEntry,
}

/// What one translated fabric packet did on worker B.
#[derive(Debug)]
struct FabricPacket {
    /// Slow-path session hits.
    session_hit: u64,
    /// Packets sent out the WAN binding.
    tx_wan: u64,
    /// `MATERIALIZE_DIVERGENCE_DROPS` across the packet. Process-global, so a
    /// parallel cell can raise it: diagnostic only, never asserted at zero.
    divergence_drops: u64,
}

impl AliasFixture {
    /// fw1 owns every RG. Worker A promoted the flow on a fabric arrival and
    /// published the pair: `SharedPromote`, `fabric_ingress`, handshake
    /// `stage`. Worker B (this table) holds nothing.
    fn served_by_a_sibling(family: Family, stage: TcpHandshakeState) -> Self {
        let forwarding = rg::fw1_owner_forwarding();
        let now_secs = monotonic_nanos() / 1_000_000_000;
        let ha = rg::owner_ha(now_secs);
        let mut forward = rg::exported_forward(&forwarding, family);
        forward.origin = SessionOrigin::SharedPromote;
        forward.metadata.fabric_ingress = true;
        forward.tcp_handshake_state = stage.to_wire();
        let mut reverse = crate::afxdp::shared_ops::synthesized_synced_reverse_entry(
            &forwarding,
            &ha,
            &Arc::new(ShardedNeighborMap::default()),
            &forward,
            now_secs,
        )
        .expect("production reverse synthesis must produce the companion");
        reverse.origin = SessionOrigin::SharedPromote;
        reverse.tcp_handshake_state = stage.to_wire();
        let mut sessions = crate::session::SessionTable::new();
        sessions.set_forwarding_revalidation_gen(7, 9);
        let fx = Self {
            forwarding,
            ha,
            family,
            sessions,
            shared: Arc::new(Mutex::new(FastMap::default())),
            shared_nat: Arc::new(Mutex::new(FastMap::default())),
            shared_wire: Arc::new(Mutex::new(FastMap::default())),
            shared_indexes: SharedSessionOwnerRgIndexes::default(),
            forward,
        };
        fx.publish(&fx.forward);
        fx.publish(&reverse);
        assert!(
            crate::afxdp::shared_ops::is_fabric_wire_placeholder(
                fx.forward.metadata.fabric_ingress,
                fx.forward.metadata.is_reverse,
                fx.forward.decision,
            ),
            "premise: the flow's forward row is a fabric wire placeholder ({family:?})"
        );
        assert_ne!(fx.wire_key(), fx.forward.key, "premise: the flow is translated ({family:?})");
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

    fn wire_key(&self) -> SessionKey {
        crate::session::forward_wire_key(&self.forward.key, self.forward.decision.nat)
    }

    fn canonical(&self) -> SyncedSessionEntry {
        crate::afxdp::shared_ops::lock_shared_recover(&self.shared)
            .get(&self.forward.key)
            .cloned()
            .expect("the canonical row is published")
    }

    fn alias(&self) -> SyncedSessionEntry {
        crate::afxdp::shared_ops::lock_shared_recover(&self.shared_wire)
            .get(&self.wire_key())
            .cloned()
            .expect("the wire alias is published")
    }

    /// One translated forward packet, redirected over the fabric with the LAN
    /// zone stamp, through the production poll body on fresh bindings.
    fn fabric_packet(&mut self) -> FabricPacket {
        let (frame, mut meta) = rg::fabric_forward_frame(&self.forwarding, self.family);
        meta.config_generation = 7;
        let mut bindings = rg::bindings();
        let drops_before = crate::afxdp::session_glue::MATERIALIZE_DIVERGENCE_DROPS
            .load(Ordering::Relaxed);
        let (_batch, dbg, _egress) = txn_run_multi_binding_with_shared_maps(
            &mut bindings,
            rg::FABRIC,
            &mut self.sessions,
            &self.forwarding,
            &self.ha,
            &frame,
            meta,
            &self.shared,
            &self.shared_nat,
            &self.shared_wire,
            &self.shared_indexes,
            7,
            0,
        );
        assert_eq!(dbg.rx, 1, "anti-vacuity: the descriptor must reach the poll body");
        FabricPacket {
            session_hit: dbg.session_hit,
            tx_wan: bindings[rg::WAN].live.tx_packets.load(Ordering::Relaxed),
            divergence_drops: crate::afxdp::session_glue::MATERIALIZE_DIVERGENCE_DROPS
                .load(Ordering::Relaxed)
                - drops_before,
        }
    }

    /// Worker B's row for the flow: is it a fabric wire placeholder, and its
    /// origin.
    fn worker_row(&self) -> Option<(bool, SessionOrigin)> {
        self.sessions
            .entry_with_origin(&self.forward.key)
            .map(|(decision, metadata, origin)| {
                (
                    crate::afxdp::shared_ops::is_fabric_wire_placeholder(
                        metadata.fabric_ingress,
                        metadata.is_reverse,
                        decision,
                    ),
                    origin,
                )
            })
    }
}

#[derive(Clone, Copy, Debug)]
enum Lag {
    /// The ct-slice advanced the canonical stage to Established; the alias is
    /// still HandshakePending.
    Handshake,
    /// A policy rebind renamed the admitting policy and turned session logging
    /// on in the canonical row; the alias still carries the old policy.
    PolicyRebind,
    /// A new incarnation of the same tuple and translation (a new session id)
    /// is published: the canonical row is the new one, the alias still the
    /// old one.
    Republish,
}

/// The republished incarnation's session id.
fn republished_id(fx: &AliasFixture) -> u64 {
    fx.forward.session_id + REPUBLISHED_ID_STEP
}

/// Worker A's writer, paused between its canonical and alias writes.
fn lag_the_alias(fx: &AliasFixture, lag: Lag) {
    let key = fx.forward.key.clone();
    match lag {
        Lag::Handshake => {
            let transitioned = crate::afxdp::shared_ops::restamp_shared_handshakes_established(
                &fx.shared,
                &[(key, fx.forward.decision.nat)],
            );
            assert_eq!(
                transitioned.len(),
                1,
                "premise: the ct-slice's canonical restamp transitioned the row"
            );
        }
        Lag::PolicyRebind => {
            let mut metadata = fx.forward.metadata.clone();
            metadata.policy_id = REBOUND_POLICY_ID;
            metadata.log_session_init = true;
            metadata.log_session_close = true;
            let entry = crate::session::PolicyRebindEntry {
                key,
                decision: fx.forward.decision,
                metadata,
                origin: fx.forward.origin,
                protocol: fx.forward.protocol,
                tcp_flags: fx.forward.tcp_flags,
                session_id: fx.forward.session_id,
                tcp_close_class: 0,
            };
            crate::afxdp::shared_ops::restamp_shared_policy_entries(
                &fx.shared,
                &scratch(),
                &scratch(),
                &[entry],
            );
        }
        Lag::Republish => {
            let mut republished = fx.forward.clone();
            republished.session_id = republished_id(fx);
            republished.generation += 1;
            crate::afxdp::shared_ops::publish_shared_session(
                &fx.shared,
                &scratch(),
                &scratch(),
                &fx.shared_indexes,
                &republished,
            );
        }
    }
}

fn scratch() -> SharedMap {
    Arc::new(Mutex::new(FastMap::default()))
}

/// The alias still lags the canonical row in exactly the field `lag` wrote.
fn alias_lags(fx: &AliasFixture, lag: Lag) -> bool {
    let (canonical, alias) = (fx.canonical(), fx.alias());
    let established = TcpHandshakeState::Established.to_wire();
    let pending = TcpHandshakeState::HandshakePending.to_wire();
    match lag {
        Lag::Handshake => {
            canonical.tcp_handshake_state == established && alias.tcp_handshake_state == pending
        }
        Lag::PolicyRebind => {
            canonical.metadata.policy_id == REBOUND_POLICY_ID
                && canonical.metadata.log_session_init
                && alias.metadata.policy_id == fx.forward.metadata.policy_id
                && !alias.metadata.log_session_init
        }
        Lag::Republish => {
            canonical.session_id == republished_id(fx)
                && alias.session_id == fx.forward.session_id
        }
    }
}

/// `PACKETS` translated fabric packets while the alias lags: none may drop,
/// and worker B ends up holding the canonical row's incarnation.
fn assert_lagging_alias_drops_nothing(family: Family, lag: Lag) {
    let stage = match lag {
        Lag::Handshake => TcpHandshakeState::HandshakePending,
        Lag::PolicyRebind | Lag::Republish => TcpHandshakeState::Established,
    };
    let mut fx = AliasFixture::served_by_a_sibling(family, stage);
    lag_the_alias(&fx, lag);
    let mut trace = Vec::new();
    let mut dropped = 0;
    let mut placeholder_after_each = true;
    for n in 1..=PACKETS {
        assert!(
            alias_lags(&fx, lag),
            "premise before packet {n} ({lag:?}, {family:?}): the alias must still lag its \
             canonical row (nothing on worker B's path writes either)"
        );
        let packet = fx.fabric_packet();
        let worker = fx.worker_row();
        assert_eq!(
            packet.session_hit, 1,
            "premise ({lag:?}, {family:?}): packet {n} must take the slow path and hit \
             ({packet:?})"
        );
        if packet.tx_wan == 0 {
            dropped += 1;
        }
        // After the first packet B holds the flow as a placeholder, so the
        // later packets reach the alias through the local-hit arms.
        placeholder_after_each &= worker.is_some_and(|(placeholder, _)| placeholder);
        trace.push(format!("packet {n}: {packet:?}, worker {worker:?}"));
    }
    assert_eq!(
        dropped, 0,
        "#19153 fold 3 ({lag:?}, {family:?}): {dropped} of {PACKETS} translated fabric packets \
         were dropped while the wire alias lagged its canonical row; an alias hit must be \
         captured as the current canonical row: {trace:#?}"
    );
    assert!(
        placeholder_after_each,
        "premise ({lag:?}, {family:?}): after each packet worker B must hold the flow as a \
         fabric wire placeholder, so packets 2.. reach the alias through the local-hit arms: \
         {trace:#?}"
    );
    assert_eq!(
        fx.sessions.session_id_for(&fx.forward.key),
        fx.canonical().session_id,
        "({lag:?}, {family:?}): worker B must hold the canonical row's incarnation"
    );
}

/// Codex re-check P2: the canonical row's handshake is Established, its wire
/// alias still HandshakePending (worker A between `ct_slice.rs`'s two
/// restamps). Zero of three packets may drop. IPv4 and IPv6.
#[test]
fn handshake_lagging_wire_alias_drops_no_fabric_packet_19153() {
    for family in [Family::V4, Family::V6] {
        assert_lagging_alias_drops_nothing(family, Lag::Handshake);
    }
}

/// The policy-restamp twin: the canonical row carries the rebound policy id
/// and logging flags, the alias the old ones (`restamp_shared_policy_entries`
/// between its canonical and wire lock sections). Zero of three packets may
/// drop. IPv4 and IPv6.
#[test]
fn policy_rebind_lagging_wire_alias_drops_no_fabric_packet_19153() {
    for family in [Family::V4, Family::V6] {
        assert_lagging_alias_drops_nothing(family, Lag::PolicyRebind);
    }
}

/// The republish twin: a new incarnation of the same tuple and translation
/// is mid-publish (`publish_shared_session` between its canonical and wire
/// sections), so the alias's session id is the lagging field. The capture is
/// keyed on the wire key, not on that id: zero of three packets may drop, and
/// worker B holds the new incarnation. IPv4 and IPv6.
#[test]
fn republish_lagging_wire_alias_drops_no_fabric_packet_19153() {
    for family in [Family::V4, Family::V6] {
        assert_lagging_alias_drops_nothing(family, Lag::Republish);
    }
}

/// Control: the capture is still classified on the alias path. A change worker
/// A publishes inside the first packet's capture..claim window (canonical and
/// alias alike, a logging flag) drops that one packet; the next packet
/// resolves the new content and forwards.
#[test]
fn in_window_change_on_the_wire_alias_path_drops_one_packet_19153() {
    let mut fx = AliasFixture::served_by_a_sibling(Family::V4, TcpHandshakeState::Established);
    let mut changed = fx.forward.clone();
    changed.metadata.log_session_close = !changed.metadata.log_session_close;
    let (shared, nat, wire, indexes) = (
        Arc::clone(&fx.shared),
        Arc::clone(&fx.shared_nat),
        Arc::clone(&fx.shared_wire),
        fx.shared_indexes.clone(),
    );
    let published = changed.clone();
    crate::afxdp::session_glue::set_materialize_before_claim_hook_for_test(move || {
        crate::afxdp::shared_ops::publish_shared_session(&shared, &nat, &wire, &indexes, &published);
    });
    let first = fx.fabric_packet();
    let second = fx.fabric_packet();
    let installed_close_flag = fx
        .sessions
        .entry_with_origin(&fx.forward.key)
        .map(|(_, metadata, _)| metadata.log_session_close);
    assert!(
        first.session_hit == 1
            && first.tx_wan == 0
            && first.divergence_drops > 0
            && second.tx_wan == 1
            && installed_close_flag == Some(changed.metadata.log_session_close),
        "an in-window change must drop exactly the packet that captured the old content, and \
         the next packet must forward on the new content (first {first:?}, second {second:?}, \
         worker log_session_close {installed_close_flag:?})"
    );
}

/// Control: the canonical row is the alias's capture only when it names the
/// alias's incarnation. Worker A's flow is replaced by a new incarnation under
/// the same canonical key (a new session id and source port); the old wire key
/// still resolves the old alias. A packet under the old translation must not
/// forward on the replacement's decision, and installs nothing. Every packet.
#[test]
fn wire_alias_of_a_replaced_incarnation_is_never_forwarded_19153() {
    let mut fx = AliasFixture::served_by_a_sibling(Family::V4, TcpHandshakeState::Established);
    let mut replacement = fx.forward.clone();
    replacement.session_id = fx.forward.session_id + 1;
    replacement.decision.nat.rewrite_src_port = Some(40_001);
    fx.publish(&replacement);
    assert_eq!(
        fx.canonical().session_id,
        replacement.session_id,
        "premise: the canonical row is the replacement"
    );
    let old_alias = crate::afxdp::shared_ops::lookup_shared_forward_wire_match(
        &fx.shared_wire,
        &fx.shared_indexes,
        &fx.wire_key(),
    );
    assert_eq!(
        old_alias.map(|alias| alias.session_id),
        Some(fx.forward.session_id),
        "premise: the old wire key still resolves the old incarnation's alias"
    );
    for n in 1..=2 {
        let packet = fx.fabric_packet();
        assert!(
            packet.session_hit == 1 && packet.tx_wan == 0 && fx.worker_row().is_none(),
            "packet {n} under the replaced translation must be dropped and install nothing \
             ({packet:?}, worker {:?})",
            fx.worker_row()
        );
    }
}
