// #18520: cross-worker TCP handshake relay.
//
// Every worker owns its `SessionTable`, and RSS hashes the two directions of
// a flow independently — under SNAT they land on different workers by
// construction. The SYN installs the authoritative pair on the worker that
// received it (A) and fans `WorkerLocalImport` replicas to every sibling; the
// SYN-ACK then arrives on another worker (B), which validates it and promotes
// only ITS replica pair. The completing ACK and the client data return to A.
// Before this module no state crossed between the two tables, so A's pair
// stayed pure Opening (no worker ever saw the whole handshake) and both tables
// sat on the 20 s opening window for the life of the flow. The #16223
// "node-level evidence" arms that were meant to bridge this read
// `node_served_stamps`, which only the table's OWN completions ever wrote.
//
// The relay carries exactly the two handshake transitions a single worker
// would have made itself, from the worker that observed the segment to its
// siblings, so the receiving table runs the SAME validation it would have run
// had the segment landed on it:
//
// * `Promoted` — B admitted a SYN-ACK on a replica pair. Carries the SYN-ACK's
//   ack (the receiver validates it against ITS client SYN end, #16042) and the
//   server SYN end (the receiver's completing ACK is then validated exactly).
//   Applied only to a pure Opening SYN-first pair; the receiver moves to
//   `established && handshake_pending` — the #6752 opening-class gap — so the
//   client's completing ACK, not the relay, completes it.
// * `Completed` — a worker completed a split pair. Applied only to a pair the
//   receiver already holds as handshake-pending (a validated SYN-ACK crossed
//   it), never to a pure Opening pair (#6752/#13679).
//
// Producers queue into a bounded per-table outbox; the worker loop drains it
// once per pass (`session_glue::fan_out_handshake_relays`), never per packet.
// A receiver applies a relay only to the same incarnation (forward session id)
// and only to a pair that serves traffic on its table (the author, or a
// replica that has forwarded a packet), so idle replicas keep reaping on the
// opening window exactly as before. A relay is never re-relayed.

use super::*;

/// Relays queued by one worker between two loop-pass fan-outs. A completed
/// handshake queues at most two relays, so 256 is several poll batches of new
/// split flows; overflow drops the newest relay and is counted — the flow then
/// behaves exactly as it did before #18520.
pub(crate) const HANDSHAKE_RELAY_OUTBOX_CAP: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandshakeRelayStage {
    /// A validated SYN-ACK promoted the sender's replica pair.
    Promoted,
    /// The sender completed the pair.
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HandshakeRelay {
    /// Canonical forward key of the pair.
    pub(crate) forward_key: SessionKey,
    /// The forward row's session id: the incarnation fence. A relay whose id
    /// does not match the receiver's forward row is dropped.
    pub(crate) session_id: u64,
    pub(crate) stage: HandshakeRelayStage,
    /// `Promoted` only: the SYN-ACK segment's ack field.
    pub(crate) synack_ack: Option<u32>,
    /// `Promoted` only: the server's SYN end (SYN-ACK seq + 1 + payload) —
    /// the ack the client's completing segment must carry.
    pub(crate) server_ack_end: Option<u32>,
}

impl SessionEntry {
    /// The pair this entry belongs to has its handshake split across
    /// workers: the entry is a replica of a row authored elsewhere, or a
    /// sibling's relay already advanced it.
    #[inline]
    fn handshake_split_across_workers(&self) -> bool {
        self.handshake_relayed
            || self.origin.is_peer_synced()
            || self.origin == SessionOrigin::SharedPromote
    }

    /// This half serves traffic on THIS table: it is the locally-authored
    /// row, or a hit here refreshed it past its creation (the same
    /// served-here proxy `cache_hit_handshake_progress` uses). Counters are
    /// not usable: an HA import carries the peer's counts (#16217).
    #[inline]
    fn serves_handshake_relay(&self) -> bool {
        !(self.origin.is_peer_synced() || self.origin == SessionOrigin::SharedPromote)
            || self.last_seen_ns > self.created_ns
    }
}

impl SessionTable {
    fn push_handshake_relay(&mut self, relay: HandshakeRelay) {
        if self
            .handshake_relay_outbox
            .iter()
            .any(|queued| queued.forward_key == relay.forward_key && queued.stage == relay.stage)
        {
            return;
        }
        if self.handshake_relay_outbox.len() >= HANDSHAKE_RELAY_OUTBOX_CAP {
            self.handshake_relay_drops = self.handshake_relay_drops.saturating_add(1);
            return;
        }
        self.handshake_relay_outbox.push(relay);
    }

    /// Producer (SYN-ACK): called from the post-admission sequence note. A
    /// reverse replica row that the slow-path Owner replay just promoted
    /// (`established && handshake_pending`) queues a `Promoted` relay
    /// carrying the segment's ack and the server SYN end. Non-SYN-ACK
    /// segments return on the first flag test.
    pub(in crate::session) fn queue_synack_promotion_relay(
        &mut self,
        key: &SessionKey,
        seq: u32,
        ack: u32,
        payload_len: u32,
        tcp_flags: u8,
    ) {
        if !is_syn_ack(tcp_flags) || key.protocol != PROTO_TCP {
            return;
        }
        let Some(record) = self.revalidation_record(key) else {
            return;
        };
        let reverse = &record.entry;
        if !reverse.metadata.is_reverse
            || reverse.closing
            || reverse.syn_ack_first
            || !(reverse.established && reverse.handshake_pending)
        {
            return;
        }
        let forward_key = reverse_session_key(&record.key, reverse.decision.nat);
        let reverse_split = reverse.handshake_split_across_workers();
        let Some(forward) = self.entry_by_key_quiet(&forward_key) else {
            return;
        };
        if forward.metadata.is_reverse
            || forward.session_id == 0
            || !(reverse_split || forward.handshake_split_across_workers())
        {
            return;
        }
        let session_id = forward.session_id;
        self.push_handshake_relay(HandshakeRelay {
            forward_key,
            session_id,
            stage: HandshakeRelayStage::Promoted,
            synack_ack: Some(ack),
            server_ack_end: Some(seq.wrapping_add(1).wrapping_add(payload_len)),
        });
    }

    /// Producer (completion): called from the single HA-Update choke point
    /// (`emit_session_state_update_inner`) on a transition INTO Established,
    /// so a deferred cache-hit completion relays only once its packet is
    /// admitted for TX, exactly like its HA Update.
    pub(in crate::session) fn queue_completion_relay(&mut self, forward_key: &SessionKey) {
        let Some(forward) = self.entry_by_key_quiet(forward_key) else {
            return;
        };
        if forward.metadata.is_reverse
            || forward.closing
            || forward.session_id == 0
            || !(forward.established && !forward.handshake_pending)
        {
            return;
        }
        let session_id = forward.session_id;
        let mut split = forward.handshake_split_across_workers();
        if !split {
            let reverse_key = reverse_session_key(forward_key, forward.decision.nat);
            split = self
                .entry_by_key_quiet(&reverse_key)
                .is_some_and(SessionEntry::handshake_split_across_workers);
        }
        if !split {
            return;
        }
        self.push_handshake_relay(HandshakeRelay {
            forward_key: forward_key.clone(),
            session_id,
            stage: HandshakeRelayStage::Completed,
            synack_ack: None,
            server_ack_end: None,
        });
    }

    /// Cheap per-pass emptiness test for the worker loop.
    #[inline]
    pub(crate) fn has_pending_handshake_relays(&self) -> bool {
        !self.handshake_relay_outbox.is_empty()
    }

    /// Move every queued relay into `out` (caller-owned, reused across
    /// passes); the outbox keeps its allocation.
    pub(crate) fn drain_handshake_relays_into(&mut self, out: &mut Vec<HandshakeRelay>) {
        out.extend(self.handshake_relay_outbox.drain(..));
    }

    /// Relays refused by the bounded outbox since start.
    pub(crate) fn handshake_relay_drops(&self) -> u64 {
        self.handshake_relay_drops
    }

    /// Consumer: apply a sibling's relay to this table's copy of the pair.
    /// Returns true when the pair advanced. Runs on the worker-command drain,
    /// never on the packet path.
    pub(crate) fn apply_handshake_relay(&mut self, relay: &HandshakeRelay, now_ns: u64) -> bool {
        let forward_key = &relay.forward_key;
        if forward_key.protocol != PROTO_TCP || relay.session_id == 0 {
            return false;
        }
        let Some(forward) = self.entry_by_key_quiet(forward_key) else {
            return false;
        };
        if forward.metadata.is_reverse
            || forward.closing
            || forward.session_id != relay.session_id
        {
            return false;
        }
        let nat = forward.decision.nat;
        let handshake_before = forward.tcp_handshake_state_wire(PROTO_TCP);
        let class_before = forward.tcp_close_class_wire();
        let forward_serves = forward.serves_handshake_relay();
        let reverse_key = reverse_session_key(forward_key, nat);
        let reverse = self.entry_by_key_quiet(&reverse_key);
        if reverse.is_some_and(|reverse| reverse.closing) {
            return false;
        }
        // An idle replica pair (neither half authored or hit here) keeps
        // its pre-#18520 opening-window reap: advancing it would only pin
        // an unused replica on the established window.
        if !forward_serves && !reverse.is_some_and(SessionEntry::serves_handshake_relay) {
            return false;
        }
        match relay.stage {
            HandshakeRelayStage::Promoted => {
                // Only a pure Opening SYN-first pair: anything further along
                // already saw (or was relayed) its own SYN-ACK.
                if forward.established || forward.handshake_pending || forward.syn_ack_first {
                    return false;
                }
                // #16042: the relayed SYN-ACK must ack THIS table's client
                // SYN end, exactly as `handshake_expected_ack` would have
                // required had the segment landed here.
                if !Self::handshake_ack_valid(forward.tcp_peer_ack_end, relay.synack_ack) {
                    return false;
                }
                if let Some(entry) = self.entry_by_key_mut(forward_key) {
                    entry.established = true;
                    entry.handshake_pending = true;
                    entry.handshake_relayed = true;
                }
                if let Some(entry) = self.entry_by_key_mut(&reverse_key) {
                    entry.established = true;
                    entry.handshake_pending = true;
                    entry.handshake_relayed = true;
                    // The SYN-ACK was never noted on this table: replace the
                    // install-time expectation with the real server SYN end
                    // so the completing ACK is validated exactly (#16042).
                    entry.tcp_peer_ack_end = relay.server_ack_end;
                }
            }
            HandshakeRelayStage::Completed => {
                // Only a pair a validated SYN-ACK already crossed here; a pure
                // Opening pair is never established by a relay (#6752/#13679).
                if !forward.handshake_pending {
                    return false;
                }
                let timeouts = self.timeouts;
                let opening_override_ns = self.opening_override_for(forward.metadata.ingress_zone);
                if let Some(entry) = self.entry_by_key_mut(forward_key) {
                    entry.established = true;
                    entry.handshake_pending = false;
                    entry.syn_ack_first = false;
                    entry.handshake_relayed = true;
                    entry.last_seen_ns = now_ns;
                    entry.expires_after_ns = session_timeout_ns(
                        PROTO_TCP,
                        0,
                        true,
                        &timeouts,
                        entry.metadata.inactivity_timeout_ns,
                        opening_override_ns,
                    );
                }
                self.propagate_tcp_state_to_companion(
                    forward_key,
                    now_ns,
                    TcpStatePropagation {
                        nat,
                        close: false,
                        reset: false,
                        fin: false,
                        established: false,
                        handshake_completed: true,
                    },
                );
                self.push_to_wheel(forward_key, now_ns);
                let rev = self.rev_packets_for(forward_key);
                self.note_node_served_handshake(
                    forward_key,
                    TcpHandshakeState::Established.to_wire(),
                    rev.max(1),
                );
            }
        }
        // HA Update for the transition, without re-relaying it.
        self.emit_session_state_update_inner(forward_key, class_before, handshake_before, None, false);
        true
    }
}
