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
//   server SYN end, seeded on the receiver's reverse half so a bare completing
//   ACK is validated exactly as on a single worker. Applied only to a pure
//   Opening SYN-first pair; the receiver moves to `established &&
//   handshake_pending` — the #6752 opening-class gap — so a client segment,
//   not the relay, completes it. Scope of the #16042 claim: a DATA segment
//   completes a pending pair through the #16223 companion arm
//   (`cache_hit_handshake_progress`), which checks no ack — on a relayed pair
//   exactly as on a single worker (#18528).
// * `Completed` — a worker completed a split pair. Applied only to a pair the
//   receiver already holds as handshake-pending (a SYN-ACK was seen on it:
//   validated for a SYN-first pair, or the installing segment of a
//   SYN-ACK-first pickup), never to a pure Opening pair (#6752/#13679).
// * `Closed` — a worker's pair took close progress (first FIN, second FIN,
//   RST). Carries the pair's close bits. The receiver ORs FIN bits in
//   exactly as a local FIN stamps them. A RST bit makes the pair CLOSING (a
//   30 s window that traffic refreshes) and never sets the sticky 2 s reset
//   fuse, because no worker of a split pair can check a RST's sequence
//   number (`apply_close_relay`). Whatever a relay can establish, a relay
//   can close: a FIN or RST that RSS delivered to one worker otherwise
//   reaches no sibling (a replica close announces only to the HA peer,
//   #9582), so a relay-established authoritative row outlived a server RST
//   by 1800 s.
//
// Producers queue into a bounded per-table outbox; the worker loop drains it
// once per pass (`session_glue::fan_out_handshake_relays`), never per packet.
// A `Promoted` relay targets only the author worker when its id is in the
// forward session id's namespace on this node; a `Completed` relay goes to
// every sibling (the SYN-ACK worker's id is not recorded anywhere). A
// receiver applies a relay only to the same incarnation (forward session id)
// and only to a pair that serves traffic on its table (the author, or a
// replica whose `served_here` bit a packet hit here set — a flag, because a
// loop pass stamps packets with a clock read taken BEFORE the replica
// import's), so idle replicas keep reaping on the opening window exactly as
// before. Relays stop at `HANDSHAKE_RELAY_QUEUE_WATERMARK` (half the worker
// command cap) so they never take the headroom HA commands need. A relay is never
// re-relayed, and the receiver publishes NO HA Update for it: the sender
// already published the same transition for the same session id from its own
// row (a replica announces with the installer's carried id, #9582, and a
// stage advance to Established always announces), so a consumer emit only
// duplicated it.

use super::*;

/// Relays queued by one worker between two loop-pass fan-outs. A completed
/// handshake queues at most two relays, so 256 is several poll batches of new
/// split flows; overflow drops the newest relay and is counted — the flow then
/// behaves exactly as it did before #18520.
pub(crate) const HANDSHAKE_RELAY_OUTBOX_CAP: usize = 256;

/// Relays refused by a full outbox, process-wide (cold path: one relaxed
/// add per refused relay). Not yet on the status/metrics surface (#18529).
pub(crate) static HANDSHAKE_RELAY_OUTBOX_DROPS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    /// Test mirror of `HANDSHAKE_RELAY_OUTBOX_DROPS` for the calling thread,
    /// so a cell is not raced by parallel tests bumping the global.
    static OUTBOX_DROPS_THIS_THREAD: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn handshake_relay_outbox_drops_this_thread_for_test() -> u64 {
    OUTBOX_DROPS_THIS_THREAD.with(std::cell::Cell::get)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandshakeRelayStage {
    /// A validated SYN-ACK promoted the sender's replica pair.
    Promoted,
    /// The sender completed the pair.
    Completed,
    /// The sender's pair took close progress (FIN or RST); `close_bits`
    /// says which. Whatever a relay can establish, a relay can close.
    Closed,
}

/// `HandshakeRelay::close_bits`: a RST was seen on the pair.
pub(crate) const RELAY_CLOSE_RESET: u8 = 1;
/// `HandshakeRelay::close_bits`: a FIN was seen in the FORWARD direction.
pub(crate) const RELAY_CLOSE_FIN_FORWARD: u8 = 2;
/// `HandshakeRelay::close_bits`: a FIN was seen in the REVERSE direction.
pub(crate) const RELAY_CLOSE_FIN_REVERSE: u8 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HandshakeRelay {
    /// Canonical forward key of the pair.
    pub(crate) forward_key: SessionKey,
    /// The forward row's session id: the incarnation fence. A relay whose id
    /// does not match the receiver's forward row is dropped.
    pub(crate) session_id: u64,
    pub(crate) stage: HandshakeRelayStage,
    /// The worker that should receive it, when known: for `Promoted`, the
    /// author worker named by a same-node forward session id. `None` fans
    /// out to every sibling.
    pub(crate) target_worker: Option<u32>,
    /// `Promoted` only: the SYN-ACK segment's ack field.
    pub(crate) synack_ack: Option<u32>,
    /// `Promoted` only: the server's SYN end (SYN-ACK seq + 1 + payload) —
    /// the ack the client's completing segment must carry.
    pub(crate) server_ack_end: Option<u32>,
    /// `Closed` only: `RELAY_CLOSE_*` bits of the sender's pair.
    pub(crate) close_bits: u8,
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
    /// row, or a packet hit here set `served_here`. Neither a timestamp nor
    /// the counters can stand in: a replica imported and hit in the same
    /// loop pass has `last_seen < created` (two clock reads, packet clock
    /// first), GC retention re-stamps idle replicas, and an HA import
    /// carries the peer's counts (#16217).
    #[inline]
    fn serves_handshake_relay(&self) -> bool {
        !(self.origin.is_peer_synced() || self.origin == SessionOrigin::SharedPromote)
            || self.served_here
    }
}

impl SessionTable {
    fn push_handshake_relay(&mut self, relay: HandshakeRelay) {
        if let Some(queued) = self
            .handshake_relay_outbox
            .iter_mut()
            .find(|queued| queued.forward_key == relay.forward_key && queued.stage == relay.stage)
        {
            // Close progress accumulates within one pass (FIN then RST).
            queued.close_bits |= relay.close_bits;
            return;
        }
        if self.handshake_relay_outbox.len() >= HANDSHAKE_RELAY_OUTBOX_CAP {
            HANDSHAKE_RELAY_OUTBOX_DROPS.fetch_add(1, AtomicOrdering::Relaxed);
            #[cfg(test)]
            OUTBOX_DROPS_THIS_THREAD.with(|drops| drops.set(drops.get() + 1));
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
        let target_worker = self.same_node_author_worker(session_id);
        self.push_handshake_relay(HandshakeRelay {
            forward_key,
            session_id,
            stage: HandshakeRelayStage::Promoted,
            target_worker,
            synack_ack: Some(ack),
            server_ack_end: Some(seq.wrapping_add(1).wrapping_add(payload_len)),
            close_bits: 0,
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
            target_worker: None,
            synack_ack: None,
            server_ack_end: None,
            close_bits: 0,
        });
    }

    /// Producer (close): called from the HA-Update choke point on a close
    /// CLASS transition of a pair split across workers. A FIN or RST that
    /// RSS delivered to one worker otherwise reaches no sibling (a replica
    /// close announces only to the HA peer, #9582, and replica expiry sends
    /// no Close), so a relay-established authoritative row would sit
    /// Established on the 1800 s window after the server reset the flow.
    pub(in crate::session) fn queue_close_relay(&mut self, forward_key: &SessionKey) {
        let Some(forward) = self.entry_by_key_quiet(forward_key) else {
            return;
        };
        if forward.metadata.is_reverse || forward.session_id == 0 {
            return;
        }
        let session_id = forward.session_id;
        let mut split = forward.handshake_split_across_workers();
        let mut close_bits = 0u8;
        if forward.reset {
            close_bits |= RELAY_CLOSE_RESET;
        }
        // A direction's FIN is recorded as `fin_own` on its own half and
        // `fin_peer` on the companion (`propagate_tcp_state_to_companion`).
        // The forward half is always present here and carries every
        // forward FIN as `fin_own` (local or relayed). Only the reverse
        // FIN can lack its own half (reaped, or never installed here), so
        // it is also read from `forward.fin_peer`.
        if forward.fin_own {
            close_bits |= RELAY_CLOSE_FIN_FORWARD;
        }
        if forward.fin_peer {
            close_bits |= RELAY_CLOSE_FIN_REVERSE;
        }
        let reverse_key = reverse_session_key(forward_key, forward.decision.nat);
        if let Some(reverse) = self.entry_by_key_quiet(&reverse_key) {
            split |= reverse.handshake_split_across_workers();
            if reverse.reset {
                close_bits |= RELAY_CLOSE_RESET;
            }
            if reverse.fin_own {
                close_bits |= RELAY_CLOSE_FIN_REVERSE;
            }
        }
        if !split || close_bits == 0 {
            return;
        }
        self.push_handshake_relay(HandshakeRelay {
            forward_key: forward_key.clone(),
            session_id,
            stage: HandshakeRelayStage::Closed,
            target_worker: None,
            synack_ack: None,
            server_ack_end: None,
            close_bits,
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

    /// The worker that minted `session_id`, when it is ANOTHER worker of
    /// THIS node (namespace = node bit | worker id in the high 16 bits,
    /// #6311). A peer-node id (HA import) or this worker's own id is `None`.
    fn same_node_author_worker(&self, session_id: u64) -> Option<u32> {
        if !self.session_id_carried_from_another_worker(session_id) {
            return None;
        }
        let namespace = session_id >> 48;
        let own_namespace = self.session_id_worker_hi >> 48;
        let node_bit = 1u64 << SESSION_ID_NODE_BIT_SHIFT;
        if namespace & node_bit != own_namespace & node_bit {
            return None;
        }
        Some((namespace & SESSION_ID_MAX_WORKER) as u32)
    }

    #[cfg(test)]
    pub(crate) fn push_handshake_relay_for_test(&mut self, relay: HandshakeRelay) {
        self.push_handshake_relay(relay);
    }

    /// Test seam: close ONE half without the companion propagation a real
    /// FIN/RST performs, to reach the receiver's per-half closing refusal.
    #[cfg(test)]
    pub(crate) fn mark_closing_for_test(&mut self, key: &SessionKey) {
        if let Some(entry) = self.entry_by_key_mut(key) {
            entry.closing = true;
        }
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
        if forward.metadata.is_reverse || forward.session_id != relay.session_id {
            return false;
        }
        let nat = forward.decision.nat;
        let forward_serves = forward.serves_handshake_relay();
        let reverse_key = reverse_session_key(forward_key, nat);
        let reverse = self.entry_by_key_quiet(&reverse_key);
        // A relay never establishes (or re-pends) a closing pair (#14630);
        // only close progress may still apply to one.
        let pair_closing = forward.closing || reverse.is_some_and(|reverse| reverse.closing);
        if pair_closing && relay.stage != HandshakeRelayStage::Closed {
            return false;
        }
        // An idle replica pair (neither half authored or hit here) keeps
        // its pre-#18520 opening-window reap: advancing it would only pin
        // an unused replica on the established window.
        if !forward_serves && !reverse.is_some_and(SessionEntry::serves_handshake_relay) {
            return false;
        }
        match relay.stage {
            HandshakeRelayStage::Closed => {
                return self.apply_close_relay(forward_key, &reverse_key, nat, relay.close_bits, now_ns);
            }
            HandshakeRelayStage::Promoted => {
                // Only a pure Opening SYN-first pair: anything further along
                // already saw (or was relayed) its own SYN-ACK. (A SYN-ACK-first
                // pickup is always `handshake_pending`, so it is refused here.)
                if forward.established || forward.handshake_pending {
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
                // Only a pair a SYN-ACK already crossed here (validated, for a
                // SYN-first pair; the installing segment of a SYN-ACK-first
                // pickup); a pure Opening pair is never established by a
                // relay (#6752/#13679).
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
        // No HA Update here: the sender published this transition for the
        // same session id from its own row (see the module header).
        true
    }

    /// Apply a sibling's close progress to this table's pair: the FIN bits a
    /// local FIN stamps (`stamp_tcp_close` on the half the segment matched,
    /// `propagate_tcp_state_to_companion` on its companion), then the shared
    /// close-window formula. Close progress re-stamps the window from `now`
    /// exactly as local close progress does (#10885); a relay that adds
    /// nothing new changes nothing.
    ///
    /// A relayed RST makes the pair CLOSING and never sets the sticky
    /// `reset` fuse. No worker of a split pair can check a RST's sequence
    /// number: B never sees the client ACKs that set the RST target
    /// (`tcp_peer_rcv_nxt`), and A never notes a server segment, so
    /// `tcp_closing_seq_verdict` is `Unknown` on both and the poll path
    /// admits a blind RST with any sequence number. The worker that
    /// received it still takes the fixed 2 s fuse locally, as before. Here
    /// the pair keeps forwarding on the 30 s close window. Ordinary traffic
    /// refreshes that window: the cache-hit keepalive is allowed for a
    /// non-reset, non-FIN-owning half, and the slow path re-applies the
    /// same window. A pair that really was reset goes quiet and reaps
    /// within two close windows (#14937 counter retention grants one more if
    /// segments still arrived after the relay), emitting the Close that
    /// frees its SNAT port. A blind RST leaves the live flow forwarding. The
    /// fixed fuse would have killed it on every worker, and the
    /// authoritative reap would have deleted the shared row and the HA
    /// peer's copy as well.
    fn apply_close_relay(
        &mut self,
        forward_key: &SessionKey,
        reverse_key: &SessionKey,
        nat: crate::nat::NatDecision,
        close_bits: u8,
        now_ns: u64,
    ) -> bool {
        let reset = close_bits & RELAY_CLOSE_RESET != 0;
        let fin_forward = close_bits & RELAY_CLOSE_FIN_FORWARD != 0;
        let fin_reverse = close_bits & RELAY_CLOSE_FIN_REVERSE != 0;
        if !reset && !fin_forward && !fin_reverse {
            return false;
        }
        let became_closing = self
            .entry_by_key_quiet(forward_key)
            .is_some_and(|forward| !forward.closing);
        let timeouts = self.timeouts;
        let mut changed = false;
        for (key, fin_own, fin_peer) in [
            (forward_key, fin_forward, fin_reverse),
            (reverse_key, fin_reverse, fin_forward),
        ] {
            let Some(entry) = self.entry_by_key_mut(key) else {
                continue;
            };
            // `reset` is never relayed (see the doc above): the RST bit only
            // makes the pair CLOSING.
            let next_fin_own = entry.fin_own || fin_own;
            let next_fin_peer = entry.fin_peer || fin_peer;
            if entry.closing && next_fin_own == entry.fin_own && next_fin_peer == entry.fin_peer {
                continue;
            }
            entry.closing = true;
            entry.fin_own = next_fin_own;
            entry.fin_peer = next_fin_peer;
            entry.last_seen_ns = entry.last_seen_ns.max(now_ns);
            entry.expires_after_ns = tcp_close_window_for_entry(entry, &timeouts);
            changed = true;
            self.push_to_wheel(key, now_ns);
        }
        if changed && became_closing {
            // #16489: baseline at the first transition into CLOSING.
            self.seed_closing_counters_baseline(forward_key, nat);
        }
        changed
    }
}
