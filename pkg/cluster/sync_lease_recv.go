package cluster

import (
	"log/slog"
	"net"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// Receive handlers for IPsec SA, persistent-NAT lease, and DHCP lease
// frames, extracted verbatim from handleMessage (#16168). The two
// multi-label arms keep their msgType parameter so the verbatim
// discriminator checks inside the bodies are unchanged. Dispatch,
// counters, sequence guards, and lock choreography are unchanged.
func (s *SessionSync) handleIPsecSA(conn net.Conn, payload []byte) bool {
	s.stats.IPsecSAReceived.Add(1)
	// #5706: split off the (incarnation, seq) ordering trailer. Check
	// against the last-applied pair before decoding, but do not advance
	// the high-water mark until a complete set commits. Decode is outside
	// the apply lock; the epoch fence prevents a frame spanning a receiver
	// reset from resurrecting a cleared guard.
	base, incarnation, seq := stripFullSetSeq(payload)
	s.recvSeqMu.Lock()
	admit := s.ipsecRecvSeq.newer(incarnation, seq)
	commitEpoch := s.recvEpoch
	s.recvSeqMu.Unlock()
	if !admit {
		s.stats.IPsecSAStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order IPsec SA set (stale sequence) — standby retains newer set",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	// #5706 review fold: strip the '\n' delimiter a new sender inserts
	// between the SA name list and the trailer so a new->new roundtrip
	// leaves no trailing empty name. A legacy / pre-fold frame has no
	// delimiter, so this is a no-op for it.
	names, malformed := decodeIPsecSAPayload(stripIPsecFullSetDelim(base))
	if malformed {
		// #9061: refuse a malformed IPsec SA full set. Unlike the additive
		// persistent-NAT lease channel, IPsec replaces the held set, so a
		// truncated prefix must not overwrite it; the standby keeps its prior
		// state until a complete frame arrives. Crucially, this does not
		// consume the sequence number.
		s.stats.IPsecSAMalformedIgnored.Add(1)
		slog.Warn("cluster sync: refusing a malformed IPsec SA full set",
			"payload_bytes", len(payload), "incarnation", incarnation, "seq", seq)
		return false
	}
	// Serialize high-water advance, held-set replacement, and callback so
	// concurrent fabric receivers cannot commit/callback out of order.
	s.ipsecApplyMu.Lock()
	s.recvSeqMu.Lock()
	applied := s.recvEpoch == commitEpoch &&
		s.ipsecRecvSeq.advanceIfNewer(incarnation, seq)
	if applied {
		s.peerSnaps.peerIPsecSAsMu.Lock()
		s.peerSnaps.peerIPsecSAs = names
		s.peerSnaps.peerIPsecSAsMu.Unlock()
		// #16758: a committed legacy set supersedes every in-flight chunk
		// assembly (its seq is newer by the guard that just advanced).
		s.ipsecChunkState.discardAll()
	}
	s.recvSeqMu.Unlock()
	if !applied {
		s.ipsecApplyMu.Unlock()
		s.stats.IPsecSAStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order IPsec SA set (stale sequence) — standby retains newer set",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	slog.Debug("cluster sync: received IPsec SA list", "count", len(names), "incarnation", incarnation, "seq", seq)
	if s.OnIPsecSAReceived != nil {
		s.OnIPsecSAReceived(names)
	}
	s.ipsecApplyMu.Unlock()
	return true
}

func (s *SessionSync) handleIPsecSAChunk(conn net.Conn, payload []byte) bool {
	// #16758: one chunk of an over-bound IPsec SA full-set. Chunks are
	// admitted in per-frame seq order, assembled by (incarnation,
	// generation), and committed atomically only when the last chunk
	// lands; anything else leaves the held set untouched.
	s.stats.IPsecSAReceived.Add(1)
	base, incarnation, seq := stripFullSetSeq(payload)
	s.recvSeqMu.Lock()
	admit := s.ipsecRecvSeq.newer(incarnation, seq)
	commitEpoch := s.recvEpoch
	s.recvSeqMu.Unlock()
	if !admit {
		s.stats.IPsecSAStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order IPsec SA chunk (stale sequence) — standby retains newer set",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	generation, index, total, totalNames, chunkBody, ok := decodeIPsecSAChunkHeader(base)
	if !ok {
		s.stats.IPsecSAMalformedIgnored.Add(1)
		slog.Warn("cluster sync: dropping malformed IPsec SA chunk header",
			"incarnation", incarnation, "seq", seq, "bytes", len(base))
		return false
	}
	names, decodeErr := decodeIPsecSAChunkBody(chunkBody)
	if decodeErr != nil {
		s.stats.IPsecSAMalformedIgnored.Add(1)
		slog.Warn("cluster sync: dropping malformed IPsec SA chunk — prior set retained",
			"generation", generation, "index", index, "error", decodeErr)
		return false
	}
	s.ipsecApplyMu.Lock()
	s.recvSeqMu.Lock()
	chunkApplied := s.recvEpoch == commitEpoch && s.ipsecRecvSeq.advanceIfNewer(incarnation, seq)
	if !chunkApplied {
		s.recvSeqMu.Unlock()
		s.ipsecApplyMu.Unlock()
		s.stats.IPsecSAStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order IPsec SA chunk (stale sequence) — prior set retained",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	key := ipsecSAChunkGeneration{incarnation: incarnation, generation: generation}
	complete, closed, accepted := s.ipsecChunkState.addChunk(key, index, total, totalNames, names)
	if !accepted {
		s.recvSeqMu.Unlock()
		s.ipsecApplyMu.Unlock()
		s.stats.IPsecSAMalformedIgnored.Add(1)
		slog.Warn("cluster sync: dropping inconsistent IPsec SA chunk assembly — prior set retained",
			"generation", generation, "index", index)
		return false
	}
	if !closed {
		s.recvSeqMu.Unlock()
		s.ipsecApplyMu.Unlock()
		return true
	}
	s.peerSnaps.peerIPsecSAsMu.Lock()
	s.peerSnaps.peerIPsecSAs = complete
	s.peerSnaps.peerIPsecSAsMu.Unlock()
	s.recvSeqMu.Unlock()
	slog.Debug("cluster sync: received chunked IPsec SA list", "count", len(complete), "chunks", total, "incarnation", incarnation, "generation", generation)
	if s.OnIPsecSAReceived != nil {
		s.OnIPsecSAReceived(complete)
	}
	s.ipsecApplyMu.Unlock()
	return true
}

func (s *SessionSync) handlePersistentNatLease(conn net.Conn, payload []byte) bool {
	// #10018 migration fence: type 38 is the pre-scope format.
	slog.Warn("cluster sync: ignoring legacy unscoped persistent-NAT lease set",
		"bytes", len(payload))
	return true
}

func (s *SessionSync) handlePersistentNatLeaseScoped(conn net.Conn, payload []byte) bool {
	// Type 39 predates durable clear generations. Admitting it would
	// bypass the receiver's permanent replay floor.
	slog.Warn("cluster sync: ignoring persistent-NAT lease set without clear generation",
		"bytes", len(payload))
	return true
}

func (s *SessionSync) handlePersistentNatLeaseGeneration(conn net.Conn, msgType uint8, payload []byte) bool {
	// #11486: generation-bearing idle-lease batch. Sequence ordering handles
	// transport reordering within one peer incarnation; the daemon persists
	// origin generation independently across reconnects and process restarts.
	base, incarnation, seq := stripFullSetSeq(payload)
	s.recvSeqMu.Lock()
	admit := s.persistentNatLeaseRecvSeq.newer(incarnation, seq)
	commitEpoch := s.recvEpoch
	s.recvSeqMu.Unlock()
	if !admit {
		slog.Warn("cluster sync: dropping out-of-order persistent-NAT generation batch",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	var batch userspace.PersistentNatLeaseBatch
	var ok bool
	switch msgType {
	case syncMsgPersistentNatLeaseProvenance:
		batch, ok = decodePersistentNatLeaseBatchPayloadProvenance(base, false)
	case syncMsgPersistentNatLeaseDeterministicProvenance:
		batch, ok = decodePersistentNatLeaseBatchPayloadProvenance(base, true)
	case syncMsgPersistentNatLeaseDeterministic:
		batch, ok = decodePersistentNatLeaseBatchPayloadDeterministic(base)
	case syncMsgPersistentNatLeaseTypedPool:
		batch, ok = decodePersistentNatLeaseBatchPayloadTypedPool(base, false)
	case syncMsgPersistentNatLeaseDeterministicTypedPool:
		batch, ok = decodePersistentNatLeaseBatchPayloadTypedPool(base, true)
	default:
		batch, ok = decodePersistentNatLeaseBatchPayload(base)
	}
	if !ok {
		s.stats.MalformedRecordsDropped.Add(1)
		slog.Warn("cluster sync: dropping malformed persistent-NAT generation batch",
			"incarnation", incarnation, "seq", seq, "bytes", len(base))
		return false
	}
	s.persistentNatLeaseApplyMu.Lock()
	s.recvSeqMu.Lock()
	applied := s.recvEpoch == commitEpoch &&
		s.persistentNatLeaseRecvSeq.advanceIfNewer(incarnation, seq)
	s.recvSeqMu.Unlock()
	if !applied {
		s.persistentNatLeaseApplyMu.Unlock()
		slog.Warn("cluster sync: dropping out-of-order persistent-NAT generation batch",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	slog.Debug("cluster sync: received persistent-NAT generation batch",
		"count", len(batch.Leases), "generation", batch.Generation,
		"incarnation", incarnation, "seq", seq)
	if s.OnPersistentNatLeasesReceived != nil {
		s.OnPersistentNatLeasesReceived(batch)
	}
	s.persistentNatLeaseApplyMu.Unlock()
	return true
}

func (s *SessionSync) handleDHCPLeaseV4(conn net.Conn, payload []byte) bool {
	s.stats.DHCPLeasesReceived.Add(1)
	base, incarnation, seq := stripFullSetSeq(payload)
	// #9915 F-117 review: do the cheap sequence admission BEFORE
	// metadata/lease decoding, but advance only when the set applies.
	s.recvSeqMu.Lock()
	admit := s.dhcpV4RecvSeq.newer(incarnation, seq)
	commitEpoch := s.recvEpoch
	s.recvSeqMu.Unlock()
	if !admit {
		s.stats.DHCPLeasesStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order DHCP v4 lease set (stale sequence) — standby retains newer set",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	leasePayload, snapshot, metadataPresent, metadataValid := stripDHCPLeaseSnapshotMeta(base)
	if !metadataValid || (metadataPresent && !validDHCPLeaseSnapshotFamily(snapshot, 4)) {
		s.stats.MalformedRecordsDropped.Add(1)
		slog.Warn("cluster sync: dropping malformed DHCP v4 lease authority snapshot")
		return false
	}
	leases, ok := decodeDHCPLeasePayload(leasePayload)
	if !ok {
		// #7175: a full-set push REPLACES the set, so storing a truncated
		// prefix would delete every lease past the truncation point. Retain
		// the prior set. The mark does not advance (see above).
		s.stats.MalformedRecordsDropped.Add(1)
		slog.Warn("cluster sync: dropping malformed DHCP v4 lease set — standby retains previous set",
			"incarnation", incarnation, "seq", seq, "bytes", len(leasePayload))
		return false
	}
	// Every decoded set is identity-filtered, legacy or sequenced alike:
	// the filter judges records, not senders. Legacy (untrailered) only
	// affects ordering (admit-always, never advances the mark).
	origCount := len(leases)
	var semanticallyDropped int
	leases, semanticallyDropped = filterDHCPLeasesBySemantics(4, leases)
	if semanticallyDropped > 0 {
		s.stats.MalformedRecordsDropped.Add(uint64(semanticallyDropped))
		slog.Warn("cluster sync: dropping semantically invalid DHCP v4 lease records — keeping the rest",
			"dropped", semanticallyDropped, "kept", len(leases), "incarnation", incarnation, "seq", seq)
	}
	leases, dropped := filterDHCPLeasesByIdentity(4, leases)
	if dropped > 0 {
		s.stats.DHCPLeasesDroppedNoIdentity.Add(uint64(dropped))
		slog.Warn("cluster sync: dropping DHCP v4 lease records without family identity — keeping the rest",
			"dropped", dropped, "kept", len(leases), "incarnation", incarnation, "seq", seq)
	}
	if len(leases) == 0 && origCount > 0 {
		// #9915 F-117: a filtered-to-empty set retains the prior held set
		// (the #7175 posture) — only a genuine count==0 push clears. The
		// mark does not advance (see above).
		slog.Warn("cluster sync: DHCP v4 lease set filtered to empty — standby retains previous set",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	// Atomic commit (#9915 F-117 review): the high-water advance, the
	// held-set replacement, and the callback are serialized by
	// dhcpApplyMu, so commit order == callback order: split out, seq 10
	// can advance, seq 11 advance+store+callback, then seq 10 store or
	// callback and regress the held set or its consumer.
	// Locking: recvSeqMu covers only mark+store inside (nesting
	// peerDHCPLeasesMu — the only direction that order is taken, so no
	// cycle); the callback runs under dhcpApplyMu AFTER recvSeqMu is
	// released, so a consumer can never deadlock on the widely-taken
	// receive mutex. Lock order dhcpApplyMu -> recvSeqMu ->
	// peerDHCPLeasesMu, taken only here.
	if s.testDHCPPreCommit != nil {
		s.testDHCPPreCommit()
	}
	s.dhcpApplyMu.Lock()
	s.recvSeqMu.Lock()
	applied := s.recvEpoch == commitEpoch && s.dhcpV4RecvSeq.advanceIfNewer(incarnation, seq)
	if applied {
		snapshot.Leases = leases
		snapshot.Received = true
		s.storePeerDHCPLeaseSnapshot(4, snapshot)
		// #15160: a committed legacy set supersedes every in-flight
		// chunk assembly for this family (its seq is newer by the
		// guard that just advanced).
		s.dhcpChunkState4.discardAll()
	}
	s.recvSeqMu.Unlock()
	if !applied {
		s.dhcpApplyMu.Unlock()
		// Lost a duplicate-fabric race to a newer set that already
		// applied, or lapped by a receiver reset (epoch changed under
		// us): drop rather than regress the held set or resurrect a
		// dead high-water.
		s.stats.DHCPLeasesStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order DHCP v4 lease set (stale sequence) — standby retains newer set",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	slog.Debug("cluster sync: received DHCP v4 lease set", "count", len(leases), "incarnation", incarnation, "seq", seq)
	if s.OnDHCPLeasesReceived != nil {
		s.OnDHCPLeasesReceived(4, leases)
	}
	s.dhcpApplyMu.Unlock()
	return true
}

func (s *SessionSync) handleDHCPLeaseV6(conn net.Conn, payload []byte) bool {
	s.stats.DHCPLeasesReceived.Add(1)
	base, incarnation, seq := stripFullSetSeq(payload)
	// #9915 F-117 review: do the cheap sequence admission BEFORE
	// metadata/lease decoding, but advance only when the set applies.
	s.recvSeqMu.Lock()
	admit := s.dhcpV6RecvSeq.newer(incarnation, seq)
	commitEpoch := s.recvEpoch
	s.recvSeqMu.Unlock()
	if !admit {
		s.stats.DHCPLeasesStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order DHCP v6 lease set (stale sequence) — standby retains newer set",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	leasePayload, snapshot, metadataPresent, metadataValid := stripDHCPLeaseSnapshotMeta(base)
	if !metadataValid || (metadataPresent && !validDHCPLeaseSnapshotFamily(snapshot, 6)) {
		s.stats.MalformedRecordsDropped.Add(1)
		slog.Warn("cluster sync: dropping malformed DHCP v6 lease authority snapshot")
		return false
	}
	leases, ok := decodeDHCPLeasePayload(leasePayload)
	if !ok {
		// #7175: see the v4 twin — retain, no advance.
		s.stats.MalformedRecordsDropped.Add(1)
		slog.Warn("cluster sync: dropping malformed DHCP v6 lease set — standby retains previous set",
			"incarnation", incarnation, "seq", seq, "bytes", len(leasePayload))
		return false
	}
	// Every decoded set is filtered: see the v4 twin.
	origCount := len(leases)
	var semanticallyDropped int
	leases, semanticallyDropped = filterDHCPLeasesBySemantics(6, leases)
	if semanticallyDropped > 0 {
		s.stats.MalformedRecordsDropped.Add(uint64(semanticallyDropped))
		slog.Warn("cluster sync: dropping semantically invalid DHCP v6 lease records — keeping the rest",
			"dropped", semanticallyDropped, "kept", len(leases), "incarnation", incarnation, "seq", seq)
	}
	leases, dropped := filterDHCPLeasesByIdentity(6, leases)
	if dropped > 0 {
		s.stats.DHCPLeasesDroppedNoIdentity.Add(uint64(dropped))
		slog.Warn("cluster sync: dropping DHCP v6 lease records without family identity — keeping the rest",
			"dropped", dropped, "kept", len(leases), "incarnation", incarnation, "seq", seq)
	}
	if len(leases) == 0 && origCount > 0 {
		// #9915 F-117: see the v4 twin — retain, no advance.
		slog.Warn("cluster sync: DHCP v6 lease set filtered to empty — standby retains previous set",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	// Atomic commit: see the v4 twin (dhcpApplyMu spans commit+callback;
	// recvSeqMu only mark+store; the callback must not reenter DHCP
	// receive paths).
	if s.testDHCPPreCommit != nil {
		s.testDHCPPreCommit()
	}
	s.dhcpApplyMu.Lock()
	s.recvSeqMu.Lock()
	applied := s.recvEpoch == commitEpoch && s.dhcpV6RecvSeq.advanceIfNewer(incarnation, seq)
	if applied {
		snapshot.Leases = leases
		snapshot.Received = true
		s.storePeerDHCPLeaseSnapshot(6, snapshot)
		s.dhcpChunkState6.discardAll()
	}
	s.recvSeqMu.Unlock()
	if !applied {
		s.dhcpApplyMu.Unlock()
		// Lost a duplicate-fabric race or lapped by a reset: see the v4 twin.
		s.stats.DHCPLeasesStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order DHCP v6 lease set (stale sequence) — standby retains newer set",
			"incarnation", incarnation, "seq", seq)
		return false
	}
	slog.Debug("cluster sync: received DHCP v6 lease set", "count", len(leases), "incarnation", incarnation, "seq", seq)
	if s.OnDHCPLeasesReceived != nil {
		s.OnDHCPLeasesReceived(6, leases)
	}
	s.dhcpApplyMu.Unlock()
	return true
}

func (s *SessionSync) handleDHCPLeaseChunk(conn net.Conn, msgType uint8, payload []byte) bool {
	// #15160: one chunk of an over-cap DHCP full-set. Chunks are
	// admitted in per-frame seq order, assembled by
	// (incarnation, generation), and committed atomically only
	// when the last chunk lands; anything else leaves the held
	// set and high-water untouched.
	family := 4
	guard := &s.dhcpV4RecvSeq
	state := &s.dhcpChunkState4
	if msgType == syncMsgDHCPLeaseV6Chunk {
		family = 6
		guard = &s.dhcpV6RecvSeq
		state = &s.dhcpChunkState6
	}
	s.stats.DHCPLeasesReceived.Add(1)
	base, incarnation, seq := stripFullSetSeq(payload)
	s.recvSeqMu.Lock()
	admit := guard.newer(incarnation, seq)
	commitEpoch := s.recvEpoch
	s.recvSeqMu.Unlock()
	if !admit {
		s.stats.DHCPLeasesStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order DHCP lease chunk (stale sequence)",
			"family", family, "incarnation", incarnation, "seq", seq)
		return false
	}
	// The #10170 authority trailer rides the last chunk only; strip
	// it (from the reassembled base tail) before header parsing is
	// impossible — it sits AFTER the chunk body, so parse the chunk
	// header first from the front, then strip the trailer from the
	// body tail.
	generation, index, total, totalLeases, chunkBody, ok := decodeDHCPLeaseChunkHeader(base)
	if !ok {
		s.stats.MalformedRecordsDropped.Add(1)
		slog.Warn("cluster sync: dropping malformed DHCP lease chunk header",
			"family", family, "incarnation", incarnation, "seq", seq, "bytes", len(base))
		return false
	}
	var snapshot dhcpserver.LeaseSyncSnapshot
	isLast := index == total-1
	if isLast {
		var metadataPresent, metadataValid bool
		chunkBody, snapshot, metadataPresent, metadataValid = stripDHCPLeaseSnapshotMeta(chunkBody)
		if !metadataValid || (metadataPresent && !validDHCPLeaseSnapshotFamily(snapshot, family)) {
			s.stats.MalformedRecordsDropped.Add(1)
			slog.Warn("cluster sync: dropping malformed DHCP lease chunk authority snapshot", "family", family)
			return false
		}
	}
	leases, decoded := decodeDHCPLeasePayload(chunkBody)
	if !decoded {
		s.stats.MalformedRecordsDropped.Add(1)
		slog.Warn("cluster sync: dropping malformed DHCP lease chunk — prior set retained",
			"family", family, "generation", generation, "index", index)
		return false
	}
	origCount := len(leases)
	var semanticallyDropped int
	leases, semanticallyDropped = filterDHCPLeasesBySemantics(family, leases)
	if semanticallyDropped > 0 {
		s.stats.MalformedRecordsDropped.Add(uint64(semanticallyDropped))
	}
	var identityDropped int
	leases, identityDropped = filterDHCPLeasesByIdentity(family, leases)
	if identityDropped > 0 {
		s.stats.DHCPLeasesDroppedNoIdentity.Add(uint64(identityDropped))
	}
	if len(leases) == 0 && origCount > 0 {
		// A chunk filtered to empty can never satisfy totalLeases;
		// refuse the generation outright (the sender counts drops
		// at encode time, so this is a corrupt/forged stream).
		slog.Warn("cluster sync: DHCP lease chunk filtered to empty — generation refused, prior set retained",
			"family", family, "generation", generation, "index", index)
		return false
	}
	// Advance the per-frame high-water for every admitted chunk
	// (monotone stream), then assemble; commit only on completion.
	if s.testDHCPPreCommit != nil {
		s.testDHCPPreCommit()
	}
	s.dhcpApplyMu.Lock()
	s.recvSeqMu.Lock()
	chunkApplied := s.recvEpoch == commitEpoch && guard.advanceIfNewer(incarnation, seq)
	if !chunkApplied {
		s.recvSeqMu.Unlock()
		s.dhcpApplyMu.Unlock()
		s.stats.DHCPLeasesStaleIgnored.Add(1)
		slog.Warn("cluster sync: dropping out-of-order DHCP lease chunk (stale sequence) — prior set retained",
			"family", family, "incarnation", incarnation, "seq", seq)
		return false
	}
	key := dhcpChunkGeneration{incarnation: incarnation, generation: generation}
	complete, closed, accepted := state.addChunk(key, index, total, totalLeases, leases)
	if !accepted {
		// #16041 fold: an inconsistent assembly (mismatched totals,
		// duplicate index, over-total, under-total at completion)
		// invalidates the generation downstream of seq admission —
		// semantically rejected, so it must not refresh liveness.
		s.recvSeqMu.Unlock()
		s.dhcpApplyMu.Unlock()
		return false
	}
	if !closed {
		s.recvSeqMu.Unlock()
		s.dhcpApplyMu.Unlock()
		return true
	}
	snapshot.Leases = complete
	snapshot.Received = true
	s.storePeerDHCPLeaseSnapshot(family, snapshot)
	s.recvSeqMu.Unlock()
	slog.Debug("cluster sync: received chunked DHCP lease set", "family", family,
		"count", len(complete), "chunks", total, "incarnation", incarnation, "generation", generation)
	if s.OnDHCPLeasesReceived != nil {
		s.OnDHCPLeasesReceived(family, complete)
	}
	s.dhcpApplyMu.Unlock()
	return true
}
