package daemon

// #9506 S4 authority core.
//
// This file owns the Go-side authorization state used by the r6 queue/permit
// lifecycle. The Rust q0 writer remains the physical full-frame writer (and
// therefore the REINJECT commit point); this package provides the immutable
// permit record, emission-gate DROP authority, queue-handle identity, and the
// supervisor-side terminal accounting that surrounds it.
//
// Plan references: r6 §2.2 (divert transaction and epoch mapping), §3.2
// (q0 ReinjectLease protocol), §3.5 items 1, 3, 4a, 5, 6, and T12[P] cells
// 3–6; r5 §12.3 (shared commit lease and uncertain terminality).

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ipsecPermitState is intentionally not a bool. CLOSING is observable and
// means new authorization is forbidden while already-held operations may drain;
// CLOSED means the queue/listener generation is retired.
type ipsecPermitState uint8

const (
	ipsecPermitClosing ipsecPermitState = iota
	ipsecPermitOpen
	ipsecPermitClosed
)

func (s ipsecPermitState) String() string {
	switch s {
	case ipsecPermitClosing:
		return "CLOSING"
	case ipsecPermitOpen:
		return "OPEN"
	case ipsecPermitClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("permit-state(%d)", s)
	}
}

// ipsecReadyResult is part of closeRequestKey. SAFE/UNSAFE/UNKNOWN must not be
// conflated: an unknown census is a conservative close and one persistent
// unknown episode, not a fresh request on every periodic tick.
type ipsecReadyResult uint8

const (
	ipsecReadySafe ipsecReadyResult = iota
	ipsecReadyUnsafe
	ipsecReadyUnknown
)

func (r ipsecReadyResult) String() string {
	switch r {
	case ipsecReadySafe:
		return "SAFE"
	case ipsecReadyUnsafe:
		return "UNSAFE"
	case ipsecReadyUnknown:
		return "UNKNOWN"
	default:
		return fmt.Sprintf("ready(%d)", r)
	}
}

// ipsecTopologyTuple is an immutable identity in the canonical close key. The
// owner is the device-ownership identity, never the worker dispatch owner.
type ipsecTopologyTuple struct {
	Kind        string
	Ifindex     int
	MasterIndex int
	Name        string
	Owner       string
}

func (t ipsecTopologyTuple) less(o ipsecTopologyTuple) bool {
	if t.Kind != o.Kind {
		return t.Kind < o.Kind
	}
	if t.Ifindex != o.Ifindex {
		return t.Ifindex < o.Ifindex
	}
	if t.MasterIndex != o.MasterIndex {
		return t.MasterIndex < o.MasterIndex
	}
	if t.Name != o.Name {
		return t.Name < o.Name
	}
	return t.Owner < o.Owner
}

func (t ipsecTopologyTuple) equal(o ipsecTopologyTuple) bool {
	return t == o
}

// ipsecCloseRequestKey is a value type so equality compares the complete
// sorted vector and ready result, rather than a lossy hash or LinkList order.
type ipsecCloseRequestKey struct {
	Ready           ipsecReadyResult
	WatchGeneration uint64
	Tuples          []ipsecTopologyTuple
}

func makeCloseRequestKey(ready ipsecReadyResult, watchGeneration uint64, tuples []ipsecTopologyTuple) ipsecCloseRequestKey {
	canon := append([]ipsecTopologyTuple(nil), tuples...)
	sort.Slice(canon, func(i, j int) bool { return canon[i].less(canon[j]) })
	return ipsecCloseRequestKey{Ready: ready, WatchGeneration: watchGeneration, Tuples: canon}
}

func (k ipsecCloseRequestKey) equal(other ipsecCloseRequestKey) bool {
	if k.Ready != other.Ready || k.WatchGeneration != other.WatchGeneration || len(k.Tuples) != len(other.Tuples) {
		return false
	}
	for i := range k.Tuples {
		if !k.Tuples[i].equal(other.Tuples[i]) {
			return false
		}
	}
	return true
}

func (k ipsecCloseRequestKey) sameCensus(other ipsecCloseRequestKey) bool {
	if len(k.Tuples) != len(other.Tuples) {
		return false
	}
	for i := range k.Tuples {
		if !k.Tuples[i].equal(other.Tuples[i]) {
			return false
		}
	}
	return true
}

// permitRecord is immutable after publication. Do not add in-place mutation:
// readers use the complete pointer as their ABA-safe expected value.
type permitRecord struct {
	state           ipsecPermitState
	permitEpoch     uint64
	closeRequestSeq uint64
	closeRequestKey ipsecCloseRequestKey
	watchGeneration uint64
}

// TransitWatchSnapshot is the immutable watcher publication bound to an OPEN
// permit. The concrete link census is intentionally represented as tuples so a
// watcher never reads protected daemon maps while classifying events.
type TransitWatchSnapshot struct {
	Generation uint64
	Ready      ipsecReadyResult
	Tuples     []ipsecTopologyTuple
}

func (s *TransitWatchSnapshot) closeKey() ipsecCloseRequestKey {
	if s == nil {
		return makeCloseRequestKey(ipsecReadyUnknown, 0, nil)
	}
	return makeCloseRequestKey(s.Ready, s.Generation, s.Tuples)
}

type ipsecTopologyEvent struct {
	Seq uint64
	Key ipsecCloseRequestKey
}

// ipsecSupervisor is deliberately usable without a Daemon so T12 can exercise
// the linearization protocol without a kernel. Daemon integration is added by
// the gate helper and keeps this state independent from dataplane ownership.
type ipsecSupervisor struct {
	permit atomic.Pointer[permitRecord]
	watch  atomic.Pointer[TransitWatchSnapshot]

	closeEventSeq atomic.Uint64

	gateMu     sync.Mutex
	gates      map[uint16]*ipsecEmissionGate
	leaseMu    sync.Mutex
	leaseEpoch uint64

	// watchPublishMu serializes the immutable watch pointer + permit-record
	// pair. It is the local equivalent of applySem ownership for publication.
	watchPublishMu sync.Mutex
	// Test seam used to force the pointer/record CAS interleaving. Production
	// revocation remains CAS-only and never invokes this callback.
	publishBeforePermitCAS func()
	// commitLease is the shared commit/close lease. Terminal verdicts hold
	// RLock from validation through the sink syscall. Revocation is a CAS-only
	// permit transition; drainCommitLeases takes the write lock before close
	// teardown so no pre-close ACCEPT remains in flight.
	commitLease sync.RWMutex

	// Supervisor-visible terminal accounting. Uncertain operations are terminal
	// and never retried; only packets that remained held may be reconciled.
	terminalMu sync.Mutex
	terminal   map[ipsecTerminalKey]ipsecTerminalState

	allocator *ipsecQueueAllocator
}

func newIpsecSupervisor() *ipsecSupervisor {
	s := &ipsecSupervisor{
		gates:     make(map[uint16]*ipsecEmissionGate),
		terminal:  make(map[ipsecTerminalKey]ipsecTerminalState),
		allocator: newIpsecQueueAllocator(),
	}
	s.permit.Store(&permitRecord{state: ipsecPermitClosing})
	return s
}

func (s *ipsecSupervisor) loadPermit() *permitRecord {
	if s == nil {
		return nil
	}
	return s.permit.Load()
}

func (s *ipsecSupervisor) allocCloseEventSeq() uint64 {
	if s == nil {
		return 0
	}
	return s.closeEventSeq.Add(1)
}

func (s *ipsecSupervisor) allocCloseEventSeqAfter(previous uint64) uint64 {
	if s == nil {
		return 0
	}
	for {
		current := s.closeEventSeq.Load()
		next := current + 1
		if next <= previous {
			next = previous + 1
		}
		if s.closeEventSeq.CompareAndSwap(current, next) {
			return next
		}
	}
}

func (s *ipsecSupervisor) observeCloseEventSeq(seq uint64) {
	if s == nil {
		return
	}
	for {
		current := s.closeEventSeq.Load()
		if current >= seq || s.closeEventSeq.CompareAndSwap(current, seq) {
			return
		}
	}
}

// It performs a full-record CAS, preserving watchGeneration and incrementing
// permitEpoch exactly once for OPEN→CLOSING. Retries with an old sequence/key
// are no-ops; a distinct CLOSING event advances only closeRequestSeq.
func (s *ipsecSupervisor) revokeTransitPermitNonblocking(event ipsecTopologyEvent) (*permitRecord, *permitRecord) {
	if s == nil {
		return nil, nil
	}
	for {
		old := s.permit.Load()
		if old == nil {
			old = &permitRecord{state: ipsecPermitClosing}
			if s.permit.CompareAndSwap(nil, old) {
				continue
			}
			continue
		}
		seq := event.Seq
		if seq == 0 {
			seq = s.allocCloseEventSeqAfter(old.closeRequestSeq)
		} else {
			s.observeCloseEventSeq(seq)
		}
		if old.state == ipsecPermitClosed {
			return old, old
		}
		if seq <= old.closeRequestSeq {
			return old, old
		}
		if old.state == ipsecPermitClosing && event.Key.equal(old.closeRequestKey) && seq == old.closeRequestSeq {
			return old, old
		}
		newRec := &permitRecord{
			state:           ipsecPermitClosing,
			permitEpoch:     old.permitEpoch,
			closeRequestSeq: seq,
			closeRequestKey: event.Key,
			watchGeneration: old.watchGeneration,
		}
		if old.state == ipsecPermitOpen {
			newRec.permitEpoch++
		}
		if s.permit.CompareAndSwap(old, newRec) {
			return newRec, old
		}
	}
}

// drainCommitLeases is called by the semaphore-owned CLOSING phase before
// installing a replacement fence or beginning teardown. Revoke remains
// CAS-only and nonblocking for topology callbacks; this drain is the close
// linearization point for already-running terminal sink syscalls.
func (s *ipsecSupervisor) drainCommitLeases() {
	if s == nil {
		return
	}
	s.commitLease.Lock()
	s.commitLease.Unlock()
}

// finalizePermitClose is the explicit queue/listener teardown ACK boundary.
// Callers invoke it only after gates are closed, listeners have exited, queue
// destruction is confirmed, and the host-fence retire protocol has completed.
// The shared commit lease prevents a terminal sink syscall from crossing this
// CLOSED publication.
func (s *ipsecSupervisor) finalizePermitClose(expected *permitRecord) bool {
	if s == nil || expected == nil || expected.state != ipsecPermitClosing {
		return false
	}
	s.commitLease.Lock()
	defer s.commitLease.Unlock()
	s.watchPublishMu.Lock()
	defer s.watchPublishMu.Unlock()
	current := s.permit.Load()
	if current != expected || current.state != ipsecPermitClosing {
		return false
	}
	closed := &permitRecord{
		state:           ipsecPermitClosed,
		permitEpoch:     current.permitEpoch,
		closeRequestSeq: current.closeRequestSeq,
		closeRequestKey: current.closeRequestKey,
		watchGeneration: current.watchGeneration,
	}
	return s.permit.CompareAndSwap(expected, closed)
}
func (s *ipsecSupervisor) tryOpenPermit(expected *permitRecord, safeKey ipsecCloseRequestKey, watchGeneration uint64) bool {
	if s == nil {
		return false
	}
	s.watchPublishMu.Lock()
	defer s.watchPublishMu.Unlock()
	if expected == nil || expected.state != ipsecPermitClosing ||
		expected.watchGeneration != watchGeneration || safeKey.WatchGeneration != watchGeneration ||
		safeKey.Ready != ipsecReadySafe ||
		(expected.closeRequestKey.Ready == ipsecReadyUnknown && !expected.closeRequestKey.equal(safeKey)) {
		return false
	}
	current := s.watch.Load()
	if current == nil || current.Generation != watchGeneration || !current.closeKey().equal(safeKey) {
		return false
	}
	opened := &permitRecord{
		state:           ipsecPermitOpen,
		permitEpoch:     expected.permitEpoch + 1,
		closeRequestSeq: expected.closeRequestSeq,
		closeRequestKey: safeKey,
		watchGeneration: watchGeneration,
	}
	return s.permit.CompareAndSwap(expected, opened)
}

func (s *ipsecSupervisor) publishWatchSnapshot(snapshot *TransitWatchSnapshot) bool {
	if s == nil || snapshot == nil {
		return false
	}
	s.watchPublishMu.Lock()
	defer s.watchPublishMu.Unlock()
	for {
		old := s.permit.Load()
		if old == nil {
			return false
		}
		if old.state == ipsecPermitClosed {
			return false
		}
		// A stale publisher must never overwrite a newer watch pointer or
		// record. A same-generation snapshot is accepted only when its full
		// close key is identical; a changed census must advance generation.
		if snapshot.Generation < old.watchGeneration {
			return false
		}
		current := s.watch.Load()
		if current != nil {
			if snapshot.Generation < current.Generation {
				return false
			}
			if old.state == ipsecPermitClosing &&
				!old.closeRequestKey.sameCensus(current.closeKey()) &&
				!old.closeRequestKey.sameCensus(snapshot.closeKey()) {
				return false
			}
			if snapshot.Generation == current.Generation &&
				snapshot.closeKey().equal(current.closeKey()) &&
				old.watchGeneration == snapshot.Generation &&
				old.closeRequestKey.equal(snapshot.closeKey()) {
				return true
			}
		} else if old.state == ipsecPermitClosing &&
			old.watchGeneration != 0 &&
			old.closeRequestSeq != 0 &&
			!old.closeRequestKey.sameCensus(snapshot.closeKey()) {
			return false
		}
		if old.state == ipsecPermitOpen {
			seq := s.allocCloseEventSeqAfter(old.closeRequestSeq)
			key := snapshot.closeKey()
			s.revokeTransitPermitNonblocking(ipsecTopologyEvent{Seq: seq, Key: key})
			continue
		}
		key := old.closeRequestKey
		seq := old.closeRequestSeq
		if !old.closeRequestKey.equal(snapshot.closeKey()) {
			seq = s.allocCloseEventSeqAfter(old.closeRequestSeq)
			key = snapshot.closeKey()
		}
		// The pointer swap happens only while CLOSING. Couple the record CAS to
		// the exact pointer and carry the changed snapshot's authority key.
		s.watch.Store(snapshot)
		if s.publishBeforePermitCAS != nil {
			s.publishBeforePermitCAS()
		}
		newRec := &permitRecord{
			state:           old.state,
			permitEpoch:     old.permitEpoch,
			closeRequestSeq: seq,
			closeRequestKey: key,
			watchGeneration: snapshot.Generation,
		}
		if s.permit.CompareAndSwap(old, newRec) {
			return true
		}
		// A CAS-only revoke may have won while the pointer was staged. Never
		// retry this stale snapshot over the newer authority; restore the prior
		// pointer and let the census owner restart from the winner.
		if s.permit.Load() != old {
			s.watch.CompareAndSwap(snapshot, current)
			return false
		}
	}
}

// ---- emission gates / terminal verdict authority -------------------------

type ipsecGateState uint8

const (
	ipsecGateOpen ipsecGateState = iota
	ipsecGateClosing
	ipsecGateClosed
)

const (
	ipsecGateForward uint8 = iota
	ipsecGateInput
	ipsecGateBridgeForward
	ipsecGateBridgeInput
)

type ipsecEmissionGate struct {
	id    uint16
	kind  uint8
	state atomic.Uint32
	epoch atomic.Uint64
}

func (g *ipsecEmissionGate) currentState() ipsecGateState {
	if g == nil {
		return ipsecGateClosed
	}
	return ipsecGateState(g.state.Load())
}

func (s *ipsecSupervisor) registerEmissionGate(id uint16, kind uint8) *ipsecEmissionGate {
	return s.registerEmissionGateEpoch(id, kind, 1)
}

func (s *ipsecSupervisor) registerEmissionGateEpoch(id uint16, kind uint8, queueEpoch uint64) *ipsecEmissionGate {
	if s == nil || id == 0 || queueEpoch == 0 {
		return nil
	}
	g := &ipsecEmissionGate{id: id, kind: kind}
	g.state.Store(uint32(ipsecGateOpen))
	g.epoch.Store(queueEpoch)
	s.gateMu.Lock()
	if s.gates == nil {
		s.gates = make(map[uint16]*ipsecEmissionGate)
	}
	s.gates[id] = g
	s.gateMu.Unlock()
	return g
}

func (s *ipsecSupervisor) closeEmissionGate(id uint16) bool {
	g := s.gate(id)
	if g == nil {
		return false
	}
	return g.state.CompareAndSwap(uint32(ipsecGateOpen), uint32(ipsecGateClosing))
}

func (s *ipsecSupervisor) retireEmissionGate(id uint16) bool {
	g := s.gate(id)
	if g == nil {
		return false
	}
	for {
		old := ipsecGateState(g.state.Load())
		if old == ipsecGateClosed {
			return true
		}
		if old != ipsecGateClosing {
			return false
		}
		if g.state.CompareAndSwap(uint32(old), uint32(ipsecGateClosed)) {
			return true
		}
	}
}

func (s *ipsecSupervisor) gate(id uint16) *ipsecEmissionGate {
	if s == nil {
		return nil
	}
	s.gateMu.Lock()
	defer s.gateMu.Unlock()
	return s.gates[id]
}

type ipsecLeaseToken struct {
	permitEpoch uint64
	queueEpoch  uint64
	requestID   uint64
}

func (s *ipsecSupervisor) leaseTokenForTest() ipsecLeaseToken {
	if s == nil {
		return ipsecLeaseToken{}
	}
	s.leaseMu.Lock()
	s.leaseEpoch++
	n := s.leaseEpoch
	s.leaseMu.Unlock()
	rec := s.loadPermit()
	if rec == nil {
		return ipsecLeaseToken{requestID: n}
	}
	return ipsecLeaseToken{permitEpoch: rec.permitEpoch, queueEpoch: 1, requestID: n}
}
func (s *ipsecSupervisor) permitLeaseLive(token ipsecLeaseToken, expected *permitRecord) bool {
	if token.requestID == 0 || expected == nil || expected.state != ipsecPermitOpen || token.permitEpoch != expected.permitEpoch {
		return false
	}
	return true
}

type ipsecVerdict uint8

const (
	ipsecVerdictDrop ipsecVerdict = iota
	ipsecVerdictAccept
)

var (
	errIpsecPermitClosed    = errors.New("ipsec: permit epoch closed")
	errIpsecGateClosed      = errors.New("ipsec: emission gate closed")
	errIpsecAlreadyTerminal = errors.New("ipsec: packet already has terminal verdict")
)

type ipsecPacketRef struct {
	GateID             uint16
	QueueNumber        uint16
	QueueEpoch         uint64
	SnapshotGeneration uint64
	PacketID           uint32
}

type ipsecTerminalKey struct {
	GateID      uint16
	QueueNumber uint16
	QueueEpoch  uint64
	PacketID    uint32
}

type ipsecTerminalState uint8

const (
	ipsecTerminalAttempted ipsecTerminalState = iota + 1
	ipsecTerminalSuccessful
	ipsecTerminalUncertain
)

type ipsecVerdictSink interface {
	Verdict(ipsecVerdict, uint32) error
}

// commitValidatedVerdict is the Go-side terminal DROP/ACCEPT path. It checks
// the complete permit record before the syscall and holds a shared lease token
// through sink invocation. An invalid/stale permit is terminal DROP; an error
// from the sink is uncertain and never retried.
func (s *ipsecSupervisor) commitValidatedVerdict(token ipsecLeaseToken, gateID uint16, requested ipsecVerdict, expected *permitRecord, packet ipsecPacketRef, sink ipsecVerdictSink) (ipsecVerdict, bool, error) {
	if s == nil || sink == nil {
		return ipsecVerdictDrop, true, errIpsecPermitClosed
	}
	g := s.gate(gateID)
	key := ipsecTerminalKey{
		GateID: gateID, QueueNumber: packet.QueueNumber,
		QueueEpoch: packet.QueueEpoch, PacketID: packet.PacketID,
	}
	// Reserve terminality before any validation or syscall. A second caller
	// cannot race past this reservation, including when the first syscall later
	// becomes uncertain.
	s.terminalMu.Lock()
	if prior := s.terminal[key]; prior != 0 {
		s.terminalMu.Unlock()
		return ipsecVerdictDrop, true, errIpsecAlreadyTerminal
	}
	s.terminal[key] = ipsecTerminalAttempted
	s.terminalMu.Unlock()

	s.commitLease.RLock()
	defer s.commitLease.RUnlock()
	current := s.loadPermit()
	verdict := requested
	refused := false
	// Validation order is load-bearing: permit record, queue epoch, then the
	// snapshot generation. A stale tuple receives one terminal DROP.
	if g == nil || g.currentState() != ipsecGateOpen {
		verdict, refused = ipsecVerdictDrop, true
	}
	if current == nil || expected == nil || current != expected || !s.permitLeaseLive(token, current) {
		verdict, refused = ipsecVerdictDrop, true
	}
	if packet.GateID != gateID || g == nil || packet.QueueNumber == 0 ||
		packet.QueueEpoch == 0 || packet.QueueNumber != g.id ||
		packet.QueueEpoch != token.queueEpoch || packet.QueueEpoch != g.epoch.Load() {
		verdict, refused = ipsecVerdictDrop, true
	}
	if packet.SnapshotGeneration == 0 || current == nil || packet.SnapshotGeneration != current.watchGeneration {
		verdict, refused = ipsecVerdictDrop, true
	}
	if err := sink.Verdict(verdict, packet.PacketID); err != nil {
		s.terminalMu.Lock()
		s.terminal[key] = ipsecTerminalUncertain
		s.terminalMu.Unlock()
		return verdict, refused, err
	}
	s.terminalMu.Lock()
	s.terminal[key] = ipsecTerminalSuccessful
	s.terminalMu.Unlock()
	return verdict, refused, nil
}

// ipsecReinjectLease is the q0-side descriptor. The actual full-frame write
// and completion ACK are performed by the sole Rust writer; this token carries
// the Go authority tuple and is rejected when its permit or queue generation
// has gone stale.
type ipsecReinjectLease struct {
	PermitEpoch uint64
	QueueEpoch  uint64
	RequestID   uint64
}

func (s *ipsecSupervisor) validateReinjectLease(lease ipsecReinjectLease, queueEpoch uint64) error {
	rec := s.loadPermit()
	if rec == nil || rec.state != ipsecPermitOpen || rec.permitEpoch != lease.PermitEpoch {
		return errIpsecPermitClosed
	}
	if lease.QueueEpoch == 0 || lease.QueueEpoch != queueEpoch || lease.RequestID == 0 {
		return fmt.Errorf("ipsec: stale reinject lease")
	}
	return nil
}

func (s *ipsecSupervisor) allocateQueue(key ipsecQueueKey) (ipsecQueueHandle, error) {
	if s == nil || s.allocator == nil {
		return ipsecQueueHandle{}, errIpsecQueueExhausted
	}
	return s.allocator.allocate(key)
}

func (s *ipsecSupervisor) retireQueue(handle ipsecQueueHandle, listenerExited, destroyConfirmed bool) error {
	if s == nil || s.allocator == nil {
		return errIpsecQueueStale
	}
	return s.allocator.retire(handle, listenerExited, destroyConfirmed)
}

// supervisorTickOnce performs bounded maintenance: allocator quarantine ages
// exactly one full tick, then terminal records for a confirmed-destroyed queue
// are reclaimed. No listener lock or channel is held here.
func (s *ipsecSupervisor) supervisorTickOnce(now time.Time) {
	if s == nil {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	_ = now
	s.allocator.tick()
	s.terminalMu.Lock()
	for key := range s.terminal {
		if key.QueueNumber == 0 || key.QueueEpoch == 0 {
			continue
		}
		if s.allocator.released(ipsecQueueHandle{Number: key.QueueNumber, Epoch: key.QueueEpoch}) {
			delete(s.terminal, key)
		}
	}
	s.terminalMu.Unlock()
}
