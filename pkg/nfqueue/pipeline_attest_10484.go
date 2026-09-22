package nfqueue

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// D11ManifestCap bounds independent attestation evidence retained by one daemon.
const D11ManifestCap = 32

// D11ArmState is the one-shot lifecycle of an attestation run.
type D11ArmState uint8

const (
	D11Inactive D11ArmState = iota
	D11Arming
	D11Armed
	D11Draining
	D11Disarmed
)

func (s D11ArmState) String() string {
	switch s {
	case D11Arming:
		return "ARMING"
	case D11Armed:
		return "ARMED"
	case D11Draining:
		return "DRAINING"
	case D11Disarmed:
		return "DISARMED"
	default:
		return "INACTIVE"
	}
}

var (
	errD11ArmDisabled = errors.New("nfqueue: D11 attestation arm environment is disabled")
	errD11ArmActive   = errors.New("nfqueue: D11 attestation run is already active")
	errD11ArmShape    = errors.New("nfqueue: invalid D11 attestation arm shape")
)

// D11AttestationArmer owns the node-local one-shot selector. The announce
// callback is the daemon's authority publication hook; it runs before ARMED is
// made visible to the pipeline.
type D11AttestationArmer struct {
	mu          sync.Mutex
	nodeID      string
	state       D11ArmState
	runID       string
	permitEpoch uint64
	selector    [16]byte
	ledger      *D11AttestationLedger
	announce    func(runID string, permitEpoch uint64) error
	allow       func() bool
}

func NewD11AttestationArmer(nodeID string, ledger *D11AttestationLedger, announce func(string, uint64) error) *D11AttestationArmer {
	return &D11AttestationArmer{nodeID: nodeID, ledger: ledger, announce: announce}
}

// SetEnvironmentGate allows daemon wiring to cache the process-start arm bit;
// nil uses XPF_ATTEST_10484_ARM directly and is intentionally fail-closed.
func (a *D11AttestationArmer) SetEnvironmentGate(allow func() bool) {
	if a == nil {
		return
	}
	a.mu.Lock()
	a.allow = allow
	a.mu.Unlock()
}

func decodeD11Selector(runID, selectorHex string) ([16]byte, error) {
	var selector [16]byte
	if !strings.HasPrefix(runID, "attest-") || len(runID) != len("attest-")+32 {
		return selector, errD11ArmShape
	}
	nonce := strings.TrimPrefix(runID, "attest-")
	for _, c := range nonce {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return selector, errD11ArmShape
		}
	}
	if len(selectorHex) != 32 {
		return selector, errD11ArmShape
	}
	for _, c := range selectorHex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return selector, errD11ArmShape
		}
	}
	decoded, err := hex.DecodeString(selectorHex)
	if err != nil || len(decoded) != len(selector) {
		return selector, errD11ArmShape
	}
	copy(selector[:], decoded)
	return selector, nil
}

// Arm validates and publishes the exact run/epoch/selector tuple. A second
// arm, including a same-nonce re-arm after disarm, is refused.
func (a *D11AttestationArmer) Arm(runID string, permitEpoch uint64, selectorHex string) error {
	if a == nil {
		return errD11ArmShape
	}
	a.mu.Lock()
	if a.announce == nil {
		a.mu.Unlock()
		return errors.New("nfqueue: D11 authority wiring unavailable")
	}
	allow := a.allow
	if a.state != D11Inactive || permitEpoch == 0 {
		a.mu.Unlock()
		return errD11ArmActive
	}
	a.mu.Unlock()
	if allow == nil {
		allow = func() bool { return os.Getenv("XPF_ATTEST_10484_ARM") == "1" }
	}
	if !allow() {
		return errD11ArmDisabled
	}
	selector, err := decodeD11Selector(runID, selectorHex)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if a.state != D11Inactive || a.announce == nil {
		a.mu.Unlock()
		return errD11ArmActive
	}
	a.state = D11Arming
	a.mu.Unlock()

	err = a.announce(runID, permitEpoch)
	a.mu.Lock()
	ledger := a.ledger
	if err != nil {
		if a.state == D11Arming {
			a.state = D11Inactive
		}
		if ledger != nil {
			ledger.Begin(a.nodeID, runID, permitEpoch)
		}
		a.mu.Unlock()
		if ledger != nil {
			ledger.MarkVoid("announce failed")
		}
		return fmt.Errorf("nfqueue: D11 announce: %w", err)
	}
	if a.state != D11Arming {
		if ledger != nil {
			ledger.Begin(a.nodeID, runID, permitEpoch)
		}
		a.mu.Unlock()
		if ledger != nil {
			ledger.MarkVoid("arm interrupted")
		}
		return errors.New("nfqueue: D11 arm interrupted")
	}
	if ledger != nil {
		ledger.Begin(a.nodeID, runID, permitEpoch)
	}
	a.runID, a.permitEpoch, a.selector = runID, permitEpoch, selector
	a.state = D11Armed
	a.mu.Unlock()
	return nil
}

func (a *D11AttestationArmer) State() D11ArmState {
	if a == nil {
		return D11Inactive
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state
}

func (a *D11AttestationArmer) Status() D11AttestationArmStatus {
	if a == nil {
		return D11AttestationArmStatus{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return D11AttestationArmStatus{NodeID: a.nodeID, RunID: a.runID, PermitEpoch: a.permitEpoch, State: a.state.String(), MarkerHex: hex.EncodeToString(a.selector[:])}
}

func (a *D11AttestationArmer) Matches(payload []byte) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	armed := a.state == D11Armed
	selector := a.selector
	a.mu.Unlock()
	if !armed {
		return false
	}
	return d11MarkerMatches(payload, selector)
}

func (a *D11AttestationArmer) BeginDrain() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != D11Armed {
		return false
	}
	a.state = D11Draining
	return true
}

func (a *D11AttestationArmer) Disarm() bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != D11Draining {
		return false
	}
	a.state = D11Disarmed
	return true
}

func d11MarkerMatches(payload []byte, selector [16]byte) bool {
	if len(payload) < 20 || (payload[0]>>4) != 4 {
		return false
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || len(payload) < ihl+8+32 || payload[9] != 1 {
		return false
	}
	icmp := payload[ihl:]
	if (icmp[0] != 0 && icmp[0] != 8) || icmp[1] != 0 {
		return false
	}
	return string(icmp[8+16:8+32]) == string(selector[:])
}

// D11LedgerKey is the composite identity used for all cross-surface joins.
type D11LedgerKey struct {
	NodeID      string
	RequestID   uint64
	PermitEpoch uint64
	QueueEpoch  uint64
	QueueNumber uint16
}

// D11LedgerRecord is a stable, bounded diagnostic row. Digest bytes are copied
// rather than recomputed from a caller-provided attribution manifest.
type D11LedgerRecord struct {
	Key             D11LedgerKey
	Origin          CaptureOrigin
	FrameDigest     [32]byte
	AdmissionCode   string
	Completion      CompletionOutcome
	ResolveCount    uint64
	TerminalState   string
	LateAttempts    uint64
	Duplicate       bool
	EarlyCompletion *ReinjectCompletion
	ContractRefusal bool
}

type D11SelectionFailure struct {
	Origin      CaptureOrigin
	FrameDigest [32]byte
	Reason      string
}

type D11AttestationArmStatus struct {
	NodeID      string
	RunID       string
	PermitEpoch uint64
	State       string
	MarkerHex   string
}

type D11LedgerSnapshot struct {
	NodeID      string
	RunID       string
	PermitEpoch uint64
	SnapshotSeq uint64
	Finalized   bool
	Truncated   bool
	Records     []D11LedgerRecord
	Failures    []D11SelectionFailure
}

type D11AttestationLedger struct {
	mu          sync.Mutex
	failures    []D11SelectionFailure
	nodeID      string
	runID       string
	permitEpoch uint64
	snapshotSeq uint64
	finalized   bool
	truncated   bool
	records     map[D11LedgerKey]*D11LedgerRecord
	byRequest   map[uint64]D11LedgerKey
}

func NewD11AttestationLedger() *D11AttestationLedger {
	return &D11AttestationLedger{records: make(map[D11LedgerKey]*D11LedgerRecord), byRequest: make(map[uint64]D11LedgerKey)}
}

func (l *D11AttestationLedger) Begin(nodeID, runID string, permitEpoch uint64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nodeID, l.runID, l.permitEpoch = nodeID, runID, permitEpoch
	l.snapshotSeq++
	l.finalized, l.truncated = false, false
	l.records = make(map[D11LedgerKey]*D11LedgerRecord)
	l.byRequest = make(map[uint64]D11LedgerKey)
	l.failures = nil
}

func (l *D11AttestationLedger) RecordFailure(frame CaptureFrame, reason string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runID == "" || l.finalized {
		return
	}
	if len(l.failures) >= D11ManifestCap {
		l.truncated = true
		l.snapshotSeq++
		return
	}
	var digest [32]byte
	if frame.Packet != nil {
		digest = d11GoFrameDigest(frame.Packet.Payload(), ReinjectLease{}, frame.origin, l.runID)
	}
	l.failures = append(l.failures, D11SelectionFailure{
		Origin: frame.origin, FrameDigest: digest, Reason: reason,
	})
	l.snapshotSeq++
}

func (l *D11AttestationLedger) Reserve(frame CaptureFrame, lease ReinjectLease) (D11LedgerKey, error) {
	if l == nil || frame.Packet == nil {
		return D11LedgerKey{}, errors.New("nfqueue: nil D11 ledger or frame")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runID == "" || l.nodeID == "" || l.finalized {
		return D11LedgerKey{}, errors.New("nfqueue: D11 ledger is not armed")
	}
	if lease.PermitEpoch == 0 || lease.PermitEpoch != l.permitEpoch {
		return D11LedgerKey{}, errors.New("nfqueue: D11 lease authority epoch mismatch")
	}
	if l.records == nil {
		l.records = make(map[D11LedgerKey]*D11LedgerRecord)
		l.byRequest = make(map[uint64]D11LedgerKey)
	}
	if len(l.records) >= D11ManifestCap {
		l.truncated = true
		l.snapshotSeq++
		return D11LedgerKey{}, errors.New("nfqueue: D11 manifest cap exceeded")
	}
	if _, exists := l.byRequest[lease.RequestID]; exists {
		return D11LedgerKey{}, errors.New("nfqueue: duplicate D11 request id")
	}
	key := D11LedgerKey{NodeID: l.nodeID, RequestID: lease.RequestID, PermitEpoch: lease.PermitEpoch, QueueEpoch: lease.QueueEpoch, QueueNumber: lease.QueueNumber}
	if _, exists := l.records[key]; exists {
		return D11LedgerKey{}, errors.New("nfqueue: duplicate D11 ledger key")
	}
	record := &D11LedgerRecord{Key: key, Origin: frame.origin, FrameDigest: d11GoFrameDigest(frame.Packet.Payload(), lease, frame.origin, l.runID), AdmissionCode: "ADMISSION_PENDING", TerminalState: "ADMISSION_PENDING"}
	l.records[key] = record
	l.byRequest[lease.RequestID] = key
	l.snapshotSeq++
	return key, nil
}

func (l *D11AttestationLedger) UpdateAdmission(key D11LedgerKey, code string, contractRefusal bool) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record := l.records[key]
	if record == nil {
		return false
	}
	record.AdmissionCode, record.ContractRefusal = code, contractRefusal
	if code != "ADMIT_OK" {
		record.TerminalState = "Uncertain"
	}
	l.snapshotSeq++
	return true
}

func (l *D11AttestationLedger) RecordEarlyCompletion(key D11LedgerKey, completion ReinjectCompletion) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record := l.records[key]
	if record == nil {
		return false
	}
	if record.EarlyCompletion == nil {
		copyCompletion := completion
		record.EarlyCompletion = &copyCompletion
		l.snapshotSeq++
	}
	return true
}

func (l *D11AttestationLedger) RecordCompletion(key D11LedgerKey, completion ReinjectCompletion, terminal string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record := l.records[key]
	if record == nil {
		return false
	}
	record.Completion = completion.Outcome
	record.ResolveCount++
	if !record.Duplicate {
		record.TerminalState = terminal
	}
	l.snapshotSeq++
	return true
}

func (l *D11AttestationLedger) MarkDuplicate(key D11LedgerKey) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	record := l.records[key]
	if record == nil {
		return false
	}
	record.Duplicate = true
	record.TerminalState = "FAIL"
	l.snapshotSeq++
	return true
}

func (l *D11AttestationLedger) MarkLate(requestID uint64) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, ok := l.byRequest[requestID]
	if !ok || l.records[key] == nil {
		return false
	}
	l.records[key].LateAttempts++
	l.snapshotSeq++
	return true
}

func (l *D11AttestationLedger) MarkVoid(reason string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.finalized = true
	if reason != "" {
		l.snapshotSeq++
	}
}

func (l *D11AttestationLedger) Finalize() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.finalized = true
	l.snapshotSeq++
	l.mu.Unlock()
}

// FinalizeIfTerminal closes the retained run only when every selected record
// has a terminal disposition. It deliberately leaves the rows queryable.
func (l *D11AttestationLedger) FinalizeIfTerminal() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.finalized {
		return true
	}
	for _, record := range l.records {
		if record == nil || record.TerminalState == "" ||
			record.TerminalState == "ADMISSION_PENDING" {
			return false
		}
	}
	l.finalized = true
	l.snapshotSeq++
	return true
}

func (l *D11AttestationLedger) Snapshot() D11LedgerSnapshot {
	if l == nil {
		return D11LedgerSnapshot{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := D11LedgerSnapshot{NodeID: l.nodeID, RunID: l.runID, PermitEpoch: l.permitEpoch, SnapshotSeq: l.snapshotSeq, Finalized: l.finalized, Truncated: l.truncated, Records: make([]D11LedgerRecord, 0, len(l.records)), Failures: append([]D11SelectionFailure(nil), l.failures...)}
	for _, record := range l.records {
		copyRecord := *record
		if record.EarlyCompletion != nil {
			completion := *record.EarlyCompletion
			copyRecord.EarlyCompletion = &completion
		}
		out.Records = append(out.Records, copyRecord)
	}
	return out
}

func d11OriginWire(origin CaptureOrigin) (uint8, uint8) {
	family := uint8(2)
	if origin.Family == CaptureFamilyInet {
		family = 1
	}
	hook := uint8(2)
	if origin.Hook == CaptureHookForward {
		hook = 1
	}
	return family, hook
}

func d11GoFrameDigest(payload []byte, lease ReinjectLease, origin CaptureOrigin, runID string) [32]byte {
	h := sha256.New()
	h.Write([]byte("XPF-D11-FRAME/v1"))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], 11)
	h.Write(count[:])
	field := func(value []byte) {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		h.Write(length[:])
		h.Write(value)
	}
	field(payload)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], lease.RequestID)
	field(u64[:])
	binary.BigEndian.PutUint64(u64[:], lease.PermitEpoch)
	field(u64[:])
	binary.BigEndian.PutUint64(u64[:], lease.QueueEpoch)
	field(u64[:])
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], lease.QueueNumber)
	field(u16[:])
	family := byte(2)
	if origin.Family == CaptureFamilyInet {
		family = 1
	}
	field([]byte{family})
	hook := byte(2)
	if origin.Hook == CaptureHookForward {
		hook = 1
	}
	field([]byte{hook})
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], origin.OwnedIfindex)
	field(u32[:])
	field([]byte(origin.Owner))
	field([]byte(origin.STN))
	field([]byte(runID))
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func (p *CapturePipeline) dispatchAttestEligible(frames []CaptureFrame) {
	if p == nil || p.attestation == nil || p.attestation.Armer == nil || p.attestation.Armer.State() != D11Armed {
		p.submitEligible(frames)
		return
	}
	selected := make([]CaptureFrame, 0, len(frames))
	ordinary := make([]CaptureFrame, 0, len(frames))
	for _, frame := range frames {
		if frame.Packet != nil && p.attestation.Armer.Matches(frame.Packet.Payload()) {
			selected = append(selected, frame)
		} else {
			ordinary = append(ordinary, frame)
		}
	}
	if len(selected) != 0 {
		p.attestSubmit(selected)
	}
	if len(ordinary) != 0 {
		p.submitEligible(ordinary)
	}
}

type D11AttestationConfig struct {
	Armer            *D11AttestationArmer
	Ledger           *D11AttestationLedger
	OriginOwner      string
	OriginSTN        string
	OriginIfindex    uint32
	AuthorityCurrent func() bool
}

func (p *CapturePipeline) validateD11Frame(frame CaptureFrame) (ZoneEvaluation, error) {
	if frame.Packet == nil {
		return ZoneEvaluation{}, errors.New("nil packet")
	}
	if p.attestation != nil && p.attestation.AuthorityCurrent != nil && !p.attestation.AuthorityCurrent() {
		return ZoneEvaluation{}, errors.New("D11 authority override is no longer current")
	}
	if frame.origin.Family != CaptureFamilyInet ||
		(frame.origin.Hook != CaptureHookForward && frame.origin.Hook != CaptureHookInput) {
		return ZoneEvaluation{}, errors.New("unsupported family or hook")
	}
	if p.attestation != nil {
		if p.attestation.OriginOwner != "" && frame.origin.Owner != p.attestation.OriginOwner {
			return ZoneEvaluation{}, errors.New("origin owner mismatch")
		}
		if p.attestation.OriginSTN != "" && frame.origin.STN != p.attestation.OriginSTN {
			return ZoneEvaluation{}, errors.New("origin stn mismatch")
		}
		if p.attestation.OriginIfindex != 0 && frame.origin.OwnedIfindex != p.attestation.OriginIfindex {
			return ZoneEvaluation{}, errors.New("origin ifindex mismatch")
		}
	}
	if p.zoneEvaluator == nil || p.zoneSnapshot == nil {
		return ZoneEvaluation{}, errors.New("zone evaluator unavailable")
	}
	if !p.zoneSnapshot.Current() {
		return ZoneEvaluation{}, errors.New("zone snapshot stale")
	}
	if reason := validateCapturedGenerations(frame, frame.origin, p.zoneSnapshot); reason != ZoneReasonZoned {
		return ZoneEvaluation{}, fmt.Errorf("captured generation rejected: %s", zoneReasonWire(reason))
	}
	evaluation := p.zoneEvaluator.Evaluate(frame.origin, p.zoneSnapshot)
	if reason := ValidateZoneEvaluation(evaluation); reason != ZoneReasonZoned {
		return ZoneEvaluation{}, fmt.Errorf("zone evaluation rejected: %s", zoneReasonWire(reason))
	}
	if evaluation.Decision != ZonePass {
		return ZoneEvaluation{}, fmt.Errorf("zone evaluation denied: %s", zoneReasonWire(evaluation.Reason))
	}
	return evaluation, nil
}

func (p *CapturePipeline) attestSubmit(frames []CaptureFrame) {
	if p == nil || p.attestation == nil || p.attestation.Ledger == nil || p.submitter == nil {
		for _, frame := range frames {
			if p != nil && p.attestation != nil && p.attestation.Ledger != nil {
				p.attestation.Ledger.RecordFailure(frame, "D11 authority unavailable")
			}
			if p != nil {
				p.finishFrame(frame, VerdictDrop)
			}
		}
		return
	}
	p.submitGate.RLock()
	admitted := make([]AdjudicatedFrame, 0, len(frames))
	pending := make([]*pendingReinject, 0, len(frames))
	for _, frame := range frames {
		evaluation, err := p.validateD11Frame(frame)
		if err != nil {
			p.attestation.Ledger.RecordFailure(frame, err.Error())
			p.finishFrame(frame, VerdictDrop)
			continue
		}
		lease, err := p.lease(frame)
		if err != nil {
			p.attestation.Ledger.RecordFailure(frame, "lease: "+err.Error())
			p.finishFrame(frame, VerdictDrop)
			continue
		}
		p.mu.Lock()
		flow := p.flows[frame.FlowKey]
		if flow == nil || flow.pending != nil || len(flow.frames) == 0 || flow.frames[0].Packet != frame.Packet {
			p.mu.Unlock()
			p.attestation.Ledger.RecordFailure(frame, "flow is no longer pending")
			p.finishFrame(frame, VerdictDrop)
			continue
		}
		key, err := p.attestation.Ledger.Reserve(frame, lease)
		if err != nil {
			p.mu.Unlock()
			p.attestation.Ledger.RecordFailure(frame, "reserve: "+err.Error())
			p.finishFrame(frame, VerdictDrop)
			continue
		}
		item := &pendingReinject{frame: frame, lease: lease, admissionPending: true, ledger: p.attestation.Ledger, ledgerKey: key}
		flow.pending = item
		p.pending[lease.RequestID] = item
		p.stats.Adjudicated++
		p.mu.Unlock()
		admitted = append(admitted, AdjudicatedFrame{Frame: frame, Origin: frame.origin, Lease: lease, ZoneID: uint16(evaluation.ZoneID), IfID: evaluation.IfID})
		pending = append(pending, item)
	}
	if len(admitted) == 0 {
		p.submitGate.RUnlock()
		return
	}
	responses, submitErr := p.submitter.SubmitAdjudicated(admitted)
	var cancelItems []*pendingReinject
	if submitErr != nil {
		for _, item := range pending {
			if p.admissionFailedState(item, "TRANSPORT", submitErr) {
				cancelItems = append(cancelItems, item)
			}
		}
	} else {
		for i, item := range pending {
			if i >= len(responses) {
				if p.admissionFailedState(item, "TRANSPORT", errors.New("missing admission response")) {
					cancelItems = append(cancelItems, item)
				}
				continue
			}
			if failed := p.applyAdmission(item, responses[i]); failed != nil {
				cancelItems = append(cancelItems, failed)
			}
		}
	}
	p.submitGate.RUnlock()
	for _, item := range cancelItems {
		p.cancelUncertainLease(item.lease)
	}
}

func (p *CapturePipeline) admissionFailed(item *pendingReinject, code string, cause error) {
	if p.admissionFailedState(item, code, cause) {
		p.cancelUncertainLease(item.lease)
	}
}

func (p *CapturePipeline) admissionFailedState(item *pendingReinject, code string, cause error) bool {
	if p == nil || item == nil {
		return false
	}
	p.mu.Lock()
	if p.pending[item.lease.RequestID] != item {
		p.mu.Unlock()
		return false
	}
	delete(p.pending, item.lease.RequestID)
	if flow := p.flows[item.frame.FlowKey]; flow != nil && flow.pending == item {
		flow.pending = nil
	}
	early := item.earlyCompletion
	item.earlyCompletion = nil
	item.admissionPending = false
	p.stats.Uncertain++
	p.mu.Unlock()

	if item.ledger != nil {
		item.ledger.UpdateAdmission(item.ledgerKey, code, code == "CONTRACT")
		if early != nil {
			item.ledger.RecordCompletion(item.ledgerKey, ReinjectCompletion{
				RequestID: early.RequestID, PermitEpoch: early.PermitEpoch,
				QueueNumber: early.QueueNumber, QueueEpoch: early.QueueEpoch,
				Family: early.Family, Hook: early.Hook, OwnedIfindex: early.OwnedIfindex,
				Outcome: CompletionUncertain, Reason: "completion before admission",
			}, "Uncertain")
		}
	}
	if cause != nil {
		p.uncertain("D11 admission " + code + ": " + cause.Error())
	} else {
		p.uncertain("D11 admission " + code)
	}
	p.finishFrame(item.frame, VerdictDrop)
	p.retireFlow(item.frame.FlowKey)
	return true
}

func (p *CapturePipeline) applyAdmission(item *pendingReinject, admission ReinjectAdmission) *pendingReinject {
	if p == nil || item == nil {
		return nil
	}
	family, hook := d11OriginWire(item.frame.origin)
	if admission.RequestID != item.lease.RequestID ||
		admission.PermitEpoch != item.lease.PermitEpoch ||
		admission.QueueNumber != item.lease.QueueNumber ||
		admission.QueueEpoch != item.lease.QueueEpoch ||
		admission.Family != family ||
		admission.Hook != hook ||
		admission.OwnedIfindex != item.frame.origin.OwnedIfindex {
		if p.admissionFailedState(item, "CONTRACT", errors.New("admission identity mismatch")) {
			return item
		}
		return nil
	}
	if !admission.Admitted {
		p.mu.Lock()
		if p.pending[item.lease.RequestID] != item {
			p.mu.Unlock()
			return nil
		}
		delete(p.pending, item.lease.RequestID)
		if flow := p.flows[item.frame.FlowKey]; flow != nil && flow.pending == item {
			flow.pending = nil
		}
		early := item.earlyCompletion
		item.earlyCompletion = nil
		item.admissionPending = false
		p.stats.Refused++
		p.mu.Unlock()
		if item.ledger != nil {
			item.ledger.UpdateAdmission(item.ledgerKey, "REFUSED", false)
			if early != nil {
				item.ledger.RecordCompletion(item.ledgerKey, ReinjectCompletion{
					RequestID: early.RequestID, PermitEpoch: early.PermitEpoch,
					QueueNumber: early.QueueNumber, QueueEpoch: early.QueueEpoch,
					Family: early.Family, Hook: early.Hook, OwnedIfindex: early.OwnedIfindex,
					Outcome: CompletionUncertain, Reason: "completion before refusal",
				}, "FAIL")
			}
		}
		p.finishFrame(item.frame, VerdictDrop)
		return nil
	}
	if item.ledger != nil {
		item.ledger.UpdateAdmission(item.ledgerKey, "ADMIT_OK", false)
	}
	p.mu.Lock()
	if p.pending[item.lease.RequestID] != item {
		p.mu.Unlock()
		return nil
	}
	item.admissionPending = false
	early := item.earlyCompletion
	item.earlyCompletion = nil
	if early == nil {
		item.deadline = time.Now().Add(p.ackDeadline)
	}
	p.mu.Unlock()
	if early != nil {
		p.resolveCompletion(*early)
	}
	return nil
}
