package nfqueue

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// PipelinePhase is the receive-time capture disposition. Shadow ACCEPTs
// originals while collecting observation data; Enforcing submits owned,
// adjudicated frames to q0; Quarantine is DROP-only.
type PipelinePhase uint8

const (
	PipelineShadow PipelinePhase = iota
	PipelineEnforcing
	PipelineQuarantine
)

// Disposition is retained as a descriptive alias for callers that model the
// phase as a disposition.
type Disposition = PipelinePhase

const (
	DispositionShadow     = PipelineShadow
	DispositionEnforcing  = PipelineEnforcing
	DispositionQuarantine = PipelineQuarantine
)

// ReinjectLease is the authority tuple mirrored by the Rust q0 writer.
type ReinjectLease struct {
	PermitEpoch uint64 `json:"permit_epoch"`
	QueueNumber uint16 `json:"queue_number"`
	QueueEpoch  uint64 `json:"queue_epoch"`
	RequestID   uint64 `json:"request_id"`
}

// LeaseMinter allocates a nonzero monotonically increasing request ID and
// binds it to the current permit/queue epochs.
type LeaseMinter interface {
	MintLease(CaptureFrame) (ReinjectLease, error)
}

// AttestLeaseMinter binds a lease to the D11 authority run and epoch. D11
// selection refuses minters that do not implement this explicit contract.
type AttestLeaseMinter interface {
	MintLeaseForAttest(CaptureFrame, string, uint64) (ReinjectLease, error)
}

// LeaseMinterFunc adapts a function to LeaseMinter.
type LeaseMinterFunc func(CaptureFrame) (ReinjectLease, error)

func (f LeaseMinterFunc) MintLease(frame CaptureFrame) (ReinjectLease, error) {
	return f(frame)
}

// ReinjectQueueScope identifies a queue number together with its epoch. Queue
// number is part of cancellation identity; an epoch alone is not sufficient
// when numbers are recycled across generations.
type ReinjectQueueScope struct {
	QueueNumber uint16
	QueueEpoch  uint64
}

// ReinjectAdmission is the Rust admission result for one submitted frame.
type ReinjectAdmission struct {
	RequestID    uint64
	PermitEpoch  uint64
	QueueNumber  uint16
	QueueEpoch   uint64
	Family       uint8
	Hook         uint8
	OwnedIfindex uint32
	Admitted     bool
	Reason       string
	ReasonCode   uint8
}

// ReinjectCompletion is the terminal q0 result. Epoch and queue-number fields
// are echoed by Rust and must match the complete pending lease tuple.
type ReinjectCompletion struct {
	RequestID    uint64
	PermitEpoch  uint64
	QueueNumber  uint16
	QueueEpoch   uint64
	Family       uint8
	Hook         uint8
	OwnedIfindex uint32
	Outcome      CompletionOutcome
	Reason       string
	BytesWritten uint32
}
type CompletionOutcome string

const (
	CompletionWritten       CompletionOutcome = "written"
	CompletionStale         CompletionOutcome = "stale"
	CompletionCancelled     CompletionOutcome = "cancelled"
	CompletionRefused       CompletionOutcome = "refused"
	CompletionUncertain     CompletionOutcome = "uncertain"
	CompletionFenced        CompletionOutcome = "fenced"
	CompletionDenied        CompletionOutcome = "denied"
	CompletionAccepted      CompletionOutcome = "accepted"
	CompletionWouldReinject CompletionOutcome = "would_reinject"
	// Rust code 10 is a worker policy would-permit. The terminal completion
	// maps that outcome to E28/byte 52 and records suppression; routine V1
	// pre-submit suppression is deny-only and emits no E28 event.
	CompletionWouldPermit CompletionOutcome = "would_permit"
)

// ReinjectSubmitter is the data-plane handoff seam. The concrete two-socket
// binary client is intentionally separate from the JSON control socket and is
// added after the Rust ACK contract is reviewed; tests and the actor can use a
// fake implementation here.
type ReinjectSubmitter interface {
	SubmitAdjudicated([]AdjudicatedFrame) ([]ReinjectAdmission, error)
	DrainReinjectCompletions(max uint32) ([]ReinjectCompletion, error)
	CancelReinject(requestIDs []uint64, permitEpoch uint64, scopes []ReinjectQueueScope) ([]uint64, error)
}

// PacketVerdictSink is the terminal NFQUEUE sink adapter. The default sink
// calls Packet.Verdict; the daemon supplies its supervisor commit adapter.
type PacketVerdictSink interface {
	Verdict(*Packet, Verdict) error
}

type packetVerdictSinkFunc func(*Packet, Verdict) error

func (f packetVerdictSinkFunc) Verdict(packet *Packet, verdict Verdict) error {
	return f(packet, verdict)
}

type CaptureFrame struct {
	Packet       *Packet
	FlowKey      string
	FragmentKey  *FragmentKey
	Fragment     *Fragment
	InnerOverlap bool
	// SnapshotGeneration is the immutable capture authority. ConfigGeneration
	// and FIBGeneration are the accepted packet/config authority; they may
	// advance independently after a same-key snapshot apply.
	// All four identities must be authoritative before enforcement proceeds.
	Generation         uint64 // legacy queue/capture generation alias
	SnapshotGeneration uint64
	ConfigGeneration   uint64
	FIBGeneration      uint32
	QueueNumber        uint16
	QueueEpoch         uint64

	origin    CaptureOrigin
	originSet bool
	phase     PipelinePhase
}

// Origin returns the structural queue provenance attached by Enqueue.
func (f CaptureFrame) Origin() CaptureOrigin { return f.origin }

// AdjudicatedFrame carries one held original and its structural origin.
type AdjudicatedFrame struct {
	Frame  CaptureFrame
	Origin CaptureOrigin
	Lease  ReinjectLease
	ZoneID uint16
	IfID   uint32
}

// CapturePipelineConfig controls all bounded resources and the P-MECH
// pre-gate. The enforcing phase is fail-closed when the evaluator/snapshot
// pair is absent; no frame can silently become a permit.
type CapturePipelineConfig struct {
	Queues           []*Queue
	Registry         *OriginRegistry
	LeaseMinter      LeaseMinter
	Submitter        ReinjectSubmitter
	Sink             PacketVerdictSink
	Phase            PipelinePhase
	HandoffCap       int
	BatchCap         int
	AckDeadline      time.Duration
	FragmentSlots    int
	FragmentPieces   int
	FragmentDeadline time.Duration
	OnUncertain      func(reason string)
	ZoneEvaluator    ZoneEvaluator
	ZoneSnapshot     ZoneSnapshotRef
	Attestation      *D11AttestationConfig
	DenyEvents       DenyEventSink
}

var (
	ErrHandoffFull     = errors.New("nfqueue: capture handoff capacity exceeded")
	ErrPipelineClosed  = errors.New("nfqueue: capture pipeline closed")
	ErrNoSubmitter     = errors.New("nfqueue: adjudication submitter unavailable")
	ErrNoLeaseMinter   = errors.New("nfqueue: adjudication lease minter unavailable")
	ErrNoZoneEvaluator = errors.New("nfqueue: zone evaluator unavailable")
)

// PipelineStats is a monotonic snapshot of fail-closed pipeline accounting.
type PipelineStats struct {
	HandoffRefusals        uint64
	ProvenanceMismatches   uint64
	ShadowDivergences      uint64
	ShadowUnavailable      uint64
	ZoneGateDrops          uint64
	ZoneGateUnavailable    uint64
	ZoneGateStale          uint64
	ZoneDivergences        uint64
	V1PermitSuppressed     uint64
	ClassificationErrors   uint64
	FragmentMetadataErrors uint64
	FragmentLate           uint64
	VersionSkews           uint64
	EventDecodeErrors      uint64
	InputAcceptErrors      uint64
	Dropped                uint64
	Accepted               uint64
	Submitted              uint64
	AdmissionsRefused      uint64
	Stale                  uint64
	Cancelled              uint64
	Refused                uint64
	Uncertain              uint64
	Written                uint64
	Timeouts               uint64
	LateCompletions        uint64
	FlowRetires            uint64
	Retries                uint64
	L2Unsupported          uint64
	OverlapRefusals        uint64
	FragmentDrops          uint64
	// #10478 Phase 2a witness: drained from the bounded handoff into pipeline
	// accounting (all receive-time dispositions).
	Consumed uint64
	// #10478 Phase 2a witness: entered q0 adjudication (lease minted).
	Adjudicated uint64
	// #10478 Phase 2a witness: terminal q0 Written completions (equals Written).
	Reinjected uint64
	// #10484 D11 terminal WouldPermit accounting; routine pre-submit
	// suppression remains V1PermitSuppressed and is intentionally separate.
	D11Suppressed uint64
	D11Deny52     uint64
}

type pipelineStats struct {
	PipelineStats
}

type pendingReinject struct {
	frame            CaptureFrame
	lease            ReinjectLease
	deadline         time.Time
	admissionPending bool
	earlyCompletion  *ReinjectCompletion
	duplicateEarly   bool
	ledger           *D11AttestationLedger
	ledgerKey        D11LedgerKey
}

type flowState struct {
	frames  []CaptureFrame
	pending *pendingReinject
	retired bool
}

// CapturePipeline is a bounded capture-to-verdict actor. Enqueue never waits
// for workers; it either hands off into the bounded channel or records a
// fail-closed DROP. Flow queues are independent, so one unresolved completion
// cannot block unrelated flows.
type CapturePipeline struct {
	mu               sync.Mutex
	drainMu          sync.Mutex
	submitGate       sync.RWMutex
	phase            PipelinePhase
	registry         *OriginRegistry
	leaseMinter      LeaseMinter
	submitter        ReinjectSubmitter
	attestation      *D11AttestationConfig
	sink             PacketVerdictSink
	onUncertain      func(string)
	zoneEvaluator    ZoneEvaluator
	zoneSnapshot     ZoneSnapshotRef
	denyEvents       DenyEventSink
	handoff          chan CaptureFrame
	batchCap         int
	ackDeadline      time.Duration
	fragmentDeadline time.Duration
	fragPool         *FragPool
	fragHolds        map[FragmentKey][]CaptureFrame
	fragTimes        map[FragmentKey]time.Time
	flows            map[string]*flowState
	pending          map[uint64]*pendingReinject
	closed           bool
	revoked          bool
	// d11RevokedPermitEpoch fences only the attestation selector after its
	// scoped rollback cancellation; ordinary capture remains reusable.
	d11RevokedPermitEpoch uint64
	stats                 pipelineStats
}

// NewCapturePipeline constructs a pipeline with explicit bounded resources.
func NewCapturePipeline(cfg CapturePipelineConfig) (*CapturePipeline, error) {
	if cfg.Registry == nil {
		return nil, errors.New("nfqueue: capture pipeline requires origin registry")
	}
	if cfg.HandoffCap <= 0 {
		cfg.HandoffCap = 16384
	}
	if cfg.BatchCap <= 0 || cfg.BatchCap > 64 {
		if cfg.BatchCap <= 0 {
			cfg.BatchCap = 64
		} else {
			return nil, errors.New("nfqueue: batch cap must be in 1..64")
		}
	}
	if cfg.AckDeadline <= 0 {
		cfg.AckDeadline = 5 * time.Millisecond
	}
	if cfg.FragmentSlots <= 0 {
		cfg.FragmentSlots = 128
	}
	if cfg.FragmentPieces <= 0 {
		cfg.FragmentPieces = 128
	}
	if cfg.FragmentDeadline <= 0 {
		cfg.FragmentDeadline = 2 * time.Second
	}
	fragPool, err := NewFragPool(cfg.FragmentPieces, cfg.FragmentSlots)
	if err != nil {
		return nil, fmt.Errorf("nfqueue: fragment slots: %w", err)
	}
	if cfg.Sink == nil {
		cfg.Sink = packetVerdictSinkFunc(func(packet *Packet, verdict Verdict) error {
			if packet == nil {
				return errors.New("nfqueue: nil packet")
			}
			return packet.Verdict(verdict)
		})
	}
	return &CapturePipeline{
		phase: cfg.Phase, registry: cfg.Registry, leaseMinter: cfg.LeaseMinter,
		submitter: cfg.Submitter, sink: cfg.Sink, onUncertain: cfg.OnUncertain,
		attestation:   cfg.Attestation,
		zoneEvaluator: cfg.ZoneEvaluator, zoneSnapshot: cfg.ZoneSnapshot,
		denyEvents: cfg.DenyEvents,
		handoff:    make(chan CaptureFrame, cfg.HandoffCap), batchCap: cfg.BatchCap,
		ackDeadline: cfg.AckDeadline, fragmentDeadline: cfg.FragmentDeadline, fragPool: fragPool,
		fragHolds: make(map[FragmentKey][]CaptureFrame), fragTimes: make(map[FragmentKey]time.Time),
		flows: make(map[string]*flowState), pending: make(map[uint64]*pendingReinject),
	}, nil
}

func (p *CapturePipeline) EnterQuarantine() error {
	return p.Cancel(0, 0, 0)
}

func (p *CapturePipeline) Phase() PipelinePhase {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.phase
}

// Enqueue is try-or-drop. Every non-nil received frame is counted as consumed;
// provenance/phase/handoff dispositions then explain where it terminated.
func (p *CapturePipeline) Enqueue(frame CaptureFrame) error {
	if p == nil || frame.Packet == nil {
		return errors.New("nfqueue: nil capture frame")
	}
	p.mu.Lock()
	p.stats.Consumed++
	p.mu.Unlock()
	if err := ValidateProvenance(frame.Packet, p.registry); err != nil {
		p.mu.Lock()
		p.stats.ProvenanceMismatches++
		p.mu.Unlock()
		p.terminal(frame.Packet, VerdictDrop)
		return err
	}
	origin, ok := p.registry.Lookup(frame.Packet.QueueID())
	if !ok {
		err := &ProvenanceError{Queue: frame.Packet.QueueID(), Reason: "queue is not registered"}
		p.mu.Lock()
		p.stats.ProvenanceMismatches++
		p.mu.Unlock()
		p.terminal(frame.Packet, VerdictDrop)
		return err
	}
	if frame.originSet && frame.origin != origin {
		err := &ProvenanceError{Queue: frame.Packet.QueueID(), Expected: origin, Got: frame.origin, Field: "origin", Reason: "caller provenance conflicts with registry"}
		p.mu.Lock()
		p.stats.ProvenanceMismatches++
		p.mu.Unlock()
		p.terminal(frame.Packet, VerdictDrop)
		return err
	}
	frame.origin = origin
	frame.originSet = true
	p.mu.Lock()
	frame.phase = p.phase
	if p.closed || p.revoked {
		p.mu.Unlock()
		p.terminal(frame.Packet, VerdictDrop)
		return ErrPipelineClosed
	}
	select {
	case p.handoff <- frame:
		p.mu.Unlock()
		return nil
	default:
		p.stats.HandoffRefusals++
		p.mu.Unlock()
		p.terminal(frame.Packet, VerdictDrop)
		return ErrHandoffFull
	}
}

// Drain transfers up to max rows from the bounded handoff through the
// receive-time phase/FIFO/fragment path. It returns the number consumed.
func (p *CapturePipeline) Drain(max int) int {
	if p == nil || max <= 0 {
		return 0
	}
	p.drainMu.Lock()
	defer p.drainMu.Unlock()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0
	}
	frames := make([]CaptureFrame, 0, max)
	for len(frames) < max {
		select {
		case frame := <-p.handoff:
			frames = append(frames, frame)
		default:
			p.mu.Unlock()
			return p.consumeFrames(frames)
		}
	}
	p.mu.Unlock()
	return p.consumeFrames(frames)
}
func (p *CapturePipeline) consumeFrames(frames []CaptureFrame) int {
	if len(frames) == 0 {
		return 0
	}
	p.mu.Lock()
	var drops []CaptureFrame
	for _, frame := range frames {
		if frame.phase == PipelineQuarantine {
			drops = append(drops, frame)
			continue
		}
		drops = append(drops, p.enqueueFlowLocked(frame)...)
	}
	eligible := p.eligibleLocked()
	p.mu.Unlock()
	for _, frame := range drops {
		if frame.phase == PipelineShadow {
			p.mu.Lock()
			p.stats.ShadowDivergences++
			p.mu.Unlock()
			p.finishFrame(frame, VerdictAccept)
		} else {
			p.finishFrame(frame, VerdictDrop)
		}
	}
	for len(eligible) != 0 {
		var shadow, enforcing []CaptureFrame
		for _, frame := range eligible {
			switch frame.phase {
			case PipelineEnforcing:
				enforcing = append(enforcing, frame)
			default:
				shadow = append(shadow, frame)
			}
		}
		for _, frame := range shadow {
			p.evaluateShadowFrame(frame)
			p.finishFrame(frame, VerdictAccept)
		}
		if len(enforcing) != 0 {
			p.dispatchAttestEligible(enforcing)
		}
		p.mu.Lock()
		eligible = p.eligibleLocked()
		p.mu.Unlock()
	}
	return len(frames)
}

func (p *CapturePipeline) enqueueFlowLocked(frame CaptureFrame) []CaptureFrame {
	flowKey := frame.FlowKey
	if flowKey == "" {
		flowKey = fmt.Sprintf("queue:%d/packet:%d", frame.Packet.QueueID(), frame.Packet.id)
		frame.FlowKey = flowKey
	}
	flow := p.flows[flowKey]
	if flow == nil {
		flow = &flowState{}
		p.flows[flowKey] = flow
	}
	if flow.retired {
		p.stats.FlowRetires++
		return []CaptureFrame{frame}
	}
	if frame.FragmentKey != nil && frame.Fragment != nil {
		fragKey := *frame.FragmentKey
		p.fragHolds[fragKey] = append(p.fragHolds[fragKey], frame)
		if _, exists := p.fragTimes[fragKey]; !exists {
			p.fragTimes[fragKey] = time.Now()
		}
		before := p.fragPool.Stats().DuplicateDrops
		complete, err := p.fragPool.insertAt(fragKey, *frame.Fragment, p.fragTimes[fragKey])
		after := p.fragPool.Stats().DuplicateDrops
		duplicate := after > before
		var drops []CaptureFrame
		if duplicate {
			holds := p.fragHolds[fragKey]
			holds = holds[:len(holds)-1]
			if len(holds) == 0 {
				delete(p.fragHolds, fragKey)
			} else {
				p.fragHolds[fragKey] = holds
			}
			drops = append(drops, frame)
		}
		if err != nil {
			holds := append([]CaptureFrame(nil), p.fragHolds[fragKey]...)
			delete(p.fragHolds, fragKey)
			delete(p.fragTimes, fragKey)
			p.stats.FragmentDrops++
			drops = append(drops, holds...)
			return drops
		}
		if !complete {
			return drops
		}
		holds := p.fragHolds[fragKey]
		delete(p.fragHolds, fragKey)
		delete(p.fragTimes, fragKey)
		flow.frames = append(flow.frames, holds...)
		return drops
	}
	flow.frames = append(flow.frames, frame)
	return nil
}

func (p *CapturePipeline) eligibleLocked() []CaptureFrame {
	owners := make(map[string][]CaptureFrame)
	for _, flow := range p.flows {
		if flow.retired || flow.pending != nil || len(flow.frames) == 0 {
			continue
		}
		frame := flow.frames[0]
		owners[frame.origin.Owner] = append(owners[frame.origin.Owner], frame)
	}
	var frames []CaptureFrame
	for _, batch := range owners {
		if len(batch) > p.batchCap {
			batch = batch[:p.batchCap]
		}
		frames = append(frames, batch...)
	}
	return frames
}

// PartitionOwnerBatches partitions a drained batch by physical dispatch owner.
// A mixed-owner input therefore cannot be sent to one worker.
func PartitionOwnerBatches(frames []CaptureFrame) map[string][]CaptureFrame {
	out := make(map[string][]CaptureFrame)
	for _, frame := range frames {
		out[frame.origin.Owner] = append(out[frame.origin.Owner], frame)
	}
	return out
}

// DispatchWorkers returns deterministic owner identities for evidence/tests.
func DispatchWorkers(parts map[string][]CaptureFrame) []string {
	owners := make([]string, 0, len(parts))
	for owner, frames := range parts {
		if len(frames) != 0 {
			owners = append(owners, owner)
		}
	}
	sort.Strings(owners)
	return owners
}
func (p *CapturePipeline) emitDeny(frame CaptureFrame, reason IpsecInnerReason) bool {
	if p == nil || p.denyEvents == nil || !reason.Valid() {
		return false
	}
	queueID := uint16(0)
	if frame.Packet != nil {
		queueID = frame.Packet.QueueID()
	}
	return p.denyEvents.EmitIpsecInnerDeny(IpsecInnerDeny{
		Reason: reason, Origin: frame.origin, OriginSet: frame.originSet,
		QueueID: queueID, Tunnel: frame.origin.STN,
		Generation: frame.Generation,
	})
}

// emitD11Deny records a reason-52 denial only after the configured sink has
// successfully delivered its operator-visible event.
func (p *CapturePipeline) emitD11Deny(frame CaptureFrame, reason IpsecInnerReason) bool {
	delivered := p.emitDeny(frame, reason)
	if delivered && reason == ReasonEvaluatorUnavailable {
		p.mu.Lock()
		p.stats.D11Deny52++
		p.mu.Unlock()
	}
	return delivered
}

func zoneReasonWire(reason ZoneReason) IpsecInnerReason {
	switch reason {
	case ZoneReasonUnzoned:
		return ReasonZoneUnzoned
	case ZoneReasonAmbiguous:
		return ReasonZoneAmbiguous
	case ZoneReasonStaleGeneration:
		return ReasonStaleGeneration
	case ZoneReasonUnknownGeneration:
		return ReasonMissingGeneration
	case ZoneReasonVersionSkew:
		return ReasonVersionSkew
	case ZoneReasonEvaluatorUnavailable:
		return ReasonEvaluatorUnavailable
	default:
		return ReasonIfIDUnderivable
	}
}

func (p *CapturePipeline) evaluateShadowFrame(frame CaptureFrame) {
	if p == nil || p.zoneEvaluator == nil || p.zoneSnapshot == nil || !p.zoneSnapshot.Current() {
		if p != nil {
			p.mu.Lock()
			p.stats.ShadowUnavailable++
			p.mu.Unlock()
		}
		return
	}
	if reason := validateCapturedGenerations(frame, frame.origin, p.zoneSnapshot); reason != ZoneReasonZoned {
		p.mu.Lock()
		p.stats.ShadowUnavailable++
		p.mu.Unlock()
		return
	}
	evaluation := p.zoneEvaluator.Evaluate(frame.origin, p.zoneSnapshot)
	if ValidateZoneEvaluation(evaluation) == ZoneReasonVersionSkew {
		p.mu.Lock()
		p.stats.ShadowUnavailable++
		p.mu.Unlock()
		return
	}
	if evaluation.Decision == ZoneDrop {
		p.mu.Lock()
		p.stats.ShadowDivergences++
		p.mu.Unlock()
	}
}

func (p *CapturePipeline) submitEligible(frames []CaptureFrame) {
	if len(frames) == 0 {
		return
	}
	parts := PartitionOwnerBatches(frames)
	owners := DispatchWorkers(parts)
	for _, owner := range owners {
		batch := parts[owner]
		if len(batch) > p.batchCap {
			batch = batch[:p.batchCap]
		}
		for _, frame := range batch {
			if frame.origin.Family != CaptureFamilyInet ||
				(frame.origin.Hook != CaptureHookForward && frame.origin.Hook != CaptureHookInput) {
				p.mu.Lock()
				p.stats.L2Unsupported++
				p.mu.Unlock()
				p.emitDeny(frame, ReasonUnsupportedHook)
				p.finishFrame(frame, VerdictDrop)
				continue
			}
			if p.zoneEvaluator == nil || p.zoneSnapshot == nil {
				p.mu.Lock()
				p.stats.ZoneGateUnavailable++
				p.stats.ZoneGateDrops++
				p.mu.Unlock()
				p.emitDeny(frame, ReasonEvaluatorUnavailable)
				p.finishFrame(frame, VerdictDrop)
				continue
			}
			if !p.zoneSnapshot.Current() {
				p.mu.Lock()
				p.stats.ZoneGateStale++
				p.stats.ZoneGateDrops++
				p.mu.Unlock()
				p.emitDeny(frame, ReasonStaleGeneration)
				p.finishFrame(frame, VerdictDrop)
				continue
			}
			if generationReason := validateCapturedGenerations(frame, frame.origin, p.zoneSnapshot); generationReason != ZoneReasonZoned {
				p.mu.Lock()
				p.stats.ZoneGateDrops++
				if generationReason == ZoneReasonStaleGeneration {
					p.stats.ZoneGateStale++
				} else {
					p.stats.ZoneGateUnavailable++
				}
				p.mu.Unlock()
				p.emitDeny(frame, zoneReasonWire(generationReason))
				p.finishFrame(frame, VerdictDrop)
				continue
			}
			evaluation := p.zoneEvaluator.Evaluate(frame.origin, p.zoneSnapshot)
			reason := ValidateZoneEvaluation(evaluation)
			if reason == ZoneReasonVersionSkew {
				p.mu.Lock()
				p.stats.VersionSkews++
				p.stats.ZoneGateDrops++
				p.mu.Unlock()
				p.emitDeny(frame, ReasonVersionSkew)
				p.finishFrame(frame, VerdictDrop)
				continue
			}
			if evaluation.Decision != ZonePass {
				p.mu.Lock()
				p.stats.ZoneGateDrops++
				if reason == ZoneReasonStaleGeneration {
					p.stats.ZoneGateStale++
				}
				p.mu.Unlock()
				p.emitDeny(frame, zoneReasonWire(reason))
				p.finishFrame(frame, VerdictDrop)
				continue
			}
			// V1 stays pre-submit deny-only until the Rust D11 worker/verdict
			// join is wired into the reinject server. Sending flags=0 here
			// would reach the legacy delegated writer without S9 adjudication.
			p.mu.Lock()
			p.stats.V1PermitSuppressed++
			p.mu.Unlock()
			p.finishFrame(frame, VerdictDrop)
		}
	}
}

func (p *CapturePipeline) lease(frame CaptureFrame) (ReinjectLease, error) {
	if p.leaseMinter == nil {
		return ReinjectLease{}, ErrNoLeaseMinter
	}
	lease, err := p.leaseMinter.MintLease(frame)
	if err != nil {
		return ReinjectLease{}, err
	}
	if lease.RequestID == 0 || lease.PermitEpoch == 0 || lease.QueueNumber == 0 || lease.QueueEpoch == 0 {
		return ReinjectLease{}, errors.New("nfqueue: invalid reinject lease")
	}
	if lease.QueueNumber != frame.Packet.QueueID() {
		return ReinjectLease{}, errors.New("nfqueue: lease queue number mismatch")
	}
	return lease, nil
}
func (p *CapturePipeline) uncertain(reason string) {
	if p == nil || p.onUncertain == nil {
		return
	}
	p.onUncertain(reason)
}

// cancelUncertainLease withdraws an admission whose positive response echoed
// the wrong lease/origin. Rust may already have accepted and started writing
// that request, so this is not an ordinary refusal: cancel by request ID and
// the complete queue-number/epoch scope before terminalizing the original.
func (p *CapturePipeline) cancelUncertainLease(lease ReinjectLease) {
	if p == nil || p.submitter == nil {
		return
	}
	p.submitGate.Lock()
	_, err := p.submitter.CancelReinject(
		[]uint64{lease.RequestID},
		0,
		[]ReinjectQueueScope{{QueueNumber: lease.QueueNumber, QueueEpoch: lease.QueueEpoch}},
	)
	p.submitGate.Unlock()
	if err != nil {
		p.uncertain("uncertain admission cancellation")
	}
}
func (p *CapturePipeline) resolveRefusal(frame CaptureFrame, reason error) {
	p.mu.Lock()
	p.stats.Refused++
	p.mu.Unlock()
	p.finishFrame(frame, VerdictDrop)
	_ = reason
}

func (p *CapturePipeline) resolveUncertain(frame CaptureFrame, requestID uint64) {
	p.mu.Lock()
	p.stats.Uncertain++
	delete(p.pending, requestID)
	p.mu.Unlock()
	p.uncertain("uncertain reinject result")
	p.finishFrame(frame, VerdictDrop)
}

func (p *CapturePipeline) disposeImmediate(phase PipelinePhase, frame CaptureFrame) {
	verdict := VerdictDrop
	if phase == PipelineShadow {
		verdict = VerdictAccept
	}
	p.finishFrame(frame, verdict)
}

// finishFrame reserves terminality in the pipeline state before invoking the
// sink. A sink error is therefore terminal/uncertain and cannot leave a
// replayable flow head.
func (p *CapturePipeline) finishFrame(frame CaptureFrame, verdict Verdict) {
	if frame.Packet == nil {
		return
	}
	p.mu.Lock()
	flowKey := frame.FlowKey
	if flow := p.flows[flowKey]; flow != nil && len(flow.frames) > 0 && flow.frames[0].Packet == frame.Packet {
		flow.frames = flow.frames[1:]
		if len(flow.frames) == 0 && flow.pending == nil {
			delete(p.flows, flowKey)
		}
	}
	p.mu.Unlock()
	err := p.terminal(frame.Packet, verdict)
	if err != nil {
		p.mu.Lock()
		p.stats.Uncertain++
		p.mu.Unlock()
		p.uncertain("terminal sink error")
		p.retireFlow(flowKey)
		return
	}
	p.mu.Lock()
	if verdict == VerdictAccept {
		p.stats.Accepted++
	} else {
		p.stats.Dropped++
	}
	p.mu.Unlock()
}

func (p *CapturePipeline) terminal(packet *Packet, verdict Verdict) error {
	if p == nil || p.sink == nil {
		return errors.New("nfqueue: nil terminal sink")
	}
	return p.sink.Verdict(packet, verdict)
}

// Poll drains terminal completions and resolves expired requests. It should be
// called on a cadence no slower than 1ms. Completion/timeout resolution is
// terminal: no late completion can ACCEPT and no request is retried.
func (p *CapturePipeline) Poll(now time.Time) int {
	if p == nil {
		return 0
	}
	if now.IsZero() {
		now = time.Now()
	}
	resolved := 0
	if p.submitter != nil {
		completions, err := p.submitter.DrainReinjectCompletions(64)
		if err != nil {
			resolved += p.failPending("completion drain error")
		} else {
			for _, completion := range completions {
				if p.resolveCompletion(completion) {
					resolved++
				}
			}
		}
	}
	var expired []*pendingReinject
	p.mu.Lock()
	for id, pending := range p.pending {
		if pending.admissionPending || pending.deadline.IsZero() {
			continue
		}
		if !now.Before(pending.deadline) {
			expired = append(expired, pending)
			delete(p.pending, id)
		}
	}
	p.mu.Unlock()
	if len(expired) > 0 {
		p.uncertain("ack timeout")
	}
	for _, pending := range expired {
		p.mu.Lock()
		p.stats.Timeouts++
		p.stats.Uncertain++
		p.stats.FlowRetires++
		p.mu.Unlock()
		if pending.ledger != nil {
			pending.ledger.RecordCompletion(pending.ledgerKey, ReinjectCompletion{
				RequestID: pending.lease.RequestID, PermitEpoch: pending.lease.PermitEpoch,
				QueueNumber: pending.lease.QueueNumber, QueueEpoch: pending.lease.QueueEpoch,
				Outcome: CompletionUncertain, Reason: "ack timeout",
			}, "Uncertain")
		}
		p.finishFrame(pending.frame, VerdictDrop)
		p.retireFlow(pending.frame.FlowKey)
		resolved++
	}
	resolved += p.expireFragments(now)
	return resolved
}
func (p *CapturePipeline) expireFragments(now time.Time) int {
	cutoff := now.Add(-p.fragmentDeadline)
	var expired []CaptureFrame
	p.mu.Lock()
	if p.fragPool != nil {
		p.fragPool.Expire(cutoff)
	}
	for key, started := range p.fragTimes {
		if started.Before(cutoff) {
			expired = append(expired, p.fragHolds[key]...)
			delete(p.fragHolds, key)
			delete(p.fragTimes, key)
		}
	}
	p.stats.FragmentDrops += uint64(len(expired))
	p.mu.Unlock()
	for _, frame := range expired {
		if frame.phase == PipelineShadow {
			p.mu.Lock()
			p.stats.ShadowDivergences++
			p.mu.Unlock()
			p.finishFrame(frame, VerdictAccept)
		} else {
			p.finishFrame(frame, VerdictDrop)
		}
	}
	return len(expired)
}

func (p *CapturePipeline) failPending(reason string) int {
	p.mu.Lock()
	pending := make([]*pendingReinject, 0, len(p.pending))
	for id, item := range p.pending {
		pending = append(pending, item)
		delete(p.pending, id)
		if flow := p.flows[item.frame.FlowKey]; flow != nil {
			flow.pending = nil
		}
		p.stats.Uncertain++
	}
	p.mu.Unlock()
	if len(pending) == 0 {
		return 0
	}
	p.uncertain(reason)
	for _, item := range pending {
		if item.ledger != nil {
			item.ledger.RecordCompletion(item.ledgerKey, ReinjectCompletion{
				RequestID: item.lease.RequestID, PermitEpoch: item.lease.PermitEpoch,
				QueueNumber: item.lease.QueueNumber, QueueEpoch: item.lease.QueueEpoch,
				Outcome: CompletionUncertain, Reason: reason,
			}, "Uncertain")
		}
		p.finishFrame(item.frame, VerdictDrop)
		p.retireFlow(item.frame.FlowKey)
	}
	return len(pending)
}

func (p *CapturePipeline) resolveCompletion(completion ReinjectCompletion) bool {
	p.mu.Lock()
	pending := p.pending[completion.RequestID]
	if pending == nil {
		p.stats.LateCompletions++
		ledger := (*D11AttestationLedger)(nil)
		if p.attestation != nil {
			ledger = p.attestation.Ledger
		}
		p.mu.Unlock()
		if ledger != nil {
			ledger.MarkLate(completion.RequestID)
		}
		return false
	}
	if pending.admissionPending {
		ledger := pending.ledger
		if pending.earlyCompletion == nil {
			copyCompletion := completion
			pending.earlyCompletion = &copyCompletion
			p.mu.Unlock()
			if ledger != nil {
				ledger.RecordEarlyCompletion(pending.ledgerKey, completion)
			}
		} else {
			pending.duplicateEarly = true
			p.mu.Unlock()
			if ledger != nil {
				ledger.MarkDuplicate(pending.ledgerKey)
			}
		}
		return true
	}
	delete(p.pending, completion.RequestID)
	if flow := p.flows[pending.frame.FlowKey]; flow != nil {
		flow.pending = nil
	}
	family, hook := d11OriginWire(pending.frame.origin)
	originMismatch := pending.ledger != nil &&
		(completion.Family != family ||
			completion.Hook != hook ||
			completion.OwnedIfindex != pending.frame.origin.OwnedIfindex)
	identityMismatch := completion.PermitEpoch != pending.lease.PermitEpoch ||
		completion.QueueNumber != pending.lease.QueueNumber ||
		completion.QueueEpoch != pending.lease.QueueEpoch ||
		originMismatch
	bytesMismatch := completion.Outcome == CompletionWritten &&
		completion.BytesWritten != uint32(len(pending.frame.Packet.Payload()))
	wouldPermit := completion.Outcome == CompletionWouldPermit &&
		!identityMismatch && !bytesMismatch
	outcomeUncertain := completion.Outcome == CompletionUncertain ||
		completion.Outcome == CompletionAccepted ||
		completion.Outcome == CompletionWouldReinject
	ambiguous := identityMismatch || bytesMismatch || outcomeUncertain
	if ambiguous {
		// Accepted/WouldReinject are advisory outcomes, not terminal q0
		// commits. Treat them exactly like an uncertain completion so the
		// stream remains usable without asserting packet disposition.
		p.stats.Uncertain++
	} else {
		switch completion.Outcome {
		case CompletionWritten:
			p.stats.Written++
			p.stats.Reinjected++
		case CompletionStale, CompletionFenced:
			p.stats.Stale++
		case CompletionCancelled:
			p.stats.Cancelled++
		case CompletionRefused, CompletionDenied:
			p.stats.Refused++
		case CompletionWouldPermit:
			if pending.ledger != nil {
				p.stats.D11Suppressed++
			} else {
				p.stats.V1PermitSuppressed++
			}
		default:
			p.stats.Uncertain++
		}
	}
	terminal := string(completion.Outcome)
	if ambiguous {
		terminal = "Uncertain"
	} else if wouldPermit {
		// E28 suppression is a deliberate terminal deny, not a successful
		// reinjection. Keep the completion outcome for accounting while
		// retaining the historical FAIL terminal discriminator for the
		// attestation manifest.
		terminal = "FAIL"
	} else if completion.Outcome == CompletionWritten {
		terminal = "Written"
	}
	ledger := pending.ledger
	ledgerKey := pending.ledgerKey
	p.mu.Unlock()
	if ledger != nil {
		ledger.RecordCompletion(ledgerKey, completion, terminal)
	}
	if ambiguous {
		reason := "uncertain completion"
		if identityMismatch {
			reason = "completion lease or origin mismatch"
		} else if bytesMismatch {
			reason = "completion byte-count mismatch"
		}
		p.uncertain(reason)
		p.finishFrame(pending.frame, VerdictDrop)
		p.retireFlow(pending.frame.FlowKey)
		return true
	}
	if wouldPermit {
		if pending.ledger != nil {
			p.emitD11Deny(pending.frame, ReasonEvaluatorUnavailable)
		}
		p.finishFrame(pending.frame, VerdictDrop)
		return true
	}
	p.finishFrame(pending.frame, VerdictDrop)
	return true
}
func (p *CapturePipeline) retireFlow(key string) {
	p.mu.Lock()
	flow := p.flows[key]
	if flow == nil || flow.retired {
		p.mu.Unlock()
		return
	}
	flow.retired = true
	remaining := append([]CaptureFrame(nil), flow.frames...)
	flow.frames = nil
	flow.pending = nil
	p.mu.Unlock()
	for _, frame := range remaining {
		p.finishFrame(frame, VerdictDrop)
	}
}

// Cancel revokes the submission gate before collecting pending work. The
// write-side submit gate prevents any submit call from starting after this
// linearization point; queued and admitted originals are then terminal-DROPed
// exactly once, while late completions are ignored. Queue number and epoch
// are always carried together when a scoped cancellation is requested.
// CancelForD11Drain fences D11 submissions and asks the reinjection owner to
// cancel the matching requests without deleting their local pending entries.
// The caller must continue polling until each Rust completion is resolved;
// pipeline Close remains the fallback for requests that never receive one.
func (p *CapturePipeline) CancelForD11Drain(permitEpoch uint64) error {
	if p == nil || permitEpoch == 0 {
		return nil
	}
	p.drainMu.Lock()
	defer p.drainMu.Unlock()
	p.submitGate.Lock()
	p.mu.Lock()
	if p.attestation != nil {
		p.d11RevokedPermitEpoch = permitEpoch
	}
	ids := make([]uint64, 0, len(p.pending))
	scopeSet := make(map[ReinjectQueueScope]struct{})
	for id, pending := range p.pending {
		if pending.lease.PermitEpoch != permitEpoch {
			continue
		}
		ids = append(ids, id)
		scopeSet[ReinjectQueueScope{
			QueueNumber: pending.lease.QueueNumber,
			QueueEpoch:  pending.lease.QueueEpoch,
		}] = struct{}{}
	}
	p.mu.Unlock()
	var err error
	if p.submitter != nil {
		scopes := make([]ReinjectQueueScope, 0, len(scopeSet))
		for scope := range scopeSet {
			scopes = append(scopes, scope)
		}
		_, err = p.submitter.CancelReinject(ids, permitEpoch, scopes)
	}
	p.submitGate.Unlock()
	return err
}

// DrainD11 polls Rust completions until no pending request remains for the
// selected permit epoch or the bounded wait expires.
func (p *CapturePipeline) DrainD11(permitEpoch uint64, timeout time.Duration) error {
	if p == nil || permitEpoch == 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		p.Poll(time.Now())
		p.mu.Lock()
		pending := 0
		for _, request := range p.pending {
			if request.lease.PermitEpoch == permitEpoch {
				pending++
			}
		}
		p.mu.Unlock()
		if pending == 0 {
			return nil
		}
		if timeout <= 0 || !time.Now().Before(deadline) {
			return fmt.Errorf("D11 drain left %d pending request(s)", pending)
		}
		time.Sleep(time.Millisecond)
	}
}

func (p *CapturePipeline) Cancel(permitEpoch uint64, queueNumber uint16, queueEpoch uint64) error {
	scoped := permitEpoch != 0 || queueNumber != 0 || queueEpoch != 0
	p.drainMu.Lock()
	defer p.drainMu.Unlock()
	p.submitGate.Lock()
	p.mu.Lock()
	if !scoped {
		p.revoked = true
		p.phase = PipelineQuarantine
	}
	ids := make([]uint64, 0, len(p.pending))
	drops := make([]CaptureFrame, 0, len(p.pending))
	ledgerItems := make([]*pendingReinject, 0, len(p.pending))
	d11Flows := make(map[string]struct{})
	scopeSet := make(map[ReinjectQueueScope]struct{})
	for id, pending := range p.pending {
		if (permitEpoch == 0 || pending.lease.PermitEpoch == permitEpoch) &&
			(queueNumber == 0 || pending.lease.QueueNumber == queueNumber) &&
			(queueEpoch == 0 || pending.lease.QueueEpoch == queueEpoch) {
			ids = append(ids, id)
			scopeSet[ReinjectQueueScope{QueueNumber: pending.lease.QueueNumber, QueueEpoch: pending.lease.QueueEpoch}] = struct{}{}
			if pending.ledger != nil {
				// Keep D11 rows and their flow heads pending through the
				// send-only cancel write. Poll may concurrently receive the
				// real Rust completion; post-write reconciliation observes
				// which terminal path won instead of manufacturing a late row.
				ledgerItems = append(ledgerItems, pending)
				d11Flows[pending.frame.FlowKey] = struct{}{}
				continue
			}
			drops = append(drops, pending.frame)
			delete(p.pending, id)
		}
	}
	if scoped {
		// A scoped rotation only owns admitted packets whose lease matches
		// the requested queue/epoch. Remove those ordinary heads from their
		// flow so they cannot be submitted again; leave unrelated queued
		// work live. D11 heads remain until cancel reconciliation above.
		for _, dropped := range drops {
			flow := p.flows[dropped.FlowKey]
			if flow == nil {
				continue
			}
			if flow.pending != nil && flow.pending.frame.Packet == dropped.Packet {
				flow.pending = nil
			}
			for i, frame := range flow.frames {
				if frame.Packet == dropped.Packet {
					copy(flow.frames[i:], flow.frames[i+1:])
					flow.frames[len(flow.frames)-1] = CaptureFrame{}
					flow.frames = flow.frames[:len(flow.frames)-1]
					break
				}
			}
			if len(flow.frames) == 0 && flow.pending == nil {
				delete(p.flows, dropped.FlowKey)
			}
		}
	} else {
		for flowKey, flow := range p.flows {
			if _, keep := d11Flows[flowKey]; keep {
				continue
			}
			flow.pending = nil
			drops = append(drops, flow.frames...)
			flow.frames = nil
			flow.retired = true
			delete(p.flows, flowKey)
		}
		for {
			select {
			case frame := <-p.handoff:
				drops = append(drops, frame)
			default:
				goto drained
			}
		}
	drained:
		for key, holds := range p.fragHolds {
			drops = append(drops, holds...)
			delete(p.fragHolds, key)
			delete(p.fragTimes, key)
		}
	}
	p.mu.Unlock()
	if scoped && queueNumber != 0 && queueEpoch != 0 {
		scopeSet[ReinjectQueueScope{QueueNumber: queueNumber, QueueEpoch: queueEpoch}] = struct{}{}
	}
	scopes := make([]ReinjectQueueScope, 0, len(scopeSet))
	for scope := range scopeSet {
		scopes = append(scopes, scope)
	}
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].QueueNumber != scopes[j].QueueNumber {
			return scopes[i].QueueNumber < scopes[j].QueueNumber
		}
		return scopes[i].QueueEpoch < scopes[j].QueueEpoch
	})
	var cancelErr error
	wirePermitEpoch := permitEpoch
	if queueNumber != 0 || queueEpoch != 0 {
		wirePermitEpoch = 0
	}
	if p.submitter != nil &&
		(len(ids) != 0 || wirePermitEpoch != 0 || len(scopes) != 0) {
		// CancelReinject is send-only; its returned IDs are a local copy,
		// not Rust acknowledgements. Terminalize retained D11 rows as
		// Uncertain unless Poll has already consumed a real completion.
		_, cancelErr = p.submitter.CancelReinject(ids, wirePermitEpoch, scopes)
	}
	p.submitGate.Unlock()
	for _, item := range ledgerItems {
		p.mu.Lock()
		current := p.pending[item.lease.RequestID] == item
		if current {
			delete(p.pending, item.lease.RequestID)
			if flow := p.flows[item.frame.FlowKey]; flow != nil && flow.pending == item {
				flow.pending = nil
			}
		}
		p.mu.Unlock()
		if !current {
			continue
		}
		p.mu.Lock()
		p.stats.Uncertain++
		p.mu.Unlock()
		p.uncertain("cancel response is not a completion")
		item.ledger.RecordCompletion(item.ledgerKey, ReinjectCompletion{
			RequestID: item.lease.RequestID, PermitEpoch: item.lease.PermitEpoch,
			QueueNumber: item.lease.QueueNumber, QueueEpoch: item.lease.QueueEpoch,
			Outcome: CompletionUncertain, Reason: "pipeline cancelled",
		}, "Uncertain")
		p.finishFrame(item.frame, VerdictDrop)
		p.retireFlow(item.frame.FlowKey)
	}
	if !scoped {
		for flowKey := range d11Flows {
			p.retireFlow(flowKey)
		}
	}
	seen := make(map[*Packet]struct{}, len(drops))
	for _, frame := range drops {
		if frame.Packet == nil {
			continue
		}
		if _, ok := seen[frame.Packet]; ok {
			continue
		}
		seen[frame.Packet] = struct{}{}
		p.finishFrame(frame, VerdictDrop)
	}
	flowKeys := make(map[string]struct{})
	for _, frame := range drops {
		if frame.FlowKey != "" {
			flowKeys[frame.FlowKey] = struct{}{}
		}
	}
	if scoped && cancelErr != nil {
		p.uncertain("cancel response loss")
		for flowKey := range flowKeys {
			p.retireFlow(flowKey)
		}
	}
	if scoped && cancelErr == nil {
		p.mu.Lock()
		eligible := p.eligibleLocked()
		p.mu.Unlock()
		p.submitEligible(eligible)
	}
	return cancelErr
}
func (p *CapturePipeline) Close() error {
	if p == nil {
		return nil
	}
	_ = p.Cancel(0, 0, 0)
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	return nil
}

func (p *CapturePipeline) Stats() PipelineStats {
	if p == nil {
		return PipelineStats{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats.PipelineStats
}

// ZoneDecision is the Go pre-gate outcome. ZonePass means only that the
// frame may be sent to the authoritative worker; it is never a permit.
type ZoneDecision uint8

const (
	ZoneInvalid ZoneDecision = iota
	ZonePass
	ZoneDrop
)

type ZoneReason uint8

const (
	ZoneReasonInvalid ZoneReason = iota
	ZoneReasonZoned
	ZoneReasonUnzoned
	ZoneReasonAmbiguous
	ZoneReasonStaleGeneration
	ZoneReasonUnknownGeneration
	ZoneReasonLookupError
	ZoneReasonEvaluatorUnavailable
	ZoneReasonVersionSkew
)

type ZoneResolution struct {
	ZoneID uint16
	IfID   uint32
	Reason ZoneReason
}

type ZoneEvaluation struct {
	Decision ZoneDecision
	ZoneID   uint16
	IfID     uint32
	Reason   ZoneReason
}

type ZoneSnapshotRef interface {
	ResolveSTN(stn string) ZoneResolution
	Generations() (configGen uint64, fibGen uint32)
	Current() bool
}

type ZoneSnapshotQueueEpochRef interface {
	QueueEpoch(queue uint16) uint64
}

type ZoneSnapshotOriginValidator interface {
	ValidateOrigin(origin CaptureOrigin) ZoneReason
}

// ZoneSnapshotAcceptedGenerationsRef is implemented by zone snapshots whose
// packet config/FIB authority advances independently of the immutable capture
// authority reported by Generations. The generation gate compares
// frame.SnapshotGeneration against the capture authority and
// frame.ConfigGeneration/frame.FIBGeneration against the accepted authority;
// snapshots without this interface keep the single-authority comparison.
// This mirrors Rust D14's two-authority triple check.
type ZoneSnapshotAcceptedGenerationsRef interface {
	AcceptedGenerations() (configGen uint64, fibGen uint32)
}

type ZoneEvaluator interface {
	Evaluate(origin CaptureOrigin, snap ZoneSnapshotRef) ZoneEvaluation
}

type DefaultZoneEvaluator struct{}

func (DefaultZoneEvaluator) Evaluate(origin CaptureOrigin, snap ZoneSnapshotRef) ZoneEvaluation {
	if snap == nil {
		return ZoneEvaluation{Decision: ZoneDrop, Reason: ZoneReasonEvaluatorUnavailable}
	}
	if !snap.Current() {
		return ZoneEvaluation{Decision: ZoneDrop, Reason: ZoneReasonStaleGeneration}
	}
	resolution := snap.ResolveSTN(origin.STN)
	if resolution.Reason != ZoneReasonZoned || resolution.ZoneID == 0 || resolution.IfID == 0 {
		if resolution.Reason == ZoneReasonInvalid {
			resolution.Reason = ZoneReasonLookupError
		}
		return ZoneEvaluation{Decision: ZoneDrop, ZoneID: resolution.ZoneID, IfID: resolution.IfID, Reason: resolution.Reason}
	}
	validator, ok := snap.(ZoneSnapshotOriginValidator)
	if !ok {
		return ZoneEvaluation{Decision: ZoneDrop, ZoneID: resolution.ZoneID, IfID: resolution.IfID, Reason: ZoneReasonEvaluatorUnavailable}
	}
	if reason := validator.ValidateOrigin(origin); reason != ZoneReasonZoned {
		return ZoneEvaluation{Decision: ZoneDrop, ZoneID: resolution.ZoneID, IfID: resolution.IfID, Reason: reason}
	}
	return ZoneEvaluation{Decision: ZonePass, ZoneID: resolution.ZoneID, IfID: resolution.IfID, Reason: ZoneReasonZoned}
}

func validateCapturedGenerations(frame CaptureFrame, origin CaptureOrigin, snap ZoneSnapshotRef) ZoneReason {
	if snap == nil {
		return ZoneReasonEvaluatorUnavailable
	}
	captureConfigGen, captureFibGen := snap.Generations()
	acceptedConfigGen, acceptedFibGen := captureConfigGen, captureFibGen
	if accepted, ok := snap.(ZoneSnapshotAcceptedGenerationsRef); ok {
		acceptedConfigGen, acceptedFibGen = accepted.AcceptedGenerations()
	}
	if frame.SnapshotGeneration == 0 || frame.ConfigGeneration == 0 || frame.FIBGeneration == 0 ||
		frame.QueueEpoch == 0 || captureConfigGen == 0 || captureFibGen == 0 ||
		acceptedConfigGen == 0 || acceptedFibGen == 0 {
		return ZoneReasonUnknownGeneration
	}
	if frame.SnapshotGeneration != captureConfigGen ||
		frame.ConfigGeneration != acceptedConfigGen ||
		frame.FIBGeneration != acceptedFibGen {
		return ZoneReasonStaleGeneration
	}
	if frame.Generation != 0 && frame.Generation != frame.SnapshotGeneration {
		return ZoneReasonStaleGeneration
	}
	if epochs, ok := snap.(ZoneSnapshotQueueEpochRef); ok {
		if expected := epochs.QueueEpoch(frame.QueueNumber); expected == 0 || expected != frame.QueueEpoch {
			return ZoneReasonStaleGeneration
		}
	}
	return ZoneReasonZoned
}

func ValidateZoneEvaluation(e ZoneEvaluation) ZoneReason {
	if e.Decision == ZonePass && (e.Reason != ZoneReasonZoned || e.ZoneID == 0 || e.IfID == 0) {
		return ZoneReasonVersionSkew
	}
	if e.Decision != ZonePass && e.Reason == ZoneReasonInvalid {
		return ZoneReasonVersionSkew
	}
	return e.Reason
}

type IpsecInnerReason uint8

const (
	ReasonLegacyPolicyDeny     IpsecInnerReason = 5
	ReasonLegacyHostDeny       IpsecInnerReason = 6
	ReasonZoneUnzoned          IpsecInnerReason = 32
	ReasonZoneAmbiguous        IpsecInnerReason = 33
	ReasonIfIDUnderivable      IpsecInnerReason = 34
	ReasonStaleGeneration      IpsecInnerReason = 35
	ReasonMissingGeneration    IpsecInnerReason = 36
	ReasonZoneAdvisoryMismatch IpsecInnerReason = 37
	ReasonScreenDeny           IpsecInnerReason = 38
	ReasonParseECN             IpsecInnerReason = 39
	ReasonSessionAlias         IpsecInnerReason = 40
	ReasonInstallRollback      IpsecInnerReason = 41
	ReasonTCPRSTSuppressed     IpsecInnerReason = 42
	ReasonNATStage             IpsecInnerReason = 43
	ReasonHookRouteMismatch    IpsecInnerReason = 44
	ReasonDomainOverlap        IpsecInnerReason = 45
	ReasonOtherDomain          IpsecInnerReason = 46
	ReasonWorkerQueueFull      IpsecInnerReason = 47
	ReasonVerdictUncertain     IpsecInnerReason = 48
	ReasonSlabExhausted        IpsecInnerReason = 49
	ReasonLeaseEpoch           IpsecInnerReason = 50
	ReasonSubmitUnavailable    IpsecInnerReason = 51
	ReasonEvaluatorUnavailable IpsecInnerReason = 52
	ReasonEgressResource       IpsecInnerReason = 53
	ReasonFragmentRefused      IpsecInnerReason = 54
	ReasonProvenance           IpsecInnerReason = 55
	ReasonUnsupportedHook      IpsecInnerReason = 56
	ReasonVersionSkew          IpsecInnerReason = 57
	ReasonWorkerOrphanHA       IpsecInnerReason = 58
	ReasonInputBoundary        IpsecInnerReason = 59
	ReasonNoRoute              IpsecInnerReason = 60
)

func (r IpsecInnerReason) Valid() bool {
	return r == ReasonLegacyPolicyDeny || r == ReasonLegacyHostDeny || (r >= ReasonZoneUnzoned && r <= ReasonNoRoute)
}

func (r IpsecInnerReason) String() string {
	switch r {
	case ReasonLegacyPolicyDeny:
		return "LEGACY_POLICY_DENY"
	case ReasonLegacyHostDeny:
		return "LEGACY_HOST_INBOUND_DENY"
	case ReasonZoneUnzoned:
		return "ZONE_UNZONED"
	case ReasonZoneAmbiguous:
		return "ZONE_AMBIGUOUS"
	case ReasonIfIDUnderivable:
		return "IFID_UNDERIVABLE"
	case ReasonStaleGeneration:
		return "STALE_GENERATION"
	case ReasonMissingGeneration:
		return "MISSING_GENERATION"
	case ReasonZoneAdvisoryMismatch:
		return "ZONE_ADVISORY_MISMATCH"
	case ReasonScreenDeny:
		return "SCREEN_DENY"
	case ReasonParseECN:
		return "PARSE_ECN"
	case ReasonSessionAlias:
		return "SESSION_ALIAS"
	case ReasonInstallRollback:
		return "INSTALL_ROLLBACK"
	case ReasonTCPRSTSuppressed:
		return "TCP_RST_SUPPRESSED"
	case ReasonNATStage:
		return "NAT_STAGE"
	case ReasonHookRouteMismatch:
		return "HOOK_ROUTE_MISMATCH"
	case ReasonDomainOverlap:
		return "DOMAIN_OVERLAP"
	case ReasonOtherDomain:
		return "OTHER_DOMAIN"
	case ReasonWorkerQueueFull:
		return "WORKER_QUEUE_FULL"
	case ReasonVerdictUncertain:
		return "VERDICT_UNCERTAIN"
	case ReasonSlabExhausted:
		return "SLAB_EXHAUSTED"
	case ReasonLeaseEpoch:
		return "LEASE_EPOCH"
	case ReasonSubmitUnavailable:
		return "SUBMIT_UNAVAILABLE"
	case ReasonEvaluatorUnavailable:
		return "EVALUATOR_UNAVAILABLE"
	case ReasonEgressResource:
		return "EGRESS_RESOURCE"
	case ReasonFragmentRefused:
		return "FRAGMENT_REFUSED"
	case ReasonProvenance:
		return "PROVENANCE"
	case ReasonUnsupportedHook:
		return "UNSUPPORTED_HOOK"
	case ReasonVersionSkew:
		return "VERSION_SKEW"
	case ReasonWorkerOrphanHA:
		return "WORKER_ORPHAN_HA"
	case ReasonInputBoundary:
		return "INPUT_BOUNDARY"
	case ReasonNoRoute:
		return "NO_ROUTE"
	default:
		return "UNKNOWN"
	}
}

type PMechAlarmClass uint8

const (
	PMechAlarmStagingSkip PMechAlarmClass = iota + 1
	PMechAlarmOwnerContested
	PMechAlarmNodeWideQuarantine
	PMechAlarmZoneAmbiguous
	PMechAlarmDomainOverlap
	PMechAlarmWorkerQueueFull
	PMechAlarmOwnerUnavailable
	PMechAlarmBypassFence
	PMechAlarmFlipGuard
	PMechAlarmInputCompletion
	PMechAlarmVersionSkew
)

type PMechAlarm struct {
	Class      PMechAlarmClass
	Reason     string
	Generation uint64
	QueueID    uint16
	Tunnel     string
}

type IpsecInnerDeny struct {
	Reason     IpsecInnerReason
	PolicyID   uint32
	Origin     CaptureOrigin
	OriginSet  bool
	QueueID    uint16
	Tunnel     string
	Generation uint64
}

type DenyEventSink interface {
	EmitIpsecInnerDeny(IpsecInnerDeny) bool
	EmitPMechAlarm(PMechAlarm) bool
}

type DenyEventSinkFunc func(IpsecInnerDeny) bool

func (f DenyEventSinkFunc) EmitIpsecInnerDeny(event IpsecInnerDeny) bool {
	if f == nil {
		return false
	}
	return f(event)
}

func (f DenyEventSinkFunc) EmitPMechAlarm(PMechAlarm) bool { return false }
