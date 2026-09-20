package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/nfqueue"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

var ipsecCaptureProcessRunID = newIpsecCaptureProcessRunID()

func newIpsecCaptureProcessRunID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("xpfd-entropy-unavailable-%d", time.Now().UnixNano())
	}
	return "xpfd-" + hex.EncodeToString(raw[:])
}

// IpsecCapturePipelineConfig wires the S4 supervisor authority to the capture
// actor. Construction is inert: no queue, divert table, goroutine, or permit
// is started until Start is called explicitly. Queues, when supplied, are
// consumed by bounded Recv loops owned by this actor.
type IpsecCaptureQueue struct {
	Queue      *nfqueue.Queue
	Tunnel     uint32
	VRF        uint32
	Generation uint64
}

type IpsecCapturePipelineConfig struct {
	Supervisor             *ipsecSupervisor
	Registry               *nfqueue.OriginRegistry
	QueueEpochs            map[uint16]uint64
	Queues                 []IpsecCaptureQueue
	RunID                  string
	Pipeline               nfqueue.CapturePipelineConfig
	DeliveredCounterReader func() (xnft.TransitFenceCounter, bool, error)
}

// IpsecCapturePipelineStatus is the bounded live-evidence view exported by the
// actor. PipelineStats contains the per-outcome, provenance, overlap, L2, and
// per-flow terminal counters. Delivered is the inet q0 mark-counter delta
// downstream of the TUN write; q0 is shared with transit MissingNeighbor, so
// it is authoritative only under a quiesced S5 window.
type IpsecCapturePipelineStatus struct {
	Available          bool
	Active             bool
	Down               bool
	Rotation           string
	RunID              string
	Generation         uint64
	PermitState        string
	PermitEpoch        uint64
	Counters           nfqueue.PipelineStats
	DeliveredAvailable bool
	Delivered          uint64
}

// IpsecCapturePipeline is the daemon-side actor for the S5 capture slice. S4
// remains the authority for permit state, queue epochs, terminality, and
// rotation; this type owns the bounded capture worker and queue receive loops.
type IpsecCapturePipeline struct {
	mu          sync.Mutex
	supervisor  *ipsecSupervisor
	registry    *nfqueue.OriginRegistry
	queueEpochs map[uint16]uint64
	queues      []IpsecCaptureQueue
	pipeline    *nfqueue.CapturePipeline
	rotation    *ipsecRotation
	runID       string
	requestID   atomic.Uint64
	active      bool
	down        bool
	cancel      context.CancelFunc
	done        chan struct{}

	deliveredCounterReader func() (xnft.TransitFenceCounter, bool, error)
	deliveredBaseline      uint64
	deliveredBaselineSet   bool
	deliveredUnavailable   bool
}

var (
	errCaptureActorStarted = errors.New("ipsec capture pipeline already started")
	errCaptureActorStopped = errors.New("ipsec capture pipeline is not started")
)

// NewIpsecCapturePipeline constructs an inactive actor. A nil supervisor is
// replaced by the S4 authority's zero-safe standalone instance for tests and
// for a daemon before its supervisor loop is attached.
func NewIpsecCapturePipeline(cfg IpsecCapturePipelineConfig) (*IpsecCapturePipeline, error) {
	if cfg.Supervisor == nil {
		cfg.Supervisor = newIpsecSupervisor()
	}
	if cfg.Registry == nil {
		cfg.Registry = new(nfqueue.OriginRegistry)
	}
	if cfg.DeliveredCounterReader == nil {
		cfg.DeliveredCounterReader = xnft.ReadTransitFenceCounter
	}
	cfg.Pipeline.Registry = cfg.Registry
	runID := cfg.RunID
	if runID == "" {
		runID = ipsecCaptureProcessRunID
	}
	actor := &IpsecCapturePipeline{
		supervisor:             cfg.Supervisor,
		registry:               cfg.Registry,
		queueEpochs:            make(map[uint16]uint64, len(cfg.QueueEpochs)),
		queues:                 append([]IpsecCaptureQueue(nil), cfg.Queues...),
		rotation:               newIpsecRotation(),
		runID:                  runID,
		deliveredCounterReader: cfg.DeliveredCounterReader,
	}
	for queue, epoch := range cfg.QueueEpochs {
		if queue == 0 || epoch == 0 {
			return nil, fmt.Errorf("ipsec capture pipeline: invalid queue epoch queue=%d epoch=%d", queue, epoch)
		}
		actor.queueEpochs[queue] = epoch
	}
	for _, captureQueue := range actor.queues {
		if captureQueue.Queue == nil {
			return nil, errors.New("ipsec capture pipeline: nil capture queue")
		}
		if captureQueue.Generation == 0 {
			return nil, fmt.Errorf("ipsec capture pipeline: queue %d has zero generation", captureQueue.Queue.ID())
		}
		if actor.queueEpochs[captureQueue.Queue.ID()] == 0 {
			return nil, fmt.Errorf("ipsec capture pipeline: queue %d has no epoch", captureQueue.Queue.ID())
		}
	}
	cfg.Pipeline.LeaseMinter = actor
	pipeline, err := nfqueue.NewCapturePipeline(cfg.Pipeline)
	if err != nil {
		return nil, err
	}
	actor.pipeline = pipeline
	return actor, nil
}

// Start launches the bounded poll/drain actor and one bounded-deadline receive
// loop per configured NFQUEUE. An actor with no queues is still useful for
// synthetic handoff tests, but it does not claim to capture packets.
func (a *IpsecCapturePipeline) Start() error {
	if a == nil {
		return errCaptureActorStopped
	}
	a.mu.Lock()
	if a.active {
		a.mu.Unlock()
		return errCaptureActorStarted
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.active = true
	a.down = false
	a.cancel = cancel
	a.done = make(chan struct{})
	done := a.done
	queues := append([]IpsecCaptureQueue(nil), a.queues...)
	a.deliveredBaseline = 0
	a.deliveredBaselineSet = false
	a.deliveredUnavailable = false
	a.mu.Unlock()

	// Capture exactly one baseline at actor start. An absent/disarmed fence,
	// read error, or any later reset latches this actor run unavailable;
	// re-baselining would turn a partial run into a false delivery claim.
	a.establishDeliveredBaseline()

	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				a.pipeline.Drain(64)
				a.pipeline.Poll(now)
			}
		}
	}()
	for _, captureQueue := range queues {
		workers.Add(1)
		go func(captureQueue IpsecCaptureQueue) {
			defer workers.Done()
			a.receiveQueue(ctx, captureQueue)
		}(captureQueue)
	}
	go func() {
		workers.Wait()
		close(done)
	}()
	return nil
}

// receiveQueue owns Recv for one queue. Close is deliberately deferred until
// all receive loops have joined in Stop because Queue.Close must not race with
// Recv.
func (a *IpsecCapturePipeline) receiveQueue(ctx context.Context, captureQueue IpsecCaptureQueue) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		packet, err := captureQueue.Queue.Recv(time.Now().Add(10 * time.Millisecond))
		if err != nil {
			if errors.Is(err, nfqueue.ErrTimeout) {
				continue
			}
			a.captureFailure(err)
			return
		}
		classification, err := nfqueue.ClassifyCapturePayload(packet.Payload())
		if err != nil {
			_ = packet.Verdict(nfqueue.VerdictDrop)
			continue
		}
		frame := nfqueue.CaptureFrame{Packet: packet, FlowKey: classification.FlowKey}
		if classification.IsFragment {
			key, keyOK := classification.FragmentKey(captureQueue.Tunnel, captureQueue.VRF, captureQueue.Generation)
			piece, pieceOK := classification.FragmentPiece(packet.Payload())
			if !keyOK || !pieceOK {
				_ = packet.Verdict(nfqueue.VerdictDrop)
				continue
			}
			frame.FragmentKey = &key
			frame.Fragment = &piece
		}
		if err := a.pipeline.Enqueue(frame); err != nil && errors.Is(err, nfqueue.ErrPipelineClosed) {
			return
		}
	}
}

func (a *IpsecCapturePipeline) captureFailure(err error) {
	if a == nil || err == nil {
		return
	}
	a.mu.Lock()
	a.down = true
	cancel := a.cancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Enqueue hands a pre-received packet to the bounded actor. Production queue
// receive loops use this same path, while hermetic tests can inject packets.
func (a *IpsecCapturePipeline) Enqueue(frame nfqueue.CaptureFrame) error {
	if a == nil || a.pipeline == nil {
		return errCaptureActorStopped
	}
	return a.pipeline.Enqueue(frame)
}

// Stop joins the poller and receive loops, closes owned queues, then closes
// the bounded pipeline. Queue.Close is only called after Recv has returned.
func (a *IpsecCapturePipeline) Stop() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	if !a.active {
		a.mu.Unlock()
		return nil
	}
	cancel, done := a.cancel, a.done
	queues := append([]IpsecCaptureQueue(nil), a.queues...)
	a.active = false
	a.cancel = nil
	a.done = nil
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
	var firstErr error
	for _, captureQueue := range queues {
		if err := captureQueue.Queue.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := a.pipeline.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// establishDeliveredBaseline captures the one baseline sample for this actor
// run. It intentionally latches unavailable instead of waiting for a fence
// install or re-baselining after a reset.
func (a *IpsecCapturePipeline) establishDeliveredBaseline() {
	if a == nil {
		return
	}
	a.mu.Lock()
	reader := a.deliveredCounterReader
	a.mu.Unlock()
	if reader == nil {
		a.mu.Lock()
		a.deliveredUnavailable = true
		a.mu.Unlock()
		return
	}
	sample, available, err := reader()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil || !available {
		a.deliveredUnavailable = true
		return
	}
	a.deliveredBaseline = sample.Packets
	a.deliveredBaselineSet = true
}

// deliveredSnapshot returns the monotonic packet delta from the start
// baseline. A negative delta, absent/disarmed fence, or read error permanently
// invalidates this actor run; it must never be converted to an authoritative
// zero or repaired by a new baseline.
func (a *IpsecCapturePipeline) deliveredSnapshot() (bool, uint64) {
	if a == nil {
		return false, 0
	}
	a.mu.Lock()
	if a.deliveredUnavailable || !a.deliveredBaselineSet || a.deliveredCounterReader == nil {
		a.mu.Unlock()
		return false, 0
	}
	reader := a.deliveredCounterReader
	baseline := a.deliveredBaseline
	a.mu.Unlock()

	sample, available, err := reader()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.deliveredUnavailable || err != nil || !available || sample.Packets < baseline {
		a.deliveredUnavailable = true
		return false, 0
	}
	return true, sample.Packets - baseline
}

// Status returns actor lifecycle, authority join keys, and terminal counters.
func (a *IpsecCapturePipeline) Status() IpsecCapturePipelineStatus {
	if a == nil {
		return IpsecCapturePipelineStatus{PermitState: ipsecPermitClosed.String(), Rotation: ipsecRotationClosed.String()}
	}
	a.mu.Lock()
	active, down := a.active, a.down
	rotation := a.rotation.state()
	generation := a.rotation.openGeneration()
	if generation == 0 && len(a.queues) != 0 {
		generation = a.queues[0].Generation
	}
	runID := a.runID
	a.mu.Unlock()
	permitState := ipsecPermitClosed.String()
	var permitEpoch uint64
	if a.supervisor != nil {
		if permit := a.supervisor.loadPermit(); permit != nil {
			permitState = permit.state.String()
			permitEpoch = permit.permitEpoch
		}
	}
	var counters nfqueue.PipelineStats
	if a.pipeline != nil {
		counters = a.pipeline.Stats()
	}
	deliveredAvailable, delivered := a.deliveredSnapshot()
	return IpsecCapturePipelineStatus{
		Available:          true,
		Active:             active,
		Down:               down,
		Rotation:           rotation.String(),
		RunID:              runID,
		Generation:         generation,
		PermitState:        permitState,
		PermitEpoch:        permitEpoch,
		Counters:           counters,
		DeliveredAvailable: deliveredAvailable,
		Delivered:          delivered,
	}
}

// EpochSnapshot returns the authority payload for the currently active
// capture actor. Closed, down, or not-yet-started actors deliberately publish
// zero/nil so a Rust helper cannot reopen a permit from a stale epoch.
func (a *IpsecCapturePipeline) EpochSnapshot() (uint64, map[uint16]uint64) {
	if a == nil {
		return 0, nil
	}
	a.mu.Lock()
	active, down := a.active, a.down
	epochs := make(map[uint16]uint64, len(a.queueEpochs))
	if active && !down {
		for queue, epoch := range a.queueEpochs {
			epochs[queue] = epoch
		}
	}
	a.mu.Unlock()
	if !active || down || a.supervisor == nil {
		return 0, nil
	}
	permit := a.supervisor.loadPermit()
	if permit == nil || permit.state != ipsecPermitOpen {
		return 0, nil
	}
	return permit.permitEpoch, epochs
}

// StageRotation creates the next four-provenance generation in QUARANTINE.
// Callers allocate and retire each handle through S4 before invoking this
// method; no partial inet-new/bridge-old generation is exposed.
func (a *IpsecCapturePipeline) StageRotation(old, staged []ipsecQueueHandle) error {
	if a == nil {
		return errCaptureActorStopped
	}
	return a.rotation.stage(old, staged)
}

// ActivateRotation atomically publishes the staged generation. Any failure
// rolls the actor back to CLOSED and marks the tunnel down rather than exposing
// one family's new queue beside another family's old queue.
func (a *IpsecCapturePipeline) ActivateRotation() error {
	if a == nil {
		return errCaptureActorStopped
	}
	if err := a.rotation.activate(); err != nil {
		a.RollbackRotation()
		return err
	}
	return nil
}

// RollbackRotation is the fail-closed tunnel-DOWN path for an incomplete or
// failed generation transaction.
func (a *IpsecCapturePipeline) RollbackRotation() {
	if a == nil {
		return
	}
	a.rotation.rollback()
	a.mu.Lock()
	a.down = true
	a.mu.Unlock()
}

// MintLease implements nfqueue.LeaseMinter using the immutable S4 permit and
// queue epoch. Request IDs are actor-local and never zero or reused.
func (a *IpsecCapturePipeline) MintLease(frame nfqueue.CaptureFrame) (nfqueue.ReinjectLease, error) {
	if a == nil || a.supervisor == nil || frame.Packet == nil {
		return nfqueue.ReinjectLease{}, errIpsecPermitClosed
	}
	permit := a.supervisor.loadPermit()
	if permit == nil || permit.state != ipsecPermitOpen {
		return nfqueue.ReinjectLease{}, errIpsecPermitClosed
	}
	queueEpoch := a.queueEpochs[frame.Packet.QueueID()]
	if queueEpoch == 0 {
		return nfqueue.ReinjectLease{}, errIpsecQueueStale
	}
	requestID := a.requestID.Add(1)
	if requestID == 0 {
		return nfqueue.ReinjectLease{}, errors.New("ipsec capture pipeline: request id exhausted")
	}
	return nfqueue.ReinjectLease{PermitEpoch: permit.permitEpoch, QueueNumber: frame.Packet.QueueID(), QueueEpoch: queueEpoch, RequestID: requestID}, nil
}

// rollback is defined beside the actor because S4's rotation type remains
// read-only in its original file while the actor owns the transition adapter.
func (r *ipsecRotation) rollback() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.stateValue = ipsecRotationClosed
	r.old = nil
	r.staged = nil
	r.active = nil
	r.failSecond = false
	r.mu.Unlock()
}
