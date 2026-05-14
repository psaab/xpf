package userspace

import (
	"math"
	"sort"
	"time"
)

const defaultFairnessThroughputWindow = 30 * time.Second

type FairnessThroughputSummary struct {
	Ifindex           int
	QueueID           uint8
	FlowCount         int
	ObservedCoV       float64
	Saturated         bool
	StarvedFlowsTotal uint64
	WindowSeconds     float64
	ObservedBytes     uint64
	SourceTruncated   bool
	EqualFlowEstimate FairnessEqualFlowEstimate
}

// FairnessEqualFlowEstimate is a measurement-only model for #1304's
// equal-flow mode. It computes the per-worker caps that would align
// delivered per-flow rates to the slowest sampled active worker in the
// current rolling window. The result is telemetry only; no scheduler
// path reads it.
type FairnessEqualFlowEstimate struct {
	Valid                  bool
	TargetPerFlowBPS       float64
	ObservedBPS            float64
	CappedBPS              float64
	SuppressedBPS          float64
	ThroughputLossRatio    float64
	ActiveWorkers          int
	SampledActiveWorkers   int
	UnsampledActiveWorkers int
	Workers                []FairnessEqualFlowWorkerEstimate
}

type FairnessEqualFlowWorkerEstimate struct {
	WorkerID        uint32
	ActiveFlows     uint32
	ObservedBytes   uint64
	ObservedBPS     float64
	ObservedPerFlow float64
	CapBPS          float64
	SuppressedBPS   float64
}

type FairnessThroughputWindow struct {
	window     time.Duration
	lastUpdate time.Time
	prev       map[fairnessFlowThroughputKey]uint64
	queues     map[fairnessQueueKey]*fairnessQueueThroughputWindow
}

type fairnessQueueKey struct {
	ifindex int
	queueID uint8
}

type fairnessFlowThroughputKey struct {
	queue fairnessQueueKey
	tuple FlowTupleStatus
}

type fairnessThroughputSample struct {
	at           time.Time
	duration     time.Duration
	deltas       map[fairnessFlowThroughputKey]uint64
	workerDeltas map[uint32]uint64
}

type fairnessQueueThroughputWindow struct {
	samples       []fairnessThroughputSample
	bytesByFlow   map[fairnessFlowThroughputKey]uint64
	bytesByWorker map[uint32]uint64
	starvedFlows  map[fairnessFlowThroughputKey]struct{}
	starvedTotal  uint64
}

func NewFairnessThroughputWindow(window time.Duration) *FairnessThroughputWindow {
	if window <= 0 {
		window = defaultFairnessThroughputWindow
	}
	return &FairnessThroughputWindow{
		window: window,
		prev:   make(map[fairnessFlowThroughputKey]uint64),
		queues: make(map[fairnessQueueKey]*fairnessQueueThroughputWindow),
	}
}

func (w *FairnessThroughputWindow) Update(now time.Time, status ProcessStatus) []FairnessThroughputSummary {
	if w == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	if w.window <= 0 {
		w.window = defaultFairnessThroughputWindow
	}
	if w.prev == nil {
		w.prev = make(map[fairnessFlowThroughputKey]uint64)
	}
	if w.queues == nil {
		w.queues = make(map[fairnessQueueKey]*fairnessQueueThroughputWindow)
	}

	duration := time.Duration(0)
	if !w.lastUpdate.IsZero() && now.After(w.lastUpdate) {
		duration = now.Sub(w.lastUpdate)
	}
	w.lastUpdate = now

	if status.FlowWorkerMapTruncated {
		w.resetWindowState()
		return nil
	}

	queueRates := fairnessQueueTransmitRates(status)
	workerSlots := uint32(boundedFairnessRSSWorkerSlots(status.Workers, maxFairnessRSSWorkerSlots))
	var activeWorkerFlows map[fairnessQueueKey]map[uint32]uint32
	if !status.CoSActiveFlowCountsTruncated {
		activeWorkerFlows = fairnessQueueActiveWorkerFlows(status, workerSlots)
	}
	seen := make(map[fairnessFlowThroughputKey]uint64)
	sampleQueues := make(map[fairnessQueueKey]struct{}, len(w.queues))
	for queue := range w.queues {
		sampleQueues[queue] = struct{}{}
	}
	sampleDeltas := make(map[fairnessQueueKey]map[fairnessFlowThroughputKey]uint64)
	sampleWorkerDeltas := make(map[fairnessQueueKey]map[uint32]uint64)
	for _, row := range status.FlowWorkerMap {
		if row.CoSQueueID == nil || row.EgressIfindex == 0 {
			continue
		}
		key := fairnessFlowThroughputKey{
			queue: fairnessQueueKey{ifindex: row.EgressIfindex, queueID: *row.CoSQueueID},
			tuple: row.ForwardWireKey,
		}
		if key.tuple == (FlowTupleStatus{}) {
			key.tuple = row.SessionKey
		}
		sampleQueues[key.queue] = struct{}{}
		seen[key] = row.ObservedBytes
		previous, ok := w.prev[key]
		w.prev[key] = row.ObservedBytes
		if duration <= 0 || !ok {
			continue
		}
		delta := uint64(0)
		if row.ObservedBytes >= previous {
			delta = row.ObservedBytes - previous
		} else {
			delta = row.ObservedBytes
		}
		if delta == 0 {
			continue
		}
		deltas := sampleDeltas[key.queue]
		if deltas == nil {
			deltas = make(map[fairnessFlowThroughputKey]uint64)
			sampleDeltas[key.queue] = deltas
		}
		deltas[key] += delta
		if row.WorkerID < workerSlots {
			workerDeltas := sampleWorkerDeltas[key.queue]
			if workerDeltas == nil {
				workerDeltas = make(map[uint32]uint64)
				sampleWorkerDeltas[key.queue] = workerDeltas
			}
			workerDeltas[row.WorkerID] += delta
		}
	}
	for key := range w.prev {
		if _, ok := seen[key]; !ok {
			delete(w.prev, key)
		}
	}

	if duration > 0 {
		for queue := range sampleQueues {
			state := w.queueState(queue)
			state.addSample(fairnessThroughputSample{
				at:           now,
				duration:     duration,
				deltas:       sampleDeltas[queue],
				workerDeltas: sampleWorkerDeltas[queue],
			})
		}
	}
	for _, state := range w.queues {
		state.prune(now.Add(-w.window))
	}

	keys := make([]fairnessQueueKey, 0, len(w.queues))
	for key := range w.queues {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ifindex != keys[j].ifindex {
			return keys[i].ifindex < keys[j].ifindex
		}
		return keys[i].queueID < keys[j].queueID
	})

	out := make([]FairnessThroughputSummary, 0, len(keys))
	for _, key := range keys {
		state := w.queues[key]
		if state == nil || len(state.bytesByFlow) == 0 {
			continue
		}
		summary := state.summary(key, queueRates[key], activeWorkerFlows[key])
		out = append(out, summary)
	}
	return out
}

func (w *FairnessThroughputWindow) resetWindowState() {
	w.lastUpdate = time.Time{}
	clear(w.prev)
	for _, state := range w.queues {
		state.samples = nil
		clear(state.bytesByFlow)
		clear(state.bytesByWorker)
		clear(state.starvedFlows)
	}
}

func (w *FairnessThroughputWindow) queueState(key fairnessQueueKey) *fairnessQueueThroughputWindow {
	state := w.queues[key]
	if state == nil {
		state = &fairnessQueueThroughputWindow{
			bytesByFlow:   make(map[fairnessFlowThroughputKey]uint64),
			bytesByWorker: make(map[uint32]uint64),
			starvedFlows:  make(map[fairnessFlowThroughputKey]struct{}),
		}
		w.queues[key] = state
	}
	return state
}

func (q *fairnessQueueThroughputWindow) addSample(sample fairnessThroughputSample) {
	if q.bytesByFlow == nil {
		q.bytesByFlow = make(map[fairnessFlowThroughputKey]uint64)
	}
	if q.bytesByWorker == nil {
		q.bytesByWorker = make(map[uint32]uint64)
	}
	if q.starvedFlows == nil {
		q.starvedFlows = make(map[fairnessFlowThroughputKey]struct{})
	}
	q.samples = append(q.samples, sample)
	for flow, delta := range sample.deltas {
		q.bytesByFlow[flow] += delta
	}
	for workerID, delta := range sample.workerDeltas {
		q.bytesByWorker[workerID] += delta
	}
}

func (q *fairnessQueueThroughputWindow) prune(cutoff time.Time) {
	keepFrom := 0
	for keepFrom < len(q.samples) && !q.samples[keepFrom].at.After(cutoff) {
		for flow, delta := range q.samples[keepFrom].deltas {
			if q.bytesByFlow[flow] <= delta {
				delete(q.bytesByFlow, flow)
			} else {
				q.bytesByFlow[flow] -= delta
			}
		}
		for workerID, delta := range q.samples[keepFrom].workerDeltas {
			if q.bytesByWorker[workerID] <= delta {
				delete(q.bytesByWorker, workerID)
			} else {
				q.bytesByWorker[workerID] -= delta
			}
		}
		keepFrom++
	}
	if keepFrom > 0 {
		copy(q.samples, q.samples[keepFrom:])
		q.samples = q.samples[:len(q.samples)-keepFrom]
	}
	for flow := range q.starvedFlows {
		if _, ok := q.bytesByFlow[flow]; !ok {
			delete(q.starvedFlows, flow)
		}
	}
}

func (q *fairnessQueueThroughputWindow) summary(
	key fairnessQueueKey,
	transmitRateBytes uint64,
	activeWorkerFlows map[uint32]uint32,
) FairnessThroughputSummary {
	var totalBytes uint64
	values := make([]float64, 0, len(q.bytesByFlow))
	for _, bytes := range q.bytesByFlow {
		if bytes == 0 {
			continue
		}
		totalBytes += bytes
		values = append(values, float64(bytes))
	}
	windowSeconds := q.windowSeconds()
	observedCoV := coefficientOfVariation(values)
	saturated := false
	if transmitRateBytes > 0 && windowSeconds > 0 {
		observedRate := float64(totalBytes) / windowSeconds
		saturated = observedRate >= 0.95*float64(transmitRateBytes)
	}
	q.markStarved(values)
	return FairnessThroughputSummary{
		Ifindex:           key.ifindex,
		QueueID:           key.queueID,
		FlowCount:         len(values),
		ObservedCoV:       observedCoV,
		Saturated:         saturated,
		StarvedFlowsTotal: q.starvedTotal,
		WindowSeconds:     windowSeconds,
		ObservedBytes:     totalBytes,
		EqualFlowEstimate: q.equalFlowEstimate(windowSeconds, activeWorkerFlows),
	}
}

func (q *fairnessQueueThroughputWindow) equalFlowEstimate(
	windowSeconds float64,
	activeWorkerFlows map[uint32]uint32,
) FairnessEqualFlowEstimate {
	if windowSeconds <= 0 || len(activeWorkerFlows) == 0 {
		return FairnessEqualFlowEstimate{}
	}

	workerIDs := make([]uint32, 0, len(activeWorkerFlows))
	for workerID, activeFlows := range activeWorkerFlows {
		if activeFlows > 0 {
			workerIDs = append(workerIDs, workerID)
		}
	}
	sort.Slice(workerIDs, func(i, j int) bool { return workerIDs[i] < workerIDs[j] })
	if len(workerIDs) == 0 {
		return FairnessEqualFlowEstimate{}
	}

	estimate := FairnessEqualFlowEstimate{
		ActiveWorkers: len(workerIDs),
		Workers:       make([]FairnessEqualFlowWorkerEstimate, 0, len(workerIDs)),
	}
	targetPerFlowBPS := 0.0
	for _, workerID := range workerIDs {
		activeFlows := activeWorkerFlows[workerID]
		observedBytes := q.bytesByWorker[workerID]
		observedBPS := float64(observedBytes) * 8.0 / windowSeconds
		estimate.ObservedBPS += observedBPS
		worker := FairnessEqualFlowWorkerEstimate{
			WorkerID:      workerID,
			ActiveFlows:   activeFlows,
			ObservedBytes: observedBytes,
			ObservedBPS:   observedBPS,
		}
		if observedBytes == 0 {
			estimate.UnsampledActiveWorkers++
			estimate.Workers = append(estimate.Workers, worker)
			continue
		}
		worker.ObservedPerFlow = observedBPS / float64(activeFlows)
		if estimate.SampledActiveWorkers == 0 || worker.ObservedPerFlow < targetPerFlowBPS {
			targetPerFlowBPS = worker.ObservedPerFlow
		}
		estimate.SampledActiveWorkers++
		estimate.Workers = append(estimate.Workers, worker)
	}
	if estimate.SampledActiveWorkers < 2 || targetPerFlowBPS <= 0 {
		return estimate
	}

	estimate.Valid = true
	estimate.TargetPerFlowBPS = targetPerFlowBPS
	for i := range estimate.Workers {
		worker := &estimate.Workers[i]
		if worker.ActiveFlows == 0 {
			continue
		}
		worker.CapBPS = targetPerFlowBPS * float64(worker.ActiveFlows)
		if worker.ObservedBPS > worker.CapBPS {
			worker.SuppressedBPS = worker.ObservedBPS - worker.CapBPS
		}
		estimate.SuppressedBPS += worker.SuppressedBPS
		estimate.CappedBPS += worker.ObservedBPS - worker.SuppressedBPS
	}
	if estimate.ObservedBPS > 0 {
		estimate.ThroughputLossRatio = estimate.SuppressedBPS / estimate.ObservedBPS
	}
	return estimate
}

func (q *fairnessQueueThroughputWindow) windowSeconds() float64 {
	var total time.Duration
	for _, sample := range q.samples {
		total += sample.duration
	}
	return total.Seconds()
}

func (q *fairnessQueueThroughputWindow) markStarved(values []float64) {
	if len(values) < 2 {
		return
	}
	var total float64
	for _, value := range values {
		total += value
	}
	if total <= 0 {
		return
	}
	threshold := (total / float64(len(values))) * 0.01
	for flow, bytes := range q.bytesByFlow {
		if bytes == 0 || float64(bytes) >= threshold {
			continue
		}
		if _, ok := q.starvedFlows[flow]; ok {
			continue
		}
		q.starvedFlows[flow] = struct{}{}
		q.starvedTotal++
	}
}

func coefficientOfVariation(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	var mean float64
	var m2 float64
	for i, value := range values {
		delta := value - mean
		mean += delta / float64(i+1)
		m2 += delta * (value - mean)
	}
	if mean <= 0 {
		return 0
	}
	variance := m2 / float64(len(values))
	if variance <= 0 {
		return 0
	}
	return math.Sqrt(variance) / mean
}

func fairnessQueueTransmitRates(status ProcessStatus) map[fairnessQueueKey]uint64 {
	out := make(map[fairnessQueueKey]uint64)
	for _, iface := range status.CoSInterfaces {
		for _, queue := range iface.Queues {
			if queue.QueueID < 0 || queue.QueueID > 255 {
				continue
			}
			rate := queue.TransmitRateBytes
			if rate == 0 {
				rate = iface.ShapingRateBytes
			}
			out[fairnessQueueKey{ifindex: iface.Ifindex, queueID: uint8(queue.QueueID)}] = rate
		}
	}
	return out
}

func fairnessQueueActiveWorkerFlows(status ProcessStatus, workerSlots uint32) map[fairnessQueueKey]map[uint32]uint32 {
	out := make(map[fairnessQueueKey]map[uint32]uint32)
	for _, row := range status.CoSActiveFlowCounts {
		if row.ActiveFlowCount == 0 || row.WorkerID >= workerSlots {
			continue
		}
		key := fairnessQueueKey{ifindex: row.Ifindex, queueID: row.QueueID}
		workers := out[key]
		if workers == nil {
			workers = make(map[uint32]uint32)
			out[key] = workers
		}
		workers[row.WorkerID] += row.ActiveFlowCount
	}
	return out
}
