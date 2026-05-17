package userspace

import (
	"fmt"
	"sort"
	"strings"
)

type systemBufferSample struct {
	Slot                        uint32
	HasSlot                     bool
	WorkerID                    uint32
	QueueID                     uint32
	Ifindex                     int
	Interface                   string
	UMEMCap                     uint32
	UMEMUsed                    uint32
	TXRingCap                   uint32
	TXRingUsed                  uint32
	ActiveFlowCount             uint32
	FlowCacheCollisionEvictions uint64
	DebugPendingFillFrames      uint32
	DebugSpareFillFrames        uint32
	DebugPendingTXPrepared      uint32
	DebugPendingTXLocal         uint32
	DbgTxRingFull               uint64
	DbgSendtoENOBUFS            uint64
	DbgBoundPendingOverflow     uint64
	DbgCoSQueueOverflow         uint64
	RxFillRingEmptyDescs        uint64
	RedirectInboxOverflowDrops  uint64
	PendingTXLocalOverflowDrops uint64
	TxSubmitErrorDrops          uint64
}

type systemBufferRow struct {
	Name     string
	Scope    string
	Capacity uint64
	Used     uint64
}

type systemBufferCounterRow struct {
	Name  string
	Scope string
	Value uint64
}

// FormatSystemBuffers renders userspace dataplane buffer capacity telemetry for
// `show system buffers`. Capacity rows only use bounded gauges published in
// helper status; unbounded helper counters/gauges render in a separate section
// so missing denominators are not mistaken for real fill percentages.
func FormatSystemBuffers(status ProcessStatus, detail bool) string {
	samples := systemBufferSamples(status)
	var umemCap, umemUsed, txCap, txUsed uint64
	var knownUMEM, knownTX int
	for _, sample := range samples {
		if sample.UMEMCap > 0 {
			knownUMEM++
			umemCap += uint64(sample.UMEMCap)
			umemUsed += uint64(sample.UMEMUsed)
		}
		if sample.TXRingCap > 0 {
			knownTX++
			txCap += uint64(sample.TXRingCap)
			txUsed += uint64(sample.TXRingUsed)
		}
	}

	var rows []systemBufferRow
	if knownUMEM > 0 {
		rows = append(rows, systemBufferRow{
			Name:     "AF_XDP UMEM frames",
			Scope:    fmt.Sprintf("aggregate/%d", knownUMEM),
			Capacity: umemCap,
			Used:     umemUsed,
		})
	}
	if knownTX > 0 {
		rows = append(rows, systemBufferRow{
			Name:     "AF_XDP TX ring",
			Scope:    fmt.Sprintf("aggregate/%d", knownTX),
			Capacity: txCap,
			Used:     txUsed,
		})
	}
	rows = append(rows, systemBufferCoSRows(status, detail)...)
	if detail {
		for _, sample := range samples {
			scope := systemBufferSampleScope(sample)
			if sample.UMEMCap > 0 {
				rows = append(rows, systemBufferRow{
					Name:     "AF_XDP UMEM frames",
					Scope:    scope,
					Capacity: uint64(sample.UMEMCap),
					Used:     uint64(sample.UMEMUsed),
				})
			}
			if sample.TXRingCap > 0 {
				rows = append(rows, systemBufferRow{
					Name:     "AF_XDP TX ring",
					Scope:    scope,
					Capacity: uint64(sample.TXRingCap),
					Used:     uint64(sample.TXRingUsed),
				})
			}
		}
	}
	counterRows := systemBufferCounterRows(status, samples, detail)

	var b strings.Builder
	b.WriteString("Userspace Buffer Utilization:\n")
	if len(rows) == 0 {
		b.WriteString("  unavailable: helper status does not include bounded AF_XDP capacity gauges\n")
		b.WriteString("  required status fields: per_binding[].umem_total_frames, per_binding[].umem_inflight_frames, per_binding[].tx_ring_capacity, per_binding[].outstanding_tx\n")
		b.WriteString("  bindings[] mirrors with the same fields are also accepted\n")
	} else {
		if knownUMEM == 0 && knownTX == 0 {
			b.WriteString("  AF_XDP unavailable: helper status does not include bounded capacity gauges\n")
		}
		fmt.Fprintf(&b, "%-24s %-24s %12s %12s %8s %s\n", "Buffer", "Scope", "Capacity", "Used", "Usage%", "Status")
		b.WriteString(strings.Repeat("-", 92) + "\n")
		warnings := 0
		for _, row := range rows {
			pct := 0.0
			if row.Capacity > 0 {
				pct = float64(row.Used) * 100.0 / float64(row.Capacity)
			}
			status := "OK"
			if pct >= 90.0 {
				status = "CRITICAL"
				warnings++
			} else if pct >= 80.0 {
				status = "WARNING"
				warnings++
			}
			fmt.Fprintf(&b, "%-24s %-24s %12d %12d %7.1f%% %s\n",
				row.Name, row.Scope, row.Capacity, row.Used, pct, status)
		}
		if warnings > 0 {
			fmt.Fprintf(&b, "\n%d userspace buffer row(s) at high utilization\n", warnings)
		}
	}
	if len(counterRows) > 0 {
		if !strings.HasSuffix(b.String(), "\n\n") {
			b.WriteString("\n")
		}
		b.WriteString("Userspace Status Counters:\n")
		fmt.Fprintf(&b, "%-32s %-24s %12s\n", "Counter", "Scope", "Value")
		b.WriteString(strings.Repeat("-", 70) + "\n")
		for _, row := range counterRows {
			fmt.Fprintf(&b, "%-32s %-24s %12d\n", row.Name, row.Scope, row.Value)
		}
	}
	return b.String()
}

func systemBufferCoSRows(status ProcessStatus, detail bool) []systemBufferRow {
	var rows []systemBufferRow
	var aggregateCap, aggregateUsed uint64
	var queueCount int
	for _, iface := range status.CoSInterfaces {
		for _, queue := range iface.Queues {
			if queue.BufferBytes == 0 {
				continue
			}
			queueCount++
			aggregateCap += queue.BufferBytes
			aggregateUsed += queue.QueuedBytes
		}
	}
	if queueCount == 0 {
		return rows
	}
	rows = append(rows, systemBufferRow{
		Name:     "CoS queue bytes",
		Scope:    fmt.Sprintf("aggregate/%d", queueCount),
		Capacity: aggregateCap,
		Used:     aggregateUsed,
	})
	if !detail {
		return rows
	}
	for _, iface := range status.CoSInterfaces {
		for _, queue := range iface.Queues {
			if queue.BufferBytes == 0 {
				continue
			}
			rows = append(rows, systemBufferRow{
				Name:     "CoS queue bytes",
				Scope:    systemBufferCoSQueueScope(iface, queue),
				Capacity: queue.BufferBytes,
				Used:     queue.QueuedBytes,
			})
		}
	}
	return rows
}

func systemBufferCounterRows(status ProcessStatus, samples []systemBufferSample, detail bool) []systemBufferCounterRow {
	var activeFlowCount uint64
	var flowCacheCollisionEvictions uint64
	var debugPendingFillFrames uint64
	var debugSpareFillFrames uint64
	var debugPendingTXPrepared uint64
	var debugPendingTXLocal uint64
	var dbgTxRingFull uint64
	var dbgSendtoENOBUFS uint64
	var dbgBoundPendingOverflow uint64
	var dbgCoSQueueOverflow uint64
	var rxFillRingEmptyDescs uint64
	var redirectInboxOverflowDrops uint64
	var pendingTXLocalOverflowDrops uint64
	var txSubmitErrorDrops uint64
	for _, sample := range samples {
		activeFlowCount += uint64(sample.ActiveFlowCount)
		flowCacheCollisionEvictions += sample.FlowCacheCollisionEvictions
		debugPendingFillFrames += uint64(sample.DebugPendingFillFrames)
		debugSpareFillFrames += uint64(sample.DebugSpareFillFrames)
		debugPendingTXPrepared += uint64(sample.DebugPendingTXPrepared)
		debugPendingTXLocal += uint64(sample.DebugPendingTXLocal)
		dbgTxRingFull += sample.DbgTxRingFull
		dbgSendtoENOBUFS += sample.DbgSendtoENOBUFS
		dbgBoundPendingOverflow += sample.DbgBoundPendingOverflow
		dbgCoSQueueOverflow += sample.DbgCoSQueueOverflow
		rxFillRingEmptyDescs += sample.RxFillRingEmptyDescs
		redirectInboxOverflowDrops += sample.RedirectInboxOverflowDrops
		pendingTXLocalOverflowDrops += sample.PendingTXLocalOverflowDrops
		txSubmitErrorDrops += sample.TxSubmitErrorDrops
	}

	var rows []systemBufferCounterRow
	appendCounter := func(name, scope string, value uint64) {
		if value > 0 {
			rows = append(rows, systemBufferCounterRow{Name: name, Scope: scope, Value: value})
		}
	}
	appendCounter("Neighbor cache entries", "dynamic", uint64(status.NeighborEntries))
	appendCounter("Flow cache active flows", "active window", activeFlowCount)
	appendCounter("Flow cache collision evict", "aggregate", flowCacheCollisionEvictions)
	appendCounter("Pending fill frames", "aggregate", debugPendingFillFrames)
	appendCounter("Spare fill frames", "aggregate", debugSpareFillFrames)
	appendCounter("Pending TX prepared", "aggregate", debugPendingTXPrepared)
	appendCounter("Pending TX local", "aggregate", debugPendingTXLocal)
	appendCounter("TX ring full events", "aggregate", dbgTxRingFull)
	appendCounter("sendto ENOBUFS", "aggregate", dbgSendtoENOBUFS)
	appendCounter("Bound pending overflow", "aggregate", dbgBoundPendingOverflow)
	appendCounter("CoS queue overflow", "aggregate", dbgCoSQueueOverflow)
	appendCounter("RX fill-ring empty descs", "aggregate", rxFillRingEmptyDescs)
	appendCounter("Redirect inbox overflow", "aggregate", redirectInboxOverflowDrops)
	appendCounter("Pending TX local overflow", "aggregate", pendingTXLocalOverflowDrops)
	appendCounter("TX submit error drops", "aggregate", txSubmitErrorDrops)

	if !detail {
		return rows
	}
	for _, sample := range samples {
		scope := systemBufferSampleScope(sample)
		appendCounter("Flow cache active flows", scope, uint64(sample.ActiveFlowCount))
		appendCounter("Flow cache collision evict", scope, sample.FlowCacheCollisionEvictions)
		appendCounter("Pending fill frames", scope, uint64(sample.DebugPendingFillFrames))
		appendCounter("Spare fill frames", scope, uint64(sample.DebugSpareFillFrames))
		appendCounter("Pending TX prepared", scope, uint64(sample.DebugPendingTXPrepared))
		appendCounter("Pending TX local", scope, uint64(sample.DebugPendingTXLocal))
		appendCounter("TX ring full events", scope, sample.DbgTxRingFull)
		appendCounter("sendto ENOBUFS", scope, sample.DbgSendtoENOBUFS)
		appendCounter("Bound pending overflow", scope, sample.DbgBoundPendingOverflow)
		appendCounter("CoS queue overflow", scope, sample.DbgCoSQueueOverflow)
		appendCounter("RX fill-ring empty descs", scope, sample.RxFillRingEmptyDescs)
		appendCounter("Redirect inbox overflow", scope, sample.RedirectInboxOverflowDrops)
		appendCounter("Pending TX local overflow", scope, sample.PendingTXLocalOverflowDrops)
		appendCounter("TX submit error drops", scope, sample.TxSubmitErrorDrops)
	}
	return rows
}

func systemBufferSamples(status ProcessStatus) []systemBufferSample {
	bindings := make(map[systemBufferBindingKey]BindingStatus, len(status.Bindings))
	for _, binding := range status.Bindings {
		bindings[systemBufferBindingKey{
			WorkerID: binding.WorkerID,
			QueueID:  binding.QueueID,
			Ifindex:  binding.Ifindex,
		}] = binding
	}

	var samples []systemBufferSample
	seen := make(map[systemBufferBindingKey]struct{}, len(status.PerBinding))
	if len(status.PerBinding) > 0 {
		for _, binding := range status.PerBinding {
			key := systemBufferBindingKey{
				WorkerID: binding.WorkerID,
				QueueID:  binding.QueueID,
				Ifindex:  binding.Ifindex,
			}
			seen[key] = struct{}{}
			sample := systemBufferSample{
				WorkerID:                    binding.WorkerID,
				QueueID:                     binding.QueueID,
				Ifindex:                     binding.Ifindex,
				UMEMCap:                     binding.UmemTotalFrames,
				UMEMUsed:                    binding.UmemInflightFrames,
				TXRingCap:                   binding.TxRingCapacity,
				TXRingUsed:                  binding.OutstandingTX,
				ActiveFlowCount:             binding.ActiveFlowCount,
				FlowCacheCollisionEvictions: binding.FlowCacheCollisionEvictions,
				DbgTxRingFull:               binding.DbgTxRingFull,
				DbgSendtoENOBUFS:            binding.DbgSendtoENOBUFS,
				DbgBoundPendingOverflow:     binding.DbgBoundPendingOverflow,
				DbgCoSQueueOverflow:         binding.DbgCoSQueueOverflow,
				RxFillRingEmptyDescs:        binding.RxFillRingEmptyDescs,
				PendingTXLocalOverflowDrops: binding.PendingTxLocalOverflowDrops,
				TxSubmitErrorDrops:          binding.TxSubmitErrorDrops,
			}
			if full, ok := bindings[key]; ok {
				sample.Slot = full.Slot
				sample.HasSlot = true
				sample.Interface = full.Interface
				if binding.UmemTotalFrames == 0 {
					sample.UMEMCap = full.UmemTotalFrames
					sample.UMEMUsed = full.UmemInflightFrames
				}
				if binding.TxRingCapacity == 0 {
					sample.TXRingCap = full.TxRingCapacity
					sample.TXRingUsed = full.OutstandingTX
				}
				sample.applyBindingStatusFallback(full)
			}
			samples = append(samples, sample)
		}
	}
	for _, binding := range status.Bindings {
		key := systemBufferBindingKey{
			WorkerID: binding.WorkerID,
			QueueID:  binding.QueueID,
			Ifindex:  binding.Ifindex,
		}
		if _, ok := seen[key]; ok {
			continue
		}
		samples = append(samples, systemBufferSample{
			Slot:                        binding.Slot,
			HasSlot:                     true,
			WorkerID:                    binding.WorkerID,
			QueueID:                     binding.QueueID,
			Ifindex:                     binding.Ifindex,
			Interface:                   binding.Interface,
			UMEMCap:                     binding.UmemTotalFrames,
			UMEMUsed:                    binding.UmemInflightFrames,
			TXRingCap:                   binding.TxRingCapacity,
			TXRingUsed:                  binding.OutstandingTX,
			ActiveFlowCount:             binding.ActiveFlowCount,
			FlowCacheCollisionEvictions: binding.FlowCacheCollisionEvictions,
			DebugPendingFillFrames:      binding.DebugPendingFillFrames,
			DebugSpareFillFrames:        binding.DebugSpareFillFrames,
			DebugPendingTXPrepared:      binding.DebugPendingTXPrepared,
			DebugPendingTXLocal:         binding.DebugPendingTXLocal,
			DbgTxRingFull:               binding.DbgTxRingFull,
			DbgSendtoENOBUFS:            binding.DbgSendtoENOBUFS,
			DbgBoundPendingOverflow:     binding.DbgBoundPendingOverflow,
			DbgCoSQueueOverflow:         binding.DbgCoSQueueOverflow,
			RxFillRingEmptyDescs:        binding.RxFillRingEmptyDescs,
			RedirectInboxOverflowDrops:  binding.RedirectInboxOverflowDrops,
			PendingTXLocalOverflowDrops: binding.PendingTXLocalOverflowDrops,
			TxSubmitErrorDrops:          binding.TxSubmitErrorDrops,
		})
	}
	sort.Slice(samples, func(i, j int) bool {
		a, b := samples[i], samples[j]
		if a.WorkerID != b.WorkerID {
			return a.WorkerID < b.WorkerID
		}
		if a.QueueID != b.QueueID {
			return a.QueueID < b.QueueID
		}
		if a.Ifindex != b.Ifindex {
			return a.Ifindex < b.Ifindex
		}
		if a.HasSlot != b.HasSlot {
			return a.HasSlot
		}
		return a.Slot < b.Slot
	})
	return samples
}

func (sample *systemBufferSample) applyBindingStatusFallback(binding BindingStatus) {
	if sample.ActiveFlowCount == 0 {
		sample.ActiveFlowCount = binding.ActiveFlowCount
	}
	if sample.FlowCacheCollisionEvictions == 0 {
		sample.FlowCacheCollisionEvictions = binding.FlowCacheCollisionEvictions
	}
	if sample.DebugPendingFillFrames == 0 {
		sample.DebugPendingFillFrames = binding.DebugPendingFillFrames
	}
	if sample.DebugSpareFillFrames == 0 {
		sample.DebugSpareFillFrames = binding.DebugSpareFillFrames
	}
	if sample.DebugPendingTXPrepared == 0 {
		sample.DebugPendingTXPrepared = binding.DebugPendingTXPrepared
	}
	if sample.DebugPendingTXLocal == 0 {
		sample.DebugPendingTXLocal = binding.DebugPendingTXLocal
	}
	if sample.DbgTxRingFull == 0 {
		sample.DbgTxRingFull = binding.DbgTxRingFull
	}
	if sample.DbgSendtoENOBUFS == 0 {
		sample.DbgSendtoENOBUFS = binding.DbgSendtoENOBUFS
	}
	if sample.DbgBoundPendingOverflow == 0 {
		sample.DbgBoundPendingOverflow = binding.DbgBoundPendingOverflow
	}
	if sample.DbgCoSQueueOverflow == 0 {
		sample.DbgCoSQueueOverflow = binding.DbgCoSQueueOverflow
	}
	if sample.RxFillRingEmptyDescs == 0 {
		sample.RxFillRingEmptyDescs = binding.RxFillRingEmptyDescs
	}
	if sample.RedirectInboxOverflowDrops == 0 {
		sample.RedirectInboxOverflowDrops = binding.RedirectInboxOverflowDrops
	}
	if sample.PendingTXLocalOverflowDrops == 0 {
		sample.PendingTXLocalOverflowDrops = binding.PendingTXLocalOverflowDrops
	}
	if sample.TxSubmitErrorDrops == 0 {
		sample.TxSubmitErrorDrops = binding.TxSubmitErrorDrops
	}
}

type systemBufferBindingKey struct {
	WorkerID uint32
	QueueID  uint32
	Ifindex  int
}

func systemBufferSampleScope(sample systemBufferSample) string {
	parts := []string{
		fmt.Sprintf("worker %d", sample.WorkerID),
		fmt.Sprintf("queue %d", sample.QueueID),
	}
	if sample.HasSlot {
		parts = append(parts, fmt.Sprintf("slot %d", sample.Slot))
	}
	if sample.Interface != "" {
		parts = append(parts, sample.Interface)
	} else if sample.Ifindex != 0 {
		parts = append(parts, fmt.Sprintf("ifindex %d", sample.Ifindex))
	}
	return strings.Join(parts, "/")
}

func systemBufferCoSQueueScope(iface CoSInterfaceStatus, queue CoSQueueStatus) string {
	var parts []string
	if iface.InterfaceName != "" {
		parts = append(parts, iface.InterfaceName)
	} else if iface.Ifindex != 0 {
		parts = append(parts, fmt.Sprintf("ifindex %d", iface.Ifindex))
	}
	parts = append(parts, fmt.Sprintf("queue %d", queue.QueueID))
	if queue.ForwardingClass != "" {
		parts = append(parts, queue.ForwardingClass)
	}
	if queue.OwnerWorkerID != nil {
		parts = append(parts, fmt.Sprintf("worker %d", *queue.OwnerWorkerID))
	}
	return strings.Join(parts, "/")
}
