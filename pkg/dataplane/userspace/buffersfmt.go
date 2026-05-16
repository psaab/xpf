package userspace

import (
	"fmt"
	"sort"
	"strings"
)

type systemBufferSample struct {
	Slot       uint32
	HasSlot    bool
	WorkerID   uint32
	QueueID    uint32
	Ifindex    int
	Interface  string
	UMEMCap    uint32
	UMEMUsed   uint32
	TXRingCap  uint32
	TXRingUsed uint32
}

type systemBufferRow struct {
	Name     string
	Scope    string
	Capacity uint64
	Used     uint64
}

// FormatSystemBuffers renders userspace dataplane buffer capacity telemetry for
// `show system buffers`. It only uses bounded AF_XDP gauges published in helper
// status; if those gauges are absent, it reports the missing wire fields rather
// than falling back to unrelated BPF map occupancy.
func FormatSystemBuffers(status ProcessStatus, _ bool) string {
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

	var b strings.Builder
	b.WriteString("Userspace Buffer Utilization:\n")
	if len(rows) == 0 {
		b.WriteString("  unavailable: helper status does not include bounded AF_XDP capacity gauges\n")
		b.WriteString("  required status fields: per_binding[].umem_total_frames, per_binding[].umem_inflight_frames, per_binding[].tx_ring_capacity, per_binding[].outstanding_tx\n")
		b.WriteString("  bindings[] mirrors with the same fields are also accepted\n")
		return b.String()
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
	return b.String()
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
	if len(status.PerBinding) > 0 {
		for _, binding := range status.PerBinding {
			sample := systemBufferSample{
				WorkerID:   binding.WorkerID,
				QueueID:    binding.QueueID,
				Ifindex:    binding.Ifindex,
				UMEMCap:    binding.UmemTotalFrames,
				UMEMUsed:   binding.UmemInflightFrames,
				TXRingCap:  binding.TxRingCapacity,
				TXRingUsed: binding.OutstandingTX,
			}
			if full, ok := bindings[systemBufferBindingKey{
				WorkerID: binding.WorkerID,
				QueueID:  binding.QueueID,
				Ifindex:  binding.Ifindex,
			}]; ok {
				sample.Slot = full.Slot
				sample.HasSlot = true
				sample.Interface = full.Interface
			}
			samples = append(samples, sample)
		}
	} else {
		for _, binding := range status.Bindings {
			samples = append(samples, systemBufferSample{
				Slot:       binding.Slot,
				HasSlot:    true,
				WorkerID:   binding.WorkerID,
				QueueID:    binding.QueueID,
				Ifindex:    binding.Ifindex,
				Interface:  binding.Interface,
				UMEMCap:    binding.UmemTotalFrames,
				UMEMUsed:   binding.UmemInflightFrames,
				TXRingCap:  binding.TxRingCapacity,
				TXRingUsed: binding.OutstandingTX,
			})
		}
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
