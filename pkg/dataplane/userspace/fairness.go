package userspace

import (
	"math"
	"sort"
)

type CoSFairnessRSSSummary struct {
	Ifindex             int
	QueueID             uint8
	ActiveFlows         uint64
	ActiveWorkers       uint64
	Cstruct             float64
	MaxWorkerFlowShare  float64
	SourceRowsTruncated bool
}

type cosFairnessRSSKey struct {
	ifindex int
	queueID uint8
}

type cosFairnessRSSAggregate struct {
	totalActiveFlows uint64
	activeWorkers    uint64
	maxWorkerFlows   uint32
	weightedMean     float64
	weightedM2       float64
}

func (a *cosFairnessRSSAggregate) add(active uint32) {
	if active == 0 {
		return
	}
	weight := float64(active)
	value := 1.0 / weight
	oldTotal := float64(a.totalActiveFlows)
	newTotal := oldTotal + weight
	delta := value - a.weightedMean
	a.weightedMean += (weight / newTotal) * delta
	a.weightedM2 += weight * delta * (value - a.weightedMean)

	a.totalActiveFlows += uint64(active)
	a.activeWorkers++
	if active > a.maxWorkerFlows {
		a.maxWorkerFlows = active
	}
}

func (a cosFairnessRSSAggregate) cstruct() float64 {
	if a.totalActiveFlows == 0 || a.weightedMean == 0 {
		return 0
	}
	variance := a.weightedM2 / float64(a.totalActiveFlows)
	if variance <= 0 {
		return 0
	}
	return math.Sqrt(variance) / a.weightedMean
}

func (a cosFairnessRSSAggregate) maxWorkerFlowShare() float64 {
	if a.totalActiveFlows == 0 {
		return 0
	}
	return float64(a.maxWorkerFlows) / float64(a.totalActiveFlows)
}

// CoSFairnessRSSSummaries derives the production/operator RSS-structure
// view from the low-frequency per-CoS active-flow snapshot. It is status
// math only: no packet-path state, no locks, no scheduler feedback.
func CoSFairnessRSSSummaries(status ProcessStatus) []CoSFairnessRSSSummary {
	byQueue := make(map[cosFairnessRSSKey]*cosFairnessRSSAggregate)
	for _, row := range status.CoSActiveFlowCounts {
		key := cosFairnessRSSKey{ifindex: row.Ifindex, queueID: row.QueueID}
		agg := byQueue[key]
		if agg == nil {
			agg = &cosFairnessRSSAggregate{}
			byQueue[key] = agg
		}
		agg.add(row.ActiveFlowCount)
	}

	keys := make([]cosFairnessRSSKey, 0, len(byQueue))
	for key := range byQueue {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ifindex != keys[j].ifindex {
			return keys[i].ifindex < keys[j].ifindex
		}
		return keys[i].queueID < keys[j].queueID
	})

	out := make([]CoSFairnessRSSSummary, 0, len(keys))
	for _, key := range keys {
		agg := byQueue[key]
		if agg == nil || agg.totalActiveFlows == 0 {
			continue
		}
		out = append(out, CoSFairnessRSSSummary{
			Ifindex:             key.ifindex,
			QueueID:             key.queueID,
			ActiveFlows:         agg.totalActiveFlows,
			ActiveWorkers:       agg.activeWorkers,
			Cstruct:             agg.cstruct(),
			MaxWorkerFlowShare:  agg.maxWorkerFlowShare(),
			SourceRowsTruncated: status.CoSActiveFlowCountsTruncated,
		})
	}
	return out
}
