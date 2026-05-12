package userspace

import (
	"math"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	fairnesscontract "github.com/psaab/xpf/pkg/fairness"
)

const maxFairnessRSSWorkerSlots = 4096

type CoSFairnessRSSSummary struct {
	Ifindex             int
	QueueID             uint8
	ActiveFlows         uint64
	ActiveWorkers       uint64
	MinWorkerFlows      uint32
	MaxWorkerFlows      uint32
	WorkerFlowCounts    []uint32
	Cstruct             float64
	MaxWorkerFlowShare  float64
	SourceRowsTruncated bool
}

type FairnessRSSExpectation struct {
	Ifindex        int
	QueueID        uint8
	RSSExpectation string
}

type FairnessRSSExpectationResult struct {
	Ifindex             int
	QueueID             uint8
	Expectation         string
	ExpectationKind     string
	ExpectationValue    float64
	HasExpectationValue bool
	Pass                bool
	Reason              string
	ActiveFlows         uint64
	ActiveWorkers       uint64
	Cstruct             float64
}

type cosFairnessRSSKey struct {
	ifindex int
	queueID uint8
}

type cosFairnessRSSAggregate struct {
	workerFlows map[uint32]uint32
}

func (a *cosFairnessRSSAggregate) add(workerID uint32, active uint32) {
	if a.workerFlows == nil {
		a.workerFlows = make(map[uint32]uint32)
	}
	a.workerFlows[workerID] += active
}

func (a cosFairnessRSSAggregate) summary(
	key cosFairnessRSSKey,
	workers int,
	truncated bool,
) CoSFairnessRSSSummary {
	workerIDs := make([]uint32, 0, len(a.workerFlows))
	for workerID := range a.workerFlows {
		workerIDs = append(workerIDs, workerID)
	}
	sort.Slice(workerIDs, func(i, j int) bool { return workerIDs[i] < workerIDs[j] })

	workerSlots := boundedFairnessRSSWorkerSlots(workers, len(workerIDs))
	distribution := make([]uint32, workerSlots)
	var overflow []uint32
	for _, workerID := range workerIDs {
		active := a.workerFlows[workerID]
		if workerID < uint32(workerSlots) {
			distribution[workerID] = active
			continue
		}
		if active > 0 {
			overflow = append(overflow, active)
		}
	}
	distribution = append(distribution, overflow...)
	return summarizeCoSFairnessRSSDistribution(key, distribution, truncated)
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
		agg.add(row.WorkerID, row.ActiveFlowCount)
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
		if agg == nil {
			continue
		}
		summary := agg.summary(key, status.Workers, status.CoSActiveFlowCountsTruncated)
		if summary.ActiveFlows == 0 {
			continue
		}
		out = append(out, summary)
	}
	return out
}

func summarizeCoSFairnessRSSDistribution(
	key cosFairnessRSSKey,
	distribution []uint32,
	truncated bool,
) CoSFairnessRSSSummary {
	var totalActiveFlows uint64
	var activeWorkers uint64
	var minWorkerFlows uint32
	var maxWorkerFlows uint32
	var weightedMean float64
	var weightedM2 float64
	for _, active := range distribution {
		if active == 0 {
			continue
		}
		weight := float64(active)
		value := 1.0 / weight
		oldTotal := float64(totalActiveFlows)
		newTotal := oldTotal + weight
		delta := value - weightedMean
		weightedMean += (weight / newTotal) * delta
		weightedM2 += weight * delta * (value - weightedMean)

		totalActiveFlows += uint64(active)
		activeWorkers++
		if minWorkerFlows == 0 || active < minWorkerFlows {
			minWorkerFlows = active
		}
		if active > maxWorkerFlows {
			maxWorkerFlows = active
		}
	}
	cstruct := 0.0
	if totalActiveFlows > 0 && weightedMean > 0 {
		variance := weightedM2 / float64(totalActiveFlows)
		if variance > 0 {
			cstruct = math.Sqrt(variance) / weightedMean
		}
	}
	maxWorkerFlowShare := 0.0
	if totalActiveFlows > 0 {
		maxWorkerFlowShare = float64(maxWorkerFlows) / float64(totalActiveFlows)
	}
	return CoSFairnessRSSSummary{
		Ifindex:             key.ifindex,
		QueueID:             key.queueID,
		ActiveFlows:         totalActiveFlows,
		ActiveWorkers:       activeWorkers,
		MinWorkerFlows:      minWorkerFlows,
		MaxWorkerFlows:      maxWorkerFlows,
		WorkerFlowCounts:    append([]uint32(nil), distribution...),
		Cstruct:             cstruct,
		MaxWorkerFlowShare:  maxWorkerFlowShare,
		SourceRowsTruncated: truncated,
	}
}

func FairnessRSSExpectationsFromConfig(cfg *config.Config) []FairnessRSSExpectation {
	if cfg == nil || cfg.ClassOfService == nil {
		return nil
	}
	out := make([]FairnessRSSExpectation, 0, len(cfg.ClassOfService.FairnessExpectations))
	for _, row := range cfg.ClassOfService.FairnessExpectations {
		if row == nil {
			continue
		}
		out = append(out, FairnessRSSExpectation{
			Ifindex:        row.Ifindex,
			QueueID:        row.QueueID,
			RSSExpectation: row.RSSExpectation,
		})
	}
	return out
}

func EvaluateFairnessRSSExpectations(
	status ProcessStatus,
	expectations []FairnessRSSExpectation,
) []FairnessRSSExpectationResult {
	if len(expectations) == 0 {
		return nil
	}
	summaries := CoSFairnessRSSSummaries(status)
	byQueue := make(map[cosFairnessRSSKey]CoSFairnessRSSSummary, len(summaries))
	for _, summary := range summaries {
		byQueue[cosFairnessRSSKey{ifindex: summary.Ifindex, queueID: summary.QueueID}] = summary
	}
	out := make([]FairnessRSSExpectationResult, 0, len(expectations))
	for _, expectation := range expectations {
		parsed, err := fairnesscontract.ParseRSSExpectation(expectation.RSSExpectation)
		key := cosFairnessRSSKey{ifindex: expectation.Ifindex, queueID: expectation.QueueID}
		summary, ok := byQueue[key]
		if !ok {
			summary = summarizeCoSFairnessRSSDistribution(
				key,
				make([]uint32, boundedFairnessRSSWorkerSlots(status.Workers, 0)),
				status.CoSActiveFlowCountsTruncated,
			)
		}
		result := fairnesscontract.RSSExpectationResult{Pass: false, Reason: errString(err)}
		canonical := expectation.RSSExpectation
		kind := "invalid"
		var value float64
		hasValue := false
		if err == nil {
			canonical = parsed.Canonical()
			kind = parsed.MetricKind()
			value, hasValue = parsed.MetricValue()
			result = fairnesscontract.EvaluateRSSExpectation(
				parsed,
				summary.WorkerFlowCounts,
				summary.Cstruct,
				fairnessRSSTotalWorkers(status.Workers, len(summary.WorkerFlowCounts)),
			)
		}
		out = append(out, FairnessRSSExpectationResult{
			Ifindex:             expectation.Ifindex,
			QueueID:             expectation.QueueID,
			Expectation:         canonical,
			ExpectationKind:     kind,
			ExpectationValue:    value,
			HasExpectationValue: hasValue,
			Pass:                result.Pass,
			Reason:              result.Reason,
			ActiveFlows:         summary.ActiveFlows,
			ActiveWorkers:       summary.ActiveWorkers,
			Cstruct:             summary.Cstruct,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ifindex != out[j].Ifindex {
			return out[i].Ifindex < out[j].Ifindex
		}
		if out[i].QueueID != out[j].QueueID {
			return out[i].QueueID < out[j].QueueID
		}
		return out[i].Expectation < out[j].Expectation
	})
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func boundedFairnessRSSWorkerSlots(workers int, fallback int) int {
	if workers > 0 {
		if workers > maxFairnessRSSWorkerSlots {
			return maxFairnessRSSWorkerSlots
		}
		return workers
	}
	if fallback < 0 {
		return 0
	}
	if fallback > maxFairnessRSSWorkerSlots {
		return maxFairnessRSSWorkerSlots
	}
	return fallback
}

func fairnessRSSTotalWorkers(workers int, fallback int) uint32 {
	return uint32(boundedFairnessRSSWorkerSlots(workers, fallback))
}
