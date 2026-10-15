package api

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type helperDownEventStreamDP13296 struct {
	*dpuserspace.LegacyDataPlaneAdapter
}

func (*helperDownEventStreamDP13296) IsLoaded() bool { return true }

// This drives the real Prometheus Collect path with a dataplane whose helper
// Status() fails. Daemon-owned event-stream counters must remain scrapeable
// without publishing stale helper status or zero-valued helper producer data.
func TestEventStreamCountersScrapeWhileHelperDown13296(t *testing.T) {
	adapter := dpuserspace.NewLegacyDataPlaneAdapter(&dpuserspace.Manager{})
	adapter.DataPlane = dataplane.New()
	dp := &helperDownEventStreamDP13296{LegacyDataPlaneAdapter: adapter}
	c := newCollector(&Server{
		dp:        dp,
		store:     newDescriptorCoverageStore(t),
		startTime: time.Now(),
	})
	ch := make(chan prometheus.Metric, 8192)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	frames := map[string]float64{}
	seen := map[string]bool{}
	var decodeErrors, sequenceGaps, unknownDrops, policyDeny float64
	var helperProducerMetrics bool
	for metric := range ch {
		var pb dto.Metric
		if err := metric.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		name := metric.Desc().String()
		const key = `fqName: "`
		if i := strings.Index(name, key); i >= 0 {
			rest := name[i+len(key):]
			if j := strings.Index(rest, `"`); j > 0 {
				name = rest[:j]
			}
		}
		value := pb.GetCounter().GetValue()
		switch name {
		case "xpf_userspace_event_stream_frames_total":
			for _, label := range pb.GetLabel() {
				if label.GetName() == "direction" {
					frames[label.GetValue()] = value
				}
			}
		case "xpf_userspace_event_stream_decode_errors_total":
			seen[name] = true
			decodeErrors = value
		case "xpf_userspace_event_stream_sequence_gaps_total":
			seen[name] = true
			sequenceGaps = value
		case "xpf_userspace_event_stream_unknown_frame_drops_total":
			seen[name] = true
			unknownDrops = value
		case "xpf_userspace_event_stream_dataplane_events_total":
			for _, label := range pb.GetLabel() {
				if label.GetName() == "type" && label.GetValue() == "policy_deny" {
					seen["policy_deny"] = true
					policyDeny = value
				}
			}
		case "xpf_userspace_event_stream_producer_frames_total":
			helperProducerMetrics = true
		}
	}

	if len(frames) != 2 || frames["read"] != 0 || frames["written"] != 0 {
		t.Errorf("event-stream frame counters = %v, want zero-valued read and written series", frames)
	}
	if !seen["xpf_userspace_event_stream_decode_errors_total"] ||
		!seen["xpf_userspace_event_stream_sequence_gaps_total"] ||
		!seen["xpf_userspace_event_stream_unknown_frame_drops_total"] ||
		!seen["policy_deny"] {
		t.Errorf("daemon-owned event-stream series missing while helper is down: %v", seen)
	}
	if decodeErrors != 0 || sequenceGaps != 0 || unknownDrops != 0 || policyDeny != 0 {
		t.Errorf("event-stream status counters decode=%v gaps=%v unknown_drops=%v policy_deny=%v; want zero",
			decodeErrors, sequenceGaps, unknownDrops, policyDeny)
	}
	if helperProducerMetrics {
		t.Error("helper producer counters emitted despite helper Status() failing")
	}
}
