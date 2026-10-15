package api

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type helperDownEventStreamDP13296 struct {
	*dataplane.Manager
	status dpuserspace.EventStreamStatus
}

func (*helperDownEventStreamDP13296) IsLoaded() bool { return true }

func (*helperDownEventStreamDP13296) Status() (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, errors.New("helper is down")
}

func (d *helperDownEventStreamDP13296) UserspaceEventStreamStatus() dpuserspace.EventStreamStatus {
	return d.status
}

// This drives the real Prometheus Collect path with a dataplane whose helper
// Status() fails. Daemon-owned event-stream counters must remain scrapeable
// without publishing stale helper status or zero-valued helper producer data.
func TestEventStreamCountersScrapeWhileHelperDown13296(t *testing.T) {
	dp := &helperDownEventStreamDP13296{
		Manager: dataplane.New(),
		status: dpuserspace.EventStreamStatus{
			FramesRead:        42,
			FramesWritten:     7,
			DecodeErrors:      3,
			SeqGaps:           2,
			PolicyDenyEvents:  17,
			UnknownFrameDrops: 1,
		},
	}
	c := newCollector(&Server{
		dp:        dp,
		store:     newDescriptorCoverageStore(t),
		startTime: time.Now(),
	})
	ch := make(chan prometheus.Metric, 8192)
	done := make(chan struct{})
	go func() {
		c.Collect(ch)
		close(ch)
		close(done)
	}()

	frames := map[string]float64{}
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
			decodeErrors = value
		case "xpf_userspace_event_stream_sequence_gaps_total":
			sequenceGaps = value
		case "xpf_userspace_event_stream_unknown_frame_drops_total":
			unknownDrops = value
		case "xpf_userspace_event_stream_dataplane_events_total":
			for _, label := range pb.GetLabel() {
				if label.GetName() == "type" && label.GetValue() == "policy_deny" {
					policyDeny = value
				}
			}
		case "xpf_userspace_event_stream_producer_frames_total":
			helperProducerMetrics = true
		}
	}

	if frames["read"] != 42 || frames["written"] != 7 {
		t.Errorf("event-stream frame counters = %v, want read=42 written=7", frames)
	}
	if decodeErrors != 3 || sequenceGaps != 2 || unknownDrops != 1 || policyDeny != 17 {
		t.Errorf("event-stream status counters decode=%v gaps=%v unknown_drops=%v policy_deny=%v; want 3,2,1,17",
			decodeErrors, sequenceGaps, unknownDrops, policyDeny)
	}
	if helperProducerMetrics {
		t.Error("helper producer counters emitted despite helper Status() failing")
	}
}
