package fwdstatus

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #13299: fill-ring inventory is idle by design. It must remain separately
// observable without being mistaken for UMEM in-flight saturation.
func TestBuildBufferPercentPreservesIdlePendingFill(t *testing.T) {
	now := time.Now()
	dp := &fakeUserspaceDP{
		fakeDP: fakeDP{loaded: true},
		status: userspace.ProcessStatus{
			WorkerHeartbeats: []time.Time{now.Add(-100 * time.Millisecond)},
			Bindings: []userspace.BindingStatus{{
				UmemTotalFrames:        4096,
				DebugPendingFillFrames: 3800,
			}},
		},
	}
	fs, err := Build(dp, freshProcReader(), time.Now(), SamplerSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if !fs.BufferKnown {
		t.Fatal("BufferKnown must be true when a binding publishes capacities")
	}
	if fs.BufferPercent != 0 {
		t.Errorf("BufferPercent=%v, want 0: idle pending-fill inventory is not in-flight utilization", fs.BufferPercent)
	}
}

func TestSamplerReadErrorsArePublished(t *testing.T) {
	proc := freshProcReader()
	proc.selfStatErr = errors.New("stat gone")
	sampler := NewSampler(nil, proc)
	sampler.sample(time.Now())
	if got := sampler.Snapshot().ReadErrors; got != 1 {
		t.Fatalf("sampler read errors: got %d, want 1 after failed ReadSelfStat", got)
	}
}
