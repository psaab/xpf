package fwdstatus

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #13299: frames stranded in DebugPendingFillFrames / DebugPendingTXPrepared /
// DebugPendingTXLocal are unavailable UMEM frames even while
// UmemInflightFrames and OutstandingTX are both zero, so they must contribute
// to Buffer% (which otherwise reports a confident 0% with BufferKnown=true).
func TestBuildBufferPercentIncludesPendingQueues(t *testing.T) {
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
	want := 100.0 * 3800.0 / 4096.0
	if fs.BufferPercent != want {
		t.Errorf("BufferPercent=%v, want %v (DebugPendingFillFrames holds 3800/4096 frames)", fs.BufferPercent, want)
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
