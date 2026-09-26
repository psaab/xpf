package fwdstatus

// #10842: the sampler presented aged/held data as current. CPU windows
// anchored to the newest SAMPLE wall and ignored Snapshot.Now, so after
// a sampler stall the last pre-stall 5s/1m/5m windows rendered as
// current indefinitely. Worker telemetry misses held both counters and
// the dead interval was silently averaged into live windows.

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// A snapshot whose newest sample is 30s old must render every window
// invalid — the pre-stall values are history, not current state.
func TestComputeCPUWindows_StaleSnapshotInvalid10842(t *testing.T) {
	base := time.Unix(2_000_000, 0)
	snap := buildSnapshot(base, 400, 500_000_000, 800_000_000, 2)
	snap.Now = base.Add(30 * time.Second) // sampler stalled 30s ago
	_, _, dValid, wValid := computeCPUWindows(snap)
	for i, label := range []string{"5s", "1m", "5m"} {
		if dValid[i] {
			t.Errorf("stale snapshot: daemon %s should be invalid", label)
		}
		if wValid[i] {
			t.Errorf("stale snapshot: worker %s should be invalid", label)
		}
	}
}

// Boundary: age == 2x interval is still usable, age > 2x is stale.
func TestComputeCPUWindows_StaleBoundary10842(t *testing.T) {
	base := time.Unix(2_000_000, 0)
	snap := buildSnapshot(base, 400, 500_000_000, 800_000_000, 2)
	snap.Now = base.Add(2 * SampleInterval)
	if _, _, dValid, _ := computeCPUWindows(snap); !dValid[CPUWindow5s] {
		t.Error("age == 2x interval: daemon 5s should still be valid")
	}
	snap.Now = base.Add(2*SampleInterval + time.Nanosecond)
	_, _, dValid, wValid := computeCPUWindows(snap)
	for i, label := range []string{"5s", "1m", "5m"} {
		if dValid[i] {
			t.Errorf("age > 2x interval: daemon %s should be invalid", label)
		}
		if wValid[i] {
			t.Errorf("age > 2x interval: worker %s should be invalid", label)
		}
	}
}

// A worker-telemetry miss inside an advancing window must invalidate
// the worker windows — not silently average the dead interval into a
// plausible-looking rate. The daemon window over the same span stays
// valid: /proc counters kept advancing through the miss.
func TestComputeCPUWindows_HeldWorkerSampleInvalidatesWorkerOnly10842(t *testing.T) {
	now := time.Now()
	acc := &countingAccessor{cachedHasVal: true}
	s := NewSampler(acc, fixedProcReader{})
	for i := 0; i < 10; i++ {
		acc.status.WorkerRuntime = []userspace.WorkerRuntimeStatus{{
			ThreadCPUNS: uint64(i+1) * 500_000_000,
			WallNS:      uint64(i+1) * 1_000_000_000,
		}}
		// Miss one tick inside the eventual 5s window span.
		acc.cachedHasVal = i != 7
		s.sample(now.Add(time.Duration(i-9) * time.Second))
	}
	snap := s.Snapshot()
	if len(snap.Samples) != 10 {
		t.Fatalf("snapshot has %d samples; want 10", len(snap.Samples))
	}
	_, _, dValid, wValid := computeCPUWindows(snap)
	if !dValid[CPUWindow5s] {
		t.Error("daemon 5s should stay valid across a worker-telemetry miss")
	}
	if wValid[CPUWindow5s] {
		t.Error("worker 5s spans a held sample: should be invalid, not an averaged rate")
	}
}

// The runtime USER_HZ value drives tick conversion, including kernels
// where it is not the common 100 Hz value.
func TestTicksToNanosUsesNon100HZ10842(t *testing.T) {
	if got := ticksToNanosAtHZ(250, 250); got != 1_000_000_000 {
		t.Errorf("250 ticks at 250 Hz = %d ns, want 1s", got)
	}
	if got := ticksToNanosAtHZ(100, 250); got != 400_000_000 {
		t.Errorf("100 ticks at 250 Hz = %d ns, want 400ms", got)
	}
	if got := ticksToNanos(uint64(userHZ)); got != 1_000_000_000 {
		t.Errorf("runtime USER_HZ (%d) conversion = %d ns, want 1s", userHZ, got)
	}
}

// /proc/self/statm reports resident pages, so heap accounting must use
// the runtime page size rather than retain a 4 KiB assumption.
func TestBuildHeapUsesRuntimePageSize10842(t *testing.T) {
	originalPageSize := systemPageSize
	systemPageSize = 16 * 1024
	defer func() { systemPageSize = originalPageSize }()

	proc := freshProcReader()
	proc.selfStatm.ResidentPages = 1
	proc.cgroupMax = uint64(systemPageSize * 100)
	fs, err := Build(nil, proc, time.Now(), SamplerSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if !fs.HeapPercentValid || fs.HeapPercent != 1 {
		t.Errorf("heap = %v valid=%v with 16 KiB pages, want 1%% valid",
			fs.HeapPercent, fs.HeapPercentValid)
	}
}

func TestBuildRendersStaleCPUAsInvalidAndAnnotated10842(t *testing.T) {
	base := time.Unix(2_000_000, 0)
	snap := buildSnapshot(base, 400, 500_000_000, 800_000_000, 2)
	snap.Now = base.Add(30 * time.Second)
	fs, err := Build(nil, freshProcReader(), time.Now(), snap)
	if err != nil {
		t.Fatal(err)
	}
	if !fs.CPUDataStale {
		t.Fatal("Build did not mark the aged snapshot stale")
	}
	for i, valid := range fs.DaemonCPUWindowValid {
		if valid {
			t.Errorf("stale daemon window %d is still marked valid", i)
		}
	}
	out := Format(fs)
	if !contains(out, "Daemon CPU utilization") ||
		!contains(out, "(stale sample)") {
		t.Errorf("stale windows must render invalid with an explicit note:\n%s", out)
	}
}

func TestFormatAnnotatesBusyPollCPUFalsePositive10842(t *testing.T) {
	fs := &ForwardingStatus{WorkerCPUMode: CPUModeWorkers}
	if out := Format(fs); !contains(out, "busy-poll can show ~100% idle") {
		t.Errorf("userspace worker CPU row must annotate busy-poll false-positive:\n%s", out)
	}
}

func TestFormatAnnotatesApproximateSchedulerRate10842(t *testing.T) {
	fs := &ForwardingStatus{UserHZApprox: true}
	if out := Format(fs); !contains(out, "approx: assumes USER_HZ=100") {
		t.Errorf("fallback scheduler rate must be labeled approximate:\n%s", out)
	}
}
