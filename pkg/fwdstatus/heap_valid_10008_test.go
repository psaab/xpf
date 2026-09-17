package fwdstatus

import (
	"os"
	"regexp"
	"testing"
	"time"
)

var heapRow10008 = regexp.MustCompile(`(?m)^\s*Heap utilization\s+(.*?)\s*$`)

func heapCell10008(t *testing.T, out string) string {
	t.Helper()
	m := heapRow10008.FindStringSubmatch(out)
	if len(m) != 2 {
		t.Fatalf("no Heap utilization row in output:\n%s", out)
	}
	return m[1]
}

func TestHeapUnknownStatmErr10008(t *testing.T) {
	dp := &fakeDP{loaded: true}
	proc := freshProcReader()
	proc.selfStatmErr = os.ErrNotExist
	fs, err := Build(dp, proc, time.Now(), SamplerSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if fs.HeapPercentValid {
		t.Fatal("HeapPercentValid=true after /proc/self/statm failed")
	}
	if got := heapCell10008(t, Format(fs)); got != "-" {
		t.Errorf("unknown heap renders %q, want %q", got, "-")
	}
}

func TestHeapUnknownNoLimit10008(t *testing.T) {
	dp := &fakeDP{loaded: true}
	proc := freshProcReader()
	proc.memInfoErr = os.ErrNotExist // cgroup max is zero in the fixture
	fs, err := Build(dp, proc, time.Now(), SamplerSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if fs.HeapPercentValid {
		t.Fatal("HeapPercentValid=true without a usable memory limit")
	}
	if got := heapCell10008(t, Format(fs)); got != "-" {
		t.Errorf("unknown heap renders %q, want %q", got, "-")
	}
}

func TestHeapMeasuredZero10008(t *testing.T) {
	dp := &fakeDP{loaded: true}
	proc := freshProcReader()
	proc.selfStatm.ResidentPages = 0
	proc.cgroupMax = 1
	fs, err := Build(dp, proc, time.Now(), SamplerSnapshot{})
	if err != nil {
		t.Fatal(err)
	}
	if !fs.HeapPercentValid {
		t.Fatal("HeapPercentValid=false for a measured zero")
	}
	if got := heapCell10008(t, Format(fs)); got != "0 percent" {
		t.Errorf("measured zero heap renders %q, want %q", got, "0 percent")
	}
}
