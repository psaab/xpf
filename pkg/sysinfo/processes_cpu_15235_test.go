package sysinfo

import (
	"strings"
	"testing"
	"time"
)

// TestCPUIntervalShowsBusy15235 is the A51-06 regression: two snapshots
// where the interval is busy must render busy, not the cumulative
// since-boot ratio (which is idle-dominated on a long-up host).
func TestCPUIntervalShowsBusy15235(t *testing.T) {
	// Cumulative: huge idle dominates. Interval: 80 user, 10 system, 10 idle (+iowait/steal dilution).
	a := cpuSample{user: 100, nice: 0, system: 50, idle: 10000, iowait: 100, irq: 0, softirq: 0, steal: 0}
	b := cpuSample{user: 180, nice: 0, system: 60, idle: 10010, iowait: 105, irq: 0, softirq: 0, steal: 5}
	u, s, i := cpuPercents(a, b)
	// total delta = 80+10+10+5+5 = 110
	if u < 72 || u > 73 {
		t.Fatalf("user%% = %.2f, want ~72.7 (busy interval); cumulative would be ~1%%", u)
	}
	if s < 9 || s > 10 {
		t.Fatalf("sys%% = %.2f, want ~9.1", s)
	}
	if i < 9 || i > 10 {
		t.Fatalf("idle%% = %.2f, want ~9.1", i)
	}
	// All-fields denominator: iowait+steal dilute so buckets sum < 100.
	if u+s+i > 99 {
		t.Fatalf("buckets sum %.2f, want <100 (iowait/steal in denominator)", u+s+i)
	}
}

func TestParseCPUSample15235(t *testing.T) {
	s, ok := parseCPUSample([]byte("cpu  100 10 50 1000 20 1 2 3 4 5\ncpu0 1 1 1 1 0 0 0 0 0 0\n"))
	if !ok || s.user != 100 || s.nice != 10 || s.system != 50 || s.idle != 1000 || s.iowait != 20 || s.irq != 1 || s.softirq != 2 || s.steal != 3 {
		t.Fatalf("parse = %+v ok=%v", s, ok)
	}
	if _, ok := parseCPUSample([]byte("cpu0 1 1 1 1\n")); ok {
		t.Fatal("cpu0-only accepted, want aggregate only")
	}
}

// TestWriteProcessesSummaryCPUDelta15235 drives the real renderer with
// stubbed snapshots: first idle-heavy cumulative, second busy interval.
func TestWriteProcessesSummaryCPUDelta15235(t *testing.T) {
	origRead, origSleep := readProcStat, cpuSleep
	defer func() { readProcStat, cpuSleep = origRead, origSleep }()
	calls := 0
	readProcStat = func() ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte("cpu  100 0 50 10000 100 0 0 0 0 0\n"), nil
		}
		return []byte("cpu  180 0 60 10010 105 0 0 5 0 0\n"), nil
	}
	slept := time.Duration(0)
	cpuSleep = func(d time.Duration) { slept = d }
	var out strings.Builder
	WriteProcessesSummary(&out, []byte("PID USER PRI NI VSZ RSS STAT TIME %CPU COMMAND\n42 root 20 0 2048 1024 R 00:01 12.5 fixture\n"))
	if slept != cpuInterval {
		t.Fatalf("sleep = %v, want %v", slept, cpuInterval)
	}
	if !strings.Contains(out.String(), "CPU: 72.7% user, 9.1% system, 9.1% idle") {
		t.Fatalf("CPU line not interval-busy:\n%s", out.String())
	}
}
