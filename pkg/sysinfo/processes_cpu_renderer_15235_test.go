package sysinfo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Renderer-level A51-06 check: with a busy interval the CPU line must
// not be the cumulative idle ratio. This compiles on base (uses only
// WriteProcessesSummary) but on base it returns instantly with the
// cumulative line; the interval implementation takes >=400ms. The
// busy assertion itself lives in processes_cpu_15235_test.go.
func TestWriteProcessesSummaryTakesInterval15235(t *testing.T) {
	// Only run on a host where /proc/stat exists.
	if _, err := os.Stat(filepath.Join("/proc/stat")); err != nil {
		t.Skip("no /proc/stat")
	}
	start := time.Now()
	var out strings.Builder
	WriteProcessesSummary(&out, []byte("PID USER PRI NI VSZ RSS STAT TIME %CPU COMMAND\n42 root 20 0 2048 1024 R 00:01 12.5 fixture\n"))
	if elapsed := time.Since(start); elapsed < 400*time.Millisecond {
		t.Fatalf("WriteProcessesSummary returned in %v, want interval sampling >=400ms (pre-fix single cumulative read)", elapsed)
	}
	if !strings.Contains(out.String(), "CPU:") {
		t.Fatalf("missing CPU line:\n%s", out.String())
	}
}
