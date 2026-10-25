package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// #16753: the #7194 withheld-batch counter must have a real `show` reader.
// Before this, UserspaceDeltaSchemaWithheldCount had no production reader,
// so the only operator signal was the once-per-episode warning.

func TestShowChassisClusterStatisticsReportsDeltaSchemaWithheld16753(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	manager := cluster.NewManager(0, 1)
	c := &CLI{cluster: manager, store: store}
	c.SetDeltaSchemaWithheldFn(func() uint64 { return 3 })

	var runErr error
	out := captureStdout(t, func() { runErr = c.showChassisClusterStatistics() })
	if runErr != nil {
		t.Fatalf("show chassis cluster statistics: %v", runErr)
	}
	if !strings.Contains(out, "Session-delta schema batches withheld: 3") {
		t.Fatalf("#16753: statistics must surface the withheld count:\n%s", out)
	}

	// Zero is silent: a healthy cluster's output is unchanged.
	c.SetDeltaSchemaWithheldFn(func() uint64 { return 0 })
	out = captureStdout(t, func() { runErr = c.showChassisClusterStatistics() })
	if runErr != nil {
		t.Fatalf("show chassis cluster statistics: %v", runErr)
	}
	if strings.Contains(out, "Session-delta schema batches withheld") {
		t.Fatalf("zero withheld count must be silent:\n%s", out)
	}
}
