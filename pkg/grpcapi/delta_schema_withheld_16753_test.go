package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

// #16753: the remote `show chassis cluster statistics` surface must read the
// same #7194 withheld-batch counter as the console.

func TestShowChassisClusterStatisticsReportsDeltaSchemaWithheld16753(t *testing.T) {
	s := &Server{
		cluster:               cluster.NewManager(0, 1),
		deltaSchemaWithheldFn: func() uint64 { return 5 },
	}
	var buf strings.Builder
	s.showChassisClusterStatistics(&buf)
	if !strings.Contains(buf.String(), "Session-delta schema batches withheld: 5") {
		t.Fatalf("#16753: statistics must surface the withheld count:\n%s", buf.String())
	}

	s.deltaSchemaWithheldFn = func() uint64 { return 0 }
	buf.Reset()
	s.showChassisClusterStatistics(&buf)
	if strings.Contains(buf.String(), "Session-delta schema batches withheld") {
		t.Fatalf("zero withheld count must be silent:\n%s", buf.String())
	}
}
