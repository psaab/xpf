package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type systemBuffersCLIUserspaceDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
	v4     int
	v6     int
}

func (f *systemBuffersCLIUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

func (f *systemBuffersCLIUserspaceDP) SessionCount() (int, int) {
	return f.v4, f.v6
}

func TestShowSystemBuffersUsesSharedUserspaceFormatter(t *testing.T) {
	c := &CLI{
		dp: &systemBuffersCLIUserspaceDP{
			Manager: dataplane.New(),
			v4:      2,
			v6:      1,
			status: dpuserspace.ProcessStatus{
				NeighborEntries: 8,
				PerBinding: []dpuserspace.BindingCountersSnapshot{
					{
						WorkerID:                    1,
						QueueID:                     2,
						Ifindex:                     7,
						UmemTotalFrames:             1000,
						UmemInflightFrames:          500,
						TxRingCapacity:              100,
						OutstandingTX:               20,
						ActiveFlowCount:             5,
						FlowCacheCollisionEvictions: 3,
						DbgTxRingFull:               4,
					},
				},
			},
		},
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.showSystemBuffers()
	})
	if callErr != nil {
		t.Fatalf("showSystemBuffers() error = %v", callErr)
	}
	for _, want := range []string{
		"Userspace Buffer Utilization:",
		"AF_XDP UMEM frames",
		"AF_XDP TX ring",
		"Userspace Status Counters:",
		"Neighbor cache entries",
		"Flow cache active flows",
		"Flow cache collision evict",
		"TX ring full events",
		"Active sessions: 2 IPv4, 1 IPv6, 3 total",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("showSystemBuffers output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "worker 1/queue 2") {
		t.Fatalf("showSystemBuffers included detail scope:\n%s", out)
	}
	if strings.Contains(out, "No BPF maps available") {
		t.Fatalf("showSystemBuffers fell back to BPF map output:\n%s", out)
	}
}
