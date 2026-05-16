package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type systemBuffersUserspaceDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
}

func (f *systemBuffersUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

func TestShowTextSystemBuffersUsesUserspaceStatus(t *testing.T) {
	s := &Server{
		store: configstore.New(t.TempDir() + "/xpf.conf"),
		dp: &systemBuffersUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				PerBinding: []dpuserspace.BindingCountersSnapshot{
					{WorkerID: 0, QueueID: 0, Ifindex: 5, UmemTotalFrames: 1000, UmemInflightFrames: 800, TxRingCapacity: 100, OutstandingTX: 90},
				},
			},
		},
	}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "buffers"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{
		"Userspace Buffer Utilization:",
		"AF_XDP UMEM frames",
		"80.0% WARNING",
		"AF_XDP TX ring",
		"90.0% CRITICAL",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("ShowText(buffers) output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "No BPF maps available") {
		t.Fatalf("ShowText(buffers) fell back to BPF map output:\n%s", out)
	}
}

func TestShowTextSystemBuffersDetailIncludesUserspaceRows(t *testing.T) {
	s := &Server{
		store: configstore.New(t.TempDir() + "/xpf.conf"),
		dp: &systemBuffersUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				Bindings: []dpuserspace.BindingStatus{
					{Slot: 3, WorkerID: 2, QueueID: 1, Ifindex: 9, Interface: "ge-0-0-9", UmemTotalFrames: 100, UmemInflightFrames: 10, TxRingCapacity: 100, OutstandingTX: 10},
				},
			},
		},
	}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "buffers-detail"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	out := resp.GetOutput()
	if !strings.Contains(out, "worker 2/queue 1/slot 3/ge-0-0-9") {
		t.Fatalf("ShowText(buffers-detail) missing detail scope:\n%s", out)
	}
	if strings.Contains(out, "BPF Map Details") {
		t.Fatalf("ShowText(buffers-detail) fell back to BPF map detail:\n%s", out)
	}
}
