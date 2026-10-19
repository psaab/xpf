package main

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #15690: the remote CLI dispatched only `show security vrrp` to
// GetVRRPStatus; the top-level Junos spelling `show vrrp` fell through to
// "unknown show target: vrrp". Both spellings must reach the same RPC.

type vrrpFake15690 struct {
	fakeBpfrxClient
	calls int
	resp  *pb.GetVRRPStatusResponse
}

func (f *vrrpFake15690) GetVRRPStatus(
	_ context.Context, _ *pb.GetVRRPStatusRequest, _ ...grpc.CallOption,
) (*pb.GetVRRPStatusResponse, error) {
	f.calls++
	if f.resp != nil {
		return f.resp, nil
	}
	return &pb.GetVRRPStatusResponse{}, nil
}

func TestShowVRRPTopLevelDispatch15690(t *testing.T) {
	fake := &vrrpFake15690{resp: &pb.GetVRRPStatusResponse{
		Instances: []*pb.VRRPInstanceInfo{
			{Interface: "reth0", GroupId: 101, State: "MASTER", Priority: 200, VirtualAddresses: []string{"10.0.61.1/24"}, Preempt: true},
		},
	}}
	c := &ctl{client: fake}

	if err := c.handleShow([]string{"vrrp"}); err != nil {
		t.Fatalf("handleShow(show vrrp): %v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("#15690: top-level `show vrrp` must call GetVRRPStatus once, got %d calls", fake.calls)
	}

	// Control: the security spelling keeps reaching the same RPC.
	if err := c.handleShow([]string{"security", "vrrp"}); err != nil {
		t.Fatalf("handleShow(show security vrrp): %v", err)
	}
	if fake.calls != 2 {
		t.Fatalf("#15690: `show security vrrp` must still call GetVRRPStatus, got %d calls total", fake.calls)
	}
}
