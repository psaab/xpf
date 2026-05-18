package grpcapi

import (
	"context"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeUserspaceInjectControl struct {
	dataplane.DataPlane
	status dpuserspace.ProcessStatus
	got    dpuserspace.InjectPacketRequest
}

func (f *fakeUserspaceInjectControl) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

func (f *fakeUserspaceInjectControl) SetForwardingArmed(bool) (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, nil
}

func (f *fakeUserspaceInjectControl) SetQueueState(uint32, bool, bool) (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, nil
}

func (f *fakeUserspaceInjectControl) SetBindingState(uint32, bool, bool) (dpuserspace.ProcessStatus, error) {
	return dpuserspace.ProcessStatus{}, nil
}

func (f *fakeUserspaceInjectControl) InjectPacket(req dpuserspace.InjectPacketRequest) (dpuserspace.ProcessStatus, error) {
	f.got = req
	return dpuserspace.ProcessStatus{PID: 1234}, nil
}

func TestSystemActionClusterFailoverProxiesPeerTarget(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	var gotAction string
	var forwarded bool
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		gotAction = req.Action
		md, ok := metadata.FromOutgoingContext(ctx)
		forwarded = ok && len(md.Get("x-peer-forwarded")) > 0
		return &pb.SystemActionResponse{Message: "proxied"}, nil
	}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v", err)
	}
	if gotAction != "cluster-failover:1:node1" {
		t.Fatalf("proxied action = %q, want %q", gotAction, "cluster-failover:1:node1")
	}
	if !forwarded {
		t.Fatal("expected x-peer-forwarded metadata on proxied system action")
	}
	if resp.Message != "proxied" {
		t.Fatalf("response = %q, want %q", resp.Message, "proxied")
	}
}

func TestSystemActionClusterFailoverRejectsForwardLoop(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-peer-forwarded", "1"))
	_, err := s.SystemAction(ctx, &pb.SystemActionRequest{Action: "cluster-failover:1:node1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.FailedPrecondition, err)
	}
}

func TestSystemActionClusterFailoverDataProxiesPeerTarget(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	var gotAction string
	var forwarded bool
	s.peerSystemActionFn = func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
		gotAction = req.Action
		md, ok := metadata.FromOutgoingContext(ctx)
		forwarded = ok && len(md.Get("x-peer-forwarded")) > 0
		return &pb.SystemActionResponse{Message: "proxied-data"}, nil
	}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover-data:node1"})
	if err != nil {
		t.Fatalf("SystemAction() error = %v", err)
	}
	if gotAction != "cluster-failover-data:node1" {
		t.Fatalf("proxied action = %q, want %q", gotAction, "cluster-failover-data:node1")
	}
	if !forwarded {
		t.Fatal("expected x-peer-forwarded metadata on proxied system action")
	}
	if resp.Message != "proxied-data" {
		t.Fatalf("response = %q, want %q", resp.Message, "proxied-data")
	}
}

func TestSystemActionClusterFailoverDataRejectsForwardLoop(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-peer-forwarded", "1"))
	_, err := s.SystemAction(ctx, &pb.SystemActionRequest{Action: "cluster-failover-data:node1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.FailedPrecondition, err)
	}
}

func TestSystemActionClusterFailoverDataRejectsUnsupportedTargetNode(t *testing.T) {
	s := NewServer("", Config{Cluster: cluster.NewManager(0, 1)})

	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "cluster-failover-data:node2"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %s, want %s (err=%v)", status.Code(err), codes.InvalidArgument, err)
	}
}

func TestSystemActionUserspaceInjectDecodesEmitOnWireTargetExtras(t *testing.T) {
	dp := &fakeUserspaceInjectControl{
		status: dpuserspace.ProcessStatus{
			InjectPacketTupleProtocolVersion: dpuserspace.InjectPacketTupleProtocolVersion,
			LastSnapshotGeneration:           11,
			LastFIBGeneration:                12,
		},
	}
	s := NewServer("", Config{DP: dp})
	target := dpuserspace.EncodeInjectPacketTarget(map[string]string{
		"destination-ip":   "172.16.80.200",
		"emit-on-wire":     "true",
		"source-ip":        "172.16.80.8",
		"source-port":      "7",
		"destination-port": "0",
		"protocol":         "icmp",
	})

	_, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{
		Action: "userspace-inject:7:valid",
		Target: target,
	})
	if err != nil {
		t.Fatalf("SystemAction() error = %v", err)
	}
	if !dp.got.EmitOnWire {
		t.Fatal("remote userspace inject request lost emit-on-wire")
	}
	if dp.got.TupleMetadataVersion != dpuserspace.InjectPacketTupleProtocolVersion {
		t.Fatalf("TupleMetadataVersion = %d, want %d", dp.got.TupleMetadataVersion, dpuserspace.InjectPacketTupleProtocolVersion)
	}
	if dp.got.AddrFamily != uint8(syscall.AF_INET) || dp.got.Protocol != 1 {
		t.Fatalf("family/protocol = %d/%d, want AF_INET/ICMP", dp.got.AddrFamily, dp.got.Protocol)
	}
	if dp.got.SourceIP != "172.16.80.8" || dp.got.DestinationIP != "172.16.80.200" {
		t.Fatalf("tuple IPs = %s -> %s", dp.got.SourceIP, dp.got.DestinationIP)
	}
	if dp.got.SourcePort == nil || *dp.got.SourcePort != 7 {
		t.Fatalf("SourcePort = %v, want 7", dp.got.SourcePort)
	}
	if dp.got.DestinationPort == nil || *dp.got.DestinationPort != 0 {
		t.Fatalf("DestinationPort = %v, want 0", dp.got.DestinationPort)
	}
}
