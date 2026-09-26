package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

type chassisForwardingIdentityPeer10841 struct {
	pb.UnimplementedBpfrxServiceServer
	response *pb.ShowTextResponse
}

func (*chassisForwardingIdentityPeer10841) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

func (p *chassisForwardingIdentityPeer10841) ShowText(context.Context, *pb.ShowTextRequest) (*pb.ShowTextResponse, error) {
	return p.response, nil
}

func TestShowChassisForwardingUsesResponderIdentity10841(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := grpc.NewServer()
	pb.RegisterBpfrxServiceServer(peer, &chassisForwardingIdentityPeer10841{
		response: &pb.ShowTextResponse{Output: "peer-forwarding-data\n", ResponderNodeId: int32Ptr10841(1)},
	})
	go func() { _ = peer.Serve(listener) }()
	t.Cleanup(func() { peer.Stop(); _ = listener.Close() })

	_, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	oldPort := peerFabricGRPCPort
	peerFabricGRPCPort = portString
	t.Cleanup(func() { peerFabricGRPCPort = oldPort })

	s := NewServer("", Config{
		Store:   newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		Cluster: cluster.NewManager(0, 1),
		FabricPeerAddrFn: func() []string {
			return []string{"127.0.0.1"}
		},
	})
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "chassis-forwarding"})
	if err != nil {
		t.Fatalf("ShowText: %v", err)
	}
	if resp.ResponderNodeId == nil || *resp.ResponderNodeId != 0 {
		t.Fatalf("local response identity = %v, want node0", resp.ResponderNodeId)
	}
	if !strings.Contains(resp.Output, "node1:\n"+chassisForwardingSeparator) {
		t.Fatalf("peer block was not labelled from responder identity:\n%s", resp.Output)
	}
	if !strings.Contains(resp.Output, "peer-forwarding-data") {
		t.Fatalf("peer output missing:\n%s", resp.Output)
	}
}

func TestShowTextOnlySetsResponderIdentityForClusterForwarding10841(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	clusterServer := NewServer("", Config{Store: store, Cluster: cluster.NewManager(1, 1)})
	clusterResp, err := clusterServer.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "chassis-forwarding"})
	if err != nil {
		t.Fatalf("cluster ShowText: %v", err)
	}
	if clusterResp.ResponderNodeId == nil || *clusterResp.ResponderNodeId != 1 {
		t.Fatalf("cluster responder identity = %v, want node1", clusterResp.ResponderNodeId)
	}

	standalone := NewServer("", Config{Store: store})
	standaloneResp, err := standalone.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "chassis-forwarding"})
	if err != nil {
		t.Fatalf("standalone ShowText: %v", err)
	}
	if standaloneResp.ResponderNodeId != nil {
		t.Fatalf("standalone responder identity = %v, want absent", standaloneResp.ResponderNodeId)
	}
	otherTopic, err := clusterServer.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "version"})
	if err != nil {
		t.Fatalf("version ShowText: %v", err)
	}
	if otherTopic.ResponderNodeId != nil {
		t.Fatalf("non-forwarding responder identity = %v, want absent", otherTopic.ResponderNodeId)
	}
}

func TestChassisForwardingPeerLabelChecksBelief10841(t *testing.T) {
	cases := []struct {
		name        string
		responderID *int32
		peerAlive   bool
		expectedID  int
		want        string
	}{
		{name: "responder cannot identify", want: "node?"},
		{name: "peer heartbeat stale but response identifies", responderID: int32Ptr10841(1), want: "node1"},
		{name: "belief matches", responderID: int32Ptr10841(1), peerAlive: true, expectedID: 1, want: "node1"},
		{name: "belief diverges", responderID: int32Ptr10841(0), peerAlive: true, expectedID: 1, want: "node0 (identity mismatch: expected node1)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := chassisForwardingPeerLabel(tc.responderID, tc.peerAlive, tc.expectedID); got != tc.want {
				t.Fatalf("chassisForwardingPeerLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}
func int32Ptr10841(value int32) *int32 { return &value }
