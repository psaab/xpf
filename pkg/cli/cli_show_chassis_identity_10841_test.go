package cli

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestShowChassisForwardingLabelsBlockFromResponderIdentity10841(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	pb.RegisterBpfrxServiceServer(server, &chassisForwardingIdentityPeer10841{
		response: &pb.ShowTextResponse{Output: "peer-forwarding-data\n", ResponderNodeId: int32Ptr10841(1)},
	})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	_, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	c := &CLI{
		store:            newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		cluster:          cluster.NewManager(0, 1),
		fabricPeerAddrFn: func() []string { return []string{"127.0.0.1"} },
		fabricPeerPort:   port,
		startTime:        time.Now(),
	}

	output := captureStdout(t, func() {
		if err := c.showChassisForwarding(); err != nil {
			t.Fatalf("showChassisForwarding: %v", err)
		}
	})
	if !strings.Contains(output, "node1:\n"+chassisForwardingSeparator) {
		t.Fatalf("peer block was not labelled from the responder identity:\n%s", output)
	}
	if strings.Contains(output, "node?:") {
		t.Fatalf("known responder identity was rendered as unknown:\n%s", output)
	}
	if !strings.Contains(output, "peer-forwarding-data") {
		t.Fatalf("peer output missing:\n%s", output)
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
