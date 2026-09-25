package grpcapi

import (
	"context"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type largeOSPFExec10708 struct {
	frr.RecordingExecutor
	mu     sync.Mutex
	output string
}

func (e *largeOSPFExec10708) setOutput(output string) {
	e.mu.Lock()
	e.output = output
	e.mu.Unlock()
}

func (e *largeOSPFExec10708) Vtysh(context.Context, string) (string, error) {
	e.mu.Lock()
	output := e.output
	e.mu.Unlock()
	return output, nil
}

func TestPrimaryServerBoundsOutboundMessages10708(t *testing.T) {
	usePasswdFixture5278(t)
	store := authzStore5278(t, authzConfig5278)
	exec := &largeOSPFExec10708{}
	s := NewServer("127.0.0.1:0", Config{
		Store:        store,
		FRR:          frr.NewForTest(t.TempDir()+"/frr.conf", exec),
		PeerLookupFn: fixedPeerUID5278(authzUIDReadOnly),
	})
	addr := serveAndWait(t, s)
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxSendMsgSize+(2<<20))),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)

	exec.setOutput(strings.Repeat("x", 16<<20))
	if _, err := client.GetOSPFStatus(callCtx(t), &pb.GetOSPFStatusRequest{Type: "database"}); err != nil {
		t.Fatalf("16 MiB diagnostic response should fit the 17 MiB send ceiling: %v", err)
	}

	overLimitSize := maxSendMsgSize + (1 << 20)
	exec.setOutput(strings.Repeat("x", overLimitSize))
	_, err = client.GetOSPFStatus(callCtx(t), &pb.GetOSPFStatusRequest{Type: "database"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("%d-byte outbound response -> %v, want ResourceExhausted at %d-byte server cap",
			overLimitSize, status.Code(err), maxSendMsgSize)
	}
}
