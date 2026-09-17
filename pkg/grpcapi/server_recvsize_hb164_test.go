package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// fable-review-164 H-2: the gRPC server must cap inbound message size so an
// oversized Load / config-sync payload is rejected at the transport with
// ResourceExhausted, never buffered and fed to the parser. This stands up the
// real service over bufconn with the production grpc.MaxRecvMsgSize option and
// confirms an over-cap Load is rejected while a normal Load succeeds.
func TestGRPCLoadRejectsOversizedMessage(t *testing.T) {
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}

	lis := bufconn.Listen(1 << 20)
	s := &Server{store: store}
	srv := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			ctx = context.WithValue(ctx, connPeerKey{}, &connPeer{
				id: authz.PeerIdentity{UID: 0, OK: true, Local: true},
			})
			return handler(ctx, req)
		}),
	)
	pb.RegisterBpfrxServiceServer(srv, s)
	go srv.Serve(lis)
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()
	client := pb.NewBpfrxServiceClient(conn)

	// Over the server's receive cap -> ResourceExhausted before the handler.
	oversized := strings.Repeat("a", maxRecvMsgSize+(1<<20))
	_, err = client.Load(context.Background(), &pb.LoadRequest{Mode: "override", Content: oversized})
	if err == nil {
		t.Fatal("gRPC Load accepted an oversized message")
	}
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("gRPC Load oversized status = %v, want ResourceExhausted (%v)", got, err)
	}

	// A normal message still round-trips through the same capped server.
	_, err = client.Load(context.Background(), &pb.LoadRequest{
		Mode:    "set",
		Content: "set system host-name fw",
	})
	if err != nil {
		t.Fatalf("gRPC Load rejected a normal message: %v", err)
	}
}
