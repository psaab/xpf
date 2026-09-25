package grpcapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/diagcmd"
	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #9143: every buffered gRPC FRR status read uses the process-wide
// VtyshLimiter, propagates the request context, and maps admission refusals to
// ResourceExhausted. The full-RIB BGP RPC now streams through a separate
// bounded path (#10708), so it has its own admission test below.

type stubFRRExec9143g struct{ frr.RecordingExecutor }

type failingFRRExec9143g struct{ frr.RecordingExecutor }

func (failingFRRExec9143g) Vtysh(context.Context, string) (string, error) {
	return "", errors.New("vtysh: exit status 1: zebra unreachable")
}

func withFreshVtyshLimiter9143g(t *testing.T, n int) {
	t.Helper()
	orig := diagcmd.VtyshLimiter
	diagcmd.VtyshLimiter = diagcmd.NewLimiter(n)
	t.Cleanup(func() { diagcmd.VtyshLimiter = orig })
}

func TestGRPCFRRStatusOverCapIsResourceExhausted9143(t *testing.T) {
	calls := map[string]func(*Server, context.Context) error{
		"GetOSPFStatus/neighbors": func(s *Server, c context.Context) error {
			_, e := s.GetOSPFStatus(c, &pb.GetOSPFStatusRequest{})
			return e
		},
		"GetOSPFStatus/database": func(s *Server, c context.Context) error {
			_, e := s.GetOSPFStatus(c, &pb.GetOSPFStatusRequest{Type: "database"})
			return e
		},
		"GetBGPStatus/summary": func(s *Server, c context.Context) error {
			_, e := s.GetBGPStatus(c, &pb.GetBGPStatusRequest{})
			return e
		},
		"GetRIPStatus": func(s *Server, c context.Context) error {
			_, e := s.GetRIPStatus(c, &pb.GetRIPStatusRequest{})
			return e
		},
		"GetISISStatus": func(s *Server, c context.Context) error {
			_, e := s.GetISISStatus(c, &pb.GetISISStatusRequest{})
			return e
		},
	}

	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			// Control: with a free slot the RPC succeeds, so the refusal
			// below is measured against an admitted case.
			withFreshVtyshLimiter9143g(t, 1)
			s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", &stubFRRExec9143g{})}
			if err := call(s, context.Background()); err != nil {
				t.Fatalf("with a free slot %s failed: %v", name, err)
			}

			release, err := diagcmd.VtyshLimiter.Acquire()
			if err != nil {
				t.Fatalf("pre-acquire: %v", err)
			}
			defer release()

			err = call(s, context.Background())
			if err == nil {
				t.Fatalf("%s succeeded while the vtysh budget was saturated", name)
			}
			if got := status.Code(err); got != codes.ResourceExhausted {
				t.Fatalf("%s over-cap -> %v, want codes.ResourceExhausted (REST renders the same "+
					"event as 429; the two surfaces must not disagree — #9142)", name, got)
			}
		})
	}
}

func TestGRPCBGPRouteStreamUsesDedicatedAdmission10708(t *testing.T) {
	orig := grpcBGPStreamLimiter
	grpcBGPStreamLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { grpcBGPStreamLimiter = orig })

	s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", &stubFRRExec9143g{})}
	release, err := grpcBGPStreamLimiter.Acquire()
	if err != nil {
		t.Fatalf("pre-acquire: %v", err)
	}
	_, err = s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: "routes"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("saturated BGP stream admission -> %v, want ResourceExhausted", status.Code(err))
	}
	release()

	if _, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: "routes"}); err != nil {
		t.Fatalf("released BGP stream admission did not accept request: %v", err)
	}
}

func TestGRPCFRROrdinaryErrorStaysInternal9143(t *testing.T) {
	withFreshVtyshLimiter9143g(t, 4)
	s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", &failingFRRExec9143g{})}

	_, err := s.GetOSPFStatus(context.Background(), &pb.GetOSPFStatusRequest{Type: "database"})
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("ordinary FRR failure -> %v, want codes.Internal (unchanged from before #9143)", got)
	}
}

// The buffered and streaming gRPC handlers must both abort a request whose
// context is already cancelled.
func TestGRPCFRRCancelledRPCAbortsTheRead9143(t *testing.T) {
	withFreshVtyshLimiter9143g(t, 4)
	s := &Server{frr: frr.NewForTest(t.TempDir()+"/frr.conf", &ctxWatchExec9143g{})}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.GetOSPFStatus(ctx, &pb.GetOSPFStatusRequest{Type: "database"}); err == nil {
		t.Fatal("a cancelled buffered RPC still ran the FRR read to completion")
	}
	if _, err := s.GetBGPStatus(ctx, &pb.GetBGPStatusRequest{Type: "routes"}); err == nil {
		t.Fatal("a cancelled streaming RPC still ran the FRR read to completion")
	}
}

type ctxWatchExec9143g struct{ frr.RecordingExecutor }

func (ctxWatchExec9143g) Vtysh(ctx context.Context, _ string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return "ok", nil
}
