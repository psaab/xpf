package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #14147: Server.Set's copy/rename/insert handlers split with
// strings.Fields while the interceptor gate lexed. The gate denied or
// allowed one pair of endpoints; the handler acted on another. These
// cells drive the full interceptor+handler path: an allow-listed
// class must be refused BEFORE the handler runs, and a permitted
// rename must land on the lexed destination the gate adjudicated.

const splitCfg14147 = `system {
    host-name split-14147;
    login {
        class limited {
            permissions [ configure view ];
            allow-configuration "^system services";
        }
        user opuser { class limited; }
    }
    services {
        ssh;
        telnet;
    }
    root-authentication { encrypted-password "$6$rounds=5000$abcdefgh$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; }
}
`

func TestGRPCQuotedToRenameDeniedAtGate14147(t *testing.T) {
	usePasswdFixture5278(t)
	store := authzStore5278(t, splitCfg14147)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	s := &Server{store: store}
	info := &grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_Set_FullMethodName}
	for name, input := range map[string]string{
		"quoted to rename":  `rename system services ssh "to" foo to system root-authentication`,
		"quoted to copy":    `copy system services ssh "to" foo to system root-authentication`,
		"comment to rename": `rename system services /* to */ ssh to system root-authentication`,
		"tab rename":        "rename\tsystem services ssh \"to\" foo to system root-authentication",
	} {
		t.Run(name, func(t *testing.T) {
			req := &pb.SetRequest{Input: input}
			called := false
			_, err := s.principalUnaryInterceptor(
				ctxWithPeerUID(authzUIDOperator), req, info,
				func(ctx context.Context, request any) (any, error) {
					called = true
					return s.Set(ctx, request.(*pb.SetRequest))
				},
			)
			if status.Code(err) != codes.PermissionDenied || called {
				t.Fatalf("%q: err=%v handlerCalled=%v, want PermissionDenied and no handler (#14147)",
					input, err, called)
			}
		})
	}
	// Positive control through the same interceptor: both endpoints
	// under the allow must reach the handler and succeed.
	req := &pb.SetRequest{Input: `rename system services ssh to system services telnet2`}
	called := false
	_, err := s.principalUnaryInterceptor(
		ctxWithPeerUID(authzUIDOperator), req, info,
		func(ctx context.Context, request any) (any, error) {
			called = true
			return s.Set(ctx, request.(*pb.SetRequest))
		},
	)
	if err != nil || !called {
		t.Fatalf("allowed rename err=%v handlerCalled=%v, want success (#14147)", err, called)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "telnet2") {
		t.Fatalf("allowed rename did not land on the lexed destination:\n%s", out)
	}
}

// Handler-only cells (superuser principal, gate exempt): the handler
// itself must act on the lexed endpoints, not the Fields endpoints.
// Pre-fix, the quoted-"to" line below renamed ssh -> root-authentication
// (Fields split at the second bare `to`); post-fix it renames the
// `ssh to foo` element to telnet2... the lexed src is
// [system services ssh to foo], which does not exist, so the handler
// must ERROR rather than silently acting on the Fields endpoints.
// The comment form is the positive handler cell: Fields would act on
// a dst containing `/*`/`*/` tokens and fail; the lexer strips them.
func TestGRPCHandlerActsOnLexedEndpoints14147(t *testing.T) {
	usePasswdFixture5278(t)
	store := authzStore5278(t, splitCfg14147)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	s := &Server{store: store}
	ctx := ctxWithAuthorizedRoot(ctxWithPeerUID(authzUIDSuperuser))

	if _, err := s.Set(ctx, &pb.SetRequest{
		Input: `rename system services ssh "to" foo to system root-authentication`,
	}); err == nil {
		t.Fatal("handler acted on the Fields endpoints (ssh -> root-authentication); " +
			"the lexed source [system services ssh to foo] does not exist and must error (#14147)")
	}
	if out := store.ShowCandidateSet(); strings.Contains(out, "root-authentication") &&
		!strings.Contains(out, "encrypted-password") {
		t.Fatalf("candidate was mutated by the Fields split:\n%s", out)
	}

	if _, err := s.Set(ctx, &pb.SetRequest{
		Input: `rename system services /* to */ ssh to system services telnet2`,
	}); err != nil {
		t.Fatalf("comment-form rename on lexed endpoints: %v (#14147)", err)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "telnet2") {
		t.Fatalf("comment-form rename did not land on telnet2:\n%s", out)
	}
}
