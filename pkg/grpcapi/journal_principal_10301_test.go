package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestGRPCJournalPrincipalUsesAdmittedSnapshot10301 proves the unary
// interceptor hands the handler the exact principal admitted by authorization.
// The active login-class snapshot changes before the handler records its audit
// entry; re-resolving from Server.activeConfig would incorrectly report the
// new class.
func TestGRPCJournalPrincipalUsesAdmittedSnapshot10301(t *testing.T) {
	usePasswdFixture5278(t)
	s := &Server{store: authzStore5278(t, authzConfig5278)}
	fullMethod := "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/GetStatus"
	ctx := ctxWithPeerUID(authzUIDReadOnly)
	const sessionID = "grpc-config-session-10301"

	updatedConfig := strings.Replace(authzConfig5278, "class read-only;", "class super-user;", 1)
	var got string
	_, err := s.principalUnaryInterceptor(ctx, &pb.GetStatusRequest{},
		&grpc.UnaryServerInfo{FullMethod: fullMethod},
		func(handlerCtx context.Context, _ any) (any, error) {
			if err := s.store.EnterConfigure(); err != nil {
				return nil, err
			}
			if err := s.store.LoadOverride(updatedConfig); err != nil {
				return nil, err
			}
			if _, err := s.store.Commit(); err != nil {
				return nil, err
			}
			got = journalPrincipalForContext(s, handlerCtx, sessionID)
			return nil, nil
		})
	if err != nil {
		t.Fatalf("unary interceptor/handler: %v", err)
	}
	want := configstore.FormatJournalPrincipal("peer-uid", authzUIDReadOnly, "opsuser", "read-only", sessionID)
	if got != want {
		t.Fatalf("journal principal after active-config turnover = %q, want admitted snapshot %q", got, want)
	}
}
