package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// clientCtx returns a context carrying a distinct gRPC peer address, so
// peerSessionID resolves to a distinct per-"client" session identifier.
func clientCtx(port int) context.Context {
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
	})
	ctx = context.WithValue(ctx, connPeerKey{}, &connPeer{
		id: authz.PeerIdentity{UID: 0, OK: true, Local: true},
	})
	// Direct handler tests bypass the production interceptor; publish the
	// principal those root-owned calls are modeling so attribution remains
	// explicit without re-resolving against a later config snapshot.
	return context.WithValue(ctx, authorizedPrincipalKey{}, authz.Principal{
		Source: authz.SourcePeerUID, UID: 0, Username: "root", Superuser: true,
	})
}

func wantCode(t *testing.T, err error, want codes.Code, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: got nil error, want %v", what, want)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("%s: error is not a status: %T (%v)", what, err, err)
	}
	if st.Code() != want {
		t.Fatalf("%s: code = %v, want %v (%v)", what, st.Code(), want, err)
	}
}

// TestConfigLockHolderEnforced_TwoClients is the #5059 fail-on-revert guard:
// once client A holds the config lock, a second client B that never entered
// config mode must be rejected (PermissionDenied) from every mutating/commit
// RPC on A's shared candidate, while A itself keeps working. Reverting the
// holder enforcement lets B's mutations through → RED.
func TestConfigLockHolderEnforced_TwoClients(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{
		store: store,
		commitFn: func(context.Context, configstore.CommitAuthority, string) (*config.Config, error) {
			return store.Commit()
		},
	}
	ctxA := clientCtx(1111)
	ctxB := clientCtx(2222)

	// A takes the config lock.
	if _, err := s.EnterConfigure(ctxA, &pb.EnterConfigureRequest{}); err != nil {
		t.Fatalf("A EnterConfigure: %v", err)
	}

	// B never entered config mode: every mutation/commit it attempts on the
	// shared candidate is rejected PermissionDenied.
	_, err := s.Set(ctxB, &pb.SetRequest{Input: "system host-name evil"})
	wantCode(t, err, codes.PermissionDenied, "B Set")

	_, err = s.Delete(ctxB, &pb.DeleteRequest{Input: "system host-name"})
	wantCode(t, err, codes.PermissionDenied, "B Delete")

	_, err = s.Load(ctxB, &pb.LoadRequest{Mode: "set", Content: "set system host-name evil"})
	wantCode(t, err, codes.PermissionDenied, "B Load set")

	_, err = s.Load(ctxB, &pb.LoadRequest{Mode: "override", Content: "system { host-name evil; }"})
	wantCode(t, err, codes.PermissionDenied, "B Load override")

	_, err = s.Rollback(ctxB, &pb.RollbackRequest{N: 0})
	wantCode(t, err, codes.PermissionDenied, "B Rollback")

	_, err = s.Commit(ctxB, &pb.CommitRequest{})
	wantCode(t, err, codes.PermissionDenied, "B Commit")

	_, err = s.CommitConfirmed(ctxB, &pb.CommitConfirmedRequest{Minutes: 5})
	wantCode(t, err, codes.PermissionDenied, "B CommitConfirmed")

	// A (the holder) can mutate normally.
	if _, err := s.Set(ctxA, &pb.SetRequest{Input: "system host-name good"}); err != nil {
		t.Fatalf("A Set (holder): %v", err)
	}

	// None of B's rejected mutations reached the candidate; A's did.
	got := store.ShowCandidateSetRedacted(nil)
	if strings.Contains(got, "evil") {
		t.Fatalf("candidate was mutated by a non-holder session: %q", got)
	}
	if !strings.Contains(got, "good") {
		t.Fatalf("holder's edit missing from candidate: %q", got)
	}
}

// TestConfigLockHolderConcurrent exercises the atomic holder check under the
// race detector: the holder A and a non-holder B hammer Set concurrently. B must
// never succeed and the candidate must never carry B's value. Run with -race.
func TestConfigLockHolderConcurrent(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{store: store}
	ctxA := clientCtx(1111)
	ctxB := clientCtx(2222)

	if _, err := s.EnterConfigure(ctxA, &pb.EnterConfigureRequest{}); err != nil {
		t.Fatalf("A EnterConfigure: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = s.Set(ctxA, &pb.SetRequest{Input: "system host-name good"})
		}()
		go func() {
			defer wg.Done()
			if _, err := s.Set(ctxB, &pb.SetRequest{Input: "system host-name evil"}); err == nil {
				t.Errorf("non-holder B Set succeeded concurrently")
			}
		}()
	}
	wg.Wait()

	if got := store.ShowCandidateSetRedacted(nil); strings.Contains(got, "evil") {
		t.Fatalf("candidate mutated by concurrent non-holder: %q", got)
	}
}
