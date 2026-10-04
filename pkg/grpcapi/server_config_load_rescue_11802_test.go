package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGRPCLoadRescueChangesOnlyCandidate11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newConfigStore(t, path)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride("system { host-name candidate-before-rescue; }"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), configstore.RescueConfigBase),
		[]byte("system { host-name rescue-from-grpc; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	activeBefore := store.ShowActiveSet()
	server := &Server{store: store}
	if _, err := server.Load(ctxWithAuthorizedRoot(ctxWithPeerUID(0)), &pb.LoadRequest{Mode: "rescue"}); err != nil {
		t.Fatalf("Load(mode=rescue): %v", err)
	}
	candidate := store.ShowCandidateSet()
	if !strings.Contains(candidate, "host-name rescue-from-grpc") || strings.Contains(candidate, "candidate-before-rescue") {
		t.Fatalf("gRPC rescue load did not replace candidate: %s", candidate)
	}
	if got := store.ShowActiveSet(); got != activeBefore {
		t.Fatalf("gRPC rescue load changed active config: before=%q after=%q", activeBefore, got)
	}
}

func TestGRPCLoadRescueMissingIsFailedPrecondition11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newConfigStore(t, path)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: store}
	_, err := server.Load(ctxWithAuthorizedRoot(ctxWithPeerUID(0)), &pb.LoadRequest{Mode: "rescue"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Load(mode=rescue) error = %v, want FailedPrecondition", err)
	}
}

func TestGRPCLoadRescueDeniedOverProductionListenerForRestrictedClass11802(t *testing.T) {
	usePasswdFixture5278(t)
	const restrictedConfig = `
system {
    login {
        class limited {
            permissions [ configure view ];
            deny-configuration "system host-name";
        }
        user opuser {
            class limited;
        }
    }
}
`
	store := authzStore5278(t, restrictedConfig)
	client := runPrimaryListener(t, Config{
		Store:        store,
		PeerLookupFn: fixedPeerUID5278(authzUIDOperator),
	})
	ctx := callCtx(t)
	if _, err := client.EnterConfigure(ctx, &pb.EnterConfigureRequest{}); err != nil {
		t.Fatalf("restricted class EnterConfigure: %v", err)
	}
	before := store.ShowCandidateSet()

	_, err := client.Load(ctx, &pb.LoadRequest{Mode: "rescue"})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("restricted gRPC load rescue error = %v, want PermissionDenied", err)
	}
	if got := store.ShowCandidateSet(); got != before {
		t.Fatalf("denied gRPC load rescue changed candidate: before=%q after=%q", before, got)
	}
}
