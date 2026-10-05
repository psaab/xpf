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

func TestGRPCLoadRescueRejectsContent11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newConfigStore(t, path)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride("system { host-name candidate-before-rejected-rescue; }"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), configstore.RescueConfigBase),
		[]byte("system { host-name saved-rescue; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := store.ShowCandidateSet()
	_, err := (&Server{store: store}).Load(ctxWithAuthorizedRoot(ctxWithPeerUID(0)),
		&pb.LoadRequest{Mode: "rescue", Content: "system { host-name ignored; }"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("gRPC rescue request with content error = %v, want InvalidArgument", err)
	}
	if got := store.ShowCandidateSet(); got != before {
		t.Fatalf("rejected gRPC rescue request changed candidate: before=%q after=%q", before, got)
	}
}

func TestGRPCLoadRescueMalformedFlatInputDoesNotLeakToRestrictedClass11802(t *testing.T) {
	usePasswdFixture5278(t)
	const restrictedConfig = `
system {
    login {
        class limited {
            permissions [ configure view ];
        }
        user opuser {
            class limited;
        }
    }
}
`
	store := authzStore5278(t, restrictedConfig)
	path := store.ConfigPath()
	const secret = "BENIGN-REVIEW-SECRET-12129"
	client := runPrimaryListener(t, Config{
		Store:        store,
		PeerLookupFn: fixedPeerUID5278(authzUIDOperator),
	})
	ctx := callCtx(t)
	if _, err := client.EnterConfigure(ctx, &pb.EnterConfigureRequest{}); err != nil {
		t.Fatalf("restricted class EnterConfigure: %v", err)
	}
	before := store.ShowCandidateSet()
	for _, tc := range []struct {
		name    string
		content string
	}{
		{
			name:    "content line spoof",
			content: "set system host-name rescue-line-one\nbogus " + secret + " offline line 9, column 2",
		},
		{
			name: "nested parser position",
			content: "set system host-name rescue-line-one\n" +
				"set security ike policy rescue pre-shared-key ascii-text \"" + secret,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(filepath.Dir(path), configstore.RescueConfigBase),
				[]byte(tc.content), 0o600); err != nil {
				t.Fatalf("write malformed flat rescue: %v", err)
			}
			_, err := client.Load(ctx, &pb.LoadRequest{Mode: "rescue"})
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("malformed flat rescue error = %v, want InvalidArgument", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("gRPC parse error leaked rescue secret %q: %v", secret, err)
			}
			if !strings.Contains(err.Error(), "line 2") || strings.Contains(err.Error(), "line 9") {
				t.Fatalf("gRPC parse error reported the wrong flat-file source position: %v", err)
			}
			if got := store.ShowCandidateSet(); got != before {
				t.Fatalf("malformed flat rescue changed candidate: before=%q after=%q", before, got)
			}
			if redacted, redErr := store.LoadRescueConfigRedacted(); redErr == nil ||
				strings.Contains(redErr.Error(), secret) || strings.Contains(redacted, secret) ||
				!strings.Contains(redErr.Error(), "line 2") || strings.Contains(redErr.Error(), "line 9") {
				t.Fatalf("malformed flat rescue redaction leaked secret or reported the wrong position: text=%q err=%v",
					redacted, redErr)
			}
		})
	}
}
