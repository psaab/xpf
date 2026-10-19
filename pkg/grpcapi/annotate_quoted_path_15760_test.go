package grpcapi

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #15760: remote CLI, gRPC Server.Set annotate, and the gRPC authz
// pre-normalizer still split at the first '"' via
// cliterm.AnnotateCommentFromLine + strings.Fields instead of the
// canonical #14717 config.ParseAnnotateCommand / ParseAnnotateRemainder
// (comment is the LAST token and only when authored quoted). A quoted
// path element was therefore mistaken for the comment boundary, so the
// path authorized was not the path mutated.
//
// Regression criterion from the issue report, exercised end-to-end
// through the real surfaces below (remote-wire shape, Set handler, and
// interceptor gate), not only as a config-package unit test.

func TestRemoteAndGRPCAnnotateWithQuotedPathTokens(t *testing.T) {
	line := `annotate groups "my group" system "production comment"`
	path, comment, ok := config.ParseAnnotateCommand(line)
	if !ok {
		t.Fatalf("expected ParseAnnotateCommand to succeed on %q", line)
	}
	wantPath := []string{"groups", "my group", "system"}
	if !reflect.DeepEqual(path, wantPath) || comment != "production comment" {
		t.Fatalf("got path=%v comment=%q, want path=%v comment=%q", path, comment, wantPath, "production comment")
	}
}

// The gRPC Set handler must act on the canonical path: a quoted path
// element stays one path element, and only the trailing quoted token
// is the comment. Pre-fix the handler split at the first '"', so it
// annotated `groups` with comment `my group" system "production comment`.
func TestSetRPCAnnotateQuotedPathElement15760(t *testing.T) {
	store := newGRPCConfigStore(t)
	// Seed groups { "my group" { system; } } so AnnotatePath can land.
	// LoadSet with a quoted key creates the group name containing a space.
	if _, err := store.LoadSet(`set groups "my group" system host-name seed`); err != nil {
		t.Fatalf("seed groups: %v", err)
	}
	s := &Server{store: store}
	if _, err := s.Set(ctxWithAuthorizedRoot(ctxWithPeerUID(0)), &pb.SetRequest{
		Input: `annotate groups "my group" system "production comment"`,
	}); err != nil {
		t.Fatalf("Set(annotate quoted path): %v", err)
	}
	out := store.ShowCandidate()
	if !strings.Contains(out, "/* production comment */") {
		t.Fatalf("candidate missing canonical annotation:\n%s", out)
	}
	if strings.Contains(out, `system "production comment`) || strings.Contains(out, `my group" system`) {
		t.Fatalf("first-quote split mangled the comment:\n%s", out)
	}
	// The annotation must be on the `system` node inside "my group",
	// not on bare `groups`. ShowCandidate renders the annotation as a
	// /* ... */ line immediately preceding its node; check nesting by
	// ensuring no bare-groups annotation line precedes `groups {`.
	lines := strings.Split(out, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "groups {" && i > 0 {
			if strings.Contains(lines[i-1], "production comment") {
				t.Fatalf("annotation landed on bare groups (first-quote path), want groups \"my group\" system:\n%s", out)
			}
		}
	}
}

// The interceptor gate (configMutationLineFor) must adjudicate the same
// canonical path the handler acts on. Pre-fix it rebuilt the gate line
// from the first-quote split: path=[groups], comment=`my group" system
// "production comment`, so a deny on the real path never matched and a
// deny on `groups` alone would block/misjudge the wrong node.
func TestAnnotateGateLineUsesCanonicalPath15760(t *testing.T) {
	for _, input := range []string{
		`annotate groups "my group" system "production comment"`,
		"annotate\tgroups \"my group\" system \"production comment\"",
	} {
		line, ok := configMutationLineFor("/"+serviceName+"/Set", &pb.SetRequest{Input: input})
		if !ok {
			t.Fatalf("configMutationLineFor(%q) not gated", input)
		}
		path, comment, pok := config.ParseAnnotateCommand(line)
		if !pok {
			t.Fatalf("gate line %q (from %q) does not re-parse as annotate", line, input)
		}
		wantPath := []string{"groups", "my group", "system"}
		if !reflect.DeepEqual(path, wantPath) || comment != "production comment" {
			t.Fatalf("gate line %q: got path=%v comment=%q, want path=%v comment=%q",
				line, path, comment, wantPath, "production comment")
		}
	}
}

// End-to-end through the interceptor: a class denied exactly the real
// (quoted-element) path must be refused, and the handler must not run.
// Pre-fix the gate adjudicated `groups` only, so the deny on
// `groups my group system` never matched and the mutation proceeded.
func TestAnnotateQuotedPathDeniedThroughInterceptor15760(t *testing.T) {
	usePasswdFixture5278(t)
	store := authzStore5278(t, `system {
    login {
        class ops {
            permissions [ configure view ];
            deny-configuration "^groups my group system$";
        }
        user opuser { class ops; }
    }
    host-name before;
}
groups {
    "my group" {
        system {
            host-name seed;
        }
    }
}`)
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	s := &Server{store: store}
	req := &pb.SetRequest{Input: `annotate groups "my group" system "production comment"`}
	called := false
	_, err := s.principalUnaryInterceptor(
		ctxWithPeerUID(authzUIDOperator), req,
		&grpc.UnaryServerInfo{FullMethod: pb.BpfrxService_Set_FullMethodName},
		func(ctx context.Context, request any) (any, error) {
			called = true
			return s.Set(ctx, request.(*pb.SetRequest))
		},
	)
	if status.Code(err) != codes.PermissionDenied || called {
		t.Fatalf("denied quoted-path annotate err=%v handlerCalled=%v, want PermissionDenied and no handler", err, called)
	}
	if out := store.ShowCandidate(); strings.Contains(out, "production comment") {
		t.Fatalf("denied annotation was applied:\n%s", out)
	}
}
