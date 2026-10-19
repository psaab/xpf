package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15657 V45-03/V48-02 on the gRPC surface: ShowCompare with
// ActiveBaseline diffs rollback vs ACTIVE (no candidate), ShowRollback
// honours every format + path, and n=0 renders active.

func newRollbackServer15657(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("set system host-name host-a-15657"); err != nil {
		t.Fatalf("LoadSet A: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit A: %v", err)
	}
	if _, err := store.LoadSet("set system host-name host-b-15657"); err != nil {
		t.Fatalf("LoadSet B: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit B: %v", err)
	}
	// Dirty candidate that must never leak into active-baseline answers.
	if _, err := store.LoadSet("set system host-name host-c-15657"); err != nil {
		t.Fatalf("LoadSet C: %v", err)
	}
	return &Server{store: store}
}

func TestShowCompareActiveBaseline15657(t *testing.T) {
	s := newRollbackServer15657(t)
	resp, err := s.ShowCompare(context.Background(), &pb.ShowCompareRequest{RollbackN: 1, ActiveBaseline: true})
	if err != nil {
		t.Fatalf("ShowCompare active-baseline: %v", err)
	}
	if !strings.Contains(resp.Output, "host-a-15657") || !strings.Contains(resp.Output, "host-b-15657") {
		t.Errorf("active-baseline diff should mention A and B:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "host-c-15657") {
		t.Errorf("active-baseline diff leaked dirty candidate:\n%s", resp.Output)
	}
	// Candidate baseline still sees C.
	resp, err = s.ShowCompare(context.Background(), &pb.ShowCompareRequest{RollbackN: 1})
	if err != nil {
		t.Fatalf("ShowCompare candidate-baseline: %v", err)
	}
	if !strings.Contains(resp.Output, "host-c-15657") {
		t.Errorf("candidate-baseline diff should mention C:\n%s", resp.Output)
	}
	// Active baseline works with no candidate at all.
	s.store.ExitConfigure()
	resp, err = s.ShowCompare(context.Background(), &pb.ShowCompareRequest{RollbackN: 1, ActiveBaseline: true})
	if err != nil {
		t.Fatalf("ShowCompare active-baseline outside config mode: %v", err)
	}
	if !strings.Contains(resp.Output, "host-a-15657") {
		t.Errorf("operational diff lost rollback content:\n%s", resp.Output)
	}
	// rollback_n=0 with active baseline is [no changes].
	resp, err = s.ShowCompare(context.Background(), &pb.ShowCompareRequest{RollbackN: 0, ActiveBaseline: true})
	if err != nil || resp.Output != "[no changes]\n" {
		t.Errorf("active-baseline 0 = %q, %v; want [no changes]", resp.Output, err)
	}
}

func TestShowRollbackZeroRendersActive15657(t *testing.T) {
	s := newRollbackServer15657(t)
	resp, err := s.ShowRollback(context.Background(), &pb.ShowRollbackRequest{N: 0})
	if err != nil {
		t.Fatalf("ShowRollback n=0: %v", err)
	}
	if !strings.Contains(resp.Output, "host-b-15657") {
		t.Errorf("ShowRollback n=0 should render active (host-b):\n%s", resp.Output)
	}
}

func TestShowRollbackFormatsAndPath15657(t *testing.T) {
	s := newRollbackServer15657(t)
	cases := []struct {
		name string
		req  *pb.ShowRollbackRequest
		want string
	}{
		{"json", &pb.ShowRollbackRequest{N: 1, Format: pb.ConfigFormat_JSON}, "host-a-15657"},
		{"xml", &pb.ShowRollbackRequest{N: 1, Format: pb.ConfigFormat_XML}, "<configuration"},
		{"set", &pb.ShowRollbackRequest{N: 1, Format: pb.ConfigFormat_SET}, "set system host-name host-a-15657"},
		{"inheritance", &pb.ShowRollbackRequest{N: 1, Format: pb.ConfigFormat_INHERITANCE}, "host-a-15657"},
		{"path json", &pb.ShowRollbackRequest{N: 1, Format: pb.ConfigFormat_JSON, Path: []string{"system"}}, "host-a-15657"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.ShowRollback(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("ShowRollback %s: %v", tc.name, err)
			}
			if !strings.Contains(resp.Output, tc.want) {
				t.Errorf("ShowRollback %s missing %q:\n%s", tc.name, tc.want, resp.Output)
			}
		})
	}
	// Path scoping scopes.
	resp, err := s.ShowRollback(context.Background(), &pb.ShowRollbackRequest{N: 1, Path: []string{"security"}})
	if err != nil {
		t.Fatalf("ShowRollback scoped: %v", err)
	}
	if strings.Contains(resp.Output, "host-name") {
		t.Errorf("scoped ShowRollback leaked out-of-path content:\n%s", resp.Output)
	}
}

// The candidate-price gate: active-baseline is view-priced, candidate
// arms stay config-priced.
func TestShowCompareActiveBaselinePricing15657(t *testing.T) {
	method := "/" + serviceName + "/ShowCompare"
	if got, ok := configTargetReadPermission(method, &pb.ShowCompareRequest{RollbackN: 1, ActiveBaseline: true}); ok {
		t.Errorf("active-baseline priced at %v; want view (ok=false)", got)
	}
	if _, ok := configTargetReadPermission(method, &pb.ShowCompareRequest{RollbackN: 1}); !ok {
		t.Error("candidate-baseline must stay config-priced")
	}
	if _, ok := configTargetReadPermission(method, &pb.ShowCompareRequest{RollbackN: 0}); !ok {
		t.Error("candidate-vs-active must stay config-priced")
	}
}
