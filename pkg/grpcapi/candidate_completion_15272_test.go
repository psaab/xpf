package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15272 B24-03/B24-04: gRPC completion and ShowCompare use the candidate.

func TestGRPCValueProviderCandidate15272(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	defer store.ExitConfigure()
	if err := store.SetFromInput("security zones security-zone oldzone"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name before15272"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteFromInput("security zones security-zone oldzone"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("security zones security-zone newzone"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name after15272"); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: store}
	vp := s.valueProvider(config.ValueHintZoneName, []string{"security", "zones", "security-zone"})
	names := map[string]bool{}
	for _, v := range vp {
		names[v.Name] = true
	}
	if !names["newzone"] || names["oldzone"] {
		t.Errorf("grpc zones = %v, want newzone only", names)
	}
	resp, err := s.ShowCompare(context.Background(), &pb.ShowCompareRequest{Path: []string{"security"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Output, "newzone") {
		t.Errorf("scoped compare missing newzone:\n%s", resp.Output)
	}
	if strings.Contains(resp.Output, "host-name") || strings.Contains(resp.Output, "after15272") {
		t.Errorf("scoped compare leaked global hunk:\n%s", resp.Output)
	}
	// Global control.
	resp2, err := s.ShowCompare(context.Background(), &pb.ShowCompareRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp2.Output, "newzone") || !strings.Contains(resp2.Output, "after15272") {
		t.Errorf("global compare missing hunks:\n%s", resp2.Output)
	}
	// Op-mode control: after exit, active (oldzone) is offered again.
	store.ExitConfigure()
	vp2 := s.valueProvider(config.ValueHintZoneName, []string{"security", "zones", "security-zone"})
	names2 := map[string]bool{}
	for _, v := range vp2 {
		names2[v.Name] = true
	}
	if !names2["oldzone"] || names2["newzone"] {
		t.Errorf("op-mode zones = %v, want oldzone only", names2)
	}
}
