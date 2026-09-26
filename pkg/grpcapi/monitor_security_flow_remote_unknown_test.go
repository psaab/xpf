package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestShowMonitorSecurityFlowRemoteStateIsUnknown(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{store: store}
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "monitor-security-flow"})
	if err != nil {
		t.Fatalf("ShowText(monitor-security-flow): %v", err)
	}
	out := resp.GetOutput()
	for _, want := range []string{
		"Monitor security flow session status: Unknown (per-CLI-session state)",
		"Monitor security flow trace file: Unknown (per-CLI-session state)",
		"Monitor security flow filters: Unknown (per-CLI-session state)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("remote monitor status lacks %q:\n%s", want, out)
		}
	}
	for _, fabricated := range []string{
		"Monitor security flow session status: Inactive",
		"Monitor security flow trace file: (not configured)",
		"Monitor security flow filters: 0",
	} {
		if strings.Contains(out, fabricated) {
			t.Errorf("remote monitor status fabricates %q:\n%s", fabricated, out)
		}
	}
}
