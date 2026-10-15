package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetSystemInfoRescueConfigurationRedactsAndFailsClosed13551(t *testing.T) {
	s := newSecretServer(t)
	if err := s.store.SaveRescueConfig(); err != nil {
		t.Fatalf("SaveRescueConfig: %v", err)
	}
	resp, err := s.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{Type: "rescue-configuration"})
	if err != nil {
		t.Fatalf("GetSystemInfo(rescue-configuration): %v", err)
	}
	if !strings.Contains(resp.Output, "system") || !strings.Contains(resp.Output, config.SecretDataPlaceholder) {
		t.Fatalf("saved rescue config missing or unredacted output: %q", resp.Output)
	}
	for _, secret := range grpcSecretSentinels {
		if strings.Contains(resp.Output, secret) {
			t.Fatalf("saved rescue config leaked secret %q: %q", secret, resp.Output)
		}
	}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	emptyServer := &Server{store: store}
	empty, err := emptyServer.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{Type: "rescue-configuration"})
	if err != nil || empty.Output != "No rescue configuration saved\n" {
		t.Fatalf("empty rescue response = (%q, %v), want standard no-rescue message", empty.GetOutput(), err)
	}

	rescuePath := filepath.Join(filepath.Dir(store.ConfigPath()), configstore.RescueConfigBase)
	const parseSecret = "MALFORMED-RESCUE-SENTINEL"
	if err := os.WriteFile(rescuePath, []byte("set system host-name good\nbogus \""+parseSecret+"\n"), 0o600); err != nil {
		t.Fatalf("write malformed rescue: %v", err)
	}
	failed, err := emptyServer.GetSystemInfo(context.Background(), &pb.GetSystemInfoRequest{Type: "rescue-configuration"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("malformed rescue response = (%q, %v), want Internal error", failed.GetOutput(), err)
	}
	if strings.Contains(err.Error(), parseSecret) || strings.Contains(failed.GetOutput(), parseSecret) {
		t.Fatalf("malformed rescue parse error leaked secret %q: output=%q err=%v", parseSecret, failed.GetOutput(), err)
	}
}
