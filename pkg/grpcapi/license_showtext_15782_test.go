package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15782: ShowText license topic must exist and match local renderer.
func TestShowTextLicense15782(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput(`system license autoupdate url "https://user:secret@lic.example/keys?token=abc"`); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if err := store.SetFromInput("system license autoupdate url https://b.example/keys"); err != nil {
		t.Fatalf("SetFromInput b: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	server := &Server{store: store}
	resp, err := server.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "license"})
	if err != nil {
		t.Fatalf("ShowText license: %v", err)
	}
	out := resp.GetOutput()
	if !strings.Contains(out, "License: open-source") {
		t.Errorf("missing license line: %q", out)
	}
	if !strings.Contains(out, "lic.example") || !strings.Contains(out, "b.example") {
		t.Errorf("missing configured URLs (multi retained?): %q", out)
	}
	if strings.Contains(out, "secret") || strings.Contains(out, "token=abc") {
		t.Errorf("secret leaked in ShowText license: %q", out)
	}
	if !strings.Contains(out, "NOT applied") {
		t.Errorf("missing inert notice: %q", out)
	}
}
