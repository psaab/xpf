package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15707: local `show system internet-options` and the gRPC renderer must
// agree. The local CLI previously printed the raw config text while gRPC
// rendered the typed field, so the two diverged (notably for the compact
// spelling and for the unset case).
func TestShowSystemInternetOptionsTypedView15707(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system internet-options no-ipv6-reject-zero-hop-limit"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := &CLI{store: store}
	var runErr error
	out := captureStdout(t, func() { runErr = c.handleShowSystem([]string{"internet-options"}) })
	if runErr != nil {
		t.Fatalf("show system internet-options: %v", runErr)
	}
	want := "Internet options:\n  no-ipv6-reject-zero-hop-limit: enabled\n"
	if out != want {
		t.Errorf("local CLI = %q, want gRPC-identical %q", out, want)
	}
	if strings.Contains(out, "internet-options {") {
		t.Errorf("local CLI still renders raw config text: %q", out)
	}
}

func TestShowSystemInternetOptionsUnset15707(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.SetFromInput("system host-name fw1"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := &CLI{store: store}
	var runErr error
	out := captureStdout(t, func() { runErr = c.handleShowSystem([]string{"internet-options"}) })
	if runErr != nil {
		t.Fatalf("show system internet-options: %v", runErr)
	}
	if out != "No internet-options configured\n" {
		t.Errorf("local CLI unset = %q, want gRPC-identical %q", out, "No internet-options configured\n")
	}
}
