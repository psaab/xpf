package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// zeroizeMarker stands in for any prior-tenant secret leaf (IKE PSK, WireGuard
// key, SNMP community). The test proves no file carrying it survives a zeroize
// and that a fresh Store.Load does not resurrect it.
const zeroizeMarker = "MARKER-SECRET-4576-ike-psk"

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected %s to be absent after zeroize, stat err = %v", path, err)
	}
}

// TestZeroizeConfigDirWipesSSOTAndSecrets pins #4576: a factory-reset wipe must
// remove the .configdb SSOT and master.key (plus the text rollback slots and
// the audit journal) so the prior tenant's config + secrets do not survive.
//
// RED on revert: before this fix, performZeroizeWipe removed only top-level
// .conf / rollback* files, so .configdb/master.key, .configdb/active.json,
// .configdb/rollback.N.json, the <base>.N text rollback slots and
// .config.journal all SURVIVED — every assertAbsent below on those paths fails,
// and a fresh Load reloads the prior tenant's config.
func TestZeroizeConfigDirWipesSSOTAndSecrets(t *testing.T) {
	dir := t.TempDir()
	configBase := "xpf.conf"
	configPath := filepath.Join(dir, configBase)
	dbDir := filepath.Join(dir, ".configdb")
	marker := []byte(zeroizeMarker)

	// The prior tenant's on-disk state: every artifact that carries config or
	// secret material.
	masterKey := filepath.Join(dbDir, "master.key")
	activeJSON := filepath.Join(dbDir, "active.json")
	candidateJSON := filepath.Join(dbDir, "candidate.json")
	rollbackJSON := filepath.Join(dbDir, "rollback.1.json")
	journalPath := filepath.Join(dir, ".config.journal")
	journalSeg := filepath.Join(dir, ".config.journal.1")
	textRollback := configPath + ".1"
	rescue := filepath.Join(dir, "rescue.conf")

	mustWriteFile(t, masterKey, make([]byte, 32))
	mustWriteFile(t, activeJSON, marker)
	mustWriteFile(t, candidateJSON, marker)
	mustWriteFile(t, rollbackJSON, marker)
	mustWriteFile(t, journalPath, marker)
	mustWriteFile(t, journalSeg, marker)
	mustWriteFile(t, configPath, marker)
	mustWriteFile(t, textRollback, marker)
	mustWriteFile(t, rescue, marker)

	// A non-xpf file in the same dir must be LEFT ALONE — the wipe is scoped to
	// xpf-authored artifacts, not everything under /etc/xpf.
	bystander := filepath.Join(dir, "node-id")
	mustWriteFile(t, bystander, []byte("0"))

	if err := zeroizeConfigDir(dir, configBase); err != nil {
		t.Fatalf("zeroizeConfigDir returned error: %v", err)
	}

	// Every secret-bearing artifact is gone (the fix; RED on revert).
	for _, p := range []string{
		dbDir, masterKey, activeJSON, candidateJSON, rollbackJSON,
		journalPath, journalSeg, configPath, textRollback, rescue,
	} {
		assertAbsent(t, p)
	}

	// Scope guard: the non-xpf file survives.
	if _, err := os.Stat(bystander); err != nil {
		t.Errorf("zeroize removed a non-xpf file %s: %v", bystander, err)
	}

	// A fresh Store.Load on the wiped dir yields the default/empty config:
	// NewDB recreates an empty .configdb, ReadActive sees no active.json, Load
	// starts fresh with no crash and no prior-tenant secret.
	store, err := configstore.New(configPath)
	if err != nil {
		t.Fatalf("configstore.New after zeroize: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load after zeroize: %v", err)
	}
	if got := store.ActiveTree().FormatSet(); strings.Contains(got, zeroizeMarker) {
		t.Errorf("post-zeroize active config still contains prior-tenant secret:\n%s", got)
	}
	if store.EverCommitted() {
		t.Errorf("post-zeroize store reports EverCommitted=true; want fresh/never-committed")
	}
}

// TestIsTextRollbackFile pins the numbered text-rollback-slot recognizer so it
// removes the canonical rollback history (<base>.N) without eating unrelated
// files.
func TestIsTextRollbackFile(t *testing.T) {
	base := "xpf.conf"
	cases := []struct {
		name string
		want bool
	}{
		{"xpf.conf.1", true},
		{"xpf.conf.42", true},
		{"xpf.conf", false},      // the live config (caught by the .conf rule)
		{"xpf.conf.bak", false},  // not all-digits
		{"xpf.conf.", false},     // empty slot number
		{"xpf.conf.1a", false},   // trailing non-digit
		{"rescue.conf.1", false}, // different base
		{"node-id", false},
	}
	for _, tc := range cases {
		if got := isTextRollbackFile(tc.name, base); got != tc.want {
			t.Errorf("isTextRollbackFile(%q, %q) = %v, want %v", tc.name, base, got, tc.want)
		}
	}
}

// TestZeroizeSurfacesWipeError pins #4576 requirement 3: a wipe that fails to
// fully erase config state must surface an error at the RPC boundary, not
// report a clean factory reset.
func TestZeroizeSurfacesWipeError(t *testing.T) {
	orig := performZeroizeWipe
	t.Cleanup(func() { performZeroizeWipe = orig })
	performZeroizeWipe = func(_, _, _ string) error { return errors.New("simulated .configdb wipe failure") }

	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	s := &Server{store: store}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
	if err == nil {
		t.Fatalf("SystemAction(zeroize) with failing wipe returned nil error, resp=%v", resp)
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("SystemAction(zeroize) error code = %v, want Internal", status.Code(err))
	}
}
