package configstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R-1 configstore twin (#10100): eraseConfigDB checks .configdb + master.key
// only, then RemoveAll. A real .configdb holding a symlinked active.json (or
// any other interior file) has the link unlinked while the target config text
// survives, nil returned. The grpcapi twin is the one production runs, but
// #9013's lesson is the pair must not drift.

const interiorSecret10100 = "SECRET-10100-INTERIOR-TWIN"

func TestFactoryResetReportsInteriorConfigDBLink10100(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	real := filepath.Join(root, "elsewhere")
	for _, d := range []string{configDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dbDir := filepath.Join(configDir, ".configdb")
	if err := os.MkdirAll(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "master.key"), []byte("keymaterial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "candidate.json"), []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(real, "active-real.json")
	if err := os.WriteFile(target, []byte("config-text "+interiorSecret10100), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dbDir, "active.json")); err != nil {
		t.Fatal(err)
	}

	err := FactoryResetConfigDir(configDir, "xpf.conf")
	var symErr *FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("R-1 twin: expected FactoryResetSymlinkError, got %v; "+
			"interior link unlinked while %s survives silently", err, target)
	}
	found := false
	for _, sk := range symErr.Skipped {
		if sk.Target == target || strings.Contains(sk.Target, "active-real.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("R-1 twin: Skipped %v does not name %s", symErr.Skipped, target)
	}
	got, rerr := os.ReadFile(target)
	if rerr != nil || !bytes.Contains(got, []byte(interiorSecret10100)) {
		t.Fatalf("R-1 twin: surviving target lost: %v", rerr)
	}
}
