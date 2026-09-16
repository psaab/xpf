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

func TestFactoryResetArchiveReportsInteriorLink10100(t *testing.T) {
	// GPT-3: a real archive dir holding a symlinked config-<ts>.<seq>.conf
	// snapshot (full cleartext config) had the link unlinked while the target
	// survived, nil returned — the R-1 interior shape in a file the cohort
	// touches but did not name. The ownership guard is undisturbed: the dir
	// here IS the (repointed) default.
	root := t.TempDir()
	archiveDir := filepath.Join(root, "xpf", "archive")
	real := filepath.Join(root, "bigvolume")
	for _, d := range []string{archiveDir, real} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(real, "config-1757000000.9.conf")
	secretBody := "security ike policy p1 pre-shared-key ascii-text \"PSK-10100-ARCHIVE\";\n"
	if err := os.WriteFile(target, []byte(secretBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(archiveDir, "config-1757000000.9.conf")); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(archiveDir, "config-1757000000.1.conf")
	if err := os.WriteFile(regular, []byte("regular snapshot\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := DefaultArchiveDir
	DefaultArchiveDir = archiveDir
	t.Cleanup(func() { DefaultArchiveDir = old })
	err := FactoryResetArchiveDir(archiveDir)
	var symErr *FactoryResetSymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("GPT-3 archive interior: expected FactoryResetSymlinkError, got %v; "+
			"link unlinked while %s survives silently", err, target)
	}
	found := false
	for _, sk := range symErr.Skipped {
		if sk.Target == target || strings.Contains(sk.Target, "config-1757000000.9.conf") {
			found = true
		}
		if !bytes.Contains([]byte(symErr.Error()), []byte(sk.Target)) {
			t.Fatalf("GPT-3 archive interior: error text omits target %q: %v", sk.Target, symErr)
		}
	}
	if !found {
		t.Fatalf("GPT-3 archive interior: Skipped %v does not name %s", symErr.Skipped, target)
	}
	got, rerr := os.ReadFile(target)
	if rerr != nil || string(got) != secretBody {
		t.Fatalf("GPT-3 archive interior: surviving target lost or altered: %v", rerr)
	}
	if _, serr := os.Lstat(regular); !os.IsNotExist(serr) {
		t.Fatal("GPT-3 archive interior: regular snapshot was not erased")
	}
}
