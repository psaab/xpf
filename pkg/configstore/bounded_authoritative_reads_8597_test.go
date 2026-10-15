package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #8597 (muse-004 K70) — the most privileged reads on the boot path were the
// least bounded.
//
// This module already has an answer to an unbounded authoritative read:
// ReadBoundedFile (#6753/#4909), which caps the read AND refuses a non-regular
// file. The comment at ReadBoundedConfigFile states the reasoning — a ceiling
// enforced only AFTER the file is resident "bounds what the store will ACCEPT,
// never what a caller will ALLOCATE".
//
// Six reads had not been brought along, and the most important was the
// SSOT the daemon must load to take over (active.json via readTreeMeta) and
// the commit-confirmed record (confirm.json via ReadConfirm).
//
// The finding names those two. A census of os.ReadFile in this package found
// SIX: the rescue config text, the text rollback slots, and both master-key
// reads were also unbounded — the last pair reading a whole file before
// checking that its length is exactly 32.

// TestNoUnboundedAuthoritativeReadRemains_8597 is the census, and it is the
// cell that catches a SEVENTH site appearing later.
//
// It scans the package source rather than exercising each path, because the
// property is "no authoritative read uses os.ReadFile" and that is a statement
// about the code, not about one execution. The positive control below keeps it
// from passing on a broken pattern.
func TestNoUnboundedAuthoritativeReadRemains_8597(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var offenders []string
	var scanned int
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		scanned++
		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			// Comments are not code. A census that matches its own explanatory
			// prose reports the property as broken whether or not it is.
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(line, "os.ReadFile(") {
				offenders = append(offenders, f+":"+itoa8597(i+1)+": "+trimmed)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("the census scanned no files; the glob is wrong, not the package clean")
	}
	if len(offenders) > 0 {
		t.Errorf("unbounded read(s) in pkg/configstore — use ReadBoundedFile, which "+
			"also refuses a non-regular file (#6753/#4909/#8597):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// TestCensusCanSeeAnUnboundedRead_8597 is the POSITIVE CONTROL for the census.
// "No offenders" is also what a broken pattern returns, so this proves the
// scan finds the string when it is present — in this very file, which uses
// os.ReadFile legitimately as a TEST helper.
func TestCensusCanSeeAnUnboundedRead_8597(t *testing.T) {
	src, err := os.ReadFile("bounded_authoritative_reads_8597_test.go")
	if err != nil {
		t.Fatalf("read self: %v", err)
	}
	if !strings.Contains(string(src), "os.ReadFile(") {
		t.Fatal("the census pattern does not appear in a file known to contain it; " +
			"the pattern is wrong and a clean result from it means nothing")
	}
}

// TestAuthoritativeReadsRefuseAnOversizedFile_8597 drives the two the finding
// names, end to end, so the census above is backed by behaviour rather than by
// source shape alone.
func TestAuthoritativeReadsRefuseAnOversizedFile_8597(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, MaxConfigSize+1)
	for i := range big {
		big[i] = 'a'
	}

	t.Run("readTreeMeta", func(t *testing.T) {
		path := filepath.Join(dir, "active.json")
		if err := os.WriteFile(path, big, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		db := &DB{dir: dir}
		_, _, err := db.readTreeMeta(path)
		if err == nil {
			t.Fatal("readTreeMeta accepted a file above MaxConfigSize; the SSOT the " +
				"daemon must load to take over is the one read that must not be able " +
				"to exhaust memory before any gate runs (#8597/K70)")
		}
		if !errors.Is(err, ErrExceedsLimit) {
			t.Errorf("refused for the wrong reason: %v (want ErrExceedsLimit)", err)
		}
	})

	t.Run("ReadConfirm", func(t *testing.T) {
		db := &DB{dir: filepath.Join(dir, "db2")}
		if err := os.MkdirAll(db.dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(db.confirmPath(), big, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := db.ReadConfirm()
		if err == nil {
			t.Fatal("ReadConfirm accepted a file above MaxConfigSize")
		}
		if !errors.Is(err, ErrExceedsLimit) {
			t.Errorf("refused for the wrong reason: %v (want ErrExceedsLimit)", err)
		}
	})
}

// TestOrdinaryAuthoritativeReadsStillWork_8597 is the OVER-BROAD control. A
// bound that refused a normal file would brick every boot, and ReadBoundedFile
// additionally refuses non-regular files — so a path that legitimately does not
// exist must still read as absent rather than as an error.
func TestOrdinaryAuthoritativeReadsStillWork_8597(t *testing.T) {
	dir := t.TempDir()
	db := &DB{dir: dir}

	// Absent confirm.json is the common case and must stay (nil, nil).
	rec, err := db.ReadConfirm()
	if err != nil || rec != nil {
		t.Errorf("absent confirm.json gave (%v, %v), want (nil, nil) — an absent file "+
			"is not an error on this path", rec, err)
	}

	// Absent tree file: (nil, true, nil) per readTreeMeta's contract.
	tree, committed, err := db.readTreeMeta(filepath.Join(dir, "nope.json"))
	if err != nil || tree != nil || !committed {
		t.Errorf("absent tree gave (%v, %v, %v), want (nil, true, nil)", tree, committed, err)
	}

	// A REAL config DB must round-trip. This is the half the first draft of
	// this control missed: it tested only ABSENT files, which never reach the
	// read at all — so an absurdly small ceiling (8 bytes) passed every cell.
	// The mutation is what said so.
	if err := os.MkdirAll(db.dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	want := &config.ConfigTree{Children: []*config.Node{{Keys: []string{"system", "host-name", "fw1"}}}}
	if err := db.WriteActive(want); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	got, _, err := db.readTreeMeta(db.activePath())
	if err != nil {
		t.Fatalf("readTreeMeta refused an ordinary config DB: %v — the ceiling must "+
			"bound a hostile file, not a real one", err)
	}
	if got == nil || len(got.Children) != 1 || len(got.Children[0].Keys) != 3 {
		t.Fatalf("round-trip lost the tree: %+v", got)
	}
}

func itoa8597(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
