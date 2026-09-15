package fsatomic

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteDetectsShortWrite_9898 (F-115, count half) pins the n==len(data)
// assertion. On base the write count is discarded (`if _, err :=
// writeTemp(...)`), so a short write that reports nil error installs a
// truncated file with success returned. Post-fix a short count fails the
// write and leaves no target behind (an existing target keeps its old
// content — the rename that would clobber it never runs).
//
// Scope note: os.File.Write already reports a short count as an error, so
// the production seam cannot return short-nil today; this is a
// defense-in-depth contract assertion plus seam uniformity, not a reachable
// production truncation. The fixture writes only its reported prefix, like a
// real short write, rather than writing everything and lying about the count.
//
// RED on base: both short-write variants return nil error (and the
// existing-target variant clobbers the old content).
func TestWriteDetectsShortWrite_9898(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    func(full int) int
	}{
		{"zero count nil error", func(int) int { return 0 }},
		{"partial count nil error", func(full int) int { return full - 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetSeams(t)
			writeTemp = func(f *os.File, b []byte) (int, error) {
				want := tc.n(len(b))
				if _, err := f.Write(b[:want]); err != nil {
					return 0, err
				}
				return want, nil
			}
			for _, durable := range []bool{false, true} {
				dir := t.TempDir()
				path := filepath.Join(dir, "out.conf")
				err := writeFile(path, []byte("0123456789abcdef"), 0600, durable)
				if err == nil {
					t.Fatalf("writeFile(durable=%v) with short count = nil error; want a short-write refusal", durable)
				}
				if _, serr := os.Stat(path); !os.IsNotExist(serr) {
					t.Fatalf("short write left target behind (stat=%v); want no target", serr)
				}
				assertNoTemps(t, dir)
			}
		})
	}
}

// TestWriteShortWritePreservesExistingTarget_9898 pins that a refused short
// write leaves a pre-existing target untouched: the failure lands before the
// rename, so the old content is never replaced by a truncation.
func TestWriteShortWritePreservesExistingTarget_9898(t *testing.T) {
	resetSeams(t)
	writeTemp = func(f *os.File, b []byte) (int, error) {
		_, _ = f.Write(b[:len(b)-1])
		return len(b) - 1, nil
	}
	for _, durable := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "out.conf")
		if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := writeFile(path, []byte("0123456789abcdef"), 0600, durable); err == nil {
			t.Fatalf("writeFile(durable=%v) with short count = nil error", durable)
		}
		if got := mustRead(t, path); got != "original" {
			t.Fatalf("short write clobbered the target: %q, want %q", got, "original")
		}
		assertNoTemps(t, dir)
	}
}

// TestWriteEmptyDataSucceeds_9898 pins the zero edge of the count assertion:
// an empty write reports n=0=len(data) and must succeed, not trip the
// short-write refusal.
func TestWriteEmptyDataSucceeds_9898(t *testing.T) {
	for _, durable := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "empty.conf")
		if err := writeFile(path, nil, 0600, durable); err != nil {
			t.Fatalf("writeFile(durable=%v, empty) errored: %v", durable, err)
		}
		if got := mustRead(t, path); got != "" {
			t.Fatalf("empty write content = %q, want empty", got)
		}
		assertNoTemps(t, dir)
	}
}

// TestWriteErrorPathsUseCloseSeam_9898 (F-115, seam half) pins a single close
// seam. On base the four pre-rename error paths call tmp.Close directly while
// only the success path routes through closeTemp, so injected close behavior
// (and any future accounting on the seam) is bypassed exactly when the write
// is failing. Post-fix every close routes through closeTemp.
//
// RED on base: the closeTemp spy never fires on error paths.
func TestWriteErrorPathsUseCloseSeam_9898(t *testing.T) {
	injected := errors.New("injected 9898 failure")
	cases := []struct {
		name    string
		durable bool
		breakIt func()
		opt     []Option
	}{
		{"write", false, func() {
			writeTemp = func(f *os.File, b []byte) (int, error) { return 0, injected }
		}, nil},
		{"chmod", false, func() {
			chmodTemp = func(f *os.File, m os.FileMode) error { return injected }
		}, nil},
		{"chown", false, func() {
			chownTemp = func(f *os.File, uid, gid int) error { return injected }
		}, []Option{WithOwner(4242, 4242)}},
		{"sync", true, func() {
			syncFile = func(f *os.File) error { return injected }
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetSeams(t)
			tc.breakIt()
			var closed int
			closeTemp = func(f *os.File) error {
				closed++
				return f.Close()
			}
			dir := t.TempDir()
			err := writeFile(filepath.Join(dir, "out.conf"), []byte("data"), 0600, tc.durable, tc.opt...)
			if err == nil {
				t.Fatalf("writeFile with failing %s = nil error; fixture broken", tc.name)
			}
			if closed != 1 {
				t.Fatalf("failing-%s path reached closeTemp %d times; want 1 (bare tmp.Close bypasses the seam)", tc.name, closed)
			}
			assertNoTemps(t, dir)
		})
	}
}
