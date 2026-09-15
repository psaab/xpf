package journal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const spoofedDetail9897 = "SPOOFED-BY-LINK-TARGET"

// #9897 F-038: the READ side must refuse a symlinked segment the way the append
// side already does. tailSegment opens with a bare os.Open (no O_NOFOLLOW, no
// IsRegular check) while appendLocked opens with O_NOFOLLOW + an fstat
// IsRegular gate — so `show system commit`/history renders attacker-chosen
// JSONL as genuine history. readAllLocked (the Tail(0) path) has the same bare
// os.ReadFile.
func TestTailRefusesSymlinkedSegment9897(t *testing.T) {
	plant := func(t *testing.T) (link, target string) {
		t.Helper()
		root := t.TempDir()
		target = filepath.Join(root, "evil.jsonl")
		body := `{"timestamp":"2026-01-01T00:00:00Z","action":"commit","Detail":"` +
			spoofedDetail9897 + `"}` + "\n"
		if err := os.WriteFile(target, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		link = filepath.Join(root, ".config.journal")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		return link, target
	}

	t.Run("Tail-limit", func(t *testing.T) {
		link, target := plant(t)
		got, err := New(link).Tail(50)
		if err == nil {
			t.Fatalf("Tail through a SYMLINKED segment = nil error (%d entries); "+
				"attacker JSONL renders as genuine history -- the #9897 F-038 defect",
				len(got))
		}
		if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), target) {
			t.Fatalf("error must name the link AND its target, got: %v", err)
		}
		for _, e := range got {
			if e.Detail == spoofedDetail9897 {
				t.Fatal("spoofed entry was returned as genuine history")
			}
		}
	})

	t.Run("Tail-0-readAll", func(t *testing.T) {
		link, target := plant(t)
		got, err := New(link).Tail(0)
		if err == nil {
			t.Fatalf("Tail(0) through a SYMLINKED segment = nil error (%d entries); "+
				"the readAllLocked path follows the link too", len(got))
		}
		if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), target) {
			t.Fatalf("error must name the link AND its target, got: %v", err)
		}
	})
}

// The IsRegular half of the F-038 discipline: a non-regular file planted at a
// segment path (here a directory) must be refused as not-a-segment, not read
// (or failed opaquely mid-scan).
func TestTailRefusesNonRegularSegment9897(t *testing.T) {
	root := t.TempDir()
	j := New(filepath.Join(root, ".config.journal"))
	mustLog(t, j, &Entry{Action: "commit", Detail: "c0"})
	// Segment .1 as a directory: Tail(50) scans seg0 (1 entry < 50) then seg1.
	if err := os.Mkdir(j.segmentPath(1), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := j.Tail(50)
	if err == nil {
		t.Fatal("Tail over a DIRECTORY segment = nil error; want a refusal")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("want a not-a-regular-file refusal, got: %v", err)
	}
}

// #9897 F-108: maybeRotateLocked stats THROUGH a symlinked current segment (the
// target's size drives rotation) and then renames the LINK into .1, laundering
// the planted link into a segment every later read follows — while the sibling
// oldestSegmentHasInflightAppendLocked deliberately uses Lstat.
func TestRotateRefusesSymlinkedCurrent9897(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "bigvictim")
	if err := os.WriteFile(target, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, ".config.journal")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	j := New(link, WithMaxSegmentBytes(64))

	err := j.Log(&Entry{Action: "commit", Detail: "c0"})
	if err == nil {
		t.Fatalf("Log through a SYMLINKED current segment succeeded; the link is " +
			"laundered into a rotated segment -- the #9897 F-108 defect")
	}
	if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), target) {
		t.Fatalf("error must name the link AND its target, got: %v", err)
	}
	// The link must NOT have been renamed into a segment slot.
	if fi, lerr := os.Lstat(link + ".1"); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("planted link was renamed into .1: later reads follow the laundered link")
	}
}

// CONTROL: ordinary rotation still launders nothing and keeps history — a small
// threshold rotates a REGULAR current file into a REGULAR .1, and both Tail
// paths read it back byte-identical.
func TestRotateOrdinaryPathUnaffected9897(t *testing.T) {
	j := testJournal(t, WithMaxSegmentBytes(256))
	mustLog(t, j, &Entry{Action: "commit", Detail: "c0"})
	for i := 1; i < 6; i++ {
		mustLog(t, j, &Entry{Action: "commit", Detail: fmt.Sprintf("c%d", i)})
	}
	fi, err := os.Lstat(j.segmentPath(1))
	if err != nil {
		t.Fatalf("ordinary rotation produced no .1: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		t.Fatalf(".1 has mode %s, want a regular file", fi.Mode())
	}
	for _, limit := range []int{50, 0} {
		got, terr := j.Tail(limit)
		if terr != nil {
			t.Fatalf("Tail(%d) on an ordinary rotated journal: %v", limit, terr)
		}
		if len(got) != 6 {
			t.Fatalf("Tail(%d): want 6 entries, got %d", limit, len(got))
		}
	}
}

// A DANGLING link at a segment path is a link, not a gap: the pre-fix code maps
// the open ENOENT to "missing segment" and skips it, so a planted dangling link
// is silently tolerated. The Lstat pre-check refuses it deterministically.
func TestTailRefusesDanglingSegment9897(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, ".config.journal")
	target := filepath.Join(root, "nowhere.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{50, 0} {
		if _, err := New(link).Tail(limit); err == nil {
			t.Fatalf("Tail(%d) over a DANGLING-link segment = nil error; want a "+
				"refusal naming the link", limit)
		} else if !strings.Contains(err.Error(), link) ||
			!strings.Contains(err.Error(), target) {
			t.Fatalf("Tail(%d) error must name the link AND its target, got: %v",
				limit, err)
		}
	}
}

// A FIFO planted at a segment path must be REFUSED, not hung on: a plain
// O_RDONLY open blocks until a writer appears, so the helper must open
// O_NONBLOCK and let the fstat IsRegular gate refuse it. The bounded goroutine
// turns the pre-fix hang into a RED timeout instead of a wedged suite.
func TestTailRefusesFifoSegmentWithoutHanging9897(t *testing.T) {
	root := t.TempDir()
	j := New(filepath.Join(root, ".config.journal"))
	mustLog(t, j, &Entry{Action: "commit", Detail: "c0"})
	if err := syscall.Mkfifo(j.segmentPath(1), 0o644); err != nil {
		t.Fatal(err)
	}
	type result struct {
		entries int
		err     error
	}
	done := make(chan result, 1)
	go func() {
		got, err := j.Tail(50)
		done <- result{entries: len(got), err: err}
	}()
	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("Tail over a FIFO segment = nil error (%d entries); want a refusal",
				r.entries)
		}
		if !strings.Contains(r.err.Error(), "not a regular file") {
			t.Fatalf("want a not-a-regular-file refusal, got: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Tail over a FIFO segment hung: the segment open must be O_NONBLOCK")
	}
}

// CONTROL: a symlinked PARENT directory keeps working — O_NOFOLLOW constrains
// only the final component (the same argument as the append path's doc), so a
// journal reached through a directory link logs and tails byte-identical.
func TestJournalThroughSymlinkedParentUnaffected9897(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "parent")
	if err := os.Symlink(real, parent); err != nil {
		t.Fatal(err)
	}
	j := New(filepath.Join(parent, ".config.journal"))
	mustLog(t, j, &Entry{Action: "commit", Detail: "c0"})
	for _, limit := range []int{50, 0} {
		got, err := j.Tail(limit)
		if err != nil {
			t.Fatalf("Tail(%d) through a symlinked parent: %v", limit, err)
		}
		if len(got) != 1 || got[0].Detail != "c0" {
			t.Fatalf("Tail(%d) through a symlinked parent: %+v, want [c0]", limit, got)
		}
	}
}
