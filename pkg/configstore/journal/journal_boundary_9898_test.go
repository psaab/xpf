package journal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLogRefusesOversizedEntry_9898 (F-110) pins a byte bound INSIDE Journal.Log.
// On base Log marshals and appends with no size bound; the only cap is the
// caller belt in Store.journalLog (4 KiB Detail truncate), so a direct Log
// caller with a pathological Detail gets a nil error while the bounded
// reverse-tail scanner later discards the poisoned line — a silently lost
// audit record with success reported. Post-fix Log refuses a marshaled entry
// past the bound with an error and appends nothing.
//
// The bound (64 KiB) holds the belted path (~4.3 KiB typical for a maxed
// Detail plus framing; ~24.8 KiB worst case when every Detail byte
// JSON-escapes 6x) and stays 256x below the 16 MiB scanner line cap.
//
// RED on base: the oversized Log returns nil and the record lands on disk.
func TestLogRefusesOversizedEntry_9898(t *testing.T) {
	t.Run("oversized refused", func(t *testing.T) {
		j := testJournal(t)
		err := j.Log(&Entry{Action: "commit", Detail: strings.Repeat("d", 1<<20)})
		if err == nil {
			t.Fatalf("Log(1MiB Detail) = nil error; want a bound refusal")
		}
		got, terr := j.Tail(0)
		if terr != nil {
			t.Fatalf("Tail: %v", terr)
		}
		if len(got) != 0 {
			t.Fatalf("refused entry left %d record(s) on disk; want none", len(got))
		}
	})

	t.Run("belted-size accepted", func(t *testing.T) {
		j := testJournal(t)
		// The largest Detail Store.journalLog can hand over (4 KiB cap)
		// plus framing must pass with wide margin.
		if err := j.Log(&Entry{Action: "commit", Detail: strings.Repeat("d", 4096)}); err != nil {
			t.Fatalf("Log(4KiB Detail) errored: %v; the bound must not touch the belted path", err)
		}
		got, err := j.Tail(0)
		if err != nil || len(got) != 1 {
			t.Fatalf("Tail = %d entries, %v; want 1, nil", len(got), err)
		}
	})

	t.Run("boundary exact", func(t *testing.T) {
		// A fixed timestamp keeps the framing byte-exact (time.Time
		// marshals with variable fractional digits).
		fixed := time.Date(2026, 9, 15, 10, 0, 0, 123456789, time.UTC)
		frame, err := json.Marshal(&Entry{Timestamp: fixed, Schema: SchemaV2, Action: "commit"})
		if err != nil {
			t.Fatal(err)
		}
		probe, err := json.Marshal(&Entry{Timestamp: fixed, Schema: SchemaV2, Action: "commit", Detail: "a"})
		if err != nil {
			t.Fatal(err)
		}
		// Self-calibrating: a non-empty Detail adds its bytes plus the
		// `,"Detail":"…"` framing (12 bytes today); "a" never escapes, so
		// Detail bytes add 1:1 past the overhead.
		overhead := len(probe) - 1 - len(frame)
		n := maxJournalEntryBytes - len(frame) - overhead
		j := testJournal(t)
		if err := j.Log(&Entry{Timestamp: fixed, Action: "commit", Detail: strings.Repeat("a", n)}); err != nil {
			t.Fatalf("Log(exactly %d marshaled bytes) errored: %v; the bound refuses past-cap, not at-cap", maxJournalEntryBytes, err)
		}
		if err := j.Log(&Entry{Timestamp: fixed, Action: "commit", Detail: strings.Repeat("a", n+1)}); err == nil {
			t.Fatalf("Log(%d marshaled bytes) = nil error; want refusal one past the bound", maxJournalEntryBytes+1)
		}
		got, err := j.Tail(0)
		if err != nil || len(got) != 1 {
			t.Fatalf("Tail = %d entries, %v; want exactly the accepted one", len(got), err)
		}
	})

	t.Run("bound is on serialized bytes", func(t *testing.T) {
		j := testJournal(t)
		// Worst-case escaping of a belted-size Detail (~24.6 KiB
		// serialized) still passes.
		if err := j.Log(&Entry{Action: "commit", Detail: strings.Repeat("\x00", 4096)}); err != nil {
			t.Fatalf("Log(escaped belted Detail) errored: %v", err)
		}
		// 11 KiB raw that escapes past the bound refuses: the bound sees
		// what the scanner would have to swallow, not the Go string.
		if err := j.Log(&Entry{Action: "commit", Detail: strings.Repeat("\x00", 11000)}); err == nil {
			t.Fatalf("Log(11KiB raw, ~66KiB serialized) = nil error; want refusal on serialized size")
		}
	})

	t.Run("refusal neither appends nor rotates", func(t *testing.T) {
		// maxSegmentBytes=1 rotates on every append past the first, so a
		// refusal ordered after rotation would leave a .1 behind.
		dir := t.TempDir()
		j := New(dir+"/.config.journal", WithMaxSegmentBytes(1))
		mustLog(t, j, &Entry{Action: "commit", Detail: "first"})
		if err := j.Log(&Entry{Action: "commit", Detail: strings.Repeat("d", 1<<20)}); err == nil {
			t.Fatalf("oversized Log = nil error; want refusal")
		}
		if _, err := os.Stat(dir + "/.config.journal.1"); !os.IsNotExist(err) {
			t.Fatalf("refused Log rotated (segment .1 exists, stat=%v); want no rotation on refusal", err)
		}
		got, err := j.Tail(0)
		if err != nil || len(got) != 1 || got[0].Detail != "first" {
			t.Fatalf("Tail after refusal = %+v, %v; want exactly the first entry", got, err)
		}
	})
}

// restorePermSeams restores the permission-repair seams after a test mutates one.
func restorePermSeams(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		journalLstat = os.Lstat
		journalChmod = os.Chmod
	})
}

var errInjectedPerm9898 = errors.New("injected 9898 perm failure")

// TestPermRepairFailureDegraded_9898 (F-113) pins retry + health signal for
// permission repair. On base a failed repair is one warning: migrated sticks
// true and nothing ever retries or reports. Post-fix the failure latches
// PermRepairDegraded, appends CONTINUE (journaling must never fail a
// commit), the next use retries, and a fully-successful pass clears the flag
// with the file actually tightened.
//
// Base RED is structural (no retry/signal exists to exercise); the test is
// revert-checked: restoring unconditional `migrated = true` fails the retry
// and recovery assertions below.
func TestPermRepairFailureDegraded_9898(t *testing.T) {
	t.Run("failure degrades, appends continue, recovery clears", func(t *testing.T) {
		restorePermSeams(t)
		dir := t.TempDir()
		seg := filepath.Join(dir, ".config.journal")
		if err := os.WriteFile(seg, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(seg, 0644); err != nil { // explicit: umask-proof
			t.Fatal(err)
		}
		journalChmod = func(path string, mode os.FileMode) error { return errInjectedPerm9898 }
		j := New(seg)
		if err := j.Log(&Entry{Action: "commit", Detail: "one"}); err != nil {
			t.Fatalf("Log while repair fails errored: %v; appends must continue while degraded", err)
		}
		if !j.PermRepairDegraded() {
			t.Fatalf("failed repair left PermRepairDegraded false; want latched degraded")
		}
		if mode := fileMode9898(t, seg); mode != 0644 {
			t.Fatalf("segment mode = %o; want still-0644 (repair never landed)", mode)
		}
		// Heal the seam: the next use retries and clears.
		journalChmod = os.Chmod
		if err := j.Log(&Entry{Action: "commit", Detail: "two"}); err != nil {
			t.Fatal(err)
		}
		if j.PermRepairDegraded() {
			t.Fatalf("successful retry left PermRepairDegraded true; want cleared")
		}
		if mode := fileMode9898(t, seg); mode != 0600 {
			t.Fatalf("segment mode = %o; want 0600 after retry", mode)
		}
		got, err := j.Tail(0)
		if err != nil || len(got) != 2 {
			t.Fatalf("Tail = %d entries, %v; want both appends intact", len(got), err)
		}
	})

	t.Run("every use retries while failing", func(t *testing.T) {
		restorePermSeams(t)
		var calls int
		journalChmod = func(path string, mode os.FileMode) error {
			calls++
			return errInjectedPerm9898
		}
		dir := t.TempDir()
		seg := filepath.Join(dir, ".config.journal")
		if err := os.WriteFile(seg, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(seg, 0644); err != nil {
			t.Fatal(err)
		}
		j := New(seg)
		mustLog(t, j, &Entry{Action: "commit", Detail: "one"})
		first := calls
		if first == 0 {
			t.Fatalf("first Log attempted no chmod; fixture broken")
		}
		mustLog(t, j, &Entry{Action: "commit", Detail: "two"})
		if calls <= first {
			t.Fatalf("second Log attempted no new chmod (%d then %d); want retry on every use", first, calls)
		}
	})

	t.Run("rotation failure degrades and rearms", func(t *testing.T) {
		restorePermSeams(t)
		dir := t.TempDir()
		seg := filepath.Join(dir, ".config.journal")
		j := New(seg, WithMaxSegmentBytes(64))
		mustLog(t, j, &Entry{Action: "commit", Detail: "seed"})
		if j.PermRepairDegraded() {
			t.Fatalf("clean migration left degraded set; fixture broken")
		}
		// A 0644 current rotates into a 0644 .1 while the re-assert fails.
		if err := os.Chmod(seg, 0644); err != nil {
			t.Fatal(err)
		}
		journalLstat = func(path string) (os.FileInfo, error) { return nil, errInjectedPerm9898 }
		mustLog(t, j, &Entry{Action: "commit", Detail: "rotates"})
		rot := seg + ".1"
		if _, err := os.Stat(rot); err != nil {
			t.Fatalf("rotation did not happen: %v; fixture broken", err)
		}
		if !j.PermRepairDegraded() {
			t.Fatalf("failed rotation re-assert left degraded false; want latched")
		}
		if mode := fileMode9898(t, rot); mode != 0644 {
			t.Fatalf("rotated segment mode = %o; want still-0644 (re-assert never landed)", mode)
		}
		// Heal: the next Tail retries the FULL pass (re-armed) and clears.
		journalLstat = os.Lstat
		if _, err := j.Tail(0); err != nil {
			t.Fatal(err)
		}
		if j.PermRepairDegraded() {
			t.Fatalf("successful repair left degraded true; want cleared")
		}
		if mode := fileMode9898(t, rot); mode != 0600 {
			t.Fatalf("rotated segment mode = %o; want 0600 after retry", mode)
		}
	})

	t.Run("symlink skip is not failure", func(t *testing.T) {
		restorePermSeams(t)
		dir := t.TempDir()
		target := filepath.Join(dir, "real.journal")
		if err := os.WriteFile(target, nil, 0644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, ".config.journal")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		j := New(link)
		// The append itself refuses the link (pre-existing #9897 behavior);
		// the point here is the repair layer reports skip, not failure.
		if err := j.Log(&Entry{Action: "commit"}); err == nil {
			t.Fatalf("Log through symlinked segment = nil error; want the append refusal")
		}
		if j.PermRepairDegraded() {
			t.Fatalf("symlink skip latched degraded; want skip-is-not-failure")
		}
		if !j.migrated {
			t.Fatalf("symlink skip left migrated false; want the pass complete")
		}
	})
}

func fileMode9898(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// TestReadAllRefusesOversizedSegment_9898 (F-114, byte-cap half) pins a bound
// on the limit<=0 full-scan path. On base readAllLocked io.ReadAlls every
// segment with no byte cap — a garbage/huge segment balloons memory before
// any check. (The O_NOFOLLOW half of F-114 is already fixed on base by #9897:
// readAllLocked routes through openSegmentNoFollow.) Post-fix a segment past
// the per-segment cap fails closed with nil history plus an error rather
// than materializing unboundedly; partial-as-complete history is never
// returned, including an overflow in a newer segment after older ones
// parsed fine.
//
// RED on base: Tail(0) over a 20 MiB segment returns nil error.
func TestReadAllRefusesOversizedSegment_9898(t *testing.T) {
	// Valid legacy-style lines (~1 KiB each): the refusal is about BYTES,
	// not malformed content.
	validLine := func(detail string) string {
		return `{"v":2,"timestamp":"2026-09-15T10:00:00Z","action":"commit","Detail":"` + detail + "\"}\n"
	}
	oversized := func(t *testing.T) []byte {
		t.Helper()
		pad := strings.Repeat("x", 900)
		var b strings.Builder
		b.Grow(20 << 20)
		for b.Len() < 20<<20 {
			b.WriteString(validLine(pad))
		}
		return []byte(b.String())
	}

	t.Run("oversized refused with nil history", func(t *testing.T) {
		dir := t.TempDir()
		seg := filepath.Join(dir, ".config.journal")
		if err := os.WriteFile(seg, oversized(t), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := New(seg).Tail(0)
		if err == nil {
			t.Fatalf("Tail(0) over a 20 MiB segment = nil error; want a bound refusal")
		}
		if got != nil {
			t.Fatalf("Tail(0) over refusal returned %d entries; want nil history, never partial", len(got))
		}
	})

	t.Run("later segment overflow yields nil not partial", func(t *testing.T) {
		dir := t.TempDir()
		seg := filepath.Join(dir, ".config.journal")
		// Older segment parses fine; the NEWER one overflows. The scan
		// reads oldest-first, so this proves a late overflow discards the
		// already-parsed prefix instead of returning it as complete.
		old := validLine("kept-a") + validLine("kept-b")
		if err := os.WriteFile(seg+".1", []byte(old), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(seg, oversized(t), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := New(seg).Tail(0)
		if err == nil {
			t.Fatalf("Tail(0) with overflowing newer segment = nil error; want refusal")
		}
		if got != nil {
			t.Fatalf("Tail(0) returned %d entries alongside the error; want nil, never partial", len(got))
		}
	})

	t.Run("ordinary journal reads", func(t *testing.T) {
		j := testJournal(t)
		mustLog(t, j, &Entry{Action: "commit", Detail: "a"})
		mustLog(t, j, &Entry{Action: "commit", Detail: "b"})
		got, err := j.Tail(0)
		if err != nil || len(got) != 2 {
			t.Fatalf("Tail(0) = %d entries, %v; want 2, nil", len(got), err)
		}
	})
}
