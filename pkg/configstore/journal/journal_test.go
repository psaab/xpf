package journal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testJournal(t *testing.T, opts ...Option) *Journal {
	t.Helper()
	return New(filepath.Join(t.TempDir(), ".config.journal"), opts...)
}

func mustLog(t *testing.T, j *Journal, e *Entry) {
	t.Helper()
	if err := j.Log(e); err != nil {
		t.Fatalf("Log: %v", err)
	}
}

func TestLogTailRoundTrip(t *testing.T) {
	j := testJournal(t)
	for i := 0; i < 10; i++ {
		mustLog(t, j, &Entry{Action: "commit", Detail: fmt.Sprintf("c%d", i), ConfigHash: "abc"})
	}
	got, err := j.Tail(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}
	// Oldest-first of the last 3.
	for i, want := range []string{"c7", "c8", "c9"} {
		if got[i].Detail != want {
			t.Errorf("entry %d: want detail %q, got %q", i, want, got[i].Detail)
		}
		if got[i].Schema != SchemaV2 {
			t.Errorf("entry %d: want schema %d, got %d", i, SchemaV2, got[i].Schema)
		}
		if got[i].ConfigHash != "abc" {
			t.Errorf("entry %d: want config hash abc, got %q", i, got[i].ConfigHash)
		}
		if got[i].Timestamp.IsZero() {
			t.Errorf("entry %d: timestamp not defaulted", i)
		}
	}
	// limit <= 0 returns everything.
	all, err := j.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 10 {
		t.Fatalf("Tail(0): want 10 entries, got %d", len(all))
	}
	if all[0].Detail != "c0" || all[9].Detail != "c9" {
		t.Fatalf("Tail(0) order wrong: first %q last %q", all[0].Detail, all[9].Detail)
	}
}

func TestTailMissingJournal(t *testing.T) {
	j := testJournal(t)
	got, err := j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want no entries, got %d", len(got))
	}
	if got, err := j.Tail(0); err != nil || len(got) != 0 {
		t.Fatalf("Tail(0) on missing journal: %v, %d entries", err, len(got))
	}
}

// countingReaderAt proves boundedness: it records how many bytes Tail
// actually reads.
type countingReaderAt struct {
	r         io.ReaderAt
	bytesRead int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.bytesRead += int64(n)
	return n, err
}

// TestTailBoundedRead is the issue's headline requirement: a journal
// with thousands of entries must serve Tail(50) by reading O(50)
// entries from the end, not the whole file.
func TestTailBoundedRead(t *testing.T) {
	j := testJournal(t)
	for i := 0; i < 5000; i++ {
		mustLog(t, j, &Entry{Action: "commit", Detail: fmt.Sprintf("commit number %d with a comment", i)})
	}
	f, err := os.Open(j.path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() < 4*readChunk {
		t.Fatalf("test journal too small (%d bytes) to prove boundedness", fi.Size())
	}

	cr := &countingReaderAt{r: f}
	entries, err := tailScan(cr, fi.Size(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 50 {
		t.Fatalf("want 50 entries, got %d", len(entries))
	}
	// 50 compact entries fit in one chunk; allow two for boundary slop.
	if cr.bytesRead > 2*readChunk {
		t.Fatalf("Tail(50) read %d bytes of a %d-byte journal — not bounded", cr.bytesRead, fi.Size())
	}
	if entries[0].Detail != "commit number 4999 with a comment" {
		t.Fatalf("newest-first order wrong: %q", entries[0].Detail)
	}
}

func BenchmarkTail50(b *testing.B) {
	j := New(filepath.Join(b.TempDir(), ".config.journal"))
	for i := 0; i < 2000; i++ {
		if err := j.Log(&Entry{Action: "commit", Detail: fmt.Sprintf("commit %d", i)}); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entries, err := j.Tail(50)
		if err != nil {
			b.Fatal(err)
		}
		if len(entries) != 50 {
			b.Fatalf("want 50, got %d", len(entries))
		}
	}
}

// legacyV1Line builds a journal line the v1 writer would have produced:
// full compiled-config payloads in "before"/"after", detail always
// present (no omitempty), no schema marker.
func legacyV1Line(ts time.Time, action, detail string, payloadBytes int) string {
	blob := strings.Repeat("x", payloadBytes)
	return fmt.Sprintf(`{"timestamp":%q,"action":%q,"detail":%q,"before":null,"after":{"hostname":%q}}`,
		ts.Format(time.RFC3339Nano), action, detail, blob)
}

// TestTailLegacyFatLines: legacy v1 entries with payloads far larger
// than the scan chunk decode tolerantly (unknown fields ignored) and
// multi-chunk line assembly reconstructs them correctly.
func TestTailLegacyFatLines(t *testing.T) {
	j := testJournal(t)
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	var sb strings.Builder
	for i := 0; i < 5; i++ {
		// 3x the chunk size: each line spans at least 4 chunks.
		sb.WriteString(legacyV1Line(ts.Add(time.Duration(i)*time.Minute), "commit", fmt.Sprintf("legacy %d", i), 3*readChunk))
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(j.path, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := j.Tail(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}
	for i, want := range []string{"legacy 2", "legacy 3", "legacy 4"} {
		if got[i].Detail != want {
			t.Errorf("entry %d: want %q, got %q", i, want, got[i].Detail)
		}
		if got[i].Schema != 0 {
			t.Errorf("entry %d: legacy schema must be 0, got %d", i, got[i].Schema)
		}
		if got[i].Action != "commit" {
			t.Errorf("entry %d: action %q", i, got[i].Action)
		}
	}
	if !got[0].Timestamp.Equal(ts.Add(2 * time.Minute)) {
		t.Errorf("legacy timestamp mismatch: %v", got[0].Timestamp)
	}
}

// TestTailUTF8AtChunkBoundary (AGY plan-r1 F2): a multi-byte rune
// split exactly across the reverse-scan chunk boundary must survive
// reassembly. The scanner works on bytes; this proves no rune-level
// corruption.
func TestTailUTF8AtChunkBoundary(t *testing.T) {
	j := testJournal(t)
	// Build the file so the LAST chunk boundary (size - readChunk)
	// falls inside a known multi-byte sequence in the final entry's
	// detail. Make one entry whose detail is umlauts spanning well
	// over the boundary region, preceded by filler entries.
	detail := strings.Repeat("ü", readChunk) // 2 bytes per rune
	var sb strings.Builder
	for i := 0; i < 20; i++ {
		line, _ := json.Marshal(&Entry{Schema: SchemaV2, Timestamp: time.Now(), Action: "commit", Detail: fmt.Sprintf("filler %d", i)})
		sb.Write(line)
		sb.WriteByte('\n')
	}
	line, _ := json.Marshal(&Entry{Schema: SchemaV2, Timestamp: time.Now(), Action: "commit", Detail: detail})
	sb.Write(line)
	sb.WriteByte('\n')
	if err := os.WriteFile(j.path, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := j.Tail(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	if got[1].Detail != detail {
		t.Fatalf("multi-byte detail corrupted across chunk boundary (len %d vs %d)", len(got[1].Detail), len(detail))
	}
	if got[0].Detail != "filler 19" {
		t.Errorf("preceding entry wrong: %q", got[0].Detail)
	}
}

// TestTornFinalLine: a crash can leave a partial trailing record. The
// reader must skip it and the next append must self-heal so the torn
// bytes cannot corrupt the new record.
func TestTornFinalLine(t *testing.T) {
	j := testJournal(t)
	mustLog(t, j, &Entry{Action: "commit", Detail: "before crash"})

	// Simulate torn write: partial JSON, no trailing newline.
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":2,"timestamp":"2026-01-01T00:00:00Z","action":"comm`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got, err := j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Detail != "before crash" {
		t.Fatalf("torn line not skipped: %+v", got)
	}

	// Self-heal: the next append starts on a fresh line.
	mustLog(t, j, &Entry{Action: "commit", Detail: "after crash"})
	got, err = j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries after self-heal, got %d", len(got))
	}
	if got[0].Detail != "before crash" || got[1].Detail != "after crash" {
		t.Fatalf("wrong entries after self-heal: %q, %q", got[0].Detail, got[1].Detail)
	}
}

// TestRotationBoundary: appends across the size threshold rotate the
// current segment, Tail merges segments in order, and the oldest
// segment is deleted at maxSegments.
func TestRotationBoundary(t *testing.T) {
	// ~80-byte lines, 1000-byte segments: ~12 entries per segment, so
	// 40 appends force >=2 rotations while retention (current + 2
	// segments) comfortably covers the last 10 entries.
	j := testJournal(t, WithMaxSegmentBytes(1000), WithMaxSegments(2))
	for i := 0; i < 40; i++ {
		mustLog(t, j, &Entry{Action: "commit", Detail: fmt.Sprintf("c%02d", i)})
	}

	// Rotation happened: current + rotated segments exist, nothing
	// beyond maxSegments.
	if _, err := os.Stat(j.segmentPath(1)); err != nil {
		t.Fatalf("segment .1 missing: %v", err)
	}
	if _, err := os.Stat(j.segmentPath(3)); !os.IsNotExist(err) {
		t.Fatalf("segment .3 must not exist (maxSegments=2): %v", err)
	}

	// Tail across the segment boundary: newest entries first from the
	// current segment, older from .1, in one ordered result.
	got, err := j.Tail(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 10 {
		t.Fatalf("want 10 entries, got %d", len(got))
	}
	for i := 0; i < 10; i++ {
		want := fmt.Sprintf("c%02d", 30+i)
		if got[i].Detail != want {
			t.Fatalf("entry %d: want %q, got %q (segment merge order broken)", i, want, got[i].Detail)
		}
	}

	// Oldest entries beyond retention are gone; the retained window is
	// contiguous and ends at the newest entry.
	all, err := j.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) >= 40 {
		t.Fatalf("retention not applied: %d entries survived", len(all))
	}
	if all[len(all)-1].Detail != "c39" {
		t.Fatalf("newest entry missing: %q", all[len(all)-1].Detail)
	}
	for i := 1; i < len(all); i++ {
		var prev, cur int
		fmt.Sscanf(all[i-1].Detail, "c%d", &prev)
		fmt.Sscanf(all[i].Detail, "c%d", &cur)
		if cur != prev+1 {
			t.Fatalf("retained window not contiguous: %q then %q", all[i-1].Detail, all[i].Detail)
		}
	}
}

// TestRotationGapTolerated (AGY plan-r1 F3): a crash mid-shift can
// leave .1 missing while .2 exists; Tail must keep scanning past the
// gap instead of stopping.
func TestRotationGapTolerated(t *testing.T) {
	j := testJournal(t, WithMaxSegments(3))
	line, _ := json.Marshal(&Entry{Schema: SchemaV2, Timestamp: time.Now(), Action: "commit", Detail: "old"})
	if err := os.WriteFile(j.segmentPath(2), append(line, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	mustLog(t, j, &Entry{Action: "commit", Detail: "new"})
	// .1 does not exist — the gap.
	got, err := j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Detail != "old" || got[1].Detail != "new" {
		t.Fatalf("gap not tolerated: %+v", got)
	}
}

// TestLegacyFatFileRotatesOnFirstAppend: upgrading over a huge v1
// journal must scrub its before/after payloads on first use (#15143)
// and then rotate the scrubbed segment to .1 on the first append —
// history (timestamp/action/detail) stays visible, cleartext payload
// does not. Pre-#15143 this asserted rotation "intact"; that intact
// retention was the credential leak.
func TestLegacyFatFileRotatesOnFirstAppend(t *testing.T) {
	j := testJournal(t, WithMaxSegmentBytes(1024))
	ts := time.Now()
	var sb strings.Builder
	for i := 0; i < 3; i++ {
		sb.WriteString(legacyV1Line(ts, "commit", fmt.Sprintf("legacy %d", i), 2048))
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(j.path, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}

	mustLog(t, j, &Entry{Action: "commit", Detail: "first v2"})

	// Legacy payloads scrubbed; rotation still moves the (now compact)
	// legacy segment to .1 and current holds only the new v2 entry.
	// The scrubbed segment is ~3 compact lines (< 1 KiB threshold), so
	// it may not rotate on this append at all — either way current must
	// hold no before/after payload and history must stay whole. Read
	// .1 if rotation happened; otherwise the scrubbed legacy lines are
	// still in current ahead of the v2 line.
	cur, err := os.ReadFile(j.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cur, []byte(`"before":`)) || bytes.Contains(cur, []byte(`"after":`)) {
		t.Fatal("legacy payload still in current segment after scrub")
	}
	if !bytes.Contains(cur, []byte("first v2")) {
		t.Fatal("new v2 entry missing from current segment")
	}
	// Wherever the legacy lines landed (rotated .1 or scrubbed in
	// place in current), their details survive and payloads do not.
	combined := cur
	if rot, rerr := os.ReadFile(j.segmentPath(1)); rerr == nil {
		if bytes.Contains(rot, []byte(`"before":`)) || bytes.Contains(rot, []byte(`"after":`)) {
			t.Fatal("legacy journal rotated with before/after payloads intact (#15143)")
		}
		combined = append(combined, rot...)
	}
	for i := range 3 {
		if !bytes.Contains(combined, []byte(fmt.Sprintf("legacy %d", i))) {
			t.Fatalf("scrubbed journal lost legacy detail %d", i)
		}
	}

	got, err := j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 entries (3 legacy + 1 v2), got %d", len(got))
	}
	if got[3].Detail != "first v2" || got[0].Detail != "legacy 0" {
		t.Fatalf("merge order wrong: %q .. %q", got[0].Detail, got[3].Detail)
	}
}

// TestSkipModeOverCapLine (AGY plan-r1 F4): a corrupt newline-free
// blob larger than maxTailLineBytes must not be buffered whole; the
// scanner discards it and resyncs at the previous newline, still
// returning the valid entries before it.
func TestSkipModeOverCapLine(t *testing.T) {
	if testing.Short() {
		t.Skip("writes >16MiB")
	}
	j := testJournal(t)
	mustLog(t, j, &Entry{Action: "commit", Detail: "valid 1"})
	mustLog(t, j, &Entry{Action: "commit", Detail: "valid 2"})

	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	garbage := bytes.Repeat([]byte{'x'}, maxTailLineBytes+2*readChunk)
	if _, err := f.Write(garbage); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got, err := j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Detail != "valid 1" || got[1].Detail != "valid 2" {
		t.Fatalf("skip mode broken: %+v", got)
	}
}

// TestSkipModeOverCapLineWithTrailingNewline (AGY code-r1 F1): an
// over-cap line that ENDS with a newline keeps that newline inside the
// pending fragment, so the no-newline branch never fires — the cap
// must trigger on every pending update or the scanner buffers the
// whole line. Valid entries on both sides must survive.
func TestSkipModeOverCapLineWithTrailingNewline(t *testing.T) {
	if testing.Short() {
		t.Skip("writes >16MiB")
	}
	j := testJournal(t)
	mustLog(t, j, &Entry{Action: "commit", Detail: "valid 1"})

	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	garbage := bytes.Repeat([]byte{'x'}, maxTailLineBytes+2*readChunk)
	garbage = append(garbage, '\n') // the F1 shape: poisoned line terminated by newline
	if _, err := f.Write(garbage); err != nil {
		t.Fatal(err)
	}
	f.Close()
	mustLog(t, j, &Entry{Action: "commit", Detail: "valid 2"})

	got, err := j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Detail != "valid 1" || got[1].Detail != "valid 2" {
		t.Fatalf("trailing-newline over-cap line broke the scan: %+v", got)
	}
}

// TestZeroMaxSegmentsClamped (AGY code-r1 F2): maxSegments=0 would make
// rotation delete the CURRENT journal file (segmentPath(0) == path);
// New must clamp it.
func TestZeroMaxSegmentsClamped(t *testing.T) {
	j := testJournal(t, WithMaxSegments(0), WithMaxSegmentBytes(0))
	if j.maxSegments != DefaultMaxSegments || j.maxSegmentBytes != DefaultMaxSegmentBytes {
		t.Fatalf("out-of-range options not clamped: segments=%d bytes=%d", j.maxSegments, j.maxSegmentBytes)
	}
	mustLog(t, j, &Entry{Action: "commit", Detail: "survives"})
	got, err := j.Tail(10)
	if err != nil || len(got) != 1 {
		t.Fatalf("journal lost after clamped-options append: %v, %d", err, len(got))
	}
}

// TestParseLineRejectsNonEntries: blank lines, garbage, and decodable
// JSON that is not a journal entry are skipped.
func TestParseLineRejectsNonEntries(t *testing.T) {
	for _, bad := range []string{"", "   ", "not json", "{}", `{"foo":1}`, `[1,2,3]`} {
		if e := parseLine([]byte(bad)); e != nil {
			t.Errorf("parseLine(%q) accepted: %+v", bad, e)
		}
	}
	if e := parseLine([]byte(`{"action":"commit"}`)); e == nil {
		t.Error("parseLine rejected an action-only entry")
	}
}

// TestTailExactChunkBoundaryLine: a line whose terminating newline is
// the first byte of a chunk (and one that is the last byte) must not
// be lost or duplicated.
func TestTailExactChunkBoundaryLine(t *testing.T) {
	j := testJournal(t)
	// Construct entries with precisely sized details so that one line
	// ends exactly at the chunk boundary (file size - readChunk).
	mk := func(detail string) []byte {
		b, _ := json.Marshal(&Entry{Schema: SchemaV2, Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Action: "commit", Detail: detail})
		return append(b, '\n')
	}
	base := mk("x")
	overhead := len(base) - 2 // bytes besides detail("x") and incl. newline... compute exactly below

	var buf bytes.Buffer
	// First line: pad so that its end lands exactly readChunk bytes
	// before the end of the final file. We assemble back-to-front:
	// target total size = first line + tail lines where tail lines
	// total exactly readChunk bytes.
	tail1 := mk(strings.Repeat("a", readChunk/2))
	need := readChunk - len(tail1)
	pad := need - (overhead + 1) // detail length for the closer line
	if pad < 0 {
		t.Fatalf("test geometry broken: pad=%d", pad)
	}
	tail2 := mk(strings.Repeat("b", pad))
	if len(tail1)+len(tail2) != readChunk {
		t.Fatalf("test geometry: tail=%d want %d", len(tail1)+len(tail2), readChunk)
	}
	buf.Write(mk("first"))
	buf.Write(tail2)
	buf.Write(tail1)
	if err := os.WriteFile(j.path, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := j.Tail(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}
	if got[0].Detail != "first" {
		t.Errorf("boundary-adjacent first entry lost: %q", got[0].Detail)
	}
	if got[1].Detail != strings.Repeat("b", pad) || got[2].Detail != strings.Repeat("a", readChunk/2) {
		t.Error("boundary lines corrupted")
	}
}

// TestFileOfOnlyNewlines: degenerate content must yield zero entries
// and no error.
func TestFileOfOnlyNewlines(t *testing.T) {
	j := testJournal(t)
	if err := os.WriteFile(j.path, bytes.Repeat([]byte{'\n'}, 1000), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 entries, got %d", len(got))
	}
}

// TestMigratePreexistingCurrent0644 (#5188): a journal upgraded from a
// pre-0600 build has a 0644 CURRENT inode. O_APPEND ignores the perm arg
// on an existing inode, so only the first-use permission-repair pass can
// tighten it. First Log must leave the current segment at 0600. Fails
// (mode stays 0644) if the migration is reverted.
func TestMigratePreexistingCurrent0644(t *testing.T) {
	j := testJournal(t)
	if err := os.WriteFile(j.path, []byte(`{"v":2,"action":"commit","detail":"old"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Defeat umask so the precondition is deterministic.
	if err := os.Chmod(j.path, 0644); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(j.path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0644 {
		t.Fatalf("precondition: want 0644, got %04o", fi.Mode().Perm())
	}

	mustLog(t, j, &Entry{Action: "commit", Detail: "new"})

	fi, err := os.Stat(j.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("current journal not migrated to 0600: got %04o", fi.Mode().Perm())
	}
	// The migration must not corrupt content: both entries survive.
	got, err := j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Detail != "old" || got[1].Detail != "new" {
		t.Fatalf("migration altered content: %+v", got)
	}
}

// TestMigrateRotatedSegment0644 (#5188): a rotated legacy segment left
// world-readable by an old build carries full v1 fat lines (secrets).
// First use — here a Tail, proving the pass runs on the read path too —
// must migrate every owned segment, current and rotated. Fails (mode
// stays 0644) if the migration is reverted.
func TestMigrateRotatedSegment0644(t *testing.T) {
	j := testJournal(t)
	if err := os.WriteFile(j.segmentPath(1),
		[]byte(legacyV1Line(time.Now(), "commit", "legacy secret", 16)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(j.segmentPath(1), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := j.Tail(50); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(j.segmentPath(1))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("rotated segment .1 not migrated to 0600: got %04o", fi.Mode().Perm())
	}
}

// TestRotationRepairsSegmentMode (#5188): the rotation path itself must
// re-assert 0600 on the segment it creates. maybeRotateLocked is called
// directly to bypass Log's first-use migration, isolating the
// rotation-repair. Fails (.1 stays 0644) if the rotation chmod is
// reverted.
func TestRotationRepairsSegmentMode(t *testing.T) {
	j := testJournal(t, WithMaxSegmentBytes(1))
	if err := os.WriteFile(j.path,
		[]byte(`{"v":2,"action":"commit","detail":"x"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(j.path, 0644); err != nil {
		t.Fatal(err)
	}

	rotated, err := j.maybeRotateLocked()
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("expected rotation of an over-threshold current segment")
	}

	fi, err := os.Stat(j.segmentPath(1))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("rotation did not repair .1 to 0600: got %04o", fi.Mode().Perm())
	}
}

// TestRotationProduces0600Segment (#5188): end-to-end through Log — a
// single Log over a 0644 upgraded current triggers exactly one rotation,
// and both the rotated .1 (the migrated legacy segment) and the freshly
// created current must be 0600. A small threshold forces one rotation
// only: with more rotations the current is re-created 0600 and the
// fresh-inode masks a reverted repair, so this test deliberately keeps
// .1 == the migrated seed. Fails if migration or rotation-repair
// regresses.
func TestRotationProduces0600Segment(t *testing.T) {
	j := testJournal(t, WithMaxSegmentBytes(10), WithMaxSegments(2))
	// Seed an upgraded 0644 current file already over the 10-byte
	// threshold, then a single append rotates it exactly once.
	if err := os.WriteFile(j.path,
		[]byte(`{"v":2,"action":"commit","detail":"seed"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(j.path, 0644); err != nil {
		t.Fatal(err)
	}

	mustLog(t, j, &Entry{Action: "commit", Detail: "post-upgrade"})

	fi, err := os.Stat(j.segmentPath(1))
	if err != nil {
		t.Fatalf("segment .1 missing: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("rotated .1 (migrated seed) not 0600: got %04o", fi.Mode().Perm())
	}
	if fi, err := os.Stat(j.path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0600 {
		t.Fatalf("current not 0600: got %04o", fi.Mode().Perm())
	}
	// Both entries remain visible across the rotation.
	got, err := j.Tail(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Detail != "seed" || got[1].Detail != "post-upgrade" {
		t.Fatalf("rotation altered content: %+v", got)
	}
}

// TestMigrateSkipsSymlink (#5188): the repair pass must lstat and refuse
// to follow a symlink — it must never chmod an arbitrary target through
// a symlinked journal path. The link target's mode must be untouched.
func TestMigrateSkipsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside")
	if err := os.WriteFile(target, []byte("unrelated 0644 file\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	jpath := filepath.Join(dir, ".config.journal")
	if err := os.Symlink(target, jpath); err != nil {
		t.Fatal(err)
	}

	j := New(jpath)
	// Trigger first-use migration via a read; a read outcome is
	// irrelevant, the security assertion is that the target is untouched.
	_, _ = j.Tail(50)

	if fi, err := os.Lstat(jpath); err != nil {
		t.Fatal(err)
	} else if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("test setup: journal path is not a symlink")
	}
	tfi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if tfi.Mode().Perm() != 0644 {
		t.Fatalf("symlink target chmod'd through the link: got %04o", tfi.Mode().Perm())
	}
}

// TestMigrateLeavesStricterModeAlone (#5188): the repair only ever
// tightens. A 0400 (owner read-only) segment must NOT be loosened to
// 0600.
func TestMigrateLeavesStricterModeAlone(t *testing.T) {
	j := testJournal(t)
	if err := os.WriteFile(j.path,
		[]byte(`{"v":2,"action":"commit","detail":"ro"}`+"\n"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(j.path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Tail(50); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(j.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0400 {
		t.Fatalf("stricter mode was loosened: got %04o", fi.Mode().Perm())
	}
}

// TestConcurrentLogTail: rotation under concurrent readers must never
// duplicate or error (internal mutex). Run with -race.
func TestConcurrentLogTail(t *testing.T) {
	j := testJournal(t, WithMaxSegmentBytes(300), WithMaxSegments(2))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_ = j.Log(&Entry{Action: "commit", Detail: fmt.Sprintf("c%d", i)})
		}
	}()
	for {
		select {
		case <-done:
			return
		default:
		}
		entries, err := j.Tail(20)
		if err != nil {
			t.Fatalf("Tail during rotation: %v", err)
		}
		seen := map[string]bool{}
		for _, e := range entries {
			if seen[e.Detail] {
				t.Fatalf("duplicate entry %q during concurrent rotation", e.Detail)
			}
			seen[e.Detail] = true
		}
	}
}

// TestTailNotBlockedByLogFsync (#4829) is the headline invariant: a
// Tail() concurrent with a Log() that is parked in fsync must return
// promptly, NOT stall for the fsync duration. The #4829 design holds j.mu
// only for the buffered write + rotation and releases it before f.Sync;
// Tail takes the same j.mu and so must not wait behind the fsync.
// RED-on-revert: move f.Sync back under j.mu (the pre-#4829 body) and
// this test fails — Tail blocks ~fsyncHold.
func TestTailNotBlockedByLogFsync(t *testing.T) {
	j := testJournal(t)

	// Seed one entry with the default fast sync so the file exists and
	// Tail has real content to read.
	mustLog(t, j, &Entry{Action: "commit", Detail: "seed"})

	// Install a slow fsync: the next Log parks in f.Sync for fsyncHold.
	// syncEntered fires the instant the fsync begins — by which point,
	// under the #4829 design, j.mu is already released.
	const fsyncHold = 750 * time.Millisecond
	var once sync.Once
	syncEntered := make(chan struct{})
	j.syncFile = func(f *os.File) error {
		once.Do(func() { close(syncEntered) })
		time.Sleep(fsyncHold)
		return f.Sync()
	}

	logDone := make(chan error, 1)
	go func() { logDone <- j.Log(&Entry{Action: "commit", Detail: "slow"}) }()

	select {
	case <-syncEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("Log never reached fsync")
	}

	start := time.Now()
	got, err := j.Tail(50)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if elapsed > fsyncHold/2 {
		t.Fatalf("Tail blocked %v behind Log's in-progress fsync (want prompt); "+
			"j.mu is held across fsync — #4829 regressed", elapsed)
	}
	// Write happens under j.mu BEFORE the fsync, so by the time the fsync
	// is running both entries are fully in the page cache and visible to a
	// reader — durability (fsync) is decoupled from visibility (the
	// write). Neither may be torn.
	for _, e := range got {
		if e.Action == "" {
			t.Fatalf("torn/partial entry observed during concurrent Log: %+v", e)
		}
	}
	if len(got) != 2 || got[0].Detail != "seed" || got[1].Detail != "slow" {
		t.Fatalf("Tail concurrent with in-flight fsync did not see both complete entries: %+v", got)
	}

	if err := <-logDone; err != nil {
		t.Fatalf("Log: %v", err)
	}
}

// TestConcurrentLogTailNoTornOrError (#4829): many writers appending
// while many readers Tail concurrently must never surface a read error, a
// torn/partial/garbage entry, or a duplicate within a single Tail
// snapshot. Exercises the write-under-lock / fsync-outside-lock split
// under -race. RED-on-revert of the torn-tail newline framing or the
// parse-or-skip guard would let a partial record through here.
func TestConcurrentLogTailNoTornOrError(t *testing.T) {
	j := testJournal(t, WithMaxSegmentBytes(4096), WithMaxSegments(3))

	const writers = 4
	const perWriter = 250

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for r := 0; r < 3; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				got, err := j.Tail(50)
				if err != nil {
					t.Errorf("Tail: %v", err)
					return
				}
				seen := map[string]bool{}
				for _, e := range got {
					if e.Action == "" || !strings.HasPrefix(e.Detail, "w") {
						t.Errorf("torn/garbage entry from concurrent read: %+v", e)
						return
					}
					if seen[e.Detail] {
						t.Errorf("duplicate %q within one Tail snapshot", e.Detail)
						return
					}
					seen[e.Detail] = true
				}
			}
		}()
	}

	var writersWG sync.WaitGroup
	for w := 0; w < writers; w++ {
		writersWG.Add(1)
		go func(w int) {
			defer writersWG.Done()
			for i := 0; i < perWriter; i++ {
				if err := j.Log(&Entry{Action: "commit", Detail: fmt.Sprintf("w%d-%05d", w, i)}); err != nil {
					t.Errorf("Log: %v", err)
					return
				}
			}
		}(w)
	}
	writersWG.Wait()
	close(stop)
	readers.Wait()
}

// TestRotationDuringSlowFsync (#4829): rotation correctness must hold when
// the fsync runs outside j.mu. With a small segment (forced rotations)
// and a deliberately slow fsync, concurrent Tails must still see complete,
// non-duplicated entries, and the final retained window must be
// contiguous and end at the newest entry.
func TestRotationDuringSlowFsync(t *testing.T) {
	j := testJournal(t, WithMaxSegmentBytes(400), WithMaxSegments(2))
	// Rotation happens under j.mu; the fsync after it. A non-zero fsync
	// delay widens the window in which a reader can race a mid-flight
	// durability op.
	j.syncFile = func(f *os.File) error {
		time.Sleep(2 * time.Millisecond)
		return f.Sync()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 300; i++ {
			if err := j.Log(&Entry{Action: "commit", Detail: fmt.Sprintf("c%05d", i)}); err != nil {
				t.Errorf("Log: %v", err)
				return
			}
		}
	}()

loop:
	for {
		select {
		case <-done:
			break loop
		default:
		}
		got, err := j.Tail(20)
		if err != nil {
			t.Fatalf("Tail during rotation+slow-fsync: %v", err)
		}
		seen := map[string]bool{}
		for _, e := range got {
			if e.Action == "" {
				t.Fatalf("torn entry during rotation+slow-fsync: %+v", e)
			}
			if seen[e.Detail] {
				t.Fatalf("duplicate %q during concurrent rotation", e.Detail)
			}
			seen[e.Detail] = true
		}
	}

	all, err := j.Tail(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("no entries survived")
	}
	if all[len(all)-1].Detail != "c00299" {
		t.Fatalf("newest entry missing: %q", all[len(all)-1].Detail)
	}
	for i := 1; i < len(all); i++ {
		var prev, cur int
		fmt.Sscanf(all[i-1].Detail, "c%d", &prev)
		fmt.Sscanf(all[i].Detail, "c%d", &cur)
		if cur != prev+1 {
			t.Fatalf("retained window not contiguous: %q then %q", all[i-1].Detail, all[i].Detail)
		}
	}
}
