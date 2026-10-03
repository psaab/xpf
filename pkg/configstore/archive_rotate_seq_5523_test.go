package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRotateArchivesPrunesBySeqNotTimestamp is the #5523 C179-060 core guard.
// The archive filename is config-<ts>.<seq>.conf with the ts FIRST, so the
// pre-fix lexical (ts-dominated) prune evicted the wrong file after a backward
// wall-clock step: the NEWEST commit formats an EARLIER ts and sorts first, so
// it was pruned as if it were the oldest. rotateArchives now prunes by the
// monotonic seq, which is the true commit order.
//
// The archives here are written with DECREASING ts but INCREASING seq (the NTP
// step-back scenario): seq 5 is the newest commit yet carries the earliest ts.
//
// FAIL-ON-REVERT: restore the sort.Strings(archives) ts-lexical sort and the
// prune keeps the three LATEST-ts files (seq 1,2,3) and evicts seq 4,5 — the
// "newest-by-seq retained" assertions go RED.
func TestRotateArchivesPrunesBySeqNotTimestamp(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	for seq := 1; seq <= 5; seq++ {
		// Higher seq (later commit) => EARLIER ts, modeling an NTP step-back.
		ts := base.Add(-time.Duration(seq) * time.Second)
		if err := writeArchive(dir, 3, fmt.Sprintf("cfg-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	remain := map[string]bool{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("want 3 archives after prune (max=3), got %d", len(ents))
	}
	for _, e := range ents {
		d, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		remain[strings.TrimSpace(string(d))] = true
	}
	// Newest three BY SEQ must survive even though they carry the earliest ts.
	for _, w := range []string{"cfg-3", "cfg-4", "cfg-5"} {
		if !remain[w] {
			t.Errorf("newest-by-seq archive %q must be retained (prune by seq, not ts); remain=%v", w, remain)
		}
	}
	// Oldest two BY SEQ must be pruned even though they carry the latest ts.
	for _, w := range []string{"cfg-1", "cfg-2"} {
		if remain[w] {
			t.Errorf("oldest-by-seq archive %q must be pruned; remain=%v", w, remain)
		}
	}
}

// TestSetArchiveConfigSeedsSeqAcrossRestart is the restart-safety half of the
// #5523 C179-060 fix. archiveSeq is a per-PROCESS counter that restarts at 0;
// because rotateArchives now prunes by seq, a fresh process that reset seq to 0
// would let a prior process's stale HIGH-seq archives outrank — and evict — its
// own fresh LOW-seq archives. SetArchiveConfig seeds archiveSeq from the highest
// seq already on disk so the counter stays globally monotonic across restarts.
//
// FAIL-ON-REVERT: drop the seeding block in SetArchiveConfig and archiveSeq
// stays 0 — the seed assertion goes RED.
func TestSetArchiveConfigSeedsSeqAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	// "Process 1" wrote archives seq 1..7.
	for seq := 1; seq <= 7; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dir, 100, fmt.Sprintf("cfg-%d\n", seq), ts, uint64(seq)); err != nil {
			t.Fatal(err)
		}
	}

	// "Process 2" starts fresh (archiveSeq == 0) and configures archival.
	s := &Store{}
	if got := s.archiveSeq.Load(); got != 0 {
		t.Fatalf("fresh Store archiveSeq = %d, want 0", got)
	}
	s.SetArchiveConfig(dir, 3)
	if got := s.archiveSeq.Load(); got != 7 {
		t.Fatalf("SetArchiveConfig must seed archiveSeq to the highest on-disk seq (7) "+
			"so it stays globally monotonic across a restart (C179-060); got %d", got)
	}

	// The next commit's seq is strictly higher than any prior-process archive.
	if next := s.archiveSeq.Add(1); next != 8 {
		t.Fatalf("post-seed next seq = %d, want 8", next)
	}
}

// TestParseArchiveSeq pins the filename parse the seq-based prune and the
// restart seed both rely on: the seq is the last dot-delimited field before
// .conf, past the ts's own seconds.nanoseconds dot. Non-archive names return
// ok=false so they order as oldest.
func TestParseArchiveSeq(t *testing.T) {
	ts := time.Date(2026, 6, 28, 12, 0, 0, 123456789, time.UTC)
	name := fmt.Sprintf("config-%s.%020d.conf", ts.Format("20060102-150405.000000000"), uint64(42))
	if seq, ok := parseArchiveSeq(name); !ok || seq != 42 {
		t.Errorf("parseArchiveSeq(%q) = (%d, %v), want (42, true)", name, seq, ok)
	}
	for _, bad := range []string{
		"config-foo.conf",         // no seq field past the prefix
		"config-20260628.conf",    // single field, no seq
		"notes.txt",               // not an archive
		"config-20260628-1.2.txt", // wrong suffix
		// #6396: a legacy pre-#3441 config-<ts>.conf with a subsecond ts has ONE
		// dot (the ts's nanoseconds) in core. The old parse mis-read those
		// nanoseconds as a sequence; it must now be rejected as unparseable.
		"config-20260628-120000.123456789.conf",
	} {
		if seq, ok := parseArchiveSeq(bad); ok {
			t.Errorf("parseArchiveSeq(%q) = (%d, true), want ok=false", bad, seq)
		}
	}
}

// TestRotateArchivesPreservesForeignConfigFiles11804 pins archive ownership in
// shared directories: retention counts and removes only XPF snapshot names.
//
// RED before fix: the prefix/suffix-only scan includes the foreign file, sorts
// it as oldest, and removes it when the three real snapshots exceed max=2.
func TestRotateArchivesPreservesForeignConfigFiles11804(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
	for seq := uint64(1); seq <= 3; seq++ {
		ts := base.Add(time.Duration(seq) * time.Second)
		if err := writeArchive(dir, 0, fmt.Sprintf("archive-%d\n", seq), ts, seq); err != nil {
			t.Fatal(err)
		}
	}

	const foreignName = "config-compliance-report.conf"
	const foreignBody = "compliance-owned config export\n"
	foreignPath := filepath.Join(dir, foreignName)
	if err := os.WriteFile(foreignPath, []byte(foreignBody), 0600); err != nil {
		t.Fatal(err)
	}

	rotateArchives(dir, 2)

	got, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatalf("rotation must preserve foreign archive-like file %q: %v", foreignName, err)
	}
	if string(got) != foreignBody {
		t.Fatalf("foreign file %q changed to %q, want %q", foreignName, got, foreignBody)
	}

	remain := map[string]bool{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !isXPFConfigArchiveSnapshot(entry.Name()) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		remain[strings.TrimSpace(string(data))] = true
	}
	if len(remain) != 2 {
		t.Fatalf("rotation must retain max=2 XPF snapshots, got %v", remain)
	}
	for _, want := range []string{"archive-2", "archive-3"} {
		if !remain[want] {
			t.Errorf("newer XPF archive %q must survive rotation; remain=%v", want, remain)
		}
	}
	if remain["archive-1"] {
		t.Errorf("oldest XPF archive must be pruned; remain=%v", remain)
	}
}
