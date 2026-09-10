package configstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9617: every configstore writer must refuse what its reader refuses. The
// reader is ReadBoundedFile(path, MaxConfigSize); before #9617 no writer
// checked, so a commit could persist an active DB the next Load rejects and a
// commit confirmed could persist a confirm.json the next boot rejects.

func TestPersistSizeGateMatchesReaderBoundary_9617(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []int{MaxConfigSize, MaxConfigSize + 1} {
		p := filepath.Join(dir, fmt.Sprintf("f%d", n))
		if err := os.WriteFile(p, make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
		_, rerr := ReadBoundedFile(p, MaxConfigSize)
		werr := checkPersistSize(p, n)
		readerAccepts, writerAccepts := rerr == nil, werr == nil
		if readerAccepts != writerAccepts {
			t.Errorf("#9617: at %d bytes the reader accepts=%v (%v) but the writer accepts=%v (%v) — a writer "+
				"that accepts what its reader refuses persists an artifact the next load rejects, and one "+
				"that refuses what the reader accepts rejects a config the store can load",
				n, readerAccepts, rerr, writerAccepts, werr)
		}
		if want := n <= MaxConfigSize; writerAccepts != want {
			t.Errorf("#9617: checkPersistSize(%d) accepts=%v, want %v at the %d byte ceiling", n, writerAccepts, want, MaxConfigSize)
		}
		if werr != nil && !errors.Is(werr, ErrPersistExceedsReadCeiling) {
			t.Errorf("#9617: the refusal at %d bytes is not ErrPersistExceedsReadCeiling: %v", n, werr)
		}
	}
}

func bigDescription9617(i, n int) string {
	return fmt.Sprintf("interfaces ge-0/0/%d description M9617-%d-%s", i, i, strings.Repeat("x", n))
}

func fileSize9617(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

func TestCommitRefusesAnActiveDBTheNextLoadWouldRefuse_9617(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name before9617"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("prior commit: %v", err)
	}
	activePath := s.db.activePath()
	before := fileSize9617(t, activePath)

	// Nine 2 MiB leaves: every Set is legal, the composition serializes to
	// ~18 MiB.
	for i := 0; i < 9; i++ {
		if err := s.SetFromInput(bigDescription9617(i, 2<<20)); err != nil {
			t.Fatalf("set %d: %v", i, err)
		}
	}
	_, err := s.Commit()
	if !errors.Is(err, ErrPersistExceedsReadCeiling) {
		t.Fatalf("#9617: Commit of an ~18 MiB tree returned %v, want ErrPersistExceedsReadCeiling — "+
			"before #9617 it SUCCEEDED and the next Store.Load refused the DB (exceeds size limit), "+
			"so the daemon did not come back", err)
	}
	if got := s.active.Format(); !strings.Contains(got, "before9617") || strings.Contains(got, "M9617-") {
		t.Errorf("#9617: the refused commit PROMOTED — active no longer reads as the prior generation")
	}
	if !strings.Contains(s.candidate.Format(), "M9617-8-") {
		t.Errorf("#9617: the refused commit discarded the candidate; it must stay intact so the operator can trim it")
	}
	if after := fileSize9617(t, activePath); after != before || after == 0 {
		t.Errorf("#9617: active.json changed %d -> %d bytes on a refused commit; the refusal must precede the write", before, after)
	}

	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("#9617: fresh Load after a refused commit failed: %v", err)
	}
	if got := s2.active.Format(); !strings.Contains(got, "before9617") || strings.Contains(got, "M9617-") {
		t.Errorf("#9617: fresh Load did not return the prior generation")
	}
}

// Positive control: the gate must not refuse a large config the reader accepts.
func TestCommitUnderTheCeilingStillCommitsAndLoads_9617(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if err := s.SetFromInput(bigDescription9617(i, 2<<20)); err != nil {
			t.Fatalf("set %d: %v", i, err)
		}
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("#9617 positive control: a ~14 MiB config must still commit: %v", err)
	}
	if n := fileSize9617(t, s.db.activePath()); n <= 14<<20 || n > MaxConfigSize {
		t.Fatalf("fixture drifted: active.json is %d bytes, want in (14 MiB, %d]", n, MaxConfigSize)
	}
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("#9617 positive control: fresh Load of a ~14 MiB DB: %v", err)
	}
	if !strings.Contains(s2.active.Format(), "M9617-6-") {
		t.Errorf("#9617 positive control: the loaded active config lost its content")
	}
}

func TestCommitConfirmedRefusesARecordTheNextBootWouldRefuse_9617(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	var stores []*Store
	open := func() *Store {
		st := newTestStoreAt(t, path)
		stores = append(stores, st)
		return st
	}
	t.Cleanup(func() {
		for _, st := range stores {
			if st.confirmTimer != nil {
				st.confirmTimer.Stop()
			}
		}
	})
	s := open()
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	// ~14k JSON lines, so the record nests the tree ~28 KiB deeper than
	// active.json, plus seven 2 MiB leaves and a filler to calibrate against.
	var groups strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&groups, "groups g%d { system { host-name h%d; } }\n", i, i)
	}
	if err := s.LoadMerge(groups.String()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		if err := s.SetFromInput(bigDescription9617(i, 2<<20)); err != nil {
			t.Fatalf("set %d: %v", i, err)
		}
	}
	setFiller := func(n int) {
		t.Helper()
		if err := s.SetFromInput("interfaces ge-0/0/9 description F9617-" + strings.Repeat("y", n)); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(what string) {
		t.Helper()
		if _, err := s.Commit(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	const filler0 = 1 << 20
	setFiller(filler0)
	commit("calibration commit")
	a0 := fileSize9617(t, s.db.activePath())
	// JSON of the filler is 1:1 with its length, so this lands active.json
	// exactly 8 KiB under the ceiling.
	filler1 := filler0 + int(int64(MaxConfigSize-8<<10)-a0)
	setFiller(filler1)
	commit("prior-generation commit")
	a1 := fileSize9617(t, s.db.activePath())
	if a1 > MaxConfigSize || a1 < MaxConfigSize-16<<10 {
		t.Fatalf("fixture: active.json is %d bytes, want within 16 KiB under %d", a1, MaxConfigSize)
	}
	if err := open().Load(); err != nil {
		t.Fatalf("fixture: the prior generation must itself be loadable: %v", err)
	}

	// The confirmed candidate is TINY: every large leaf is deleted. Its own
	// active DB is nowhere near the ceiling, so the only thing that can refuse
	// this commit is the record's rollback target — the prior generation.
	if err := s.DeleteFromInput("interfaces"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name confirmed9617"); err != nil {
		t.Fatal(err)
	}
	_, err := s.CommitConfirmed(10)
	if !errors.Is(err, ErrPersistExceedsReadCeiling) {
		t.Fatalf("#9617: CommitConfirmed over a readable %d-byte prior generation returned %v, want "+
			"ErrPersistExceedsReadCeiling — before #9617 it SUCCEEDED, wrote a confirm.json over the ceiling, "+
			"and a restart inside the window kept the unconfirmed config with no rollback timer", a1, err)
	}
	if s.confirmTimer != nil {
		t.Errorf("#9617: a refused commit confirmed armed a rollback timer")
	}
	if _, serr := os.Stat(s.db.confirmPath()); !os.IsNotExist(serr) {
		t.Errorf("#9617: a refused commit confirmed left a confirm.json behind (stat: %v)", serr)
	}
	if strings.Contains(s.active.Format(), "confirmed9617") {
		t.Errorf("#9617: the refused commit confirmed PROMOTED its candidate")
	}
	if !strings.Contains(s.candidate.Format(), "confirmed9617") {
		t.Errorf("#9617: the refused commit confirmed discarded the candidate")
	}
	if got := fileSize9617(t, s.db.activePath()); got != a1 {
		t.Errorf("#9617: active.json changed %d -> %d bytes on a refused commit confirmed", a1, got)
	}
	s2 := open()
	if err := s2.Load(); err != nil {
		t.Fatalf("#9617: fresh Load after a refused commit confirmed: %v", err)
	}
	if s2.confirmTimer != nil || s2.confirmRecoveryReadFailed {
		t.Errorf("#9617: fresh Load timer=%v recoveryReadFailed=%v, want neither — nothing was armed",
			s2.confirmTimer != nil, s2.confirmRecoveryReadFailed)
	}
	if strings.Contains(s2.active.Format(), "confirmed9617") {
		t.Errorf("#9617: fresh Load returned the refused candidate")
	}

	// Positive control: shrink the prior generation so its record fits; the
	// same state machine arms, and a restart re-arms.
	for i := 0; i < 7; i++ {
		if err := s.SetFromInput(bigDescription9617(i, 2<<20)); err != nil {
			t.Fatalf("re-set %d: %v", i, err)
		}
	}
	setFiller(filler1 - 64<<10)
	if err := s.SetFromInput("system host-name plain9617"); err != nil {
		t.Fatal(err)
	}
	commit("shrunk prior-generation commit")
	if err := s.DeleteFromInput("interfaces"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFromInput("system host-name confirmed9617b"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(10); err != nil {
		t.Fatalf("#9617 positive control: a record under the ceiling must arm: %v", err)
	}
	if n := fileSize9617(t, s.db.confirmPath()); n > MaxConfigSize {
		t.Fatalf("#9617 positive control: armed confirm.json is %d bytes, over %d", n, MaxConfigSize)
	}
	s3 := open()
	if err := s3.Load(); err != nil {
		t.Fatalf("#9617 positive control: fresh Load: %v", err)
	}
	if s3.confirmTimer == nil {
		t.Errorf("#9617 positive control: a readable confirm record did not re-arm after restart (recoveryReadFailed=%v)", s3.confirmRecoveryReadFailed)
	}
	if !strings.Contains(s3.active.Format(), "confirmed9617b") {
		t.Errorf("#9617 positive control: fresh Load did not return the confirmed candidate")
	}
}

// The writer's boundary is the reader's EXACT bytes. The envelope header (and
// any encryption) counts, so a check on the bare JSON body would admit a file
// the reader refuses by a header's width. Ceiling accepted, ceiling+1 refused,
// both measured as the file the reader opens.
func TestWriteActiveBoundaryIsTheReadersExactBytes_9617(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	tree := func(n int) *config.ConfigTree {
		t.Helper()
		tr := &config.ConfigTree{}
		for _, cmd := range []string{
			"set system host-name edge9617",
			"set interfaces ge-0/0/0 description " + strings.Repeat("x", n),
		} {
			p, err := config.ParseSetCommand(cmd)
			if err != nil {
				t.Fatal(err)
			}
			if err := tr.SetPath(p); err != nil {
				t.Fatal(err)
			}
		}
		return tr
	}
	path := s.db.activePath()
	const l0 = 1 << 20
	if err := s.db.WriteActive(tree(l0)); err != nil {
		t.Fatal(err)
	}
	overhead := fileSize9617(t, path) - l0
	atCeiling := int(int64(MaxConfigSize) - overhead)
	if err := s.db.WriteActive(tree(atCeiling)); err != nil {
		t.Fatalf("#9617: an active.json of exactly the %d byte ceiling was refused: %v", MaxConfigSize, err)
	}
	if n := fileSize9617(t, path); n != MaxConfigSize {
		t.Fatalf("fixture: want an active.json of exactly %d bytes, got %d", MaxConfigSize, n)
	}
	if _, err := ReadBoundedFile(path, MaxConfigSize); err != nil {
		t.Fatalf("fixture: the reader refused the exact-ceiling file: %v", err)
	}
	err := s.db.WriteActive(tree(atCeiling + 1))
	if !errors.Is(err, ErrPersistExceedsReadCeiling) {
		t.Fatalf("#9617: an active.json of %d bytes (ceiling+1, counted with its envelope header) "+
			"returned %v, want ErrPersistExceedsReadCeiling — the reader refuses that file", MaxConfigSize+1, err)
	}
	if n := fileSize9617(t, path); n != MaxConfigSize {
		t.Errorf("#9617: the refused write changed active.json to %d bytes", n)
	}
}
