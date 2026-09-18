package dhcpserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #8597 (muse-004 K52) — a SUCCESSFUL kea-lfc rotation landing mid-read
// silently drops rows from the destructive DDNS lease set.
//
// parseActiveLeases opens `.2`, `.1` and the current file SEQUENTIALLY.
// lease_lfc.go documents the success swap as ".output -> .2, unlink .1". If
// that lands between our open(.2) and our open(.1) we read:
//
//	old .2      the stale compacted set
//	.1          MISSING (just unlinked) — every append since the last
//	            compaction, gone
//	current     near-empty (just rotated)
//
// and the merged result is a plausible-looking set missing all recent leases.
// The destructive DDNS diff's precondition is a "trusted-empty / trusted-set"
// read, and a routine successful rotation violates it silently.
//
// This is NOT the case §Invariant-3 argues about. That argument is about a
// CRASH-interrupted cleanup, where `.1` stays intact and is read, and it is
// sound. The gap is the SUCCESSFUL rotation, where `.1` is deliberately
// removed.

const leaseHdr8597 = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n"

func leaseRow8597(addr, host string) string {
	return addr + ",aa:bb:cc:dd:ee:01,,3600,1900000000,1,0,1," + host + ",0\n"
}

// rotateSet performs exactly what a successful kea-lfc swap does: rename
// `.output` over `.2`, then unlink `.1`.
func rotateSet(t *testing.T, base string) {
	t.Helper()
	out := base + ".output"
	if err := os.WriteFile(out, []byte(leaseHdr8597+leaseRow8597("10.0.0.99", "compacted")), 0o644); err != nil {
		t.Fatalf("write .output: %v", err)
	}
	if err := os.Rename(out, base+".2"); err != nil {
		t.Fatalf("rename .output -> .2: %v", err)
	}
	if err := os.Remove(base + ".1"); err != nil && !os.IsNotExist(err) {
		t.Fatalf("unlink .1: %v", err)
	}
}

// TestRotationDuringReadIsRefused_8597 is the RED-on-revert core.
//
// The rotation is made DETERMINISTIC through the parseLeaseFileFn seam rather
// than raced for: it fires after the first file (`.2`) is parsed, which is
// exactly the window the finding describes. A probabilistic version of this
// cell would be flaky in one direction and vacuous in the other.
func TestRotationDuringReadIsRefused_8597(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "leases4.csv")

	// The steady state before a rotation: a compacted `.2`, the appends in
	// `.1`, and a current file.
	if err := os.WriteFile(base+".2", []byte(leaseHdr8597+leaseRow8597("10.0.0.10", "old")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".1", []byte(leaseHdr8597+leaseRow8597("10.0.0.11", "recent")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte(leaseHdr8597+leaseRow8597("10.0.0.12", "live")), 0o644); err != nil {
		t.Fatal(err)
	}

	prev := parseLeaseFileFn
	var seen int
	parseLeaseFileFn = func(p string, family int, now time.Time, acc *ddnsLeaseAccum) error {
		err := prev(p, family, now, acc)
		seen++
		if seen == 1 {
			// The swap lands between our open(.2) and our open(.1).
			rotateSet(t, base)
		}
		return err
	}
	t.Cleanup(func() { parseLeaseFileFn = prev })

	leases, err := parseActiveLeases(base, 4, time.Unix(1_700_000_000, 0))
	if err == nil {
		t.Fatalf("parseActiveLeases returned %d leases and NO error after a successful "+
			"kea-lfc rotation landed mid-read. The merged set is missing every lease "+
			"appended since the last compaction, and the destructive DDNS diff would "+
			"treat it as authoritative (#8597/K52): %+v", len(leases), leases)
	}
	if !strings.Contains(err.Error(), "rotated during read") {
		t.Errorf("refused for a different reason, so this cell is not exercising the "+
			"race it is about: %v", err)
	}
	// Non-vacuity: the rotation must actually have happened, or the refusal
	// above is about something else.
	if seen < 2 {
		t.Fatalf("the parse visited %d files; the seam never reached the second open, "+
			"so no rotation was interleaved", seen)
	}
	if _, statErr := os.Stat(base + ".1"); !os.IsNotExist(statErr) {
		t.Errorf(".1 still exists after the simulated rotation; the fixture did not "+
			"reproduce the unlink that loses the rows: %v", statErr)
	}
}

// TestCompletedAppearsDuringSelectionIsRefused_10170 covers the source-selection
// race introduced by `.completed` recovery. A reader that selects the fallback
// `.2/.1/current` set before the compaction completes must still compare all
// four names afterward; otherwise the completed-only result can be mistaken for
// a stable trusted-empty/current snapshot.
func TestCompletedAppearsDuringSelectionIsRefused_10170(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "leases4.csv")
	if err := os.WriteFile(base+".2", []byte(leaseHdr8597+leaseRow8597("10.0.0.10", "old")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".1", []byte(leaseHdr8597+leaseRow8597("10.0.0.11", "recent")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte(leaseHdr8597), 0o644); err != nil {
		t.Fatal(err)
	}

	prev := parseLeaseFileFn
	var seen int
	parseLeaseFileFn = func(p string, family int, now time.Time, acc *ddnsLeaseAccum) error {
		err := prev(p, family, now, acc)
		seen++
		if seen == 1 {
			// Kea's completed output becomes authoritative while the reader is
			// between source files. Remove the old generations to model the
			// interrupted rename window and leave the lease in completed only.
			if err := os.WriteFile(base+".completed", []byte(leaseHdr8597+leaseRow8597("10.0.0.10", "completed")), 0o644); err != nil {
				t.Fatalf("write completed: %v", err)
			}
			if err := os.Remove(base + ".2"); err != nil {
				t.Fatalf("remove .2: %v", err)
			}
			if err := os.Remove(base + ".1"); err != nil {
				t.Fatalf("remove .1: %v", err)
			}
		}
		return err
	}
	t.Cleanup(func() { parseLeaseFileFn = prev })

	if _, err := parseActiveLeases(base, 4, time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatal("completed-only transition during source selection was trusted; " +
			"the four-name stability guard must refuse the read")
	} else if !strings.Contains(err.Error(), "rotated during read") {
		t.Fatalf("refused for an unrelated reason: %v", err)
	}
	if seen < 2 {
		t.Fatalf("the parse visited %d files; the transition was not interleaved", seen)
	}
}

// TestQuiescentSetIsStillTrusted_8597 is the OVER-BROAD control, and the one
// that decides whether a fail-closed detector can ship: refusing a quiescent
// read would disable the destructive DDNS diff permanently.
func TestQuiescentSetIsStillTrusted_8597(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "leases4.csv")
	if err := os.WriteFile(base+".2", []byte(leaseHdr8597+leaseRow8597("10.0.0.10", "old")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".1", []byte(leaseHdr8597+leaseRow8597("10.0.0.11", "recent")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte(leaseHdr8597+leaseRow8597("10.0.0.12", "live")), 0o644); err != nil {
		t.Fatal(err)
	}

	leases, err := parseActiveLeases(base, 4, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("a quiescent lease set was refused: %v — this detector runs on every "+
			"reconcile, so a false positive disables the destructive DDNS diff", err)
	}
	if len(leases) != 3 {
		t.Fatalf("merged %d leases, want 3 (one per file): %+v", len(leases), leases)
	}
}

// TestAbsentRotationFilesAreNotAChange_8597: `.1` and `.2` legitimately do not
// exist on a fresh install or between compactions. Absent-then-absent must
// compare EQUAL, or the detector fires on the most common steady state there
// is.
func TestAbsentRotationFilesAreNotAChange_8597(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "leases4.csv")
	if err := os.WriteFile(base, []byte(leaseHdr8597+leaseRow8597("10.0.0.12", "live")), 0o644); err != nil {
		t.Fatal(err)
	}
	leases, err := parseActiveLeases(base, 4, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("a set with no .1/.2 was refused: %v — that is a fresh install", err)
	}
	if len(leases) != 1 {
		t.Fatalf("got %d leases, want 1", len(leases))
	}
}

// TestIdentityComparisonUsesTheInodeNotTheName_8597 pins the discriminator.
//
// kea-lfc's swap is a RENAME: the path keeps its name and gets a new inode. A
// comparison on name, size or mtime can miss it — a rotation that produces a
// same-sized file within the timestamp's resolution is exactly the case a
// stat-based check gets wrong. os.SameFile is the comparison that cannot.
func TestIdentityComparisonUsesTheInodeNotTheName_8597(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	content := []byte("same size!!")

	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	before := leaseSetIdentity([]string{p})

	// Replace by rename with byte-identical content — same name, same size,
	// different inode. This is the rotation's shape.
	tmp := filepath.Join(dir, "tmp")
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
	after := leaseSetIdentity([]string{p})

	if leaseSetIdentityStable(before, after) {
		t.Error("a same-name, same-size replacement compared as UNCHANGED; the " +
			"comparison must be on file identity (os.SameFile), because kea-lfc's " +
			"swap is a rename and leaves both the name and the size available to " +
			"collide")
	}

	// And the control: an untouched file must compare stable, or the detector
	// refuses every read.
	stable := leaseSetIdentity([]string{p})
	if !leaseSetIdentityStable(after, stable) {
		t.Error("an untouched file compared as CHANGED; the detector would refuse " +
			"every quiescent read")
	}
}
