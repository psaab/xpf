package upgrade

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// #5428: the PRE-purge installed-set loop and the POST-purge confirmed-absent
// re-query both use the dpkg "is this package installed?" helper, which returns
// false on ANY dpkg-query error. A false-negative there (dpkg-DB corruption /
// parse error / lock while the package IS actually installed) would drop a
// still-owned package from the set, skip the purge, and let the sweep delete
// the candidate's package-owned /boot + /lib/modules files while dpkg still
// owns them — the same dpkg/filesystem divergence #5427 closed on the
// lock/maintainer-script vector, now reached via a DB query error. The helper
// is tri-state (installed / not-installed / query-error) and a query error must
// FAIL SAFE (treat the package as POSSIBLY-INSTALLED, never delete its files).

// dpkgParseErr models a genuine dpkg-query FAILURE (DB corruption) — distinct
// from the "no packages found matching" absent verdict, so it must fail safe.
func dpkgParseErr() error {
	return fmt.Errorf("dpkg-query -W -f=${Status} linux-image: exit status 2 " +
		"(output: dpkg-query: error: parsing file '/var/lib/dpkg/status' near line 42)")
}

func TestPruneInactiveSlot_PrePurgeQueryErrorFailsSafe(t *testing.T) {
	// dpkg-query ERRORS for every candidate package in the PRE-purge loop while
	// the packages are (unknowably) still installed. The loop must treat the
	// query error as possibly-installed: attempt the purge and, because the
	// error persists, leave the package-owned files intact rather than sweeping
	// them. Reverting the fix drops the packages from the set, skips the purge,
	// and sweeps the files — this test then fails (files gone).
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	purgeAttempted := false
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return knownGood, nil },
		pkgInstalledFn:  func(string) (bool, error) { return false, dpkgParseErr() },
		aptGetFn: func(args ...string) error {
			if len(args) > 0 && args[0] == "purge" {
				purgeAttempted = true
			}
			return nil
		},
	}

	err := sys.PruneInactiveSlot("xpf-B", knownGood, cand)
	if err == nil {
		t.Fatal("expected a non-nil error when dpkg status cannot be determined")
	}
	// The pre-purge loop must have kept the query-error packages in the set, so
	// a real purge was attempted (not skipped as if nothing were installed).
	if !purgeAttempted {
		t.Error("purge must be attempted when dpkg status is unknown (fail-safe possibly-installed), not skipped")
	}
	// Package-owned files MUST survive: a query error is not a confirmed
	// removal, so the sweep must not run.
	if _, statErr := os.Stat(modulesDir); statErr != nil {
		t.Errorf("/lib/modules/%s deleted despite an unresolved dpkg-query error (%v) — dpkg/FS divergence", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); statErr != nil {
		t.Errorf("/boot/vmlinuz-%s deleted despite an unresolved dpkg-query error (%v)", cand, statErr)
	}
	// The slot selector is still pointed at known-good regardless.
	if sel, selErr := sys.ReadSlotSelector("xpf-B"); selErr != nil || sel != knownGood {
		t.Errorf("slot selector = %q (err %v), want known-good %q", sel, selErr, knownGood)
	}
}

func TestPruneInactiveSlot_PostPurgeQueryErrorKeepsFiles(t *testing.T) {
	// The packages are confirmed installed in the PRE-purge loop and apt-get
	// purge returns success, but the POST-purge confirmed-absent re-query
	// ERRORS (DB became unreadable). A query error is NOT a confirmed removal,
	// so the files must be kept and the anomaly surfaced. Reverting the fix
	// makes the errored re-query read as "not installed" and sweeps the files.
	root := t.TempDir()
	const cand = "7.0.0-99-generic"
	const knownGood = "7.0.0-22-generic"
	modulesDir, bootFile := seedCandidatePayload(t, root, cand)

	purged := false
	sys := &realKernelSystem{
		fsRoot:          root,
		runningKernelFn: func() (string, error) { return knownGood, nil },
		pkgInstalledFn: func(string) (bool, error) {
			if !purged {
				return true, nil // installed before the purge
			}
			return false, dpkgParseErr() // status unverifiable after the purge
		},
		aptGetFn: func(args ...string) error {
			if len(args) > 0 && args[0] == "purge" {
				purged = true
			}
			return nil
		},
	}

	err := sys.PruneInactiveSlot("xpf-B", knownGood, cand)
	if err == nil {
		t.Fatal("expected an error when the post-purge re-query cannot confirm removal")
	}
	if !strings.Contains(err.Error(), "still installed") {
		t.Errorf("error should flag the unconfirmed removal: %v", err)
	}
	if _, statErr := os.Stat(modulesDir); statErr != nil {
		t.Errorf("/lib/modules/%s deleted despite an unconfirmed post-purge removal (%v)", cand, statErr)
	}
	if _, statErr := os.Stat(bootFile); statErr != nil {
		t.Errorf("/boot/vmlinuz-%s deleted despite an unconfirmed post-purge removal (%v)", cand, statErr)
	}
}

func TestDpkgQueryAbsent(t *testing.T) {
	// A genuinely-unknown package ("no packages found matching") is a legitimate
	// confirmed-absent — NOT a fail-safe query error (else a never-installed
	// optional pkg would be pushed into the purge set and apt-get would fail
	// with "Unable to locate package").
	notFound := fmt.Errorf("dpkg-query -W -f=${Status} linux-headers-x: exit status 1 " +
		"(output: dpkg-query: no packages found matching linux-headers-x)")
	if !dpkgQueryAbsent(notFound) {
		t.Errorf("a \"no packages found matching\" error must classify as absent: %v", notFound)
	}
	// A real query failure (DB parse error) is NOT absent — it must fail safe.
	if dpkgQueryAbsent(dpkgParseErr()) {
		t.Error("a dpkg DB parse error must NOT classify as absent (must fail safe as possibly-installed)")
	}
	// A permission failure is likewise a query error, not an absent verdict.
	permErr := fmt.Errorf("dpkg-query -W: exit status 2 (output: dpkg-query: cannot open '/var/lib/dpkg/status': Permission denied)")
	if dpkgQueryAbsent(permErr) {
		t.Error("a permission error must NOT classify as absent")
	}
	if dpkgQueryAbsent(nil) {
		t.Error("nil is not an absent verdict")
	}
}

func TestIsPkgInstalled_RealDpkgQueryTriState(t *testing.T) {
	// End-to-end classification against the real dpkg-query: a package dpkg has
	// never heard of must come back (false, nil) — confirmed absent, NO error —
	// so the pre-purge loop skips it instead of pushing it into the purge set.
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available")
	}
	installed, err := isPkgInstalled("xpf-nonexistent-package-zzz-5428")
	if err != nil {
		t.Errorf("an unknown package must classify as confirmed-absent (false, nil), got err %v", err)
	}
	if installed {
		t.Error("an unknown package must not report installed")
	}
}
