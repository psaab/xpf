package upgrade

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #6601 r6 MAJOR. Every prior design inferred "which xpfd is live" from ambient
// state, and each signal in turn proved stale-able. The last one broke
// concretely: a DISABLED unit still reports LoadState=loaded with MainPID=0, so
// a leftover default unit whose drop-in named an OLD version passed the
// arm-time check and its stale ExecStart was accepted at boot.
//
// The arming is the authority: it IS an xpfd, so it knows the live binary by
// construction. These tests pin that the record is written, is the thing the
// gate reads, and that nothing falls back to inference.

func withArmingBinaryResolver(t *testing.T, fn func() (string, error)) {
	t.Helper()
	orig := resolveArmingBinary
	t.Cleanup(func() { resolveArmingBinary = orig })
	resolveArmingBinary = fn
}

func newRecordRunner(t *testing.T) (*KernelRunner, string) {
	t.Helper()
	dir := t.TempDir()
	journal := filepath.Join(dir, "kernel-upgrade.state")
	return &KernelRunner{cfg: KernelConfig{JournalPath: journal}}, journal
}

// TestRecordPromoteBinaryWritesBothRecords: the journal field and the sidecar
// must come from the SAME resolved value. They exist separately only because
// the boot gate is POSIX sh and cannot parse JSON.
func TestRecordPromoteBinaryWritesBothRecords(t *testing.T) {
	r, journal := newRecordRunner(t)
	live := fakeXpfd(t, filepath.Join(t.TempDir(), "versions", "vB"), 0)
	withArmingBinaryResolver(t, func() (string, error) { return live, nil })

	j := &KernelJournal{}
	if err := r.recordPromoteBinary(j); err != nil {
		t.Fatalf("recordPromoteBinary: %v", err)
	}
	if j.PromoteBinary != live {
		t.Fatalf("journal PromoteBinary = %q, want %q", j.PromoteBinary, live)
	}
	got, err := ReadArmRecord(journal)
	if err != nil {
		t.Fatalf("ReadArmRecord: %v", err)
	}
	if got != live {
		t.Fatalf("sidecar = %q, want %q — the two records must not diverge", got, live)
	}
}

// TestRecordPromoteBinaryFailsClosed is MINOR-1: a preflight that cannot
// establish readiness must REFUSE. The previous arm-time check permitted a
// probe error or an empty answer, so an unverifiable layout stayed armable
// exactly when the system could not be interrogated. Arming is retryable; an
// unverified candidate kernel is not.
func TestRecordPromoteBinaryFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		bin  string
		err  error
	}{
		{"resolver error", "", errors.New("no /proc")},
		{"empty path", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, journal := newRecordRunner(t)
			withArmingBinaryResolver(t, func() (string, error) {
				if tc.err != nil {
					return "", tc.err
				}
				return tc.bin, validateGateBin(tc.bin)
			})
			j := &KernelJournal{}
			err := r.recordPromoteBinary(j)
			if err == nil {
				t.Fatalf("recordPromoteBinary succeeded with an unresolvable arming " +
					"binary; the arm must fail CLOSED (#6601 r6 MINOR-1)")
			}
			if !errors.Is(err, ErrKernelPromoteBinaryUnresolvable) {
				t.Fatalf("error does not wrap the sentinel: %v", err)
			}
			if _, serr := os.Stat(ArmRecordPath(journal)); serr == nil {
				t.Fatal("a sidecar was written despite the refusal")
			}
		})
	}
}

// TestReadArmRecordAbsentMeansNothingArmed: absence is a definitive statement,
// not a diagnosis problem. The record is written by arming and removed with the
// journal, so no record == no candidate == the one state in which not running
// the gate is harmless.
func TestReadArmRecordAbsentMeansNothingArmed(t *testing.T) {
	got, err := ReadArmRecord(filepath.Join(t.TempDir(), "kernel-upgrade.state"))
	if err != nil {
		t.Fatalf("absent record must not be an error: %v", err)
	}
	if got != "" {
		t.Fatalf("absent record returned %q", got)
	}
}

// TestReadArmRecordMalformedIsAnErrorNotAbsence: "absent" is acted on as
// "nothing armed", so it must not be reachable by mis-parsing a file that IS
// present — that would silently skip the gate for an armed candidate.
func TestReadArmRecordMalformedIsAnErrorNotAbsence(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty", ""},
		{"whitespace", "   \n"},
		{"relative", "./xpfd\n"},
		{"bare name", "xpfd\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			journal := filepath.Join(dir, "kernel-upgrade.state")
			if err := os.WriteFile(ArmRecordPath(journal), []byte(tc.body), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, err := ReadArmRecord(journal)
			if err == nil {
				t.Fatalf("malformed record %q parsed as %q; a present-but-unusable "+
					"record must ERROR, never read as 'nothing armed'", tc.body, got)
			}
		})
	}
}

// TestClearKernelJournalClearsTheArmRecord: if the sidecar outlived the
// journal, every subsequent ordinary boot would find a record pointing at a
// candidate that no longer exists and refuse.
func TestClearKernelJournalClearsTheArmRecord(t *testing.T) {
	r, journal := newRecordRunner(t)
	live := fakeXpfd(t, t.TempDir(), 0)
	withArmingBinaryResolver(t, func() (string, error) { return live, nil })
	if err := r.recordPromoteBinary(&KernelJournal{}); err != nil {
		t.Fatalf("recordPromoteBinary: %v", err)
	}
	if err := os.WriteFile(journal, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	if err := r.clearKernelJournal(); err != nil {
		t.Fatalf("clearKernelJournal: %v", err)
	}
	if _, err := os.Stat(ArmRecordPath(journal)); !os.IsNotExist(err) {
		t.Fatalf("arm record survived the journal clear (err=%v); every later "+
			"ordinary boot would refuse", err)
	}
}

// TestVerifyPromoteBinaryMatchesRecord is the Go half of the cross-check.
func TestVerifyPromoteBinaryMatchesRecord(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable: %v", err)
	}

	t.Run("match", func(t *testing.T) {
		if err := VerifyPromoteBinaryMatchesRecord(self); err != nil {
			t.Fatalf("same binary reported a mismatch: %v", err)
		}
	})
	t.Run("mismatch reverts", func(t *testing.T) {
		if err := VerifyPromoteBinaryMatchesRecord("/nonexistent/other/xpfd"); err == nil {
			t.Fatal("an undesignated binary was allowed to authorize the promotion")
		}
	})
	// An older build's journal has no recorded value. Refusing would strand an
	// in-flight candidate across an upgrade, and the outer hop already refuses
	// when it has no usable record to select from.
	t.Run("empty record tolerated", func(t *testing.T) {
		if err := VerifyPromoteBinaryMatchesRecord(""); err != nil {
			t.Fatalf("empty (pre-r6) record treated as a mismatch: %v", err)
		}
	})
}

var armRecordPathRE = regexp.MustCompile(`(?m)^ARM_RECORD="([^"]+)"`)

// TestPromoteScriptArmRecordPathMatchesGo is the CROSS-LANGUAGE canary for the
// record's location. The boot gate is POSIX sh and hardcodes the path; Go
// derives it from the journal path. If they drift, arming writes a record the
// gate never reads — and the gate would then skip every boot as "nothing
// armed", silently, which is precisely the laundering this round removes.
func TestPromoteScriptArmRecordPathMatchesGo(t *testing.T) {
	data, err := os.ReadFile(promoteScriptPath(t))
	if err != nil {
		t.Fatalf("read promote script: %v", err)
	}
	m := armRecordPathRE.FindSubmatch(data)
	if m == nil {
		t.Fatal("no `ARM_RECORD=\"...\"` assignment in the promote script; the " +
			"record location is no longer assertable from Go")
	}
	got := string(m[1])
	want := ArmRecordPath(DefaultKernelJournalPath)
	if got != want {
		t.Fatalf("promote script reads the arm record from %q but Go writes it to "+
			"%q. Arming would record where the gate never looks, and the gate "+
			"would skip every boot as 'nothing armed'.", got, want)
	}
}

// ---------------------------------------------------------------------------
// PRODUCER WIRING (#6601 r8 MAJOR-2).
//
// The tests above pin the record's SHAPE and the shell's view of it. None of
// them drove the state machine, so four load-bearing points were unbound: that
// arming calls recordPromoteBinary at all, that the promote path enforces the
// record, that resolveArmingBinary itself fails closed, and that a failed
// sidecar write refuses the arm. Deleting any of them left the entire Go suite
// and all 65 python tests green while the feature was inert -- with the
// recordPromoteBinary call removed, arming writes no sidecar, and EVERY
// candidate boot then refuses. Python cannot see it: the shell harness writes
// the record itself, never through Go.
// ---------------------------------------------------------------------------

// TestArmWritesTheSidecarAndJournalField drives the REAL arm and asserts the
// record exists afterwards. This is the one that kills "delete the
// recordPromoteBinary call from armCandidate".
func TestArmWritesTheSidecarAndJournalField(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatalf("load journal: %v", err)
	}
	if j.State != KernelStateArmed {
		t.Fatalf("journal state = %s, want ARMED", j.State)
	}
	if j.PromoteBinary == "" {
		t.Error("arming reached ARMED without stamping PromoteBinary on the journal; " +
			"Gate 2b then has nothing to enforce")
	}

	rec := ArmRecordPath(r.cfg.JournalPath)
	data, err := os.ReadFile(rec)
	if err != nil {
		t.Fatalf("arming reached ARMED without writing the sidecar %s (%v). The boot "+
			"gate reads THIS file and never infers a path, so every candidate boot "+
			"would find the record absent, the journal ARMED, and refuse — the "+
			"feature is inert", rec, err)
	}
	got := strings.TrimSpace(string(data))
	if got != j.PromoteBinary {
		t.Errorf("sidecar = %q but journal PromoteBinary = %q; they are written from "+
			"one resolved value and must not diverge", got, j.PromoteBinary)
	}
	self, err := osExecutable()
	if err == nil && got != self {
		t.Errorf("sidecar = %q, want the arming process's own binary %q — the whole "+
			"point is that the arming knows this by construction", got, self)
	}
}

// TestPromoteRevertsWhenTheRunningBinaryIsNotTheRecordedOne drives the REAL
// promote path with a journal whose PromoteBinary names some other xpfd. Gate 2b
// must REVERT: an undesignated binary does not get to authorize a promotion, and
// on an A/B kernel trial reverting is the safe direction.
func TestPromoteRevertsWhenTheRunningBinaryIsNotTheRecordedOne(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	// The candidate boot is otherwise PERFECT: firmware honoured BootNext, the
	// running kernel is the candidate, and both verification gates pass. The
	// ONLY thing wrong is that this process is not the xpfd the arming
	// designated — so a green result here means Gate 2b did not run.
	j, err := r.loadKernelJournal()
	if err != nil {
		t.Fatalf("load journal: %v", err)
	}
	j.PromoteBinary = "/nonexistent/some-other/xpfd"
	if err := r.saveKernelJournal(j); err != nil {
		t.Fatalf("save journal: %v", err)
	}
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = true
	f.beaconPass = true

	_, err = r.Promote()
	if err == nil {
		t.Fatal("Promote SUCCEEDED while running a binary the arming did not designate; " +
			"an undesignated xpfd authorized the promotion (#6601 Gate 2b)")
	}
	if !errorsIsReverted(err) {
		t.Fatalf("Promote error = %v, want ErrKernelReverted — a record mismatch must "+
			"REVERT, not surface as an infra error the oneshot ignores", err)
	}
	if f.order[0] == "0004" {
		t.Error("the candidate slot was promoted to the BootOrder front despite the " +
			"arm-record mismatch")
	}
}

// TestResolveArmingBinaryFailsClosed exercises the REAL resolveArmingBinary.
//
// TestRecordPromoteBinaryFailsClosed above replaces the resolver wholesale, so
// it proves only that recordPromoteBinary propagates an error handed to it —
// the real function body was executed by no test in the repo. Both of its arms
// are covered here, and the refusal is asserted end to end through Arm: a
// preflight that cannot establish which binary is arming must refuse, because
// arming is retryable and an unverified candidate kernel is not.
func TestResolveArmingBinaryFailsClosed(t *testing.T) {
	origExe := osExecutable
	t.Cleanup(func() { osExecutable = origExe })

	cases := []struct {
		name string
		exe  func() (string, error)
		want string
	}{
		{
			name: "os.Executable errors",
			exe:  func() (string, error) { return "", errors.New("no /proc/self/exe") },
			want: "os.Executable",
		},
		{
			name: "os.Executable names something unusable",
			exe:  func() (string, error) { return "/nonexistent/xpfd", nil },
			want: "running binary",
		},
		{
			name: "os.Executable returns a relative path",
			exe:  func() (string, error) { return "xpfd", nil },
			want: "running binary",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			osExecutable = tc.exe

			got, err := resolveArmingBinary()
			if err == nil {
				t.Fatalf("resolveArmingBinary returned %q with no error; it FAILED OPEN, "+
					"so an unverifiable layout stays armable precisely when the system "+
					"cannot be interrogated", got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}

			// End to end: the arm itself must refuse, at the operator's terminal.
			f := newFakeKernelSystem()
			r := newKernelRunner(t, f)
			err = r.Arm("6.18.5-12-generic")
			if err == nil {
				t.Fatal("Arm SUCCEEDED although the arming binary is unresolvable; the " +
					"candidate would boot UNVERIFIED and never be promoted")
			}
			if !errors.Is(err, ErrKernelPromoteBinaryUnresolvable) {
				t.Errorf("Arm error = %v, want ErrKernelPromoteBinaryUnresolvable", err)
			}
			j, jerr := r.loadKernelJournal()
			if jerr != nil {
				t.Fatalf("load journal: %v", jerr)
			}
			if j.State.atLeast(KernelStateArmed) {
				t.Errorf("journal reached %s despite the refusal; the record is written "+
					"BEFORE the ARMED transition precisely so this cannot happen", j.State)
			}
		})
	}
}

// TestArmRefusesWhenTheSidecarCannotBeWritten covers the third fail-closed
// point: the resolve succeeded but the sidecar did not land. An ARMED journal
// with no readable record is the divergent state the boot gate refuses on, so
// producing one here would arm a candidate that can never be promoted.
//
// The sidecar path is occupied by a DIRECTORY, so the durable rename onto it
// fails while the journal's own directory stays writable (a read-only-directory
// model would not survive a root test runner).
func TestArmRefusesWhenTheSidecarCannotBeWritten(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	rec := ArmRecordPath(r.cfg.JournalPath)
	if err := os.MkdirAll(rec, 0o755); err != nil {
		t.Fatalf("stage a directory at the sidecar path: %v", err)
	}

	err := r.Arm("6.18.5-12-generic")
	if err == nil {
		t.Fatal("Arm SUCCEEDED although the sidecar could not be written; the candidate " +
			"would boot with the journal ARMED and no record, which the gate refuses")
	}
	if !errors.Is(err, ErrKernelPromoteBinaryUnresolvable) {
		t.Errorf("Arm error = %v, want ErrKernelPromoteBinaryUnresolvable", err)
	}
	j, jerr := r.loadKernelJournal()
	if jerr != nil {
		t.Fatalf("load journal: %v", jerr)
	}
	if j.State.atLeast(KernelStateArmed) {
		t.Errorf("journal reached %s with no sidecar on disk", j.State)
	}
}

var (
	kernelJournalPathRE = regexp.MustCompile(`(?m)^KERNEL_JOURNAL="([^"]+)"`)
	journalArmedStateRE = regexp.MustCompile(`(?m)^JOURNAL_ARMED_STATE="([^"]+)"`)
	promoteUnitRE       = regexp.MustCompile(`(?m)^PROMOTE_UNIT="([^"]+)"`)
)

// TestPromoteScriptJournalMatchesGo is the CROSS-LANGUAGE canary for the r7
// divergent-state check. When the arm record is absent the boot gate consults
// the journal for ONE BIT — is a candidate ARMED — so that a record which
// desynced out of band produces a loud refusal instead of a benign "nothing to
// promote". Both the journal's location and the state token it looks for are
// hardcoded in POSIX sh; if either drifts from Go, the check silently never
// fires and the silent skip is back.
func TestPromoteScriptJournalMatchesGo(t *testing.T) {
	data, err := os.ReadFile(promoteScriptPath(t))
	if err != nil {
		t.Fatalf("read promote script: %v", err)
	}

	m := kernelJournalPathRE.FindSubmatch(data)
	if m == nil {
		t.Fatal("no `KERNEL_JOURNAL=\"...\"` assignment in the promote script; " +
			"the gate can no longer tell an armed-without-record box from an " +
			"ordinary boot")
	}
	if got, want := string(m[1]), DefaultKernelJournalPath; got != want {
		t.Errorf("promote script reads the kernel journal from %q but Go writes it "+
			"to %q; an ARMED candidate whose record went missing would be reported "+
			"as 'nothing to promote'", got, want)
	}

	m = journalArmedStateRE.FindSubmatch(data)
	if m == nil {
		t.Fatal("no `JOURNAL_ARMED_STATE=\"...\"` assignment in the promote script")
	}
	got := string(m[1])
	if want := string(KernelStateArmed); got != want {
		t.Errorf("promote script looks for journal state %q but Go writes %q", got, want)
	}
	// ARMING is PREPARED INTENT recorded before the firmware one-shot is read
	// back — not a trial in flight. upgrade.IsArmed draws exactly this line, and
	// matching it here would put a loud refusal on every boot of a box whose arm
	// was interrupted.
	if got == string(KernelStateArming) {
		t.Errorf("promote script treats %q as a trial in flight; only the verified "+
			"%q state is one (see IsArmed)", KernelStateArming, KernelStateArmed)
	}
}

// TestPromoteScriptUnitMatchesDefaultUnit pins the unit the gate CROSS-CHECKS
// the record against. Since r6 this unit is no longer the authority, so drift
// no longer selects a wrong binary — it silently retires the cross-check (a
// unit that never resolves can never contradict a stale record) or, worse,
// contradicts a good record and refuses every promotion.
func TestPromoteScriptUnitMatchesDefaultUnit(t *testing.T) {
	data, err := os.ReadFile(promoteScriptPath(t))
	if err != nil {
		t.Fatalf("read promote script: %v", err)
	}
	m := promoteUnitRE.FindSubmatch(data)
	if m == nil {
		t.Fatal("no `PROMOTE_UNIT=\"...\"` assignment in the promote script")
	}
	if got, want := string(m[1]), DefaultUnit+".service"; got != want {
		t.Errorf("promote script cross-checks against %q but the default unit is %q", got, want)
	}
}

// TestPromoteScriptSelectsFromTheRecordNotInference guards the design itself:
// the record must be consulted, and the inference helpers must not be able to
// select a binary on their own. `try_candidate` may still run — it feeds the
// cross-check — but the executed path has to come from the record.
func TestPromoteScriptSelectsFromTheRecordNotInference(t *testing.T) {
	data, err := os.ReadFile(promoteScriptPath(t))
	if err != nil {
		t.Fatalf("read promote script: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, `XPFD="$RECORDED"`) {
		t.Error("the gate never assigns the executed binary from the arm record; " +
			"selection has drifted back to inference (#6601 r6)")
	}
	// The cross-check must refuse on disagreement rather than prefer one side.
	if !strings.Contains(src, `! same_file "$CROSS" "$RECORDED"`) {
		t.Error("no record-vs-unit disagreement check; a stale leftover unit " +
			"could again select an older binary (#6601 r6 MAJOR)")
	}
	// ...and it must compare FILES. os.Executable() records a RESOLVED path
	// while the shipped base unit's ExecStart is the /usr/local/sbin/xpfd
	// symlink until the first cut, so a string compare refuses a healthy
	// candidate on every never-cut box (#6601 r8 MAJOR-1).
	if strings.Contains(src, `"$CROSS" != "$RECORDED"`) {
		t.Error("the cross-check compares the record and the unit as STRINGS; one " +
			"file reached through two names reads as a disagreement and refuses a " +
			"healthy promotion (#6601 r8 MAJOR-1)")
	}
	// Nothing may re-introduce a compiled-default fallback.
	for _, banned := range []string{
		`try_candidate /usr/local/sbin/xpfd`,
		`try_candidate /var/lib/xpf/versions/current/xpfd`,
	} {
		if strings.Contains(src, banned) {
			t.Errorf("compiled-default inference reintroduced: %s", banned)
		}
	}
}

// promoteScriptPath locates the boot-time gate from this package's directory.
func promoteScriptPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	p := filepath.Join(wd, "..", "..", "scripts", "image", "xpf-kernel-promote")
	if _, err := os.Stat(p); err != nil {
		// FATAL, not Skip (#6601 r8 NIT). These are cross-language canaries: a
		// packaging move that relocated the script would otherwise retire all
		// four of them silently, which is the failure mode they exist to
		// prevent, applied to themselves.
		t.Fatalf("promote script not found at %s: %v — the cross-language canaries "+
			"cannot run, so the shell's ARM_RECORD/KERNEL_JOURNAL/JOURNAL_ARMED_STATE/"+
			"PROMOTE_UNIT are no longer pinned against Go", p, err)
	}
	return p
}
