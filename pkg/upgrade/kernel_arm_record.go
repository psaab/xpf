package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// ErrKernelPromoteBinaryUnresolvable marks an arm-time refusal: the arming
// process could not establish which xpfd the promotion gate must run, so a
// candidate armed here could never be verified.
var ErrKernelPromoteBinaryUnresolvable = errors.New("kernel promotion binary unresolvable")

// armRecordName is the sidecar the arming writes next to the kernel journal:
// ONE line, the absolute path of the xpfd the promotion gate must run.
//
// It duplicates KernelJournal.PromoteBinary deliberately. The journal is JSON
// and the boot-time gate is POSIX sh, which has no safe JSON parser; a
// single-line file is something `read` handles exactly. Both are written from
// the SAME resolved value inside recordPromoteBinary, and the Go half of the
// gate cross-checks the two, so a divergence is caught rather than trusted.
const armRecordName = "kernel-promote-binary"

// ArmRecordPath returns the sidecar path for a given kernel journal path. The
// sidecar lives beside the journal so it shares its directory and lifetime.
func ArmRecordPath(journalPath string) string {
	return filepath.Join(filepath.Dir(journalPath), armRecordName)
}

// resolveArmingBinary returns the absolute path of the xpfd running THIS
// process, validated as an executable regular file.
//
// This is the authority the arming has and no later stage does: `xpfd upgrade
// kernel arm` IS an xpfd, so os.Executable() names the live binary by
// construction rather than by inference. On Linux it reads /proc/self/exe,
// which has already resolved the sbin -> current -> versions/<ver>/xpfd chain
// down to the concrete versioned artifact.
//
// A caveat stated rather than hidden: os.Executable yields a PATH, not an
// inode, so a binary cut between arming and the candidate boot could leave it
// naming a different build. That is why the gate VALIDATES the recorded path at
// boot and refuses when it no longer resolves, and why refusal means revert —
// the safe direction — rather than a fallback.
var resolveArmingBinary = func() (string, error) {
	self, err := osExecutable()
	if err != nil {
		return "", fmt.Errorf("os.Executable: %w", err)
	}
	if err := validateGateBin(self); err != nil {
		return "", fmt.Errorf("running binary %q: %w", self, err)
	}
	return self, nil
}

// recordPromoteBinary resolves the arming binary, stamps it onto j, and writes
// the sidecar durably. Called during Arm BEFORE the verified ARMED transition,
// so a candidate is never recorded as armed without a usable record of which
// xpfd must verify it.
//
// FAILS CLOSED (#6601 r6 MINOR-1). The previous arm-time readiness check
// permitted a probe error or an empty answer, so an unverifiable layout stayed
// armable exactly when the system could not be interrogated. A preflight that
// cannot establish readiness must refuse: arming is retryable, an unverified
// candidate kernel is not.
func (r *KernelRunner) recordPromoteBinary(j *KernelJournal) error {
	bin, err := resolveArmingBinary()
	if err != nil {
		return fmt.Errorf("%w: cannot determine which xpfd the promotion gate "+
			"must run (%v). Refusing to arm: the gate reads this record and "+
			"never falls back to inferring a path, so arming now would boot a "+
			"candidate kernel that runs UNVERIFIED and is never promoted",
			ErrKernelPromoteBinaryUnresolvable, err)
	}
	j.PromoteBinary = bin

	path := ArmRecordPath(r.cfg.JournalPath)
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("%w: create arm-record dir: %v",
			ErrKernelPromoteBinaryUnresolvable, err)
	}
	if err := fsatomic.WriteFileDurable(path, []byte(bin+"\n"), 0o644); err != nil {
		return fmt.Errorf("%w: persist arm record %s: %v",
			ErrKernelPromoteBinaryUnresolvable, path, err)
	}
	// A refusal from a PRIOR candidate must not be read as a verdict on this
	// one (#6622). Cleared here, at the point the new arm record is written,
	// rather than at the top of Arm: an arm that fails preflight leaves the
	// previous refusal intact, which is what an operator diagnosing that
	// failure needs on screen.
	//
	// Best-effort. Failing to remove a diagnostic must not refuse an arm that
	// has already passed preflight and installed a candidate — the fail-closed
	// rule above is about the arm RECORD, whose absence would strand the
	// candidate unverifiable, and a stale refusal costs only a confusing line
	// that carries its own timestamp and boot id.
	_ = r.clearRefusalRecord()
	return nil
}

// clearArmRecord removes the sidecar. Called wherever the journal is cleared so
// "nothing armed" and "no record" stay the same statement — which is what lets
// the boot-time gate treat an absent record as a definitive "nothing to
// promote" rather than as a failure.
func (r *KernelRunner) clearArmRecord() error {
	return clearArmRecordForJournal(r.cfg.JournalPath)
}

func clearArmRecordForJournal(journalPath string) error {
	if err := os.Remove(ArmRecordPath(journalPath)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove arm record: %w", err)
	}
	return nil
}

// ReadArmRecord returns the recorded promotion binary, or "" when no record
// exists. A malformed record is an ERROR, never an empty answer: "absent" means
// nothing is armed and is acted on as such, so it must not be reachable by
// mis-parsing a file that is present.
func ReadArmRecord(journalPath string) (string, error) {
	path := ArmRecordPath(journalPath)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read arm record %s: %w", path, err)
	}
	line := strings.TrimSpace(string(data))
	if line == "" {
		return "", fmt.Errorf("arm record %s is empty", path)
	}
	if !filepath.IsAbs(line) {
		return "", fmt.Errorf("arm record %s = %q is not an absolute path", path, line)
	}
	return line, nil
}

// VerifyPromoteBinaryMatchesRecord is the Go half of the cross-check: the
// binary now executing the promotion gate must be the one the arming recorded.
//
// The outer hop selects from the sidecar, so in the normal path this is
// trivially true. It earns its place when the gate is invoked by hand, or by an
// older or otherwise different xpfd, or when the sidecar and the journal
// diverged — cases where the process running the gate is NOT the one the arming
// designated. A mismatch is reported so the caller REVERTS, never so it adopts
// the running binary.
//
// An empty recorded value means the journal predates this field (armed by an
// older build). That is accepted rather than treated as a mismatch: refusing
// would strand an in-flight candidate across an upgrade, and the outer hop
// already refuses when it has no usable record to select from.
func VerifyPromoteBinaryMatchesRecord(recorded string) error {
	if recorded == "" {
		return nil
	}
	self, err := osExecutable()
	if err != nil {
		// Indeterminate, and this is a cross-check rather than the authority:
		// the outer hop already selected from the record.
		return nil
	}
	if self != recorded {
		return fmt.Errorf("promotion gate is running %q but the arming recorded "+
			"%q as the xpfd that must verify this candidate; refusing rather "+
			"than letting an undesignated binary authorize the promotion",
			self, recorded)
	}
	return nil
}
