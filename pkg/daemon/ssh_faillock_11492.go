package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

const (
	pamFaillockPreBegin  = "# BEGIN xpf SSH faillock preauth (#11492)"
	pamFaillockPreEnd    = "# END xpf SSH faillock preauth (#11492)"
	pamFaillockPostBegin = "# BEGIN xpf SSH faillock result (#11492)"
	pamFaillockPostEnd   = "# END xpf SSH faillock result (#11492)"

	// The faillock tally is shared per user across every PAM service
	// that includes common-auth, so the managed faillock lines must
	// run ONLY for sshd. Without scoping, five failed root passwords
	// over SSH — which sshd itself rejects anyway when PermitRootLogin
	// is not yes, but still runs through PAM with a substituted fake
	// password — lock root out of the local console (login) and
	// `su -`, the documented bare-metal recovery path (#16733; the
	// Junos CVE-2017-10604 pattern).
	//
	// Scoping mechanism (verified against real libpam in the 16733
	// executed cell — controls and jump counts are load-bearing):
	// pam_succeed_if returns PAM_SUCCESS when its condition is true
	// and PAM_AUTH_ERR when false (never PAM_IGNORE), so each guard
	// is [auth_err=N default=ignore] with condition "service in sshd":
	// for sshd the guard succeeds and default=ignore gives "no
	// opinion" (fall through to the faillock line); for every other
	// service it returns PAM_AUTH_ERR and the jump skips faillock:
	//
	//   - Preauth guard [auth_err=1]: skips preauth, lands on pam_unix.
	//
	//   - pam_unix's stock control is rewritten [success=1] ->
	//     [success=2]: its success jump must clear the result guard
	//     (GuardAuthfail) plus authfail and land on authsucc,
	//     exactly as [success=1] landed there without guards. Only
	//     managed edit to a stock line; render requires the exact
	//     stock pam_unix line on input and restores it on removal.
	//
	//   - GuardAuthfail [auth_err=3]: pam_unix FAILURE falls through
	//     to it. For sshd: ignored, authfail records. For non-sshd:
	//     skips authfail, GuardAuthsucc and authsucc, landing on
	//     pam_deny (jumps count module lines only; BEGIN/END markers
	//     are comments and transparent — a jump landing on a guard
	//     re-fires it, proven in the executed cell).
	//
	//   - GuardAuthsucc [auth_err=2]: landed on by pam_unix's
	//     [success=2] jump. For sshd: ignored, authsucc clears the
	//     tally. The non-sshd success path never lands here (only
	//     sshd's jump does); the guard keeps arithmetic fail-closed.
	//
	// Net: outside sshd no faillock line ever runs (tally neither
	// consulted, recorded, nor cleared); inside sshd the original
	// preauth/unix/authfail/authsucc flow is unchanged.
	//
	// Each guard sits INSIDE its managed block so begin/end markers
	// bracket the whole body and strip/tamper checks cover it.
	pamFaillockGuardPre      = "auth [auth_err=1 default=ignore] pam_succeed_if.so service in sshd quiet_success quiet_fail"
	pamFaillockGuardAuthfail = "auth [auth_err=3 default=ignore] pam_succeed_if.so service in sshd quiet_success quiet_fail"
	pamFaillockGuardAuthsucc = "auth [auth_err=2 default=ignore] pam_succeed_if.so service in sshd quiet_success quiet_fail"

	pamFaillockPreauth  = "auth requisite pam_faillock.so preauth silent deny=5 fail_interval=600 unlock_time=300 even_deny_root"
	pamFaillockAuthfail = "auth [default=die] pam_faillock.so authfail deny=5 fail_interval=600 unlock_time=300 even_deny_root"
	pamFaillockAuthsucc = "auth [success=1 default=ignore] pam_faillock.so authsucc deny=5 fail_interval=600 unlock_time=300 even_deny_root"

	// Stock pam_unix line's managed jump-compensated form:
	// [success=2] skips GuardAuthfail and authfail on success,
	// landing on authsucc exactly as [success=1] did without guards.
	pamUnixAuthLineManaged = "auth [success=2 default=ignore] pam_unix.so nullok"

	// Pre-#16733 managed bodies: the same faillock lines without the
	// sshd-only guard. Recognised in stripPAMFaillockBlock so hosts
	// already carrying the unguarded rules can be upgraded (enable=true
	// strips then re-adds the current body) and rolled back
	// (enable=false strips) instead of erroring "modified".
	pamFaillockPreauthUnguarded  = pamFaillockPreauth
	pamFaillockAuthfailUnguarded = pamFaillockAuthfail
	pamFaillockAuthsuccUnguarded = pamFaillockAuthsucc

	// Pre-#14973 managed bodies, without even_deny_root. Recognised in
	// stripPAMFaillockBlock so hosts already carrying the old rules can be
	// upgraded (enable=true strips then re-adds the current body) and rolled
	// back (enable=false strips) instead of erroring "modified".
	pamFaillockPreauthLegacy  = "auth requisite pam_faillock.so preauth silent deny=5 fail_interval=600 unlock_time=300"
	pamFaillockAuthfailLegacy = "auth [default=die] pam_faillock.so authfail deny=5 fail_interval=600 unlock_time=300"
	pamFaillockAuthsuccLegacy = "auth [success=1 default=ignore] pam_faillock.so authsucc deny=5 fail_interval=600 unlock_time=300"

	pamUnixAuthLine   = "auth [success=1 default=ignore] pam_unix.so nullok"
	pamDenyAuthLine   = "auth requisite pam_deny.so"
	pamPermitAuthLine = "auth required pam_permit.so"
)

var (
	sshdPAMCommonAuthPath  = "/etc/pam.d/common-auth"
	sshdPAMReadFile        = os.ReadFile
	sshdPAMWriteFile       = fsatomic.WriteFileAtomic
	sshdPAMModuleAvailable = func() bool {
		for _, pattern := range []string{
			"/lib/security/pam_faillock.so",
			"/lib/*/security/pam_faillock.so",
			"/usr/lib/security/pam_faillock.so",
			"/usr/lib/*/security/pam_faillock.so",
		} {
			matches, _ := filepath.Glob(pattern)
			if len(matches) > 0 {
				return true
			}
		}
		return false
	}

	errSSHPAMFaillockUnsupported = errors.New("unsupported host PAM authentication stack")
)

// applySSHPAMFaillock adds an SSH-only five-failures/ten-minutes,
// five-minute lockout to Debian's stock common-auth stack: the managed
// faillock lines are guarded to the sshd PAM service (#16733), so the
// per-user tally is only read or written by sshd and a network peer
// cannot lock any account — root included — out of the local console
// or `su`. The appliance image
// disables password authentication and owns a separate PAM posture, so this
// host-PAM integration is limited to non-appliance installs. A custom PAM
// stack is left untouched for its administrator to configure explicitly.
func applySSHPAMFaillock() error {
	_, _, err := applySSHPAMFaillockChanged()
	return err
}

// applySSHPAMFaillockChanged is applySSHPAMFaillock reporting whether it
// changed common-auth and, when it did, the exact pre-apply bytes, so
// applySSHConfig can restore precisely those bytes when a later step
// rolls back (#14973, #16421). Restoring the prior bytes — rather than
// stripping every managed block — matters on the upgrade transition:
// a legacy-to-current rewrite changed the bytes but the lockout already
// existed, so a strip would leave the host with less lockout than
// before the apply.
func applySSHPAMFaillockChanged() (bool, []byte, error) {
	return setSSHPAMFaillock(true)
}

// renderSSHPAMFaillock inserts faillock controls only into the stock Debian
// pam_unix -> pam_deny -> pam_permit authentication sequence. Keeping the
// success jumps explicit preserves the original stack's success path; unknown
// or third-party stacks are refused rather than reordered speculatively.
func renderSSHPAMFaillock(current []byte, enable bool) ([]byte, bool, error) {
	original := string(current)
	newline := "\n"
	if strings.Contains(original, "\r\n") {
		newline = "\r\n"
	}
	text := strings.ReplaceAll(original, "\r\n", "\n")
	lines := strings.Split(text, "\n")
	lines, removedPre, err := stripPAMFaillockBlock(lines, pamFaillockPreBegin, pamFaillockPreEnd,
		[]string{pamFaillockGuardPre, pamFaillockPreauth},
		[]string{pamFaillockPreauthUnguarded},
		[]string{pamFaillockPreauthLegacy})
	if err != nil {
		return nil, false, err
	}
	lines, removedPost, err := stripPAMFaillockBlock(lines, pamFaillockPostBegin, pamFaillockPostEnd,
		[]string{pamFaillockGuardAuthfail, pamFaillockAuthfail, pamFaillockGuardAuthsucc, pamFaillockAuthsucc},
		[]string{pamFaillockAuthfailUnguarded, pamFaillockAuthsuccUnguarded},
		[]string{pamFaillockAuthfailLegacy, pamFaillockAuthsuccLegacy})
	if err != nil {
		return nil, false, err
	}
	removed := removedPre || removedPost
	// The managed pam_unix jump ([success=2]) is not inside a managed
	// block; normalise it back to the stock line before any further
	// processing so removal restores stock bytes and a re-install
	// sees the stock shape. A [success=2] unix line with NO managed
	// block is not ours — but it also is not the stock shape the
	// install path requires, and normalising it here would silently
	// rewrite an admin's line on the enable=false path; only
	// normalise when a managed block was present.
	if removed {
		for i, line := range lines {
			if strings.Join(strings.Fields(line), " ") == pamUnixAuthLineManaged {
				// Restore [success=1] in place, preserving the line's
				// original field spacing (stock uses tabs).
				lines[i] = strings.Replace(line, "[success=2", "[success=1", 1)
			}
		}
	}
	clean := strings.Join(lines, "\n")
	if !enable {
		if !removed {
			return current, false, nil
		}
		return []byte(strings.ReplaceAll(clean, "\n", newline)), true, nil
	}
	if hasActivePAMFaillock(lines) {
		if removed {
			return []byte(strings.ReplaceAll(clean, "\n", newline)), true, nil
		}
		return current, false, nil
	}

	unixAt, denyAt, permitAt, authCount := -1, -1, -1, 0
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "auth" {
			continue
		}
		authCount++
		switch strings.Join(fields, " ") {
		case pamUnixAuthLine:
			unixAt = i
		case pamDenyAuthLine:
			denyAt = i
		case pamPermitAuthLine:
			permitAt = i
		}
	}
	if authCount != 3 || unixAt < 0 || denyAt <= unixAt || permitAt <= denyAt {
		return nil, false, fmt.Errorf("%w: expected stock pam_unix, pam_deny, pam_permit auth sequence", errSSHPAMFaillockUnsupported)
	}

	// Guard placement (see the guard constants): preauth is preceded
	// by GuardPre, authfail by GuardAuthfail, authsucc by GuardPre,
	// and pam_unix is rewritten to [success=2] so its success jump
	// clears both result guards and lands on authsucc.
	pre := []string{pamFaillockPreBegin, pamFaillockGuardPre, pamFaillockPreauth, pamFaillockPreEnd}
	lines = insertPAMLines(lines, unixAt, pre)
	lines[unixAt+len(pre)] = strings.Replace(lines[unixAt+len(pre)], "[success=1", "[success=2", 1)
	post := []string{pamFaillockPostBegin, pamFaillockGuardAuthfail, pamFaillockAuthfail, pamFaillockGuardAuthsucc, pamFaillockAuthsucc, pamFaillockPostEnd}
	lines = insertPAMLines(lines, unixAt+len(pre)+1, post)
	updated := []byte(strings.ReplaceAll(strings.Join(lines, "\n"), "\n", newline))
	if bytes.Equal(updated, current) {
		return current, false, nil
	}
	return updated, true, nil
}

// stripPAMFaillockBlock removes one managed block. bodies lists every
// known-good variant of the block body (current + pre-#14973 legacy);
// any other body is refused as modified, preserving the tamper check.
func stripPAMFaillockBlock(lines []string, begin, end string, bodies ...[]string) ([]string, bool, error) {
	start, finish, starts, ends := -1, -1, 0, 0
	for i, line := range lines {
		switch line {
		case begin:
			start = i
			starts++
		case end:
			finish = i
			ends++
		}
	}
	if starts == 0 && ends == 0 {
		return lines, false, nil
	}
	if starts != 1 || ends != 1 || finish <= start {
		return nil, false, fmt.Errorf("malformed managed PAM faillock block %q", begin)
	}
	matched := false
	for _, body := range bodies {
		want := make([]string, 0, len(body)+2)
		want = append(want, begin)
		want = append(want, body...)
		want = append(want, end)
		if finish-start+1 != len(want) {
			continue
		}
		ok := true
		for i, line := range want {
			if lines[start+i] != line {
				ok = false
				break
			}
		}
		if ok {
			matched = true
			break
		}
	}
	if !matched {
		return nil, false, fmt.Errorf("managed PAM faillock block %q was modified", begin)
	}
	out := make([]string, 0, len(lines)-(finish-start+1))
	out = append(out, lines[:start]...)
	out = append(out, lines[finish+1:]...)
	return out, true, nil
}

// hasActivePAMFaillock reports whether any non-comment PAM line invokes
// pam_faillock.so. Comment lines (first non-blank byte '#') and blank lines
// are ignored: a comment merely mentioning the module (#14973) must not be
// mistaken for an administrator-installed faillock policy.
func hasActivePAMFaillock(lines []string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(line)
		for _, f := range fields[1:] {
			if f == "pam_faillock.so" || strings.HasSuffix(f, "/pam_faillock.so") {
				return true
			}
		}
	}
	return false
}

// setSSHPAMFaillock installs (enable=true) or removes (enable=false) the
// managed faillock rules, mirroring applySSHPAMFaillock's guards. It
// reports whether common-auth was changed and, when it was, the exact
// pre-change bytes so a rollback can restore them. Appliance hosts and
// unsupported stacks report (false, nil, nil) on removal — nothing
// xpf-managed can be present there — and removal still runs for a
// render error's managed blocks via the enable=false render path below.
func setSSHPAMFaillock(enable bool) (bool, []byte, error) {
	if _, err := os.Stat(applianceMarkerFile); err == nil {
		return false, nil, nil
	} else if !os.IsNotExist(err) {
		return false, nil, fmt.Errorf("check appliance marker before PAM update: %w", err)
	}
	if enable && !sshdPAMModuleAvailable() {
		return false, nil, fmt.Errorf("%w: pam_faillock.so is not installed", errSSHPAMFaillockUnsupported)
	}
	current, err := sshdPAMReadFile(sshdPAMCommonAuthPath)
	if err != nil {
		if os.IsNotExist(err) {
			if !enable {
				return false, nil, nil
			}
			return false, nil, fmt.Errorf("%w: %s is absent", errSSHPAMFaillockUnsupported, sshdPAMCommonAuthPath)
		}
		return false, nil, fmt.Errorf("read PAM common-auth stack: %w", err)
	}
	if !enable && !strings.Contains(string(current), pamFaillockPreBegin) && !strings.Contains(string(current), pamFaillockPostBegin) {
		return false, nil, nil
	}
	updated, changed, err := renderSSHPAMFaillock(current, enable)
	if err != nil {
		return false, nil, err
	}
	if !changed {
		return false, nil, nil
	}
	info, err := os.Lstat(sshdPAMCommonAuthPath)
	if err != nil {
		return false, nil, fmt.Errorf("stat PAM common-auth stack: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, nil, fmt.Errorf("%w: %s is not a regular file", errSSHPAMFaillockUnsupported, sshdPAMCommonAuthPath)
	}
	if err := sshdPAMWriteFile(sshdPAMCommonAuthPath, updated, info.Mode().Perm()); err != nil {
		return false, nil, fmt.Errorf("write PAM common-auth stack: %w", err)
	}
	return true, current, nil
}

// restoreSSHPAMFaillockOnRollback undoes a failed applySSHConfig's
// common-auth change (#14973, #16421). When the apply captured the
// pre-apply bytes they are restored verbatim — the same posture as
// revertDropIn for the sshd drop-in — so a host whose legacy managed
// rules were merely upgraded keeps its pre-existing lockout. With no
// captured bytes (nil) it falls back to stripping the managed rules
// this apply installed, which is exactly restore-to-stock when the
// apply started from stock. It is best-effort: failures are logged
// and joined into the apply error by the caller, never masking the
// original failure. It only acts when this apply actually changed
// common-auth, so a pre-existing admin faillock is never removed by
// an unrelated rollback.
func restoreSSHPAMFaillockOnRollback(installed bool, prior []byte) error {
	if !installed {
		return nil
	}
	if prior != nil {
		info, err := os.Lstat(sshdPAMCommonAuthPath)
		if err != nil {
			slog.Warn("failed to stat PAM common-auth stack on SSH apply rollback", "err", err)
			return fmt.Errorf("stat PAM common-auth stack on rollback: %w", err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("restore PAM common-auth stack on rollback: %w: %s is not a regular file", errSSHPAMFaillockUnsupported, sshdPAMCommonAuthPath)
		}
		if err := sshdPAMWriteFile(sshdPAMCommonAuthPath, prior, info.Mode().Perm()); err != nil {
			slog.Warn("failed to restore prior PAM faillock rules on SSH apply rollback", "err", err)
			return fmt.Errorf("restore prior PAM faillock on rollback: %w", err)
		}
		slog.Info("restored prior PAM faillock rules on SSH apply rollback")
		return nil
	}
	changed, _, err := setSSHPAMFaillock(false)
	if err != nil {
		slog.Warn("failed to strip managed PAM faillock rules on SSH apply rollback", "err", err)
		return fmt.Errorf("strip managed PAM faillock on rollback: %w", err)
	}
	if changed {
		slog.Info("stripped managed PAM faillock rules on SSH apply rollback")
	}
	return nil
}

func insertPAMLines(lines []string, at int, insert []string) []string {
	out := make([]string, 0, len(lines)+len(insert))
	out = append(out, lines[:at]...)
	out = append(out, insert...)
	out = append(out, lines[at:]...)
	return out
}
