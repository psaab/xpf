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

	pamFaillockPreauth  = "auth requisite pam_faillock.so preauth silent deny=5 fail_interval=600 unlock_time=300 even_deny_root"
	pamFaillockAuthfail = "auth [default=die] pam_faillock.so authfail deny=5 fail_interval=600 unlock_time=300 even_deny_root"
	pamFaillockAuthsucc = "auth [success=1 default=ignore] pam_faillock.so authsucc deny=5 fail_interval=600 unlock_time=300 even_deny_root"

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

// applySSHPAMFaillock adds an account-wide five-failures/ten-minutes,
// five-minute lockout to Debian's stock common-auth stack. The appliance image
// disables password authentication and owns a separate PAM posture, so this
// host-PAM integration is limited to non-appliance installs. A custom PAM
// stack is left untouched for its administrator to configure explicitly.
func applySSHPAMFaillock() error {
	_, err := applySSHPAMFaillockChanged()
	return err
}

// applySSHPAMFaillockChanged is applySSHPAMFaillock reporting whether it
// changed common-auth, so applySSHConfig can strip exactly the rules this
// apply installed when a later step rolls back (#14973).
func applySSHPAMFaillockChanged() (bool, error) {
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
		[]string{pamFaillockPreauth}, []string{pamFaillockPreauthLegacy})
	if err != nil {
		return nil, false, err
	}
	lines, removedPost, err := stripPAMFaillockBlock(lines, pamFaillockPostBegin, pamFaillockPostEnd,
		[]string{pamFaillockAuthfail, pamFaillockAuthsucc},
		[]string{pamFaillockAuthfailLegacy, pamFaillockAuthsuccLegacy})
	if err != nil {
		return nil, false, err
	}
	removed := removedPre || removedPost
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

	pre := []string{pamFaillockPreBegin, pamFaillockPreauth, pamFaillockPreEnd}
	lines = insertPAMLines(lines, unixAt, pre)
	post := []string{pamFaillockPostBegin, pamFaillockAuthfail, pamFaillockAuthsucc, pamFaillockPostEnd}
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
// managed faillock rules, mirroring applySSHPAMFaillock's guards. It reports
// whether common-auth was changed so a rollback knows the strip took effect.
// Appliance hosts and unsupported stacks report (false, nil) on removal —
// nothing xpf-managed can be present there — and removal still runs for a
// render error's managed blocks via the enable=false render path below.
func setSSHPAMFaillock(enable bool) (bool, error) {
	if _, err := os.Stat(applianceMarkerFile); err == nil {
		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("check appliance marker before PAM update: %w", err)
	}
	if enable && !sshdPAMModuleAvailable() {
		return false, fmt.Errorf("%w: pam_faillock.so is not installed", errSSHPAMFaillockUnsupported)
	}
	current, err := sshdPAMReadFile(sshdPAMCommonAuthPath)
	if err != nil {
		if os.IsNotExist(err) {
			if !enable {
				return false, nil
			}
			return false, fmt.Errorf("%w: %s is absent", errSSHPAMFaillockUnsupported, sshdPAMCommonAuthPath)
		}
		return false, fmt.Errorf("read PAM common-auth stack: %w", err)
	}
	if !enable && !strings.Contains(string(current), pamFaillockPreBegin) && !strings.Contains(string(current), pamFaillockPostBegin) {
		return false, nil
	}
	updated, changed, err := renderSSHPAMFaillock(current, enable)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	info, err := os.Lstat(sshdPAMCommonAuthPath)
	if err != nil {
		return false, fmt.Errorf("stat PAM common-auth stack: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%w: %s is not a regular file", errSSHPAMFaillockUnsupported, sshdPAMCommonAuthPath)
	}
	if err := sshdPAMWriteFile(sshdPAMCommonAuthPath, updated, info.Mode().Perm()); err != nil {
		return false, fmt.Errorf("write PAM common-auth stack: %w", err)
	}
	return true, nil
}

// stripSSHPAMFaillockOnRollback removes the managed faillock rules a failed
// applySSHConfig installed (#14973). It is best-effort: failures are logged
// and joined into the apply error by the caller, never masking the original
// failure. It only strips when this apply actually changed common-auth, so a
// pre-existing admin faillock is never removed by an unrelated rollback.
func stripSSHPAMFaillockOnRollback(installed bool) error {
	if !installed {
		return nil
	}
	changed, err := setSSHPAMFaillock(false)
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
