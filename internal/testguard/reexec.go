package testguard

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// RequireNetnsEnv is set (to any value) by scripts/testguard-run.sh. Inside
// its private namespaces a test can always create a further network
// namespace, so there a namespace that could not be created is a defect to
// report, not an environment to skip (#19066).
const RequireNetnsEnv = "XPF_REQUIRE_NETNS"

// UnshareFlags returns the `unshare` flag words for a test that re-executes
// its own test binary (or anything that runs a guarded test binary) in a new
// namespace (#19066).
//
// Pass the flags the test would use as an unprivileged caller, e.g.
// UnshareFlags("-rn") or UnshareFlags("-Urnm", "--propagation", "private").
// A non-root caller gets them unchanged. It needs the user namespace to gain
// the privilege for the others.
//
// A caller that is already uid 0 gets them with the user-namespace flags
// removed: the letters U, r and c from a short cluster, and --user,
// --map-root-user and --map-current-user. Such a caller is the Go suite
// under scripts/testguard-run.sh (uid 0 in a user namespace) or real root on
// a VM leg. The reason: the child is a guarded package's test binary, and
// its TestMain runs ExitIfUnsafe, which reads /proc/1/ns/{net,mnt}. A NESTED
// user namespace's root has no ptrace access to PID 1, which lives in the
// parent user namespace, so that read fails with EACCES and the guard
// refuses the child. Measured at master b8bd60dc61: 27 of 42 re-exec cells
// were refused this way, 10 of them skipping as "netns unavailable" on
// every run. Without the nested user namespace the child stays in the
// caller's, can read PID 1's links, and passes the guard, because the
// namespaces it asked for are new.
func UnshareFlags(flags ...string) []string {
	if os.Geteuid() != 0 {
		return append([]string(nil), flags...)
	}
	return stripUserNamespaceFlags(flags)
}

// unshareNoArgShortFlags are unshare(1)'s short options that take no
// argument. Only a cluster made of these is rewritten: in any other cluster a
// letter may be an attached argument ("-w/srv/run"), and stripping U or r
// there would corrupt it (R18 N2 on #19066).
const unshareNoArgShortFlags = "mUinpuCTrcf"

// stripUserNamespaceFlags is UnshareFlags' uid-0 rewrite, separated so it is
// testable without being root.
func stripUserNamespaceFlags(flags []string) []string {
	out := make([]string, 0, len(flags))
	for _, f := range flags {
		switch {
		case f == "--user" || f == "--map-root-user" || f == "--map-current-user":
			continue
		case strings.HasPrefix(f, "--user=") || strings.HasPrefix(f, "--map-"):
			continue
		case len(f) > 1 && f[0] == '-' && f[1] != '-' &&
			strings.Trim(f[1:], unshareNoArgShortFlags) == "":
			// c is --map-current-user, which implies --user like r does
			// (#19066 Codex F4).
			kept := strings.Map(func(r rune) rune {
				if r == 'U' || r == 'r' || r == 'c' {
					return -1
				}
				return r
			}, f[1:])
			if kept == "" {
				continue
			}
			out = append(out, "-"+kept)
		default:
			out = append(out, f)
		}
	}
	return out
}

// NetnsUnavailable reports that a test could not get the namespace it
// needs (unshare missing, the re-executed child never started, a namespace
// operation refused). Under RequireNetnsEnv, which testguard-run.sh sets, it
// FAILS the test. Otherwise it skips (#19066).
//
// A skip there is not an environment property. Inside testguard a namespace
// is always creatable, so a skip means the cell's own mechanism is broken,
// and a skip reads as "nothing to see" on every run. That is how the 10
// silently skipping re-exec cells of #19066 went unnoticed.
func NetnsUnavailable(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv(RequireNetnsEnv) != "" {
		t.Fatalf("namespace required ("+RequireNetnsEnv+" is set, as scripts/testguard-run.sh does) but unavailable: "+format, args...)
		return // a real testing.T never returns from Fatalf; a recording TB does
	}
	t.Skipf(format, args...)
}

// ReexecCommand is exec.CommandContext for a re-executed child, with a
// deadline of its own (R18 N1 on #19066). A test binary run directly has no
// default -test.timeout, so a hung child would block the parent's
// CombinedOutput until the package -timeout panicked the whole package, with
// no trace of which child hung.
//
// With a parent deadline, the child gets the parent's remaining budget minus
// a cleanup margin: reexecMargin, or a quarter of the remaining budget when
// that is shorter, so a short budget still leaves the child three quarters of
// it (Codex F2). Only without a parent deadline does reexecDefault apply.
// WaitDelay keeps a killed child's inherited pipes from holding the parent.
// The kill is announced on the parent's stderr, so a harness-budget
// exhaustion is not mistaken for a product failure; it surfaces as a nonzero
// exit that RequireChildPass reports.
func ReexecCommand(t testing.TB, name string, args ...string) *exec.Cmd {
	t.Helper()
	deadline := reexecDeadline(t, time.Now())
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 5 * time.Second
	testName := t.Name()
	cmd.Cancel = func() error {
		fmt.Fprintf(os.Stderr, "testguard: %s: re-executed child killed at its harness deadline %s (testguard.ReexecCommand)\n",
			testName, deadline.Format(time.RFC3339))
		return cmd.Process.Kill()
	}
	return cmd
}

// reexecDeadline is ReexecCommand's deadline policy, separated for testing.
func reexecDeadline(t testing.TB, now time.Time) time.Time {
	if d, ok := t.(interface{ Deadline() (time.Time, bool) }); ok {
		if pd, ok := d.Deadline(); ok {
			margin := reexecMargin
			if remaining := pd.Sub(now); remaining/4 < margin {
				margin = remaining / 4
			}
			return pd.Add(-margin)
		}
	}
	return now.Add(reexecDefault)
}

const (
	reexecDefault = 10 * time.Minute
	reexecMargin  = 30 * time.Second
)

// ChildVerdict is how RequireChildPass reads a re-executed child.
type ChildVerdict int

const (
	ChildFailed ChildVerdict = iota
	ChildPassed
	ChildSkipped
)

var childLogLine = regexp.MustCompile(`(?m)^\s+\S+_test\.go:\d+: (.*)$`)

// JudgeChild reads a re-executed child's -test.v output for the test name.
// Its exit status cannot judge it: Go exits 0 for a test that SKIPs and for
// a -test.run pattern that matches nothing ("testing: warning: no tests to
// run"), so a parent that trusted the status reported PASS having examined
// nothing (#19058 R16 F1; #19066 R2 F1).
//
// A result record for the exact name ("--- PASS|SKIP|FAIL: <name> (" at
// column 0) decides first. FAIL is a failure. SKIP with a zero exit is a skip
// carrying the child's reason; SKIP with a nonzero exit is a crash after the
// skip, a failure. PASS with a zero exit is the only pass. Only with NO
// record does the pre-start refusal exception apply: an unshare that failed
// before the child test started (no "=== RUN" line, a nonzero exit, and
// unshare's refusal text) is a skip. Everything else is a failure, including
// an EPERM from inside a child that did start, which is the acceptance
// failing, not the namespace being unavailable. Output is CRLF-normalized
// first, so a CRLF "=== RUN" line still reads as started (#19058 Codex F1).
//
// This is a presence and precedence check over the records, not a validator
// of a whole transcript: a duplicated PASS, a PASS beside a SKIP, or a line
// truncated right after " (" are decided only by the precedence above.
func JudgeChild(name string, out []byte, runErr error) (ChildVerdict, string) {
	s := strings.ReplaceAll(string(out), "\r\n", "\n")
	line := func(kind string) bool {
		return regexp.MustCompile(`(?m)^--- ` + kind + `: ` + regexp.QuoteMeta(name) + ` \(`).MatchString(s)
	}
	started := strings.Contains(s, "=== RUN   "+name+"\n")
	passed, skipped, failed := line("PASS"), line("SKIP"), line("FAIL")
	record := passed || skipped || failed
	switch {
	case failed:
		return ChildFailed, fmt.Sprintf("the child reported FAIL (exit: %v)", runErr)
	case skipped && runErr != nil:
		return ChildFailed, fmt.Sprintf("the child skipped and then exited nonzero (exit: %v)", runErr)
	case skipped:
		reason := "the child skipped"
		if m := childLogLine.FindAllStringSubmatch(s, -1); len(m) > 0 {
			reason += ": " + m[len(m)-1][1]
		}
		return ChildSkipped, reason
	case passed && runErr == nil:
		return ChildPassed, ""
	case !record && !started && runErr != nil &&
		(strings.Contains(s, "Operation not permitted") || strings.Contains(s, "unshare:")):
		return ChildSkipped, fmt.Sprintf("cannot create private namespace: %v: %s", runErr, strings.TrimSpace(s))
	}
	return ChildFailed, fmt.Sprintf("the child did not report \"--- PASS: %s\" (exit: %v)", name, runErr)
}

// RequireChildPass judges a re-executed child (run with -test.v) and acts on
// the verdict: a PASS returns, a SKIP goes through NetnsUnavailable (a FAIL
// under RequireNetnsEnv), and anything else FAILS the test with the reason.
func RequireChildPass(t testing.TB, name string, out []byte, runErr error) {
	t.Helper()
	switch verdict, reason := JudgeChild(name, out, runErr); verdict {
	case ChildPassed:
	case ChildSkipped:
		NetnsUnavailable(t, "%s: %s", name, reason)
	default:
		t.Fatalf("%s: re-executed child failed: %s", name, reason)
	}
}
