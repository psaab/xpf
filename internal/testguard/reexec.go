package testguard

import (
	"os"
	"strings"
	"testing"
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
// removed: the letters U and r from a short cluster, and --user,
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
		case len(f) > 1 && f[0] == '-' && f[1] != '-':
			kept := strings.Map(func(r rune) rune {
				if r == 'U' || r == 'r' {
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
