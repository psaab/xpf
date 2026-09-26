//go:build functional1944

// This functional test proves the #1944 encrypted-password lifecycle
// against a REAL /etc/shadow + chpasswd. It is build-tagged so it never
// runs in the normal `go test ./...` gate; run it as root inside a
// throwaway container:
//
//	go test -tags functional1944 -run TestFunctional1944 -v ./pkg/daemon/
//
// It exercises the actual production code paths: passwordAction +
// currentShadowHash + chpasswd -e (apply, idempotent skip, D2 lock) and
// the UID-keyed provenance marker.
package daemon

import (
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestFunctional1944(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("must run as root against a real /etc/shadow")
	}
	d := &Daemon{}
	const name = "op1944"
	// A known $6$ hash for the password "test123".
	const hash = "$6$xpf1944salt$s8d7fYE06wZEyLJfvxc/JummvisDB5xVgxwC/uULzXz0a25H/ywrHJM4m6XKDJ2nEyW58IhFaXabC3PrR689K."

	t.Cleanup(func() {
		runCommandTimeout("userdel", "-r", name)
		os.Remove(markerPath(name))
	})

	// Build the user struct the daemon would compile from config.
	user := &config.LoginUser{Name: name, Class: "operator", EncryptedPassword: hash}

	// This password-only fixture intentionally uses bash so `su -c true` can
	// verify PAM without requiring a running CLI daemon. It does not exercise
	// applySystemLogin's class-aware OS-shell policy.
	if out, err := runCommandTimeout("useradd", "-m", "-s", "/bin/bash", name); err != nil {
		t.Fatalf("useradd: %v / %s", err, out)
	}
	if uid, ok := lookupUID(name); ok {
		if err := markProvisioned(name, uid); err != nil {
			t.Fatalf("markProvisioned: %v", err)
		}
	} else {
		t.Fatal("lookupUID failed right after useradd")
	}

	d.reconcileUserPassword(user)

	cur, ok := currentShadowHash(name)
	if !ok || cur != hash {
		t.Fatalf("(a) after apply: shadow field = %q ok=%v, want the hash", cur, ok)
	}
	t.Logf("(a) PASS: shadow field for %s equals the configured hash", name)

	// Prove authentication actually works with the cleartext password via
	// `su`. `su -c true` runs a PAM auth; pipe the password on stdin.
	if !suAuthSucceeds(t, name, "test123") {
		t.Fatal("(a) su auth with correct password failed")
	}
	t.Logf("(a) PASS: %s authenticates with the cleartext password", name)

	// (d) Idempotent re-commit: same hash, must NOT churn. We assert the
	// decision helper returns pwNoop given the now-on-disk hash.
	if act := passwordAction(cur, ok, hash); act != pwNoop {
		t.Fatalf("(d) idempotent re-commit decision = %v, want pwNoop", act)
	}
	t.Logf("(d) PASS: unchanged re-commit is a noop (no chpasswd churn)")

	// (b) Remove the directive → D2 lock (not orphan). The marker UID
	// matches the current account, so reconcileUserPassword must lock.
	user.EncryptedPassword = ""
	d.reconcileUserPassword(user)
	cur, ok = currentShadowHash(name)
	if !ok {
		t.Fatal("(b) could not read shadow after lock")
	}
	if cur == hash {
		t.Fatal("(b) FAIL: password is still the orphaned hash — D2 did not lock")
	}
	if !isLockedShadow(cur) {
		t.Fatalf("(b) FAIL: shadow field %q is not a lock sentinel", cur)
	}
	t.Logf("(b) PASS: directive removal locked %s (shadow=%q), hash not orphaned", name, cur)

	// Locked account must NOT authenticate with the old password.
	if suAuthSucceeds(t, name, "test123") {
		t.Fatal("(b) FAIL: locked account still authenticates")
	}
	t.Logf("(b) PASS: locked account rejects the old password")
}

// suAuthSucceeds runs `su <name> -c true` feeding password on stdin and
// reports whether PAM authentication succeeded.
func suAuthSucceeds(t *testing.T, name, password string) bool {
	t.Helper()
	// Use `su` with the target user; it prompts for the target's password
	// when invoked by root? No — root's su does not prompt. Use `runuser`
	// equivalence is not an auth test. Instead test PAM directly via
	// `chage`-free path: spawn `su` as nobody is complex; rely on a small
	// expect-free approach: `echo pw | su name -c true` only prompts when
	// the caller is not root. So drop privileges via `setpriv` to a
	// non-root uid first.
	out, err := runCommandStdinTimeout(
		strings.NewReader(password+"\n"),
		"setpriv", "--reuid", "65534", "--regid", "65534", "--clear-groups",
		"sh", "-c", "su "+name+" -c true",
	)
	if err != nil {
		t.Logf("su auth attempt: err=%v out=%s", err, strings.TrimSpace(string(out)))
		return false
	}
	return true
}
