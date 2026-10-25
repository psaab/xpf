package daemon

import (
	_ "embed"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed testdata/faillock_pamtest_16733.c
var faillockPAMTestC16733 string

// #16733 (R3-A45-01): the #14973 managed faillock lines carried
// even_deny_root in /etc/pam.d/common-auth, which every PAM service
// includes (login, su, sudo, sshd). pam_faillock's tally is per user,
// shared across services, and sshd runs PAM even for root attempts it
// will itself reject (PermitRootLogin != yes) with a substituted fake
// password — so five failed root passwords from any network peer
// locked root out of the local console and `su -` for unlock_time,
// repeatably. The fix guards each managed faillock line to the sshd
// PAM service with pam_succeed_if, keeping the sshd-side lockout
// (root included) while making the tally invisible to — and
// unwritable by — every other service.
//
// These cells render the production stack and execute it with the
// host's real libpam modules (pam_succeed_if / pam_faillock /
// pam_unix / pam_deny / pam_permit) through a small C driver linked
// against libpam, so the guard semantics are exercised, not assumed.

// unguardedCommonAuth16733 reconstructs the pre-#16733 managed stack:
// the current lines without the sshd-only guards.
func unguardedCommonAuth16733(t *testing.T) []byte {
	t.Helper()
	seed := []byte("# Debian pam-auth-update common-auth\n" +
		pamFaillockPreBegin + "\n" + pamFaillockPreauthUnguarded + "\n" + pamFaillockPreEnd + "\n" +
		"auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
		pamFaillockPostBegin + "\n" + pamFaillockAuthfailUnguarded + "\n" + pamFaillockAuthsuccUnguarded + "\n" + pamFaillockPostEnd + "\n" +
		"auth\trequisite\t\t\t\tpam_deny.so\n" +
		"auth\trequired\t\t\t\tpam_permit.so\n")
	return seed
}

// TestRenderSSHPAMFaillockGuardedToSSHD16733 pins the rendered shape:
// three distinct guards (preauth/authfail/authsucc), pam_unix rewritten
// to the managed [success=2] line, each guard immediately before its
// faillock line (authsucc guard before authsucc), and byte-exact
// idempotence/reversibility.
func TestRenderSSHPAMFaillockGuardedToSSHD16733(t *testing.T) {
	got, changed, err := renderSSHPAMFaillock(stockCommonAuth11492(), true)
	if err != nil || !changed {
		t.Fatalf("render: changed=%v err=%v", changed, err)
	}
	text := string(got)
	for _, g := range []string{pamFaillockGuardPre, pamFaillockGuardAuthfail, pamFaillockGuardAuthsucc} {
		if strings.Count(text, g) != 1 {
			t.Fatalf("rendered stack has %d of %q, want 1:\n%s", strings.Count(text, g), g, text)
		}
	}
	if !strings.Contains(text, "[success=2 default=ignore]") || strings.Contains(text, "[success=1 default=ignore]\tpam_unix") {
		t.Fatalf("pam_unix line not rewritten to [success=2]:\n%s", text)
	}
	lines := strings.Split(text, "\n")
	wantOrder := []string{"pam_succeed_if", "pam_faillock.so preauth", "pam_unix.so", "pam_succeed_if", "pam_faillock.so authfail", "pam_succeed_if", "pam_faillock.so authsucc", "pam_deny.so", "pam_permit.so"}
	at := 0
	for _, want := range wantOrder {
		found := false
		for at < len(lines) {
			if strings.Contains(lines[at], want) {
				found = true
				at++
				break
			}
			at++
		}
		if !found {
			t.Fatalf("rendered stack missing %q in order:\n%s", want, text)
		}
	}
	// even_deny_root stays: the sshd-side root lockout is the #14973
	// property being preserved.
	for _, line := range []string{pamFaillockPreauth, pamFaillockAuthfail, pamFaillockAuthsucc} {
		if !strings.Contains(line, "even_deny_root") || !strings.Contains(text, line) {
			t.Fatalf("rendered stack missing guarded line %q:\n%s", line, text)
		}
	}
	// Idempotent and reversible against the guarded body.
	again, changed, err := renderSSHPAMFaillock(got, true)
	if err != nil || changed || string(again) != text {
		t.Fatalf("re-render guarded stack: changed=%v err=%v", changed, err)
	}
	restored, changed, err := renderSSHPAMFaillock(got, false)
	if err != nil || !changed || string(restored) != string(stockCommonAuth11492()) {
		t.Fatalf("strip guarded stack: changed=%v err=%v\n%s", changed, err, restored)
	}
}

// TestRenderSSHPAMFaillockUpgradesUnguardedRules16733 pins the
// migration: a host already carrying the pre-#16733 (unguarded,
// otherwise current) managed blocks is upgraded in place — not
// refused as modified — to byte-identical output as a fresh install.
func TestRenderSSHPAMFaillockUpgradesUnguardedRules16733(t *testing.T) {
	seed := unguardedCommonAuth16733(t)
	got, changed, err := renderSSHPAMFaillock(seed, true)
	if err != nil || !changed {
		t.Fatalf("upgrade unguarded rules: changed=%v err=%v", changed, err)
	}
	fresh, _, err := renderSSHPAMFaillock(stockCommonAuth11492(), true)
	if err != nil || string(got) != string(fresh) {
		t.Fatalf("upgrade != fresh install:\n got:\n%s\nwant:\n%s", got, fresh)
	}
	// Removal strips the unguarded body too (rollback path).
	restored, changed, err := renderSSHPAMFaillock(seed, false)
	if err != nil || !changed || string(restored) != string(stockCommonAuth11492()) {
		t.Fatalf("strip unguarded rules: changed=%v err=%v\n%s", changed, err, restored)
	}
	// A tampered unguarded body (tuned deny= plus a dropped guard)
	// is still refused, not silently stripped or upgraded.
	tampered := strings.Replace(string(seed), "deny=5", "deny=99", 1)
	if _, _, err := renderSSHPAMFaillock([]byte(tampered), true); err == nil {
		t.Fatal("tampered unguarded managed block must be refused")
	}
	tamperedGuard := strings.Replace(string(fresh), "quiet_fail", "quiet_nothing", 1)
	if _, _, err := renderSSHPAMFaillock([]byte(tamperedGuard), true); err == nil {
		t.Fatal("tampered guard line must be refused")
	}
}

// runPAM16733 executes the compiled driver once.
func runPAM16733(t *testing.T, bin, dir, service, user, pass string) string {
	t.Helper()
	cmd := exec.Command(bin, dir, service, user, pass)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		t.Fatalf("pam driver %s/%s: %v\n%s", service, user, err, text)
	}
	return text
}

// runPAMWrong16733 drives one wrong-password attempt. With the
// production stack a wrong password ends in pam_faillock authfail
// ([default=die]) after pam_unix fails; depending on module return
// plumbing the driver prints AUTH_ERR or exits 2 with a non-AUTH_ERR
// PAM code — both prove the failure was recorded (the subsequent
// correct-password refusal is the assertion that matters). A SUCCESS
// here is the only impossible outcome.
func runPAMWrong16733(t *testing.T, bin, dir, service, user string) {
	t.Helper()
	cmd := exec.Command(bin, dir, service, user, "wrongpass16733")
	out, _ := cmd.CombinedOutput()
	if strings.TrimSpace(string(out)) == "SUCCESS" {
		t.Fatalf("pam driver %s/%s wrong password = SUCCESS", service, user)
	}
}

// TestPAMFaillockSSHDOnlyScoping16733 is the executed acceptance cell.
// pam_faillock only tallies users present in passwd and refuses
// (PAM_BUF_ERR) for root when running unprivileged, so the "victim"
// account is the current user (a real passwd entry, tally file owned
// by the test process) and the independent control account is
// nobody (also a real passwd entry). The defect under test is
// service-scoping, not which account: five failed victim attempts
// via the sshd service must lock the victim out of sshd while
// console (login) authentication with the correct password still
// succeeds. The pre-fix (unguarded) stack run through the identical
// sequence denies the console login — the in-cell RED control.
// The stub verifier accepts "correct<user>pw" for the PAM_USER.
func TestPAMFaillockSSHDOnlyScoping16733(t *testing.T) {
	gcc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc not available for PAM harness")
	}
	for _, mod := range []string{"pam_succeed_if.so", "pam_faillock.so", "pam_deny.so", "pam_permit.so"} {
		found := false
		for _, pat := range []string{"/lib/*/security/" + mod, "/usr/lib/*/security/" + mod, "/lib/security/" + mod, "/usr/lib/security/" + mod} {
			if m, _ := filepath.Glob(pat); len(m) > 0 {
				found = true
			}
		}
		if !found {
			t.Skipf("host PAM module %s not available", mod)
		}
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "pamtest16733")
	stub := filepath.Join(tmp, "pam_unix.so")
	src := filepath.Join(tmp, "pamtest16733.c")
	if err := os.WriteFile(src, []byte(faillockPAMTestC16733), 0o644); err != nil {
		t.Fatal(err)
	}
	libpam := ""
	for _, pat := range []string{"/lib/*/libpam.so.0", "/usr/lib/*/libpam.so.0", "/lib/libpam.so.0", "/usr/lib/libpam.so.0"} {
		if m, _ := filepath.Glob(pat); len(m) > 0 {
			libpam = m[0]
		}
	}
	if libpam == "" {
		t.Skip("libpam.so.0 not available")
	}
	if out, err := exec.Command(gcc, "-O2", "-o", bin, src, libpam).CombinedOutput(); err != nil {
		t.Skipf("cannot build PAM driver: %v\n%s", err, out)
	}
	if out, err := exec.Command(gcc, "-O2", "-DSTUB_UNIX", "-shared", "-fPIC", "-o", stub, src).CombinedOutput(); err != nil {
		t.Fatalf("cannot build stub pam_unix: %v\n%s", err, out)
	}

	// Victim = current user (real passwd entry; the tally file is
	// created owned by this process, which pam_faillock requires).
	// Control = nobody (real passwd entry with an independent tally).
	cur, uerr := user.Current()
	if uerr != nil || cur.Username == "" || cur.Username == "nobody" {
		t.Skipf("no usable current passwd user for PAM harness: %v", uerr)
	}
	victim, control := cur.Username, "nobody"
	victimPW, controlPW := "correct"+victim+"pw", "correctnobodypw"

	rendered, changed, err := renderSSHPAMFaillock(stockCommonAuth11492(), true)
	if err != nil || !changed {
		t.Fatalf("render: changed=%v err=%v", changed, err)
	}

	cases := []struct {
		name     string
		stack    []byte
		wantVuln bool // pre-fix control: console root login is denied
	}{
		{name: "guarded-current", stack: rendered, wantVuln: false},
		{name: "unguarded-prefix-control", stack: unguardedCommonAuth16733(t), wantVuln: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(tmp, tc.name)
			if err := os.MkdirAll(filepath.Join(dir, "tally"), 0o755); err != nil {
				t.Fatal(err)
			}
			// Retarget only the tally dir (so the test never touches
			// the host tally) and pam_unix.so (to the stub verifier);
			// every other token — the guard and faillock semantics
			// under test — is the production render.
			stack := strings.ReplaceAll(string(tc.stack),
				"pam_faillock.so ", "pam_faillock.so dir="+filepath.Join(dir, "tally")+" ")
			stack = strings.ReplaceAll(stack, "pam_unix.so", stub)
			for _, svc := range []string{"sshd", "login"} {
				if err := os.WriteFile(filepath.Join(dir, svc),
					[]byte("auth include common-auth16733\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "common-auth16733"), []byte(stack), 0o644); err != nil {
				t.Fatal(err)
			}

			// 5 failed victim attempts via sshd (wrong-password leg;
			// the driver reports it via AUTH_ERR or exit-2, both are
			// a recorded failure — see runPAMWrong16733).
			for range 5 {
				runPAMWrong16733(t, bin, dir, "sshd", victim)
			}
			// sshd now refuses the victim even with the correct
			// password (the preserved #14973 network-side lockout).
			if got := runPAM16733(t, bin, dir, "sshd", victim, victimPW); got != "AUTH_ERR" {
				t.Fatalf("sshd victim correct after 5 sshd failures = %s, want AUTH_ERR (sshd lockout lost)", got)
			}
			// Control tally is independent: nobody is unaffected.
			if got := runPAM16733(t, bin, dir, "sshd", control, controlPW); got != "SUCCESS" {
				t.Fatalf("sshd control correct = %s, want SUCCESS", got)
			}
			// Victim console login: succeeds post-fix, denied pre-fix.
			got := runPAM16733(t, bin, dir, "login", victim, victimPW)
			if tc.wantVuln {
				if got != "AUTH_ERR" {
					t.Fatalf("pre-fix control: login victim correct after sshd failures = %s, want AUTH_ERR (defect not reproduced)", got)
				}
				return
			}
			if got != "SUCCESS" {
				t.Fatalf("login victim correct after 5 sshd failures = %s, want SUCCESS (console lockout, #16733)", got)
			}
			// A correct console login must not clear the sshd tally
			// (authsucc is guarded too): sshd still refuses victim.
			if got := runPAM16733(t, bin, dir, "sshd", victim, victimPW); got != "AUTH_ERR" {
				t.Fatalf("sshd victim correct after console success = %s, want AUTH_ERR (console cleared sshd tally)", got)
			}
			// Control-user sshd lockout still works (positive control).
			for range 5 {
				runPAMWrong16733(t, bin, dir, "sshd", control)
			}
			if got := runPAM16733(t, bin, dir, "sshd", control, controlPW); got != "AUTH_ERR" {
				t.Fatalf("sshd control correct after 5 sshd failures = %s, want AUTH_ERR (control sshd lockout lost)", got)
			}
			if got := runPAM16733(t, bin, dir, "login", control, controlPW); got != "SUCCESS" {
				t.Fatalf("login control correct after sshd failures = %s, want SUCCESS", got)
			}
		})
	}
}
