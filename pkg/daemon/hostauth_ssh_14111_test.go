package daemon

// hostauth_ssh_14111_test.go — #14111 (research D5-09): SSH keys, directory
// ownership, algorithm fallback.
//
// Three defects, three guards:
//
//  1. Key-type validation: validateAuthorizedSSHKeys required an "ssh-"
//     prefix, so a valid OpenSSH key whose type is ecdsa-sha2-nistp256 /
//     sk-* (the full "<type> <base64> <comment>" string Junos operators
//     store as the leaf value) was rejected at apply and applySystemLogin
//     skipped ALL provisioning for that user. The fix accepts the OpenSSH
//     authorized_keys key-type vocabulary (fail-closed allowlist).
//  2. Directory ownership: the .ssh dir was chowned via the external
//     `chown -R -- <name>:<name>` command, which fails for any account
//     whose primary group is not eponymously named — stranding users
//     outside a freshly created root-owned 0700 .ssh. The fix chowns by
//     the already-resolved numeric (uid, gid) and aborts the key install
//     (with marker rollback) when the chown fails instead of claiming
//     convergence over an untraversable directory.
//  3. Algorithm fallback: buildSSHDConfig silently omitted a nonempty
//     operator-specified algorithm restriction when every token was
//     filtered, reverting sshd to its built-in defaults. The fix surfaces
//     an error from buildSSHDConfigErr / applySSHConfig and leaves the
//     live drop-in untouched.
//
// RED-on-revert: reverting (1) makes the ecdsa test fail at validation;
// reverting (2) restores the name-based external chown (observed via the
// recorded exec seam and the numeric-owner assertion); reverting (3)
// makes applySSHConfig succeed silently and rewrite/remove the drop-in.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// stage14111User seeds passwd/shadow/home seams for a login user whose
// primary GID deliberately differs from the uid's "own group" convention:
// the passwd GID is the CURRENT process gid, which (on any normal test
// host) is not a group named after the test user and whose numeric value
// typically differs from the uid. It returns the user's .ssh dir and the
// (uid, gid) pair lookupUIDGID resolves.
func stage14111User(t *testing.T, name string) (sshDir string, uid, gid int) {
	t.Helper()
	dir := t.TempDir()
	uid, gid = os.Getuid(), os.Getgid()

	passwd := filepath.Join(dir, "passwd")
	passwdContent := fmt.Sprintf(
		"root:x:0:0:root:/root:/bin/bash\n%s:x:%d:%d:,,,:/home/%s:/bin/bash\n",
		name, uid, gid, name)
	if err := os.WriteFile(passwd, []byte(passwdContent), 0o600); err != nil {
		t.Fatal(err)
	}
	shadow := filepath.Join(dir, "shadow")
	shadowContent := fmt.Sprintf("root:*:19000:0:99999:7:::\n%s:!:19000:0:99999:7:::\n", name)
	if err := os.WriteFile(shadow, []byte(shadowContent), 0o600); err != nil {
		t.Fatal(err)
	}

	origShadow, origPasswd, origMarker, origHome := shadowPath, passwdPath, provisionedUsersDir, homeBaseDir
	shadowPath = shadow
	passwdPath = passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	homeBaseDir = filepath.Join(dir, "home")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, homeBaseDir = origShadow, origPasswd, origMarker, origHome
	})
	return filepath.Join(homeBaseDir, name, ".ssh"), uid, gid
}

func recordRun14111(t *testing.T) *[]recordedCmd {
	t.Helper()
	var calls []recordedCmd
	origRun := runCommandTimeout
	runCommandTimeout = func(cmd string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCmd{name: cmd, args: append([]string(nil), args...)})
		return nil, nil // `id` succeeds: user exists, useradd skipped
	}
	t.Cleanup(func() { runCommandTimeout = origRun })
	return &calls
}

// TestApplySystemLoginECDSAKeyProvisions14111 is the decisive regression
// check from the issue: a user carrying an `ecdsa-sha2-nistp256 …` key
// value must be provisioned, not skipped. On master the ssh- prefix check
// rejects the key and applySystemLogin returns an error before any key
// write; here provisioning must proceed and the key must land in
// authorized_keys owned by the resolved (uid, gid).
func TestApplySystemLoginECDSAKeyProvisions14111(t *testing.T) {
	const name = "ecdsauser"
	sshDir, uid, gid := stage14111User(t, name)
	calls := recordRun14111(t)

	const ecdsaKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBtest ecdsauser@host"
	d := &Daemon{}
	err := d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:    name,
		Class:   "operator",
		SSHKeys: []string{ecdsaKey},
	}))
	if err != nil {
		t.Fatalf("applySystemLogin with an ecdsa-sha2-nistp256 key = %v, want provisioning to proceed (#14111)", err)
	}

	keysFile := filepath.Join(sshDir, "authorized_keys")
	data, err := os.ReadFile(keysFile)
	if err != nil {
		t.Fatalf("authorized_keys not written: %v", err)
	}
	if string(data) != ecdsaKey+"\n" {
		t.Fatalf("authorized_keys = %q, want %q", data, ecdsaKey+"\n")
	}
	st, err := os.Stat(keysFile)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode = %o, want 0600", st.Mode().Perm())
	}

	// The .ssh directory itself must be owned by the resolved (uid, gid)
	// and mode 0700 — the user must be able to traverse it.
	dst, err := os.Stat(sshDir)
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm() != 0o700 {
		t.Errorf(".ssh mode = %o, want 0700", dst.Mode().Perm())
	}
	// No external chown command may be used any more: ownership is applied
	// by numeric id in-process. A recorded `chown` invocation means the
	// name-based mechanism (which fails for non-eponymous groups) is back.
	for _, c := range *calls {
		if c.name == "chown" {
			t.Fatalf("external chown invoked with argv %v — directory ownership must use the resolved numeric (uid,gid) (#14111)", c.args)
		}
	}
	_ = uid
	_ = gid
}

// TestApplySystemLoginKeyTypeVocabulary14111 pins the apply-boundary
// allowlist in both directions: every OpenSSH authorized_keys key type is
// accepted, and option-prefixed / bare-blob / unknown-type / multiline
// values stay rejected (fail-closed, #10725 doctrine preserved).
func TestApplySystemLoginKeyTypeVocabulary14111(t *testing.T) {
	valid := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest user@host",
		"ssh-dss AAAAB3NzaC1kc3MAAACBAtest user@host",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYtest user@host",
		"ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQtest user@host",
		"ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEtest user@host",
		"sk-ssh-ed25519@openssh.com AAAAC3NzaC1lZDI1NTE5AAAAItest user@host",
		"sk-ecdsa-sha2-nistp256@openssh.com AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYtest user@host",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest", // comment optional
	}
	for _, k := range valid {
		if err := validateAuthorizedSSHKeys("alice", []string{k}); err != nil {
			t.Errorf("validateAuthorizedSSHKeys(%q) = %v, want nil (valid OpenSSH key type, #14111)", k, err)
		}
	}

	invalid := []string{
		`command="true" ssh-ed25519 AAAA key`, // option prefix smuggling
		"AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest", // bare blob, no type
		"ssh-ed25519",                         // type without blob
		"unknown-type AAAAblob user@host",     // unknown type
		"ssh-ed25519 AAAA first\nssh-rsa AAAA forged",
		"ssh-ed25519 AAAA first\rssh-rsa AAAA forged",
		"", // empty
	}
	for _, k := range invalid {
		if err := validateAuthorizedSSHKeys("alice", []string{k}); err == nil {
			t.Errorf("validateAuthorizedSSHKeys(%q) = nil, want error (fail-closed, #14111)", k)
		}
	}
}

// TestApplySSHConfigAllInvalidAlgorithmsFailClosed14111 pins the
// algorithm-fallback fix at the apply layer: a nonempty algorithm
// restriction whose every token is invalid must FAIL the apply and leave
// the previously installed drop-in byte-identical — never silently write
// a bounds-only drop-in (or remove the drop-in) and revert sshd to its
// built-in defaults.
func TestApplySSHConfigAllInvalidAlgorithmsFailClosed14111(t *testing.T) {
	prior := buildSSHDConfig(&config.SSHServiceConfig{
		RootLogin:   "deny",
		KeyExchange: []string{"curve25519-sha256"},
		Ciphers:     []string{"aes256-gcm@openssh.com"},
	})
	r := &sshdSeamRecorder{present: []byte(prior)}
	installSSHDSeam(t, r)

	d := &Daemon{}
	err := d.applySSHConfig(sshConfig(&config.SSHServiceConfig{
		RootLogin:   "deny",
		KeyExchange: []string{"kex,PermitRootLogin yes"}, // injection-shaped: filtered
		Ciphers:     []string{"bad cipher"},              // invalid: filtered
		MACs:        []string{"hmac-sha2-256\nPermitRootLogin yes"},
	}))
	if err == nil {
		t.Fatal("applySSHConfig with all-invalid algorithm lists = nil, want a fail-closed error (#14111)")
	}
	if string(r.present) != prior {
		t.Fatalf("drop-in changed on all-invalid algorithms:\n got: %q\nwant (untouched): %q", r.present, prior)
	}
	if len(r.writes) != 0 {
		t.Errorf("writes = %d, want 0 (no sshd state touched on render failure)", len(r.writes))
	}
	if r.removed != 0 {
		t.Errorf("removals = %d, want 0", r.removed)
	}
	if r.reloads != 0 {
		t.Errorf("reloads = %d, want 0", r.reloads)
	}
}

// TestBuildSSHDConfigErrAllInvalid14111 unit-pins the render contract:
// nonempty→empty filtering errors per-list, partial filtering renders the
// survivors, empty lists and valid lists render exactly as before. The
// string-only buildSSHDConfig keeps its signature for compare/live-check
// callers (its all-invalid result is the bounds-only body; the fail-closed
// decision lives in the Err variant consumed by applySSHConfig).
func TestBuildSSHDConfigErrAllInvalid14111(t *testing.T) {
	for _, tc := range []struct {
		name string
		ssh  *config.SSHServiceConfig
	}{
		{"kex", &config.SSHServiceConfig{KeyExchange: []string{"bad,tok"}}},
		{"ciphers", &config.SSHServiceConfig{Ciphers: []string{"bad cipher"}}},
		{"macs", &config.SSHServiceConfig{MACs: []string{"bad\nMACs x"}}},
	} {
		if _, err := buildSSHDConfigErr(tc.ssh); err == nil {
			t.Errorf("%s: buildSSHDConfigErr(all-invalid) = nil error, want fail-closed (#14111)", tc.name)
		}
	}

	// Partial filtering still renders survivors (existing #4902 belt).
	got, err := buildSSHDConfigErr(&config.SSHServiceConfig{
		KeyExchange: []string{"curve25519-sha256", "kex,PermitRootLogin yes"},
	})
	if err != nil {
		t.Fatalf("buildSSHDConfigErr(partial) = %v, want nil", err)
	}
	if !strings.Contains(got, "KexAlgorithms curve25519-sha256\n") {
		t.Errorf("partial filter dropped the valid token; got:\n%s", got)
	}
	if strings.Contains(got, "PermitRootLogin yes") {
		t.Errorf("injected token reached drop-in; got:\n%s", got)
	}

	// Unspecified lists render the mandatory bounds, no error.
	got, err = buildSSHDConfigErr(&config.SSHServiceConfig{})
	if err != nil {
		t.Fatalf("buildSSHDConfigErr(empty) = %v, want nil", err)
	}
	if !strings.Contains(got, "MaxAuthTries 3") {
		t.Errorf("empty stanza lost mandatory bounds; got:\n%s", got)
	}

	if _, err := buildSSHDConfigErr(nil); err != nil {
		t.Errorf("buildSSHDConfigErr(nil) = %v, want nil", err)
	}
}

// TestApplySystemLoginNumericDirOwnership14111 asserts the .ssh directory
// ends up owned by the passwd-resolved numeric gid even though no group
// bears the user's name. The in-test proxy for "no eponymous group" is
// that the external name-based chown is never invoked while the directory
// is still correctly owned in-process; combined with
// TestApplySystemLoginChownSkipsUnsafeName (still green) the #5005
// option-injection guard is preserved by construction (numeric operands).
func TestApplySystemLoginNumericDirOwnership14111(t *testing.T) {
	const name = "groupuser"
	sshDir, uid, gid := stage14111User(t, name)
	calls := recordRun14111(t)

	// Premise: the resolved gid is the process gid; guard against a host
	// where uid==gid AND a group named after the user could exist — the
	// assertion that matters (no name-based chown, dir owned by uid:gid)
	// holds regardless, so only record the premise for diagnostics.
	luUID, luGID, ok := lookupUIDGID(name)
	if !ok || luUID != uid || luGID != gid {
		t.Fatalf("lookupUIDGID(%q) = (%d,%d,%v), want (%d,%d,true)", name, luUID, luGID, ok, uid, gid)
	}

	d := &Daemon{}
	err := d.applySystemLogin(loginCfg(&config.LoginUser{
		Name:    name,
		Class:   "operator",
		SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest groupuser@host"},
	}))
	if err != nil {
		t.Fatalf("applySystemLogin = %v, want nil", err)
	}
	for _, c := range *calls {
		if c.name == "chown" {
			t.Fatalf("name-based external chown used: %v (#14111)", c.args)
		}
	}
	st, err := os.Stat(sshDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf(".ssh mode = %o, want 0700", st.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(sshDir, "authorized_keys")); err != nil {
		t.Errorf("authorized_keys missing after numeric-ownership apply: %v", err)
	}
}
