package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// ownedMarker/ownedAccount/ownedPassword/ownedKey adapt the #6798 (bool, error)
// marker readers for tests that assert ownership in a boolean context.
//
// They deliberately FAIL the test on a read error instead of returning false.
// Every one of these call sites is asserting a DETERMINATION — "the marker is
// genuinely absent" or "the marker is genuinely ours" — and a reader that
// silently reported an unreadable marker as `false` is precisely the collapse
// #6798 closes. A test helper that repeated it would let a fixture whose marker
// root became unreadable pass while proving nothing.
func ownedMarker(t *testing.T, dir, name string, curUID int) bool {
	t.Helper()
	owned, err := readProvenanceMarker(dir, name, curUID)
	if err != nil {
		t.Fatalf("readProvenanceMarker(%s, %s, %d): unexpected read error, so "+
			"this assertion proves nothing: %v", dir, name, curUID, err)
	}
	return owned
}

func ownedAccount(t *testing.T, name string, curUID int) bool {
	t.Helper()
	return ownedMarker(t, provisionedUsersDir, name, curUID)
}

func ownedPassword(t *testing.T, name string, curUID int) bool {
	t.Helper()
	return ownedMarker(t, provisionedPasswordsDir(), name, curUID)
}

func ownedKey(t *testing.T, name string, curUID int) bool {
	t.Helper()
	return ownedMarker(t, provisionedKeysDir(), name, curUID)
}

// TestPasswordAction is the central #1944 safety-invariant table test
// (§7.6): fail-OPEN toward applying a real password, fail-CLOSED (noop) on
// a read error in the lock branch so a transient /etc/shadow read failure
// can never lock out an operator.
func TestPasswordAction(t *testing.T) {
	cases := []struct {
		name    string
		cur     string
		ok      bool
		desired string
		want    pwAction
	}{
		{"set, mismatch -> apply", "$6$old$x", true, "$6$new$y", pwApply},
		{"set, match -> noop", "$6$same$z", true, "$6$same$z", pwNoop},
		{"set, read-fail -> apply (fail-open)", "", false, "$6$new$y", pwApply},
		{"set, missing entry -> apply", "", true, "$6$new$y", pwApply},
		{"empty, passwordless -> lock", "", true, "", pwLock},
		{"empty, usable hash -> lock", "$6$x$y", true, "", pwLock},
		{"empty, locked ! -> noop", "!", true, "", pwNoop},
		{"empty, locked !! -> noop", "!!", true, "", pwNoop},
		{"empty, locked * -> noop", "*", true, "", pwNoop},
		{"empty, locked !hash -> noop", "!$6$x$y", true, "", pwNoop},
		{"empty, read-fail -> noop (no lockout)", "", false, "", pwNoop},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := passwordAction(tc.cur, tc.ok, tc.desired); got != tc.want {
				t.Errorf("passwordAction(%q,%v,%q) = %v, want %v",
					tc.cur, tc.ok, tc.desired, got, tc.want)
			}
		})
	}
}

func TestIsLockedShadow(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false}, // passwordless = most permissive, NOT locked
		{"*", true},
		{"!", true},
		{"!!", true},
		{"!$6$x$y", true},
		{"$6$x$y", false},
	}
	for _, tc := range cases {
		if got := isLockedShadow(tc.in); got != tc.want {
			t.Errorf("isLockedShadow(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestProvenanceMarkerUIDKeyed covers the UID-keyed provenance marker that
// dissolves the leave-rejoin vs out-of-band-recreate tension without any GC
// pass (#1944 §5.4 / §7.9).
func TestProvenanceMarkerUIDKeyed(t *testing.T) {
	dir := t.TempDir()
	old := provisionedUsersDir
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	t.Cleanup(func() { provisionedUsersDir = old })

	// No marker → not provisioned.
	if ownedAccount(t, "op", 1001) {
		t.Error("account marker with no marker = true, want false")
	}

	// markProvisioned then matching UID → provisioned.
	if err := markProvisioned("op", 1001); err != nil {
		t.Fatalf("markProvisioned: %v", err)
	}
	if !ownedAccount(t, "op", 1001) {
		t.Error("account marker for (op,1001) = false after mark, want true")
	}

	// Re-mark with same UID then UID mismatch (out-of-band recreate with a
	// different UID) → not provisioned, and the stale marker is cleaned.
	if err := markProvisioned("op", 1001); err != nil {
		t.Fatalf("markProvisioned: %v", err)
	}
	if ownedAccount(t, "op", 2002) {
		t.Error("account marker for (op,2002) on UID mismatch = true, want false")
	}
	if _, err := os.Stat(markerPath("op")); !os.IsNotExist(err) {
		t.Error("stale marker not removed on UID mismatch")
	}

	// Leave-then-rejoin same account: re-mark, same UID still matches.
	if err := markProvisioned("op", 1001); err != nil {
		t.Fatalf("markProvisioned: %v", err)
	}
	if !ownedAccount(t, "op", 1001) {
		t.Error("account marker for (op,1001) on rejoin = false, want true")
	}

	// Corrupt marker → not provisioned, cleaned.
	if err := os.WriteFile(markerPath("op"), []byte("not-a-number"), 0o600); err != nil {
		t.Fatalf("write corrupt marker: %v", err)
	}
	if ownedAccount(t, "op", 1001) {
		t.Error("account marker with corrupt marker = true, want false")
	}
	if _, err := os.Stat(markerPath("op")); !os.IsNotExist(err) {
		t.Error("corrupt marker not removed")
	}
}

// TestMarkerPathContainment verifies a username can never escape the
// provisioned-users directory (defensive Clean/Base).
func TestMarkerPathContainment(t *testing.T) {
	old := provisionedUsersDir
	provisionedUsersDir = "/var/lib/xpf/provisioned-users"
	t.Cleanup(func() { provisionedUsersDir = old })

	// The first three inputs all end in a real component, so Base(Clean(x))
	// yields "shadow"/"passwd"/"c" and containment holds however it is
	// implemented -- they cannot distinguish a correct implementation from
	// a broken one. The names that clean to a bare traversal element are
	// the ones that actually probe the property this test claims to
	// verify: Base(Clean("..")) is "..", and Join(dir, "..") is dir's
	// PARENT (#7171).
	for _, name := range []string{
		"../../etc/shadow", "/etc/passwd", "a/b/c",
		"..", "../..", "a/../..", ".", "/",
	} {
		got := markerPath(name)
		if dir := filepath.Dir(got); dir != provisionedUsersDir {
			t.Errorf("markerPath(%q) = %q escaped %q", name, got, provisionedUsersDir)
		}
	}
}

// TestCurrentShadowHashParse exercises the real currentShadowHash against a
// sample /etc/shadow via the injectable shadowPath (#1944 §7.8). The
// chpasswd exec itself is integration/live-only.
func TestCurrentShadowHashParse(t *testing.T) {
	dir := t.TempDir()
	shadow := filepath.Join(dir, "shadow")
	content := "root:$6$rootsalt$roothash:19000:0:99999:7:::\n" +
		"op:$6$opsalt$ophash:19000:0:99999:7:::\n" +
		"locked:!:19000:0:99999:7:::\n" +
		"empty::19000:0:99999:7:::\n"
	if err := os.WriteFile(shadow, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := shadowPath
	shadowPath = shadow
	t.Cleanup(func() { shadowPath = old })

	if h, ok := currentShadowHash("op"); !ok || h != "$6$opsalt$ophash" {
		t.Errorf("currentShadowHash(op) = %q,%v", h, ok)
	}
	if h, ok := currentShadowHash("locked"); !ok || h != "!" {
		t.Errorf("currentShadowHash(locked) = %q,%v", h, ok)
	}
	if h, ok := currentShadowHash("empty"); !ok || h != "" {
		t.Errorf("currentShadowHash(empty) = %q,%v", h, ok)
	}
	if _, ok := currentShadowHash("absent"); ok {
		t.Error("currentShadowHash(absent) ok = true, want false")
	}

	// Read error → ("", false).
	shadowPath = filepath.Join(dir, "does-not-exist")
	if _, ok := currentShadowHash("op"); ok {
		t.Error("currentShadowHash with missing file ok = true, want false")
	}
}

// TestReconcileApplyBoundaryRevalidatesHash proves the defense-in-depth
// validation in reconcileUserPassword: lenient Load/SyncApply ingress may
// carry weak or structurally impossible hashes, so the apply boundary must
// reject them. It also proves a zero-exit chpasswd is not treated as success
// until /etc/shadow contains the desired hash.
func TestReconcileApplyBoundaryRevalidatesHash(t *testing.T) {
	dir := t.TempDir()
	shadow := filepath.Join(dir, "shadow")
	if err := os.WriteFile(shadow, []byte("op:$6$old$existinghash:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("op:x:1001:1001:,,,:/home/op:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldShadow, oldPasswd, oldDir := shadowPath, passwdPath, provisionedUsersDir
	shadowPath = shadow
	passwdPath = passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	t.Cleanup(func() { shadowPath, passwdPath, provisionedUsersDir = oldShadow, oldPasswd, oldDir })

	sentinel := filepath.Join(dir, "chpasswd-ran")
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ntouch " + sentinel + "\nIFS=: read -r user hash\n" +
		"if [ \"${CHPASSWD_NO_WRITE:-0}\" != 1 ]; then printf '%s:%s:19000:0:99999:7:::\\n' \"$user\" \"$hash\" > " + shadow + "; fi\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))
	d := &Daemon{}

	for _, invalid := range []string{
		"password12345",
		"$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/",
		"$6$a$b",
	} {
		err := d.reconcileUserPassword(&config.LoginUser{Name: "op", EncryptedPassword: config.Secret(invalid)})
		if err == nil {
			t.Errorf("reconcileUserPassword accepted invalid hash %q, want error", invalid)
		}
		if _, err := os.Stat(sentinel); err == nil {
			t.Fatalf("chpasswd ran for invalid hash %q", invalid)
		}
		if _, err := os.Stat(markerPath("op")); err == nil {
			t.Fatalf("provenance marker written for invalid hash %q", invalid)
		}
	}

	const validHash = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	t.Setenv("CHPASSWD_NO_WRITE", "1")
	if err := d.reconcileUserPassword(&config.LoginUser{Name: "op", EncryptedPassword: validHash}); err == nil {
		t.Fatal("reconcileUserPassword reported success when chpasswd did not update shadow")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatal("chpasswd did NOT run for a valid hash")
	}
	if actual, ok := currentShadowHash("op"); !ok || actual == validHash {
		t.Fatalf("shadow readback = (%q, %t), want old value after fake no-write", actual, ok)
	}

	t.Setenv("CHPASSWD_NO_WRITE", "0")
	if err := d.reconcileUserPassword(&config.LoginUser{Name: "op", EncryptedPassword: validHash}); err != nil {
		t.Fatalf("reconcileUserPassword rejected a valid hash after successful write: %v", err)
	}
	if actual, ok := currentShadowHash("op"); !ok || actual != validHash {
		t.Fatalf("shadow readback = (%q, %t), want desired hash", actual, ok)
	}
}

// TestRootAuthApplyBoundaryRevalidatesHash mirrors the per-user apply-boundary
// checks for root authentication. The lenient ingress can carry an invalid
// value, so applyRootAuth must reject it before `chpasswd -e`.
func TestRootAuthApplyBoundaryRevalidatesHash(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "chpasswd-ran")
	fakeBin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	shadow := filepath.Join(dir, "shadow")
	if err := os.WriteFile(shadow, []byte("root:$6$existing$hash:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ntouch " + sentinel + "\nIFS=: read -r user hash\n" +
		"printf '%s:%s:19000:0:99999:7:::\\n' \"$user\" \"$hash\" > " + shadow + "\n"
	if err := os.WriteFile(filepath.Join(fakeBin, "chpasswd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+":"+os.Getenv("PATH"))

	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origShadow, origPasswd, origDir, origRoot := shadowPath, passwdPath, provisionedUsersDir, rootSSHDir
	shadowPath, passwdPath = shadow, passwd
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	rootSSHDir = filepath.Join(dir, "root-ssh")
	t.Cleanup(func() {
		shadowPath, passwdPath, provisionedUsersDir, rootSSHDir = origShadow, origPasswd, origDir, origRoot
	})
	d := &Daemon{}

	for _, invalid := range []string{
		"password12345",
		"$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/",
		"$6$a$b",
	} {
		cfg := &config.Config{}
		cfg.System.RootAuthentication = &config.RootAuthConfig{EncryptedPassword: config.Secret(invalid)}
		if err := d.applyRootAuth(cfg); err == nil {
			t.Errorf("applyRootAuth accepted invalid root hash %q, want error", invalid)
		}
		if _, err := os.Stat(sentinel); err == nil {
			t.Fatalf("chpasswd ran for invalid root hash %q", invalid)
		}
	}

	const validHash = "$y$j9T$saltsaltsaltsalt$Uxvkjnhdr/2B6SINV1mXACdXVbd5kc899ms5aqhxMQD"
	cfgGood := &config.Config{}
	cfgGood.System.RootAuthentication = &config.RootAuthConfig{EncryptedPassword: validHash}
	if err := d.applyRootAuth(cfgGood); err != nil {
		t.Fatalf("applyRootAuth rejected a valid yescrypt hash: %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatal("chpasswd did NOT run for a valid root hash")
	}
	if actual, ok := currentShadowHash("root"); !ok || actual != validHash {
		t.Fatalf("root shadow readback = (%q, %t), want desired hash", actual, ok)
	}
}

// TestLookupUID exercises the direct /etc/passwd UID parse via the
// injectable passwdPath.
func TestLookupUID(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	content := "root:x:0:0:root:/root:/bin/bash\n" +
		"op:x:1001:1001:,,,:/home/op:/bin/bash\n" +
		"bad:x:notanumber:1002::/home/bad:/bin/bash\n"
	if err := os.WriteFile(passwd, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := passwdPath
	passwdPath = passwd
	t.Cleanup(func() { passwdPath = old })

	if uid, ok := lookupUID("op"); !ok || uid != 1001 {
		t.Errorf("lookupUID(op) = %d,%v, want 1001,true", uid, ok)
	}
	if _, ok := lookupUID("absent"); ok {
		t.Error("lookupUID(absent) ok = true, want false")
	}
	if _, ok := lookupUID("bad"); ok {
		t.Error("lookupUID(bad) ok = true, want false (unparseable uid)")
	}
}

// TestLookupUIDGID exercises the /etc/passwd UID+GID parse (field 2 uid,
// field 3 gid), including a distinct uid/gid pair, an unparseable gid, and
// an absent user.
func TestLookupUIDGID(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	// Distinct uid (1001) and gid (2002) so a uid/gid field swap is caught.
	content := "root:x:0:0:root:/root:/bin/bash\n" +
		"op:x:1001:2002:,,,:/home/op:/bin/bash\n" +
		"baduid:x:notanumber:1002::/home/b:/bin/bash\n" +
		"badgid:x:1003:notanumber::/home/b:/bin/bash\n"
	if err := os.WriteFile(passwd, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := passwdPath
	passwdPath = passwd
	t.Cleanup(func() { passwdPath = old })

	uid, gid, ok := lookupUIDGID("op")
	if !ok || uid != 1001 || gid != 2002 {
		t.Errorf("lookupUIDGID(op) = %d,%d,%v, want 1001,2002,true", uid, gid, ok)
	}
	if u, g, ok := lookupUIDGID("root"); !ok || u != 0 || g != 0 {
		t.Errorf("lookupUIDGID(root) = %d,%d,%v, want 0,0,true", u, g, ok)
	}
	if _, _, ok := lookupUIDGID("absent"); ok {
		t.Error("lookupUIDGID(absent) ok = true, want false")
	}
	if _, _, ok := lookupUIDGID("baduid"); ok {
		t.Error("lookupUIDGID(baduid) ok = true, want false (unparseable uid)")
	}
	if _, _, ok := lookupUIDGID("badgid"); ok {
		t.Error("lookupUIDGID(badgid) ok = true, want false (unparseable gid)")
	}
}
