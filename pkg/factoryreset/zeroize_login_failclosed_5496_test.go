package factoryreset

import (
	"os"
	"path/filepath"
	"testing"
)

// #5496: the login-account teardown resolves account ownership from TWO reads —
// the live UID (/etc/passwd) and the recorded UID (provenance marker). If either
// read/parse FAILS, ownership is UNKNOWN, not proven-absent. The prior code
// collapsed "unreadable / malformed" into the same (0,false) as "genuinely
// absent" (and folded an unreadable marker into the stale-marker branch), so an
// unresolved read looked like proof the account was gone: the wipe erased the
// only provenance marker and reported a CLEAN reset (firstErr stayed nil) while
// a live xpf-provisioned PASSWORD account survived — now un-rediscoverable
// because its retry marker was destroyed. These tests pin the fail-CLOSED
// contract: on uncertainty, surface an error, RETAIN the marker, make no
// destructive account change.
//
// RED on revert (all four uncertainty tests): before the fix,
// wipeLoginAccounts returns nil AND removes the marker in each case below, so
// the `err == nil` and `assertPresent(marker)` assertions both fail.

// TestZeroizeLoginUnreadablePasswdFailsClosed: /etc/passwd cannot be read (here a
// directory stands in, which os.ReadFile fails on regardless of euid). The
// account may still exist with a live credential, so the reset must fail closed.
func TestZeroizeLoginUnreadablePasswdFailsClosed(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	// Make /etc/passwd unreadable: a directory at the path → os.ReadFile errors
	// (EISDIR) even when the test runs as root, so the RED path is deterministic.
	if err := os.MkdirAll(passwdPath, 0o755); err != nil {
		t.Fatalf("mkdir passwd dir: %v", err)
	}
	carolMarker := filepath.Join(provDir, "carol")
	mustWriteFile(t, carolMarker, []byte("1700"))
	carolKeys := filepath.Join(homeBase, "carol", ".ssh", "authorized_keys")
	mustWriteFile(t, carolKeys, []byte("ssh-ed25519 AAAAcarol carol\n"))

	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := wipeLoginAccounts(); err == nil {
		t.Fatalf("wipeLoginAccounts with an UNREADABLE /etc/passwd returned nil; want fail-closed error")
	}
	if len(*deleted) != 0 {
		t.Errorf("userdel invoked %v on an unresolved /etc/passwd; want none (no destructive change)", *deleted)
	}
	assertPresent(t, carolMarker) // RETAINED for a safe retry
}

// TestZeroizeLoginMalformedPasswdUIDFailsClosed: the account's /etc/passwd line
// is present but its UID field is non-numeric. The account EXISTS (the line is
// there) but its UID cannot be resolved → uncertainty, not absence.
func TestZeroizeLoginMalformedPasswdUIDFailsClosed(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	mustWriteFile(t, passwdPath, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"carol:x:notanumber:1700:carol:/home/carol:/bin/bash\n"))
	carolMarker := filepath.Join(provDir, "carol")
	mustWriteFile(t, carolMarker, []byte("1700"))
	carolKeys := filepath.Join(homeBase, "carol", ".ssh", "authorized_keys")
	mustWriteFile(t, carolKeys, []byte("ssh-ed25519 AAAAcarol carol\n"))

	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := wipeLoginAccounts(); err == nil {
		t.Fatalf("wipeLoginAccounts with a MALFORMED passwd UID returned nil; want fail-closed error")
	}
	if len(*deleted) != 0 {
		t.Errorf("userdel invoked %v on a malformed passwd UID; want none", *deleted)
	}
	assertPresent(t, carolMarker) // RETAINED
	assertPresent(t, carolKeys)   // no destructive change on uncertainty
}

// TestZeroizeLoginUnparseableMarkerFailsClosed: /etc/passwd is fine and the
// account exists, but the provenance marker's content is not a UID. We cannot
// resolve OUR recorded UID → cannot decide if the live account is ours → fail
// closed rather than silently drop the marker.
func TestZeroizeLoginUnparseableMarkerFailsClosed(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	mustWriteFile(t, passwdPath, []byte("carol:x:1700:1700:carol:/home/carol:/bin/bash\n"))
	carolMarker := filepath.Join(provDir, "carol")
	mustWriteFile(t, carolMarker, []byte("not-a-uid\n")) // unparseable content
	carolKeys := filepath.Join(homeBase, "carol", ".ssh", "authorized_keys")
	mustWriteFile(t, carolKeys, []byte("ssh-ed25519 AAAAcarol carol\n"))

	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := wipeLoginAccounts(); err == nil {
		t.Fatalf("wipeLoginAccounts with an UNPARSEABLE marker returned nil; want fail-closed error")
	}
	if len(*deleted) != 0 {
		t.Errorf("userdel invoked %v on an unparseable marker; want none", *deleted)
	}
	assertPresent(t, carolMarker) // RETAINED
	assertPresent(t, carolKeys)   // no destructive change on uncertainty
}

// TestZeroizeLoginUIDMismatchReportedNonDestructive: a PROVEN UID-mismatch (live
// UID != marker UID) is an out-of-band userdel+recreate — the current account
// belongs to someone else, so it is left fully intact. But absent an explicit
// durable stale-marker policy the condition is REPORTED (unresolved) and the
// marker RETAINED rather than silently erased with a clean-reset report.
func TestZeroizeLoginUIDMismatchReportedNonDestructive(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	// marker says UID 2000; the live account is a recreate at UID 2001.
	mustWriteFile(t, passwdPath, []byte("stale:x:2001:2001:stale:/home/stale:/bin/bash\n"))
	staleMarker := filepath.Join(provDir, "stale")
	mustWriteFile(t, staleMarker, []byte("2000"))
	staleKeys := filepath.Join(homeBase, "stale", ".ssh", "authorized_keys")
	mustWriteFile(t, staleKeys, []byte("ssh-ed25519 AAAAnew newowner\n"))

	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := wipeLoginAccounts(); err == nil {
		t.Fatalf("wipeLoginAccounts with a UID-mismatch returned nil; want the unresolved condition reported")
	}
	if len(*deleted) != 0 {
		t.Errorf("userdel invoked %v on a UID-mismatch recreate; want none (someone else's account)", *deleted)
	}
	assertPresent(t, staleKeys)   // the recreated owner's home is untouched
	assertPresent(t, staleMarker) // marker RETAINED (not silently erased)
}

// TestZeroizeLoginRetryAfterFailClosedRediscovers proves the point of retaining
// the marker: a first reset that failed closed (unreadable passwd) leaves the
// marker AND account intact, so a SECOND reset — once /etc/passwd is readable —
// still rediscovers the account and completes the userdel + marker removal. If
// the first pass had erased the marker (the fail-open bug), the account would be
// un-rediscoverable and its credential would persist forever.
func TestZeroizeLoginRetryAfterFailClosedRediscovers(t *testing.T) {
	root := t.TempDir()
	provDir := filepath.Join(root, "provisioned-users")
	sudoersDir := filepath.Join(root, "sudoers.d")
	homeBase := filepath.Join(root, "home")
	passwdPath := filepath.Join(root, "passwd")

	daveMarker := filepath.Join(provDir, "dave")
	mustWriteFile(t, daveMarker, []byte("1800"))
	daveKeys := filepath.Join(homeBase, "dave", ".ssh", "authorized_keys")
	mustWriteFile(t, daveKeys, []byte("ssh-ed25519 AAAAdave dave\n"))

	// Pass 1: /etc/passwd unreadable (directory). Fail closed.
	if err := os.MkdirAll(passwdPath, 0o755); err != nil {
		t.Fatalf("mkdir passwd dir: %v", err)
	}
	deleted := setZeroizeLoginPaths(t, provDir, sudoersDir, homeBase, passwdPath)

	if err := wipeLoginAccounts(); err == nil {
		t.Fatalf("pass 1 (unreadable passwd) returned nil; want fail-closed error")
	}
	if len(*deleted) != 0 {
		t.Errorf("pass 1 userdel invoked %v; want none", *deleted)
	}
	assertPresent(t, daveMarker) // marker survives for the retry

	// Pass 2: /etc/passwd now readable with the account present at the marker
	// UID. Replace the directory with a real passwd file at the same path.
	if err := os.RemoveAll(passwdPath); err != nil {
		t.Fatalf("remove passwd dir: %v", err)
	}
	mustWriteFile(t, passwdPath, []byte("dave:x:1800:1800:dave:/home/dave:/bin/bash\n"))

	if err := wipeLoginAccounts(); err != nil {
		t.Fatalf("pass 2 (readable passwd) returned error: %v; want a clean completion", err)
	}
	got := append([]string(nil), *deleted...)
	if len(got) != 1 || got[0] != "dave" {
		t.Errorf("pass 2 userdel invoked %v; want exactly [dave] — the rediscovered account", got)
	}
	assertAbsent(t, daveKeys)   // SSH vector removed
	assertAbsent(t, daveMarker) // marker cleared only after the successful teardown
}
