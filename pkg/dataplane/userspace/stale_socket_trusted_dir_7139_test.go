package userspace

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stale_socket_trusted_dir_7139_test.go — #7139.
//
// Two residuals of #5839, both measured before they were fixed:
//
//  1. the liveness probe compared the configured path STRING against
//     /proc/net/unix, so a live socket reached through another spelling of the
//     same file read as STALE and was unlinked out from under its listener;
//  2. every check re-resolved the whole path, so a parent component could be
//     re-pointed between a check and the unlink.
//
// The fixtures use a SHORT scratch root because AF_UNIX sun_path is 108 octets
// and t.TempDir() under a long TMPDIR silently exceeds it — a bind that fails
// for length looks exactly like a bind that fails for the reason under test.

func shortTempDir7139(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "x7139")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// TestLiveSocketThroughSymlinkedParentIsNotUnlinked_7139 is residual 1, and it
// is the outage case rather than the attack case: `/var/run` -> `/run` is a
// symlink on every systemd distro, so this is reachable by configuration alone.
func TestLiveSocketThroughSymlinkedParentIsNotUnlinked_7139(t *testing.T) {
	real := shortTempDir7139(t)
	sock := filepath.Join(real, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot bind a unix socket here: %v", err)
	}
	defer ln.Close()

	// A second spelling of the very same file, via a symlinked parent.
	alias := real + "-link"
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot symlink: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })
	aliasSock := filepath.Join(alias, "c.sock")

	// Precondition: the alias spelling is genuinely absent from the kernel
	// table, which is what made the old string compare answer "stale". Without
	// this the cell could pass because the table happened to list both.
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		t.Skipf("cannot read /proc/net/unix: %v", err)
	}
	if strings.Contains(string(data), aliasSock) {
		t.Fatalf("precondition: the kernel table lists the ALIAS spelling %q, so this "+
			"fixture no longer reproduces the aliasing the fix is for", aliasSock)
	}

	err = removeStaleUnixSocket(socketKindControl, aliasSock)
	if err == nil {
		t.Fatal("removeStaleUnixSocket UNLINKED a live socket reached through a " +
			"symlinked parent. Its listener keeps serving an unreachable inode while " +
			"the next bring-up binds a fresh socket at the same path — two helpers " +
			"contending for the same AF_XDP queues, with the first undialable (#7139)")
	}
	if !strings.Contains(err.Error(), "live listener") {
		t.Fatalf("refused for the WRONG REASON: %v. It must be recognised as live, not "+
			"rejected for some incidental property of the path", err)
	}
	if _, statErr := os.Stat(sock); statErr != nil {
		t.Fatalf("the socket file is gone after a refusal: %v", statErr)
	}
}

// TestStaleSocketIsStillRemoved_7139 is the negative control: without it every
// assertion above is satisfied by a function that refuses everything.
func TestStaleSocketIsStillRemoved_7139(t *testing.T) {
	dir := shortTempDir7139(t)
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	// Close WITHOUT removing the file: the classic stale socket, left by a
	// helper that died.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	_ = ln.Close()
	if _, err := os.Stat(sock); err != nil {
		t.Skipf("listener removed its own socket, cannot stage a stale one: %v", err)
	}

	if err := removeStaleUnixSocket(socketKindControl, sock); err != nil {
		t.Fatalf("a genuinely stale socket must be removed, got: %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("stale socket still present after removal: %v", err)
	}
}

// TestNonSocketIsRefusedThroughTheDirFD_7139 keeps #5839's data-destruction
// guarantee across the move from os.Lstat/os.Remove to fstatat/unlinkat. The
// file-type wording is operator-facing, so it is asserted, not just the refusal.
func TestNonSocketIsRefusedThroughTheDirFD_7139(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, want string
		create     func(string) error
	}{
		{"regular_file", "regular file", func(p string) error { return os.WriteFile(p, []byte("x"), 0o600) }},
		{"directory", "directory", func(p string) error { return os.Mkdir(p, 0o755) }},
		{"symlink", "symlink", func(p string) error { return os.Symlink("/dev/null", p) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name)
			if err := tc.create(p); err != nil {
				t.Fatalf("create: %v", err)
			}
			err := removeStaleUnixSocket(socketKindControl, p)
			if err == nil {
				t.Fatalf("removeStaleUnixSocket DELETED a %s. #5839's whole subject is "+
					"that xpfd runs as root and the path is operator-supplied", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error names the wrong file type: %v (want %q)", err, tc.want)
			}
			if _, statErr := os.Lstat(p); statErr != nil {
				t.Fatalf("the %s was removed despite the refusal: %v", tc.name, statErr)
			}
		})
	}
}

// TestMissingSocketAndMissingDirAreNotErrors_7139: a first boot has neither, and
// that is the normal path, not a failure. The directory case is new — the old
// code Lstat'd the file and never opened the parent.
func TestMissingSocketAndMissingDirAreNotErrors_7139(t *testing.T) {
	dir := shortTempDir7139(t)
	if err := removeStaleUnixSocket(socketKindControl, filepath.Join(dir, "absent.sock")); err != nil {
		t.Fatalf("absent socket must be tolerated: %v", err)
	}
	if err := removeStaleUnixSocket(socketKindControl, filepath.Join(dir, "no-such-dir", "c.sock")); err != nil {
		t.Fatalf("absent DIRECTORY must be tolerated (first boot before the runtime "+
			"directory exists), got: %v", err)
	}
}

// TestCanonicalSocketPathResolvesDirNotBase_7139 pins the asymmetry directly.
//
// The directory is resolved and the base is not: the base names the socket whose
// identity is the question, and following a symlink AT that name would equate
// two different sockets.
func TestCanonicalSocketPathResolvesDirNotBase_7139(t *testing.T) {
	real := shortTempDir7139(t)
	alias := real + "-link"
	if err := os.Symlink(real, alias); err != nil {
		t.Skipf("cannot symlink: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(alias) })

	got := canonicalSocketPath(filepath.Join(alias, "c.sock"))
	want := canonicalSocketPath(filepath.Join(real, "c.sock"))
	if got != want {
		t.Fatalf("two spellings of one file canonicalised differently: %q vs %q", got, want)
	}

	// A symlink AT the base must NOT be followed: two names pointing at one
	// target are still two sockets as far as bind() is concerned.
	other := filepath.Join(real, "other.sock")
	if err := os.Symlink(filepath.Join(real, "c.sock"), other); err != nil {
		t.Skipf("cannot symlink: %v", err)
	}
	if canonicalSocketPath(other) == want {
		t.Fatal("canonicalSocketPath followed a symlink at the BASE, equating two " +
			"distinct socket names; a live listener on one would then refuse the " +
			"unlink of the other")
	}
}
