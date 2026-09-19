package userspace

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #5839: the helper control socket was removed with a bare, result-discarding
// `os.Remove(cfg.ControlSocket)`. The path comes from operator configuration
// (`system dataplane control-socket`) and xpfd runs as root, so that unlink
// deleted whatever object the path named — a regular file, a symlink, the live
// socket of a running helper — and swallowed the failure when it could not.
// The sibling event-socket half was hardened in #5273; these tests pin the same
// four checks on the shared primitive both halves now use.

// shortSocketDir returns a scratch directory under /tmp. AF_UNIX sun_path is
// 108 bytes; a t.TempDir() path (which carries the full test name) can push a
// bound socket past it and produce "bind: invalid argument" instead of the
// behaviour under test.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "xpf5839")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// listenUnix binds a real Unix-stream listener at path and returns it.
func listenUnix(t *testing.T, path string) *net.UnixListener {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix(%s): %v", path, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestRemoveStaleUnixSocketRefusesNonSocketPaths_5839 covers check 2 (the
// os.ModeSocket gate) for every non-socket file type the path could name. Each
// case asserts BOTH halves: the call fails, and the object is still there —
// "returned an error" alone would pass even if the unlink had already run.
func TestRemoveStaleUnixSocketRefusesNonSocketPaths_5839(t *testing.T) {
	cases := []struct {
		name    string
		create  func(t *testing.T, path string)
		wantSub string
	}{
		{
			name: "regular file",
			create: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("operator data"), 0600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			},
			wantSub: "regular file",
		},
		{
			name: "directory",
			create: func(t *testing.T, path string) {
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatalf("Mkdir: %v", err)
				}
			},
			wantSub: "directory",
		},
		{
			name: "fifo",
			create: func(t *testing.T, path string) {
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatalf("Mkfifo: %v", err)
				}
			},
			wantSub: "FIFO",
		},
		{
			// Lstat, not Stat: a symlink is judged on its own inode, so a
			// symlink POINTING AT a socket is still refused rather than
			// followed into an unlink of the target.
			name: "symlink to a socket",
			create: func(t *testing.T, path string) {
				target := filepath.Join(filepath.Dir(path), "real.sock")
				ln := listenUnix(t, target)
				_ = ln
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("Symlink: %v", err)
				}
			},
			wantSub: "symlink",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := shortSocketDir(t)
			path := filepath.Join(dir, "control.sock")
			tc.create(t, path)

			err := removeStaleUnixSocket(socketKindControl, path)
			if err == nil {
				t.Fatalf("removeStaleUnixSocket(%s) = nil, want refusal for a %s", path, tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want it to name the file type %q", err, tc.wantSub)
			}
			if !strings.Contains(err.Error(), "refusing to unlink") {
				t.Errorf("error = %q, want a refusal, not an incidental failure", err)
			}
			if _, statErr := os.Lstat(path); statErr != nil {
				t.Fatalf("%s at %s was destroyed by a refused removal: %v", tc.name, path, statErr)
			}
		})
	}
}

// TestRemoveStaleUnixSocketRefusesLiveListener_5839 covers check 3, the one
// that matters most: unlinking the socket of a LIVE listener does not stop that
// listener, it only makes it unreachable while a second process binds a fresh
// socket at the same name. The socket must survive the refusal AND still
// accept a connection.
func TestRemoveStaleUnixSocketRefusesLiveListener_5839(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "control.sock")
	listenUnix(t, path)

	err := removeStaleUnixSocket(socketKindControl, path)
	if err == nil {
		t.Fatal("removeStaleUnixSocket() = nil for a socket with a LIVE listener, want refusal")
	}
	if !strings.Contains(err.Error(), "live listener") {
		t.Errorf("error = %q, want it to name the live listener", err)
	}
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatalf("live socket at %s was unlinked by a refused removal: %v", path, statErr)
	}
	conn, dialErr := net.DialTimeout("unix", path, 2*time.Second)
	if dialErr != nil {
		t.Fatalf("live listener at %s is no longer reachable after the refusal: %v", path, dialErr)
	}
	_ = conn.Close()
}

// TestRemoveStaleUnixSocketRemovesStaleSocket_5839 is the positive control for
// checks 1 and 4: a crash artifact — a socket file with no listener behind it —
// is removed, and a path that does not exist at all is not an error.
func TestRemoveStaleUnixSocketRemovesStaleSocket_5839(t *testing.T) {
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "control.sock")

	if err := removeStaleUnixSocket(socketKindControl, path); err != nil {
		t.Fatalf("removeStaleUnixSocket() on a missing path = %v, want nil", err)
	}

	ln := listenUnix(t, path)
	// Leave the socket file behind on close, which is what a SIGKILLed helper
	// leaves on disk.
	ln.SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("precondition: stale socket not left on disk: %v", err)
	}

	if err := removeStaleUnixSocket(socketKindControl, path); err != nil {
		t.Fatalf("removeStaleUnixSocket() on a stale socket = %v, want removal", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("stale socket still present after removal: err=%v", err)
	}
}

// TestRemoveStaleUnixSocketSurfacesRemoveFailure_5839 covers check 4: a removal
// that FAILS must be reported, not discarded. Pre-#5839 the control-socket call
// site was `_ = os.Remove(...)`, so an unremovable socket produced a confusing
// downstream bind failure instead of a diagnosis.
func TestRemoveStaleUnixSocketSurfacesRemoveFailure_5839(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permission; the unlink cannot be made to fail this way")
	}
	dir := shortSocketDir(t)
	path := filepath.Join(dir, "control.sock")
	ln := listenUnix(t, path)
	ln.SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	// Deny unlink in the parent directory.
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0755) })

	err := removeStaleUnixSocket(socketKindControl, path)
	if err == nil {
		t.Fatal("removeStaleUnixSocket() = nil when the unlink failed, want the failure surfaced")
	}
	if !strings.Contains(err.Error(), "remove stale") {
		t.Errorf("error = %q, want it to report the failed removal", err)
	}
}

// TestEnsureProcessLockedRefusesLiveControlSocket_5839 pins the check through
// the PRODUCTION path rather than the primitive alone: bring-up must refuse
// before spawning a helper, and the live socket must still be there and still
// serving afterwards.
func TestEnsureProcessLockedRefusesLiveControlSocket_5839(t *testing.T) {
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "control.sock")
	listenUnix(t, sock)

	m := New()
	cfg := config.UserspaceConfig{
		Binary:        testBinary,
		ControlSocket: sock,
		StateFile:     filepath.Join(dir, "state.json"),
	}
	m.mu.Lock()
	err = m.ensureProcessLocked(cfg)
	m.mu.Unlock()

	if err == nil {
		t.Fatal("ensureProcessLocked() = nil with a LIVE listener on the control socket, want refusal")
	}
	if !strings.Contains(err.Error(), "live listener") {
		t.Errorf("error = %q, want it to name the live listener", err)
	}
	if m.proc != nil {
		t.Errorf("helper spawned despite the refusal: %+v", m.proc)
	}
	if _, statErr := os.Lstat(sock); statErr != nil {
		t.Fatalf("live control socket was unlinked by bring-up: %v", statErr)
	}
	conn, dialErr := net.DialTimeout("unix", sock, 2*time.Second)
	if dialErr != nil {
		t.Fatalf("live control socket no longer reachable after bring-up refusal: %v", dialErr)
	}
	_ = conn.Close()
}

// TestEnsureProcessLockedRefusesNonSocketControlPath_5839 is the data-loss
// case through the production path: a regular file at the control-socket path
// must be preserved and bring-up must fail closed.
func TestEnsureProcessLockedRefusesNonSocketControlPath_5839(t *testing.T) {
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "control.sock")
	const payload = "operator data that must survive bring-up"
	if err := os.WriteFile(sock, []byte(payload), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := New()
	cfg := config.UserspaceConfig{
		Binary:        testBinary,
		ControlSocket: sock,
		StateFile:     filepath.Join(dir, "state.json"),
	}
	m.mu.Lock()
	err = m.ensureProcessLocked(cfg)
	m.mu.Unlock()

	if err == nil {
		t.Fatal("ensureProcessLocked() = nil with a regular file at the control socket, want refusal")
	}
	if m.proc != nil {
		t.Errorf("helper spawned despite the refusal: %+v", m.proc)
	}
	got, readErr := os.ReadFile(sock)
	if readErr != nil {
		t.Fatalf("regular file at the control-socket path was deleted by bring-up: %v", readErr)
	}
	if string(got) != payload {
		t.Errorf("file contents = %q, want %q", got, payload)
	}
}

// TestEnsureProcessLockedKeepsRunningHelperOnBadPathSet_5839 pins the ordering
// half of #5839: ensureProcessLocked stops generation N before it prepares
// generation N+1, so a path fault used to be paid for with forwarding — the
// healthy helper was killed and only then did preparation fail, leaving the
// node with no dataplane at all. A deterministic path fault must be caught
// while the previous generation is still running.
func TestEnsureProcessLockedKeepsRunningHelperOnBadPathSet_5839(t *testing.T) {
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "control.sock")
	if err := os.WriteFile(sock, []byte("not a socket"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// A stand-in for the running helper: ensureProcessLocked only needs a
	// live *exec.Cmd to decide there is a generation to tear down.
	running := exec.Command("/bin/sleep", "60")
	if err := running.Start(); err != nil {
		t.Fatalf("start stand-in helper: %v", err)
	}
	t.Cleanup(func() {
		_ = running.Process.Kill()
		_ = running.Wait()
	})

	m := New()
	m.proc = running
	cfg := config.UserspaceConfig{
		Binary:        "/bin/sleep",
		ControlSocket: sock,
		StateFile:     filepath.Join(dir, "state.json"),
	}

	m.mu.Lock()
	err := m.ensureProcessLocked(cfg)
	m.mu.Unlock()

	if err == nil {
		t.Fatal("ensureProcessLocked() = nil with a non-socket control path, want refusal")
	}
	if !strings.Contains(err.Error(), "previous generation left running") {
		t.Errorf("error = %q, want it to say the previous generation was spared", err)
	}
	if m.proc == nil {
		t.Fatal("running helper was torn down for a config that could never come up")
	}
	// Signal 0 probes liveness without delivering anything.
	if sigErr := m.proc.Process.Signal(syscall.Signal(0)); sigErr != nil {
		t.Fatalf("running helper process was killed for a config that could never come up: %v", sigErr)
	}
}

// TestPreflightHelperPathsRejectsAliasedPaths_5839 pins the aliasing guard: the
// socket-unlink primitive must never be aimed at the state file, where a
// REGULAR FILE is the expected object, and the two sockets cannot share a path
// because the daemon's event listener would occupy the name the helper must
// bind.
func TestPreflightHelperPathsRejectsAliasedPaths_5839(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.UserspaceConfig
	}{
		{
			name: "control aliases state",
			cfg: config.UserspaceConfig{
				ControlSocket: "/run/xpf/dp.sock",
				StateFile:     "/run/xpf/dp.sock",
			},
		},
		{
			name: "control aliases event",
			cfg: config.UserspaceConfig{
				ControlSocket: "/run/xpf/dp.sock",
				EventSocket:   "/run/xpf/dp.sock",
				StateFile:     "/run/xpf/state.json",
			},
		},
		{
			name: "event aliases state",
			cfg: config.UserspaceConfig{
				ControlSocket: "/run/xpf/dp.sock",
				EventSocket:   "/run/xpf/state.json",
				StateFile:     "/run/xpf/state.json",
			},
		},
		{
			name: "derived event socket aliases an explicit control socket",
			cfg: config.UserspaceConfig{
				ControlSocket: "/run/xpf/userspace-dp-events.sock",
				StateFile:     "/run/xpf/state.json",
			},
		},
		{
			name: "dot-segment reinject submit aliases control",
			cfg: config.UserspaceConfig{
				ControlSocket: "/run/xpf/./reinject-submit.sock",
				StateFile:     "/run/xpf/state.json",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := preflightHelperPaths(tc.cfg)
			if err == nil {
				t.Fatal("preflightHelperPaths() = nil, want a distinct-paths refusal")
			}
			if !strings.Contains(err.Error(), "distinct paths") {
				t.Errorf("error = %q, want a distinct-paths refusal", err)
			}
		})
	}

	ok := config.UserspaceConfig{
		ControlSocket: "/run/xpf/userspace-dp.sock",
		StateFile:     "/run/xpf/state.json",
	}
	if err := preflightHelperPaths(ok); err != nil {
		t.Fatalf("preflightHelperPaths() on the default-shaped path set = %v, want nil", err)
	}
}

func TestPreflightHelperPathsRejectsReinjectRegularFile9506(t *testing.T) {
	dir := shortSocketDir(t)
	cfg := config.UserspaceConfig{
		ControlSocket: filepath.Join(dir, "control.sock"),
		StateFile:     filepath.Join(dir, "state.json"),
	}
	reinjectSubmit, _ := helperReinjectSocketPaths(cfg)
	if err := os.WriteFile(reinjectSubmit, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	err := preflightHelperPaths(cfg)
	if err == nil || !strings.Contains(err.Error(), "reinject submit socket") {
		t.Fatalf("preflightHelperPaths()=%v, want reinject regular-file refusal", err)
	}
}
