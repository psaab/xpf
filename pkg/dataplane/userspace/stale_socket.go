package userspace

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Socket-kind labels for removeStaleUnixSocket. They appear verbatim in the
// operator-facing error, so keep them noun phrases that read as the subject of
// "refusing to unlink <kind> <path>".
const (
	socketKindControl          = "control socket"
	socketKindEventStream      = "event stream socket"
	socketKindReinjectSubmit  = "reinject submit socket"
	socketKindReinjectComplete = "reinject complete socket"
)

// removeStaleUnixSocket removes only a PROVEN STALE Unix socket at path, and is
// the single implementation of stale-socket removal in this package (#5839).
//
// Both helper sockets are named by operator-supplied configuration
// (`system dataplane control-socket`, and the event socket derived beside it),
// and xpfd runs as root, so an unconditional os.Remove would silently unlink
// whatever filesystem object the path happened to name. Four checks stand
// between the path and the unlink, in this order:
//
//  1. Lstat, with "does not exist" tolerated. A first boot has no socket, and
//     that is the normal case, not an error. Lstat rather than Stat so a
//     SYMLINK is judged on its own inode: a symlink is not a socket and is
//     therefore rejected below instead of being followed to its target.
//  2. os.ModeSocket. A regular file, directory, FIFO, device, or symlink at the
//     path is refused rather than deleted. This is the data-destruction case.
//  3. A liveness probe against the kernel Unix socket table. Unlinking the
//     socket of a LIVE listener does not stop that listener: it keeps serving
//     the now-unreachable inode while a second process binds a fresh socket at
//     the same path. For the control socket that means two helpers contending
//     for the same AF_XDP queues (the second fails to bind, EBUSY) while the
//     first becomes undialable — including by the #1993 boot armed-probe, which
//     resolves forwarding state through exactly this path. Fail closed instead:
//     a live owner is reported, never evicted.
//  4. A NON-ignored os.Remove. A removal that fails (EACCES, EROFS, an
//     immutable parent) must fail bring-up rather than let the caller proceed
//     into a bind that will fail more confusingly. ErrNotExist is tolerated
//     because a concurrent cleanup racing us to the same unlink reached the
//     intended end state.
//
// Reading /proc/net/unix is deliberately non-invasive: DIALING as a liveness
// probe would, on the event socket, make the daemon accept the probe as its new
// helper and disconnect the real one. An unreadable table is inconclusive and
// fails closed — it is never treated as "not active".
//
// The caller is responsible for whatever ownership serialization its socket
// needs (EventStream.Start holds a sidecar flock across this call). The control
// socket has no such lock because xpfd does not bind it — the Rust helper does,
// and it does not participate in the flock protocol.
//
// #7139 CLOSED TWO WAYS, and neither is a stricter string test.
//
// THE PARENT IS PINNED. The directory is opened ONCE (O_PATH|O_DIRECTORY) and
// every subsequent operation is relative to that descriptor — fstatat for the
// checks, unlinkat for the removal. Previously each step re-resolved the whole
// path string, so an attacker who could re-point a parent component between two
// of them redirected the unlink into a different directory. `unlink` does not
// follow a symlink in the FINAL component, so that was never arbitrary file
// deletion; it was "delete the configured basename in a directory of my
// choosing", plus a way to defeat the live-listener refusal in check 3. Both
// need the path's parent to be attacker-writable, which the config permits
// today: ValidateUnixSocketPath accepts any absolute path, so a committed
// `/tmp/xpf.sock` puts the parent in a world-writable directory.
//
// What remains after pinning is a swap of the FINAL component within that same
// directory, which is inherent to removing by name — unlinkat takes a name, not
// a descriptor. It is strictly smaller: the attacker must already be able to
// write the socket's own directory.
//
// LIVENESS IS KEYED ON THE CANONICAL PATH, not the configured spelling. The
// kernel table lists the string the listener passed to bind(), which need not
// be the spelling xpf holds, and `/var/run` -> `/run` is a symlink on every
// systemd distro — so a LIVE socket read as stale and was unlinked out from
// under its listener. Both sides are now canonicalised before comparison.
//
// NOT INODE-KEYED, and the issue's suggestion to compare Lstat's inode against
// the /proc/net/unix inode column is wrong — measured, not assumed. They are
// different objects: the filesystem inode of the bound socket file and the
// socket's own inode in sockfs. On one live socket here they read 23374170 and
// 773414179. Comparing them matches NOTHING, so every live socket would be
// judged stale and unlinked — a worse bug than the one being fixed, wearing the
// shape of a tightening.
//
// STILL OUT OF SCOPE (#7139's third bullet): pinning both sockets under an
// xpfd-owned /run/xpf and dropping the arbitrary path. That subsumes the whole
// class, but it is an operator-visible config change and needs its own #1960
// no-brick analysis for deployments that already set a custom path.
func removeStaleUnixSocket(kind, path string) error {
	dir, base := filepath.Split(path)
	if base == "" {
		return fmt.Errorf("refusing to unlink %s %s: path names no file", kind, path)
	}
	if dir == "" {
		dir = "."
	}

	// Resolve the DIRECTORY once and hold it. Symlinks are followed here on
	// purpose — an operator naming /var/run/xpf means the real /run/xpf, and
	// refusing that would break a legitimate configuration. What the descriptor
	// buys is that every step below acts on THIS directory, so no later
	// re-pointing of a parent component can move the target.
	dirFD, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			// No directory means no socket. A first boot before the runtime
			// directory exists is the normal case, not an error.
			return nil
		}
		return fmt.Errorf("open %s directory %s: %w", kind, dir, err)
	}
	defer unix.Close(dirFD)

	var st unix.Stat_t
	if err := unix.Fstatat(dirFD, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("inspect %s %s: %w", kind, path, err)
	}
	// AT_SYMLINK_NOFOLLOW so a SYMLINK is judged on its own inode: a symlink is
	// not a socket and is refused below rather than followed to its target.
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return fmt.Errorf("refusing to unlink %s %s: existing path is a %s, not a Unix socket",
			kind, path, describeFileMode(modeFromStat(st.Mode)))
	}

	active, err := unixSocketPathActive(path)
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("refusing to unlink %s %s: it already has a live listener", kind, path)
	}
	if err := unix.Unlinkat(dirFD, base, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove stale %s %s: %w", kind, path, err)
	}
	return nil
}

// modeFromStat converts a raw st_mode file-type to the os.FileMode bits
// describeFileMode reads, so the operator-facing wording is unchanged by the
// move from os.Lstat to fstatat.
func modeFromStat(m uint32) os.FileMode {
	switch m & unix.S_IFMT {
	case unix.S_IFDIR:
		return os.ModeDir
	case unix.S_IFLNK:
		return os.ModeSymlink
	case unix.S_IFIFO:
		return os.ModeNamedPipe
	case unix.S_IFSOCK:
		return os.ModeSocket
	case unix.S_IFCHR:
		return os.ModeDevice | os.ModeCharDevice
	case unix.S_IFBLK:
		return os.ModeDevice
	}
	return 0
}

// unixSocketPathActive reports whether the kernel Unix socket table lists a
// socket bound to path — i.e. some process is still holding it. A table that
// cannot be read returns an error and never a bare false, so an inconclusive
// read fails closed at the caller.
func unixSocketPathActive(path string) (bool, error) {
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return false, fmt.Errorf("inspect kernel Unix socket table for %s: %w", path, err)
	}
	want := canonicalSocketPath(path)
	base := filepath.Base(path)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		// Columns are fixed through Flags/Type/St/Inode; the path is the
		// 8th field onward, rejoined because a bound path may contain
		// spaces.
		if len(fields) < 8 {
			continue
		}
		bound := strings.Join(fields[7:], " ")
		if bound == path {
			return true, nil
		}
		// #7139: the table lists the string the LISTENER bound, which need not
		// be the spelling this node holds. Canonicalise before deciding — but
		// only for entries whose basename already matches, so a host with
		// thousands of Unix sockets does not pay a symlink resolution each.
		if filepath.Base(bound) != base {
			continue
		}
		if canonicalSocketPath(bound) == want {
			return true, nil
		}
	}
	return false, nil
}

// canonicalSocketPath resolves a socket path's DIRECTORY through symlinks and
// rejoins the final component.
//
// The directory is resolved and the base is not, deliberately: the base names
// the socket itself, whose own identity is the question, while the directory is
// where the aliasing lives (`/var/run` -> `/run`). Resolving the whole path
// would follow a symlink AT the socket name and could equate two different
// sockets.
//
// An unresolvable directory falls back to a lexical cleanup rather than
// failing. This function only ever makes the comparison MORE likely to match,
// and matching means "a live listener holds it" — which refuses the unlink. So
// the failure direction is a refusal to remove a socket that may be stale,
// visible to the operator, rather than a removal of one that is live.
func canonicalSocketPath(p string) string {
	dir, base := filepath.Split(p)
	if dir == "" {
		dir = "."
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return filepath.Clean(p)
	}
	return filepath.Join(resolved, base)
}

// describeFileMode names the file type an operator sees at a refused path, so
// the error says what is actually there rather than only what it is not. It
// mirrors the helper-side wording in userspace-dp/src/server/lifecycle.rs
// (describe_file_type).
func describeFileMode(mode os.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode&os.ModeDir != 0:
		return "directory"
	case mode&os.ModeNamedPipe != 0:
		return "FIFO"
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		return "character device"
	case mode&os.ModeDevice != 0:
		return "block device"
	case mode&os.ModeType == 0:
		return "regular file"
	default:
		return "non-socket file"
	}
}
