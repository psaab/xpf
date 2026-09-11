package userspace

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// socket_trust_9003.go answers a question the control socket never asked before
// #9003: "is the process on the other end of this socket actually the helper?"
//
// It matters because of WHAT crosses. `buildTunnelSnapshots`
// (tunnels.go) puts the WireGuard local private key and every per-peer
// preshared key into the `apply_snapshot` body in CLEARTEXT. The on-disk half of
// that was already handled — snapshot.rs marks both fields `skip_serializing`
// with a redacting Debug impl so `state.json` cannot carry them — but the socket
// half was gated by nothing except the filesystem mode the socket happened to
// inherit from the ambient umask, which no code, unit file or test asserted.
//
// Three defects composed:
//
//  1. the compiled-in DEFAULT control-socket path was
//     `os.TempDir()/xpf-userspace-dp/control.sock`, i.e. a directory inside
//     world-writable `/tmp` that xpfd creates on first boot;
//  2. `os.MkdirAll(dir, 0755)` returns nil for a directory that ALREADY EXISTS
//     and never looks at its owner or mode, so an unprivileged local user who
//     wins the race to `mkdir /tmp/xpf-userspace-dp` OWNS the directory the root
//     helper then binds inside — and can unlink that socket and bind their own;
//  3. nothing on either end checked the peer, so whoever holds the socket gets
//     `apply_snapshot` (the keys) AND gets to answer `status` — which is how the
//     #1993 fail-closed boot decision and the #5286 upgrade-readiness gate learn
//     whether forwarding is live (boot_probe.go dials before any helper spawn,
//     so removeStaleUnixSocket's fail-closed guard has not run yet).
//
// The path checks below close (1) and (2). The peer check closes (3) and is the
// one that is RACE-FREE: SO_PEERCRED is answered by the kernel for the socket
// this connection is actually attached to, so it cannot be defeated by swapping
// the path between the check and the connect.

// DefaultRuntimeDir is where the helper's runtime objects live when the operator
// does not name a path. It is the directory the shipped reference configs
// already pin (`docs/ha-cluster-userspace.conf`, `docs/ha-cluster-loss.conf`),
// and the one xpf already owns for its other runtime state (the #5286 upgrade
// lock at /run/xpf/upgrade.lock, the host-tunables snapshot).
//
// It is deliberately NOT under os.TempDir(): /run is root-owned and 0755 on
// every systemd distro, so a subdirectory xpfd creates there cannot be
// pre-created by an unprivileged user.
const DefaultRuntimeDir = "/run/xpf"

// DefaultControlSocket / DefaultStateFile are the compiled-in defaults used when
// `system dataplane control-socket` / `state-file` are unset. They match the
// spellings in the shipped reference configs so a deployment that omits the
// leaves lands on the same paths as one that sets them.
const (
	DefaultControlSocket = DefaultRuntimeDir + "/userspace-dp.sock"
	DefaultStateFile     = DefaultRuntimeDir + "/userspace-dp.json"
)

// runtimeDirMode is the mode xpfd CREATES a helper runtime directory with. Only
// root (and the helper, which is root) needs to traverse it. A directory that
// already exists keeps its own mode and is judged by verifyTrustedRuntimeDir
// instead — we do not chmod a directory we did not create, because a chmod is
// exactly the operation an adopted attacker-owned directory would make look
// safe without making it safe (the attacker still owns it and can chmod back).
const runtimeDirMode = 0o750

// errUntrustedRuntimeDir / errUntrustedHelperPeer are the two refusals. They are
// sentinels so a caller can tell "the environment is hostile" from "the helper
// is not up yet", which are opposite operational conclusions.
var (
	errUntrustedRuntimeDir = errors.New("helper runtime directory is not trusted")
	errUntrustedHelperPeer = errors.New("helper control socket peer is not privileged")
)

// ensureTrustedRuntimeDir creates dir if it is absent and then PROVES it is
// ours. MkdirAll succeeding is not evidence the directory is yours: it returns
// nil for a pre-existing directory of any owner and any mode.
func ensureTrustedRuntimeDir(kind, dir string) error {
	if err := os.MkdirAll(dir, runtimeDirMode); err != nil {
		return fmt.Errorf("mkdir %s directory %s: %w", kind, dir, err)
	}
	return verifyTrustedRuntimeDir(kind, dir)
}

// verifyTrustedRuntimeDir refuses a directory an unprivileged local user could
// have created, or could still write into.
//
// TWO checks, and they are not the same check:
//
//   - the directory ITSELF must be owned by root (or by us, so a non-root test
//     binary can drive this against a t.TempDir()) and must not be
//     world-writable. This is the #9003 adoption case: the attacker mkdir'd it
//     first, so they own it, so they can unlink the root helper's socket and
//     bind their own at the same name.
//   - every ANCESTOR that is world-writable must carry the sticky bit. Sticky is
//     what stops a non-owner renaming or removing our directory out from under
//     us; without it, a world-writable ancestor lets an attacker swap the whole
//     subtree even though the leaf directory's own mode is fine.
//
// The second check is what keeps the first honest and is also why this does NOT
// brick a deployment that committed `control-socket /tmp/xpf.sock`: /tmp is
// 1777, i.e. world-writable AND sticky, and root-owned, so it passes. What is
// refused is precisely the shape the issue describes — a world-writable-parent
// SUBDIRECTORY owned by someone else.
func verifyTrustedRuntimeDir(kind, dir string) error {
	fd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s directory %s: %w", kind, dir, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("inspect %s directory %s: %w", kind, dir, err)
	}
	if err := runtimeDirTrustError(kind, dir, st.Uid, st.Gid, st.Mode,
		uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
		return err
	}
	return verifyAncestorsNotSwappable(kind, dir)
}

// runtimeDirTrustError is the DECISION, split from the syscall shell above so
// every arm is reachable from a test on any machine.
//
// The ownership arm cannot be exercised end-to-end by a non-root test binary —
// chown(2) to a foreign uid needs CAP_CHOWN — and the project rule is that a
// test needing a kernel capability STUBS it rather than skipping on it (#6675),
// because a skip is indistinguishable from a pass in every summary line. Making
// the decision a pure function of (uid, mode, self) is that stub: the shell
// supplies real values in production and the cells supply the hostile ones.
func runtimeDirTrustError(kind, dir string, uid, gid, mode, self, selfGid uint32) error {
	if uid != 0 && uid != self {
		return fmt.Errorf("%w: %s directory %s is owned by uid %d, not root (uid 0) or this daemon (uid %d) — "+
			"an unprivileged owner can replace the socket xpfd is about to talk to, which carries the "+
			"WireGuard private key and every preshared key; remove it or point "+
			"`set system dataplane control-socket` at a root-owned directory such as %s",
			errUntrustedRuntimeDir, kind, dir, uid, self, DefaultRuntimeDir)
	}
	if mode&unix.S_IWOTH != 0 && mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("%w: %s directory %s has mode %04o — it is world-writable without the sticky bit, "+
			"so any local user can replace the socket xpfd is about to talk to; "+
			"point `set system dataplane control-socket` at a root-owned directory such as %s",
			errUntrustedRuntimeDir, kind, dir, mode&0o7777, DefaultRuntimeDir)
	}
	// #9171: the GROUP-writable arm. This check tested S_IWOTH only, so a
	// root-owned but group-writable directory passed — and every member of that
	// group can then unlink the socket and bind their own.
	//
	// It matters more than it looks because it was the half that made a SECOND
	// bounded finding reachable: the helper's event-socket CLIENT is the one leg
	// of six with no peer verification, and that gap was dismissed as needing
	// "write access to a root-owned directory, i.e. root already". Group-write
	// is exactly the case where that premise fails. **Each of the two findings
	// was dismissed by assuming the other held.**
	//
	// gid 0 and the daemon's own egid are accepted, mirroring the uid arm
	// directly above: membership of the root group is already root-equivalent on
	// any system where this check could help, and refusing the daemon's own
	// group would refuse the directory the daemon itself creates.
	if mode&unix.S_IWGRP != 0 && mode&unix.S_ISVTX == 0 && gid != 0 && gid != selfGid {
		return fmt.Errorf("%w: %s directory %s has mode %04o and group %d — it is group-writable "+
			"without the sticky bit and the group is neither root (0) nor this daemon's (%d), "+
			"so any member of that group can replace the socket xpfd is about to talk to and "+
			"receive the live session-delta stream; point `set system dataplane control-socket` "+
			"at a root-owned directory such as %s",
			errUntrustedRuntimeDir, kind, dir, mode&0o7777, gid, selfGid, DefaultRuntimeDir)
	}
	return nil
}

// verifyAncestorsNotSwappable walks dir's ancestors and refuses a world-writable
// one that is missing the sticky bit. Such an ancestor lets any local user
// rename our directory aside and put their own in its place, which defeats the
// leaf check above entirely.
//
// The path is resolved through symlinks first: /var/run -> /run on every systemd
// distro, and judging the unresolved spelling would inspect components that do
// not exist.
func verifyAncestorsNotSwappable(kind, dir string) error {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		// The directory exists (we just opened it), so this is an unusual
		// failure. Fail closed: an unresolvable path is not one we can vouch for.
		return fmt.Errorf("resolve %s directory %s: %w", kind, dir, err)
	}
	for p := filepath.Dir(resolved); ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			return fmt.Errorf("inspect %s directory ancestor %s: %w", kind, p, err)
		}
		if st.Mode&unix.S_IWOTH != 0 && st.Mode&unix.S_ISVTX == 0 {
			return fmt.Errorf("%w: %s directory %s has ancestor %s with mode %04o — world-writable without "+
				"the sticky bit, so any local user can move it aside and substitute their own; "+
				"point `set system dataplane control-socket` at a path under a root-owned directory such as %s",
				errUntrustedRuntimeDir, kind, dir, p, st.Mode&0o7777, DefaultRuntimeDir)
		}
		// #9171: an ancestor is as good as the directory itself — moving a
		// parent aside substitutes the whole subtree. Same gid exemptions.
		if st.Mode&unix.S_IWGRP != 0 && st.Mode&unix.S_ISVTX == 0 &&
			st.Gid != 0 && st.Gid != uint32(os.Getegid()) {
			return fmt.Errorf("%w: %s directory %s has ancestor %s with mode %04o and group %d — "+
				"group-writable without the sticky bit and not a trusted group, so any member of "+
				"that group can move it aside and substitute their own; point "+
				"`set system dataplane control-socket` at a path under a root-owned directory such as %s",
				errUntrustedRuntimeDir, kind, dir, p, st.Mode&0o7777, st.Gid, DefaultRuntimeDir)
		}
		if p == "/" || p == "." {
			return nil
		}
	}
}

// dialTrustedHelperSocket dials an AF_UNIX helper socket and refuses to hand it
// anything until the kernel has confirmed who is listening.
//
// This is the check that does not race. Every path-based check answers a
// question about a NAME at some earlier instant; SO_PEERCRED answers a question
// about THIS connection's peer, resolved by the kernel from the socket the
// connection is actually attached to. An attacker who swaps the path between the
// stat and the connect defeats the former and cannot touch the latter.
//
// It is the only thing standing between a /tmp squatter and `apply_snapshot`'s
// cleartext WireGuard private key, and between the same squatter and the #1993
// boot armed-probe, which it could otherwise answer with any Enabled /
// ForwardingArmed pair it liked.
func dialTrustedHelperSocket(kind, path string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, err
	}
	if err := verifyUnixPeerIsPrivileged(kind, path, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// verifyUnixPeerIsPrivileged reads SO_PEERCRED from an AF_UNIX connection and
// refuses a peer that is neither root nor this process's own euid.
//
// The euid arm exists so a non-root test binary can drive the real production
// path against a real socket it binds itself. In production both ends are root,
// so it is uid 0 == uid 0 and the arm never fires.
func verifyUnixPeerIsPrivileged(kind, path string, conn net.Conn) error {
	cred, err := readUnixPeerCred(kind, path, conn)
	if err != nil {
		return err
	}
	return peerCredTrustError(kind, path, cred, uint32(os.Geteuid()))
}

// readUnixPeerCred is the syscall shell: it asks the kernel who is on the other
// end of an AF_UNIX connection. It NEVER substitutes a zero value for a failed
// read — a zeroed unix.Ucred has Uid 0, which peerCredTrustError would accept as
// root, so swallowing the error here would convert this whole guard into a
// fail-OPEN. Every failure is returned.
func readUnixPeerCred(kind, path string, conn net.Conn) (*unix.Ucred, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("%w: %s %s is not an AF_UNIX connection (%T), so its peer cannot be identified",
			errUntrustedHelperPeer, kind, path, conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("%w: %s %s: obtain raw connection: %v", errUntrustedHelperPeer, kind, path, err)
	}
	var (
		cred    *unix.Ucred
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, fmt.Errorf("%w: %s %s: read peer credentials: %v", errUntrustedHelperPeer, kind, path, err)
	}
	if credErr != nil {
		return nil, fmt.Errorf("%w: %s %s: read peer credentials: %v", errUntrustedHelperPeer, kind, path, credErr)
	}
	if cred == nil {
		return nil, fmt.Errorf("%w: %s %s: kernel returned no peer credentials", errUntrustedHelperPeer, kind, path)
	}
	return cred, nil
}

// peerCredTrustError is the DECISION, split from the syscall shell for the same
// reason runtimeDirTrustError is: a non-root test binary cannot manufacture a
// connection from a foreign uid, so the hostile case is supplied to the pure
// function while the shell is proved separately against a real socket.
func peerCredTrustError(kind, path string, cred *unix.Ucred, self uint32) error {
	if cred == nil {
		return fmt.Errorf("%w: %s %s: no peer credentials", errUntrustedHelperPeer, kind, path)
	}
	if cred.Uid != 0 && cred.Uid != self {
		return fmt.Errorf("%w: %s %s is held by uid %d (pid %d), not root (uid 0) or this daemon (uid %d) — "+
			"refusing to speak the control protocol to it; the snapshot carries the WireGuard private key "+
			"and every preshared key in cleartext",
			errUntrustedHelperPeer, kind, path, cred.Uid, cred.Pid, self)
	}
	return nil
}

// MaxControlResponseBytes bounds a single helper RESPONSE, mirroring
// MaxControlRequestBytes on the request side.
//
// The architecture doc's "Both sides therefore bound a single request" was
// accurate and incomplete: the response direction had a DEADLINE and no byte
// cap. Over AF_UNIX a 3 s deadline still admits GB-scale allocation at memory
// bandwidth, and ControlResponse carries four unbounded slice fields
// (SessionDeltas, IdleLeases, DisplayLeases, SessionCounters) whose contents are
// RETAINED after the decode rather than transiently buffered.
//
// Sized at the request ceiling rather than something smaller because the same
// dimensions that make a request large (feed-scale address books, whole-table
// lease exports) make a legitimate response large, and a cap that rejects a
// legitimate answer is a self-inflicted outage. What it removes is the
// UNBOUNDED case, not headroom.
const MaxControlResponseBytes = MaxControlRequestBytes

// boundedResponseReader wraps a helper connection so a decode cannot allocate
// past MaxControlResponseBytes no matter how long the peer streams, and RECORDS
// whether the cap was the thing that ended the read.
//
// #9322 corrected the premise this used to rest on. The original comment said
// the cap "being reached at all is not a reachable state for the real helper (it
// is bounded by the same MaxControlRequestBytes ceiling on what it can be asked
// to produce), so the case this discriminates is a hostile peer" — and therefore
// that a truncation and a mid-write death were not worth telling apart.
//
// THAT PREMISE IS FALSE, and the counter-example is an ordinary HA path.
// MaxControlRequestBytes bounds what can be ASKED; it says nothing about the
// answer. `export_owner_rg_sessions` is asked with a ~60-byte request and
// answered with the UNBOUNDED owner-RG session set: the Go callers pass max=0
// deliberately (daemon_ha_userspace_export.go — "a capped export would silently
// truncate the window and delete the remainder on the peer"), the helper honours
// it (`remaining = if self.max == 0 { usize::MAX }`, afxdp/ha/export.rs), and one
// worker alone can hold DEFAULT_MAX_SESSIONS = 131072 live sessions. The
// response side was unbounded on both sides while the reader capped it at the
// REQUEST ceiling.
//
// So the two cases must be told apart, because they send the operator to
// different places: a mid-write death is a helper fault to be found in the
// helper log, and a truncation is OUR cap refusing the helper's legitimate
// answer, which no helper log will ever mention. Whether the cap is the RIGHT
// SIZE for that answer is a separate question, tracked separately; this type
// only makes the difference nameable.
// controlResponseCapBytes is the cap boundedResponseReader enforces and
// responseCapError names. It always equals MaxControlResponseBytes. It is a
// package var, not the const, ONLY so the #9322 socket cells can shrink it
// (#9697). Reaching a 64 MiB cap means receiving and decoding 64 MiB of JSON,
// and under load that outran the round-trip deadline, so the cells reported
// the deadline instead of the cap. Nothing in production mutates it, and
// TestResponseCapSeamDefaultsToTheConst9697 pins the default. This is the same
// seam shape as sessionSyncRoundtripDeadline.
var controlResponseCapBytes int64 = MaxControlResponseBytes

func boundedResponseReader(r io.Reader) *limitedResponseReader {
	return &limitedResponseReader{r: r, remaining: controlResponseCapBytes}
}

// limitedResponseReader is io.LimitReader plus a truncated flag.
//
// `io.LimitReader` reports the cap as a plain io.EOF, which json.Decoder turns
// into io.ErrUnexpectedEOF for a partial body — byte-identical to a peer that
// died mid-write, which is exactly the conflation #9322 is about.
type limitedResponseReader struct {
	r         io.Reader
	remaining int64
	// truncated is set only when the underlying reader still had data at the
	// moment the budget ran out. That distinction is not pedantry: a response
	// that ends EXACTLY at the cap is complete, and reporting it as truncated
	// would be the same class of wrong diagnostic in the other direction.
	truncated bool
}

func (l *limitedResponseReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		// Budget exhausted. One-byte probe to tell "the body ended exactly at
		// the cap" (complete) from "the body is larger than the cap"
		// (truncated). The probed byte is discarded — the caller is failing
		// either way — so this costs one read, on an error path only.
		var probe [1]byte
		if n, err := l.r.Read(probe[:]); n > 0 || (err != nil && !errors.Is(err, io.EOF)) {
			l.truncated = true
		}
		return 0, io.EOF
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// responseCapError wraps a decode failure that was caused by
// MaxControlResponseBytes rather than by the helper.
//
// It NAMES the cap, the verb and the byte ceiling, because the sentence it
// replaces ("the helper rejected it before replying — check the helper log")
// names the wrong component: there is nothing in the helper log to find, the
// helper answered, and the answer did not fit. Per docs/engineering-style.md a
// wrong diagnostic is worse than a missing one.
func responseCapError(verb string, err error) error {
	return fmt.Errorf(
		"helper response to %q request exceeded the %d-byte control-response cap "+
			"(MaxControlResponseBytes) and was truncated; the helper ANSWERED and "+
			"the answer did not fit — this is not a helper rejection and the helper "+
			"log will not mention it: %w",
		verb, controlResponseCapBytes, err)
}
