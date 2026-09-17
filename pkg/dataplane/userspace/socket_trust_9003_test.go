package userspace

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
)

// socket_trust_9003_test.go pins the four properties #9003 is about, and each
// cell is written so that reverting the production change it guards reds it.
//
// The shape that made #9003 survive review is worth naming: EVERY individual
// piece looked defensible. `os.MkdirAll(dir, 0755)` is the idiom. `os.TempDir()`
// is the idiom for "a scratch path". A Unix socket's mode does gate connect. The
// shipped reference configs do pin a safe path. What nothing asserted was the
// COMPOSITION — that the compiled-in default landed inside a world-writable
// directory, that MkdirAll adopts, and that nothing on either end ever asked who
// the peer was.

func TestDefaultHelperPathsAreNotInATempDirectory9003(t *testing.T) {
	cfg := deriveUserspaceConfig(nil)

	// The DEFAULT is the subject. A deployment that omits
	// `set system dataplane control-socket` takes this path, and before #9003 it
	// was ${TMPDIR}/xpf-userspace-dp/control.sock.
	for _, tc := range []struct {
		what string
		got  string
		want string
	}{
		{"control socket", cfg.ControlSocket, DefaultControlSocket},
		{"state file", cfg.StateFile, DefaultStateFile},
		{"event socket", cfg.EventSocket, DefaultRuntimeDir + "/userspace-dp-events.sock"},
	} {
		if tc.got != tc.want {
			t.Errorf("default %s = %q, want %q", tc.what, tc.got, tc.want)
		}
		if !strings.HasPrefix(tc.got, DefaultRuntimeDir+"/") {
			t.Errorf("default %s = %q, which is not under the root-owned runtime directory %q",
				tc.what, tc.got, DefaultRuntimeDir)
		}
		// The specific pre-#9003 shape, named so a revert cannot pass by
		// landing on some OTHER world-writable location.
		if strings.HasPrefix(tc.got, os.TempDir()+string(os.PathSeparator)) {
			t.Errorf("default %s = %q is under the temp directory %q — that is the #9003 defect: "+
				"xpfd creates the subdirectory with MkdirAll, which ADOPTS one an unprivileged "+
				"local user created first", tc.what, tc.got, os.TempDir())
		}
	}

	// POSITIVE CONTROL. Without this the cell above is satisfied by a
	// deriveUserspaceConfig that ignores its argument and returns constants, so
	// it would not notice the resolver being broken — only the constant being
	// changed. An operator-set path must still win.
	custom := deriveUserspaceConfig(&config.Config{
		System: config.SystemConfig{
			UserspaceDataplane: &config.UserspaceConfig{
				ControlSocket: "/run/somewhere-else/dp.sock",
			},
		},
	})
	if custom.ControlSocket != "/run/somewhere-else/dp.sock" {
		t.Fatalf("operator-set control socket = %q, want it honoured over the default", custom.ControlSocket)
	}
	if custom.EventSocket != "/run/somewhere-else/userspace-dp-events.sock" {
		t.Fatalf("event socket derived from an operator-set control socket = %q, want it beside it",
			custom.EventSocket)
	}
}

// TestRuntimeDirTrustDecision9003 drives every arm of the decision the
// MkdirAll-and-assume code never made.
func TestRuntimeDirTrustDecision9003(t *testing.T) {
	const self = 1000
	const selfGid = 1000
	for _, tc := range []struct {
		name    string
		uid     uint32
		gid     uint32
		mode    uint32
		wantSub string
	}{
		{"root-owned 0750 is trusted", 0, 0, unix.S_IFDIR | 0o750, ""},
		{"own-uid 0700 is trusted (a non-root test binary)", self, selfGid, unix.S_IFDIR | 0o700, ""},
		{"root-owned 0755 is trusted", 0, 0, unix.S_IFDIR | 0o755, ""},
		{"sticky world-writable root-owned is trusted (/tmp itself)", 0, 0, unix.S_IFDIR | unix.S_ISVTX | 0o777, ""},
		// THE #9003 CASE. The attacker won the mkdir race, so they own it.
		{"foreign-owned is refused", 4242, 0, unix.S_IFDIR | 0o755, "owned by uid 4242"},
		// The other half: ours, but anyone may write it.
		{"world-writable without sticky is refused", 0, 0, unix.S_IFDIR | 0o777, "world-writable without the sticky bit"},
		{"foreign-owned AND world-writable is refused by ownership first", 4242, 0, unix.S_IFDIR | 0o777, "owned by uid 4242"},

		// #9171 — THE GROUP-WRITABLE ARM. This check tested S_IWOTH only, so a
		// root-owned but group-writable directory passed, and every member of
		// that group could unlink the socket and bind their own.
		//
		// It is the half that made a SECOND bounded finding reachable: the
		// helper's event-socket CLIENT has no peer verification, dismissed as
		// needing "write access to a root-owned directory, i.e. root already".
		// Group-write is exactly where that premise fails.
		{"root-owned but group-writable by a FOREIGN group is refused", 0, 4242, unix.S_IFDIR | 0o770, "group-writable"},
		{"group-writable and world-writable is refused by the world arm first", 0, 4242, unix.S_IFDIR | 0o777, "world-writable without the sticky bit"},
		// EXEMPTIONS, mirroring the uid arm directly above.
		{"group-writable by ROOT group is trusted", 0, 0, unix.S_IFDIR | 0o770, ""},
		{"group-writable by the daemon's OWN group is trusted", 0, selfGid, unix.S_IFDIR | 0o770, ""},
		{"sticky group-writable is trusted", 0, 4242, unix.S_IFDIR | unix.S_ISVTX | 0o770, ""},
		// NARROWNESS: group-READABLE is not group-writable.
		{"group-readable only is trusted", 0, 4242, unix.S_IFDIR | 0o750, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runtimeDirTrustError("control socket", "/somewhere", tc.uid, tc.gid, tc.mode, self, selfGid)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("runtimeDirTrustError(uid=%d, mode=%04o) = %v, want trusted", tc.uid, tc.mode&0o7777, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("runtimeDirTrustError(uid=%d, mode=%04o) = nil, want a refusal", tc.uid, tc.mode&0o7777)
			}
			if !errors.Is(err, errUntrustedRuntimeDir) {
				t.Fatalf("refusal does not match errUntrustedRuntimeDir: %v", err)
			}
			// Assert the MESSAGE, not merely the failure: a refusal produced by
			// the wrong arm reads exactly like a working guard.
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("refusal = %q, want it to name %q", err, tc.wantSub)
			}
		})
	}
}

// TestEnsureTrustedRuntimeDirEndToEnd9003 proves the syscall shell actually
// reads the directory — the decision table above is inert if the stat is wrong.
func TestEnsureTrustedRuntimeDirEndToEnd9003(t *testing.T) {
	base := t.TempDir()

	t.Run("creates a directory that is then trusted", func(t *testing.T) {
		dir := filepath.Join(base, "created")
		if err := ensureTrustedRuntimeDir("control socket", dir); err != nil {
			t.Fatalf("ensureTrustedRuntimeDir on a fresh directory = %v, want nil", err)
		}
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o007 != 0 {
			t.Fatalf("created runtime directory mode = %04o, want no world bits", st.Mode().Perm())
		}
	})

	t.Run("refuses a pre-existing world-writable directory", func(t *testing.T) {
		// This is the observable half of the #9003 adoption case that a
		// non-root binary CAN construct: a directory that already exists and
		// that any local user may write. MkdirAll returns nil for it.
		dir := filepath.Join(base, "adopted")
		if err := os.Mkdir(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil { // defeat the umask
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("precondition: MkdirAll on the pre-existing directory = %v, want nil "+
				"(this is what made adoption silent)", err)
		}
		err := ensureTrustedRuntimeDir("control socket", dir)
		if err == nil {
			t.Fatal("ensureTrustedRuntimeDir adopted a world-writable directory, want a refusal")
		}
		if !errors.Is(err, errUntrustedRuntimeDir) {
			t.Fatalf("refusal does not match errUntrustedRuntimeDir: %v", err)
		}
	})

	t.Run("refuses a directory under a swappable ancestor", func(t *testing.T) {
		// The leaf's own mode is fine; the ancestor is world-writable and NOT
		// sticky, so any local user can rename the leaf aside and substitute
		// their own. Checking only the leaf misses this entirely.
		parent := filepath.Join(base, "swappable")
		if err := os.Mkdir(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(parent, "leaf")
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		err := ensureTrustedRuntimeDir("control socket", dir)
		if err == nil {
			t.Fatal("ensureTrustedRuntimeDir accepted a directory under a world-writable non-sticky " +
				"ancestor, want a refusal")
		}
		if !strings.Contains(err.Error(), "ancestor") {
			t.Fatalf("refusal = %q, want it to name the ancestor", err)
		}
	})

	t.Run("accepts a sticky world-writable ancestor", func(t *testing.T) {
		// NEGATIVE CONTROL for the ancestor walk, and the reason this change
		// does not brick a deployment that committed `control-socket
		// /tmp/xpf.sock`: /tmp is 1777, i.e. world-writable AND sticky, so a
		// non-owner cannot rename our directory aside.
		parent := filepath.Join(base, "sticky")
		if err := os.Mkdir(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(parent, "leaf")
		if err := ensureTrustedRuntimeDir("control socket", dir); err != nil {
			t.Fatalf("ensureTrustedRuntimeDir under a STICKY world-writable ancestor = %v, want nil "+
				"(this is /tmp, and refusing it would brick a working deployment)", err)
		}
	})
}

// TestPeerCredentialTrustDecision9003 covers the arms of the peer check.
func TestPeerCredentialTrustDecision9003(t *testing.T) {
	const self = 1000
	if err := peerCredTrustError("control socket", "/s", &unix.Ucred{Uid: 0, Pid: 7}, self); err != nil {
		t.Fatalf("root peer refused: %v", err)
	}
	if err := peerCredTrustError("control socket", "/s", &unix.Ucred{Uid: self, Pid: 7}, self); err != nil {
		t.Fatalf("own-uid peer refused: %v", err)
	}
	err := peerCredTrustError("control socket", "/s", &unix.Ucred{Uid: 4242, Pid: 99}, self)
	if err == nil {
		t.Fatal("peerCredTrustError(uid=4242) = nil, want a refusal — this is the squatter that " +
			"otherwise receives the WireGuard private key")
	}
	if !errors.Is(err, errUntrustedHelperPeer) {
		t.Fatalf("refusal does not match errUntrustedHelperPeer: %v", err)
	}
	for _, want := range []string{"uid 4242", "pid 99"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal = %q, want it to name %q", err, want)
		}
	}
	if err := peerCredTrustError("control socket", "/s", nil, self); err == nil {
		t.Fatal("peerCredTrustError(nil cred) = nil; a missing credential must never read as root")
	}
}

// TestPeerCredentialIsActuallyReadFromTheKernel9003 is the positive control for
// the syscall shell.
//
// It matters more than it looks. A zeroed unix.Ucred has Uid 0, and uid 0 is
// exactly what peerCredTrustError ACCEPTS — so a getsockopt whose failure was
// swallowed, or a shell that returned a zero value, would turn this whole guard
// into a fail-open and every decision-table cell above would still be green.
// This cell reads a real credential off a real connection and asserts it carries
// THIS process's identity, which a zero value cannot.
func TestPeerCredentialIsActuallyReadFromTheKernel9003(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	conn, err := dialTrustedHelperSocket("control socket", path, time.Second)
	if err != nil {
		t.Fatalf("dialTrustedHelperSocket to a socket held by this process = %v, want it accepted", err)
	}
	defer conn.Close()

	cred, err := readUnixPeerCred("control socket", path, conn)
	if err != nil {
		t.Fatalf("readUnixPeerCred = %v", err)
	}
	if cred.Pid != int32(os.Getpid()) {
		t.Fatalf("peer pid = %d, want this process (%d) — the credential is not being read from "+
			"the kernel, so the uid arm is comparing a placeholder", cred.Pid, os.Getpid())
	}
	if cred.Uid != uint32(os.Geteuid()) {
		t.Fatalf("peer uid = %d, want this process's euid (%d)", cred.Uid, os.Geteuid())
	}
}

// TestPeerCredentialReadFailsClosed9003 covers the shell's failure arms, and
// the reason they need their own cell is the direction they fail in.
//
// A zeroed unix.Ucred has Uid 0, and uid 0 is precisely what
// peerCredTrustError ACCEPTS. So any failure in the read that ends in a zero
// value rather than an error converts the whole guard into a fail-OPEN, and
// every decision-table cell stays green while it does. The read must therefore
// have no path that yields a credential it did not actually obtain.
func TestPeerCredentialReadFailsClosed9003(t *testing.T) {
	t.Run("a non-AF_UNIX connection is refused, not defaulted", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			if c, err := ln.Accept(); err == nil {
				defer c.Close()
				time.Sleep(50 * time.Millisecond)
			}
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		cred, err := readUnixPeerCred("control socket", "tcp", conn)
		if err == nil {
			t.Fatalf("readUnixPeerCred over TCP returned cred=%+v and no error; a connection whose "+
				"peer cannot be identified must never be treated as root", cred)
		}
		if !errors.Is(err, errUntrustedHelperPeer) {
			t.Fatalf("refusal does not match errUntrustedHelperPeer: %v", err)
		}
	})

	t.Run("a closed connection is refused, not defaulted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "closed.sock")
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			if c, err := ln.Accept(); err == nil {
				defer c.Close()
				time.Sleep(50 * time.Millisecond)
			}
		}()
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		cred, err := readUnixPeerCred("control socket", path, conn)
		if err == nil {
			t.Fatalf("readUnixPeerCred on a CLOSED connection returned cred=%+v and no error", cred)
		}
	})
}

// TestHelperResponseDecodeIsByteBounded9003 pins the cap itself.
func TestHelperResponseDecodeIsByteBounded9003(t *testing.T) {
	// An endless stream, which is what a squatter supplies. Before #9003 the
	// decode was deadline-bounded and byte-unbounded: over AF_UNIX a 3s deadline
	// admits GB-scale allocation, and ControlResponse RETAINS four unbounded
	// slice fields.
	n, err := io.Copy(io.Discard, boundedResponseReader(endlessReader{}))
	if err != nil {
		t.Fatalf("io.Copy over the bounded reader = %v", err)
	}
	if n != MaxControlResponseBytes {
		t.Fatalf("bounded reader yielded %d bytes, want exactly the %d-byte cap", n, MaxControlResponseBytes)
	}

	// And the decoder built on it must FAIL rather than complete, on a body that
	// never terminates.
	dec := json.NewDecoder(boundedResponseReader(io.MultiReader(
		strings.NewReader(`{"ok":true,"error":"`),
		endlessReader{filler: 'a'},
	)))
	var resp ControlResponse
	if err := dec.Decode(&resp); err == nil {
		t.Fatal("decode of an unterminated response succeeded; the cap is not reached")
	}
}

type endlessReader struct{ filler byte }

func (e endlessReader) Read(p []byte) (int, error) {
	f := e.filler
	if f == 0 {
		f = ' '
	}
	for i := range p {
		p[i] = f
	}
	return len(p), nil
}

// TestEveryHelperResponseDecodeIsBounded9003 is the census the issue asks for:
// a decode-cap cell at EACH of the five sites, not one site plus an assumption
// about the rest.
//
// It scans source rather than behaviour because four of the five sites need a
// live helper to reach, and a guard that can only see the one reachable site
// would report a clean board while the other four stayed unbounded — which is
// how the originating report counted three of them and missed the fourth.
func TestEveryHelperResponseDecodeIsBounded9003(t *testing.T) {
	sites := map[string][]string{
		"boot_probe.go":                  {"ProbeStatus"},
		"process_control.go":             {"requestDetailedLocked", "requestSessionSyncLocked", "requestHAWatchdogSessionLockedAtPath"},
		"../../dhcpserver/lease_sync.go": {"keaControl"},
	}
	decodeRe := regexp.MustCompile(`json\.NewDecoder\(([^)]*)`)
	// #9322: a site may now bind the bounded reader to a local first, because
	// the caller has to INSPECT it (`bounded.truncated`) to tell a cap
	// truncation from a helper that died mid-write. Accept such an identifier
	// ONLY when this same file assigns it from boundedResponseReader — the
	// guard still refuses any decoder fed from something it cannot trace to the
	// bound. Matching on the bare word "bounded" would have loosened the census
	// into accepting any variable somebody chose to name that.
	boundRe := regexp.MustCompile(`(\w+)\s*:?=\s*(?:boundedResponseReader|io\.LimitReader)\(`)
	total := 0
	for rel := range sites {
		src, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		boundIdents := map[string]bool{}
		for _, m := range boundRe.FindAllStringSubmatch(string(src), -1) {
			boundIdents[m[1]] = true
		}
		matches := decodeRe.FindAllStringSubmatch(string(src), -1)
		if len(matches) == 0 {
			t.Fatalf("%s: found no json.NewDecoder call at all — this census is matching nothing, "+
				"which reads exactly like a clean board", rel)
		}
		for _, m := range matches {
			total++
			arg := m[1]
			ok := strings.Contains(arg, "boundedResponseReader") || strings.Contains(arg, "io.LimitReader")
			if !ok {
				for ident := range boundIdents {
					if regexp.MustCompile(`\b` + regexp.QuoteMeta(ident) + `\b`).MatchString(arg) {
						ok = true
						break
					}
				}
			}
			if !ok {
				t.Errorf("%s: json.NewDecoder(%s) is byte-unbounded — a hostile peer on this "+
					"socket can stream until the daemon OOMs inside the connection deadline", rel, arg)
			}
		}
	}
	// POSITIVE CONTROL on the census itself: the five sites (four #9003 enumerated
	// plus session HA refresh #9629) must all still be found. A refactor that
	// moves one somewhere this walk does not look would otherwise silently
	// shrink the population to a green.
	if total != 5 {
		t.Fatalf("census matched %d json.NewDecoder sites across the helper/Kea control sockets, want the 5 "+
			"(4 #9003 enumerated + session HA #9629); a different number means the population moved and this guard no longer "+
			"covers what it claims", total)
	}
}

// TestEventStreamSocketIsOwnerOnly9003 is end-to-end: bind the real listener and
// stat the real socket.
//
// Before #9003 the mode was 0777 &^ umask — inherited, and asserted by nothing.
// The originating report's "any local user can read the keys" did not follow
// from what it cited precisely BECAUSE of that inherited umask; a `UMask=0000`
// in the unit converts it to exactly that with no signal anywhere. An unasserted
// umask is not a control, so this asserts the mode instead.
func TestEventStreamSocketIsOwnerOnly9003(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.sock")
	es := NewEventStream(path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := es.Start(ctx); err != nil {
		t.Fatalf("EventStream.Start = %v", err)
	}
	defer es.Close()

	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket (mode %v)", path, st.Mode())
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("event socket mode = %04o, want 0600. The helper control-plane sockets carry the "+
			"WireGuard private key and every preshared key; their mode must not be whatever the "+
			"ambient umask happened to leave", perm)
	}
}

// TestHelperSocketTrustIsWiredAtEveryCallSite9003 binds the WIRING, not the
// helpers.
//
// The decision tables above prove the predicates are right. They are silent
// about whether anything CALLS them, and that is the failure this project keeps
// paying for: a correct guard reachable from no production path is decoration,
// and its unit tests stay green forever. Three of the five sites below cannot be
// driven from a unit test at all (they need a live helper), so the wiring is
// asserted at the source.
func TestHelperSocketTrustIsWiredAtEveryCallSite9003(t *testing.T) {
	read := func(rel string) string {
		src, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(src)
	}

	process := read("process.go")
	// The #9003 defect verbatim. os.MkdirAll returns nil for a pre-existing
	// directory of ANY owner and ANY mode, so "it succeeded" is not "it is
	// mine".
	if strings.Contains(process, "os.MkdirAll(filepath.Dir(cfg.ControlSocket)") ||
		strings.Contains(process, "os.MkdirAll(filepath.Dir(cfg.StateFile)") {
		t.Error("process.go creates a helper runtime directory with a bare os.MkdirAll — " +
			"that ADOPTS a pre-existing directory an unprivileged local user created first")
	}
	for _, want := range []string{
		`ensureTrustedRuntimeDir("control socket", filepath.Dir(cfg.ControlSocket))`,
		`ensureTrustedRuntimeDir("state file", filepath.Dir(cfg.StateFile))`,
	} {
		if !strings.Contains(process, want) {
			t.Errorf("process.go does not call %s; the directory trust check is unreachable "+
				"from the bring-up path it exists to guard", want)
		}
	}

	// Every DIAL of a helper socket must go through the peer check. A bare
	// net.DialTimeout here is the pre-#9003 shape: it hands the WireGuard
	// private key to whoever holds the path.
	for _, rel := range []string{"process_control.go", "boot_probe.go"} {
		src := read(rel)
		if strings.Contains(src, `net.DialTimeout("unix"`) {
			t.Errorf("%s dials a helper socket without verifying the peer (bare net.DialTimeout); "+
				"use dialTrustedHelperSocket", rel)
		}
		if !strings.Contains(src, "dialTrustedHelperSocket(") {
			t.Errorf("%s never calls dialTrustedHelperSocket", rel)
		}
	}

	// The event-stream ACCEPT path installs the connecting process as the event
	// source and closes the previous one, so an unprivileged connect is both a
	// disconnect of the real helper and a way to feed fabricated session events
	// into the control plane.
	events := read("eventstream.go")
	if !strings.Contains(events, `verifyUnixPeerIsPrivileged("event stream socket"`) {
		t.Error("eventstream.go accepts a connection without verifying the peer; an unprivileged " +
			"local process can displace the helper and become the event source")
	}
	if !strings.Contains(events, `os.Chmod(es.socketPath, 0o600)`) {
		t.Error("eventstream.go does not restrict the bound socket's mode; it would keep " +
			"0777 &^ umask, a value nothing in the tree asserts")
	}

	// The SO_PEERCRED read must never substitute a value it did not obtain. This
	// is a source assertion rather than a behavioural one because the arm it
	// guards — getsockopt itself failing on a live AF_UNIX socket — cannot be
	// induced from a hermetic test, and the failure DIRECTION is fail-open: a
	// zeroed unix.Ucred has Uid 0, which peerCredTrustError accepts as root. A
	// swallowed error here is invisible to every other cell in this file.
	trust := read("socket_trust_9003.go")
	shell := trust[strings.Index(trust, "func readUnixPeerCred("):]
	shell = shell[:strings.Index(shell, "\n}\n")]
	if strings.Contains(shell, "&unix.Ucred{") {
		t.Error("readUnixPeerCred constructs a unix.Ucred rather than returning the kernel's; a " +
			"zeroed credential has Uid 0, which the trust decision ACCEPTS as root")
	}
	for _, want := range []string{"if credErr != nil {", "if cred == nil {"} {
		if !strings.Contains(shell, want) {
			t.Errorf("readUnixPeerCred no longer has the %q arm; a failed credential read would "+
				"reach the trust decision as a zero value, i.e. as root", want)
		}
	}

	// POSITIVE CONTROL on this census: prove the reader is looking at real
	// source and not at an empty string, by asserting a stable fact that is true
	// today and unrelated to the change.
	if !strings.Contains(process, "func (m *Manager) ensureProcessLocked(") {
		t.Fatal("census read process.go but did not find ensureProcessLocked — the file this " +
			"guard scans is not the one it thinks it is")
	}
}

// TestHelperDefaultPathsAreInLockstepWithRust9003 pins the two compiled-in
// defaults to each other.
//
// They are not merely cosmetic duplicates. The #1993 boot armed-probe dials the
// path the GO side derived, and a surviving helper is listening on the path the
// RUST side chose. A skew between them makes the probe read "no helper" on a
// deployment that has one — which is the fail-closed direction, but it clears
// FRR on every boot of a default-config box.
func TestHelperDefaultPathsAreInLockstepWithRust9003(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/server/lifecycle.rs")
	if err != nil {
		t.Fatalf("read lifecycle.rs: %v", err)
	}
	find := func(name string) string {
		re := regexp.MustCompile(`(?m)^pub\(crate\) const ` + name + `: &str = "([^"]+)";`)
		m := re.FindStringSubmatch(string(src))
		if m == nil {
			t.Fatalf("lifecycle.rs has no `pub(crate) const %s: &str = ...` — the lockstep this "+
				"guard asserts cannot be read, which is not the same as it holding", name)
		}
		return m[1]
	}
	if got := find("DEFAULT_CONTROL_SOCKET"); got != DefaultControlSocket {
		t.Errorf("Rust DEFAULT_CONTROL_SOCKET = %q, Go DefaultControlSocket = %q", got, DefaultControlSocket)
	}
	if got := find("DEFAULT_STATE_FILE"); got != DefaultStateFile {
		t.Errorf("Rust DEFAULT_STATE_FILE = %q, Go DefaultStateFile = %q", got, DefaultStateFile)
	}
	// The Rust helper must not fall back into a temp directory either.
	if strings.Contains(string(src), `env::temp_dir()
        .join("xpf-userspace-dp")`) {
		t.Error("lifecycle.rs still derives a default helper path from env::temp_dir()")
	}
}

// TestHelperSocketsAreOwnerOnlyInRust9003 pins the helper-side half of the mode
// and peer contract, which no Go test can observe.
func TestHelperSocketsAreOwnerOnlyInRust9003(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/server/lifecycle.rs")
	if err != nil {
		t.Fatalf("read lifecycle.rs: %v", err)
	}
	body := string(src)
	for _, want := range []string{
		"restrict_socket_mode(&args.control_socket)?;",
		"restrict_socket_mode(&session_socket)?;",
		`reject_unprivileged_peer("control socket", &stream)`,
		`reject_unprivileged_peer("session socket", &stream)`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("lifecycle.rs is missing %q — the helper side of the #9003 contract is not wired", want)
		}
	}
	if strings.Contains(body, "fs::create_dir_all(parent).map_err(|e| format!(\"create control dir") {
		t.Error("lifecycle.rs creates the control directory with a mode-less create_dir_all")
	}
}
