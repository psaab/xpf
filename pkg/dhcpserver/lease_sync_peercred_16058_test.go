package dhcpserver

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #16058: the Kea lease-sync client must verify SO_PEERCRED (expected
// _kea/daemon uid) on connect. A squatter that won the control-socket
// pathname must be refused before a single command byte is written, so
// it can neither feed fabricated leases into HA lease sync nor receive
// lease-add commands. Pre-fix the client bare-dialed the pathname and
// consumed squatter data.
//
// The hostile arm cannot be exercised end-to-end by a non-root test
// binary — it cannot manufacture a connection from a foreign uid — so,
// following the #9003 shape, the DECISION is a pure function of the
// peer uid (hostile values supplied directly, with the daemon euid
// stated explicitly so the cells are deterministic as any user) and
// the syscall SHELL is proved separately against a real socket held
// by this process.

// pinKeaPeerResolver overrides the expected-Kea-uid seam for one test.
func pinKeaPeerResolver(t *testing.T, uid int, ok bool) {
	t.Helper()
	orig := keaPeerUIDResolver
	keaPeerUIDResolver = func() (int, bool) { return uid, ok }
	t.Cleanup(func() { keaPeerUIDResolver = orig })
}

func TestKeaPeerTrustDecision16058(t *testing.T) {
	const (
		keaUID     = 4242 // the resolved _kea uid
		daemonUID  = 0    // xpfd, root in production
		squatterID = 9999 // a foreign local user that won the pathname
	)
	pinKeaPeerResolver(t, keaUID, true)

	for _, tc := range []struct {
		name    string
		peerUID int
		wantErr bool
	}{
		{"kea runtime uid admitted", keaUID, false},
		{"daemon uid admitted (production xpfd, root)", daemonUID, false},
		{"root admitted (Kea packaged to run as root)", 0, false},
		{"foreign uid refused (the squatter)", squatterID, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := keaPeerTrustErrorAs("/run/kea/kea4-ctrl-socket", tc.peerUID, daemonUID)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("keaPeerTrustErrorAs(peer=%d) = nil, want a refusal — this is the squatter whose fabricated leases HA sync would consume", tc.peerUID)
				}
				if !errors.Is(err, errUntrustedKeaPeer) {
					t.Fatalf("refusal does not match errUntrustedKeaPeer: %v", err)
				}
				if !strings.Contains(err.Error(), "uid 9999") {
					t.Fatalf("refusal = %q, want it to name the peer uid", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("keaPeerTrustErrorAs(peer=%d) = %v, want nil", tc.peerUID, err)
			}
		})
	}
}

// When neither Kea user resolves (dev host / Kea not installed), the
// trusted set collapses to the daemon alone: a foreign uid is still
// refused, never waved through on an unresolved lookup.
func TestKeaPeerTrustNoKeaUser16058(t *testing.T) {
	pinKeaPeerResolver(t, 0, false)
	if err := keaPeerTrustErrorAs("/s", 9999, 1000); !errors.Is(err, errUntrustedKeaPeer) {
		t.Fatalf("foreign uid with no Kea user resolved = %v, want errUntrustedKeaPeer", err)
	}
	if err := keaPeerTrustErrorAs("/s", 1000, 1000); err != nil {
		t.Fatalf("daemon uid with no Kea user resolved = %v, want nil", err)
	}
}

// The syscall shell must read the credential from the kernel, not a
// placeholder: a zeroed Ucred has Uid 0, so a shell that swallowed its
// error could fabricate a "root" credential. Reading a real
// connection held by this process must return this process's uid
// (a zero value cannot, on a non-root test host), and the production
// dialer must admit that same-process peer end to end.
func TestKeaPeerUIDReadFromKernel16058(t *testing.T) {
	// Pin the expected Kea uid to this process, so the stub below is
	// admitted by the Kea arm as well as the daemon arm.
	pinKeaPeerResolver(t, os.Geteuid(), true)
	sock := tmpSocket(t, "probe.sock")
	ln, err := net.Listen("unix", sock)
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

	conn, err := defaultKeaDialer(context.Background(), sock)
	if err != nil {
		t.Fatalf("defaultKeaDialer to a socket held by this process = %v, want admitted", err)
	}
	defer conn.Close()

	uid, err := readKeaPeerUID(sock, conn)
	if err != nil {
		t.Fatalf("readKeaPeerUID = %v", err)
	}
	if uid != os.Geteuid() {
		t.Fatalf("peer uid = %d, want this process's euid (%d) — the credential is not being read from the kernel", uid, os.Geteuid())
	}
	if err := verifyKeaPeer(sock, conn); err != nil {
		t.Fatalf("verifyKeaPeer(same-process peer) = %v, want nil", err)
	}
}

// A connection that cannot present credentials (not AF_UNIX) is
// refused, never defaulted: defaulting would fabricate a credential
// the kernel never issued, the exact fail-open the shell exists to
// prevent.
func TestKeaPeerUIDReadFailsClosed16058(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, err := readKeaPeerUID("/s", client); !errors.Is(err, errUntrustedKeaPeer) {
		t.Fatalf("readKeaPeerUID(net.Pipe) = %v, want errUntrustedKeaPeer", err)
	}
	if err := verifyKeaPeer("/s", client); !errors.Is(err, errUntrustedKeaPeer) {
		t.Fatalf("verifyKeaPeer(net.Pipe) = %v, want errUntrustedKeaPeer", err)
	}

	// A failed SO_PEERCRED read must surface, never fall through as a
	// zero Ucred (Uid 0 == root == accepted).
	sock := tmpSocket(t, "failclosed.sock")
	ln, err := net.Listen("unix", sock)
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
	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	boom := errors.New("peercred read boom")
	orig := keaGetsockoptUcred
	keaGetsockoptUcred = func(int, int, int) (*unix.Ucred, error) { return nil, boom }
	t.Cleanup(func() { keaGetsockoptUcred = orig })
	if err := verifyKeaPeer(sock, conn); !errors.Is(err, errUntrustedKeaPeer) {
		t.Fatalf("failed peercred read = %v, want fail-closed sentinel refusal", err)
	}
}

// The decisive regression check from the issue: point the client at a
// squatter socket → it must refuse on peer-cred and sync zero leases
// from it.
//
// The squatter is a stub server offering a fabricated lease
// (10.0.61.99). Its real kernel credential is this process's uid,
// which production would admit (the daemon/test arm), so — exactly as
// in the #16052 shape, because a test binary cannot manufacture a
// connection from a foreign uid — the cell substitutes the peer
// decision defaultKeaDialer applies (keaPeerVerify) with one that
// judges a supplied foreign credential: Kea is the pinned uid 4242,
// the daemon is root, and the peer is uid 9999, foreign on both arms.
// That makes the refusal deterministic whatever uid the test binary
// itself runs as, including root and 4242. The dial, the refusal, the
// zero-command record and the fallback read are all real; only the
// credential value is supplied, as in the decision-table cells.
//
// The memfile fallback is an isolated fixture holding one known
// legitimate lease (10.0.61.70), never the host default Kea path, so
// the result proves both halves: zero leases synced from the squatter
// AND the fallback returning exactly its own row.
//
// RED on the bare-dial mutant: removing the keaPeerVerify call in
// defaultKeaDialer makes the get-all reach the squatter, which records
// the command and returns the fabricated lease → both assertions fail.
func TestSquatterRefusedAndSyncsZeroLeases16058(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	pinKeaPeerResolver(t, 4242, true)

	origVerify := keaPeerVerify
	keaPeerVerify = func(socketPath string, conn net.Conn) error {
		if _, err := readKeaPeerUID(socketPath, conn); err != nil {
			return err
		}
		// Judge the supplied foreign credential as production judges
		// a squatter: daemon is root (0), Kea is the pinned 4242, and
		// uid 9999 is neither — for any test-binary uid.
		return keaPeerTrustErrorAs(socketPath, 9999, 0)
	}
	t.Cleanup(func() { keaPeerVerify = origVerify })

	sock := tmpSocket(t, "squat.sock")
	stub := &stubKea{handler: func(cmd keaCommand) keaResponse {
		return leaseGetAllResponse([]keaLeaseJSON{{
			IPAddress: "10.0.61.99", HWAddress: "aa:bb:cc:dd:ee:99",
			ClientID: "01:aa:bb:cc:dd:ee:99", SubnetID: 1,
			ValidLft: 3600, CLTT: now.Unix(), State: keaStateDefault,
			Hostname: "squatter",
		}})
	}}
	_, stop := startStubKea(t, sock, stub)
	defer stop()

	// Isolated memfile fixture: one known legitimate lease.
	dir := t.TempDir()
	memfile := filepath.Join(dir, "kea-leases4.csv")
	expire := now.Unix() + 1800
	csv := "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n" +
		"10.0.61.70,aa:bb:cc:dd:ee:70,01:aa:bb:cc:dd:ee:70,3600," +
		strconv.FormatInt(expire, 10) + ",2,0,0,host-mem,0\n"
	if err := os.WriteFile(memfile, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}

	// nil dialer → the production defaultKeaDialer path, exactly what
	// a Manager with no test seams uses.
	m := New()
	m.SetLeaseSyncSeamsForTesting(nil, sock, "", memfile, "")
	leases, err := m.GetSyncLeases4(context.Background(), now)
	if err != nil {
		t.Fatalf("GetSyncLeases4 against a squatter = %v, want isolated-memfile fallback success", err)
	}
	if len(leases) != 1 || leases[0].Address != "10.0.61.70" {
		t.Fatalf("synced leases = %+v, want exactly the isolated memfile lease 10.0.61.70 and zero from the squatter", leases)
	}
	if seen := stub.seen(); len(seen) != 0 {
		t.Fatalf("squatter received %d commands, want 0 (refusal precedes any write)", len(seen))
	}
}

// Readiness must not report an unverifiable peer as Kea-ready: with a
// custom dialer, waitControlSocket re-verifies the peer, and a
// connection that cannot present credentials (net.Pipe) can never be
// verified, so readiness stays false. Pre-fix, any successful dial
// meant ready.
func TestWaitControlSocketRefusesUnverifiablePeer16058(t *testing.T) {
	m := New()
	sock := tmpSocket(t, "wait.sock")
	m.SetLeaseSyncSeamsForTesting(func(context.Context, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { _ = server.Close() }()
		return client, nil
	}, sock, "", "", "")
	if m.WaitControlSocket4(context.Background(), 300*time.Millisecond) {
		t.Fatal("WaitControlSocket4 reported an unverifiable peer ready, want false")
	}
}
