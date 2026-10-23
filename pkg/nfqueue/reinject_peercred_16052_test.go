package nfqueue

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// #16052: the reinject client dialed both helper sockets with a bare
// net.DialTimeout and never checked SO_PEERCRED. A squatter listening on
// the socket path in a non-default (operator-selected, writable/sticky)
// socket dir received ANNOUNCE plus decrypted IPsec-inner payloads, and
// could return spoofed completions the client reported as success while
// every packet was dropped. The client must verify the peer (root or
// the daemon's own uid) immediately after connect, before ANNOUNCE.

func foreignReinjectUID16052(self uint32) uint32 {
	foreign := uint32(4242)
	if foreign == self {
		foreign = 4243
	}
	return foreign
}

func TestReinjectPeerTrustError16052(t *testing.T) {
	self := uint32(os.Geteuid())
	foreign := foreignReinjectUID16052(self)

	if err := reinjectPeerTrustError16052("/tmp-style/submit.sock", &unix.Ucred{Uid: 0, Pid: 7}, self); err != nil {
		t.Fatalf("root peer refused: %v", err)
	}
	if err := reinjectPeerTrustError16052("/tmp-style/submit.sock", &unix.Ucred{Uid: self, Pid: 7}, self); err != nil {
		t.Fatalf("own-uid peer refused: %v", err)
	}
	err := reinjectPeerTrustError16052("/tmp-style/submit.sock", &unix.Ucred{Uid: foreign, Pid: 99}, self)
	if err == nil {
		t.Fatal("foreign peer accepted, want refusal — this is the squatter that " +
			"otherwise receives ANNOUNCE and decrypted payloads")
	}
	if !errors.Is(err, errUntrustedReinjectPeer16052) {
		t.Fatalf("refusal does not match errUntrustedReinjectPeer16052: %v", err)
	}
	// A missing credential must never read as root: a zeroed Ucred has
	// Uid 0, so a swallowed SO_PEERCRED read would fail open.
	if err := reinjectPeerTrustError16052("/tmp-style/submit.sock", nil, self); err == nil {
		t.Fatal("nil credential accepted; a missing credential must never read as root")
	} else if !errors.Is(err, errUntrustedReinjectPeer16052) {
		t.Fatalf("nil-credential refusal does not match sentinel: %v", err)
	}
}

func TestReinjectPeerCredReadFailureFailsClosed16052(t *testing.T) {
	// Non-AF_UNIX connection: the peer cannot be identified at all.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	if err := verifyReinjectPeer16052("/tmp-style/submit.sock", clientConn); !errors.Is(err, errUntrustedReinjectPeer16052) {
		t.Fatalf("non-unix peer verify = %v, want errUntrustedReinjectPeer16052", err)
	}

	// A failed SO_PEERCRED read must surface, never fall through as a
	// zero Ucred (Uid 0 == root == accepted).
	dir := t.TempDir()
	path := filepath.Join(dir, "submit.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	serverSide := <-accepted
	defer serverSide.Close()

	boom := errors.New("peercred read boom")
	orig := reinjectGetsockoptUcred16052
	reinjectGetsockoptUcred16052 = func(int, int, int) (*unix.Ucred, error) {
		return nil, boom
	}
	t.Cleanup(func() { reinjectGetsockoptUcred16052 = orig })
	if err := verifyReinjectPeer16052(path, conn); !errors.Is(err, errUntrustedReinjectPeer16052) {
		t.Fatalf("failed peercred read = %v, want fail-closed sentinel refusal", err)
	}
}

// squatter16052 accepts connections, records every byte it receives,
// and reports the per-connection byte count when the peer hangs up.
type squatter16052 struct {
	listener net.Listener
	bytes    chan int
}

func startSquatter16052(t *testing.T, path string) *squatter16052 {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("squatter listen %s: %v", path, err)
	}
	s := &squatter16052{listener: listener, bytes: make(chan int, 8)}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				data, _ := io.ReadAll(conn)
				s.bytes <- len(data)
			}(conn)
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return s
}

func (s *squatter16052) expectZeroBytes16052(t *testing.T, what string) {
	t.Helper()
	select {
	case n := <-s.bytes:
		if n != 0 {
			t.Fatalf("squatter received %d bytes on %s, want zero (peer must be refused before any byte is written)", n, what)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("squatter saw no hangup on %s; client did not close the refused connection", what)
	}
}

func TestReinjectSquatterSeesZeroBytes16052(t *testing.T) {
	dir := t.TempDir()
	submitPath := filepath.Join(dir, "reinject-submit.sock")
	completePath := filepath.Join(dir, "reinject-complete.sock")
	submitSquatter := startSquatter16052(t, submitPath)
	completeSquatter := startSquatter16052(t, completePath)

	self := uint32(os.Geteuid())
	foreign := foreignReinjectUID16052(self)
	client := &SocketReinjectSubmitter{
		submitPath:   submitPath,
		completePath: completePath,
		timeout:      time.Second,
		peerVerify: func(path string, conn net.Conn) error {
			return reinjectPeerTrustError16052(path, &unix.Ucred{Uid: foreign, Pid: 99}, self)
		},
	}

	// ANNOUNCE arm: the authority frame must never reach the squatter.
	if err := client.AnnounceReinject("test-run", 9, 7, true, []ReinjectQueueEpoch{{Queue: 12, Epoch: 31}}); !errors.Is(err, errUntrustedReinjectPeer16052) {
		t.Fatalf("announce to squatter = %v, want peer refusal", err)
	}
	submitSquatter.expectZeroBytes16052(t, "submit (announce)")

	// SUBMIT arm: decrypted payloads must never reach the squatter.
	frame := AdjudicatedFrame{
		Frame: CaptureFrame{
			Packet:  pipelineTestPacket(77, 2, 2, 7, 41),
			FlowKey: "flow-41",
		},
		Origin: CaptureOrigin{
			Family: CaptureFamilyInet, Hook: CaptureHookForward,
			Owner: "owner-a", STN: "st0", OwnedIfindex: 7,
		},
		Lease:           ReinjectLease{RequestID: 41, PermitEpoch: 5, QueueNumber: 77, QueueEpoch: 9},
		DeadlineMonoNS:  0x0102030405060708,
		DeadlineClockID: reinjectDeadlineClockMonotonic,
	}
	if _, err := client.SubmitAdjudicated([]AdjudicatedFrame{frame}); !errors.Is(err, errUntrustedReinjectPeer16052) {
		t.Fatalf("submit to squatter = %v, want peer refusal (no lying success)", err)
	}
	submitSquatter.expectZeroBytes16052(t, "submit (payload)")

	// COMPLETE arm: spoofed completions must never be solicited.
	if _, err := client.DrainReinjectCompletions(1); !errors.Is(err, errUntrustedReinjectPeer16052) {
		t.Fatalf("complete drain from squatter = %v, want peer refusal", err)
	}
	completeSquatter.expectZeroBytes16052(t, "complete")

	if client.submit != nil || client.complete != nil {
		t.Fatalf("refused connections retained (submit=%v complete=%v), want both nil", client.submit, client.complete)
	}
}

func TestReinjectTrustedPeerAccepted16052(t *testing.T) {
	// A same-uid (in production: root) helper is accepted and the
	// ANNOUNCE frame flows — the guard must not brick the real helper.
	dir := t.TempDir()
	submitPath := filepath.Join(dir, "reinject-submit.sock")
	listener, err := net.Listen("unix", submitPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	announced := make(chan byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		typ, _, err := readReinjectMessage(conn)
		if err == nil {
			announced <- typ
		}
	}()

	client, err := NewSocketReinjectSubmitter(submitPath, filepath.Join(dir, "unused-complete.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.AnnounceReinject("test-run", 9, 7, true, []ReinjectQueueEpoch{{Queue: 12, Epoch: 31}}); err != nil {
		t.Fatalf("announce to trusted helper: %v", err)
	}
	select {
	case typ := <-announced:
		if typ != reinjectMsgAnnounce {
			t.Fatalf("helper received type %d, want ANNOUNCE (%d)", typ, reinjectMsgAnnounce)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("trusted helper received no ANNOUNCE frame")
	}
	// The real peer credential of a same-process socket reads back as
	// this process's euid.
	if err := verifyReinjectPeer16052(submitPath, client.submit); err != nil {
		t.Fatalf("verifyReinjectPeer16052 on trusted connection: %v", err)
	}
}
