package authz

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #14581: the listener-owner attribution the grpcapi supervisor's fatal
// decision and the CLI's server verification both stand on.
//
// The fixtures render real /proc/net/tcp rows. Ports/addresses are
// rendered through procAddr4/procAddr6 — the same code the lookup uses
// to build its keys — so a fixture cannot drift from the key format;
// the UID and state columns, which are the DECISION inputs, are
// written literally.

const listenHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func listenRow(t *testing.T, local *net.TCPAddr, uid int) string {
	t.Helper()
	key, ok := procAddr4(local)
	if !ok {
		key, ok = procAddr6(local)
	}
	if !ok {
		t.Fatalf("cannot render %v", local)
	}
	// st 0A = TCP_LISTEN.
	return fmt.Sprintf("   0: %s 00000000:0000 0A 00000000:00000000 00:00000000 00000000  %4d        0 4242 1 0000000000000000 100 0 0 10 0\n", key, uid)
}

func writeListenTables(t *testing.T, v4, v6 string) {
	t.Helper()
	dir := t.TempDir()
	p4 := filepath.Join(dir, "tcp")
	p6 := filepath.Join(dir, "tcp6")
	if err := os.WriteFile(p4, []byte(v4), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p6, []byte(v6), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(SetProcNetTCPPathsForTest(p4, p6))
}

func TestLookupListenerOwnerNonRootHolder_14581(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50051}
	writeListenTables(t, listenHeader+listenRow(t, addr, 1001), listenHeader)

	owner, err := LookupListenerOwner("127.0.0.1:50051")
	if err != nil {
		t.Fatalf("LookupListenerOwner: %v", err)
	}
	if !owner.Found || owner.UID != 1001 {
		t.Fatalf("owner = %+v, want found uid 1001", owner)
	}
	if owner.Privileged(uint32(os.Getuid())) {
		if os.Getuid() != 1001 && os.Getuid() != 0 {
			t.Fatal("a uid-1001 holder was reported privileged — fatal-on-any-holder is back")
		}
	}
}

func TestLookupListenerOwnerRootHolderIsPrivileged_14581(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50051}
	writeListenTables(t, listenHeader+listenRow(t, addr, 0), listenHeader)

	owner, err := LookupListenerOwner("127.0.0.1:50051")
	if err != nil {
		t.Fatalf("LookupListenerOwner: %v", err)
	}
	if !owner.Privileged(1000) {
		t.Fatalf("owner = %+v, want privileged for a uid-0 holder", owner)
	}
}

func TestLookupListenerOwnerWildcardHolder_14581(t *testing.T) {
	wild := &net.TCPAddr{IP: net.IPv4zero, Port: 50051}
	writeListenTables(t, listenHeader+listenRow(t, wild, 999), listenHeader)

	owner, err := LookupListenerOwner("127.0.0.1:50051")
	if err != nil {
		t.Fatalf("LookupListenerOwner: %v", err)
	}
	if !owner.Found || owner.UID != 999 {
		t.Fatalf("owner = %+v, want the wildcard holder uid 999", owner)
	}
}

func TestLookupListenerOwnerNeighbourIsNotHolder_14581(t *testing.T) {
	// 127.0.0.2:50051 does not block a bind of 127.0.0.1:50051.
	neighbour := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 50051}
	writeListenTables(t, listenHeader+listenRow(t, neighbour, 0), listenHeader)

	owner, err := LookupListenerOwner("127.0.0.1:50051")
	if err != nil {
		t.Fatalf("LookupListenerOwner: %v", err)
	}
	if owner.Found {
		t.Fatalf("owner = %+v, want unattributed: a neighbour address must not be read as the holder", owner)
	}
	if owner.Privileged(1000) {
		t.Fatal("an unattributed holder was reported privileged")
	}
}

func TestLookupListenerOwnerEstablishedRowIsNotHolder_14581(t *testing.T) {
	// An ESTABLISHED client row of the real holder must not be mistaken
	// for the LISTEN row: state 01, local = server, remote = client.
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50051}
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43210}
	skey, _ := procAddr4(server)
	ckey, _ := procAddr4(client)
	row := fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n", skey, ckey)
	writeListenTables(t, listenHeader+row, listenHeader)

	owner, err := LookupListenerOwner("127.0.0.1:50051")
	if err != nil {
		t.Fatalf("LookupListenerOwner: %v", err)
	}
	if owner.Found {
		t.Fatalf("owner = %+v, want unattributed: an ESTABLISHED row is not the holder", owner)
	}
}

func TestLookupListenerOwnerNoRow_14581(t *testing.T) {
	writeListenTables(t, listenHeader, listenHeader)
	owner, err := LookupListenerOwner("127.0.0.1:50051")
	if err != nil {
		t.Fatalf("LookupListenerOwner: %v", err)
	}
	if owner.Found || owner.Privileged(0) {
		t.Fatalf("owner = %+v, want unattributed and not privileged", owner)
	}
}

func TestListenerOwnerPrivilegedMatrix_14581(t *testing.T) {
	cases := []struct {
		name  string
		owner ListenerOwner
		self  uint32
		want  bool
	}{
		{"root holder", ListenerOwner{Found: true, UID: 0}, 1000, true},
		{"own-uid holder", ListenerOwner{Found: true, UID: 1000}, 1000, true},
		{"non-root holder", ListenerOwner{Found: true, UID: 1001}, 1000, false},
		{"unattributed", ListenerOwner{Found: false}, 1000, false},
		{"unattributed self-zero", ListenerOwner{Found: false}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.owner.Privileged(tc.self); got != tc.want {
				t.Errorf("Privileged = %v, want %v", got, tc.want)
			}
		})
	}
}

// The client half: a loopback server owned by a non-root uid is refused
// before any RPC (#14581 foreign uid; #14982 same uid). Driven through
// the fixture table (the only way to get a foreign-uid row without a
// second uid); a real-socket own-uid server is refused post-#14982
// unless the suite itself runs as root (see client_14982_test.go).
func TestVerifyLoopbackServerConnRefusesForeignUID_14581(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	// Foreign-uid fixture: the row for this very 4-tuple, owned by 9999.
	server := lis.Addr().(*net.TCPAddr)
	conn, err := net.Dial("tcp", server.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := conn.LocalAddr().(*net.TCPAddr)
	skey, _ := procAddr4(server)
	ckey, _ := procAddr4(client)
	row := fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000  9999        0 4242 1 0000000000000000 100 0 0 10 0\n", skey, ckey)
	writeListenTables(t, listenHeader+row, listenHeader)

	err = VerifyLoopbackServerConn(conn)
	if err == nil {
		t.Fatal("a foreign-uid loopback server was accepted — the CLI would hand it RPCs and secrets")
	}
	if !strings.Contains(err.Error(), "uid 9999") {
		t.Errorf("refusal does not name the holder uid: %v", err)
	}
}

func TestVerifyLoopbackServerConnOwnUIDPasses_14581(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	// Real tables: the server socket is owned by this process.
	// Post-#14982 only uid 0 is trusted, so this passes only when the
	// suite runs as root (own uid == 0); a non-root own-uid server is
	// now refused — pinned by TestVerifyLoopbackServerConnRefusesSameUIDSquatter_14982.
	if os.Getuid() != 0 {
		t.Skip("post-#14982 a non-root own-uid loopback server is refused; " +
			"covered by TestVerifyLoopbackServerConnRefusesSameUIDSquatter_14982")
	}
	conn, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for range 50 {
		if err = VerifyLoopbackServerConn(conn); err == nil {
			return
		}
		if !strings.Contains(err.Error(), "could not be attributed") {
			t.Fatalf("VerifyLoopbackServerConn: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("own-uid loopback server never verified: %v", err)
}

func TestVerifyLoopbackServerConnNonLoopbackOutOfScope_14581(t *testing.T) {
	// A non-loopback remote address is never table-checked here (the
	// fabric listener's own auth chain owns it). Driven with a fake
	// conn whose RemoteAddr is routable: LookupPeer is never consulted,
	// so even an unverifiable server passes THIS gate.
	c := &fakeConn{remote: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 50051}}
	if err := VerifyLoopbackServerConn(c); err != nil {
		t.Fatalf("non-loopback server refused: %v", err)
	}
}

type fakeConn struct {
	remote net.Addr
}

func (f *fakeConn) Read([]byte) (int, error)         { return 0, errors.New("unused") }
func (f *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 40000} }
func (f *fakeConn) RemoteAddr() net.Addr             { return f.remote }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }
