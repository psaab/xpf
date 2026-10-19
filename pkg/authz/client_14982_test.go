package authz

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

// #14982 (D36-01, surviving same-UID leg): VerifyLoopbackServerConn
// must NOT trust a loopback server merely because it shares the
// caller's uid. xpfd runs as uid 0 (its unit has no User=), so the
// only privileged loopback management server is uid 0. A same-uid
// non-root squatter — e.g. a process running as the operator's own
// uid that bound 127.0.0.1:50051 before xpfd / while xpfd is down —
// was accepted by the `id.UID == os.Getuid()` arm and would receive
// the operator's management RPCs and secrets.
//
// The fixtures render the ESTABLISHED row for this very connection
// owned by the test process's own (non-root) uid, exactly as the
// foreign-uid fixture in listener_14581_test.go renders uid 9999.
// When the suite itself runs as root the same-uid arm and the uid-0
// arm coincide, so the defect is unobservable and the test skips.

func dialLoopbackWithServerUID(t *testing.T, serverUID uint32) net.Conn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	server := lis.Addr().(*net.TCPAddr)
	conn, err := net.Dial("tcp", server.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	client := conn.LocalAddr().(*net.TCPAddr)
	skey, _ := procAddr4(server)
	ckey, _ := procAddr4(client)
	row := fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000  %4d        0 4242 1 0000000000000000 100 0 0 10 0\n", skey, ckey, serverUID)
	writeListenTables(t, listenHeader+row, listenHeader)
	return conn
}

func TestVerifyLoopbackServerConnRefusesSameUIDSquatter_14982(t *testing.T) {
	self := uint32(os.Getuid())
	if self == 0 {
		t.Skip("running as root: same-uid and uid-0 coincide, defect unobservable")
	}
	conn := dialLoopbackWithServerUID(t, self)
	err := VerifyLoopbackServerConn(conn)
	if err == nil {
		t.Fatalf("same-uid (uid %d, non-root) loopback server was accepted — "+
			"a squatter running as the operator's own uid would receive management RPCs and secrets (#14982)", self)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("uid %d", self)) {
		t.Errorf("refusal does not name the holder uid %d: %v", self, err)
	}
}

func TestVerifyLoopbackServerConnRootServerPasses_14982(t *testing.T) {
	// Control: a uid-0 loopback server is the real xpfd and must pass
	// regardless of the caller's uid.
	conn := dialLoopbackWithServerUID(t, 0)
	if err := VerifyLoopbackServerConn(conn); err != nil {
		t.Fatalf("uid-0 loopback server refused: %v — legitimate xpfd must stay reachable (#14982)", err)
	}
}
