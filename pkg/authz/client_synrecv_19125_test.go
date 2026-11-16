package authz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// #19125: the CLIENT half of #14581 read the server's row while the server
// half of the just-dialed loopback connection was still in TCP_SYN_RECV (its
// kernel had not yet processed the client's final ACK) and refused the real
// xpfd: "peer socket is in TCP state 3, not established". The fix re-reads,
// for a bounded time, ONLY a row in SYN_RECV, then applies the unchanged
// checks (ESTABLISHED, uid 0). These cells drive the socket-table fixture
// through the re-read seam.

// synRecvConn19125 dials a real loopback listener and returns the connection
// plus a function that rewrites this connection's server row with a state and
// a uid (the fixture is what LookupPeer reads).
func synRecvConn19125(t *testing.T) (net.Conn, func(state string, uid uint32)) {
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
	skey, _ := procAddr4(server)
	ckey, _ := procAddr4(conn.LocalAddr().(*net.TCPAddr))
	set := func(state string, uid uint32) {
		row := fmt.Sprintf("   0: %s %s %s 00000000:00000000 00:00000000 00000000  %4d        0 4242 1 0000000000000000 100 0 0 10 0\n",
			skey, ckey, state, uid)
		writeListenTables(t, listenHeader+row, listenHeader)
	}
	return conn, set
}

// stubSleep19125 replaces the re-read wait. onCall runs at each wait (1-based
// count) and may rewrite the fixture; after limit calls it returns an error,
// so an unbounded re-read loop ends (and is caught by the count assertion).
func stubSleep19125(t *testing.T, limit int, onCall func(n int)) *int {
	t.Helper()
	n := 0
	orig := synRecvSleep19125
	synRecvSleep19125 = func(ctx context.Context, d time.Duration) error {
		n++
		if onCall != nil {
			onCall(n)
		}
		if n > limit {
			return errors.New("stub: re-read loop exceeded its bound")
		}
		return nil
	}
	t.Cleanup(func() { synRecvSleep19125 = orig })
	return &n
}

// The defect's own shape: the real xpfd (uid 0) is found in SYN_RECV, then
// ESTABLISHED on the next read. It must be accepted after ONE re-read.
func TestVerifyLoopbackServerConnWaitsOutSynRecv_19125(t *testing.T) {
	conn, set := synRecvConn19125(t)
	set("03", 0)
	sleeps := stubSleep19125(t, 100, func(n int) {
		if n == 1 {
			set("01", 0)
		}
	})
	if err := VerifyLoopbackServerConn(conn); err != nil {
		t.Fatalf("uid-0 server whose half went SYN_RECV -> ESTABLISHED was refused: %v (#19125)", err)
	}
	if *sleeps != 1 {
		t.Fatalf("re-reads = %d, want exactly 1", *sleeps)
	}
}

// The wait attributes nothing: the uid test runs on the ESTABLISHED row read
// AFTER the wait. A non-root owner there is refused, and so is a row whose uid
// changed from 0 to non-root across the wait (the SYN_RECV row's uid is never
// trusted).
func TestVerifyLoopbackServerConnUIDCheckedAfterSynRecvWait_19125(t *testing.T) {
	for _, tc := range []struct {
		name         string
		synUID, eUID uint32
	}{
		{"non-root throughout", 9999, 9999},
		{"uid 0 while SYN_RECV, non-root once ESTABLISHED", 0, 9999},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, set := synRecvConn19125(t)
			set("03", tc.synUID)
			stubSleep19125(t, 100, func(n int) {
				if n == 1 {
					set("01", tc.eUID)
				}
			})
			err := VerifyLoopbackServerConn(conn)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("uid %d", tc.eUID)) {
				t.Fatalf("err = %v, want a refusal naming uid %d (the ESTABLISHED row's owner)", err, tc.eUID)
			}
		})
	}
}

// A server half that STAYS in SYN_RECV is refused after exactly the bounded
// number of re-reads, even though its row reports uid 0 (a SYN_RECV row is
// never attributed).
func TestVerifyLoopbackServerConnPersistentSynRecvRefusedBounded_19125(t *testing.T) {
	conn, set := synRecvConn19125(t)
	set("03", 0)
	sleeps := stubSleep19125(t, 1000, nil)
	err := VerifyLoopbackServerConn(conn)
	if err == nil {
		t.Fatal("a server half that never left SYN_RECV was accepted: a SYN_RECV row must never be attributed")
	}
	if want := len(synRecvRereadDelays19125); *sleeps != want {
		t.Fatalf("re-reads = %d, want the bound %d", *sleeps, want)
	}
	for _, s := range []string{"TCP state 3", "still SYN_RECV", "#19125"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("refusal %q does not say %q", err, s)
		}
	}
}

// Every OTHER non-established state is refused at once, with no re-read: the
// wait is for SYN_RECV only. TIME_WAIT is the state whose mini-socket reports
// uid 0, the reason only ESTABLISHED counts (peer.go).
func TestVerifyLoopbackServerConnOtherStatesNotRetried_19125(t *testing.T) {
	for _, st := range []string{"02", "04", "05", "06", "07", "08", "09", "0A", "0B"} {
		t.Run("state_"+st, func(t *testing.T) {
			conn, set := synRecvConn19125(t)
			set(st, 0)
			sleeps := stubSleep19125(t, 1000, nil)
			if err := VerifyLoopbackServerConn(conn); err == nil {
				t.Fatalf("state %s (uid 0) was accepted", st)
			}
			if *sleeps != 0 {
				t.Fatalf("state %s was re-read %d times; only SYN_RECV may wait", st, *sleeps)
			}
		})
	}
}

// The wait honours the dial's context: a cancelled context ends it at once,
// with the refusal, instead of sleeping out the full bound (about 1 s).
func TestVerifyLoopbackServerConnSynRecvWaitHonoursContext_19125(t *testing.T) {
	conn, set := synRecvConn19125(t)
	set("03", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := verifyLoopbackServerConn(ctx, conn)
	if err == nil {
		t.Fatal("accepted a SYN_RECV server with a cancelled context")
	}
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("a cancelled context still waited %s; the wait must end with the context", el)
	}
}

// DialContext (the CLI's and pkg/upgrade's dialer) hands ITS context to the
// wait, so the gRPC dial deadline bounds it.
func TestDialContextSynRecvWaitUsesDialContext_19125(t *testing.T) {
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
	// Pin the client port so the row can be written before the dial.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client := probe.Addr().(*net.TCPAddr)
	probe.Close()
	orig := loopbackDialer19125
	loopbackDialer19125 = net.Dialer{LocalAddr: client}
	t.Cleanup(func() { loopbackDialer19125 = orig })
	skey, _ := procAddr4(lis.Addr().(*net.TCPAddr))
	ckey, _ := procAddr4(client)
	row := fmt.Sprintf("   0: %s %s 03 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n", skey, ckey)
	writeListenTables(t, listenHeader+row, listenHeader)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := DialContext(ctx, lis.Addr().String())
	if err == nil {
		conn.Close()
		t.Fatal("DialContext accepted a server half stuck in SYN_RECV")
	}
	if !strings.Contains(err.Error(), "still SYN_RECV") {
		t.Fatalf("err = %v, want the SYN_RECV refusal (the pinned row was not the one read?)", err)
	}
	if el := time.Since(start); el > 600*time.Millisecond {
		t.Fatalf("DialContext waited %s under a 100 ms dial context; the wait must use the dial's context", el)
	}
}
