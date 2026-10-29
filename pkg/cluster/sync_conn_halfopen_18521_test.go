package cluster

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// #18521 cells. The live shape (tcp cluster, 2026-10-29): RGs moved to fw1,
// fw1 (accept side) logged a bare "fabric 0 disconnected", and fw0 (dial
// side, the only side that redials) noticed 56 s later. These cells rebuild
// each link of that chain on real loopback TCP, because the defect lives in
// kernel TCP semantics (a graceful FIN queued behind unsent bytes) that
// net.Pipe cannot exhibit.

// lockedBuffer is a goroutine-safe log sink: the watchdog and the receive
// loop log from their own goroutines.
type lockedBuffer18521 struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer18521) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer18521) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// lines returns the captured log lines containing every needle.
func (b *lockedBuffer18521) lines(needles ...string) []string {
	var out []string
	for _, line := range strings.Split(b.String(), "\n") {
		ok := line != ""
		for _, n := range needles {
			if !strings.Contains(line, n) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, line)
		}
	}
	return out
}

func captureSyncLogs18521(t *testing.T) *lockedBuffer18521 {
	t.Helper()
	buf := &lockedBuffer18521{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

// tcpPair18521 returns a connected loopback pair with the production socket
// buffer sizing (configureSessionSyncConn) on the session-sync side.
func tcpPair18521(t *testing.T) (local, peer *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	d, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	a := <-accepted
	if a == nil {
		t.Fatal("accept failed")
	}
	local, peer = a.(*net.TCPConn), d.(*net.TCPConn)
	configureSessionSyncConn(local)
	if err := peer.SetReadBuffer(256 * 1024); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		local.Close()
		peer.Close()
	})
	return local, peer
}

func waitFor18521(t *testing.T, budget time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func kernelState18521(t *testing.T, c *net.TCPConn) uint8 {
	t.Helper()
	state, _, ok := tcpConnKernelState(c)
	if !ok {
		t.Fatal("TCP_INFO unavailable on an open socket")
	}
	return state
}

// The fw1 half. A queued-frame write that cannot finish within
// syncWriteDeadline (the peer stopped reading) tears the connection down from
// sendLoop. Two things must be true of that teardown:
//
//  1. the PEER's kernel learns at once. A graceful close queues the FIN behind
//     the ~1 MB still in flight; with the peer's window closed it is never
//     transmitted, so the peer stays ESTABLISHED until it has read all of it.
//     Abortive close sends RST, which the window does not gate: the peer goes
//     to TCP_CLOSE immediately. RED on the graceful close (state stays 1).
//  2. the disconnect line names the cause. sendLoop logged the write error
//     only at Debug, so "fabric 0 disconnected" was the ENTIRE record of the
//     event that opened the 56 s window. RED on the bare line.
func TestSendWriteTimeoutTeardownReachesStalledPeer18521(t *testing.T) {
	logs := captureSyncLogs18521(t)
	local, peer := tcpPair18521(t)
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	ac := &authConn{Conn: local}
	ac.diag.installedMono.Store(MonotonicNanos())
	ss.installConn(0, ac)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss.wg.Add(1)
	go func() {
		defer ss.wg.Done()
		ss.sendLoop(ctx)
	}()
	defer ss.wg.Wait()
	defer cancel()

	// The peer never reads: this is fw0 with its receive loop off the socket.
	frame := encodeRawMessage(250, make([]byte, 64*1024))
	for i := 0; i < 64; i++ {
		if !ss.enqueueQueuedFrame(append([]byte(nil), frame...)) {
			t.Fatalf("send queue refused frame %d", i)
		}
	}
	if !waitFor18521(t, syncWriteDeadline+5*time.Second, func() bool { return ss.getActiveConn() == nil }) {
		t.Fatal("sendLoop never tore the connection down although the peer stopped reading " +
			"and the write deadline expired")
	}

	// (1) The peer's kernel must see the teardown while it is still not reading.
	var state uint8
	reached := waitFor18521(t, time.Second, func() bool {
		state = kernelState18521(t, peer)
		return state == linuxTCPStateClose
	})
	if !reached {
		_, unread, _ := tcpConnKernelState(peer)
		t.Errorf("after the local teardown the stalled peer's socket is still in TCP state %d "+
			"(1 = ESTABLISHED) with %d bytes queued: the close was graceful, so its FIN sits "+
			"behind every unsent byte and the peer cannot learn of it until it drains the "+
			"backlog — the 56 s half-open window of #18521. Teardown must be abortive (RST).",
			state, unread)
	}

	// (2) The disconnect line must carry the cause and the error.
	lines := logs.lines("fabric 0 disconnected")
	if len(lines) != 1 {
		t.Fatalf("want exactly one fabric 0 disconnected line, got %d:\n%s", len(lines), logs.String())
	}
	for _, want := range []string{`reason="queued frame write failed"`, "i/o timeout", "remote=", "conn_age="} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("disconnect line does not name its cause (missing %q) — sendLoop's write "+
				"error was Debug-only, so this line was the whole record:\n%s", want, lines[0])
		}
	}
}

// The fw0 half. The receive loop is stuck inside one handler (here a fence
// whose OnFenceReceived blocks, standing in for an install waiting on the
// helper) while the peer has already given up and reset the connection.
// Without the watchdog the slot stays occupied — so fabricConnectLoop never
// redials — until the handler returns AND the loop drains the dead backlog.
// RED: the slot is still installed after the budget.
func TestPeerResetWhileReceiveLoopStalledTearsDown18521(t *testing.T) {
	// Review of #18525 (finding 7): the handler-in-flight arm must tear down
	// on its own, with NOTHING queued behind the stuck handler (unread 0).
	t.Run("backlog queued", func(t *testing.T) { peerResetWhileStalled18521(t, true) })
	t.Run("no unread bytes", func(t *testing.T) { peerResetWhileStalled18521(t, false) })
}

func peerResetWhileStalled18521(t *testing.T, backlog bool) {
	logs := captureSyncLogs18521(t)
	local, peer := tcpPair18521(t)
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	ss.readDeadline = time.Minute
	ss.testConnWatchInterval = 20 * time.Millisecond
	ss.testSlowHandlerThreshold = 100 * time.Millisecond
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	ss.OnFenceReceived = func() FenceResult {
		once.Do(func() { close(entered) })
		<-release
		return FenceResult{}
	}
	ac := &authConn{Conn: local}
	ac.diag.installedMono.Store(MonotonicNanos())
	ss.installConn(0, ac)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopDone := make(chan struct{})
	ss.wg.Add(1)
	go func() {
		defer ss.wg.Done()
		defer close(loopDone)
		ss.receiveLoop(ctx, ac)
	}()
	released := false
	releaseHandler := func() {
		if !released {
			released = true
			close(release)
		}
	}
	defer releaseHandler()

	if err := writeMsg(peer, syncMsgFence, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("fence handler never ran")
	}
	// Queue a backlog behind the stuck handler, as fw1's sendLoop did.
	filler := encodeRawMessage(250, make([]byte, 16*1024))
	for i := 0; backlog && i < 32; i++ {
		_ = peer.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := peer.Write(filler); err != nil {
			break
		}
	}
	// While the handler is still stuck, the watchdog must say so — the loop's
	// own report can only fire when the call returns, which a stuck call never
	// does.
	if !waitFor18521(t, 3*time.Second, func() bool {
		return len(logs.lines("receive loop blocked in a message handler")) > 0
	}) {
		t.Fatalf("no in-flight stall report while the handler was blocked:\n%s", logs.String())
	}
	// The peer gives up: abortive close, exactly what the fixed fw1 sends.
	if err := peer.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	peer.Close()

	if !waitFor18521(t, 3*time.Second, func() bool { return ss.getActiveConn() == nil }) {
		t.Fatal("the peer reset the connection, but the stalled receive loop's slot is still " +
			"installed: nothing tears it down until the handler returns and the loop drains the " +
			"dead backlog, and fabricConnectLoop does not redial an occupied slot (#18521)")
	}
	if got := logs.lines("receive loop blocked in a message handler", "msg_type=fence"); len(got) != 1 {
		t.Errorf("want ONE in-flight stall report naming msg_type=fence, got %d:\n%s", len(got), logs.String())
	}
	if got := logs.lines("peer reset the session-sync connection while the receive loop was behind"); len(got) != 1 {
		t.Errorf("want ONE watchdog teardown line, got %d:\n%s", len(got), logs.String())
	}
	if got := logs.lines("fabric 0 disconnected", `reason="peer reset while receive loop behind"`); len(got) != 1 {
		t.Errorf("disconnect line does not name the watchdog teardown:\n%s", logs.String())
	}

	// Releasing the handler lets the loop wake on the closed socket and exit
	// through the stale branch, logging its exit exactly once.
	releaseHandler()
	select {
	case <-loopDone:
	case <-time.After(5 * time.Second):
		t.Fatal("receive loop did not exit after the handler was released")
	}
	if got := logs.lines("slow message handler held the receive loop off the socket", "msg_type=fence", "reported_while_blocked=true"); len(got) != 1 {
		t.Errorf("want ONE completion report for the slow fence handler, got %d:\n%s", len(got), logs.String())
	}
	if got := logs.lines("receive loop exited"); len(got) != 1 {
		t.Errorf("want exactly one receive-loop exit line per connection, got %d:\n%s", len(got), logs.String())
	}
}

// A stale disconnect (the conn is no longer in a slot) used to return without
// closing the socket. Every slot-emptying path closes what it removes today,
// so the branch normally sees a closed conn — but when it does not, returning
// with the socket open IS a half-open connection: this node stopped counting
// it and the peer's kernel still believes it is ESTABLISHED. RED: the peer's
// read blocks until its deadline instead of failing.
func TestStaleDisconnectClosesItsOwnSocket18521(t *testing.T) {
	local, peer := tcpPair18521(t)
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	installed, installedPeer := tcpPair18521(t)
	_ = installedPeer
	ss.installConn(0, &authConn{Conn: installed})
	stale := &authConn{Conn: local}

	ss.disconnectConn(stale, "test: stale conn", nil)

	if ss.getActiveConn() == nil {
		t.Fatal("a stale disconnect must not touch the installed slot")
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := peer.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the stale-disconnect branch returned with its socket still open: the peer " +
			"sees an ESTABLISHED connection this node has already forgotten (#18521)")
	}
	if err == nil {
		t.Fatal("peer read returned data from a connection that should be closed")
	}
}

// Every receive-loop exit names itself, once, and the reason reaches the
// disconnect line. The three exits that used to be silent are covered: a
// non-timeout header read error (peer FIN), a payload read error (frame cut
// off mid-payload), and a peer reset. RED: no exit line exists.
func TestReceiveLoopExitNamesItsReason18521(t *testing.T) {
	cases := []struct {
		name       string
		peer       func(t *testing.T, peer *net.TCPConn)
		wantReason string
	}{
		{
			name:       "peer FIN at a frame boundary",
			peer:       func(t *testing.T, peer *net.TCPConn) { peer.Close() },
			wantReason: "header: peer closed the connection",
		},
		{
			name: "frame cut off inside the payload",
			peer: func(t *testing.T, peer *net.TCPConn) {
				hdr := make([]byte, syncHeaderSize)
				copy(hdr[:4], syncMagic[:])
				hdr[4] = 250
				binary.LittleEndian.PutUint32(hdr[8:12], 1000)
				if _, err := peer.Write(append(hdr, make([]byte, 10)...)); err != nil {
					t.Fatal(err)
				}
				peer.Close()
			},
			wantReason: "payload: peer closed the connection",
		},
		{
			name: "peer reset",
			peer: func(t *testing.T, peer *net.TCPConn) {
				_ = peer.SetLinger(0)
				peer.Close()
			},
			wantReason: "header: peer reset the connection",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureSyncLogs18521(t)
			local, peer := tcpPair18521(t)
			ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
			ss.readDeadline = time.Minute
			ac := &authConn{Conn: local}
			ss.installConn(0, ac)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			ss.wg.Add(1)
			go func() {
				defer ss.wg.Done()
				defer close(done)
				ss.receiveLoop(ctx, ac)
			}()
			tc.peer(t, peer)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("receive loop did not exit")
			}
			exits := logs.lines("receive loop exited")
			if len(exits) != 1 {
				t.Fatalf("want exactly one receive-loop exit line, got %d:\n%s", len(exits), logs.String())
			}
			if !strings.Contains(exits[0], `reason="`+tc.wantReason+`"`) || !strings.Contains(exits[0], "level=WARN") {
				t.Errorf("exit line must be a Warn naming %q:\n%s", tc.wantReason, exits[0])
			}
			if got := logs.lines("fabric 0 disconnected", `reason="receive loop: `+tc.wantReason+`"`); len(got) != 1 {
				t.Errorf("disconnect line must carry the receive-loop reason:\n%s", logs.String())
			}
		})
	}
}

// One slow handler call -> one Warn naming the type; fast calls -> nothing.
// The per-message path must stay silent (CLAUDE.md logging rules).
func TestSlowHandlerWarnsOncePerCallNamingType18521(t *testing.T) {
	logs := captureSyncLogs18521(t)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	ss.readDeadline = time.Minute
	ss.testSlowHandlerThreshold = 50 * time.Millisecond
	ss.testConnWatchInterval = time.Hour // isolate the completion report
	var calls int
	ss.OnFenceReceived = func() FenceResult {
		calls++
		if calls == 1 {
			time.Sleep(120 * time.Millisecond)
		}
		return FenceResult{}
	}
	ac := &authConn{Conn: local}
	ss.installConn(0, ac)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	ss.wg.Add(1)
	go func() {
		defer ss.wg.Done()
		defer close(done)
		ss.receiveLoop(ctx, ac)
	}()
	for i := 0; i < 20; i++ {
		if err := writeMsg(peer, syncMsgFence, nil); err != nil {
			t.Fatal(err)
		}
	}
	// net.Pipe is synchronous: one more frame proves the 20 fences were read.
	if err := writeMsg(peer, 250, nil); err != nil {
		t.Fatal(err)
	}
	cancel()
	peer.Close()
	<-done

	slow := logs.lines("slow message handler held the receive loop off the socket")
	if len(slow) != 1 {
		t.Fatalf("want exactly ONE slow-handler Warn for one slow call among 20, got %d:\n%s", len(slow), logs.String())
	}
	if !strings.Contains(slow[0], "msg_type=fence") || !strings.Contains(slow[0], "level=WARN") {
		t.Errorf("slow-handler line must be a Warn naming msg_type=fence:\n%s", slow[0])
	}
	exits := logs.lines("receive loop exited")
	if len(exits) != 1 {
		t.Fatalf("want one exit line, got %d:\n%s", len(exits), logs.String())
	}
	for _, want := range []string{"frames_read=21", "handler_max_type=fence"} {
		if !strings.Contains(exits[0], want) {
			t.Errorf("exit summary missing %q:\n%s", want, exits[0])
		}
	}
}

// syncMsgName must name every type handleMessage dispatches, or the slow-
// handler report degrades to "unknown" for exactly the type that was added
// last. Compared by identifier set over the two functions' case labels.
func TestSyncMsgNameCoversHandleMessage18521(t *testing.T) {
	labels := func(file, fn string) []string {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name.Name != fn {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				cc, ok := n.(*ast.CaseClause)
				if !ok {
					return true
				}
				for _, e := range cc.List {
					if id, ok := e.(*ast.Ident); ok {
						out = append(out, id.Name)
					}
				}
				return true
			})
		}
		if len(out) < 40 {
			t.Fatalf("%s in %s: found only %d case labels — the scan is broken", fn, file, len(out))
		}
		sort.Strings(out)
		return out
	}
	dispatch := labels("sync_conn_read.go", "handleMessage")
	names := labels("sync_conn_teardown_18521.go", "syncMsgName")
	if strings.Join(dispatch, ",") != strings.Join(names, ",") {
		t.Fatalf("syncMsgName labels differ from handleMessage dispatch:\n dispatch=%v\n names=%v", dispatch, names)
	}
}

// Review of #18525 (finding 4): Stop closed its connections GRACEFULLY, so a
// restart of this node while the peer's receive loop is behind left the peer
// ESTABLISHED behind the unsent bytes — the half-open shape again. RED with
// Stop's graceful Close.
func TestStopTeardownReachesStalledPeer18521(t *testing.T) {
	local, peer := tcpPair18521(t)
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	ss.installConn(0, &authConn{Conn: local})
	// Fill the send path: the peer is not reading.
	chunk := make([]byte, 64*1024)
	for {
		_ = local.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := local.Write(chunk); err != nil {
			break
		}
	}
	ss.Stop()
	var state uint8
	if !waitFor18521(t, time.Second, func() bool {
		state = kernelState18521(t, peer)
		return state == linuxTCPStateClose
	}) {
		t.Fatalf("after Stop the stalled peer's socket is in TCP state %d (1 = ESTABLISHED): "+
			"the stop-time close was graceful and its FIN sits behind the unsent bytes", state)
	}
}

// The receiver's side of the same-generation re-send (#18521): an exact
// duplicate of the applied generation is re-ACKed without applying again and
// without moving the config-epoch barrier.
func TestDuplicateAppliedConfigIsReackedWithoutApply18521(t *testing.T) {
	s := NewSessionSync(":0", "10.0.0.2:4785", &mockSweepDP{})
	conn := &captureConn{}
	s.mu.Lock()
	s.conn0 = conn
	s.mu.Unlock()
	const gen = uint64(1890891765099)
	s.lastAppliedConfigGen.Store(gen)
	var applies int
	s.OnConfigReceived = func(string) error { applies++; return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.configApplyLoop(ctx)
	}()
	s.configApplyCh <- configApplyItem{gen: gen, text: "set system host-name standby", conn: conn}
	acked := waitFor18521(t, 2*time.Second, func() bool {
		for _, f := range conn.frames() {
			if f.msgType == syncMsgConfigApplyAck && len(f.payload) >= 8 &&
				binary.LittleEndian.Uint64(f.payload[:8]) == gen {
				return true
			}
		}
		return false
	})
	cancel()
	<-done
	if !acked {
		t.Fatal("a re-sent, already-applied generation was not re-ACKed")
	}
	if applies != 0 {
		t.Fatalf("the duplicate was applied again (%d applies)", applies)
	}
	if got := s.applyingConfigGen.Load(); got != 0 {
		t.Fatalf("the duplicate raised the apply fence to %d", got)
	}
	if got := s.lastAppliedConfigGen.Load(); got != gen {
		t.Fatalf("applied high-water moved to %d", got)
	}
}
