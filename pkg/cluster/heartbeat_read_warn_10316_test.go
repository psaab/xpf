package cluster

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)
// #10316: readLoop had two pre-authentication rejection paths that logged one
// warning per datagram even though sibling heartbeat rejection paths were
// rate-limited: malformed frames and frames from the wrong cluster. A sender
// that can reach UDP/4784 could therefore flood the daemon's warning log before
// HMAC admission ran.
//
// These cells drive the real readLoop over a real UDP socket. A direct test of
// heartbeatRejectWarnLimiter would not bind the two pre-auth call sites and
// would stay green if either unconditional slog.Warn remained.

func awaitHeartbeatRecvErrors10316(t *testing.T, r *heartbeatReceiver, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r.recvErrors.Load() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("readLoop recorded %d rejected datagrams, want >= %d", r.recvErrors.Load(), want)
}

type warnLogBuffer10316 struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *warnLogBuffer10316) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *warnLogBuffer10316) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func withCapturedWarnLog10316(t *testing.T) *warnLogBuffer10316 {
	t.Helper()
	buf := new(warnLogBuffer10316)
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

func newWarnReadLoop10316(t *testing.T) (*heartbeatReceiver, *net.UDPConn, *net.UDPConn) {
	t.Helper()
	mgr := NewManager(1, 42)
	recvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("receiver socket: %v", err)
	}
	sendConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		recvConn.Close()
		t.Fatalf("sender socket: %v", err)
	}
	r := newHeartbeatReceiver(mgr, recvConn, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	mgr.mu.Lock()
	mgr.hbReceiver = r
	mgr.mu.Unlock()
	r.start()
	t.Cleanup(func() {
		r.stop()
		sendConn.Close()
	})
	return r, recvConn, sendConn
}

// TestMalformedHeartbeatWarningsAreRateLimitedBeforeAuth_10316 drives the
// malformed pre-auth path. RED on the old code: 40 datagrams produce 40 WARN
// lines rather than one line in the limiter interval.
func TestMalformedHeartbeatWarningsAreRateLimitedBeforeAuth_10316(t *testing.T) {
	logBuf := withCapturedWarnLog10316(t)
	r, recvConn, sendConn := newWarnReadLoop10316(t)
	dst := recvConn.LocalAddr().(*net.UDPAddr)
	const frames = 40
	for range frames {
		if _, err := sendConn.WriteToUDP([]byte("not-a-heartbeat"), dst); err != nil {
			t.Fatalf("send malformed heartbeat: %v", err)
		}
	}
	awaitHeartbeatRecvErrors10316(t, r, frames)
	if got := strings.Count(logBuf.String(), "cluster: invalid heartbeat"); got != 1 {
		t.Fatalf("%d malformed datagrams produced %d warnings, want 1",
			frames, got)
	}
}

// TestWrongClusterWarningsAreRateLimitedBeforeAuth_10316 drives the other
// malformed pre-auth path. The frame is structurally valid, but its cluster ID
// is rejected before HMAC admission; this path must have its own budget.
func TestWrongClusterWarningsAreRateLimitedBeforeAuth_10316(t *testing.T) {
	logBuf := withCapturedWarnLog10316(t)
	r, recvConn, sendConn := newWarnReadLoop10316(t)
	dst := recvConn.LocalAddr().(*net.UDPAddr)
	frame := MarshalHeartbeat(&HeartbeatPacket{NodeID: 2, ClusterID: 99})
	const frames = 40
	for range frames {
		if _, err := sendConn.WriteToUDP(frame, dst); err != nil {
			t.Fatalf("send wrong-cluster heartbeat: %v", err)
		}
	}
	awaitHeartbeatRecvErrors10316(t, r, frames)
	if got := strings.Count(logBuf.String(), "cluster: heartbeat from wrong cluster"); got != 1 {
		t.Fatalf("%d wrong-cluster datagrams produced %d warnings, want 1",
			frames, got)
	}
}
