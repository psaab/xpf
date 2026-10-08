package routing

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// fakeProbeConn is an in-memory probeConn driven by a scripted reply
// builder, so the production icmpProber can be exercised with no real
// network. The replyFn is called with the just-sent echo (Seq, nonce) so
// a test can echo a matching, mismatched, or foreign reply.
type fakeProbeConn struct {
	replies  [][]byte // queued replies (icmp.ParseMessage-parseable bytes)
	writeErr error
	readErr  error
	sentSeq  int
	sentData []byte
	replyFn  func(seq int, data []byte) [][]byte
	// parseProto is the IANA proto the fake uses to parse the SENT echo (1
	// for ICMPv4, 58 for ICMPv6). Defaults to 1.
	parseProto int
}

func (c *fakeProbeConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	proto := c.parseProto
	if proto == 0 {
		proto = 1
	}
	// Parse the echo we are sending so the test reply builder can mirror it.
	if m, err := icmp.ParseMessage(proto, b); err == nil {
		if e, ok := m.Body.(*icmp.Echo); ok {
			c.sentSeq = e.Seq
			c.sentData = append([]byte(nil), e.Data...)
		}
	}
	if c.replyFn != nil {
		c.replies = append(c.replies, c.replyFn(c.sentSeq, c.sentData)...)
	}
	return len(b), nil
}

func (c *fakeProbeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	if len(c.replies) == 0 {
		// Mimic a read deadline expiry.
		return 0, nil, &timeoutErr{}
	}
	r := c.replies[0]
	c.replies = c.replies[1:]
	n := copy(b, r)
	return n, &net.UDPAddr{IP: net.ParseIP("203.0.113.1")}, nil
}

func (c *fakeProbeConn) SetReadDeadline(t time.Time) error { return nil }
func (c *fakeProbeConn) Close() error                      { return nil }

type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "i/o timeout" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }

// buildEchoReply marshals an ICMPv4 echo reply with the given seq/data.
func buildEchoReply(seq int, data []byte) []byte {
	m := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: 1234, Seq: seq, Data: data},
	}
	b, _ := m.Marshal(nil)
	return b
}

func withListenICMP(conn probeConn, err error, fn func()) {
	orig := listenICMP
	listenICMP = func(network, source, bindDevice string) (probeConn, error) {
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
	defer func() { listenICMP = orig }()
	fn()
}

func TestProberMatchingReplyAlive(t *testing.T) {
	conn := &fakeProbeConn{replyFn: func(seq int, data []byte) [][]byte {
		return [][]byte{buildEchoReply(seq, data)}
	}}
	withListenICMP(conn, nil, func() {
		res, _, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("nonce123"), 200*time.Millisecond)
		if res != ProbeAlive {
			t.Fatalf("matching reply must be Alive, got %v", res)
		}
	})
}

// buildEchoReplyV6 marshals an ICMPv6 echo reply. ICMPv6 checksums need
// a pseudo-header; icmp.Message.Marshal(psh) with a nil psh leaves the
// checksum zero, but ParseMessage(58, ...) does not verify it, so a nil
// psh is fine for the round-trip-match test.
func buildEchoReplyV6(seq int, data []byte) []byte {
	m := icmp.Message{
		Type: ipv6.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: 1234, Seq: seq, Data: data},
	}
	b, _ := m.Marshal(nil)
	return b
}

// IPv6 path coverage (Copilot PR #1947): exercise the v6-specific
// constants/parsing with a real round-trip match.
func TestProberIPv6MatchingReplyAlive(t *testing.T) {
	conn := &fakeProbeConn{
		parseProto: 58,
		replyFn: func(seq int, data []byte) [][]byte {
			return [][]byte{buildEchoReplyV6(seq, data)}
		},
	}
	withListenICMP(conn, nil, func() {
		res, _, _ := icmpProber{}.Probe("", "2001:db8::1", "2001:db8::2", 11, []byte("v6nonce0"), 200*time.Millisecond)
		if res != ProbeAlive {
			t.Fatalf("v6 matching reply must be Alive, got %v", res)
		}
	})
}

func TestProberIPv6WrongNonceIsDead(t *testing.T) {
	conn := &fakeProbeConn{
		parseProto: 58,
		replyFn: func(seq int, data []byte) [][]byte {
			return [][]byte{buildEchoReplyV6(seq, []byte("OTHER!!!"))}
		},
	}
	withListenICMP(conn, nil, func() {
		res, _, _ := icmpProber{}.Probe("", "2001:db8::1", "2001:db8::2", 11, []byte("v6nonce0"), 200*time.Millisecond)
		if res != ProbeDead {
			t.Fatalf("v6 wrong-nonce reply must be Dead, got %v", res)
		}
	})
}

func TestProberWrongSeqIsDead(t *testing.T) {
	conn := &fakeProbeConn{replyFn: func(seq int, data []byte) [][]byte {
		return [][]byte{buildEchoReply(seq+1, data)} // wrong seq
	}}
	withListenICMP(conn, nil, func() {
		res, _, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("nonce123"), 200*time.Millisecond)
		if res != ProbeDead {
			t.Fatalf("wrong-seq reply must be Dead, got %v", res)
		}
	})
}

func TestProberWrongNonceIsDead(t *testing.T) {
	conn := &fakeProbeConn{replyFn: func(seq int, data []byte) [][]byte {
		return [][]byte{buildEchoReply(seq, []byte("different"))} // wrong nonce
	}}
	withListenICMP(conn, nil, func() {
		res, _, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("nonce123"), 200*time.Millisecond)
		if res != ProbeDead {
			t.Fatalf("wrong-nonce reply must be Dead, got %v", res)
		}
	})
}

func TestProberForeignReplySkippedThenMatch(t *testing.T) {
	conn := &fakeProbeConn{replyFn: func(seq int, data []byte) [][]byte {
		// A foreign reply first, then the matching one — the read loop must
		// skip the foreign datagram and match ours.
		return [][]byte{
			buildEchoReply(seq+99, []byte("foreign!")),
			buildEchoReply(seq, data),
		}
	}}
	withListenICMP(conn, nil, func() {
		res, _, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("nonce123"), 500*time.Millisecond)
		if res != ProbeAlive {
			t.Fatalf("foreign-then-matching must be Alive, got %v", res)
		}
	})
}

func TestProberNoReplyIsDead(t *testing.T) {
	conn := &fakeProbeConn{} // no replyFn → read times out
	withListenICMP(conn, nil, func() {
		res, _, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("nonce123"), 50*time.Millisecond)
		if res != ProbeDead {
			t.Fatalf("no reply must be Dead, got %v", res)
		}
	})
}

func TestProberListenErrorStructural(t *testing.T) {
	withListenICMP(nil, &os.SyscallError{Syscall: "socket", Err: syscall.EPERM}, func() {
		res, kind, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("n"), 50*time.Millisecond)
		if res != ProbeUnsupported || kind != UnsupportedStructural {
			t.Fatalf("EPERM must be Unsupported/Structural, got %v/%v", res, kind)
		}
	})
}

func TestProberListenErrorTransient(t *testing.T) {
	withListenICMP(nil, &os.SyscallError{Syscall: "socket", Err: syscall.EMFILE}, func() {
		res, kind, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("n"), 50*time.Millisecond)
		if res != ProbeUnsupported || kind != UnsupportedTransient {
			t.Fatalf("EMFILE must be Unsupported/Transient, got %v/%v", res, kind)
		}
	})
}

func TestProberUnknownErrnoIsTransient(t *testing.T) {
	withListenICMP(nil, &os.SyscallError{Syscall: "socket", Err: syscall.ENOMEM}, func() {
		_, kind, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("n"), 50*time.Millisecond)
		if kind != UnsupportedTransient {
			t.Fatalf("ENOMEM must be Transient, got %v", kind)
		}
	})
}

// WriteTo local-resource errors must NOT be reported as Dead (Codex PR
// #1947 r1 HIGH): a transmit-buffer storm would otherwise self-inflict a
// tunnel down.
func TestProberWriteResourceErrorIsTransient(t *testing.T) {
	conn := &fakeProbeConn{writeErr: &os.SyscallError{Syscall: "sendto", Err: syscall.ENOBUFS}}
	withListenICMP(conn, nil, func() {
		res, kind, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("n"), 50*time.Millisecond)
		if res != ProbeUnsupported || kind != UnsupportedTransient {
			t.Fatalf("ENOBUFS on WriteTo must be Unsupported/Transient, got %v/%v", res, kind)
		}
	})
}

// WriteTo path-unreachable errors ARE a real liveness signal → Dead.
func TestProberWritePathUnreachableIsDead(t *testing.T) {
	conn := &fakeProbeConn{writeErr: &os.SyscallError{Syscall: "sendto", Err: syscall.EHOSTUNREACH}}
	withListenICMP(conn, nil, func() {
		res, _, _ := icmpProber{}.Probe("", "198.51.100.1", "203.0.113.1", 7, []byte("n"), 50*time.Millisecond)
		if res != ProbeDead {
			t.Fatalf("EHOSTUNREACH on WriteTo must be Dead, got %v", res)
		}
	})
}

func TestProberBadDestStructural(t *testing.T) {
	res, kind, _ := icmpProber{}.Probe("", "198.51.100.1", "not-an-ip", 7, []byte("n"), 50*time.Millisecond)
	if res != ProbeUnsupported || kind != UnsupportedStructural {
		t.Fatalf("unparseable dst must be Unsupported/Structural, got %v/%v", res, kind)
	}
}
