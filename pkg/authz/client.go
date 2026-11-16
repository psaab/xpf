package authz

import (
	"context"
	"fmt"
	"net"
	"time"
)

// client.go is the client half of #14581: before a local management
// client (the remote `cli`, pkg/upgrade's cluster control) speaks a
// single RPC to a loopback endpoint, it asks the kernel who owns the
// SERVER end of the connection it just dialed, and refuses to talk to
// a server that is not running as a privileged uid.
//
// # Why this half exists
//
// The supervisor half (listener.go + pkg/grpcapi) stops xpfd from
// exiting when a non-root process squats on 127.0.0.1:50051, but a
// squatter that is already listening when the operator runs `cli`
// would otherwise be spoken to as if it were xpfd — including being
// handed the operator's `set`/`load` payloads, which carry secrets.
// The server-side #5278 gate cannot help: the squatter is not xpfd and
// runs no gate. The only point that can refuse is the client, before
// the first RPC.
//
// # How the server is attributed
//
// The same /proc/net/tcp{,6} lookup peer.go uses for inbound peers,
// mirrored: for our outbound connection the kernel row's LOCAL address
// is the server and its REMOTE address is us, and LookupPeer already
// matches that mirrored 4-tuple in TCP_ESTABLISHED and returns the
// row's UID — here, the server process's UID. It runs at DIAL time,
// on the established connection, so the row exists and the squatter
// cannot choose the moment (the half-close/TIME_WAIT games peer.go
// documents are why only ESTABLISHED counts, and a dialed connection
// we hold open is ESTABLISHED).
//
// # Scope
//
// Only a LOOPBACK server address is checked. A non-loopback target
// (the cluster fabric listener) has no local socket-table row for the
// server process and is authenticated by its own #4107/#4122 chain;
// attributing it here would refuse every legitimate fabric peer. On a
// loopback target, an unattributable server is REFUSED, not assumed
// genuine: "we could not tell who that is" is exactly the squatter's
// best case, so it fails closed.
//
// Only uid 0 is trusted on loopback (#14982). xpfd runs as uid 0
// (its unit has no User=), so a genuine management server is always
// uid 0. Trusting "our own uid" as well (#14581's original shape)
// also trusted any squatter running as the CALLER's uid: the
// operator's own shell uid is exactly the uid an unprivileged local
// process that binds 127.0.0.1:50051 before xpfd starts (or while
// it is down) would present, and it would then receive the
// operator's management RPCs and secrets. Same-uid is therefore
// refused like any other non-root uid. (This changes nothing when
// the caller itself is root: same-uid and uid 0 coincide there.)
//
// # The server half may still be in SYN_RECV (#19125)
//
// "A dialed connection we hold open is ESTABLISHED" is true of OUR half
// only. connect() returns once the client has the SYN-ACK and has sent
// the final ACK; the SERVER half leaves TCP_SYN_RECV only when the
// kernel has processed that ACK. On loopback that is softirq work, so a
// table read made right after the dial can land before it — more often
// on a loaded box. A gate's harness hit it once in 640 RG moves: the CLI
// refused the real xpfd ("peer socket is in TCP state 3") and the
// manual failover was never sent.
//
// So when, and only when, the server's row is found in TCP_SYN_RECV, the
// client re-reads the table on a bounded backoff (synRecvRereadDelays19125,
// about 1 s in total, honouring the dial's context) until the row is
// ESTABLISHED, and then applies the unchanged checks: an ESTABLISHED row,
// owned by uid 0. Nothing is attributed from the SYN_RECV row. Each
// re-read is a fresh table scan (the batcher answers a query only from a
// read that started after it). Every OTHER non-established state is
// refused at once, as before: TIME_WAIT's mini-socket reports uid 0 and
// is exactly why only ESTABLISHED counts (peer.go). A server half that
// stays in SYN_RECV past the bound (its accept queue overflowing, say) is
// refused with that said. The SERVER side (#5278 / #5561) never waits:
// the caller it attributes completed its handshake before accept()
// returned.

// VerifyLoopbackServerConn reports whether the server end of conn — a
// just-dialed TCP connection — is running as uid 0 (what xpfd runs
// as) when the server address is loopback.
// A non-loopback server returns nil (out of scope, see file comment).
// A loopback server that is not uid 0 (including one sharing the
// caller's own non-root uid, #14982) or is unattributable returns
// an error naming what was found; the caller must not use the conn.
func VerifyLoopbackServerConn(conn net.Conn) error {
	return verifyLoopbackServerConn(context.Background(), conn)
}

// synRecvRereadDelays19125 is the bounded backoff between re-reads of a
// server row found in TCP_SYN_RECV (#19125); about 1 s in total.
// synRecvSleep19125 waits one step, returning early with ctx's error.
// Both are variables so the cells can drive them.
var (
	synRecvRereadDelays19125 = []time.Duration{
		1 * time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond, 10 * time.Millisecond,
		20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond,
		300 * time.Millisecond, 300 * time.Millisecond,
	}
	synRecvSleep19125 = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
)

// loopbackDialer19125 is DialContext's dialer, a zero net.Dialer in
// production. It is a variable only so a cell can pin the client port and
// write the matching socket-table row before the dial (#19125).
var loopbackDialer19125 net.Dialer

func verifyLoopbackServerConn(ctx context.Context, conn net.Conn) error {
	if conn == nil {
		return fmt.Errorf("no connection to verify")
	}
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("server address %v is not TCP; cannot verify its owner", conn.RemoteAddr())
	}
	if !remote.IP.IsLoopback() {
		return nil
	}
	id := LookupPeer(remote, conn.LocalAddr())
	rereads := 0
	var waited time.Duration
	for !id.OK && id.synRecv && rereads < len(synRecvRereadDelays19125) {
		d := synRecvRereadDelays19125[rereads]
		if synRecvSleep19125(ctx, d) != nil {
			break
		}
		rereads++
		waited += d
		id = LookupPeer(remote, conn.LocalAddr())
	}
	if !id.OK {
		detail := id.Detail
		if detail == "" {
			detail = "the kernel socket table did not attribute this server"
		}
		if id.synRecv {
			detail += fmt.Sprintf("; still SYN_RECV after %d re-reads over %s (#19125)", rereads, waited)
		}
		return fmt.Errorf("refusing to talk to the server at %s: its owner could not be attributed (%s) — "+
			"not sending management RPCs to an unverified local server (#14581)", remote, detail)
	}
	if id.UID != 0 {
		return fmt.Errorf("refusing to talk to the server at %s: it is owned by uid %d, not uid 0 — "+
			"this is not xpfd; a non-root process is squatting on the management port and would "+
			"receive your commands and any secrets in them (#14581, #14982)", remote, id.UID)
	}
	return nil
}

// DialContext dials addr over TCP and, for a loopback target, verifies
// the server's owning uid before returning the connection (see
// VerifyLoopbackServerConn). A refused server's connection is closed
// before any byte is written, so a squatter receives no RPC and no
// payload. It is shaped for grpc.WithContextDialer.
func DialContext(ctx context.Context, addr string) (net.Conn, error) {
	d := loopbackDialer19125
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := verifyLoopbackServerConn(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
