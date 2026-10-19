package authz

import (
	"context"
	"fmt"
	"net"
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

// VerifyLoopbackServerConn reports whether the server end of conn — a
// just-dialed TCP connection — is running as uid 0 (what xpfd runs
// as) when the server address is loopback.
// A non-loopback server returns nil (out of scope, see file comment).
// A loopback server that is not uid 0 (including one sharing the
// caller's own non-root uid, #14982) or is unattributable returns
// an error naming what was found; the caller must not use the conn.
func VerifyLoopbackServerConn(conn net.Conn) error {
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
	if !id.OK {
		detail := id.Detail
		if detail == "" {
			detail = "the kernel socket table did not attribute this server"
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
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if err := VerifyLoopbackServerConn(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
