package cluster

import (
	"net"
	"strings"
	"testing"
)

func TestUnkeyedAuthorityStatusRemainsAlarmed16016(t *testing.T) {
	m := NewManager(0, 1)
	got := m.controlLinkAuthStatus()
	if !strings.Contains(got, "ALARM: unauthenticated control authority remains enabled") {
		t.Fatalf("unkeyed control-link status does not expose the persistent alarm: %q", got)
	}
}

type staticKeyProvider16016 struct{ key []byte }

func (p staticKeyProvider16016) ControlLinkAuthKey() []byte { return p.key }

type remoteAddrConn16016 struct {
	net.Conn
	remote net.Addr
	closed bool
}

func (c *remoteAddrConn16016) RemoteAddr() net.Addr { return c.remote }
func (c *remoteAddrConn16016) Close() error {
	c.closed = true
	return c.Conn.Close()
}

func TestUnauthenticatedAuthorityFramesRejectedOnceKeyed16016(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "10.0.0.2:4785", nil)
	s.SetAuthProvider(staticKeyProvider16016{key: []byte("local-key-16016")})
	s.configApplyCh = make(chan configApplyItem, 4)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := s.wrapSyncConn(0, local, syncAuthUnauthenticated, syncNoiseKeysWithPSK{})

	// The cleartext config would be queued for wholesale SyncApply; the empty
	// BulkStart would open an authoritative session window; and a heartbeat ack
	// would arm a capability consumed by failover admission. These authority
	// actions must be refused once local key material exists.
	if s.handleFrame(conn, nil, syncMsgConfig,
		encodeConfigPayload("system { host-name forged; }", 1)) {
		t.Fatal("unauthenticated config frame accepted on a locally keyed node (#16016)")
	}
	select {
	case <-s.configApplyCh:
		t.Fatal("unauthenticated config reached the apply queue (#16016)")
	default:
	}
	if s.handleFrame(conn, nil, syncMsgBulkStart, bulkStartPayload(1, nil)) {
		t.Fatal("unauthenticated BulkStart accepted on a locally keyed node (#16016)")
	}
	s.bulkMu.Lock()
	bulkInProgress := s.bulkInProgress
	s.bulkMu.Unlock()
	if bulkInProgress {
		t.Fatal("unauthenticated BulkStart opened a session-reconcile window (#16016)")
	}
	if s.handleFrame(conn, nil, syncMsgHeartbeatAck, nil) {
		t.Fatal("unauthenticated heartbeat ack armed peer failover capability (#16016)")
	}
	if s.handleFrame(conn, nil, syncMsgPeerCapabilities, nil) {
		t.Fatal("unauthenticated peer capabilities changed sync authority (#16016)")
	}

	// A fresh unkeyed connection retains the legacy key-bootstrap path; this
	// keyed-node guard must not break the peer-pushed first-keying flow.
	unkeyed := NewSessionSync("127.0.0.1:0", "10.0.0.2:4785", nil)
	unkeyed.configApplyCh = make(chan configApplyItem, 1)
	unkeyedConn := unkeyed.wrapSyncConn(0, conn, syncAuthUnauthenticated, syncNoiseKeysWithPSK{})
	if !unkeyed.handleFrame(unkeyedConn, nil, syncMsgConfig,
		encodeConfigPayload("system { host-name key-push; }", 1)) {
		t.Fatal("unkeyed peer-pushed config was rejected before keying")
	}
	if len(unkeyed.configApplyCh) != 1 {
		t.Fatal("unkeyed peer-pushed config was not queued before keying")
	}
	if !unkeyed.handleFrame(unkeyedConn, nil, syncMsgBulkStart, bulkStartPayload(1, nil)) {
		t.Fatal("unkeyed peer's bulk sync was rejected before keying")
	}
}

func TestAuthenticatedAuthorityFrameRemainsAcceptedOnceKeyed16016(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "10.0.0.2:4785", nil)
	s.SetAuthProvider(staticKeyProvider16016{key: []byte("local-key-16016")})
	s.configApplyCh = make(chan configApplyItem, 1)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	conn := &authConn{Conn: local, readKey: []byte("read-key"), writeKey: []byte("write-key")}
	if !s.handleFrame(conn, nil, syncMsgConfig,
		encodeConfigPayload("system { host-name authentic; }", 1)) {
		t.Fatal("authenticated config frame was rejected")
	}
	if len(s.configApplyCh) != 1 {
		t.Fatal("authenticated config was not queued for apply")
	}
}

func TestNonPeerCannotDisplaceLiteralPeerConnection16016(t *testing.T) {
	s := NewSessionSync("127.0.0.1:0", "10.0.0.2:4785", nil)
	peerLocal, peerRemote := net.Pipe()
	defer peerRemote.Close()
	genuineBase := &remoteAddrConn16016{
		Conn: peerLocal, remote: &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 53000},
	}
	genuine := s.wrapSyncConn(0, genuineBase, syncAuthUnauthenticated, syncNoiseKeysWithPSK{})
	s.installConn(0, genuine)

	attackerLocal, attackerRemote := net.Pipe()
	defer attackerRemote.Close()
	attackerBase := &remoteAddrConn16016{
		Conn: attackerLocal, remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.99"), Port: 53001},
	}
	attacker := s.wrapSyncConn(0, attackerBase, syncAuthUnauthenticated, syncNoiseKeysWithPSK{})
	s.installConn(0, attacker)

	s.mu.Lock()
	installed := s.conn0
	s.mu.Unlock()
	if installed != genuine {
		t.Fatal("non-peer connection displaced the genuine literal-IP peer (#16016 A5-08)")
	}
	if genuineBase.closed {
		t.Fatal("refusing the non-peer connection closed the genuine peer")
	}
	if !attackerBase.closed {
		t.Fatal("refused non-peer connection was not closed")
	}
}
