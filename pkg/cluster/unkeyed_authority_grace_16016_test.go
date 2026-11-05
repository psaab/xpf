package cluster

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestWriteFrameChokePointCensus16016(t *testing.T) {
	want := map[string]map[string]int{
		"unkeyed_authority_grace_16016.go": {
			"writeFrameLocked.writeFull": 1,
			"writeFrameLocked.writeMsg":  1,
		},
		"sync_auth_noise_7163.go": {
			"performNoiseHandshake.writeMsg":          2,
			"performNoiseResponderHandshake.writeMsg": 1,
		},
		"sync_protocol.go": {
			"writeMsg.writeFull": 1,
		},
	}
	allowedTestFiles := map[string]bool{
		"heartbeat_neverseen_idle_11682_test.go": true,
		"sync_accept_test.go":                    true,
		"sync_auth_confirm_15140_test.go":        true,
		"sync_auth_test.go":                      true,
		"sync_boot_incarnation_5084_test.go":     true,
		"sync_bulk_recv_cap_16039_test.go":       true,
		"sync_conn_halfopen_18521_test.go":       true,
		"sync_liveness_caps_16041_test.go":       true,
		"sync_test.go":                           true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		got := make(map[string]int)
		functionCalls := 0
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					callee = fun.Name
				case *ast.SelectorExpr:
					callee = fun.Sel.Name
				}
				if callee == "writeMsg" || callee == "writeFull" {
					got[fn.Name.Name+"."+callee]++
					functionCalls++
				}
				return true
			})
		}
		allCalls := 0
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				if fun.Name == "writeMsg" || fun.Name == "writeFull" {
					allCalls++
				}
			case *ast.SelectorExpr:
				if fun.Sel.Name == "writeMsg" || fun.Sel.Name == "writeFull" {
					allCalls++
				}
			}
			return true
		})
		if allCalls != functionCalls {
			t.Errorf("%s has a package-scope direct sync writer call", name)
		}
		if strings.HasSuffix(name, "_test.go") {
			if functionCalls > 0 && !allowedTestFiles[name] {
				t.Errorf("new test writer site in unenumerated %s", name)
			}
			continue
		}
		expected, enumerated := want[name]
		if functionCalls > 0 && !enumerated {
			t.Errorf("production direct sync writer site in %s bypasses the choke point", name)
		}
		if !enumerated {
			continue
		}
		for site, count := range expected {
			if got[site] != count {
				t.Errorf("%s has %d direct %s calls, want %d", name, got[site], site, count)
			}
		}
		for site, count := range got {
			if expected[site] != count {
				t.Errorf("%s has unexpected direct writer site %s (%d)", name, site, count)
			}
		}
	}
}

type authorityClock16016 struct {
	mu   sync.Mutex
	wall time.Time
	mono int64
}

func (c *authorityClock16016) wallNow() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

func (c *authorityClock16016) monoNow() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

func (c *authorityClock16016) advance(d time.Duration) {
	c.mu.Lock()
	c.wall = c.wall.Add(d)
	c.mono += int64(d)
	c.mu.Unlock()
}

func (c *authorityClock16016) setWall(t time.Time) {
	c.mu.Lock()
	c.wall = t
	c.mu.Unlock()
}

func (c *authorityClock16016) setMono(n int64) {
	c.mu.Lock()
	c.mono = n
	c.mu.Unlock()
}

func setupAuthorityManager16016(t *testing.T) (*Manager, *authorityClock16016, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "unkeyed-authority-grace")
	clock := &authorityClock16016{wall: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), mono: int64(time.Second)}
	oldGrace := unkeyedAuthorityGrace
	unkeyedAuthorityGrace = 72 * time.Hour
	t.Cleanup(func() { unkeyedAuthorityGrace = oldGrace })
	restoreFabric := SetFabricAuthGraceStatePathForTesting(filepath.Join(t.TempDir(), "fabric-auth-grace"))
	t.Cleanup(restoreFabric)
	restoreEpoch := SetPeerEpochStatePathForTesting(filepath.Join(t.TempDir(), "peer-epoch"))
	t.Cleanup(restoreEpoch)
	restorePath := SetUnkeyedAuthorityGraceStatePathForTesting(path)
	t.Cleanup(restorePath)
	restoreClock := SetUnkeyedAuthorityClocksForTesting(clock.wallNow, clock.monoNow)
	t.Cleanup(restoreClock)
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	return m, clock, path
}

func groupConfig16016() *config.ClusterConfig {
	return &config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: []*config.RedundancyGroup{{
			ID: 0, NodePriorities: map[int]int{0: 100, 1: 200},
		}},
	}
}

func TestUnkeyedGraceHighWaterRestartAndNoReanchor16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	firstExpiry := m.UnkeyedGraceExpiry()
	clock.advance(24 * time.Hour)
	m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var version string
	var earliest, highWater int64
	if _, err := fmt.Sscanf(string(data), "%s %d %d", &version, &earliest, &highWater); err != nil {
		t.Fatalf("parse grace record %q: %v", data, err)
	}
	if version != "v1" || time.Unix(0, earliest).UTC().Add(72*time.Hour) != firstExpiry {
		t.Fatalf("record = %q, expiry %s; want original expiry %s", data, time.Unix(0, earliest).UTC().Add(72*time.Hour), firstExpiry)
	}
	if !time.Unix(0, highWater).UTC().Equal(clock.wallNow()) {
		t.Fatalf("high-water = %s, want %s", time.Unix(0, highWater).UTC(), clock.wallNow())
	}
	clock.advance(49 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("monotonic deadline did not expire after 73h")
	}
	clock.setWall(time.Date(2026, 11, 3, 13, 0, 0, 0, time.UTC)) // roll back across restart
	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	restarted.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if !restarted.UnkeyedAuthorityExpired() {
		t.Fatal("routine restart with a high-water record silently reopened grace")
	}
	if got := restarted.UnkeyedGraceExpiry(); !got.Equal(firstExpiry) {
		t.Fatalf("restart re-anchored expiry to %s, want %s", got, firstExpiry)
	}
}
func TestUnkeyedGraceRestartPreservesRemainingMonotonicBudget16016(t *testing.T) {
	_, clock, _ := setupAuthorityManager16016(t)
	firstExpiry := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	clock.advance(24 * time.Hour)
	original := NewManager(0, 1)
	original.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if got := original.UnkeyedGraceExpiry(); !got.Equal(firstExpiry) {
		t.Fatalf("original expiry = %s, want %s", got, firstExpiry)
	}

	// Simulate a process restart after one day of grace. The restarted
	// monotonic budget must be the 48 hours remaining, not another 72 hours.
	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	restarted.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if got := restarted.UnkeyedGraceExpiry(); !got.Equal(firstExpiry) {
		t.Fatalf("restart changed expiry to %s, want %s", got, firstExpiry)
	}
	if restarted.UnkeyedAuthorityExpired() {
		t.Fatal("restart prematurely expired an in-grace anchor")
	}
	clock.advance(48*time.Hour - time.Nanosecond)
	if restarted.UnkeyedAuthorityExpired() {
		t.Fatal("restart granted a fresh 72-hour monotonic budget")
	}
	clock.advance(time.Nanosecond)
	if !restarted.UnkeyedAuthorityExpired() {
		t.Fatal("restored monotonic budget did not expire at the persisted cutoff")
	}
}

func TestUnkeyedGraceCorruptFailsClosedAndFutureClamps16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	if err := os.WriteFile(path, []byte("corrupt anchor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := NewManager(0, 1)
	corrupt.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if !corrupt.UnkeyedAuthorityExpired() || !corrupt.UnkeyedGraceAnchorCorrupt() {
		t.Fatal("present corrupt anchor did not fail closed at boot")
	}

	futurePath := filepath.Join(t.TempDir(), "future-anchor")
	restore := SetUnkeyedAuthorityGraceStatePathForTesting(futurePath)
	defer restore()
	future := clock.wallNow().Add(24 * time.Hour)
	if err := os.WriteFile(futurePath, []byte(fmt.Sprintf("v1 %d %d\n", future.UnixNano(), future.UnixNano())), 0o600); err != nil {
		t.Fatal(err)
	}
	clamped := NewManager(0, 1)
	clamped.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if clamped.UnkeyedAuthorityExpired() {
		t.Fatal("future-dated anchor extended or prematurely expired the grace")
	}
	if got := clamped.UnkeyedGraceExpiry(); !got.Equal(clock.wallNow().Add(72 * time.Hour)) {
		t.Fatalf("future anchor expiry = %s, want clamped expiry %s", got, clock.wallNow().Add(72*time.Hour))
	}
	data, err := os.ReadFile(futurePath)
	if err != nil || !strings.Contains(string(data), fmt.Sprint(clock.wallNow().UnixNano())) {
		t.Fatalf("clamped record = %q, err=%v", data, err)
	}
	_ = m
}

func TestUnkeyedGraceWriteFailureExpiresInProcess16016(t *testing.T) {
	clock := &authorityClock16016{wall: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), mono: int64(time.Second)}
	oldGrace := unkeyedAuthorityGrace
	unkeyedAuthorityGrace = 72 * time.Hour
	t.Cleanup(func() { unkeyedAuthorityGrace = oldGrace })
	tempDir := t.TempDir()
	restorePath := SetUnkeyedAuthorityGraceStatePathForTesting(filepath.Join(tempDir, "unkeyed-authority-grace"))
	defer restorePath()
	restoreFabric := SetFabricAuthGraceStatePathForTesting(filepath.Join(tempDir, "fabric-auth-grace"))
	defer restoreFabric()
	restoreEpoch := SetPeerEpochStatePathForTesting(filepath.Join(tempDir, "peer-epoch"))
	defer restoreEpoch()
	restorePersist := SetUnkeyedAuthorityPersistForTesting(func(string, time.Time, time.Time) error {
		return fmt.Errorf("injected persist failure")
	})
	defer restorePersist()
	restoreClock := SetUnkeyedAuthorityClocksForTesting(clock.wallNow, clock.monoNow)
	defer restoreClock()
	m := NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if !m.UnkeyedGraceNotPersisted() {
		t.Fatal("failed anchor write was not exposed in status")
	}
	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("persist failure disabled the in-process monotonic deadline")
	}
	if got := m.unkeyedAuthorityGraceStatus(); !strings.Contains(got, "anchor not persisted") {
		t.Fatalf("expired status omitted persistence failure: %q", got)
	}
}

func TestUnkeyedGraceWireGateWritersAndKeyRearm16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	s := NewSessionSync("127.0.0.1:0", "", nil)
	s.SetAuthProvider(m)
	s.configApplyCh = make(chan configApplyItem, 2)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	if !s.handleFrame(local, nil, syncMsgConfig, encodeConfigPayload("system { host-name first-key; }", 1)) {
		t.Fatal("first-key config was refused inside the grace")
	}
	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("grace did not expire")
	}
	for _, typ := range []uint8{syncMsgHeartbeat, syncMsgAuthUpgradeRequest, syncMsgConfig, syncMsgBulkStart, syncMsgFence, syncMsgFailover, 255} {
		if s.handleFrame(local, nil, typ, nil) {
			t.Fatalf("post-grace frame type %d was accepted", typ)
		}
	}
	s.writeMu.Lock()
	writeErr := s.writeFrameLocked(local, syncMsgHeartbeat, nil, nil)
	s.writeMu.Unlock()
	if writeErr != errUnkeyedAuthorityGraceEnded {
		t.Fatalf("post-grace direct writer error = %v, want grace refusal", writeErr)
	}
	if got := s.enforceStrictSessionAuth(); got != 0 {
		t.Fatalf("evicted %d connections when no conn was installed", got)
	}
	before := m.UnkeyedGraceExpiry()
	clock.advance(time.Hour)
	m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if got := m.UnkeyedGraceExpiry(); !got.Equal(before) {
		t.Fatalf("wire/config touch re-anchored expiry from %s to %s", before, got)
	}
	m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0", ControlLinkAuthKey: config.NewSecret("key-16016")})
	if m.UnkeyedAuthorityExpired() {
		t.Fatal("local key commit did not clear expired posture")
	}
	if _, err := os.Stat(unkeyedAuthorityGraceStatePath); !os.IsNotExist(err) {
		t.Fatalf("local key commit did not delete anchor: %v", err)
	}
	m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if m.UnkeyedAuthorityExpired() || !m.UnkeyedGraceExpiry().After(clock.wallNow()) {
		t.Fatal("local key clear did not stamp a fresh grace")
	}
}
func TestWriteFrameGuardBlocksDirectFamiliesPostExpiry16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	s := NewSessionSync("127.0.0.1:0", "", nil)
	s.SetAuthProvider(m)
	clock.advance(73 * time.Hour)
	tests := []struct {
		name    string
		msgType uint8
		payload []byte
		encoded []byte
	}{
		{name: "liveness", msgType: syncMsgHeartbeat},
		{name: "configuration", msgType: syncMsgConfig, payload: []byte("config")},
		{name: "auth-upgrade", msgType: syncMsgAuthUpgradeRequest, payload: []byte{syncAuthUpgradeVersion}},
		{name: "bulk-and-barrier", msgType: syncMsgBulkStart, payload: []byte("bulk")},
		{name: "failover", msgType: syncMsgFailover, payload: []byte("failover")},
		{name: "queued-session", encoded: []byte("encoded-frame")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			local, peer := net.Pipe()
			defer local.Close()
			defer peer.Close()
			_ = local.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			s.writeMu.Lock()
			err := s.writeFrameLocked(local, test.msgType, test.payload, test.encoded)
			s.writeMu.Unlock()
			if err != errUnkeyedAuthorityGraceEnded {
				t.Fatalf("writer error = %v, want grace refusal", err)
			}
			_ = peer.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			var got [1]byte
			if n, err := peer.Read(got[:]); err == nil || n != 0 {
				t.Fatalf("post-grace writer emitted %d byte(s), err=%v", n, err)
			}
		})
	}
}

func TestExpiredConnectionInstallAndSweep16016(t *testing.T) {
	entryManager, entryClock, _ := setupAuthorityManager16016(t)
	entryClock.advance(73 * time.Hour)
	entrySync := NewSessionSync("127.0.0.1:0", "", nil)
	entrySync.SetAuthProvider(entryManager)
	entryConn, entryPeer := net.Pipe()
	defer entryPeer.Close()
	entrySync.handleNewConnection(context.Background(), 0, entryConn, false)
	entryPeer.SetReadDeadline(time.Now().Add(time.Second))
	var probe [1]byte
	if _, err := entryPeer.Read(probe[:]); err == nil {
		t.Fatal("expired connection admission left the peer stream open")
	}
	entrySync.mu.Lock()
	entryInstalled := entrySync.conn0 != nil || entrySync.conn1 != nil
	entrySync.mu.Unlock()
	if entryInstalled {
		t.Fatal("expired connection admission installed an unauthenticated connection")
	}

	replaceManager, replaceClock, _ := setupAuthorityManager16016(t)
	replaceSync := NewSessionSync("127.0.0.1:0", "", nil)
	replaceSync.SetAuthProvider(replaceManager)
	oldConn, oldPeer := net.Pipe()
	defer oldConn.Close()
	defer oldPeer.Close()
	if d := replaceSync.installConn(0, oldConn); !d.installed {
		t.Fatal("in-grace incumbent did not install")
	}
	newConn, newPeer := net.Pipe()
	defer newConn.Close()
	defer newPeer.Close()
	replaceClock.advance(73 * time.Hour)
	if d := replaceSync.installConn(0, newConn); d.installed {
		t.Fatal("expired candidate displaced the installed unauthenticated connection")
	}
	replaceSync.mu.Lock()
	incumbentPreserved := replaceSync.conn0 == oldConn
	replaceSync.mu.Unlock()
	if !incumbentPreserved {
		t.Fatal("expired candidate changed the installed connection slot")
	}

	m, clock, _ := setupAuthorityManager16016(t)
	s := NewSessionSync("127.0.0.1:0", "", nil)
	s.SetAuthProvider(m)
	local, remote := net.Pipe()
	defer remote.Close()
	s.testBeforeInstallConn = func() { clock.setMono(int64(time.Second) + int64(73*time.Hour)) }
	s.handleNewConnection(context.Background(), 0, local, false)
	s.mu.Lock()
	installed := s.conn0
	s.mu.Unlock()
	if installed != nil {
		t.Fatal("expired install seam stored an unauthenticated connection")
	}
	if err := local.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed rejected connection: %v", err)
	}

	// A separate in-grace connection is evicted when the periodic strict-auth
	// sweep first observes the expired posture.
	m2, clock2, _ := setupAuthorityManager16016(t)
	s2 := NewSessionSync("127.0.0.1:0", "", nil)
	s2.SetAuthProvider(m2)
	var peers []net.Conn
	for i := 0; i < 2; i++ {
		localConn, peerConn := net.Pipe()
		peers = append(peers, peerConn)
		if d := s2.installConn(i, localConn); !d.installed {
			t.Fatalf("in-grace connection %d did not install", i)
		}
	}
	defer func() {
		for _, p := range peers {
			_ = p.Close()
		}
	}()
	clock2.advance(73 * time.Hour)
	if n := s2.enforceStrictSessionAuth(); n != 2 {
		t.Fatalf("strict sweep evicted %d expired unauthenticated connections, want 2", n)
	}
	s2.mu.Lock()
	remaining := s2.conn0 != nil || s2.conn1 != nil
	s2.mu.Unlock()
	if remaining {
		t.Fatal("expired unauthenticated connection remained installed")
	}
}

func TestExpiredUnkeyedHeartbeatAndElectionHold16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	m.UpdateConfig(groupConfig16016())
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.peerAlive = false
	m.mu.Unlock()
	clock.advance(73 * time.Hour)
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	pkt := &HeartbeatPacket{NodeID: 1, ClusterID: 1, Groups: []HeartbeatGroup{{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)}}}
	frame := MarshalHeartbeat(pkt)
	decoded, err := UnmarshalHeartbeat(frame)
	if err != nil {
		t.Fatal(err)
	}
	if r.admitFrame(frame, decoded) {
		t.Fatal("expired unauthenticated heartbeat was admitted")
	}
	if r.received.Load() != 0 || m.PeerProofGeneration() != 0 {
		t.Fatal("rejected heartbeat refreshed liveness or published peer proof")
	}
	m.mu.Lock()
	m.electSingleNode()
	m.runElection()
	state := m.groups[0].State
	m.mu.Unlock()
	if state != StateSecondary {
		t.Fatalf("expired election acquired primary: %s", state)
	}
}

func TestProofGenerationAfterPeerStateAndNoSyncRelease16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	m.UpdateConfig(groupConfig16016())
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.mu.Unlock()
	clock.advance(73 * time.Hour)
	m.UnkeyedAuthorityExpired()
	key := []byte("recovery-key-16016")
	m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0", RedundancyGroups: groupConfig16016().RedundancyGroups, ControlLinkAuthKey: config.NewSecret(string(key))})
	if !m.RecoveryHoldActive() {
		t.Fatal("keying expired cluster did not arm recovery hold")
	}
	m.noteSyncPeerAuthenticated(key)
	if !m.RecoveryHoldActive() || m.PeerProofGeneration() != 0 {
		t.Fatal("sync transport proof released recovery hold")
	}
	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	r.testBeforeProofPublish = func() { close(entered); <-release }
	pkt := &HeartbeatPacket{NodeID: 1, ClusterID: 1, Groups: []HeartbeatGroup{{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)}}}
	frame := MarshalHeartbeatAuth(pkt, key, 16016, 1)
	decoded, err := UnmarshalHeartbeat(frame)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan bool, 1)
	go func() { accepted <- r.admitFrame(frame, decoded) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("authenticated heartbeat did not reach post-state proof seam")
	}
	m.mu.RLock()
	peer, installed := m.peerGroups[0]
	m.mu.RUnlock()
	if !installed || peer.State != StatePrimary || !m.RecoveryHoldActive() || m.PeerProofGeneration() != 0 {
		t.Fatal("proof was published before authenticated peer state was installed")
	}
	close(release)
	if !<-accepted {
		t.Fatal("authenticated heartbeat was rejected")
	}
	if m.RecoveryHoldActive() || m.PeerProofGeneration() != 1 {
		t.Fatal("post-install authenticated heartbeat did not release recovery hold")
	}
}

func TestForcePrimaryRecoveryPinnedAndAudited16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	m.UpdateConfig(groupConfig16016())
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.mu.Unlock()
	clock.advance(73 * time.Hour)
	m.UnkeyedAuthorityExpired()
	m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0", RedundancyGroups: groupConfig16016().RedundancyGroups, ControlLinkAuthKey: config.NewSecret("force-key-16016")})
	var audited bool
	m.SetUnkeyedRecoveryAuditHook(func(action, operator string, rgID, nodeID int, at time.Time, reason string) {
		audited = action == "force-primary" && operator == "manual-operator-16016" &&
			rgID == 0 && nodeID == m.NodeID() && !at.IsZero() &&
			strings.Contains(reason, "authenticated heartbeat proof")
	})
	if err := m.ForcePrimaryRecovery(0, "manual-operator-16016"); err != nil {
		t.Fatalf("ForcePrimaryRecovery: %v", err)
	}
	if !audited {
		t.Fatal("force-primary recovery did not invoke the local audit sink")
	}
	if !m.IsLocalPrimary(0) {
		t.Fatal("force-primary recovery did not acquire primary")
	}
	m.mu.RLock()
	pinned := m.groups[0].forcedPrimary
	m.mu.RUnlock()
	if !pinned {
		t.Fatal("force-primary recovery did not pin ownership")
	}
	if err := m.ResetFailover(0); err != nil {
		t.Fatalf("ResetFailover: %v", err)
	}
	m.mu.RLock()
	pinned = m.groups[0].forcedPrimary
	m.mu.RUnlock()
	if pinned {
		t.Fatal("ResetFailover did not clear force-primary pin")
	}
}

func TestForcePrimaryRecoveryRefusedOutsideRecovery16016(t *testing.T) {
	m, _, _ := setupAuthorityManager16016(t)
	m.UpdateConfig(groupConfig16016())
	if err := m.ForcePrimaryRecovery(0, "manual-operator-16016"); err == nil {
		t.Fatal("force-primary recovery was accepted without recovery hold")
	}
}

func TestForcePrimaryRecoveryBlockedByKernelUpgradeHold16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	m.UpdateConfig(groupConfig16016())
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.mu.Unlock()
	clock.advance(73 * time.Hour)
	m.UnkeyedAuthorityExpired()
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0", RedundancyGroups: groupConfig16016().RedundancyGroups,
		ControlLinkAuthKey: config.NewSecret("force-key-16016"),
	})
	m.mu.Lock()
	m.kernelUpgradeHold = true
	m.mu.Unlock()
	if err := m.ForcePrimaryRecovery(0, "manual-operator-16016"); err == nil {
		t.Fatal("force-primary recovery overrode the kernel-upgrade hold")
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("kernel-upgrade hold left the RG primary")
	}
}
func setupBareAuthorityManager16016(t *testing.T) (*Manager, *authorityClock16016, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "unkeyed-authority-grace")
	clock := &authorityClock16016{
		wall: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
		mono: int64(time.Second),
	}
	oldGrace := unkeyedAuthorityGrace
	unkeyedAuthorityGrace = 72 * time.Hour
	t.Cleanup(func() { unkeyedAuthorityGrace = oldGrace })
	restoreFabric := SetFabricAuthGraceStatePathForTesting(filepath.Join(t.TempDir(), "fabric-auth-grace"))
	t.Cleanup(restoreFabric)
	restoreEpoch := SetPeerEpochStatePathForTesting(filepath.Join(t.TempDir(), "peer-epoch"))
	t.Cleanup(restoreEpoch)
	restorePath := SetUnkeyedAuthorityGraceStatePathForTesting(path)
	t.Cleanup(restorePath)
	restoreClock := SetUnkeyedAuthorityClocksForTesting(clock.wallNow, clock.monoNow)
	t.Cleanup(restoreClock)
	return NewManager(0, 1), clock, path
}

func TestUnkeyedGraceFabricOnlyTransportAnchorsAndExpires16016(t *testing.T) {
	m, clock, path := setupBareAuthorityManager16016(t)
	cfg := &config.ClusterConfig{
		FabricInterface:   "fab0",
		FabricPeerAddress: "192.0.2.2",
	}
	m.UpdateConfig(cfg)
	expiry := m.UnkeyedGraceExpiry()
	if expiry.IsZero() || !expiry.Equal(clock.wallNow().Add(unkeyedAuthorityGrace)) {
		t.Fatalf("fabric-only zero-RG expiry = %s, want %s", expiry, clock.wallNow().Add(unkeyedAuthorityGrace))
	}
	if len(m.GroupStates()) != 0 {
		t.Fatalf("fabric-only zero-RG config created groups: %+v", m.GroupStates())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fabric-only config did not persist a grace anchor: %v", err)
	}

	// The pre-listener belt sees the same compiled transport fields and
	// restores, rather than moving, the persisted cutoff.
	bootManager := NewManager(0, 1)
	bootManager.StampUnkeyedAuthorityAnchor(cfg)
	if got := bootManager.UnkeyedGraceExpiry(); !got.Equal(expiry) {
		t.Fatalf("fabric-only boot belt expiry = %s, want original %s", got, expiry)
	}
	clock.advance(73 * time.Hour)
	if !bootManager.UnkeyedAuthorityExpired() {
		t.Fatal("fabric-only zero-RG cluster remained unexpired beyond 72h")
	}

	ss := NewSessionSync(":0", "192.0.2.2:4785", nil)
	ss.SetAuthProvider(bootManager)
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	ss.writeMu.Lock()
	err := ss.writeFrameLocked(local, syncMsgHeartbeat, nil, nil)
	ss.writeMu.Unlock()
	if err == nil || err != errUnkeyedAuthorityGraceEnded {
		t.Fatalf("post-grace fabric-only direct frame write error = %v, want %v", err, errUnkeyedAuthorityGraceEnded)
	}
}

func TestPeerKeyTransitionsPreserveOriginalUnkeyedCutoff16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	firstExpiry := m.UnkeyedGraceExpiry()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	keyed := &config.ClusterConfig{
		ControlInterface:  "em0",
		ControlLinkAuthKey: config.NewSecret("peer-key-16016"),
	}
	m.UpdateConfigFromPeer(keyed)
	if !m.ControlLinkAuthConfigured() {
		t.Fatal("peer first-key config did not install the accepted key")
	}
	if m.RecoveryHoldActive() {
		t.Fatal("peer first-key config armed a local expired-to-keyed recovery hold")
	}
	keyless := &config.ClusterConfig{ControlInterface: "em0"}
	m.UpdateConfigFromPeer(keyless)
	if m.ControlLinkAuthConfigured() {
		t.Fatal("peer key-clear config did not remove the accepted key")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("peer key/clear sequence changed the local grace record: before=%q after=%q", before, after)
	}
	if got := m.UnkeyedGraceExpiry(); !got.Equal(firstExpiry) {
		t.Fatalf("peer key/clear sequence moved cutoff to %s, want %s", got, firstExpiry)
	}
	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("peer key-clear reopened an expired original grace window")
	}
}

func TestUnkeyedGraceSweepRatchetsHighWaterWithoutConfigTouch16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	earliest := clock.wallNow()
	expiry := m.UnkeyedGraceExpiry()

	clock.setWall(earliest.Add(48 * time.Hour))
	// No UpdateConfig or comms restart: the existing one-second sweep is the
	// only owner that observes and persists this wall-clock progress.
	m.checkUnkeyedGraceNotices()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var version string
	var savedEarliest, highWater int64
	if _, err := fmt.Sscanf(string(data), "%s %d %d", &version, &savedEarliest, &highWater); err != nil {
		t.Fatalf("parse grace record %q: %v", data, err)
	}
	if version != "v1" || time.Unix(0, savedEarliest).UTC() != earliest ||
		time.Unix(0, highWater).UTC() != earliest.Add(48*time.Hour) {
		t.Fatalf("sweep record = %q, want earliest=%s high-water=%s", data, earliest, earliest.Add(48*time.Hour))
	}

	clock.setWall(earliest.Add(time.Hour))
	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	restarted.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if got := restarted.UnkeyedGraceExpiry(); !got.Equal(expiry) {
		t.Fatalf("rollback restart moved cutoff to %s, want %s", got, expiry)
	}
	if restarted.UnkeyedAuthorityExpired() {
		t.Fatal("high-water ratchet caused early expiry after rollback")
	}
	clock.advance(24*time.Hour - time.Nanosecond)
	if restarted.UnkeyedAuthorityExpired() {
		t.Fatal("rollback restart refunded or shortened the remaining 24-hour budget")
	}
	clock.advance(time.Nanosecond)
	if !restarted.UnkeyedAuthorityExpired() {
		t.Fatal("rollback restart extended the original cutoff")
	}

	// Expiry itself persists the cutoff as the high-water, so another routine
	// restart remains expired rather than opening a third window.
	clock.setWall(earliest.Add(25 * time.Hour))
	clock.setMono(int64(time.Second))
	restartedAgain := NewManager(0, 1)
	restartedAgain.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if !restartedAgain.UnkeyedAuthorityExpired() {
		t.Fatal("repeated rollback restart reopened an expired grace window")
	}
}

func TestUnkeyedGraceKeyedSweepPreservesCutoffAcrossRestart16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	earliest := clock.wallNow()
	expiry := m.UnkeyedGraceExpiry()
	m.UpdateConfigFromPeer(&config.ClusterConfig{
		ControlInterface:   "em0",
		ControlLinkAuthKey: config.NewSecret("peer-key-16016"),
	})
	clock.setWall(earliest.Add(48 * time.Hour))
	m.checkUnkeyedGraceNotices()
	m.UpdateConfigFromPeer(&config.ClusterConfig{ControlInterface: "em0"})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var version string
	var savedEarliest, highWater int64
	if _, err := fmt.Sscanf(string(data), "%s %d %d", &version, &savedEarliest, &highWater); err != nil {
		t.Fatalf("parse keyed grace record %q: %v", data, err)
	}
	if time.Unix(0, highWater).UTC() != earliest.Add(48*time.Hour) {
		t.Fatalf("keyed sweep high-water = %s, want %s", time.Unix(0, highWater).UTC(), earliest.Add(48*time.Hour))
	}
	clock.setWall(earliest.Add(time.Hour))
	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	restarted.UpdateConfigFromBoot(&config.ClusterConfig{ControlInterface: "em0"})
	if got := restarted.UnkeyedGraceExpiry(); !got.Equal(expiry) {
		t.Fatalf("keyed-period rollback restart expiry = %s, want original %s", got, expiry)
	}
	clock.advance(24 * time.Hour)
	if !restarted.UnkeyedAuthorityExpired() {
		t.Fatal("keyed-period high-water progress was refundable after restart")
	}
}
func TestForcePrimaryRecoveryPinSurvivesNonPrimaryProof16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	m.UpdateConfig(groupConfig16016())
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.mu.Unlock()
	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("test setup did not expire unkeyed grace")
	}
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0", RedundancyGroups: groupConfig16016().RedundancyGroups,
		ControlLinkAuthKey: config.NewSecret("force-key-16016"),
	})
	if err := m.ForcePrimaryRecovery(0, "manual-operator-16016"); err != nil {
		t.Fatalf("ForcePrimaryRecovery: %v", err)
	}
	m.mu.Lock()
	m.peerGroups[0] = PeerGroupState{GroupID: 0, State: StateSecondary}
	m.peerAlive = false
	m.mu.Unlock()
	m.publishFreshHeartbeatProof()
	m.mu.RLock()
	pinned := m.groups[0].forcedPrimary
	localPrimary := m.groups[0].State == StatePrimary
	m.mu.RUnlock()
	if m.RecoveryHoldActive() || !pinned || !localPrimary {
		t.Fatalf("non-primary proof released pin incorrectly: hold=%v pinned=%v localPrimary=%v",
			m.RecoveryHoldActive(), pinned, localPrimary)
	}
}

func TestUnkeyedGraceNoticeLadderEscalates16016(t *testing.T) {
	m, clock, _ := setupBareAuthorityManager16016(t)
	type notice struct {
		rung   string
		raised bool
		expiry time.Time
	}
	notices := make(chan notice, 8)
	m.SetUnkeyedGraceAlarmHook(func(rung string, raised bool, expiry time.Time) {
		notices <- notice{rung: rung, raised: raised, expiry: expiry}
	})
	m.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	expiry := m.UnkeyedGraceExpiry()
	expect := func(rung string, raised bool) {
		t.Helper()
		select {
		case got := <-notices:
			if got.rung != rung || got.raised != raised || !got.expiry.Equal(expiry) {
				t.Fatalf("notice = %+v, want rung=%q raised=%v expiry=%s", got, rung, raised, expiry)
			}
		case <-time.After(time.Second):
			t.Fatalf("missing %q notice", rung)
		}
	}
	expect("stamped", true)
	for _, tc := range []struct {
		advance time.Duration
		rung    string
	}{
		{48 * time.Hour, "t-24h"},
		{23 * time.Hour, "t-1h"},
		{time.Hour, "expired"},
		{24 * time.Hour, "daily-expired"},
	} {
		clock.advance(tc.advance)
		m.checkUnkeyedGraceNotices()
		expect(tc.rung, true)
	}
	m.checkUnkeyedGraceNotices()
	select {
	case extra := <-notices:
		t.Fatalf("duplicate notice after ladder completed: %+v", extra)
	default:
	}
}

func TestUnkeyedGraceRoutineRestartStaysExpired16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	cutoff := m.UnkeyedGraceExpiry()
	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("grace did not expire")
	}
	clock.setWall(time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	restarted.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if !restarted.UnkeyedAuthorityExpired() {
		t.Fatal("routine restart reopened expired grace")
	}
	if got := restarted.UnkeyedGraceExpiry(); !got.Equal(cutoff) {
		t.Fatalf("routine restart moved cutoff to %s, want %s", got, cutoff)
	}
}

func TestWrongRTCClockInstaExpiryHoldsAndAlarms16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	cutoff := m.UnkeyedGraceExpiry()
	clock.setWall(cutoff.Add(time.Hour))
	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	notices := make(chan notice16016, 4)
	restarted.SetUnkeyedGraceAlarmHook(func(rung string, raised bool, expiry time.Time) {
		notices <- notice16016{rung: rung, raised: raised, expiry: expiry}
	})
	restarted.UpdateConfig(groupConfig16016())
	if !restarted.UnkeyedAuthorityExpired() {
		t.Fatal("forward RTC step did not expire the persisted cutoff at boot")
	}
	restarted.mu.RLock()
	held := restarted.electionHoldActiveLocked()
	restarted.mu.RUnlock()
	if !held {
		t.Fatal("expired RTC posture did not suppress election")
	}
	select {
	case got := <-notices:
		if got.rung != "expired" || !got.raised || !got.expiry.Equal(cutoff) {
			t.Fatalf("expiry alarm = %+v, want expired raise at %s", got, cutoff)
		}
	case <-time.After(time.Second):
		t.Fatal("forward RTC expiry did not raise an alarm")
	}
	if got := restarted.UnkeyedGraceExpiry(); !got.Equal(cutoff) {
		t.Fatalf("forward RTC step re-anchored cutoff to %s, want %s", got, cutoff)
	}
}

type notice16016 struct {
	rung   string
	raised bool
	expiry time.Time
}

func TestUnkeyedGraceCorruptAnchorFailsClosed16016(t *testing.T) {
	_, clock, path := setupAuthorityManager16016(t)
	if err := os.WriteFile(path, []byte("corrupt unkeyed authority anchor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	notices := make(chan notice16016, 4)
	restarted.SetUnkeyedGraceAlarmHook(func(rung string, raised bool, expiry time.Time) {
		notices <- notice16016{rung: rung, raised: raised, expiry: expiry}
	})
	restarted.UpdateConfig(groupConfig16016())
	if !restarted.UnkeyedGraceAnchorCorrupt() || !restarted.UnkeyedAuthorityExpired() {
		t.Fatal("corrupt persisted anchor did not fail closed at boot")
	}
	select {
	case got := <-notices:
		if got.rung != "expired" || !got.raised {
			t.Fatalf("corrupt-anchor alarm = %+v, want expired raise", got)
		}
	case <-time.After(time.Second):
		t.Fatal("corrupt anchor did not raise an expiry alarm")
	}
}

func TestUnkeyedGraceRestartRequiresExpiredUnkeyedPosture16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	if _, err := m.RestartUnkeyedAuthorityGrace("operator-16016"); err == nil {
		t.Fatal("operator re-armed an active grace window")
	}
	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("grace did not expire")
	}
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0", ControlLinkAuthKey: config.NewSecret("key-16016"),
	})
	if _, err := m.RestartUnkeyedAuthorityGrace("operator-16016"); err == nil {
		t.Fatal("operator re-armed grace while keyed")
	}
}

func TestUnkeyedGraceRestartIsAuditedAndPersistsFreshCutoff16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("grace did not expire")
	}
	var auditAction, auditOperator, auditReason string
	var auditRG, auditNode int
	var auditAt time.Time
	m.SetUnkeyedRecoveryAuditHook(func(action, operator string, rgID, nodeID int, at time.Time, reason string) {
		auditAction, auditOperator, auditRG, auditNode, auditAt, auditReason =
			action, operator, rgID, nodeID, at, reason
	})
	expiry, err := m.RestartUnkeyedAuthorityGrace("rtc-operator-16016")
	if err != nil {
		t.Fatalf("RestartUnkeyedAuthorityGrace: %v", err)
	}
	now := clock.wallNow()
	if !expiry.Equal(now.Add(72 * time.Hour)) || m.UnkeyedAuthorityExpired() {
		t.Fatalf("re-armed expiry=%s expired=%v, want %s and active",
			expiry, m.UnkeyedAuthorityExpired(), now.Add(72*time.Hour))
	}
	if auditAction != "unkeyed-grace-restart" || auditOperator != "rtc-operator-16016" ||
		auditRG != -1 || auditNode != m.NodeID() || !auditAt.Equal(now) ||
		!strings.Contains(auditReason, "clock step") {
		t.Fatalf("re-arm audit = action=%q operator=%q rg=%d node=%d at=%s reason=%q",
			auditAction, auditOperator, auditRG, auditNode, auditAt, auditReason)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var version string
	var earliest, highWater int64
	if _, err := fmt.Sscanf(string(data), "%s %d %d", &version, &earliest, &highWater); err != nil {
		t.Fatalf("parse re-armed anchor %q: %v", data, err)
	}
	if version != "v1" || time.Unix(0, earliest).UTC() != now ||
		time.Unix(0, highWater).UTC() != now {
		t.Fatalf("re-armed anchor = %q, want fresh earliest/high-water %s", data, now)
	}
}
func TestLocalKeyThenPeerClearFailsClosedAcrossRestart16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0", ControlLinkAuthKey: config.NewSecret("local-key-16016"),
	})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("local key commit did not delete the old grace anchor: %v", err)
	}
	m.UpdateConfigFromPeer(&config.ClusterConfig{ControlInterface: "em0"})
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("peer key-clear without a surviving local cutoff reopened unkeyed authority")
	}
	now := clock.wallNow()
	if got := m.UnkeyedGraceExpiry(); !got.Equal(now) {
		t.Fatalf("peer key-clear cutoff=%s, want fail-closed cutoff %s", got, now)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("peer key-clear did not persist its fail-closed cutoff: %v", err)
	}

	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	restarted.UpdateConfigFromBoot(&config.ClusterConfig{ControlInterface: "em0"})
	if !restarted.UnkeyedAuthorityExpired() {
		t.Fatal("restart reopened the peer-cleared cluster without a local re-arm")
	}
	if got := restarted.UnkeyedGraceExpiry(); !got.Equal(now) {
		t.Fatalf("restart moved fail-closed cutoff to %s, want %s", got, now)
	}
}
func TestBootKeyedPeerClearWithoutAnchorStaysExpired16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0", ControlLinkAuthKey: config.NewSecret("local-key-16016"),
	})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("local key commit did not delete the old grace anchor: %v", err)
	}
	clock.setMono(int64(time.Second))
	keyedRestart := NewManager(0, 1)
	keyedRestart.UpdateConfigFromBoot(&config.ClusterConfig{
		ControlInterface: "em0", ControlLinkAuthKey: config.NewSecret("local-key-16016"),
	})
	keyedRestart.UpdateConfigFromPeer(&config.ClusterConfig{ControlInterface: "em0"})
	if !keyedRestart.UnkeyedAuthorityExpired() {
		t.Fatal("peer key-clear after keyed boot opened fresh unkeyed authority")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("keyed-boot peer clear did not persist its expired cutoff: %v", err)
	}
}
