package cluster

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
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
func TestElectionCallerCensus16016(t *testing.T) {
	want := map[string]map[string]int{
		"election.go": {
			"recalcWeight.runElection":               1,
			"recalcWeight.electSingleNode":           1,
			"armDegradedTimerLocked.runElection":     1,
			"armDegradedTimerLocked.electSingleNode": 1,
		},
		"failover.go": {
			"commitRequestedPeerFailoverWith.runElection":  1,
			"abortRequestedPeerFailover.runElection":       1,
			"AbortRemoteTransferOut.runElection":           1,
			"commitRequestedPeerFailoverBatch.runElection": 1,
			"abortRequestedPeerFailoverBatch.runElection":  1,
		},
		"group_state.go": {
			"updateConfig.runElection":     1,
			"updateConfig.electSingleNode": 1,
		},
		"heartbeat_manager.go": {
			"handlePeerHeartbeat.runElection":     1,
			"handlePeerTimeout.runElection":       1,
			"handlePeerTimeout.electSingleNode":   1,
			"handlePeerNeverSeen.electSingleNode": 1,
		},
		"kernel_selfrecover.go": {
			"ClearKernelUpgradeHold.runElection":     1,
			"ClearKernelUpgradeHold.electSingleNode": 1,
		},
		"readiness.go": {
			"SetRGReady.runElection":     2,
			"SetRGReady.electSingleNode": 2,
		},
		"unkeyed_authority_grace_16016.go": {
			"publishFreshHeartbeatProof.runElection":     1,
			"publishFreshHeartbeatProof.electSingleNode": 1,
		},
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		got := make(map[string]int)
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
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if ok && (selector.Sel.Name == "runElection" || selector.Sel.Name == "electSingleNode") {
					got[fn.Name.Name+"."+selector.Sel.Name]++
				}
				return true
			})
		}
		expected, enumerated := want[name]
		if len(got) > 0 && !enumerated {
			t.Errorf("unkeyed-election bypass found in %s: %v", name, got)
			continue
		}
		for site, count := range expected {
			if got[site] != count {
				t.Errorf("%s has %d calls at %s, want %d", name, got[site], site, count)
			}
		}
		for site, count := range got {
			if expected[site] != count {
				t.Errorf("%s has unenumerated election caller %s (%d)", name, site, count)
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
func TestUnkeyedGraceRollbackCannotRefundMonotonicElapsedAcrossRestarts16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	t0 := clock.wallNow()
	clock.advance(48 * time.Hour)
	m.checkUnkeyedGraceNotices()

	clock.setWall(t0.Add(time.Hour))
	clock.setMono(int64(time.Second))
	firstRestart := NewManager(0, 1)
	firstRestart.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if got := firstRestart.UnkeyedGraceExpiry(); !got.Equal(t0.Add(72 * time.Hour)) {
		t.Fatalf("first rollback restart expiry = %s, want %s", got, t0.Add(72*time.Hour))
	}
	clock.advance(23 * time.Hour)
	firstRestart.checkUnkeyedGraceNotices()

	clock.setWall(t0.Add(time.Hour))
	clock.setMono(int64(time.Second))
	secondRestart := NewManager(0, 1)
	secondRestart.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if secondRestart.UnkeyedAuthorityExpired() {
		t.Fatal("second rollback restart expired before cumulative monotonic time reached 72h")
	}
	clock.advance(time.Hour)
	if !secondRestart.UnkeyedAuthorityExpired() {
		t.Fatal("elapsed floor refunded the final hour after repeated rollback and restart")
	}

	clock.setWall(t0.Add(time.Hour))
	clock.setMono(int64(time.Second))
	thirdRestart := NewManager(0, 1)
	thirdRestart.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if !thirdRestart.UnkeyedAuthorityExpired() {
		t.Fatal("a further rollback/restart cycle reopened the expired grace")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var version string
	var earliest, highWater, elapsed int64
	if _, err := fmt.Sscanf(string(data), "%s %d %d %d", &version, &earliest, &highWater, &elapsed); err != nil {
		t.Fatalf("parse grace record %q: %v", data, err)
	}
	if version != "v2" || time.Duration(elapsed) < 72*time.Hour {
		t.Fatalf("terminal record = %q, want v2 elapsed floor >=72h", data)
	}
}

func TestUnkeyedGraceSweepAndConfigTouchPersistExpiryAcrossRollback16016(t *testing.T) {
	for _, trigger := range []string{"sweep", "config-touch"} {
		t.Run(trigger, func(t *testing.T) {
			m, clock, path := setupAuthorityManager16016(t)
			earliest := clock.wallNow()
			expiry := m.UnkeyedGraceExpiry()
			clock.advance(73 * time.Hour)

			var expired bool
			if trigger == "sweep" {
				m.checkUnkeyedGraceNotices()
				expired = m.UnkeyedAuthorityExpired()
			} else {
				bootManager := NewManager(0, 1)
				bootManager.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
				expired = bootManager.UnkeyedAuthorityExpired()
			}
			if !expired {
				t.Fatalf("%s did not observe the expired cutoff", trigger)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var version string
			var earliestNS, highWaterNS, elapsedNS int64
			if _, err := fmt.Sscanf(string(data), "%s %d %d %d",
				&version, &earliestNS, &highWaterNS, &elapsedNS); err != nil {
				t.Fatalf("parse terminal grace record %q: %v", data, err)
			}
			if version != "v2" || !time.Unix(0, earliestNS).Add(72*time.Hour).Equal(expiry) ||
				time.Unix(0, highWaterNS).Before(expiry) || time.Duration(elapsedNS) < 72*time.Hour {
				t.Fatalf("terminal grace record = %q, want original cutoff %s and elapsed >=72h", data, expiry)
			}

			clock.setWall(earliest.Add(time.Hour))
			clock.setMono(int64(time.Second))
			restarted := NewManager(0, 1)
			restarted.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
			if !restarted.UnkeyedAuthorityExpired() {
				t.Fatalf("%s-triggered terminal record reopened after wall rollback and restart", trigger)
			}
		})
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
	var earliest, highWater, elapsed int64
	if _, err := fmt.Sscanf(string(data), "%s %d %d %d", &version, &earliest, &highWater, &elapsed); err != nil {
		t.Fatalf("parse grace record %q: %v", data, err)
	}
	if version != "v2" || time.Unix(0, earliest).UTC().Add(72*time.Hour) != firstExpiry {
		t.Fatalf("record = %q, expiry %s; want original expiry %s", data, time.Unix(0, earliest).UTC().Add(72*time.Hour), firstExpiry)
	}
	if !time.Unix(0, highWater).UTC().Equal(clock.wallNow()) {
		t.Fatalf("high-water = %s, want %s", time.Unix(0, highWater).UTC(), clock.wallNow())
	}
	if time.Duration(elapsed) != 24*time.Hour {
		t.Fatalf("elapsed floor = %s, want 24h", time.Duration(elapsed))
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
	legacyEarliest := clock.wallNow().Add(-time.Hour)
	if err := os.WriteFile(path, []byte(fmt.Sprintf("v1 %d %d\n", legacyEarliest.UnixNano(), legacyEarliest.UnixNano())), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := NewManager(0, 1)
	legacy.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if !legacy.UnkeyedAuthorityExpired() || !legacy.UnkeyedGraceAnchorCorrupt() {
		t.Fatal("legacy v1 anchor without monotonic history did not fail closed")
	}

	futurePath := filepath.Join(t.TempDir(), "future-anchor")
	restore := SetUnkeyedAuthorityGraceStatePathForTesting(futurePath)
	defer restore()
	future := clock.wallNow().Add(24 * time.Hour)
	if err := os.WriteFile(futurePath, []byte(fmt.Sprintf("v2 %d %d 0\n", future.UnixNano(), future.UnixNano())), 0o600); err != nil {
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
	restorePersist := SetUnkeyedAuthorityPersistForTesting(func(string, time.Time, time.Time, time.Duration) error {
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

func TestUnkeyedGracePostRenameSyncErrorVisibleAcrossRestart16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	expiry := m.UnkeyedGraceExpiry()
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	restoreSync := fsatomic.SetAfterRenameSyncDirForTesting(func(string) error {
		return fmt.Errorf("injected post-rename directory sync failure")
	})
	clock.advance(time.Second)
	m.checkUnkeyedGraceNotices()
	restoreSync()

	record, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("post-rename anchor is not visible: %v", err)
	}
	m.unkeyedGrace.mu.Lock()
	wantRecord := fmt.Sprintf("v2 %d %d %d\n",
		m.unkeyedGrace.earliestWall.UnixNano(),
		m.unkeyedGrace.highWaterWall.UnixNano(),
		m.unkeyedGrace.elapsedFloor.Nanoseconds())
	m.unkeyedGrace.mu.Unlock()
	if string(record) != wantRecord {
		t.Fatalf("post-rename anchor = %q, want new state %q", record, wantRecord)
	}
	notPersisted, durabilityUnknown := m.unkeyedGracePersistenceState()
	if !notPersisted || !durabilityUnknown {
		t.Fatalf("post-rename failure state = notPersisted:%t durabilityUnknown:%t, want both true",
			notPersisted, durabilityUnknown)
	}
	logText := logs.String()
	if got := strings.Count(logText, "cluster: unkeyed-authority grace anchor persist failed"); got != 1 {
		t.Fatalf("post-rename anchor error logged %d times, want exactly once: %s", got, logText)
	}
	if !strings.Contains(logText, "new content is visible") ||
		!strings.Contains(logText, "durability across power loss is unknown") {
		t.Fatalf("typed post-rename durability detail missing from log: %s", logText)
	}
	status := m.unkeyedAuthorityGraceStatus()
	for _, phrase := range []string{"anchor not persisted", "visible to an immediate restart", "durability across power loss is unknown"} {
		if !strings.Contains(status, phrase) {
			t.Fatalf("post-rename status omitted %q: %s", phrase, status)
		}
	}
	if m.UnkeyedAuthorityExpired() || !m.UnkeyedGraceExpiry().Equal(expiry) {
		t.Fatal("post-rename durability warning changed the in-process grace deadline")
	}

	restarted := NewManager(0, 1)
	restarted.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	if restarted.UnkeyedAuthorityExpired() || !restarted.UnkeyedGraceExpiry().Equal(expiry) {
		t.Fatalf("visible anchor did not preserve active expiry across immediate restart: expired=%t expiry=%s want=%s",
			restarted.UnkeyedAuthorityExpired(), restarted.UnkeyedGraceExpiry(), expiry)
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
	if !m.RecoveryHoldActive() {
		t.Fatal("expired local key commit did not arm recovery hold")
	}
	if _, err := os.Stat(unkeyedAuthorityGraceStatePath); err != nil {
		t.Fatalf("expired local key commit did not retain recovery evidence: %v", err)
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
func TestKeyedSecondaryRestartConfirmedAbsentHoldsUntilHeartbeatProof16016(t *testing.T) {
	primary, clock, path := setupAuthorityManager16016(t)
	groupConfig := groupConfig16016()
	primary.UpdateConfig(groupConfig)
	primary.mu.Lock()
	primary.groups[0].State = StatePrimary
	primary.peerAlive = false
	primary.mu.Unlock()
	clock.advance(73 * time.Hour)
	if !primary.UnkeyedAuthorityExpired() {
		t.Fatal("primary fixture did not expire unkeyed authority")
	}

	key := []byte("recovery-key-restart-16016")
	keyedConfig := &config.ClusterConfig{
		ControlInterface:   "em0",
		RedundancyGroups:   groupConfig.RedundancyGroups,
		ControlLinkAuthKey: config.NewSecret(string(key)),
	}
	keyingSecondary := NewManager(1, 1)
	keyingSecondary.UpdateConfigFromBoot(groupConfig)
	if !keyingSecondary.UnkeyedAuthorityExpired() {
		t.Fatal("secondary did not load the expired unkeyed cutoff")
	}
	keyingSecondary.UpdateConfig(keyedConfig)
	if !keyingSecondary.RecoveryHoldActive() {
		t.Fatal("keying the secondary alone did not arm recovery hold")
	}
	if primary.ControlLinkAuthConfigured() {
		t.Fatal("test setup keyed the still-unkeyed primary before secondary recovery")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expired recovery evidence was not retained through secondary keying: %v", err)
	}

	// Restart S after its local key commit, before any authenticated proof.
	secondary := NewManager(1, 1)
	secondary.UpdateConfigFromBoot(keyedConfig)
	if !secondary.RecoveryHoldActive() {
		t.Fatal("keyed secondary restart did not restore the recovery hold")
	}
	secondary.mu.Lock()
	rg := secondary.groups[0]
	rg.State = StateSecondary
	rg.Weight = 255
	rg.Ready = true
	rg.ReadySince = time.Now().Add(-time.Hour)
	rg.NotReadySince = time.Time{}
	secondary.takeoverHoldTime = 0
	secondary.degradedPromoteTimeout = 0
	// Simulate the completed peer-loss/confirmed-absence posture. These flags
	// deliberately bypass the cold-boot mask in electSingleNode, so only the
	// recovery hold can prevent this otherwise-ready secondary from promoting.
	secondary.peerAlive = false
	secondary.peerEverSeen = true
	secondary.peerConfirmedAbsent = true
	secondary.mu.Unlock()

	if !primary.IsLocalPrimary(0) || primary.ControlLinkAuthConfigured() {
		t.Fatal("P must remain the unkeyed-expired primary while S is held")
	}
	secondary.mu.Lock()
	secondary.electSingleNode()
	singleNodeState := secondary.groups[0].State
	secondary.runElection()
	normalState := secondary.groups[0].State
	confirmedAbsence := secondary.peerEverSeen && secondary.peerConfirmedAbsent && !secondary.peerAlive
	secondary.mu.Unlock()
	if !confirmedAbsence {
		t.Fatal("test did not establish confirmed peer absence after restart")
	}
	primary.mu.RLock()
	primaryState := primary.groups[0].State
	primary.mu.RUnlock()
	if singleNodeState == StatePrimary || normalState == StatePrimary ||
		primaryState != StatePrimary || !secondary.RecoveryHoldActive() {
		t.Fatalf("confirmed-absence recovery must keep P-only-primary: P=%s S-single=%s S-normal=%s hold=%t",
			primaryState, singleNodeState, normalState, secondary.RecoveryHoldActive())
	}
	secondary.noteSyncPeerAuthenticated(key)
	if !secondary.RecoveryHoldActive() || secondary.PeerProofGeneration() != 0 {
		t.Fatal("session-sync authentication released the recovery hold")
	}

	// P can provide a genuine authenticated proof only after it is keyed too.
	// Until this point P remained the unkeyed-expired primary.
	primary.UpdateConfig(keyedConfig)
	if !primary.IsLocalPrimary(0) {
		t.Fatal("keying P changed its existing primary role before proof")
	}
	r := newHeartbeatReceiver(secondary, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	pkt := &HeartbeatPacket{
		NodeID: 0, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 100, Weight: 255, State: uint8(StatePrimary)}},
	}
	frame := MarshalHeartbeatAuth(pkt, key, 16016, 1)
	decoded, err := UnmarshalHeartbeat(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !r.admitFrame(frame, decoded) {
		t.Fatal("authenticated primary heartbeat proof was rejected")
	}
	if secondary.RecoveryHoldActive() || secondary.PeerProofGeneration() != 1 {
		t.Fatal("installed authenticated peer heartbeat did not release recovery hold")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("fresh peer proof did not delete recovery evidence: %v", err)
	}
	if secondary.IsLocalPrimary(0) || !primary.IsLocalPrimary(0) {
		t.Fatal("normal election did not resume with P as the sole primary")
	}
}

func TestInterposedKeyClearRekeyDoesNotReleaseRecoveryHold16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	groupConfig := groupConfig16016()
	m.UpdateConfig(groupConfig)
	m.mu.Lock()
	m.groups[0].State = StateSecondary
	m.mu.Unlock()
	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("test fixture did not expire unkeyed authority")
	}

	keyA := []byte("interposed-recovery-key-A-16016")
	keyB := []byte("interposed-recovery-key-B-16016")
	keyedA := &config.ClusterConfig{
		ControlInterface:   "em0",
		RedundancyGroups:   groupConfig.RedundancyGroups,
		ControlLinkAuthKey: config.NewSecret(string(keyA)),
	}
	m.UpdateConfig(keyedA)
	if !m.RecoveryHoldActive() {
		t.Fatal("key A did not arm the expired-cluster recovery hold")
	}

	r := newHeartbeatReceiver(m, nil, DefaultHeartbeatThreshold, DefaultHeartbeatInterval, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	r.testBeforeProofPublish = func() { close(entered); <-release }
	pkt := &HeartbeatPacket{
		NodeID: 1, ClusterID: 1,
		Groups: []HeartbeatGroup{{GroupID: 0, Priority: 200, Weight: 255, State: uint8(StatePrimary)}},
	}
	frameA := MarshalHeartbeatAuth(pkt, keyA, 16016, 1)
	decodedA, err := UnmarshalHeartbeat(frameA)
	if err != nil {
		t.Fatal(err)
	}
	acceptedA := make(chan bool, 1)
	go func() { acceptedA <- r.admitFrame(frameA, decodedA) }()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	select {
	case <-entered:
	case <-time.After(time.Second):
		unblock()
		t.Fatal("key-A heartbeat did not reach the proof-publication seam")
	}

	// A peer key-clear preserves expired debt; the following local re-key
	// arms a new hold generation while the old A-verified frame is paused.
	m.UpdateConfigFromPeer(&config.ClusterConfig{
		ControlInterface: "em0",
		RedundancyGroups: groupConfig.RedundancyGroups,
	})
	keyedB := &config.ClusterConfig{
		ControlInterface:   "em0",
		RedundancyGroups:   groupConfig.RedundancyGroups,
		ControlLinkAuthKey: config.NewSecret(string(keyB)),
	}
	m.UpdateConfig(keyedB)
	if !m.RecoveryHoldActive() || m.PeerProofGeneration() != 0 {
		unblock()
		t.Fatal("clear/re-key failed to leave a fresh recovery hold before stale proof publication")
	}

	unblock()
	if !<-acceptedA {
		t.Fatal("the already-admitted key-A heartbeat was not accepted")
	}
	r.testBeforeProofPublish = nil
	if !m.RecoveryHoldActive() || m.PeerProofGeneration() != 0 {
		t.Fatal("key-A proof released the recovery hold armed for key B")
	}

	frameB := MarshalHeartbeatAuth(pkt, keyB, 16016, 2)
	decodedB, err := UnmarshalHeartbeat(frameB)
	if err != nil {
		t.Fatal(err)
	}
	if !r.admitFrame(frameB, decodedB) {
		t.Fatal("current-key authenticated heartbeat proof was rejected")
	}
	if m.RecoveryHoldActive() || m.PeerProofGeneration() != 1 {
		t.Fatal("current key-B proof did not release the recovery hold")
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
		ControlInterface:   "em0",
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
	var savedEarliest, highWater, elapsed int64
	if _, err := fmt.Sscanf(string(data), "%s %d %d %d", &version, &savedEarliest, &highWater, &elapsed); err != nil {
		t.Fatalf("parse grace record %q: %v", data, err)
	}
	if version != "v2" || time.Unix(0, savedEarliest).UTC() != earliest ||
		time.Unix(0, highWater).UTC() != earliest.Add(48*time.Hour) ||
		time.Duration(elapsed) != 48*time.Hour {
		t.Fatalf("sweep record = %q, want earliest=%s high-water=%s elapsed=48h", data, earliest, earliest.Add(48*time.Hour))
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
func TestUnkeyedGraceTerminalAndKeyedSweepsDoNotRewrite16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	writes := 0
	originalPersist := unkeyedAuthorityPersist
	restorePersist := SetUnkeyedAuthorityPersistForTesting(func(path string, earliest, highWater time.Time, elapsed time.Duration) error {
		writes++
		return originalPersist(path, earliest, highWater, elapsed)
	})
	defer restorePersist()

	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("test precondition: grace did not expire")
	}
	terminalWrites := writes
	if terminalWrites > 1 {
		t.Fatalf("terminal expiry performed %d persistence writes, want at most one", terminalWrites)
	}
	for range 20 {
		m.checkUnkeyedGraceNotices()
	}
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0", ControlLinkAuthKey: config.NewSecret("terminal-key-16016"),
	})
	for range 20 {
		m.checkUnkeyedGraceNotices()
	}
	if writes != terminalWrites {
		t.Fatalf("terminal/keyed sweeps rewrote the anchor %d additional times", writes-terminalWrites)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expired recovery evidence was not retained after keying: %v", err)
	}
}

func TestUnkeyedGraceKeyedSweepDoesNotRewriteAndPeerClearKeepsOriginalCutoff16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	earliest := clock.wallNow()
	expiry := m.UnkeyedGraceExpiry()
	m.UpdateConfigFromPeer(&config.ClusterConfig{
		ControlInterface:   "em0",
		ControlLinkAuthKey: config.NewSecret("peer-key-16016"),
	})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(48 * time.Hour)
	for i := 0; i < 10; i++ {
		m.checkUnkeyedGraceNotices()
	}
	afterKeyedTicks, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterKeyedTicks) != string(before) {
		t.Fatalf("keyed grace sweeps rewrote the retained anchor: before=%q after=%q", before, afterKeyedTicks)
	}
	m.UpdateConfigFromPeer(&config.ClusterConfig{ControlInterface: "em0"})
	if m.UnkeyedAuthorityExpired() {
		t.Fatal("peer key-clear expired before the original 72-hour cutoff")
	}
	if got := m.UnkeyedGraceExpiry(); !got.Equal(expiry) {
		t.Fatalf("peer key-clear moved original cutoff to %s, want %s", got, expiry)
	}

	// A restart after a keyed interval and a wall rollback keeps only the
	// unspent portion of the original cutoff; it must neither re-anchor nor
	// prematurely expire.
	clock.setWall(earliest.Add(time.Hour))
	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	restarted.UpdateConfigFromBoot(&config.ClusterConfig{ControlInterface: "em0"})
	if restarted.UnkeyedAuthorityExpired() {
		t.Fatal("restart expired before cumulative elapsed time reached 72h")
	}
	if got := restarted.UnkeyedGraceExpiry(); !got.Equal(expiry) {
		t.Fatalf("restart moved original cutoff to %s, want %s", got, expiry)
	}
	clock.advance(24 * time.Hour)
	if !restarted.UnkeyedAuthorityExpired() {
		t.Fatal("restart refunded the remaining 24-hour grace budget")
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
	_, keyGeneration := m.controlLinkAcceptedKeysSnapshot()
	m.publishFreshHeartbeatProof(keyGeneration)
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
	if !expiry.Equal(now.Add(72*time.Hour)) || m.UnkeyedAuthorityExpired() {
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
	var earliest, highWater, elapsed int64
	if _, err := fmt.Sscanf(string(data), "%s %d %d %d", &version, &earliest, &highWater, &elapsed); err != nil {
		t.Fatalf("parse re-armed anchor %q: %v", data, err)
	}
	if version != "v2" || time.Unix(0, earliest).UTC() != now ||
		time.Unix(0, highWater).UTC() != now || elapsed != 0 {
		t.Fatalf("re-armed anchor = %q, want fresh earliest/high-water %s and elapsed 0", data, now)
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
func TestUnkeyedGraceExpiredStatusSurfacesLocalReArm16016(t *testing.T) {
	m, clock, path := setupAuthorityManager16016(t)
	clock.advance(73 * time.Hour)
	expiredStatus := m.unkeyedAuthorityGraceStatus()
	for _, want := range []string{
		"expired at",
		"key the cluster",
		"RTC was wrong",
		"request chassis cluster unkeyed-grace restart",
	} {
		if !strings.Contains(expiredStatus, want) {
			t.Errorf("expired grace status %q missing %q", expiredStatus, want)
		}
	}

	if err := os.WriteFile(path, []byte("corrupt anchor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clock.setMono(int64(time.Second))
	restarted := NewManager(0, 1)
	restarted.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	corruptStatus := restarted.unkeyedAuthorityGraceStatus()
	for _, want := range []string{
		"corrupt",
		"RTC was wrong",
		"request chassis cluster unkeyed-grace restart",
	} {
		if !strings.Contains(corruptStatus, want) {
			t.Errorf("corrupt grace status %q missing %q", corruptStatus, want)
		}
	}
}

func TestUnkeyedGraceWithinGraceStatusRendersExpiry16016(t *testing.T) {
	m, _, _ := setupAuthorityManager16016(t)
	expiry := m.UnkeyedGraceExpiry()
	status := m.FormatControlPlaneStatistics()
	want := "Unkeyed authority grace:    active; expires at " + expiry.Format(time.RFC3339)
	if !strings.Contains(status, want) {
		t.Fatalf("control-plane status missing expiry line %q:\n%s", want, status)
	}
}

func TestExpiredUnkeyedGraceSuppressesConfigAndReadinessElections16016(t *testing.T) {
	m, clock, _ := setupAuthorityManager16016(t)
	defer func() {
		m.mu.Lock()
		if rg := m.groups[0]; rg != nil && rg.holdTimer != nil {
			rg.holdTimer.Stop()
			rg.holdTimer = nil
		}
		m.mu.Unlock()
		m.Stop()
	}()
	m.UpdateConfig(groupConfig16016())

	clock.advance(73 * time.Hour)
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("test setup did not expire unkeyed authority")
	}
	m.mu.Lock()
	m.peerEverSeen = true
	m.peerConfirmedAbsent = true
	m.groups[0].State = StateSecondary
	m.mu.Unlock()

	// Config replacement and both readiness election edges must retain the
	// existing secondary role even when a single-node election could promote.
	m.UpdateConfig(groupConfig16016())
	m.mu.Lock()
	m.takeoverHoldTime = time.Hour
	m.mu.Unlock()
	if m.IsLocalPrimary(0) {
		t.Fatal("expired grace allowed UpdateConfig election to claim primary")
	}
	m.SetRGReady(0, true, nil)
	if m.IsLocalPrimary(0) {
		t.Fatal("expired grace allowed readiness edge election to claim primary")
	}

	m.mu.Lock()
	holdTimerArmed := m.groups[0].holdTimer != nil
	m.mu.Unlock()
	if !holdTimerArmed {
		t.Fatal("readiness transition did not arm the takeover hold timer")
	}

	// The timer callback re-evaluates via electSingleNode. Invoke that exact
	// election path deterministically; timer arming is asserted separately.
	m.mu.Lock()
	m.electSingleNode()
	m.mu.Unlock()
	if m.IsLocalPrimary(0) {
		t.Fatal("expired grace allowed the delayed readiness election to claim primary")
	}
}

type interposedPeerClearAuthProvider16016 struct {
	manager         *Manager
	lookupStarted   chan struct{}
	releaseLookup   chan struct{}
	lookupStartedDo sync.Once
}

func (p *interposedPeerClearAuthProvider16016) ControlLinkAuthKey() []byte {
	return p.manager.ControlLinkAuthKey()
}

func (p *interposedPeerClearAuthProvider16016) ControlLinkAuthConfigured() bool {
	p.lookupStartedDo.Do(func() { close(p.lookupStarted) })
	<-p.releaseLookup
	return p.manager.ControlLinkAuthConfigured()
}

func (p *interposedPeerClearAuthProvider16016) UnkeyedAuthorityExpired() bool {
	return p.manager.UnkeyedAuthorityExpired()
}

func TestPeerKeyClearInterposedFrameRefuses16016(t *testing.T) {
	m, _, _ := setupAuthorityManager16016(t)
	m.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0", ControlLinkAuthKey: config.NewSecret("local-key-16016"),
	})
	if !m.ControlLinkAuthConfigured() {
		t.Fatal("test setup did not configure a control-link key")
	}

	persistStarted := make(chan struct{})
	releasePersist := make(chan struct{})
	var persistOnce sync.Once
	var releasePersistOnce sync.Once
	unblockPersist := func() {
		releasePersistOnce.Do(func() { close(releasePersist) })
	}
	restorePersist := SetUnkeyedAuthorityPersistForTesting(func(string, time.Time, time.Time, time.Duration) error {
		persistOnce.Do(func() {
			close(persistStarted)
			<-releasePersist
		})
		return nil
	})
	provider := &interposedPeerClearAuthProvider16016{
		manager:       m,
		lookupStarted: make(chan struct{}),
		releaseLookup: make(chan struct{}),
	}
	var releaseLookupOnce sync.Once
	unblockLookup := func() {
		releaseLookupOnce.Do(func() { close(provider.releaseLookup) })
	}
	t.Cleanup(func() {
		unblockLookup()
		unblockPersist()
		restorePersist()
	})
	ss := NewSessionSync(":0", ":0", nil)
	ss.SetAuthProvider(provider)
	local, peer := net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})

	frameDone := make(chan bool, 1)
	go func() {
		frameDone <- ss.rejectUnauthenticatedAuthorityFrame(local, syncMsgHeartbeat)
	}()
	select {
	case <-provider.lookupStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("frame gate did not reach the auth-configured lookup")
	}

	clearDone := make(chan struct{})
	go func() {
		m.UpdateConfigFromPeer(&config.ClusterConfig{ControlInterface: "em0"})
		close(clearDone)
	}()
	select {
	case <-persistStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("peer key-clear did not reach the persistence interpose")
	}
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("frame gate could observe an open posture while peer key-clear cutoff persistence was blocked")
	}

	unblockLookup()
	unblockPersist()
	select {
	case <-clearDone:
	case <-time.After(5 * time.Second):
		t.Fatal("peer key-clear did not finish after persistence was released")
	}
	select {
	case rejected := <-frameDone:
		if !rejected {
			t.Fatal("unauthenticated heartbeat passed after auth lookup waited out peer key-clear")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("frame gate did not finish after peer key-clear")
	}
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("peer key-clear finished without retaining the fail-closed expired posture")
	}
}

func TestPeerUnkeyedNoAnchorPublishesPendingBeforePersist16016(t *testing.T) {
	m, _, path := setupBareAuthorityManager16016(t)
	if m.UnkeyedAuthorityExpired() {
		t.Fatal("bare manager unexpectedly began with expired authority")
	}

	persistStarted := make(chan struct{})
	releasePersist := make(chan struct{})
	var persistOnce sync.Once
	var releaseOnce sync.Once
	unblockPersist := func() {
		releaseOnce.Do(func() { close(releasePersist) })
	}
	originalPersist := unkeyedAuthorityPersist
	restorePersist := SetUnkeyedAuthorityPersistForTesting(func(path string, earliest, highWater time.Time, elapsed time.Duration) error {
		persistOnce.Do(func() {
			close(persistStarted)
			<-releasePersist
		})
		return originalPersist(path, earliest, highWater, elapsed)
	})
	clearDone := make(chan struct{})
	go func() {
		m.UpdateConfigFromPeer(&config.ClusterConfig{ControlInterface: "em0"})
		close(clearDone)
	}()
	t.Cleanup(func() {
		unblockPersist()
		select {
		case <-clearDone:
		case <-time.After(5 * time.Second):
			t.Error("peer config update did not finish after persistence was released")
		}
		restorePersist()
	})

	select {
	case <-persistStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("unkeyed peer config did not reach expired-cutoff persistence")
	}
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("missing-anchor sentinel persistence left unauthenticated authority open")
	}

	unblockPersist()
	select {
	case <-clearDone:
	case <-time.After(5 * time.Second):
		t.Fatal("peer config update did not finish after persistence was released")
	}
	if !m.UnkeyedAuthorityExpired() {
		t.Fatal("unkeyed peer config finished without retaining the expired posture")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("peer config did not persist the fail-closed sentinel: %v", err)
	}
}

func TestPeerUnkeyedUpdatePreservesActiveGrace16016(t *testing.T) {
	m, _, path := setupAuthorityManager16016(t)
	expiry := m.UnkeyedGraceExpiry()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read active grace anchor: %v", err)
	}

	m.UpdateConfigFromPeer(&config.ClusterConfig{ControlInterface: "em0"})
	if m.UnkeyedAuthorityExpired() {
		t.Fatal("unkeyed peer update expired an active local grace window")
	}
	if m.unkeyedGrace.peerKeyClearPending.Load() {
		t.Fatal("unkeyed peer update retained the temporary pending-deny posture")
	}
	if got := m.UnkeyedGraceExpiry(); !got.Equal(expiry) {
		t.Fatalf("unkeyed peer update moved cutoff to %s, want %s", got, expiry)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read active grace anchor after peer update: %v", err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("unkeyed peer update rewrote active grace anchor: before=%q after=%q", before, after)
	}
}
