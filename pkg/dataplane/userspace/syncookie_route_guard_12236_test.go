package userspace

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func authKeyRotationConfig12236(key string) *config.Config {
	cfg := synCookieCfg9173(keyedCluster9173(key, ""), "", "fw")
	routes := overlayTestConfig()
	cfg.RoutingOptions = routes.RoutingOptions
	cfg.RoutingInstances = routes.RoutingInstances
	return cfg
}

func TestRouteDeltaCannotAckFailedAuthKeyRotation12236(t *testing.T) {
	dir := t.TempDir()
	controlSock, reqCh := overlayControlServer(t, dir)

	cfgA := authKeyRotationConfig12236("auth-key-before")
	cfgB := authKeyRotationConfig12236("auth-key-after")
	beforeJSON, err := json.Marshal(cfgA)
	if err != nil {
		t.Fatal(err)
	}
	afterJSON, err := json.Marshal(cfgB)
	if err != nil {
		t.Fatal(err)
	}
	if string(beforeJSON) != string(afterJSON) {
		t.Fatal("fixture: auth-key rotation must be hidden by redacted config JSON")
	}

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfgA, config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	if m.lastSnapshot.SYNCookieKeyRing == nil || len(m.lastSnapshot.SYNCookieKeyRing.Bases) != 1 {
		t.Fatalf("fixture: old full snapshot lacks its SYN-cookie ring: %+v", m.lastSnapshot.SYNCookieKeyRing)
	}
	_, newRing := buildSYNCookieKeys(cfgB, synCookieT0_9173)
	if newRing == nil || len(newRing.Bases) != 1 ||
		m.lastSnapshot.SYNCookieKeyRing.Bases[0].Base == newRing.Bases[0].Base {
		t.Fatal("fixture: rotated auth key must derive a different new SYN-cookie base")
	}
	if h, ok := snapshotContentHash(m.lastSnapshot); ok {
		m.lastSnapshotHash = h
	}
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	m.appliedSnapshot = appliedSnapshot{Config: cfgA, Generation: 7}

	// Model the post-failure state of the attempted full key-rotation publish:
	// the helper and applied identity still hold cfgA, while cfgB is the newly
	// committed intent. A later route-only delta must not ACK cfgB while the
	// inherited snapshot still has cfgA's cookie base.
	overlay := []config.RouteOverlayEntry{{
		Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "wan-failover",
	}}
	published, err := m.PublishRouteOverlaySnapshot(cfgB, overlay, nil)
	if err == nil {
		t.Fatal("route-only publish ACK'd the rotated auth key while retaining the old SYN-cookie base")
	}
	if !strings.Contains(err.Error(), "refusing route-only publish") {
		t.Fatalf("route-only snapshot reached the helper or failed for an unrelated reason: %v", err)
	}
	if published {
		t.Fatal("route-only publish reported success for an unpublished auth-key rotation")
	}
	if m.appliedSnapshot.Config != cfgA || m.lastSnapshot == nil || m.lastSnapshot.Config != cfgA {
		t.Fatal("refused auth-key rotation advanced the applied or retained config identity")
	}
	if m.lastSnapshot.SYNCookieKeyRing.Bases[0].Base == newRing.Bases[0].Base {
		t.Fatal("retained snapshot unexpectedly changed its SYN-cookie base")
	}
	select {
	case req := <-reqCh:
		t.Fatalf("route delta shipped a snapshot ACK'ing the rotated config: %q", req.Type)
	case <-time.After(200 * time.Millisecond):
	}
}
