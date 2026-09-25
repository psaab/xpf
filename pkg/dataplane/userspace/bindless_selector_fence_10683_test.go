package userspace

import (
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func bindlessSelectorConfig10683() *config.Config {
	cfg := overlayTestConfig()
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"policy-vpn": {
			Name: "policy-vpn",
			TrafficSelectors: map[string]*config.IPsecTrafficSelector{
				"corp": {LocalIP: "10.20.0.0/16", RemoteIP: "198.51.100.10-198.51.100.20"},
			},
		},
	}
	return cfg
}

// The #10683 fence must be present before the first IPsec capture apply and
// remain present when a later routes-only publish reuses the prior snapshot.
// The empty capture rows/generation prove neither case depends on a live SA.
func TestBindlessSelectorFenceSnapshotSurvivesCaptureWindows10683(t *testing.T) {
	stubRuleListHermetic(t)
	cfg := bindlessSelectorConfig10683()
	initial, err := buildSnapshot(cfg, config.UserspaceConfig{}, 7, 0)
	if err != nil {
		t.Fatalf("build bind-less snapshot before capture commit: %v", err)
	}
	wantRows := []IpsecBindlessSelectorSnapshot{{
		LocalTS:  "10.20.0.0/16",
		RemoteTS: "198.51.100.10-198.51.100.20",
	}}
	if !initial.BindlessSelectorFenceEnabled || !reflect.DeepEqual(initial.BindlessSelectorRows, wantRows) {
		t.Fatalf("initial selector fence = enabled:%v rows:%+v, want enabled with %+v",
			initial.BindlessSelectorFenceEnabled, initial.BindlessSelectorRows, wantRows)
	}
	if len(initial.IpsecTunnelRows) != 0 || initial.IpsecTunnelSnapshotGeneration != 0 {
		t.Fatalf("selector fence unexpectedly depends on capture/SA state: tunnel rows=%+v generation=%d",
			initial.IpsecTunnelRows, initial.IpsecTunnelSnapshotGeneration)
	}

	dir := t.TempDir()
	controlSock, requests := overlayControlServer(t, dir)
	manager := New()
	manager.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	manager.cfg.ControlSocket = controlSock
	manager.generation = initial.Generation
	manager.lastSnapshot = initial
	manager.lastSnapshot.Config = cfg
	if hash, ok := snapshotContentHash(initial); ok {
		manager.lastSnapshotHash = hash
	}
	manager.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion

	published, err := manager.PublishRouteOverlaySnapshot(cfg, []config.RouteOverlayEntry{{
		Destination: "0.0.0.0/0", NextHop: "172.16.80.1", Policy: "window-a-retry",
	}}, nil)
	if err != nil || !published {
		t.Fatalf("route-only retry publish: published=%v err=%v", published, err)
	}
	var request ControlRequest
	select {
	case request = <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("route-only retry did not publish its snapshot")
	}
	if request.Snapshot == nil || !request.Snapshot.BindlessSelectorFenceEnabled ||
		!reflect.DeepEqual(request.Snapshot.BindlessSelectorRows, wantRows) {
		t.Fatalf("route-only retry lost the selector fence: %+v", request.Snapshot)
	}
	if !reflect.DeepEqual(manager.lastSnapshot.BindlessSelectorRows, wantRows) {
		t.Fatalf("accepted route-only snapshot lost selector rows: %+v", manager.lastSnapshot.BindlessSelectorRows)
	}
}
