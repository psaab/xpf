package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestPolicySnapshotCIDRMaskRefusalStampParity12122(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{name: "policy-literal", cfg: cidrMaskCfg12047("10.0.0.0/008", false)},
		{name: "address-book", cfg: cidrMaskCfg12047("10.0.0.0/008", true)},
	} {
		t.Run(tc.name+"/full-build", func(t *testing.T) {
			snap := mustBuildSnapshot(t, tc.cfg, config.UserspaceConfig{}, 1, 0)
			assertCIDRMaskStampParity12122(t, tc.cfg, snap.Capabilities.PolicyContentRejected)
		})
		t.Run(tc.name+"/scheduler-republish", func(t *testing.T) {
			snap := publishCIDRMaskSchedulerSnapshot12122(t, tc.cfg)
			assertCIDRMaskStampParity12122(t, tc.cfg, snap.Capabilities.PolicyContentRejected)
		})
	}
}

func assertCIDRMaskStampParity12122(t *testing.T, cfg *config.Config, got []string) {
	t.Helper()
	want := PolicyContentRejectionReasons(cfg, nil)
	if !has12047Reason(want) {
		t.Fatalf("fixture does not produce a #12047 mirror reason: %v", want)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("PolicyContentRejected = %v, want mirror reasons %v", got, want)
	}
}

func publishCIDRMaskSchedulerSnapshot12122(t *testing.T, cfg *config.Config) *ConfigSnapshot {
	t.Helper()
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	reqCh := make(chan ControlRequest, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req ControlRequest
		if err := json.NewDecoder(conn).Decode(&req); err != nil {
			return
		}
		reqCh <- req
		_ = json.NewEncoder(conn).Encode(ControlResponse{
			OK: true,
			Status: &ProcessStatus{
				Enabled:                true,
				LastSnapshotGeneration: req.Snapshot.Generation,
				LastFIBGeneration:      req.Snapshot.FIBGeneration,
			},
		})
	}()

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = controlSock
	m.generation = 7
	m.lastSnapshot = mustBuildSnapshot(t, cfg,
		config.UserspaceConfig{ControlSocket: controlSock}, 7, 0)
	m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
	if err := m.UpdatePolicyScheduleState(cfg, map[string]bool{}); err != nil {
		t.Fatalf("UpdatePolicyScheduleState: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scheduler apply_snapshot")
	}
	select {
	case req := <-reqCh:
		if req.Type != "apply_snapshot" || req.Snapshot == nil {
			t.Fatalf("scheduler request = %+v, want apply_snapshot with snapshot", req)
		}
		return req.Snapshot
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scheduler snapshot request")
		return nil
	}
}
