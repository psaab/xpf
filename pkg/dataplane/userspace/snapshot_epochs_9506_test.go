package userspace

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestSnapshotEpochFeedSerde9506(t *testing.T) {
	provider := func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return 41,
			[]QueueEpochSnapshot{{Queue: 1000, Epoch: 9}, {Queue: 1001, Epoch: 10}},
			17,
			[]IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}}
	}
	snap, err := buildSnapshotWithEpochProvider(nil, configUserspaceForEpochTest(), 7, 3, provider)
	if err != nil {
		t.Fatalf("buildSnapshotWithEpochProvider: %v", err)
	}
	if snap.PermitEpoch != 41 {
		t.Fatalf("PermitEpoch=%d, want 41", snap.PermitEpoch)
	}
	if len(snap.QueueEpochs) != 2 || snap.QueueEpochs[0].Queue != 1000 || snap.QueueEpochs[1].Epoch != 10 {
		t.Fatalf("QueueEpochs=%+v, want ordered list", snap.QueueEpochs)
	}
	if snap.IpsecTunnelSnapshotGeneration != 17 || len(snap.IpsecTunnelRows) != 1 ||
		snap.IpsecTunnelRows[0].STN != "st0" {
		t.Fatalf("IpsecTunnelRows=%d/%+v, want capture generation 17 and st0 row",
			snap.IpsecTunnelSnapshotGeneration, snap.IpsecTunnelRows)
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		PermitEpoch uint64 `json:"permit_epoch"`
		QueueEpochs []struct {
			Queue uint16 `json:"queue"`
			Epoch uint64 `json:"epoch"`
		} `json:"queue_epochs"`
		TunnelGeneration uint64 `json:"ipsec_tunnel_snapshot_generation"`
		TunnelRows       []struct {
			STN            string `json:"stn"`
			IfID           uint32 `json:"if_id"`
			LogicalIfindex int32  `json:"logical_ifindex"`
		} `json:"ipsec_tunnel_rows"`
	}
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PermitEpoch != 41 || len(decoded.QueueEpochs) != 2 || decoded.QueueEpochs[0].Queue != 1000 ||
		decoded.TunnelGeneration != 17 || len(decoded.TunnelRows) != 1 ||
		decoded.TunnelRows[0].STN != "st0" || decoded.TunnelRows[0].IfID != 9 ||
		decoded.TunnelRows[0].LogicalIfindex != 10 {
		t.Fatalf("wire authority=%+v, want additive snake_case epoch and row fields", decoded)
	}
}

// TestStampCaptureAuthorityHelper9506 pins the shared authority stamper
// directly: the provider's immutable tunnel generation and row must survive
// onto a builder-produced snapshot. It does NOT reach Manager.Compile — the
// Compile-level cell below owns that path (M2).
func TestStampCaptureAuthorityHelper9506(t *testing.T) {
	provider := func(configGeneration uint64, fibGeneration uint32) (
		uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot,
	) {
		if configGeneration == 0 || fibGeneration == 0 {
			t.Fatalf("provider received zero requested authority: config=%d fib=%d",
				configGeneration, fibGeneration)
		}
		return 41,
			[]QueueEpochSnapshot{{Queue: 1000, Epoch: 9}},
			17,
			[]IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}}
	}

	snap, err := buildSnapshotWithSchedulerStateAndNATCounters(
		&config.Config{}, config.UserspaceConfig{}, 7, 3, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatalf("build compiled snapshot: %v", err)
	}
	stampCaptureAuthority(snap, provider)
	if snap.PermitEpoch != 41 || len(snap.QueueEpochs) != 1 ||
		snap.QueueEpochs[0].Queue != 1000 ||
		snap.IpsecTunnelSnapshotGeneration != 17 ||
		len(snap.IpsecTunnelRows) != 1 ||
		snap.IpsecTunnelRows[0].STN != "st0" {
		t.Fatalf("compiled capture authority=%+v, want epoch 41, queue 1000/9, generation 17, st0 row",
			snap)
	}
}

// TestCompilePublishesCaptureAuthorityRows10485 is the M2 Compile-level pin:
// it drives the real Manager.Compile with a live capture provider and asserts
// the emitted apply_snapshot carries the provider's rows and generation.
// The test-only shim hook avoids privileged XDP cleanup/attach while retaining
// the production snapshot build, stamper, and publication path.
func TestCompilePublishesCaptureAuthorityRows10485(t *testing.T) {
	dir := t.TempDir()
	controlSock, reqCh := overlayControlServer(t, dir)
	cfg := overlayTestConfig()
	cfg.System.UserspaceDataplane = &config.UserspaceConfig{ControlSocket: controlSock}
	ucfg := deriveUserspaceConfig(cfg)
	m := New()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m.proc = &exec.Cmd{Process: proc}
	m.cfg = ucfg
	m.syncCancel = func() {}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.clearHelperHAStateHook = func() error { return nil }
	m.lastStatus = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
	m.helperStatusObserved = true
	m.xskLivenessProven = true
	seed := mustBuildSnapshotWithSchedulerState(t, cfg, ucfg, 7, 0, nil, nil, nil)
	m.lastSnapshot = seed
	m.generation = 7
	m.publishedSnapshot = 7
	m.publishedPlanKey = snapshotBindingPlanKey(seed)
	if h, ok := snapshotContentHash(seed); ok {
		m.lastSnapshotHash = h
	}
	m.compileUserspaceShimHook = func(*config.Config) (*dataplane.CompileResult, error) {
		return &dataplane.CompileResult{}, nil
	}
	m.SetCaptureEpochProvider(func(uint64, uint32) (uint64, []QueueEpochSnapshot, uint64, []IpsecTunnelRowSnapshot) {
		return 41,
			[]QueueEpochSnapshot{{Queue: 1000, Epoch: 9}},
			17,
			[]IpsecTunnelRowSnapshot{{STN: "st0", IfID: 9, LogicalIfindex: 10}}
	})
	if _, err := m.Compile(cfg); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case req := <-reqCh:
			if req.Type != "apply_snapshot" || req.Snapshot == nil {
				continue
			}
			snap := req.Snapshot
			if snap.PermitEpoch != 41 {
				t.Fatalf("PermitEpoch=%d, want 41", snap.PermitEpoch)
			}
			if len(snap.QueueEpochs) != 1 || snap.QueueEpochs[0].Queue != 1000 ||
				snap.QueueEpochs[0].Epoch != 9 {
				t.Fatalf("QueueEpochs=%+v, want [1000/9]", snap.QueueEpochs)
			}
			if snap.IpsecTunnelSnapshotGeneration != 17 {
				t.Fatalf("IpsecTunnelSnapshotGeneration=%d, want 17", snap.IpsecTunnelSnapshotGeneration)
			}
			if len(snap.IpsecTunnelRows) != 1 || snap.IpsecTunnelRows[0].STN != "st0" ||
				snap.IpsecTunnelRows[0].IfID != 9 || snap.IpsecTunnelRows[0].LogicalIfindex != 10 {
				t.Fatalf("IpsecTunnelRows=%+v, want one st0/9/10 row", snap.IpsecTunnelRows)
			}
			return
		case <-deadline:
			t.Fatal("Compile published no apply_snapshot")
		}
	}
}

// configUserspaceForEpochTest keeps the nil-config builder path explicit; the
// epoch feed must be available even before a compiled policy exists.
func configUserspaceForEpochTest() config.UserspaceConfig { return config.UserspaceConfig{} }
