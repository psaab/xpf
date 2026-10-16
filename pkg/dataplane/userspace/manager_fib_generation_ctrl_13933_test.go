// Copyright (c) 2026 Petter Sælen. All rights reserved.

package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13933 (H06-06): a successful route-only BumpFIBGeneration previously
// refreshed only the shim FIB-generation map and the helper's RuntimeView.
// It never updated the userspace_ctrl map row. The shim therefore stamped
// redirected packets with the stale ctrl.fib_generation and the helper
// rejected them as FibGenerationMismatch.
func TestBumpFIBGenerationPublishesRouteOnlyGenerationToUserspaceCtrl13933(t *testing.T) {
	m, ctrl := seamedManager(t)
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m.proc = &exec.Cmd{Process: proc}
	const priorFIB, bumpedFIB = 41, 42
	m.lastSnapshot = &ConfigSnapshot{
		Version:       ProtocolVersion,
		Generation:    4,
		FIBGeneration: priorFIB,
		Config:        &config.Config{},
	}
	m.generation = 4
	ctrl.haveStored = true
	ctrl.stored = userspaceCtrlValue{
		Enabled: 1, MetadataVersion: userspaceMetadataVersion,
		ConfigGeneration: 4, FIBGeneration: priorFIB,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	}
	m.ctrlWasEnabled = true
	m.bumpFIBGenerationHook = func() (uint32, error) { return bumpedFIB, nil }
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type != "bump_fib_generation" {
			return nil
		}
		// The helper response reflects the accepted bump's generation.
		*status = ProcessStatus{
			Enabled:                true,
			Workers:                1,
			Bindings:               readyHelperStatus().Bindings,
			NeighborGeneration:     1,
			LastSnapshotGeneration: 4,
			LastFIBGeneration:      req.Snapshot.FIBGeneration,
		}
		return nil
	}

	gotGen, err := m.BumpFIBGeneration()
	if err != nil {
		t.Fatalf("BumpFIBGeneration: %v", err)
	}
	if gotGen <= priorFIB {
		t.Fatalf("BumpFIBGeneration returned %d, want generation > prior %d", gotGen, priorFIB)
	}
	if gotGen != bumpedFIB {
		t.Fatalf("BumpFIBGeneration returned %d, want injected generation %d", gotGen, bumpedFIB)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctrl.stored.FIBGeneration == priorFIB {
		t.Fatalf("userspace_ctrl retained prior FIBGeneration %d after bump to %d", priorFIB, gotGen)
	}
	if ctrl.stored.FIBGeneration != gotGen {
		t.Fatalf("userspace_ctrl FIBGeneration = %d after route-only bump, want confirmed helper generation %d; shim stamps redirected packets with ctrl.fib_generation, so mismatch drops transit", ctrl.stored.FIBGeneration, gotGen)
	}
}

func TestBumpFIBGenerationHelperRefusalDoesNotPublishStaleCtrlGeneration13933(t *testing.T) {
	m, ctrl := seamedManager(t)
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m.proc = &exec.Cmd{Process: proc}
	m.lastSnapshot = &ConfigSnapshot{
		Version:       ProtocolVersion,
		Generation:    4,
		FIBGeneration: 0,
		Config:        &config.Config{},
	}
	m.generation = 4
	rejected := newHelperRejection("fib generation rollback rejected")
	m.controlRequestHook = func(req ControlRequest, _ *ProcessStatus) error {
		if req.Type == "bump_fib_generation" {
			return rejected
		}
		return nil
	}

	if _, err := m.BumpFIBGeneration(); !errors.Is(err, errHelperRejected) {
		t.Fatalf("BumpFIBGeneration error = %v, want helper rejection", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastSnapshot.FIBGeneration != 0 || m.lastSnapshot.Generation != 4 {
		t.Fatalf("refusal mutated retained snapshot: FIB=%d Generation=%d, want 0/4", m.lastSnapshot.FIBGeneration, m.lastSnapshot.Generation)
	}
	if ctrl.haveStored {
		t.Fatalf("refused route-only bump wrote userspace_ctrl: %+v", ctrl.stored)
	}
}
