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
	m.lastSnapshot = &ConfigSnapshot{
		Version:       ProtocolVersion,
		Generation:    4,
		FIBGeneration: 0,
		Config:        &config.Config{},
	}
	m.generation = 4
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type != "bump_fib_generation" {
			return nil
		}
		// The helper's response reflects the accepted bump's generation.
		*status = ProcessStatus{
			Enabled:                true,
			Workers:                1,
			Bindings:               readyHelperStatus().Bindings,
			NeighborGeneration:     1,
			LastSnapshotGeneration: req.Snapshot.Generation,
			LastFIBGeneration:      req.Snapshot.FIBGeneration,
		}
		return nil
	}

	_, _ = m.BumpFIBGeneration()
	m.mu.Lock()
	defer m.mu.Unlock()
	if !ctrl.haveStored {
		t.Fatal("successful route-only bump wrote nothing to userspace_ctrl")
	}
	if ctrl.stored.FIBGeneration != m.lastSnapshot.FIBGeneration {
		t.Fatalf("userspace_ctrl FIBGeneration = %d after route-only bump, want confirmed helper generation %d; the shim stamps redirected packets with ctrl.fib_generation, so a missing ctrl publication leaves its packet stamp stale and causes FibGenerationMismatch", ctrl.stored.FIBGeneration, m.lastSnapshot.FIBGeneration)
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
