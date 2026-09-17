package userspace

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

func scopedLease10018() IdleLeaseWire {
	scope := uint32(7)
	return IdleLeaseWire{
		Pool:           "p1",
		Protocol:       6,
		SrcIP:          "10.0.61.50",
		SrcPort:        40000,
		RoutingScope:   &scope,
		RemoteIP:       "8.8.8.8",
		RemotePort:     443,
		TranslatedIP:   "203.0.113.1",
		TranslatedPort: 1024,
		RemainingNs:    5,
		TimeoutNs:      10,
	}
}

// #10018: live lease verbs must not cross to an old helper or to a helper whose
// protocol cannot be observed. The latter is intentionally stricter than the
// no-brick config-compile gates: an export/import request is about to carry a
// security-sensitive identity, so unknown is not safe.
func TestPersistentNatLeaseVerbsFailClosedOnProtocol10018(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation func(*Manager) error
		old       bool
		probeErr  error
	}{
		{
			name: "export-old-helper",
			operation: func(m *Manager) error {
				_, err := m.ExportIdleLeases()
				return err
			},
			old: true,
		},
		{
			name: "display-old-helper",
			operation: func(m *Manager) error {
				_, err := m.ExportPersistentLeaseDisplay()
				return err
			},
			old: true,
		},
		{
			name: "import-old-helper",
			operation: func(m *Manager) error {
				return m.ImportIdleLeases([]IdleLeaseWire{scopedLease10018()})
			},
			old: true,
		},
		{
			name: "export-status-probe-failure",
			operation: func(m *Manager) error {
				_, err := m.ExportIdleLeases()
				return err
			},
			probeErr: errors.New("status probe failed"),
		},
		{
			name: "import-status-probe-failure",
			operation: func(m *Manager) error {
				return m.ImportIdleLeases([]IdleLeaseWire{scopedLease10018()})
			},
			probeErr: errors.New("status probe failed"),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
			m.helperStatusObserved = false
			statusCalls := 0
			m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
				statusCalls++
				if req.Type != "status" {
					t.Fatalf("lease verb %q crossed before the protocol gate", req.Type)
				}
				if tc.probeErr != nil {
					return tc.probeErr
				}
				if tc.old {
					status.ConfigSnapshotProtocolVersion = ProtocolVersion - 1
				} else {
					status.ConfigSnapshotProtocolVersion = ProtocolVersion
				}
				return nil
			}
			err := tc.operation(m)
			if !errors.Is(err, ErrPersistentNatLeaseScopeProtocolIncompatible) {
				t.Fatalf("error = %v, want scoped lease incompatibility", err)
			}
			if statusCalls != 1 {
				t.Fatalf("status probe calls = %d, want exactly one", statusCalls)
			}
		})
	}
}

func TestPersistentNatLeaseVerbsAllowObservedCurrentProtocol10018(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation func(*Manager) error
	}{
		{
			name: "export",
			operation: func(m *Manager) error {
				_, err := m.ExportIdleLeases()
				return err
			},
		},
		{
			name: "import",
			operation: func(m *Manager) error {
				return m.ImportIdleLeases([]IdleLeaseWire{scopedLease10018()})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
			statusCalls := 0
			m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
				statusCalls++
				if req.Type != "status" {
					t.Fatalf("unexpected request during protocol probe: %q", req.Type)
				}
				status.ConfigSnapshotProtocolVersion = ProtocolVersion
				return nil
			}
			err := tc.operation(m)
			if err == nil {
				t.Fatal("operation unexpectedly succeeded without a lease control socket")
			}
			if errors.Is(err, ErrPersistentNatLeaseScopeProtocolIncompatible) {
				t.Fatalf("current helper was rejected by lease gate: %v", err)
			}
			if statusCalls != 1 {
				t.Fatalf("status probe calls = %d, want exactly one", statusCalls)
			}
		})
	}
}

func TestPersistentNatLeaseImportRejectsMissingScope10018(t *testing.T) {
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	called := false
	m.controlRequestHook = func(ControlRequest, *ProcessStatus) error {
		called = true
		return nil
	}
	lease := scopedLease10018()
	lease.RoutingScope = nil
	if err := m.ImportIdleLeases([]IdleLeaseWire{lease}); !errors.Is(err, ErrPersistentNatLeaseScopeProtocolIncompatible) {
		t.Fatalf("missing scope error = %v, want scoped lease incompatibility", err)
	}
	if called {
		t.Fatal("missing scope reached protocol probe or lease verb")
	}
}
