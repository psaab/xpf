package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

type linkCycleControlEvent struct {
	Request       ControlRequest
	Ctrl          userspaceCtrlValue
	CtrlLookupErr error
	Err           error
}

func TestPrepareLinkCycleDisablesCtrlBeforeStopWorkers(t *testing.T) {
	controlSock := filepath.Join(t.TempDir(), "control.sock")
	m, ctrlMap, _ := newLinkCycleTestManager(t, controlSock)
	seedUserspaceCtrl(t, ctrlMap, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            2,
		QueueCount:         2,
		Flags:              userspaceCtrlFlagStrict,
		ConfigGeneration:   41,
		FIBGeneration:      7,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})

	events := startLinkCycleControlServer(t, controlSock, ctrlMap, []ProcessStatus{{
		PID:      4242,
		Bindings: []BindingStatus{{Slot: 3, Ifindex: 2, QueueID: 1, Ready: true}},
	}})

	m.PrepareLinkCycle()

	ev := nextLinkCycleControlEvent(t, events)
	if ev.Request.Type != "stop_workers" {
		t.Fatalf("request type = %q, want stop_workers", ev.Request.Type)
	}
	if ev.CtrlLookupErr != nil {
		t.Fatalf("lookup userspace_ctrl at stop_workers: %v", ev.CtrlLookupErr)
	}
	if ev.Ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled at stop_workers = %d, want 0", ev.Ctrl.Enabled)
	}
	ctrl := lookupUserspaceCtrl(t, ctrlMap)
	if ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled after PrepareLinkCycle = %d, want 0", ctrl.Enabled)
	}
	if ctrl.Flags != userspaceCtrlFlagStrict {
		t.Fatalf("userspace_ctrl.Flags after PrepareLinkCycle = %#x, want strict flag preserved", ctrl.Flags)
	}
	if got := m.bpfShim.XDPEntryProgram(); got != userspaceXDPEntryProg {
		t.Fatalf("XDPEntryProgram() = %q, want %q", got, userspaceXDPEntryProg)
	}
}

func TestNotifyLinkCycleRebindsAndAppliesHelperStatusCompat(t *testing.T) {
	skipLinkCycleRebindSleep(t)

	controlSock := filepath.Join(t.TempDir(), "control.sock")
	m, ctrlMap, bindingsMap := newLinkCycleTestManager(t, controlSock)
	seedUserspaceCtrl(t, ctrlMap, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            2,
		QueueCount:         2,
		ConfigGeneration:   11,
		FIBGeneration:      3,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})
	m.configuredMode = ModeUserspaceCompat
	m.neighborsPrewarmed = true
	m.ctrlWasEnabled = true
	m.xskLivenessProven = true
	m.xskLivenessFailed = true
	m.xskProbeStart = time.Now().Add(-20 * time.Second)
	m.lastXSKRX = 99

	rebindStatus := ProcessStatus{
		PID:                    5150,
		Workers:                4,
		Enabled:                true,
		ForwardingArmed:        true,
		Capabilities:           UserspaceCapabilities{ForwardingSupported: true},
		LastSnapshotGeneration: 88,
		LastFIBGeneration:      13,
		NeighborGeneration:     21,
		Bindings: []BindingStatus{{
			Slot:          5,
			Ifindex:       2,
			QueueID:       1,
			Registered:    true,
			Armed:         true,
			Bound:         true,
			XSKRegistered: true,
			// #1666: the binding-array READY write now gates on the
			// helper-derived Ready (registered && bound && xsk_registered
			// && heartbeat_fresh), so a genuinely-live binding fixture must
			// set Ready to keep asserting Flags == userspaceBindingReady.
			Ready:     true,
			RXPackets: 17,
		}},
	}
	events := startLinkCycleControlServer(t, controlSock, ctrlMap, []ProcessStatus{rebindStatus})

	m.NotifyLinkCycle()

	ev := nextLinkCycleControlEvent(t, events)
	if ev.Request.Type != "rebind" {
		t.Fatalf("request type = %q, want rebind", ev.Request.Type)
	}
	if ev.CtrlLookupErr != nil {
		t.Fatalf("lookup userspace_ctrl at rebind: %v", ev.CtrlLookupErr)
	}
	if ev.Ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled at rebind = %d, want 0", ev.Ctrl.Enabled)
	}

	ctrl := lookupUserspaceCtrl(t, ctrlMap)
	if ctrl.Enabled != 1 {
		t.Fatalf("userspace_ctrl.Enabled after NotifyLinkCycle = %d, want 1", ctrl.Enabled)
	}
	if ctrl.Flags&userspaceCtrlFlagStrict != 0 {
		t.Fatalf("userspace_ctrl.Flags = %#x, want compat mode without strict flag", ctrl.Flags)
	}
	if ctrl.Workers != 4 || ctrl.QueueCount != 2 || ctrl.ConfigGeneration != 88 || ctrl.FIBGeneration != 13 {
		t.Fatalf("userspace_ctrl after NotifyLinkCycle = %+v, want helper status applied", ctrl)
	}
	if !m.xskLivenessProven || m.xskLivenessFailed || !m.xskProbeStart.IsZero() || m.lastXSKRX != 17 {
		t.Fatalf(
			"XSK liveness after NotifyLinkCycle = proven=%v failed=%v probe=%v lastRX=%d, want fresh live state from rebind status",
			m.xskLivenessProven,
			m.xskLivenessFailed,
			m.xskProbeStart,
			m.lastXSKRX,
		)
	}
	if got := m.lastStatus.PID; got != rebindStatus.PID {
		t.Fatalf("lastStatus.PID = %d, want %d", got, rebindStatus.PID)
	}
	binding := lookupUserspaceBinding(t, bindingsMap, 2*bindingQueuesPerIface+1)
	if binding.Slot != 5 || binding.Flags != userspaceBindingReady {
		t.Fatalf("userspace_bindings[ifindex=2 queue=1] = %+v, want slot=5 ready", binding)
	}
	if got := m.bpfShim.XDPEntryProgram(); got != userspaceXDPEntryProg {
		t.Fatalf("XDPEntryProgram() = %q, want %q", got, userspaceXDPEntryProg)
	}
}

func TestNotifyLinkCycleStrictModePublishesFailClosedCtrlFlags(t *testing.T) {
	skipLinkCycleRebindSleep(t)

	controlSock := filepath.Join(t.TempDir(), "control.sock")
	m, ctrlMap, _ := newLinkCycleTestManager(t, controlSock)
	seedUserspaceCtrl(t, ctrlMap, userspaceCtrlValue{
		Enabled:            1,
		MetadataVersion:    userspaceMetadataVersion,
		Workers:            1,
		QueueCount:         1,
		ConfigGeneration:   4,
		FIBGeneration:      2,
		HeartbeatTimeoutMS: userspaceHeartbeatTimeoutMS,
	})
	m.configuredMode = ModeUserspaceStrict
	m.mode = ModeUserspaceCompat
	m.neighborsPrewarmed = true
	m.ctrlWasEnabled = true
	m.xskLivenessProven = true
	m.xskLivenessFailed = true
	m.xskProbeStart = time.Now().Add(-20 * time.Second)
	m.lastXSKRX = 44

	rebindStatus := ProcessStatus{
		PID:                    6161,
		Workers:                2,
		Enabled:                false,
		ForwardingArmed:        false,
		Capabilities:           UserspaceCapabilities{ForwardingSupported: true},
		LastSnapshotGeneration: 91,
		LastFIBGeneration:      14,
		NeighborGeneration:     0,
		Bindings: []BindingStatus{{
			Slot:       7,
			Ifindex:    3,
			QueueID:    0,
			Registered: true,
			Armed:      true,
			Bound:      false,
		}},
	}
	events := startLinkCycleControlServer(t, controlSock, ctrlMap, []ProcessStatus{rebindStatus})

	m.NotifyLinkCycle()

	ev := nextLinkCycleControlEvent(t, events)
	if ev.Request.Type != "rebind" {
		t.Fatalf("request type = %q, want rebind", ev.Request.Type)
	}
	if ev.CtrlLookupErr != nil {
		t.Fatalf("lookup userspace_ctrl at rebind: %v", ev.CtrlLookupErr)
	}
	if ev.Ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled at rebind = %d, want 0", ev.Ctrl.Enabled)
	}

	ctrl := lookupUserspaceCtrl(t, ctrlMap)
	if ctrl.Enabled != 0 {
		t.Fatalf("userspace_ctrl.Enabled after strict NotifyLinkCycle = %d, want fail-closed", ctrl.Enabled)
	}
	if ctrl.Flags&userspaceCtrlFlagStrict == 0 {
		t.Fatalf("userspace_ctrl.Flags = %#x, want strict fail-closed flag", ctrl.Flags)
	}
	if ctrl.Workers != 2 || ctrl.QueueCount != 1 || ctrl.ConfigGeneration != 91 || ctrl.FIBGeneration != 14 {
		t.Fatalf("userspace_ctrl after strict NotifyLinkCycle = %+v, want helper status applied", ctrl)
	}
	if m.xskLivenessProven || m.xskLivenessFailed || !m.xskProbeStart.IsZero() || m.lastXSKRX != 0 {
		t.Fatalf(
			"XSK liveness after strict NotifyLinkCycle = proven=%v failed=%v probe=%v lastRX=%d, want reset fail-closed state",
			m.xskLivenessProven,
			m.xskLivenessFailed,
			m.xskProbeStart,
			m.lastXSKRX,
		)
	}
	if m.mode != ModeUserspaceStrict {
		t.Fatalf("mode after strict NotifyLinkCycle = %s, want %s", m.mode, ModeUserspaceStrict)
	}
	if got := m.lastStatus.PID; got != rebindStatus.PID {
		t.Fatalf("lastStatus.PID = %d, want %d", got, rebindStatus.PID)
	}
	if got := m.bpfShim.XDPEntryProgram(); got != userspaceXDPEntryProg {
		t.Fatalf("XDPEntryProgram() = %q, want %q", got, userspaceXDPEntryProg)
	}
}

func TestLegacyDataPlaneAdapterLinkForwardsLinkCycleToUserspaceManager(t *testing.T) {
	skipLinkCycleRebindSleep(t)

	controlSock := filepath.Join(t.TempDir(), "control.sock")
	m := newLinkCycleProcessOnlyManager(t, controlSock)

	events := startLinkCycleControlServer(t, controlSock, nil, []ProcessStatus{
		{PID: 7001, Bindings: []BindingStatus{{Slot: 1, Ifindex: 2, QueueID: 0, Ready: true}}},
		{
			PID:                    7002,
			Workers:                2,
			Enabled:                false,
			Capabilities:           UserspaceCapabilities{ForwardingSupported: true},
			LastSnapshotGeneration: 5,
			LastFIBGeneration:      6,
		},
	})

	link := NewLegacyDataPlaneAdapter(m).Link()
	link.PrepareLinkCycle()
	first := nextLinkCycleControlEvent(t, events)
	if first.Request.Type != "stop_workers" {
		t.Fatalf("first request type = %q, want stop_workers", first.Request.Type)
	}

	link.NotifyLinkCycle()
	second := nextLinkCycleControlEvent(t, events)
	if second.Request.Type != "rebind" {
		t.Fatalf("second request type = %q, want rebind", second.Request.Type)
	}
	if got := m.bpfShim.XDPEntryProgram(); got != userspaceXDPEntryProg {
		t.Fatalf("XDPEntryProgram() = %q, want %q", got, userspaceXDPEntryProg)
	}
}

func newLinkCycleTestManager(t *testing.T, controlSock string) (*Manager, *ebpf.Map, *ebpf.Map) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	m := newLinkCycleProcessOnlyManager(t, controlSock)
	ctrlMap, bindingsMap := injectCtrlAndBindingMaps(t, m)
	injectUserspaceBootstrapMaps(t, m)
	return m, ctrlMap, bindingsMap
}

func newLinkCycleProcessOnlyManager(t *testing.T, controlSock string) *Manager {
	t.Helper()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	m.bpfShim.SelectUserspaceXDPShimEntryProgram()
	m.lastRSTAttempt = time.Now()
	m.lastRSTInstallOK = true
	// #6871 round 10 (F1): release any link-cycle lease this manager ends up
	// holding, HERE rather than at each call site.
	//
	// A real lease starts a real heartbeat, and most tests that take one do not
	// install the fake ticker — so the goroutine sits on the production 15s
	// period. Once a package run exceeds 15s (this one takes 38-56s) an orphan
	// from an earlier test beats, reads the linkCycleLeaseElapsed package var,
	// and races a later test swapping it through fakeLinkCycleClock. Measured:
	// `go test -race` failed 1 run in 3 at the round-9 head, and every run under
	// -count=5 on the link-cycle subset.
	//
	// Centralised deliberately. The review named three leaking sites; a sweep
	// found twelve constructions through this helper and several more
	// PrepareLinkCycle calls among them, including error paths that take the
	// lease BEFORE the failure they are testing. Fixing the named three would
	// have left the class open, and the next test to take a lease would reopen
	// it. releaseLinkCycleLease is idempotent and stops-then-joins, so this is a
	// no-op for the tests that already release.
	t.Cleanup(m.releaseLinkCycleLease)
	return m
}

func startLinkCycleControlServer(
	t *testing.T,
	controlSock string,
	ctrlMap *ebpf.Map,
	responses []ProcessStatus,
) <-chan linkCycleControlEvent {
	t.Helper()
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Each response can publish at most one request event and one encode
	// failure. The non-blocking send below keeps future edits from turning a
	// fixture failure into a wedged server goroutine.
	events := make(chan linkCycleControlEvent, len(responses)*2)
	sendEvent := func(ev linkCycleControlEvent) bool {
		select {
		case events <- ev:
			return true
		default:
			t.Errorf("helper control event buffer exhausted")
			return false
		}
	}
	go func() {
		defer close(events)
		for _, status := range responses {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					sendEvent(linkCycleControlEvent{Err: err})
					return
				}
				ev := linkCycleControlEvent{Request: req}
				if ctrlMap != nil {
					var zero uint32
					ev.CtrlLookupErr = ctrlMap.Lookup(zero, &ev.Ctrl)
				}
				if !sendEvent(ev) {
					return
				}
				if err := json.NewEncoder(conn).Encode(ControlResponse{
					OK:     true,
					Status: &status,
				}); err != nil {
					sendEvent(linkCycleControlEvent{Err: err})
					return
				}
			}()
		}
	}()
	return events
}

func skipLinkCycleRebindSleep(t *testing.T) {
	t.Helper()
	oldSleep := linkCycleRebindSleep
	linkCycleRebindSleep = func(time.Duration) {}
	t.Cleanup(func() {
		linkCycleRebindSleep = oldSleep
	})
}

func nextLinkCycleControlEvent(t *testing.T, events <-chan linkCycleControlEvent) linkCycleControlEvent {
	t.Helper()
	select {
	case ev, ok := <-events:
		if !ok {
			t.Fatal("helper control server exited before receiving request")
		}
		if ev.Err != nil {
			t.Fatalf("helper control server decode request: %v", ev.Err)
		}
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for helper control request")
		return linkCycleControlEvent{}
	}
}

func seedUserspaceCtrl(t *testing.T, ctrlMap *ebpf.Map, ctrl userspaceCtrlValue) {
	t.Helper()
	var zero uint32
	if err := ctrlMap.Update(zero, ctrl, ebpf.UpdateAny); err != nil {
		t.Fatalf("seed userspace_ctrl: %v", err)
	}
}

func lookupUserspaceCtrl(t *testing.T, ctrlMap *ebpf.Map) userspaceCtrlValue {
	t.Helper()
	var zero uint32
	var ctrl userspaceCtrlValue
	if err := ctrlMap.Lookup(zero, &ctrl); err != nil {
		t.Fatalf("lookup userspace_ctrl: %v", err)
	}
	return ctrl
}

func lookupUserspaceBinding(t *testing.T, bindingsMap *ebpf.Map, idx uint32) userspaceBindingValue {
	t.Helper()
	var binding userspaceBindingValue
	if err := bindingsMap.Lookup(idx, &binding); err != nil {
		t.Fatalf("lookup userspace_bindings[%d]: %v", idx, err)
	}
	return binding
}
