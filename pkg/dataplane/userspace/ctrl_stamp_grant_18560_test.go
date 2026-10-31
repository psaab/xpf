package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func monoNowNS18560(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("clock_gettime: %v", err)
	}
	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec)
}

// roundTripGrant18560 sends one request through the real control-socket round
// trip (requestDetailedLocked) to a fake helper and returns the grant the
// helper received, bracketed by CLOCK_MONOTONIC readings taken before the send
// and after the reply.
func roundTripGrant18560(t *testing.T, req ControlRequest) (grant, before, after uint64) {
	t.Helper()
	controlSock := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()
	got := make(chan uint64, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var in ControlRequest
		if err := json.NewDecoder(conn).Decode(&in); err != nil {
			return
		}
		got <- in.CtrlStampDeadlineMonoNS
		_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true, Status: &ProcessStatus{}})
	}()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	before = monoNowNS18560(t)
	m.mu.Lock()
	_, err = m.requestDetailedLocked(req)
	m.mu.Unlock()
	after = monoNowNS18560(t)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	select {
	case grant = <-got:
	default:
		t.Fatal("the fake helper never received the request")
	}
	return grant, before, after
}

// #18560: apply_snapshot and bump_fib_generation (the requests that carry a
// snapshot) carry a CLOCK_MONOTONIC grant that starts at the send and lasts
// ctrlStampGrant; nothing else carries one, even if a caller filled the field
// in. RED if the stamping in requestDetailedAtSocket is removed, widened to
// requests without a snapshot, or computed on another clock.
func TestCtrlStampGrantOnlyOnStampChangingVerbs18560(t *testing.T) {
	for _, verb := range []string{"apply_snapshot", "bump_fib_generation"} {
		grant, before, after := roundTripGrant18560(t, ControlRequest{Type: verb, Snapshot: &ConfigSnapshot{}})
		if grant < before+uint64(ctrlStampGrant) || grant > after+uint64(ctrlStampGrant) {
			t.Fatalf("%s grant %d not within [send+grant, reply+grant] = [%d, %d]",
				verb, grant, before+uint64(ctrlStampGrant), after+uint64(ctrlStampGrant))
		}
	}
	for _, verb := range []string{"status", "update_neighbors", "update_ha_state", "set_forwarding_state"} {
		grant, _, _ := roundTripGrant18560(t, ControlRequest{Type: verb, CtrlStampDeadlineMonoNS: 42})
		if grant != 0 {
			t.Fatalf("%s carried a ctrl-stamp grant (%d); only the stamp-changing verbs may", verb, grant)
		}
	}
}

// The grant must end before the smallest deadline a granting round trip can
// be given, including a shutdown cut. Pinned at compile time in
// ctrl_stamp_grant_18560.go; restated here so a constant change is visible
// in the test output too.
func TestCtrlStampGrantEndsBeforeEveryDeadline18560(t *testing.T) {
	if ctrlStampGrant >= controlShutdownCutover || ctrlStampGrant >= controlBaseDeadline {
		t.Fatalf("ctrlStampGrant %v must be shorter than controlShutdownCutover %v and controlBaseDeadline %v",
			ctrlStampGrant, controlShutdownCutover, controlBaseDeadline)
	}
}
