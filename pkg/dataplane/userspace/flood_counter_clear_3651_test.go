package userspace

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

// assertOnlyNoBPFMapsError accepts the ONE error Manager.ClearAllCounters
// unavoidably returns in a unit fixture -- the embedded bpfShim has no BPF maps
// loaded, so its ClearInterfaceCounters reports "interface_counters map not
// found" (in production the retained AF_XDP shim registers that map, so this
// leg succeeds). Any OTHER error must fail the test rather than be swallowed,
// so a genuine failure in the new flood-clear path cannot hide behind it.
func assertOnlyNoBPFMapsError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if !strings.Contains(err.Error(), "interface_counters map not found") {
		t.Fatalf("ClearAllCounters: %v", err)
	}
	// A joined error carrying MORE than the known map error is a real failure.
	for _, line := range strings.Split(err.Error(), "\n") {
		if line != "" && !strings.Contains(line, "interface_counters map not found") {
			t.Fatalf("ClearAllCounters returned an unexpected error alongside the "+
				"known no-BPF-maps one: %q (full: %v)", line, err)
		}
	}
}

// TestClearAllCountersSendsFloodClearIPCAndIsDurable is the #3651 fail-on-revert
// guard for the flood-counter clear.
//
// The operator counter clear must reset BOTH the Go offset map AND the helper's
// cumulative FloodCounterStore (via the clear_flood_counters IPC); otherwise the
// next 1/s status poll re-mirrors the helper's cumulative counts over the
// cleared offset and the cleared value snaps back within <=1s.
//
// The fake helper models exactly that: a `status` request reports the cumulative
// counts UNTIL it has received a `clear_flood_counters` request, after which it
// reports nothing (the real helper's FloodCounterStore.clear() zeroes the blocks
// and the sparse snapshot then omits the all-zero row). The test:
//  1. seeds the offset map with cumulative counts (a prior poll),
//  2. clears via Manager.ClearAllCounters,
//  3. asserts the clear_flood_counters IPC was sent,
//  4. runs a follow-up status poll through the real syncBPFCountersLocked and
//     asserts the counters stay cleared (not restored to the cumulative).
//
// FAIL-ON-REVERT: drop the clearHelperFloodCountersLocked call from
// ClearAllCounters (or the IPC send inside it) and step 3 times out / step 4's
// poll restores the cumulative counts.
func TestClearAllCountersSendsFloodClearIPCAndIsDurable(t *testing.T) {
	// Socket-binding test: sun_path is 108 bytes, so keep the dir short.
	dir, err := os.MkdirTemp("/tmp", "xpf3651")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	const zoneID = uint32(2868932339) // config.StableZoneID("trust")
	cumulative := []ZoneFloodCounterStatus{
		{ZoneID: zoneID, SynFloodEvents: 42, ICMPFloodEvents: 43, UDPFloodEvents: 44},
	}

	reqCh := make(chan string, 16)
	cleared := make(chan struct{})
	go func() {
		clearedFlag := false
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				conn.Close()
				return
			}
			reqCh <- req.Type
			var flood []ZoneFloodCounterStatus
			switch req.Type {
			case "clear_flood_counters":
				if !clearedFlag {
					clearedFlag = true
					close(cleared)
				}
				// Post-clear the store is all-zero, so the sparse snapshot
				// publishes NO row for the zone.
				flood = nil
			case "status":
				if !clearedFlag {
					flood = cumulative
				}
			}
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK: true,
				Status: &ProcessStatus{
					FloodCounterLayoutVersion: 1,
					ZoneFloodCounters:         flood,
				},
			})
			conn.Close()
		}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock

	// Step 1: a prior poll mirrored the helper's cumulative counts into the
	// bpfShim offset map.
	m.mu.Lock()
	m.syncBPFCountersLocked(&ProcessStatus{
		FloodCounterLayoutVersion: 1,
		ZoneFloodCounters:         cumulative,
	})
	m.mu.Unlock()
	if fs, err := m.bpfShim.ReadFloodCounters(zoneID); err != nil || fs.SynCount != 42 {
		t.Fatalf("pre-clear ReadFloodCounters = %+v err=%v; want SynCount 42, nil", fs, err)
	}

	// Step 2: operator clear.
	assertOnlyNoBPFMapsError(t, m.ClearAllCounters())

	// Step 3: the clear_flood_counters IPC must have been sent — the
	// load-bearing half. Revert the IPC send and this never fires.
	select {
	case <-cleared:
	case <-time.After(5 * time.Second):
		t.Fatal("helper never received the clear_flood_counters IPC — clearing only " +
			"the Go offset map is undone by the next status poll")
	}
	// NOTE: the Go-side offset drop (bpfShim.ClearFloodCounterOffsets, reached
	// via bpfShim.ClearAllCounters) does not run in this fixture — the shim has
	// no BPF maps loaded, so ClearAllCounters returns early at
	// ClearInterfaceCounters. That is fine for what this test is for: the
	// question is whether the HELPER reset sticks, which step 4 answers.

	// Step 4: the next 1/s status poll. The helper (now cleared) publishes no
	// row, so syncBPFCountersLocked replaces the offset map with an empty one
	// and the cleared state STICKS. Without the IPC the helper would still
	// report the cumulative here and this poll would restore it.
	m.mu.Lock()
	var status ProcessStatus
	pollErr := m.requestLocked(ControlRequest{Type: "status"}, &status)
	if pollErr == nil {
		m.syncBPFCountersLocked(&status)
	}
	m.mu.Unlock()
	if pollErr != nil {
		t.Fatalf("status poll: %v", pollErr)
	}
	if _, err := m.bpfShim.ReadFloodCounters(zoneID); !errors.Is(err, dataplane.ErrCounterNotPopulated) {
		fs, _ := m.bpfShim.ReadFloodCounters(zoneID)
		t.Fatalf("after the post-clear poll ReadFloodCounters = %+v err=%v; want "+
			"ErrCounterNotPopulated (counts snapped back — clear_flood_counters IPC "+
			"missing?)", fs, err)
	}

	var sawClear bool
	for {
		select {
		case typ := <-reqCh:
			if typ == "clear_flood_counters" {
				sawClear = true
			}
			continue
		default:
		}
		break
	}
	if !sawClear {
		t.Fatal("clear_flood_counters request not observed in helper request log")
	}
}

// TestClearAllCountersZerosCachedFloodCountersWithoutHelper covers the
// no-live-helper path: with no helper process the cached
// m.lastStatus.ZoneFloodCounters are dropped directly so a clear still takes
// effect (parity with clearHelperZoneCountersLocked's without-helper branch).
func TestClearAllCountersZerosCachedFloodCountersWithoutHelper(t *testing.T) {
	m := New()
	m.proc = nil // no live helper
	m.lastStatus = ProcessStatus{
		ZoneFloodCounters: []ZoneFloodCounterStatus{{ZoneID: 2868932339, SynFloodEvents: 9}},
	}
	assertOnlyNoBPFMapsError(t, m.ClearAllCounters())
	if len(m.lastStatus.ZoneFloodCounters) != 0 {
		t.Fatalf("cached helper flood counters after clear = %+v, want empty",
			m.lastStatus.ZoneFloodCounters)
	}
}
