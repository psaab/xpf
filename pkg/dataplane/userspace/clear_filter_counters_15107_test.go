package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// #15107 (A64-03): `clear firewall all` must reach the HELPER, not the
// retired-eBPF array.
//
// LegacyDataPlaneAdapter had no ClearFilterCounters method, so the embedded
// dataplane.DataPlane (= bpfShim) was PROMOTED and its ClearFilterCounters
// zeroed the retired `filter_counters` per-CPU array. It returned nil, so the
// CLI printed "Firewall filter counters cleared" while the counters `show
// firewall` READS (the helper's FilterTermCounters, via ProcessStatus) were
// untouched. This is the filter member of the #6566 census: #2218 (NAT),
// #3651 (zone) and #6566 (policy) fixed their siblings; this one was missed.
//
// FAIL-ON-REVERT: delete the adapter's ClearFilterCounters method (or the
// Manager override) and the call promotes to bpfShim again — no
// clear_filter_counters IPC is sent and the assertion below fails.
// Manager.ClearAllCounters must send it too, so `clear security counters`
// keeps resetting filter hit counts.

func runClearFilterCounterServer(t *testing.T) (string, chan string) {
	t.Helper()
	// Short prefix under /tmp (the flood_counter_clear_3651_test.go idiom):
	// the unix socket path limit (~108 bytes) is exceeded by t.TempDir()
	// under a long GOTMPDIR for the longer test names.
	dir, err := os.MkdirTemp("/tmp", "xpf15107")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	reqCh := make(chan string, 16)
	go func() {
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
			_ = json.NewEncoder(conn).Encode(ControlResponse{
				OK:     true,
				Status: &ProcessStatus{},
			})
			conn.Close()
		}
	}()
	return controlSock, reqCh
}

func newClearFilterAdapter(t *testing.T, controlSock string) *LegacyDataPlaneAdapter {
	t.Helper()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock
	// NewLegacyDataPlaneAdapter wires the embedded bpfShim exactly as
	// production does; a bare &LegacyDataPlaneAdapter{manager: m} leaves it
	// nil and the promoted call panics instead of failing cleanly.
	return NewLegacyDataPlaneAdapter(m)
}

func waitForFilterRequest15107(t *testing.T, reqCh chan string, want string) {
	t.Helper()
	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for !seen[want] {
		select {
		case got := <-reqCh:
			seen[got] = true
		case <-deadline:
			t.Fatalf("helper never received %q; saw %v — the clear was promoted "+
				"to the retired-eBPF bpfShim array, so the live filter counters "+
				"the display reads are untouched while the operator is told "+
				"they were cleared (#15107)", want, seen)
		}
	}
}

func TestAdapterClearFilterCountersReachesTheHelper15107(t *testing.T) {
	controlSock, reqCh := runClearFilterCounterServer(t)
	adapter := newClearFilterAdapter(t, controlSock)
	// Error ignored: the unarmed bpfShim leg is joined into it and is not the
	// property under test (same as clear_policy_counters_6566_test.go).
	_ = adapter.ClearFilterCounters()
	waitForFilterRequest15107(t, reqCh, "clear_filter_counters")
}

func TestAdapterClearAllCountersAlsoClearsFilterCounters15107(t *testing.T) {
	controlSock, reqCh := runClearFilterCounterServer(t)
	adapter := newClearFilterAdapter(t, controlSock)
	_ = adapter.ClearAllCounters()
	waitForFilterRequest15107(t, reqCh, "clear_filter_counters")
}

func TestOfflineClearFilterCountersZeroesCachedStatus15107(t *testing.T) {
	m := New()
	m.bpfShim = nil
	m.setLastStatusLocked(ProcessStatus{
		PID: 1234,
		FilterTermCounters: []FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "protect-RE", TermName: "count-web", Packets: 7, Bytes: 700},
		},
		ThreeColorPolicerCounters: []ThreeColorPolicerStatus{
			{ID: 1, Name: "wan-pol", Mode: "single-rate", GreenPackets: 5, GreenBytes: 500, DropPackets: 2, DropBytes: 200},
		},
	})
	beforeSeq := m.lastStatusSeq
	if err := m.ClearFilterCounters(); err != nil {
		t.Fatalf("ClearFilterCounters: %v", err)
	}
	if m.lastStatusSeq != beforeSeq+1 {
		t.Fatalf("lastStatusSeq = %d, want %d after cached status mutation", m.lastStatusSeq, beforeSeq+1)
	}
	view, ok := m.CachedStatus()
	if !ok {
		t.Fatal("CachedStatus unavailable after clear")
	}
	if len(view.FilterTermCounters) != 1 || view.FilterTermCounters[0].Packets != 0 || view.FilterTermCounters[0].Bytes != 0 {
		t.Fatalf("published filter counters did not reflect clear: %+v", view.FilterTermCounters)
	}
	if len(view.ThreeColorPolicerCounters) != 1 {
		t.Fatalf("policer rows = %+v, want the row retained with zeroed counts", view.ThreeColorPolicerCounters)
	}
	p := view.ThreeColorPolicerCounters[0]
	if p.GreenPackets != 0 || p.GreenBytes != 0 || p.DropPackets != 0 || p.DropBytes != 0 {
		t.Fatalf("published policer counters did not reflect clear: %+v", p)
	}
	if p.Name != "wan-pol" || p.Mode != "single-rate" {
		t.Fatalf("policer identity lost by clear: %+v", p)
	}
}
