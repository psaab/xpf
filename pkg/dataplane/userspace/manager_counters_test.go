package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestStatusIPCRecordsSYNCookieBindingCounters(t *testing.T) {
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	defer ln.Close()

	reqCh := make(chan ControlRequest, 1)
	done := make(chan struct{}, 1)
	go func() {
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
				PID: 4321,
				Bindings: []BindingStatus{
					{
						Slot:                       0,
						SYNCookieChallenges:        3,
						SYNCookieSecretUnavailable: 5,
						SYNCookieSynAckSent:        7,
						SYNCookieAckRstSent:        11,
						SYNCookieReplyBudgetDrops:  13,
						SYNCookieAckValid:          17,
						SYNCookieAckInvalid:        19,
						SYNCookieBypass:            23,
					},
					{
						Slot:                       1,
						SYNCookieChallenges:        17,
						SYNCookieSecretUnavailable: 19,
						SYNCookieSynAckSent:        29,
						SYNCookieAckRstSent:        31,
						SYNCookieReplyBudgetDrops:  37,
						SYNCookieAckValid:          41,
						SYNCookieAckInvalid:        43,
						SYNCookieBypass:            47,
					},
				},
			},
		})
		done <- struct{}{}
	}()

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("FindProcess: %v", err)
	}
	m := New()
	m.proc = &exec.Cmd{Process: proc}
	m.cfg.ControlSocket = controlSock

	m.mu.Lock()
	var status ProcessStatus
	err = m.requestLocked(ControlRequest{Type: "status"}, &status)
	if err == nil {
		m.recordHelperStatusLocked(&status)
	}
	m.mu.Unlock()
	if err != nil {
		t.Fatalf("status IPC: %v", err)
	}
	select {
	case req := <-reqCh:
		if req.Type != "status" {
			t.Fatalf("request type = %q, want status", req.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("helper did not receive status request")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("helper did not finish status response")
	}

	// Aggregate the per-binding SYN-cookie counters the manager recorded.
	// The shared SumSYNCookieCounters/SYNCookieCounters helpers now live in
	// the format subpackage (which imports this package), so this manager
	// test sums inline to assert the recording behavior without creating an
	// import cycle. The summation helper itself is covered by the format
	// package tests.
	type synCookieTotals struct {
		Challenges        uint64
		SecretUnavailable uint64
		SynAckSent        uint64
		AckRstSent        uint64
		ReplyBudgetDrops  uint64
		AckValid          uint64
		AckInvalid        uint64
		Bypass            uint64
	}
	var got synCookieTotals
	for _, binding := range m.lastStatus.Bindings {
		got.Challenges += binding.SYNCookieChallenges
		got.SecretUnavailable += binding.SYNCookieSecretUnavailable
		got.SynAckSent += binding.SYNCookieSynAckSent
		got.AckRstSent += binding.SYNCookieAckRstSent
		got.ReplyBudgetDrops += binding.SYNCookieReplyBudgetDrops
		got.AckValid += binding.SYNCookieAckValid
		got.AckInvalid += binding.SYNCookieAckInvalid
		got.Bypass += binding.SYNCookieBypass
	}
	want := synCookieTotals{
		Challenges:        20,
		SecretUnavailable: 24,
		SynAckSent:        36,
		AckRstSent:        42,
		ReplyBudgetDrops:  50,
		AckValid:          58,
		AckInvalid:        62,
		Bypass:            70,
	}
	if got != want {
		t.Fatalf("SYN-cookie counters after status IPC = %+v, want %+v", got, want)
	}
}

func TestSumBindingCounters(t *testing.T) {
	status := &ProcessStatus{
		Bindings: []BindingStatus{
			{
				RXPackets:                100,
				TXPackets:                80,
				ForwardCandidatePkts:     70,
				SessionCreates:           10,
				SessionExpires:           5,
				PolicyDeniedPackets:      3,
				HostInboundDeniedPackets: 6,
				UMEMSliceDropped:         1,
				UnknownVLANDropped:       2,
				DstMACDropped:            3,
				ScreenDrops:              2,
				// #3343: per-reason screen drops, one element per
				// dataplane.ScreenReasonCounters ordinal.
				ScreenReasonDrops:   []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
				SYNCookieSynAckSent: 7,
				SYNCookieAckValid:   11,
				SYNCookieAckInvalid: 13,
				SYNCookieBypass:     17,
				SNATPackets:         20,
				DNATPackets:         15,
				Nat64Translations:   9,
				NatAllocFail:        8,
			},
			{
				RXPackets:                200,
				TXPackets:                160,
				ForwardCandidatePkts:     140,
				SessionCreates:           20,
				SessionExpires:           10,
				PolicyDeniedPackets:      7,
				HostInboundDeniedPackets: 14,
				UMEMSliceDropped:         5,
				UnknownVLANDropped:       7,
				DstMACDropped:            11,
				ScreenDrops:              4,
				ScreenReasonDrops:        []uint64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150},
				SYNCookieSynAckSent:      17,
				SYNCookieAckValid:        19,
				SYNCookieAckInvalid:      23,
				SYNCookieBypass:          29,
				SNATPackets:              40,
				DNATPackets:              30,
				Nat64Translations:        21,
				NatAllocFail:             16,
			},
		},
	}
	s := sumBindingCounters(status)
	if s.rxPackets != 300 {
		t.Fatalf("rxPackets = %d, want 300", s.rxPackets)
	}
	if s.txPackets != 240 {
		t.Fatalf("txPackets = %d, want 240", s.txPackets)
	}
	if s.forwardPackets != 210 {
		t.Fatalf("forwardPackets = %d, want 210", s.forwardPackets)
	}
	if s.sessionCreates != 30 {
		t.Fatalf("sessionCreates = %d, want 30", s.sessionCreates)
	}
	if s.sessionExpires != 15 {
		t.Fatalf("sessionExpires = %d, want 15", s.sessionExpires)
	}
	if s.policyDenied != 10 {
		t.Fatalf("policyDenied = %d, want 10", s.policyDenied)
	}
	// #3326: host-inbound admission denies aggregate like policy denies and are
	// pushed into GlobalCtrHostInboundDeny by syncBPFCountersLocked. RED if the
	// `s.hostInboundDenied += b.HostInboundDeniedPackets` line is reverted.
	if s.hostInboundDenied != 20 {
		t.Fatalf("hostInboundDenied = %d, want 20", s.hostInboundDenied)
	}
	if s.unknownVLANDrops != 9 {
		t.Fatalf("unknownVLANDrops = %d, want 9", s.unknownVLANDrops)
	}
	if s.dstMACDrops != 14 {
		t.Fatalf("dstMACDrops = %d, want 14", s.dstMACDrops)
	}
	if s.screenDrops != 6 {
		t.Fatalf("screenDrops = %d, want 6", s.screenDrops)
	}
	if s.synCookieSent != 24 {
		t.Fatalf("synCookieSent = %d, want 24", s.synCookieSent)
	}
	if s.synCookieValid != 30 {
		t.Fatalf("synCookieValid = %d, want 30", s.synCookieValid)
	}
	if s.synCookieInvalid != 36 {
		t.Fatalf("synCookieInvalid = %d, want 36", s.synCookieInvalid)
	}
	if s.synCookieBypass != 46 {
		t.Fatalf("synCookieBypass = %d, want 46", s.synCookieBypass)
	}
	if s.snatPackets != 60 {
		t.Fatalf("snatPackets = %d, want 60", s.snatPackets)
	}
	if s.dnatPackets != 45 {
		t.Fatalf("dnatPackets = %d, want 45", s.dnatPackets)
	}
	// #2161: NAT64 translations are aggregated across bindings like
	// snat/dnat and pushed into GlobalCtrNAT64Xlate by syncBPFCountersLocked.
	if s.nat64Translations != 30 {
		t.Fatalf("nat64Translations = %d, want 30", s.nat64Translations)
	}
	// #4477: source-NAT allocation failures aggregate across bindings and are
	// pushed into GlobalCtrNATAllocFail by syncBPFCountersLocked. RED if the
	// `s.natAllocFail += b.NatAllocFail` line is reverted.
	if s.natAllocFail != 24 {
		t.Fatalf("natAllocFail = %d, want 24", s.natAllocFail)
	}
	// #4477/#10498: totalDrops() is the aggregate "Packets dropped" figure
	// pushed into GlobalCtrDrops: policyDenied(10) + screenDrops(6) +
	// hostInboundDenied(20) + unknownVLANDrops(9) + dstMACDrops(14) +
	// natAllocFail(24) = 83. UMEMSliceDropped is intentionally excluded.
	if s.totalDrops() != 83 {
		t.Fatalf("totalDrops() = %d, want 83", s.totalDrops())
	}
	// #3343: per-reason screen drops sum element-wise across bindings. RED if
	// the `s.screenReasonDrops[i] += b.ScreenReasonDrops[i]` loop is reverted
	// (the per-reason GlobalCtrScreen* counters would then stay 0).
	for i := 0; i < dataplane.ScreenReasonDropCount; i++ {
		want := uint64((i + 1) * 11) // (i+1) + (i+1)*10
		if s.screenReasonDrops[i] != want {
			t.Fatalf("screenReasonDrops[%d] (%s) = %d, want %d",
				i, dataplane.ScreenReasonCounters[i].Reason, s.screenReasonDrops[i], want)
		}
	}
}

// TestSyncBPFCountersPushesPerScreenReason is the #3343 fail-on-revert guard
// for the publish path: the userspace helper reports per-screen-reason drops in
// BindingStatus.ScreenReasonDrops, and syncBPFCountersLocked must push each
// ordinal's delta into its dataplane.GlobalCtrScreen* global counter so the
// CLI/gRPC/REST/Prometheus screen-statistics surfaces (which read those
// GlobalCtrScreen* indices) stop reading a permanent 0. Reverting the push loop
// in syncBPFCountersLocked leaves every per-reason counter at 0 and fails the
// per-reason ReadGlobalCounter assertions below.
func TestSyncBPFCountersPushesPerScreenReason(t *testing.T) {
	m := New()

	// Two bindings, every per-reason ordinal exercised with a distinct value so
	// a wrong ordinal→index mapping (or a missing reason like port-scan /
	// ip-sweep / session-limit) is detectable.
	b0 := make([]uint64, dataplane.ScreenReasonDropCount)
	b1 := make([]uint64, dataplane.ScreenReasonDropCount)
	for i := range b0 {
		b0[i] = uint64(i + 1)
		b1[i] = uint64((i + 1) * 100)
	}
	status := &ProcessStatus{
		Bindings: []BindingStatus{
			{Slot: 0, ScreenReasonDrops: b0},
			{Slot: 1, ScreenReasonDrops: b1},
		},
	}

	m.mu.Lock()
	m.syncBPFCountersLocked(status)
	m.mu.Unlock()

	// syncBPFCountersLocked pushes each ordinal's delta into its GlobalCtrScreen*
	// index via IncrementGlobalCounter, which records the userspace offset
	// independent of any loaded BPF map — so the publish path is assertable
	// without BPF privileges. Reading the in-memory offset is exactly what
	// ReadGlobalCounter merges in for the live CLI/gRPC/REST/Prometheus reads.
	for i := range dataplane.ScreenReasonCounters {
		rc := &dataplane.ScreenReasonCounters[i]
		want := uint64((i + 1) * 101) // (i+1) + (i+1)*100
		got := m.bpfShim.ReadUserspaceCounterOffset(rc.Index)
		if got != want {
			t.Fatalf("per-reason counter %s (idx=%d) = %d, want %d (push loop reverted?)",
				rc.Reason, rc.Index, got, want)
		}
	}

	// The aggregate GlobalCtrScreenDrops must not be inflated by the per-reason
	// push (the helper bumps the aggregate separately via b.ScreenDrops).
	if got := m.bpfShim.ReadUserspaceCounterOffset(dataplane.GlobalCtrScreenDrops); got != 0 {
		t.Fatalf("aggregate GlobalCtrScreenDrops = %d, want 0 (per-reason push must not touch it)", got)
	}
}

// TestSyncBPFCountersPushesDropAndNATAllocFail is the #4477 fail-on-revert
// guard: the userspace helper reports source-NAT allocation failures in
// BindingStatus.NatAllocFail, and syncBPFCountersLocked must push their delta
// into dataplane.GlobalCtrNATAllocFail AND fold them (with policy deny + screen
// + host-inbound deny) into the aggregate dataplane.GlobalCtrDrops. Before
// #4477 neither index was ever written, so `show security flow statistics`
// ("Packets dropped" / "NAT allocation failures"), REST, Prometheus, and the
// CLI printed a permanent, false 0. Reverting either delta drops the counter
// back to 0 and fails the ReadUserspaceCounterOffset assertions below.
func TestSyncBPFCountersPushesDropAndNATAllocFail(t *testing.T) {
	m := New()
	status := &ProcessStatus{
		Bindings: []BindingStatus{
			{
				Slot:                     0,
				PolicyDeniedPackets:      3,
				ScreenDrops:              2,
				HostInboundDeniedPackets: 6,
				UMEMSliceDropped:         17,
				UnknownVLANDropped:       1,
				DstMACDropped:            2,
				NatAllocFail:             8,
			},
			{
				Slot:                     1,
				PolicyDeniedPackets:      7,
				ScreenDrops:              4,
				HostInboundDeniedPackets: 14,
				UMEMSliceDropped:         19,
				UnknownVLANDropped:       8,
				DstMACDropped:            8,
				NatAllocFail:             16,
			},
		},
	}

	m.mu.Lock()
	m.syncBPFCountersLocked(status)
	m.mu.Unlock()

	// Dedicated reason indices aggregate their distinct per-binding values.
	if got := m.bpfShim.ReadUserspaceCounterOffset(dataplane.GlobalCtrNATAllocFail); got != 24 {
		t.Fatalf("GlobalCtrNATAllocFail = %d, want 24", got)
	}
	if got := m.bpfShim.ReadUserspaceCounterOffset(dataplane.GlobalCtrUnknownVLANDrops); got != 9 {
		t.Fatalf("GlobalCtrUnknownVLANDrops = %d, want 9", got)
	}
	if got := m.bpfShim.ReadUserspaceCounterOffset(dataplane.GlobalCtrDstMACDrops); got != 10 {
		t.Fatalf("GlobalCtrDstMACDrops = %d, want 10", got)
	}
	// GlobalCtrDrops includes the configured VLAN/MAC admission reasons but
	// excludes UMEM hygiene: 10 + 6 + 20 + 24 + 9 + 10 = 79.
	if got := m.bpfShim.ReadUserspaceCounterOffset(dataplane.GlobalCtrDrops); got != 79 {
		t.Fatalf("GlobalCtrDrops = %d, want 79", got)
	}

	// A second poll with the same cumulative totals produces zero deltas.
	m.mu.Lock()
	m.syncBPFCountersLocked(status)
	m.mu.Unlock()
	for idx, want := range map[uint32]uint64{
		dataplane.GlobalCtrNATAllocFail:     24,
		dataplane.GlobalCtrUnknownVLANDrops: 9,
		dataplane.GlobalCtrDstMACDrops:      10,
		dataplane.GlobalCtrDrops:            79,
	} {
		if got := m.bpfShim.ReadUserspaceCounterOffset(idx); got != want {
			t.Fatalf("counter %d after idempotent re-poll = %d, want %d", idx, got, want)
		}
	}

	// A subsequent poll advances only by each changed cumulative delta.
	status.Bindings[0].NatAllocFail = 18       // +10
	status.Bindings[0].UnknownVLANDropped = 11 // +10
	status.Bindings[1].DstMACDropped = 28      // +20
	m.mu.Lock()
	m.syncBPFCountersLocked(status)
	m.mu.Unlock()
	if got := m.bpfShim.ReadUserspaceCounterOffset(dataplane.GlobalCtrNATAllocFail); got != 34 {
		t.Fatalf("GlobalCtrNATAllocFail after deltas = %d, want 34", got)
	}
	if got := m.bpfShim.ReadUserspaceCounterOffset(dataplane.GlobalCtrUnknownVLANDrops); got != 19 {
		t.Fatalf("GlobalCtrUnknownVLANDrops after delta = %d, want 19", got)
	}
	if got := m.bpfShim.ReadUserspaceCounterOffset(dataplane.GlobalCtrDstMACDrops); got != 30 {
		t.Fatalf("GlobalCtrDstMACDrops after delta = %d, want 30", got)
	}
	if got := m.bpfShim.ReadUserspaceCounterOffset(dataplane.GlobalCtrDrops); got != 119 {
		t.Fatalf("GlobalCtrDrops after deltas = %d, want 119", got)
	}
}

// TestSyncBPFCountersMirrorsNATRuleCounters is the #2218 fail-on-revert
// guard for the Go control-plane half: the Rust helper reports per-rule SNAT/
// DNAT/static-NAT translation hits in ProcessStatus.NATRuleCounters, and
// syncBPFCountersLocked must mirror them into the bpfShim offset map so the
// existing operator read path (Manager/adapter ReadNATRuleCounter →
// `show security nat ... rule`) returns the live total instead of a perpetual
// 0. Before the fix the helper counts were never surfaced through
// ReadNATRuleCounter; this test FAILS (counter stays 0) if the mirror loop is
// reverted.
func TestSyncBPFCountersMirrorsNATRuleCounters(t *testing.T) {
	m := New()
	status := &ProcessStatus{
		NATRuleCounters: []NATRuleCounterStatus{
			{CounterID: 1, Packets: 7, Bytes: 700},
			{CounterID: 3, Packets: 11, Bytes: 1100},
			// CounterID 0 is the "no per-rule counter" sentinel and must be
			// skipped (never overwrite counter slot 0).
			{CounterID: 0, Packets: 99, Bytes: 9900},
		},
	}
	m.mu.Lock()
	m.syncBPFCountersLocked(status)
	m.mu.Unlock()

	got, err := m.bpfShim.ReadNATRuleCounter(1)
	if err != nil {
		t.Fatalf("ReadNATRuleCounter(1): %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 7, Bytes: 700}) {
		t.Fatalf("counter 1 = %+v, want packets=7 bytes=700 (mirror loop reverted?)", got)
	}
	got, err = m.bpfShim.ReadNATRuleCounter(3)
	if err != nil {
		t.Fatalf("ReadNATRuleCounter(3): %v", err)
	}
	if got != (dataplane.CounterValue{Packets: 11, Bytes: 1100}) {
		t.Fatalf("counter 3 = %+v, want packets=11 bytes=1100", got)
	}
	// Counter 0 must be untouched (sentinel skipped).
	got, err = m.bpfShim.ReadNATRuleCounter(0)
	if err != nil {
		t.Fatalf("ReadNATRuleCounter(0): %v", err)
	}
	if got != (dataplane.CounterValue{}) {
		t.Fatalf("counter 0 = %+v, want zero (sentinel must be skipped)", got)
	}

	// Subsequent polls overwrite absolutely (helper reports cumulative).
	status.NATRuleCounters[0].Packets = 50
	status.NATRuleCounters[0].Bytes = 5000
	m.mu.Lock()
	m.syncBPFCountersLocked(status)
	m.mu.Unlock()
	got, _ = m.bpfShim.ReadNATRuleCounter(1)
	if got != (dataplane.CounterValue{Packets: 50, Bytes: 5000}) {
		t.Fatalf("counter 1 after second poll = %+v, want packets=50 bytes=5000 (absolute overwrite)", got)
	}

	// ClearNATRuleCounters drops the offsets.
	if err := m.bpfShim.ClearNATRuleCounters(); err != nil {
		t.Fatalf("ClearNATRuleCounters: %v", err)
	}
	got, _ = m.bpfShim.ReadNATRuleCounter(1)
	if got != (dataplane.CounterValue{}) {
		t.Fatalf("counter 1 after clear = %+v, want zero", got)
	}
}

// Test_clear_global_counters_resets_userspace_offset_5098 is the #5098
// fail-on-revert merge gate. ReadGlobalCounter returns the per-CPU BPF array sum
// PLUS the in-memory userspaceCounterOffsets entry that IncrementGlobalCounter
// and the 1/s status poll (syncBPFCountersLocked) accrue for userspace-forwarded
// packets that bypass the BPF pipeline. Before #5098 neither ClearGlobalCounters
// nor ClearAllCounters reset that offset map, so a cleared global RX/TX/drop/
// session total snapped straight back to its pre-clear value on the next read.
//
// The gate is deliberately mapless (no BPF privileges required): it keys on
// ReadUserspaceCounterOffset, which is exactly the offset half ReadGlobalCounter
// merges on top of the (zeroed) BPF array — so the assertion runs everywhere,
// not only on a privileged host. The full ReadGlobalCounter read equation
// (array + offset == 0) is pinned by the sibling dataplane-package test
// Test_clear_global_counters_read_equation_zero_5098.
//
// Reverting the offset reset in dataplane.Manager.ClearGlobalCounters fails the
// post-clear "offset == 0" assertions; reverting the prevBindingCounters rebase
// in userspace.Manager.ClearAllCounters fails the post-clear delta assertion.
func Test_clear_global_counters_resets_userspace_offset_5098(t *testing.T) {
	const rxIdx = dataplane.GlobalCtrRxPackets
	const txIdx = dataplane.GlobalCtrTxPackets

	t.Run("ClearGlobalCounters_resets_offset_and_restarts_accrual", func(t *testing.T) {
		m := New()

		// Seed a non-zero offset the way userspace-forwarded accounting does.
		if err := m.bpfShim.IncrementGlobalCounter(rxIdx, 100); err != nil {
			t.Fatalf("seed IncrementGlobalCounter: %v", err)
		}
		if got := m.bpfShim.ReadUserspaceCounterOffset(rxIdx); got != 100 {
			t.Fatalf("seed rx offset = %d, want 100", got)
		}

		// The clear must drop the offset, not just the BPF array. Mapless, so the
		// BPF-array zero is skipped and the offset reset is the whole clear.
		if err := m.bpfShim.ClearGlobalCounters(); err != nil {
			t.Fatalf("ClearGlobalCounters: %v", err)
		}
		if got := m.bpfShim.ReadUserspaceCounterOffset(rxIdx); got != 0 {
			t.Fatalf("rx offset after ClearGlobalCounters = %d, want 0 "+
				"(cleared total snaps back — #5098 offset reset reverted?)", got)
		}

		// A NEW delta after the clear accrues from zero, not on top of the stale
		// pre-clear value.
		if err := m.bpfShim.IncrementGlobalCounter(rxIdx, 42); err != nil {
			t.Fatalf("post-clear IncrementGlobalCounter: %v", err)
		}
		if got := m.bpfShim.ReadUserspaceCounterOffset(rxIdx); got != 42 {
			t.Fatalf("rx offset after post-clear accrual = %d, want 42 "+
				"(offset did not restart from zero)", got)
		}
	})

	t.Run("ClearAllCounters_resets_offset_and_rebases_delta_baseline", func(t *testing.T) {
		m := New()

		mkStatus := func(rx, tx uint64) *ProcessStatus {
			return &ProcessStatus{Bindings: []BindingStatus{
				{Slot: 0, RXPackets: rx, TXPackets: tx},
			}}
		}
		// poll advances lastStatus AND accrues the helper delta into the offset
		// (recording prevBindingCounters), exactly like the 1/s status poll.
		poll := func(rx, tx uint64) {
			t.Helper()
			status := mkStatus(rx, tx)
			m.mu.Lock()
			m.recordHelperStatusLocked(status)
			m.syncBPFCountersLocked(status)
			m.mu.Unlock()
		}
		// record advances lastStatus WITHOUT a counter sync — what a status poll
		// or a prior domain-scoped clear (e.g. `clear policies counters`) does.
		record := func(rx, tx uint64) {
			t.Helper()
			status := mkStatus(rx, tx)
			m.mu.Lock()
			m.recordHelperStatusLocked(status)
			m.mu.Unlock()
		}

		// First poll seeds the offset with the full cumulative (prev starts at 0).
		poll(100, 80)
		if got := m.bpfShim.ReadUserspaceCounterOffset(rxIdx); got != 100 {
			t.Fatalf("seed rx offset = %d, want 100", got)
		}
		if got := m.bpfShim.ReadUserspaceCounterOffset(txIdx); got != 80 {
			t.Fatalf("seed tx offset = %d, want 80", got)
		}

		// A later status refresh advances lastStatus past prevBindingCounters
		// without a counter sync. This makes the prevBindingCounters rebase
		// observable: the clear must adopt this fresher cumulative (120/90) as the
		// new epoch baseline, not the stale poll-time baseline (100/80).
		record(120, 90)

		// Operator clear-all. Mapless, bpfShim.ClearInterfaceCounters returns a
		// benign "interface_counters map not found"; the offset/baseline
		// invariants under test are unaffected, so tolerate only that error.
		if err := m.ClearAllCounters(); err != nil &&
			!strings.Contains(err.Error(), "interface_counters map not found") {
			t.Fatalf("ClearAllCounters: unexpected error: %v", err)
		}
		if got := m.bpfShim.ReadUserspaceCounterOffset(rxIdx); got != 0 {
			t.Fatalf("rx offset after ClearAllCounters = %d, want 0 "+
				"(cleared total snaps back — #5098 offset reset reverted?)", got)
		}
		if got := m.bpfShim.ReadUserspaceCounterOffset(txIdx); got != 0 {
			t.Fatalf("tx offset after ClearAllCounters = %d, want 0 "+
				"(cleared total snaps back — #5098 offset reset reverted?)", got)
		}

		// A subsequent poll with a HIGHER cumulative advances from zero by the
		// POST-clear delta only. The helper keeps counting from launch, so the
		// cumulative goes 120 -> 150 (a +30 post-clear delta). With the baseline
		// rebased to the cumulative-at-clear (120/90), the offset reads 30/20. If
		// prevBindingCounters were left at the stale poll-time baseline (100/80),
		// the delta would be 50/30 and the cleared counter would jump past its
		// pre-clear value.
		poll(150, 110)
		if got := m.bpfShim.ReadUserspaceCounterOffset(rxIdx); got != 30 {
			t.Fatalf("rx offset after post-clear poll = %d, want 30 "+
				"(delta baseline not rebased — #5098 prevBindingCounters revert?)", got)
		}
		if got := m.bpfShim.ReadUserspaceCounterOffset(txIdx); got != 20 {
			t.Fatalf("tx offset after post-clear poll = %d, want 20 "+
				"(delta baseline not rebased — #5098 prevBindingCounters revert?)", got)
		}
	})
}

// Test_clear_all_counters_offset_atomic_vs_status_poll_5098 is the #5098
// review-fold regression gate for the lock-ordering residual. It proves the
// global-counter offset reset and the delta-baseline rebase inside
// ClearAllCounters run as ONE userspace-m.mu critical section that a concurrent
// status poll cannot interleave with.
//
// Reproduction of the pre-fold hazard: a status poll (statusLoop) holds the
// userspace m.mu across its whole cycle and, near the end,
// syncBPFCountersLocked -> IncrementGlobalCounter accumulates its
// cur-prevBindingCounters delta into the offset map (under the DATAPLANE m.mu).
// Before the fold, ClearAllCounters reset the offset via bpfShim.ClearAllCounters
// OUTSIDE the userspace m.mu, so it could zero the offset AFTER a mid-cycle poll
// had already computed its delta but BEFORE that poll applied it — the poll then
// re-added the delta into the just-zeroed offset, and the baseline rebase did
// not re-zero it, leaving a persistent residual on the cleared totals.
//
// The test drives that exact interleaving deterministically via the
// syncBPFCountersPreIncrementObserver seam: the observer fires while the poll
// still holds the userspace m.mu and has advanced its baseline but not yet
// applied the delta. It launches a concurrent ClearAllCounters there. With the
// fold, that clear parks on the userspace m.mu and only runs (offset reset +
// baseline rebase, atomically) after the poll releases it, so the offset ends at
// 0. Reverting the fold — moving bpfShim.ClearAllCounters back outside the lock —
// lets the residual reappear and fails the final assertion.
func Test_clear_all_counters_offset_atomic_vs_status_poll_5098(t *testing.T) {
	const rxIdx = dataplane.GlobalCtrRxPackets
	m := New()

	mkStatus := func(rx uint64) *ProcessStatus {
		return &ProcessStatus{Bindings: []BindingStatus{{Slot: 0, RXPackets: rx}}}
	}
	// poll runs the REAL syncBPFCountersLocked so the pre-increment seam fires,
	// exactly like the 1/s status poll.
	poll := func(rx uint64) {
		t.Helper()
		status := mkStatus(rx)
		m.mu.Lock()
		m.recordHelperStatusLocked(status)
		m.syncBPFCountersLocked(status)
		m.mu.Unlock()
	}

	// First poll seeds prevBindingCounters=100 and the offset=100.
	poll(100)
	if got := m.bpfShim.ReadUserspaceCounterOffset(rxIdx); got != 100 {
		t.Fatalf("seed rx offset = %d, want 100", got)
	}

	clearDone := make(chan error, 1)
	var once sync.Once
	syncBPFCountersPreIncrementObserver = func() {
		once.Do(func() {
			// Launch the clear while THIS poll still holds the userspace m.mu and
			// is mid-sync (baseline advanced, IncrementGlobalCounter pending).
			go func() { clearDone <- m.ClearAllCounters() }()
			// Give the concurrent clear time to reach its offset reset. Pre-fold
			// that reset lands here (it needs only the dataplane m.mu); post-fold
			// the clear is parked on the userspace m.mu and this sleep is idle.
			time.Sleep(100 * time.Millisecond)
		})
	}
	defer func() { syncBPFCountersPreIncrementObserver = nil }()

	// Second poll: cur=150, prev=100 -> delta=+50. Fires the seam (launching the
	// concurrent clear), then applies IncrementGlobalCounter(rxIdx, 50).
	poll(150)

	if err := <-clearDone; err != nil &&
		!strings.Contains(err.Error(), "interface_counters map not found") {
		t.Fatalf("concurrent ClearAllCounters: unexpected error: %v", err)
	}

	// Atomic offset-reset + baseline-rebase ran entirely after the poll released
	// m.mu, so the cleared offset is 0. A residual here means the clear's Phase-1
	// reset slipped in mid-poll (fold reverted).
	if got := m.bpfShim.ReadUserspaceCounterOffset(rxIdx); got != 0 {
		t.Fatalf("rx offset after concurrent clear = %d, want 0 "+
			"(residual — ClearAllCounters offset/baseline atomicity fold reverted?)", got)
	}
}

// Test_clear_all_counters_concurrent_poll_race_5098 hammers ClearAllCounters
// concurrently with a simulated 1/s status poll under -race. The offset reset
// (dataplane m.mu) and the poll's IncrementGlobalCounter (dataplane m.mu) share
// the dataplane lock, so the pre-fold bug was a lock-ORDERING residual, not a
// data race; this test therefore does not detect the residual on its own (the
// deterministic sibling above does). Its jobs are (1) prove the fold's
// userspace->dataplane lock order never inverts into a deadlock — the test
// completing at all is the proof — and (2) let -race confirm no path touches the
// offset map unsynchronized. The final quiescent clear pins offset==0.
func Test_clear_all_counters_concurrent_poll_race_5098(t *testing.T) {
	const rxIdx = dataplane.GlobalCtrRxPackets
	m := New()

	mkStatus := func(rx uint64) *ProcessStatus {
		return &ProcessStatus{Bindings: []BindingStatus{{Slot: 0, RXPackets: rx}}}
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		var rx uint64
		for {
			select {
			case <-stop:
				return
			default:
			}
			rx += 7
			status := mkStatus(rx)
			m.mu.Lock()
			m.recordHelperStatusLocked(status)
			m.syncBPFCountersLocked(status)
			m.mu.Unlock()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := m.ClearAllCounters(); err != nil &&
				!strings.Contains(err.Error(), "interface_counters map not found") {
				t.Errorf("ClearAllCounters: %v", err)
				return
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	if err := m.ClearAllCounters(); err != nil &&
		!strings.Contains(err.Error(), "interface_counters map not found") {
		t.Fatalf("final ClearAllCounters: %v", err)
	}
	if got := m.bpfShim.ReadUserspaceCounterOffset(rxIdx); got != 0 {
		t.Fatalf("rx offset after final clear = %d, want 0", got)
	}
}

func TestSafeDelta(t *testing.T) {
	// Normal increment
	if d := safeDelta(100, 50); d != 50 {
		t.Fatalf("safeDelta(100, 50) = %d, want 50", d)
	}
	// No change
	if d := safeDelta(50, 50); d != 0 {
		t.Fatalf("safeDelta(50, 50) = %d, want 0", d)
	}
	// Counter reset (prev > cur) — return cur as delta
	if d := safeDelta(10, 100); d != 10 {
		t.Fatalf("safeDelta(10, 100) = %d, want 10 (counter reset)", d)
	}
	// First poll (prev=0)
	if d := safeDelta(42, 0); d != 42 {
		t.Fatalf("safeDelta(42, 0) = %d, want 42", d)
	}
}

func TestBindingStatusDecodesNamedPreL3Keys10498(t *testing.T) {
	var got BindingStatus
	err := json.Unmarshal([]byte(`{
		"umem_slice_dropped": 1,
		"unknown_vlan_dropped": 2,
		"dst_mac_dropped": 3
	}`), &got)
	if err != nil {
		t.Fatalf("decode BindingStatus: %v", err)
	}
	if got.UMEMSliceDropped != 1 || got.UnknownVLANDropped != 2 || got.DstMACDropped != 3 {
		t.Fatalf(
			"named pre-L3 fields = (%d, %d, %d), want (1, 2, 3)",
			got.UMEMSliceDropped,
			got.UnknownVLANDropped,
			got.DstMACDropped,
		)
	}
}
