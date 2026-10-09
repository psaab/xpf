package userspace

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

func TestManagerReadContinuationRefusesAfterUnknownTransition12072(t *testing.T) {
	m, controlSock := newReadOnlyManager10512(t)
	expectedCfg := &config.Config{}
	m.appliedSnapshot.Config = expectedCfg
	newCfg := &config.Config{}
	applyRec := &applyRecorder9520{replies: []error{errLostResponse9520}}
	m.controlRequestHook = applyRec.hook
	ln, err := net.Listen("unix", controlSock)
	if err != nil {
		t.Fatalf("listen controlled READ fake: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	firstPageRead := make(chan struct{})
	firstPageSent := make(chan struct{})
	releaseFirstPage := make(chan struct{})
	pageMatches := make([]SessionPolicyMatch, 32768)
	for i := range pageMatches {
		pageMatches[i] = readMatch10512(1, 100007, uint64(i+1))
	}
	var requestsMu sync.Mutex
	var requests []SessionPolicyListRequest
	serverErr := make(chan error, 1)
	go func() {
		for page := 0; ; page++ {
			conn, err := ln.Accept()
			if err != nil {
				if page == 0 {
					serverErr <- err
				}
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				_ = conn.Close()
				serverErr <- err
				return
			}
			if req.SessionPolicyList == nil {
				_ = conn.Close()
				serverErr <- errors.New("received non-LIST request")
				return
			}
			requestsMu.Lock()
			requests = append(requests, *req.SessionPolicyList)
			requestsMu.Unlock()
			var resp ControlResponse
			if page == 0 {
				close(firstPageRead)
				<-releaseFirstPage
				resp = ControlResponse{
					OK: true, SessionPolicyMatches: pageMatches,
					SessionPolicyContinuation: "next",
				}
			} else {
				resp = ControlResponse{OK: true, SessionPolicyComplete: true}
			}
			encodeErr := json.NewEncoder(conn).Encode(resp)
			_ = conn.Close()
			if encodeErr != nil {
				serverErr <- encodeErr
				return
			}
			if page == 0 {
				close(firstPageSent)
			}
		}
	}()

	type readResult struct {
		resp ControlResponse
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		resp, err := m.ListSessionsByPolicy(SessionPolicyListRequest{
			PolicyIDs: []uint32{1}, Mode: "prepublish", ExpectedConfig: expectedCfg,
		})
		readDone <- readResult{resp: resp, err: err}
	}()
	select {
	case <-firstPageRead:
	case err := <-serverErr:
		t.Fatalf("first LIST request: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("helper did not receive first LIST page")
	}

	// Lose the response to a real apply_snapshot while the first page is being
	// aggregated outside Manager.mu. This establishes the unknown-outcome marker
	// between page one and the continuation page's authority check.
	close(releaseFirstPage)
	select {
	case <-firstPageSent:
	case err := <-serverErr:
		t.Fatalf("first LIST response: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("helper did not finish the first LIST page")
	}
	snap := ConfigSnapshot{Version: ProtocolVersion, Generation: 1, Config: newCfg}
	m.mu.Lock()
	applyErr := m.requestApplySnapshotLocked(&snap, nil)
	unknown, appliedCfg := m.applySnapshotOutcomeUnknown, m.appliedSnapshot.Config
	m.mu.Unlock()
	if applyErr == nil || !unknown {
		t.Fatalf("premise: lost apply response must leave publication outcome unknown (err=%v unknown=%v)",
			applyErr, unknown)
	}
	if appliedCfg != expectedCfg {
		t.Fatalf("apply outcome changed the last known config to %p, want preserved %p", appliedCfg, expectedCfg)
	}
	if len(applyRec.sent) != 1 || applyRec.sent[0].Config != newCfg {
		t.Fatalf("apply attempts = %+v, want one publish of the replacement config", applyRec.sent)
	}
	select {
	case result := <-readDone:
		if result.err == nil {
			requestsMu.Lock()
			got := len(requests)
			requestsMu.Unlock()
			m.mu.Lock()
			unknown := m.applySnapshotOutcomeUnknown
			m.mu.Unlock()
			t.Fatalf("continuation LIST returned success after unknown transition (unknown=%v requests=%d)",
				unknown, got)
		}
		if !errors.Is(result.err, ErrPolicyReadAuthority) {
			t.Fatalf("continuation refusal error = %v, want ErrPolicyReadAuthority", result.err)
		}
		if len(result.resp.SessionPolicyMatches) != 0 {
			t.Fatalf("refused continuation returned %d partial matches, want none", len(result.resp.SessionPolicyMatches))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("paged LIST did not finish after the authority transition")
	}
	requestsMu.Lock()
	gotRequests := len(requests)
	requestsMu.Unlock()
	if gotRequests != 1 {
		t.Fatalf("helper received %d LIST requests, want only page one after authority became unknown", gotRequests)
	}
	select {
	case err := <-serverErr:
		t.Fatalf("controlled LIST fake: %v", err)
	default:
	}
}

func TestDeletePolicySessionsSettledMixedOutcomes12072(t *testing.T) {
	m, sessionSock := newBatchTestManager10512(t)
	first := batchOK10512(policyDeleteBatchMatches)
	first.PolicyDeleteOutcomes[1] = "stale_forward"
	first.PolicyDeleteOutcomes[2] = "refused_identity"
	first.PolicyDeleteOutcomes[3] = "partial_companion"
	fail := ControlResponse{OK: false, Error: "injected semantic batch refusal"}
	fake := startScriptedBatchSocket10512(t, sessionSock, []ControlResponse{
		first, fail, batchOK10512(policyDeleteBatchMatches), fail, fail, fail,
	})
	matches := make([]SessionPolicyMatch, policyDeleteBatchMatches*7+1)
	for i := range matches {
		matches[i] = policyDeleteTestMatch10512(uint64(i + 1))
	}

	result, err := m.DeletePolicySessions(matches)
	if err == nil {
		t.Fatal("mixed refused/semantic outcomes must surface an incomplete-batch error")
	}
	if result.Applied != 126 || result.Stale != 1 || result.Partial != 1 || result.Refused != 1 {
		t.Fatalf("mixed result counters = %+v, want applied/stale/partial/refused = 126/1/1/1", result)
	}
	if got := fake.requestCount(); got != 6 {
		t.Fatalf("batch requests = %d, want 6 (stop before the unprocessed seventh batch)", got)
	}
	if result.RefusedSessionIDs == nil || len(result.RefusedSessionIDs) != 1 ||
		result.RefusedSessionIDs[0] != matches[2].ExpectedRTFlowSessionID {
		t.Fatalf("refused identities = %v, want only input index 2's live identity", result.RefusedSessionIDs)
	}
	if result.SettledPrefix != 2 {
		t.Fatalf("SettledPrefix = %d, want 2 (applied and stale rows before refusal)", result.SettledPrefix)
	}
	if len(result.SettledBeyondPrefix) != 125 {
		t.Fatalf("SettledBeyondPrefix = %v, want 125 resolved indexes", result.SettledBeyondPrefix)
	}
	for i, got := range result.SettledBeyondPrefix {
		var want int
		if i < 61 {
			want = i + 3
		} else {
			want = 128 + i - 61
		}
		if got != want {
			t.Fatalf("SettledBeyondPrefix[%d] = %d, want ascending resolved input index %d", i, got, want)
		}
	}

	allOKManager, allOKSock := newBatchTestManager10512(t)
	startScriptedBatchSocket10512(t, allOKSock, []ControlResponse{batchOK10512(3)})
	allOK, err := allOKManager.DeletePolicySessions([]SessionPolicyMatch{
		policyDeleteTestMatch10512(1001), policyDeleteTestMatch10512(1002), policyDeleteTestMatch10512(1003),
	})
	if err != nil {
		t.Fatalf("all-success batch: %v", err)
	}
	if allOK.SettledPrefix != 3 {
		t.Fatalf("all-success SettledPrefix = %d, want 3", allOK.SettledPrefix)
	}
	if allOK.SettledBeyondPrefix != nil {
		t.Fatalf("all-success SettledBeyondPrefix = %v, want nil", allOK.SettledBeyondPrefix)
	}
}

func TestPolicyDeleteSettledTrackingNoAllocationOnFullSuccess12072(t *testing.T) {
	var result PolicyDeleteResult
	allocs := testing.AllocsPerRun(100, func() {
		result = PolicyDeleteResult{}
		for i := range policyDeleteBatchMatches {
			recordPolicyDeleteSettled(&result, i)
		}
	})
	if allocs != 0 {
		t.Fatalf("all-success settlement tracking allocated %.2f times per run, want 0", allocs)
	}
	if result.SettledPrefix != policyDeleteBatchMatches || result.SettledBeyondPrefix != nil {
		t.Fatalf("all-success settlement = prefix:%d beyond:%v, want prefix:%d beyond:nil",
			result.SettledPrefix, result.SettledBeyondPrefix, policyDeleteBatchMatches)
	}
}

func TestDeferredPolicySnapshotAuthorityRefusalBlocksStatusPublish12072(t *testing.T) {
	oldInterval := statusLoopInterval
	statusLoopInterval = 10 * time.Millisecond
	t.Cleanup(func() { statusLoopInterval = oldInterval })

	m, _ := seamedManager(t)
	m.proc = selfProc(t)
	const generation = uint64(7)
	m.lastSnapshot = &ConfigSnapshot{
		Version: ProtocolVersion, Generation: generation, Config: &config.Config{},
	}
	m.generation = generation
	m.publishedSnapshot = generation - 1
	m.pendingFullSnapshotMetadata = true
	m.lastStatus = ProcessStatus{
		ConfigSnapshotProtocolVersion: ProtocolVersion,
		LastSnapshotGeneration:        generation - 1,
	}
	m.helperStatusObserved = true

	prepublish := make(chan uint64, 1)
	applyRequests := make(chan ControlRequest, 1)
	m.SetPolicySnapshotPrePublisher(func(got uint64) error {
		select {
		case prepublish <- got:
		default:
		}
		return ErrPolicyReadAuthority
	})
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "status" && status != nil {
			reply := readyHelperStatus()
			reply.ConfigSnapshotProtocolVersion = ProtocolVersion
			reply.LastSnapshotGeneration = generation - 1
			*status = *reply
		}
		if req.Type == "apply_snapshot" {
			applyRequests <- req
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-loopDone
	})
	go func() {
		m.statusLoop(ctx)
		close(loopDone)
	}()
	select {
	case got := <-prepublish:
		if got != generation {
			t.Fatalf("deferred pre-publisher generation = %d, want %d", got, generation)
		}
	case <-time.After(2 * time.Second):
		cancel()
		<-loopDone
		t.Fatal("status loop did not invoke the deferred policy pre-publisher")
	}
	cancel()
	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("status loop did not stop after cancellation")
	}
	select {
	case req := <-applyRequests:
		t.Fatalf("status loop published snapshot after authority refusal: %+v", req.Snapshot)
	default:
	}
	m.mu.Lock()
	pending, published := m.pendingFullSnapshotMetadata, m.publishedSnapshot
	m.mu.Unlock()
	if !pending || published != generation-1 {
		t.Fatalf("deferred state after authority refusal = pending:%v published:%d, want pending:true published:%d",
			pending, published, generation-1)
	}
}
