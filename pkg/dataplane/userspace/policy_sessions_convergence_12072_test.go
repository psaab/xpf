package userspace

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
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
func TestDeferredLostACKRecoveryReplaysStampedGenerationWithoutFreshCapture12072(t *testing.T) {
	m, _ := seamedManager(t)
	m.proc = selfProc(t)
	m.syncCancel = func() {} // prevent the retry owner goroutine; this test drives its exact calls.
	const generation = uint64(7)
	oldCfg, targetCfg := &config.Config{}, &config.Config{}
	m.appliedSnapshot = appliedSnapshot{Config: oldCfg, Generation: generation - 1}
	m.lastSnapshot = &ConfigSnapshot{
		Version: ProtocolVersion, Generation: generation, Config: targetCfg,
	}
	m.generation = generation
	m.publishedSnapshot = generation - 1
	m.pendingFullSnapshotMetadata = true
	m.lastStatus = ProcessStatus{
		ConfigSnapshotProtocolVersion: ProtocolVersion,
		LastSnapshotGeneration:        generation - 1,
	}
	m.helperStatusObserved = true

	ancestry := []PolicyRenameAncestry{{SourceRuleID: "old", DestinationRuleID: "new"}}
	rebinds := []PolicySessionRebind{{
		Family: "ipv4", SrcIP: "192.0.2.1", DstIP: "198.51.100.1",
		Protocol: 6, PolicyID: 3, RuleID: "new",
	}}
	captureCalls := 0
	m.SetPolicySnapshotPrePublisher(func(got uint64) error {
		captureCalls++
		if got != generation || !m.SetDeferredPolicyRenameMetadata(got, ancestry, rebinds) {
			return errors.New("failed to stamp the retained generation")
		}
		return nil
	})
	var sent []ConfigSnapshot
	first := true
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type != "apply_snapshot" {
			return nil
		}
		snapshot := *req.Snapshot
		snapshot.PolicyRenameAncestry = append([]PolicyRenameAncestry(nil), snapshot.PolicyRenameAncestry...)
		snapshot.PolicySessionRebinds = append([]PolicySessionRebind(nil), snapshot.PolicySessionRebinds...)
		sent = append(sent, snapshot)
		if first {
			first = false
			return errLostResponse9520
		}
		if status != nil {
			reply := readyHelperStatus()
			reply.ConfigSnapshotProtocolVersion = ProtocolVersion
			reply.LastSnapshotGeneration = req.Snapshot.Generation
			reply.LastFIBGeneration = req.Snapshot.FIBGeneration
			*status = *reply
		}
		return nil
	}

	m.mu.Lock()
	prepared := m.prepareDeferredPolicySnapshotLocked()
	m.mu.Unlock()
	if !prepared || captureCalls != 1 || m.policySnapshotPrepublishGeneration != generation {
		t.Fatalf("initial deferred capture = prepared:%v calls:%d capturedGeneration:%d",
			prepared, captureCalls, m.policySnapshotPrepublishGeneration)
	}
	m.mu.Lock()
	err := m.syncSnapshotLocked()
	unknown, pending := m.applySnapshotOutcomeUnknown, m.pendingFullSnapshotMetadata
	m.mu.Unlock()
	policyAuthority := m.PolicyReadConfig()
	if err == nil || !unknown || !pending || policyAuthority != nil || len(sent) != 1 {
		t.Fatalf("lost-ACK state = err:%v unknown:%v pending:%v authority:%p sends:%d",
			err, unknown, pending, policyAuthority, len(sent))
	}

	// The status-loop retry must reuse this exact snapshot's successful capture;
	// the unknown outcome is resolved only by the second apply_snapshot ACK.
	m.mu.Lock()
	prepared = m.prepareDeferredPolicySnapshotLocked()
	m.mu.Unlock()
	if !prepared || captureCalls != 1 {
		t.Fatalf("stamped unknown recovery re-captured policy IDs: prepared:%v captureCalls:%d",
			prepared, captureCalls)
	}
	m.mu.Lock()
	err = m.syncSnapshotLocked()
	unknown, pending = m.applySnapshotOutcomeUnknown, m.pendingFullSnapshotMetadata
	m.mu.Unlock()
	policyAuthority = m.PolicyReadConfig()
	if err != nil || unknown || pending || policyAuthority != targetCfg || len(sent) != 2 {
		t.Fatalf("recovery = err:%v unknown:%v pending:%v authority:%p sends:%d",
			err, unknown, pending, policyAuthority, len(sent))
	}
	for i, snapshot := range sent {
		if snapshot.Generation != generation ||
			len(snapshot.PolicyRenameAncestry) != 1 ||
			snapshot.PolicyRenameAncestry[0] != ancestry[0] ||
			len(snapshot.PolicySessionRebinds) != 1 ||
			snapshot.PolicySessionRebinds[0] != rebinds[0] {
			t.Fatalf("send %d did not preserve the identity-stamped generation %d: %+v",
				i+1, generation, snapshot)
		}
	}
}

func deferredPolicyRecoveryFixture12072(
	t *testing.T,
) (*fixture9824, *config.Config, []PolicyRenameAncestry, []PolicySessionRebind) {
	t.Helper()
	f := newFixture9824(t)
	oldCfg := &config.Config{}
	f.cfg = oldCfg
	zones := baseZones9824()
	neighbors := []NeighborSnapshot{neighbor9824(7, "10.0.0.2", "02:00:00:00:00:01")}
	fabrics := []FabricSnapshot{fabricAlpha9824()}
	old := f.seedPublished(t, 6, zones, neighbors, fabrics)

	targetCfg := &config.Config{}
	f.cfg = targetCfg
	target := f.snap9824(7, zones, neighbors, fabrics)
	target.Policies = []PolicyRuleSnapshot{{
		PolicyID: 2, Name: "web", FromZone: "trust", ToZone: "untrust", Action: "permit",
	}}
	target.PolicyRematchExtensive = true
	ancestry := []PolicyRenameAncestry{{
		SourceRuleID: "old", DestinationRuleID: "new",
		SourceFromZone: "trust", SourceToZone: "untrust",
	}}
	rebinds := []PolicySessionRebind{{
		Family: "ipv4", SrcIP: "192.0.2.1", DstIP: "198.51.100.1",
		Protocol: 6, PolicyID: 2, RuleID: "new", IngressZone: 1, EgressZone: 2,
	}}
	m := f.m
	m.mu.Lock()
	m.lastSnapshot = target
	m.generation = 7
	m.publishedSnapshot = 6
	m.publishedPlanKey = snapshotBindingPlanKey(old)
	m.pendingFullSnapshotMetadata = true
	m.appliedSnapshot = appliedSnapshot{Config: oldCfg, Generation: 6}
	m.lastStatus = ProcessStatus{
		ConfigSnapshotProtocolVersion: ProtocolVersion,
		LastSnapshotGeneration:        6,
	}
	m.helperStatusObserved = true
	m.mu.Unlock()
	return f, targetCfg, ancestry, rebinds
}
func servePolicyList12072(t *testing.T, m *Manager) <-chan SessionPolicyListRequest {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen policy READ fixture: %v", err)
	}
	m.cfg.ControlSocket = socket
	requests := make(chan SessionPolicyListRequest, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err != nil {
				t.Errorf("decode policy READ request: %v", err)
				_ = conn.Close()
				continue
			}
			if req.Type != "list_sessions_by_policy" || req.SessionPolicyList == nil {
				t.Errorf("unexpected policy READ request: %+v", req)
				_ = conn.Close()
				continue
			}
			requests <- *req.SessionPolicyList
			err = json.NewEncoder(conn).Encode(ControlResponse{
				OK: true, SessionPolicyComplete: true,
			})
			_ = conn.Close()
			if err != nil {
				t.Errorf("encode policy READ response: %v", err)
			}
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return requests
}

func readDeferredPolicyMetadata12072(
	m *Manager, generation uint64, ancestry []PolicyRenameAncestry, rebinds []PolicySessionRebind,
) error {
	expected := m.PolicyReadConfig()
	if expected == nil {
		return ErrPolicyReadAuthority
	}
	if _, err := m.ListSessionsByPolicy(SessionPolicyListRequest{
		PolicyIDs: []uint32{2}, Mode: "prepublish", ExpectedConfig: expected,
	}); err != nil {
		return err
	}
	if !m.SetDeferredPolicyRenameMetadata(generation, ancestry, rebinds) {
		return errors.New("retained generation changed during prepublish capture")
	}
	return nil
}

func assertInitialDeferredPolicyList12072(t *testing.T, requests <-chan SessionPolicyListRequest) {
	t.Helper()
	select {
	case request := <-requests:
		if request.Mode != "prepublish" || len(request.PolicyIDs) != 1 || request.PolicyIDs[0] != 2 {
			t.Fatalf("initial policy READ request = %+v, want prepublish for policy ID 2", request)
		}
	default:
		t.Fatal("initial deferred capture did not issue a positional policy READ")
	}
}

func requireNoDeferredPolicyList12072(t *testing.T, requests <-chan SessionPolicyListRequest) {
	t.Helper()
	select {
	case request := <-requests:
		t.Fatalf("unexpected positional READ after first capture: %+v", request)
	default:
	}
}

func TestDeferredPolicyRecoveryPreservesProofAcrossPartialUpdates12072(t *testing.T) {
	for _, partial := range []string{"neighbor", "fabric", "fib"} {
		t.Run(partial, func(t *testing.T) {
			f, targetCfg, ancestry, rebinds := deferredPolicyRecoveryFixture12072(t)
			m := f.m
			listRequests := servePolicyList12072(t, m)
			captureCalls := 0
			m.SetPolicySnapshotPrePublisher(func(generation uint64) error {
				captureCalls++
				return readDeferredPolicyMetadata12072(m, generation, ancestry, rebinds)
			})
			f.model.scriptDrops(1)

			m.mu.Lock()
			prepared := m.prepareDeferredPolicySnapshotLocked()
			err := m.syncSnapshotLocked()
			unknown := m.applySnapshotOutcomeUnknown
			m.mu.Unlock()
			if !prepared || err == nil || !unknown || captureCalls != 1 || len(listRequests) != 1 {
				t.Fatalf("lost-ACK setup = prepared:%v err:%v unknown:%v capture:%d list:%d",
					prepared, err, unknown, captureCalls, len(listRequests))
			}
			assertInitialDeferredPolicyList12072(t, listRequests)

			switch partial {
			case "neighbor":
				f.neighborFunc = func(*config.Config) []NeighborSnapshot {
					return []NeighborSnapshot{neighbor9824(7, "10.0.0.2", "02:00:00:00:00:02")}
				}
				m.RegenerateNeighborSnapshot()
			case "fabric":
				f.fabricFunc = func(*config.Config) []FabricSnapshot {
					return []FabricSnapshot{fabricBeta9824()}
				}
				m.SyncFabricState()
			case "fib":
				f.neighborFunc = func(*config.Config) []NeighborSnapshot {
					return append([]NeighborSnapshot(nil), m.lastSnapshot.Neighbors...)
				}
				_, _ = m.BumpFIBGeneration()
			}
			m.mu.Lock()
			generation := m.lastSnapshot.Generation
			stampedGeneration := m.policySnapshotPrepublishGeneration
			stampedIdentity := m.policySnapshotPrepublishIdentity
			currentIdentity, identityOK := policySnapshotIdentity(m.lastSnapshot)
			m.mu.Unlock()
			if generation != 8 || stampedGeneration != 7 || !identityOK ||
				currentIdentity != stampedIdentity {
				t.Fatalf("partial %s changed proof identity: generation=%d stamp=%d identityOK=%v equal=%v",
					partial, generation, stampedGeneration, identityOK, currentIdentity == stampedIdentity)
			}

			m.mu.Lock()
			prepared = m.prepareDeferredPolicySnapshotLocked()
			err = m.syncSnapshotLocked()
			unknown, pending, published := m.applySnapshotOutcomeUnknown,
				m.pendingFullSnapshotMetadata, m.publishedSnapshot
			m.mu.Unlock()
			if !prepared || err != nil || unknown || pending || published != generation ||
				captureCalls != 1 {
				t.Fatalf("recovery after %s = prepared:%v err:%v unknown:%v pending:%v "+
					"published:%d capture:%d",
					partial, prepared, err, unknown, pending, published, captureCalls)
			}
			requireNoDeferredPolicyList12072(t, listRequests)
			if got := m.PolicyReadConfig(); got != targetCfg {
				t.Fatalf("recovered policy authority = %p, want target %p", got, targetCfg)
			}
			if !f.ctrl.haveStored || f.ctrl.stored.Enabled != 1 {
				t.Fatalf("successful recovery left userspace ctrl disabled: %+v", f.ctrl)
			}
		})
	}
}

func TestDeferredPolicyRecoveryRejectsChangedPolicyOrRenameIdentity12072(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ConfigSnapshot)
	}{
		{"policy", func(s *ConfigSnapshot) { s.Policies[0].Action = "deny" }},
		{"rename", func(s *ConfigSnapshot) {
			s.PolicyRenameAncestry[0].DestinationRuleID = "replacement"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, ancestry, rebinds := deferredPolicyRecoveryFixture12072(t)
			m := f.m
			listRequests := servePolicyList12072(t, m)
			captureCalls := 0
			m.SetPolicySnapshotPrePublisher(func(generation uint64) error {
				captureCalls++
				return readDeferredPolicyMetadata12072(m, generation, ancestry, rebinds)
			})
			f.model.scriptDrops(1)
			m.mu.Lock()
			initialPrepared := m.prepareDeferredPolicySnapshotLocked()
			err := m.syncSnapshotLocked()
			invalidatePolicySnapshotIdentity(m.lastSnapshot)
			tc.mutate(m.lastSnapshot)
			applyCount := f.model.countVerb("apply_snapshot")
			recoveryPrepared := m.prepareDeferredPolicySnapshotLocked()
			applyCountAfter := f.model.countVerb("apply_snapshot")
			unknown := m.applySnapshotOutcomeUnknown
			m.mu.Unlock()
			if !initialPrepared || err == nil || !unknown || applyCount != 1 ||
				recoveryPrepared || applyCountAfter != 1 || captureCalls != 2 ||
				len(listRequests) != 1 {
				t.Fatalf("changed %s identity recovery = prepared:%v→%v err:%v unknown:%v "+
					"applySnapshots:%d→%d capture:%d list:%d",
					tc.name, initialPrepared, recoveryPrepared, err, unknown, applyCount,
					applyCountAfter, captureCalls, len(listRequests))
			}
			assertInitialDeferredPolicyList12072(t, listRequests)
			requireNoDeferredPolicyList12072(t, listRequests)
		})
	}
}
func TestDeferredPolicyRenameRefreshInvalidatesStampedIdentity12072(t *testing.T) {
	f, _, ancestry, rebinds := deferredPolicyRecoveryFixture12072(t)
	m := f.m
	captureCalls := 0
	m.SetPolicySnapshotPrePublisher(func(uint64) error {
		captureCalls++
		return nil
	})
	f.model.scriptDrops(1)
	m.mu.Lock()
	prepared := m.prepareDeferredPolicySnapshotLocked()
	err := m.syncSnapshotLocked()
	initialUnknown := m.applySnapshotOutcomeUnknown
	stampedGeneration := m.policySnapshotPrepublishGeneration
	stampedIdentity := m.policySnapshotPrepublishIdentity
	generation := m.lastSnapshot.Generation
	m.mu.Unlock()
	if !prepared || err == nil || !initialUnknown || captureCalls != 1 ||
		stampedGeneration != generation {
		t.Fatalf("lost-ACK setup: prepared=%v err=%v unknown=%v capture=%d stamp=%d generation=%d",
			prepared, err, initialUnknown, captureCalls, stampedGeneration, generation)
	}

	updatedAncestry := append([]PolicyRenameAncestry(nil), ancestry...)
	updatedAncestry[0].DestinationRuleID = "replacement"
	if !m.SetDeferredPolicyRenameMetadata(generation, updatedAncestry, rebinds) {
		t.Fatal("deferred rename metadata refresh rejected the retained generation")
	}
	m.mu.Lock()
	prepared = m.prepareDeferredPolicySnapshotLocked()
	unknown := m.applySnapshotOutcomeUnknown
	updatedIdentity := m.policySnapshotPrepublishIdentity
	m.mu.Unlock()
	if !prepared || !unknown || captureCalls != 2 || updatedIdentity == stampedIdentity {
		t.Fatalf("rename refresh reused stale recovery proof: prepared=%v unknown=%v captures=%d identityChanged=%v",
			prepared, unknown, captureCalls, updatedIdentity != stampedIdentity)
	}
}

func TestStripSingleUseCommitMetadataInvalidatesCachedIdentity12072(t *testing.T) {
	f, _, ancestry, rebinds := deferredPolicyRecoveryFixture12072(t)
	next := *f.m.lastSnapshot
	next.PolicyRenameAncestry = append([]PolicyRenameAncestry(nil), ancestry...)
	next.PolicySessionRebinds = append([]PolicySessionRebind(nil), rebinds...)
	before, ok := policySnapshotIdentity(&next)
	if !ok {
		t.Fatal("could not cache identity before stripping single-use metadata")
	}

	stripSingleUseCommitMetadata(&next)
	after, ok := policySnapshotIdentity(&next)
	if !ok || after == before || len(next.PolicyRenameAncestry) != 0 ||
		len(next.PolicySessionRebinds) != 0 {
		t.Fatalf("stripping single-use metadata left stale identity: ok=%v identityChanged=%v ancestry=%d rebinds=%d",
			ok, after != before, len(next.PolicyRenameAncestry), len(next.PolicySessionRebinds))
	}
}

func TestDeferredPolicyRecoveryInvalidatesProofAfterScheduledPartial12072(t *testing.T) {
	f, targetCfg, ancestry, rebinds := deferredPolicyRecoveryFixture12072(t)
	m := f.m
	listRequests := servePolicyList12072(t, m)
	captureCalls := 0
	m.SetPolicySnapshotPrePublisher(func(generation uint64) error {
		captureCalls++
		return readDeferredPolicyMetadata12072(m, generation, ancestry, rebinds)
	})
	f.model.scriptDrops(1)
	m.mu.Lock()
	initialPrepared := m.prepareDeferredPolicySnapshotLocked()
	initialErr := m.syncSnapshotLocked()
	initialUnknown := m.applySnapshotOutcomeUnknown
	stampedIdentity := m.policySnapshotPrepublishIdentity
	m.mu.Unlock()
	if !initialPrepared || initialErr == nil || !initialUnknown || captureCalls != 1 {
		t.Fatalf("lost-ACK setup = prepared:%v err:%v unknown:%v capture:%d",
			initialPrepared, initialErr, initialUnknown, captureCalls)
	}

	assertInitialDeferredPolicyList12072(t, listRequests)

	if err := m.UpdatePolicyScheduleState(targetCfg, map[string]bool{}); err != nil {
		t.Fatalf("scheduled partial update: %v", err)
	}
	m.mu.Lock()
	updatedIdentity, identityOK := policySnapshotIdentity(m.lastSnapshot)
	if !identityOK || updatedIdentity == stampedIdentity {
		m.mu.Unlock()
		t.Fatalf("scheduled partial retained stale proof identity: ok=%v equal=%v",
			identityOK, updatedIdentity == stampedIdentity)
	}
	m.lastSnapshot.Generation++
	m.generation = m.lastSnapshot.Generation
	m.publishedSnapshot = m.lastSnapshot.Generation - 1
	m.pendingFullSnapshotMetadata = true
	m.applySnapshotOutcomeUnknown = true
	prepared := m.prepareDeferredPolicySnapshotLocked()
	unknown := m.applySnapshotOutcomeUnknown
	m.mu.Unlock()
	if prepared || !unknown || captureCalls != 2 || len(listRequests) != 0 {
		t.Fatalf("recovery reused pre-scheduler proof: prepared:%v unknown:%v capture:%d list:%d",
			prepared, unknown, captureCalls, len(listRequests))
	}
	requireNoDeferredPolicyList12072(t, listRequests)
}
