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
)

// scriptedBatchSocket10512 answers session-socket batch requests from a
// per-request script (index-matched in arrival order). Past the script it
// fails loud (a test bug) rather than silently passing.
type scriptedBatchSocket10512 struct {
	ln     net.Listener
	mu     sync.Mutex
	seen   []ControlRequest
	script []ControlResponse
}

func startScriptedBatchSocket10512(t *testing.T, sockPath string, script []ControlResponse) *scriptedBatchSocket10512 {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen helper session socket: %v", err)
	}
	f := &scriptedBatchSocket10512{ln: ln, script: script}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				f.mu.Lock()
				index := len(f.seen)
				f.seen = append(f.seen, req)
				var resp ControlResponse
				if index < len(f.script) {
					resp = f.script[index]
				} else {
					resp = ControlResponse{OK: false, Error: "script exhausted (test bug)"}
				}
				f.mu.Unlock()
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	return f
}

func (f *scriptedBatchSocket10512) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func newBatchTestManager10512(t *testing.T) (*Manager, string) {
	t.Helper()
	// Short tmpdir prefix keeps the AF_UNIX path under sun_path limits.
	dir, err := os.MkdirTemp("", "x10512")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	return m, filepath.Join(dir, "userspace-dp-sessions.sock")
}

func policyDeleteTestMatch10512(seq uint64) SessionPolicyMatch {
	return SessionPolicyMatch{
		AddrFamily:    4,
		RoutingDomain: 0,
		Tuple: SessionPolicyTuple{
			AddrFamily: 4,
			Protocol:   6,
			SrcIP:      "10.0.0.1",
			DstIP:      "10.0.0.2",
			SrcPort:    10000 + uint16(seq%50000),
			DstPort:    443,
		},
		PolicyID:                7,
		ExpectedRTFlowSessionID: seq,
	}
}

func batchOK10512(n int) ControlResponse {
	outcomes := make([]string, n)
	for i := range outcomes {
		outcomes[i] = "applied"
	}
	return ControlResponse{OK: true, PolicyDeleteOutcomes: outcomes, PolicyDeleteComplete: true}
}

// Success/failure/success across three micro-batches: the failed middle
// batch's matches must stay in the persistent gap even after the trailing
// batch succeeds — a later success must never jump the confirmed count over
// an earlier failed range (which would report 0 unconfirmed for matches with
// no confirmed outcome at all).
func TestDeletePolicySessionsGapSpansFailedBatch10512(t *testing.T) {
	m, sessionSock := newBatchTestManager10512(t)
	fake := startScriptedBatchSocket10512(t, sessionSock, []ControlResponse{
		batchOK10512(64),
		{OK: false, Error: "injected batch failure"},
		batchOK10512(2),
	})
	matches := make([]SessionPolicyMatch, 0, 130)
	for seq := uint64(1); seq <= 130; seq++ {
		matches = append(matches, policyDeleteTestMatch10512(seq))
	}
	result, err := m.DeletePolicySessions(matches)
	if err == nil {
		t.Fatal("a failed middle batch must surface a gap error, got nil")
	}
	if !strings.Contains(err.Error(), "INCOMPLETE") {
		t.Errorf("gap error must be labeled INCOMPLETE, got: %v", err)
	}
	if !strings.Contains(err.Error(), "injected batch failure") {
		t.Errorf("gap error must preserve the first batch failure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "64 without confirmed outcomes") {
		t.Errorf("gap must span exactly the failed batch's 64 matches, got: %v", err)
	}
	if result.Applied != 66 || result.Stale != 0 || result.Partial != 0 {
		t.Errorf("result = %+v, want {Applied:66 Stale:0 Partial:0}", result)
	}
	if got := fake.requestCount(); got != 3 {
		t.Errorf("request count = %d, want 3 (failed batch continues to the next, with no semantic retry)", got)
	}
	// Batch identities: content digests differ per batch (different matches),
	// operation IDs differ per attempt.
	seen := fake.seen
	if len(seen) != 3 {
		t.Fatalf("recorded %d requests, want 3", len(seen))
	}
	mutations := map[string]bool{}
	operations := map[string]bool{}
	for i, req := range seen {
		if req.SessionSync == nil || req.SessionSync.Operation != "mirror_delete_policy_batch" {
			t.Fatalf("request %d is not a policy batch: %+v", i, req.SessionSync)
		}
		mutations[req.SessionSync.MutationID] = true
		operations[req.SessionSync.OperationID] = true
		if !strings.HasPrefix(req.SessionSync.MutationID, "pb:") {
			t.Errorf("request %d MutationID = %q, want pb:-prefixed digest", i, req.SessionSync.MutationID)
		}
	}
	if len(mutations) != 3 {
		t.Errorf("MutationIDs are not content-distinct across batches: %v", mutations)
	}
	if len(operations) != 3 {
		t.Errorf("OperationIDs are not distinct per attempt: %v", operations)
	}
}

// Three consecutive semantic failures stop the driver fast instead of burning
// the deadline batch by batch; the fourth batch is never issued.
func TestDeletePolicySessionsSemanticBreakerStops10512(t *testing.T) {
	m, sessionSock := newBatchTestManager10512(t)
	fail := ControlResponse{OK: false, Error: "injected sustained failure"}
	fake := startScriptedBatchSocket10512(t, sessionSock, []ControlResponse{fail, fail, fail, fail})
	matches := make([]SessionPolicyMatch, 0, 193)
	for seq := uint64(1); seq <= 193; seq++ {
		matches = append(matches, policyDeleteTestMatch10512(seq))
	}
	result, err := m.DeletePolicySessions(matches)
	if err == nil {
		t.Fatal("sustained batch failures must surface a gap error, got nil")
	}
	if got := fake.requestCount(); got != 3 {
		t.Errorf("request count = %d, want 3 (breaker trips, fourth batch never issued)", got)
	}
	if !strings.Contains(err.Error(), "193 without confirmed outcomes") {
		t.Errorf("gap must span all 193 unconfirmed matches, got: %v", err)
	}
	if result.Applied != 0 || result.Stale != 0 || result.Partial != 0 {
		t.Errorf("result = %+v, want zero counts", result)
	}
}

// The batch mutation digest is a stable function of ordered content: same
// batch → same ID (retries/re-sends reconcile); any content or order change →
// a different ID (never falsely reconciled).
func TestPolicyDeleteBatchMutationIDStable10512(t *testing.T) {
	batch := []SessionPolicyMatch{
		policyDeleteTestMatch10512(1),
		policyDeleteTestMatch10512(2),
		policyDeleteTestMatch10512(3),
	}
	again := []SessionPolicyMatch{
		policyDeleteTestMatch10512(1),
		policyDeleteTestMatch10512(2),
		policyDeleteTestMatch10512(3),
	}
	reordered := []SessionPolicyMatch{
		policyDeleteTestMatch10512(3),
		policyDeleteTestMatch10512(2),
		policyDeleteTestMatch10512(1),
	}
	changed := []SessionPolicyMatch{
		policyDeleteTestMatch10512(1),
		policyDeleteTestMatch10512(2),
		policyDeleteTestMatch10512(4),
	}
	base := policyDeleteBatchMutationID(batch)
	if got := policyDeleteBatchMutationID(again); got != base {
		t.Errorf("same content yielded %q then %q, want stability", base, got)
	}
	if got := policyDeleteBatchMutationID(reordered); got == base {
		t.Errorf("reordered batch kept digest %q, want distinct", got)
	}
	if got := policyDeleteBatchMutationID(changed); got == base {
		t.Errorf("changed batch kept digest %q, want distinct", got)
	}
	if !strings.HasPrefix(base, "pb:") {
		t.Errorf("digest = %q, want pb: prefix", base)
	}
}
