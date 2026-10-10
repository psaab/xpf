package userspace

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// scriptedReadFake10512 serves scripted list_sessions_by_policy pages on
// the CONTROL socket (the manager deliberately uses it, not the session
// socket) and records every decoded list request.
type scriptedReadFake10512 struct {
	mu     sync.Mutex
	ln     net.Listener
	script []ControlResponse
	reqs   []SessionPolicyListRequest
}

func startScriptedReadFake10512(t *testing.T, sockPath string, script []ControlResponse) *scriptedReadFake10512 {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen read fake: %v", err)
	}
	f := &scriptedReadFake10512{ln: ln, script: script}
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
				idx := len(f.reqs)
				if req.SessionPolicyList != nil {
					f.reqs = append(f.reqs, *req.SessionPolicyList)
				}
				resp := ControlResponse{OK: true, SessionPolicyComplete: true}
				if idx < len(f.script) {
					resp = f.script[idx]
				}
				f.mu.Unlock()
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	return f
}

func (f *scriptedReadFake10512) requests() []SessionPolicyListRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SessionPolicyListRequest(nil), f.reqs...)
}

func newReadOnlyManager10512(t *testing.T) (*Manager, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "x10512")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	controlSock := filepath.Join(dir, "control.sock")
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{}}
	m.cfg.ControlSocket = controlSock
	return m, controlSock
}

func readMatch10512(policy uint32, domain uint32, id uint64) SessionPolicyMatch {
	return SessionPolicyMatch{
		AddrFamily: 4, RoutingDomain: domain, PolicyID: policy,
		ExpectedRTFlowSessionID: id,
		Tuple: SessionPolicyTuple{
			AddrFamily: 4, Protocol: 6,
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 40001, DstPort: 80,
		},
	}
}

// The manager READ merges continuation pages, chains the token, and
// passes mode/families/classes through untouched.
func TestManagerReadMergesContinuationPages10512(t *testing.T) {
	m, controlSock := newReadOnlyManager10512(t)
	expectedCfg := &config.Config{}
	m.appliedSnapshot.Config = expectedCfg
	fake := startScriptedReadFake10512(t, controlSock, []ControlResponse{
		{
			OK:                        true,
			SessionPolicyMatches:      []SessionPolicyMatch{readMatch10512(1, 100007, 0xA1)},
			SessionPolicyContinuation: "c1",
		},
		{
			OK:                    true,
			SessionPolicyMatches:  []SessionPolicyMatch{readMatch10512(1, 100008, 0xB1)},
			SessionPolicyComplete: true,
		},
	})

	resp, err := m.ListSessionsByPolicy(SessionPolicyListRequest{
		PolicyIDs: []uint32{1}, Mode: "prepublish",
		Families: []uint8{4}, Classes: []string{"forward"},
		ExpectedConfig: expectedCfg,
	})
	if err != nil {
		t.Fatalf("paged READ: %v", err)
	}
	if !resp.SessionPolicyComplete {
		t.Fatal("merged READ must be complete")
	}
	if len(resp.SessionPolicyMatches) != 2 {
		t.Fatalf("merged %d matches, want 2 (both pages)", len(resp.SessionPolicyMatches))
	}
	reqs := fake.requests()
	if len(reqs) != 2 {
		t.Fatalf("helper got %d requests, want 2 (initial + continuation)", len(reqs))
	}
	for i, r := range reqs {
		if r.ExpectedConfig != nil {
			t.Errorf("req %d serialized Go-local ExpectedConfig: %p", i, r.ExpectedConfig)
		}
		if r.Mode != "prepublish" || len(r.Families) != 1 || r.Families[0] != 4 ||
			len(r.Classes) != 1 || r.Classes[0] != "forward" {
			t.Errorf("req %d mutated mode/families/classes: %+v", i, r)
		}
		if len(r.PolicyIDs) != 1 || r.PolicyIDs[0] != 1 {
			t.Errorf("req %d policy ids = %v, want [1]", i, r.PolicyIDs)
		}
	}
	if reqs[1].Continuation != "c1" {
		t.Errorf("page 2 continuation = %q, want c1", reqs[1].Continuation)
	}
}

// A committed apply_snapshot whose response is lost leaves Go's applied config
// at C0 while the helper has advanced to C1. A prepublish LIST expecting C0
// must be refused before the helper is asked for any page.
func TestManagerReadRejectsLostSnapshotOutcome12072(t *testing.T) {
	oldCfg, newCfg := &config.Config{}, &config.Config{}
	m, controlSock := newReadOnlyManager10512(t)
	m.appliedSnapshot.Config = oldCfg
	fake := startScriptedReadFake10512(t, controlSock, []ControlResponse{{
		OK: true, SessionPolicyMatches: []SessionPolicyMatch{readMatch10512(1, 100007, 0xA1)},
		SessionPolicyComplete: true,
	}})

	applyRec := &applyRecorder9520{replies: []error{errLostResponse9520}}
	var helperConfig *config.Config
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" {
			helperConfig = req.Snapshot.Config
		}
		return applyRec.hook(req, status)
	}
	snap := ConfigSnapshot{Version: ProtocolVersion, Generation: 1, Config: newCfg}
	m.mu.Lock()
	applyErr := m.requestApplySnapshotLocked(&snap, nil)
	unknown, appliedCfg := m.applySnapshotOutcomeUnknown, m.appliedSnapshot.Config
	m.mu.Unlock()
	if applyErr == nil || !unknown {
		t.Fatalf("premise: lost apply response must mark outcome unknown (err=%v unknown=%v)", applyErr, unknown)
	}
	if helperConfig != newCfg || appliedCfg != oldCfg {
		t.Fatalf("premise: helper/applied configs = %p/%p, want C1/C0 %p/%p",
			helperConfig, appliedCfg, newCfg, oldCfg)
	}

	resp, err := m.ListSessionsByPolicy(SessionPolicyListRequest{
		PolicyIDs: []uint32{1}, Mode: "prepublish", ExpectedConfig: oldCfg,
	})
	if err == nil {
		t.Fatal("prepublish READ with unknown apply outcome must fail closed")
	}
	if !errors.Is(err, ErrPolicyReadAuthority) {
		t.Fatalf("prepublish refusal error = %v, want ErrPolicyReadAuthority", err)
	}
	if got := m.PolicyReadConfig(); got != nil {
		t.Fatalf("PolicyReadConfig under unknown outcome = %p, want nil", got)
	}
	if got := m.AppliedConfig(); got != oldCfg {
		t.Fatalf("AppliedConfig under unknown outcome = %p, want preserved snapshot %p", got, oldCfg)
	}
	if len(resp.SessionPolicyMatches) != 0 {
		t.Fatalf("refused prepublish READ returned %d matches, want none", len(resp.SessionPolicyMatches))
	}
	if got := len(fake.requests()); got != 0 {
		t.Fatalf("helper received %d LIST requests after unknown apply outcome, want none", got)
	}
}

// A prepublish request must not reinterpret policy IDs after the acknowledged
// snapshot has moved to a different config, even when no apply outcome is
// currently unknown.
func TestManagerReadRejectsMismatchedExpectedConfig12072(t *testing.T) {
	expectedCfg, appliedCfg := &config.Config{}, &config.Config{}
	m, controlSock := newReadOnlyManager10512(t)
	m.appliedSnapshot.Config = appliedCfg
	fake := startScriptedReadFake10512(t, controlSock, []ControlResponse{{
		OK: true, SessionPolicyMatches: []SessionPolicyMatch{readMatch10512(1, 100007, 0xA1)},
		SessionPolicyComplete: true,
	}})

	resp, err := m.ListSessionsByPolicy(SessionPolicyListRequest{
		PolicyIDs: []uint32{1}, Mode: "prepublish", ExpectedConfig: expectedCfg,
	})
	if err == nil {
		t.Fatal("prepublish READ with mismatched applied config must fail closed")
	}
	if !errors.Is(err, ErrPolicyReadAuthority) {
		t.Fatalf("prepublish refusal error = %v, want ErrPolicyReadAuthority", err)
	}
	if len(resp.SessionPolicyMatches) != 0 {
		t.Fatalf("refused prepublish READ returned %d matches, want none", len(resp.SessionPolicyMatches))
	}
	if got := len(fake.requests()); got != 0 {
		t.Fatalf("helper received %d LIST requests after config mismatch, want none", got)
	}
}

func TestManagerReadRejectsLegacyListWithUnknownAuthority12072(t *testing.T) {
	m, controlSock := newReadOnlyManager10512(t)
	fake := startScriptedReadFake10512(t, controlSock, []ControlResponse{{
		OK: true, SessionPolicyMatches: []SessionPolicyMatch{readMatch10512(1, 100007, 0xA1)},
		SessionPolicyComplete: true,
	}})
	m.mu.Lock()
	m.applySnapshotOutcomeUnknown = true
	m.mu.Unlock()
	beforeSecs := uint64(0)
	resp, err := m.ListSessionsByPolicy(SessionPolicyListRequest{
		PolicyIDs: []uint32{1}, Mode: "legacy", BeforeSecs: &beforeSecs,
	})
	if !errors.Is(err, ErrPolicyReadAuthority) {
		t.Fatalf("legacy LIST error = %v, want ErrPolicyReadAuthority", err)
	}
	if len(resp.SessionPolicyMatches) != 0 {
		t.Fatalf("refused legacy LIST returned %d matches, want none", len(resp.SessionPolicyMatches))
	}
	if got := len(fake.requests()); got != 0 {
		t.Fatalf("helper received %d legacy LIST requests under unknown authority, want none", got)
	}
}

func TestManagerPolicyReadConfigReturnsKnownAppliedSnapshot12072(t *testing.T) {
	m := New()
	want := &config.Config{}
	m.mu.Lock()
	m.appliedSnapshot.Config = want
	m.mu.Unlock()
	if got := m.PolicyReadConfig(); got != want {
		t.Fatalf("PolicyReadConfig = %p, want applied config %p", got, want)
	}
	m.mu.Lock()
	m.applySnapshotOutcomeUnknown = true
	m.mu.Unlock()
	if got := m.PolicyReadConfig(); got != nil {
		t.Fatalf("PolicyReadConfig with unknown outcome = %p, want nil", got)
	}
	if got := m.AppliedConfig(); got != want {
		t.Fatalf("AppliedConfig changed semantics under unknown outcome: got %p, want %p", got, want)
	}
}

// Incomplete with no continuation is a stranded READ — error, not an
// authoritative empty.
func TestManagerReadIncompleteWithoutTokenErrors10512(t *testing.T) {
	m, controlSock := newReadOnlyManager10512(t)
	startScriptedReadFake10512(t, controlSock, []ControlResponse{
		{OK: true, SessionPolicyComplete: false},
	})

	if _, err := m.ListSessionsByPolicy(SessionPolicyListRequest{PolicyIDs: []uint32{1}}); err == nil {
		t.Fatal("READ incomplete-without-continuation must error")
	}
}

// A repeated continuation token is a wedged helper — fail fast.
func TestManagerReadRepeatedTokenErrors10512(t *testing.T) {
	m, controlSock := newReadOnlyManager10512(t)
	fake := startScriptedReadFake10512(t, controlSock, []ControlResponse{
		{OK: true, SessionPolicyContinuation: "stuck"},
		{OK: true, SessionPolicyContinuation: "stuck"},
	})

	if _, err := m.ListSessionsByPolicy(SessionPolicyListRequest{PolicyIDs: []uint32{1}}); err == nil {
		t.Fatal("READ with a repeated continuation token must error")
	}
	if got := len(fake.requests()); got != 2 {
		t.Fatalf("helper got %d requests, want 2 (detect on first repeat)", got)
	}
}
