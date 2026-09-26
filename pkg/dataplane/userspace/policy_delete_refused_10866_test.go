package userspace

import (
	"encoding/json"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// answerThenHangup10866 answers the first policy-batch request with a scripted
// response and hangs up every later connection without answering: the client
// read fails (EOF) and the request classifies as a transport error
// (errSessionHelperUnreachable), deterministically and without waiting out any
// deadline. DeletePolicySessions is strictly sequential (one batch in flight,
// one transport retry), so accept order is deterministic.
type answerThenHangup10866 struct {
	mu   sync.Mutex
	fst  ControlResponse
	seen int
}

func startAnswerThenHangup10866(t *testing.T, sockPath string, first ControlResponse) *answerThenHangup10866 {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen helper session socket: %v", err)
	}
	f := &answerThenHangup10866{fst: first}
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
				idx := f.seen
				f.seen++
				f.mu.Unlock()
				if idx == 0 {
					_ = json.NewEncoder(conn).Encode(f.fst)
				}
				// idx >= 1: hang up without answering -> transport error.
			}()
		}
	}()
	return f
}

func (f *answerThenHangup10866) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen
}

// #10866: one refused batch + one transport-error batch. The gap must report
// the refused survivor, not just the transport cause.
func TestDeletePolicySessionsRefusedThenTransportReportsSurvivor10866(t *testing.T) {
	m, sessionSock := newBatchTestManager10512(t)
	outcomes := make([]string, 64)
	for i := range outcomes {
		outcomes[i] = "applied"
	}
	outcomes[63] = "refused_identity"
	fake := startAnswerThenHangup10866(t, sessionSock, ControlResponse{
		OK: true, PolicyDeleteOutcomes: outcomes, PolicyDeleteComplete: true,
	})
	matches := make([]SessionPolicyMatch, 0, 65)
	for seq := uint64(1); seq <= 65; seq++ {
		matches = append(matches, policyDeleteTestMatch10512(seq))
	}
	result, err := m.DeletePolicySessions(matches)
	if err == nil {
		t.Fatal("refused + transport-error batches must surface a gap error, got nil")
	}
	if !strings.Contains(err.Error(), "INCOMPLETE") {
		t.Errorf("gap error must be labeled INCOMPLETE, got: %v", err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "refused") {
		t.Errorf("gap error must report the refused survivor, got: %v", err)
	}
	if got, want := result.Refused, 1; got != want {
		t.Errorf("Refused = %d, want %d (result=%+v)", got, want, result)
	}
	if len(result.RefusedSessionIDs) != 1 || result.RefusedSessionIDs[0] != 64 {
		t.Errorf("RefusedSessionIDs = %v, want [64]", result.RefusedSessionIDs)
	}
	if !strings.Contains(err.Error(), "refused 1 session") {
		t.Errorf("gap error must report the refused survivor, got: %v", err)
	}
	if got := fake.requestCount(); got != 3 {
		t.Errorf("request count = %d, want 3 (1 answered + attempt + transport retry)", got)
	}
}

var rustRefusedIdentityOutcome10866 = regexp.MustCompile(
	`SyncedDeleteOutcome::RefusedIdentity\s*=>\s*"([^"]+)"`,
)

// The token originates in Rust's handler mapping and traverses the Go session
// socket decoder and policy-delete outcome accounting, pinning the cross-
// language refusal contract end to end.
func TestDeletePolicySessionsRefusedIdentityRustWireTokenEndToEnd10866(t *testing.T) {
	rust, err := os.ReadFile("../../../userspace-dp/src/server/handlers/sync_session.rs")
	if err != nil {
		t.Fatalf("read Rust session outcome mapping: %v", err)
	}
	match := rustRefusedIdentityOutcome10866.FindSubmatch(rust)
	if len(match) != 2 {
		t.Fatal("Rust handler no longer maps SyncedDeleteOutcome::RefusedIdentity to a wire token")
	}
	token := string(match[1])
	m, sessionSock := newBatchTestManager10512(t)
	startScriptedBatchSocket10512(t, sessionSock, []ControlResponse{
		{OK: true, PolicyDeleteOutcomes: []string{token}, PolicyDeleteComplete: true},
	})
	wantID := uint64(7001)
	result, err := m.DeletePolicySessions([]SessionPolicyMatch{policyDeleteTestMatch10512(wantID)})
	if err == nil {
		t.Fatalf("Rust refusal token %q must produce a surfaced policy-delete gap", token)
	}
	if result.Refused != 1 || len(result.RefusedSessionIDs) != 1 || result.RefusedSessionIDs[0] != wantID {
		t.Fatalf("Rust refusal token %q produced result %+v, want refused session %d", token, result, wantID)
	}
	if !strings.Contains(err.Error(), "refused 1 session") {
		t.Errorf("Rust refusal token %q was not reported in the gap: %v", token, err)
	}
}
