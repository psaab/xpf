package userspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/dataplane"
)

// newAnsweringManager6785 builds a Manager whose helper session socket is LIVE
// and answers every request with the supplied response. That is the shape the
// #6785 discrimination turns on: the socket round-trips fine, so it is NOT the
// unreachable-helper case newMirrorFailManager5305 produces — the failure comes
// back IN the answer.
func newAnsweringManager6785(t *testing.T, resp ControlResponse) *Manager {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	// #9337: NOT t.TempDir(). Its directory name embeds the full test and
	// sub-test names, and this pair's are long enough that
	// <tmp>/<Test+subtest+nonce>/001/userspace-dp-sessions.sock exceeds the
	// 108-byte AF_UNIX sun_path limit — `bind: invalid argument`, which reads
	// like a dataplane defect and is not one. Memlock-gated, so it only
	// surfaced once #9337 ran these guards under CAP_BPF. A short prefix keeps
	// the path bounded no matter how the test is renamed.
	dir, err := os.MkdirTemp("", "x6785")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	ln, lerr := net.Listen("unix", sessionSock)
	if lerr != nil {
		t.Fatalf("listen session socket: %v", lerr)
	}
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
				_ = json.NewDecoder(conn).Decode(&req)
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)
	return m
}

func newScriptedSessionManager10788(
	t *testing.T,
	responses []ControlResponse,
) (*Manager, <-chan SessionSyncRequest) {
	t.Helper()
	dir, err := os.MkdirTemp("", "x10788")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	ln, err := net.Listen("unix", sessionSock)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	requests := make(chan SessionSyncRequest, len(responses))
	go func() {
		for _, response := range responses {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err == nil && req.SessionSync != nil {
				requests <- *req.SessionSync
			}
			_ = json.NewEncoder(conn).Encode(response)
			_ = conn.Close()
		}
		_ = ln.Close()
	}()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	return m, requests
}

// TestSyncedImportRefusalRollsBackWithoutGatingTakeover6785 is the #6785
// contract on the Go side, and it is a PAIRED test: the same call site, two
// helper answers, opposite health outcomes.
//
// A SEMANTIC refusal (`ok=false` with the helper's refusal token) must:
//   - roll the BPF mirror row back, because the helper did NOT take the session
//     and a row left behind is the split truth #5305 exists to prevent;
//   - NOT set sessionMirrorFailed, because that gates HA takeover-readiness
//     (#5247) and the helper is healthy — it answered correctly;
//   - be counted as its own debt.
//
// A TRANSPORT-shaped failure (`ok=false` with any other message) must do the
// opposite on the health flag. Without that half, "does not set the flag on a
// refusal" would be satisfied by an implementation that never sets the flag at
// all, which silently removes the #5247 gate.
func TestSyncedImportRefusalRollsBackWithoutGatingTakeover6785(t *testing.T) {
	key := rollbackKeyV4()
	val := dataplane.SessionValue{IsReverse: 0, IngressZone: 1, EgressZone: 2}

	t.Run("semantic-refusal", func(t *testing.T) {
		m := newAnsweringManager6785(t, ControlResponse{
			OK:    false,
			Error: syncedImportRefusedPrefix + "capacity",
		})

		err := m.SetClusterSyncedSessionV4(key, val)
		if err == nil {
			t.Fatal("SetClusterSyncedSessionV4() = nil after the helper REFUSED " +
				"the import — the caller records a success and keeps a BPF row " +
				"for a session the helper never took (#6785)")
		}
		if !errors.Is(err, dataplane.ErrSyncedImportRefused) {
			t.Fatalf("error does not classify as a semantic refusal: %v", err)
		}
		if _, getErr := m.bpfShim.GetSessionV4(key); !errors.Is(getErr, ebpf.ErrKeyNotExist) {
			t.Fatalf("BPF row survived a REFUSED import: GetSessionV4 err = %v, "+
				"want ErrKeyNotExist — this is the split truth", getErr)
		}
		if m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = true after a SEMANTIC refusal: the " +
				"helper answered correctly, so gating HA takeover-readiness on " +
				"this would keep a working standby from ever taking over once a " +
				"peer oversubscribed it (#5247)")
		}
		if got := m.syncedImportRefusals.Load(); got != 1 {
			t.Fatalf("syncedImportRefusals = %d, want 1 — a rolled-back import "+
				"that is counted nowhere is not health debt, it is a silent drop", got)
		}
	})

	t.Run("non-refusal-failure-still-gates", func(t *testing.T) {
		m := newAnsweringManager6785(t, ControlResponse{
			OK:    false,
			Error: "session table write failed",
		})

		err := m.SetClusterSyncedSessionV4(key, val)
		if err == nil {
			t.Fatal("SetClusterSyncedSessionV4() = nil on a helper failure")
		}
		if errors.Is(err, dataplane.ErrSyncedImportRefused) {
			t.Fatalf("an UNPREFIXED helper error was classified as a semantic "+
				"refusal: %v — the classifier is matching too broadly and every "+
				"real mirror failure would stop gating takeover", err)
		}
		if !m.sessionMirrorFailed {
			t.Fatal("sessionMirrorFailed = false on a non-refusal helper " +
				"failure — the #5247 takeover gate is gone")
		}
		if got := m.syncedImportRefusals.Load(); got != 0 {
			t.Fatalf("syncedImportRefusals = %d on a non-refusal failure, want 0", got)
		}
	})
}

// TestSyncedImportRefusalRollsBackWithoutGatingTakeoverV6_6785 is the IPv6 twin.
// The two entry points carry independently written copies of the classify /
// compensate / count sequence, so a divergence between them is always a bug and
// each needs its own cell — binding only V4 would let V6 keep reporting success.
func TestSyncedImportRefusalRollsBackWithoutGatingTakeoverV6_6785(t *testing.T) {
	key := rollbackKeyV6()
	val := dataplane.SessionValueV6{IsReverse: 0, IngressZone: 1, EgressZone: 2}

	m := newAnsweringManager6785(t, ControlResponse{
		OK:    false,
		Error: syncedImportRefusedPrefix + "stale-generation",
	})

	err := m.SetClusterSyncedSessionV6(key, val)
	if err == nil {
		t.Fatal("SetClusterSyncedSessionV6() = nil after the helper REFUSED the import (#6785)")
	}
	if !errors.Is(err, dataplane.ErrSyncedImportRefused) {
		t.Fatalf("v6 error does not classify as a semantic refusal: %v", err)
	}
	if _, getErr := m.bpfShim.GetSessionV6(key); !errors.Is(getErr, ebpf.ErrKeyNotExist) {
		t.Fatalf("v6 BPF row survived a REFUSED import: err = %v, want ErrKeyNotExist", getErr)
	}
	if m.sessionMirrorFailed {
		t.Fatal("v6: sessionMirrorFailed = true after a semantic refusal")
	}
	if got := m.syncedImportRefusals.Load(); got != 1 {
		t.Fatalf("v6: syncedImportRefusals = %d, want 1", got)
	}
}

// rustRefusalPrefixRe extracts the helper's SYNCED_IMPORT_REFUSED_PREFIX literal.
var rustRefusalPrefixRe = regexp.MustCompile(
	`(?m)^pub const SYNCED_IMPORT_REFUSED_PREFIX:\s*&str\s*=\s*"([^"]*)"\s*;`)

// TestSyncedImportRefusedPrefixMatchesTheHelper6785 asserts the AGREEMENT
// between the Go classifier's token and the Rust constant the helper actually
// emits, by READING the Rust source rather than pinning either side to a
// literal.
//
// Pinning would encode which side is trusted, and here neither is: if the Rust
// constant is renamed and Go keeps a hard-coded string, every semantic refusal
// silently reclassifies as a transport failure — which sets sessionMirrorFailed
// and permanently disarms HA takeover on a healthy standby. That failure is
// worse than the bug #6785 fixes, and it is invisible: both sides compile, all
// unit tests on either side pass, and the only symptom is a standby that never
// takes over.
func TestSyncedImportRefusedPrefixMatchesTheHelper6785(t *testing.T) {
	src, err := os.ReadFile("../../../userspace-dp/src/afxdp/ha/session_import.rs")
	if err != nil {
		t.Fatalf("read the helper source that owns the refusal token: %v", err)
	}
	// Strip line comments first: the doc comment above the constant quotes the
	// token, and a gate satisfiable by its own documentation proves nothing.
	var stripped strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			stripped.WriteString("\n")
			continue
		}
		stripped.WriteString(line)
		stripped.WriteString("\n")
	}
	match := rustRefusalPrefixRe.FindStringSubmatch(stripped.String())
	if match == nil {
		t.Fatal("SYNCED_IMPORT_REFUSED_PREFIX not found in the helper source — " +
			"it was renamed or removed, so Go can no longer tell a semantic " +
			"refusal from a transport failure and every refusal would disarm " +
			"HA takeover (#6785)")
	}
	if match[1] != syncedImportRefusedPrefix {
		t.Fatalf("refusal token disagreement: helper emits %q, Go matches %q — "+
			"every refusal would be misclassified as a transport failure",
			match[1], syncedImportRefusedPrefix)
	}
}

// TestHelperErrorClassification6785 binds the discriminator itself, at the
// transport, with NO BPF maps involved.
//
// This cell exists because the two rollback cells above need real BPF session
// maps and SKIP without CAP_BPF — a guard that skips is indistinguishable from a
// guard that passes, and the classification is the decision every other
// behaviour in #6785 hangs off: get it wrong in the permissive direction and a
// real mirror failure stops gating HA takeover; get it wrong in the strict
// direction and every capacity refusal permanently disarms a healthy standby.
//
// The token-not-at-the-start row is load-bearing: an error containing the
// refusal prefix away from byte zero must not change helper-health classification.
func TestHelperErrorClassification6785(t *testing.T) {
	cases := []struct {
		name         string
		helperError  string
		wantRefusal  bool
		wantGateBusy bool
	}{
		{"refusal-capacity", syncedImportRefusedPrefix + "capacity", true, false},
		{"refusal-stale", syncedImportRefusedPrefix + "stale-generation", true, false},
		{"refusal-reserve", syncedImportRefusedPrefix + "reserve", true, false},
		{"retryable-gate-busy", syncedImportRefusedPrefix + "gate-busy", false, true},
		{"token-not-at-the-start", "write failed while handling " + syncedImportRefusedPrefix + "capacity", false, false},
		{"plain-helper-error", "session table write failed", false, false},
		{"unknown-operation", "unknown session sync operation frobnicate", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sock := filepath.Join(dir, "userspace-dp-sessions.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()
			go func() {
				for {
					conn, aerr := ln.Accept()
					if aerr != nil {
						return
					}
					go func() {
						defer conn.Close()
						var req ControlRequest
						_ = json.NewDecoder(conn).Decode(&req)
						_ = json.NewEncoder(conn).Encode(ControlResponse{
							OK: false, Error: tc.helperError,
						})
					}()
				}
			}()

			m := New()
			m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
			m.cfg.ControlSocket = filepath.Join(dir, "control.sock")

			err = m.requestSessionSync(ControlRequest{
				Type:           "sync_session",
				SuppressStatus: true,
				SessionSync:    &SessionSyncRequest{Operation: "upsert"},
			})
			if err == nil {
				t.Fatal("requestSessionSync() = nil on an ok=false answer")
			}
			if got := errors.Is(err, dataplane.ErrSyncedImportRefused); got != tc.wantRefusal {
				t.Fatalf("classified as a terminal semantic refusal = %v, want %v (err %v)",
					got, tc.wantRefusal, err)
			}
			if got := errors.Is(err, errSyncedImportGateBusy); got != tc.wantGateBusy {
				t.Fatalf("classified as retryable gate-busy = %v, want %v (err %v)",
					got, tc.wantGateBusy, err)
			}
			// A refusal must keep its reason readable; dropping it would leave
			// an operator unable to tell a capacity problem from a stale peer.
			if tc.wantRefusal || tc.wantGateBusy {
				reason := strings.TrimPrefix(tc.helperError, syncedImportRefusedPrefix)
				if !strings.Contains(err.Error(), reason) {
					t.Fatalf("refusal error %q lost the reason %q", err, reason)
				}
			}
		})
	}
}

func TestSyncedImportGateBusyRetriesWithFreshOperationID_10788(t *testing.T) {
	tests := []struct {
		name string
		send func(*Manager) error
	}{
		{
			name: "v4",
			send: func(m *Manager) error {
				m.mu.Lock()
				defer m.mu.Unlock()
				return m.syncSessionV4Locked("mirror_upsert", rollbackKeyV4(),
					&dataplane.SessionValue{Generation: 7, RTFlowSessionID: 0x10788})
			},
		},
		{
			name: "v6",
			send: func(m *Manager) error {
				m.mu.Lock()
				defer m.mu.Unlock()
				return m.syncSessionV6Locked("mirror_upsert", rollbackKeyV6(),
					&dataplane.SessionValueV6{Generation: 7, RTFlowSessionID: 0x10788})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, requests := newScriptedSessionManager10788(t, []ControlResponse{
				{Error: syncedImportRefusedPrefix + "gate-busy"},
				{OK: true},
			})
			if err := tc.send(m); err != nil {
				t.Fatalf("synced import did not succeed after the gate became available: %v", err)
			}
			var got [2]SessionSyncRequest
			for i := range got {
				select {
				case got[i] = <-requests:
				case <-time.After(time.Second):
					t.Fatalf("helper received only %d requests; want initial refusal and retry", i)
				}
			}
			if got[0].Operation != "mirror_upsert" || got[1].Operation != "mirror_upsert" {
				t.Fatalf("operations = %q, %q; want mirror_upsert for both attempts",
					got[0].Operation, got[1].Operation)
			}
			if got[0].OperationID == got[1].OperationID {
				t.Fatalf("retry reused OperationID %q; helper would replay its cached gate-busy response",
					got[1].OperationID)
			}
			if got[0].MutationID == "" || got[0].MutationID != got[1].MutationID {
				t.Fatalf("MutationID changed across retry: %q then %q",
					got[0].MutationID, got[1].MutationID)
			}
			if len(requests) != 0 {
				t.Fatal("helper received more requests after the successful retry")
			}
		})
	}
}

func TestSyncedImportGateBusyRetryIsBoundedAndSkipsTerminalRefusal_10788(t *testing.T) {
	t.Run("bounded-retries", func(t *testing.T) {
		const wantAttempts = 5
		responses := make([]ControlResponse, wantAttempts)
		for i := range responses {
			responses[i] = ControlResponse{Error: syncedImportRefusedPrefix + "gate-busy"}
		}
		m, requests := newScriptedSessionManager10788(t, responses)
		m.mu.Lock()
		err := m.syncSessionV4Locked("mirror_upsert", rollbackKeyV4(),
			&dataplane.SessionValue{Generation: 8, RTFlowSessionID: 0x10789})
		m.mu.Unlock()
		if !errors.Is(err, errSyncedImportGateBusy) {
			t.Fatalf("exhausted gate-busy result = %v, want retryable gate-busy", err)
		}
		var first SessionSyncRequest
		for i := range wantAttempts {
			select {
			case req := <-requests:
				if i == 0 {
					first = req
				} else {
					if req.OperationID == first.OperationID {
						t.Fatalf("attempt %d reused OperationID %q", i+1, req.OperationID)
					}
					if req.MutationID != first.MutationID {
						t.Fatalf("attempt %d MutationID = %q, want original %q",
							i+1, req.MutationID, first.MutationID)
					}
				}
			case <-time.After(time.Second):
				t.Fatalf("helper received %d requests; want exactly %d", i, wantAttempts)
			}
		}
		if len(requests) != 0 {
			t.Fatalf("helper received %d requests beyond the bounded retry limit", len(requests))
		}
	})

	t.Run("capacity-refusal-is-terminal", func(t *testing.T) {
		m, requests := newScriptedSessionManager10788(t, []ControlResponse{
			{Error: syncedImportRefusedPrefix + "capacity"},
		})
		m.mu.Lock()
		err := m.syncSessionV4Locked("mirror_upsert", rollbackKeyV4(),
			&dataplane.SessionValue{Generation: 9, RTFlowSessionID: 0x10790})
		m.mu.Unlock()
		if !errors.Is(err, dataplane.ErrSyncedImportRefused) {
			t.Fatalf("capacity result = %v, want terminal semantic refusal", err)
		}
		if errors.Is(err, errSyncedImportGateBusy) {
			t.Fatalf("capacity refusal was misclassified as retryable: %v", err)
		}
		select {
		case req := <-requests:
			if req.Operation != "mirror_upsert" {
				t.Fatalf("operation = %q, want mirror_upsert", req.Operation)
			}
		case <-time.After(time.Second):
			t.Fatal("helper did not receive the terminal refusal request")
		}
		if len(requests) != 0 {
			t.Fatalf("terminal capacity refusal triggered %d retries", len(requests))
		}
	})
}

// TestUnreachableHelperIsNotARefusal6785 is the transport half of the same
// discriminator: with nothing listening, the round trip must classify as
// errSessionHelperUnreachable and NOT as a semantic refusal. Without this the
// classifier could return the refusal sentinel for every failure and the two
// rollback cells above — which skip without CAP_BPF — would be the only thing
// standing between that and a standby that never gates takeover.
func TestUnreachableHelperIsNotARefusal6785(t *testing.T) {
	dir := t.TempDir()
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")

	err := m.requestSessionSync(ControlRequest{
		Type:           "sync_session",
		SuppressStatus: true,
		SessionSync:    &SessionSyncRequest{Operation: "upsert"},
	})
	if err == nil {
		t.Fatal("requestSessionSync() = nil with no helper listening")
	}
	if errors.Is(err, dataplane.ErrSyncedImportRefused) {
		t.Fatalf("an UNREACHABLE helper classified as a semantic refusal: %v — "+
			"a down helper would stop gating HA takeover-readiness (#5247)", err)
	}
	if !errors.Is(err, errSessionHelperUnreachable) {
		t.Fatalf("transport failure lost its errSessionHelperUnreachable "+
			"classification: %v", err)
	}
}

// TestSyncedMirrorFailureAccounting6785 binds the health decision itself, with
// NO BPF maps involved — and it exists because the two rollback cells above
// SKIP without CAP_BPF.
//
// That skip is not cosmetic. A mutation that made a semantic refusal set the
// sticky mirror-failure flag ran GREEN across the whole suite, because the only
// cells that could see it were skipped. A guard that skips is indistinguishable
// from a guard that passes, so the decision is now reachable on its own.
//
// It is a PAIRED table: the same function, three error shapes, and the flag must
// move in opposite directions. The refusal row alone would be satisfied by an
// implementation that never sets the flag at all — which silently deletes the
// #5247 takeover gate.
func TestSyncedMirrorFailureAccounting6785(t *testing.T) {
	cases := []struct {
		name            string
		err             error
		wantMirrorFail  bool
		wantRefusalsAdd uint64
	}{
		{
			name:            "semantic-refusal",
			err:             fmt.Errorf("%w: capacity", dataplane.ErrSyncedImportRefused),
			wantMirrorFail:  false,
			wantRefusalsAdd: 1,
		},
		{
			name:            "transport-failure",
			err:             fmt.Errorf("%w: dial session socket", errSessionHelperUnreachable),
			wantMirrorFail:  true,
			wantRefusalsAdd: 0,
		},
		{
			name:            "plain-helper-error",
			err:             errors.New("session table write failed"),
			wantMirrorFail:  true,
			wantRefusalsAdd: 0,
		},
		{
			name:            "gate-busy-after-retries-exhausted",
			err:             errSyncedImportGateBusy,
			wantMirrorFail:  true,
			wantRefusalsAdd: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}

			m.noteSyncedMirrorFailureLocked(tc.err)

			if m.sessionMirrorFailed != tc.wantMirrorFail {
				t.Fatalf("sessionMirrorFailed = %v, want %v — this flag gates HA "+
					"takeover-readiness (#5247): true on a refusal keeps a healthy "+
					"standby from ever taking over once a peer oversubscribes it, "+
					"and false on a real failure deletes the gate",
					m.sessionMirrorFailed, tc.wantMirrorFail)
			}
			if got := m.syncedImportRefusals.Load(); got != tc.wantRefusalsAdd {
				t.Fatalf("syncedImportRefusals = %d, want %d", got, tc.wantRefusalsAdd)
			}
		})
	}
}

// TestSyncedMirrorFailureAccountingIsSingleSourced6785 pins that both cluster
// install entry points route their failure accounting through the ONE helper
// above, rather than carrying their own copy of the classification.
//
// This is a source check, and it is deliberate: the behavioural cells for V6
// need BPF maps and skip here, so "V6 classifies the same way" is currently
// unprovable behaviourally on an unprivileged runner. A divergence between the
// two copies is always a bug — an IPv6-only misclassification would disarm HA
// takeover on exactly the deployments least likely to notice — so the agreement
// is bound structurally instead of left unbound.
//
// Comments are stripped before matching: the doc comment on the helper names
// both functions, and a gate satisfiable by its own documentation proves
// nothing.
func TestSyncedMirrorFailureAccountingIsSingleSourced6785(t *testing.T) {
	src, err := os.ReadFile("manager_sessions.go")
	if err != nil {
		t.Fatalf("read manager_sessions.go: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			code.WriteString("\n")
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	body := code.String()

	if n := strings.Count(body, "m.noteSyncedMirrorFailureLocked(err)"); n != 4 {
		t.Fatalf("noteSyncedMirrorFailureLocked is called %d times, want exactly "+
			"4 (the v4 and v6 cluster installs plus the v4 and v6 mirror installs) — a path that accounts its own "+
			"mirror failure has its own copy of the #5247 classification", n)
	}
	// The classification must not ALSO appear inline: a call plus a surviving
	// inline copy is the divergence this guards against.
	if n := strings.Count(body, "m.recordSessionMirrorFailureLocked("); n != 0 {
		t.Fatalf("recordSessionMirrorFailureLocked is called %d times directly "+
			"from manager_sessions.go, want 0 — the cluster install paths must "+
			"go through noteSyncedMirrorFailureLocked so the refusal "+
			"classification cannot be bypassed", n)
	}
}
