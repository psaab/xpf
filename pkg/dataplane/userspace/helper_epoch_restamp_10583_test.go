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

	"github.com/psaab/xpf/pkg/dataplane"
)

// churnRendezvousFake10583 holds the FIRST request until the test bumps
// procGen, making restart-during-send deterministic: receipt signals
// arrived, the test churns, then closes release to let responses flow.
// Later requests answer immediately. Records every request's epoch.
type churnRendezvousFake10583 struct {
	mu      sync.Mutex
	ln      net.Listener
	epochs  []uint64
	ops     []string
	arrived chan struct{}
	release chan struct{}
	once    sync.Once
	script  []ControlResponse
}

func startChurnRendezvousFake10583(t *testing.T, sockPath string, script []ControlResponse) *churnRendezvousFake10583 {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen churn fake: %v", err)
	}
	f := &churnRendezvousFake10583{
		ln:      ln,
		arrived: make(chan struct{}),
		release: make(chan struct{}),
		script:  script,
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
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					return
				}
				f.mu.Lock()
				idx := len(f.ops)
				if req.SessionSync != nil {
					f.ops = append(f.ops, req.SessionSync.Operation)
					f.epochs = append(f.epochs, req.SessionSync.HelperEpoch)
				}
				first := idx == 0
				resp := ControlResponse{OK: true}
				if idx < len(f.script) {
					resp = f.script[idx]
				}
				f.mu.Unlock()
				if first {
					close(f.arrived)
					<-f.release
				}
				_ = json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()
	return f
}

func (f *churnRendezvousFake10583) snapshot() (ops []string, epochs []uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...), append([]uint64(nil), f.epochs...)
}

func newChurnManager10583(t *testing.T, gen uint64) (*Manager, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "x10583")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{}}
	m.procGen = gen
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	return m, filepath.Join(dir, "userspace-dp-sessions.sock")
}

// P12-D: a policy batch in flight across a helper restart gaps LOUDLY
// and sends nothing further — no restamped batch, no batch 2. The
// pre-churn capture must never evaluate against reminted tables.
func TestPolicyBatchChurnGapsWithOneSend10583(t *testing.T) {
	m, sessionSock := newChurnManager10583(t, 41)
	fake := startChurnRendezvousFake10583(t, sessionSock, []ControlResponse{batchOK10512(64), batchOK10512(1)})

	matches := make([]SessionPolicyMatch, 0, 65)
	for i := uint64(1); i <= 65; i++ {
		matches = append(matches, policyDeleteTestMatch10512(i))
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := m.DeletePolicySessions(matches)
		errCh <- err
	}()

	<-fake.arrived // batch 1 (epoch 41) is in flight; restart under it
	m.mu.Lock()
	m.procGen = 42
	m.mu.Unlock()
	close(fake.release)

	err := <-errCh
	ops, epochs := fake.snapshot()
	if len(ops) != 1 {
		t.Fatalf("helper got %d batch sends, want exactly 1 (batch 2 never sent, no restamp)", len(ops))
	}
	if epochs[0] != 41 {
		t.Fatalf("the single send carried epoch %d, want the pre-churn 41 (never restamped)", epochs[0])
	}
	if err == nil || !strings.Contains(err.Error(), "churned") {
		t.Fatalf("churned policy delete must gap loudly, got %v", err)
	}
}

// P12-E: single-key idempotent sends self-heal across a restart — the
// churned send is restamped to the live generation and retried once.
func TestSingleMirrorSendRestampsAcrossChurn10583(t *testing.T) {
	m, sessionSock := newChurnManager10583(t, 41)
	fake := startChurnRendezvousFake10583(t, sessionSock, []ControlResponse{
		{OK: true}, {OK: true},
	})

	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2},
		SrcPort: 40001, DstPort: 80, Protocol: 6,
	}
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		m.mirrorSessionV4(key, dataplane.SessionValue{})
	}()

	<-fake.arrived // req 1 (epoch 41) is in flight; restart under it
	m.mu.Lock()
	m.procGen = 42
	m.mu.Unlock()
	close(fake.release)
	<-doneCh

	ops, epochs := fake.snapshot()
	if len(ops) != 2 {
		t.Fatalf("helper got %d sends, want 2 (original + restamped retry)", len(ops))
	}
	if epochs[0] != 41 || epochs[1] != 42 {
		t.Fatalf("epochs = %v, want [41 42] (restamp to live)", epochs)
	}
}
