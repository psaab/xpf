package frr

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

type daemonLoadCall struct {
	daemon  string
	config  string
	ctxLive bool
}

// fakeExecutor is a hand-rolled test double for the frrExecutor interface.
// Per-method response programming + per-method call counting. No external
// test framework dependencies. All state is mutex-guarded because the
// degraded-retry goroutine (#1880) calls FrrReloadPy concurrently with
// test-goroutine assertions.
type fakeExecutor struct {
	mu sync.Mutex

	// vtyshResp returns the canned response for a given input command.
	// If the command is missing from the map, vtyshErr is returned.
	vtyshResp map[string]string
	vtyshErr  error

	// frrReloadPyErr is returned by FrrReloadPy. frrReloadPyHook, when
	// set, runs inside the call (under the manager's reloadMu) and its
	// return value wins — used by the stale-success and
	// converge-after-N tests.
	frrReloadPyErr  error
	frrReloadPyHook func(call int) error

	// vtyshLoadResp / vtyshLoadErr are returned by VtyshLoad.
	vtyshLoadResp []byte
	vtyshLoadErr  error

	daemonLoadResp          []byte
	daemonLoadRespByDaemon  map[string][]byte
	daemonLoadErr           error
	daemonLoadErrByDaemon   map[string]error
	daemonLoads             []daemonLoadCall
	callOrder               []string

	// Capture: most recent call args.
	lastVtyshCmd       string
	lastVtyshLoadConf  string
	lastVtyshLoadCtx   context.Context
	frrReloadPyCalls   int
	vtyshLoadCalls     int
	vtyshCalls         int
	lastFrrReloadPyCtx context.Context
	lastFrrReloadConf  string

	// vtyshLoadCtxLiveAtCall records whether the fallback's context was
	// still live when VtyshLoad ran (fresh-context contract).
	vtyshLoadCtxLiveAtCall bool
}

func (f *fakeExecutor) Vtysh(_ context.Context, command string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vtyshCalls++
	f.lastVtyshCmd = command
	if resp, ok := f.vtyshResp[command]; ok {
		return resp, nil
	}
	return "", f.vtyshErr
}

func (f *fakeExecutor) FrrReloadPy(ctx context.Context, conf string) error {
	f.mu.Lock()
	f.frrReloadPyCalls++
	call := f.frrReloadPyCalls
	f.lastFrrReloadPyCtx = ctx
	f.lastFrrReloadConf = conf
	hook := f.frrReloadPyHook
	err := f.frrReloadPyErr
	f.callOrder = append(f.callOrder, "reload")
	f.mu.Unlock()
	if hook != nil {
		return hook(call)
	}
	return err
}

func (f *fakeExecutor) VtyshStream(_ context.Context, command string) (io.ReadCloser, func() error, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vtyshCalls++
	f.lastVtyshCmd = command
	if resp, ok := f.vtyshResp[command]; ok {
		return io.NopCloser(strings.NewReader(resp)), func() error { return nil }, nil
	}
	if f.vtyshErr != nil {
		return nil, nil, f.vtyshErr
	}
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

func (f *fakeExecutor) reloadPyCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.frrReloadPyCalls
}

func (f *fakeExecutor) VtyshLoad(ctx context.Context, conf string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callOrder = append(f.callOrder, "global-load")
	f.vtyshLoadCalls++
	f.lastVtyshLoadCtx = ctx
	f.lastVtyshLoadConf = conf
	// Liveness must be sampled AT CALL TIME — the caller's deferred
	// cancel runs before the test can assert.
	f.vtyshLoadCtxLiveAtCall = ctx.Err() == nil
	return f.vtyshLoadResp, f.vtyshLoadErr
}

func (f *fakeExecutor) VtyshLoadDaemon(ctx context.Context, daemon, conf string) ([]byte, error) {
	contents, readErr := os.ReadFile(conf)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.callOrder = append(f.callOrder, "daemon-load:"+daemon)
	if readErr != nil {
		return nil, readErr
	}
	f.daemonLoads = append(f.daemonLoads, daemonLoadCall{
		daemon: daemon, config: string(contents), ctxLive: ctx.Err() == nil,
	})
	resp := f.daemonLoadRespByDaemon[daemon]
	if resp == nil {
		resp = f.daemonLoadResp
	}
	err := f.daemonLoadErrByDaemon[daemon]
	if err == nil {
		err = f.daemonLoadErr
	}
	return resp, err
}

// TestExecVtyshUsesExecutor proves that Manager.ExecVtysh routes through
// the injected executor and returns its result verbatim. This is the
// archetype for AC#3 ("vtysh command execution is behind a narrow
// interface for tests").
func TestExecVtyshUsesExecutor(t *testing.T) {
	fake := &fakeExecutor{
		vtyshResp: map[string]string{"show whatever": "canned output"},
	}
	m := &Manager{exec: fake}
	out, err := m.ExecVtysh(context.Background(), "show whatever")
	if err != nil {
		t.Fatalf("ExecVtysh: %v", err)
	}
	if out != "canned output" {
		t.Errorf("ExecVtysh: got %q, want %q", out, "canned output")
	}
	if fake.lastVtyshCmd != "show whatever" {
		t.Errorf("Vtysh called with %q, want %q", fake.lastVtyshCmd, "show whatever")
	}
}

// TestGetRIPRoutesUsesExecutor proves that a parsed Get* method also
// routes through the executor. Picks GetRIPRoutes because the parser is
// small and the inputs are easy to construct.
func TestGetRIPRoutesUsesExecutor(t *testing.T) {
	// FRR's "show ip rip" sample with two routes and a header line.
	canned := `Codes: R - RIP, C - connected, S - Static, O - OSPF, B - BGP
Network            Next Hop         Metric From            Tag Time
10.0.0.0/24        10.0.0.1         1      192.168.1.1     0   00:01:23
10.1.0.0/24        10.1.0.1         2      192.168.1.2     0   00:02:34
`
	fake := &fakeExecutor{
		vtyshResp: map[string]string{"show ip rip": canned},
	}
	m := &Manager{exec: fake}
	routes, err := m.GetRIPRoutes(context.Background())
	if err != nil {
		t.Fatalf("GetRIPRoutes: %v", err)
	}
	if len(routes) < 2 {
		t.Fatalf("GetRIPRoutes: got %d routes, want at least 2", len(routes))
	}
	if routes[0].Network != "10.0.0.0/24" {
		t.Errorf("routes[0].Network = %q, want 10.0.0.0/24", routes[0].Network)
	}
	if fake.vtyshCalls != 1 {
		t.Errorf("Vtysh calls = %d, want 1", fake.vtyshCalls)
	}
}

// reloadForTest wraps reloadLocked with the lock the production
// callers (commitManagedSection, retryReloadOnce) hold.
func (m *Manager) reloadForTest() error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	return m.reloadLocked()
}

// TestReloadPrimaryHappyPath verifies that reload calls FrrReloadPy
// first with the manager's conf path and a deadline-carrying context,
// and that the VtyshLoad fallback is NOT invoked on success.
func TestReloadPrimaryHappyPath(t *testing.T) {
	fake := &fakeExecutor{
		frrReloadPyErr: nil, // happy path
	}
	m := &Manager{exec: fake, frrConf: "/tmp/test-frr.conf"}
	if err := m.reloadForTest(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if fake.frrReloadPyCalls != 1 {
		t.Errorf("FrrReloadPy calls = %d, want 1", fake.frrReloadPyCalls)
	}
	if fake.vtyshLoadCalls != 0 {
		t.Errorf("VtyshLoad calls = %d, want 0 on happy path", fake.vtyshLoadCalls)
	}
	if fake.lastFrrReloadConf != "/tmp/test-frr.conf" {
		t.Errorf("FrrReloadPy conf = %q, want %q", fake.lastFrrReloadConf, "/tmp/test-frr.conf")
	}
	if fake.lastFrrReloadPyCtx == nil {
		t.Fatalf("FrrReloadPy called with nil context — expected the 15s WithTimeout")
	}
	if _, ok := fake.lastFrrReloadPyCtx.Deadline(); !ok {
		t.Errorf("FrrReloadPy ctx has no deadline; expected the 15s reload timeout")
	}
}

// TestReloadFallsBackToVtyshLoad verifies that reload falls through to
// VtyshLoad when the primary frr-reload.py fails, that the fallback
// gets a FRESH deadline-carrying context (never the primary's possibly
// dead one — Codex/AGY plan-r1), and that the result is the
// ErrFRRReloadDegraded sentinel wrapping the primary cause.
func TestReloadFallsBackToVtyshLoad(t *testing.T) {
	primaryErr := errors.New("frr-reload.py: vtysh socket refused")
	fake := &fakeExecutor{
		frrReloadPyErr: primaryErr,
		vtyshLoadResp:  []byte(""),
		vtyshLoadErr:   nil,
	}
	m := &Manager{exec: fake, frrConf: "/tmp/test-frr.conf"}
	err := m.reloadForTest()
	if !errors.Is(err, ErrFRRReloadDegraded) {
		t.Fatalf("reload = %v, want ErrFRRReloadDegraded", err)
	}
	if !errors.Is(err, primaryErr) {
		t.Errorf("degraded sentinel does not wrap the primary cause: %v", err)
	}
	if fake.frrReloadPyCalls != 1 {
		t.Errorf("FrrReloadPy calls = %d, want 1", fake.frrReloadPyCalls)
	}
	if fake.vtyshLoadCalls != 1 {
		t.Errorf("VtyshLoad calls = %d, want 1 (fallback)", fake.vtyshLoadCalls)
	}
	if fake.lastVtyshLoadConf != "/tmp/test-frr.conf" {
		t.Errorf("VtyshLoad conf = %q, want %q", fake.lastVtyshLoadConf, "/tmp/test-frr.conf")
	}
	if fake.lastVtyshLoadCtx == nil {
		t.Fatalf("VtyshLoad called with nil context — expected the fresh 15s WithTimeout")
	}
	if _, ok := fake.lastVtyshLoadCtx.Deadline(); !ok {
		t.Errorf("VtyshLoad ctx has no deadline; expected the fresh 15s reload timeout")
	}
	if !fake.vtyshLoadCtxLiveAtCall {
		t.Errorf("VtyshLoad ctx already dead at call time — fallback must get a fresh context")
	}
}

// TestReloadFallbackErrorPropagated verifies that when both
// frr-reload.py and vtysh -f fail, the error from VtyshLoad is wrapped
// with the captured output and returned (and is NOT the degraded
// sentinel — nothing was applied).
func TestReloadFallbackErrorPropagated(t *testing.T) {
	fake := &fakeExecutor{
		frrReloadPyErr: errors.New("frr-reload.py failed"),
		vtyshLoadResp:  []byte("syntax error at line 12"),
		vtyshLoadErr:   errors.New("exit status 1"),
	}
	m := &Manager{exec: fake, frrConf: "/tmp/test-frr.conf"}
	err := m.reloadForTest()
	if err == nil {
		t.Fatalf("reload: expected error, got nil")
	}
	if errors.Is(err, ErrFRRReloadDegraded) {
		t.Errorf("hard double-failure must not be reported as degraded: %v", err)
	}
	if !strings.Contains(err.Error(), "syntax error at line 12") {
		t.Errorf("reload error %q missing captured output", err.Error())
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("reload error %q missing underlying err", err.Error())
	}
}

// TestZeroValueManagerExecVtyshNoPanic verifies that a zero-value
// Manager — `var m frr.Manager` or `&Manager{}` — does NOT panic when
// ExecVtysh is called. The accessor returns realExecutor{} when m.exec
// is nil; the call may then fail because no vtysh binary is on PATH in
// CI, but it must not panic.
//
// Historical motivation: tests and ad-hoc callers in pkg/grpcapi /
// pkg/api have constructed literal Managers; the executor seam must not
// break that contract.
func TestZeroValueManagerExecVtyshNoPanic(t *testing.T) {
	var m Manager
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-value Manager.ExecVtysh panicked: %v", r)
		}
	}()
	// Don't assert on success — in CI there's likely no vtysh binary.
	// We just want to confirm no nil-deref via the accessor.
	_, _ = m.ExecVtysh(context.Background(), "show version")
}
