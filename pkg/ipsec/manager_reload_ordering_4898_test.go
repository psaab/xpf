package ipsec

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// #4898: two coupled reload-error / state-ordering defects in Manager.Apply.
//  1. clearConfig() swallowed the reload error on the empty-config branch
//     (`_ = m.reload(); return nil`), so deleting the last VPN reported success
//     even when `swanctl --load-all` failed and charon kept the old connection
//     loaded — a decommissioned/compromised peer stayed authorized.
//  2. prevConnNames was advanced (swapConnNames) and removed SAs terminated
//     BEFORE the reload succeeded, so a failed reload forgot the still-loaded
//     connection and tore down a still-effective tunnel.
//
// The fix gates promotion + teardown on reload success and makes clearConfig
// propagate the reload error like applyConfig (the #4433 contract).

// reloadRecorder is a swanctl exec double that records every invocation and can
// force `swanctl --load-all` to fail on demand, exercising the reload-failure
// branches. It is independent of swanctlRecorder (delete_terminate_3941_test.go)
// so toggling --load-all failure does not perturb those tests.
type reloadRecorder struct {
	calls       [][]string
	listSAs     string
	listConns   []byte
	listPools   []byte
	failLoadAll bool
	loadErr     error
}

func (r *reloadRecorder) run(args ...string) ([]byte, error) {
	r.calls = append(r.calls, args)
	switch {
	case len(args) > 0 && args[0] == "--load-all" && r.failLoadAll:
		return []byte("unable to load config"), r.loadErr
	case len(args) > 0 && args[0] == "--list-sas":
		return []byte(r.listSAs), nil
	case len(args) > 0 && args[0] == "--list-conns":
		return r.listConns, nil
	case len(args) > 0 && args[0] == "--list-pools":
		return r.listPools, nil
	}
	return nil, nil
}

func listConns4898(names ...string) []byte {
	var b strings.Builder
	for _, name := range names {
		b.WriteString("list-conn event {" + name + " {children {" + name + " {}}}}\n")
	}
	b.WriteString("list-conns reply {}\n")
	return []byte(b.String())
}

func (r *reloadRecorder) terminated() []string {
	var out []string
	for _, c := range r.calls {
		if len(c) == 4 && c[0] == "--terminate" && c[1] == "--ike" && c[3] == "--force" {
			out = append(out, c[2])
		}
	}
	return out
}

func (m *Manager) tracks(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prevConnNames[name]
}

// TestClearReloadFailurePropagatesAndPreservesState covers defect (1): deleting
// the last VPN (Apply(nil) → clearConfig) with `--load-all` failing must RETURN
// the error, must NOT terminate the still-loaded connection, and must keep
// prevConnNames so a later successful clear retries the teardown.
//
// fail-on-revert: restore `_ = m.reload(); return nil` in clearConfig and
// Apply(nil) returns nil → the `err == nil` assertion fails RED.
func TestClearReloadFailurePropagatesAndPreservesState(t *testing.T) {
	reloadErr := errors.New("charon vici socket refused")
	rec := &reloadRecorder{loadErr: reloadErr}
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = rec.run

	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	priorConfig, readErr := os.ReadFile(m.configPath)
	if readErr != nil {
		t.Fatalf("FIXTURE: read prior config: %v", readErr)
	}
	rec.listPools = poolsForPrior17882(t, priorConfig)
	rec.listConns = listConns4898("site-a")

	// Reload now fails; delete the only VPN.
	rec.failLoadAll = true
	rec.listSAs = liveSA("site-a")
	err := m.Apply(nil)
	if err == nil {
		t.Fatal("Apply(nil) must return the swanctl --load-all failure, not nil " +
			"(clearConfig swallowed it → false teardown success while the peer " +
			"stays authorized)")
	}
	if !errors.Is(err, reloadErr) {
		t.Fatalf("Apply error must wrap the underlying reload error, got %v", err)
	}
	if got := rec.terminated(); len(got) != 0 {
		t.Fatalf("a failed reload must not terminate any connection (site-a is "+
			"still the loaded, effective config), got %v", got)
	}
	if !m.tracks("site-a") {
		t.Fatal("prevConnNames must still track site-a after a failed clear so a " +
			"later successful clear retries its teardown")
	}

	// Reload recovers; clear again → site-a's SA is finally torn down.
	rec.failLoadAll = false
	if err := m.Apply(nil); err != nil {
		t.Fatalf("retry clear Apply: %v", err)
	}
	if got := rec.terminated(); len(got) != 1 || got[0] != "site-a" {
		t.Fatalf("the recovered clear must terminate the still-loaded site-a, got %v", got)
	}
}

// TestReplaceReloadFailurePreservesRemovedConn covers defect (2): replacing
// site-a with site-b while the reload fails must NOT advance prevConnNames to
// {site-b} and must NOT terminate site-a's still-effective SA.
//
// fail-on-revert: restore swapConnNames-before-reload + unconditional
// terminateRemovedConns and a failed reload advances prevConnNames to {site-b}
// AND terminates site-a → the tracking + terminate assertions fail RED.
func TestReplaceReloadFailurePreservesRemovedConn(t *testing.T) {
	reloadErr := errors.New("malformed peer config")
	rec := &reloadRecorder{loadErr: reloadErr}
	m := NewWithConfigDir(t.TempDir())
	m.swanctl = rec.run

	if err := m.Apply(vpnCfg("site-a")); err != nil {
		t.Fatalf("initial Apply: %v", err)
	}
	priorConfig, readErr := os.ReadFile(m.configPath)
	if readErr != nil {
		t.Fatalf("FIXTURE: read prior config: %v", readErr)
	}
	rec.listPools = poolsForPrior17882(t, priorConfig)
	rec.listConns = listConns4898("site-a")
	rec.listSAs = liveSA("site-a")

	// Replace site-a with site-b, but the reload fails.
	rec.failLoadAll = true
	if err := m.Apply(vpnCfg("site-b")); err == nil {
		t.Fatal("replace Apply must return the reload failure")
	}

	if got := rec.terminated(); len(got) != 0 {
		t.Fatalf("a failed reload must not terminate the still-loaded site-a, got %v", got)
	}
	if !m.tracks("site-a") {
		t.Fatal("prevConnNames advanced past a failed reload: site-a forgotten " +
			"while it is still the loaded config, so a later Clear won't retry it")
	}
	if m.tracks("site-b") {
		t.Fatal("prevConnNames advanced to site-b despite the reload failure " +
			"(site-b was never actually loaded)")
	}
}
