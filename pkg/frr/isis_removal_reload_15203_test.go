package frr

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// isisRemovalExecutor15203 models the exact A12-06 mechanism: the running
// config still carries IS-IS on an interface, the desired config removes it,
// and frr-reload.py deletes `ip router isis` before the per-interface
// `no isis circuit-type`, which isisd then rejects (YANG area-tag missing).
// The end state is already correct, so a re-check with `frr-reload.py --test`
// finds no diff. `testErr` models a genuine non-convergence instead.
type isisRemovalExecutor15203 struct {
	reloadErr    error
	testErr      error
	extraLoadErr error

	reloadCalls  int
	testCalls    int
	loadCalls    int
	loadContents []string
}

func (e *isisRemovalExecutor15203) Vtysh(context.Context, string) (string, error) {
	return "", nil
}

func (e *isisRemovalExecutor15203) FrrReloadPy(context.Context, string) error {
	e.reloadCalls++
	return e.reloadErr
}

func (e *isisRemovalExecutor15203) FrrReloadPyTest(context.Context, string) error {
	e.testCalls++
	return e.testErr
}

func (e *isisRemovalExecutor15203) VtyshLoad(_ context.Context, conf string) ([]byte, error) {
	e.loadCalls++
	b, _ := os.ReadFile(conf)
	e.loadContents = append(e.loadContents, string(b))
	return nil, e.extraLoadErr
}

func (e *isisRemovalExecutor15203) VtyshLoadDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func (e *isisRemovalExecutor15203) VtyshDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func (e *isisRemovalExecutor15203) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

// TestISISRemovalBenignReloadIsConverged15203 pins A12-06: removing IS-IS
// from an interface renders no `router isis` / `ip router isis` /
// `isis circuit-type` lines, frr-reload.py fails the dependent removal, but
// the end state is correct (`--test` shows no diff), so the commit must
// return nil — not the degraded sentinel and not a hard failure.
func TestISISRemovalBenignReloadIsConverged15203(t *testing.T) {
	m0 := &Manager{}
	rendered := m0.generateProtocols(nil, nil, nil, nil, nil, "", 0, nil, nil)
	if strings.Contains(rendered, "router isis") || strings.Contains(rendered, "isis circuit-type") {
		t.Fatalf("removal render still carries IS-IS lines:\n%s", rendered)
	}
	withISIS := m0.generateProtocols(nil, nil, nil, nil,
		&config.ISISConfig{NET: "49.0001.1921.6800.1001.00", Level: "level-1-2",
			Interfaces: []*config.ISISInterface{{Name: "ge-0-0-1", Level: "level-1-2", Passive: true}}},
		"", 0, nil, nil)
	for _, want := range []string{"router isis xpf", "interface ge-0-0-1", " ip router isis xpf", " isis circuit-type level-1-2", " isis passive"} {
		if !strings.Contains(withISIS, want) {
			t.Fatalf("pre-removal render missing %q:\n%s", want, withISIS)
		}
	}

	reloadErr := errors.New("frr-reload.py: no isis circuit-type: YANG area-tag missing")
	exec := &isisRemovalExecutor15203{reloadErr: reloadErr}
	conf := filepath.Join(t.TempDir(), "frr.conf")
	m := NewForTest(conf, exec)
	seed := markerBegin + "\n" + withISIS + markerEnd + "\n"
	if err := os.WriteFile(conf, []byte(seed), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := m.ApplyFull(&FullConfig{}); err != nil {
		t.Fatalf("IS-IS removal commit = %v, want nil (benign frr-reload failure, end state correct)", err)
	}
	if m.ReloadDegraded() {
		t.Fatal("benign IS-IS removal must not set the degraded gauge")
	}
	if exec.reloadCalls != 1 || exec.testCalls != 1 {
		t.Fatalf("reload/test calls = %d/%d, want 1/1", exec.reloadCalls, exec.testCalls)
	}
	if exec.loadCalls != 0 {
		t.Fatalf("VtyshLoad calls = %d, want 0 (no additive fallback needed once --test proves convergence)", exec.loadCalls)
	}
}

// TestReloadBenignRecheckStillDegradesWhenDiffRemains15203 is the
// fail-closed control: when the `--test` re-check still finds a diff (a
// genuine non-convergence), the reload must NOT be certified — it falls
// back additively and reports degraded, preserving both causes on a hard
// double failure.
func TestReloadBenignRecheckStillDegradesWhenDiffRemains15203(t *testing.T) {
	reloadErr := errors.New("frr-reload.py: rejected line")

	t.Run("test finds remaining diff", func(t *testing.T) {
		diffErr := errors.New("frr-reload.py --test: lines to delete remain")
		exec := &isisRemovalExecutor15203{reloadErr: reloadErr, testErr: diffErr}
		m := &Manager{exec: exec, frrConf: filepath.Join(t.TempDir(), "frr.conf")}
		err := m.reloadForTest()
		if !errors.Is(err, ErrFRRReloadDegraded) {
			t.Fatalf("reload = %v, want ErrFRRReloadDegraded", err)
		}
		if !errors.Is(err, reloadErr) {
			t.Fatalf("degraded error must wrap the primary cause: %v", err)
		}
		if exec.loadCalls != 1 {
			t.Fatalf("VtyshLoad calls = %d, want 1 (additive fallback)", exec.loadCalls)
		}
	})

	t.Run("primary hard failure stays hard", func(t *testing.T) {
		loadErr := errors.New("vtysh -f exit status 1")
		exec := &isisRemovalExecutor15203{reloadErr: reloadErr, testErr: errors.New("diff remains"), extraLoadErr: loadErr}
		m := &Manager{exec: exec, frrConf: filepath.Join(t.TempDir(), "frr.conf")}
		err := m.reloadForTest()
		if err == nil || errors.Is(err, ErrFRRReloadDegraded) {
			t.Fatalf("reload = %v, want a non-degraded hard failure", err)
		}
		if !errors.Is(err, loadErr) || !errors.Is(err, reloadErr) {
			t.Fatalf("hard error must preserve both causes: %v", err)
		}
	})
}
