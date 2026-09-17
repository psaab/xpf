package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// lo0_vacated_enforced_6529_test.go carries the #9940 fail-on-revert proofs
// for the two zero-render shapes that survived #9883: a DEFINED-but-empty
// filter and a DEFINED filter whose terms all match nothing.
//
// The daemon must reject either shape BEFORE InstallLo0 runs. That preserves
// the prior live xpf_lo0 table, returns a commit-visible error, and logs the
// refusal. On cold start, the same refusal takes the existing #6476 fence path
// so the host input path is not left open.
//
// TestRealLo0FilterStillEnforces6529 is the anti-over-fix half and must remain
// green: a render with at least one kernel rule still installs and records
// enforcement, and a later failed install retains that real table.
//
// #9883 remains separately covered by lo0_quarantined_failclosed_9883_test.go:
// a DANGLING lo0 filter name is rejected before rendering and never reaches
// either zero-render shape.

// vacatedLo0Config returns a config whose lo0 input filters are DEFINED but
// carry no terms. It is a legitimate compiler output shape (strict compilation
// accepts it with the existing no-terminal-catch-all warning), but it is not a
// legitimate RE-protection render: swapping it would install an empty
// policy-accept shell. #9940 therefore refuses it unconditionally.
func vacatedLo0Config() *config.Config {
	cfg := hostInboundTestConfig()
	cfg.System.Lo0FilterInputV4 = "protect-re"
	cfg.System.Lo0FilterInputV6 = "protect-re6"
	// Defined-but-empty: the filters EXIST (so the #9883 dangling pre-check
	// passes) but carry no terms (so the install renders zero rules).
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re"},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"protect-re6": {Name: "protect-re6"},
	}
	return cfg
}

// TestVacatedLo0FilterRefusesEmptyRender9940 is the primary #9940 proof:
// a DEFINED-but-empty render must retain a prior real table, return an error,
// and never call the installer.
func TestVacatedLo0FilterRefusesEmptyRender9940(t *testing.T) {
	cfg := vacatedLo0Config()

	calls, fences := 0, 0
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:              func(xnft.Lo0FilterSpec) error { calls++; return nil },
		lo0ColdBootFence: func(xnft.FenceSpec) error { fences++; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	// Model the prior live real xpf_lo0 table. The fake has no kernel state,
	// so lo0Enforced is the observable retention latch.
	d.lo0Enforced.Store(true)
	logBuf, restoreLog := captureSlog(t)
	defer restoreLog()
	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("an empty lo0 render must fail closed, got nil")
	}
	if !strings.Contains(err.Error(), "renders no rules") {
		t.Fatalf("error must identify the empty render, got %v", err)
	}
	if !strings.Contains(logBuf.String(), "refusing to replace the live table with an empty policy-accept shell") {
		t.Fatalf("empty-render refusal must be operator-visible in the log, got %q", logBuf.String())
	}
	if calls != 0 {
		t.Fatalf("empty render must be refused before InstallLo0; call count=%d", calls)
	}
	if fences != 0 {
		t.Fatalf("a retained real table must not be replaced by a fence; fence count=%d", fences)
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("refusing the empty render must retain the prior real-table state")
	}
}

// TestVacatedLo0ColdStartRefusesAndFences9940 proves the no-prior-table arm:
// refusal is still visible, InstallLo0 is not called, and the existing
// fail-closed fence is installed as the only protection.
func TestVacatedLo0ColdStartRefusesAndFences9940(t *testing.T) {
	cfg := vacatedLo0Config()

	calls, fences := 0, 0
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:              func(xnft.Lo0FilterSpec) error { calls++; return nil },
		lo0ColdBootFence: func(xnft.FenceSpec) error { fences++; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	logBuf, restoreLog := captureSlog(t)
	defer restoreLog()
	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("an empty lo0 render must fail closed, got nil")
	}
	if !strings.Contains(err.Error(), "renders no rules") {
		t.Fatalf("error must identify the empty render, got %v", err)
	}
	if !strings.Contains(logBuf.String(), "refusing to replace the live table with an empty policy-accept shell") {
		t.Fatalf("cold-start empty-render refusal must be operator-visible in the log, got %q", logBuf.String())
	}
	if calls != 0 {
		t.Fatalf("empty render must be refused before InstallLo0; call count=%d", calls)
	}
	if fences != 1 {
		t.Fatalf("cold-start empty render must install one fail-closed fence; count=%d", fences)
	}
	if d.lo0Enforced.Load() {
		t.Fatal("a fence is not a real operator filter")
	}
}

// TestLo0InstallerDriftRefusesAndFences9940 covers the renderer-drift guard:
// the daemon oracle predicts a real render, but the installer reports zero
// after its atomic replacement. The now-empty live table is fenced regardless
// of whether the old latch said cold start or a real filter was loaded.
func TestLo0InstallerDriftRefusesAndFences9940(t *testing.T) {
	for _, tc := range []struct {
		name     string
		enforced bool
	}{
		{name: "cold-start-latch-false", enforced: false},
		{name: "existing-state-latch-true", enforced: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := lo0FenceTestConfig()
			zero := 0
			calls, fences := 0, 0
			orig := nftInstaller
			nftInstaller = &fakeNftInstaller{
				lo0:              func(xnft.Lo0FilterSpec) error { calls++; return nil },
				lo0Rules:         &zero,
				lo0ColdBootFence: func(xnft.FenceSpec) error { fences++; return nil },
			}
			defer func() { nftInstaller = orig }()

			d := &Daemon{}
			d.lo0Enforced.Store(tc.enforced)
			logBuf, restoreLog := captureSlog(t)
			defer restoreLog()
			err := d.applyLo0Filter(cfg)
			if err == nil {
				t.Fatal("renderer drift must fail closed, got nil")
			}
			if !strings.Contains(err.Error(), "rendered no rules") {
				t.Fatalf("renderer-drift error must identify the zero-rule parity failure, got %v", err)
			}
			if !strings.Contains(logBuf.String(), "renderer parity is broken") {
				t.Fatalf("renderer-drift failure must be operator-visible in the log, got %q", logBuf.String())
			}
			if calls != 1 {
				t.Fatalf("renderer drift must reach InstallLo0 once before the guard; call count=%d", calls)
			}
			if fences != 1 {
				t.Fatalf("renderer drift must install one fail-closed fence for %s; count=%d", tc.name, fences)
			}
			if d.lo0Enforced.Load() {
				t.Fatal("renderer drift must clear the real-filter latch")
			}
		})
	}
}

// TestMatchNothingLo0RenderRefuses9940 proves the second residual shape:
// terms are present in both family pools, but each term is constrained to the
// opposite address family and therefore lowers to no kernel rules.
func TestMatchNothingLo0RenderRefuses9940(t *testing.T) {
	cfg := lo0FenceTestConfig()
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "nothing-v4", SourceAddresses: []string{"2001:db8::/32"}, Action: "discard"},
		}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"protect-re6": {Name: "protect-re6", Terms: []*config.FirewallFilterTerm{
			{Name: "nothing-v6", SourceAddresses: []string{"10.0.0.0/8"}, Action: "discard"},
		}},
	}

	calls, fences := 0, 0
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:              func(xnft.Lo0FilterSpec) error { calls++; return nil },
		lo0ColdBootFence: func(xnft.FenceSpec) error { fences++; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	d.lo0Enforced.Store(true)
	logBuf, restoreLog := captureSlog(t)
	defer restoreLog()
	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("a match-nothing lo0 render must fail closed, got nil")
	}
	if !strings.Contains(err.Error(), "renders no rules") {
		t.Fatalf("error must identify the match-nothing render, got %v", err)
	}
	if !strings.Contains(logBuf.String(), "refusing to replace the live table with an empty policy-accept shell") {
		t.Fatalf("match-nothing refusal must be operator-visible in the log, got %q", logBuf.String())
	}
	if calls != 0 {
		t.Fatalf("match-nothing render must be refused before InstallLo0; call count=%d", calls)
	}
	if fences != 0 {
		t.Fatalf("a retained real table must not be replaced by a fence; fence count=%d", fences)
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("refusing the match-nothing render must retain the prior real-table state")
	}
}

// TestRealLo0FilterStillEnforces6529 is the anti-over-fix half: a real filter
// that renders rules must still set lo0Enforced, and a later failed install
// must still SKIP the fence — the deliberate #6476/#6489 day-2 divergence.
func TestRealLo0FilterStillEnforces6529(t *testing.T) {
	cfg := lo0FenceTestConfig()
	injected := errors.New("nftables: injected day-2 lo0 failure")

	failNext := false
	fences := 0
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error {
			if failNext {
				return injected
			}
			return nil
		},
		lo0ColdBootFence: func(xnft.FenceSpec) error { fences++; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	if err := d.applyLo0Filter(cfg); err != nil {
		t.Fatalf("real install: %v", err)
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("a real filter that renders rules must record enforcement")
	}

	failNext = true
	if err := d.applyLo0Filter(cfg); err == nil {
		t.Fatal("the day-2 failure must be surfaced")
	}
	if fences != 0 {
		t.Fatalf("with a REAL filter retained, a day-2 failure must NOT fence (#6489 divergence); "+
			"fence install count = %d, want 0", fences)
	}
}
