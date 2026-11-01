package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// lo0_vacated_enforced_6529_test.go carries the #9940 proofs for the two
// shapes that used to render zero rules after #9883: a DEFINED-but-empty
// filter and a DEFINED filter whose terms all match nothing.
//
// Before #18728 both rendered an empty policy-accept shell, so the daemon
// refused them BEFORE InstallLo0 (retaining the prior table, or fencing on
// cold start). Since #18728 neither has a terminal catch-all, so each family
// renders the Junos implicit final discard: the filter is a real
// discard-everything filter (except the exempt netdevs) and INSTALLS. The
// cells below pin that; the zero-render refusal itself is kept as a
// defensive preflight that no defined filter reaches any more, and the
// renderer-drift guard (TestLo0InstallerDriftRefusesAndFences9940) still
// covers a post-install zero count.
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
// accepts it with the no-terminal-catch-all warning). Since #18728 it is the
// Junos empty filter: it discards all host-bound traffic but the exempt
// netdevs.
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

// installsImplicitDiscardOnly18728 runs applyLo0Filter against a fake
// installer and asserts the #18728 outcome for a filter whose authored terms
// render nothing: InstallLo0 runs once, both families carry the implicit
// discard with the "lo" exemption, no fence is installed, and the real-filter
// latch is set.
func installsImplicitDiscardOnly18728(t *testing.T, cfg *config.Config, priorEnforced bool) xnft.Lo0FilterSpec {
	t.Helper()
	calls, fences := 0, 0
	var spec xnft.Lo0FilterSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:              func(s xnft.Lo0FilterSpec) error { calls++; spec = s; return nil },
		lo0ColdBootFence: func(xnft.FenceSpec) error { fences++; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	d.lo0Enforced.Store(priorEnforced)
	if err := d.applyLo0Filter(cfg); err != nil {
		t.Fatalf("a no-catch-all lo0 filter renders its implicit discard and must install, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("InstallLo0 call count=%d, want 1", calls)
	}
	if fences != 0 {
		t.Fatalf("a real (implicit-discard) filter must not be replaced by a fence; fence count=%d", fences)
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("the installed implicit-discard filter is a real operator filter; lo0Enforced must be set")
	}
	if !spec.ImplicitDiscardV4 || !spec.ImplicitDiscardV6 {
		t.Fatalf("both families must carry the implicit discard, got v4=%v v6=%v", spec.ImplicitDiscardV4, spec.ImplicitDiscardV6)
	}
	if len(spec.ImplicitDiscardExemptNetdevs) == 0 || spec.ImplicitDiscardExemptNetdevs[0] != "lo" {
		t.Fatalf("implicit discard must exempt loopback first, got %v", spec.ImplicitDiscardExemptNetdevs)
	}
	return spec
}

// TestVacatedLo0FilterInstallsImplicitDiscard18728 (formerly the #9940
// empty-render refusal): a DEFINED-but-empty lo0 filter replaces a prior
// real table with the Junos discard-everything filter, never an empty
// policy-accept shell.
func TestVacatedLo0FilterInstallsImplicitDiscard18728(t *testing.T) {
	cfg := vacatedLo0Config()
	if got := lo0RenderedRuleCount(cfg, "protect-re", "protect-re6"); got != 2 {
		t.Fatalf("daemon preflight count = %d, want 2 (one implicit discard per family)", got)
	}
	spec := installsImplicitDiscardOnly18728(t, cfg, true)
	if len(spec.V4Terms)+len(spec.V6Terms) != 0 {
		t.Fatalf("an empty filter has no authored terms, got %+v", spec)
	}
	payload := buildLo0FilterPayload(cfg, "protect-re", "protect-re6")
	for _, fam := range []string{"ipv4", "ipv6"} {
		if !strings.Contains(payload, "meta nfproto "+fam+" iifname != ") {
			t.Errorf("oracle lacks the %s implicit discard:\n%s", fam, payload)
		}
	}
}

// TestVacatedLo0ColdStartInstallsImplicitDiscard18728: the same shape on cold
// start installs the real filter instead of falling back to the fence.
func TestVacatedLo0ColdStartInstallsImplicitDiscard18728(t *testing.T) {
	installsImplicitDiscardOnly18728(t, vacatedLo0Config(), false)
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

// TestMatchNothingLo0RenderInstallsImplicitDiscard18728 (formerly the #9940
// match-nothing refusal): terms are present in both family pools but each is
// constrained to the opposite address family and lowers to no kernel rule.
// The filters have no catch-all, so each family renders its implicit discard
// and the filter installs.
func TestMatchNothingLo0RenderInstallsImplicitDiscard18728(t *testing.T) {
	cfg := lo0FenceTestConfig()
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "nothing-v4", SourceAddresses: []string{"2001:db8::/32"}, Action: config.FilterActionDiscard},
		}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"protect-re6": {Name: "protect-re6", Terms: []*config.FirewallFilterTerm{
			{Name: "nothing-v6", SourceAddresses: []string{"10.0.0.0/8"}, Action: config.FilterActionDiscard},
		}},
	}
	if got := lo0RenderedRuleCount(cfg, "protect-re", "protect-re6"); got != 2 {
		t.Fatalf("daemon preflight count = %d, want 2 (the match-nothing terms render nothing; one implicit discard per family)", got)
	}
	installsImplicitDiscardOnly18728(t, cfg, true)
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
