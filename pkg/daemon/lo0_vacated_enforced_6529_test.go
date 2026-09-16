package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// lo0_vacated_enforced_6529_test.go are the #6529 fail-on-revert proofs. A
// VACATED lo0 filter — one that installs cleanly but renders NO kernel rules —
// used to set lo0Enforced=true on the unconditional success path, which
// permanently suppressed the #6476 cold-boot fence: with the flag true every
// later failed install skips the fence and the host input path stays open.
//
// Revert the `if rules == 0` branch in applyLo0Filter and every test here goes
// RED except TestRealLo0FilterStillEnforces6529, which is the anti-over-fix
// half and must stay green under both.
//
// Production call path: applyLo0Filter -> toNftLo0Spec ->
// nftInstaller.InstallLo0(spec) (which now reports the RENDERED rule count from
// nlPlan.rules) -> the lo0Enforced decision -> the `!lo0Enforced` fence gate on
// the next failed install.
//
// #9883: a DANGLING lo0 filter name (configured but not defined — a quarantined
// unknown-family filter on the tolerant path, or any typo'd hook) NO LONGER
// reaches the zero-rules branch: the dangling pre-check in applyLo0Filter fails
// it closed WITHOUT installing (fence on cold-start, retain on existing-state).
// These proofs therefore use a DEFINED-but-empty vacated shape (filters present
// with no terms) — the zero-rules door that CAN occur on a clean commit and must
// still clear the gate without fencing. Dangling fail-closed is proven in
// lo0_quarantined_failclosed_9883_test.go.

// vacatedLo0Config returns a config whose lo0 input filters are DEFINED but carry
// no terms, so toNftLo0Spec yields no terms and the installed xpf_lo0 table is an
// empty `policy accept` shell. This is the #6529 zero-rules shape that survives
// #9883: strict ACCEPTS an empty filter, so it CAN occur on a clean commit and
// must clear the gate without fencing (unlike a DANGLING name, which strict
// rejects and #9883 fails closed before installing).
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

// TestVacatedLo0FilterDoesNotClaimEnforcement6529 is the primary proof and the
// issue's first acceptance criterion: a DEFINED-but-empty filter (no terms) must
// NOT set lo0Enforced. (#9883: a DANGLING name no longer reaches this branch —
// it fails closed before installing; see lo0_quarantined_failclosed_9883_test.go.)
func TestVacatedLo0FilterDoesNotClaimEnforcement6529(t *testing.T) {
	cfg := vacatedLo0Config()

	var got xnft.Lo0FilterSpec
	calls := 0
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(s xnft.Lo0FilterSpec) error { got = s; calls++; return nil },
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	if err := d.applyLo0Filter(cfg); err != nil {
		t.Fatalf("a vacated install still SUCCEEDS; applyLo0Filter must not error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("InstallLo0 call count = %d, want 1", calls)
	}
	// Precondition: this really is the vacated shape — the install went through
	// with an empty spec, not with a filter that happened to render something.
	// (Defined-but-empty lowers to no terms, exactly as a dangling name did
	// before #9883 moved dangling to the fail-closed pre-check.)
	if len(got.V4Terms)+len(got.V6Terms) != 0 {
		t.Fatalf("precondition: a defined-but-empty filter must lower to NO terms, got v4=%d v6=%d",
			len(got.V4Terms), len(got.V6Terms))
	}
	if d.lo0Enforced.Load() {
		t.Fatal("a lo0 table that renders NO rules enforces nothing; recording it as a real " +
			"operator filter permanently suppresses the #6476 cold-boot fence (the #6529 hole)")
	}
}

// TestVacatedLo0ThenFailedInstallStillFences6529 is the issue's second
// acceptance criterion: after the vacated install, a later FAILED install must
// still install the fence.
func TestVacatedLo0ThenFailedInstallStillFences6529(t *testing.T) {
	cfg := vacatedLo0Config()
	injected := errors.New("nftables: injected lo0 failure")

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
		t.Fatalf("vacated install: %v", err)
	}

	// Now a real filter appears in the config but its install fails.
	failNext = true
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"protect-re": {Name: "protect-re", Terms: []*config.FirewallFilterTerm{
			{Name: "deny-rest", Action: "discard"},
		}},
	}
	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("the failed install must be surfaced as an error")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned error must wrap the injected failure, got %v", err)
	}
	if fences != 1 {
		t.Fatalf("the earlier VACATED install must not have suppressed the fence; "+
			"cold-boot fence install count = %d, want 1", fences)
	}
}

// TestVacatedLo0ClearsAPriorRealFilter6529 pins the half a "don't Store(true)"
// fix would miss. On an HA peer-sync a DEFINED-but-empty vacated generation
// atomically REPLACES a real filter that is already live, so the kernel loses
// its rules. Leaving the flag at its stale true would keep suppressing the
// fence — the same hole through a different door. The vacated branch must
// Store(FALSE), mirroring the no-filter teardown (#5790 parity). (#9883: a
// DANGLING generation does NOT replace — the pre-check retains the prior real
// filter and keeps the flag true; see lo0_quarantined_failclosed_9883_test.go.)
func TestVacatedLo0ClearsAPriorRealFilter6529(t *testing.T) {
	real := lo0FenceTestConfig()
	vacated := vacatedLo0Config()

	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	if err := d.applyLo0Filter(real); err != nil {
		t.Fatalf("real install: %v", err)
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("precondition: a real rendering filter must set lo0Enforced")
	}

	if err := d.applyLo0Filter(vacated); err != nil {
		t.Fatalf("vacated install: %v", err)
	}
	if d.lo0Enforced.Load() {
		t.Fatal("the vacated generation atomically REPLACED the real filter; the kernel table " +
			"now enforces nothing, so the stale true must be cleared or the fence stays suppressed")
	}
}

// TestZeroRenderedRulesClearsEnforcement6529 pins the decision on the RENDERED
// rule count rather than on "the spec had terms". The second remaining door into
// a zero-rule install (the dangling-name door moved to the #9883 fail-closed
// pre-check) is a DEFINED filter whose every term lowers to zero kernel rules —
// a Junos match-nothing scope, e.g. an unresolved `from source-prefix-list` on
// the lenient path. pkg/nftables/netlink_lo0_zero_render_6529_test.go proves that
// door is real against the production builder; this pins the consequence, with
// the fake reporting the count the real builder would.
func TestZeroRenderedRulesClearsEnforcement6529(t *testing.T) {
	cfg := lo0FenceTestConfig() // a filter WITH terms
	zero := 0

	var got xnft.Lo0FilterSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0:      func(s xnft.Lo0FilterSpec) error { got = s; return nil },
		lo0Rules: &zero,
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	if err := d.applyLo0Filter(cfg); err != nil {
		t.Fatalf("applyLo0Filter: %v", err)
	}
	// Precondition: the spec DID carry terms, so a term-count gate would have
	// wrongly recorded enforcement here.
	if len(got.V4Terms)+len(got.V6Terms) == 0 {
		t.Fatal("precondition: this case must have terms; otherwise it is the defined-empty case")
	}
	if d.lo0Enforced.Load() {
		t.Fatal("terms that render NO kernel rules enforce nothing; the gate must key on the " +
			"RENDERED rule count, not on the presence of terms")
	}
}

// TestRealLo0FilterStillEnforces6529 is the anti-over-fix half: a real filter
// that renders rules must still set lo0Enforced, and a later failed install must
// still SKIP the fence — the deliberate #6476/#6489 day-2 divergence (the
// retained operator filter is not per-destination-address scoped, so lo0 needs
// no gap fence). A fix that cleared the flag too eagerly would re-fence over a
// live operator filter and turn this RED.
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
