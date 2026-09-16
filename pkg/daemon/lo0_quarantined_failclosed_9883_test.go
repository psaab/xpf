package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// lo0_quarantined_failclosed_9883_test.go are the #9883 GPT-HIGH fail-on-revert
// proofs: a lo0 hook naming a QUARANTINED unknown-family filter must fail closed
// in the kernel lo0 consumer too — not install an empty `policy accept` shell.
//
// Chain (tolerant boot/peer-sync): the unknown-family filter disappears from
// FiltersInet (quarantine) but the lo0 reference survives
// (compiler_derivations.go extracts FilterInputV4 unconditionally),
// toNftLo0Spec's map lookup silently yields no terms, and InstallLo0 commits
// that empty shell SUCCESSFULLY. Before this fix the #6529 zero-rules branch
// cleared the gate but left the kernel open until the NEXT failure — on
// existing-state it atomically REPLACED a live real filter, on cold-start it
// left boot open with no fence.
//
// The dangling pre-check in applyLo0Filter fails closed WITHOUT installing:
//   - cold-start (!enforced): install the #6476 fence, surface an error.
//   - existing-state (enforced): retain the prior real filter (no install, no
//     fence — the #6489 divergence), surface an error.
//
// Both cells drive the PRODUCTION path end-to-end from a lenient compile (the
// tolerant ingress that admits the quarantine+dangle), not from a hand-built
// vacated struct: CompileConfigLenient(braced inett + lo0 hook) -> applyLo0Filter.
// Revert the pre-check and both go RED (InstallLo0 called with an empty spec,
// no fence on cold-start, prior real replaced on existing-state).

// lenientQuarantinedLo0Config9883 compiles a braced unknown-family filter hooked
// by lo0 on the tolerant path and pins the quarantine+dangle preconditions: the
// filter is out of BOTH pools, the lo0 hook survives, and BOTH warnings (unknown
// token + dangling reference) are present. The ge-0/0/0 addressed interface gives
// the cold-start fence a scoped drop (unzoned, so it renders via the unzoned set).
func lenientQuarantinedLo0Config9883(t *testing.T) *config.Config {
	t.Helper()
	text := `firewall {
		family inett {
			filter BAD { term T1 { then { discard; } } }
		}
	}
	interfaces {
		lo0 {
			unit 0 {
				family inet {
					filter { input BAD; }
				}
			}
		}
		ge-0/0/0 {
			unit 0 {
				family inet {
					address 10.0.0.1/24;
				}
			}
		}
	}`
	root, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse hierarchical: %v", perrs)
	}
	tree := &config.ConfigTree{Children: root.Children}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on a quarantined lo0 hook (#1960): %v", err)
	}
	// Quarantine holds: BAD out of both pools.
	if _, ok := cfg.Firewall.FiltersInet["BAD"]; ok {
		t.Fatal("precondition: quarantine breach — BAD landed in FiltersInet")
	}
	if _, ok := cfg.Firewall.FiltersInet6["BAD"]; ok {
		t.Fatal("precondition: quarantine breach — BAD landed in FiltersInet6")
	}
	// The lo0 hook survives (only its target is absent).
	if cfg.System.Lo0FilterInputV4 != "BAD" {
		t.Fatalf("precondition: lo0 hook lost — Lo0FilterInputV4=%q, want %q",
			cfg.System.Lo0FilterInputV4, "BAD")
	}
	// Both warnings true at once (unknown token + dangling reference).
	var tokenWarned, danglingWarned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "inett") {
			tokenWarned = true
		}
		if strings.Contains(w, "undefined filter") {
			danglingWarned = true
		}
	}
	if !tokenWarned {
		t.Fatalf("precondition: missing unknown-token warning (warnings=%v)", cfg.Warnings)
	}
	if !danglingWarned {
		t.Fatalf("precondition: missing dangling-reference warning for the hooked quarantine (warnings=%v)", cfg.Warnings)
	}
	return cfg
}

// TestQuarantinedLo0ColdStartFences9883: on cold-start (no prior real filter) a
// lenient quarantined-dangling lo0 generation must NOT install an empty shell —
// it must install the fail-closed fence and surface an error.
func TestQuarantinedLo0ColdStartFences9883(t *testing.T) {
	cfg := lenientQuarantinedLo0Config9883(t)

	lo0Calls, fenceCalls := 0, 0
	var fenceSpec xnft.FenceSpec
	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{
		lo0: func(xnft.Lo0FilterSpec) error { lo0Calls++; return nil },
		lo0ColdBootFence: func(s xnft.FenceSpec) error {
			fenceSpec = s
			fenceCalls++
			return nil
		},
	}
	defer func() { nftInstaller = orig }()

	d := &Daemon{}
	if d.lo0Enforced.Load() {
		t.Fatal("precondition: cold boot means lo0Enforced false")
	}
	err := d.applyLo0Filter(cfg)
	if err == nil {
		t.Fatal("a dangling lo0 reference must be surfaced as an error (fail closed), got nil")
	}
	if !strings.Contains(err.Error(), "BAD") || !strings.Contains(err.Error(), "not defined") {
		t.Fatalf("error must name the dangling filter, got: %v", err)
	}
	if lo0Calls != 0 {
		t.Fatalf("InstallLo0 must NOT be called for a dangling reference (it would commit an "+
			"empty policy-accept shell); call count = %d, want 0", lo0Calls)
	}
	if fenceCalls != 1 {
		t.Fatalf("cold-start dangling must install the fail-closed fence; fence count = %d, want 1", fenceCalls)
	}
	// The fence must be SCOPED (not a zero-drop shell): the ge-0/0/0 address is
	// unzoned, so it renders via the unzoned set.
	if got := fenceViewAddrs(fenceSpec, false); !sliceContains(got, "10.0.0.1") {
		t.Fatalf("cold-start fence must scope the firewall-local address 10.0.0.1, got v4=%v", got)
	}
	if d.lo0Enforced.Load() {
		t.Fatal("a fence is not a real filter — lo0Enforced must stay false so a later failed " +
			"install re-fences from the then-current snapshot (#6489)")
	}
}

// TestQuarantinedLo0ExistingStateRetains9883: with a prior REAL filter live, a
// lenient quarantined-dangling generation must RETAIN it — no install (which
// would atomically replace the real filter with an empty shell), no fence (the
// #6489 divergence: a retained real filter governs every local address), and
// the error surfaced so the commit fails.
func TestQuarantinedLo0ExistingStateRetains9883(t *testing.T) {
	real := lo0FenceTestConfig()

	orig := nftInstaller
	nftInstaller = &fakeNftInstaller{}
	d := &Daemon{}
	if err := d.applyLo0Filter(real); err != nil {
		t.Fatalf("real install: %v", err)
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("precondition: a real rendering filter must set lo0Enforced")
	}

	dangling := lenientQuarantinedLo0Config9883(t)
	lo0Calls, fenceCalls := 0, 0
	nftInstaller = &fakeNftInstaller{
		lo0:              func(xnft.Lo0FilterSpec) error { lo0Calls++; return nil },
		lo0ColdBootFence: func(xnft.FenceSpec) error { fenceCalls++; return nil },
	}
	defer func() { nftInstaller = orig }()

	err := d.applyLo0Filter(dangling)
	if err == nil {
		t.Fatal("a dangling lo0 reference must be surfaced as an error (fail closed), got nil")
	}
	if !strings.Contains(err.Error(), "BAD") {
		t.Fatalf("error must name the dangling filter, got: %v", err)
	}
	if lo0Calls != 0 {
		t.Fatalf("InstallLo0 must NOT be called for a dangling reference — it would atomically "+
			"REPLACE the live real filter with an empty shell; call count = %d, want 0", lo0Calls)
	}
	if fenceCalls != 0 {
		t.Fatalf("with a REAL filter retained, a dangling generation must NOT fence (#6489 "+
			"divergence); fence count = %d, want 0", fenceCalls)
	}
	if !d.lo0Enforced.Load() {
		t.Fatal("the prior real filter was retained (no install), so lo0Enforced must stay true")
	}
}
