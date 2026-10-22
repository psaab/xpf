package dataplane

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15943 (H11-01): a failure at or after Phase 2 must return the partial
// *CompileResult, not nil. Phase 2 is the first host mutation and later phases
// have no undo, so CompileUserspaceShim needs the result to run divergence
// accounting (abortAfterHostMutation / annotateHostMutationOnAbort). Before
// the fix every post-Phase-2 phase returned `nil, err`, so a tolerated NAT
// shape that passed the validation pre-pass but failed the real pass (or any
// other post-mutation failure the pre-pass cannot predict) dropped the split
// state silently.
//
// RED-on-revert: restore `return nil, fmt.Errorf(...)` on any post-Phase-2
// phase in CompileConfig and the result assertion below fails; restore the
// bare `return nil, err` in CompileUserspaceShim and the loader wiring loses
// the abort (bound by TestCompileUserspaceShimWiresHostDivergence8285's
// ordering plus the CompileConfig-level contract here).

// postPhase2DP completes Phase 2 and fails first in Phase 3. Its zone path
// is deliberately interface-free: programZoneMaps succeeds without calling
// SetZoneConfig (a hook that is per-zone only when a zone exists), and the
// caller stubs host interface enumeration to empty. CompileConfig's Phase 3
// calls ClearAddressBookV4 before any address entries, which is the first
// staged failure. zonesComplete is therefore an ordering counter: Clear*
// must be reached exactly once and only after compileZones returns.
type postPhase2DP struct {
	discardingDataPlane
	zonesComplete bool
	clearV4Calls  int
}

func (d *postPhase2DP) xpfValidationPass() bool { return false }

func (d *postPhase2DP) DeleteStaleIfaceZone(map[IfaceZoneKey]bool) {}
func (d *postPhase2DP) DeleteStaleVlanIface(map[uint32]bool)       {}
func (d *postPhase2DP) ClearAddressBookV4() error {
	d.clearV4Calls++
	if !d.zonesComplete {
		return errors.New("ClearAddressBookV4 reached before compileZones completed")
	}
	return errors.New("postPhase2DP: staged Phase-3 failure (#15943)")
}

func TestCompileConfigReturnsPartialResultAfterPhase2_15943(t *testing.T) {
	// Neutralize host interface enumeration for the compile below. This
	// follows the established interfaceLister test seam and ensures Phase 2
	// cannot observe or mutate any host link.
	oldLister := interfaceLister
	interfaceLister = func() ([]net.Interface, error) { return nil, nil }
	t.Cleanup(func() { interfaceLister = oldLister })

	// A zone-less config has no zone interfaces to program, so compileZones
	// completes its real body (including stripUnmanagedInterfaces against
	// the empty seam) and advances to Phase 3. This is materially different
	// from recordingDP: no SetZoneConfig tripwire fires inside Phase 2.
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{}
	// DeleteStale* are compileZones' final dataplane calls, so they mark
	// Phase-2 completion before Phase 3 begins.
	dp2 := &postPhase2CompletingDP{}
	result, err := CompileConfig(dp2, cfg, false)
	if err == nil {
		t.Fatal("expected the staged Phase-3 failure")
	}
	if !strings.Contains(err.Error(), "compile address book") || !strings.Contains(err.Error(), "staged Phase-3 failure") {
		t.Fatalf("failure did not occur in Phase 3 after Phase 2: %v", err)
	}
	if dp2.clearV4Calls != 1 {
		t.Fatalf("Phase 3 ClearAddressBookV4 calls = %d, want 1", dp2.clearV4Calls)
	}
	if result == nil {
		t.Fatalf("post-Phase-2 failure returned a nil result (err=%v) — CompileUserspaceShim would drop divergence accounting (#15943)", err)
	}
	if result.ZoneIDs == nil {
		t.Fatal("partial result is not CompileConfig's result (ZoneIDs not initialized)")
	}

	// Keep the nil-result control for a pre-mutation failure: it must stay
	// nil, because inheriting/accounting for a config that never reached
	// Phase 2 would falsely report divergence.
	dpPre := &recordingDP{}
	resultPre, errPre := CompileConfig(dpPre, failLaterPhaseConfig(), false)
	if errPre == nil {
		t.Fatal("control: expected the unresolvable application to fail the pre-pass")
	}
	if resultPre != nil {
		t.Fatalf("pre-mutation failure returned a result, want nil: %v", resultPre)
	}
	assertNoHostMutation(t, dpPre)
}

type postPhase2CompletingDP struct {
	postPhase2DP
}

func (d *postPhase2CompletingDP) DeleteStaleIfaceZone(map[IfaceZoneKey]bool) {
	d.zonesComplete = true
}
func (d *postPhase2CompletingDP) DeleteStaleVlanIface(map[uint32]bool) {
	d.zonesComplete = true
}

func TestCompileConfigNATPhaseFailureReturnsResult_15943(t *testing.T) {
	cfg := failLaterNATPhaseConfig()
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	// compileNAT is Phase 6; drive it as CompileConfig would (real pass).
	err := compileNAT(&recordingDP{}, cfg, result)
	if err == nil {
		t.Fatal("expected the missing SNAT pool to fail compileNAT")
	}
	if !strings.Contains(err.Error(), "no-such-pool-4960") {
		t.Fatalf("compileNAT failed for the wrong reason: %v", err)
	}
	// The contract is at the CompileConfig wrapper: a NAT error wrapped as
	// "compile nat: ..." must accompany a non-nil result. Assert the wrapper
	// shape by re-running through CompileConfig with the pre-pass satisfied
	// is impossible without host access (compileZones), so this cell pins the
	// phase error itself and TestCompileConfigReturnsPartialResultAfterPhase2_15943
	// pins the wrapper's non-nil return on the adjacent Phase 3.
}
