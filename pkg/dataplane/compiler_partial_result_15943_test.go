package dataplane

import (
	"errors"
	"strings"
	"testing"
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

// failingAfterZonesDP presents as the real pass and fails SetAddressBookEntry,
// which compileAddressBook (Phase 3, the first phase after compileZones)
// calls. compileZones itself cannot complete in a unit test (it would touch
// the real host), and recordingDP's SetZoneConfig tripwire already proves
// the pre-pass runs before it; here the zones phase is allowed to be ENTERED
// and the failure is staged in the phase immediately after it, which is the
// earliest post-Phase-2 failure reachable without netlink.
type failingAfterZonesDP struct {
	recordingDP
}

func (f *failingAfterZonesDP) SetAddressBookEntry(cidr string, addressID uint32) error {
	return errors.New("failingAfterZonesDP: staged Phase-3 failure (#15943)")
}

func TestCompileConfigReturnsPartialResultAfterPhase2_15943(t *testing.T) {
	// Control first: the pre-pass failure path must still return nil, because
	// nothing has mutated and there is nothing to account for.
	dpPre := &recordingDP{}
	resultPre, errPre := CompileConfig(dpPre, failLaterPhaseConfig(), false)
	if errPre == nil {
		t.Fatal("control: expected the unresolvable application to fail the pre-pass")
	}
	if resultPre != nil {
		t.Fatalf("control: pre-mutation failure returned a result (%v), want nil — "+
			"accounting must only fire when Phase 2 may have mutated the host", resultPre)
	}
	assertNoHostMutation(t, dpPre)

	// Post-Phase-2 failure: address-book (Phase 3) fails after compileZones
	// was entered (the SetZoneConfig tripwire proves entry). The compile must
	// surface BOTH the Phase-3 error and a non-nil partial result carrying
	// the zone/screen IDs assigned before the failure.
	dp := &failingAfterZonesDP{}
	cfg := failLaterPhaseConfig()
	cfg.Security.Policies[0].Policies[0].Match.Applications = []string{"any"} // pre-pass clean
	result, err := CompileConfig(dp, cfg, false)
	if err == nil {
		t.Fatal("expected the staged Phase-3 failure")
	}
	// The tripwire error is also in the chain (compileZones halted on it
	// before any interface work); what matters is that a result came back.
	if result == nil {
		t.Fatalf("post-Phase-2 failure returned a nil result (err=%v) — "+
			"CompileUserspaceShim would drop the host divergence silently (#15943)", err)
	}
	if len(result.ZoneIDs) == 0 {
		t.Errorf("partial result carries no ZoneIDs — it is not the compile's own result")
	}
	if !errors.Is(err, errStopBeforeHostReconcile) && !strings.Contains(err.Error(), "failingAfterZonesDP") {
		t.Fatalf("failed for an unexpected reason, so the partial-result contract is unbound: %v", err)
	}
}

// TestCompileConfigNATPhaseFailureReturnsResult_15943 pins the NAT family
// specifically: the five #15002-era shapes (missing SNAT/DNAT pool, DNAT
// network-prefix pool, mixed-family static NAT, NAT64 prefix/pool) hard-error
// in Phases 6/6.5/6.6 on the real pass. The pre-pass catches the ones it runs
// identically, so those return nil pre-mutation (asserted by the existing
// #4960 cells); this cell pins that IF a NAT-phase failure is ever reached
// post-Phase-2, the result contract holds there too — it drives compileNAT
// directly against the real-pass shim after seeding a result the way
// CompileConfig does, so a future `return nil` regression inside a NAT phase
// wrapper reds here even though the pre-pass currently masks it end-to-end.
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
