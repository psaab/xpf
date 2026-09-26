package dataplane

// #5268 (High, security): a non-fatal ensureRxVlanOff failure let HW-stripped
// 802.1Q traffic bypass zone classification. The XDP dataplane derives VLAN
// (security-domain) identity SOLELY from the in-frame tag; if a NIC's RX-VLAN
// offload strips the tag into skb->vlan_tci (unreadable by XDP) and xpf cannot
// disable it, tagged frames parse as vlan_id=0 and fall back to the parent
// ifindex → the parent's / first-subinterface's zone → untrusted VLAN traffic
// classified into a TRUSTED zone. The fix makes RX-VLAN-offload-disable an
// activation precondition — but ONLY for a parent that carries configured VLAN
// subinterfaces (a plain parent, or a NIC that legitimately lacks the offload
// knob when no VLANs are present, is unaffected).

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// mockEthtool substitutes the package `runEthtool` for the duration of the test.
func mockEthtool(t *testing.T, fn func(args ...string) ([]byte, error)) {
	t.Helper()
	orig := runEthtool
	runEthtool = fn
	t.Cleanup(func() { runEthtool = orig })
}

func newRxVlanResult() *CompileResult {
	return &CompileResult{rxTagStripOffCache: make(map[string]bool)}
}

// ensureRxVlanForTest extracts the 802.1Q result from the production combined
// check; these #5268 cases pin its existing error contract.
func ensureRxVlanForTest(r *CompileResult, iface string) error {
	rxvlanErr, _ := r.ensureRxVlanParsePreconditions(iface)
	return rxvlanErr
}

func cfgWithVlanSubif() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0-0-0": {
					Name: "ge-0-0-0",
					Units: map[int]*config.InterfaceUnit{
						0:  {Number: 0, VlanID: 0},
						50: {Number: 50, VlanID: 50},
					},
				},
			},
		},
	}
}

func cfgPlainParent() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0-0-0": {
					Name:  "ge-0-0-0",
					Units: map[int]*config.InterfaceUnit{0: {Number: 0, VlanID: 0}},
				},
			},
		},
	}
}

// ---- ensureRxVlanOff error contract (#5268) -------------------------------

// Offload reported ON and `-K rxvlan off` fails → error (the dangerous case:
// the NIC WILL strip tags and we could not stop it).
func TestEnsureRxVlanOffErrorWhenOnAndDisableFails_5268(t *testing.T) {
	calls := 0
	mockEthtool(t, func(args ...string) ([]byte, error) {
		calls++
		switch args[0] {
		case "-k":
			return []byte("Features for ge-0-0-0:\nrx-vlan-offload: on\n"), nil
		case "-K":
			return []byte("Cannot set device feature settings: not supported"),
				errors.New("exit status 1")
		}
		return nil, errors.New("unexpected ethtool " + args[0])
	})
	err := ensureRxVlanForTest(newRxVlanResult(), "ge-0-0-0")
	if err == nil {
		t.Fatal("combined precondition check must return a C-tag error when the 802.1Q offload is ON and cannot be disabled")
	}
	if calls != 2 {
		t.Fatalf("expected -k then -K (2 calls), got %d", calls)
	}
}

// Already `off [fixed]` (e.g. virtio) → nil, and `-K` is NEVER attempted (a
// toggle would drive a needless driver reset).
func TestEnsureRxVlanOffNilWhenAlreadyOffFixed_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		if args[0] == "-k" {
			return []byte("Features for ge-0-0-0:\nrx-vlan-offload: off [fixed]\n"), nil
		}
		t.Fatalf("must NOT call ethtool %v when already off", args)
		return nil, nil
	})
	if err := ensureRxVlanForTest(newRxVlanResult(), "ge-0-0-0"); err != nil {
		t.Fatalf("already-off must return nil, got %v", err)
	}
}

// Feature ABSENT from a successful query (NIC has no rx-vlan-offload knob) →
// nil, `-K` NEVER attempted. This is the virtio-safe path that must NOT falsely
// trip the fail-closed gate.
func TestEnsureRxVlanOffNilWhenFeatureAbsent_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		if args[0] == "-k" {
			return []byte("Features for ge-0-0-0:\ntx-checksumming: on\nscatter-gather: on\n"), nil
		}
		t.Fatalf("must NOT call ethtool %v when the feature is absent", args)
		return nil, nil
	})
	if err := ensureRxVlanForTest(newRxVlanResult(), "ge-0-0-0"); err != nil {
		t.Fatalf("feature-absent must return nil, got %v", err)
	}
}

// Query fails but the disable SUCCEEDS → nil (we achieved "off").
func TestEnsureRxVlanOffNilWhenQueryFailsButDisableOk_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return nil, errors.New("ethtool -k failed")
		case "-K":
			return []byte(""), nil
		}
		return nil, errors.New("unexpected")
	})
	if err := ensureRxVlanForTest(newRxVlanResult(), "ge-0-0-0"); err != nil {
		t.Fatalf("query-fail + disable-ok must return nil, got %v", err)
	}
}

// Query fails AND the disable fails → error (state unknown, could not confirm).
func TestEnsureRxVlanOffErrorWhenQueryAndDisableFail_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		return nil, errors.New("ethtool unavailable")
	})
	if err := ensureRxVlanForTest(newRxVlanResult(), "ge-0-0-0"); err == nil {
		t.Fatal("query-fail + disable-fail must return an error")
	}
}

// Cached-off short-circuits with no ethtool call.
func TestEnsureRxVlanOffCachedShortCircuits_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		t.Fatalf("cached off must not call ethtool %v", args)
		return nil, nil
	})
	r := newRxVlanResult()
	r.rxTagStripOffCache["ge-0-0-0"] = true
	if err := ensureRxVlanForTest(r, "ge-0-0-0"); err != nil {
		t.Fatalf("cached-off must return nil, got %v", err)
	}
}

// ---- parentHasVlanSubinterface (#5268 gate input) -------------------------

func TestParentHasVlanSubinterface_5268(t *testing.T) {
	if !parentHasVlanSubinterface(cfgWithVlanSubif(), "ge-0-0-0") {
		t.Fatal("a config with a VlanID>0 unit must report a VLAN subinterface")
	}
	if parentHasVlanSubinterface(cfgPlainParent(), "ge-0-0-0") {
		t.Fatal("a config with only VlanID==0 units must NOT report a VLAN subinterface")
	}
	if parentHasVlanSubinterface(cfgWithVlanSubif(), "ge-0-0-9") {
		t.Fatal("an unknown interface name must report no VLAN subinterface")
	}
	if parentHasVlanSubinterface(nil, "ge-0-0-0") {
		t.Fatal("nil config must report no VLAN subinterface")
	}
}

// ---- THE FAIL-ON-REVERT: activation gate (#5268) --------------------------

// FAIL-ON-REVERT: a parent that carries a configured VLAN subinterface whose
// RX-VLAN offload could NOT be disabled MUST fail activation closed
// (rxVlanOffloadActivationError returns a non-nil error, which the compile path
// at compiler_iface.go returns). The `ensureErr` is produced by the REAL
// ensureRxVlanOff over a mocked ethtool that reports the offload ON and fails
// the disable. Reverting the fix (gate returns nil / warn-and-continue) makes
// the assertion RED.
func TestRxVlanFailClosedOnVlanParent_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			return []byte("not supported"), errors.New("exit status 1")
		}
		return nil, errors.New("unexpected")
	})
	ensureErr := ensureRxVlanForTest(newRxVlanResult(), "ge-0-0-0")
	if ensureErr == nil {
		t.Fatal("precondition: combined check must return a C-tag error for an ON-and-undisable-able offload")
	}
	if err := rxVlanOffloadActivationError(cfgWithVlanSubif(), "ge-0-0-0", "ge-0-0-0", ensureErr); err == nil {
		t.Fatal("#5268: a VLAN-subinterface parent whose rxvlan offload cannot be disabled MUST fail activation closed")
	}
}

// NEGATIVE SCOPE: a PLAIN parent (no configured VLAN subinterfaces) whose
// rxvlan disable fails must STILL succeed — the offload state is irrelevant when
// no tag-based zone classification is in use. Stays GREEN on revert.
func TestRxVlanTolerantOnPlainParent_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			return []byte("not supported"), errors.New("exit status 1")
		}
		return nil, errors.New("unexpected")
	})
	ensureErr := ensureRxVlanForTest(newRxVlanResult(), "ge-0-0-0")
	if ensureErr == nil {
		t.Fatal("precondition: combined check must return a C-tag error here too")
	}
	if err := rxVlanOffloadActivationError(cfgPlainParent(), "ge-0-0-0", "ge-0-0-0", ensureErr); err != nil {
		t.Fatalf("#5268 negative scope: a plain parent must NOT fail activation on a rxvlan disable failure, got %v", err)
	}
}

// ---- COMPILE-LEVEL FAIL-ON-REVERT: call-site wiring (#5268 / #6124) --------
//
// TestRxVlanFailClosedOnVlanParent_5268 above binds only the C-tag DECISION
// FUNCTION (rxVlanOffloadActivationError called directly). NOTHING there binds
// the CALL-SITE WIRING in compiler_iface.go that turns the decision into a
// fail-closed compile abort:
//
//	rxvlanErr, stagErr := result.ensureRxVlanParsePreconditions(physName)
//	if err := rxVlanOffloadActivationError(cfg, cfgName, physName, rxvlanErr); err != nil {
//		return err
//	}
//	if err := rxVlanStagHwParseActivationError(physName, stagErr); err != nil {
//		return err
//	}
//
// A revert that drops the C-tag `if err != nil { return err }` would reopen
// the cross-zone bypass with every decision-function test still green. The
// test below drives the REAL compileZones() path.

// errCompileStopBeforeReconcile is a sentinel returned by the stub's AddTxPort
// for the SECOND (guard) interface. compileZones cannot be driven to completion
// in a unit test: its tail enumerates real host interfaces via net.Interfaces()
// and brings the unmanaged ones DOWN with netlink (compiler_iface.go documents
// this as "not unit-testable"). On the CORRECT code the #5268 gate returns at
// line 489 while processing the FIRST interface, so the tail is never reached.
// On a REVERTED call site the gate no longer returns, execution would fall
// through toward that dangerous host reconcile — so a second interface whose
// AddTxPort trips this sentinel halts the compile EARLY and SAFELY, turning the
// revert into a clean assertion failure instead of a host-mutating run.
var errCompileStopBeforeReconcile = errors.New(
	"compile-test guard: AddTxPort tripwire (execution passed the #5268 gate)")

// compileRxVlanTestDP is a netlink-free DataPlane stub. It embeds the DataPlane
// interface (nil) and overrides only the methods compileZones reaches on the
// one-time physical-interface setup path (SetZoneConfig, SetZone, AddTxPort).
// AddTxPort returns errCompileStopBeforeReconcile for stopIfindex so the revert
// path halts before the host-interface reconcile; any other embedded method is
// never called on this path and would nil-panic — an intended tripwire.
type compileRxVlanTestDP struct {
	DataPlane
	stopIfindex int
}

func (compileRxVlanTestDP) SetZoneConfig(uint16, ZoneConfig) error { return nil }
func (compileRxVlanTestDP) SetZone(int, uint16, uint16, uint32, uint8, uint8, uint32) error {
	return nil
}
func (d compileRxVlanTestDP) AddTxPort(ifindex int) error {
	if d.stopIfindex != 0 && ifindex == d.stopIfindex {
		return errCompileStopBeforeReconcile
	}
	return nil
}

// cfgVlanParentInZone builds a two-interface config:
//   - ge-0-0-0 (ifindex 4242): a physical parent placed directly in a zone via
//     its unit-0 ref AND carrying a configured 802.1Q subinterface (unit 50).
//     parentHasVlanSubinterface(ge-0-0-0) is therefore true, so compileZones
//     reaches the #5268 gate while processing the unit-0 (vlanID==0) ref.
//     Referencing the VLAN subinterface (ge-0-0-0.50) instead would divert into
//     ensureVLANSubInterface (a real netlink create) and `continue` before ever
//     reaching line 489, so the parent's unit-0 ref is the ref that exercises
//     the call site.
//   - ge-0-0-1 (ifindex 4243): a plain guard interface listed SECOND in the same
//     zone's ordered Interfaces slice. It is only reached on the revert path
//     (the gate no longer short-circuits the first interface); its AddTxPort
//     trips the sentinel, halting the compile before the host reconcile.
func cfgVlanParentInZone() *config.Config {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0-0-0": {
					Name:        "ge-0-0-0",
					VlanTagging: true,
					Units: map[int]*config.InterfaceUnit{
						0:  {Number: 0, VlanID: 0},
						50: {Number: 50, VlanID: 50},
					},
				},
				"ge-0-0-1": {
					Name:  "ge-0-0-1",
					Units: map[int]*config.InterfaceUnit{0: {Number: 0, VlanID: 0}},
				},
			},
		},
	}
	// One zone, ordered slice → ge-0-0-0.0 is ALWAYS processed before the
	// ge-0-0-1.0 guard (map iteration randomness does not apply within a slice).
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Interfaces: []string{"ge-0-0-0.0", "ge-0-0-1.0"}},
	}
	return cfg
}

// TestRxVlanFailClosedWiredIntoCompile_5268 is the COMPILE-LEVEL fail-on-revert
// that binds the C-tag CALL-SITE wiring in compiler_iface.go, not merely its
// decision function. It drives the real compileZones() over a VLAN-parent
// config with a mocked ethtool that reports rx-vlan-offload ON and fails
// `-K rxvlan off`, then asserts compileZones ABORTS with the specific #5268
// fail-closed error while processing the VLAN parent.
//
// RED-on-revert: if the C-tag gate is reverted back to ignoring `rxvlanErr`,
// execution falls through to the ge-0-0-1 guard whose AddTxPort trips
// errCompileStopBeforeReconcile, so compileZones returns THAT error instead of
// the fail-closed one — the signature assertion fails and this test goes RED,
// while TestRxVlanFailClosedOnVlanParent_5268 (decision function only) stays
// GREEN. Target-count 1: only this test binds the propagation.
func TestRxVlanFailClosedWiredIntoCompile_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			return []byte("not supported"), errors.New("exit status 1")
		}
		return nil, errors.New("unexpected ethtool " + args[0])
	})

	result := &CompileResult{
		ZoneIDs:             map[string]uint16{"trust": 1},
		ScreenIDs:           make(map[string]uint16),
		rxTagStripOffCache:  make(map[string]bool),
		ifCache:             make(map[string]*net.Interface),
		ethtoolApplied:      make(map[string]bool),
		genericXDPIfindexes: make(map[int]bool),
	}
	// Pre-seed the interface cache so cachedInterfaceByName resolves both parents
	// WITHOUT a syscall (the test host has no ge-0-0-*). The high, otherwise-unused
	// ifindexes make the one netlink fallback on the revert path
	// (cachedLinkByIndex → LinkByIndex) miss cleanly (guarded by `nlErr == nil`).
	result.ifCache["ge-0-0-0"] = &net.Interface{Index: 4242, Name: "ge-0-0-0"}
	result.ifCache["ge-0-0-1"] = &net.Interface{Index: 4243, Name: "ge-0-0-1"}

	err := compileZones(compileRxVlanTestDP{stopIfindex: 4243}, cfgVlanParentInZone(), result)
	if err == nil {
		t.Fatal("#5268/#6124: compileZones MUST abort (fail closed) when a VLAN-parent's " +
			"rx-vlan offload cannot be disabled — the call-site error propagation at " +
			"compiler_iface.go:489 was dropped, reopening the cross-zone bypass")
	}
	if !strings.Contains(err.Error(), "RX-VLAN hardware offload could not be disabled") {
		t.Fatalf("compileZones did not abort at the #5268 fail-closed gate — the "+
			"call-site error propagation at compiler_iface.go:489 was dropped; got: %v", err)
	}
}

// A successful disable on a VLAN parent must NOT fail activation (happy path).
func TestRxVlanNoErrorOnVlanParentWhenDisableOk_5268(t *testing.T) {
	mockEthtool(t, func(args ...string) ([]byte, error) {
		switch args[0] {
		case "-k":
			return []byte("rx-vlan-offload: on\n"), nil
		case "-K":
			return []byte(""), nil
		}
		return nil, errors.New("unexpected")
	})
	ensureErr := ensureRxVlanForTest(newRxVlanResult(), "ge-0-0-0")
	if ensureErr != nil {
		t.Fatalf("disable succeeded, the C-tag precondition must return nil, got %v", ensureErr)
	}
	if err := rxVlanOffloadActivationError(cfgWithVlanSubif(), "ge-0-0-0", "ge-0-0-0", ensureErr); err != nil {
		t.Fatalf("a successful disable must not fail activation, got %v", err)
	}
}
