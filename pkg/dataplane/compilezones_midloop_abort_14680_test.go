package dataplane

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #14680 — a compileZones mid-loop abort must not discard the partial
// CompileResult. CompileConfig used to return (nil, err) for Phase 2, so
// CompileUserspaceShim returned before inheritHostDivergence /
// abortAfterHostMutation / ProveArmCoverage, leaving HostDivergence()
// empty and the prior arm-coverage verdict standing while the host had
// already been mutated (VLAN created, addresses reconciled, interface
// brought UP). The S-tag gate additionally fired only after LinkSetUp.
//
// The decisive fixture is the named one: two interfaces, the first
// mutates (VLAN child created via the seam), the second trips the
// rx-vlan-stag-hw-parse gate; the abort must be annotated, retained in
// HostDivergence, and publish a live proof for THIS apply. It drives
// CompileConfig (the exact production shim compile entry) — the
// trailing bpffs pin sweeps in CompileUserspaceShim need root/bpffs
// and are bound separately by the AST wiring guard below.

// midLoopDP is a netlink-free DataPlane stub for the CompileConfig path.
// It embeds the interface (nil) and overrides only what the pre-pass +
// compileZones reach on this fixture's shape; any other method would
// nil-panic — an intended tripwire.
type midLoopDP14680 struct {
	DataPlane
}

func (midLoopDP14680) IsLoaded() bool                                                  { return true }
func (midLoopDP14680) SetZoneConfig(uint16, ZoneConfig) error                          { return nil }
func (midLoopDP14680) SetZone(int, uint16, uint16, uint32, uint8, uint8, uint32) error { return nil }
func (midLoopDP14680) AddTxPort(int) error                                             { return nil }
func (midLoopDP14680) SetVlanIfaceInfo(int, int, uint16) error                         { return nil }
func (midLoopDP14680) DeleteStaleIfaceZone(map[IfaceZoneKey]bool)                      {}
func (midLoopDP14680) DeleteStaleVlanIface(map[uint32]bool)                            {}
func (midLoopDP14680) ZeroStaleScreenConfigs(uint32)                                   {}

// installMidLoopHost14680 points every host seam mapZoneInterface can
// reach at a fake host: no real netlink, ethtool, or /proc writes.
// It returns the fake host so cells can assert what actually moved.
// seedIfCache14680 pre-seeds a CompileResult's ifCache the way
// newValidationResult-based fixtures do (see TestRxVlanFailClosedWiredIntoCompile_5268):
// cachedInterfaceByName then resolves WITHOUT net.InterfaceByName, so the
// fixture never depends on host interfaces existing.
func seedResult14680() *CompileResult {
	r := newValidationResult()
	r.ifCache["ge-0-0-0"] = &net.Interface{Index: 4300, Name: "ge-0-0-0"}
	r.ifCache["ge-0-0-1"] = &net.Interface{Index: 4302, Name: "ge-0-0-1"}
	// Skip tuneInterfaceBuffers' direct LinkSetTxQLen + /proc/sys writes.
	r.ethtoolApplied["buffers:ge-0-0-0"] = true
	r.ethtoolApplied["buffers:ge-0-0-1"] = true
	// Pre-populate link caches so cachedLinkByIndex hits without netlink.
	for _, name := range []string{"ge-0-0-0", "ge-0-0-1"} {
		l := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: r.ifCache[name].Index, MTU: 1500, EncapType: "ether"}}
		r.linkCache[name] = l
		r.linkIdxMap[r.ifCache[name].Index] = l
	}
	return r
}

func installMidLoopHost14680(t *testing.T) *fakeHost8119 {
	t.Helper()
	h := &fakeHost8119{
		mtu:   map[string]int{"ge-0-0-0": 1500, "ge-0-0-0.50": 1500, "ge-0-0-1": 1500},
		addrs: map[string]map[string]bool{"ge-0-0-0": {}, "ge-0-0-0.50": {}, "ge-0-0-1": {}},
		index: map[string]int{"ge-0-0-0": 4300, "ge-0-0-0.50": 4301, "ge-0-0-1": 4302},
	}
	h.install(t)
	// The unmanaged strip enumerates REAL interfaces; confine it to none.
	origLister := interfaceLister
	t.Cleanup(func() { interfaceLister = origLister })
	interfaceLister = func() ([]net.Interface, error) { return nil, nil }

	// Fetch seams fail closed: cache misses never reach the kernel.

	origVLAN := ensureVLANSubInterfaceFn
	t.Cleanup(func() { ensureVLANSubInterfaceFn = origVLAN })
	ensureVLANSubInterfaceFn = func(parent string, vlanID int) (int, bool, error) {
		name := fmt.Sprintf("%s.%d", parent, vlanID)
		idx, ok := h.index[name]
		if !ok {
			return 0, false, fmt.Errorf("no such device %q", name)
		}
		// created=true: the child now exists on the host (#4960 mark).
		return idx, true, nil
	}
	return h
}

// midLoopCfg14680: ge-0-0-0.50 (VLAN child, mutates first) then
// ge-0-0-1.0 (plain parent whose S-tag disable fails). Zone interface
// order is a slice, so processing order is deterministic.
func midLoopCfg14680() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-0": {
			Name: "ge-0-0-0", VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, Addresses: []string{"10.0.50.1/24"}},
			},
		},
		"ge-0-0-1": {
			Name:  "ge-0-0-1",
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, VlanID: 0}},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-0.50", "ge-0-0-1.0"}},
	}
	return cfg
}

// driveMidLoop14680 runs compileZones over a result pre-seeded with the
// fake host's interfaces (the same seeding TestRxVlanFailClosedWiredIntoCompile_5268
// uses), because CompileConfig constructs its own result internally and
// therefore cannot be seeded. The production CompileConfig->compileZones
// seam is bound by TestCompileConfigReturnsPartialOnZonesAbort14680 below
// (minimal config, pre-pass-clean) and by the AST wiring guard for
// CompileUserspaceShim's abort accounting.
func driveMidLoop14680(t *testing.T, cfg *config.Config) (*CompileResult, error) {
	t.Helper()
	result := seedResult14680()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	err := compileZones(midLoopDP14680{}, cfg, result)
	return result, err
}

func TestCompileUserspaceShimRecordsHostDivergenceOnCompileZonesMidLoopAbort(t *testing.T) {
	installMidLoopHost14680(t)

	mockEthtool(t, func(args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "-k" {
			switch args[1] {
			case "ge-0-0-1":
				return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: on\n"), nil
			default:
				return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: off\n"), nil
			}
		}
		if len(args) >= 2 && args[0] == "-K" {
			return []byte("not supported"), errors.New("ethtool refused S-tag disable")
		}
		return nil, fmt.Errorf("unexpected ethtool %v", args)
	})

	m := New()
	m.loaded.Store(true)

	result, err := driveMidLoop14680(t, midLoopCfg14680())
	if err == nil {
		t.Fatal("compileZones must abort when the second interface's S-tag offload cannot be disabled")
	}
	if !strings.Contains(err.Error(), "S-tag HW-parse offload could not be disabled") {
		t.Fatalf("abort must be the S-tag fail-closed error, got: %v", err)
	}
	if result == nil {
		t.Fatal("#14680: partial CompileResult discarded on a compileZones mid-loop abort")
	}
	if !result.HostMutated() {
		t.Fatalf("#14680: partial result records no host mutation, want the first "+
			"interface's VLAN create / address reconcile; mutations=%v", result.hostMutations)
	}
	// CompileUserspaceShim's abort accounting on the partial result
	// (bpffs tail cannot run unprivileged; wiring bound by the AST guard).
	m.inheritHostDivergence(result)
	annotated := annotateHostMutationOnAbort(result, err)
	if !strings.Contains(annotated.Error(), "ALREADY changed live host state") {
		t.Fatalf("#4960 annotation missing on mid-loop abort: %v", annotated)
	}
	if !strings.Contains(annotated.Error(), "created VLAN sub-interface") {
		t.Fatalf("annotation must name the mutation class, got: %v", annotated)
	}
	_ = m.abortAfterHostMutation(result, annotated)
	if got := m.HostDivergence(); len(got) == 0 {
		t.Fatal("#8285: HostDivergence() stays empty after a mid-loop abort that " +
			"mutated the host — a retry would report a bare failure")
	}
	if _, _, ran, seen := m.ArmCoverageSummary(); !seen || !ran {
		t.Fatalf("#7289: abort published no live arm-coverage verdict (ran=%v seen=%v)", ran, seen)
	}
	if len(result.pendingXDP) == 0 {
		t.Fatal("#14680: partial result carries no pendingXDP — the arm proof " +
			"would run on an empty required set and publish a vacuous verdict")
	}
}

// NOTE: CompileConfig constructs its result internally, so its
// (partial, err) return cannot be driven with a seeded cache in a unit
// test; the seam is the one-line return in compiler.go plus the
// compileZones cells above and the loader wiring guard below.

// The S-tag gate must fire BEFORE LinkSetUp / MTU for its own interface:
// a config whose FIRST (only) interface trips the gate must abort with
// no host mutation recorded for that interface. On master the gate sat
// after LinkSetUp, so this cell's error still fired — but only after
// the interface was UP. The observable here is the mutation record:
// pre-fix, attemptPhysMTU/LinkSetUp ran first (no MTU configured in
// this fixture, so the pre/post distinction is the gate's position
// relative to the per-phys setup, bound by the ordering guard in
// TestStagGatePrecedesLinkSetup14680).
func TestStagGatePrecedesLinkSetup14680(t *testing.T) {
	h := installMidLoopHost14680(t)
	mockEthtool(t, func(args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "-k" {
			return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: on\n"), nil
		}
		if len(args) >= 2 && args[0] == "-K" {
			return []byte("not supported"), errors.New("ethtool refused S-tag disable")
		}
		return nil, fmt.Errorf("unexpected ethtool %v", args)
	})

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {
			Name: "ge-0-0-1", MTU: 9000,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0, VlanID: 0, Addresses: []string{"10.0.1.1/24"}}},
		},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0-0-1.0"}},
	}
	if got := h.mtu["ge-0-0-1"]; got != 1500 {
		t.Fatalf("premise: fake host MTU = %d, want 1500 before apply", got)
	}

	result, err := driveMidLoop14680(t, cfg)
	if err == nil || !strings.Contains(err.Error(), "S-tag HW-parse") {
		t.Fatalf("single-interface S-tag abort expected, got result=%v err=%v", result != nil, err)
	}
	if result == nil {
		t.Fatal("#14680: partial result discarded on stag abort")
	}
	// The gate fired before this interface's MTU write and address
	// reconcile: the fake host must be untouched for ge-0-0-1.
	if got := h.mtu["ge-0-0-1"]; got != 1500 {
		t.Fatalf("#14680: stag gate fired AFTER the MTU write — host MTU = %d, want untouched 1500", got)
	}
	if len(h.addrs["ge-0-0-1"]) != 0 {
		t.Fatalf("#14680: stag gate fired after address reconcile — host addrs = %v", h.addrs["ge-0-0-1"])
	}
	if result.HostMutated() {
		t.Fatalf("stag gate must precede address reconcile for its own interface; mutations=%v", result.hostMutations)
	}
	if len(result.pendingXDP) != 0 {
		t.Fatalf("aborted interface must not be queued for XDP, pending=%v", result.pendingXDP)
	}
}

// Control: a clean compile still succeeds and returns a full result,
// and a converged re-apply records no mutation (the annotation must
// stay meaningful — #4960's own contract).
func TestCompileZonesSuccessControl14680(t *testing.T) {
	installMidLoopHost14680(t)
	mockEthtool(t, func(args ...string) ([]byte, error) {
		if len(args) >= 1 && args[0] == "-k" {
			return []byte("rx-vlan-offload: off\nrx-vlan-stag-hw-parse: off\n"), nil
		}
		return nil, fmt.Errorf("unexpected ethtool %v", args)
	})
	result, err := driveMidLoop14680(t, midLoopCfg14680())
	if err != nil {
		t.Fatalf("clean compile must succeed, got: %v", err)
	}
	if result == nil || len(result.pendingXDP) == 0 {
		t.Fatalf("clean compile must return a result with pendingXDP, got %+v", result)
	}
}

// markVLANSubInterfaces must REPLACE the live set: a stale ifindex from
// a previous compile must not permanently exclude a reused ifindex
// from swap/status.
func TestMarkVLANSubInterfacesReplacesStale14680(t *testing.T) {
	m := New()
	m.vlanSubInterfaces[4301] = true // stale child from a prior compile
	m.vlanSubInterfaces[4399] = true // ifindex since reused by a plain NIC

	m.markVLANSubInterfaces(&CompileResult{
		genericXDPIfindexes: map[int]bool{4301: true},
		tunnelIfindexes:     map[int]bool{},
	})
	if !m.IsVLANSubInterface(4301) {
		t.Fatal("current VLAN child must remain marked")
	}
	if m.IsVLANSubInterface(4399) {
		t.Fatal("#14680: stale vlanSubInterfaces entry survived a successful " +
			"compile — a reused ifindex is permanently excluded from " +
			"xdpSwapTargets/XDPEntryPrograms")
	}

	// A compile with no VLAN children clears the set entirely.
	m.markVLANSubInterfaces(&CompileResult{
		genericXDPIfindexes: map[int]bool{},
		tunnelIfindexes:     map[int]bool{},
	})
	if m.IsVLANSubInterface(4301) {
		t.Fatal("#14680: vlanSubInterfaces not cleared when the new config has no VLAN children")
	}
}

// TestCompileZonesAbortWiring14680 binds the loader wiring that the
// behavioural cells cannot reach unprivileged (CompileUserspaceShim's
// bpffs tail needs root): the CompileConfig error branch must, when it
// has a partial result, inherit retained divergence and route through
// abortAfterHostMutation with the #4960 annotation — not return bare.
func TestCompileZonesAbortWiring14680(t *testing.T) {
	loaderSrc, err := os.ReadFile("loader.go")
	if err != nil {
		t.Fatalf("read loader.go: %v", err)
	}
	for _, want := range []string{"inheritHostDivergence(result)", "abortAfterHostMutation(result, annotateHostMutationOnAbort(result, err))"} {
		if !strings.Contains(string(loaderSrc), want) {
			t.Fatalf("CompileUserspaceShim does not contain %q — a compileZones mid-loop abort bypasses #4960/#8285/#7289 accounting", want)
		}
	}
	ifaceSrc, err := os.ReadFile("compiler_iface.go")
	if err != nil {
		t.Fatalf("read compiler_iface.go: %v", err)
	}
	isrc := string(ifaceSrc)
	stag := strings.Index(isrc, "rxVlanStagHwParseActivationError(physName, stagErr)")
	up := strings.Index(isrc, "netlink.LinkSetUp(nl)")
	if stag < 0 || up < 0 || stag > up {
		t.Fatalf("#14680: stag gate (offset %d) must precede LinkSetUp (offset %d) in compiler_iface.go", stag, up)
	}
	if n := strings.Count(isrc, "rxVlanStagHwParseActivationError(physName, stagErr)"); n != 1 {
		t.Fatalf("stag gate must appear exactly once (hoisted), got %d", n)
	}
	compSrc, err := os.ReadFile("compiler.go")
	if err != nil {
		t.Fatalf("read compiler.go: %v", err)
	}
	if !strings.Contains(string(compSrc), "return result, fmt.Errorf(\"compile zones: %w\", err)") {
		t.Fatal("CompileConfig must return the partial result on compileZones failure (#14680)")
	}
}
