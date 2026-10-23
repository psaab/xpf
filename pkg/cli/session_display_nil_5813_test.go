// #5813: the CLI session-display egress-interface map builder walked
// cfg.Interfaces.Interfaces and ifc.Units with no nil guard. The tolerant load
// / HA config-sync path admits present-but-nil InterfaceConfig and
// InterfaceUnit map values (#3494/#5068), so a routine `show security flow
// session` against a peer-synced config nil-dereferenced and panicked the
// in-process daemon. The builder now walks via config.RangeInterfaces /
// config.RangeUnits, which skip the nil slots.
//
// FAIL-ON-REVERT: reverting either nil guard (in config.RangeInterfaces or
// config.RangeUnits) makes the corresponding nil slot deref and panic — the
// seam test's deterministic lookup resolves every name so both nil-deref sites
// are actually reached, and the handler test keys the nil slots on the
// loopback so the real net.InterfaceByName path reaches them too.
package cli

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// require5813NoPanic fails the test (rather than crashing the run) if fn panics,
// with a message that names the #5813 nil-guard regression.
func require5813NoPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked (nil-guard regression #5813): %v", name, r)
		}
	}()
	fn()
}

// nilGuardFlowDP is an empty, "loaded" dataplane so showFlowSession runs the
// egress-interface map builder against the config (no sessions to iterate).
type nilGuardFlowDP struct {
	*dataplane.Manager
}

func (nilGuardFlowDP) IsLoaded() bool { return true }
func (nilGuardFlowDP) IterateSessions(func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	return nil
}
func (nilGuardFlowDP) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

// TestBuildSessionEgressIfacesNilSlots5813 drives the real builder through its
// deterministic-lookup seam with a config carrying a nil InterfaceConfig, a nil
// InterfaceUnit on a valid interface, and valid sibling units. The lookup
// resolves every name so both nil-deref sites are reachable — the guard, not a
// failed lookup, is what keeps it safe. It also proves the valid siblings map
// to the expected (ifindex, vlanID) -> display name with first-wins preserved,
// and that the nil slots contribute no bogus entry.
func TestBuildSessionEgressIfacesNilSlots5813(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},              // untagged unit
			50: {Number: 50, VlanID: 50}, // tagged subinterface
			7:  nil,                      // nil unit (tolerant path)
		}},
		"zz-nil-ifc": nil, // nil InterfaceConfig (tolerant path)
	}
	// #16065: the lookup receives each unit's OWN kernel device
	// ("ge-0-0-0" for unit 0, the VLAN child "ge-0-0-0.50" for unit
	// 50), each with its own ifindex. Resolve every device so the
	// nil-interface's ifc.Units deref and the nil unit's field read
	// WOULD both be reached without the guards.
	lookup := func(name string) (int, error) {
		switch name {
		case "ge-0-0-0":
			return 10, nil
		case "ge-0-0-0.50":
			return 16, nil
		}
		return 10, nil
	}

	var got map[sessionIfaceKey]string
	require5813NoPanic(t, "buildSessionEgressIfacesWithLookup", func() {
		got = buildSessionEgressIfacesWithLookup(cfg, lookup)
	})

	if name := got[sessionIfaceKey{Ifindex: 10, VlanID: 0}]; name != "ge-0/0/0" {
		t.Fatalf("untagged unit: got %q, want ge-0/0/0 (map=%v)", name, got)
	}
	if name := got[sessionIfaceKey{Ifindex: 16, VlanID: 50}]; name != "ge-0/0/0.50" {
		t.Fatalf("tagged unit child: got %q, want ge-0/0/0.50 (map=%v)", name, got)
	}
	// Dual keying: the tagged unit also registers its parent form.
	if name := got[sessionIfaceKey{Ifindex: 10, VlanID: 50}]; name != "ge-0/0/0.50" {
		t.Fatalf("tagged unit parent form: got %q, want ge-0/0/0.50 (map=%v)", name, got)
	}
	// Exactly the two valid units produced entries (3 keys: unit 0 plus
	// unit 50's parent+child forms); the nil unit and the nil
	// InterfaceConfig contributed nothing.
	if len(got) != 3 {
		t.Fatalf("egress map has %d entries, want 3 (nil slots must be omitted): %v", len(got), got)
	}
}

// TestBuildSessionEgressIfacesConcurrentPublish5813 models tolerant config
// publication: a publisher atomically swaps the active config pointer between
// fresh tolerant configs (each carrying a nil InterfaceConfig and a nil unit)
// while several readers concurrently build the egress-interface map. Run under
// -race, it exercises concurrent read-only presentation against config
// publication — the pointer swap is the only shared state, each config's maps
// are immutable once published, and the nil guards keep every read safe.
func TestBuildSessionEgressIfacesConcurrentPublish5813(t *testing.T) {
	mkTolerantCfg := func() *config.Config {
		c := &config.Config{}
		c.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
			"ge-0/0/0":   {Units: map[int]*config.InterfaceUnit{0: {Number: 0}, 7: nil}},
			"zz-nil-ifc": nil,
		}
		return c
	}
	lookup := func(string) (int, error) { return 10, nil }

	var published atomic.Pointer[config.Config]
	published.Store(mkTolerantCfg())

	stop := make(chan struct{})
	var publisher sync.WaitGroup
	publisher.Add(1)
	go func() { // publisher: atomic pointer swap, fresh config each time
		defer publisher.Done()
		for {
			select {
			case <-stop:
				return
			default:
				published.Store(mkTolerantCfg())
			}
		}
	}()

	const readers = 8
	var reading sync.WaitGroup
	for r := 0; r < readers; r++ {
		reading.Add(1)
		go func() { // reader: read-only presenter against the published config
			defer reading.Done()
			for i := 0; i < 500; i++ {
				got := buildSessionEgressIfacesWithLookup(published.Load(), lookup)
				if len(got) != 1 { // only ge-0/0/0 unit 0 survives; nil slots skipped
					t.Errorf("concurrent build yielded %d entries, want 1: %v", len(got), got)
					return
				}
			}
		}()
	}

	reading.Wait()   // readers finish their bounded loops...
	close(stop)      // ...then stop the publisher...
	publisher.Wait() // ...and wait for it to exit.
}

// TestShowFlowSessionNilSlots5813 drives the REAL local `show security flow
// session` handler (fake loaded dataplane, empty session table) against a
// tolerant config whose nil slots sit on the loopback, so the production
// net.InterfaceByName lookup resolves and reaches the nil-deref site. Each
// sub-case exercises one guard end-to-end through the handler.
func TestShowFlowSessionNilSlots5813(t *testing.T) {
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	cases := []struct {
		name   string
		mutate func(cfg *config.Config)
	}{
		{"nil-interface-config", func(cfg *config.Config) {
			// A present-but-nil InterfaceConfig on a resolving name: without the
			// RangeInterfaces guard, `range ifc.Units` nil-derefs.
			cfg.Interfaces.Interfaces["lo"] = nil
		}},
		{"nil-interface-unit", func(cfg *config.Config) {
			// A nil unit alongside a valid unit on a resolving name: without the
			// RangeUnits guard, `unit.Number` nil-derefs.
			cfg.Interfaces.Interfaces["lo"] = &config.InterfaceConfig{
				Units: map[int]*config.InterfaceUnit{0: nil, 5: {Number: 5, VlanID: 5}},
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := nilInterfaceCLIStore(t) // #5068 fixture: nil ge-0/0/x slots
			cfg := store.ActiveConfig()
			if cfg == nil || cfg.Interfaces.Interfaces == nil {
				t.Fatalf("fixture missing active config")
			}
			tc.mutate(cfg)
			c := &CLI{store: store, dp: nilGuardFlowDP{Manager: dataplane.New()}}
			require5813NoPanic(t, "showFlowSession "+tc.name, func() {
				_ = captureStdout(t, func() {
					if err := c.showFlowSession(nil); err != nil {
						t.Fatalf("showFlowSession: %v", err)
					}
				})
			})
		})
	}
}
