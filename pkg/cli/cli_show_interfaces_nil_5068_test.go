package cli

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// #5068: the local CLI `show interfaces` presenter family (terse / detail /
// extensive / vlans / the summary walk) and the interface-name / unit-number
// value-hint completers dereference present-but-nil InterfaceConfig and
// InterfaceUnit map values. Those nil slots are admitted on the tolerant /
// HA-sync config path that the compiler warn-pass already tolerates
// (compiler_validate_warn_nil_3494_test.go codifies "zz-nil-ifc": nil and a
// nil Units[N] value). CLI.Run has no panic recovery, so a nil-deref there
// exits the in-process xpfd. This test injects a nil interface value AND a
// nil unit value into the live ActiveConfig and drives every show-interfaces
// surface; reverting any of the added nil guards makes the matching call
// panic (RED on revert).

func nilInterfaceCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/9 {
        unit 0 { family inet { address 10.20.30.40/24; } }
    }
    ge-0/0/8 {
        unit 0 { family inet { address 10.20.31.40/24; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces { ge-0/0/8.0; ge-0/0/9.0; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatalf("fixture missing active config")
	}
	real := cfg.Interfaces.Interfaces["ge-0/0/9"]
	if real == nil || real.Units == nil {
		t.Fatalf("fixture missing ge-0/0/9 units")
	}
	// nil InterfaceConfig value (present key, nil pointer) — tolerated by the
	// compiler warn-pass (#3494); reachable in every range-all presenter.
	cfg.Interfaces.Interfaces["zz-nil-ifc"] = nil
	// nil InterfaceConfig value referenced by a security zone — drives the
	// summary walk's cfg.Interfaces.Interfaces[physName] deref (line ~139/365).
	cfg.Interfaces.Interfaces["ge-0/0/8"] = nil
	// nil InterfaceUnit value on an otherwise real interface — reachable in
	// every unit-iterating presenter and the unit-number completer.
	real.Units[7] = nil
	return store
}

func TestShowInterfacesNilMapValuesNoPanic5068(t *testing.T) {
	store := nilInterfaceCLIStore(t)
	c := &CLI{store: store} // dp nil: exercise the config-display walk only

	// A panic in any presenter unwinds through captureStdout and fails the
	// test; each reverts RED without its nil guard.
	//
	// Output is kept tiny on purpose. captureStdout drains its os.Pipe only
	// AFTER the callback returns, so a presenter that writes past the pipe
	// buffer would deadlock. The detail/extensive presenters build their
	// interface maps by iterating EVERY interface config value (the nil-deref
	// site) BEFORE filtering by name, so a filter that matches no host netdev
	// still exercises the guard while skipping the whole-host link dump. The
	// summary walk derefs the config only for zone-referenced logicals, so it
	// takes a filter that MATCHES the nil zone member (ge-0/0/8).
	const noMatch = "zz-no-such-netdev-5068"
	cases := []struct {
		name string
		fn   func() error
	}{
		{"terse", c.showInterfacesTerse},
		{"detail", func() error { return c.showInterfacesDetail(noMatch) }},
		{"extensive", func() error { return c.showInterfacesExtensiveFiltered(noMatch) }},
		{"vlans", c.showVlans},
		{"summary", func() error { return c.showInterfaces([]string{"ge-0/0/8"}) }},
	}
	for _, tc := range cases {
		captureStdout(t, func() {
			if err := tc.fn(); err != nil {
				t.Fatalf("show interfaces %s: %v", tc.name, err)
			}
		})
	}
}

// TestShowInterfacesMalformedZoneUnitSuffix6218 pins #6218 item 12. A zone
// member naming a NON-NUMERIC unit suffix (e.g. "ge-0/0/9.abc") is hard-
// rejected on the STRICT commit path since #5829/#5933
// (validateInterfaceUnitReferencesStrict), but that gate is deliberately
// DOWNGRADED to a warning on the tolerant/peer-sync load path (an older
// binary's already-persisted config, or an HA peer's config predating the
// gate, per the #1960 fail-closed-on-load doctrine) — so the malformed
// reference CAN still reach ActiveConfig in memory without ever having
// passed the strict gate. This test injects that post-load state directly
// (mirroring the sibling nil-map-value fixture above, which does the same
// for a defect class gated the same way) rather than fighting the lenient
// compiler path, and drives `show interfaces` over it.
//
// The pre-fix `strconv.Atoi(parts[1])` with its error silently discarded
// defaulted such a logical interface to unit 0 — a display-only
// misattribution that could ALSO borrow the REAL unit 0's config (VLAN id,
// address) for a zone member that names no such unit. -1 is the sentinel
// that can never collide with a real (always >= 0) configured unit.
//
// RED on revert: restoring `unitNum, _ = strconv.Atoi(parts[1])` renders
// "Logical interface lo.0" instead of "...-1", failing the assertion.
func TestShowInterfacesMalformedZoneUnitSuffix6218(t *testing.T) {
	// show interfaces prints "Physical interface: <name>, Not present" and
	// SKIPS the logical-unit loop entirely for a physical name with no live
	// kernel netdev — bind to the always-present loopback so the code path
	// under test is actually reached (mirrors TestShowInterfacesHostInbound3654).
	if _, err := net.InterfaceByName("lo"); err != nil {
		t.Skip("loopback interface not present; skipping show interfaces golden test")
	}
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    lo { unit 0 { family inet { address 127.0.0.2/32; } } }
}
security {
    zones {
        security-zone trust {
            interfaces { lo.0; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatalf("fixture missing active config")
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil {
		t.Fatalf("fixture missing trust zone")
	}
	// Simulate the tolerant-load-admitted malformed reference in-place, as
	// the sibling nil-map-value fixture above does for its own defect class.
	zone.Interfaces = []string{"lo.abc"}

	c := &CLI{store: store}
	out := captureStdout(t, func() {
		if err := c.showInterfaces([]string{"lo"}); err != nil {
			t.Fatalf("showInterfaces: %v", err)
		}
	})
	if strings.Contains(out, "Logical interface lo.0") {
		t.Errorf("malformed unit suffix must not display/borrow the real unit 0; got:\n%s", out)
	}
	if !strings.Contains(out, "Logical interface lo.-1") {
		t.Errorf("malformed unit suffix must render the -1 sentinel, not silently default; got:\n%s", out)
	}
}

func TestValueProviderInterfaceNilMapValuesNoPanic5068(t *testing.T) {
	c := &CLI{store: nilInterfaceCLIStore(t)}

	// Interface-name completion iterates every interface value — panics on the
	// nil InterfaceConfig without the completion.go guard.
	_ = c.valueProvider(config.ValueHintInterfaceName,
		[]string{"interfaces"})
	// Unit-number completion iterates one interface's units — panics on the
	// nil InterfaceUnit without the completion.go guard.
	_ = c.valueProvider(config.ValueHintUnitNumber,
		[]string{"interfaces", "ge-0/0/9", "unit"})
}
