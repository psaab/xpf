package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16556 probe: on a tolerant load, ge-0/0/0.0 is claimed by trust AND
// untrust, so the runtime map binds it to NEITHER and it fails closed.
// `show security zones` must mark it [UNBOUND ...] under both zones and
// exclude it from "Interfaces bound"; `show interfaces` must not print a
// map-order-chosen zone; `show system alarms` must name it. The control
// ge-0/0/1.0 (trust only) renders bound and unchanged.

func quarantinedZoneCfg16556(t *testing.T) *config.Config {
	t.Helper()
	text := `
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
security {
    zones {
        security-zone trust { interfaces [ ge-0/0/0.0 ge-0/0/1.0 ]; }
        security-zone untrust { interfaces [ ge-0/0/0.0 ]; }
    }
}
`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("Parse() errors = %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if _, ok := config.QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/0.0"]; !ok {
		t.Fatalf("premise: ge-0/0/0.0 not quarantined: %v", config.QuarantinedZoneInterfaceKeys(cfg))
	}
	if got := config.InterfaceZoneMap(cfg)["ge-0/0/0.0"]; got != "" {
		t.Fatalf("premise: runtime map binds contested key to %q", got)
	}
	return cfg
}

func TestQuarantinedZoneInterfaceShownUnbound16556(t *testing.T) {
	cfg := quarantinedZoneCfg16556(t)

	out := captureStdout(t, func() {
		if err := (&CLI{}).showZonesDisplay(cfg, false, ""); err != nil {
			t.Fatalf("showZonesDisplay: %v", err)
		}
	})
	// trust: one bound (ge-0/0/1.0), contested member annotated.
	if !strings.Contains(out, "Interfaces bound: 1") {
		t.Fatalf("trust bound count wrong:\n%s", out)
	}
	// untrust: zero bound, contested member annotated there too.
	if !strings.Contains(out, "Interfaces bound: 0") {
		t.Fatalf("untrust bound count wrong (want 0):\n%s", out)
	}
	annotated := "ge-0/0/0.0 [UNBOUND — claimed by zones trust and untrust]"
	if n := strings.Count(out, annotated); n != 2 {
		t.Fatalf("annotated member count = %d, want 2 (both zones):\n%s", n, out)
	}
	// Control stays a plain bound listing.
	if !strings.Contains(out, "    ge-0/0/1.0\n") {
		t.Fatalf("control member not listed plainly:\n%s", out)
	}

	// show system alarms names the interface.
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	store.SetCompiledForTesting(cfg)
	alarmOut := captureStdout(t, func() {
		if err := (&CLI{store: store}).handleShowSystem([]string{"alarms"}); err != nil {
			t.Fatalf("showSystem alarms: %v", err)
		}
	})
	if !strings.Contains(alarmOut, "ge-0/0/0.0") ||
		!strings.Contains(alarmOut, "bound to neither") {
		t.Fatalf("system alarms do not name the quarantined interface:\n%s", alarmOut)
	}
}
