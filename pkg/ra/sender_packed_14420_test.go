package ra

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #14420, the WIRE consequence of the packed RA opening.
//
//	protocols { router-advertisement { interface trust0 managed-configuration default-lifetime 0; } }
//	  before: RouterLifetime 1800 ("I am a default router")
//	  after:  RouterLifetime 0    ("I am NOT a default router", RFC 4861 §6.2.1)
func TestBuildRA_PackedOpeningPreservesExplicitZero14420(t *testing.T) {
	compileBrace := func(t *testing.T, body string) *config.RAInterfaceConfig {
		t.Helper()
		p := config.NewParser(body)
		tree, errs := p.Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", body, errs)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", body, err)
		}
		for _, i := range cfg.Protocols.RouterAdvertisement {
			if i != nil && i.Interface == "trust0" {
				return i
			}
		}
		t.Fatal("no RA interface trust0 (#14420)")
		return nil
	}

	braced := newTestSender3895(compileBrace(t,
		`protocols { router-advertisement { interface trust0 { managed-configuration; default-lifetime 0; } } }`)).buildRA()
	if braced.RouterLifetime != 0 {
		t.Fatalf("braced reference no longer reaches wire as RouterLifetime 0 (got %v); comparison meaningless (#14420)", braced.RouterLifetime)
	}
	packed := newTestSender3895(compileBrace(t,
		`protocols { router-advertisement { interface trust0 managed-configuration default-lifetime 0; } }`)).buildRA()
	if packed.RouterLifetime != braced.RouterLifetime {
		t.Errorf("packed spelling marshals RouterLifetime %v, braced marshals %v. "+
			"Explicit default-lifetime 0 means \"this router is NOT a default router\" (RFC 4861 §6.2.1); "+
			"advertising %v hijacks host default-route selection (#14420/#4119)",
			packed.RouterLifetime, braced.RouterLifetime, packed.RouterLifetime)
	}
	if !packed.ManagedConfiguration {
		t.Errorf("packed spelling lost managed-configuration: RA ManagedConfiguration flag false, want true (#14420)")
	}
}
