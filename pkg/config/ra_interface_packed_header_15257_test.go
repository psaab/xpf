package config

import (
	"strings"
	"testing"
)

// #15257 (A88-03): `interface X managed-configuration default-lifetime 0 { ... }`
// fanned out phantom RA entries via bracketedGroupInstances8794.
// Strict must reject naming the header token; lenient warns and compiles
// as before (#1960); bracketed and bare groups still fan out.
func TestRAInterfacePackedHeaderPhantomFanout15257(t *testing.T) {
	wrap := func(inner string) string {
		return "protocols { router-advertisement { " + inner + " } }"
	}
	mixed := wrap("interface ge-0/0/0 managed-configuration default-lifetime 0 { prefix 2001:db8::/64; }")

	t.Run("strict rejects mixed packed header", func(t *testing.T) {
		tree, errs := NewParser(mixed).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "managed-configuration") || !strings.Contains(err.Error(), "#15257") {
			t.Fatalf("want strict rejection naming managed-configuration #15257, got %v", err)
		}
	})

	t.Run("lenient warns and compiles as before", func(t *testing.T) {
		tree, errs := NewParser(mixed).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#15257") {
				found = true
			}
		}
		if !found {
			t.Fatalf("want lenient #15257 warning, got %v", cfg.Warnings)
		}
		// Lenient keeps historical compilation (phantoms included) so a
		// persisted config boots; strict is the gate.
		if len(cfg.Protocols.RouterAdvertisement) == 0 {
			t.Fatalf("lenient compiled no RA entries")
		}
	})

	t.Run("other-stateful packed header also rejected", func(t *testing.T) {
		txt := wrap("interface ge-0/0/0 other-stateful-configuration { prefix 2001:db8::/64; }")
		tree, _ := NewParser(txt).Parse()
		if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "other-stateful-configuration") {
			t.Fatalf("want rejection, got %v", err)
		}
	})

	t.Run("bracketed group still fans out", func(t *testing.T) {
		txt := wrap("interface [ ge-0/0/0 ge-0/0/1 ] { managed-configuration; default-lifetime 0; prefix 2001:db8::/64; }")
		tree, errs := NewParser(txt).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("bracketed group rejected: %v", err)
		}
		if len(cfg.Protocols.RouterAdvertisement) != 2 {
			t.Fatalf("got %d RA entries, want 2", len(cfg.Protocols.RouterAdvertisement))
		}
		for _, ra := range cfg.Protocols.RouterAdvertisement {
			if !ra.ManagedConfig || !ra.DefaultLifetimeSet || ra.DefaultLifetime != 0 || len(ra.Prefixes) != 1 {
				t.Errorf("group member incomplete: %+v", ra)
			}
		}
	})

	t.Run("bare group still fans out", func(t *testing.T) {
		txt := wrap("interface ge-0/0/0 ge-0/0/1 { managed-configuration; default-lifetime 0; prefix 2001:db8::/64; }")
		tree, _ := NewParser(txt).Parse()
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("bare group rejected: %v", err)
		}
		if len(cfg.Protocols.RouterAdvertisement) != 2 {
			t.Fatalf("got %d RA entries, want 2", len(cfg.Protocols.RouterAdvertisement))
		}
	})

	t.Run("braced single interface unchanged", func(t *testing.T) {
		txt := wrap("interface ge-0/0/0 { managed-configuration; default-lifetime 0; prefix 2001:db8::/64; }")
		tree, _ := NewParser(txt).Parse()
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("braced rejected: %v", err)
		}
		if len(cfg.Protocols.RouterAdvertisement) != 1 {
			t.Fatalf("got %d, want 1", len(cfg.Protocols.RouterAdvertisement))
		}
		ra := cfg.Protocols.RouterAdvertisement[0]
		if ra.Interface != "ge-0/0/0" || !ra.ManagedConfig || !ra.DefaultLifetimeSet || len(ra.Prefixes) != 1 {
			t.Errorf("braced changed: %+v", ra)
		}
	})

	t.Run("packed no-brace opening unchanged", func(t *testing.T) {
		// #14420 spelling: no braced body, so no fan-out and no gate.
		txt := wrap("interface ge-0/0/0 managed-configuration default-lifetime 0;")
		tree, _ := NewParser(txt).Parse()
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("packed no-brace rejected: %v", err)
		}
		if len(cfg.Protocols.RouterAdvertisement) != 1 || !cfg.Protocols.RouterAdvertisement[0].ManagedConfig || !cfg.Protocols.RouterAdvertisement[0].DefaultLifetimeSet {
			t.Errorf("packed no-brace changed: %+v", cfg.Protocols.RouterAdvertisement)
		}
	})
}
