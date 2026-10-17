package config

import "testing"

// #14420 (DR15-H5): the PACKED (brace-elided) RA interface opening drops its
// whole tail when it opens with a zero-arg flag.
//
//	protocols { router-advertisement { interface ge-0/0/0 managed-configuration default-lifetime 0; } }
//	  before: ManagedConfig=false DefaultLifetimeSet=false -> sender advertises 1800
//	  after:  ManagedConfig=true  DefaultLifetime=0 DefaultLifetimeSet=true -> sender advertises 0
//
// The braced twin and the flat `set … managed-configuration default-lifetime 0`
// spelling (#8939) both already compile correctly. Only the packed opening —
// extra tokens on the `interface <name>` node's own Keys with no Children —
// was invisible: compileRouterAdvertisement iterated inst.node.Children only,
// so the instance was created (name survives) with an empty body. An explicit
// `default-lifetime 0` (RFC 4861 §6.2.1 "this router is NOT a default router")
// therefore reached the wire as 1800, hijacking host default-route selection —
// #4119's defect reached by dropping the leaf rather than coercing it.
func TestRAInterfacePackedOpening14420(t *testing.T) {
	compileBrace := func(t *testing.T, body string) *RAInterfaceConfig {
		t.Helper()
		p := NewParser(body)
		tree, errs := p.Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", body, errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig(%q): %v", body, err)
		}
		if len(cfg.Protocols.RouterAdvertisement) != 1 {
			t.Fatalf("%q: compiled %d RA interfaces, want 1", body, len(cfg.Protocols.RouterAdvertisement))
		}
		return cfg.Protocols.RouterAdvertisement[0]
	}
	wrap := func(inner string) string {
		return "protocols { router-advertisement { " + inner + " } }"
	}

	// Reference arm: braced spelling that always worked.
	ref := compileBrace(t, wrap("interface ge-0/0/0 { managed-configuration; default-lifetime 0; prefix 2001:db8::/64; }"))
	if !ref.ManagedConfig || !ref.DefaultLifetimeSet || ref.DefaultLifetime != 0 || len(ref.Prefixes) != 1 {
		t.Fatalf("braced reference arm incomplete (%+v prefixes=%v); comparison meaningless (#14420)", ref, ref.Prefixes)
	}

	cases := []struct {
		name  string
		inner string
		check func(t *testing.T, got *RAInterfaceConfig)
	}{
		{
			name:  "managed-configuration opening drops default-lifetime 0",
			inner: "interface ge-0/0/0 managed-configuration default-lifetime 0;",
			check: func(t *testing.T, got *RAInterfaceConfig) {
				if !got.ManagedConfig {
					t.Errorf("ManagedConfig=false, want true (#14420)")
				}
				if !got.DefaultLifetimeSet || got.DefaultLifetime != 0 {
					t.Errorf("DefaultLifetime=%d set=%v, want 0/true; sender would advertise 1800 instead of 0 (#14420/#4119)", got.DefaultLifetime, got.DefaultLifetimeSet)
				}
			},
		},
		{
			name:  "other-stateful-configuration opening drops whole tail",
			inner: "interface ge-0/0/0 other-stateful-configuration default-lifetime 0 prefix 2001:db8::/64;",
			check: func(t *testing.T, got *RAInterfaceConfig) {
				if !got.OtherStateful {
					t.Errorf("OtherStateful=false, want true (#14420)")
				}
				if !got.DefaultLifetimeSet || got.DefaultLifetime != 0 {
					t.Errorf("DefaultLifetime=%d set=%v, want 0/true (#14420)", got.DefaultLifetime, got.DefaultLifetimeSet)
				}
				if len(got.Prefixes) != 1 || got.Prefixes[0].Prefix != "2001:db8::/64" {
					t.Errorf("Prefixes=%v, want [2001:db8::/64] (#14420)", got.Prefixes)
				}
			},
		},
		{
			name:  "packed opening matches braced twin",
			inner: "interface ge-0/0/0 managed-configuration default-lifetime 0 prefix 2001:db8::/64;",
			check: func(t *testing.T, got *RAInterfaceConfig) {
				if got.ManagedConfig != ref.ManagedConfig || got.DefaultLifetime != ref.DefaultLifetime ||
					got.DefaultLifetimeSet != ref.DefaultLifetimeSet || len(got.Prefixes) != len(ref.Prefixes) {
					t.Errorf("packed=%+v prefixes=%v, braced=%+v prefixes=%v (#14420)", got, got.Prefixes, ref, ref.Prefixes)
				}
			},
		},
		{
			// Control: valued-leaf opening already worked via the compact
			// normalizer scope; must stay green.
			name:  "control valued-leaf opening",
			inner: "interface ge-0/0/0 default-lifetime 0 managed-configuration;",
			check: func(t *testing.T, got *RAInterfaceConfig) {
				if !got.ManagedConfig || !got.DefaultLifetimeSet || got.DefaultLifetime != 0 {
					t.Errorf("control regressed: %+v (#14420)", got)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := compileBrace(t, wrap(tc.inner))
			if got.Interface != "ge-0/0/0" {
				t.Fatalf("Interface=%q, want ge-0/0/0 (#14420)", got.Interface)
			}
			tc.check(t, got)
		})
	}
}
