package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6640 — the ENFORCEMENT half of the shared-view claim.
//
// The commit-time advisory in pkg/config used to re-derive its own
// approximation of this package's override resolution, so the two reasoned
// about different objects and the advisory contradicted enforcement. The fix
// moved the resolution into pkg/config (ResolveInterfaceHostInbound) and made
// this package delegate to it.
//
// A claim that two callers SHARE a function is only worth what a mutation can
// show, so this test is deliberately anchored to the same fixture as
// pkg/config/host_inbound_advisory_effective_view_6640_test.go
// (`hostInbound6640PhysicalUnit`, reproduced here because the packages cannot
// share test helpers). Breaking config.ResolveInterfaceHostInbound — dropping
// the #3720 physical->unit merge, say — must red BOTH files. If only the
// advisory reds, they are not actually sharing it and the fix is a fourth copy
// of enforcement semantics rather than the end of the class.

func hostInbound6640Cfg(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func hostInbound6640PhysicalUnitLines(phy, unit string) []string {
	return []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces ge-0/0/0 host-inbound-traffic system-services " + phy,
		"set security zones security-zone trust interfaces ge-0/0/0.0 host-inbound-traffic system-services " + unit,
	}
}

// TestEnforcementFullAdmitsTheTwoPhysicalUnitShapes_6640 is the observation the
// advisory used to contradict. In both orders the physical-level override is
// inherited by ge-0/0/0.0 and UNIONED with the unit-level one (#3720), so the
// effective set carries `any-service` and the classifier admits an arbitrary
// host-bound tuple.
//
// The tuple is tcp/7000 — a port no named system-service admits — so a token
// admit here can only come from the full-admit, not from some other token
// happening to cover it.
func TestEnforcementFullAdmitsTheTwoPhysicalUnitShapes_6640(t *testing.T) {
	for _, tc := range []struct{ name, phy, unit string }{
		{"physical any-service, unit rpm", "any-service", "rpm"},
		{"physical rpm, unit any-service", "rpm", "any-service"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := hostInbound6640Cfg(t, hostInbound6640PhysicalUnitLines(tc.phy, tc.unit))

			resolved := config.ResolveInterfaceHostInbound(cfg)
			if resolved["ge-0/0/0.0"] == nil {
				t.Fatalf("the shared resolver produced no override for the unit key: %v", resolved)
			}
			svc, _ := effectiveHostInboundTokens(
				cfg.Security.Zones["trust"], "ge-0/0/0.0", resolved["ge-0/0/0.0"])
			var full bool
			for _, s := range svc {
				if config.HostInboundFullAdmitService(s) {
					full = true
				}
			}
			if !full {
				t.Errorf("effective set on ge-0/0/0.0 = %v, want a full admit — the physical "+
					"and unit overrides are BOTH interface-level statements and union (#3720)", svc)
			}

			adm := ClassifyHostInboundForInterface(cfg, "trust", "ge-0/0/0.0", 6, true, 7000, true, nil, "inet")
			if adm.Status == HostInboundDenied {
				t.Errorf("classifier DENIED tcp/7000 on a full-admitting interface (status %v) — "+
					"if this reds together with the pkg/config advisory test, the two are sharing "+
					"the resolver, which is the point", adm.Status)
			}
		})
	}
}

// TestEnforcementDeniesWhenNeitherLevelFullAdmits_6640 is the enforcement-side
// negative control, the minimal edit of the rows above: with the unit's token
// `ping` instead of `any-service` the union is [rpm ping], nothing full-admits,
// and tcp/7000 really is denied. Without it, "the classifier did not deny" would
// be satisfied by a classifier that never denies anything.
func TestEnforcementDeniesWhenNeitherLevelFullAdmits_6640(t *testing.T) {
	cfg := hostInbound6640Cfg(t, hostInbound6640PhysicalUnitLines("rpm", "ping"))
	adm := ClassifyHostInboundForInterface(cfg, "trust", "ge-0/0/0.0", 6, true, 7000, true, nil, "inet")
	if adm.Status != HostInboundDenied {
		t.Errorf("tcp/7000 with effective set [rpm ping] must be DENIED, got %v", adm.Status)
	}
}
