package config

import (
	"strings"
	"testing"
)

// #14352: a compact per-interface `host-inbound-traffic <token> ...`
// statement folds its first tail token into UnknownChildren, but the
// strict unknown-child gate only rejected nested-marker entries at
// interface scope, so `apply-groups` / `apply-groups-except` /
// `apply-macro` (and any other non-nested unknown keyword) passed
// strict compilation with zero errors and installed a non-nil empty
// override that replaces the zone's host-inbound admission with
// deny-all on that interface. The zone-level stanza rejects every
// unknown child; the per-interface stanza must do the same. Braced
// apply-meta children (`host-inbound-traffic { apply-groups-except G;
// system-services ssh; }`) are expanded/skipped by parseHostInboundNode
// and must keep compiling — only the compact tail form, which the
// typed reader cannot bind and therefore records as unknown, rejects.

func perInterfaceHostInbound14352(t *testing.T, stanza string) *ConfigTree {
	t.Helper()
	tree := parseHierarchical(t, `
interfaces {
    ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
security {
    zones {
        security-zone trust {
            host-inbound-traffic { system-services { all; } }
            interfaces { ge-0/0/0.0 { `+stanza+` } }
        }
    }
}`)
	return tree
}

// TestPerInterfaceHostInboundCompactApplyGroupsIsRejectedStrict is the
// decisive regression named by #14352.
func TestPerInterfaceHostInboundCompactApplyGroupsIsRejectedStrict(t *testing.T) {
	cases := []struct {
		name    string
		stanza  string
		wantTok string
	}{
		{"apply-groups", `host-inbound-traffic apply-groups G;`, "apply-groups"},
		{"apply-groups-except", `host-inbound-traffic apply-groups-except G;`, "apply-groups-except"},
		{"apply-macro", `host-inbound-traffic apply-macro M;`, "apply-macro"},
		{"apply-groups with trailing body tokens", `host-inbound-traffic apply-groups G system-services ssh;`, "apply-groups"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := perInterfaceHostInbound14352(t, tc.stanza)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict CompileConfig accepted per-interface %q, installing an empty deny-all override (#14352)", tc.stanza)
			}
			if !strings.Contains(err.Error(), `interfaces "ge-0/0/0.0"`) ||
				!strings.Contains(err.Error(), `"`+tc.wantTok+`"`) {
				t.Fatalf("strict error = %v, want it to name interfaces \"ge-0/0/0.0\" and %q", err, tc.wantTok)
			}

			// Tolerant path still boots (#1960), warns naming the token,
			// and keeps the fail-closed empty override visible.
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient CompileConfig: %v", err)
			}
			if !hasWarning(cfg.Warnings, `interfaces "ge-0/0/0.0"`) ||
				!hasWarning(cfg.Warnings, `unknown child keyword "`+tc.wantTok+`"`) {
				t.Fatalf("lenient warnings %v do not name the discarded per-interface keyword %q", cfg.Warnings, tc.wantTok)
			}
			hib := cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0.0"]
			if hib == nil {
				t.Fatal("lenient compile dropped the per-interface host-inbound stanza")
			}
			if len(hib.UnknownChildren) != 1 || hib.UnknownChildren[0] != tc.wantTok {
				t.Fatalf("unknown children = %v, want [%q]", hib.UnknownChildren, tc.wantTok)
			}
			svc, proto, overridden := cfg.Security.Zones["trust"].InterfaceHostInboundEffective("ge-0/0/0.0")
			if !overridden || len(svc) != 0 || len(proto) != 0 {
				t.Fatalf("effective override = (%v, %v, %v), want empty deny-all override on tolerant path", svc, proto, overridden)
			}
		})
	}
}

// TestPerInterfaceHostInboundBracedApplyMetaStillCompiles14352 pins the
// legitimate shapes the strict rejection must not break: braced
// apply-meta children are group machinery, not unknown children, and a
// well-formed braced or packed body keeps compiling.
func TestPerInterfaceHostInboundBracedApplyMetaStillCompiles14352(t *testing.T) {
	cases := []struct {
		name    string
		stanza  string
		wantSvc string
	}{
		{"braced apply-groups-except with body", `host-inbound-traffic { apply-groups-except G; system-services ssh; }`, "ssh"},
		{"braced apply-macro with body", `host-inbound-traffic { apply-macro M { k v; } system-services ssh; }`, "ssh"},
		{"braced body", `host-inbound-traffic { system-services ssh; }`, "ssh"},
		{"packed body", `host-inbound-traffic system-services ssh;`, "ssh"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(perInterfaceHostInbound14352(t, tc.stanza))
			if err != nil {
				t.Fatalf("strict CompileConfig rejected legitimate per-interface stanza %q: %v", tc.stanza, err)
			}
			hib := cfg.Security.Zones["trust"].InterfaceHostInbound["ge-0/0/0.0"]
			if hib == nil || len(hib.SystemServices) != 1 || hib.SystemServices[0] != tc.wantSvc {
				t.Fatalf("per-interface hib = %+v, want system-services [%s]", hib, tc.wantSvc)
			}
			if len(hib.UnknownChildren) != 0 {
				t.Fatalf("legitimate stanza recorded unknown children %v", hib.UnknownChildren)
			}
		})
	}
}
