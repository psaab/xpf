package config

import (
	"strings"
	"testing"
)

// #13138 (D2-07): the tolerant compile path must not let the #4146 junos-host
// advisory report coverage that the RI quarantines later change. cfg.Warnings
// and the post-compile projection must agree on the actual covered ingress.
func TestJunosHostWarningsMatchPostQuarantineProjection13138(t *testing.T) {
	denyPolicy := func(pol string) []string {
		return []string{
			"set security policies from-zone trust to-zone junos-host policy " + pol + " match source-address any",
			"set security policies from-zone trust to-zone junos-host policy " + pol + " match destination-address any",
			"set security policies from-zone trust to-zone junos-host policy " + pol + " match application junos-ssh",
			"set security policies from-zone trust to-zone junos-host policy " + pol + " then deny",
		}
	}
	zone := func(ifref string) []string {
		return []string{
			"set security zones security-zone trust interfaces " + ifref,
			"set security zones security-zone trust host-inbound-traffic system-services ssh",
		}
	}
	cases := []struct {
		name         string
		lines        []string
		policy       string
		wantLifeline bool
		// wantIngress false marks cases where the quarantine removed the
		// zone's only ingress row (#14390 tunnel removal): the policy then
		// has no applicable ingress at all, so the #4146 warning (which
		// warns about unenforced restrictions on a live ingress path)
		// still fires from validateJunosHostDirectDeliveryWarnings, and
		// the no-gap assertion below does not apply.
		wantIngress bool
	}{
		{
			name: "12520 removes undefined tunnel routing-instance target",
			lines: append(append([]string{
				"set interfaces gr-0/0/0 unit 0 tunnel source 192.0.2.1",
				"set interfaces gr-0/0/0 unit 0 tunnel destination 192.0.2.2",
				"set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination ghost",
				"set interfaces gr-0/0/0 unit 0 family inet address 10.0.0.1/30",
			}, zone("gr-0/0/0.0")...), denyPolicy("deny-ssh")...),
			policy: "deny-ssh",
			// The removed tunnel was the zone's only ingress: no gap is
			// recorded (nothing to cover), yet the deny still warns.
			wantIngress: false,
		},
		{
			name: "9909 drops WireGuard forwarding-instance membership",
			lines: append(append(append(wgBase9909(t, "wg0", "51820", wgKeyA, wgKeyB),
				"set routing-instances fwd instance-type forwarding",
				"set routing-instances fwd interface wg0",
				"set interfaces wg0 unit 0 family inet address 10.9.0.1/30",
			), zone("wg0.0")...), denyPolicy("deny-wg")...),
			policy:      "deny-wg",
			wantIngress: true,
		},
		{
			name: "11060 dual-claim quarantine removes stale gap",
			lines: append(append([]string{
				"set interfaces ge-0/0/7 unit 0 family inet address 10.70.0.1/24",
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue interface ge-0/0/7.0",
				"set routing-instances red instance-type virtual-router",
				"set routing-instances red interface ge-0/0/7.0",
			}, zone("ge-0/0/7.0")...), denyPolicy("deny-shared")...),
			policy:      "deny-shared",
			wantIngress: true,
		},
		{
			name: "11392 mgmt quarantine preserves lifeline warning",
			lines: append(append([]string{
				"set interfaces fxp0 unit 0 family inet address 10.7.0.1/24",
				"set routing-instances tenant instance-type virtual-router",
				"set routing-instances tenant interface fxp0.0",
			}, zone("fxp0.0")...), denyPolicy("deny-mgmt")...),
			policy:       "deny-mgmt",
			wantLifeline: true,
			wantIngress:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(treeFromSet(t, tc.lines))
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			key := JunosHostZonePairPolicyKey("trust", tc.policy)
			proj := BuildJunosHostDenyProjection(cfg)
			gaps := proj.unscopableIngressByKey[key]["trust"]
			lifeline := len(proj.LifelineOnlyZones[key]) > 0
			var policyWarnings []string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "\""+tc.policy+"\"") && strings.Contains(w, "#4146") {
					policyWarnings = append(policyWarnings, w)
				}
			}
			if tc.wantIngress && len(gaps) == 0 && !lifeline && len(policyWarnings) != 0 {
				t.Fatalf("warning claims incomplete direct-path coverage but post-quarantine projection has no gap for policy %q: warnings=%v projection={rendered:%v zones:%v}",
					tc.policy, policyWarnings, proj.RenderedPolicyKeys, proj.RenderedPolicyZoneKeys)
			}
			if !tc.wantIngress && len(policyWarnings) == 0 {
				t.Fatalf("policy %q with no surviving ingress should still warn (#4146): warnings=%v", tc.policy, cfg.Warnings)
			}
			if len(gaps) > 0 && !strings.Contains(strings.Join(policyWarnings, "\n"), "not covered on") {
				t.Fatalf("post-quarantine ingress gap for policy %q is silent in cfg.Warnings: gaps=%v warnings=%v", tc.policy, gaps, policyWarnings)
			}
			for nd := range gaps {
				if !strings.Contains(strings.Join(policyWarnings, "\n"), "\""+nd+"\"") {
					t.Fatalf("warning omits post-quarantine uncovered netdev %q for policy %q: gaps=%v warnings=%v", nd, tc.policy, gaps, policyWarnings)
				}
			}
			if lifeline != tc.wantLifeline {
				t.Fatalf("post-quarantine lifeline coverage=%v, want %v; zones=%v", lifeline, tc.wantLifeline, proj.LifelineOnlyZones[key])
			}
			if tc.wantLifeline && !strings.Contains(strings.Join(policyWarnings, "\n"), "lifeline-only") {
				t.Fatalf("warning omits post-quarantine lifeline-only coverage for policy %q: %v", tc.policy, policyWarnings)
			}
		})
	}
}
