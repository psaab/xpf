package config

import (
	"strings"
	"testing"
)

// buildJunosHostWarnTree parses flat set commands via the ParseSetCommand +
// SetPath loop (NewParser must not be used for set syntax — see CLAUDE.md
// "Testing flat set syntax").
func buildJunosHostWarnTree(t *testing.T, cmds []string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// junosHostWarnings returns the ValidateConfig warnings that mention the #4146
// junos-host direct-host-bound parity limitation.
func junosHostWarnings(t *testing.T, cmds []string) []string {
	t.Helper()
	cfg, err := CompileConfig(buildJunosHostWarnTree(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var got []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "to-zone junos-host") && strings.Contains(w, "#4146") {
			got = append(got, w)
		}
	}
	return got
}

// baseZones is the minimal zone/address-book scaffolding the junos-host policy
// cases reference.
var junosHostBaseZones = []string{
	"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
	"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	"set security zones security-zone untrust interfaces ge-0/0/1.0",
	"set security zones security-zone untrust host-inbound-traffic system-services ssh",
	"set security zones security-zone trust interfaces ge-0/0/0.0",
	"set security address-book global address bad-host 10.0.0.5/32",
	"set security address-book global address mgmt-net 10.10.0.0/24",
}

// TestJunosHostDirectDeliveryWarns is the #4146 fail-on-revert guard for the
// UN-REPRESENTABLE remainder: a `to-zone junos-host` policy the kernel nft chain
// cannot faithfully enforce on the direct host-bound path — a source-restricted
// PERMIT (whose implied deny-non-permitted half no path enforces) or a
// feed-tainted source — STILL emits the commit-time parity warning. #9504 moved
// `reject` and a `tcp-rst` ingress zone OUT of this remainder; they are pinned as
// enforced by TestJunosHostRejectAndTCPRstAreEnforced9504 below. Reverting the suppression logic must not silence
// these (they are a genuine, still-open gap). REPRESENTABLE denies are covered
// by TestJunosHostDirectDeliveryEnforcedNoWarn instead (they are now enforced).
func TestJunosHostDirectDeliveryWarns(t *testing.T) {
	cases := []struct {
		name       string
		policyName string
		reason     string // substring the warning must carry
		cmds       []string
	}{
		{
			name:       "zone-pair source-restricted permit (deny-non-permitted half is §6.5)",
			policyName: `"mgmt-only"`,
			reason:     "a source-restricted permit to-zone junos-host",
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security policies from-zone untrust to-zone junos-host policy mgmt-only match source-address mgmt-net",
				"set security policies from-zone untrust to-zone junos-host policy mgmt-only match destination-address any",
				"set security policies from-zone untrust to-zone junos-host policy mgmt-only match application junos-ssh",
				"set security policies from-zone untrust to-zone junos-host policy mgmt-only then permit",
			),
		},
		{
			name:       "deny with feed-tainted source (not commit-stable, §6.2)",
			policyName: `"block-feed"`,
			reason:     "a deny to-zone junos-host",
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name feed-bad profile feed-name malware",
				"set security policies from-zone untrust to-zone junos-host policy block-feed match source-address feed-bad",
				"set security policies from-zone untrust to-zone junos-host policy block-feed match destination-address any",
				"set security policies from-zone untrust to-zone junos-host policy block-feed match application any",
				"set security policies from-zone untrust to-zone junos-host policy block-feed then deny",
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := junosHostWarnings(t, tc.cmds)
			if len(got) != 1 {
				t.Fatalf("expected exactly 1 junos-host parity warning, got %d: %v", len(got), got)
			}
			w := got[0]
			for _, want := range []string{tc.policyName, tc.reason, "direct host-bound path", "docs/host-inbound-service-matrix.md"} {
				if !strings.Contains(w, want) {
					t.Errorf("warning missing substring %q:\n  %s", want, w)
				}
			}
		})
	}
}

// TestJunosHostRejectAndTCPRstAreEnforced9504 pins the two classes #9504 moved
// out of the remainder above. A `then reject`, and a deny on a `tcp-rst` ingress
// zone, now render with the verdict the runtime answers with rather than a silent
// drop, so their parity warning is suppressed. The verdict is asserted, not just
// the rendering: suppressing the warning for a rule that drops where the runtime
// RSTs would trade a visible gap for an invisible divergence.
func TestJunosHostRejectAndTCPRstAreEnforced9504(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  string
		verdict JunosHostVerdict
		cmds    []string
	}{
		{
			name:    "then reject",
			policy:  "reject-bad",
			verdict: JunosHostReject,
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security policies from-zone untrust to-zone junos-host policy reject-bad match source-address bad-host",
				"set security policies from-zone untrust to-zone junos-host policy reject-bad match destination-address any",
				"set security policies from-zone untrust to-zone junos-host policy reject-bad match application any",
				"set security policies from-zone untrust to-zone junos-host policy reject-bad then reject",
			),
		},
		{
			name:    "deny on a tcp-rst ingress zone",
			policy:  "block-rst",
			verdict: JunosHostDropTCPReset,
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security zones security-zone untrust tcp-rst",
				"set security policies from-zone untrust to-zone junos-host policy block-rst match source-address bad-host",
				"set security policies from-zone untrust to-zone junos-host policy block-rst match destination-address any",
				"set security policies from-zone untrust to-zone junos-host policy block-rst match application any",
				"set security policies from-zone untrust to-zone junos-host policy block-rst then deny",
			),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := junosHostWarnings(t, tc.cmds); len(got) != 0 {
				t.Errorf("an enforced policy still carries the parity warning (%d): %v", len(got), got)
			}
			cfg, err := CompileConfig(buildJunosHostWarnTree(t, tc.cmds))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			proj := BuildJunosHostDenyProjection(cfg)
			if !proj.RenderedPolicyKeys[JunosHostZonePairPolicyKey("untrust", tc.policy)] {
				t.Fatalf("%s is not marked rendered, so the suppressed warning above is a SILENT gap: %+v",
					tc.policy, proj)
			}
			n := 0
			for _, p := range proj.Programs {
				for _, r := range append(append([]JunosHostDenyRule{}, p.RulesV4...), p.RulesV6...) {
					n++
					if r.Verdict != tc.verdict {
						t.Errorf("rule verdict = %v, want %v — the kernel must answer as the runtime does", r.Verdict, tc.verdict)
					}
				}
			}
			if n == 0 {
				t.Fatal("no rule projected, so the verdict assertion above checked nothing")
			}
		})
	}
}

// TestJunosHostDirectDeliveryEnforcedNoWarn is the #4146 enforcement guard: a
// REPRESENTABLE `to-zone junos-host` DENY (static-address / any source,
// application any, no scheduler, non-tcp-rst enforceable ingress zone) is now
// kernel-enforced on the direct host-bound path, so its parity warning is
// SUPPRESSED. Reverting the suppression (or the BuildJunosHostDenyProjection
// rendered-key logic) makes a warning reappear and this test goes RED.
func TestJunosHostDirectDeliveryEnforcedNoWarn(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "zone-pair deny with static source scope (enforced)",
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security policies from-zone untrust to-zone junos-host policy block-bad match source-address bad-host",
				"set security policies from-zone untrust to-zone junos-host policy block-bad match destination-address any",
				"set security policies from-zone untrust to-zone junos-host policy block-bad match application any",
				"set security policies from-zone untrust to-zone junos-host policy block-bad then deny",
			),
		},
		{
			name: "zone-pair blanket deny source any (enforced)",
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security policies from-zone untrust to-zone junos-host policy block-all match source-address any",
				"set security policies from-zone untrust to-zone junos-host policy block-all match destination-address any",
				"set security policies from-zone untrust to-zone junos-host policy block-all match application any",
				"set security policies from-zone untrust to-zone junos-host policy block-all then deny",
			),
		},
		{
			name: "global deny to-zone junos-host (enforced in every applicable zone)",
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security zones security-zone trust host-inbound-traffic system-services ping",
				"set security policies global policy g-block match source-address bad-host",
				"set security policies global policy g-block match destination-address any",
				"set security policies global policy g-block match application any",
				"set security policies global policy g-block match to-zone junos-host",
				"set security policies global policy g-block then deny",
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := junosHostWarnings(t, tc.cmds); len(got) != 0 {
				t.Fatalf("expected no junos-host parity warning (enforced), got: %v", got)
			}
		})
	}
}

// TestJunosHostDirectDeliveryNoWarn confirms the trigger is conservative: a
// `to-zone junos-host` policy that only mirrors the coarse permit-by-service
// gate (a plain permit from any source), and a config with no junos-host
// policy at all, emit NO parity warning.
func TestJunosHostDirectDeliveryNoWarn(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
	}{
		{
			name: "plain permit-any to junos-host mirrors the coarse gate",
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security policies from-zone untrust to-zone junos-host policy allow-mgmt match source-address any",
				"set security policies from-zone untrust to-zone junos-host policy allow-mgmt match destination-address any",
				"set security policies from-zone untrust to-zone junos-host policy allow-mgmt match application any",
				"set security policies from-zone untrust to-zone junos-host policy allow-mgmt then permit",
			),
		},
		{
			name: "no junos-host policy at all",
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security policies from-zone trust to-zone untrust policy any-any match source-address any",
				"set security policies from-zone trust to-zone untrust policy any-any match destination-address any",
				"set security policies from-zone trust to-zone untrust policy any-any match application any",
				"set security policies from-zone trust to-zone untrust policy any-any then permit",
			),
		},
		{
			name: "global permit-any to junos-host mirrors the coarse gate",
			cmds: append(append([]string{}, junosHostBaseZones...),
				"set security policies global policy g-allow match source-address any",
				"set security policies global policy g-allow match destination-address any",
				"set security policies global policy g-allow match application any",
				"set security policies global policy g-allow match to-zone junos-host",
				"set security policies global policy g-allow then permit",
			),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := junosHostWarnings(t, tc.cmds); len(got) != 0 {
				t.Fatalf("expected no junos-host parity warning, got: %v", got)
			}
		})
	}
}

// TestJunosHostDirectDeliveryWarningsNilSafe mirrors the #3494 nil-tolerance of
// the surrounding warn pass: the sub-validator must not panic on a nil config
// or on the tolerant/HA-sync path's nil zone-pair / nil policy entries.
func TestJunosHostDirectDeliveryWarningsNilSafe(t *testing.T) {
	if got := validateJunosHostDirectDeliveryWarnings(nil); got != nil {
		t.Errorf("nil cfg: want nil, got %v", got)
	}
	cfg := &Config{}
	cfg.Security.Policies = []*ZonePairPolicies{
		nil,
		{FromZone: "untrust", ToZone: "junos-host", Policies: []*Policy{nil}},
	}
	cfg.Security.GlobalPolicies = []*Policy{nil}
	if got := validateJunosHostDirectDeliveryWarnings(cfg); got != nil {
		t.Errorf("nil entries: want nil, got %v", got)
	}
}
