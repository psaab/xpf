package config

import (
	"strings"
	"testing"
)

// #4626 M03: a scoped global policy's from-zone/to-zone match context is a zone
// SET. These tests pin the strict commit gate (per-element undefined reject,
// mixed-any reject, junos-host no-mix reject), the accumulate-across-lines
// behaviour (#3984), and the single-concrete-zone-only zone-local address book
// carve-out (A7).

func zoneSet4626Base() []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
	}
}

func compileScopedGlobal4626(t *testing.T, extra ...string) (*Config, error) {
	t.Helper()
	cmds := append(zoneSet4626Base(), extra...)
	cmds = append(cmds,
		"set security policies global policy p match source-address any",
		"set security policies global policy p match destination-address any",
		"set security policies global policy p match application any",
		"set security policies global policy p then deny",
	)
	return CompileConfig(build3148Tree(t, cmds...))
}

// TestScopedGlobalTwoSetLinesAccumulate proves two SEPARATE `set` lines for the
// same match leaf UNION into the zone set (#3984 multi-value accumulate), rather
// than the second REPLACING the first.
func TestScopedGlobalTwoSetLinesAccumulate(t *testing.T) {
	cfg, err := compileScopedGlobal4626(t,
		"set security policies global policy p match from-zone trust",
		"set security policies global policy p match from-zone dmz",
	)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := cfg.Security.GlobalPolicies[0].Match.FromZones
	if len(got) != 2 || got[0] != "dmz" || got[1] != "trust" {
		t.Fatalf("two-line accumulate FromZones = %q, want [dmz trust]", got)
	}
}

// TestScopedGlobalDedupSorts proves a duplicate + unsorted bracket list is
// canonicalized to a sorted, de-duplicated set.
func TestScopedGlobalDedupSorts(t *testing.T) {
	cfg, err := compileScopedGlobal4626(t,
		"set security policies global policy p match from-zone [ dmz trust dmz ]",
	)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	got := cfg.Security.GlobalPolicies[0].Match.FromZones
	if len(got) != 2 || got[0] != "dmz" || got[1] != "trust" {
		t.Fatalf("dedup/sort FromZones = %q, want [dmz trust]", got)
	}
}

// TestScopedGlobalStrictGate exercises the per-element strict commit gate.
func TestScopedGlobalStrictGate(t *testing.T) {
	cases := []struct {
		name       string
		matchLines []string
		wantErr    string // "" => must commit
	}{
		{
			name: "multi-zone from commits",
			matchLines: []string{
				"set security policies global policy p match from-zone [ trust dmz ]",
				"set security policies global policy p match to-zone untrust",
			},
		},
		{
			name: "undefined element rejected naming it",
			matchLines: []string{
				"set security policies global policy p match from-zone [ trust nonexistent ]",
			},
			wantErr: "nonexistent",
		},
		{
			name: "from-zone list mixing any rejected",
			matchLines: []string{
				"set security policies global policy p match from-zone [ any trust ]",
			},
			wantErr: "mixes `any`",
		},
		{
			name: "to-zone list mixing any rejected",
			matchLines: []string{
				"set security policies global policy p match to-zone [ any untrust ]",
			},
			wantErr: "mixes `any`",
		},
		{
			name: "to-zone list mixing junos-host rejected",
			matchLines: []string{
				"set security policies global policy p match to-zone [ junos-host untrust ]",
			},
			wantErr: "mixes `junos-host`",
		},
		{
			name: "from-zone element junos-host rejected",
			matchLines: []string{
				"set security policies global policy p match from-zone [ trust junos-host ]",
			},
			wantErr: "junos-host",
		},
		{
			name: "lone to-zone junos-host commits (host-inbound)",
			matchLines: []string{
				"set security policies global policy p match to-zone junos-host",
			},
		},
		{
			name: "single from-zone any commits",
			matchLines: []string{
				"set security policies global policy p match from-zone any",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileScopedGlobal4626(t, tc.matchLines...)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CompileConfig hard-failed on a valid scope: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CompileConfig accepted %q; want a reject naming %q", tc.name, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v; want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestScopedGlobalMultiZoneAddressBookGlobalResolution pins A7 as narrowed
// by #16596: a scoped global resolves its address references against the
// GLOBAL book for EVERY scope — Junos requires global-policy addresses to
// be in the global book, so a single-concrete-zone scope no longer keeps
// the former #3287/#4626 zone-local resolution either. All scopes agree.
func TestScopedGlobalMultiZoneAddressBookGlobalResolution(t *testing.T) {
	// A zone-local book entry `foo` under trust, and a distinct global `foo`.
	base := append(zoneSet4626Base(),
		"set security zones security-zone trust address-book address foo 10.1.0.0/24",
		"set security address-book global address foo 10.9.0.0/24",
	)

	buildWith := func(scope string) *Config {
		cmds := append(append([]string(nil), base...),
			"set security policies global policy p match from-zone "+scope,
			"set security policies global policy p match source-address foo",
			"set security policies global policy p match destination-address any",
			"set security policies global policy p match application any",
			"set security policies global policy p then deny",
		)
		cfg, err := CompileConfigLenient(build3148Tree(t, cmds...))
		if err != nil {
			t.Fatalf("CompileConfigLenient(scope=%q): %v", scope, err)
		}
		return cfg
	}

	// Single concrete zone (#16596): `foo` stays the bare name (GLOBAL book),
	// exactly like the multi-zone scope — the zone scope narrows which flows
	// the policy applies to, it does not rebind its address names.
	single := buildWith("trust")
	if got := single.Security.GlobalPolicies[0].Match.SourceAddresses; len(got) != 1 || got[0] != "foo" {
		t.Fatalf("single-zone scope source-address = %q, want the bare global-book name \"foo\" (#16596)", got)
	}

	// Multi-zone scope: `foo` stays the bare name (GLOBAL book) — no zone-local
	// qualification.
	multi := buildWith("[ trust dmz ]")
	if got := multi.Security.GlobalPolicies[0].Match.SourceAddresses; len(got) != 1 || got[0] != "foo" {
		t.Fatalf("multi-zone scope source-address = %q, want the bare global-book name \"foo\"", got)
	}
}
