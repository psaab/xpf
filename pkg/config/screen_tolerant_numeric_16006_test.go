package config

import (
	"strings"
	"testing"
)

// #16006: on the tolerant load / peer-sync path a bad syn-flood subfield
// (alarm/source/destination-threshold, timeout) fell to 0/disabled behind
// the `if ok` guards, and a bad limit-session value did the same — the
// configured per-source/per-destination caps were silently off while the
// aggregate syn-flood gate stayed armed. Strict commit already rejects
// every bad value (#3317). The tolerant fix is two-armed:
//   - syn-flood subfields keep their Junos defaults (512/4000/4000/20)
//     because the leaf was authored — an unset leaf stays disabled, so
//     the repair must key off BadNumeric, not off `<= 0`;
//   - limit-session has no Junos default, so the profile is marked
//     BadNumericUnresolved and the snapshot builder substitutes the
//     conservative default for referencing zones instead of publishing
//     the profile with the cap silently disabled.
//
// FAIL-ON-REVERT: drop the #16006 default-repair loop in compileScreen
// and the syn-flood cells read 0; drop the BadNumericUnresolved marking
// in parseThresh and the limit-session cells read unresolved=false.

func TestScreenTolerantBadSynFloodSubfieldsKeepJunosDefaults16006(t *testing.T) {
	cases := []struct {
		name string
		line string
		want SynFloodConfig
	}{
		{"alarm", "set security screen ids-option s tcp syn-flood alarm-threshold abc",
			SynFloodConfig{AlarmThreshold: 512, AttackThreshold: 200}},
		{"source", "set security screen ids-option s tcp syn-flood source-threshold 1o00",
			SynFloodConfig{AttackThreshold: 200, SourceThreshold: 4000}},
		{"destination", "set security screen ids-option s tcp syn-flood destination-threshold -5",
			SynFloodConfig{AttackThreshold: 200, DestinationThreshold: 4000}},
		{"timeout", "set security screen ids-option s tcp syn-flood timeout xyz",
			SynFloodConfig{AttackThreshold: 200, Timeout: 20}},
		{"attack-still-defaults", "set security screen ids-option s tcp syn-flood attack-threshold abc",
			SynFloodConfig{AttackThreshold: 200}},
		{"over-maxuint32-source", "set security screen ids-option s tcp syn-flood source-threshold 4294967296",
			SynFloodConfig{AttackThreshold: 200, SourceThreshold: 4000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree(t, []string{tc.line}))
			if err != nil {
				t.Fatalf("lenient compile must boot: %v", err)
			}
			p := cfg.Security.Screen["s"]
			if p == nil || p.TCP.SynFlood == nil {
				t.Fatalf("profile/syn-flood missing: %+v", p)
			}
			if got := *p.TCP.SynFlood; got != tc.want {
				t.Errorf("SynFlood = %+v, want %+v (Junos default kept on tolerant path)", got, tc.want)
			}
			if p.BadNumericUnresolved {
				t.Errorf("syn-flood bad value has a Junos default; profile must stay resolved")
			}
			if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "screen numeric") {
				t.Errorf("expected downgraded screen-numeric warning, got %v", cfg.Warnings)
			}
			// Strict must still reject the same authored value.
			if _, err := CompileConfig(buildTree(t, []string{tc.line})); err == nil {
				t.Errorf("strict commit must reject bad syn-flood value")
			}
		})
	}
}

func TestScreenTolerantBadLimitSessionMarksUnresolved16006(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"source", "set security screen ids-option s limit-session source-ip-based foo"},
		{"destination", "set security screen ids-option s limit-session destination-ip-based 0"},
		{"source-over-maxuint32", "set security screen ids-option s limit-session source-ip-based 4294967296"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree(t, []string{tc.line}))
			if err != nil {
				t.Fatalf("lenient compile must boot: %v", err)
			}
			p := cfg.Security.Screen["s"]
			if p == nil {
				t.Fatalf("profile missing")
			}
			if !p.BadNumericUnresolved {
				t.Errorf("bad limit-session value has no Junos default; profile must be BadNumericUnresolved")
			}
			if p.LimitSession.SourceIPBased != 0 || p.LimitSession.DestinationIPBased != 0 {
				t.Errorf("no default may be invented for limit-session, got %+v", p.LimitSession)
			}
			if _, err := CompileConfig(buildTree(t, []string{tc.line})); err == nil {
				t.Errorf("strict commit must reject bad limit-session value")
			}
		})
	}
}

// An unset syn-flood subfield stays disabled on BOTH paths: the #16006
// repair keys off the BadNumeric record, so it must never arm a cap the
// operator did not author (#15269).
func TestScreenUnsetSynFloodSubfieldsStayDisabled16006(t *testing.T) {
	for _, compile := range []struct {
		name string
		fn   func(*ConfigTree) (*Config, error)
	}{{"strict", CompileConfig}, {"lenient", CompileConfigLenient}} {
		cfg, err := compile.fn(buildTree(t, []string{
			"set security screen ids-option s tcp syn-flood attack-threshold 2000",
		}))
		if err != nil {
			t.Fatalf("%s: %v", compile.name, err)
		}
		sf := cfg.Security.Screen["s"].TCP.SynFlood
		if sf.AlarmThreshold != 0 || sf.SourceThreshold != 0 || sf.DestinationThreshold != 0 || sf.Timeout != 0 {
			t.Errorf("%s: unset subfields must stay disabled, got %+v", compile.name, sf)
		}
		if cfg.Security.Screen["s"].BadNumericUnresolved {
			t.Errorf("%s: clean profile must not be unresolved", compile.name)
		}
	}
}

// A valid limit-session / syn-flood profile is never marked unresolved,
// and a bad value on a leaf WITH a default (icmp flood) does not mark it
// either — only the no-default limit-session leaves do.
func TestScreenResolvedControls16006(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set security screen ids-option s limit-session source-ip-based 100",
		"set security screen ids-option s icmp flood threshold abc",
		"set security screen ids-option s tcp syn-flood source-threshold 50",
	}))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	p := cfg.Security.Screen["s"]
	if p.BadNumericUnresolved {
		t.Errorf("valid limit-session + defaulted icmp flood must stay resolved")
	}
	if p.LimitSession.SourceIPBased != 100 {
		t.Errorf("valid limit-session value lost: %+v", p.LimitSession)
	}
	if p.ICMP.FloodThreshold != 1000 {
		t.Errorf("bad icmp flood must keep Junos default 1000, got %d", p.ICMP.FloodThreshold)
	}
	if p.TCP.SynFlood == nil || p.TCP.SynFlood.SourceThreshold != 50 {
		t.Errorf("valid source-threshold must not be overwritten by default repair: %+v", p.TCP.SynFlood)
	}
}

// A valid sibling value must survive a bad sibling in the same syn-flood
// block: the repair only fills fields that are still <= 0.
func TestScreenBadSubfieldKeepsValidSibling16006(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set security screen ids-option s tcp syn-flood source-threshold 50",
		"set security screen ids-option s tcp syn-flood alarm-threshold abc",
		"set security screen ids-option s tcp syn-flood timeout 30",
	}))
	if err != nil {
		t.Fatalf("lenient: %v", err)
	}
	sf := cfg.Security.Screen["s"].TCP.SynFlood
	want := SynFloodConfig{AlarmThreshold: 512, AttackThreshold: 200, SourceThreshold: 50, Timeout: 30}
	if *sf != want {
		t.Errorf("SynFlood = %+v, want %+v", *sf, want)
	}
}
