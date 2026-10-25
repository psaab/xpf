package config

import (
	"strings"
	"testing"
)

// #15944 H13-03: a depth-1 packed screen family
// (`tcp syn-flood alarm-threshold 100 attack-threshold 500;`) must
// compile both thresholds. Before the fix, screenFamilyBody chained
// each token under the previous node with a single never-popping
// schema cursor: after the value-bearing `alarm-threshold 100` leaf,
// `attack-threshold` resolved against the leaf's childless schema,
// failed, and chained UNDER the leaf — strict compile rejected the
// valid stanza as an unsupported option and the second threshold
// never landed on the profile.
//
// FAIL-ON-REVERT: restoring the single-cursor chain makes the packed
// cells below fail strict compile (UnknownLeaves) or lose the second
// threshold.

func TestScreenPackedSynFloodSiblings15944(t *testing.T) {
	packed := compileHierStrict(t,
		"security { screen { ids-option s1 { tcp syn-flood alarm-threshold 100 attack-threshold 500; } } }\n")
	prof := packed.Security.Screen["s1"]
	if prof == nil || prof.TCP.SynFlood == nil {
		t.Fatalf("packed: profile/SynFlood missing: %+v", prof)
	}
	if prof.TCP.SynFlood.AlarmThreshold != 100 || prof.TCP.SynFlood.AttackThreshold != 500 {
		t.Fatalf("packed: SynFlood = %+v, want alarm=100 attack=500", prof.TCP.SynFlood)
	}
	if len(prof.UnknownLeaves) != 0 {
		t.Fatalf("packed: UnknownLeaves = %v, want none", prof.UnknownLeaves)
	}

	// The fully-braced control must agree exactly.
	braced := compileHierStrict(t,
		"security { screen { ids-option s1 { tcp { syn-flood { alarm-threshold 100; attack-threshold 500; } } } } }\n")
	bp := braced.Security.Screen["s1"]
	if bp.TCP.SynFlood.AlarmThreshold != 100 || bp.TCP.SynFlood.AttackThreshold != 500 {
		t.Fatalf("braced control: SynFlood = %+v, want alarm=100 attack=500", bp.TCP.SynFlood)
	}

	// The flat-set spelling of the same statement must agree too.
	flat := compileSetStrict(t,
		"set security screen ids-option s1 tcp syn-flood alarm-threshold 100",
		"set security screen ids-option s1 tcp syn-flood attack-threshold 500")
	fp := flat.Security.Screen["s1"]
	if fp.TCP.SynFlood.AlarmThreshold != 100 || fp.TCP.SynFlood.AttackThreshold != 500 {
		t.Fatalf("flat control: SynFlood = %+v, want alarm=100 attack=500", fp.TCP.SynFlood)
	}

	// Lenient channel: the packed run reaches the reader there too
	// (#9792 shapes) and must land the same values.
	lenient := compileHierLenient(t,
		"security { screen { ids-option s1 { tcp syn-flood alarm-threshold 100 attack-threshold 500; } } }\n")
	lp := lenient.Security.Screen["s1"]
	if lp.TCP.SynFlood.AlarmThreshold != 100 || lp.TCP.SynFlood.AttackThreshold != 500 {
		t.Fatalf("lenient packed: SynFlood = %+v, want alarm=100 attack=500", lp.TCP.SynFlood)
	}
}

// A packed run with a third sibling after two value leaves: every
// option must land, not just the second.
func TestScreenPackedSynFloodThreeSiblings15944(t *testing.T) {
	cfg := compileHierStrict(t,
		"security { screen { ids-option s1 { tcp syn-flood alarm-threshold 100 attack-threshold 500 source-threshold 300; } } }\n")
	sf := cfg.Security.Screen["s1"].TCP.SynFlood
	if sf.AlarmThreshold != 100 || sf.AttackThreshold != 500 || sf.SourceThreshold != 300 {
		t.Fatalf("SynFlood = %+v, want alarm=100 attack=500 source=300", sf)
	}
}

// Valueless limit-session leaves: `limit-session source-ip-based;`
// carries no value. #16571 deliberately amends the compile-level
// contract pinned here: a valueless numeric leaf is no longer
// "enabled without an explicit threshold" — it is a missing value.
// Strict commit now rejects it; the tolerant path keeps the leaf 0
// (disabled, no invented threshold) and warns. BadNumeric stays empty:
// a missing value is recorded on MissingValue, not as a bad number.
func TestScreenValuelessLimitSession15944(t *testing.T) {
	if _, err := CompileConfig(parseHierText(t,
		"security { screen { ids-option s1 { limit-session source-ip-based; } } }\n")); err == nil {
		t.Fatalf("strict commit accepted a valueless limit-session leaf (#16571)")
	} else if !strings.Contains(err.Error(), "limit-session source-ip-based") ||
		!strings.Contains(err.Error(), "declares a value and none was given") {
		t.Fatalf("strict error does not name the valueless leaf: %v", err)
	}
	cfg := compileHierLenient(t,
		"security { screen { ids-option s1 { limit-session source-ip-based; } } }\n")
	prof := cfg.Security.Screen["s1"]
	if prof.LimitSession.SourceIPBased != 0 {
		t.Fatalf("valueless source-ip-based = %d, want 0 (no threshold authored)", prof.LimitSession.SourceIPBased)
	}
	if len(prof.BadNumeric) != 0 {
		t.Fatalf("valueless leaf must not record BadNumeric: %v", prof.BadNumeric)
	}
	if len(prof.MissingValue) != 1 || prof.MissingValue[0] != "limit-session source-ip-based" {
		t.Fatalf("valueless leaf MissingValue = %v, want [limit-session source-ip-based]", prof.MissingValue)
	}
	// Positive control: the valued spelling lands, and the defaulted
	// syn-flood case (no attack-threshold) still arms at the Junos
	// default 200 — the refutation boundary from the research ledger.
	cfg2 := compileHierStrict(t,
		"security { screen { ids-option s1 { limit-session source-ip-based 100; tcp { syn-flood { alarm-threshold 100; } } } } }\n")
	prof2 := cfg2.Security.Screen["s1"]
	if prof2.LimitSession.SourceIPBased != 100 {
		t.Fatalf("valued source-ip-based = %d, want 100", prof2.LimitSession.SourceIPBased)
	}
	if prof2.TCP.SynFlood.AttackThreshold != 200 {
		t.Fatalf("defaulted syn-flood attack-threshold = %d, want Junos default 200", prof2.TCP.SynFlood.AttackThreshold)
	}
}
