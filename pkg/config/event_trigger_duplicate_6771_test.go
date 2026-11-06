package config

import "testing"

// #6771: the `within … trigger` compile read used FindChild — the FIRST
// same-keyed sibling — on both levels.
//
// The hierarchical parser keeps repeated same-keyed statements as SIBLINGS
// (parseStatements), and SetPath does the same for a repeated flat `set`.
// Measured: `trigger on 3` followed by `trigger on 9` yields TWO leaf children
// under one `trigger` node:
//
//	Keys=[within 60]
//	  Keys=[trigger]
//	    Keys=[on 3]  leaf
//	    Keys=[on 9]  leaf
//
// So the later value was silently dropped and the operator got 3 where Junos —
// which REPLACES a single-valued leaf on a later set — gives 9. It committed
// clean with zero warnings.
//
// This is the same defect #6714 fixed two cases below in the same switch, for
// `then change-configuration commands`, with the same reasoning. `trigger` is
// the sibling input that rule never reached.
//
// No warning is asserted for the duplicate on purpose: re-setting a leaf is
// ordinary operator behaviour and every override would trip it. Taking the LAST
// value IS the Junos semantic.

func eventTree6771(t *testing.T, sets ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range sets {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func within6771(t *testing.T, cfg *Config) *EventWithin {
	t.Helper()
	for _, p := range cfg.EventOptions {
		if p.Name != "P" {
			continue
		}
		if len(p.WithinClauses) != 1 {
			t.Fatalf("expected exactly one within clause, got %d", len(p.WithinClauses))
		}
		return p.WithinClauses[0]
	}
	t.Fatal("policy P did not compile")
	return nil
}

// TestDuplicateTriggerOnTakesTheLastValue6771 is the defect proper.
func TestDuplicateTriggerOnTakesTheLastValue6771(t *testing.T) {
	cfg := eventTree6771(t,
		"set event-options policy P events ping_probe_failed",
		"set event-options policy P within 60 trigger on 3",
		"set event-options policy P within 60 trigger on 9",
	)
	w := within6771(t, cfg)
	if w.TriggerOn != 9 {
		t.Errorf("TriggerOn = %d, want 9 — a later `set` of a single-valued leaf REPLACES in "+
			"Junos, but the first-only sibling read kept the earlier value and dropped the "+
			"operator's override silently, with a clean commit and no warning", w.TriggerOn)
	}
}

// TestDuplicateTriggerUntilTakesTheLastValue6771 pins the sibling keyword —
// `until` had the identical first-only read, and a fix applied to `on` alone
// would leave it open while this file still looked covered.
func TestDuplicateTriggerUntilTakesTheLastValue6771(t *testing.T) {
	cfg := eventTree6771(t,
		"set event-options policy P events ping_probe_failed",
		"set event-options policy P within 60 trigger until 4",
		"set event-options policy P within 60 trigger until 11",
	)
	w := within6771(t, cfg)
	if w.TriggerUntil != 11 {
		t.Errorf("TriggerUntil = %d, want 11 — the later value must replace the earlier one",
			w.TriggerUntil)
	}
	// TriggerOn must stay ZERO. Asserting only TriggerUntil above cannot see a
	// read that takes every CHILD of the trigger node regardless of keyword —
	// such a read sets TriggerOn from the `until` value too, and a config with
	// only `until` would then look like the contradictory on+until form.
	// (Measured: a mutation doing exactly that passed until this assertion
	// existed.)
	if w.TriggerOn != 0 {
		t.Errorf("TriggerOn = %d for a trigger specifying ONLY `until`, want 0 — the "+
			"keyword must select which field is written, not merely the position of the "+
			"child", w.TriggerOn)
	}
}

// TestSingleTriggerIsUnchanged6771 is the TIGHTENING control.
//
// Reading every sibling and letting the last win must not disturb the ordinary
// single-trigger case. A fix that, say, took the last CHILD regardless of
// keyword, or reset the field before scanning, would satisfy both tests above
// while corrupting the common config.
func TestSingleTriggerIsUnchanged6771(t *testing.T) {
	cfg := eventTree6771(t,
		"set event-options policy P events ping_probe_failed",
		"set event-options policy P within 60 trigger on 3",
	)
	w := within6771(t, cfg)
	if w.Seconds != 60 || w.TriggerOn != 3 || w.TriggerUntil != 0 {
		t.Errorf("single trigger compiled as seconds=%d on=%d until=%d, want 60/3/0",
			w.Seconds, w.TriggerOn, w.TriggerUntil)
	}
}

// TestContradictoryTriggerStillRejected6771 pins that reading MORE siblings did
// not weaken the existing contradiction gate: `on` and `until` together is
// rejected at commit, and must stay rejected now that both are read from
// every sibling rather than the first.
func TestContradictoryTriggerStillRejected6771(t *testing.T) {
	tree := &ConfigTree{}
	for _, c := range []string{
		"set event-options policy P events ping_probe_failed",
		"set event-options policy P within 60 trigger on 3",
		"set event-options policy P within 60 trigger until 5",
	} {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Error("a trigger specifying BOTH on and until compiled cleanly; the contradiction " +
			"gate must survive the widened sibling read")
	}
}

// TestMultipleWithinClausesUnaffected6771 pins that distinct `within` values
// still produce distinct clauses — measured as already correct, and worth
// holding so the trigger fix cannot collapse them.
func TestMultipleWithinClausesUnaffected6771(t *testing.T) {
	cfg := eventTree6771(t,
		"set event-options policy P events ping_probe_failed",
		"set event-options policy P within 60 trigger on 3",
		"set event-options policy P within 120 trigger on 7",
	)
	for _, p := range cfg.EventOptions {
		if p.Name != "P" {
			continue
		}
		if len(p.WithinClauses) != 2 {
			t.Fatalf("expected 2 within clauses, got %d", len(p.WithinClauses))
		}
		got := map[int]int{}
		for _, w := range p.WithinClauses {
			got[w.Seconds] = w.TriggerOn
		}
		if got[60] != 3 || got[120] != 7 {
			t.Errorf("within clauses compiled as %v, want {60:3, 120:7}", got)
		}
		return
	}
	t.Fatal("policy P did not compile")
}
