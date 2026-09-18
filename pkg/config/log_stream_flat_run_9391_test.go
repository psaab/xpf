package config

import "testing"

// #9391 (the one OPERATOR-REACHABLE row of the original 26): `security log
// stream <s>` declares `port` with no valueType and no validator, so it is an
// ADMISSION HEAD — validateModifierChild has nothing to reject the token after
// it with, and the reader kept only the head.
//
// The consequence is an INVERSION rather than a loss. `Categories == 0` means
// ALL (pkg/logging/syslog.go: `return s.Categories == 0 || ...`), so dropping a
// NARROWING turns it into "export every category" — a collector scoped for one
// category receives all of them. Over-export, not a monitoring blind spot, and
// saying which it is decides the severity.
//
// This row exists at all only because the flat-set axis was restored: the
// braced-only gate found 26 differing containers of which ZERO were
// operator-reachable, and missed the one that was.
// The fixture deliberately uses valid category `policy`, not the historical
// `rt-flow`: `rt-flow` is absent from syslogCategories and only committed
// before the strict arm exposed the run, so keeping it would test enum
// validation rather than the #9391 reader loss (invalid-value coverage is
// owned by #3349).

func stream9391(t *testing.T, lines ...string) (*SyslogStream, bool) {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	strictOK := SchemaValidateWithDefinitions(tree, tree, nil) == nil
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, s := range cfg.Security.Log.Streams {
		return s, strictOK
	}
	t.Fatalf("no stream compiled")
	return nil, false
}

func TestLogStreamCategorySurvivesTheRun9391(t *testing.T) {
	// ORACLE: the same statements on separate lines.
	oracle, _ := stream9391(t,
		"set security log stream s1 host 10.9.9.9",
		"set security log stream s1 port 5514",
		"set security log stream s1 category policy",
	)
	if oracle.Category != "policy" || oracle.Port != 5514 {
		t.Fatalf("ORACLE: separate lines give port=%d category=%q — the control is "+
			"broken, so the arm below cannot be read", oracle.Port, oracle.Category)
	}

	got, strictOK := stream9391(t,
		"set security log stream s1 host 10.9.9.9",
		"set security log stream s1 port 5514 category policy",
	)
	// The reachability half: this row is OPERATOR-REACHABLE, and pinning that
	// keeps the severity honest. If the strict gate ever starts rejecting this
	// spelling the row becomes lenient-only and its severity drops, which is a
	// change someone should make deliberately rather than discover.
	if !strictOK {
		t.Errorf("the one-line spelling is no longer admitted at strict commit. That is " +
			"a severity change for this row — it would become lenient-only, like the " +
			"other 25 — and it should be a decision, not a surprise")
	}
	if got.Category != oracle.Category {
		t.Errorf("one-line gives category=%q, the separate-lines oracle gives %q. "+
			"Categories == 0 means ALL, so a dropped NARROWING is inverted into "+
			"exporting every category to a collector scoped for one",
			got.Category, oracle.Category)
	}
	if got.Port != oracle.Port {
		t.Errorf("port = %d, want %d — the head must survive its own run", got.Port, oracle.Port)
	}
}

// TestLogStreamSeveritySurvivesTheRun9391 is the sibling leaf, so the fix is
// bound to the CONTAINER rather than to the one leaf that was measured.
func TestLogStreamSeveritySurvivesTheRun9391(t *testing.T) {
	oracle, _ := stream9391(t,
		"set security log stream s1 host 10.9.9.9",
		"set security log stream s1 port 5514",
		"set security log stream s1 severity info",
	)
	got, _ := stream9391(t,
		"set security log stream s1 host 10.9.9.9",
		"set security log stream s1 port 5514 severity info",
	)
	if oracle.Severity != "info" {
		t.Fatalf("ORACLE broken: severity=%q", oracle.Severity)
	}
	if got.Severity != oracle.Severity {
		t.Errorf("one-line gives severity=%q, oracle gives %q", got.Severity, oracle.Severity)
	}
}

// TestLogStreamStrictCheckSeesTheSameStatements9391 binds the SECOND reader.
//
// The strict tls-profile check walks the stream body too. If it saw the
// UNexpanded children while the compiler saw the expanded ones, a value could
// be both checked and dropped — or, worse, checked by nobody. Both readers use
// the same expansion, and this drives a value the check would reject to prove
// the check actually reaches it.
func TestLogStreamStrictCheckSeesTheSameStatements9391(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range []string{
		"set security log stream s1 host 10.9.9.9",
		"set security log stream s1 port 99999 category policy",
	} {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("%v", err)
		}
	}
	// An out-of-range port must still be caught once the run is expanded. A
	// reader that only saw the head would check 99999 anyway (it IS the head);
	// what this pins is that expanding did not make the check skip it.
	if _, err := CompileConfig(tree); err == nil {
		t.Errorf("an out-of-range port in an expanded run was not rejected; the strict " +
			"check and the compiler must walk the SAME statements")
	}
}
