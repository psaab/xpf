package config

import (
	"strings"
	"testing"
)

// #3320: a custom application's `inactivity-timeout` / `timeout` leaf was an
// untyped schema leaf with no integer validation. A malformed value (a unit
// suffix like "30s", a non-numeric like "thirty", a negative, or an
// out-of-range integer) committed cleanly and was then SILENTLY dropped by
// compileApplications (the strconv.Atoi error was ignored), leaving
// InactivityTimeout at its zero default — which the userspace serializer treats
// as "use the global per-protocol timeout" (clampNonNegU32). The operator's
// intent to age a sensitive application early was silently lost.
//
// The fix has two layers, both with the #1960 strict-commit / lenient-load
// downgrade:
//   - schema typed leaf (schema_security.go ValueInteger + ValidateInteger):
//     rejects a malformed TOP-LEVEL value at commit-check via SchemaValidate
//     (downgraded to a warning on the tolerant load / peer-sync path by
//     compileTreeLenient). Covers every application, referenced or not.
//   - validateApplicationSpecsStrict (compiler_validate_strict_application.go): rejects a
//     malformed top-level OR inline-term timeout of a REFERENCED application via
//     the recorded Application.UnknownTimeouts (the inline-term shape is opaque
//     to the schema walk, so the compiler gate is what covers it), downgraded to
//     a warning on the tolerant path (lenientApplicationSpecs).
//
// All trees are built from flat `set` commands via flatTreeFromSets / SetPath,
// the only correct way to exercise set syntax (see CLAUDE.md).

// referencedTimeoutApp wires a policy `deny` rule that matches an application
// whose top-level inactivity-timeout/timeout leaf carries `val`. The protocol
// and destination-port are valid, so a reject is caused solely by the timeout.
func referencedTimeoutApp(leaf, val string) []string {
	return []string{
		"set applications application BAD protocol tcp",
		"set applications application BAD destination-port 80",
		"set applications application BAD " + leaf + " " + val,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application BAD",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	}
}

// referencedTimeoutTermApp wires a policy that matches the implicit
// application-set of a multi-term application whose inline term carries a
// timeout of `val`. The inline term collapses every token onto one node, so it
// must be a single `set` line (see TestMultiTermApplication / parser_ast_test).
func referencedTimeoutTermApp(val string) []string {
	return []string{
		"set applications application MULTI term t1 protocol tcp destination-port 80 inactivity-timeout " + val,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application MULTI",
		"set security policies from-zone trust to-zone untrust policy p then deny",
	}
}

// A referenced application with a malformed top-level inactivity-timeout must
// reject at commit, naming the application and the bad token. Covers the issue's
// four malformed shapes: unit suffix, non-numeric, negative, out-of-range.
//
// FAIL-ON-REVERT: removing the `len(app.UnknownTimeouts) > 0` block in
// validateApplicationSpecsStrict (or restoring the silent `strconv.Atoi(...);
// err == nil` drop in compileApplications) makes these commit clean again, so
// CompileConfig returns nil and the `err == nil` assertions fire RED.
func TestApplicationSpec_ReferencedBadInactivityTimeout_RejectsAtCommit(t *testing.T) {
	// Only MALFORMED values reject: non-numeric, negative, and over-max. The
	// 86401 / 99999 cases pin the upper edge (86400 is the last accepted value).
	// 0 is NOT here — it is the valid inherit-global sentinel (see the accept
	// test below).
	for _, val := range []string{"30s", "thirty", "-1", "86401", "99999"} {
		tree := flatTreeFromSets(t, referencedTimeoutApp("inactivity-timeout", val)...)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("inactivity-timeout %q: expected commit to reject, got nil", val)
		}
		if !strings.Contains(err.Error(), "BAD") ||
			!strings.Contains(err.Error(), "inactivity-timeout") ||
			!strings.Contains(err.Error(), val) {
			t.Fatalf("inactivity-timeout %q: error %q must name application BAD, the leaf, and the bad value", val, err.Error())
		}
	}
}

// The `timeout` alias leaf is silently dropped the same way; it must reject too.
func TestApplicationSpec_ReferencedBadTimeoutAlias_RejectsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedTimeoutApp("timeout", "5m")...)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to reject application BAD with timeout 5m")
	}
	if !strings.Contains(err.Error(), "BAD") || !strings.Contains(err.Error(), "5m") {
		t.Fatalf("error %q must name application BAD and the bad value 5m", err.Error())
	}
}

// A malformed timeout inside an inline TERM (opaque to the schema walk) must
// reject at commit via the recorded UnknownTimeouts. The application is matched
// through its implicit application-set.
func TestApplicationSpec_ReferencedBadTermTimeout_RejectsAtCommit(t *testing.T) {
	for _, val := range []string{"30s", "thirty", "100000"} {
		tree := flatTreeFromSets(t, referencedTimeoutTermApp(val)...)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("term inactivity-timeout %q: expected commit to reject, got nil", val)
		}
		if !strings.Contains(err.Error(), "MULTI-t1") ||
			!strings.Contains(err.Error(), val) {
			t.Fatalf("term inactivity-timeout %q: error %q must name the term application and the bad value", val, err.Error())
		}
	}
}

// Non-tautological companion: the SAME policy structure with a VALID
// inactivity-timeout must commit cleanly, proving the rejects above are caused
// by the malformed value and not the surrounding policy. The inclusive range
// edges 0 (inherit-global sentinel) and 86400 are both accepted, and the
// configured value actually LANDS on the compiled application (a regression that
// accepted but dropped it to 0 would be caught by the want check below).
func TestApplicationSpec_ReferencedValidTimeout_AcceptsAtCommit(t *testing.T) {
	for _, val := range []struct {
		raw  string
		want int
	}{
		{"0", 0}, // inherit-global sentinel — pre-existing valid (capabilities.go)
		{"1", 1},
		{"300", 300},
		{"1800", 1800},
		{"86400", 86400}, // upper edge
	} {
		tree := flatTreeFromSets(t, referencedTimeoutApp("inactivity-timeout", val.raw)...)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("inactivity-timeout %q: expected commit to accept, got %v", val.raw, err)
		}
		app := cfg.Applications.Applications["BAD"]
		if app == nil {
			t.Fatalf("inactivity-timeout %q: application BAD missing from compiled config", val.raw)
		}
		if app.InactivityTimeout != val.want {
			t.Fatalf("inactivity-timeout %q: value did not land: got %d, want %d", val.raw, app.InactivityTimeout, val.want)
		}
	}
}

// The 0 inherit-global sentinel must commit cleanly and compile to
// InactivityTimeout==0 on EVERY path: top-level `timeout` alias and inline term
// (the top-level `inactivity-timeout 0` case is covered by the accept loop
// above). RED-on-revert: with appTimeoutMin=1 these go RED (0 is rejected).
func TestApplicationSpec_ZeroInheritSentinel_Accepts(t *testing.T) {
	// Top-level `timeout 0`.
	tree := flatTreeFromSets(t, referencedTimeoutApp("timeout", "0")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("timeout 0: expected commit to accept the inherit sentinel, got %v", err)
	}
	if app := cfg.Applications.Applications["BAD"]; app == nil || app.InactivityTimeout != 0 {
		t.Fatalf("timeout 0: expected InactivityTimeout==0 (inherit), got %+v", app)
	}
	// Inline term `inactivity-timeout 0`.
	tree = flatTreeFromSets(t, referencedTimeoutTermApp("0")...)
	cfg, err = CompileConfig(tree)
	if err != nil {
		t.Fatalf("term inactivity-timeout 0: expected commit to accept, got %v", err)
	}
	if app := cfg.Applications.Applications["MULTI-t1"]; app == nil || app.InactivityTimeout != 0 {
		t.Fatalf("term inactivity-timeout 0: expected InactivityTimeout==0 (inherit), got %+v", app)
	}
}

// A valid inline-term timeout must commit and land on the term application.
func TestApplicationSpec_ReferencedValidTermTimeout_AcceptsAtCommit(t *testing.T) {
	tree := flatTreeFromSets(t, referencedTimeoutTermApp("1800")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("valid term timeout: expected commit to accept, got %v", err)
	}
	app := cfg.Applications.Applications["MULTI-t1"]
	if app == nil {
		t.Fatal("term application MULTI-t1 missing from compiled config")
	}
	if app.InactivityTimeout != 1800 {
		t.Fatalf("term inactivity-timeout not applied: got %d, want 1800", app.InactivityTimeout)
	}
}

// No-brick (#1960 doctrine): a config persisted/synced with a policy-referenced
// malformed timeout must still LOAD on the tolerant path (CompileConfigLenient)
// — downgraded to a warning — so an upgraded node does not fail closed on boot.
// The application simply keeps the global per-protocol timeout it had before.
func TestApplicationSpec_ReferencedBadTimeout_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, referencedTimeoutApp("inactivity-timeout", "30s")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a referenced bad timeout must not fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application spec") && strings.Contains(w, "BAD") && strings.Contains(w, "30s") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient path to record an application-spec timeout downgrade warning, got %v", cfg.Warnings)
	}
}

// The inline-term malformed timeout must also downgrade-to-warning on the
// lenient path, not brick.
func TestApplicationSpec_ReferencedBadTermTimeout_LenientWarns(t *testing.T) {
	tree := flatTreeFromSets(t, referencedTimeoutTermApp("thirty")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load of a referenced bad term timeout must not fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "application spec") && strings.Contains(w, "thirty") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient path to warn about the bad term timeout, got %v", cfg.Warnings)
	}
}

// Schema typed-leaf gate: the SchemaValidate commit-check (the path the
// configstore runs before compile) rejects a malformed TOP-LEVEL timeout for
// ANY application — referenced or not — and accepts a valid one.
//
// FAIL-ON-REVERT: reverting the inactivity-timeout/timeout leaves in
// schema_security.go back to untyped (`args:1` with no validator) makes the
// reject cases below return nil and go RED.
func TestApplicationSpec_SchemaGate_TopLevelTimeout(t *testing.T) {
	reject := func(leaf, val string) {
		t.Helper()
		tree := flatTreeFromSets(t, "set applications application X "+leaf+" "+val)
		if err := SchemaValidate(tree); err == nil {
			t.Fatalf("%s %q: expected SchemaValidate to reject, got nil", leaf, val)
		}
	}
	accept := func(leaf, val string) {
		t.Helper()
		tree := flatTreeFromSets(t, "set applications application X "+leaf+" "+val)
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("%s %q: expected SchemaValidate to accept, got %v", leaf, val, err)
		}
	}
	for _, val := range []string{"30s", "thirty", "-1", "86401", "99999"} {
		reject("inactivity-timeout", val)
		reject("timeout", val)
	}
	// 0 is the inherit-global sentinel and 86400 the upper edge — both accepted.
	for _, val := range []string{"0", "1", "300", "1800", "86400"} {
		accept("inactivity-timeout", val)
		accept("timeout", val)
	}
}
