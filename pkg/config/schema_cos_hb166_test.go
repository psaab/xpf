package config

// Regression tests for the fable-review-166 CoS config-schema gaps
// (#4217 G-4, #4218 G-3, #4219 G-5, #4220 G-1). Each of the four
// scheduler/interface leaves below was untyped, missing, or inert; the
// fix types them so garbage HARD-REJECTS at commit and adds
// accepted-but-inert commit warnings for the two knobs the dataplane
// does not enforce (codel-target AQM, priority-low-min-share).
//
// FAIL-ON-REVERT: dropping the typed-leaf metadata from schema_cos.go
// (or the warnings from compiler_validate_warn.go) makes the "rejects"
// / "warns" assertions go RED — the garbage values commit clean again
// and the inert knobs go silent, exactly the pre-fix behavior.

import (
	"strings"
	"testing"
)

func hb166SchemaCheck(t *testing.T, cmds ...string) error {
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
	return SchemaValidate(tree, nil)
}

func hb166Compile(t *testing.T, cmds ...string) *Config {
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
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func hb166HasWarning(cfg *Config, substr string) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// --- G-4: shaping-rate / burst-size typed (unit level + interface level) ---

func TestHB166_G4_ShapingRate_RejectsGarbage(t *testing.T) {
	// Unit level and #4021 interface level. Before #4217 both committed
	// as 0 (parseBandwidthLimit silent-zero) and the shaper vanished.
	bad := []string{
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10gg",
		"set class-of-service interfaces reth0 shaping-rate 10gg",
	}
	for _, cmd := range bad {
		err := hb166SchemaCheck(t, cmd)
		if err == nil {
			t.Fatalf("%q: expected rejection, got nil", cmd)
		}
		if !strings.Contains(err.Error(), "shaping-rate") {
			t.Fatalf("%q: error should reference shaping-rate: %v", cmd, err)
		}
	}
}

func TestHB166_G4_ShapingRate_AcceptsValid(t *testing.T) {
	good := []string{
		"set class-of-service interfaces reth0 unit 80 shaping-rate 25g",
		"set class-of-service interfaces reth0 shaping-rate 1g",
	}
	for _, cmd := range good {
		if err := hb166SchemaCheck(t, cmd); err != nil {
			t.Fatalf("%q: expected accept, got %v", cmd, err)
		}
	}
}

func TestHB166_G4_BurstSize_RejectsGarbage(t *testing.T) {
	bad := []string{
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10m burst-size garbage",
		"set class-of-service interfaces reth0 shaping-rate 10m burst-size garbage",
	}
	for _, cmd := range bad {
		err := hb166SchemaCheck(t, cmd)
		if err == nil {
			t.Fatalf("%q: expected rejection, got nil", cmd)
		}
		if !strings.Contains(err.Error(), "burst-size") {
			t.Fatalf("%q: error should reference burst-size: %v", cmd, err)
		}
	}
}

func TestHB166_G4_BurstSize_AcceptsValid(t *testing.T) {
	if err := hb166SchemaCheck(t,
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10m burst-size 15k"); err != nil {
		t.Fatalf("expected accept, got %v", err)
	}
}

// --- G-3: codel-target typed + inert warning ---

func TestHB166_G3_CodelTarget_RejectsGarbage(t *testing.T) {
	err := hb166SchemaCheck(t,
		"set class-of-service schedulers be codel-target banana")
	if err == nil {
		t.Fatal("expected rejection for codel-target banana, got nil")
	}
	if !strings.Contains(err.Error(), "codel-target") {
		t.Fatalf("error should reference codel-target: %v", err)
	}
}

func TestHB166_G3_CodelTarget_AcceptsValidAndWarnsInert(t *testing.T) {
	if err := hb166SchemaCheck(t,
		"set class-of-service schedulers be codel-target 5"); err != nil {
		t.Fatalf("expected codel-target 5 to pass schema, got %v", err)
	}
	cfg := hb166Compile(t,
		"set class-of-service schedulers be codel-target 5")
	if !hb166HasWarning(cfg, "codel-target is accepted for compatibility but inert") {
		t.Fatalf("expected inert codel-target warning; got: %v", cfg.Warnings)
	}
}

// --- G-5: oversubscription-policy + priority-low-min-share typed ---

func TestHB166_G5_GuaranteeRateFraction_RejectsOutOfRange(t *testing.T) {
	// The compiler silently clamps 1.7 -> 1.0 today; the schema now
	// rejects the out-of-range fraction at commit.
	err := hb166SchemaCheck(t,
		"set class-of-service interfaces reth0 unit 80 oversubscription-policy guarantee-rate 1.7")
	if err == nil {
		t.Fatal("expected rejection for guarantee-rate 1.7, got nil")
	}
	if !strings.Contains(err.Error(), "guarantee-rate") {
		t.Fatalf("error should reference guarantee-rate: %v", err)
	}
}

func TestHB166_G5_GuaranteeRateFraction_AcceptsValid(t *testing.T) {
	good := []string{
		"set class-of-service interfaces reth0 unit 80 oversubscription-policy guarantee-rate 0.7",
		"set class-of-service interfaces reth0 unit 80 oversubscription-policy proportional",
		"set class-of-service interfaces reth0 oversubscription-policy guarantee-rate 0.5",
	}
	for _, cmd := range good {
		if err := hb166SchemaCheck(t, cmd); err != nil {
			t.Fatalf("%q: expected accept, got %v", cmd, err)
		}
	}
}

func TestHB166_G5_PriorityLowMinShare_RejectsGarbage(t *testing.T) {
	bad := []string{
		"set class-of-service interfaces reth0 unit 80 priority-low-min-share 10gg",
		"set class-of-service interfaces reth0 priority-low-min-share 10gg",
	}
	for _, cmd := range bad {
		err := hb166SchemaCheck(t, cmd)
		if err == nil {
			t.Fatalf("%q: expected rejection, got nil", cmd)
		}
		if !strings.Contains(err.Error(), "priority-low-min-share") {
			t.Fatalf("%q: error should reference priority-low-min-share: %v", cmd, err)
		}
	}
}

// --- G-1: priority-low-min-share accepted but inert warning ---

func TestHB166_G1_PriorityLowMinShare_AcceptsValidAndWarnsInert(t *testing.T) {
	if err := hb166SchemaCheck(t,
		"set class-of-service interfaces reth0 unit 80 priority-low-min-share 100m"); err != nil {
		t.Fatalf("expected priority-low-min-share 100m to pass schema, got %v", err)
	}
	cfg := hb166Compile(t,
		"set class-of-service interfaces reth0 unit 80 priority-low-min-share 100m")
	if !hb166HasWarning(cfg, "priority-low-min-share is accepted for compatibility but inert") {
		t.Fatalf("expected inert priority-low-min-share warning; got: %v", cfg.Warnings)
	}
}

// --- completion: the new leaves are reachable via `set ... ?` ---

func TestHB166_Completion_NewLeavesPresent(t *testing.T) {
	// codel-target under schedulers.
	sched := CompleteSetPathWithValues(
		[]string{"class-of-service", "schedulers", "be"}, nil)
	if !containsCompletionName(sched, "codel-target") {
		t.Fatalf("expected codel-target in schedulers completions; got %v", completionNames(sched))
	}
	// oversubscription-policy + priority-low-min-share under interfaces>unit.
	unit := CompleteSetPathWithValues(
		[]string{"class-of-service", "interfaces", "reth0", "unit", "80"}, nil)
	for _, want := range []string{"oversubscription-policy", "priority-low-min-share", "shaping-rate"} {
		if !containsCompletionName(unit, want) {
			t.Fatalf("expected %q in unit completions; got %v", want, completionNames(unit))
		}
	}
	// oversubscription-policy children.
	oversub := CompleteSetPathWithValues(
		[]string{"class-of-service", "interfaces", "reth0", "unit", "80", "oversubscription-policy"}, nil)
	for _, want := range []string{"guarantee-rate", "proportional"} {
		if !containsCompletionName(oversub, want) {
			t.Fatalf("expected %q in oversubscription-policy completions; got %v", want, completionNames(oversub))
		}
	}
	// Interface-level (#4021) leaves too.
	iface := CompleteSetPathWithValues(
		[]string{"class-of-service", "interfaces", "reth0"}, nil)
	for _, want := range []string{"oversubscription-policy", "priority-low-min-share", "shaping-rate"} {
		if !containsCompletionName(iface, want) {
			t.Fatalf("expected %q in interface-level completions; got %v", want, completionNames(iface))
		}
	}
}

// #11813 [C1/C14]: interface-level classifier bindings must expose the same
// inet-precedence schema child as unit-level bindings. The compiler already
// consumes both shapes; this pins the schema-driven completion surface.
func TestCoSInterfaceLevelInetPrecedenceClassifierCompletion_11813(t *testing.T) {
	for _, tc := range []struct {
		name string
		path []string
	}{
		{
			name: "unit",
			path: []string{"class-of-service", "interfaces", "reth0", "unit", "80", "classifiers"},
		},
		{
			name: "interface level",
			path: []string{"class-of-service", "interfaces", "reth0", "classifiers"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CompleteSetPathWithValues(tc.path, nil)
			for _, want := range []string{"dscp", "inet-precedence", "ieee-802.1"} {
				if !containsCompletionName(got, want) {
					t.Fatalf("expected %q completion, got %v", want, completionNames(got))
				}
			}
		})
	}
}

// --- T-4: BA classifier code-point -> unmaterialized queue commit warning ---

// TestHB166_T4_ClassifierUnmaterializedQueue_Warns pins the fable-review-166
// T-4 commit-time visibility: a DSCP classifier that steers a code-point to a
// forwarding-class whose queue is NOT in the interface's scheduler-map (so the
// dataplane never materializes it) must WARN at commit — the pre-fix dataplane
// silently blackholed such traffic, and the post-fix dataplane forwards it on
// the best-effort queue, so the operator needs to know the intended queue does
// not exist on this interface.
//
// It is a WARN, not a strict reject: a classifier steering to a
// forwarding-class without a scheduler-map entry is a valid Junos config
// (queues exist by default), so the config must still COMPILE.
//
// FAIL-ON-REVERT: dropping classOfServiceClassifierQueueWarnings (or its call
// site in compiler_validate_warn.go) makes the warn assertion go RED — the
// unmaterialized-queue classifier commits silently again, exactly the
// pre-fix blackhole-with-no-diagnostic behavior.
func TestHB166_T4_ClassifierUnmaterializedQueue_Warns(t *testing.T) {
	cmds := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 ef",
		"set class-of-service schedulers sched-be priority low",
		// Scheduler-map materializes ONLY best-effort (queue 0); ef (queue 5)
		// is never built on the interface.
		"set class-of-service scheduler-maps be-only forwarding-class best-effort scheduler sched-be",
		// Classifier steers dscp 46 -> ef (queue 5, unmaterialized) and
		// dscp 0 -> best-effort (queue 0, materialized -> admits the iface).
		"set class-of-service classifiers dscp cls forwarding-class ef loss-priority low code-points 46",
		"set class-of-service classifiers dscp cls forwarding-class best-effort loss-priority low code-points 0",
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10g",
		"set class-of-service interfaces reth0 unit 80 scheduler-map be-only",
		"set class-of-service interfaces reth0 unit 80 classifiers dscp cls",
	}
	cfg := hb166Compile(t, cmds...) // must COMPILE (WARN, not reject)
	if !hb166HasWarning(cfg, `forwarding-class "ef"`) ||
		!hb166HasWarning(cfg, "no scheduler-map entry on this interface") {
		t.Fatalf("expected an unmaterialized-queue classifier warning naming ef; got warnings: %v", cfg.Warnings)
	}
	// The best-effort code-point (queue 0, materialized) must NOT warn.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `forwarding-class "best-effort"`) &&
			strings.Contains(w, "no scheduler-map entry on this interface") {
			t.Fatalf("best-effort maps to a materialized queue; must not warn: %q", w)
		}
	}
}

// TestHB166_T4_ClassifierMaterializedQueue_NoWarn is the control: when the
// scheduler-map materializes every forwarding-class the classifier references,
// no unmaterialized-queue warning fires.
func TestHB166_T4_ClassifierMaterializedQueue_NoWarn(t *testing.T) {
	cmds := []string{
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 ef",
		"set class-of-service schedulers sched-be priority low",
		"set class-of-service schedulers sched-ef priority strict-high",
		"set class-of-service scheduler-maps full forwarding-class best-effort scheduler sched-be",
		"set class-of-service scheduler-maps full forwarding-class ef scheduler sched-ef",
		"set class-of-service classifiers dscp cls forwarding-class ef loss-priority low code-points 46",
		"set class-of-service classifiers dscp cls forwarding-class best-effort loss-priority low code-points 0",
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10g",
		"set class-of-service interfaces reth0 unit 80 scheduler-map full",
		"set class-of-service interfaces reth0 unit 80 classifiers dscp cls",
	}
	cfg := hb166Compile(t, cmds...)
	if hb166HasWarning(cfg, "no scheduler-map entry on this interface") {
		t.Fatalf("all classifier classes are materialized; must not warn; got: %v", cfg.Warnings)
	}
}

// TestHB166_T5_FilterForwardingClassUnmaterialized_Warns checks the filter
// marking path for every family/direction binding. A scheduler-map entry for
// another defined class must not hide the missing filter forwarding-class.
func TestHB166_T5_FilterForwardingClassUnmaterialized_Warns(t *testing.T) {
	for _, tc := range []struct {
		name            string
		family          string
		direction       string
		separateIngress bool
		material        bool
		wantWarn        bool
	}{
		{name: "inet input on other egress", family: "inet", direction: "input", separateIngress: true, wantWarn: true},
		{name: "inet output", family: "inet", direction: "output", wantWarn: true},
		{name: "inet6 input on other egress", family: "inet6", direction: "input", separateIngress: true, wantWarn: true},
		{name: "inet6 output", family: "inet6", direction: "output", wantWarn: true},
		{name: "materialized", family: "inet", direction: "output", material: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filterBinding := "set interfaces reth0 unit 80 family " + tc.family + " filter " + tc.direction + " f"
			if tc.separateIngress {
				filterBinding = "set interfaces reth1 unit 0 family " + tc.family + " filter " + tc.direction + " f"
			}
			cmds := []string{
				"set interfaces reth0 unit 80 family inet address 198.51.100.80/24",
				"set interfaces reth0 unit 80 family inet6 address 2001:db8:80::1/64",
				"set interfaces reth1 unit 0 family inet address 198.51.100.1/24",
				"set interfaces reth1 unit 0 family inet6 address 2001:db8:1::1/64",
				"set class-of-service forwarding-classes queue 0 best-effort",
				"set class-of-service forwarding-classes queue 5 voice",
				"set class-of-service schedulers sched-be priority low",
				"set class-of-service scheduler-maps be-only forwarding-class best-effort scheduler sched-be",
				"set class-of-service interfaces reth0 unit 80 shaping-rate 10g",
				"set class-of-service interfaces reth0 unit 80 scheduler-map be-only",
				"set firewall family " + tc.family + " filter f term mark then forwarding-class voice",
				"set firewall family " + tc.family + " filter f term mark then accept",
				filterBinding,
			}
			if tc.material {
				cmds = append(cmds,
					"set class-of-service schedulers sched-voice priority strict-high",
					"set class-of-service scheduler-maps be-only forwarding-class voice scheduler sched-voice")
			}
			cfg := hb166Compile(t, cmds...)
			gotWarn := hb166HasWarning(cfg, `sets defined forwarding-class "voice"`)
			if gotWarn != tc.wantWarn {
				t.Fatalf("filter forwarding-class warning = %t, want %t; warnings: %v", gotWarn, tc.wantWarn, cfg.Warnings)
			}
		})
	}
}

func TestHB166_T5_FilterForwardingClassSyntheticBestEffort_NoWarn(t *testing.T) {
	cfg := hb166Compile(t,
		"set class-of-service forwarding-classes queue 0 best-effort",
		"set class-of-service forwarding-classes queue 5 voice",
		"set class-of-service schedulers sched-voice priority strict-high",
		"set class-of-service scheduler-maps voice-only forwarding-class voice scheduler sched-voice",
		"set class-of-service interfaces reth0 unit 80 shaping-rate 10g",
		"set class-of-service interfaces reth0 unit 80 scheduler-map voice-only",
		"set firewall family inet filter f term mark then forwarding-class best-effort",
		"set firewall family inet filter f term mark then accept",
		"set interfaces reth0 unit 80 family inet filter output f",
	)
	if hb166HasWarning(cfg, `sets defined forwarding-class "best-effort"`) {
		t.Fatalf("the runtime synthesizes best-effort when omitted from the scheduler-map; got warnings: %v", cfg.Warnings)
	}
}

func TestHB166_T5_FilterForwardingClassNoRuntime_NoWarn(t *testing.T) {
	cfg := hb166Compile(t,
		"set class-of-service forwarding-classes queue 5 voice",
		"set class-of-service interfaces reth0 unit 80",
		"set firewall family inet filter f term mark then forwarding-class voice",
		"set firewall family inet filter f term mark then accept",
		"set interfaces reth0 unit 80 family inet address 198.51.100.80/24",
		"set interfaces reth0 unit 80 family inet filter output f",
	)
	if hb166HasWarning(cfg, `sets defined forwarding-class "voice"`) {
		t.Fatalf("an output filter alone does not admit a CoS runtime; got warnings: %v", cfg.Warnings)
	}
}
