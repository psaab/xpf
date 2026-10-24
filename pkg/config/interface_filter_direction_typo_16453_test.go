package config

import (
	"strings"
	"testing"
)

// #16453: a misspelt / case-variant filter direction under
// `interfaces <if> unit <n> family inet|inet6 filter` (`inpt`, `Input`, …)
// strict-committed clean and bound no filter. The #15199 open-world walker
// skips the `filter` container and the #10293/#12090 knob scan enumerated
// only known wrong spellings with no default arm, so the typo was invisible
// to both. The fix adds the default arm to unsupportedInterfaceFilterKnobs
// (packed tail and braced child), plus the split `family { inet { … } }`
// shape. Strict rejects, lenient warns (#1960), both naming #10293 and the
// typo token. Controls (`input`/`output`, a filter NAMED like a typo, the
// #15199 `filtr` warning, two-direction packed runs) are unchanged.
//
// Fail-on-revert: removing the default arms makes every reject cell below
// compile clean again.

var typoDirs16453 = []string{"inptu", "inpt", "Input", "ouput", "imput"}

func mustReject16453(t *testing.T, tree *ConfigTree, knob string) {
	t.Helper()
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatalf("filter direction %q committed cleanly, but nothing binds it", knob)
	}
	if !strings.Contains(err.Error(), "#10293") || !strings.Contains(err.Error(), "filter "+knob) {
		t.Fatalf("reject error %q must name #10293 and filter %s", err.Error(), knob)
	}
}

func mustWarn16453(t *testing.T, tree *ConfigTree, knob string) {
	t.Helper()
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path must not brick on typo direction %q: %v", knob, err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#10293") && strings.Contains(w, "filter "+knob) {
			return
		}
	}
	t.Fatalf("lenient path must warn #10293 naming filter %s, got %q", knob, cfg.Warnings)
}

func TestInterfaceFilterTypoDirectionFlat16453(t *testing.T) {
	for _, dir := range typoDirs16453 {
		for _, tc := range []struct{ family, filter, addr string }{
			{"inet", "f1", "10.0.0.1/24"},
			{"inet6", "f6", "2001:db8::1/64"},
		} {
			t.Run(tc.family+"/"+dir, func(t *testing.T) {
				sets := func() *ConfigTree {
					return flatTreeFromSets(t,
						"set firewall family inet filter f1 term t1 then accept",
						"set firewall family inet6 filter f6 term t1 then accept",
						"set interfaces ge-0/0/0 unit 0 family "+tc.family+" address "+tc.addr,
						"set interfaces ge-0/0/0 unit 0 family "+tc.family+" filter "+dir+" "+tc.filter,
					)
				}
				mustReject16453(t, sets(), dir)
				mustWarn16453(t, sets(), dir)
			})
		}
	}
}

func TestLo0FilterTypoDirection16453(t *testing.T) {
	build := func() *ConfigTree {
		return flatTreeFromSets(t,
			"set firewall family inet filter f1 term t1 then accept",
			"set interfaces lo0 unit 0 family inet address 127.0.0.1/32",
			"set interfaces lo0 unit 0 family inet filter inptu f1",
		)
	}
	if _, err := CompileConfig(build()); err == nil || !strings.Contains(err.Error(), "lo0") {
		t.Fatalf("lo0 typo direction must reject naming lo0, got %v", err)
	}
	mustReject16453(t, build(), "inptu")
	mustWarn16453(t, build(), "inptu")
}

func TestInterfaceFilterTypoDirectionHier16453(t *testing.T) {
	const fw = ` firewall { family inet { filter f1 { term t1 { then accept; } } } }`
	cases := map[string]string{
		"braced leaf":       `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; filter { inpt f1; } } } } }` + fw,
		"braced block":      `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; filter { inpt { f1; } } } } } }` + fw,
		"packed in brace":   `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; filter inpt f1; } } } }` + fw,
		"family packed":     `interfaces { ge-0/0/0 { unit 0 { family inet filter inpt f1; } } }` + fw,
		"unit packed tail":  `interfaces { ge-0/0/0 { unit 0 family inet filter inpt f1; } }` + fw,
		"split family":      `interfaces { ge-0/0/0 { unit 0 { family { inet { filter { inpt f1; } } } } } }` + fw,
		"apply-groups":      `groups { g { interfaces { ge-0/0/0 { unit 0 { family inet { filter { inpt f1; } } } } } } } apply-groups g;` + fw,
		"interface-range":   `interfaces { interface-range r { member ge-0/0/0; unit 0 { family inet { filter { inpt f1; } } } } }` + fw,
		"packed second dir": `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; filter input f1 inpt f1; } } } }` + fw,
	}
	for name, src := range cases {
		knob := "inpt"
		if name == "packed second dir" {
			// `input f1 inpt f1` packed is indistinguishable from the
			// #10293 multi-value `input f1 f2`; the proven diagnostics
			// name `filter input`. Both reject strict / warn lenient.
			knob = "input"
		}
		t.Run(name, func(t *testing.T) {
			mustReject16453(t, hierTree(t, src), knob)
			mustWarn16453(t, hierTree(t, src), knob)
		})
	}
}

func TestInterfaceFilterTypoDirectionControls16453(t *testing.T) {
	// Valid directions still bind, in flat and packed two-direction runs.
	cfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set firewall family inet filter f1 term t1 then accept",
		"set firewall family inet6 filter f6 term t1 then accept",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet filter input f1",
		"set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64",
		"set interfaces ge-0/0/0 unit 0 family inet6 filter output f6",
	))
	u := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if u.FilterInputV4 != "f1" || u.FilterOutputV6 != "f6" {
		t.Fatalf("valid direction bindings lost: %+v", u)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#10293") {
			t.Fatalf("valid directions must not warn #10293: %q", w)
		}
	}

	hierCfg := assertCommitAccepts(t, hierTree(t,
		`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; filter input f1 output f1; } } } } firewall { family inet { filter f1 { term t1 { then accept; } } } }`))
	hu := hierCfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	if hu.FilterInputV4 != "f1" || hu.FilterOutputV4 != "f1" {
		t.Fatalf("packed two-direction run lost a binding: %+v", hu)
	}

	// A filter NAMED like a typo is a value, not a direction: it binds.
	nameCfg := assertCommitAccepts(t, flatTreeFromSets(t,
		"set firewall family inet filter inpt term t1 then accept",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
		"set interfaces ge-0/0/0 unit 0 family inet filter input inpt",
	))
	if got := nameCfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].FilterInputV4; got != "inpt" {
		t.Fatalf("filter named inpt must bind as a value, got %q", got)
	}

	// #15199 twin unchanged: `filtr` (wrong container) stays warn-only
	// (#10707) on strict, never a #10293 reject.
	filtr, err := CompileConfig(flatTreeFromSets(t,
		"set interfaces ge-0/0/1 unit 0 family inet filtr input f1",
		"set interfaces ge-0/0/1 unit 0 family inet address 10.0.1.1/24",
	))
	if err != nil {
		t.Fatalf("filtr must remain warn-only on strict, got %v", err)
	}
	found := false
	for _, w := range filtr.Warnings {
		if strings.Contains(w, "#10293") {
			t.Fatalf("filtr must not draw #10293: %q", w)
		}
		if strings.Contains(w, "#10707") && strings.Contains(w, "filtr") {
			found = true
		}
	}
	if !found {
		t.Fatalf("filtr must keep its #10707 warning, got %q", filtr.Warnings)
	}
	if got := filtr.Interfaces.Interfaces["ge-0/0/1"].Units[0].FilterInputV4; got != "" {
		t.Fatalf("filtr must not bind, got %q", got)
	}
}
