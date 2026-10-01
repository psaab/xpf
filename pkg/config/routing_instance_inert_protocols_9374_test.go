package config

import (
	"sort"
	"strings"
	"testing"
)

// #9374: a routing instance may name a protocol the compiler builds and then
// throws away. `compileRoutingInstances` copies five fields out of the shared
// compileProtocols result; `router-advertisement` and `lldp` go out of scope
// with the local value.
//
// Unlike the 25 lenient-only rows of #9391 this is OPERATOR-REACHABLE — the
// strict commit walk admits it — which is why it gets a warning rather than a
// place in a debt register.

func warnFor9374(t *testing.T, text string) []string {
	t.Helper()
	tr, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	if err := SchemaValidateWithDefinitions(tr, tr, nil); err != nil {
		t.Fatalf("STRICT REJECT — the arm cannot be read: %v", err)
	}
	cfg, err := CompileConfig(tr)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var out []string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#9374") {
			out = append(out, w)
		}
	}
	return out
}

// TestInertPerInstanceProtocolWarns9374 is the defect, with the two arms that
// stop it being "warn about everything".
func TestInertPerInstanceProtocolWarns9374(t *testing.T) {
	for _, kw := range []string{"router-advertisement", "lldp"} {
		body := "interface ge-0/0/0.0 { max-advertisement-interval 30; }"
		if kw == "lldp" {
			body = "interface ge-0/0/0.0;"
		}
		got := warnFor9374(t, "routing-instances { V { instance-type vrf; protocols { "+kw+" { "+body+" } } } }")
		if len(got) != 1 {
			t.Errorf("per-instance %s produced %d warnings, want 1 — it compiles to "+
				"NOTHING on this instance or globally, and silence is the defect", kw, len(got))
			continue
		}
		if !strings.Contains(got[0], kw) {
			t.Errorf("the warning must NAME the keyword the operator wrote; got %q", got[0])
		}
	}

	// NEGATIVE ARM 1: a protocol that IS carried must not warn. Without this a
	// warning on every per-instance protocol would pass the loop above.
	if got := warnFor9374(t,
		"routing-instances { V { instance-type vrf; protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0; } } } } }"); len(got) != 0 {
		t.Errorf("a COPIED protocol must not warn; got %v", got)
	}

	// NEGATIVE ARM 2: the GLOBAL spelling is where these protocols work.
	if got := warnFor9374(t,
		"protocols { router-advertisement { interface ge-0/0/0.0 { max-advertisement-interval 30; } } }"); len(got) != 0 {
		t.Errorf("the global spelling is the one that WORKS and must not warn; got %v", got)
	}

	// NEGATIVE ARM 3: apply-* meta keywords are not protocols.
	if got := warnFor9374(t,
		"routing-instances { V { instance-type vrf; protocols { apply-macro m { a b; } } } }"); len(got) != 0 {
		t.Errorf("an apply-* meta keyword must not warn; got %v", got)
	}
}

// TestInertProtocolWarningIsDerivedNotListed9374 is the total claim, and it is
// what makes the warning maintain itself.
//
// For EVERY child of the global `protocols` grammar, writing it under a routing
// instance must warn IFF the per-instance node does not declare it. The
// expectation is computed from the schema here, and
// TestRoutingInstanceProtocolsShareTheGlobalGrammar9351 separately binds that
// node's membership to the `ri.X = proto.X` assignments in the compiler source.
// So the chain is: compiler copy set -> schema membership -> this warning, with
// no list anywhere that can fall out of date.
func TestInertProtocolWarningIsDerivedNotListed9374(t *testing.T) {
	var keys []string
	for k := range schemaProtocols.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) < 5 {
		t.Fatalf("VOID: the global protocols grammar has %d children; the sweep below "+
			"would be vacuous", len(keys))
	}

	warnedCount, carriedCount := 0, 0
	for _, kw := range keys {
		// A body every protocol accepts is not available, so probe the bare
		// keyword: the warning is about the KEYWORD being uncarried, and an
		// empty body is enough to make the node exist.
		text := "routing-options { autonomous-system 65000; } routing-instances { V { instance-type vrf; protocols { " + kw + " { } } } }"
		tr, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse %q: %v", kw, perrs)
		}
		cfg, err := CompileConfig(tr)
		if err != nil {
			t.Fatalf("compile %q: %v", kw, err)
		}
		var warned bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "#9374") && strings.Contains(w, kw) {
				warned = true
			}
		}
		carried := schemaRoutingInstanceProtocols.children[kw] != nil
		if carried {
			carriedCount++
		}
		if warned {
			warnedCount++
		}
		if carried && warned {
			t.Errorf("`protocols %s` IS carried into the instance but warned as inert", kw)
		}
		if !carried && !warned {
			t.Errorf("`protocols %s` is NOT carried into the instance and did not warn — "+
				"it compiles to nothing and says nothing", kw)
		}
	}
	if warnedCount == 0 || carriedCount == 0 {
		t.Fatalf("VOID: warned=%d carried=%d — one side empty makes every verdict above "+
			"pass for the wrong reason", warnedCount, carriedCount)
	}
	t.Logf("swept %d protocol keywords: %d carried, %d warned as inert",
		len(keys), carriedCount, warnedCount)
}
