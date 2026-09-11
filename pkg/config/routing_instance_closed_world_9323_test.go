package config

import (
	"sort"
	"strings"
	"testing"
)

// #9323: `routing-instances <name>` was an OPEN-WORLD container at every config
// channel, so a `security`, `firewall` or entirely bogus subtree nested under a
// routing instance committed clean, rendered back in `show configuration`, and
// compiled to NOTHING.
//
// Per-instance scoping is the natural thing an operator reaches for when they
// want NAT64 or a filter to apply only inside a VRF — and there is no supported
// way to do it (`routing_domain` is stamped from the ingress interface, never
// from the NAT rule-set, and `NAT64RuleSnapshot` carries no routing scope at
// all), so the spelling they would try is the one that silently does nothing.
//
// The sibling it would most plausibly be confused with, `security nat nat64`,
// is `closedWorld: true` for exactly this reason: "a silent drop here is a real
// footgun".

func tree9323(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

// validate9323 drives the STRICT commit path, which is where the gate lives.
//
// Deliberately CompileConfig rather than SchemaValidate: the gate is a prewalk
// AST check, for the reason the defect exists — an unknown subtree compiles to
// nothing, so there is no typed leaf for the schema walk to judge. Asserting
// against SchemaValidate would have measured a function the gate is not in, and
// reported ACCEPT for a config the operator's commit now refuses.
func validate9323(t *testing.T, lines ...string) error {
	t.Helper()
	_, err := CompileConfig(tree9323(t, lines...))
	return err
}

// THE DEFECT: the three spellings the issue measured must be REFUSED.
//
// RED at master: all three return nil from SchemaValidate and compile to zero
// objects, with no error and no warning.
func TestNestedSubtreesUnderARoutingInstanceAreRefused9323(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
		tok  string
	}{
		{"security-nat-nat64", "set routing-instances VRF-A security nat nat64 rule-set rs1 prefix 64:ff9b::/96", "security"},
		{"bogus-keyword", "set routing-instances VRF-A totally-bogus-keyword foo bar", "totally-bogus-keyword"},
		{"firewall-filter", "set routing-instances VRF-A firewall filter f1 term t1 then discard", "firewall"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := validate9323(t, tc.line)
			if err == nil {
				t.Fatalf("%q was ACCEPTED. It compiles to nothing: the operator gets a "+
					"clean commit, `show configuration` renders it back, and enforcement "+
					"is zero", tc.line)
			}
			if !strings.Contains(err.Error(), tc.tok) {
				t.Errorf("the rejection does not name the offending keyword %q: %v", tc.tok, err)
			}
			if !strings.Contains(err.Error(), "routing-instances") {
				t.Errorf("the rejection does not name the container: %v", err)
			}
		})
	}
}

// THE POSITIVE CONTROL, and it is what makes the reject cell more than "closing
// a world rejects things". Every keyword the COMPILER admits must still commit.
//
// The four #9323 additions are the ones that matter here: arming the closed
// world without declaring `description`, `vrf-target`, `vrf-table-label` and
// `route-distinguisher` REJECTS them, and `go test ./...` does not notice —
// measured, no fixture in the tree writes any of them. This cell is the reason
// that regression is not shipped.
func TestEveryCompilerAdmittedRoutingInstanceKeywordStillCommits9323(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"instance-type", "set routing-instances VRF-A instance-type vrf"},
		{"interface", "set routing-instances VRF-A interface ge-0/0/1.0"},
		{"description", `set routing-instances VRF-A description "tenant a"`},
		{"vrf-target", "set routing-instances VRF-A vrf-target target:65000:100"},
		{"vrf-table-label", "set routing-instances VRF-A vrf-table-label"},
		{"route-distinguisher", "set routing-instances VRF-A route-distinguisher 65000:100"},
		{"routing-options", "set routing-instances VRF-A routing-options static route 0.0.0.0/0 next-hop 10.0.0.1"},
		{"protocols", "set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := validate9323(t, tc.line); err != nil {
				t.Fatalf("%q was REJECTED by the closed world: %v.\nThe compiler admits "+
					"this keyword, so refusing it at "+
					"commit is a regression, not a fix", tc.line, err)
			}
		})
	}
}

// `description` is not merely admitted — it is COMPILED. Rejecting it would
// have refused a value the tree stores and renders, which is the sharpest form
// of the regression the cell above guards.
func TestRoutingInstanceDescriptionStillCompiles9323(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set routing-instances VRF-A instance-type vrf",
		`set routing-instances VRF-A description "tenant a"`,
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("got %d routing instances, want 1", len(cfg.RoutingInstances))
	}
	if got := cfg.RoutingInstances[0].Description; got != "tenant a" {
		t.Errorf("Description = %q, want %q", got, "tenant a")
	}
}

// THE ANTI-DRIFT GUARD, and the one that outlives this change.
//
// Since #9620 a brace-elided instance is split by the schema's own declarations
// (normalizeElidedRoutingInstance9620), so the compiler keeps no packed-run
// keyword list that could drift from them. What remains to bind is the
// direction that always mattered: every keyword the compiler READS OR ACCEPTS
// must be DECLARED, because the gate's permitted set is the schema and anything
// undeclared is rejected at commit. Before #9323 the schema declared 4 of the
// compiler's 8, so `description`, which the compiler reads into
// RoutingInstanceConfig.Description, would have been refused.
//
// The converse must NOT be asserted. MEASURED counterexample: `interface-routes`
// appears directly under an instance in the shipped #2226 rib-group contract
// and is declared here, while the compiler's old packed-run keyword list never
// named it.
func TestRoutingInstanceSchemaAndCompilerAgree9323(t *testing.T) {
	ri := setSchema.children["routing-instances"]
	if ri == nil || ri.wildcard == nil {
		t.Fatalf("routing-instances wildcard not found — this guard is measuring nothing")
	}
	// The wildcard is deliberately NOT closedWorld (that flip inherits — see
	// compiler_routing_children_9323.go). What makes the relation below matter
	// is the GATE, whose permitted set is read from these same declarations.
	declared := routingInstanceChildTokens9323()
	if len(declared) == 0 {
		t.Fatalf("the gate reads no permitted tokens from the schema, so it declines to " +
			"judge and every assertion here is vacuous")
	}
	declaredSet := make(map[string]bool, len(declared))
	for _, tok := range declared {
		declaredSet[tok] = true
	}

	// EVERY keyword the compiler reads or accepts must be declared.
	read := []string{
		"instance-type", "description", "interface", "routing-options",
		"protocols", "vrf-target", "vrf-table-label", "route-distinguisher",
	}
	for _, tok := range read {
		if !declaredSet[tok] {
			t.Errorf("the compiler reads or accepts %q but the schema does not "+
				"declare it — the #9323 gate now REJECTS it at commit", tok)
		}
	}

	// The CONVERSE is deliberately NOT asserted, and this is the measured
	// counterexample that says why. If it ever starts holding, that is a fact
	// worth noticing, not a rule to enforce.
	if !declaredSet["interface-routes"] {
		t.Errorf("`interface-routes` is no longer declared under the routing-instance " +
			"wildcard; the #2226 rib-group contract writes it DIRECTLY under an " +
			"instance, so the gate would reject a shipped spelling")
	}
}

// OVER-REACH GUARD. closedWorld INHERITS, and that is what made the same flip
// wrong at the config root (9 of 10 shipped configs rejected) and at `firewall
// family` (#9017). The subtrees beneath a routing instance must still accept
// the grammar they accepted before.
//
// Not a restatement of the reject cell: these are the spellings a flip that
// over-reached would break, and they are drawn from the deep grammar
// (`protocols` and `routing-options`) rather than from the level being closed.
func TestClosingTheInstanceDoesNotCloseWhatItContains9323(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"ospf-area-interface-passive", []string{
			"set routing-instances VRF-A protocols ospf area 0.0.0.0 interface ge-0/0/1.0 passive"}},
		{"bgp-group-neighbor", []string{
			// The group carries peer-as rather than the neighbor line, and that
			// is NOT cosmetic: `neighbor 10.0.0.1 peer-as 65001` on ONE line is
			// rejected inside a routing instance while the identical GLOBAL
			// spelling compiles — a separate defect this cell found, tracked as
			// #9351. Using the working spelling keeps this cell about the #9323
			// gate instead of quietly becoming a second cell for that one.
			"set routing-instances VRF-A protocols bgp group g1 peer-as 65001",
			"set routing-instances VRF-A protocols bgp group g1 neighbor 10.0.0.1"}},
		{"isis-interface", []string{
			"set routing-instances VRF-A protocols isis interface ge-0/0/1.0"}},
		{"rib-static-route", []string{
			"set routing-instances VRF-A routing-options rib VRF-A.inet.0 static route 10.0.0.0/8 next-hop 10.0.0.1"}},
		{"interface-routes-ribgroup", []string{
			"set routing-instances VRF-A routing-options interface-routes rib-group inet rg1"}},
		{"static-qualified-next-hop", []string{
			"set routing-instances VRF-A routing-options static route 0.0.0.0/0 qualified-next-hop 10.0.0.1 preference 5"}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := validate9323(t, tc.lines...); err != nil {
				t.Fatalf("%v was REJECTED: %v.\nA closed world at the instance level "+
					"INHERITS and closes the whole protocol grammar beneath it — that "+
					"is the failure mode this cell exists for, and it is why #9323 "+
					"uses a scoped gate instead", tc.lines, err)
			}
		})
	}
}

// The multi-value leaf the closed world newly makes ABSORBING must still reach
// the compiler with every value.
//
// The #9206 census's own failure text asks for exactly this check ("a new
// closedWorld flip over an existing one — check whether it reaches the compiler
// too"). `routing-instances <n> interface` is read with `firewallMatchValues`,
// the SSOT that reads BOTH Keys[1:] and Children, so an absorbed trailing token
// lands in ri.Interfaces rather than being stranded on the node key — which is
// the #3904 VRF-isolation break in a new place.
func TestTheNewlyAbsorbingInterfaceLeafStillReachesTheCompiler9323(t *testing.T) {
	tree := &ConfigTree{}
	for _, line := range []string{
		"set routing-instances VRF-A instance-type vrf",
		"set routing-instances VRF-A interface [ ge-0/0/1.0 ge-0/0/2.0 ge-0/0/3.0 ]",
	} {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Fatalf("got %d routing instances, want 1", len(cfg.RoutingInstances))
	}
	got := append([]string(nil), cfg.RoutingInstances[0].Interfaces...)
	sort.Strings(got)
	want := []string{"ge-0/0/1.0", "ge-0/0/2.0", "ge-0/0/3.0"}
	if len(got) != len(want) {
		t.Fatalf("Interfaces = %v, want %v — reading only the first value is the "+
			"#3904 VRF-isolation break", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Interfaces = %v, want %v", got, want)
		}
	}
}

// THE #1960 NO-BRICK SPLIT. The strict commit path rejects; the tolerant load /
// peer-sync path must WARN and still boot, or an already-persisted config an
// older binary accepted bricks the node on upgrade.
//
// Both halves in one cell, because either alone is satisfiable by the wrong
// thing: a lenient-only cell passes for a gate that never rejects, and a
// strict-only cell passes for a gate that bricks the boot.
func TestTheRoutingInstanceGateIsStrictOnCommitAndLenientOnLoad9323(t *testing.T) {
	const line = "set routing-instances VRF-A security nat nat64 rule-set rs1 prefix 64:ff9b::/96"

	if _, err := CompileConfig(tree9323(t, line)); err == nil {
		t.Fatalf("strict CompileConfig ACCEPTED %q", line)
	}

	cfg, err := CompileConfigLenient(tree9323(t, line))
	if err != nil {
		t.Fatalf("lenient CompileConfigLenient REJECTED %q: %v.\nA config an older "+
			"binary persisted must still BOOT (#1960 no-brick); rejecting here "+
			"blacks out the node on upgrade", line, err)
	}
	if cfg == nil {
		t.Fatalf("lenient compile returned no config")
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "9323") && strings.Contains(w, "security") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("the lenient path swallowed the diagnostic entirely — it must WARN, "+
			"not go silent, or the operator has no signal that the stanza does "+
			"nothing.\nwarnings: %v", cfg.Warnings)
	}
}

// --- SPELLING COVERAGE, stated rather than inferred. ---
//
// Three spellings reach this gate and they put the same tokens in DIFFERENT
// places in the AST, so a gate that handles one is not thereby handling the
// others. The cells above all use the flat-set chain; these pin the other two
// explicitly, in both directions.
//
// The FALSE-REJECT arms are the ones that matter. The first version of the gate
// read a brace-elided node's Children as instance properties, and they are not —
// they are the BODY of the keyword on the Keys tail. It rejected
// `VRF-A routing-options { static { … } }` naming "static", and
// `VRF-A protocols { ospf { … } }` naming "ospf". Both are valid configuration,
// and a commit gate that refuses valid configuration is a worse defect than the
// silent drop #9323 fixes. "Consistency" is satisfiable by rejecting
// everything; these arms are what makes it not.

func parse9323(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", text, errs)
	}
	return tree
}

func TestTheGateCoversAllThreeSpellings9323(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		// wantTok is the keyword the rejection must name; "" means ACCEPT.
		wantTok string
	}{
		// --- MUST REJECT ---
		{
			name:    "braced/nested-security",
			text:    "routing-instances {\n  VRF-A {\n    security {\n      nat { nat64 { rule-set rs1 { prefix 64:ff9b::/96; } } }\n    }\n  }\n}\n",
			wantTok: "security",
		},
		{
			name: "brace-elided/security-on-the-keys-tail",
			// [VRF-A security] > [nat] > … — the keyword is on the Keys tail and
			// `nat` is its BODY. Naming "nat" here would be naming the wrong
			// token, which is what the first version of the gate did.
			text:    "routing-instances {\n  VRF-A security {\n    nat { nat64 { rule-set rs1 { prefix 64:ff9b::/96; } } }\n  }\n}\n",
			wantTok: "security",
		},
		{
			name:    "packed/bogus-keyword-with-values",
			text:    "routing-instances {\n  VRF-A totally-bogus-keyword foo bar;\n}\n",
			wantTok: "totally-bogus-keyword",
		},

		// --- REFERENCE ARMS: MUST ACCEPT ---
		{
			name: "brace-elided/routing-options-body",
			// The arm the first version false-rejected, naming "static".
			text:    "routing-instances {\n  VRF-A routing-options {\n    static { route 0.0.0.0/0 next-hop 10.0.0.1; }\n  }\n}\n",
			wantTok: "",
		},
		{
			name: "brace-elided/protocols-body",
			// The arm the first version false-rejected, naming "ospf".
			text:    "routing-instances {\n  VRF-A protocols {\n    ospf { area 0.0.0.0 { interface ge-0/0/1.0; } }\n  }\n}\n",
			wantTok: "",
		},
		{
			name:    "packed/instance-type-and-interface",
			text:    "routing-instances {\n  VRF-A instance-type vrf;\n  VRF-A interface ge-0/0/1.0;\n}\n",
			wantTok: "",
		},
		{
			name:    "braced/nested-legitimate-children",
			text:    "routing-instances {\n  VRF-A {\n    instance-type vrf;\n    interface ge-0/0/1.0;\n    routing-options { static { route 0.0.0.0/0 next-hop 10.0.0.1; } }\n  }\n}\n",
			wantTok: "",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parse9323(t, tc.text))
			if tc.wantTok == "" {
				if err != nil {
					t.Fatalf("VALID configuration was REJECTED: %v\n%s\n"+
						"A commit gate that refuses valid configuration is a worse "+
						"defect than the silent drop #9323 fixes", err, tc.text)
				}
				return
			}
			if err == nil {
				t.Fatalf("ACCEPTED, want a rejection naming %q:\n%s", tc.wantTok, tc.text)
			}
			if !strings.Contains(err.Error(), `"`+tc.wantTok+`"`) {
				t.Errorf("the rejection names the WRONG keyword.\n got: %v\nwant it to name %q\n%s",
					err, tc.wantTok, tc.text)
			}
		})
	}
}

// The empty-schema DECLINE. If the permitted set cannot be read, the gate must
// judge NOTHING — refusing every routing instance would turn a lookup failure
// into a total commit outage, which is the levelling-down failure in its purest
// form.
//
// Driven white-box, by swapping the schema node for the duration, because the
// arm is unreachable in production (the schema is a package-level literal). A
// mutant that removes the decline SURVIVED the whole suite until this cell
// existed.
func TestTheGateDeclinesToJudgeWhenTheSchemaCannotBeRead9323(t *testing.T) {
	ri := setSchema.children["routing-instances"]
	if ri == nil || ri.wildcard == nil {
		t.Fatalf("routing-instances wildcard not found")
	}
	saved := ri.wildcard.children
	t.Cleanup(func() { ri.wildcard.children = saved })

	if len(routingInstanceChildTokens9323()) == 0 {
		t.Fatalf("fixture: the permitted set is already empty, so the swap below " +
			"changes nothing and this cell proves nothing")
	}
	ri.wildcard.children = nil
	if got := routingInstanceChildTokens9323(); len(got) != 0 {
		t.Fatalf("fixture: the permitted set is %v after the swap, not empty", got)
	}

	nodes := parse9323(t, "routing-instances {\n  VRF-A totally-bogus-keyword foo bar;\n}\n").Children
	warns, err := validateRoutingInstanceChildTokensAST(nodes, false)
	if err != nil {
		t.Errorf("the gate REJECTED with an unreadable schema: %v.\nA lookup failure "+
			"must not become a total commit outage — decline to judge instead", err)
	}
	if len(warns) != 0 {
		t.Errorf("the gate warned with an unreadable schema: %v", warns)
	}
}
