package config

// compiler_multivalue_leaf_6714_test.go — the three #6714 arms plus the
// repeated-`forwarding-table`-block site the #6673 fold left a note about in
// compiler_routing.go.
//
// All four are the #2419 multi-value-leaf class, and all four survived the
// behavioural spelling gate (schema_spelling_differential_gate_test.go) for
// reasons worth stating, because they are that gate's actual limits rather
// than an oversight in it:
//
//   - Arms 1 and 4 are not a LEAF spelling at all. The gate authors five
//     spellings of ONE leaf statement; these two are a second STATEMENT (a
//     value tail riding on a block child, a second `forwarding-table` block),
//     which the enumerator never emits.
//   - Arm 3 (`commands`) is a spelling the gate deliberately does not compare:
//     setSchema marks the leaf scalar, and for a scalar leaf a repeated
//     statement legitimately REPLACES, so comparing the repeated spellings
//     would manufacture a finding at every scalar leaf in the schema.
//   - Arm 2 (proxy-ARP) compiles identically in every spelling — the drop is
//     uniform, and the leaf is not `multi: true`-shaped in the way class B
//     requires. A differential cannot see a compiler that agrees with itself
//     about discarding something.
//
// Each test below therefore carries its own shape corpus rather than leaning
// on the gate.

import (
	"reflect"
	"strings"
	"testing"
)

// TestFirewallMatchValues6714ReadsEveryKeyOfEveryChild pins arm 1.
//
// firewallMatchValues is the shared reader for ~70 value-list call sites. It
// read child.Keys[0] and stopped, while reading the node's OWN tail in full
// (Keys[1:]) — so the identical token sequence contributed every value on one
// side of the AST and one value on the other. The property asserted here is
// that AGREEMENT, not a particular output: whichever side of the AST the
// parser puts a statement's tokens on, the reader must see the same values.
//
// The shape is produced by a hand-authored / `load merge` file that packs more
// than one token onto a statement inside a value block, and by a bracketed list
// nested inside one. Neither is the spelling Junos itself emits, which is
// exactly why it survived every brace-authored fixture in this package: the
// canonical spellings put one token per child.
func TestFirewallMatchValues6714ReadsEveryKeyOfEveryChild(t *testing.T) {
	for _, tc := range []struct {
		name string
		node *Node
		want []string
	}{
		{"own tail carries every token (unchanged)",
			&Node{Keys: []string{"flag", "a", "b", "c"}},
			[]string{"a", "b", "c"}},
		{"one token per child (unchanged)",
			&Node{Keys: []string{"flag"}, Children: []*Node{
				{Keys: []string{"a"}}, {Keys: []string{"b"}}, {Keys: []string{"c"}},
			}},
			[]string{"a", "b", "c"}},
		{"a child carrying a multi-token tail",
			&Node{Keys: []string{"flag"}, Children: []*Node{
				{Keys: []string{"a"}}, {Keys: []string{"b", "c"}},
			}},
			[]string{"a", "b", "c"}},
		{"every token on ONE child",
			&Node{Keys: []string{"flag"}, Children: []*Node{
				{Keys: []string{"a", "b", "c"}},
			}},
			[]string{"a", "b", "c"}},
		{"empty tokens are still skipped",
			&Node{Keys: []string{"flag", ""}, Children: []*Node{
				{Keys: []string{"a", "", "b"}}, {Keys: []string{""}},
			}},
			[]string{"a", "b"}},
		{"a child with a sub-block contributes its name only",
			&Node{Keys: []string{"neighbor"}, Children: []*Node{
				{Keys: []string{"10.0.0.1"}, Children: []*Node{{Keys: []string{"metric", "2"}}}},
			}},
			[]string{"10.0.0.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firewallMatchValues(tc.node); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("firewallMatchValues = %q, want %q", got, tc.want)
			}
		})
	}

	// The agreement property, stated as a property: the same token sequence
	// must read the same however the parser distributed it. A reader that takes
	// only Keys[0] of each child fails the third pairing below and passes the
	// first two, which is why one shape is not enough to bind this.
	for _, toks := range [][]string{{"a", "b"}, {"a", "b", "c"}, {"x"}} {
		tail := &Node{Keys: append([]string{"leaf"}, toks...)}
		perChild := &Node{Keys: []string{"leaf"}}
		for _, tok := range toks {
			perChild.Children = append(perChild.Children, &Node{Keys: []string{tok}})
		}
		oneChild := &Node{Keys: []string{"leaf"}, Children: []*Node{{Keys: append([]string{}, toks...)}}}
		a, b, c := firewallMatchValues(tail), firewallMatchValues(perChild), firewallMatchValues(oneChild)
		if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(a, c) {
			t.Fatalf("tokens %q read differently per AST shape: own-tail=%q per-child=%q one-child=%q",
				toks, a, b, c)
		}
	}
}

// TestFlowTraceFlags6714NestedTailCompilesAndValidates is arm 1 end-to-end on
// the leaf #6659 named, and it asserts the half that makes the drop more than
// cosmetic: `flag` has a commit-time validator that walks exactly what this
// reader returns, so a dropped token was ALSO a dropped check. An unknown flag
// riding on a block child's tail committed clean and enabled nothing.
func TestFlowTraceFlags6714NestedTailCompilesAndValidates(t *testing.T) {
	// `flag` implements exactly two tokens, so the multi-token child carries
	// both of them; a third would be an unknown flag and is asserted below.
	cfg, err := CompileConfig(hierTree6659(t, `
security { flow { traceoptions { flag { basic-datapath session; } } } }`))
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	want := []string{"basic-datapath", "session"}
	if got := cfg.Security.Flow.Traceoptions.Flags; !reflect.DeepEqual(got, want) {
		t.Fatalf("Flags = %q, want %q — the second token of a block child's "+
			"statement was dropped, so the operator gets less tracing than "+
			"they asked for with no diagnostic", got, want)
	}

	// A bracketed list nested inside the block — the shape #6714 names — is
	// the same AST node and must read the same.
	cfg, err = CompileConfig(hierTree6659(t, `
security { flow { traceoptions { flag { [ basic-datapath session ]; } } } }`))
	if err != nil {
		t.Fatalf("strict compile: %v", err)
	}
	if got := cfg.Security.Flow.Traceoptions.Flags; !reflect.DeepEqual(got, want) {
		t.Fatalf("Flags = %q, want %q", got, want)
	}

	// The gate-escape half, and the reason this arm is not cosmetic: the
	// commit-time validator walks exactly what this reader returns
	// (compiler_security_flow.go), so a dropped token was ALSO a dropped
	// check. An unknown flag past the first slot committed CLEAN and enabled
	// nothing.
	if _, err := CompileConfig(hierTree6659(t, `
security { flow { traceoptions { flag { basic-datapath totally-bogus; } } } }`)); err == nil {
		t.Fatalf("strict compile ACCEPTED an unknown flow trace flag riding on a " +
			"block child's tail")
	}
}

// TestPolicyCommunityAction6714BlockFormIsNotLost is the same arm on a leaf
// where the one-sided read did not truncate a list but discarded a whole
// ACTION. `then { community { add cA; } }` puts the operation keyword and its
// argument on one child; reading Keys[0] returned ["add"] alone, and
// applyCommunityAction requires len(vals) >= 2 — so the term compiled with NO
// community action at all and FRR rendered nothing.
func TestPolicyCommunityAction6714BlockFormIsNotLost(t *testing.T) {
	for _, tc := range []struct{ name, cfg, wantOp, wantAdd string }{
		{"block form", `policy-options { policy-statement PS { term T { then { community { add cA; } } } } }`, "add", "cA"},
		{"leaf form (control)", `policy-options { policy-statement PS { term T { then { community add cA; } } } }`, "add", "cA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(hierTree6659(t, tc.cfg))
			if err != nil {
				t.Fatalf("strict compile: %v", err)
			}
			ps := cfg.PolicyOptions.PolicyStatements["PS"]
			if ps == nil {
				t.Fatalf("policy-statement PS missing")
			}
			terms := ps.Terms
			if len(terms) != 1 {
				t.Fatalf("terms = %d, want 1", len(terms))
			}
			if terms[0].CommunityOp != tc.wantOp || terms[0].CommunityAdd != tc.wantAdd {
				t.Fatalf("CommunityOp/Add = %q/%q, want %q/%q",
					terms[0].CommunityOp, terms[0].CommunityAdd, tc.wantOp, tc.wantAdd)
			}
		})
	}
}

// TestEventChangeConfigCommands6714RepeatedStatementsAllCompile pins arm 3.
//
// The parser keeps repeated same-keyed statements as SIBLINGS, so the
// FindChild read compiled the first `commands` (and the first
// `change-configuration` block) and discarded every later one: a remediation
// action the operator authored that never runs.
//
// The flat-set row is the control that makes the defect's SHAPE-dependence
// explicit — it already kept both, because SetPath merges a repeated leaf into
// one node instead of appending a sibling. A fixture built only from `set`
// commands (which is what CLAUDE.md tells you to reach for) could not have
// seen this.
func TestEventChangeConfigCommands6714RepeatedStatementsAllCompile(t *testing.T) {
	want := []string{"set system host-name a", "set system host-name b"}

	for _, tc := range []struct{ name, cfg string }{
		{"repeated commands leaves", `
event-options { policy P { events e1; then { change-configuration {
  commands "set system host-name a"; commands "set system host-name b"; } } } }`},
		{"repeated change-configuration blocks", `
event-options { policy P { events e1; then {
  change-configuration { commands "set system host-name a"; }
  change-configuration { commands "set system host-name b"; } } } }`},
		{"repeated then blocks (control: already worked)", `
event-options { policy P { events e1;
  then { change-configuration { commands "set system host-name a"; } }
  then { change-configuration { commands "set system host-name b"; } } } }`},
		{"block spelling (control: already worked)", `
event-options { policy P { events e1; then { change-configuration {
  commands { "set system host-name a"; "set system host-name b"; } } } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(hierTree6659(t, tc.cfg))
			if err != nil {
				t.Fatalf("strict compile: %v", err)
			}
			if len(cfg.EventOptions) != 1 {
				t.Fatalf("policies = %d, want 1", len(cfg.EventOptions))
			}
			if got := cfg.EventOptions[0].ThenCommands; !reflect.DeepEqual(got, want) {
				t.Fatalf("ThenCommands = %q, want %q", got, want)
			}
		})
	}

	t.Run("flat-set repeated (control: already worked)", func(t *testing.T) {
		cfg, err := CompileConfig(setTree6659(t,
			`set event-options policy P events e1`,
			`set event-options policy P then change-configuration commands "set system host-name a"`,
			`set event-options policy P then change-configuration commands "set system host-name b"`))
		if err != nil {
			t.Fatalf("strict compile: %v", err)
		}
		if got := cfg.EventOptions[0].ThenCommands; !reflect.DeepEqual(got, want) {
			t.Fatalf("ThenCommands = %q, want %q", got, want)
		}
	})
}

// TestForwardingTableExports6714RepeatedBlocksAreVisible pins the fourth site,
// the one compiler_routing.go carried as a named #6714 blind spot.
//
// Two `forwarding-table` blocks inside ONE `routing-options` root left the
// second block's export invisible to BOTH halves of the contract: it was
// neither rendered NOR reference-checked, and the cardinality gate — which
// exists to reject exactly this ambiguity — could not see it, so the config
// committed clean with one of two authored policies in effect.
//
// The asymmetry the fix preserves is asserted here, not just described: the
// SCALAR (what FRR installs) still comes from the FIRST block, so no config
// changes which policy renders. Only what an operator can COMMIT changes.
func TestForwardingTableExports6714RepeatedBlocksAreVisible(t *testing.T) {
	twoPolicies := `
policy-options { policy-statement p1 { term t { then accept; } } policy-statement p2 { term t { then accept; } } }
routing-options { forwarding-table { export p1; } forwarding-table { export p2; } }`

	// Strict: the ambiguity is now operator-visible.
	if _, err := CompileConfig(hierTree6659(t, twoPolicies)); err == nil {
		t.Fatalf("strict compile ACCEPTED two forwarding-table blocks naming two " +
			"different export policies; only one renders, so accepting it is the " +
			"silent drop this gate exists to reject")
	} else if !strings.Contains(err.Error(), "forwarding-table export declares 2 policies") {
		t.Fatalf("rejected by the wrong gate: %v", err)
	}

	// Tolerant: boots, warns, and renders exactly what it rendered before —
	// the FIRST block's policy (#1960 no-brick).
	cfg, err := CompileConfigLenient(hierTree6659(t, twoPolicies))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if got, want := cfg.RoutingOptions.ForwardingTableExport, "p1"; got != want {
		t.Fatalf("ForwardingTableExport = %q, want %q — the rendered policy must "+
			"not move; only the diagnostic is new", got, want)
	}
	if got, want := cfg.RoutingOptions.ForwardingTableExports, []string{"p1", "p2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ForwardingTableExports = %q, want %q", got, want)
	}

	// A leading block with no export must NOT let a later block's export
	// become the rendered policy: master resolved `forwarding-table` with
	// FindChild and looked for an export inside whatever it got.
	cfg, err = CompileConfigLenient(hierTree6659(t, `
policy-options { policy-statement p1 { term t { then accept; } } }
routing-options { forwarding-table { indirect-next-hop; } forwarding-table { export p1; } }`))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if got := cfg.RoutingOptions.ForwardingTableExport; got != "" {
		t.Fatalf("ForwardingTableExport = %q, want \"\" — a leading export-less "+
			"block left the scalar unset on master, and selecting the next "+
			"block's export instead would render a policy master did not", got)
	}
	if got, want := cfg.RoutingOptions.ForwardingTableExports, []string{"p1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ForwardingTableExports = %q, want %q", got, want)
	}

	// Two blocks naming the SAME policy is not an ambiguity and must still
	// commit clean — the cardinality gate counts DISTINCT non-empty values
	// (#6673), and this is the row that proves the widening did not turn a
	// harmless duplicate into a rejection.
	if _, err := CompileConfig(hierTree6659(t, `
policy-options { policy-statement p1 { term t { then accept; } } }
routing-options { forwarding-table { export p1; } forwarding-table { export p1; } }`)); err != nil {
		t.Fatalf("strict compile rejected two blocks naming ONE policy: %v", err)
	}

	// A single block is bit-identical to before.
	cfg, err = CompileConfigLenient(hierTree6659(t, `
policy-options { policy-statement p1 { term t { then accept; } } }
routing-options { forwarding-table { export p1; } }`))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if cfg.RoutingOptions.ForwardingTableExport != "p1" ||
		!reflect.DeepEqual(cfg.RoutingOptions.ForwardingTableExports, []string{"p1"}) {
		t.Fatalf("single block regressed: scalar=%q list=%q",
			cfg.RoutingOptions.ForwardingTableExport, cfg.RoutingOptions.ForwardingTableExports)
	}
}

// TestProxyARPMalformedRange6714IsDiagnosedNotSilent pins arm 2.
//
// The INSTALLED SET does not move — that parity is #6673's, measured against
// origin/master through the installer's own netip.ParsePrefix gate, and
// TestProxyARPAddresses6673MalformedRangeInstallsExactlyWhatMasterInstalled
// still owns every row of it. What changes is that the discard stops being
// silent: strict rejects at commit, the tolerant load / peer-sync path warns
// and installs exactly what it installed before (#1960 no-brick).
//
// Widening the READ instead was considered and rejected. `address [ .1 .2 to
// .9 ]` is not authorable Junos — the leaf takes one address/prefix, one
// `<low> to <high>` range, or a list of plain addresses, never a mixture — so
// expanding it would invent a grammar, and it would make an appliance answer
// ARP for addresses it did not answer for before the upgrade. A rejection can
// be relaxed later; an ARP response cannot be un-sent.
func TestProxyARPMalformedRange6714IsDiagnosedNotSilent(t *testing.T) {
	const mixed = `
security { nat { proxy-arp { interface ge-0-0-0 { address [ 192.0.2.1 192.0.2.2 to 192.0.2.4 ]; } } } }`

	if _, err := CompileConfig(hierTree6659(t, mixed)); err == nil {
		t.Fatalf("strict compile ACCEPTED a proxy-arp address list mixing a " +
			"discrete address with a range; the compiler installs only the first " +
			"value, so accepting it silently narrows the proxy-ARP set")
	} else if !strings.Contains(err.Error(), "is not a valid address statement") {
		t.Fatalf("rejected by the wrong gate: %v", err)
	}

	cfg, err := CompileConfigLenient(hierTree6659(t, mixed))
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if got, want := cfg.Security.NAT.ProxyARP[0].Addresses, []string{"192.0.2.1/32"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Addresses = %q, want %q — the installed set is #6673 parity and "+
			"must not move", got, want)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "is not a valid address statement") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("tolerant compile installed one address of an authored list and "+
			"said nothing: warnings = %q", cfg.Warnings)
	}

	// The offending statement is quoted in full, in AUTHORED order, whichever
	// AST shape the parser chose — that is what makes the diagnostic
	// actionable, and it is the reason proxyARPStatementTokens walks the whole
	// subtree instead of one Keys slice.
	for _, tc := range []struct{ name, cfg, wantSpec string }{
		{"bracket", mixed, "192.0.2.1 192.0.2.2 to 192.0.2.4"},
		{"block", `
security { nat { proxy-arp { interface ge-0-0-0 { address { 192.0.2.1; 192.0.2.2 to 192.0.2.4; } } } } }`,
			"192.0.2.1 192.0.2.2 to 192.0.2.4"},
		{"nested", `
security { nat { proxy-arp { interface ge-0-0-0 { address { 192.0.2.1 { to 192.0.2.4; } } } } } }`,
			"192.0.2.1 to 192.0.2.4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(hierTree6659(t, tc.cfg))
			if err != nil {
				t.Fatalf("tolerant compile: %v", err)
			}
			got := cfg.Security.NAT.ProxyARP[0].MalformedRangeSpecs
			if !reflect.DeepEqual(got, []string{tc.wantSpec}) {
				t.Fatalf("MalformedRangeSpecs = %q, want %q", got, []string{tc.wantSpec})
			}
		})
	}

	// Controls: a well-formed range and a plain list must still commit clean,
	// which is what proves the gate fires on the FALL-THROUGH rather than on
	// "the config mentions a range".
	for _, tc := range []struct{ name, cfg string }{
		{"well-formed range", `
security { nat { proxy-arp { interface ge-0-0-0 { address 192.0.2.1 to 192.0.2.3; } } } }`},
		{"plain list", `
security { nat { proxy-arp { interface ge-0-0-0 { address [ 192.0.2.1 192.0.2.2 ]; } } } }`},
		{"plain block", `
security { nat { proxy-arp { interface ge-0-0-0 { address { 192.0.2.1; 192.0.2.2; } } } } }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(hierTree6659(t, tc.cfg))
			if err != nil {
				t.Fatalf("strict compile rejected a well-formed statement: %v", err)
			}
			if got := cfg.Security.NAT.ProxyARP[0].MalformedRangeSpecs; got != nil {
				t.Fatalf("MalformedRangeSpecs = %q, want none", got)
			}
		})
	}
}
