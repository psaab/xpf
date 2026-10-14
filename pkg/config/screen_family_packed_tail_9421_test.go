package config

import (
	"fmt"
	"strings"
	"testing"
)

// #9421 — the screen FAMILY node's packed tail.
//
// #6683 normalised the ids-option node's packed body and stopped one level
// short. A family node (`icmp`, `ip`, `tcp`, `udp`, `limit-session`) that
// carries its own body on its Keys arrives with ZERO children, so every reader
// in compileScreen runs zero times: the check compiles DISABLED and nothing
// reaches ScreenProfile.UnknownLeaves, so the #3318 gate that would have
// rejected an unsupported spelling is never armed either.
//
// The FLAT spelling of the identical statement does not lose it — SetPath
// builds a chain rather than packing onto one node — so before the fix ONE
// statement produced three different observables depending only on how the
// operator typed it. Measured on the base revision for
// `icmp [ ping-death fragment ]`:
//
//	shape          strict CompileConfig   ICMP.PingDeath   UnknownLeaves
//	hierarchical   ACCEPT                 false            []
//	flat set       REJECT (#1960 msg)     true             [icmp ping-death fragment]
//
// This table asserts, per family and per spelling, that BOTH AST shapes reach
// the identical strict verdict AND the identical compiled profile — including
// the booleans, not merely that the profile exists.
//
// The bracketed multi-token rows are the REFUSE half: `icmp` is declared with
// `children` and no `multi:`, so a bracketed list is not a shape this grammar
// has. The flat path already refused it; the fix makes the hierarchical path
// refuse it identically (the #9246 precedent — refuse rather than drop).
//
// Scope: the brace-elided rows exercise the same depth #9056 catalogues as one
// of its 83 sites. #9056 is the general class and its remedy is an admission
// into the compact_normalize_scope.go table, whose stated precondition (the
// site must appear in the measured divergence inventory) a valueless flag
// cannot satisfy — that is #9056's whole finding. This fix is site-local to
// compileScreen and does not close it.

// screenProfileSummary renders every typed field a screen profile carries, so
// a cross-shape comparison cannot pass by ignoring the field that moved.
func screenProfileSummary9421(p *ScreenProfile) string {
	if p == nil {
		return "<nil>"
	}
	sf := "nil"
	if p.TCP.SynFlood != nil {
		sf = fmt.Sprintf("{alarm=%d attack=%d src=%d dst=%d timeout=%d}",
			p.TCP.SynFlood.AlarmThreshold, p.TCP.SynFlood.AttackThreshold,
			p.TCP.SynFlood.SourceThreshold, p.TCP.SynFlood.DestinationThreshold,
			p.TCP.SynFlood.Timeout)
	}
	return fmt.Sprintf(
		"icmp{ping-death=%v fragment=%v flood=%d} ip{source-route=%v tear-drop=%v ip-sweep=%d} "+
			"tcp{land=%v winnuke=%v syn-frag=%v syn-fin=%v no-flag=%v fin-no-ack=%v port-scan=%d syn-flood=%s} "+
			"udp{flood=%d} limit-session{src=%d dst=%d} alarm-without-drop=%v unknown=%v",
		p.ICMP.PingDeath, p.ICMP.Fragment, p.ICMP.FloodThreshold,
		p.IP.SourceRouteOption, p.IP.TearDrop, p.IP.IPSweepThreshold,
		p.TCP.Land, p.TCP.WinNuke, p.TCP.SynFrag, p.TCP.SynFin, p.TCP.NoFlag,
		p.TCP.FinNoAck, p.TCP.PortScanThreshold, sf,
		p.UDP.FloodThreshold,
		p.LimitSession.SourceIPBased, p.LimitSession.DestinationIPBased,
		p.AlarmWithoutDrop, p.UnknownLeaves)
}

func screenHierTree9421(t *testing.T, body string) *ConfigTree {
	t.Helper()
	text := "security { screen { ids-option P { " + body + " } } }"
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse %q: %v", text, errs)
	}
	return tree
}

func screenFlatTree9421(t *testing.T, stmt string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand("set security screen ids-option P " + stmt)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", stmt, err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath(%q): %v", stmt, err)
	}
	return tree
}

// screenChannels9421 runs the three in-package config channels and returns the
// strict verdict plus the profile each of the accepting paths compiled.
//
// The fourth channel, configstore.CheckText (the operator commit path), cannot
// be reached from this package without an import cycle; it is asserted in
// pkg/configstore by TestScreenFamilyPackedTailCheckText9421 against the same
// statements.
func screenChannels9421(t *testing.T, tree *ConfigTree) (strictErr error, schemaErr error, summary string) {
	t.Helper()
	_, strictErr = CompileConfig(tree)
	lenient, lenErr := CompileConfigLenient(tree)
	if lenErr != nil {
		t.Fatalf("CompileConfigLenient must not reject (tolerant path): %v", lenErr)
	}
	schemaErr = SchemaValidate(tree, lenient)
	return strictErr, schemaErr, screenProfileSummary9421(lenient.Security.Screen["P"])
}

func TestScreenFamilyPackedTailBothShapes9421(t *testing.T) {
	cases := []struct {
		name string
		// hier is the ids-option BODY in hierarchical source; flat is the
		// tail of the equivalent `set` command. They are the SAME statement.
		hier       string
		flat       string
		wantStrict bool // true = strict CompileConfig must REJECT
		// wantSummary is the compiled profile both shapes must produce.
		wantSummary func(s string) bool
		wantDesc    string
	}{
		// ---- icmp -------------------------------------------------------
		{
			name: "icmp nested", hier: "icmp { ping-death; }", flat: "icmp ping-death",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "icmp{ping-death=true fragment=false") },
			wantDesc:    "ping-death=true",
		},
		{
			name: "icmp brace-elided", hier: "icmp ping-death;", flat: "icmp ping-death",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "icmp{ping-death=true fragment=false") },
			wantDesc:    "ping-death=true",
		},
		{
			name: "icmp bracketed multi-token", hier: "icmp [ ping-death fragment ];", flat: "icmp [ ping-death fragment ]",
			wantStrict: true,
			wantSummary: func(s string) bool {
				return strings.Contains(s, "unknown=[icmp ping-death fragment]")
			},
			wantDesc: "unknown=[icmp ping-death fragment]",
		},
		// ---- ip ---------------------------------------------------------
		{
			name: "ip nested", hier: "ip { tear-drop; }", flat: "ip tear-drop",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "tear-drop=true") },
			wantDesc:    "tear-drop=true",
		},
		{
			name: "ip brace-elided", hier: "ip tear-drop;", flat: "ip tear-drop",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "tear-drop=true") },
			wantDesc:    "tear-drop=true",
		},
		{
			name: "ip bracketed multi-token", hier: "ip [ tear-drop source-route-option ];", flat: "ip [ tear-drop source-route-option ]",
			wantStrict: true,
			wantSummary: func(s string) bool {
				return strings.Contains(s, "unknown=[ip tear-drop source-route-option]")
			},
			wantDesc: "unknown=[ip tear-drop source-route-option]",
		},
		// ---- tcp --------------------------------------------------------
		{
			name: "tcp nested", hier: "tcp { land; }", flat: "tcp land",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "tcp{land=true") },
			wantDesc:    "land=true",
		},
		{
			name: "tcp brace-elided", hier: "tcp land;", flat: "tcp land",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "tcp{land=true") },
			wantDesc:    "land=true",
		},
		{
			name: "tcp bracketed multi-token", hier: "tcp [ syn-fin land ];", flat: "tcp [ syn-fin land ]",
			wantStrict:  true,
			wantSummary: func(s string) bool { return strings.Contains(s, "unknown=[tcp syn-fin land]") },
			wantDesc:    "unknown=[tcp syn-fin land]",
		},
		// ---- udp --------------------------------------------------------
		{
			name: "udp nested", hier: "udp { flood { threshold 900; } }", flat: "udp flood threshold 900",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "udp{flood=900}") },
			wantDesc:    "udp flood threshold 900",
		},
		{
			name: "udp brace-elided", hier: "udp flood threshold 900;", flat: "udp flood threshold 900",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "udp{flood=900}") },
			wantDesc:    "udp flood threshold 900",
		},
		{
			name: "udp bracketed unmodelled token", hier: "udp [ flood bogus ];", flat: "udp [ flood bogus ]",
			wantStrict:  true,
			wantSummary: func(s string) bool { return strings.Contains(s, "unknown=[udp flood bogus]") },
			wantDesc:    "unknown=[udp flood bogus]",
		},
		// ---- limit-session ----------------------------------------------
		{
			name: "limit-session nested", hier: "limit-session { source-ip-based 100; }", flat: "limit-session source-ip-based 100",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "limit-session{src=100 dst=0}") },
			wantDesc:    "src=100",
		},
		{
			name: "limit-session brace-elided", hier: "limit-session source-ip-based 100;", flat: "limit-session source-ip-based 100",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "limit-session{src=100 dst=0}") },
			wantDesc:    "src=100",
		},
		// ---- packed tail AND a braced body on ONE family node ---------
		// `icmp flood { threshold 900; }` parses as Keys=["icmp","flood"] WITH
		// Children=[["threshold","900"]]. The two halves spell one path, so the
		// braced body has to be re-attached UNDER the deepest packed node; left
		// beside it the sub-knob is invisible and the check arms at its DEFAULT
		// instead of the configured value — 1000 rather than 900, a plausible
		// number, which is the failure mode that reads as working.
		{
			name: "icmp flood packed tail plus braced body", hier: "icmp flood { threshold 900; }", flat: "icmp flood threshold 900",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "flood=900}") },
			wantDesc:    "icmp flood threshold 900 (not the 1000 default)",
		},
		{
			name: "ip ip-sweep packed tail plus braced body", hier: "ip ip-sweep { threshold 7000; }", flat: "ip ip-sweep threshold 7000",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "ip-sweep=7000}") },
			wantDesc:    "ip ip-sweep threshold 7000 (not the 5000 default)",
		},
		{
			name: "tcp syn-flood packed tail plus braced body", hier: "tcp syn-flood { attack-threshold 300; }", flat: "tcp syn-flood attack-threshold 300",
			wantStrict:  false,
			wantSummary: func(s string) bool { return strings.Contains(s, "attack=300") },
			wantDesc:    "tcp syn-flood attack-threshold 300 (not the 200 default)",
		},
		// ---- unknown leaf at family depth: the GATE-REACHABILITY cell ----
		{
			name: "tcp unsupported leaf brace-elided", hier: "tcp bogus-check;", flat: "tcp bogus-check",
			wantStrict:  true,
			wantSummary: func(s string) bool { return strings.Contains(s, "unknown=[tcp bogus-check]") },
			wantDesc:    "unknown=[tcp bogus-check]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hStrict, hSchema, hSum := screenChannels9421(t, screenHierTree9421(t, tc.hier))
			fStrict, fSchema, fSum := screenChannels9421(t, screenFlatTree9421(t, tc.flat))

			// (a) the strict verdict must be the SAME in both AST shapes.
			if (hStrict != nil) != (fStrict != nil) {
				t.Fatalf("strict CompileConfig verdict DIVERGES by AST shape:\n  hierarchical: %v\n  flat set:     %v", hStrict, fStrict)
			}
			// (b) and must be the verdict the cell expects.
			if got := hStrict != nil; got != tc.wantStrict {
				t.Fatalf("strict CompileConfig reject=%v, want %v (err=%v)", got, tc.wantStrict, hStrict)
			}
			// (c) SchemaValidate agrees across shapes too.
			if (hSchema != nil) != (fSchema != nil) {
				t.Fatalf("SchemaValidate verdict DIVERGES by AST shape:\n  hierarchical: %v\n  flat set:     %v", hSchema, fSchema)
			}
			// (d) the COMPILED profile is identical in both shapes — every
			// typed field, not merely "the profile exists".
			if hSum != fSum {
				t.Fatalf("compiled screen profile DIVERGES by AST shape:\n  hierarchical: %s\n  flat set:     %s", hSum, fSum)
			}
			// (e) and carries what the spelling actually configured.
			if !tc.wantSummary(hSum) {
				t.Fatalf("compiled screen profile does not carry %s:\n  %s", tc.wantDesc, hSum)
			}
		})
	}
}

// TestScreenPackedMalformedTailRejected12871 covers tokens after a valid
// screen path where packedBody abandons normalization on the first unknown
// token. Neither the configured flag nor its trailing garbage may disappear
// before the strict unknown-leaf gate sees it.
func TestScreenPackedMalformedTailRejected12871(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "recognized flag followed by unknown token",
			body: "tcp land bogus-tail;",
			want: "tcp land bogus-tail",
		},
		{
			name: "missing intermediate threshold keyword",
			body: "ip ip-sweep 7777;",
			want: "ip ip-sweep 7777",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "security { screen { ids-option P " + tc.body + " } }"
			tree, errs := NewParser(src).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse %q: %v", src, errs)
			}
			strictErr, _, summary := screenChannels9421(t, tree)
			if strictErr == nil {
				t.Fatalf("strict CompileConfig accepted malformed packed body %q; compiled profile: %s", tc.body, summary)
			}
			if !strings.Contains(summary, tc.want) {
				t.Fatalf("lenient compile lost malformed packed tokens %q:\n%s", tc.want, summary)
			}
		})
	}
}

// TestScreenFamilyPackedTailRefusalMessage9421 pins the refusal TEXT, not just
// the refusal. A mutation caught by the wrong branch reads as a working gate:
// the bracketed spelling must be rejected by the #3318 unknown-leaf gate naming
// the operator's own tokens, which is what makes the message actionable — and
// it must be the SAME message the flat path already produced.
func TestScreenFamilyPackedTailRefusalMessage9421(t *testing.T) {
	_, hErr := CompileConfig(screenHierTree9421(t, "icmp [ ping-death fragment ];"))
	_, fErr := CompileConfig(screenFlatTree9421(t, "icmp [ ping-death fragment ]"))
	if hErr == nil || fErr == nil {
		t.Fatalf("both shapes must reject: hier=%v flat=%v", hErr, fErr)
	}
	if hErr.Error() != fErr.Error() {
		t.Fatalf("refusal message differs by AST shape:\n  hierarchical: %v\n  flat set:     %v", hErr, fErr)
	}
	if !strings.Contains(hErr.Error(), "`icmp ping-death fragment` is not a supported screen option") {
		t.Fatalf("refusal does not name the operator's tokens: %v", hErr)
	}
}

// TestScreenFamilyBodyLeavesAuthoredASTAlone9421 pins that the normalization
// never mutates the operator's tree. `show configuration` renders from the AST,
// so rewriting a packed one-liner into nested form as a side effect of
// compiling it would change what the operator is shown.
func TestScreenFamilyBodyLeavesAuthoredASTAlone9421(t *testing.T) {
	tree := screenHierTree9421(t, "icmp ping-death;")
	fam := tree.FindChild("security").FindChild("screen").Children[0].Children[0]
	before := fmt.Sprintf("%v/%d", fam.Keys, len(fam.Children))
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if after := fmt.Sprintf("%v/%d", fam.Keys, len(fam.Children)); after != before {
		t.Fatalf("compileScreen mutated the authored AST: before=%s after=%s", before, after)
	}
	if before != "[icmp ping-death]/0" {
		t.Fatalf("fixture no longer holds the packed shape this test is about: %s", before)
	}
}
