package config

import (
	"strings"
	"testing"
)

// #6524: a chained flat-set custom application compiled PROTOCOL-ONLY.
//
// `set a b c d` builds a CHAIN of single-key nodes, so in
//
//	set applications application myapp protocol tcp destination-port 8080
//
// `destination-port` is nested under the VALUE node `tcp` and is never a
// sibling of `protocol`. compileApplications iterated only
// inst.node.Children, saw only `protocol`, and never assigned
// app.DestinationPort — an empty port term matches ANY port, so a policy
// referencing the application permitted all TCP.
//
// Nothing caught it: `protocol` / `destination-port` / `source-port` are the
// only application match leaves that are neither typed nor `scalar: true`
// (schema_security.go), so no arity gate engages and the chained form validates
// clean at BOTH SchemaValidate and strict commit. The REVERSE token order was
// caught only incidentally, by the #3109 protocol-less gate — that asymmetry
// hid this.
//
// The fix is in the COMPILER (applicationDirectLeaves walks the chain across
// both AST shapes) rather than in the schema. A schema-only reject would leave
// the LENIENT path — boot load and HA SyncApply, where a schema rejection is
// downgraded to a warning — still compiling protocol-only and still permitting
// all TCP; see TestChainedAppLenientPathAlsoHonorsChain.
//
// The policy-OUTCOME fail-on-revert lives in
// pkg/policymatch/app_chained_leaves_6524_test.go (pkg/config cannot import
// pkg/policymatch — policymatch imports config).

func setTree6524(t *testing.T, cmds ...string) *ConfigTree {
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
	return tree
}

// TestChainedAppDirectLeavesCompile is the core structural fail-on-revert: each
// chained leaf must land in its own typed field.
func TestChainedAppDirectLeavesCompile(t *testing.T) {
	cases := []struct {
		name  string
		set   string
		check func(t *testing.T, app *Application)
	}{
		{
			name: "protocol + destination-port",
			set:  "set applications application myapp protocol tcp destination-port 8080",
			check: func(t *testing.T, app *Application) {
				if app.Protocol != "tcp" || app.DestinationPort != "8080" {
					t.Fatalf("protocol=%q destination-port=%q, want tcp/8080 — the "+
						"chained destination-port was dropped (#6524)",
						app.Protocol, app.DestinationPort)
				}
			},
		},
		{
			name: "protocol + source-port",
			set:  "set applications application myapp protocol udp source-port 5000",
			check: func(t *testing.T, app *Application) {
				if app.Protocol != "udp" || app.SourcePort != "5000" {
					t.Fatalf("protocol=%q source-port=%q, want udp/5000", app.Protocol, app.SourcePort)
				}
			},
		},
		{
			name: "three-deep chain",
			set:  "set applications application myapp protocol tcp source-port 5000 destination-port 8080",
			check: func(t *testing.T, app *Application) {
				if app.Protocol != "tcp" || app.SourcePort != "5000" || app.DestinationPort != "8080" {
					t.Fatalf("protocol=%q source-port=%q destination-port=%q, want "+
						"tcp/5000/8080 — the walk must follow the WHOLE chain, not "+
						"just one link", app.Protocol, app.SourcePort, app.DestinationPort)
				}
			},
		},
		{
			name: "protocol + icmp-type",
			set:  "set applications application myapp protocol icmp icmp-type 8",
			check: func(t *testing.T, app *Application) {
				if app.ICMPType == nil || *app.ICMPType != 8 {
					t.Fatalf("ICMPType=%v, want 8 — a dropped icmp-type leaves the "+
						"application matching EVERY ICMP type", app.ICMPType)
				}
			},
		},
		{
			name: "protocol + icmp-type + icmp-code",
			set:  "set applications application myapp protocol icmp icmp-type 3 icmp-code 1",
			check: func(t *testing.T, app *Application) {
				if app.ICMPType == nil || *app.ICMPType != 3 {
					t.Fatalf("ICMPType=%v, want 3", app.ICMPType)
				}
				if app.ICMPCode == nil || *app.ICMPCode != 1 {
					t.Fatalf("ICMPCode=%v, want 1 (a type<->code swap shows 3)", app.ICMPCode)
				}
			},
		},
		{
			name: "protocol + inactivity-timeout",
			set:  "set applications application myapp protocol tcp inactivity-timeout 1800",
			check: func(t *testing.T, app *Application) {
				if app.InactivityTimeout != 1800 {
					t.Fatalf("InactivityTimeout=%d, want 1800 — a dropped timeout "+
						"silently falls back to the global per-protocol timeout",
						app.InactivityTimeout)
				}
			},
		},
		{
			name: "protocol + alg",
			set:  "set applications application myapp protocol tcp alg ftp",
			check: func(t *testing.T, app *Application) {
				if app.ALG != "ftp" {
					t.Fatalf("ALG=%q, want ftp", app.ALG)
				}
			},
		},
		{
			name: "named service port resolves through the chain",
			set:  "set applications application myapp protocol tcp destination-port https",
			check: func(t *testing.T, app *Application) {
				// resolveAppPort must still run on a chained value.
				if app.DestinationPort != "443" {
					t.Fatalf("destination-port=%q, want 443 (the service name must "+
						"resolve on the chained path too)", app.DestinationPort)
				}
			},
		},
		{
			name: "port range survives the chain",
			set:  "set applications application myapp protocol tcp destination-port 8080-8090",
			check: func(t *testing.T, app *Application) {
				if app.DestinationPort != "8080-8090" {
					t.Fatalf("destination-port=%q, want 8080-8090", app.DestinationPort)
				}
			},
		},
		{
			// REVERSE order. Pre-#6524 this dropped `protocol`, leaving a
			// protocol-less app that the #3109 gate rejected — the incidental
			// catch that hid the forward-order hole. It must now compile BOTH
			// leaves rather than reject.
			name: "reverse order (destination-port first)",
			set:  "set applications application myapp destination-port 8080 protocol tcp",
			check: func(t *testing.T, app *Application) {
				if app.Protocol != "tcp" || app.DestinationPort != "8080" {
					t.Fatalf("protocol=%q destination-port=%q, want tcp/8080", app.Protocol, app.DestinationPort)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := CompileConfig(setTree6524(t, c.set))
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			app := cfg.Applications.Applications["myapp"]
			if app == nil {
				t.Fatalf("application myapp missing from compiled config")
			}
			c.check(t, app)
		})
	}
}

// TestChainedAppLenientPathAlsoHonorsChain is the reason the fix lives in the
// COMPILER and not (only) in the schema. CompileConfigLenient is the tolerant
// boot-load / HA SyncApply path: it downgrades a strict rejection to a warning
// and keeps compiling. A schema-only fix would reject the chained form at
// interactive commit but leave a PERSISTED or PEER-PUSHED config compiling
// protocol-only — still permitting all TCP, and precisely where an operator
// would never see the warning.
func TestChainedAppLenientPathAlsoHonorsChain(t *testing.T) {
	cfg, err := CompileConfigLenient(setTree6524(t,
		"set applications application myapp protocol tcp destination-port 8080"))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	app := cfg.Applications.Applications["myapp"]
	if app == nil {
		t.Fatalf("application myapp missing from lenient-compiled config")
	}
	if app.Protocol != "tcp" || app.DestinationPort != "8080" {
		t.Fatalf("lenient path: protocol=%q destination-port=%q, want tcp/8080 — "+
			"a persisted or peer-synced chained application must NOT compile "+
			"protocol-only (it would permit ALL TCP with no operator-visible "+
			"error, #6524)", app.Protocol, app.DestinationPort)
	}
}

// TestChainedAppUnrepresentableTailRejected covers the tokens the chain walk
// cannot honor. A direct application body holds ONE protocol and ONE port
// (Application.Protocol / .DestinationPort are single fields — multi-valued
// matching is what `term` sub-blocks are for), so a bracketed list silently
// dropped every value past the first, and a typo'd leaf silently dropped its
// whole constraint. Both widen the application; both must now be
// operator-visible commit errors.
func TestChainedAppUnrepresentableTailRejected(t *testing.T) {
	cases := []struct {
		name      string
		set       string
		wantToken string
	}{
		{"bracketed protocol list", "set applications application myapp protocol [ tcp udp ]", "udp"},
		{"bracketed dest-port list", "set applications application myapp protocol tcp destination-port [ 22 23 ]", "23"},
		{"bracketed source-port list", "set applications application myapp protocol tcp source-port [ 1 2 ]", "2"},
		{"typo'd chained leaf", "set applications application myapp protocol tcp destination-poort 8080", "destination-poort"},
		{"typo'd leading leaf", "set applications application myapp protocoll tcp", "protocoll"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := CompileConfig(setTree6524(t, c.set))
			if err == nil {
				t.Fatalf("expected commit to REJECT %q — the unrepresentable tail "+
					"was silently dropped, widening the application (#6524)", c.set)
			}
			if !strings.Contains(err.Error(), `"`+c.wantToken+`"`) {
				t.Fatalf("reject message must name the offending token %q, got: %v",
					c.wantToken, err)
			}
			if !strings.Contains(err.Error(), "myapp") {
				t.Fatalf("reject message must name the application, got: %v", err)
			}
		})
	}
}

// TestChainedAppUnrepresentableTailLenientWarns pins the other half of the
// strict-reject / lenient-warn contract (#1960 no-brick): the same config must
// still BOOT on the tolerant path, downgraded to a warning.
func TestChainedAppUnrepresentableTailLenientWarns(t *testing.T) {
	cfg, err := CompileConfigLenient(setTree6524(t,
		"set applications application myapp protocol [ tcp udp ]"))
	if err != nil {
		t.Fatalf("lenient path must not hard-fail on an unrepresentable tail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "myapp") && strings.Contains(w, "udp") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("lenient path must record a downgrade warning naming myapp/udp, got %v",
			cfg.Warnings)
	}
}

// TestTermBearingAppStrayTokenStillRejected closes the propagation path. For a
// term-bearing application the parent `app` struct is DISCARDED (only the
// generated per-term applications are stored), so an UnknownDirectLeaves record
// left on the parent would vanish and escape the strict gate.
func TestTermBearingAppStrayTokenStillRejected(t *testing.T) {
	_, err := CompileConfig(setTree6524(t,
		"set applications application myapp term t1 protocol tcp destination-port 80",
		"set applications application myapp bogus-leaf 1",
	))
	if err == nil {
		t.Fatal("expected commit to REJECT a stray token on a term-bearing " +
			"application body — the parent struct is discarded, so the record " +
			"must be carried onto the generated term applications (#6524)")
	}
	if !strings.Contains(err.Error(), "bogus-leaf") {
		t.Fatalf("reject message must name the stray token, got: %v", err)
	}
}

// TestChainedAppDuplicateDetectionStillFires proves the #5574 conflicting-
// duplicate gate still engages once the chain is flattened — the chained
// spelling must not become a way to smuggle two conflicting values past it.
func TestChainedAppDuplicateDetectionStillFires(t *testing.T) {
	_, err := CompileConfig(setTree6524(t,
		"set applications application myapp protocol tcp destination-port 22",
		"set applications application myapp destination-port 53",
	))
	if err == nil {
		t.Fatal("expected commit to REJECT conflicting duplicate destination-port")
	}
	// QUOTED, for the same reason as :233 above. This hits the #5574
	// conflicting-duplicate message, whose static enumeration prints EVERY
	// application leaf unquoted — so the bare form is true for a reject that
	// names `protocol`, or any other leaf. Measured on a config whose
	// conflicting leaf is `protocol`: Contains(err, "destination-port") is
	// TRUE, Contains(err, `"destination-port"`) is FALSE.
	if !strings.Contains(err.Error(), `"destination-port"`) {
		t.Fatalf("reject message must name destination-port, got: %v", err)
	}
}

// TestHierarchicalAppBodyUnchanged is the over-reach guard: the hierarchical
// (braced) shape, where the leaves are already siblings, must compile exactly
// as before. This subtest must stay GREEN under a revert of the #6524 compiler
// change — if it goes RED the fix altered a shape it had no business touching.
func TestHierarchicalAppBodyUnchanged(t *testing.T) {
	p := NewParser(`
applications {
    application myapp {
        protocol tcp;
        destination-port 8080;
        source-port 5000;
        inactivity-timeout 1800;
        description sample;
    }
}
`)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	app := cfg.Applications.Applications["myapp"]
	if app == nil {
		t.Fatalf("application myapp missing")
	}
	if app.Protocol != "tcp" || app.DestinationPort != "8080" ||
		app.SourcePort != "5000" || app.InactivityTimeout != 1800 ||
		app.Description != "sample" {
		t.Fatalf("hierarchical body compiled differently: %+v", app)
	}
	if len(app.UnknownDirectLeaves) != 0 {
		t.Fatalf("hierarchical body must record no unknown leaves, got %v",
			app.UnknownDirectLeaves)
	}
}

// TestSiblingFlatSetAppBodyUnchanged is the second over-reach guard: the
// one-leaf-per-set-line spelling (the shape that always worked) is untouched,
// and records no unknown leaves. Also stays GREEN under revert.
func TestSiblingFlatSetAppBodyUnchanged(t *testing.T) {
	cfg, err := CompileConfig(setTree6524(t,
		"set applications application myapp protocol tcp",
		"set applications application myapp destination-port 8080",
		"set applications application myapp description sample",
	))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	app := cfg.Applications.Applications["myapp"]
	if app == nil {
		t.Fatalf("application myapp missing")
	}
	if app.Protocol != "tcp" || app.DestinationPort != "8080" || app.Description != "sample" {
		t.Fatalf("sibling flat-set body compiled differently: %+v", app)
	}
	if len(app.UnknownDirectLeaves) != 0 {
		t.Fatalf("sibling body must record no unknown leaves, got %v", app.UnknownDirectLeaves)
	}
}

// TestApplicationDirectLeafKeywordsMatchSchema is a drift canary against the
// AUTHORITATIVE source rather than a restatement of it. `setSchema`
// (schema_security.go) declares which statements an `applications application
// <name>` body accepts; applicationDirectLeaves classifies anything outside its
// own map as operator garbage and the strict gate then hard-rejects it. So a
// leaf ADDED to the schema but missed in the map becomes a fail-CLOSED
// regression on valid config — and a hardcoded expected-list here could never
// catch that, because the same hand cranks both. Enumerate the schema instead.
//
// Scope note: this guards the KEY SET only. It does not catch `args` drift — the
// walk assumes every one of these leaves takes exactly one value token (with
// `description` handled as a tail). A future schema leaf declared `args: 2`, or
// an existing one widened, would need applicationDirectLeaves updated to match;
// TestApplicationDirectLeafArityIsOne below pins today's assumption so such a
// change cannot land silently.
func TestApplicationDirectLeafKeywordsMatchSchema(t *testing.T) {
	appNode := schemaApplications.children["application"]
	if appNode == nil || len(appNode.children) == 0 {
		t.Fatalf("schemaApplications has no `application` children to enumerate — " +
			"this canary has lost its authoritative source")
	}
	for kw := range appNode.children {
		if !applicationDirectLeafKeywords[kw] {
			t.Errorf("schema declares `applications application <name> %s` but "+
				"applicationDirectLeafKeywords omits it — the statement would be "+
				"recorded as an unknown leaf and HARD-REJECTED at commit "+
				"(fail-closed on valid config)", kw)
		}
	}
	for kw := range applicationDirectLeafKeywords {
		if _, ok := appNode.children[kw]; !ok {
			t.Errorf("applicationDirectLeafKeywords accepts %q but the schema does "+
				"not declare it — the token would be silently accepted by the walk "+
				"instead of rejected", kw)
		}
	}
}

// TestApplicationTermEnumerationSharedWithCollisionGate pins the #6524 MAJOR
// contract at the seam: compileApplications and collectApplicationCollisions
// must enumerate terms through the SAME walk, or the compiler mints
// `<parent>-<term>` applications the namespace gates cannot see.
func TestApplicationTermEnumerationSharedWithCollisionGate(t *testing.T) {
	// A term reachable ONLY through a flat-set chain (nested under the
	// `description` value node).
	tree := setTree6524(t,
		"set applications application myapp description doc term t1 protocol udp")
	appsNode := tree.FindChild("applications")
	if appsNode == nil {
		t.Fatalf("applications node missing")
	}
	inst := namedInstances(appsNode.FindChildren("application"))
	if len(inst) != 1 {
		t.Fatalf("expected 1 application instance, got %d", len(inst))
	}
	// The enumeration helper the collision gate uses must find the chained term.
	terms := applicationTermNodes(inst[0].node)
	if len(terms) != 1 {
		t.Fatalf("applicationTermNodes found %d terms, want 1 — the collision gate "+
			"would be blind to a chained term the compiler still mints (#6524)",
			len(terms))
	}
	// And it must reassemble the same tokens the compiler feeds
	// parseApplicationTerms, so the predicted name matches what gets written.
	gen := parseApplicationTerms("myapp", applicationTermKeys(terms[0]))
	if len(gen) != 1 || gen[0].Name != "myapp-t1" {
		t.Fatalf("predicted generated apps = %+v, want exactly one named myapp-t1", gen)
	}
}

// TestChainedTermCannotClobberAuthoredApp is the #6524 review-fold MAJOR: once
// the compiler follows the flat-set chain it also reaches `term` nodes nested
// down that chain and mints `<parent>-<term>` applications from them. The
// collision gate (collectApplicationCollisions) enumerated the application
// node's immediate Children, so those generated names were invisible to EVERY
// gate guarding the flat Junos namespace — H01 authored-app overwrite, H02
// cross-namespace, H03 cross-parent, M08 duplicate term name, M03 predefined
// shadow.
//
// The consequence is a silent fail-open: a generated name overwrites an
// AUTHORED application, so a deny referencing that authored name is erased and
// the traffic falls through to a later permit. `description` is the entry route
// on the STRICT path because it deliberately does not set hasDirectBody
// (#3366), so MixedDirectTermApps never engages.
//
// RED-on-revert: point the collision gate's loop back at
// `inst.node.Children` and the commit succeeds with myapp-t1 silently redefined
// as protocol udp / no port.
func TestChainedTermCannotClobberAuthoredApp(t *testing.T) {
	tree := setTree6524(t,
		"set applications application myapp-t1 protocol tcp",
		"set applications application myapp-t1 destination-port 22",
		"set applications application myapp description doc term t1 protocol udp",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected commit to REJECT a chained term whose generated name " +
			"collides with the authored application myapp-t1 — it silently " +
			"overwrites it and erases any deny referencing it (#6524)")
	}
	if !strings.Contains(err.Error(), "myapp-t1") {
		t.Fatalf("reject must name the colliding generated application, got: %v", err)
	}
}

// TestChainedTermClobberIsSurfacedOnLenientPath covers the tolerant load / HA
// SyncApply variant. There MixedDirectTermApps is only a warning, so the
// `description` prefix is not needed at all — a plain `protocol udp term t1 ...`
// chain reaches the same clobber. The lenient path must still SURFACE the
// collision; before the fold its only warning was the unrelated mixed
// direct+term one, which never mentions that an authored application was
// redefined.
func TestChainedTermClobberIsSurfacedOnLenientPath(t *testing.T) {
	cfg, err := CompileConfigLenient(setTree6524(t,
		"set applications application myapp-t1 protocol tcp",
		"set applications application myapp-t1 destination-port 22",
		"set applications application myapp protocol udp term t1 protocol udp",
	))
	if err != nil {
		t.Fatalf("lenient path must not hard-fail: %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "myapp-t1") && strings.Contains(w, "collides") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("lenient path must warn that the generated myapp-t1 collides with "+
			"the authored application, got %v", cfg.Warnings)
	}
}

// TestSiblingTermClobberStillRejected is the GREEN control for the two tests
// above: the one-leaf-per-line term spelling was always caught by the #3472
// gate and must stay caught. It passes on master and on every revision of this
// branch, proving the chained cases above fail for the chain-specific reason
// rather than because the gate is broken generally.
func TestSiblingTermClobberStillRejected(t *testing.T) {
	_, err := CompileConfig(setTree6524(t,
		"set applications application myapp-t1 protocol tcp",
		"set applications application myapp-t1 destination-port 22",
		"set applications application myapp term t1 protocol udp",
	))
	if err == nil {
		t.Fatal("the sibling term spelling must still hard-reject on the #3472 " +
			"authored-name collision")
	}
}

// TestLeafValueSlotReservedAgainstKeywordText covers the review-fold MINOR: a
// leaf declared `args: 1` consumes exactly ONE token as its value even when
// that token happens to spell a grammar keyword. Without the reservation the
// chain scan synthesized a PHANTOM valueless leaf that reset an
// already-assigned field.
//
// The `description destination-port` case is the security-relevant one: the
// phantom drove DestinationPort back to "", which on the tolerant path means
// the application matches EVERY port — the exact widening #6524 exists to
// close, reintroduced by another route. It also produced a FALSE strict reject
// ("conflicting duplicate"), and the phantom's unconditional hasDirectBody
// falsely tripped the #3366 mixed direct+term gate on a term-only application.
func TestLeafValueSlotReservedAgainstKeywordText(t *testing.T) {
	t.Run("description text spelling a match keyword", func(t *testing.T) {
		cfg, err := CompileConfig(setTree6524(t,
			"set applications application myapp protocol tcp destination-port 8080",
			"set applications application myapp description destination-port",
		))
		if err != nil {
			t.Fatalf("CompileConfig: %v (a description whose TEXT is a keyword must "+
				"not synthesize a phantom leaf)", err)
		}
		app := cfg.Applications.Applications["myapp"]
		if app == nil {
			t.Fatalf("application myapp missing")
		}
		if app.DestinationPort != "8080" {
			t.Fatalf("DestinationPort=%q, want 8080 — a phantom `destination-port` "+
				"leaf reset the assigned port, so the application matches EVERY port",
				app.DestinationPort)
		}
		if app.Description != "destination-port" {
			t.Fatalf("Description=%q, want %q", app.Description, "destination-port")
		}
	})

	t.Run("description text spelling protocol", func(t *testing.T) {
		cfg, err := CompileConfig(setTree6524(t,
			"set applications application myapp protocol tcp destination-port 8080",
			"set applications application myapp description protocol",
		))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		app := cfg.Applications.Applications["myapp"]
		if app == nil || app.Protocol != "tcp" {
			t.Fatalf("Protocol=%v, want tcp — a phantom `protocol` leaf wiped it, "+
				"which fails the whole snapshot closed at runtime (#3323)", app)
		}
	})

	t.Run("term-only app with keyword-text description", func(t *testing.T) {
		cfg, err := CompileConfig(setTree6524(t,
			"set applications application myapp term t1 protocol tcp destination-port 80",
			"set applications application myapp description timeout",
		))
		if err != nil {
			t.Fatalf("CompileConfig: %v — the phantom leaf set hasDirectBody and "+
				"falsely tripped the #3366 mixed direct+term gate", err)
		}
		if app := cfg.Applications.Applications["myapp-t1"]; app == nil ||
			app.Protocol != "tcp" || app.DestinationPort != "80" {
			t.Fatalf("term app myapp-t1 = %+v, want tcp/80", app)
		}
	})

	t.Run("bracket tail still caught after the reservation", func(t *testing.T) {
		// The reservation must not blind the bracket-list gate: the SECOND
		// value token is still an unrepresentable tail.
		_, err := CompileConfig(setTree6524(t,
			"set applications application myapp protocol tcp destination-port [ 22 23 ]"))
		if err == nil || !strings.Contains(err.Error(), "23") {
			t.Fatalf("bracket tail must still reject naming 23, got: %v", err)
		}
	})
}

// TestApplicationDirectLeafArityIsOne pins the arity assumption the chain scan
// is built on: every direct-body leaf takes exactly ONE value token, so the walk
// can reserve a single value slot and treat everything after it as either the
// next statement or unrepresentable surplus. `description` is the deliberate
// exception — it is a TAIL leaf whose run is joined — but it is still declared
// args:1 in the schema, so it is included here. If a leaf is ever widened to
// args:2, applicationDirectLeaves must learn to consume that many tokens; this
// pin makes such a schema change fail loudly instead of silently truncating.
func TestApplicationDirectLeafArityIsOne(t *testing.T) {
	appNode := schemaApplications.children["application"]
	if appNode == nil {
		t.Fatalf("schemaApplications has no `application` node")
	}
	for kw, leaf := range appNode.children {
		if leaf.args != 1 {
			t.Errorf("schema leaf %q declares args:%d — applicationDirectLeaves "+
				"reserves exactly ONE value token per leaf and would truncate or "+
				"mis-split this statement", kw, leaf.args)
		}
	}
}

// TestUnknownTokenDoesNotRecoverLaterKeywords is the #6524 review-fold MAJOR-2
// structural half: an unrepresentable token must poison the rest of its run,
// not be skipped so a later keyword can be compiled. See
// pkg/policymatch/app_unknown_recovery_6524_test.go for the VERDICT-level half,
// which is the assertion that actually matters.
func TestUnknownTokenDoesNotRecoverLaterKeywords(t *testing.T) {
	cases := []struct {
		name    string
		set     string
		wantDst string
	}{
		{"unknown statement then protocol",
			"set applications application myapp bogus value protocol tcp", ""},
		{"bracket tail then protocol",
			"set applications application myapp destination-port [ 22 23 ] protocol tcp", "22"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(setTree6524(t, c.set))
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			app := cfg.Applications.Applications["myapp"]
			if app == nil {
				t.Fatalf("application myapp missing")
			}
			if app.Protocol != "" {
				t.Fatalf("Protocol=%q, want \"\" — the token after unrepresentable "+
					"content was RECOVERED, arming a protocol the operator never "+
					"authored. Master left this application protocol-less and "+
					"therefore unrepresentable (fail-closed); recovering it makes "+
					"the tolerant path WIDER than master (#6524)", app.Protocol)
			}
			if app.DestinationPort != c.wantDst {
				t.Fatalf("DestinationPort=%q, want %q", app.DestinationPort, c.wantDst)
			}
		})
	}
}

// TestUnknownTokenDoesNotPoisonSiblingLeaves is the paired over-reach guard:
// poisoning is scoped to the NODE that carries the unparsable token. A stray
// statement on its own `set` line must NOT suppress a neighbouring leaf, which
// master compiled normally.
func TestUnknownTokenDoesNotPoisonSiblingLeaves(t *testing.T) {
	cfg, err := CompileConfigLenient(setTree6524(t,
		"set applications application myapp protocol tcp",
		"set applications application myapp destination-port 8080",
		"set applications application myapp bogus value",
	))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	app := cfg.Applications.Applications["myapp"]
	if app == nil || app.Protocol != "tcp" || app.DestinationPort != "8080" {
		t.Fatalf("app=%+v, want tcp/8080 — a stray SIBLING statement must not "+
			"suppress leaves master compiled normally", app)
	}
}

// TestDescriptionIsATailLeaf covers the review-fold MINOR. Junos takes a
// description's text to the end of the statement, so an unquoted multi-word
// description is legal config that master committed in the chained spelling.
// Treating it as `args: 1` turned it into a hard commit error over a METADATA
// leaf that cannot affect what the application matches.
func TestDescriptionIsATailLeaf(t *testing.T) {
	t.Run("chained multi-word description commits", func(t *testing.T) {
		cfg, err := CompileConfig(setTree6524(t,
			"set applications application myapp protocol tcp description my web app"))
		if err != nil {
			t.Fatalf("CompileConfig: %v — an unquoted multi-word description is "+
				"legal Junos and committed on master in this spelling", err)
		}
		app := cfg.Applications.Applications["myapp"]
		if app == nil || app.Description != "my web app" || app.Protocol != "tcp" {
			t.Fatalf("app=%+v, want protocol tcp and description %q", app, "my web app")
		}
	})

	t.Run("description text spelling a keyword is kept whole", func(t *testing.T) {
		cfg, err := CompileConfig(setTree6524(t,
			"set applications application myapp protocol tcp description destination-port"))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		app := cfg.Applications.Applications["myapp"]
		if app == nil || app.Description != "destination-port" || app.DestinationPort != "" {
			t.Fatalf("app=%+v, want description %q and NO destination-port",
				app, "destination-port")
		}
	})

	t.Run("description does not swallow a following statement", func(t *testing.T) {
		// The run stops at the next recognized keyword, so a chained `term`
		// after a description is still parsed (this is the shape the #6524
		// collision reproducer uses).
		cfg, err := CompileConfig(setTree6524(t,
			"set applications application myapp description doc term t1 protocol udp"))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		term := cfg.Applications.Applications["myapp-t1"]
		if term == nil || term.Protocol != "udp" {
			t.Fatalf("term app myapp-t1 = %+v, want protocol udp — the description "+
				"tail must stop at the next recognized keyword", term)
		}
		if term.Description != "doc" {
			t.Fatalf("term Description=%q, want %q", term.Description, "doc")
		}
	})

	// The tail-join covers exactly ONE of the positions a multi-word description
	// can occupy, and the review-fold comment that justifies it must not claim
	// more than that. When the description HEADS a flat-set chain, SetPath
	// consumes its args:1 value and parks the REST in a CHILD node —
	//
	//	set applications application myapp description my web app protocol tcp
	//	  -> [description my] -> [web app protocol tcp]
	//
	// — so the run this branch joins is just ["my"], and "web" opens a fresh run
	// that the walk records as unknown content. That line therefore stays a
	// commit error.
	//
	// This is PARITY, not a regression, and the assertion pins the mechanism
	// that makes it parity: the schema's own arity gate rejects the same line
	// independently. That gate predates this PR and is untouched by it, so
	// master refused this spelling too — asserting the schema still fires is a
	// durable proof of that, where asserting only "commit fails" would not
	// distinguish a pre-existing gate from one this PR introduced.
	t.Run("head-of-chain multi-word description stays a commit error", func(t *testing.T) {
		tree := setTree6524(t,
			"set applications application myapp description my web app protocol tcp")

		lenient, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient: %v", err)
		}
		schemaErr := SchemaValidate(tree)
		if schemaErr == nil {
			t.Fatalf("SchemaValidate returned nil — the head-of-chain spelling is " +
				"supposed to be caught by the leaf's own untouched arity gate " +
				"(#3332), which is what makes leaving it rejected PARITY with " +
				"master rather than a new refusal. If the shape changed so the " +
				"schema no longer sees it, the tail-join must grow to cover this " +
				"position too, or the line silently becomes a compiler-only reject")
		}
		if !strings.Contains(schemaErr.Error(), "web") {
			t.Fatalf("SchemaValidate error %q does not name the trailing token", schemaErr)
		}

		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("CompileConfig accepted the head-of-chain spelling; master " +
				"rejected it via SchemaValidate, and the compiler records the " +
				"tail as unknown direct content")
		}

		// Fail-closed on the tolerant path for the same reason master was: the
		// trailing `protocol tcp` sits behind unrepresentable content, so it is
		// poisoned rather than recovered and the application stays protocol-less.
		app := lenient.Applications.Applications["myapp"]
		if app == nil {
			t.Fatalf("application myapp missing")
		}
		if app.Protocol != "" {
			t.Fatalf("Protocol=%q, want \"\" — the `protocol tcp` after the "+
				"description tail must be POISONED, not recovered (#6524 MAJOR)",
				app.Protocol)
		}
		if len(app.UnknownDirectLeaves) == 0 {
			t.Fatalf("UnknownDirectLeaves empty, want the trailing description word " +
				"recorded so the deferred gate rejects/warns")
		}
	})
}
