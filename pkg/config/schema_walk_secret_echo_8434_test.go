package config

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// #8434: a typed-leaf validation error must never render the VALUE of a leaf
// the secret registry claims.
//
// The leak was in `typedLeafInvalidErrorf`, which quoted the offending token,
// AND in the validator's own message (schema_validators.go's
// "invalid value %q (expected one of: ...)"), so the canary appeared TWICE in
// one error. Redacting only the wrapper leaves the leak.
//
// This is keyed on the REGISTRY, not on a list of leaves: `secretLeafKeywords`
// already claimed `encrypted-password` while this path rendered it anyway.

const secretCanary8434 = "PLAINTEXTCANARY123"

// The canary must not appear in a commit error for a leaf the registry claims.
// RED before #8434 with TWO occurrences.
func TestSecretLeafValueNeverEchoedInCommitError8434(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  string
	}{
		{
			name: "login user encrypted-password",
			cfg: `system {
    login {
        user alice {
            authentication {
                encrypted-password "` + secretCanary8434 + `";
            }
        }
    }
}`,
		},
		{
			name: "root-authentication encrypted-password",
			cfg: `system {
    root-authentication {
        encrypted-password "` + secretCanary8434 + `";
    }
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier(t, tc.cfg)
			// SchemaValidate, NOT CompileConfig. The typed-leaf validators —
			// including ValidateCryptHash, which is what rejects this value —
			// run here; CompileConfig is a layer BELOW and returns nil for
			// this input. An earlier draft of this cell used CompileConfig,
			// got no error, and SKIPPED every subtest while the parent
			// reported PASS. That is the same layer confusion this finding's
			// source review made throughout, reproduced inside the test for
			// it.
			err := SchemaValidate(tree)
			if err == nil {
				t.Fatal("fixture must produce a validation error, or this cell " +
					"proves nothing — a value the validator ACCEPTS never reaches " +
					"the error renderer under test")
			}
			if n := strings.Count(err.Error(), secretCanary8434); n != 0 {
				t.Errorf("the commit error echoed the credential %d time(s); a leaf in "+
					"secretLeafKeywords must never have its value rendered (#8434).\n"+
					"got: %v", n, err)
			}
		})
	}
}

// #16066 fold (Codex on #16090): the ADDITIONAL-token arm. When the first
// encrypted-password value is a VALID hash, validateTypedLeaf accepts it
// and then formats any extra token via typedLeafErrorf("unknown modifier
// %q") — which (pre-fold) quoted a plaintext pasted as that extra token
// straight into the schema error that tolerant ingress logs. The token
// must never appear; the "unknown modifier" defect class must survive.
// RED pre-fold with the canary quoted in the error.
func TestSecretLeafExtraTokenNeverEchoed16066(t *testing.T) {
	const validHash = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	for _, tc := range []struct {
		name string
		cfg  string
	}{
		{
			name: "login user encrypted-password extra token",
			cfg: `system {
    login {
        user alice {
            authentication {
                encrypted-password "` + validHash + `" "` + secretCanary8434 + `";
            }
        }
    }
}`,
		},
		{
			name: "root-authentication encrypted-password extra token",
			cfg: `system {
    root-authentication {
        encrypted-password "` + validHash + `" "` + secretCanary8434 + `";
    }
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier(t, tc.cfg)
			err := SchemaValidate(tree)
			if err == nil {
				t.Fatal("fixture must produce a validation error (extra token), " +
					"or this cell proves nothing")
			}
			if strings.Contains(err.Error(), secretCanary8434) {
				t.Errorf("the commit error echoed the additional credential token "+
					"of a secret leaf (#16066): %v", err)
			}
			if !strings.Contains(err.Error(), "unknown modifier") {
				t.Errorf("the error lost its defect-class diagnostic: %v", err)
			}
		})
	}
	// Positive control: typedLeafErrorf on a NON-secret leaf still quotes
	// its token, so the redaction stays registry-scoped (not blanket).
	ctrl := typedLeafErrorf([]string{"system", "host-name"}, "unknown modifier %q", "bogusmod")
	if !strings.Contains(ctrl.Error(), `"bogusmod"`) {
		t.Errorf("non-secret leaf must keep its quoted modifier diagnostic; got: %v", ctrl)
	}
}

// #16066 fold 2 witness: the #8437 fused-statement formatter under the
// UNTYPED dynamic-dns provider leaves `password` and `tsig-secret`.
// A missing semicolon fuses `backend` onto the secret leaf's node; the
// formatter quoted that extra token twice. Through the shared choke
// point the token must appear NOWHERE in the returned error (the exit
// scrub sees the whole tree), the sibling/fused defect class must
// survive, and the non-secret `server` control on the same formatter
// must keep quoting it. Both braced and flat spellings are covered.
// RED pre-fold with "backend" quoted in both secret cells.
func TestSecretLeafFusedTokenNeverEchoed16066(t *testing.T) {
	for _, leaf := range []string{"password", "tsig-secret", "server"} {
		t.Run(leaf+"/braced", func(t *testing.T) {
			text := "system { services { dynamic-dns { provider p { " +
				leaf + " firstvalue backend; } } } }"
			err := SchemaValidate(parseHier(t, text))
			if err == nil || !strings.Contains(err.Error(), "names a SIBLING") {
				t.Fatalf("fixture did not reach the #8437 formatter: %v", err)
			}
			assertFusedTokenDisposition16066(t, leaf, err)
		})
		t.Run(leaf+"/flat-valid", func(t *testing.T) {
			tree := &ConfigTree{}
			cmd := "set system services dynamic-dns provider p " + leaf + " firstvalue"
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
			if err := SchemaValidate(tree); err != nil {
				t.Fatalf("flat valid %s leaf must validate clean: %v", leaf, err)
			}
		})
	}
}

func assertFusedTokenDisposition16066(t *testing.T, leaf string, err error) {
	t.Helper()
	quoted := strings.Contains(err.Error(), `"backend"`) || strings.Contains(err.Error(), " backend")
	if leaf == "server" {
		if !strings.Contains(err.Error(), `"backend"`) {
			t.Errorf("non-secret control lost its quoted keyword diagnostic: %v", err)
		}
		return
	}
	if quoted || strings.Contains(err.Error(), "backend") {
		t.Errorf("registered secret leaf %q echoed its extra operand in the schema error (#16066): %v", leaf, err)
	}
	if !strings.Contains(err.Error(), "names a SIBLING") {
		t.Errorf("error lost its fused-statement defect class: %v", err)
	}
}

// POSITIVE CONTROL on the instrument: a NON-secret leaf must still quote its
// value. Without this, a change that redacted every validation error would pass
// the cell above while destroying every ordinary diagnostic.
//

// #16066 fold 3 (F1): Go-escaped %q operands. An extra token after a
// valid encrypted-password hash is rendered by typedLeafErrorf with
// %q, which escapes quotes/backslashes/newlines — the raw token no
// longer occurs verbatim, so a raw-only scrub misses it. Each token
// below carries a distinctive fragment; neither the raw fragment nor
// its strconv.Quote rendering may survive in the SchemaValidate
// error. The non-secret control (same formatter, host-name leaf via
// typedLeafErrorf directly) must still quote its escaped token.
func TestSecretLeafEscapedExtraTokenNeverEchoed16066(t *testing.T) {
	const validHash = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	cases := []struct {
		name  string
		token string
		frag  string
	}{
		{"quote", `pa"ss16066`, `pa"ss16066`},
		{"backslash", `pa\ss16066`, `pa\ss16066`},
		{"newline", "pa\nss16066", "pa\nss16066"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Build the AST directly: the config lexer cannot author a
			// bare quote/backslash/newline token without escapes, and
			// testing the lexer is not the point — the formatter's %q
			// rendering of an arbitrary token value is. Keys mirror the
			// hierarchical parse of `encrypted-password "<hash>" <tok>;`.
			tree := &ConfigTree{Children: []*Node{{
				Keys: []string{"system"},
				Children: []*Node{{
					Keys: []string{"root-authentication"},
					Children: []*Node{{
						Keys: []string{"encrypted-password", validHash, tc.token},
					}},
				}},
			}}}
			err := SchemaValidate(tree)
			if err == nil {
				t.Fatal("fixture must produce a validation error (extra token)")
			}
			msg := err.Error()
			if strings.Contains(msg, tc.frag) {
				t.Errorf("error leaked the raw secret fragment %q: %v (#16066 fold 3)", tc.frag, err)
			}
			// The %q (strconv.Quote) rendering of the secret must not
			// survive: after scrub it may only appear as "<redacted>".
			if q := strconv.Quote(tc.token); strings.Contains(msg, q) {
				t.Errorf("error leaked the quoted secret form %s: %v (#16066 fold 3)", q, err)
			}
			if q := strconv.Quote(tc.frag); q != strconv.Quote(SecretRedacted) && strings.Contains(msg, q) && tc.frag != tc.token {
				t.Errorf("error leaked the quoted secret fragment %s: %v (#16066 fold 3)", q, err)
			}
			if !strings.Contains(msg, "unknown modifier") {
				t.Errorf("error lost its defect-class diagnostic: %v", err)
			}
		})
	}
	// Non-secret control: typedLeafErrorf on host-name still quotes.
	ctrl := typedLeafErrorf([]string{"system", "host-name"}, "unknown modifier %q", `pa"ss`)
	if !strings.Contains(ctrl.Error(), strconv.Quote(`pa"ss`)) {
		t.Errorf("non-secret control must keep its quoted escaped token; got: %v", ctrl)
	}
}

// #16066 fold 3 (F2): the pre-walk redaction-placeholder guard. A
// secret leaf carrying an ordinary canary operand BEFORE the
// ##SECRET-DATA## placeholder made findRedactionPlaceholder embed
// the canary in its returned path, and checkRedactionPlaceholder
// quoted it — returned before the exit scrub. The error must still
// classify as IsRedactionPlaceholderIngestError but omit the canary.
func TestPlaceholderGuardNeverEchoesPrecedingSecret16066(t *testing.T) {
	const canary = "CANARYPRE16066"
	text := "system { services { dynamic-dns { provider p { password \"" + canary + "\" \"##SECRET-DATA##\"; } } } }"
	err := SchemaValidate(parseHier(t, text))
	if err == nil {
		t.Fatal("placeholder fixture must be rejected")
	}
	if !IsRedactionPlaceholderIngestError(err) {
		t.Fatalf("error lost its placeholder classification: %v", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Errorf("placeholder error echoed the preceding secret operand: %v (#16066 fold 3)", err)
	}
}

// #16066 fold 4 (F1): a secret containing escapable characters inside a
// %q-quoted WHOLE path. The placeholder guard quotes the entire
// space-joined flattened path, so the preceding password token is
// escaped IN PLACE — neither its raw form nor strconv.Quote(token)
// (surrounding quotes) occurs. The final-string scrub must catch the
// quoted-interior form. Authored through the real parser, whose lexer
// admits \" and \\ inside quoted strings.
func TestPlaceholderGuardEscapedSecretNeverEchoed16066(t *testing.T) {
	// Config text: password "pa\"ss\\CANARY4" "##SECRET-DATA##"
	// Lexer decodes to token: pa"ss\CANARY4
	text := `system { services { dynamic-dns { provider p { password "pa\"ss\\CANARY4" "##SECRET-DATA##"; } } } }`
	err := SchemaValidate(parseHier(t, text))
	if err == nil {
		t.Fatal("placeholder fixture must be rejected")
	}
	if !IsRedactionPlaceholderIngestError(err) {
		t.Fatalf("error lost its placeholder classification: %v", err)
	}
	msg := err.Error()
	for _, frag := range []string{"CANARY4", `pa"ss`, `pa\"ss`, `ss\\CANARY4`, `ss\CANARY4`} {
		if strings.Contains(msg, frag) {
			t.Errorf("placeholder error leaked secret fragment %q: %v (#16066 fold 4 F1)", frag, err)
		}
	}
}

// #16066 fold 4 (F2): a secret operand inside a quoted
// change-configuration commands payload. The outer AST sees one
// payload token; the exit scrub must lex it (as the ingest guard
// does) and remove the inner credential from the quoted outer path
// the guard reports.
func TestEmbeddedPlaceholderNeverEchoesInnerSecret16066(t *testing.T) {
	const psk = "REALPSK16066"
	// Build the reviewer's shape from RedactedClone's own output:
	// the clone masks every token after `pre-shared-key`, emitting
	// the nested-quote spelling the guard detects. Re-author that
	// spelling with [REAL, placeholder] as the two secret values:
	// both are secret-indexed after `pre-shared-key` (no qualifier),
	// so the guard fires on the placeholder and quotes the outer
	// path embedding the real secret.
	clear := embeddedIngest15209FlatTree(t,
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 then change-configuration commands "set security ike policy p1 pre-shared-key `+psk+` tailtoken"`,
	)
	cloneText := clear.RedactedClone().FormatSet()
	if !strings.Contains(cloneText, SecretDataPlaceholder) {
		t.Fatalf("premise: clone did not mask the embedded secret:\n%s", cloneText)
	}
	tree := &ConfigTree{}
	for _, line := range strings.Split(cloneText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Clone emits ... pre-shared-key \"##SECRET-DATA##\" (one
		// masked value for the two-token secret). Put the real
		// secret back as a second value token before it.
		line = strings.Replace(line, `\"##SECRET-DATA##\"`, `\"`+psk+` ##SECRET-DATA##\"`, 1)
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	if err := checkRedactionPlaceholder(tree); err == nil {
		t.Fatalf("premise: authored multi-token shape does not fire the guard:\n%s", tree.FormatSet())
	}
	err := SchemaValidate(tree)
	if err == nil {
		t.Fatal("embedded placeholder fixture must be rejected")
	}
	if !IsRedactionPlaceholderIngestError(err) {
		t.Fatalf("error lost its placeholder classification: %v", err)
	}
	if strings.Contains(err.Error(), psk) {
		t.Errorf("schema error echoed the inner embedded secret: %v (#16066 fold 4 F2)", err)
	}
}

// #16090 fold 5 (reviewer witness 1): twice-escaped embedded PSK.
// The payload reaches the guard TWICE-escaped (its inner tokens were
// strconv.Quote'd, then the whole command Quote'd again). String
// scrubbing cannot win this race — the guard must never embed the
// payload in the first place (names-only location). Post-fix the
// SchemaValidate error contains neither CANARY nor the payload.
func TestEmbeddedTwiceEscapedSecretNeverEchoed16090(t *testing.T) {
	const secret = `pa"ssCANARY16090`
	inner := `set security ike policy p1 pre-shared-key ` + strconv.Quote(secret) + ` ` + strconv.Quote(SecretDataPlaceholder)
	outer := `set event-options policy p1 then change-configuration commands ` + strconv.Quote(inner)
	tree := embeddedIngest15209FlatTree(t,
		`set event-options policy p1 events ping_test_failed`, outer)
	if guard := checkRedactionPlaceholder(tree); guard == nil || !IsRedactionPlaceholderIngestError(guard) {
		t.Fatalf("premise: placeholder guard must reject the embedded command: %v", guard)
	}
	err := SchemaValidate(tree)
	if err == nil || !IsRedactionPlaceholderIngestError(err) {
		t.Fatalf("schema gate lost placeholder classification: %v", err)
	}
	if strings.Contains(err.Error(), "CANARY16090") {
		t.Errorf("twice-escaped inner credential survived: %v (#16090 fold 5)", err)
	}
}

// #16090 fold 5 (reviewer witness 2): the literal word `password` as
// the plaintext value of encrypted-password. `password` is public
// vocabulary (a leaf keyword), so the belt must NOT substitute it —
// the diagnostic must stay readable: leaf name and defect class
// intact, typed-leaf classification intact.
func TestCommonWordSecretKeepsPublicDiagnostics16090(t *testing.T) {
	text := `system { root-authentication { encrypted-password password; } }`
	err := SchemaValidate(parseHier(t, text))
	if err == nil {
		t.Fatal("fixture: plaintext must be rejected")
	}
	if !IsTypedLeafSchemaError(err) {
		t.Fatalf("lost typed-leaf classification: %v", err)
	}
	got := err.Error()
	if !strings.Contains(got, "encrypted-password") {
		t.Errorf("public leaf keyword lost (common-word belt mangling): %s (#16090 fold 5)", got)
	}
	// Fixed HEAD of the defect class survives verbatim; the tail
	// after the operand-coinciding word (`password` inside the
	// validator's own sentence, when the secret IS that word) is
	// dropped by design — that drop is the fold-6 no-embed
	// guarantee, not mangling.
	if !strings.Contains(got, "not an encrypted") {
		t.Errorf("public crypt-hash defect class lost: %s (#16090 fold 5)", got)
	}
}

// #16090 fold 5 (reviewer witness 3): an unrelated public zone path
// must survive when a secret value coincides with one of its words.
// password value `security` must not mangle the `security zones`
// path in the unknown-zone error (classification + path intact).
func TestCoincidentSecretDoesNotManglePublicPath16090(t *testing.T) {
	text := `system { services { dynamic-dns { provider p { password security; } } } } ` +
		`security { zones { security-zone trust { bogus; } } }`
	err := SchemaValidate(parseHier(t, text))
	if err == nil || !IsUnknownSecurityZoneChildSchemaError(err) {
		t.Fatalf("fixture not on unknown-zone branch: %v", err)
	}
	if !strings.Contains(err.Error(), "security zones security-zone trust") {
		t.Errorf("unrelated public path mangled by coincident secret: %v (#16090 fold 5)", err)
	}
}

// #16090 fold 6: SHORT and VOCABULARY extra tokens after a valid hash.
// The belt filters len<4 and vocabulary values, and the construction
// scrub sees no secret in the leaf path alone (the token is not in
// it) — so these survived unchanged. At construction, operands ON a
// known secret leaf are now dropped unconditionally. Witnesses:
// extra tokens `abc` (short) and `password` (vocabulary) must never
// appear as the quoted modifier operand; defect class survives.
// Non-secret control still quotes its token.
func TestSecretLeafShortVocabExtraTokensNeverEchoed16090(t *testing.T) {
	const validHash = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	for _, tok := range []string{"abc", "password"} {
		t.Run(tok, func(t *testing.T) {
			tree := &ConfigTree{Children: []*Node{{
				Keys: []string{"system"},
				Children: []*Node{{
					Keys: []string{"root-authentication"},
					Children: []*Node{{
						Keys: []string{"encrypted-password", validHash, tok},
					}},
				}},
			}}}
			err := SchemaValidate(tree)
			if err == nil {
				t.Fatal("extra-token fixture must be rejected")
			}
			msg := err.Error()
			if strings.Contains(msg, strconv.Quote(tok)) {
				t.Errorf("extra token %q appeared as quoted operand: %v (#16090 fold 6)", tok, err)
			}
			if tok == "abc" && strings.Contains(msg, "abc") {
				t.Errorf("short extra token appeared anywhere: %v (#16090 fold 6)", err)
			}
			if !strings.Contains(msg, "unknown modifier") {
				t.Errorf("defect class lost: %v", err)
			}
			if !strings.Contains(msg, "<redacted>") {
				t.Errorf("expected redacted operand placeholder: %v", err)
			}
		})
	}
	// Non-secret control: same formatter on host-name still quotes.
	ctrl := typedLeafErrorf([]string{"system", "host-name"}, "unknown modifier %q", "abc")
	if !strings.Contains(ctrl.Error(), `"abc"`) {
		t.Errorf("non-secret control must still quote its token; got: %v", ctrl)
	}
	ctrl2 := typedLeafErrorf([]string{"system", "host-name"}, "unknown modifier %q", "password")
	if !strings.Contains(ctrl2.Error(), `"password"`) {
		t.Errorf("non-secret control must still quote vocabulary token; got: %v", ctrl2)
	}
}

// #16090 fold 6 statics (1): vocabulary derives from the schema
// registry. `encrypted-password plaintext` — the validator's fixed
// sentence "plaintext is not allowed" and the leaf/stanza names
// must survive; only the operand is redacted. A hand vocabulary
// list omitted these words and ate them.
func TestVocabularyWordsSurviveDiagnostics16090(t *testing.T) {
	text := `system { root-authentication { encrypted-password plaintext; } }`
	err := SchemaValidate(parseHier(t, text))
	if err == nil {
		t.Fatal("plaintext fixture must be rejected")
	}
	got := err.Error()
	for _, want := range []string{"root-authentication", "encrypted-password", "not an encrypted password hash"} {
		if !strings.Contains(got, want) {
			t.Errorf("vocabulary word %q lost from diagnostic: %s (#16090 fold 6)", want, got)
		}
	}
	if !IsTypedLeafSchemaError(err) {
		t.Errorf("typed classification lost: %v", err)
	}
}

// #16090 fold 6 statics (2): whole-error-equals-secret must keep
// its classification. A placeholder error whose entire text would
// be neutralized still classifies as the placeholder sentinel
// after the scrub — the whole-eq shortcut must not return a bare
// error before the wrapper arms.
func TestWholeEqSecretKeepsClassification16090(t *testing.T) {
	const canary = "CLASSCANARY16090"
	tree := &ConfigTree{Children: []*Node{{Keys: []string{"system", "services", "dynamic-dns", "provider", "p", "password", canary}}}}
	got := scrubSchemaErrorSecrets(tree, &typedLeafSchemaError{msg: canary})
	if !IsTypedLeafSchemaError(got) {
		t.Errorf("whole-eq typed error lost classification: %T %v", got, got)
	}
	if strings.Contains(got.Error(), canary) {
		t.Errorf("whole-eq secret retained: %v", got)
	}
	got2 := scrubSchemaErrorSecrets(tree, fmt.Errorf("%w (at %q)", errRedactionPlaceholderIngest, "x "+canary))
	if !IsRedactionPlaceholderIngestError(got2) {
		t.Errorf("placeholder classification lost: %T %v", got2, got2)
	}
	if strings.Contains(got2.Error(), canary) {
		t.Errorf("placeholder canary retained: %v", got2)
	}
}

// GLM F3 witness: beltSecretValues must not alias its input.
func TestBeltDoesNotAliasInput16090(t *testing.T) {
	in := []string{"password", "highentropyvalue1", "abc", "anotherSecret99"}
	before := append([]string(nil), in...)
	_ = beltSecretValues(in)
	for i := range before {
		if in[i] != before[i] {
			t.Fatalf("belt aliased input: in=%v before=%v (GLM F3)", in, before)
		}
	}
}

// GLM B1/F1 witness (reshaped fold 7): the keyword is INNOCENT
// (`bogus`); the secret spans path-suffix + fixed template head
// (`security-zone trust: unknown`). Fold-6's witness put the canary
// in keyword — a shape fold-5 already neutralized, hence
// test-only-green. This shape is RED without the fold-7 render
// carry (final render contains the span verbatim).
func TestRebuiltWrapperRescrubbedOnRender16090(t *testing.T) {
	const secret = "security-zone trust: unknown"
	text := `system { services { dynamic-dns { provider p { password "` + secret + `"; } } } } ` +
		`security { zones { security-zone trust { bogus; } } }`
	err := SchemaValidate(parseHier(t, text))
	if err == nil || !IsUnknownSecurityZoneChildSchemaError(err) {
		t.Fatalf("fixture not on unknown-zone branch: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("zone wrapper reassembled path+template span secret: %v (GLM B1)", err)
	}
	// Policies arm, same span class (GLM probe P1 shape, direct).
	const secret2 = "untrust policy: child"
	tree := &ConfigTree{Children: []*Node{
		{Keys: []string{"system", "services", "dynamic-dns", "provider", "p", "password", secret2}},
	}}
	got := scrubSchemaErrorSecrets(tree, &unknownSecurityPoliciesChildSchemaError12217{
		path: "security policies from-zone trust to-zone untrust policy", keyword: "bogus", content: "x"})
	if !IsUnknownSecurityPoliciesChildSchemaError12217(got) {
		t.Fatalf("policies classification lost: %T %v", got, got)
	}
	if strings.Contains(got.Error(), secret2) {
		t.Errorf("policies wrapper reassembled span secret: %v (GLM B1/P1)", got)
	}
	// Fused-statement location (GLM F2): the #8437 error on a secret
	// leaf keeps its stanza location while the operand stays absent.
	ferr := SchemaValidate(parseHier(t, "system { services { dynamic-dns { provider p { password firstvalue backend; } } } }"))
	if ferr == nil {
		t.Fatal("fused fixture must be rejected")
	}
	for _, want := range []string{"dynamic-dns", "provider", "names a SIBLING"} {
		if !strings.Contains(ferr.Error(), want) {
			t.Errorf("fused diagnostic lost %q: %v (GLM F2)", want, ferr)
		}
	}
	if strings.Contains(ferr.Error(), "backend") {
		t.Errorf("fused diagnostic still echoes operand: %v", ferr)
	}
}

// #16066 fold 4 (F3): a secret literal colliding with an unknown
// closed-world child keyword. The unknown-zone wrapper rebuilds its
// message from path+keyword; if keyword is left unscrubbed, Error()
// re-prints the secret after the message scrub removed it.
func TestUnknownZoneKeywordCollisionNeverEchoed16066(t *testing.T) {
	const collide = "collidekw16066"
	text := "system { services { dynamic-dns { provider p { password " + collide + "; } } } }\n" +
		"security { zones { security-zone trust { " + collide + "; } } }"
	err := SchemaValidate(parseHier(t, text))
	if err == nil {
		t.Fatal("unknown zone child fixture must be rejected")
	}
	if !IsUnknownSecurityZoneChildSchemaError(err) {
		t.Fatalf("error lost its unknown-zone-child classification: %v", err)
	}
	if strings.Contains(err.Error(), collide) {
		t.Errorf("rebuilt unknown-zone error re-printed the colliding secret: %v (#16066 fold 4 F3)", err)
	}
}

// Asserted DIRECTLY on typedLeafInvalidErrorf rather than through a config
// fixture. The first draft used `system host-name "bad name with spaces"`,
// which compiles cleanly — so the cell SKIPPED, and a skipped control has no
// power at all. Driving the function directly cannot skip and cannot drift onto
// a different error path: `interfaces ... unit foo` also fails validation, but
// through a different message builder, so it would have exercised nothing here.
func TestNonSecretLeafStillQuotesItsValue8434(t *testing.T) {
	err := typedLeafInvalidErrorf(
		[]string{"system", "host-name"}, "bad name", errTyped8434{})
	got := err.Error()
	if strings.Contains(got, "<redacted>") {
		t.Errorf("a non-secret leaf must keep its value in the error — redaction is "+
			"scoped to the secret registry, not applied to every typed leaf (#8434).\n"+
			"got: %v", got)
	}
	if !strings.Contains(got, "bad name") {
		t.Errorf("a non-secret leaf's value must still be quoted so the operator can "+
			"see what was rejected; got: %v", got)
	}
	if !strings.Contains(got, "the reason") {
		t.Errorf("the validator's own message must survive for a non-secret leaf; "+
			"got: %v", got)
	}
}

// errTyped8434 stands in for a validator's own error so the control can assert
// the reason survives, without depending on which validator a real fixture hits.
type errTyped8434 struct{}

func (errTyped8434) Error() string { return "the reason" }

// The registry is the enumeration, and this cell says so: every keyword the
// registry claims must be redacted by the SAME code path.
//
// It binds the AGREEMENT between the registry and the error renderer rather
// than naming leaves. A cell pinning `encrypted-password` leaves the next typed
// secret leaf to reintroduce the leak — which is exactly how this one arrived
// while `pre-shared-key` was already correct.
func TestEverySecretKeywordIsRedactedByTheSamePath8434(t *testing.T) {
	if !IsSecretLeafKeyword("encrypted-password") {
		t.Fatal("premise: the registry must claim encrypted-password, or this cell " +
			"and #8434 are about different things")
	}
	if IsSecretLeafKeyword("host-name") {
		t.Fatal("negative control: host-name must NOT be claimed, or the registry " +
			"predicate cannot discriminate and the cell above passes vacuously")
	}
	for _, kw := range []string{"encrypted-password", "pre-shared-key", "password"} {
		if !IsSecretLeafKeyword(kw) {
			t.Errorf("registry no longer claims %q — if it was deliberately removed, "+
				"this cell and the redaction it guards need re-scoping together", kw)
			continue
		}
		err := typedLeafInvalidErrorf([]string{"system", kw}, secretCanary8434, nil)
		if strings.Contains(err.Error(), secretCanary8434) {
			t.Errorf("typedLeafInvalidErrorf echoed the value for registry keyword %q "+
				"(#8434): %v", kw, err)
		}
	}
}
