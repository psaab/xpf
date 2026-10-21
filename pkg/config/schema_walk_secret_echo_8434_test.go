package config

import (
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
			err := SchemaValidate(tree, nil)
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
			err := SchemaValidate(tree, nil)
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
			err := SchemaValidate(parseHier(t, text), nil)
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
			if err := SchemaValidate(tree, nil); err != nil {
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
			err := SchemaValidate(tree, nil)
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
	err := SchemaValidate(parseHier(t, text), nil)
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
	err := SchemaValidate(parseHier(t, text), nil)
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
	err := SchemaValidate(tree, nil)
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

// #16066 fold 4 (F3): a secret literal colliding with an unknown
// closed-world child keyword. The unknown-zone wrapper rebuilds its
// message from path+keyword; if keyword is left unscrubbed, Error()
// re-prints the secret after the message scrub removed it.
func TestUnknownZoneKeywordCollisionNeverEchoed16066(t *testing.T) {
	const collide = "collidekw16066"
	text := "system { services { dynamic-dns { provider p { password " + collide + "; } } } }\n" +
		"security { zones { security-zone trust { " + collide + "; } } }"
	err := SchemaValidate(parseHier(t, text), nil)
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
