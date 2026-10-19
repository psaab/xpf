package config

import (
	"errors"
	"strings"
	"testing"
)

// #15209 (A20-03): the #4060 placeholder ingest guard
// (checkRedactionPlaceholder / findRedactionPlaceholder / findRedactedURL)
// inspected only direct secret/URL leaf tokens. It never lexed embedded
// `event-options … then change-configuration commands` payloads, even though
// #14413 taught RedactedClone to mask credentials inside those commands.
// A redacted export therefore re-committed cleanly: the event policy carried
// `set … pre-shared-key ascii-text "##SECRET-DATA##"` (or a redacted URL)
// verbatim, and the embedded change failed only when the event fired.
//
// The decisive v9 re-ingest cells below build the redacted render exactly as
// an operator would re-apply it (RedactedClone -> FormatSet -> ParseSetCommand
// + SetPath, plus the hierarchical and block shapes), and require the guard —
// and the production commit-ingest schema gate — to refuse it. The cleartext
// original must ingest cleanly and the compiled ThenCommands must stay raw,
// so the fix cannot be satisfied by refusing event policies wholesale.

func embeddedIngest15209FlatTree(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, line := range lines {
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree
}

func embeddedIngest15209HierTree(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	return tree
}

// TestEmbeddedRedactedPlaceholderIngestRefused15209 is the decisive
// regression: every RedactedClone shape of an embedded credential command,
// re-ingested, must be refused by checkRedactionPlaceholder with the secret
// placeholder sentinel, and the flat quoted shape must also be refused by
// SchemaValidate (the production commit-ingest gate).
func TestEmbeddedRedactedPlaceholderIngestRefused15209(t *testing.T) {
	const psk = "PSK-EMBEDDED-15209"
	clearLines := []string{
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 then change-configuration commands "set security ike policy p1 pre-shared-key ascii-text ` + psk + `"`,
		`set event-options policy p1 then change-configuration commands "set system host-name foo"`,
		`set event-options policy p1 then change-configuration commands "set system login user bob class operator"`,
	}
	cleartext := embeddedIngest15209FlatTree(t, clearLines...)

	// Premise: RedactedClone masks the embedded PSK (the #14413 display fix),
	// so the export an operator re-applies really carries the placeholder
	// inside the quoted command.
	redactedSet := cleartext.RedactedClone().FormatSet()
	if !strings.Contains(redactedSet, SecretDataPlaceholder) {
		t.Fatalf("redacted export did not contain the placeholder; test precondition broken:\n%s", redactedSet)
	}
	if strings.Contains(redactedSet, psk) {
		t.Fatalf("redacted export leaked the embedded PSK; test precondition broken:\n%s", redactedSet)
	}

	reingested := &ConfigTree{}
	for _, line := range strings.Split(redactedSet, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		toks, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := reingested.SetPath(toks); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}

	if err := checkRedactionPlaceholder(reingested); err == nil {
		t.Fatalf("checkRedactionPlaceholder accepted a redacted embedded command; want rejection:\n%s", reingested.FormatSet())
	} else if !errors.Is(err, errRedactionPlaceholderIngest) {
		t.Fatalf("checkRedactionPlaceholder err = %v, want errRedactionPlaceholderIngest", err)
	}
	if err := SchemaValidate(reingested, nil); err == nil {
		t.Fatal("SchemaValidate accepted a redacted embedded command; want rejection")
	} else if !errors.Is(err, errRedactionPlaceholderIngest) {
		t.Fatalf("SchemaValidate err = %v, want errRedactionPlaceholderIngest", err)
	}

	// Hierarchical quoted, flat-set unquoted, commands-block and bracket
	// shapes: every shape RedactedClone masks must be refused on ingest.
	hierQuoted := embeddedIngest15209HierTree(t, `
event-options {
    policy p1 {
        events ping_test_failed;
        then {
            change-configuration {
                commands "set security ike policy p1 pre-shared-key ascii-text `+SecretDataPlaceholder+`";
            }
        }
    }
}
`)
	// The hierarchical fixture above carries the placeholder literally — but
	// build it through RedactedClone so the shape is proven to be one the
	// display path produces, not a hand-invented spelling.
	hierClear := embeddedIngest15209HierTree(t, `
event-options {
    policy p1 {
        events ping_test_failed;
        then {
            change-configuration {
                commands "set security ike policy p1 pre-shared-key ascii-text `+psk+`";
            }
        }
    }
}
`)
	hierRedacted := hierClear.RedactedClone()
	if !strings.Contains(hierRedacted.FormatSet(), SecretDataPlaceholder) {
		t.Fatalf("hierarchical RedactedClone did not mask embedded PSK:\n%s", hierRedacted.FormatSet())
	}
	_ = hierQuoted

	blockClear := embeddedIngest15209HierTree(t, `
event-options {
    policy p1 {
        events ping_test_failed;
        then {
            change-configuration {
                commands {
                    "set security ike policy p1 pre-shared-key ascii-text `+psk+`";
                    "set system host-name foo";
                }
                commands [ "set security ike policy p1 pre-shared-key ascii-text `+psk+`" "set system host-name foo" ];
            }
        }
    }
}
`)

	unquoted := embeddedIngest15209FlatTree(t,
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 then change-configuration commands set security ike policy p1 pre-shared-key ascii-text `+psk,
	)

	for name, tree := range map[string]*ConfigTree{
		"hierarchical quoted (redacted clone)":      hierRedacted,
		"commands block + bracket (redacted clone)": blockClear.RedactedClone(),
		"flat-set unquoted (redacted clone)":        unquoted.RedactedClone(),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(tree.FormatSet(), SecretDataPlaceholder) {
				t.Fatalf("redacted clone did not contain placeholder:\n%s", tree.FormatSet())
			}
			err := checkRedactionPlaceholder(tree)
			if err == nil {
				t.Fatalf("guard accepted redacted embedded command (%s):\n%s", name, tree.FormatSet())
			}
			if !errors.Is(err, errRedactionPlaceholderIngest) {
				t.Fatalf("err = %v, want errRedactionPlaceholderIngest", err)
			}
		})
	}

	// Control: the cleartext original ingests cleanly through both gates.
	if err := checkRedactionPlaceholder(cleartext); err != nil {
		t.Fatalf("guard rejected a cleartext embedded credential command: %v", err)
	}
	if err := SchemaValidate(cleartext, nil); err != nil {
		t.Fatalf("SchemaValidate rejected a cleartext embedded credential command: %v", err)
	}
}

// TestEmbeddedRedactedURLIngestRefused15209 pins the URL sibling: an embedded
// command whose URL leaf RedactURL rewrote to contain "<redacted>" must be
// refused with the redacted-URL sentinel, while the cleartext URL command
// ingests cleanly.
func TestEmbeddedRedactedURLIngestRefused15209(t *testing.T) {
	const urlSecret = "URLTOKEN15209"
	cleartext := embeddedIngest15209FlatTree(t,
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 then change-configuration commands "set system services dynamic-dns provider dy url https://user:`+urlSecret+`@dyn.example.com/upd"`,
	)
	redacted := cleartext.RedactedClone()
	if strings.Contains(redacted.FormatSet(), urlSecret) {
		t.Fatalf("redacted clone leaked embedded URL credential:\n%s", redacted.FormatSet())
	}
	if !strings.Contains(redacted.FormatSet(), SecretRedacted) {
		t.Fatalf("redacted clone did not contain the redacted-URL sentinel; precondition broken:\n%s", redacted.FormatSet())
	}
	err := checkRedactionPlaceholder(redacted)
	if err == nil {
		t.Fatalf("guard accepted redacted embedded URL command:\n%s", redacted.FormatSet())
	}
	if !errors.Is(err, errRedactedURLIngest) {
		t.Fatalf("err = %v, want errRedactedURLIngest", err)
	}
	if err := checkRedactionPlaceholder(cleartext); err != nil {
		t.Fatalf("guard rejected a cleartext embedded URL command: %v", err)
	}
}

// TestEmbeddedNonSecretPlaceholderIngestAllowed15209 pins the deliberate
// narrowness, mirroring TestRedactionPlaceholderIngest_NonSecretScoped: the
// placeholder inside a NON-secret embedded command (host-name), a GRE tunnel
// key, or a delete command is never produced by RedactedClone, so ingesting
// it must stay allowed — the embedded arm must judge inner tokens with the
// same secretIndices/urlLeafIndices gates, not a substring scan.
func TestEmbeddedNonSecretPlaceholderIngestAllowed15209(t *testing.T) {
	cases := map[string]*ConfigTree{
		"non-secret host-name command": embeddedIngest15209FlatTree(t,
			`set event-options policy p1 events ping_test_failed`,
			`set event-options policy p1 then change-configuration commands "set system host-name `+SecretDataPlaceholder+`"`),
		"GRE key command": embeddedIngest15209FlatTree(t,
			`set event-options policy p1 events ping_test_failed`,
			`set event-options policy p1 then change-configuration commands "set interfaces gr-0-0-0 unit 0 tunnel key `+SecretDataPlaceholder+`"`),
		"delete PSK command (no value minted)": embeddedIngest15209FlatTree(t,
			`set event-options policy p1 events ping_test_failed`,
			`set event-options policy p1 then change-configuration commands "delete security ike policy p1 pre-shared-key"`),
		"clean commands only": embeddedIngest15209FlatTree(t,
			`set event-options policy p1 events ping_test_failed`,
			`set event-options policy p1 then change-configuration commands "set system host-name foo"`,
			`set event-options policy p1 then change-configuration commands "set system login user bob class operator"`),
	}
	for name, tree := range cases {
		t.Run(name, func(t *testing.T) {
			if err := checkRedactionPlaceholder(tree); err != nil {
				t.Fatalf("guard over-reached onto %s: %v\n%s", name, err, tree.FormatSet())
			}
		})
	}
}

// TestEmbeddedPlaceholderDirectToken15209 covers a placeholder that arrives
// as a direct token in an unquoted tail rather than inside a quoted command
// string: `commands set … pre-shared-key ascii-text "##SECRET-DATA##"`
// re-lexed by the ingest path must still be refused. (The placeholder is
// quoted here exactly as RedactedClone's re-join renders it: a bare
// `##SECRET-DATA##` token is a lexer comment and never reaches the AST —
// see the lexer check below.) A placeholder glued inside a larger token
// must NOT be refused (RedactedClone replaces whole tokens).
func TestEmbeddedPlaceholderDirectToken15209(t *testing.T) {
	direct := embeddedIngest15209FlatTree(t,
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 then change-configuration commands set security ike policy p1 pre-shared-key ascii-text "`+SecretDataPlaceholder+`"`,
	)
	if err := checkRedactionPlaceholder(direct); err == nil {
		t.Fatalf("guard accepted direct-token embedded placeholder:\n%s", direct.FormatSet())
	} else if !errors.Is(err, errRedactionPlaceholderIngest) {
		t.Fatalf("err = %v, want errRedactionPlaceholderIngest", err)
	}

	glued := embeddedIngest15209FlatTree(t,
		`set event-options policy p1 events ping_test_failed`,
		`set event-options policy p1 then change-configuration commands set security ike policy p1 pre-shared-key ascii-text x`+SecretDataPlaceholder+`y`,
	)
	if err := checkRedactionPlaceholder(glued); err != nil {
		t.Fatalf("guard over-reached onto a glued (non-placeholder) token: %v", err)
	}
}
