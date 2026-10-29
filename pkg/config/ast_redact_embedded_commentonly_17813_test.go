package config

import (
	"errors"
	"strings"
	"testing"
)

// #17813: a comment-only embedded command lexes successfully to zero tokens
// (the lexer skips the entire `# ...` line), so redactEmbeddedCommand took
// the len(tokens)==0 && lexOK branch and returned the payload unchanged
// with changed=false — the outer quoted command was retained verbatim and
// its credential text persisted in redacted configuration renders and in
// event-engine rejection logs (evaluate.go logs the helper's return).
// Only actually empty / whitespace-only payloads may keep the
// empty-command exemption; any other zero-token payload is a nonempty
// command the lexer completely discarded and must be masked whole.

const secret17813 = "SENTINEL-17813-COMMENTONLY-PSK"

func TestRedactEmbeddedCommentOnly17813(t *testing.T) {
	commentOnly := []string{
		"# set security ike policy p1 pre-shared-key ascii-text " + secret17813,
		"#set security ike policy p1 pre-shared-key ascii-text " + secret17813,
		"  # set security ike policy p1 pre-shared-key ascii-text " + secret17813,
		"/* set security ike policy p1 pre-shared-key ascii-text " + secret17813 + " */",
	}
	for _, in := range commentOnly {
		got := RedactEmbeddedChangeConfigCommand(in)
		if strings.Contains(got, secret17813) {
			t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, still contains the secret", in, got)
		}
		if got != SecretDataPlaceholder {
			t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, want whole-payload %q", in, got, SecretDataPlaceholder)
		}
	}
	// Controls: actually empty / whitespace-only payloads keep the
	// empty-command exemption byte-identical.
	for _, in := range []string{"", "   ", "\t \n"} {
		if got := RedactEmbeddedChangeConfigCommand(in); got != in {
			t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, want unchanged empty-command exemption", in, got)
		}
	}
	// Control: a well-formed set command keeps its existing render
	// (verb structure preserved, only the value token masked).
	in := "set security ike policy p1 pre-shared-key ascii-text " + secret17813
	got := RedactEmbeddedChangeConfigCommand(in)
	want := "set security ike policy p1 pre-shared-key ascii-text \"" + SecretDataPlaceholder + "\""
	if got != want {
		t.Errorf("RedactEmbeddedChangeConfigCommand(%q) = %q, want %q", in, got, want)
	}
	// Control: a plain `# comment` without idempotent-provable safety is
	// also a discarded nonempty payload — masking it whole is the
	// fail-closed price; it carries no credential and renders as the
	// placeholder rather than surviving verbatim.
	if got := RedactEmbeddedChangeConfigCommand("# hello"); got != SecretDataPlaceholder {
		t.Errorf("plain comment command = %q, want whole-payload %q", got, SecretDataPlaceholder)
	}
}

func TestEmbeddedCommentOnlyRedactedClone17813(t *testing.T) {
	commentCommand := "# set security ike policy p1 pre-shared-key ascii-text " + secret17813
	controlCommand := "set system host-name foo"
	makeTree := func(commands ...string) *ConfigTree {
		nodes := make([]*Node, 0, len(commands))
		for _, command := range commands {
			nodes = append(nodes, &Node{
				Keys:   []string{"event-options", "policy", "p1", "then", "change-configuration", "commands", command},
				IsLeaf: true,
			})
		}
		return &ConfigTree{Children: nodes}
	}
	makeUnquotedTree := func(command string) *ConfigTree {
		keys := append([]string{"event-options", "policy", "p1", "then", "change-configuration", "commands"},
			strings.Fields(command)...)
		return &ConfigTree{Children: []*Node{{Keys: keys, IsLeaf: true}}}
	}
	makeUnquotedBlockTree := func(command string) *ConfigTree {
		return &ConfigTree{Children: []*Node{{
			Keys:     []string{"event-options", "policy", "p1", "then", "change-configuration", "commands"},
			Children: []*Node{{Keys: strings.Fields(command), IsLeaf: true}},
		}}}
	}

	// A stored AST leaf is the persistence shape read by RedactedClone. Keep
	// the command in the quoted `commands` value, where the comment marker is
	// part of the stored payload rather than an outer config comment.
	tree := makeTree(commentCommand, controlCommand)
	if !strings.Contains(tree.Format(), secret17813) {
		t.Fatalf("test precondition: stored tree omitted comment-only payload:\n%s", tree.Format())
	}
	redacted := tree.RedactedClone()
	for name, rendered := range map[string]string{
		"Format()":     redacted.Format(),
		"FormatSet()":  redacted.FormatSet(),
		"FormatJSON()": redacted.FormatJSON(),
		"FormatXML()":  redacted.FormatXML(),
	} {
		if strings.Contains(rendered, secret17813) {
			t.Errorf("%s leaked comment-only embedded PSK:\n%s", name, rendered)
		}
		if !strings.Contains(rendered, SecretDataPlaceholder) {
			t.Errorf("%s did not render placeholder:\n%s", name, rendered)
		}
		if !strings.Contains(rendered, controlCommand) {
			t.Errorf("%s dropped non-secret control:\n%s", name, rendered)
		}
	}
	// The cleartext tree remains the persisted source of truth.
	if !strings.Contains(tree.Format(), secret17813) {
		t.Errorf("source tree was mutated by RedactedClone:\n%s", tree.Format())
	}
	// Flat persisted render also cannot retain the embedded secret.
	flatRedacted := redacted.FormatSet()
	if strings.Contains(flatRedacted, secret17813) ||
		!strings.Contains(flatRedacted, SecretDataPlaceholder) {
		t.Errorf("flat RedactedClone leaked or failed to mask comment-only command:\n%s", flatRedacted)
	}
	// The unquoted joined-tail and block-child variants use separate AST
	// rewrite paths: the whole-payload sentinel lexes as a comment, so each
	// path must retain it as one stored key instead of dropping it.
	for name, makeUnquoted := range map[string]func(string) *ConfigTree{
		"unquoted joined tail": makeUnquotedTree,
		"unquoted block child": makeUnquotedBlockTree,
	} {
		t.Run(name, func(t *testing.T) {
			oldTree := makeUnquoted(commentCommand)
			got := oldTree.RedactedClone().FormatSet()
			if strings.Contains(got, secret17813) || !strings.Contains(got, SecretDataPlaceholder) {
				t.Errorf("RedactedClone leaked or dropped comment-only whole-payload mask:\n%s", got)
			}
			newCommand := strings.Replace(commentCommand, secret17813, "OTHER-17813", 1)
			diff := FormatCompareRedacted(oldTree, makeUnquoted(newCommand))
			if strings.Contains(diff, secret17813) || strings.Contains(diff, "OTHER-17813") {
				t.Errorf("FormatCompareRedacted leaked unquoted comment-only PSK:\n%s", diff)
			}
			if !strings.Contains(diff, "secret fingerprint") {
				t.Errorf("FormatCompareRedacted lost unquoted comment-only fingerprint:\n%s", diff)
			}
		})
	}
	// Compare: different comment-only credentials diff as changed (whole-
	// payload fingerprint), identical trees diff cleanly, neither renders a
	// credential value.
	changedTree := makeTree(strings.Replace(commentCommand, secret17813, "OTHER-17813", 1), controlCommand)
	diff := FormatCompareRedacted(tree, changedTree)
	if strings.Contains(diff, secret17813) || strings.Contains(diff, "OTHER-17813") {
		t.Errorf("FormatCompareRedacted leaked a comment-only PSK:\n%s", diff)
	}
	if !strings.Contains(diff, "secret fingerprint") {
		t.Errorf("FormatCompareRedacted (changed comment-only PSK) lost fingerprint:\n%s", diff)
	}
	same := FormatCompareRedacted(tree, tree)
	if strings.Contains(same, secret17813) || strings.Contains(same, SecretDataPlaceholder) {
		t.Errorf("FormatCompareRedacted (identical) should render neither PSK nor placeholder:\n%s", same)
	}
	// Ingest symmetry: a redacted whole-payload placeholder is refused on
	// re-ingest, while the original cleartext command remains ingestible.
	if err := checkRedactionPlaceholder(redacted); !errors.Is(err, errRedactionPlaceholderIngest) {
		t.Fatalf("guard err = %v, want errRedactionPlaceholderIngest for redacted comment-only command", err)
	}
	if err := checkRedactionPlaceholder(tree); err != nil {
		t.Fatalf("guard rejected cleartext comment-only command: %v", err)
	}
}
