package config

import (
	"strconv"
	"strings"
	"testing"
)

const commentPayloadSecret18379 = "SENTINEL-18379-COMMENT-MASK"

func TestRedactEmbeddedCommentPayloads18379(t *testing.T) {
	credential := "set security ike policy p1 pre-shared-key ascii-text " + commentPayloadSecret18379
	cases := []struct {
		name            string
		command         string
		keepOrdinary    bool
		wantPlaceholder bool
	}{
		{
			name:         "trailing line comment",
			command:      "set system host-name preserved # " + credential,
			keepOrdinary: true,
		},
		{
			name:            "quoted credential value with trailing comment",
			command:         "set security ike policy p1 pre-shared-key ascii-text " + strconv.Quote(commentPayloadSecret18379) + " # trailing comment",
			wantPlaceholder: true,
		},
		{
			name:         "trailing block comment",
			command:      "set system host-name preserved /* " + credential + " */",
			keepOrdinary: true,
		},
		{
			name:         "nested block comment",
			command:      "set system host-name preserved /* outer /* " + credential + " */ */",
			keepOrdinary: true,
		},
		{
			name:         "credential comment line before ordinary command",
			command:      "# " + credential + "\nset system host-name preserved",
			keepOrdinary: true,
		},
		{
			name:            "quoted whole-command comment",
			command:         strconv.Quote("# " + credential),
			wantPlaceholder: true,
		},
		{
			name:            "quoted whole-command credential",
			command:         strconv.Quote(credential),
			wantPlaceholder: true,
		},
		{
			name:         "quoted command with trailing comment credential",
			command:      strconv.Quote("set system host-name preserved # " + credential),
			keepOrdinary: true,
		},
		{
			name:         "quoted prefix with comment tail credential",
			command:      strconv.Quote("set system host-name preserved") + " # " + credential,
			keepOrdinary: true,
		},
		{
			name:            "quoted prefix with junk tail credential",
			command:         strconv.Quote("set system host-name preserved") + " |" + credential,
			wantPlaceholder: true,
		},
	}

	makeTree := func(command string) *ConfigTree {
		return &ConfigTree{Children: []*Node{{
			Keys:   []string{"event-options", "policy", "p1", "then", "change-configuration", "commands", command},
			IsLeaf: true,
		}}}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clear := makeTree(tc.command)
			redacted := clear.RedactedClone()
			for name, render := range map[string]func() string{
				"Format":     redacted.Format,
				"FormatSet":  redacted.FormatSet,
				"FormatJSON": redacted.FormatJSON,
				"FormatXML":  redacted.FormatXML,
			} {
				got := render()
				if strings.Contains(got, commentPayloadSecret18379) {
					t.Errorf("%s leaked the credential:\n%s", name, got)
				}
				if tc.keepOrdinary && !strings.Contains(got, "set system host-name preserved") {
					t.Errorf("%s dropped the surviving ordinary command:\n%s", name, got)
				}
				if tc.wantPlaceholder && !strings.Contains(got, SecretDataPlaceholder) {
					t.Errorf("%s omitted the redaction placeholder:\n%s", name, got)
				}
			}

			alternate := strings.Replace(tc.command, commentPayloadSecret18379, "OTHER-18379-COMMENT-MASK", 1)
			diff := FormatCompareRedacted(clear, makeTree(alternate))
			if strings.Contains(diff, commentPayloadSecret18379) || strings.Contains(diff, "OTHER-18379-COMMENT-MASK") {
				t.Errorf("FormatCompareRedacted leaked a credential:\n%s", diff)
			}
		})
	}
	t.Run("clean quoted command keeps authored spacing", func(t *testing.T) {
		clear := makeTree(strconv.Quote("set system host-name   preserved"))
		redacted := clear.RedactedClone()
		for _, tc := range []struct {
			name   string
			render func(*ConfigTree) string
		}{
			{"Format", func(tree *ConfigTree) string { return tree.Format() }},
			{"FormatSet", func(tree *ConfigTree) string { return tree.FormatSet() }},
			{"FormatJSON", func(tree *ConfigTree) string { return tree.FormatJSON() }},
			{"FormatXML", func(tree *ConfigTree) string { return tree.FormatXML() }},
		} {
			if got, want := tc.render(redacted), tc.render(clear); got != want {
				t.Errorf("%s churned a clean command:\n got: %s\nwant: %s", tc.name, got, want)
			}
		}
	})
}
