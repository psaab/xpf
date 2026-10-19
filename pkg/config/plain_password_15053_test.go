package config

import (
	"strings"
	"testing"
)

// #15053 (A20-05): Junos plain-text-password-value under root-authentication /
// login user authentication commits clean, is inert, and is shown in cleartext.
// Strict SchemaValidate must reject both spellings at both sites with a hint to
// encrypted-password; the canary must never appear in RedactedClone.

const canary15053 = "CanaryP15053x"

func TestPlainTextPasswordStrictRejects15053(t *testing.T) {
	cases := []string{
		"set system root-authentication plain-text-password-value " + canary15053,
		"set system root-authentication plain-text-password " + canary15053,
		"set system login user alice authentication plain-text-password-value " + canary15053,
		"set system login user alice authentication plain-text-password " + canary15053,
	}
	for _, line := range cases {
		tree := buildTree(t, []string{line})
		err := SchemaValidate(tree, nil)
		if err == nil {
			t.Errorf("%q: SchemaValidate accepted plain-text-password (RED pre-fix)", line)
			continue
		}
		if !strings.Contains(err.Error(), "encrypted-password") {
			t.Errorf("%q: error %q lacks encrypted-password hint", line, err)
		}
		if strings.Contains(err.Error(), canary15053) {
			t.Errorf("%q: error leaks canary: %q", line, err)
		}
	}
}

func TestPlainTextPasswordNeverInRedactedClone15053(t *testing.T) {
	for _, line := range []string{
		"set system root-authentication plain-text-password-value " + canary15053,
		"set system login user alice authentication plain-text-password-value " + canary15053,
	} {
		tree := buildTree(t, []string{line})
		redacted := tree.RedactedClone()
		for name, rendered := range map[string]string{
			"hierarchical": redacted.Format(),
			"flat-set":     redacted.FormatSet(),
			"json":         redacted.FormatJSON(),
		} {
			if strings.Contains(rendered, canary15053) {
				t.Errorf("%s: %q rendered canary in cleartext:\n%s", name, line, rendered)
			}
		}
	}
}

func TestPlainTextPasswordControls15053(t *testing.T) {
	// Legitimate neighbours stay green.
	hash := "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	for _, line := range []string{
		`set system root-authentication encrypted-password "` + hash + `"`,
		"set system root-authentication ssh-ed25519 \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfirst a@b\"",
		`set system login user alice authentication encrypted-password "` + hash + `"`,
		"set system login user alice authentication ssh-ed25519 \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfirst a@b\"",
		"set system login user alice class super-user",
		"set system login user alice uid 1000",
	} {
		tree := buildTree(t, []string{line})
		if err := SchemaValidate(tree, nil); err != nil {
			t.Errorf("control %q rejected: %v", line, err)
		}
	}
}
