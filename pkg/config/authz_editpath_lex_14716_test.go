package config

import (
	"strings"
	"testing"
)

// #14716: the edit cursor stored by the local and remote CLIs was raw
// strings.Fields output, so a lexically decorated edit path (`edit
// /* interfaces */ "system"`, `edit "system"`, `edit system /*` +
// `set */ ...`) desynchronized the authorization gate from the store
// lexer. The gate prepended the raw tokens, so anchored denies missed
// and comment text could satisfy allows, while execution re-joined the
// raw tokens and the store lexer skipped the comment and unquoted the
// string, mutating the denied subtree.
//
// The fix normalizes the cursor at the shared gate/executor boundary:
// ParseConfigPath lexes a typed edit fragment the way the store does,
// and NormalizeEditPathTokens drops lexically invisible (comment-only /
// error) stored tokens so cursors minted before the fix — or by any
// other raw writer — are judged as the paths the store will act on.

func TestParseConfigPath14716(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want []string
		ok   bool
	}{
		{"plain", "system", []string{"system"}, true},
		{"quoted", `"system"`, []string{"system"}, true},
		{"comment decorated", `/* interfaces */ "system"`, []string{"system"}, true},
		{"comment only", `/* interfaces */`, nil, true},
		{"empty", ``, nil, true},
		{"split comment open", `system /*`, nil, false},
		{"split comment close is data", `*/ root-authentication`, []string{"*/", "root-authentication"}, true},
		{"unterminated string", `"system`, nil, false},
		{"brace", `system {`, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseConfigPath(tc.in)
			if ok != tc.ok {
				t.Fatalf("ParseConfigPath(%q) ok=%v, want %v (tokens %v)", tc.in, ok, tc.ok, got)
			}
			if !tc.ok {
				return
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("ParseConfigPath(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// The packet's exact constructions, at the gate: a deny on
// ^system root-authentication must refuse, and an allow of ^interfaces
// must not be satisfied by comment text.
func TestAuthorizeConfigMutationDecoratedEditPath14716(t *testing.T) {
	deny := classWithConfigRegex9154(t, "", "^system root-authentication")
	allow := classWithConfigRegex9154(t, "^interfaces", "")

	cases := []struct {
		name     string
		editPath []string
		line     string
	}{
		{"quote only", []string{`"system"`}, "set root-authentication plain-text-password hunter2"},
		{"comment plus quote", []string{"/*", "interfaces", "*/", `"system"`}, "set root-authentication plain-text-password hunter2"},
		{"split comment across lines", []string{"system", "/*"}, "set */ root-authentication plain-text-password hunter2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := AuthorizeConfigMutation(deny, "limited", tc.editPath, tc.line); err == nil {
				t.Fatalf("editPath %v + %q was ALLOWED under deny ^system root-authentication; "+
					"the gate judged the raw cursor while the store executes the lexed path (#14716)", tc.editPath, tc.line)
			}
			if err := AuthorizeConfigMutation(allow, "limited", tc.editPath, tc.line); err == nil {
				t.Fatalf("editPath %v + %q was ALLOWED under allow ^interfaces; comment text "+
					"satisfied the allow while the store executes system root-authentication (#14716)", tc.editPath, tc.line)
			}
		})
	}

	// Control: a genuinely allowed path under a decorated cursor that
	// lexes to it must still pass, so the normalization is not a
	// deny-everything hammer.
	allowIface := classWithConfigRegex9154(t, "^interfaces", "")
	if err := AuthorizeConfigMutation(allowIface, "limited",
		[]string{"/*", "x", "*/", `"interfaces"`}, "set ge-0/0/0 description uplink"); err != nil {
		t.Errorf("decorated cursor lexing to interfaces was refused under allow ^interfaces: %v", err)
	}
	// Control: plain cursors keep their verdicts.
	if err := AuthorizeConfigMutation(deny, "limited",
		[]string{"system"}, "set host-name fw1"); err != nil {
		t.Errorf("plain system cursor + host-name was refused: %v", err)
	}
	if err := AuthorizeConfigMutation(deny, "limited",
		nil, "set system host-name fw1"); err != nil {
		t.Errorf("top-level host-name set was refused: %v", err)
	}
}
