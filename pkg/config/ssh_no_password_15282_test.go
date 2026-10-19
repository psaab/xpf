package config

import (
	"strings"
	"testing"
)

// #15282 (V31-S1, residual of #4305): the Junos SSH hardening leaves
// no-password-authentication and no-passwords were unmodeled, so they
// committed clean with zero warnings and no consumer — xpfd's sshd drop-in
// never set PasswordAuthentication. On a .deb install the host sshd default
// then applied. The ssh subtree is now closedWorld as well, so an unknown
// leaf such as bogus-knob-xyz is rejected at strict commit instead of being
// silently dropped.
//
// RED on revert:
//   - removing the two schema leaves / compiler reads makes the boolean
//     fields stay false (TestSSHNoPasswordKnobsCompiled15282 fails);
//   - removing closedWorld from system services ssh makes
//     TestSSHUnknownKnobRejected15282 fail (SchemaValidate returns nil).

func TestSSHNoPasswordKnobsCompiled15282(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cmds       []string
		wantNPA    bool
		wantNoPass bool
	}{
		{
			name:    "no-password-authentication only",
			cmds:    []string{"set system services ssh no-password-authentication"},
			wantNPA: true,
		},
		{
			name:       "no-passwords only",
			cmds:       []string{"set system services ssh no-passwords"},
			wantNoPass: true,
		},
		{
			name: "both",
			cmds: []string{
				"set system services ssh no-password-authentication",
				"set system services ssh no-passwords",
			},
			wantNPA:    true,
			wantNoPass: true,
		},
		{
			name: "neither (control)",
			cmds: []string{"set system services ssh root-login deny"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree4303(t, tc.cmds)
			c, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if err := SchemaValidate(tree, c); err != nil {
				t.Fatalf("SchemaValidate rejected the password knobs: %v", err)
			}
			if c.System.Services == nil || c.System.Services.SSH == nil {
				t.Fatalf("no SSH config compiled")
			}
			ssh := c.System.Services.SSH
			if ssh.NoPasswordAuthentication != tc.wantNPA {
				t.Errorf("NoPasswordAuthentication = %v, want %v", ssh.NoPasswordAuthentication, tc.wantNPA)
			}
			if ssh.NoPasswords != tc.wantNoPass {
				t.Errorf("NoPasswords = %v, want %v", ssh.NoPasswords, tc.wantNoPass)
			}
			all := strings.Join(c.Warnings, "\n")
			if strings.Contains(all, "no-password") && strings.Contains(all, "NOT") {
				t.Errorf("enforced knobs must not carry an inert advisory; warnings=%v", c.Warnings)
			}
		})
	}
}

// Hierarchical spelling reaches the same fields (the production parse path,
// not only flat set).
func TestSSHNoPasswordKnobsHierarchical15282(t *testing.T) {
	tree, errs := NewParser("system { services { ssh { no-passwords; root-login deny; } } }").Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := SchemaValidate(tree, c); err != nil {
		t.Fatalf("SchemaValidate rejected no-passwords: %v", err)
	}
	ssh := c.System.Services.SSH
	if ssh == nil || !ssh.NoPasswords || ssh.RootLogin != "deny" {
		t.Fatalf("hierarchical compile = %+v, want NoPasswords=true RootLogin=deny", ssh)
	}
}

func TestSSHUnknownKnobRejected15282(t *testing.T) {
	tree := buildTree4303(t, []string{"set system services ssh bogus-knob-xyz"})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile (closed-world rejection is a SchemaValidate duty): %v", err)
	}
	err = SchemaValidate(tree, c)
	if err == nil {
		t.Fatalf("SchemaValidate accepted bogus-knob-xyz under system services ssh; want closed-world rejection (#15282)")
	}
	if !strings.Contains(err.Error(), "bogus-knob-xyz") {
		t.Fatalf("rejection %q does not name the unknown knob", err)
	}
	// The recognized hardening neighbourhood still commits clean.
	ok := buildTree4303(t, []string{
		"set system services ssh root-login deny",
		"set system services ssh no-passwords",
		"set system services ssh protocol-version v2",
		"set system services ssh rate-limit 20",
	})
	oc, err := CompileConfig(ok)
	if err != nil {
		t.Fatalf("compile valid ssh stanza: %v", err)
	}
	if err := SchemaValidate(ok, oc); err != nil {
		t.Fatalf("SchemaValidate rejected a valid ssh stanza: %v", err)
	}
}
