package config

import (
	"sort"
	"strings"
	"testing"
)

// gate6662Marker is the substring unique to the #6662 packed-body rejection.
// Several gates can reject a `system login` config (the schema keyValidator on
// the user name, validateLoginClassRef on an undefined class, the duplicate
// named-block gate), so every rejection assertion in this file is attributed:
// a bare `err != nil` would pass even if this gate never ran.
const gate6662Marker = "written on the instance line"

// gate6662StatementMarker is the sibling marker for the one-level-down packed
// BLOCK statement (`authentication ssh-rsa "..."` inside a nested user body).
const gate6662StatementMarker = "written on the statement line"

// gate6701ShadowMarker attributes the built-in-shadowing rejection found while
// sweeping the #6701 fail-open for siblings.
const gate6701ShadowMarker = "is a SYSTEM-DEFINED login class"

// compileHierarchical drives the REAL hierarchical parse -> compile path.
func compileLogin6662(t *testing.T, text string) (*Config, error) {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	return CompileConfig(tree)
}

// compileLogin6662Lenient is compileHierarchical on the tolerant load /
// peer-sync path (#1960).
func compileLogin6662Lenient(t *testing.T, text string) (*Config, error) {
	t.Helper()
	p := NewParser(text)
	tree, perrs := p.Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse %q: %v", text, perrs)
	}
	return CompileConfigLenient(tree)
}

// compileFlatSet drives the REAL flat-set path: ParseSetCommand + SetPath per
// line, never NewParser (which merges newline-separated `set` lines into one
// giant node and would silently test something else).
func compileLogin6662FlatSet(t *testing.T, lines ...string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		path, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%v): %v", path, err)
		}
	}
	return CompileConfig(tree)
}

func mustReject(t *testing.T, err error, marker, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: compiled with NO error — the gate did not fire and the operator's "+
			"configuration was silently altered", what)
	}
	if !strings.Contains(err.Error(), marker) {
		t.Fatalf("%s: rejected by a DIFFERENT gate (want a message containing %q):\n  %v",
			what, marker, err)
	}
}

// ---------------------------------------------------------------------------
// Outcome 1: the nested spelling compiles CORRECTLY (and its safety nets fire).
// ---------------------------------------------------------------------------

// TestLoginNestedCompilesCorrectly_6662 is the baseline: the block spelling
// carries every leaf through.
//
// The fixture carries no deny-* leaf, and that is a #5831 consequence, not an
// oversight: those two leaves are now hard-REJECTED at commit
// (validateLoginClassDenyStrict), so a fixture carrying one can no longer be a
// positive control for "this spelling compiles". Their carry-through moved to
// TestLoginNestedCarriesDenyLeaves_6662 below, which drives the same nested
// spelling through the tolerant path where the class is folded rather than
// refused. Splitting them keeps BOTH properties bound; deleting the leaves
// outright would have dropped the second one.
// ROLE: POSITIVE CONTROL — the shape that must keep working. Measured, not assumed: disabling
// validateLoginPackedStatementsAST entirely leaves this test GREEN (#6706
// review r11), so it binds no gate behaviour and must not be counted as gate
// coverage. It is kept because a gate with no over-reach control is one
// widening away from rejecting valid configuration.
func TestLoginNestedCompilesCorrectly_6662(t *testing.T) {
	cfg, err := compileLogin6662(t, `system {
		login {
			class ops {
				permissions [ view configure ];
				idle-timeout 30;
				allow-commands "show .*";
			}
			user alice {
				uid 2001;
				class ops;
				authentication {
					ssh-rsa "ssh-rsa AAAAB3NzaC1yc2E alice";
					encrypted-password "$6$rounds=5000$abc$def";
				}
			}
		}
	}`)
	if err != nil {
		t.Fatalf("nested spelling must compile: %v", err)
	}

	if cfg.System.Login == nil {
		t.Fatal("System.Login is nil")
	}
	if len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("got %d classes, want 1", len(cfg.System.Login.Classes))
	}
	lc := cfg.System.Login.Classes[0]
	if lc.Name != "ops" {
		t.Errorf("class name = %q, want \"ops\"", lc.Name)
	}
	if got := strings.Join(lc.Permissions, ","); got != "view,configure" {
		t.Errorf("permissions = %q, want \"view,configure\"", got)
	}
	if len(lc.MappedPermissions) != 2 {
		t.Errorf("MappedPermissions = %v, want 2 entries", lc.MappedPermissions)
	}
	if lc.IdleTimeout != 30 {
		t.Errorf("IdleTimeout = %d, want 30", lc.IdleTimeout)
	}
	if lc.AllowCommands != "show .*" {
		t.Errorf("AllowCommands = %q, want \"show .*\"", lc.AllowCommands)
	}

	if len(cfg.System.Login.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(cfg.System.Login.Users))
	}
	u := cfg.System.Login.Users[0]
	if u.Name != "alice" || u.Class != "ops" || u.UID != 2001 {
		t.Errorf("user = {Name:%q Class:%q UID:%d}, want {alice ops 2001}", u.Name, u.Class, u.UID)
	}
	if len(u.SSHKeys) != 1 || u.SSHKeys[0] != "ssh-rsa AAAAB3NzaC1yc2E alice" {
		t.Errorf("SSHKeys = %v, want one ssh-rsa key", u.SSHKeys)
	}
	if u.EncryptedPassword.Reveal() != "$6$rounds=5000$abc$def" {
		t.Errorf("EncryptedPassword = %q, want the configured hash", u.EncryptedPassword.Reveal())
	}

	// The safety net the packed drop disabled, measured on the TYPED CONFIG
	// rather than on an advisory string.
	//
	// It has been re-aimed twice, and the reason matters. Originally it read
	// the #4304 "MORE PERMISSIVE" deny-commands advisory; #5831 replaced that
	// with a hard rejection, so it moved to the #4304 per-class advisory naming
	// `allow-commands` as recognized-but-unenforced; #7172 cut 6 ENFORCES
	// allow-commands, so that advisory no longer names it and the assertion
	// went red for a reason unrelated to the packed-body bug.
	//
	// Twice is the signal: this cell was asserting on the nearest observable
	// rather than on its own subject. Its subject is that a NESTED class body
	// is not dropped, and the direct evidence is the leaf arriving in the typed
	// class. That survives every future change to how the leaf is treated.
	var advisory string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, `system login class "ops"`) && strings.Contains(w, "recognized (custom RBAC)") {
			advisory = w
		}
	}
	if advisory == "" {
		t.Fatalf("the #4304 per-class advisory did not fire, so the class did not survive "+
			"the nested spelling at all; warnings: %v", cfg.Warnings)
	}
	if len(cfg.System.Login.Classes) == 0 {
		t.Fatal("no login classes compiled")
	}
	if got := cfg.System.Login.Classes[0].AllowCommands; got != "show .*" {
		t.Errorf("the nested class body was dropped: AllowCommands = %q, want the "+
			"configured pattern. This is the #6662 packed-body bug's direct symptom.", got)
	}
}

// TestLoginCarriesDenyLeavesBothShapes_6662 holds the half that moved out of
// the two positive controls when #5831 made deny-* a commit rejection.
//
// Both spellings must still carry the restrictive leaves into the typed class —
// value AND presence — because that is exactly what the packed-body bug
// destroyed, and because a #5831 gate reading DenyLeavesPresent is only ever as
// good as the parse that fills it. Compiled through the tolerant path (the
// peer-sync / persisted-load ingress) because the strict path now refuses the
// config outright; that rejection is the #5831 suite's job, not this file's.
//
// Running BOTH shapes is the point: DenyLeavesPresent is populated off
// prop.Name() from the loginClassLeafRestrictive table, and the two AST shapes
// reach that switch by different routes (a nested block child vs a flat-set
// leaf), so a one-shape test would leave half the parse unbound.
// ROLE: POSITIVE CONTROL — the leaves the packed drop silently emptied.
func TestLoginCarriesDenyLeavesBothShapes_6662(t *testing.T) {
	t.Run("nested", func(t *testing.T) {
		cfg, err := compileLogin6662Lenient(t, `system {
			login {
				class ops {
					permissions [ view configure ];
					deny-commands "request system zeroize";
					deny-configuration "system login";
				}
			}
		}`)
		if err != nil {
			t.Fatalf("tolerant compile must not reject a previously-accepted config (#1960): %v", err)
		}
		assertOpsCarriesDenyLeaves6662(t, cfg)
	})

	t.Run("flat-set", func(t *testing.T) {
		tree := &ConfigTree{}
		for _, l := range []string{
			"set system login class ops permissions [ view configure ]",
			`set system login class ops deny-commands "request system zeroize"`,
			`set system login class ops deny-configuration "system login"`,
		} {
			path, err := ParseSetCommand(l)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", l, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%v): %v", path, err)
			}
		}
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant compile must not reject a previously-accepted config (#1960): %v", err)
		}
		assertOpsCarriesDenyLeaves6662(t, cfg)
	})
}

func assertOpsCarriesDenyLeaves6662(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg.System.Login == nil || len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("got %+v, want exactly one class", cfg.System.Login)
	}
	lc := cfg.System.Login.Classes[0]
	if lc.DenyCommands != "request system zeroize" {
		t.Errorf("DenyCommands = %q, want \"request system zeroize\"", lc.DenyCommands)
	}
	if lc.DenyConfiguration != "system login" {
		t.Errorf("DenyConfiguration = %q, want \"system login\"", lc.DenyConfiguration)
	}
	// Presence is what the gate actually reads, and it is recorded separately
	// from the value (a quoted-empty regex is the most restrictive thing an
	// operator can write and flattens to the same "").
	if got := strings.Join(lc.DenyLeavesPresent, ","); got != "deny-commands,deny-configuration" {
		t.Errorf("DenyLeavesPresent = %q, want both leaves recorded in config order", got)
	}
}

// ---------------------------------------------------------------------------
// Outcome 2: the packed spelling is REJECTED at commit, by THIS gate.
// ---------------------------------------------------------------------------

// TestLoginPackedRejectedAtCommit_6662 walks the whole `system login` body
// vocabulary in its packed spelling. Each row previously compiled an EMPTY
// object and returned no error.
func TestLoginPackedRejectedAtCommit_6662(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		marker string
	}{
		// --- login user <name> ---
		{"user class", `system { login { user alice class ops; } }`, gate6662Marker},
		{"user uid", `system { login { user alice uid 2001; } }`, gate6662Marker},
		{"user authentication (fully packed)",
			`system { login { user alice authentication ssh-rsa "ssh-rsa AAAA k"; } }`, gate6662Marker},
		{"user multiple statements packed",
			`system { login { user alice class ops uid 2001; } }`, gate6662Marker},

		// --- login class <name> ---
		{"class permissions (bracketed)",
			`system { login { class ops permissions [ view configure ]; } }`, gate6662Marker},
		{"class permissions (single)",
			`system { login { class ops permissions view; } }`, gate6662Marker},
		{"class idle-timeout", `system { login { class ops idle-timeout 30; } }`, gate6662Marker},
		{"class deny-commands",
			`system { login { class ops deny-commands "request system zeroize"; } }`, gate6662Marker},
		{"class deny-configuration",
			`system { login { class ops deny-configuration "system login"; } }`, gate6662Marker},
		{"class allow-commands",
			`system { login { class ops allow-commands "show .*"; } }`, gate6662Marker},
		{"class allow-configuration",
			`system { login { class ops allow-configuration "interfaces"; } }`, gate6662Marker},
		{"class login-alarms", `system { login { class ops login-alarms; } }`, gate6662Marker},
		{"class login-tip", `system { login { class ops login-tip; } }`, gate6662Marker},

		// --- one level down: a BLOCK statement written inline inside a nested body ---
		{"authentication ssh-rsa inline in a nested user body",
			`system { login { user alice { authentication ssh-rsa "ssh-rsa AAAA k"; } } }`,
			gate6662StatementMarker},
		{"authentication ssh-ed25519 inline in a nested user body",
			`system { login { user alice { authentication ssh-ed25519 "ssh-ed25519 AAAA k"; } } }`,
			gate6662StatementMarker},
		{"authentication encrypted-password inline in a nested user body",
			`system { login { user alice { authentication encrypted-password "$6$abc$def"; } } }`,
			gate6662StatementMarker},

		// --- the bare-container AST shape (namedInstances' second branch) ---
		{"packed inside a bare `user { }` container",
			`system { login { user { alice class ops; } } }`, gate6662Marker},
		{"packed inside a bare `class { }` container",
			`system { login { class { ops permissions view; } } }`, gate6662Marker},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileLogin6662(t, tt.text)
			mustReject(t, err, tt.marker, tt.name)
			if !strings.Contains(err.Error(), "#6662") {
				t.Errorf("rejection does not cite the issue: %v", err)
			}
			if !strings.Contains(err.Error(), "Rewrite as") {
				t.Errorf("rejection is not actionable (no rewrite shown): %v", err)
			}
		})
	}
}

// TestLoginPackedRejectionNamesTheDroppedTokens_6662 pins the message CONTENT,
// not just the fact of rejection: an operator has to be able to see which
// statement was dropped and how to spell it. A gate that rejected with a
// generic message would satisfy the table above.
func TestLoginPackedRejectionNamesTheDroppedTokens_6662(t *testing.T) {
	_, err := compileLogin6662(t,
		`system { login { class ops deny-commands "request system zeroize"; } }`)
	if err == nil {
		t.Fatal("packed class body compiled with no error")
	}
	msg := err.Error()
	for _, want := range []string{
		"system login class ops",
		`deny-commands "request system zeroize"`,
		"SILENTLY DROPPED",
		"set system login class ops deny-commands",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("rejection does not contain %q:\n  %s", want, msg)
		}
	}
}

// TestLoginPackedRejectionPreservesQuoting_6662 pins the rewrite suggestions as
// PASTEABLE (#6706 review MINOR-5). The message renders every instance name and
// body token through quoteKey, the same round-trip renderer Format uses.
//
// Before this, `strings.Join(keys, " ")` dropped the quotes the lexer had
// already consumed, so
//
//	class "noc ops" deny-commands "request system zeroize";
//
// produced the suggestion `class noc ops { deny-commands request system
// zeroize; }` — neither token boundary preserved. An operator pasting that got
// a class named `noc` with three stray tokens, i.e. a DIFFERENT configuration
// than the one being rejected. Whitespace-bearing class names and
// deny-commands regexes are both ordinary Junos, so this is the common case,
// not a corner.
func TestLoginPackedRejectionPreservesQuoting_6662(t *testing.T) {
	_, err := compileLogin6662(t,
		`system { login { class "noc ops" deny-commands "request system zeroize"; } }`)
	if err == nil {
		t.Fatal("packed class body with a quoted name compiled with no error")
	}
	msg := err.Error()
	for _, want := range []string{
		// the instance name keeps its quotes wherever it is rendered ...
		`system login class "noc ops"`,
		// ... including inside both rewrite suggestions,
		"`class \"noc ops\" { deny-commands \"request system zeroize\"; }`",
		`set system login class "noc ops" deny-commands "request system zeroize"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("rejection loses quoting — missing %q:\n  %s", want, msg)
		}
	}
	// A bare-token rewrite is exactly the unpasteable output this guards
	// against; assert its absence so re-introducing strings.Join reds here.
	if strings.Contains(msg, "class noc ops") {
		t.Errorf("rejection renders the quoted name as bare tokens (`class noc ops`):\n  %s", msg)
	}
}

// TestLoginPackedUserRejectionExplainsTheRBACCost_6662 requires the `user`
// rejection to state the consequence that makes this a security defect rather
// than a typo: an empty class is the CLI's legacy allow-everything mode.
func TestLoginPackedUserRejectionExplainsTheRBACCost_6662(t *testing.T) {
	_, err := compileLogin6662(t, `system { login { user alice class ops; } }`)
	if err == nil {
		t.Fatal("packed user body compiled with no error")
	}
	msg := err.Error()
	for _, want := range []string{"NO login class", "allow-everything"} {
		if !strings.Contains(msg, want) {
			t.Errorf("rejection does not explain the RBAC cost (missing %q):\n  %s", want, msg)
		}
	}
}

// ---------------------------------------------------------------------------
// Outcome 3: flat-set still compiles CORRECTLY (regression guard).
// ---------------------------------------------------------------------------

// TestLoginFlatSetStillCompiles_6662 is the regression guard. Flat-set works
// today — the schema consumes exactly the instance name as the keyed arg and
// hangs the body off as children — and the new gate must not touch it. Without
// this, a gate keyed on "the instance node carries extra tokens" that got the
// identity-key count wrong would reject every `set system login ...` line and
// brick config authoring, while the reject-table above stayed green.
//
// Carries no deny-* line for the same #5831 reason as the nested control above:
// those leaves are refused at commit now, so they cannot appear in a fixture
// whose job is to compile. Their flat-set carry-through is bound by
// TestLoginCarriesDenyLeavesBothShapes_6662.
// ROLE: POSITIVE CONTROL — the ingress the gate must never touch. Measured, not assumed: disabling
// validateLoginPackedStatementsAST entirely leaves this test GREEN (#6706
// review r11), so it binds no gate behaviour and must not be counted as gate
// coverage. It is kept because a gate with no over-reach control is one
// widening away from rejecting valid configuration.
func TestLoginFlatSetStillCompiles_6662(t *testing.T) {
	cfg, err := compileLogin6662FlatSet(t,
		"set system login class ops permissions [ view configure ]",
		"set system login class ops idle-timeout 30",
		`set system login class ops allow-commands "show .*"`,
		"set system login class ops login-alarms",
		"set system login user alice uid 2001",
		"set system login user alice class ops",
		`set system login user alice authentication ssh-rsa "ssh-rsa AAAAB3NzaC1yc2E alice"`,
		`set system login user alice authentication encrypted-password "$6$rounds=5000$abc$def"`,
	)
	if err != nil {
		t.Fatalf("flat-set spelling must still compile: %v", err)
	}

	if len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("got %d classes, want 1", len(cfg.System.Login.Classes))
	}
	lc := cfg.System.Login.Classes[0]
	if got := strings.Join(lc.Permissions, ","); got != "view,configure" {
		t.Errorf("permissions = %q, want \"view,configure\"", got)
	}
	if lc.IdleTimeout != 30 {
		t.Errorf("IdleTimeout = %d, want 30", lc.IdleTimeout)
	}
	if lc.AllowCommands != "show .*" {
		t.Errorf("AllowCommands = %q, want the configured regex", lc.AllowCommands)
	}

	if len(cfg.System.Login.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(cfg.System.Login.Users))
	}
	u := cfg.System.Login.Users[0]
	if u.Name != "alice" || u.Class != "ops" || u.UID != 2001 {
		t.Errorf("user = {Name:%q Class:%q UID:%d}, want {alice ops 2001}", u.Name, u.Class, u.UID)
	}
	if len(u.SSHKeys) != 1 {
		t.Errorf("SSHKeys = %v, want one key", u.SSHKeys)
	}
	if u.EncryptedPassword.Reveal() != "$6$rounds=5000$abc$def" {
		t.Errorf("EncryptedPassword = %q, want the configured hash", u.EncryptedPassword.Reveal())
	}
}

// TestLoginBareInstanceStillCompiles_6662 guards the other false-positive edge:
// an instance with NO body at all (`user alice;` / `class ops;`) carries exactly
// the identity keys and must pass the gate untouched.
// ROLE: POSITIVE CONTROL — an unpacked instance the gate must not claim. Measured, not assumed: disabling
// validateLoginPackedStatementsAST entirely leaves this test GREEN (#6706
// review r11), so it binds no gate behaviour and must not be counted as gate
// coverage. It is kept because a gate with no over-reach control is one
// widening away from rejecting valid configuration.
func TestLoginBareInstanceStillCompiles_6662(t *testing.T) {
	for _, text := range []string{
		`system { login { user alice; } }`,
		`system { login { class ops; } }`,
		`system { login { user alice { } } }`,
	} {
		if _, err := compileLogin6662(t, text); err != nil {
			t.Errorf("%s: bare instance must compile, got: %v", text, err)
		}
	}
}

// TestLoginPackedInsideAppliedGroupRejected_6662 pins that the gate sees a
// packed body arriving through `apply-groups`.
//
// The gate walks TOP-LEVEL `system`, so its coverage depends on running AFTER
// apply-groups expansion — which runPreWalkGates does. If it ever moved ahead of
// expansion, a packed login body hidden in an applied group would compile empty
// again with the top-level cases still green, and `groups` is exactly how a
// migrated vSRX config carries shared login stanzas.
//
// The UNAPPLIED case is the false-positive half and must NOT reject: an
// unapplied group is inert (the compiler ignores its body too), so rejecting it
// would fail a config that does nothing.
//
// Scope note, so the binding is not overclaimed: only the APPLIED subtest is
// mutation-bound. Making the gate blind to `system` reds it (M16). The UNAPPLIED
// subtest holds STRUCTURALLY rather than by assertion — ExpandGroups DELETES the
// whole `groups` stanza before compileExpanded runs runPreWalkGates, so the gate
// cannot see an unapplied body no matter what it walks. An attempt to mutate the
// gate into rejecting one was a no-op for exactly that reason. It is kept as
// documentation of the ordering the applied case depends on, not as a guard that
// a plausible edit could trip.
func TestLoginPackedInsideAppliedGroupRejected_6662(t *testing.T) {
	const groupBody = `groups { g1 { system { login { user alice class ops; } } } }`
	const classDef = `system { login { class ops { permissions view; } } }`

	t.Run("applied group is rejected", func(t *testing.T) {
		_, err := compileLogin6662(t, groupBody+"\napply-groups g1;\n"+classDef)
		mustReject(t, err, gate6662Marker, "packed body inside an applied group")
	})

	t.Run("unapplied group is inert, not rejected", func(t *testing.T) {
		cfg, err := compileLogin6662(t, groupBody+"\n"+classDef)
		if err != nil {
			t.Fatalf("an UNAPPLIED group must not be rejected — its body never compiles: %v", err)
		}
		if len(cfg.System.Login.Users) != 0 {
			t.Fatalf("unapplied group contributed users %+v; the premise of not rejecting it is "+
				"that it contributes nothing", cfg.System.Login.Users)
		}
	})

	t.Run("nested body inside an applied group still compiles", func(t *testing.T) {
		cfg, err := compileLogin6662(t,
			`groups { g1 { system { login { user alice { class ops; } } } } }`+
				"\napply-groups g1;\n"+classDef)
		if err != nil {
			t.Fatalf("the NESTED spelling inside an applied group must compile: %v", err)
		}
		if len(cfg.System.Login.Users) != 1 || cfg.System.Login.Users[0].Class != "ops" {
			t.Fatalf("users = %+v, want alice with class ops", cfg.System.Login.Users)
		}
	})

	t.Run("shadowing class inside an applied group is rejected", func(t *testing.T) {
		_, err := compileLogin6662(t,
			`groups { g1 { system { login { class super-user { permissions view; } } } } }`+
				"\napply-groups g1;")
		mustReject(t, err, gate6701ShadowMarker, "shadowing class inside an applied group")
	})
}

// ---------------------------------------------------------------------------
// The tolerant path WARNS rather than rejecting (#1960 no-brick).
// ---------------------------------------------------------------------------

// TestLoginPackedLenientWarns_6662 covers the tolerant load / peer-sync path.
// It asserts the WARNING TEXT, not merely the absence of an error: a lenient
// path that dropped the finding entirely would satisfy `err == nil`.
func TestLoginPackedLenientWarns_6662(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		marker string
	}{
		{"packed user body", `system { login { user alice class ops; } }`, gate6662Marker},
		{"packed class body", `system { login { class ops permissions view; } }`, gate6662Marker},
		{"inline authentication block",
			`system { login { user alice { authentication ssh-rsa "ssh-rsa AAAA k"; } } }`,
			gate6662StatementMarker},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := compileLogin6662Lenient(t, tt.text)
			if err != nil {
				t.Fatalf("tolerant path must NOT reject (#1960 no-brick): %v", err)
			}
			var found string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tt.marker) {
					found = w
				}
			}
			if found == "" {
				t.Fatalf("tolerant path emitted no warning containing %q; warnings: %v",
					tt.marker, cfg.Warnings)
			}
			if !strings.Contains(found, "#6662") {
				t.Errorf("warning does not cite the issue: %q", found)
			}
		})
	}
}

// TestLoginPackedLenientStillCompilesEmpty_6662 pins the residual for the
// INSTANCE-line packing specifically: on the tolerant path that stanza still
// compiles a user with an EMPTY class (that is what "warn, don't reject"
// means), so the commit gate alone does not close the RBAC hole there. What
// closes it is pkg/cli ResolveLoginClass mapping a MATCHED user with an empty
// class to the fail-closed class — asserted independently in
// pkg/daemon TestApplyCLILoginClassLenientEmptyClassFailsClosed_6701.
//
// ROLE, measured rather than asserted: this test does NOT guard the packed
// gate. Disabling validateLoginPackedStatementsAST entirely leaves it GREEN
// (#6706 review r11) — correctly, because its subject is the LENIENT path,
// where the gate only warns. It is a residual pin, and it should be read as
// one.
//
// SCOPE, because the belt it names does not cover every packing. "A matched
// user with an empty class" only exists at the INSTANCE level. At either
// ANCESTOR level there is no matched user: the `login` line drops to a non-nil
// but empty LoginConfig, and the `system` line drops to System.Login == nil,
// which used to reach pkg/cli's legacy allow-everything mode. Those two are
// covered by Config.System.LoginDroppedByPacking and pkg/daemon
// TestApplyCLILoginClass6706DroppedLoginFailsClosed, not by this belt.
func TestLoginPackedLenientStillCompilesEmpty_6662(t *testing.T) {
	cfg, err := compileLogin6662Lenient(t, `system { login { user alice class ops; } }`)
	if err != nil {
		t.Fatalf("tolerant path must not reject: %v", err)
	}
	if len(cfg.System.Login.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(cfg.System.Login.Users))
	}
	if got := cfg.System.Login.Users[0].Class; got != "" {
		t.Fatalf("leniently-loaded packed user Class = %q; this test documents the residual "+
			"(it compiles EMPTY) — if unpacking was added, update the pkg/cli belt rationale too", got)
	}
}

// ---------------------------------------------------------------------------
// #6701 sibling: a custom class shadowing a system-defined one.
// ---------------------------------------------------------------------------

// TestLoginClassShadowingBuiltinRejected_6701 covers the sibling found while
// sweeping the RBAC fail-open. `class super-user { permissions view; }` compiled
// cleanly, recorded MappedPermissions=[PermView], and the commit advisory
// reported the narrowing as applied — while pkg/cli resolveClassPerms resolved
// the BUILT-IN [PermAll] at runtime, so the user held every permission.
func TestLoginClassShadowingBuiltinRejected_6701(t *testing.T) {
	for _, name := range []string{"super-user", "operator", "read-only", "config-viewer", "unauthorized"} {
		t.Run(name, func(t *testing.T) {
			_, err := compileLogin6662(t,
				`system { login { class `+name+` { permissions view; } } }`)
			mustReject(t, err, gate6701ShadowMarker, "class "+name)
			if !strings.Contains(err.Error(), "INERT") {
				t.Errorf("rejection does not say the definition is inert: %v", err)
			}
		})
	}
}

// TestLoginClassShadowingBuiltinLenientWarns_6701 is the tolerant-path half.
func TestLoginClassShadowingBuiltinLenientWarns_6701(t *testing.T) {
	cfg, err := compileLogin6662Lenient(t,
		`system { login { class super-user { permissions view; } } }`)
	if err != nil {
		t.Fatalf("tolerant path must NOT reject (#1960 no-brick): %v", err)
	}
	var found bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, gate6701ShadowMarker) {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant path emitted no shadowing warning; warnings: %v", cfg.Warnings)
	}
}

// TestLoginCustomClassStillCompiles_6701 is the false-positive guard for the
// shadow gate: a custom class whose name is NOT a built-in must keep compiling
// exactly as #4304 S-2 intends.
// ROLE: POSITIVE CONTROL — a custom class the gate must not claim. Measured, not assumed: disabling
// validateLoginPackedStatementsAST entirely leaves this test GREEN (#6706
// review r11), so it binds no gate behaviour and must not be counted as gate
// coverage. It is kept because a gate with no over-reach control is one
// widening away from rejecting valid configuration.
func TestLoginCustomClassStillCompiles_6701(t *testing.T) {
	cfg, err := compileLogin6662(t, `system {
		login {
			class noc-admin { permissions [ view configure ]; }
			user bob { class noc-admin; }
		}
	}`)
	if err != nil {
		t.Fatalf("a non-shadowing custom class must compile: %v", err)
	}
	if len(cfg.System.Login.Classes) != 1 || cfg.System.Login.Classes[0].Name != "noc-admin" {
		t.Fatalf("classes = %+v, want one named noc-admin", cfg.System.Login.Classes)
	}
	if len(cfg.System.Login.Users) != 1 || cfg.System.Login.Users[0].Class != "noc-admin" {
		t.Fatalf("users = %+v, want bob with class noc-admin", cfg.System.Login.Users)
	}
}

// ---------------------------------------------------------------------------
// Enumeration drift guards.
// ---------------------------------------------------------------------------

// TestLoginInstanceKeywordsMatchSchema_6662 pins the enumeration to the schema.
// `system login` has exactly two children (`class`, `user`); if a third named
// instance is added to setSchema without a row in loginInstanceKeywords, the new
// stanza's packed spelling silently compiles empty again — the exact regression
// this gate exists to prevent, reintroduced one stanza over.
func TestLoginInstanceKeywordsMatchSchema_6662(t *testing.T) {
	sys, ok := setSchema.children["system"]
	if !ok || sys == nil {
		t.Fatal("setSchema has no `system` node")
	}
	login, ok := sys.children["login"]
	if !ok || login == nil {
		t.Fatal("setSchema has no `system login` node")
	}

	var schemaKeys []string
	for name := range login.children {
		schemaKeys = append(schemaKeys, name)
	}
	sort.Strings(schemaKeys)

	gateKeys := append([]string(nil), loginInstanceKeywords...)
	sort.Strings(gateKeys)

	if strings.Join(schemaKeys, ",") != strings.Join(gateKeys, ",") {
		t.Fatalf("loginInstanceKeywords = %v but the `system login` schema children are %v — "+
			"a stanza missing from the gate compiles its packed spelling EMPTY with no error (#6662)",
			gateKeys, schemaKeys)
	}
}

// TestLoginBlockOnlyStatementsAreSchemaChildren_6662 guards the other
// enumeration: every `<keyword> <statement>` listed as block-only must be a real
// schema child of that instance, and must itself have children (which is what
// makes it a block rather than a leaf). A typo would silently disable the
// one-level-down half of the gate while the instance-line half stayed green.
func TestLoginBlockOnlyStatementsAreSchemaChildren_6662(t *testing.T) {
	login := setSchema.children["system"].children["login"]

	names := loginBlockOnlyStatementNames()
	if len(names) == 0 {
		t.Fatal("loginBlockOnlyStatements is empty — the one-level-down gate binds nothing")
	}

	for _, full := range names {
		parts := strings.SplitN(full, " ", 2)
		keyword, stmt := parts[0], parts[1]

		inst, ok := login.children[keyword]
		if !ok || inst == nil {
			t.Errorf("block-only entry %q: %q is not a `system login` schema child", full, keyword)
			continue
		}
		node, ok := inst.children[stmt]
		if !ok || node == nil {
			t.Errorf("block-only entry %q: %q is not a schema child of `login %s`", full, stmt, keyword)
			continue
		}
		if len(node.children) == 0 {
			t.Errorf("block-only entry %q: the schema node has no children, so it is a LEAF, "+
				"not a block — listing it here gates the wrong shape", full)
		}
		// The recorded ARITY must equal the schema's, because the gate skips
		// exactly that many key tokens before calling the rest a packed body.
		// Recording it too low rejects the correct nested spelling; too high
		// lets a packed body through (#6701 MINOR-4).
		gotArity, listed := loginBlockOnlyArity(keyword, stmt)
		if !listed {
			t.Errorf("block-only entry %q: not retrievable through loginBlockOnlyArity", full)
			continue
		}
		if gotArity != node.args {
			t.Errorf("block-only entry %q: gate records arity %d but the schema node takes %d "+
				"arg(s) — the gate would skip the wrong number of key tokens", full, gotArity, node.args)
		}
	}
}

// TestLoginBlockOnlyEnumerationIsComplete_6662 is the completeness half: it
// derives, from the SCHEMA, every `login <keyword> <statement>` that is a block
// (has children — at ANY arity) and requires each to be listed as block-only.
//
// Reading the compiler by hand is how the enumeration was built; this is what
// stops it rotting. If someone adds a second block-bodied login statement to
// the schema and forgets the gate row, its inline spelling starts dropping
// silently — and this test names it.
func TestLoginBlockOnlyEnumerationIsComplete_6662(t *testing.T) {
	login := setSchema.children["system"].children["login"]

	listed := map[string]bool{}
	for _, full := range loginBlockOnlyStatementNames() {
		listed[full] = true
	}

	var missing []string
	for _, keyword := range loginInstanceKeywords {
		inst := login.children[keyword]
		if inst == nil {
			continue
		}
		for stmt, node := range inst.children {
			// A BLOCK is any node with children, REGARDLESS of arity. The
			// previous version also skipped `node.args != 0`, which put an
			// args-bearing block statement (`foo <name> { ... }`) outside the
			// guard's scope entirely — guard scope narrower than the claim it
			// protects. Such a statement is exactly as droppable as a
			// zero-arity one; the arity only changes how many key tokens the
			// gate must skip, which loginBlockOnlyStatements now records
			// (#6701 MINOR-4).
			if node == nil || len(node.children) == 0 {
				continue // a leaf: not a block
			}
			if !listed[keyword+" "+stmt] {
				missing = append(missing, keyword+" "+stmt)
			}
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("`login %s` is a BLOCK statement in setSchema but is not listed in "+
			"loginBlockOnlyStatements — its inline spelling drops silently (#6662)", m)
	}
}

// ---------------------------------------------------------------------------
// #6706 review blocker: a `${node}`-scoped group must not smuggle a login body
// past BOTH gates.
// ---------------------------------------------------------------------------

// peerOnlyLoginGroup wraps a `system login` body in a `groups node1` block
// selected by `apply-groups "${node}"`, plus a benign `groups node0` so BOTH
// node views expand cleanly. Committed on node 0 the body is stripped before
// compilation; the peer receives it through Store.SyncApply, which is lenient.
func peerOnlyLoginGroup(body string) string {
	return `groups {
	node0 { system { host-name fw0; } }
	node1 { system { login { ` + body + ` } } }
}
apply-groups "${node}";
`
}

// TestLoginGatesRejectPeerOnlyNodeGroupBody_6706 is the blocker: a login body
// that only the PEER's `${node}` expansion renders must be rejected by the
// commit on EITHER node.
//
// Before this, both gates ran post-expansion on the single local view:
//
//	node 0 commits -> ExpandGroupsWithVars({node: node0}) strips the node1 body
//	              -> neither gate ever sees it -> strict commit-check PASSES
//	node 1 ingests via Store.SyncApply -> compileTreeLenient -> WARNS only
//	              -> `class super-user { permissions view; }` is live on node 1,
//	                 pkg/cli resolveClassPerms returns the BUILT-IN PermAll,
//	                 and bob holds every permission on the standby
//
// so the authored narrowing applied on neither node and no strict check
// existed anywhere in the cluster. Both gates now evaluate node0 AND node1
// effective views pre-expansion (forEachClusterNodeView), which is the same
// doctrine as #5878/#5879/#6178 and the AST-layer analogue of the #5876
// peer-effective source-NAT replay.
//
// FAIL-ON-REVERT: restrict forEachClusterNodeView to the committing node's view
// and every strict sub-test here goes RED.
func TestLoginGatesRejectPeerOnlyNodeGroupBody_6706(t *testing.T) {
	strictCases := []struct {
		name   string
		body   string
		marker string
	}{
		{
			name:   "shadowing built-in class in a peer-only ${node} group",
			body:   `class super-user { permissions view; } user bob { class super-user; }`,
			marker: gate6701ShadowMarker,
		},
		{
			name:   "packed user body in a peer-only ${node} group",
			body:   `user bob class ops;`,
			marker: gate6662Marker,
		},
		{
			name:   "packed class body in a peer-only ${node} group",
			body:   `class ops permissions view;`,
			marker: gate6662Marker,
		},
		{
			name:   "inline authentication block in a peer-only ${node} group",
			body:   `user bob { authentication ssh-rsa "ssh-rsa AAAA k"; }`,
			marker: gate6662StatementMarker,
		},
	}

	for _, tc := range strictCases {
		t.Run(tc.name, func(t *testing.T) {
			text := peerOnlyLoginGroup(tc.body)
			// Rejected on the node whose OWN view does not contain the body ...
			p := NewParser(text)
			tree, perrs := p.Parse()
			if len(perrs) != 0 {
				t.Fatalf("parse: %v", perrs)
			}
			_, err := CompileConfigForNode(tree, 0)
			mustReject(t, err, tc.marker, "peer-only ${node} body committed on NODE 0")

			// ... and on the node that does render it, so the verdict is
			// HA-symmetric whichever node the operator happens to commit from.
			_, err = CompileConfigForNode(tree, 1)
			mustReject(t, err, tc.marker, "peer-only ${node} body committed on NODE 1")
		})
	}

	t.Run("the peer body is caught even when the local ${node} group is undefined", func(t *testing.T) {
		// No `groups node0`, so node 0's own view fails to expand entirely. The
		// gate must still reject from the node-1 view rather than falling
		// through to the apply-groups error (which would leave the finding
		// unreported the moment an operator defines only the peer's group).
		text := `groups {
	node1 { system { login { class super-user { permissions view; } } } }
}
apply-groups "${node}";
`
		p := NewParser(text)
		tree, perrs := p.Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse: %v", perrs)
		}
		_, err := CompileConfigForNode(tree, 0)
		mustReject(t, err, gate6701ShadowMarker, "peer-only body with no local ${node} group")
	})

	t.Run("tolerant peer-sync ingress warns rather than rejecting", func(t *testing.T) {
		// #1960 no-brick: the standby must still boot a config an older binary
		// accepted. CompileConfigForNodeLenient is exactly what
		// Store.SyncApply runs.
		text := peerOnlyLoginGroup(`class super-user { permissions view; } user bob { class super-user; }`)
		p := NewParser(text)
		tree, perrs := p.Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse: %v", perrs)
		}
		cfg, err := CompileConfigForNodeLenient(tree, 0)
		if err != nil {
			t.Fatalf("tolerant peer-sync path must NOT reject (#1960 no-brick): %v", err)
		}
		var found bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, gate6701ShadowMarker) {
				found = true
			}
		}
		if !found {
			t.Fatalf("tolerant path dropped the peer-only finding entirely; warnings: %v", cfg.Warnings)
		}
	})

	t.Run("a peer-only group with a WELL-FORMED body still compiles", func(t *testing.T) {
		// The false-positive guard. A per-node login stanza is legitimate
		// configuration; only the packed and shadowing shapes are rejected.
		text := peerOnlyLoginGroup(
			`class noc-admin { permissions [ view configure ]; } user bob { class noc-admin; }`)
		p := NewParser(text)
		tree, perrs := p.Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse: %v", perrs)
		}
		for _, nodeID := range []int{0, 1} {
			if _, err := CompileConfigForNode(tree, nodeID); err != nil {
				t.Fatalf("node %d rejected a well-formed peer-only login body: %v", nodeID, err)
			}
		}
	})

	t.Run("a body in an UNAPPLIED group stays inert on both nodes", func(t *testing.T) {
		// The View-1 boundary: a shadowing class staged in a group that no
		// apply-groups references renders on no node, so rejecting it would be
		// rejecting dead config.
		text := `groups {
	unused { system { login { class super-user { permissions view; } } } }
}
system { host-name fw; }
`
		p := NewParser(text)
		tree, perrs := p.Parse()
		if len(perrs) != 0 {
			t.Fatalf("parse: %v", perrs)
		}
		for _, nodeID := range []int{0, 1} {
			if _, err := CompileConfigForNode(tree, nodeID); err != nil {
				t.Fatalf("node %d rejected an UNAPPLIED group body: %v", nodeID, err)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// #6706: the same drop at the two ANCESTOR levels of the path.
// ---------------------------------------------------------------------------

// gate6706SystemLineMarker / gate6706LoginLineMarker attribute the two
// ancestor-level arms SEPARATELY. One fixture cannot cover both — the walk
// reaches them through different branches (a `system` node that never descends,
// vs a `login` node that does) — so a single marker would let one arm regress
// while the other kept the assertion green.
const (
	gate6706SystemLineMarker = "is written on the `system` statement line"
	gate6706LoginLineMarker  = "is written on the `login` statement line"
)

// TestLoginPathPackedRejectedAtCommit_6706 is the fail-on-revert binder for the
// ancestor-level arms.
//
// The original gate walked `system` -> `login` -> `<keyword>` with forEachChild
// and FindChildren, both of which match on Keys[0]. With the path packed onto
// the `login` line that node carries Keys=["login","user","alice",...] and ZERO
// children, so FindChildren("user") returns nothing; with it packed onto the
// `system` line, sys.Children is empty and the inner walk never runs. Measured
// through configstore.CheckText (the real operator commit / commit-check
// pipeline) at the parent commit, all of these committed GREEN:
//
//	system login user alice class read-only;         -> ACCEPT, System.Login == nil
//	system { login user alice class read-only; }     -> ACCEPT, 0 users, 0 classes
//
// and the `system`-line arm is the fail-OPEN one: System.Login == nil makes
// pkg/daemon applyCLILoginClass early-return, SetUserClass is never called, and
// pkg/cli runs with an empty class — allow every command, render secrets in
// cleartext. The one level the gate DID cover (the instance line) is the
// fail-CLOSED one.
//
// FAIL-ON-REVERT: drop either `if len(...Keys) > 1` arm from
// collectLoginPackedFindings and that arm's sub-tests go RED on the assertion
// in mustReject ("compiled with NO error — the gate did not fire"); the other
// arm stays green, which is the point of splitting the markers.
func TestLoginPathPackedRejectedAtCommit_6706(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		marker string
	}{
		{
			name:   "user instance on the system line",
			text:   `system login user alice class read-only;`,
			marker: gate6706SystemLineMarker,
		},
		{
			name:   "class instance on the system line",
			text:   `system login class noc permissions view;`,
			marker: gate6706SystemLineMarker,
		},
		{
			name:   "login BLOCK hung off the system line",
			text:   `system login { user alice { class read-only; } }`,
			marker: gate6706SystemLineMarker,
		},
		{
			name:   "user BLOCK hung off the system line",
			text:   `system login user alice { class read-only; }`,
			marker: gate6706SystemLineMarker,
		},
		{
			name:   "user instance on the login line",
			text:   `system { login user alice class read-only; }`,
			marker: gate6706LoginLineMarker,
		},
		{
			name:   "class instance on the login line",
			text:   `system { login class noc permissions view; }`,
			marker: gate6706LoginLineMarker,
		},
		{
			name:   "user BLOCK hung off the login line",
			text:   `system { login user alice { class read-only; } }`,
			marker: gate6706LoginLineMarker,
		},
		{
			name: "a second, packed login block beside a well-formed one",
			// The nested `user a` is lost too: two sibling `login` nodes under
			// one `system` reduce to the LAST, so the packed line does not
			// merely fail to add bob, it wipes the stanza that worked.
			text:   `system { login { user a { class read-only; } } login user bob class ops; }`,
			marker: gate6706LoginLineMarker,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileLogin6662(t, tt.text)
			mustReject(t, err, tt.marker, "ancestor-level packed `system login` path")
			if !strings.Contains(err.Error(), "#6662") {
				t.Errorf("rejection does not cite the issue: %v", err)
			}
		})
	}
}

// TestLoginPathPackedRejectionIsPasteable_6706 pins the rewrite. The operator
// is mid-migration from a vSRX config; a rejection that does not hand back a
// working spelling just moves the guesswork.
func TestLoginPathPackedRejectionIsPasteable_6706(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		wantSet string
	}{
		{
			name:    "system line reconstructs the full set path",
			text:    `system login user alice class read-only;`,
			wantSet: "set system login user alice class read-only",
		},
		{
			name:    "login line reconstructs the full set path",
			text:    `system { login class noc permissions view; }`,
			wantSet: "set system login class noc permissions view",
		},
		{
			name: "a multi-word instance name stays ONE token",
			// A bare strings.Join would render `set system login class noc ops
			// idle-timeout 5`, which is a different (invalid) configuration.
			text:    `system { login class "noc ops" idle-timeout 5; }`,
			wantSet: `set system login class "noc ops" idle-timeout 5`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileLogin6662(t, tt.text)
			if err == nil {
				t.Fatalf("gate did not fire")
			}
			if !strings.Contains(err.Error(), tt.wantSet) {
				t.Fatalf("rejection does not offer the pasteable rewrite %q:\n  %v",
					tt.wantSet, err)
			}
		})
	}
}

// TestLoginPathPackedNamesTheRBACCost_6706 pins the CONSEQUENCE clause per arm.
// The two ancestor levels do NOT fail the same way and the message must not
// claim they do: `system`-line packing yields System.Login == nil, which is
// pkg/cli's legacy no-RBAC allow-everything shortcut, while `login`-line
// packing yields a non-nil but EMPTY stanza, where ResolveLoginClass falls to
// the fail-closed `unauthorized` class. Stating the permissive outcome on the
// fail-closed arm (or the reverse) would send the operator to the wrong
// urgency.
func TestLoginPathPackedNamesTheRBACCost_6706(t *testing.T) {
	t.Run("system line names the allow-everything outcome", func(t *testing.T) {
		_, err := compileLogin6662(t, `system login user alice class read-only;`)
		if err == nil {
			t.Fatalf("gate did not fire")
		}
		for _, want := range []string{"System.Login == nil", "CLEARTEXT", "DEPROVISIONED"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("system-line rejection omits %q:\n  %v", want, err)
			}
		}
	})

	t.Run("login line names the fail-closed lockout, not a promotion", func(t *testing.T) {
		_, err := compileLogin6662(t, `system { login user alice class read-only; }`)
		if err == nil {
			t.Fatalf("gate did not fire")
		}
		for _, want := range []string{"`unauthorized`", "DEPROVISIONED"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("login-line rejection omits %q:\n  %v", want, err)
			}
		}
		if strings.Contains(err.Error(), "CLEARTEXT") {
			t.Errorf("login-line rejection claims the allow-everything outcome, which belongs "+
				"to the `system`-line arm (this arm compiles a PRESENT but empty stanza, so "+
				"ResolveLoginClass fails closed):\n  %v", err)
		}
	})
}

// TestLoginPathPackedLenientWarns_6706 covers the tolerant load / peer-sync
// ingress. A strict-only fix re-creates the #1960 brick: a node that persisted
// such a config under an older binary must still BOOT, with the drop stated.
//
// FAIL-ON-REVERT: wire either arm to report unconditionally rather than through
// loginFindings (or gate it on !lenient) and these go RED on the missing
// warning, while the strict tests above stay green.
func TestLoginPathPackedLenientWarns_6706(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		marker string
	}{
		{"system line", `system login user alice class read-only;`, gate6706SystemLineMarker},
		{"login line", `system { login user alice class read-only; }`, gate6706LoginLineMarker},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := compileLogin6662Lenient(t, tt.text)
			if err != nil {
				t.Fatalf("tolerant path must NOT reject (#1960 no-brick): %v", err)
			}
			var found string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tt.marker) {
					found = w
				}
			}
			if found == "" {
				t.Fatalf("tolerant path emitted no warning containing %q; warnings: %v",
					tt.marker, cfg.Warnings)
			}
			if !strings.Contains(found, "#6662") {
				t.Errorf("warning does not cite the issue: %q", found)
			}
		})
	}
}

// TestLoginPathPackedRejectedFromBothNodeViews_6706 extends the #6706 both-node
// contract to the ancestor arms: a peer-only `${node}` group carrying a packed
// path must be rejected whichever node the operator commits from, or the origin
// commits green and the peer ingests it through the tolerant sync path.
//
// peerOnlyLoginGroup nests the body inside `system { login { ... } }`, which is
// the wrong wrapper for an ancestor-level fixture (it would produce an INSTANCE
// -level packing), so this builds the group body directly.
func TestLoginPathPackedRejectedFromBothNodeViews_6706(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		marker string
	}{
		{
			name:   "system line in a peer-only ${node} group",
			body:   `system login user bob class read-only;`,
			marker: gate6706SystemLineMarker,
		},
		{
			name:   "login line in a peer-only ${node} group",
			body:   `system { login user bob class read-only; }`,
			marker: gate6706LoginLineMarker,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := `groups {
	node0 { system { host-name fw0; } }
	node1 { ` + tt.body + ` }
}
apply-groups "${node}";
`
			p := NewParser(text)
			tree, perrs := p.Parse()
			if len(perrs) != 0 {
				t.Fatalf("parse: %v", perrs)
			}
			for _, nodeID := range []int{0, 1} {
				_, err := CompileConfigForNode(tree, nodeID)
				mustReject(t, err, tt.marker,
					"peer-only ${node} packed path committed on a node")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// #6706 over-reach guards: what the ancestor arms must NOT reject.
// These stay GREEN under the revert of either arm — they assert the behaviour
// the fix did not intend to change, so they separate a guard from a restatement
// of the fix.
// ---------------------------------------------------------------------------

// TestLoginPathPackedDoesNotOverReach_6706 pins the accept side.
// ROLE: POSITIVE CONTROL — the boundary of what the gate may reject. Measured, not assumed: disabling
// validateLoginPackedStatementsAST entirely leaves this test GREEN (#6706
// review r11), so it binds no gate behaviour and must not be counted as gate
// coverage. It is kept because a gate with no over-reach control is one
// widening away from rejecting valid configuration.
func TestLoginPathPackedDoesNotOverReach_6706(t *testing.T) {
	t.Run("the nested spelling still compiles", func(t *testing.T) {
		cfg, err := compileLogin6662(t, `system {
		login {
			class noc { permissions [ view configure ]; }
			user alice { class noc; }
		}
	}`)
		if err != nil {
			t.Fatalf("the correct spelling was rejected: %v", err)
		}
		if len(cfg.System.Login.Users) != 1 || cfg.System.Login.Users[0].Class != "noc" {
			t.Fatalf("nested spelling did not compile: %+v", cfg.System.Login)
		}
	})

	t.Run("a user CONTAINER block still compiles", func(t *testing.T) {
		// `user { alice { ... } }` — the identity-1 shape the instance arm
		// branches on. The `user` node has one key, so no ancestor arm applies.
		cfg, err := compileLogin6662(t, `system { login { user { alice { class read-only; } } } }`)
		if err != nil {
			t.Fatalf("container spelling was rejected: %v", err)
		}
		if len(cfg.System.Login.Users) != 1 || cfg.System.Login.Users[0].Name != "alice" {
			t.Fatalf("container spelling did not compile: %+v", cfg.System.Login)
		}
	})

	t.Run("a user literally NAMED login still compiles", func(t *testing.T) {
		// The `system` arm branches on Keys[1] == "login" and the `login` arm
		// on the node's own key count, so neither can be tripped by an
		// instance whose NAME collides with a path keyword.
		cfg, err := compileLogin6662(t, `system { login { user login { class read-only; } } }`)
		if err != nil {
			t.Fatalf("a user named `login` was rejected: %v", err)
		}
		if len(cfg.System.Login.Users) != 1 || cfg.System.Login.Users[0].Name != "login" {
			t.Fatalf("user named `login` did not compile: %+v", cfg.System.Login)
		}
	})

	t.Run("a non-login system statement line is not this gate's business", func(t *testing.T) {
		// `system host-name fw1;` is dropped by the compiler too (an adjacent
		// defect, filed separately), but it is NOT an RBAC fail-open and this
		// gate must not claim it. Rejecting every packed `system` key would
		// turn one gate into an unbounded one.
		if _, err := compileLogin6662(t, `system host-name fw1;`); err != nil {
			t.Fatalf("gate reached beyond `system login`: %v", err)
		}
	})

	t.Run("an empty path prefix names no instance and is not rejected", func(t *testing.T) {
		// A prefix that stops before an instance name declares no user and no
		// class, so there is nothing dropped to report and a gate that rejected
		// it would be rejecting config master accepts. That accept assertion is
		// the over-reach control and it stands.
		//
		// The RATIONALE this subtest used to carry did not: it said the two
		// spellings "compile to nothing in BOTH spellings, so no statement was
		// dropped", which made it a positive control PROTECTING A FALSE AND
		// PERMISSIVE INVARIANT (#6706 review r11). Measured, they diverge, and
		// in the fail-OPEN direction — so the divergence is asserted here
		// rather than denied.
		for _, text := range []string{`system login;`, `system login user;`, `system { login user; }`} {
			if _, err := compileLogin6662(t, text); err != nil {
				t.Fatalf("%q names no instance yet was rejected: %v", text, err)
			}
		}

		// The divergence itself, in both directions, so neither half can drift.
		nested, err := compileLogin6662(t, `system { login; }`)
		if err != nil {
			t.Fatalf("`system { login; }` rejected: %v", err)
		}
		if nested.System.Login == nil {
			t.Fatal("`system { login; }` compiled System.Login == nil; the whole point of " +
				"this assertion is that the NESTED spelling compiles a present-but-empty " +
				"LoginConfig, which is what makes every non-root caller resolve to " +
				"`unauthorized`")
		}
		packed, err := compileLogin6662(t, `system login;`)
		if err != nil {
			t.Fatalf("`system login;` rejected: %v", err)
		}
		if packed.System.Login != nil {
			t.Fatal("`system login;` compiled a non-nil System.Login; if the compiler " +
				"was taught to descend a packed path, this subtest's premise — and the " +
				"LoginDroppedByPacking posture that compensates for it — need revisiting")
		}

		// And the flag that makes the two agree at RUNTIME, which is where the
		// divergence is actually closed (pkg/daemon applyCLILoginClass). Without
		// it, `system login;` reaches pkg/cli's legacy unset-class mode: every
		// command permitted, secrets in cleartext.
		for _, text := range []string{`system login;`, `system login user;`} {
			cfg, err := compileLogin6662(t, text)
			if err != nil {
				t.Fatalf("%q rejected: %v", text, err)
			}
			if !cfg.System.LoginDroppedByPacking {
				t.Fatalf("%q left LoginDroppedByPacking false — the daemon would then take "+
					"its legacy unset-class early return, which is the fail-open the "+
					"nested spelling of the same text does not have", text)
			}
		}
		// NEGATIVE CONTROL for the flag: a correctly nested stanza must not set
		// it, or every deployment would be forced into the resolver.
		ok, err := compileLogin6662(t, `system { login { user alice { class ops; } } }`)
		if err != nil {
			t.Fatalf("nested stanza rejected: %v", err)
		}
		if ok.System.LoginDroppedByPacking {
			t.Fatal("a correctly nested `system login` set LoginDroppedByPacking")
		}
	})

	t.Run("flat set still compiles every leaf", func(t *testing.T) {
		// The flat-set ingress hangs the body off as CHILDREN at every level,
		// so no packed shape arises. If an arm ever matched here the whole
		// `set` grammar would become uncommittable.
		cfg, err := compileLogin6662FlatSet(t,
			"set system login class noc permissions view",
			"set system login user alice class noc",
			`set system login user alice authentication ssh-rsa "ssh-rsa AAAA k"`)
		if err != nil {
			t.Fatalf("flat set was rejected: %v", err)
		}
		if len(cfg.System.Login.Users) != 1 || cfg.System.Login.Users[0].Class != "noc" {
			t.Fatalf("flat-set user did not compile: %+v", cfg.System.Login)
		}
		if len(cfg.System.Login.Users[0].SSHKeys) != 1 {
			t.Fatalf("flat-set ssh key did not compile: %+v", cfg.System.Login.Users[0])
		}
	})

	t.Run("deactivated config stays accepted", func(t *testing.T) {
		// `inactive:` subtrees are pruned by cloneForExpansion before any gate
		// runs, so an operator can park a stanza the gate would otherwise
		// reject. A gate that rejected deactivated config is its own outage.
		for _, text := range []string{
			`inactive: system login user alice class read-only;`,
			`system { inactive: login user alice class read-only; }`,
			`system { inactive: login { user alice class read-only; } }`,
			`system { login { inactive: user alice class ops; } }`,
		} {
			if _, err := compileLogin6662(t, text); err != nil {
				t.Fatalf("deactivated config was rejected: %q\n  %v", text, err)
			}
		}
	})
}

// TestLoginClassShadowSkipsInstanceLineChildren_6706 pins the shadow gate's
// half of the fix, in BOTH directions.
//
// `system { login user alice { class super-user; } }` puts the USER on the
// login line, so login.Children hold that user's body. The shadow walk read the
// `class super-user;` ASSIGNMENT there as a class DEFINITION and rejected with
// "system login class super-user: this definition is INERT" — naming a
// definition the operator never wrote, and sending them to rename a class that
// does not exist. It now skips a login node carrying extra keys.
//
// The stanza must STILL be rejected — by the ancestor arm, which diagnoses the
// real defect — so this is not a rejection removed, it is a rejection
// re-attributed. Asserting only "no longer says INERT" would pass if the whole
// stanza had started committing green.
//
// The STRICT path cannot bind the skip on its own: compileTree runs
// the packed gate before the shadow gate and returns on its first error, so
// with the skip reverted strict still surfaces the packed message and a
// strict-only assertion stays green. The observable difference is on the
// TOLERANT path, where both gates run and accumulate — which is also where it
// matters operationally, since that is the boot log of a node that persisted
// such a config. Hence the lenient leg below.
func TestLoginClassShadowSkipsInstanceLineChildren_6706(t *testing.T) {
	const instanceLine = `system { login user alice { class super-user; } }`

	_, err := compileLogin6662(t, instanceLine)
	mustReject(t, err, gate6706LoginLineMarker, "user instance on the login line")

	// FAIL-ON-REVERT for the shadow-gate skip: drop the `len(login.Keys) > 1`
	// early return from collectLoginClassShadowFindings and this goes RED.
	cfg, lerr := compileLogin6662Lenient(t, instanceLine)
	if lerr != nil {
		t.Fatalf("tolerant path must NOT reject (#1960 no-brick): %v", lerr)
	}
	var sawPacked bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, gate6701ShadowMarker) {
			t.Errorf("the shadow gate misread a user's class ASSIGNMENT as a class "+
				"DEFINITION — it names `class super-user` as INERT config the operator "+
				"never wrote:\n  %s", w)
		}
		if strings.Contains(w, gate6706LoginLineMarker) {
			sawPacked = true
		}
	}
	if !sawPacked {
		t.Fatalf("the tolerant path lost the real finding while suppressing the bogus one; "+
			"warnings: %v", cfg.Warnings)
	}

	// The genuine shadowing definition, one level in, still rejects — the skip
	// must not have disabled the shadow gate wholesale.
	_, err = compileLogin6662(t, `system { login { class super-user { permissions view; } } }`)
	mustReject(t, err, gate6701ShadowMarker, "a real shadowing class definition")
}
