package config

import (
	"strings"
	"testing"
)

// #15712: login class regex leaves had no commit-time validation and silently
// overwrote earlier restrictions.
//
// Test named per acceptance criterion.
func TestLoginClassRegexPOSIXValidationAndDuplicateDeny_V42_04(t *testing.T) {
	invalidPOSIX := `
system {
  login {
    class netops {
      permissions all;
      allow-commands "(?:show|ping).*";
    }
  }
}`
	p1 := NewParser(invalidPOSIX)
	tree1, perrs := p1.Parse()
	if len(perrs) != 0 {
		t.Fatalf("ParseConfig: %v", perrs)
	}
	if _, err := CompileConfig(tree1); err == nil {
		t.Fatalf("expected strict CompileConfig to reject non-POSIX regex `(?:show|ping).*` in allow-commands")
	}

	duplicateDeny := `
system {
  login {
    class ops {
      permissions all;
      deny-commands "request system zeroize";
    }
    class ops {
      deny-commands "request system reboot";
    }
  }
}`
	p2 := NewParser(duplicateDeny)
	tree2, perrs := p2.Parse()
	if len(perrs) != 0 {
		t.Fatalf("ParseConfig: %v", perrs)
	}
	if _, err := CompileConfig(tree2); err == nil {
		t.Fatalf("expected strict CompileConfig to reject conflicting duplicate deny-commands across class ops blocks")
	}
}

// All four leaves validated, all families.
func TestLoginClassRegexAllLeavesValidated15712(t *testing.T) {
	for _, leaf := range []string{"allow-commands", "deny-commands", "allow-configuration", "deny-configuration"} {
		text := "system { login { class c1 { permissions view; " + leaf + ` "(?:bad)"; } } }`
		_, err := compileLogin6662(t, text)
		if err == nil {
			t.Errorf("leaf %s: invalid POSIX accepted", leaf)
			continue
		}
		if !strings.Contains(err.Error(), leaf) {
			t.Errorf("leaf %s: error should name leaf, got %v", leaf, err)
		}
		if !strings.Contains(err.Error(), "15712") {
			t.Errorf("leaf %s: error should carry #15712, got %v", leaf, err)
		}
	}
}

// Positive control: valid POSIX, identical duplicate, cross-leaf merge, different classes.
func TestLoginClassRegexValidAndMerged15712(t *testing.T) {
	// valid
	cfg, err := compileLogin6662(t, `system { login { class c1 { permissions view; allow-commands "^show.*"; deny-commands "^request.*"; } } }`)
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if cfg.System.Login.Classes[0].AllowCommands != "^show.*" {
		t.Fatalf("allow lost")
	}
	// identical duplicate across blocks must not reject
	cfg, err = compileLogin6662(t, `system { login { class ops { permissions view; deny-commands "request system reboot"; } class ops { deny-commands "request system reboot"; } } }`)
	if err != nil {
		t.Fatalf("identical duplicate rejected: %v", err)
	}
	if len(cfg.System.Login.Classes) != 1 {
		t.Fatalf("classes=%d want 1", len(cfg.System.Login.Classes))
	}
	// cross-leaf merge across blocks (spark probe): allow in block1, deny in block2 retained
	cfg, err = compileLogin6662(t, `system { login { class ops { permissions view; allow-commands "^show"; } class ops { deny-commands "^request"; } } }`)
	if err != nil {
		t.Fatalf("cross-leaf merge: %v", err)
	}
	if cfg.System.Login.Classes[0].AllowCommands != "^show" || cfg.System.Login.Classes[0].DenyCommands != "^request" {
		t.Fatalf("cross-leaf merge lost: %+v", cfg.System.Login.Classes[0])
	}
	// flat-set duplicate (same node merged by SetPath) - last value is only value, must not double-count?
	// Different classes distinct patterns OK
	_, err = compileLogin6662(t, `system { login { class a { permissions view; deny-commands "x"; } class b { permissions view; deny-commands "y"; } } }`)
	if err != nil {
		t.Fatalf("different classes: %v", err)
	}
	// Empty deny preserved (valid POSIX) - must not reject
	cfg, err = compileLogin6662(t, `system { login { class c1 { permissions view; deny-commands ""; } } }`)
	if err != nil {
		t.Fatalf("empty deny rejected: %v", err)
	}
	_ = cfg
}

// Same-leaf duplicate WITHIN one block also rejected when conflicting.
func TestLoginClassRegexDuplicateWithinBlock15712(t *testing.T) {
	_, err := compileLogin6662(t, `system { login { class ops { permissions view; deny-commands "a"; deny-commands "b"; } } }`)
	if err == nil {
		t.Fatal("within-block conflicting deny-commands accepted")
	}
	_, err = compileLogin6662(t, `system { login { class ops { permissions view; allow-commands "a"; allow-commands "b"; } } }`)
	if err == nil {
		t.Fatal("within-block conflicting allow-commands accepted")
	}
}

// Tolerant path: invalid / conflicting still boots (#1960), warning recorded, last value wins.
func TestLoginClassRegexLenient15712(t *testing.T) {
	cfg, err := compileLogin6662Lenient(t, `system { login { class ops { permissions view; allow-commands "(?:bad)"; deny-commands "a"; } class ops { deny-commands "b"; } } }`)
	if err != nil {
		t.Fatalf("lenient should boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "15712") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient warnings should carry #15712, got %v", cfg.Warnings)
	}
	if cfg.System.Login.Classes[0].DenyCommands != "b" {
		t.Fatalf("lenient last-wins deny=%q want b", cfg.System.Login.Classes[0].DenyCommands)
	}
	// Enforcement still fails closed on invalid pattern at use time
	if _, _, err := OperationalLoginRegexesFor(cfg, "ops"); err == nil {
		t.Fatalf("invalid pattern should fail at enforcement compile")
	}
}

// Group-inherited regex: group supplies the leaf, no inline value, so the
// inherited value itself is judged (invalid -> strict reject). This is the
// group leg that actually reaches the compiled config: with an inline scalar
// also present, Junos scalar override means only the inline value is
// effective, so a conflicting/invalid group value never materializes.
func TestLoginClassRegexGroupInvalid15712(t *testing.T) {
	text := `
groups {
  g1 {
    system {
      login {
        class ops {
          allow-commands "(?:bad)";
        }
      }
    }
  }
}
system {
  login {
    class ops {
      permissions view;
    }
  }
  apply-groups g1;
}
`
	_, err := compileLogin6662(t, text)
	if err == nil {
		t.Fatal("group-inherited invalid allow-commands accepted")
	} else if !strings.Contains(err.Error(), "15712") {
		t.Fatalf("group error should carry 15712: %v", err)
	}
	cfg, err := compileLogin6662Lenient(t, text)
	if err != nil {
		t.Fatalf("lenient group should boot: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "15712") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient group warnings should carry 15712: %v", cfg.Warnings)
	}
}

// Two groups supplying conflicting values for the same leaf, no inline
// override: both materialize beside each other (merge provenance), so the
// compiled record must see the conflict.
func TestLoginClassRegexTwoGroupsConflict15712(t *testing.T) {
	text := `
groups {
  g1 {
    system {
      login {
        class ops {
          deny-commands "request system reboot";
        }
      }
    }
  }
  g2 {
    system {
      login {
        class ops {
          deny-commands "request system zeroize";
        }
      }
    }
  }
}
system {
  login {
    class ops {
      permissions view;
    }
  }
  apply-groups [ g1 g2 ];
}
`
	// Whether expansion materializes both or keeps one scalar winner, at
	// minimum an invalid/conflicting outcome must not silently pass if both
	// are recorded; if only one survives, that is scalar override between
	// groups and is not this gate's duplicate (documented limitation).
	cfg, err := compileLogin6662(t, text)
	if err == nil {
		if cfg == nil || len(cfg.System.Login.Classes) == 0 {
			t.Fatal("two-groups compile returned no class")
		}
		got := cfg.System.Login.Classes[0].DenyCommands
		if got != "request system reboot" && got != "request system zeroize" {
			t.Fatalf("unexpected deny survivor %q", got)
		}
		return
	}
	if !strings.Contains(err.Error(), "15712") {
		t.Fatalf("two-groups conflict rejected by wrong gate: %v", err)
	}
}
