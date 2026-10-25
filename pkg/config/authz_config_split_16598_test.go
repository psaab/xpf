package config

import (
	"strings"
	"testing"
)

// #16598: a flat `set` line the store splits at schema arity into several
// statements was adjudicated as one joined path, so a deny on a later
// statement was bypassed.

const splitLine16598 = "set system domain-search attacker.example login user evil class super-user"

func TestSplitSetLineDenied16598(t *testing.T) {
	for _, deny := range []string{`^system login`, `system login`, `^system root-authentication`} {
		cfg := classWithConfigRegex9154(t, "", deny)
		// Premise: the lone second statement is denied.
		lone := "set system login user evil class super-user"
		if deny == `^system root-authentication` {
			lone = "set system root-authentication plain-text-password-value x"
		}
		if err := AuthorizeConfigMutation(cfg, "limited", nil, lone); err == nil {
			t.Fatalf("deny %q: premise failed, lone denied statement allowed", deny)
		}
		line := splitLine16598
		if deny == `^system root-authentication` {
			line = "set system domain-search a.example root-authentication plain-text-password-value x"
		}
		if err := AuthorizeConfigMutation(cfg, "limited", nil, line); err == nil {
			t.Errorf("deny %q: split line %q ALLOWED; the store executes it as two statements and the later one is denied (#16598)", deny, line)
		} else if strings.Contains(err.Error(), "attacker") || strings.Contains(err.Error(), "evil") {
			t.Errorf("deny %q: error leaked operator path data: %v", deny, err)
		}
	}
}

func TestSplitSetLineAllowedControl16598(t *testing.T) {
	cfg := classWithConfigRegex9154(t, "", `^system login`)
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "set system domain-search attacker.example"); err != nil {
		t.Errorf("single domain-search set refused: %v", err)
	}
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "set system domain-search a.example domain-search b.example"); err != nil {
		t.Errorf("split into two allowed domain-search statements refused: %v", err)
	}
	// Positive control from probe: substring deny present in joined string also refuses split (already did pre-fix, must stay).
	cfg2 := classWithConfigRegex9154(t, "", `login`)
	if err := AuthorizeConfigMutation(cfg2, "limited", nil, splitLine16598); err == nil {
		t.Error("deny `login`: split line allowed")
	}
}

func TestSplitSetLineAllowConfiguration16598(t *testing.T) {
	cfg := classWithConfigRegex9154(t, `^system domain-search`, "")
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "set system login user evil class super-user"); err == nil {
		t.Fatal("premise: out-of-scope lone line allowed under allowlist")
	}
	if err := AuthorizeConfigMutation(cfg, "limited", nil, splitLine16598); err == nil {
		t.Error("allow ^system domain-search: split line ALLOWED though second executed statement is outside allow (#16598)")
	}
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "set system domain-search attacker.example"); err != nil {
		t.Errorf("in-scope domain-search refused under allow: %v", err)
	}
}

func TestSplitSetLineEditPath16598(t *testing.T) {
	cfg := classWithConfigRegex9154(t, "", `^system login`)
	if err := AuthorizeConfigMutation(cfg, "limited", []string{"system"}, "set domain-search attacker.example login user evil class super-user"); err == nil {
		t.Error("edit-path split line ALLOWED (#16598)")
	}
	if err := AuthorizeConfigMutation(cfg, "limited", []string{"system"}, "set domain-search attacker.example"); err != nil {
		t.Errorf("edit-path single allowed refused: %v", err)
	}
}

func TestSplitSetLineLoad16598(t *testing.T) {
	for _, deny := range []string{`^system login`, `system login`} {
		cfg := classWithConfigRegex9154(t, "", deny)
		for _, mode := range []string{"set", "merge"} {
			if err := AuthorizeConfigLoad(cfg, "limited", mode, splitLine16598); err == nil {
				t.Errorf("deny %q load %s: flat split line ALLOWED (#16598)", deny, mode)
			}
			if err := AuthorizeConfigLoad(cfg, "limited", mode, "set system domain-search attacker.example"); err != nil {
				t.Errorf("deny %q load %s: allowed domain-search refused: %v", deny, mode, err)
			}
			if err := AuthorizeConfigLoad(cfg, "limited", mode, "set system login user evil class super-user"); err == nil {
				t.Errorf("deny %q load %s: lone denied line allowed (premise)", deny, mode)
			}
		}
		// Hierarchical form was already denied; must stay.
		if err := AuthorizeConfigLoad(cfg, "limited", "merge", "system { domain-search attacker.example; login { user evil { class super-user; } } }"); err == nil {
			t.Errorf("deny %q: hierarchical split ALLOWED", deny)
		}
	}
	allowCfg := classWithConfigRegex9154(t, `^system domain-search`, "")
	if err := AuthorizeConfigLoad(allowCfg, "limited", "set", splitLine16598); err == nil {
		t.Error("allow ^system domain-search: flat load split line ALLOWED (#16598)")
	}
	// LoadMutationLines renders the executed statements.
	lines, err := LoadMutationLines(splitLine16598)
	if err != nil {
		t.Fatalf("LoadMutationLines: %v", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "set system login user evil class super-user") {
		t.Errorf("LoadMutationLines did not render executed login statement: %q", lines)
	}
	if !strings.Contains(joined, "set system domain-search attacker.example") {
		t.Errorf("LoadMutationLines did not render executed domain-search statement: %q", lines)
	}
}

func TestSplitSetLineCredentialSurcharge16598(t *testing.T) {
	// A configure class with NO *-configuration regexes (so the regex
	// loop never runs) is still fenced by #16080: the executed
	// root-authentication statement must hit the credential surcharge.
	cfg := classWithConfigRegex9154(t, "", "")
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "set system domain-search a.example"); err != nil {
		t.Errorf("allowed domain-search refused for no-regex class: %v", err)
	}
	if err := AuthorizeConfigMutation(cfg, "limited", nil, "set system domain-search a.example root-authentication plain-text-password-value x"); err == nil {
		t.Error("split root-authentication ALLOWED for PermConfig class without PermAll (#16598/#16080)")
	}
}
