package config

import (
	"strings"
	"testing"
)

// #15782: multiple license autoupdate URLs, inert warning, retained not truncated.

func TestLicenseMultiURLRetained15782(t *testing.T) {
	tree := buildTree(t, []string{
		"set system license autoupdate url https://a.example/keys",
		"set system license autoupdate url https://b.example/keys",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.System.LicenseAutoUpdateURLs) != 2 {
		t.Fatalf("URLs = %v, want 2 retained", cfg.System.LicenseAutoUpdateURLs)
	}
	if cfg.System.LicenseAutoUpdate != "https://a.example/keys" {
		t.Errorf("scalar = %q want first", cfg.System.LicenseAutoUpdate)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "license autoupdate") && strings.Contains(w, "NOT") {
			found = true
		}
	}
	if !found {
		t.Errorf("no inert-knob warning, warnings=%v", cfg.Warnings)
	}
}

func TestLicenseMultiURLHier15782(t *testing.T) {
	src := "system { license { autoupdate { url https://a.example/k; url https://b.example/k; } } }"
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.System.LicenseAutoUpdateURLs) != 2 {
		t.Fatalf("hier URLs = %v want 2", cfg.System.LicenseAutoUpdateURLs)
	}
}

func TestLicenseSingleNoSpuriousMulti15782(t *testing.T) {
	tree := buildTree(t, []string{"set system license autoupdate url https://a.example/keys"})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.System.LicenseAutoUpdateURLs) != 1 {
		t.Fatalf("URLs=%v want 1", cfg.System.LicenseAutoUpdateURLs)
	}
}

func TestLicenseBracketURLListRetained15782(t *testing.T) {
	tree := buildTree(t, []string{
		"set system license autoupdate url [ https://a.example/keys https://b.example/keys ]",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.System.LicenseAutoUpdateURLs) != 2 {
		t.Fatalf("bracket URLs = %v, want 2 retained", cfg.System.LicenseAutoUpdateURLs)
	}
}
