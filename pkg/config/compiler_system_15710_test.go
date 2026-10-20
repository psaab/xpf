package config

import "testing"

// #15710 regression tests: multi-stanza archival/root-auth merge is
// covered by #15018 for the braced spelling; the remaining legs are
// (a) multiple `configuration` blocks under ONE `archival`, (b) the
// compact `configuration transfer-on-commit` spelling, (c) compact
// `system no-redirects`, and (d) packed multi-value transfer-interval
// last-wins. Each leg was probed failing on the pre-fix code.

func compile15710(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse error for %q: %v", text, perrs[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile failed for %q: %v", text, err)
	}
	return cfg
}

func TestArchivalMultipleConfigurationBlocksMerge15710(t *testing.T) {
	cfg := compile15710(t, `system {
 archival {
  configuration { transfer-on-commit; }
  configuration {
   transfer-interval 30;
   archive-sites { "scp://backup@10.0.0.1:/configs"; }
  }
 }
}`)
	arch := cfg.System.Archival
	if arch == nil {
		t.Fatal("Archival is nil")
	}
	if !arch.TransferOnCommit {
		t.Error("TransferOnCommit lost: first configuration block wiped by second")
	}
	if arch.TransferInterval != 30 {
		t.Errorf("TransferInterval = %d, want 30", arch.TransferInterval)
	}
	if len(arch.ArchiveSites) != 1 || arch.ArchiveSites[0] != "scp://backup@10.0.0.1:/configs" {
		t.Errorf("ArchiveSites = %v, want second block's site", arch.ArchiveSites)
	}
}

func TestArchivalTransferIntervalLastWins15710(t *testing.T) {
	cfg := compile15710(t, `system {
 archival {
  configuration { transfer-interval 10; }
  configuration { transfer-interval 30; }
 }
}`)
	if cfg.System.Archival == nil || cfg.System.Archival.TransferInterval != 30 {
		t.Errorf("TransferInterval = %+v, want last-wins 30", cfg.System.Archival)
	}
	// Packed run inside one configuration block: last value wins too.
	cfg = compile15710(t, "system { archival { configuration { transfer-interval 10 transfer-interval 30; } } }")
	if cfg.System.Archival == nil || cfg.System.Archival.TransferInterval != 30 {
		t.Errorf("packed TransferInterval = %+v, want last-wins 30", cfg.System.Archival)
	}
}

func TestArchivalCompactTransferOnCommit15710(t *testing.T) {
	for name, text := range map[string]string{
		"braced":          "system { archival { configuration { transfer-on-commit; } } }",
		"compact":         "system { archival { configuration transfer-on-commit; } }",
		"elided archival": "system { archival configuration { transfer-on-commit; } }",
		"fully compact":   "system archival configuration transfer-on-commit;",
	} {
		cfg := compile15710(t, text)
		if cfg.System.Archival == nil || !cfg.System.Archival.TransferOnCommit {
			t.Errorf("%s (%q): TransferOnCommit = %+v, want true", name, text, cfg.System.Archival)
		}
	}
}

func TestSystemNoRedirectsCompact15710(t *testing.T) {
	for name, text := range map[string]string{
		"braced":  "system { no-redirects; }",
		"compact": "system no-redirects;",
	} {
		cfg := compile15710(t, text)
		if !cfg.System.NoRedirects {
			t.Errorf("%s (%q): NoRedirects = false, want true", name, text)
		}
	}
	// Control: no stanza -> false.
	if cfg := compile15710(t, "system { host-name fw1; }"); cfg.System.NoRedirects {
		t.Error("NoRedirects set without the stanza")
	}
}

func TestRepeatedRootAuthCompactAndBracedAgree15710(t *testing.T) {
	// Multi-stanza braced merge is #15018; this pins that a compact
	// first block plus a braced second block merge the same way.
	cfg := compile15710(t, "system {\n"+
		" root-authentication encrypted-password \""+rootAuthHash15018+"\";\n"+
		" root-authentication { ssh-ed25519 \""+rootAuthKey1_15018+"\"; }\n"+
		"}")
	wantRootAuth15018(t, cfg, rootAuthHash15018, 1)
}
