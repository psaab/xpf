package config

import (
	"strings"
	"testing"
)

// #15708: system syslog file/user lacked packedBodyChildren expansion and
// same-name coalescing enjoyed by host (#6684/#9854).

func TestSyslogFileUserPacked15708(t *testing.T) {
	tree := parseHierarchical(t, `system { syslog { file authlog authorization info; user * any emergency; } }`)
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate packed: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.Syslog == nil || len(cfg.System.Syslog.Files) != 1 {
		t.Fatalf("files=%+v", cfg.System.Syslog)
	}
	if got := cfg.System.Syslog.Files[0].Selectors; len(got) != 1 || got[0] != (SyslogFacility{Facility: "authorization", Severity: "info"}) {
		t.Fatalf("file selectors=%+v want authorization/info", got)
	}
	if len(cfg.System.Syslog.Users) != 1 {
		t.Fatalf("users=%+v", cfg.System.Syslog.Users)
	}
	if got := cfg.System.Syslog.Users[0].Selectors; len(got) != 1 || got[0] != (SyslogFacility{Facility: "any", Severity: "emergency"}) {
		t.Fatalf("user selectors=%+v want any/emergency", got)
	}
}

func TestSyslogFileUserPackedInvalidSeverity15708(t *testing.T) {
	tree := parseHierarchical(t, `system { syslog { file authlog authorization bogus; } }`)
	if err := SchemaValidate(tree, nil); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("SchemaValidate packed bogus severity = %v, want rejection naming bogus", err)
	}
	tree2 := parseHierarchical(t, `system { syslog { user bob daemon bogus; } }`)
	if err := SchemaValidate(tree2, nil); err == nil {
		t.Fatalf("SchemaValidate user packed bogus severity accepted")
	}
}

func TestSyslogFileUserCoalesce15708(t *testing.T) {
	tree := parseHierarchical(t, `system { syslog {
		file messages { any notice; }
		file messages { auth info; any notice; archive { size 10m; } }
		user bob { daemon info; }
		user bob { any emergency; daemon info; }
	} }`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	sl := cfg.System.Syslog
	if sl == nil || len(sl.Files) != 1 {
		t.Fatalf("files=%+v want 1 coalesced", sl)
	}
	if got := selectorPairs(sl.Files[0].Selectors); got != "any.notice auth.info" {
		t.Fatalf("file selectors=%q want deduped union", got)
	}
	if !sl.Files[0].ArchiveConfigured {
		t.Fatalf("ArchiveConfigured not merged")
	}
	foundSize := false
	for _, k := range sl.Files[0].ArchiveKnobs {
		if k == "size" {
			foundSize = true
		}
	}
	if !foundSize {
		t.Fatalf("ArchiveKnobs=%v want size", sl.Files[0].ArchiveKnobs)
	}
	if len(sl.Users) != 1 {
		t.Fatalf("users=%+v want 1 coalesced", sl.Users)
	}
	if got := selectorPairs(sl.Users[0].Selectors); got != "daemon.info any.emergency" {
		t.Fatalf("user selectors=%q want deduped union", got)
	}
}

func TestSyslogFileModifierOnlyNoSelectors15708(t *testing.T) {
	tree := parseHierarchical(t, `system { syslog { file messages { archive { size 10m; } } } }`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.System.Syslog.Files) != 1 || len(cfg.System.Syslog.Files[0].Selectors) != 0 {
		t.Fatalf("modifier-only file=%+v want 0 selectors", cfg.System.Syslog.Files)
	}
	if !cfg.System.Syslog.Files[0].ArchiveConfigured {
		t.Fatalf("archive not recorded")
	}
}
