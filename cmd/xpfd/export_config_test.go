package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

func TestParseExportConfigArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
		fail bool
	}{
		{name: "required output path", fail: true},
		{name: "reject extra operands", args: []string{"one.conf", "two.conf"}, fail: true},
		{name: "reject stdout", args: []string{"-"}, fail: true},
		{name: "one output path", args: []string{"current.conf"}, want: "current.conf"},
		{name: "explicit config db", args: []string{"--configdb-dir", "/srv/xpf/.configdb", "current.conf"}, want: "current.conf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExportConfigArgs(tt.args)
			if tt.fail {
				if err == nil {
					t.Fatalf("parseExportConfigArgs(%q) succeeded, want usage error", tt.args)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseExportConfigArgs(%q): %v", tt.args, err)
			}
			if got.outPath != tt.want {
				t.Errorf("outPath = %q, want %q", got.outPath, tt.want)
			}
			if tt.name == "explicit config db" && got.configDBDir != "/srv/xpf/.configdb" {
				t.Errorf("configDBDir = %q, want /srv/xpf/.configdb", got.configDBDir)
			}
		})
	}
}

// #10736 RED-on-revert: the install-time xpf.conf remains at day-0 after a
// later active DB commit. The exported file must instead carry that CURRENT
// committed config through the same EnterConfigure + LoadOverride + Commit
// sequence the first-boot day-0 loader uses. Reading d.opts.ConfigFile (or
// switching the command back to copying xpf.conf) makes this fail: the new
// image silently imports the old day-0 host-name.
func TestExportConfigCarriesCurrentActiveConfigAcrossImageReplace10736(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "source")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bootFile := filepath.Join(sourceDir, "xpf.conf")
	const day0Config = "system { host-name day0-10736; }\n"
	const currentConfig = "system { host-name current-commit-10736; }\n"
	if err := os.WriteFile(bootFile, []byte(day0Config), 0o600); err != nil {
		t.Fatal(err)
	}

	// Install/import the day-0 config, then make a later commit. The boot file
	// deliberately remains day-0; active.json is now the authority.
	source, err := configstore.New(bootFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Load(); err != nil {
		t.Fatal(err)
	}
	commitText(t, source, day0Config)
	commitText(t, source, currentConfig)
	if got, err := os.ReadFile(bootFile); err != nil {
		t.Fatal(err)
	} else if string(got) != day0Config {
		t.Fatalf("boot file changed unexpectedly: %q", got)
	}

	exportPath := filepath.Join(root, "current-export.conf")
	if err := exportActiveConfig(filepath.Join(sourceDir, ".configdb"), exportPath); err != nil {
		t.Fatalf("exportActiveConfig: %v", err)
	}
	exported, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("read exported file: %v", err)
	}
	if !strings.Contains(string(exported), "current-commit-10736") || strings.Contains(string(exported), "day0-10736") {
		t.Fatalf("export did not reflect current active config; got:\n%s", exported)
	}
	fi, err := os.Stat(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("export mode = %#o, want 0600", got)
	}

	// A fresh replacement image has no DB. The day-0 import path takes the
	// exported text, commits it, and must come up with the latest setting.
	replacementPath := filepath.Join(root, "replacement", "xpf.conf")
	replacement, err := configstore.New(replacementPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Load(); err != nil {
		t.Fatal(err)
	}
	commitText(t, replacement, string(exported))
	active := replacement.ShowActive()
	if !strings.Contains(active, "current-commit-10736") || strings.Contains(active, "day0-10736") {
		t.Fatalf("replacement active configuration reverted instead of carrying current commit:\n%s", active)
	}
}

func TestExportConfigRefusesMissingOrEmptyActiveDB(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "export.conf")
	if err := exportActiveConfig(filepath.Join(root, "missing"), out); err == nil {
		t.Fatal("exportActiveConfig accepted a missing config DB")
	}

	emptyDir := filepath.Join(root, "empty")
	if err := os.MkdirAll(emptyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := configstore.NewDB(filepath.Join(emptyDir, ".configdb")); err != nil {
		t.Fatal(err)
	}
	if err := exportActiveConfig(filepath.Join(emptyDir, ".configdb"), out); err == nil {
		t.Fatal("exportActiveConfig accepted a config DB with no active config")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("failed export left an output artifact: stat error = %v", err)
	}
}

func TestOfflineExportHashesLegacyAPIAuthWithoutRewritingDB_10825(t *testing.T) {
	root := t.TempDir()
	dbDir := filepath.Join(root, ".configdb")
	db, err := configstore.NewDB(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	const legacy = `system {
 services {
  web-management {
   api-auth {
    expires 2099-01-01;
    user admin { password correct-horse-battery; }
    api-key machine-generated-key-alpha;
    key automation { secret automation-key-secret-alpha; }
   }
  }
 }
}`
	tree, parseErrs := config.NewParser(legacy).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse legacy fixture: %v", parseErrs)
	}
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("write legacy active: %v", err)
	}

	outPath := filepath.Join(root, "export.conf")
	if err := exportActiveConfig(dbDir, outPath); err != nil {
		t.Fatalf("exportActiveConfig: %v", err)
	}
	exported, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, cleartext := range []string{
		"correct-horse-battery",
		"machine-generated-key-alpha",
		"automation-key-secret-alpha",
	} {
		if strings.Contains(string(exported), cleartext) {
			t.Fatalf("offline export contains cleartext api-auth credential %q:\n%s", cleartext, exported)
		}
	}
	if !strings.Contains(string(exported), "$xpf-bcrypt$") {
		t.Fatalf("offline export contains no tagged api-auth verifiers:\n%s", exported)
	}

	// The portable artifact remains usable, while exporting does not mutate
	// the live DB that a later boot will migrate.
	exportTree, parseErrs := config.NewParser(string(exported)).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse exported config: %v", parseErrs)
	}
	auth := exportTree.FindChild("system").FindChild("services").
		FindChild("web-management").FindChild("api-auth")
	user := auth.FindChild("user")
	apiKey := auth.FindChild("api-key")
	key := auth.FindChild("key")
	if user == nil || len(user.Keys) < 2 || apiKey == nil || len(apiKey.Keys) < 2 ||
		key == nil || len(key.Keys) < 2 {
		t.Fatalf("exported api-auth credentials are incomplete:\n%s", exported)
	}
	if !config.VerifyAPIAuthSecret(user.FindChild("password").Keys[1], "correct-horse-battery") ||
		!config.VerifyAPIAuthSecret(apiKey.Keys[1], "machine-generated-key-alpha") ||
		!config.VerifyAPIAuthSecret(key.FindChild("secret").Keys[1], "automation-key-secret-alpha") {
		t.Fatal("exported api-auth verifiers do not accept their original secrets")
	}
	after, err := db.ReadActive()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(after.Format(), "machine-generated-key-alpha") {
		t.Fatal("offline export rewrote the legacy active DB instead of migrating only its copy")
	}
}

func commitText(t *testing.T, store *configstore.Store, text string) {
	t.Helper()
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
}

func TestOfflineExportRejectsMalformedTaggedAPIAuthWithoutMutation_10825(t *testing.T) {
	root := t.TempDir()
	dbDir := filepath.Join(root, ".configdb")
	db, err := configstore.NewDB(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	const invalid = `system {
 services {
  web-management {
   api-auth {
    expires 2099-01-01;
    user admin { password "$xpf-bcrypt$not-a-valid-verifier"; }
   }
  }
 }
}`
	tree, parseErrs := config.NewParser(invalid).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse malformed-tag fixture: %v", parseErrs)
	}
	if err := db.WriteActive(tree); err != nil {
		t.Fatalf("write invalid-tag active: %v", err)
	}
	activePath := filepath.Join(dbDir, "active.json")
	before, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(root, "unsafe-export.conf")
	err = exportActiveConfig(dbDir, outPath)
	if err == nil || !strings.Contains(err.Error(), "migrate api-auth credentials") {
		t.Fatalf("export invalid tagged api-auth config = %v, want actionable migration error", err)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("invalid api-auth export left an unsafe output: stat error = %v", err)
	}
	after, err := os.ReadFile(activePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed offline export mutated active.json")
	}
}
