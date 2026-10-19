package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// #15729 legs 2+3: FactoryResetArchiveDir must erase the xpf-owned DEFAULT
// even when the configured (custom) dir is skipped, and FactoryResetConfigDir
// must erase day0 mktemp staging files.

func TestFactoryResetArchiveDirErasesDefaultEvenWhenCustomSkipped(t *testing.T) {
	root := t.TempDir()
	defaultDir := filepath.Join(root, "default-archive")
	old := DefaultArchiveDir
	DefaultArchiveDir = defaultDir
	t.Cleanup(func() { DefaultArchiveDir = old })

	defaultSecret := seedArchiveFile(t, defaultDir)
	customDir := filepath.Join(root, "compliance-archive")
	customSecret := seedArchiveFile(t, customDir)

	err := FactoryResetArchiveDir(customDir)
	var skipped *ArchiveDirSkippedError
	if !errors.As(err, &skipped) {
		t.Fatalf("FactoryResetArchiveDir(custom) = %v, want *ArchiveDirSkippedError", err)
	}
	if skipped.Dir != customDir {
		t.Errorf("skipped dir = %q, want %q", skipped.Dir, customDir)
	}
	if _, statErr := os.Stat(defaultSecret); !os.IsNotExist(statErr) {
		t.Errorf("default archive snapshot survived a custom-dir zeroize (stat err=%v); cleartext secrets remain", statErr)
	}
	if _, statErr := os.Stat(defaultDir); !os.IsNotExist(statErr) {
		t.Errorf("default archive dir survived a custom-dir zeroize (stat err=%v)", statErr)
	}
	// The custom dir itself must still survive untouched (ownership guard).
	if _, statErr := os.Stat(customSecret); statErr != nil {
		t.Errorf("custom archive must survive zeroize untouched: %v", statErr)
	}
}

func TestFactoryResetConfigDirErasesDay0StagedTemps(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, ".xpf.conf.Ab12Cd")
	if err := os.WriteFile(staged, []byte("system { authentication-key DAY0-SECRET; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Preservation controls: an unrelated dotfile and a longer-suffix
	// name must survive (matcher must stay narrow). (.config.journal is
	// itself an owned artifact erased by its own rule, so it is not a
	// preservation control here.)
	keepStagedLong := filepath.Join(dir, ".xpf.conf.Ab12CdEf")
	for _, keep := range []string{".keepme", keepStagedLong} {
		p := keep
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, keep)
		}
		if err := os.WriteFile(p, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := FactoryResetConfigDir(dir, "xpf.conf"); err != nil {
		t.Fatalf("FactoryResetConfigDir: %v", err)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Errorf("day0 staged temp %s survived factory reset (stat err=%v); cleartext config remains", staged, err)
	}
	for _, keep := range []string{".keepme", keepStagedLong} {
		p := keep
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, keep)
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("factory reset removed non-staged file %s: %v", p, err)
		}
	}
	// Note: .day0-config-applied is the loader's stamp and is removed by a
	// normal (non-pending) reset, so it is intentionally not asserted kept.
}

func TestIsDay0StagedTemp(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{".xpf.conf.Ab12Cd", true},
		{".xpf.conf.XXXXXX", true},
		{".xpf.conf.a1_B2c", true},
		{".node-id.Ab12Cd", true},
		{".day0-config-applied", false},
		{".config.journal", false},
		{".config.journal.1", false},
		{".keepme", false},
		{"xpf.conf.Ab12Cd", false},
		{".xpf.conf.Ab12CdEf", false},
		{".xpf.conf.Ab1", false},
		{".xpf.conf.tmp-abc123", false},
		{".xpf.conf.Ab12!d", false},
		{".Ab12Cd", false},
	}
	for _, tc := range cases {
		if got := isDay0StagedTemp(tc.name); got != tc.want {
			t.Errorf("isDay0StagedTemp(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
