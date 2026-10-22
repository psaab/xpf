package factoryreset

import (
	"os"
	"path/filepath"
	"testing"
)

func TestZeroizeConfigDirErasesDay0StagedTemps15729(t *testing.T) {
	dir := t.TempDir()
	staged := filepath.Join(dir, ".xpf.conf.Ab12Cd")
	mustWriteFile(t, staged, []byte("system { authentication-key DAY0-SECRET; }\n"))
	keep := filepath.Join(dir, ".keepme")
	mustWriteFile(t, keep, []byte("keep"))

	if err := wipeConfigDir(dir, "xpf.conf"); err != nil {
		t.Fatalf("wipeConfigDir: %v", err)
	}
	assertAbsent(t, staged)
	if _, err := os.Stat(keep); err != nil {
		t.Errorf("zeroize removed unrelated dotfile %s: %v", keep, err)
	}
}
