package dataplane

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #19072: the RSS key is one random key per BOOT. Two xpfd starts in one boot
// must program the same key, and a new boot must draw a new one.

const (
	rssTestBootA = "0f6c2a4e-1b3d-4c5e-8f70-9a1b2c3d4e5f"
	rssTestBootB = "7a8b9c0d-1e2f-4a3b-9c4d-5e6f7a8b9c0d"
)

func rssTestFiles(t *testing.T, bootID string) (keyPath, bootPath string) {
	t.Helper()
	dir := t.TempDir()
	keyPath = filepath.Join(dir, "run", "xpf", "rss-hash-key")
	bootPath = filepath.Join(dir, "boot_id")
	if err := os.WriteFile(bootPath, []byte(strings.ToUpper(bootID)+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	return keyPath, bootPath
}

func rssTestRandom(fill byte) *bytes.Reader {
	return bytes.NewReader(bytes.Repeat([]byte{fill}, rssHashKeySize))
}

func rssTestKey(fill byte) [rssHashKeySize]byte {
	var k [rssHashKeySize]byte
	for i := range k {
		k[i] = fill
	}
	return k
}

// Each loadOrCreateBootRSSKey call is one xpfd process start: a fresh
// process has a fresh sync.Once, and the only state that survives is the
// file. The second start is handed DIFFERENT random bytes, so it can only
// match the first by reading the stored key back.
func TestRSSBootKeySameAcrossProcessStartsInOneBoot19072(t *testing.T) {
	keyPath, bootPath := rssTestFiles(t, rssTestBootA)
	first, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x11))
	if err != nil {
		t.Fatal(err)
	}
	if first != rssTestKey(0x11) {
		t.Fatalf("first start: key %x, want the CSPRNG draw", first)
	}
	second, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x22))
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("second start in the same boot drew a new key %x, want the boot's key %x", second, first)
	}
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode %#o, want 0600", perm)
	}
	raw, _ := os.ReadFile(keyPath)
	if !strings.Contains(string(raw), " "+rssTestBootA+" ") {
		t.Fatalf("key file does not name its (lowercased) boot: %q", raw)
	}
}

func TestRSSBootKeyDiffersAcrossBoots19072(t *testing.T) {
	keyPath, bootPath := rssTestFiles(t, rssTestBootA)
	first, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x11))
	if err != nil {
		t.Fatal(err)
	}
	// A reboot: a new boot_id. /run is normally emptied too; the file is
	// kept here to prove the boot_id binding alone forces a new key.
	if err := os.WriteFile(bootPath, []byte(rssTestBootB+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x33))
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatalf("a new boot reused the previous boot's key %x", first)
	}
	if second != rssTestKey(0x33) {
		t.Fatalf("new boot: key %x, want the new CSPRNG draw", second)
	}
	third, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x44))
	if err != nil {
		t.Fatal(err)
	}
	if third != second {
		t.Fatalf("restart in the new boot: key %x, want %x", third, second)
	}
}

// A stored key that cannot be trusted or parsed is never used: the start
// draws a fresh key, exactly as a process with no file would.
func TestRSSBootKeyRefusesUntrustedOrMalformedFile19072(t *testing.T) {
	cases := map[string]func(t *testing.T, keyPath string){
		"group/other readable": func(t *testing.T, keyPath string) {
			if err := os.Chmod(keyPath, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, keyPath string) {
			target := keyPath + ".real"
			if err := os.Rename(keyPath, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, keyPath); err != nil {
				t.Fatal(err)
			}
		},
		"short key": func(t *testing.T, keyPath string) {
			if err := os.WriteFile(keyPath, []byte("v1 "+rssTestBootA+" abcd\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"unknown version": func(t *testing.T, keyPath string) {
			raw, _ := os.ReadFile(keyPath)
			if err := os.WriteFile(keyPath, []byte(strings.Replace(string(raw), "v1 ", "v9 ", 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			keyPath, bootPath := rssTestFiles(t, rssTestBootA)
			if _, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x11)); err != nil {
				t.Fatal(err)
			}
			spoil(t, keyPath)
			got, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x55))
			if err != nil {
				t.Fatal(err)
			}
			if got != rssTestKey(0x55) {
				t.Fatalf("%s: key %x, want a fresh draw (the stored key must not be used)", name, got)
			}
		})
	}
}

// Without a boot_id, or without a writable /run, the key is still a fresh
// CSPRNG key: the pre-#19072 per-process behaviour, never a fixed key.
func TestRSSBootKeyFallsBackToAProcessKey19072(t *testing.T) {
	t.Run("boot_id unreadable", func(t *testing.T) {
		keyPath, _ := rssTestFiles(t, rssTestBootA)
		got, err := loadOrCreateBootRSSKey(keyPath, filepath.Join(t.TempDir(), "missing"), rssTestRandom(0x66))
		if err != nil || got != rssTestKey(0x66) {
			t.Fatalf("key %x err %v, want the CSPRNG draw", got, err)
		}
		if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
			t.Fatalf("a key with no boot to bind it to was stored (stat err %v)", err)
		}
	})
	t.Run("boot_id malformed", func(t *testing.T) {
		keyPath, bootPath := rssTestFiles(t, rssTestBootA)
		if err := os.WriteFile(bootPath, []byte("not-a-uuid\n"), 0o444); err != nil {
			t.Fatal(err)
		}
		got, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x67))
		if err != nil || got != rssTestKey(0x67) {
			t.Fatalf("key %x err %v, want the CSPRNG draw", got, err)
		}
	})
	t.Run("store unwritable", func(t *testing.T) {
		_, bootPath := rssTestFiles(t, rssTestBootA)
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := loadOrCreateBootRSSKey(filepath.Join(blocker, "rss-hash-key"), bootPath, rssTestRandom(0x77))
		if err != nil || got != rssTestKey(0x77) {
			t.Fatalf("key %x err %v, want the CSPRNG draw", got, err)
		}
	})
	t.Run("CSPRNG failure is an error", func(t *testing.T) {
		keyPath, bootPath := rssTestFiles(t, rssTestBootA)
		if _, err := loadOrCreateBootRSSKey(keyPath, bootPath, bytes.NewReader(nil)); err == nil {
			t.Fatal("an empty random source produced a key")
		}
		if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
			t.Fatalf("a failed draw stored a key (stat err %v)", err)
		}
	})
}

// The production wrapper reads the package paths. TestMain points
// rssBootKeyPath at a private directory, so this proves the wrapper stores
// there and nothing in the package writes /run/xpf.
func TestRSSHashKeyForBootUsesTheBootStore19072(t *testing.T) {
	if strings.HasPrefix(rssBootKeyPath, "/run/") {
		t.Fatalf("test binary would write the live key file %s", rssBootKeyPath)
	}
	key, err := rssHashKeyForBoot()
	if err != nil {
		t.Fatal(err)
	}
	bootID, err := readRSSBootID(rssBootIDPath)
	if err != nil {
		t.Skipf("no kernel boot_id here (%v); the wrapper fell back to a process key", err)
	}
	stored, err := readRSSBootKeyFile(rssBootKeyPath, bootID)
	if err != nil {
		t.Fatalf("wrapper did not store this boot's key: %v", err)
	}
	if stored != key {
		t.Fatalf("stored key differs from the programmed key")
	}
}
