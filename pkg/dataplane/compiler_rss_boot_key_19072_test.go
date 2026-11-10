package dataplane

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
		// Whitespace padding keeps the three fields intact, so only the
		// exact-record check can refuse it.
		"padding after the record": func(t *testing.T, keyPath string) {
			raw, _ := os.ReadFile(keyPath)
			if err := os.WriteFile(keyPath, append(raw, []byte("   \n\n")...), 0o600); err != nil {
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

// The trust checks run on the opened descriptor (#19072 review R1). The
// foreign-owner and FIFO cells are adopted from R7's review of ca81cda7a8
// (R7-1): each pins one predicate no other cell can see.
//   - A file owned by another uid is a known key and must not be used. The
//     cell needs real root to chown, and FAILS rather than skips without it,
//     so it cannot pass vacuously (the package's testguard already requires
//     the runner's root namespace leg).
//   - A FIFO at the path with no writer must not block the apply: the load
//     runs inside CompileConfig before XDP attach, so a block is a bring-up
//     hang. O_NONBLOCK is what this pins.
//   - A FIFO held open by an idle writer: even a non-blocking open then
//     parks the read, so only the regular-file check on the descriptor
//     keeps it from hanging. That pins the regular-file check.
//
// Each FIFO case is bounded at 5 s, so a regression fails instead of hanging
// the package run.
func TestRSSBootKeyRefusesAForeignOwner19072(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatalf("FIXTURE: needs real root to chown (euid %d); run this package in the runner's root leg", os.Geteuid())
	}
	keyPath, bootPath := rssTestFiles(t, rssTestBootA)
	if _, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x11)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(keyPath, 65534, 65534); err != nil {
		t.Fatalf("FIXTURE: chown: %v", err)
	}
	got, err := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(0x56))
	if err != nil || got != rssTestKey(0x56) {
		t.Fatalf("key %x err %v: a key file owned by uid 65534 was used, want a fresh draw", got, err)
	}
}

// It launches a goroutine (the 5 s bound), so the ./pkg/dataplane/ race leg
// in the Makefile runs it too (race_gate_coverage_9045_test.go).
func TestRSSBootKeyFIFOAtThePathNeverBlocks19072(t *testing.T) {
	fifoCase := func(t *testing.T, holdWriter bool, fill byte) {
		keyPath, bootPath := rssTestFiles(t, rssTestBootA)
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(keyPath, 0o600); err != nil {
			t.Fatalf("FIXTURE: mkfifo: %v", err)
		}
		if holdWriter {
			// O_RDWR opens a FIFO without waiting for a peer (Linux).
			w, err := os.OpenFile(keyPath, os.O_RDWR, 0)
			if err != nil {
				t.Fatalf("FIXTURE: open the FIFO's writer: %v", err)
			}
			defer w.Close()
		}
		type result struct {
			key [rssHashKeySize]byte
			err error
		}
		done := make(chan result, 1)
		go func() {
			k, e := loadOrCreateBootRSSKey(keyPath, bootPath, rssTestRandom(fill))
			done <- result{k, e}
		}()
		select {
		case r := <-done:
			if r.err != nil || r.key != rssTestKey(fill) {
				t.Fatalf("key %x err %v, want a fresh draw", r.key, r.err)
			}
			fi, err := os.Lstat(keyPath)
			if err != nil || !fi.Mode().IsRegular() {
				t.Fatalf("the FIFO was not replaced by a regular key file (%v, %v)", fi, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a FIFO at the key path blocked the key load for 5 s (bring-up would hang)")
		}
	}
	t.Run("fifo with no writer", func(t *testing.T) { fifoCase(t, false, 0x57) })
	t.Run("fifo held open by an idle writer", func(t *testing.T) { fifoCase(t, true, 0x58) })
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
