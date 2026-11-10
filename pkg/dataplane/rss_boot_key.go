package dataplane

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// One RSS hash key per BOOT, not per xpfd process (#19072).
//
// #11057 replaced a fleet-wide hardcoded Toeplitz key, which let a remote
// attacker precompute tuple-to-queue placement and aim a flood at one worker,
// with a CSPRNG key. Its acceptance asked for a key "randomized per box/boot";
// the implementation drew a new key in every xpfd process, so every restart,
// deploy and upgrade moved every flow to a different worker. That was never a
// security requirement: a restart is not a designed rotation, and the key is
// just as unpredictable when it is kept for the boot.
//
// The key is still drawn from the CSPRNG. It is kept in rssBootKeyPath, on
// /run (tmpfs, emptied at every boot), next to the boot_id it was drawn for,
// so a later xpfd process in the same boot reuses it and the first process of
// a new boot draws a fresh one. It is NOT derived from boot_id: boot_id is
// readable by every local user and travels in journal metadata (_BOOT_ID), so
// an unkeyed derivation would be predictable, and a keyed one would need a
// long-lived secret at rest. A boot-scoped random key needs neither.
//
// Trade-off, accepted: placement knowledge an attacker infers through a side
// channel now lasts until the next reboot instead of the next xpfd restart.
//
// Only one xpfd runs at a time (the #15085 singleton lock), so the file has a
// single writer; a plain atomic replace is enough.

// rssBootKeyPath is where this boot's key lives. A var so tests (and the
// package TestMain) point it at a temporary directory; production never
// reassigns it.
var rssBootKeyPath = "/run/xpf/rss-hash-key"

// rssBootIDPath is the kernel's per-boot UUID.
var rssBootIDPath = "/proc/sys/kernel/random/boot_id"

const rssBootKeyFileVersion = "v1"

// readRSSBootID returns the kernel boot_id as a lowercase dashed UUID.
func readRSSBootID(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 128))
	if err != nil {
		return "", err
	}
	id := strings.ToLower(strings.TrimSpace(string(raw)))
	if !validRSSBootID(id) {
		return "", fmt.Errorf("boot_id %q is not a dashed UUID", id)
	}
	return id, nil
}

func validRSSBootID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
	}
	return true
}

// readRSSBootKeyFile returns the key stored for bootID. It refuses a file
// that is not a regular file owned by this process's user with no group or
// other permissions: such a file may have been planted, and a planted key is
// a known key.
func readRSSBootKeyFile(path, bootID string) ([rssHashKeySize]byte, error) {
	var key [rssHashKeySize]byte
	fi, err := os.Lstat(path)
	if err != nil {
		return key, err
	}
	if !fi.Mode().IsRegular() {
		return key, fmt.Errorf("%s is not a regular file (%s)", path, fi.Mode().Type())
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return key, fmt.Errorf("%s has mode %#o, want no group or other access", path, perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return key, fmt.Errorf("%s is owned by uid %d, not %d", path, st.Uid, os.Geteuid())
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return key, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 256))
	if err != nil {
		return key, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 3 || fields[0] != rssBootKeyFileVersion {
		return key, fmt.Errorf("%s: unrecognized format", path)
	}
	if fields[1] != bootID {
		return key, errRSSBootKeyOtherBoot
	}
	decoded, err := hex.DecodeString(fields[2])
	if err != nil || len(decoded) != rssHashKeySize {
		return key, fmt.Errorf("%s: key is not %d hex bytes", path, rssHashKeySize)
	}
	copy(key[:], decoded)
	return key, nil
}

var errRSSBootKeyOtherBoot = errors.New("key belongs to another boot")

func writeRSSBootKeyFile(path, bootID string, key [rssHashKeySize]byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	data := fmt.Sprintf("%s %s %s\n", rssBootKeyFileVersion, bootID, hex.EncodeToString(key[:]))
	return fsatomic.WriteFileAtomic(path, []byte(data), 0o600)
}

// loadOrCreateBootRSSKey returns this boot's key: the stored one when it
// belongs to the current boot_id, otherwise a fresh key from random, stored
// for the rest of the boot. When boot_id cannot be read or the key cannot be
// stored, it returns a fresh key for this process only — the pre-#19072
// behaviour, never a weaker key. Key material is never logged.
func loadOrCreateBootRSSKey(keyPath, bootIDPath string, random io.Reader) ([rssHashKeySize]byte, error) {
	bootID, err := readRSSBootID(bootIDPath)
	if err != nil {
		slog.Warn("RSS hash key: boot_id unreadable; using a key for this process only",
			"path", bootIDPath, "err", err)
		return readRSSHashKey(random)
	}
	key, err := readRSSBootKeyFile(keyPath, bootID)
	if err == nil {
		slog.Info("RSS hash key: reusing this boot's key", "path", keyPath)
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errRSSBootKeyOtherBoot) {
		slog.Warn("RSS hash key: ignoring the stored key", "path", keyPath, "err", err)
	}
	key, err = readRSSHashKey(random)
	if err != nil {
		return key, err
	}
	if werr := writeRSSBootKeyFile(keyPath, bootID, key); werr != nil {
		slog.Warn("RSS hash key: could not store this boot's key; the next xpfd start draws another",
			"path", keyPath, "err", werr)
		return key, nil
	}
	slog.Info("RSS hash key: drew a new key for this boot", "path", keyPath)
	return key, nil
}
