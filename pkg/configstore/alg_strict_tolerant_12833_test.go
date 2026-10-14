package configstore

import (
	"path/filepath"
	"strings"
	"testing"
)

const duplicateALGConfig12833 = `security { alg { ftp { } ftp { disable; } } }`

func TestALGStrictAndTolerantPaths12833(t *testing.T) {
	// CheckText is the exact strict CLI commit-check pipeline, including the
	// expanded schema walk that rejects packed/braced typos.
	compiled, err := CheckText(duplicateALGConfig12833, -1)
	if err != nil {
		t.Fatalf("CheckText rejected duplicate ALG blocks: %v", err)
	}
	if !compiled.Security.ALG.FTPDisable ||
		compiled.Security.ALG.DNSDisable || compiled.Security.ALG.SIPDisable || compiled.Security.ALG.TFTPDisable {
		t.Fatalf("CheckText ALG flags = %+v; want FTP disabled and other wired ALGs enabled", compiled.Security.ALG)
	}
	for _, tc := range []struct {
		name string
		text string
	}{{
		name: "packed typo",
		text: `security { alg { ftp desable; } }`,
	}, {
		name: "braced typo control",
		text: `security { alg { ftp { desable; } } }`,
	}} {
		t.Run("strict/"+tc.name, func(t *testing.T) {
			if _, err := CheckText(tc.text, -1); err == nil || !strings.Contains(err.Error(), "desable") {
				t.Fatalf("CheckText error = %v; want strict rejection naming desable", err)
			}
		})
	}

	// Tolerant peer ingestion must not brick on a config that predates the
	// strict typo gate, and the repeated protocol blocks must still compile to
	// the operator's effective disable state. Persist via SyncApply, then boot
	// a fresh Store through its real Load ingress to exercise both paths.
	path := filepath.Join(t.TempDir(), "config")
	peer := newTestStoreAt(t, path)
	compiled, err = peer.SyncApply(duplicateALGConfig12833, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected duplicate ALG blocks: %v", err)
	}
	if !compiled.Security.ALG.FTPDisable {
		t.Fatal("SyncApply lost the second FTP block's disable")
	}
	boot := newTestStoreAt(t, path)
	if err := boot.Load(); err != nil {
		t.Fatalf("Store.Load rejected duplicate ALG blocks: %v", err)
	}
	if !boot.ActiveConfig().Security.ALG.FTPDisable {
		t.Fatal("Store.Load lost the second FTP block's disable")
	}

	// A misspelled packed token is strict-invalid but must remain loadable from
	// an older persisted configuration on tolerant ingress.
	legacyPath := filepath.Join(t.TempDir(), "legacy-config")
	legacy := newTestStoreAt(t, legacyPath)
	if _, err := legacy.SyncApply(`security { alg { ftp desable; } }`, nil); err != nil {
		t.Fatalf("SyncApply bricked on a legacy packed typo: %v", err)
	}
	legacyBoot := newTestStoreAt(t, legacyPath)
	if err := legacyBoot.Load(); err != nil {
		t.Fatalf("Store.Load bricked on a legacy packed typo: %v", err)
	}
}
