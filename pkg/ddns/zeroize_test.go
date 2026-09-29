package ddns

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestEraseStateIfEmptyRemovesCrashTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp-ddns-state.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(dir, ".dhcp-ddns-state.json.tmp-12345")
	if err := os.WriteFile(temp, []byte(`{"version":1,"records":[{"fqdn":"tenant.example"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, ".unrelated.json.tmp-1")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EraseStateIfEmpty(path); err != nil {
		t.Fatalf("erase with crash temp: %v", err)
	}
	if _, err := os.Lstat(temp); !os.IsNotExist(err) {
		t.Fatalf("crash temp survived: %v", err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("another writer's temp must survive: %v", err)
	}
}

// RED on revert: unlinking before the census destroys the nlink evidence,
// so a retry succeeds while the sibling retains the bytes. Both attempts
// must fail with the inode-scan error and remove nothing.
func TestEraseStateIfEmptyRefusesHardlinkedStore10769(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp-ddns-state.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(dir, "sibling.json")
	if err := os.Link(path, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		var linkErr *configstore.FactoryResetHardlinkError
		if err := EraseStateIfEmpty(path); !errors.As(err, &linkErr) {
			t.Fatalf("attempt %d: expected FactoryResetHardlinkError, got %v", attempt, err)
		}
		for _, p := range []string{path, sibling} {
			if _, serr := os.Lstat(p); serr != nil {
				t.Fatalf("attempt %d: refusal must remove nothing, %s stat err=%v", attempt, p, serr)
			}
		}
	}
}

func TestEraseStateIfEmptyRefusesHardlinkedTemp10769(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dhcp-ddns-state.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"records":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(dir, ".dhcp-ddns-state.json.tmp-1")
	if err := os.WriteFile(temp, []byte(`{"orphan":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(dir, "sibling.tmp")
	if err := os.Link(temp, sibling); err != nil {
		t.Fatalf("hardlink plant: %v", err)
	}
	var linkErr *configstore.FactoryResetHardlinkError
	if err := EraseStateIfEmpty(path); !errors.As(err, &linkErr) {
		t.Fatalf("expected FactoryResetHardlinkError, got %v", err)
	}
	for _, p := range []string{temp, sibling} {
		if _, serr := os.Lstat(p); serr != nil {
			t.Fatalf("refusal must remove nothing, %s stat err=%v", p, serr)
		}
	}
}
