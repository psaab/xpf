package ddns

import (
	"os"
	"path/filepath"
	"testing"
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
