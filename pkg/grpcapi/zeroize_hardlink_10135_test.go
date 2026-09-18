package grpcapi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestZeroizeAttestsTLSHardlink10135(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "etc", "xpf")
	outside := filepath.Join(root, "elsewhere")
	for _, dir := range []string{configDir, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tlsDir := filepath.Join(configDir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(tlsDir, "key.pem")
	if err := os.WriteFile(managed, []byte("PRIVATE KEY 10135"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(outside, "key-alias.pem")
	if err := os.Link(managed, alias); err != nil {
		t.Fatalf("hardlink plant for #10135: %v", err)
	}

	err := zeroizeConfigDir(configDir, "xpf.conf")
	var linkErr *configstore.FactoryResetHardlinkError
	if !errors.As(err, &linkErr) {
		t.Fatalf("expected FactoryResetHardlinkError naming the managed path, got %v", err)
	}
	recorded := linkErr.Paths[0]
	if len(linkErr.Paths) != 1 || recorded.Path != managed || recorded.Nlink != 2 || recorded.Dev == 0 || recorded.Ino == 0 {
		t.Fatalf("unexpected hardlink attestation: %+v", linkErr.Paths)
	}
	errorText := strings.ToLower(linkErr.Error())
	if !strings.Contains(errorText, strings.ToLower(managed)) ||
		!strings.Contains(errorText, "remove every hard-link name") ||
		!strings.Contains(errorText, fmt.Sprintf("-inum %d", recorded.Ino)) {
		t.Fatalf("hardlink error omits path, inode, or operator action: %v", linkErr)
	}
	if _, statErr := os.Lstat(managed); !os.IsNotExist(statErr) {
		t.Fatalf("managed name should be removed despite the attestation, stat err=%v", statErr)
	}
	got, readErr := os.ReadFile(alias)
	if readErr != nil || string(got) != "PRIVATE KEY 10135" {
		t.Fatalf("hardlink survivor should remain for operator remediation: err=%v content=%q", readErr, got)
	}
}

func TestZeroizeTLSWithoutHardlinkStillSucceeds10135(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "etc", "xpf")
	tlsDir := filepath.Join(configDir, "tls")
	if err := os.MkdirAll(tlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(tlsDir, "key.pem")
	if err := os.WriteFile(managed, []byte("PRIVATE KEY 10135"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := zeroizeConfigDir(configDir, "xpf.conf"); err != nil {
		t.Fatalf("ordinary non-hardlinked TLS wipe failed: %v", err)
	}
	if _, statErr := os.Lstat(managed); !os.IsNotExist(statErr) {
		t.Fatalf("ordinary managed TLS file should be removed, stat err=%v", statErr)
	}
}
