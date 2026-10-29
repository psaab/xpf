package factoryreset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestZeroizeErasesNoRedirectsCapture17792(t *testing.T) {
	root := t.TempDir()
	hermeticWipe10100(t, root)
	configDir := filepath.Join(root, "etc-xpf")
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "master.key"), []byte("key"))
	mustWriteFile(t, filepath.Join(configDir, ".configdb", "active.json"), []byte("{}"))
	mustWriteFile(t, filepath.Join(configDir, "xpf.conf"), []byte("system { host-name fw; }\n"))

	capturePath := filepath.Join(root, "var", "lib", "xpf", "no-redirects-capture.json")
	mustWriteFile(t, capturePath, []byte(`{"version":1,"values":{"ipv4/conf/r0/send_redirects":"0"}}`))
	helperPath := filepath.Join(root, "custom", "userspace-dp.json")
	if err := PerformZeroizeWipeUngated(configDir, "xpf.conf", "", ZeroizeLogInventory{}, helperPath); err != nil {
		t.Fatalf("PerformZeroizeWipeUngated: %v", err)
	}
	if _, err := os.Lstat(capturePath); !os.IsNotExist(err) {
		t.Fatalf("factory reset left redirect capture %s: %v", capturePath, err)
	}
}

func TestFinalEraseVerificationCatchesNoRedirectCapture17792(t *testing.T) {
	root := t.TempDir()
	restore := RedirectWipePathsForTesting(root)
	t.Cleanup(restore)
	capturePath := wipeNoRedirectsCapturePath
	mustWriteFile(t, capturePath, []byte(`{"version":1,"values":{"ipv4/conf/r0/send_redirects":"0"}}`))

	err := wipeFinalEraseVerification(wipeComplete)
	if err == nil {
		t.Fatal("reappeared redirect capture must fail final verification")
	}
	if !strings.Contains(err.Error(), capturePath) {
		t.Fatalf("final-verification error %q does not name redirect capture %s", err, capturePath)
	}
}
