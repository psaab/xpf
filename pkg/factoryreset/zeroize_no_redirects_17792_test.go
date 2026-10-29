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
	captureBytes := []byte(`{"version":1,"values":{"ipv4/conf/r0/send_redirects":"0"}}`)
	mustWriteFile(t, capturePath, captureBytes)
	captureTemp := filepath.Join(filepath.Dir(capturePath), "."+filepath.Base(capturePath)+".tmp-999")
	mustWriteFile(t, captureTemp, captureBytes)
	helperPath := filepath.Join(root, "custom", "userspace-dp.json")
	if err := PerformZeroizeWipeUngated(configDir, "xpf.conf", "", ZeroizeLogInventory{}, helperPath); err != nil {
		t.Fatalf("PerformZeroizeWipeUngated: %v", err)
	}
	for _, path := range []string{capturePath, captureTemp} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("factory reset left redirect capture artifact %s: %v", path, err)
		}
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

func TestFinalEraseVerificationCatchesNoRedirectCaptureCrashTemp17792(t *testing.T) {
	root := t.TempDir()
	restore := RedirectWipePathsForTesting(root)
	t.Cleanup(restore)
	tempPath := filepath.Join(filepath.Dir(wipeNoRedirectsCapturePath), "."+filepath.Base(wipeNoRedirectsCapturePath)+".tmp-999")
	mustWriteFile(t, tempPath, []byte(`{"version":1,"values":{"ipv4/conf/r0/send_redirects":"0"}}`))

	err := wipeFinalEraseVerification(wipeComplete)
	if err == nil {
		t.Fatal("reappeared redirect capture crash temp must fail final verification")
	}
	if !strings.Contains(err.Error(), tempPath) {
		t.Fatalf("final-verification error %q does not name redirect capture temp %s", err, tempPath)
	}
}
