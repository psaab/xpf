package testguard

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	hostCanaryEnv    = "XPF_TESTGUARD_HOST_CANARY_18038"
	privateCanaryEnv = "XPF_TESTGUARD_PRIVATE_CANARY_18038"
)

func TestHostCanaryFailsClosed18038(t *testing.T) {
	if os.Getenv(hostCanaryEnv) == "1" {
		RequireDisposable(t)
		return
	}
	cmd := exec.Command("unshare", "-Urp", "--fork", "--mount-proc", os.Args[0], "-test.run=^TestHostCanaryFailsClosed18038$")
	cmd.Env = append(os.Environ(), hostCanaryEnv+"=1", SentinelEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("host canary passed; sentinel must not override namespace identity\n%s", out)
	}
	if !strings.Contains(string(out), "testguard: host not disposable") {
		t.Fatalf("host canary failed for an unexpected reason: %v\n%s", err, out)
	}
}

func TestPrivateNamespaceCanaryPasses18038(t *testing.T) {
	if os.Getenv(privateCanaryEnv) == "1" {
		if !Disposable() {
			t.Fatal("Disposable() rejected the private net+mount namespace")
		}
		RequireDisposable(t)
		return
	}
	// A private PID namespace makes the original init process visible as PID 1
	// to the namespace probe. The test binary then creates private network and
	// mount namespaces below it, so PID 1 remains a trustworthy baseline.
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-Urp", "--fork", "--mount-proc", "sh", "-c", "(unshare -nm \"$@\")", "testguard", binary, "-test.run=^TestPrivateNamespaceCanaryPasses18038$")
	cmd.Env = append(os.Environ(), privateCanaryEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("private namespace canary failed: %v\n%s", err, out)
	}
}
