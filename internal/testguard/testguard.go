package testguard

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

const SentinelEnv = "XPF_SACRIFICIAL_HOST"

// ExitIfUnsafe is the first action required in a package TestMain. It exits
// before package setup or tests can touch host state when isolation is absent
// or cannot be verified.
func ExitIfUnsafe() {
	if err := CheckDisposable(); err != nil {
		fmt.Fprintf(os.Stderr, "testguard: refusing package tests: %v; run in a private net+mount namespace\n", err)
		os.Exit(1)
	}
}

// Disposable reports whether the calling OS thread is isolated from PID 1 in
// both network and mount namespaces. SentinelEnv is advisory only and never
// changes this result.
func Disposable() bool {
	return CheckDisposable() == nil
}

// CheckDisposable fails closed when either namespace identity cannot be read.
func CheckDisposable() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for _, kind := range []string{"net", "mnt"} {
		different, err := namespaceDiffers("/proc/thread-self/ns/"+kind, "/proc/1/ns/"+kind)
		if err != nil {
			return fmt.Errorf("read %s namespace identity: %w", kind, err)
		}
		if !different {
			return fmt.Errorf("process shares PID 1's %s namespace", kind)
		}
	}
	return nil
}

// RequireDisposable makes an unsafe or unverifiable host identity a hard test
// failure; an environment sentinel is not an exemption.
func RequireDisposable(t interface {
	Helper()
	Fatalf(string, ...any)
}) {
	t.Helper()
	if err := CheckDisposable(); err != nil {
		t.Fatalf("testguard: host not disposable: %v; run under `unshare -Urnm` or in a VM leg", err)
	}
}

// Intent returns the wrapper-provided advisory sentinel without treating it as
// proof that the current host is disposable.
func Intent() string { return os.Getenv(SentinelEnv) }

func namespaceDiffers(selfPath, initPath string) (bool, error) {
	self, err := os.Readlink(selfPath)
	if err != nil {
		return false, err
	}
	initNS, err := os.Readlink(initPath)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(self) == "" || strings.TrimSpace(initNS) == "" {
		return false, fmt.Errorf("empty namespace identity")
	}
	return self != initNS, nil
}
