package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestReconcileCompletedSupersededChpasswdVerifiesAndKeepsClaims17872 is
// fail-on-revert for #17872: a successful chpasswd completed before its owner
// was superseded, so reconcile must verify the changed shadow hash and retain
// the ownership claims. Before the fix it entered the generic error branch,
// rolled both fresh claims back, and never verified the hash.
func TestReconcileCompletedSupersededChpasswdVerifiesAndKeepsClaims17872(t *testing.T) {
	stageLoginTree15539(t)
	oldHash := "$6$old$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:"+oldHash+":19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origRun := runCommandStdinTimeout
	runCommandStdinTimeout = func(stdin io.Reader, name string, args ...string) ([]byte, error) {
		if name != "chpasswd" || strings.Join(args, " ") != "-e" {
			t.Fatalf("unexpected command %q %v", name, args)
		}
		input, err := io.ReadAll(stdin)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(input), "alice:"+testHash15539+"\n"; got != want {
			t.Fatalf("chpasswd stdin = %q, want %q", got, want)
		}
		shadow := "root:!:19000:0:99999:7:::\nalice:" + testHash15539 + ":19000:0:99999:7:::\n"
		if err := os.WriteFile(shadowPath, []byte(shadow), 0o600); err != nil {
			t.Fatal(err)
		}
		return []byte("updated"), errHostAuthExecCompletedSuperseded16830
	}
	t.Cleanup(func() { runCommandStdinTimeout = origRun })

	if err := (&Daemon{}).reconcileUserPassword(loginUser17872()); err != nil {
		t.Fatalf("reconcile completed-but-superseded success: %v", err)
	}
	if got, ok := currentShadowHash("alice"); !ok || got != testHash15539 {
		t.Fatalf("shadow hash after completed chpasswd = %q,%v; want verified desired hash", got, ok)
	}
	for _, dir := range []string{provisionedPasswordsDir(), provisionedUsersDir} {
		if !markerExists16830(dir, "alice") {
			t.Errorf("completed-but-superseded success withdrew ownership marker in %s", dir)
		}
	}
}

// TestReconcileCompletedSupersededChpasswdRejectsUnverifiedHash17872 pins
// the readback half: the completed marker is not enough to report convergence
// if the child did not actually leave the desired hash in shadow.
func TestReconcileCompletedSupersededChpasswdRejectsUnverifiedHash17872(t *testing.T) {
	stageLoginTree15539(t)
	oldHash := "$6$old$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:"+oldHash+":19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origRun := runCommandStdinTimeout
	runCommandStdinTimeout = func(io.Reader, string, ...string) ([]byte, error) {
		return []byte("updated"), errHostAuthExecCompletedSuperseded16830
	}
	t.Cleanup(func() { runCommandStdinTimeout = origRun })

	if err := (&Daemon{}).reconcileUserPassword(loginUser17872()); err == nil {
		t.Fatal("reconcile reported convergence without shadow readback matching the desired hash")
	}
	if got, ok := currentShadowHash("alice"); !ok || got != oldHash {
		t.Fatalf("shadow hash after unverified completed child = %q,%v, want unchanged old hash", got, ok)
	}
	for _, dir := range []string{provisionedPasswordsDir(), provisionedUsersDir} {
		if !markerExists16830(dir, "alice") {
			t.Errorf("unverified completed child withdrew ownership marker in %s", dir)
		}
	}
}

// TestReconcileSupersededChpasswdChildFailureReportsErrorAndKeepsClaims17872
// proves an actual child error remains a failed apply even when wrapped by
// the completed marker, and that a stale owner's fenced rollback preserves
// the claims after authority advances.
func TestReconcileSupersededChpasswdChildFailureReportsErrorAndKeepsClaims17872(t *testing.T) {
	stageLoginTree15539(t)
	oldHash := "$6$old$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.WriteFile(shadowPath, []byte("root:!:19000:0:99999:7:::\nalice:"+oldHash+":19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origRun := runCommandStdinTimeout
	childErr := errors.New("chpasswd failed")
	runCommandStdinTimeout = func(io.Reader, string, ...string) ([]byte, error) {
		beginHostAuthAuthority14969()
		return []byte("failed"), fmt.Errorf("%w: %w", errHostAuthExecCompletedSuperseded16830, childErr)
	}
	t.Cleanup(func() { runCommandStdinTimeout = origRun })

	gen := beginHostAuthAuthority14969()
	err := runWithHostAuthGeneration14969(gen, func() error {
		return (&Daemon{}).reconcileUserPassword(loginUser17872())
	})
	if !errors.Is(err, childErr) || !errors.Is(err, errHostAuthExecCompletedSuperseded16830) {
		t.Fatalf("reconcile wrapped chpasswd failure = %v, want child error and completed marker", err)
	}
	if errors.Is(err, errHostAuthStaleOwner14969) {
		t.Fatalf("real chpasswd child failure was replaced by stale-owner error: %v", err)
	}
	if got, ok := currentShadowHash("alice"); !ok || got != oldHash {
		t.Fatalf("failed chpasswd changed shadow hash to %q,%v", got, ok)
	}
	for _, dir := range []string{provisionedPasswordsDir(), provisionedUsersDir} {
		if !markerExists16830(dir, "alice") {
			t.Errorf("stale rollback withdrew marker that newer authority may rely on in %s", dir)
		}
	}
}

func loginUser17872() *config.LoginUser {
	return &config.LoginUser{Name: "alice", EncryptedPassword: config.NewSecret(testHash15539)}
}
