package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestLoginShellForClass10833(t *testing.T) {
	cfg := &config.Config{System: config.SystemConfig{Login: &config.LoginConfig{
		Classes: []*config.LoginClass{{Name: "custom", MappedPermissions: []config.LoginClassPermission{config.PermView}}},
	}}}
	const cliShell = "/usr/local/sbin/cli"
	for _, tc := range []struct {
		class string
		want  string
	}{
		{"super-user", loginShellBash},
		{"operator", cliShell},
		{"read-only", cliShell},
		{"config-viewer", cliShell},
		{"custom", cliShell},
		{"unauthorized", loginShellNologin},
		{"", loginShellNologin},
		{"undefined", loginShellNologin},
	} {
		t.Run(tc.class, func(t *testing.T) {
			if got := loginShellForClass(cfg, tc.class, cliShell); got != tc.want {
				t.Fatalf("loginShellForClass(%q) = %q, want %q", tc.class, got, tc.want)
			}
		})
	}
}

func TestApplySystemLoginRestrictsReadOnlyShell10833(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	shadow := filepath.Join(dir, "shadow")
	if err := os.WriteFile(passwd, []byte("alice:x:1001:1001:,,,:/home/alice:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadow, []byte("alice:!:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPasswd, oldShadow, oldUsersDir := passwdPath, shadowPath, provisionedUsersDir
	oldCandidates, oldRun := loginCLIShellCandidates, runCommandTimeout
	passwdPath, shadowPath = passwd, shadow
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	const cliShell = "/test/xpf/cli"
	loginCLIShellCandidates = []string{cliShell}
	t.Cleanup(func() {
		passwdPath, shadowPath, provisionedUsersDir = oldPasswd, oldShadow, oldUsersDir
		loginCLIShellCandidates, runCommandTimeout = oldCandidates, oldRun
	})

	var sawUsermod bool
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "id" {
			return nil, nil
		}
		if name != "usermod" {
			return nil, fmt.Errorf("unexpected command %q %v", name, args)
		}
		if len(args) != 4 || args[0] != "-s" || args[1] != cliShell || args[2] != "--" || args[3] != "alice" {
			return nil, fmt.Errorf("unexpected usermod argv %v", args)
		}
		sawUsermod = true
		data, err := os.ReadFile(passwd)
		if err != nil {
			return nil, err
		}
		updated := strings.Replace(string(data), ":/bin/bash\n", ":"+cliShell+"\n", 1)
		return nil, os.WriteFile(passwd, []byte(updated), 0o600)
	}

	cfg := loginCfg(&config.LoginUser{Name: "alice", Class: "read-only"})
	if err := (&Daemon{}).applySystemLogin(cfg); err != nil {
		t.Fatalf("applySystemLogin: %v", err)
	}
	if !sawUsermod {
		t.Fatal("read-only account kept its existing bash shell; usermod was not called")
	}
	data, err := os.ReadFile(passwd)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(strings.TrimSpace(string(data)), ":")[6]; got != cliShell {
		t.Fatalf("read-only passwd shell = %q, want CLI shell %q (bash must be unavailable)", got, cliShell)
	}
}

func TestApplySystemLoginCreatesRestrictedShell10833(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	shadow := filepath.Join(dir, "shadow")
	if err := os.WriteFile(passwd, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shadow, []byte("alice:!:19000:0:99999:7:::\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPasswd, oldShadow, oldUsersDir := passwdPath, shadowPath, provisionedUsersDir
	oldCandidates, oldRun := loginCLIShellCandidates, runCommandTimeout
	passwdPath, shadowPath = passwd, shadow
	provisionedUsersDir = filepath.Join(dir, "provisioned-users")
	const cliShell = "/test/xpf/cli"
	loginCLIShellCandidates = []string{cliShell}
	t.Cleanup(func() {
		passwdPath, shadowPath, provisionedUsersDir = oldPasswd, oldShadow, oldUsersDir
		loginCLIShellCandidates, runCommandTimeout = oldCandidates, oldRun
	})

	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		switch name {
		case "id":
			return nil, fmt.Errorf("user does not exist")
		case "useradd":
			want := []string{"-m", "-s", cliShell, "--", "alice"}
			if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
				return nil, fmt.Errorf("useradd argv = %v, want %v", args, want)
			}
			return nil, os.WriteFile(passwd, []byte("alice:x:1001:1001:,,,:/home/alice:"+cliShell+"\n"), 0o600)
		default:
			return nil, fmt.Errorf("unexpected command %q %v", name, args)
		}
	}

	cfg := loginCfg(&config.LoginUser{Name: "alice", Class: "read-only"})
	if err := (&Daemon{}).applySystemLogin(cfg); err != nil {
		t.Fatalf("applySystemLogin: %v", err)
	}
	data, err := os.ReadFile(passwd)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(strings.TrimSpace(string(data)), ":")[6]; got != cliShell {
		t.Fatalf("new read-only account shell = %q, want CLI shell %q", got, cliShell)
	}
}
