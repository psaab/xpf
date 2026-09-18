package daemon

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const fakeSCP10298 = `#!/bin/sh
set -eu
: "${FAKE_SCP_ARGS:?}"
printf '%s\n' "$@" > "$FAKE_SCP_ARGS"
strict=no
known=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            shift
            case "$1" in
                StrictHostKeyChecking=*) strict=${1#StrictHostKeyChecking=} ;;
                UserKnownHostsFile=*) known=${1#UserKnownHostsFile=} ;;
            esac
            ;;
    esac
    shift
done
# Model OpenSSH's security decision: this fake endpoint presents the key in
# FAKE_SCP_PRESENTED_KEY, and only a strict check against the configured
# UserKnownHostsFile may accept it. The pre-fix StrictHostKeyChecking=no argv
# therefore accepts the MITM and makes the RED assertion fail.
if [ "$strict" != "yes" ] || [ -z "$known" ]; then
    exit 0
fi
trusted=$(awk 'NF >= 3 && $1 !~ /^#/ { print $3; exit }' "$known")
if [ "${FAKE_SCP_PRESENTED_KEY:-}" != "$trusted" ]; then
    printf 'Host key verification failed\n' >&2
    exit 255
fi
exit 0
`

func stageFakeSCP10298(t *testing.T) (knownHosts, argsPath string) {
	t.Helper()
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir fake scp dir: %v", err)
	}
	scpPath := filepath.Join(binDir, "scp")
	if err := os.WriteFile(scpPath, []byte(fakeSCP10298), 0o755); err != nil {
		t.Fatalf("write fake scp: %v", err)
	}
	argsPath = filepath.Join(dir, "scp-args")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_SCP_ARGS", argsPath)
	knownHosts = filepath.Join(dir, "ssh_known_hosts")
	oldKnownHosts := sshKnownHostsPath
	sshKnownHostsPath = knownHosts
	t.Cleanup(func() { sshKnownHostsPath = oldKnownHosts })
	return knownHosts, argsPath
}

// TestScpArchiveTransfer10298RejectsMITMAndAcceptsTrustedKey is the primary
// #10298 RED-on-revert guard. A fake scp endpoint models OpenSSH host-key
// verification: a presented key that differs from UserKnownHostsFile is
// refused, while the configured key succeeds. Reverting the production argv
// to StrictHostKeyChecking=no makes the first assertion RED.
func TestScpArchiveTransfer10298RejectsMITMAndAcceptsTrustedKey(t *testing.T) {
	knownHosts, argsPath := stageFakeSCP10298(t)
	if err := os.WriteFile(knownHosts, []byte("# Managed by xpfd — do not edit\narchive.example ssh-ed25519 trusted-key\n"), 0o600); err != nil {
		t.Fatalf("write known hosts: %v", err)
	}
	srcPath := filepath.Join(t.TempDir(), "xpf.conf")
	if err := os.WriteFile(srcPath, []byte("system { host-name archived; }\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	dest := "scp://archive.example:/configs"

	t.Setenv("FAKE_SCP_PRESENTED_KEY", "attacker-key")
	if err := scpArchiveTransfer(context.Background(), srcPath, dest); err == nil {
		t.Fatal("MITM archival unexpectedly succeeded; host-key mismatch must fail closed")
	} else if !strings.Contains(err.Error(), "Host key verification failed") {
		t.Fatalf("MITM error = %v, want host-key verification failure", err)
	}

	t.Setenv("FAKE_SCP_PRESENTED_KEY", "trusted-key")
	if err := scpArchiveTransfer(context.Background(), srcPath, dest); err != nil {
		t.Fatalf("correct-key archival failed: %v", err)
	}

	gotArgsBytes, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read captured scp argv: %v", err)
	}
	gotArgs := strings.Split(strings.TrimSuffix(string(gotArgsBytes), "\n"), "\n")
	wantArgs := []string{
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		srcPath, dest,
	}
	if !reflect.DeepEqual(gotArgs, wantArgs) {
		t.Fatalf("scp argv = %q, want %q", gotArgs, wantArgs)
	}
}

// TestScpArchiveTransfer10298MissingTrustFailsClosed proves archival never
// falls back to the user's global known_hosts or unchecked mode when xpfd's
// rendered trust file is absent. Reverting the pre-exec trust gate makes this
// RED because the fake scp accepts the old StrictHostKeyChecking=no argv.
func TestScpArchiveTransfer10298MissingTrustFailsClosed(t *testing.T) {
	knownHosts, argsPath := stageFakeSCP10298(t)
	if err := os.Remove(knownHosts); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove known hosts: %v", err)
	}
	srcPath := filepath.Join(t.TempDir(), "xpf.conf")
	if err := os.WriteFile(srcPath, []byte("system { host-name archived; }\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	err := scpArchiveTransfer(context.Background(), srcPath, "scp://archive.example:/configs")
	if err == nil {
		t.Fatal("archival without rendered SSH trust unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "no SSH host-key trust") {
		t.Fatalf("missing-trust error = %v, want explicit fail-closed reason", err)
	}
	if _, statErr := os.Stat(argsPath); !os.IsNotExist(statErr) {
		t.Fatalf("scp was invoked despite missing trust file (stat err=%v)", statErr)
	}
}

// TestScpArchiveTransfer10298RejectsLeadingDashDestination verifies the
// runtime boundary remains safe even if a tolerant-load/direct caller bypasses
// the compiler's archive-site validation. Reverting this guard lets scp parse
// the destination as an option after the unsupported `--` separator is gone.
func TestScpArchiveTransfer10298RejectsLeadingDashDestination(t *testing.T) {
	knownHosts, argsPath := stageFakeSCP10298(t)
	if err := os.WriteFile(knownHosts, []byte("archive.example ssh-ed25519 trusted-key\n"), 0o600); err != nil {
		t.Fatalf("write known hosts: %v", err)
	}
	srcPath := filepath.Join(t.TempDir(), "xpf.conf")
	if err := os.WriteFile(srcPath, []byte("system { host-name archived; }\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	err := scpArchiveTransfer(context.Background(), srcPath, "-oProxyCommand=evil")
	if err == nil {
		t.Fatal("leading-dash archival destination unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "must not begin with '-'") {
		t.Fatalf("leading-dash error = %v, want destination rejection", err)
	}
	if _, statErr := os.Stat(argsPath); !os.IsNotExist(statErr) {
		t.Fatalf("scp was invoked for leading-dash destination (stat err=%v)", statErr)
	}
}

// TestScpArchiveTransfer10298OpenSSHLoopbackKeySwap exercises the exact
// production scp argv against a real loopback OpenSSH server. The server owns
// the trusted host key; the rendered file first contains a different key
// (MITM/wrong-key refusal), then is updated to the server key (legitimate
// rotation succeeds). This is intentionally not a fake scp decision model.
func TestScpArchiveTransfer10298OpenSSHLoopbackKeySwap(t *testing.T) {
	const (
		sshdPath       = "/usr/sbin/sshd"
		scpPath        = "/usr/bin/scp"
		sshKeygenPath  = "/usr/bin/ssh-keygen"
		sftpServerPath = "/usr/lib/openssh/sftp-server"
	)
	for _, path := range []string{sshdPath, scpPath, sshKeygenPath, sftpServerPath} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("OpenSSH loopback prerequisites unavailable: %s: %v", path, err)
		}
	}

	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("create test home: %v", err)
	}
	hostKey := filepath.Join(root, "host_ed25519")
	wrongHostKey := filepath.Join(root, "wrong_host_ed25519")
	clientKey := filepath.Join(home, ".ssh", "id_ed25519")
	for _, keyPath := range []string{hostKey, wrongHostKey, clientKey} {
		out, keygenErr := exec.Command(sshKeygenPath, "-q", "-t", "ed25519", "-N", "", "-f", keyPath).CombinedOutput()
		if keygenErr != nil {
			t.Fatalf("generate SSH key %s: %v (%s)", keyPath, keygenErr, strings.TrimSpace(string(out)))
		}
	}
	clientPub, err := os.ReadFile(clientKey + ".pub")
	if err != nil {
		t.Fatalf("read client public key: %v", err)
	}
	authorizedKeys := filepath.Join(root, "authorized_keys")
	if err := os.WriteFile(authorizedKeys, clientPub, 0o600); err != nil {
		t.Fatalf("write authorized keys: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	sshdConfig := filepath.Join(root, "sshd_config")
	configText := fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
AuthorizedKeysFile %s
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
StrictModes no
AllowUsers %s
Subsystem sftp %s
LogLevel ERROR
`, port, hostKey, filepath.Join(root, "sshd.pid"), authorizedKeys, currentUser.Username, sftpServerPath)
	if err := os.WriteFile(sshdConfig, []byte(configText), 0o600); err != nil {
		t.Fatalf("write sshd config: %v", err)
	}
	var sshdLog bytes.Buffer
	sshd := exec.Command(sshdPath, "-D", "-e", "-f", sshdConfig)
	sshd.Stdout = &sshdLog
	sshd.Stderr = &sshdLog
	if err := sshd.Start(); err != nil {
		t.Fatalf("start sshd: %v", err)
	}
	t.Cleanup(func() {
		if sshd.Process != nil {
			_ = sshd.Process.Kill()
		}
		_ = sshd.Wait()
	})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshd did not listen on %s: %v\n%s", addr, dialErr, sshdLog.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("create scp PATH: %v", err)
	}
	scpWrapper := filepath.Join(binDir, "scp")
	if err := os.WriteFile(scpWrapper, []byte(fmt.Sprintf("#!/bin/sh\nexec %s -i %s -o IdentitiesOnly=yes \"$@\"\n", scpPath, clientKey)), 0o755); err != nil {
		t.Fatalf("write scp wrapper: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", home)

	knownHosts := filepath.Join(root, "ssh_known_hosts")
	oldKnownHosts := sshKnownHostsPath
	sshKnownHostsPath = knownHosts
	t.Cleanup(func() { sshKnownHostsPath = oldKnownHosts })
	wrongPub, err := os.ReadFile(wrongHostKey + ".pub")
	if err != nil {
		t.Fatalf("read wrong host public key: %v", err)
	}
	trustedPub, err := os.ReadFile(hostKey + ".pub")
	if err != nil {
		t.Fatalf("read trusted host public key: %v", err)
	}
	writeKnownHost := func(pub []byte) {
		t.Helper()
		line := "[127.0.0.1]:" + strconv.Itoa(port) + " " + strings.TrimSpace(string(pub)) + "\n"
		if err := os.WriteFile(knownHosts, []byte(line), 0o600); err != nil {
			t.Fatalf("write rendered known hosts: %v", err)
		}
	}
	writeKnownHost(wrongPub)

	srcPath := filepath.Join(root, "source.conf")
	placeholder, err := os.CreateTemp(currentUser.HomeDir, ".xpf-archive-10298-*.conf")
	if err != nil {
		t.Fatalf("reserve collision-free remote destination: %v", err)
	}
	remotePath := placeholder.Name()
	remoteName := filepath.Base(remotePath)
	if err := placeholder.Close(); err != nil {
		t.Fatalf("close remote destination placeholder: %v", err)
	}
	if err := os.Remove(remotePath); err != nil {
		t.Fatalf("remove remote destination placeholder: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(remotePath) })
	const contents = "system { host-name openssh-verified; }\n"
	if err := os.WriteFile(srcPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write source config: %v", err)
	}
	dest := fmt.Sprintf("scp://%s@127.0.0.1:%d/%s", currentUser.Username, port, remoteName)

	if err := scpArchiveTransfer(context.Background(), srcPath, dest); err == nil {
		t.Fatal("OpenSSH accepted a wrong host key; MITM archival must fail closed")
	} else if !strings.Contains(err.Error(), "Host key verification failed") {
		t.Fatalf("wrong-key OpenSSH error = %v, want host-key verification failure", err)
	}

	writeKnownHost(trustedPub)
	if err := scpArchiveTransfer(context.Background(), srcPath, dest); err != nil {
		t.Fatalf("OpenSSH archival with trusted key failed: %v", err)
	}
	got, err := os.ReadFile(remotePath)
	if err != nil {
		t.Fatalf("read OpenSSH archive destination: %v", err)
	}
	if string(got) != contents {
		t.Fatalf("OpenSSH archive contents = %q, want %q", got, contents)
	}
}
