package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #14691: a non-remote archive destination makes real OpenSSH scp perform a
// LOCAL copy of the unredacted staged config onto the destination as root.
// scpArchiveTransfer must refuse every such shape BEFORE exec and leave a
// sentinel target byte-identical. This test uses the REAL scp binary (no
// fake on PATH) with a valid non-empty known-hosts file staged, proving the
// old known-hosts pre-check could not stop a local copy.
//
// RED-on-revert: without the ArchiveDestinationError gate, scp local-copies
// the source over the sentinel (verified against OpenSSH scp: two colon-less
// operands exit 0 and overwrite the target without consulting SSH) and this
// test fails on the sentinel comparison / nil error.
func TestScpArchiveTransfer14691RejectsLocalDestination(t *testing.T) {
	dir := t.TempDir()
	knownHosts := filepath.Join(dir, "ssh_known_hosts")
	if err := os.WriteFile(knownHosts, []byte("archive.example ssh-ed25519 trusted-key\n"), 0o600); err != nil {
		t.Fatalf("write known hosts: %v", err)
	}
	oldKnownHosts := sshKnownHostsPath
	sshKnownHostsPath = knownHosts
	t.Cleanup(func() { sshKnownHostsPath = oldKnownHosts })

	sentinel := []byte("SENTINEL-14691-do-not-overwrite\n")
	target := filepath.Join(dir, "cron.d-x")
	if err := os.WriteFile(target, sentinel, 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	srcPath := filepath.Join(dir, "xpf.conf")
	secret := []byte("system { root-authentication { encrypted-password SECRET; } }\n")
	if err := os.WriteFile(srcPath, secret, 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	bad := []struct {
		name string
		dest string
	}{
		{"absolute local path", target},
		{"relative local path", "xpf.conf"},
		{"colon slash local", ":::/cfg"},
		{"scheme relative local", "//host/path"},
		{"colon only", ":"},
		{"user at only", "user@"},
		{"dash option", "-oProxyCommand=evil"},
		{"user dash host", "user@-oProxyCommand=evil:/cfg"},
		{"empty user", "@host:/cfg"},
		{"ftp scheme", "ftp://host/dir"},
		{"scp url empty host", "scp:///cfg"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if err := scpArchiveTransfer(context.Background(), srcPath, tc.dest); err == nil {
				t.Fatalf("scpArchiveTransfer(%q) succeeded; want pre-exec rejection", tc.dest)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("read sentinel: %v", err)
			}
			if string(got) != string(sentinel) {
				t.Fatalf("sentinel target overwritten by local destination %q: got %q", tc.dest, got)
			}
		})
	}
}

// The runtime gate fires even when no SSH trust is configured: destination
// validation precedes the trust-file stat, so a local destination is refused
// for its own reason rather than the missing-trust reason.
func TestScpArchiveTransfer14691LocalRejectedBeforeTrustCheck(t *testing.T) {
	dir := t.TempDir()
	oldKnownHosts := sshKnownHostsPath
	sshKnownHostsPath = filepath.Join(dir, "absent_known_hosts")
	t.Cleanup(func() { sshKnownHostsPath = oldKnownHosts })
	srcPath := filepath.Join(dir, "xpf.conf")
	if err := os.WriteFile(srcPath, []byte("system {}\n"), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	err := scpArchiveTransfer(context.Background(), srcPath, "/etc/cron.d/x")
	if err == nil {
		t.Fatal("local destination without trust unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "SSH host-key trust") {
		t.Fatalf("local destination rejected for trust reason, want destination reason: %v", err)
	}
}
