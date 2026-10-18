package daemon

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/crypto/ssh"
)

// realKey14692 returns (OpenSSH type, base64 blob) for a freshly generated
// public key of the requested kind, so type/key mismatch cells can pair a
// genuine blob of one algorithm with the Junos spelling of another.
func realKey14692(t *testing.T, kind string) (string, string) {
	t.Helper()
	var pub any
	switch kind {
	case "ssh-ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519 keygen: %v", err)
		}
		pub = priv.Public()
	case "ssh-rsa":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa keygen: %v", err)
		}
		pub = &priv.PublicKey
	case "ecdsa-sha2-nistp256":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa keygen: %v", err)
		}
		pub = &priv.PublicKey
	default:
		t.Fatalf("unknown kind %q", kind)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey(%s): %v", kind, err)
	}
	parts := strings.Fields(string(ssh.MarshalAuthorizedKey(sshPub)))
	if len(parts) != 2 {
		t.Fatalf("MarshalAuthorizedKey = %q", parts)
	}
	return parts[0], parts[1]
}

func applyKnownHosts14692(t *testing.T, path string, hosts map[string][]config.SSHKnownHostKey) string {
	t.Helper()
	cfg := &config.Config{}
	cfg.Security.SSHKnownHosts = hosts
	d := &Daemon{}
	d.applySSHKnownHosts(cfg)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatalf("read rendered known hosts: %v", err)
	}
	return string(data)
}

// TestApplySSHKnownHosts14692WildcardTrustRejected: a host field of `*`,
// `@cert-authority *`, a negated/wildcard list member, or a bracketed
// wildcard must never reach /etc/ssh/ssh_known_hosts — OpenSSH would honor
// it for every host, defeating StrictHostKeyChecking for archival scp.
// A valid entry alongside the poison must still render.
func TestApplySSHKnownHosts14692WildcardTrustRejected(t *testing.T) {
	path := withTempSSHKnownHostsPath(t)
	_, edBlob := realKey14692(t, "ssh-ed25519")
	ed := config.SSHKnownHostKey{Type: "ssh-ed25519-key", Key: edBlob}

	content := applyKnownHosts14692(t, path, map[string][]config.SSHKnownHostKey{
		"*":                 {ed},
		"@cert-authority *": {ed},
		"@cert-authority":   {ed},
		"@revoked *":        {ed},
		"!*":                {ed},
		"*,archive.example": {ed},
		"archive.example,*": {ed},
		"[*]:22":            {ed},
		"archive?.example":  {ed},
		"good.example":      {ed},
	})
	for _, bad := range []string{"@cert-authority", "@revoked", "*", "?", "[*]"} {
		if strings.Contains(content, bad) {
			t.Fatalf("wildcard/CA trust %q rendered into known hosts:\n%s", bad, content)
		}
	}
	want := "good.example ssh-ed25519 " + edBlob + "\n"
	if !strings.Contains(content, want) {
		t.Fatalf("valid entry missing, want %q in:\n%s", want, content)
	}
}

// TestApplySSHKnownHosts14692MalformedRejected: malformed hosts, unknown or
// mismatched key types, and non-canonical / injectable key blobs are
// skipped fail-closed; none of their lines may appear in the managed file.
func TestApplySSHKnownHosts14692MalformedRejected(t *testing.T) {
	path := withTempSSHKnownHostsPath(t)
	_, edBlob := realKey14692(t, "ssh-ed25519")
	_, rsaBlob := realKey14692(t, "ssh-rsa")

	content := applyKnownHosts14692(t, path, map[string][]config.SSHKnownHostKey{
		"[bad":           {{Type: "ssh-ed25519-key", Key: edBlob}},
		"bad host":       {{Type: "ssh-ed25519-key", Key: edBlob}},
		"bad\nhost":      {{Type: "ssh-ed25519-key", Key: edBlob}},
		"bad\thost":      {{Type: "ssh-ed25519-key", Key: edBlob}},
		"-oProxyCommand": {{Type: "ssh-ed25519-key", Key: edBlob}},
		"":               {{Type: "ssh-ed25519-key", Key: edBlob}},
		// Unknown / unmapped key type renders verbatim pre-fix.
		"unknown.example": {{Type: "evil-type", Key: edBlob}},
		// OpenSSH spelling without the Junos -key suffix is not a
		// recognized Junos spelling and must not pass through raw.
		"rawtype.example": {{Type: "ssh-ed25519", Key: edBlob}},
		// Type/key mismatch: RSA blob under an ed25519 type (and the
		// blob's internal algorithm disagrees with the rendered type).
		"mismatch.example":  {{Type: "ssh-ed25519-key", Key: rsaBlob}},
		"mismatch2.example": {{Type: "ssh-rsa-key", Key: edBlob}},
		// Injectable / malformed key material.
		"inject.example":   {{Type: "ssh-ed25519-key", Key: edBlob + "\nevil.example ssh-ed25519 " + edBlob}},
		"spacekey.example": {{Type: "ssh-ed25519-key", Key: edBlob + " extra"}},
		"badb64.example":   {{Type: "ssh-ed25519-key", Key: "!!!not-base64!!!"}},
		"garbage.example":  {{Type: "ssh-ed25519-key", Key: "aGVsbG8gd29ybGQ="}}, // base64 "hello world", not an SSH blob
		"emptykey.example": {{Type: "ssh-ed25519-key", Key: ""}},
		"good.example":     {{Type: "ssh-ed25519-key", Key: edBlob}},
	})
	for _, bad := range []string{
		"[bad", "bad host", "bad\nhost", "-oProxyCommand", "evil-type",
		"unknown.example", "rawtype.example", "mismatch.example", "mismatch2.example",
		"inject.example", "evil.example", "spacekey.example", "badb64.example",
		"garbage.example", "emptykey.example",
	} {
		if strings.Contains(content, bad) {
			t.Fatalf("malformed entry %q rendered into known hosts:\n%s", bad, content)
		}
	}
	// Exactly one data line (the valid entry) plus the header.
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("rendered %d lines, want header + 1 valid entry:\n%s", len(lines), content)
	}
	if !strings.Contains(content, "good.example ssh-ed25519 "+edBlob+"\n") {
		t.Fatalf("valid entry missing:\n%s", content)
	}
}

// TestApplySSHKnownHosts14692ValidFormsRender: legitimate host forms
// (hostname, IPv4, IPv6, [host]:port, comma list, hashed |1| entry) with
// correctly typed real keys still render, with Junos->OpenSSH mapping.
func TestApplySSHKnownHosts14692ValidFormsRender(t *testing.T) {
	path := withTempSSHKnownHostsPath(t)
	_, edBlob := realKey14692(t, "ssh-ed25519")
	_, rsaBlob := realKey14692(t, "ssh-rsa")
	_, ecBlob := realKey14692(t, "ecdsa-sha2-nistp256")

	content := applyKnownHosts14692(t, path, map[string][]config.SSHKnownHostKey{
		"archive.example":              {{Type: "ssh-ed25519-key", Key: edBlob}},
		"192.0.2.10":                   {{Type: "ssh-rsa-key", Key: rsaBlob}},
		"2001:db8::10":                 {{Type: "ecdsa-sha2-nistp256-key", Key: ecBlob}},
		"[archive.example]:2222":       {{Type: "ssh-ed25519-key", Key: edBlob}},
		"a.example,b.example":          {{Type: "ssh-ed25519-key", Key: edBlob}},
		"|1|abcd1234+/8=|efgh5678+/8=": {{Type: "ssh-ed25519-key", Key: edBlob}},
	})
	for _, want := range []string{
		"archive.example ssh-ed25519 " + edBlob + "\n",
		"192.0.2.10 ssh-rsa " + rsaBlob + "\n",
		"2001:db8::10 ecdsa-sha2-nistp256 " + ecBlob + "\n",
		"[archive.example]:2222 ssh-ed25519 " + edBlob + "\n",
		"a.example,b.example ssh-ed25519 " + edBlob + "\n",
		"|1|abcd1234+/8=|efgh5678+/8= ssh-ed25519 " + edBlob + "\n",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("valid line %q missing from:\n%s", want, content)
		}
	}
}

// TestApplySSHKnownHosts14692PoisonOnlyPreservesExisting: when every entry
// is invalid, a previously rendered managed file must not be replaced by a
// header-only (or poisoned) file.
func TestApplySSHKnownHosts14692PoisonOnlyPreservesExisting(t *testing.T) {
	path := withTempSSHKnownHostsPath(t)
	_, edBlob := realKey14692(t, "ssh-ed25519")
	ed := config.SSHKnownHostKey{Type: "ssh-ed25519-key", Key: edBlob}

	good := applyKnownHosts14692(t, path, map[string][]config.SSHKnownHostKey{"good.example": {ed}})
	if good == "" {
		t.Fatal("valid seed entry did not render")
	}
	after := applyKnownHosts14692(t, path, map[string][]config.SSHKnownHostKey{
		"*":                 {ed},
		"@cert-authority *": {ed},
	})
	if after != good {
		t.Fatalf("poison-only apply mutated managed file:\nbefore:\n%s\nafter:\n%s", good, after)
	}
}
