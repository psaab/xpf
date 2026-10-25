package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func edBlob16770(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub.Marshal())
}

// TestSSHKnownHostsStrict16770RejectsAllInvalid: strict compile must reject
// an ssh-known-hosts entry the daemon renderer would skip (OpenSSH spelling
// without the Junos -key suffix, unknown type, malformed blob, wildcard
// host), naming host and type. Without the gate the commit succeeded while
// the old key stayed trusted (#16770).
func TestSSHKnownHostsStrict16770RejectsAllInvalid(t *testing.T) {
	blob := edBlob16770(t)
	cases := []struct {
		name, text, want string
	}{
		{"malformed blob", "security { ssh-known-hosts { host archive.example { ssh-ed25519-key notbase64token; } } }", "ssh-ed25519-key"},
		{"unknown type", "security { ssh-known-hosts { host archive.example { evil-type " + blob + "; } } }", "evil-type"},
		{"wildcard host", "security { ssh-known-hosts { host * { ssh-ed25519-key " + blob + "; } } }", "*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(parseHierText(t, tc.text))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict compile error = %v, want naming %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "ssh-known-hosts") {
				t.Fatalf("strict error must name ssh-known-hosts: %v", err)
			}
		})
	}
}

// TestSSHKnownHostsStrict16770ValidAndLenient: a valid entry compiles on
// both paths; an invalid entry compiles leniently with a warning (#1960)
// so the daemon can still revoke the stale managed file.
func TestSSHKnownHostsStrict16770ValidAndLenient(t *testing.T) {
	blob := edBlob16770(t)
	valid := "security { ssh-known-hosts { host archive.example { ssh-ed25519-key " + blob + "; } } }"
	if _, err := CompileConfig(parseHierText(t, valid)); err != nil {
		t.Fatalf("valid ssh-known-hosts rejected strict: %v", err)
	}
	invalid := "security { ssh-known-hosts { host archive.example { ssh-ed25519 " + blob + "; } } }"
	cfg, err := CompileConfigLenient(parseHierText(t, invalid))
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "ssh-known-hosts") {
			found = true
		}
	}
	if !found {
		t.Fatalf("lenient compile must warn on invalid ssh-known-hosts; warnings=%v", cfg.Warnings)
	}
	if len(cfg.Security.SSHKnownHosts["archive.example"]) != 1 {
		t.Fatalf("lenient compile must retain the entry for daemon revocation: %+v", cfg.Security.SSHKnownHosts)
	}
}
