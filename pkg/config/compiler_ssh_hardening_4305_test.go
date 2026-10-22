package config

import (
	"strings"
	"testing"
)

// TestSSHHardeningKnobsCompiled is the RED-on-revert guard for #4305 S-4: the
// SSH hardening knobs must reach SSHServiceConfig (the compiler previously read
// only root-login + key-exchange, so these were silently inert), and the
// config must commit clean.
func TestSSHHardeningKnobsCompiled(t *testing.T) {
	tree := buildTree4303(t, []string{
		// Bracketed list (must not be truncated to the first element) plus a
		// quoted OpenSSH `@`-suffixed name (the lexer accepts `@` when quoted).
		"set system services ssh ciphers [ aes256-ctr aes192-ctr ]",
		`set system services ssh macs "hmac-sha2-512-etm@openssh.com"`,
		"set system services ssh connection-limit 10",
		"set system services ssh client-alive-interval 120",
		"set system services ssh client-alive-count-max 3",
		"set system services ssh protocol-version v2",
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected valid SSH hardening config: %v", err)
	}
	if c.System.Services == nil || c.System.Services.SSH == nil {
		t.Fatalf("no SSH config compiled")
	}
	ssh := c.System.Services.SSH
	if len(ssh.Ciphers) != 2 || ssh.Ciphers[0] != "aes256-ctr" || ssh.Ciphers[1] != "aes192-ctr" {
		t.Fatalf("Ciphers = %v, want [aes256-ctr aes192-ctr] (bracketed list not truncated)", ssh.Ciphers)
	}
	if len(ssh.MACs) != 1 || ssh.MACs[0] != "hmac-sha2-512-etm@openssh.com" {
		t.Fatalf("MACs = %v", ssh.MACs)
	}
	if ssh.ConnectionLimit != 10 {
		t.Fatalf("ConnectionLimit = %d, want 10", ssh.ConnectionLimit)
	}
	if !ssh.ClientAliveIntervalSet || ssh.ClientAliveInterval != 120 {
		t.Fatalf("ClientAliveInterval = %d set=%v, want 120/true", ssh.ClientAliveInterval, ssh.ClientAliveIntervalSet)
	}
	if !ssh.ClientAliveCountMaxSet || ssh.ClientAliveCountMax != 3 {
		t.Fatalf("ClientAliveCountMax = %d set=%v, want 3/true", ssh.ClientAliveCountMax, ssh.ClientAliveCountMaxSet)
	}
}

// TestSSHProtocolVersionAdvisory checks the accept-with-advisory path: a
// non-v2 protocol-version commits (sshd is SSH-2 only) but emits an advisory;
// v2 is a silent no-op.
func TestSSHProtocolVersionAdvisory(t *testing.T) {
	tree := buildTree4303(t, []string{
		"set system services ssh protocol-version v1",
	})
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("protocol-version v1 should commit (accept-with-advisory): %v", err)
	}
	found := false
	for _, w := range c.Warnings {
		if strings.Contains(w, "protocol-version") && strings.Contains(w, "SSH-2") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an SSH-2-only advisory for protocol-version v1; warnings=%v", c.Warnings)
	}
}
