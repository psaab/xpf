package config_test

// Regression tests for #4902: several untyped `system` string leaves were
// rendered verbatim into root-owned host service / resolver config files
// (chrony, sshd, rsyslog, resolved/resolv.conf). The lexer decodes `\n` in a
// quoted string into a literal newline, and even a control-char-clean value
// with an embedded SPACE (a second directive token) or a path separator (a
// syslog filename) reached the generated config, injecting a directive or
// failing the service reload.
//
// The fix adds typed grammar validators, strict at commit-check:
//   - system ntp server              -> ValidateNTPServer (IP or DNS hostname)
//   - system domain-name/search      -> ValidateDNSDomain (DNS name)
//   - system services ssh {kex,ciphers,macs} -> ValidateSSHAlgorithm (algo token)
//   - system syslog file <name>      -> ValidateSyslogFileName (safe base name)
//   - system syslog user <user>      -> ValidateSyslogUser ('*' or safe name)
//
// Fail-on-revert: strip the validator/keyValidator from any leaf (or run
// against origin/master) and its "Rejects" cases below stop erroring.

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// --- Validator unit tables ----------------------------------------------

func TestValidateNTPServer_Table(t *testing.T) {
	valid := []string{"192.0.2.1", "2001:db8::1", "pool.ntp.org", "time.example.net", "ntp1", "a.b.c.d.example."}
	for _, v := range valid {
		if err := config.ValidateNTPServer(v); err != nil {
			t.Errorf("ValidateNTPServer(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"",                                   // empty
		"pool.example.net\nlocal stratum 10", // newline injection
		"pool.example.net local",             // embedded space (2nd chrony token)
		"pool.example.net iburst\nmakestep",  // newline injection
		"-bad.example",                       // leading hyphen label
		"a/b",                                // slash
		"has space",                          // space
	}
	for _, v := range invalid {
		if err := config.ValidateNTPServer(v); err == nil {
			t.Errorf("ValidateNTPServer(%q) = nil, want error", v)
		}
	}
}

func TestValidateDNSDomain_Table(t *testing.T) {
	valid := []string{"", "example.net", "corp.example.net", "example.net.", "a-b.example"}
	for _, v := range valid {
		if err := config.ValidateDNSDomain(v); err != nil {
			t.Errorf("ValidateDNSDomain(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"example.net\nDomains=evil", // newline injection
		"example.net evil.corp",     // embedded space (2nd search token)
		"-lead.example", "a..b", "a/b",
	}
	for _, v := range invalid {
		if err := config.ValidateDNSDomain(v); err == nil {
			t.Errorf("ValidateDNSDomain(%q) = nil, want error", v)
		}
	}
}

func TestValidateSSHAlgorithm_Table(t *testing.T) {
	valid := []string{
		"curve25519-sha256", "curve25519-sha256@libssh.org",
		"diffie-hellman-group-exchange-sha256", "aes256-gcm@openssh.com",
		"hmac-sha2-256-etm@openssh.com", "chacha20-poly1305@openssh.com",
	}
	for _, v := range valid {
		if err := config.ValidateSSHAlgorithm(v); err != nil {
			t.Errorf("ValidateSSHAlgorithm(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"",                            // empty
		"aes256-gcm,evil",             // comma (list separator / 2nd token)
		"aes256\nPermitRootLogin yes", // newline injection
		"aes 256",                     // space
		"-lead",                       // leading punctuation
	}
	for _, v := range invalid {
		if err := config.ValidateSSHAlgorithm(v); err == nil {
			t.Errorf("ValidateSSHAlgorithm(%q) = nil, want error", v)
		}
	}
}

func TestValidateSyslogFileName_Table(t *testing.T) {
	valid := []string{"messages", "kern.log", "xpf-audit", "app_1"}
	for _, v := range valid {
		if err := config.ValidateSyslogFileName(v); err != nil {
			t.Errorf("ValidateSyslogFileName(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"",                   // empty
		"../etc/cron.d/evil", // path traversal
		"a/b",                // slash
		"..",                 // dotdot
		"name\n*.* @evil",    // newline injection
		"has space",          // space
		"*",                  // glob (not a valid file base name here)
	}
	for _, v := range invalid {
		if err := config.ValidateSyslogFileName(v); err == nil {
			t.Errorf("ValidateSyslogFileName(%q) = nil, want error", v)
		}
	}
}

func TestValidateSyslogUser_Table(t *testing.T) {
	valid := []string{"*", "root", "netadmin", "user_1"}
	for _, v := range valid {
		if err := config.ValidateSyslogUser(v); err != nil {
			t.Errorf("ValidateSyslogUser(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{"", "a/b", "has space", "u\n:omusrmsg:*", ".."}
	for _, v := range invalid {
		if err := config.ValidateSyslogUser(v); err == nil {
			t.Errorf("ValidateSyslogUser(%q) = nil, want error", v)
		}
	}
}

// --- Commit-check gate: flat-set shape ----------------------------------

func TestSchema4902_FlatSet_Rejects(t *testing.T) {
	// Each of these commits verbatim into a root-owned service config on the
	// pre-fix code; SchemaValidate must now reject them.
	cases := []string{
		`set system ntp server "pool.example.net local stratum 10"`,
		`set system ntp server "pool.example.net\nlocal stratum 10"`,
		`set system domain-name "example.net evil.corp"`,
		`set system domain-search "example.net\nDomains=evil"`,
		`set system services ssh ciphers "aes256-gcm,evil"`,
		`set system services ssh macs "hmac-sha2-256\nPermitRootLogin yes"`,
		`set system services ssh key-exchange "curve25519 sha256"`,
		`set system syslog file "../etc/cron.d/evil" any any`,
		`set system syslog user "u\n:omusrmsg:*" any any`,
	}
	for _, c := range cases {
		if err := flatSchemaCheck(t, c); err == nil {
			t.Errorf("expected SchemaValidate to reject %q, got nil", c)
		}
	}
}

func TestSchema4902_FlatSet_Accepts(t *testing.T) {
	cases := []string{
		`set system ntp server 192.0.2.1`,
		`set system ntp server pool.ntp.org`,
		`set system domain-name example.net`,
		`set system domain-search corp.example.net`,
		`set system services ssh ciphers "aes256-gcm@openssh.com"`,
		`set system services ssh macs hmac-sha2-256`,
		`set system services ssh key-exchange curve25519-sha256`,
		`set system syslog file messages any any`,
		`set system syslog user "*" any any`,
	}
	for _, c := range cases {
		if err := flatSchemaCheck(t, c); err != nil {
			t.Errorf("expected SchemaValidate to accept %q, got %v", c, err)
		}
	}
}

// --- Commit-check gate: hierarchical (imported/saved) shape -------------

func TestSchema4902_Hierarchical_RejectsSyslogFileTraversal(t *testing.T) {
	// A space (non-control) name proves the keyValidator fires in the
	// hierarchical shape, not just the global control-char gate.
	if err := schemaCheck(t, `system {
    syslog {
        file "bad name" {
            any any;
        }
    }
}`); err == nil {
		t.Fatal("expected hierarchical syslog file name with a space to be rejected")
	}
}

func TestSchema4902_Hierarchical_RejectsNTPSpace(t *testing.T) {
	if err := schemaCheck(t, `system {
    ntp {
        server "pool.example.net prefer";
    }
}`); err == nil {
		t.Fatal("expected hierarchical ntp server with an embedded space to be rejected")
	}
}
