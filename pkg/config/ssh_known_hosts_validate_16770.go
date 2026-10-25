package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SSHKnownHostTypes maps Junos key-type spellings (and the legacy short
// spellings used with real keys, #10078) to the OpenSSH algorithm name that
// must also match the algorithm embedded in the decoded key blob. Any
// spelling outside this map is rejected (#14692, #16770). Moved from
// pkg/daemon so the commit-time gate and the render-time belt share one
// table and cannot drift (#16770).
var SSHKnownHostTypes = map[string]string{
	"ssh-rsa-key":                                  "ssh-rsa",
	"rsa-key":                                      "ssh-rsa",
	"ssh-ed25519-key":                              "ssh-ed25519",
	"ed25519-key":                                  "ssh-ed25519",
	"ssh-ecdsa-key":                                "ecdsa-sha2-nistp256",
	"ecdsa-key":                                    "ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp256-key":                      "ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384-key":                      "ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp521-key":                      "ecdsa-sha2-nistp521",
	"sk-ssh-ed25519@openssh.com-key":               "sk-ssh-ed25519@openssh.com",
	"sk-ecdsa-sha2-nistp256@openssh.com-key":       "sk-ecdsa-sha2-nistp256@openssh.com",
	"ssh-rsa-cert-v01@openssh.com-key":             "ssh-rsa-cert-v01@openssh.com",
	"ssh-ed25519-cert-v01@openssh.com-key":         "ssh-ed25519-cert-v01@openssh.com",
	"ecdsa-sha2-nistp256-cert-v01@openssh.com-key": "ecdsa-sha2-nistp256-cert-v01@openssh.com",
	"ecdsa-sha2-nistp384-cert-v01@openssh.com-key": "ecdsa-sha2-nistp384-cert-v01@openssh.com",
	"ecdsa-sha2-nistp521-cert-v01@openssh.com-key": "ecdsa-sha2-nistp521-cert-v01@openssh.com",
}

// ValidSSHKnownHostField reports whether host is a single OpenSSH
// known_hosts host pattern that cannot widen trust. It rejects empty
// fields, whitespace/control (newline injection), leading '-' and '@'
// markers (@cert-authority / @revoked), and '*'/'?' wildcards in any
// comma-separated member. Allowed: hostnames, IP literals, [host]:port,
// and hashed |1|salt|hash entries.
func ValidSSHKnownHostField(host string) bool {
	if host == "" {
		return false
	}
	for _, r := range host {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	if strings.HasPrefix(host, "|1|") {
		parts := strings.Split(host, "|")
		if len(parts) != 4 || parts[0] != "" || parts[1] != "1" {
			return false
		}
		salt, err1 := base64.StdEncoding.DecodeString(parts[2])
		hash, err2 := base64.StdEncoding.DecodeString(parts[3])
		return err1 == nil && err2 == nil && len(salt) > 0 && len(hash) > 0
	}
	if strings.ContainsAny(host, "*?@") || strings.HasPrefix(host, "-") || strings.HasPrefix(host, "!") {
		return false
	}
	for _, member := range strings.Split(host, ",") {
		if !validSSHKnownHostMember(member) {
			return false
		}
	}
	return true
}

func validSSHKnownHostMember(member string) bool {
	if member == "" || strings.HasPrefix(member, "-") || strings.HasPrefix(member, "!") {
		return false
	}
	name := member
	if strings.HasPrefix(member, "[") {
		end := strings.Index(member, "]")
		if end <= 1 || end+1 >= len(member) || member[end+1] != ':' {
			return false
		}
		port, err := strconv.Atoi(member[end+2:])
		if err != nil || port < 1 || port > 65535 {
			return false
		}
		name = member[1:end]
		if name == "" || strings.ContainsAny(name, "[]") {
			return false
		}
	} else if strings.ContainsAny(member, "[]") {
		return false
	}
	if ip := net.ParseIP(name); ip != nil {
		return true
	}
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

// ValidSSHKnownHostKey validates one configured key against its mapped
// OpenSSH type, returning the canonical OpenSSH type and base64 blob to
// render. The blob must be a single whitespace-free base64 token, decode
// canonically, parse as that exact algorithm via ssh.ParsePublicKey, and
// re-marshal to the same canonical encoding. This rejects unknown types,
// type/key mismatches, truncated legacy markers, and newline/space
// injection.
func ValidSSHKnownHostKey(key SSHKnownHostKey) (string, string, bool) {
	sshType, ok := SSHKnownHostTypes[key.Type]
	if !ok || key.Key == "" {
		return "", "", false
	}
	for _, r := range key.Key {
		if r <= ' ' || r == 0x7f {
			return "", "", false
		}
	}
	raw, err := base64.StdEncoding.DecodeString(key.Key)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != key.Key {
		return "", "", false
	}
	pub, err := ssh.ParsePublicKey(raw)
	if err != nil || pub.Type() != sshType {
		return "", "", false
	}
	canonical := base64.StdEncoding.EncodeToString(pub.Marshal())
	return sshType, canonical, true
}

// ValidateSSHKnownHostsStrict rejects any ssh-known-hosts entry whose host
// field or key would be skipped by the daemon renderer (#16770). Without
// this gate an all-invalid replacement committed cleanly while the daemon
// kept the previously rendered trust. Strict commit rejects naming host
// and type (never the key material); the tolerant path downgrades to a
// warning and the daemon's all-invalid removal revokes the stale file.
// Every entry is checked; a truncated Junos-style marker is therefore
// also rejected strict (it was only ever a test-fixture shorthand).
func ValidateSSHKnownHostsStrict(cfg *Config) error {
	if cfg == nil || len(cfg.Security.SSHKnownHosts) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(cfg.Security.SSHKnownHosts))
	for h := range cfg.Security.SSHKnownHosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		if !ValidSSHKnownHostField(host) {
			return fmt.Errorf("security ssh-known-hosts host %q: invalid host pattern (wildcard, marker, or malformed host)", host)
		}
		for _, key := range cfg.Security.SSHKnownHosts[host] {
			if _, _, ok := ValidSSHKnownHostKey(key); !ok {
				return fmt.Errorf("security ssh-known-hosts host %q: invalid key for type %q (unknown type, type/key mismatch, or malformed key blob)", host, key.Type)
			}
		}
	}
	return nil
}
