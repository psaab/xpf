package config

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/rendersafe"
)

// ValidateBridgeDomainName admits a bridge-domain name that is safe to become a
// device name and a networkd file name (#9494). The dataplane names the bridge
// "br-" + <name> and xpfd writes 10-xpf-br-<name>.{netdev,network} under
// /etc/systemd/network, so a "/" let a committed name write outside that
// directory as root while the commit reported success. Bridge-domain names are
// plain identifiers; separators, NUL and whitespace never belong in one.
// Glob metacharacters are a separate [Match] Name= claim hazard (#10089).
func ValidateBridgeDomainName(raw string, _ *Config) error {
	if raw == "" {
		return fmt.Errorf("missing bridge-domain name")
	}
	if strings.ContainsAny(raw, "/\\\x00") {
		return fmt.Errorf("bridge-domain name %q must not contain a path separator or NUL: it becomes a device and file name (#9494)", raw)
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("bridge-domain name %q must not contain whitespace", raw)
	}
	if glob := rendersafe.FirstGlobMetacharacter(raw); glob != "" {
		return fmt.Errorf("bridge-domain name %q contains the glob metacharacter %q; it becomes [Match] Name=br-%s and systemd reads that as a shell-style glob claiming every matching interface (#10089)", raw, glob, raw)
	}
	return nil
}
