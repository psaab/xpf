// Application/address name resolution helpers shared by the show
// presenters. The builtin-app table mirrors Junos predefined services;
// `resolveAppName` and `resolveAddress` walk the active config first
// and fall back to the table.
//
// Note: `resolveAppName`, `resolveAddress` are currently unused — they
// were superseded by appid-package resolution but have not been
// deleted yet. They are retained here so the pure-code-motion scope of
// #1444 remains mechanical. Deletion is tracked as a follow-up.
package cli

import (
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// builtinApp defines a well-known Junos application by protocol and port.
type builtinApp struct {
	proto uint8
	port  uint16
}

// builtinApps maps Junos application names to protocol/port.
var builtinApps = map[string]builtinApp{
	"junos-http":        {proto: 6, port: 80},
	"junos-https":       {proto: 6, port: 443},
	"junos-ssh":         {proto: 6, port: 22},
	"junos-telnet":      {proto: 6, port: 23},
	"junos-ftp":         {proto: 6, port: 21},
	"junos-smtp":        {proto: 6, port: 25},
	"junos-dns-tcp":     {proto: 6, port: 53},
	"junos-dns-udp":     {proto: 17, port: 53},
	"junos-bgp":         {proto: 6, port: 179},
	"junos-ntp":         {proto: 17, port: 123},
	"junos-snmp":        {proto: 17, port: 161},
	"junos-syslog":      {proto: 17, port: 514},
	"junos-dhcp-client": {proto: 17, port: 68},
	"junos-ike":         {proto: 17, port: 500},
	"junos-ipsec-nat-t": {proto: 17, port: 4500},
}

// resolveAppName resolves a session's protocol and destination port to a
// known application name, checking user-defined apps first then builtins.
func resolveAppName(proto uint8, dstPort uint16, cfg *config.Config) string {
	if cfg != nil {
		for name, app := range cfg.Applications.Applications {
			var appProto uint8
			switch strings.ToLower(app.Protocol) {
			case "tcp":
				appProto = 6
			case "udp":
				appProto = 17
			case "icmp":
				appProto = 1
			default:
				continue
			}
			if appProto != proto {
				continue
			}
			// Parse destination port (handle ranges like "8080-8090")
			portStr := app.DestinationPort
			if portStr == "" {
				continue
			}
			if strings.Contains(portStr, "-") {
				parts := strings.SplitN(portStr, "-", 2)
				lo, err1 := strconv.Atoi(parts[0])
				hi, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil && int(dstPort) >= lo && int(dstPort) <= hi {
					return name
				}
			} else {
				if v, err := strconv.Atoi(portStr); err == nil && uint16(v) == dstPort {
					return name
				}
			}
		}
	}
	for name, ba := range builtinApps {
		if ba.proto == proto && ba.port == dstPort {
			return name
		}
	}
	return ""
}

// resolveAddress looks up a named address in the global address book and returns its CIDR suffix.
//
// #9523: a match-all keyword is never looked up as a name (see
// config.IsPolicyAddressWildcardKeyword).
func resolveAddress(cfg *config.Config, name string) string {
	if config.IsPolicyAddressWildcardKeyword(name) {
		return ""
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return ""
	}
	if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
		return " (" + addr.Value + ")"
	}
	if _, ok := ab.AddressSets[name]; ok {
		return " (address-set)"
	}
	return ""
}
