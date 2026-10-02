package config

import (
	"fmt"
	"strings"
)

// applicationALGHasDataplaneTag reports whether a configured application ALG
// has any destination-port/protocol tuple that the userspace session tagger
// recognizes. The per-application pin is not sent to userspace; conntrack
// tagging is inferred from these built-in service tuples instead.
func applicationALGHasDataplaneTag(app *Application) bool {
	alg := strings.TrimSpace(app.ALG)
	servicePort := 0
	switch {
	case strings.EqualFold(alg, "ftp"):
		servicePort = 21
	case strings.EqualFold(alg, "dns"):
		servicePort = 53
	case strings.EqualFold(alg, "sip"):
		servicePort = 5060
	default:
		// TFTP has no userspace conntrack tag; unsupported names are handled
		// by the existing accepted-with-advisory path.
		return false
	}

	proto := strings.TrimSpace(app.Protocol)
	switch {
	case strings.EqualFold(alg, "ftp"):
		if proto != "" && !strings.EqualFold(proto, "tcp") && proto != "6" {
			return false
		}
	case strings.EqualFold(alg, "dns"):
		if proto != "" && !strings.EqualFold(proto, "udp") && proto != "17" {
			return false
		}
	case strings.EqualFold(alg, "sip"):
		if proto != "" && !strings.EqualFold(proto, "tcp") && proto != "6" &&
			!strings.EqualFold(proto, "udp") && proto != "17" {
			return false
		}
	}

	spec := strings.TrimSpace(app.DestinationPort)
	if spec == "" {
		return true
	}
	if low, high, found := strings.Cut(spec, "-"); found {
		lo, errLo := parseCanonicalPort(low)
		hi, errHi := parseCanonicalPort(high)
		return errLo == nil && errHi == nil && lo <= servicePort && servicePort <= hi
	}
	port, err := parseCanonicalPort(spec)
	return err == nil && port == servicePort
}

func applicationALGInertWarning(name string, app *Application) string {
	pin := fmt.Sprintf("application %s: alg %q", name, app.ALG)
	if app.DestinationPort != "" {
		pin += fmt.Sprintf(" on destination-port %q", app.DestinationPort)
	}
	if strings.EqualFold(strings.TrimSpace(app.ALG), "tftp") {
		return pin + " accepted but has no dataplane effect — xpf has no TFTP session tagging; " +
			"per-application ALG enforcement is deferred to #2008"
	}
	return pin + " accepted but has no dataplane effect — userspace session tagging recognizes " +
		"only the well-known FTP TCP/21, DNS UDP/53, and SIP TCP/UDP/5060 tuples; " +
		"per-application ALG enforcement is deferred to #2008"
}
