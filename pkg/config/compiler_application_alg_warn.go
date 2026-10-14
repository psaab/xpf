package config

import (
	"fmt"
	"strings"
)

// applicationALGHasDataplaneTag reports whether a configured application ALG
// has any destination-port/protocol tuple that the userspace session tagger
// both recognizes and is allowed to tag (#12837). Two facts beyond the raw
// spelling feed that judgment:
//
//   - the protocol token may be a Junos predefined alias (`junos-tcp-any` /
//     `junos-udp-any`) or a numeric string; the appid SSOT (ProtocolNumber)
//     resolves those to 6/17, and sessions under them are tagged, so matching
//     only the literal "tcp"/"udp" here false-warned a perfectly tagged pin;
//   - `security alg <proto> disable` makes the tagger
//     (publish_conntrack.rs alg_type_for_session) stamp ALG_TYPE_NONE for
//     EVERY tuple of that ALG — the global bitfield is the only ALG config
//     on the wire — so a disabled ALG has no dataplane tag even on its
//     well-known service port, and the pin must warn naming that knob.
//
// The per-application pin is not sent to userspace; conntrack tagging is
// inferred from these built-in service tuples instead.
func applicationALGHasDataplaneTag(app *Application, alg *ALGConfig) bool {
	if !applicationALGTupleTaggable(app) {
		return false
	}
	algName := strings.ToLower(strings.TrimSpace(app.ALG))
	return alg == nil || !alg.ALGDisabled(algName)
}

// applicationALGTupleTaggable is the protocol/port half of
// applicationALGHasDataplaneTag: whether any destination-port/protocol tuple
// of the pin is one the tagger recognizes when the ALG is enabled. Kept
// separate so the warning wording can distinguish "this tuple is never tagged"
// (custom port, foreign protocol) from "the tuple is taggable but the global
// disable knob turns tagging off" (#12837).
func applicationALGTupleTaggable(app *Application) bool {
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
	if proto != "" {
		n := applicationALGProtocolNumber(proto)
		switch {
		case strings.EqualFold(alg, "ftp"):
			if n != 6 {
				return false
			}
		case strings.EqualFold(alg, "dns"):
			if n != 17 {
				return false
			}
		case strings.EqualFold(alg, "sip"):
			if n != 6 && n != 17 {
				return false
			}
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

// applicationALGProtocolNumber resolves a custom application's protocol token
// to 6 (TCP) or 17 (UDP); 0 means "neither". It mirrors exactly the tcp/udp
// rows of the appid SSOT (appid.ProtocolNumber, pkg/appid/catalog.go) —
// pkg/config cannot import that leaf package — including the canonical
// numeric spellings, so the warn pass judges the SAME tokens the catalog and
// the tagger resolve. The aliases also fold via normalizeProtocol, but that
// helper returns a canonical NAME while the tag judgment needs the NUMBER.
func applicationALGProtocolNumber(proto string) int {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "tcp", "junos-tcp-any":
		return 6
	case "udp", "junos-udp-any":
		return 17
	}
	if n, err := ParseCanonicalUint(proto); err == nil && (n == 6 || n == 17) {
		return n
	}
	return 0
}

func applicationALGInertWarning(name string, app *Application, alg *ALGConfig) string {
	pin := fmt.Sprintf("application %s: alg %q", name, app.ALG)
	if app.DestinationPort != "" {
		pin += fmt.Sprintf(" on destination-port %q", app.DestinationPort)
	}
	algName := strings.ToLower(strings.TrimSpace(app.ALG))
	if strings.EqualFold(algName, "tftp") {
		return pin + " accepted but has no dataplane effect — xpf has no TFTP session tagging; " +
			"per-application ALG enforcement is deferred to #2008"
	}
	// Distinguish the two inertness causes (#12837): a tuple the tagger would
	// tag is inert solely because the global disable knob turns the whole ALG
	// off — name the knob so the operator sees which config nullified the pin.
	if applicationALGTupleTaggable(app) && alg != nil && alg.ALGDisabled(algName) {
		return pin + " accepted but has no dataplane effect — `security alg " + algName +
			" disable` turns off userspace " + strings.ToUpper(algName) +
			" session tagging on every tuple; per-application ALG enforcement is deferred to #2008"
	}
	return pin + " accepted but has no dataplane effect — userspace session tagging recognizes " +
		"only the well-known FTP TCP/21, DNS UDP/53, and SIP TCP/UDP/5060 tuples; " +
		"per-application ALG enforcement is deferred to #2008"
}
