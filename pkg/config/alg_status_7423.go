package config

import "strings"

// ALG status wording (#7423 row 6).
//
// SINGLE authority for how `security alg` is described on an operator surface,
// in the same shape and for the same reason as flow_tcp_timeouts_6539.go: the
// CLI, gRPC and REST all render this stanza, and three surfaces disagreeing
// about whether something is enforced is always a bug rather than a legitimate
// divergence. Layout stays per-surface; only the WORDING and the proto set are
// shared, so a change to what an ALG actually does is one edit rather than
// three that can drift apart.
//
// Why none of them says "enabled": for DNS/FTP/SIP nothing in the userspace
// dataplane performs data-channel pinholing or payload doctoring. Those bits
// reach exactly one consumer, alg_type_for_session, which stamps a tag on
// the conntrack row for `show security flow session`. A non-disabled
// DNS/FTP/SIP ALG is session-tagged, not enforcing anything, and "enabled"
// invites an operator to leave a pinhole unconfigured in the belief that
// the firewall is tracking the control channel.
//
// PPTP (#15655 V12-01) is different: the Rust dataplane DOES implement the
// RFC 2637 ALG — TCP/1723 control learning and GRE v1 Call-ID data
// association — so a non-disabled PPTP renders as control-inspected, and
// `pptp disable` (bit 0x10) turns that learning/association off.
//
// TFTP is weaker still and is worded differently on purpose: it has no
// alg_type at all, and its wire bit is #[allow(dead_code)] in the Rust helper,
// whose own comment says it "has no consumer here". It is recorded, not tagged
// and not enforced.
const (
	ALGProtoDNS  = "dns"
	ALGProtoFTP  = "ftp"
	ALGProtoSIP  = "sip"
	ALGProtoTFTP = "tftp"
	ALGProtoPPTP = "pptp"

	ALGStatusDisabled       = "disabled"
	ALGStatusSessionTagged  = "session-tagged (no data-channel pinholing)"
	ALGStatusRecordedOnly   = "configured (not enforced)"
	ALGStatusNotImplemented = "configured (not implemented)"
	// ALGStatusPPTPActive describes the live PPTP ALG: control-channel
	// inspection and GRE Call-ID association are performed.
	ALGStatusPPTPActive = "control-inspected (GRE Call-ID association)"
)

// ALGModeledProtos returns the ALGs `security alg` actually models, in the
// order every surface renders them. Sharing the order as well as the wording
// means the three surfaces cannot disagree about which ALGs exist either --
// they previously rendered the same four in three different orders, and the
// CLI additionally rendered twelve that do not exist at all.
func ALGModeledProtos() []string {
	return []string{ALGProtoDNS, ALGProtoFTP, ALGProtoSIP, ALGProtoTFTP, ALGProtoPPTP}
}

// ALGDisplayName is the operator-facing spelling of a proto name.
func ALGDisplayName(proto string) string { return strings.ToUpper(proto) }

// ALGStatusText returns the status for one modeled ALG. proto is the lower-case
// Junos leaf name; disabled is the corresponding *Disable field.
func ALGStatusText(proto string, disabled bool) string {
	if disabled {
		return ALGStatusDisabled
	}
	if proto == ALGProtoTFTP {
		return ALGStatusRecordedOnly
	}
	if proto == ALGProtoPPTP {
		return ALGStatusPPTPActive
	}
	return ALGStatusSessionTagged
}

// ALGStatusUnmodeled is the status for a `security alg <proto>` stanza recorded
// in UnsupportedProtos (#4232). Such a stanza is accepted at commit and has no
// behaviour, so it must render as configured-but-inert rather than vanish from
// the surface an operator checks.
func ALGStatusUnmodeled() string { return ALGStatusNotImplemented }

// ALGDisabled reports whether a is disabling proto, so no surface has to carry
// its own copy of the field-per-proto switch.
func (a *ALGConfig) ALGDisabled(proto string) bool {
	switch proto {
	case ALGProtoDNS:
		return a.DNSDisable
	case ALGProtoFTP:
		return a.FTPDisable
	case ALGProtoSIP:
		return a.SIPDisable
	case ALGProtoTFTP:
		return a.TFTPDisable
	case ALGProtoPPTP:
		return a.PPTPDisable
	}
	return false
}

// ALGUnmodeledConfigured returns the unmodeled protos an operator configured,
// deduplicated in config order (compileALG appends per `security {}` block, so
// repeats are real). Shared so the advisory and every surface name the same set
// in the same order.
func (a *ALGConfig) ALGUnmodeledConfigured() []string {
	seen := make(map[string]bool, len(a.UnsupportedProtos))
	out := make([]string, 0, len(a.UnsupportedProtos))
	for _, p := range a.UnsupportedProtos {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
