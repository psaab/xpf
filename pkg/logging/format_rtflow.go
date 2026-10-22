// Package logging: RT_FLOW message BODY formatting.
//
// Split out of ringbuf.go (#9321) when that file crossed the 1500 LOC [WATCH]
// modularity floor. PURE CODE MOTION: every function below is moved verbatim
// from ringbuf.go, in order, with no behavioural change. The split follows the
// seam the file already had — ringbuf.go decodes wire frames and fans them out
// to sinks; these functions turn a decoded EventRecord into the TEXT a sink
// emits. Same seam #5661 used to lift agent_ber.go out of agent.go.
package logging

import (
	"fmt"
	"net"
	"strings"
)

// formatSyslogMsg formats an EventRecord as a syslog message body.
func formatSyslogMsg(rec EventRecord) string {
	inZone := rec.InZoneName
	if inZone == "" {
		inZone = fmt.Sprintf("%d", rec.InZone)
	}
	outZone := rec.OutZoneName
	if outZone == "" {
		outZone = fmt.Sprintf("%d", rec.OutZone)
	}
	if rec.Type == "SCREEN_DROP" {
		return fmt.Sprintf("RT_FLOW %s screen=%s src=%s dst=%s proto=%s action=%s zone=%s",
			rec.Type, rec.ScreenCheck, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action, inZone)
	}
	if rec.Type == "SESSION_CLOSE" {
		// A session close is not a forwarding decision, so it carries no
		// permit/deny/reject action (the wire action byte is intentionally 0
		// for closes; see userspace-dp encode_session_close_rt_flow). Rendering
		// the 0 byte via actionName would print action=deny and mislead
		// incident response into reading normal session termination as a drop
		// (#2513). Omit action entirely — like the structured RT_FLOW_SESSION_
		// CLOSE line, which carries a close reason instead. The close reason is
		// surfaced on the structured line; the standard line keeps the volume
		// counters operators use here.
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s policy=%d zone=%s->%s pkts=%d bytes=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol,
			rec.PolicyID, inZone, outZone, rec.SessionPkts, rec.SessionBytes)
	}
	if rec.Type == "SESSION_OPEN" {
		// A session open (RT_FLOW_SESSION_CREATE) is a permit-and-create
		// event, not a forwarding decision, so it carries no permit/deny/
		// reject action (the wire action byte is intentionally 0 for creates;
		// see userspace-dp encode_session_create_rt_flow). Rendering the 0
		// byte via actionName would print action=deny and mislead incident
		// response into reading a successful permit-and-open as a drop (#2593,
		// the SESSION_CREATE sibling of #2513). Omit action entirely — like
		// the structured RT_FLOW_SESSION_CREATE line, which never carried one.
		// The standard line keeps the proto/policy/zone fields operators read.
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s policy=%d zone=%s->%s",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol,
			rec.PolicyID, inZone, outZone)
	}
	if rec.Type == "FILTER_LOG" {
		source := rec.Reason
		if source == "" {
			source = "unknown"
		}
		return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s zone=%s->%s source=%s filter=%d term=%d",
			rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
			inZone, outZone, source, rec.RuleID, rec.TermID)
	}
	return fmt.Sprintf("RT_FLOW %s src=%s dst=%s proto=%s action=%s policy=%d zone=%s->%s",
		rec.Type, rec.SrcAddr, rec.DstAddr, rec.Protocol, rec.Action,
		rec.PolicyID, inZone, outZone)
}

// escapeSDParamValue escapes the three characters RFC 5424 §6.3.3 requires
// escaped inside a STRUCTURED-DATA PARAM-VALUE: `"` (%d34), `\` (%d92) and
// `]` (%d93), each by prefixing a backslash.
//
// #9321. `formatStructuredMsg` interpolates operator- and config-derived names
// — policy, zone, application, `service-name`, interface — straight into
// `param="%s"` inside the `[junos@2636.1.1.1.2.129 …]` element. A policy named
// `p1" injected-param="1` therefore forged a SECOND SD-PARAM in every deny
// record shipped off-box, and a `]` closed the element early so a conforming
// collector read the remainder as MSG and lost the record. Junos accepts those
// characters in a quoted name and so does this tree's commit gate, correctly —
// the value is legal; the INTERPOLATION was not.
//
// This is deliberately NOT done by widening `termsafe.SanitizeForDisplay`, the
// #6585 guard one layer out at `SyslogClient.Send`. That guard is scoped to
// control bytes on purpose: its third acceptance criterion is an explicit
// over-reach guard that "ordinary multi-word and UTF-8 attribute values are
// unchanged on the wire", and it protects the RFC 3164 FRAME, which these three
// printable bytes cannot damage. Escaping them there would mangle every other
// consumer of that sanitizer — gRPC show output, IPsec error text — for a
// property only the SD element has. #6585 closed frame integrity; this closes
// SD-element integrity. They are different boundaries and both are needed.
//
// The scan is by BYTE, which is correct rather than merely convenient: all
// three characters are ASCII, and every byte of a multi-byte UTF-8 sequence is
// >= 0x80, so a byte scan can neither split a rune nor match inside one.
//
// Allocation-free fast path for the already-clean case — every ordinary record
// — because this runs on the shared dataplane event path (#2283), once per
// firewall event per structured client.
func escapeSDParamValue(v string) string {
	if !strings.ContainsAny(v, `"\]`) {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 8)
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '"' || c == '\\' || c == ']' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// formatStructuredMsg formats an EventRecord as a Junos-compatible structured
// syslog message with RT_FLOW_SESSION_CREATE/CLOSE/DENY and
// RT_SCREEN_DROP event tags.
// Output matches vSRX RT_FLOW/RT_IDS format with [junos@2636...] wrapping.
func formatStructuredMsg(rec EventRecord, protoNum uint8) string {
	// Split addr:port pairs
	srcIP, srcPort := splitAddrPort(rec.SrcAddr)
	dstIP, dstPort := splitAddrPort(rec.DstAddr)
	natSrcIP, natSrcPort := resolveNATAddrPort(rec.NATSrcAddr, srcIP, srcPort)
	natDstIP, natDstPort := resolveNATAddrPort(rec.NATDstAddr, dstIP, dstPort)

	policyName := rec.PolicyName
	if policyName == "" {
		policyName = fmt.Sprintf("%d", rec.PolicyID)
	}
	appName := rec.AppName
	if appName == "" {
		appName = "UNKNOWN"
	}
	inIface := rec.IngressIface
	if inIface == "" {
		inIface = "N/A"
	}

	// #9321: every value that lands in an SD-PARAM below is escaped per RFC 5424
	// §6.3.3 exactly once, HERE — after the empty-value fallbacks, because a
	// fallback is itself a param value, and before the switch, because several
	// of these are interpolated twice in one record (appName is both
	// `service-name` and `application`).
	//
	// The address/port values are machine-derived today, but `splitAddrPort`
	// returns its input VERBATIM when `net.SplitHostPort` fails, so "this one
	// cannot contain a quote" is a claim about a parser rather than about the
	// data. Escaping is a no-op on every value that does not need it (the helper
	// has an allocation-free fast path), so the cheap thing and the total thing
	// are the same thing here — and a total rule is the one a new field inherits.
	srcIP = escapeSDParamValue(srcIP)
	srcPort = escapeSDParamValue(srcPort)
	dstIP = escapeSDParamValue(dstIP)
	dstPort = escapeSDParamValue(dstPort)
	natSrcIP = escapeSDParamValue(natSrcIP)
	natSrcPort = escapeSDParamValue(natSrcPort)
	natDstIP = escapeSDParamValue(natDstIP)
	natDstPort = escapeSDParamValue(natDstPort)
	policyName = escapeSDParamValue(policyName)
	appName = escapeSDParamValue(appName)
	inIface = escapeSDParamValue(inIface)
	inZone := escapeSDParamValue(rec.InZoneName)
	outZone := escapeSDParamValue(rec.OutZoneName)
	screenCheck := escapeSDParamValue(rec.ScreenCheck)
	action := escapeSDParamValue(rec.Action)

	switch rec.Type {
	case "SESSION_OPEN":
		return fmt.Sprintf("RT_FLOW - RT_FLOW_SESSION_CREATE "+
			"[junos@2636.1.1.1.2.129 "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"connection-tag=\"0\" service-name=\"%s\" "+
			"nat-source-address=\"%s\" nat-source-port=\"%s\" "+
			"nat-destination-address=\"%s\" nat-destination-port=\"%s\" "+
			"nat-connection-tag=\"0\" "+
			"src-nat-rule-type=\"N/A\" src-nat-rule-name=\"N/A\" "+
			"dst-nat-rule-type=\"N/A\" dst-nat-rule-name=\"N/A\" "+
			"protocol-id=\"%d\" policy-name=\"%s\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\" "+
			"session-id=\"%d\" "+
			"username=\"N/A\" roles=\"N/A\" "+
			"packet-incoming-interface=\"%s\" application=\"%s\"]",
			srcIP, srcPort, dstIP, dstPort,
			appName,
			natSrcIP, natSrcPort, natDstIP, natDstPort,
			protoNum, policyName,
			inZone, outZone,
			rec.SessionID,
			inIface, appName)

	case "SESSION_CLOSE":
		reason := rec.CloseReason
		if reason == "" {
			reason = "N/A"
		}
		reason = escapeSDParamValue(reason)
		return fmt.Sprintf("RT_FLOW - RT_FLOW_SESSION_CLOSE "+
			"[junos@2636.1.1.1.2.129 "+
			"reason=\"%s\" "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"connection-tag=\"0\" service-name=\"%s\" "+
			"nat-source-address=\"%s\" nat-source-port=\"%s\" "+
			"nat-destination-address=\"%s\" nat-destination-port=\"%s\" "+
			"nat-connection-tag=\"0\" "+
			"src-nat-rule-type=\"N/A\" src-nat-rule-name=\"N/A\" "+
			"dst-nat-rule-type=\"N/A\" dst-nat-rule-name=\"N/A\" "+
			"protocol-id=\"%d\" policy-name=\"%s\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\" "+
			"session-id=\"%d\" "+
			"packets-from-client=\"%d\" bytes-from-client=\"%d\" "+
			"packets-from-server=\"%d\" bytes-from-server=\"%d\" "+
			"elapsed-time=\"%d\" "+
			"packet-incoming-interface=\"%s\" application=\"%s\"]",
			reason,
			srcIP, srcPort, dstIP, dstPort,
			appName,
			natSrcIP, natSrcPort, natDstIP, natDstPort,
			protoNum, policyName,
			inZone, outZone,
			rec.SessionID,
			rec.SessionPkts, rec.SessionBytes,
			rec.RevSessionPkts, rec.RevSessionBytes,
			rec.ElapsedTime,
			inIface, appName)

	case "POLICY_DENY":
		// #3610: render the on-wire reason instead of a hardcoded string. For a
		// transit security-policy deny the reason byte is closeReasonPolicy, so
		// rec.Reason is "Rejected by policy" — byte-identical to the prior output.
		// For a host-inbound-traffic admission deny the byte is
		// closeReasonHostInbound, so the record shows "Denied by
		// host-inbound-traffic", letting incident response tell a control-plane
		// host-inbound drop apart from a transit policy deny (was conflated).
		reason := rec.Reason
		if reason == "" {
			reason = "Rejected by policy"
		}
		reason = escapeSDParamValue(reason)
		return fmt.Sprintf("RT_FLOW - RT_FLOW_SESSION_DENY "+
			"[junos@2636.1.1.1.2.129 "+
			"source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"connection-tag=\"0\" service-name=\"None\" "+
			"protocol-id=\"%d\" policy-name=\"%s\" "+
			"source-zone-name=\"%s\" destination-zone-name=\"%s\" "+
			"session-id=\"%d\" "+
			"packet-incoming-interface=\"%s\" application=\"%s\" "+
			"reason=\"%s\"]",
			srcIP, srcPort, dstIP, dstPort,
			protoNum, policyName,
			inZone, outZone,
			rec.SessionID,
			inIface, appName, reason)

	case "SCREEN_DROP":
		// #15945 (H22-02): Junos sd-syslog screen shape, cited from the
		// Graylog Juniper SRX content pack (Junos OS 17.4+ sd-syslog):
		//   RT_IDS - RT_SCREEN_TCP [junos@2636.1.1.1.2.40
		//   attack-name="..." source-address="..." source-port="..."
		//   destination-address="..." destination-port="..."
		//   source-zone-name="..." interface-name="..." action="drop"]
		// The SD-ID suffix (.40) and param set are Junos's screen
		// element, distinct from the session element (.129). The
		// MSGID here is the generic RT_SCREEN_DROP: Junos further
		// splits by attack category (RT_SCREEN_TCP/IP/... per the
		// Juniper System Log Explorer), but the wire record carries
		// only the free-form screen check name, so no category can be
		// derived without inventing a mapping. Fields the record does
		// not carry (session-id, policy-name, ...) are omitted rather
		// than fabricated.
		return fmt.Sprintf("RT_IDS - RT_SCREEN_DROP "+
			"[junos@2636.1.1.1.2.40 "+
			"attack-name=\"%s\" source-address=\"%s\" source-port=\"%s\" "+
			"destination-address=\"%s\" destination-port=\"%s\" "+
			"source-zone-name=\"%s\" interface-name=\"%s\" action=\"%s\"]",
			screenCheck, srcIP, srcPort, dstIP, dstPort, inZone, inIface, action)

	case "FILTER_LOG":
		// #15945 (H22-02): no Junos sd-syslog reference was found for a
		// firewall-filter log SD element (Junos filter logging is a
		// system/firewall-facility message, not an RT_FLOW security-log
		// record), so no SD params are invented here. The record still
		// gets a well-formed RFC 5424 envelope from formatSDSyslogLine:
		// MSGID=FILTER_LOG with NILVALUE SD and the flat body as MSG.
		// Returning the flat body keeps splitRTFlowStructured from
		// mistaking it for a session SD element.
		return formatSyslogMsg(rec)

	default:
		return formatSyslogMsg(rec)
	}
}

// validSDElement15945 reports whether s is exactly one complete
// RFC 5424 SD-ELEMENT and nothing else: "[SD-ID *(SP PARAM-NAME=
// \"%s\")]" where every PARAM-VALUE is quoted, only \" \\ \] escapes
// appear inside it, and the closing "]" is the last byte. The scan is
// by byte; all structural characters are ASCII, so it cannot split a
// multi-byte UTF-8 sequence. This mirrors the reading rules of the
// #9321 test oracle, independently implemented for the producer.
func validSDElement15945(s string) bool {
	if len(s) < 2 || s[0] != '[' {
		return false
	}
	i := 1
	// SD-ID: 1*(%d33-126 except "=" (%d61), "]" (%d93), '"' (%d34)).
	idStart := i
	for i < len(s) && s[i] != ' ' && s[i] != ']' {
		if s[i] < 33 || s[i] > 126 || s[i] == '=' || s[i] == '"' {
			return false
		}
		i++
	}
	if i == idStart {
		return false // empty SD-ID
	}
	for {
		if i >= len(s) {
			return false // no closing "]"
		}
		if s[i] == ']' {
			return i == len(s)-1 // "]" must end the element
		}
		if s[i] != ' ' {
			return false
		}
		i++
		// PARAM-NAME: 1*(%d33-126 except "=", "]", '"').
		nameStart := i
		for i < len(s) && s[i] != '=' {
			if s[i] < 33 || s[i] > 126 || s[i] == ']' || s[i] == '"' || s[i] == ' ' {
				return false
			}
			i++
		}
		if i == nameStart || i >= len(s) {
			return false // empty name or ran out before "="
		}
		i++ // consume "="
		if i >= len(s) || s[i] != '"' {
			return false // value must be quoted
		}
		i++
		for {
			if i >= len(s) {
				return false // unterminated value
			}
			switch s[i] {
			case '\\':
				i++
				if i >= len(s) {
					return false // dangling escape
				}
				i++
			case '"':
				i++
				goto valueDone
			case ']':
				return false // unescaped "]" inside value
			default:
				i++
			}
		}
	valueDone:
	}
}

// splitRTFlowStructured splits a formatStructuredMsg output into the
// APP-NAME, MSGID and SD element. Structured output is shaped
// "RT_FLOW - <MSGID> [<SD-ID> ...]" for session events and
// "RT_IDS - <MSGID> [<SD-ID> ...]" for screen events; anything else
// (the formatSyslogMsg fallback) returns ok=false unchanged. The SD
// arm is validated with validSDElement15945 (#16295 fold): a bare
// prefix+"[junos@" trust let malformed SD (unterminated quote,
// missing "]", trailing garbage) pass verbatim into the RFC 5424
// STRUCTURED-DATA slot that formatSDSyslogLine emits, recreating
// the strict-parser misparse H22-02 fixed. Malformed input falls
// back to the NILVALUE envelope with the body intact as MSG.
func splitRTFlowStructured(structured string) (appName, msgid, sd string, ok bool) {
	for _, prefix := range []string{"RT_FLOW - ", "RT_IDS - "} {
		if !strings.HasPrefix(structured, prefix) {
			continue
		}
		rest := structured[len(prefix):]
		sp := strings.IndexByte(rest, ' ')
		if sp <= 0 {
			return "", "", "", false
		}
		m, s := rest[:sp], strings.TrimSpace(rest[sp+1:])
		if !strings.HasPrefix(s, "[junos@") || !validSDElement15945(s) {
			return "", "", "", false
		}
		return strings.TrimSuffix(prefix, " - "), m, s, true
	}
	return "", "", "", false
}

// formatSDSyslogLine renders one Junos sd-syslog record (#14611, #15945):
// "<PRI>1 TS HOST RT_FLOW - <MSGID> [<junos SD>]" for session events,
// "<PRI>1 TS HOST RT_IDS - <MSGID> [<junos SD>]" for screen events, and
// a NILVALUE-SD envelope for event types with no SD shape:
// "<PRI>1 TS HOST RT_FLOW - FILTER_LOG - <flat body>",
// "<PRI>1 TS HOST RT_FLOW - - - <flat body>", or
// "<PRI>1 TS HOST xpf - - - <flat body>".
// RFC 5424 §6: HEADER is PRI VERSION SP TIMESTAMP SP HOSTNAME SP
// APP-NAME SP PROCID SP MSGID, followed by STRUCTURED-DATA (NILVALUE
// "-" or 1*SD-ELEMENT) and optional MSG. The pre-#15945 fallbacks
// emitted only two dashes after APP-NAME, placing the body in the
// STRUCTURED-DATA slot where a strict parser misparses or drops it.
// It is the single envelope builder shared by SyslogClient and
// LocalLogWriter so the stream and event-mode writers cannot drift.
// ts is the RFC 5424 TIMESTAMP the caller formats (one clock read per
// record at the caller keeps stream/event behaviour aligned with the
// pre-#14611 code, which read time.Now() inside each Send).
func formatSDSyslogLine(priority int, ts, hostname, structured, flat string) string {
	hostname = sanitizeSyslogHostname(hostname)
	if appName, msgid, sd, ok := splitRTFlowStructured(structured); ok {
		return fmt.Sprintf("<%d>1 %s %s %s - %s %s", priority, ts, hostname, appName, msgid, sd)
	}
	// No SD shape: keep the record parseable. APP-NAME is still RT_FLOW
	// for RT_FLOW bodies so SIEM routing by app-name keeps working, and
	// the STRUCTURED-DATA slot carries the NILVALUE "-".
	body := structured
	if body == "" {
		body = flat
	}
	if strings.HasPrefix(body, "RT_FLOW FILTER_LOG ") {
		return fmt.Sprintf("<%d>1 %s %s RT_FLOW - FILTER_LOG - %s", priority, ts, hostname, body)
	}
	if strings.HasPrefix(body, "RT_FLOW ") || body == "RT_FLOW" {
		return fmt.Sprintf("<%d>1 %s %s RT_FLOW - - - %s", priority, ts, hostname, body)
	}
	return fmt.Sprintf("<%d>1 %s %s xpf - - - %s", priority, ts, hostname, body)
}

// stripRTFlowLeadIn removes the "RT_FLOW - "/"RT_IDS - " lead-in
// formatStructuredMsg historically emitted, leaving "<MSGID> [<SD>]".
// Used where the body is carried as MSG (RFC 3164 structured, local
// structured) so the wire no longer shows the doubled
// "RT_FLOW - RT_FLOW_SESSION_*" (#14611).
// Non-structured bodies are returned unchanged.
func stripRTFlowLeadIn(msg string) string {
	if _, _, _, ok := splitRTFlowStructured(msg); !ok {
		return msg
	}
	msg = strings.TrimPrefix(msg, "RT_FLOW - ")
	return strings.TrimPrefix(msg, "RT_IDS - ")
}

// splitAddrPort splits "10.0.1.5:443" or "[::1]:443" into IP and port strings.
func splitAddrPort(addr string) (string, string) {
	if addr == "" {
		return "0.0.0.0", "0"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "0"
	}
	return host, port
}

// resolveNATAddrPort returns the effective post-NAT (ip, port) for structured
// RT_FLOW messages (#15697). When the wire NAT slot is untranslated (empty, or
// a zero IP / zero port as the decoders render an absent rewrite), Junos vSRX
// reports the original pre-NAT address/port for that component. Each
// component resolves independently: a translated IP with an untranslated
// port keeps the IP and mirrors the original port, and vice versa. Without
// this, a non-NAT (or IP-only SNAT) session rendered
// nat-source-address="0.0.0.0"/"::" nat-source-port="0", which SIEMs read as
// a distinct bogus tuple instead of the effective one.
func resolveNATAddrPort(natAddrPort, origIP, origPort string) (string, string) {
	ip, port := splitAddrPort(natAddrPort)
	if isZeroIP15697(ip) {
		ip = origIP
	}
	if port == "" || port == "0" {
		port = origPort
	}
	return ip, port
}

// isZeroIP15697 reports whether ip is the unspecified address ("0.0.0.0" or
// any spelling of "::"), the placeholder the decoders emit for an absent NAT
// rewrite. A value that does not parse as an IP is left untouched.
func isZeroIP15697(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsUnspecified()
}
