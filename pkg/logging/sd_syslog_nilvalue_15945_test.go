package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #15945 (H22-02): sd-syslog records with no Junos SD shape must still
// be well-formed RFC 5424. The pre-fix fallbacks in formatSDSyslogLine
// emitted only two NILVALUE dashes after APP-NAME
// ("RT_FLOW - - <body>" / "xpf - - <body>"), so the body landed in the
// STRUCTURED-DATA slot: RFC 5424 §6 is
//   HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP
//            PROCID SP MSGID, then STRUCTURED-DATA (NILVALUE "-" or
//            1*SD-ELEMENT), then optional MSG.
// A strict parser (rsyslog pmrfc5424, syslog-ng syslog-protocol)
// consumes the first body token as STRUCTURED-DATA and misparses or
// drops the record.
//
// SCREEN_DROP additionally gains the Junos screen SD arm cited from
// the Graylog Juniper SRX content pack (Junos OS 17.4+ sd-syslog):
//   RT_IDS - RT_SCREEN_TCP [junos@2636.1.1.1.2.40 attack-name="..."
//   source-address="..." ... action="drop"]
// with MSGID generalized to RT_SCREEN_DROP (the wire record carries
// only the free-form screen check name, so Junos's per-category
// RT_SCREEN_TCP/IP split cannot be derived). FILTER_LOG has no cited
// Junos SD element, so it gets MSGID=FILTER_LOG with NILVALUE SD and
// the flat body as MSG — no invented SD params.

const (
	ts15945   = "2026-10-22T00:00:00.000Z"
	host15945 = "fw0"
)

// rfc5424Fields15945 parses a line with the same field discipline a
// strict RFC 5424 parser applies: exactly the 7 header fields, then
// STRUCTURED-DATA must be "-" or "[...]", and the remainder is MSG.
// It is deliberately independent of the producer formatting.
func rfc5424Fields15945(t *testing.T, line string) (app, msgid, sd, msg string) {
	t.Helper()
	line = strings.TrimRight(line, "\n")
	if !strings.HasPrefix(line, "<") {
		t.Fatalf("no <PRI> in %q", line)
	}
	end := strings.Index(line, ">")
	if end < 0 {
		t.Fatalf("unterminated <PRI> in %q", line)
	}
	rest := line[end+1:]
	// VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID then SD/MSG.
	fields := strings.SplitN(rest, " ", 7)
	if len(fields) < 7 {
		t.Fatalf("RFC5424 header needs 7 fields, got %d in %q", len(fields), line)
	}
	if fields[0] != "1" {
		t.Fatalf("VERSION=%q want 1 in %q", fields[0], line)
	}
	app, msgid = fields[3], fields[5]
	procd := fields[4]
	if procd == "" || msgid == "" {
		t.Fatalf("empty PROCID/MSGID in %q", line)
	}
	tail := fields[6]
	if tail == "-" {
		return app, msgid, "-", ""
	}
	if strings.HasPrefix(tail, "- ") {
		return app, msgid, "-", strings.TrimPrefix(tail, "- ")
	}
	if strings.HasPrefix(tail, "[") {
		// Find the SD element close, honoring \] escapes.
		for i := 1; i < len(tail); i++ {
			if tail[i] == '\\' {
				i++
				continue
			}
			if tail[i] == ']' {
				msg = strings.TrimPrefix(tail[i+1:], " ")
				return app, msgid, tail[:i+1], msg
			}
		}
		t.Fatalf("unterminated SD element in %q", line)
	}
	t.Fatalf("STRUCTURED-DATA slot is neither NILVALUE nor SD element: %q in %q", tail, line)
	return "", "", "", ""
}

func sdLine15945(rec EventRecord) string {
	structured := formatStructuredMsg(rec, 6)
	return formatSDSyslogLine(14, ts15945, host15945, structured, structured)
}

func TestSDSyslogNilvalueFallbacks15945(t *testing.T) {
	// SCREEN_DROP: Junos RT_IDS SD arm.
	screen := baseRecord9321("SCREEN_DROP")
	screen.ScreenCheck = "SYN flood!"
	screen.Action = "deny"
	screen.Protocol = "TCP"
	line := sdLine15945(screen)
	app, msgid, sd, msg := rfc5424Fields15945(t, line)
	if app != "RT_IDS" {
		t.Fatalf("SCREEN_DROP APP-NAME=%q want RT_IDS: %q", app, line)
	}
	if msgid != "RT_SCREEN_DROP" {
		t.Fatalf("SCREEN_DROP MSGID=%q want RT_SCREEN_DROP: %q", msgid, line)
	}
	if !strings.HasPrefix(sd, "[junos@2636.1.1.1.2.40 ") {
		t.Fatalf("SCREEN_DROP SD=%q want [junos@2636.1.1.1.2.40 ...]: %q", sd, line)
	}
	for _, want := range []string{`attack-name="SYN flood!"`, `source-address="10.0.1.5"`, `destination-address="10.0.2.7"`, `source-zone-name="trust"`, `action="deny"`} {
		if !strings.Contains(sd, want) {
			t.Fatalf("SCREEN_DROP SD missing %s: %q", want, line)
		}
	}
	if msg != "" {
		t.Fatalf("SCREEN_DROP has MSG tail %q, want none: %q", msg, line)
	}

	// FILTER_LOG: MSGID=FILTER_LOG, NILVALUE SD, full flat body as MSG.
	filter := baseRecord9321("FILTER_LOG")
	filter.Action = "deny"
	filter.Protocol = "TCP"
	filter.Reason = "filter-log"
	filter.RuleID = 7
	filter.TermID = 3
	line = sdLine15945(filter)
	app, msgid, sd, msg = rfc5424Fields15945(t, line)
	if app != "RT_FLOW" || msgid != "FILTER_LOG" || sd != "-" {
		t.Fatalf("FILTER_LOG header app=%q msgid=%q sd=%q, want RT_FLOW/FILTER_LOG/-: %q", app, msgid, sd, line)
	}
	if !strings.Contains(msg, "FILTER_LOG") || !strings.Contains(msg, "filter=7") {
		t.Fatalf("FILTER_LOG body did not survive as MSG: %q", line)
	}

	// Aggregate / non-session body: this string does not start with
	// "RT_FLOW " (it is "RT_FLOW_SESSION_AGGREGATE ..."), so today it
	// takes the generic xpf fallback — the aggregate APP-NAME question
	// flagged unresolved by the validators. Either way the envelope
	// must be well-formed: NILVALUE SD with the body intact as MSG.
	line = formatSDSyslogLine(14, ts15945, host15945, "", `RT_FLOW_SESSION_AGGREGATE top-source="10.0.1.5" sessions=1 bytes=1000`)
	app, msgid, sd, msg = rfc5424Fields15945(t, line)
	if msgid != "-" || sd != "-" {
		t.Fatalf("aggregate header app=%q msgid=%q sd=%q, want msgid/sd NILVALUE: %q", app, msgid, sd, line)
	}
	if !strings.Contains(msg, "RT_FLOW_SESSION_AGGREGATE") {
		t.Fatalf("aggregate body did not survive as MSG: %q", line)
	}

	// Generic daemon (non-RT_FLOW) message: xpf NILVALUE envelope.
	line = formatSDSyslogLine(14, ts15945, host15945, "daemon started ok", "daemon started ok")
	app, msgid, sd, msg = rfc5424Fields15945(t, line)
	if app != "xpf" || msgid != "-" || sd != "-" {
		t.Fatalf("generic header app=%q msgid=%q sd=%q, want xpf/-/-: %q", app, msgid, sd, line)
	}
	if msg != "daemon started ok" {
		t.Fatalf("generic body=%q want verbatim: %q", msg, line)
	}

	// Unknown RT_FLOW record type also takes the NILVALUE path with
	// the body intact.
	unknown := baseRecord9321("SOME_FUTURE_TYPE")
	unknown.Action = "deny"
	line = sdLine15945(unknown)
	app, msgid, sd, msg = rfc5424Fields15945(t, line)
	if app != "RT_FLOW" || sd != "-" || !strings.Contains(msg, "SOME_FUTURE_TYPE") {
		t.Fatalf("unknown RT_FLOW app=%q msgid=%q sd=%q msg=%q: %q", app, msgid, sd, msg, line)
	}
}

// The session control must be byte-unchanged by the envelope fix.
func TestSDSyslogSessionControlUnchanged15945(t *testing.T) {
	line := sdLine15945(baseRecord9321("SESSION_OPEN"))
	want := `<14>1 2026-10-22T00:00:00.000Z fw0 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.129 source-address="10.0.1.5" source-port="41234" destination-address="10.0.2.7" destination-port="443" connection-tag="0" service-name="junos-https" nat-source-address="172.16.1.1" nat-source-port="12345" nat-destination-address="10.0.2.7" nat-destination-port="443" nat-connection-tag="0" src-nat-rule-type="N/A" src-nat-rule-name="N/A" dst-nat-rule-type="N/A" dst-nat-rule-name="N/A" protocol-id="6" policy-name="allow-web" source-zone-name="trust" destination-zone-name="untrust" session-id="4242" username="N/A" roles="N/A" packet-incoming-interface="ge-0/0/0.0" application="junos-https"]`
	if line != want {
		t.Fatalf("session sd-syslog line changed:\n got: %s\nwant: %s", line, want)
	}
}

// Both writers share formatSDSyslogLine; drive the local event-mode
// writer end to end so a writer-side bypass cannot pass silently.
func TestSDSyslogScreenDropEventModeWire15945(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	lw.Format = "sd-syslog"
	rec := baseRecord9321("SCREEN_DROP")
	rec.ScreenCheck = "SYN flood!"
	rec.Action = "deny"
	structured := formatStructuredMsg(rec, 6)
	if err := lw.Send(SyslogInfo, structured); err != nil {
		t.Fatal(err)
	}
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.TrimRight(string(b), "\n")
	lines := strings.Split(out, "\n")
	line := lines[len(lines)-1]
	app, msgid, sd, _ := rfc5424Fields15945(t, line)
	if app != "RT_IDS" || msgid != "RT_SCREEN_DROP" || !strings.HasPrefix(sd, "[junos@2636.1.1.1.2.40 ") {
		t.Fatalf("event-mode screen line app=%q msgid=%q sd=%q: %q", app, msgid, sd, line)
	}
}

// Malformed structured input must not pass through into the
// STRUCTURED-DATA slot. splitRTFlowStructured historically trusted
// prefix + "[junos@" and emitted the rest verbatim, so an
// unterminated quote, a missing closing bracket, or an unescaped
// "]" inside a value produced a line a strict RFC 5424 parser
// misparses exactly like the two-dash defect above. The envelope
// must instead fall back to NILVALUE SD with the full body as MSG.
func TestSDSyslogMalformedSDFallsBackToNilvalue15945(t *testing.T) {
	cases := []struct {
		name       string
		structured string
		wantApp    string
	}{
		{"screen_unterminated_quote", `RT_IDS - RT_SCREEN_DROP [junos@2636.1.1.1.2.40 attack-name="SYN flood]`, "xpf"},
		{"screen_missing_closing_bracket", `RT_IDS - RT_SCREEN_DROP [junos@2636.1.1.1.2.40 attack-name="SYN flood" action="drop"`, "xpf"},
		{"screen_unescaped_bracket_in_value", `RT_IDS - RT_SCREEN_DROP [junos@2636.1.1.1.2.40 attack-name="SYN]flood" action="drop"]`, "xpf"},
		{"screen_unquoted_param_value", `RT_IDS - RT_SCREEN_DROP [junos@2636.1.1.1.2.40 attack-name=synflood action="drop"]`, "xpf"},
		{"screen_param_without_equals", `RT_IDS - RT_SCREEN_DROP [junos@2636.1.1.1.2.40 attack-name "SYN flood"]`, "xpf"},
		{"screen_dangling_escape", `RT_IDS - RT_SCREEN_DROP [junos@2636.1.1.1.2.40 attack-name="SYN flood\`, "xpf"},
		{"screen_trailing_garbage_after_element", `RT_IDS - RT_SCREEN_DROP [junos@2636.1.1.1.2.40 attack-name="SYN flood"] forged-tail`, "xpf"},
		{"session_unterminated_quote", `RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.129 source-address="10.0.1.5]`, "RT_FLOW"},
		{"session_missing_closing_bracket", `RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.129 source-address="10.0.1.5"`, "RT_FLOW"},
		{"session_bare_token_in_element", `RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.129 source-address="10.0.1.5" bare]`, "RT_FLOW"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := formatSDSyslogLine(14, ts15945, host15945, tc.structured, tc.structured)
			app, msgid, sd, msg := rfc5424Fields15945(t, line)
			if app != tc.wantApp {
				t.Fatalf("app=%q want %q (NILVALUE fallback): %q", app, tc.wantApp, line)
			}
			if msgid != "-" || sd != "-" {
				t.Fatalf("msgid=%q sd=%q, want NILVALUE -/- for malformed SD: %q", msgid, sd, line)
			}
			if !strings.Contains(msg, tc.structured) {
				t.Fatalf("body did not survive verbatim as MSG:\n got msg: %q\nfull line: %q", msg, line)
			}
			if strings.Contains(sd, "[junos@") {
				t.Fatalf("malformed SD element reached the wire: %q", line)
			}
		})
	}
}

// Control: a well-formed screen element (including an escaped quote
// and bracket inside a value, as escapeSDParamValue produces) still
// decomposes into the RT_IDS SD arm — validation must not reject the
// records the fix itself emits.
func TestSDSyslogWellFormedScreenStillStructured15945(t *testing.T) {
	rec := baseRecord9321("SCREEN_DROP")
	rec.ScreenCheck = `SYN "flood"]test`
	rec.Action = "deny"
	line := sdLine15945(rec)
	app, msgid, sd, msg := rfc5424Fields15945(t, line)
	if app != "RT_IDS" || msgid != "RT_SCREEN_DROP" {
		t.Fatalf("well-formed screen header app=%q msgid=%q: %q", app, msgid, line)
	}
	if !strings.HasPrefix(sd, "[junos@2636.1.1.1.2.40 ") || msg != "" {
		t.Fatalf("well-formed screen SD=%q msg=%q: %q", sd, msg, line)
	}
	el := parseSDElement9321(t, sd)
	if got := paramValue9321(t, el, "attack-name"); got != rec.ScreenCheck {
		t.Fatalf("attack-name=%q want %q", got, rec.ScreenCheck)
	}
}
