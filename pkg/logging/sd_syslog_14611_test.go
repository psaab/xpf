package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #14611: `security log format sd-syslog` must be Junos sd-syslog, not a
// bare RFC 5424 envelope around the flat RT_FLOW body.
//
// Junos reference (docs/junos-cli-reference.md, Graylog SRX shape):
//
//	<PRI>1 TS HOST RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.129 source-address="..." ...]
//
// i.e. APP-NAME=RT_FLOW, PROCID="-", MSGID=RT_FLOW_SESSION_CREATE,
// SD=[junos@2636... source-address=...], and no trailing MSG body.
// Acceptance (z4): a golden wire test where a format sd-syslog
// session-create parses with an RFC 5424 parser to APP-NAME=RT_FLOW,
// MSGID=RT_FLOW_SESSION_CREATE, SD-ID junos@2636.1.1.1.2.* with a
// source-address param, for both the stream and event-mode writers.
//
// RED at master: sd-syslog emits `xpf - - - RT_FLOW SESSION_OPEN src=...`
// (NILVALUE APP/MSGID/SD, flat body); structured emits the SD body but
// under an RFC 3164 (or local timestamp) envelope with doubled
// `RT_FLOW -`.

// rfc5424Header is the parsed RFC 5424 header (RFC 5424 §6).
type rfc5424Header struct {
	pri     string
	version string
	ts      string
	host    string
	app     string
	procid  string
	msgid   string
	rest    string // SD + optional MSG
}

// parseRFC5424 splits a wire line into header fields. It is deliberately
// independent of the producer formatting.
func parseRFC5424(t *testing.T, line string) rfc5424Header {
	t.Helper()
	line = strings.TrimRight(line, "\n")
	if !strings.HasPrefix(line, "<") {
		t.Fatalf("no <PRI> in %q", line)
	}
	end := strings.Index(line, ">")
	if end < 0 {
		t.Fatalf("unterminated <PRI> in %q", line)
	}
	h := rfc5424Header{pri: line[1:end]}
	rest := line[end+1:]
	fields := strings.SplitN(rest, " ", 7)
	if len(fields) < 7 {
		t.Fatalf("RFC5424 header needs 7 fields, got %d in %q", len(fields), line)
	}
	h.version, h.ts, h.host, h.app, h.procid, h.msgid, h.rest = fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]
	return h
}

func assertJunosSDSyslog(t *testing.T, line, wantMsgID string) {
	t.Helper()
	h := parseRFC5424(t, line)
	if h.version != "1" {
		t.Fatalf("VERSION=%q want 1: %q", h.version, line)
	}
	if h.host == "" || h.host == "-" {
		t.Fatalf("HOSTNAME missing (Junos carries it): %q", line)
	}
	if h.app != "RT_FLOW" {
		t.Fatalf("APP-NAME=%q want RT_FLOW: %q", h.app, line)
	}
	if h.msgid != wantMsgID {
		t.Fatalf("MSGID=%q want %q: %q", h.msgid, wantMsgID, line)
	}
	// SD must be the junos element with source-address; reuse the
	// independent SD oracle from #9321.
	el := parseSDElement9321(t, h.rest)
	if !strings.HasPrefix(el.id, "junos@2636.1.1.1.2.") {
		t.Fatalf("SD-ID=%q want junos@2636.1.1.1.2.*: %q", el.id, line)
	}
	if got := paramValue9321(t, el, "source-address"); got == "" {
		t.Fatalf("source-address empty: %q", line)
	}
	if len(el.violations) != 0 {
		t.Fatalf("SD violations %v: %q", el.violations, line)
	}
	if strings.TrimSpace(el.tail) != "" {
		t.Fatalf("unexpected MSG after SD %q: %q", el.tail, line)
	}
	// The legacy doubled body (as MSG) must be gone; the correct header
	// itself reads "RT_FLOW - RT_FLOW_SESSION_*".
	if strings.Contains(h.rest, "RT_FLOW - RT_FLOW") {
		t.Fatalf("doubled RT_FLOW prefix in MSG/SD: %q", line)
	}
}

func TestSDSyslogStreamWireIsJunos14611(t *testing.T) {
	c, pc := newLoopbackSyslogClient(t)
	c.Format = "sd-syslog"
	c.MinSeverity = SyslogInfo
	c.Categories = CategoryAll
	// End-to-end: raw frame -> EventReader fanout -> queued client Send.
	// This binds the ringbuf body selection, not just Send in isolation:
	// reverting the fanout to the flat body reds this cell.
	reader := NewEventReader(nil, NewEventBuffer(8))
	reader.ReplaceSyslogClients([]*SyslogClient{c})
	defer reader.ReplaceSyslogClients(nil)
	if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionOpen, 1)); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}
	frame := recvOneFrame(t, pc)
	if i := strings.Index(frame, "<"); i > 0 {
		frame = frame[i:]
	}
	assertJunosSDSyslog(t, frame, "RT_FLOW_SESSION_CREATE")
	if !strings.Contains(frame, `source-address="10.0.1.1"`) {
		t.Fatalf("missing source-address param: %q", frame)
	}
}

func TestSDSyslogEventModeWireIsJunos14611(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security.log")
	lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	lw.Format = "sd-syslog"
	reader := NewEventReader(nil, NewEventBuffer(8))
	reader.ReplaceLocalWriters([]*LocalLogWriter{lw})
	if ok := reader.ProcessRawEvent(rawSessionFrame(eventTypeSessionOpen, 1)); !ok {
		t.Fatalf("ProcessRawEvent returned false")
	}
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.TrimRight(string(b), "\n")
	if out == "" {
		t.Fatalf("empty event-mode output")
	}
	// Last line is the event line.
	lines := strings.Split(out, "\n")
	assertJunosSDSyslog(t, lines[len(lines)-1], "RT_FLOW_SESSION_CREATE")
}

// Structured must remain the Junos RT_FLOW body (now also usable as the
// MSG/SD payload); its stream envelope stays RFC 3164 per the documented
// decision in config-schema.md.
func TestStructuredStreamStill3164WithRTFlowBody14611(t *testing.T) {
	c, pc := newLoopbackSyslogClient(t)
	c.Format = "structured"
	structured := formatStructuredMsg(baseRecord9321("SESSION_OPEN"), 6)
	if err := c.Send(SyslogInfo, structured); err != nil {
		t.Fatal(err)
	}
	frame := recvOneFrame(t, pc)
	if strings.Contains(frame, "RT_FLOW - RT_FLOW") {
		t.Fatalf("structured doubled RT_FLOW: %q", frame)
	}
	if !strings.Contains(frame, "RT_FLOW_SESSION_CREATE [junos@") {
		t.Fatalf("structured missing RT_FLOW_SESSION_CREATE SD: %q", frame)
	}
}
