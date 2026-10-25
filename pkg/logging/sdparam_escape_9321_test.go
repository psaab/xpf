package logging

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// #9321: RFC 5424 §6.3.3 requires `"`, `\` and `]` to be escaped inside an
// SD-PARAM value. `formatStructuredMsg` interpolated operator- and
// config-derived names — policy, zone, application, service-name, interface —
// straight into `param="%s"`, so a policy named `p1" injected-param="1` forged
// a SECOND SD-PARAM in every deny record shipped off-box, and a `]` closed the
// `[junos@2636.1.1.1.2.129 …]` element early so a conforming collector read the
// remainder as MSG and lost the record.
//
// WHY THE #6585 GUARD DOES NOT COVER IT, and why widening it would be wrong.
// `termsafe.SanitizeForDisplay` at `SyslogClient.Send` is scoped to control
// bytes ON PURPOSE: #6585's third acceptance criterion is an explicit
// over-reach guard that "ordinary multi-word and UTF-8 attribute values are
// unchanged on the wire", and it protects the RFC 3164 FRAME, which these three
// printable bytes cannot damage. Widening it would mangle every other consumer
// of that sanitizer — gRPC show output, IPsec error text — for a property only
// the SD element has. Two different boundaries; both are needed.
//
// The cells below assert on the EMITTED SD ELEMENT, parsed, rather than on
// substrings: a substring check ("the record contains policy-name=") cannot see
// a second forged param, which is the defect.

const poison9321 = `a"b\c]d`

// --- A minimal RFC 5424 SD-ELEMENT parser, used as the ORACLE. ---
//
// Deliberately independent of the producer: it implements §6.3.3's reading
// rules (a `\` escapes the next character inside a PARAM-VALUE; an unescaped
// `"` ends the value; an unescaped `]` ends the element) rather than reversing
// whatever the formatter did. A parser derived from the formatter would agree
// with it by construction and could not fail.
type sdElement9321 struct {
	id     string
	params []sdParam9321 // ordered; a forged param appears here
	tail   string        // bytes after the element's closing "]"
	// violations records each place an UNESCAPED `]` appeared inside a
	// PARAM-VALUE. §6.3.3 says the character MUST be escaped, so its presence
	// is malformed input rather than a parse choice — and collectors differ in
	// how they recover, rsyslog terminating the element there. The oracle
	// therefore does BOTH: it records the violation and it ends the element,
	// so a cell can assert on the fact ("the record is malformed") without
	// depending on a guess about any one collector's recovery.
	violations []string
}

type sdParam9321 struct{ name, value string }

// parseSDElement9321 locates the `[junos@…]` SD-ELEMENT in msg and parses it.
//
// It anchors on the SD-ID rather than on the first `[`: the local-writer
// framing puts a `[TAG]` in front of the body, and anchoring on the first
// bracket parsed THAT and reported an element with zero params — a fixture
// defect that would have read as "the escape works" in every cell that only
// checked for the absence of a forged param.
func parseSDElement9321(t *testing.T, msg string) sdElement9321 {
	t.Helper()
	open := strings.Index(msg, "[junos@")
	if open < 0 {
		t.Fatalf("no [junos@… SD element in %q", msg)
	}
	i := open + 1
	// SD-ID runs to the first SP or ']'.
	idEnd := i
	for idEnd < len(msg) && msg[idEnd] != ' ' && msg[idEnd] != ']' {
		idEnd++
	}
	el := sdElement9321{id: msg[i:idEnd]}
	i = idEnd
	for i < len(msg) {
		if msg[i] == ']' {
			el.tail = msg[i+1:]
			return el
		}
		if msg[i] == ' ' {
			i++
			continue
		}
		nameEnd := i
		for nameEnd < len(msg) && msg[nameEnd] != '=' && msg[nameEnd] != ']' && msg[nameEnd] != ' ' {
			nameEnd++
		}
		if nameEnd >= len(msg) || msg[nameEnd] != '=' {
			t.Fatalf("malformed SD-PARAM at offset %d in %q", i, msg)
		}
		name := msg[i:nameEnd]
		i = nameEnd + 1
		if i >= len(msg) || msg[i] != '"' {
			t.Fatalf("SD-PARAM %q value is not quoted in %q", name, msg)
		}
		i++
		var val strings.Builder
		for {
			if i >= len(msg) {
				t.Fatalf("unterminated SD-PARAM value for %q in %q", name, msg)
			}
			switch msg[i] {
			case '\\':
				if i+1 >= len(msg) {
					t.Fatalf("trailing escape in %q", msg)
				}
				val.WriteByte(msg[i+1])
				i += 2
				continue
			case ']':
				// UNESCAPED `]` inside a PARAM-VALUE: malformed per §6.3.3.
				// Record it and end the element here, the strict reading.
				el.violations = append(el.violations,
					fmt.Sprintf("unescaped ] inside %s at offset %d", name, i))
				el.params = append(el.params, sdParam9321{name: name, value: val.String()})
				el.tail = msg[i+1:]
				return el
			case '"':
				i++
			default:
				val.WriteByte(msg[i])
				i++
				continue
			}
			break
		}
		el.params = append(el.params, sdParam9321{name: name, value: val.String()})
	}
	t.Fatalf("SD element never closed in %q", msg)
	return el
}

func paramNames9321(el sdElement9321) []string {
	out := make([]string, 0, len(el.params))
	for _, p := range el.params {
		out = append(out, p.name)
	}
	return out
}

func paramValue9321(t *testing.T, el sdElement9321, name string) string {
	t.Helper()
	for _, p := range el.params {
		if p.name == name {
			return p.value
		}
	}
	t.Fatalf("no SD-PARAM %q; have %v", name, paramNames9321(el))
	return ""
}

// baseRecord9321 is a clean, ordinary record of the given type.
func baseRecord9321(typ string) EventRecord {
	return EventRecord{
		Type:         typ,
		SrcAddr:      "10.0.1.5:41234",
		DstAddr:      "10.0.2.7:443",
		NATSrcAddr:   "172.16.1.1:12345",
		NATDstAddr:   "10.0.2.7:443",
		InZoneName:   "trust",
		OutZoneName:  "untrust",
		PolicyName:   "allow-web",
		AppName:      "junos-https",
		IngressIface: "ge-0/0/0.0",
		CloseReason:  "TCP FIN",
		Reason:       "Rejected by policy",
		SessionID:    4242,
	}
}

var recordTypes9321 = []string{"SESSION_OPEN", "SESSION_CLOSE", "POLICY_DENY"}

// THE DEFECT, on the shape the issue measured: a policy name that closes its
// own param and opens another.
//
// Asserted on the PARSED element, because that is the only way to see the
// forgery: the raw record contains `injected-param=` either way — escaped, it
// is INSIDE policy-name's value; unescaped, it is a param of its own.
//
// RED at master: the element gains an `injected-param` param, and policy-name's
// value is `p1`.
func TestAForgedSDParamCannotBeInjectedThroughAName9321(t *testing.T) {
	const forge = `p1" injected-param="1`
	for _, typ := range recordTypes9321 {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			clean := parseSDElement9321(t, formatStructuredMsg(baseRecord9321(typ), 6))

			rec := baseRecord9321(typ)
			rec.PolicyName = forge
			el := parseSDElement9321(t, formatStructuredMsg(rec, 6))

			if got := paramValue9321(t, el, "policy-name"); got != forge {
				t.Errorf("policy-name = %q, want the operator's literal name %q — the "+
					"escape must be transparent to a reader, not lossy", got, forge)
			}
			if len(el.params) != len(clean.params) {
				t.Errorf("the record grew from %d to %d SD-PARAMs (%v); a NAME must not "+
					"be able to add a param", len(clean.params), len(el.params),
					paramNames9321(el))
			}
			for _, p := range el.params {
				if p.name == "injected-param" {
					t.Errorf("forged SD-PARAM %q=%q is present on the wire", p.name, p.value)
				}
			}
		})
	}
}

// The AVAILABILITY half: a `]` must not terminate the element early. A strict
// RFC 5424 collector reads everything after the element's `]` as MSG, so every
// param after the injected one is silently lost at the SIEM.
//
// RED at master: the element closes inside the zone name and `tail` carries the
// rest of the record.
func TestARbracketInANameCannotTerminateTheElement9321(t *testing.T) {
	for _, typ := range recordTypes9321 {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			want := parseSDElement9321(t, formatStructuredMsg(baseRecord9321(typ), 6))

			rec := baseRecord9321(typ)
			rec.InZoneName = `tru]st`
			msg := formatStructuredMsg(rec, 6)
			el := parseSDElement9321(t, msg)

			if len(el.violations) != 0 {
				t.Errorf("the emitted record is malformed per RFC 5424 §6.3.3: %v. "+
					"A strict collector ends the element there and reads the rest as "+
					"MSG, so every later param is lost", el.violations)
			}
			if el.tail != "" {
				t.Errorf("the SD element closed early: %d bytes became MSG (%q). Every "+
					"param after the `]` is lost on a conforming collector", len(el.tail), el.tail)
			}
			if got := paramValue9321(t, el, "source-zone-name"); got != `tru]st` {
				t.Errorf("source-zone-name = %q, want %q", got, `tru]st`)
			}
			if len(el.params) != len(want.params) {
				t.Errorf("param count %d != clean-record count %d (%v)",
					len(el.params), len(want.params), paramNames9321(el))
			}
		})
	}
}

// TOTALITY, by reflection rather than by a hand-kept list.
//
// Every STRING field of EventRecord is poisoned in turn with a value carrying
// all three characters, and the emitted element must keep its exact param-name
// list and close at the very end. A hand-written list of "the fields that reach
// the formatter" would be an inventory built by reading today's format strings
// — blind by construction to the field somebody adds tomorrow. Reflection makes
// a new string field poisoned automatically, so this cell fails the day an
// unescaped one is wired in.
//
// RED at master on the fields that reach the SD element; GREEN (vacuously) on
// the ones that do not, which is why the cell also asserts that a meaningful
// number of fields DO reach it.
func TestEveryStringFieldIsSDParamSafe9321(t *testing.T) {
	rt := reflect.TypeOf(EventRecord{})
	var stringFields []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Type.Kind() == reflect.String && f.IsExported() {
			stringFields = append(stringFields, f.Name)
		}
	}
	if len(stringFields) < 8 {
		t.Fatalf("only %d exported string fields found (%v); the reflection walk is "+
			"not seeing the record and this cell would be vacuous",
			len(stringFields), stringFields)
	}

	reached := 0
	for _, typ := range recordTypes9321 {
		clean := parseSDElement9321(t, formatStructuredMsg(baseRecord9321(typ), 6))
		cleanNames := strings.Join(paramNames9321(clean), ",")

		for _, name := range stringFields {
			if name == "Type" {
				continue // selects the arm; poisoning it just picks the default arm
			}
			rec := baseRecord9321(typ)
			rv := reflect.ValueOf(&rec).Elem()
			rv.FieldByName(name).SetString(poison9321)

			msg := formatStructuredMsg(rec, 6)
			if !strings.Contains(msg, "junos@2636") {
				continue // this arm did not produce an SD element
			}
			el := parseSDElement9321(t, msg)
			if len(el.violations) != 0 {
				t.Errorf("%s/%s: malformed SD element: %v", typ, name, el.violations)
			}
			if el.tail != "" {
				t.Errorf("%s/%s: the SD element closed early, %q became MSG",
					typ, name, el.tail)
			}
			if got := strings.Join(paramNames9321(el), ","); got != cleanNames {
				t.Errorf("%s/%s: the param-name list changed\n got: %s\nwant: %s",
					typ, name, got, cleanNames)
			}
			for _, p := range el.params {
				if p.value == poison9321 {
					reached++
				}
			}
		}
	}
	if reached == 0 {
		t.Fatalf("no poisoned field value reached an SD-PARAM in any record type; " +
			"this cell asserted nothing about escaping")
	}
	t.Logf("poison reached %d SD-PARAM values across %d record types",
		reached, len(recordTypes9321))
}

// OVER-REACH GUARD, and the #6585-style acceptance criterion: an ordinary
// record is BYTE-IDENTICAL to what it was before the escape existed.
//
// The golden strings are the pre-#9321 output, CAPTURED by running the
// unmodified formatter at origin/master (77240ec4e) in a throwaway worktree
// and pasting its stdout — not transcribed from the format strings, which
// would only prove the transcription agrees with itself. Escaping
// that touched an ordinary name would be a wire-format change for every
// deployment, which is the failure mode #6585 wrote its own third criterion
// against.
//
// GREEN at master. It constrains what the fix must NOT do.
func TestAnOrdinaryRecordIsByteIdenticalAfterTheEscape9321(t *testing.T) {
	golden := map[string]string{
		"SESSION_OPEN":  `RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.129 source-address="10.0.1.5" source-port="41234" destination-address="10.0.2.7" destination-port="443" connection-tag="0" service-name="junos-https" nat-source-address="172.16.1.1" nat-source-port="12345" nat-destination-address="10.0.2.7" nat-destination-port="443" nat-connection-tag="0" src-nat-rule-type="N/A" src-nat-rule-name="N/A" dst-nat-rule-type="N/A" dst-nat-rule-name="N/A" protocol-id="6" policy-name="allow-web" source-zone-name="trust" destination-zone-name="untrust" session-id="4242" username="N/A" roles="N/A" packet-incoming-interface="ge-0/0/0.0" application="junos-https"]`,
		"SESSION_CLOSE": `RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.129 reason="TCP FIN" source-address="10.0.1.5" source-port="41234" destination-address="10.0.2.7" destination-port="443" connection-tag="0" service-name="junos-https" nat-source-address="172.16.1.1" nat-source-port="12345" nat-destination-address="10.0.2.7" nat-destination-port="443" nat-connection-tag="0" src-nat-rule-type="N/A" src-nat-rule-name="N/A" dst-nat-rule-type="N/A" dst-nat-rule-name="N/A" protocol-id="6" policy-name="allow-web" source-zone-name="trust" destination-zone-name="untrust" session-id="4242" packets-from-client="0" bytes-from-client="0" packets-from-server="0" bytes-from-server="0" elapsed-time="0" packet-incoming-interface="ge-0/0/0.0" application="junos-https"]`,
		"POLICY_DENY":   `RT_FLOW - RT_FLOW_SESSION_DENY [junos@2636.1.1.1.2.129 source-address="10.0.1.5" source-port="41234" destination-address="10.0.2.7" destination-port="443" connection-tag="0" service-name="None" protocol-id="6" policy-name="allow-web" source-zone-name="trust" destination-zone-name="untrust" session-id="4242" packet-incoming-interface="ge-0/0/0.0" application="junos-https" reason="Rejected by policy"]`,
	}
	for typ, want := range golden {
		if got := formatStructuredMsg(baseRecord9321(typ), 6); got != want {
			t.Errorf("%s output changed for an ORDINARY record.\n got: %s\nwant: %s", typ, got, want)
		}
	}
	// And every type: no record whose values need no escaping may contain a
	// backslash at all.
	for _, typ := range recordTypes9321 {
		if got := formatStructuredMsg(baseRecord9321(typ), 6); strings.Contains(got, `\`) {
			t.Errorf("%s: an ordinary record grew a backslash: %s", typ, got)
		}
	}
}

// The helper itself: RFC 5424 §6.3.3 is exactly three characters, each escaped
// by ONE backslash, and nothing else changes.
//
// The `\` row is the one that pins ORDER: escaping `"` first and `\` second
// would double the backslash it just inserted, so `a"b` would emit `a\\"b` —
// which a conforming parser reads as a literal backslash followed by an
// UNESCAPED quote, i.e. the injection back again through the fix.
func TestEscapeSDParamValueIsExactlyRFC5424_9321(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"allow-web", "allow-web"},
		{"ge-0/0/0.0", "ge-0/0/0.0"},
		{`a"b`, `a\"b`},
		{`a\b`, `a\\b`},
		{`a]b`, `a\]b`},
		{`"`, `\"`},
		{`\`, `\\`},
		{`]`, `\]`},
		{`a"b\c]d`, `a\"b\\c\]d`},
		{`p1" injected-param="1`, `p1\" injected-param=\"1`},
		// UTF-8 is untouched: no byte of a multi-byte sequence is 0x22/0x5c/0x5d.
		{"policy-é中\U0001f600", "policy-é中\U0001f600"},
		{"café\"x", `caf` + "é" + `\"x`},
		// Control bytes are NOT this helper's business — #6585's sanitizer at
		// SyslogClient.Send owns those, and duplicating it here would be the
		// over-reach that guard's own criteria forbid.
		{"a\nb", "a\nb"},
	} {
		if got := escapeSDParamValue(tc.in); got != tc.want {
			t.Errorf("escapeSDParamValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// The escape must be a bijection onto what the oracle reads back: parse
	// every escaped form and recover the input exactly.
	for _, in := range []string{"", "allow-web", `a"b`, `a\b`, `a]b`, poison9321,
		`p1" injected-param="1`, `\\\`, `]]]`, `"""`} {
		msg := fmt.Sprintf(`RT_FLOW - X [junos@2636.1.1.1.2.129 policy-name="%s"]`,
			escapeSDParamValue(in))
		el := parseSDElement9321(t, msg)
		if len(el.violations) != 0 {
			t.Errorf("escaped %q is still malformed: %v", in, el.violations)
		}
		if el.tail != "" {
			t.Errorf("escaped %q left %q outside the element", in, el.tail)
		}
		if len(el.params) != 1 {
			t.Errorf("escaped %q produced %d params (%v), want 1",
				in, len(el.params), paramNames9321(el))
			continue
		}
		if got := el.params[0].value; got != in {
			t.Errorf("round trip of %q gave %q", in, got)
		}
	}
}

// END TO END, from the OPERATOR'S CONFIG to the emitted bytes — and the cell
// that binds the WIRING.
//
// The cells above call `formatStructuredMsg` directly, so severing its call
// site in the emit fanout would kill none of them. This one drives the real
// path: a raw dataplane frame -> `EventReader.ProcessRawEvent` -> the
// `Format == "structured"` branch of the local-writer fanout -> the file the
// operator ships. The poisoned names arrive the way the issue traces them, via
// `SetPolicyNames` / `SetZoneNames` — the maps `daemon_system.go` fills from the
// compiled config — rather than being written onto an EventRecord by hand.
//
// RED at master: the emitted line carries a forged `injected-param` and an SD
// element that closes inside the zone name.
// RED on the wiring mutation: emit `formatSyslogMsg` for `structured` and there
// is no SD element to parse at all.
func TestConfigDerivedNamesCannotForgeAnSDParamOnTheWire9321(t *testing.T) {
	const (
		forgedPolicy = `p1" injected-param="1`
		forgedZone   = `tru]st`
		policyID     = uint32(7)
		ingressZone  = uint16(3)
	)

	emit := func(t *testing.T, policyName, zoneName string) string {
		t.Helper()
		dir := t.TempDir()
		path := dir + "/security.log"
		lw, err := NewLocalLogWriter(LocalLogConfig{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		lw.Format = "structured"

		reader := NewEventReader(nil, NewEventBuffer(8))
		reader.SetPolicyNames(map[uint32]string{policyID: policyName})
		reader.SetZoneNames(map[uint32]string{uint32(ingressZone): zoneName})
		reader.ReplaceLocalWriters([]*LocalLogWriter{lw})

		frame := rawSessionFrame(eventTypeSessionOpen, 1)
		frame[44] = byte(policyID) // [44:48] policy id, little-endian
		frame[48] = byte(ingressZone)
		if ok := reader.ProcessRawEvent(frame); !ok {
			t.Fatalf("ProcessRawEvent returned false")
		}
		if err := lw.Close(); err != nil {
			t.Fatal(err)
		}
		b, err := readFileString9321(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	clean := parseSDElement9321(t, emit(t, "allow-web", "trust"))
	if got := paramValue9321(t, clean, "policy-name"); got != "allow-web" {
		t.Fatalf("fixture: the clean policy name did not reach the wire (got %q); the "+
			"poisoned assertions below would then be about a record that never "+
			"carried an operator name", got)
	}
	if got := paramValue9321(t, clean, "source-zone-name"); got != "trust" {
		t.Fatalf("fixture: the clean zone name did not reach the wire (got %q)", got)
	}

	el := parseSDElement9321(t, emit(t, forgedPolicy, forgedZone))
	// The local writer terminates each record with a newline, so only
	// NON-whitespace after the element's `]` is an early close. The clean
	// record's own tail is asserted first, so this trim cannot hide a real one.
	if strings.TrimRight(clean.tail, "\r\n") != "" {
		t.Fatalf("fixture: even the CLEAN record has bytes after the SD element (%q); "+
			"the early-close assertion below would be meaningless", clean.tail)
	}
	if len(el.violations) != 0 {
		t.Errorf("the emitted log line is malformed per RFC 5424 §6.3.3: %v", el.violations)
	}
	if strings.TrimRight(el.tail, "\r\n") != "" {
		t.Errorf("the SD element closed early on the wire: %q became MSG", el.tail)
	}
	if len(el.params) != len(clean.params) {
		t.Errorf("the wire record grew from %d to %d SD-PARAMs (%v)",
			len(clean.params), len(el.params), paramNames9321(el))
	}
	for _, p := range el.params {
		if p.name == "injected-param" {
			t.Errorf("forged SD-PARAM %q=%q reached the emitted log line", p.name, p.value)
		}
	}
	if got := paramValue9321(t, el, "policy-name"); got != forgedPolicy {
		t.Errorf("policy-name on the wire = %q, want the operator's literal %q", got, forgedPolicy)
	}
	if got := paramValue9321(t, el, "source-zone-name"); got != forgedZone {
		t.Errorf("source-zone-name on the wire = %q, want %q", got, forgedZone)
	}
}

func readFileString9321(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
