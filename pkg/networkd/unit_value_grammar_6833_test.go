package networkd

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// unit_value_grammar_6833_test.go pins the consumer grammar behind the
// Description= control-byte sanitizer and the complete networkd interpolation
// inventory. #10718 structured fields use refusal rather than substitution:
// a space or control byte cannot be made safe by replacing it with another
// systemd token.

// TestUnitValueSanitizerReplacesTheNewline pins the byte the belt is actually
// for. Its failure message says why, so a relaxation that keeps "no control
// characters" while admitting the live byte cannot pass silently.
func TestUnitValueSanitizerReplacesTheNewline_6833(t *testing.T) {
	got := sanitizeUnitValue("lan\nDHCP=ipv4")
	if strings.ContainsRune(got, '\n') {
		t.Fatalf("a newline survived sanitizeUnitValue (%q): systemd units are "+
			"one Key=Value per line, so the remainder is read as a NEW directive "+
			"-- this is the #1798 injection the belt exists to stop", got)
	}
	if got != "lan DHCP=ipv4" {
		t.Errorf("got %q, want %q", got, "lan DHCP=ipv4")
	}
}

// TestNetworkdUnitInterpolationInventory_10718 inventories every string sink
// in generated unit key=value lines. A new raw sink or a bypass around the
// Description sanitizer must update this inventory instead of silently
// extending the set of unguarded fields.
//
// The field checks themselves are pinned by behavior in
// TestApplyRefusesUnsafeUnitFieldsAndSweeps_10718; this census prevents a new
// interpolation field from escaping that coverage.
func TestNetworkdUnitInterpolationInventory_10718(t *testing.T) {
	src := stripLineComments6833(readNetworkdSource6833(t, "networkd.go"))
	call := regexp.MustCompile(`fmt\.Fprintf\(&b,\s*"([A-Za-z]+)=%s\\n",\s*([^\n]+)\)`)
	calls := call.FindAllStringSubmatch(src, -1)
	if len(calls) == 0 {
		t.Fatal("found no generated key/value unit sinks; inventory would be vacuous")
	}

	// Counts distinguish every renderer branch that emits a sink. Expression
	// checks make the allowed boundary explicit: descriptions are sanitized;
	// single-token fields are validated in renderedUnitTokenError.
	want := map[string]map[string]int{
		"Name":             {"ifc.Name": 4},
		"Description":      {"sanitizeUnitValue(ifc.Description)": 3},
		"Mode":             {"mode": 1},
		"LACPTransmitRate": {"rate": 1},
		"OriginalName":     {"ifc.OriginalName": 1},
		"MACAddress":       {"ifc.MACAddress": 1},
		"BitsPerSecond":    {"junosSpeedToNetworkd(ifc.Speed)": 1},
		"Duplex":           {"ifc.Duplex": 1},
		"VRF":              {"ifc.VRFName": 1},
		"Bond":             {"ifc.BondMaster": 1},
		"Bridge":           {"ifc.BridgeMaster": 1},
		"Address":          {"addr": 3},
	}
	got := make(map[string]map[string]int)
	for _, m := range calls {
		key, expr := m[1], strings.TrimSpace(m[2])
		expected, ok := want[key]
		if !ok {
			t.Errorf("unrecorded generated systemd unit sink %s= with expression %q (#10718)", key, expr)
			continue
		}
		if _, ok := expected[expr]; !ok {
			t.Errorf("generated systemd unit sink %s= interpolates unrecorded expression %q (#10718)", key, expr)
		}
		if got[key] == nil {
			got[key] = make(map[string]int)
		}
		got[key][expr]++
	}
	for key, expressions := range want {
		for expr, count := range expressions {
			if got[key][expr] != count {
				t.Errorf("generated systemd unit sink %s=%s occurs %d times, want %d (#10718)",
					key, expr, got[key][expr], count)
			}
		}
	}
}

func readNetworkdSource6833(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

func stripLineComments6833(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
