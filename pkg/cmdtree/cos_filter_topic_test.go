package cmdtree

import (
	"strings"
	"testing"
)

// #6848/#6858: the shared `name <n>` / `type <t>` filter grammar and its
// ShowText topic encoding.
//
// This file owns the ONE copy of the grammar table. Before #6858 the same table
// was written twice — pkg/cli asserting arg->filter, cmd/cli asserting
// arg->topic — under a comment asking future editors to keep them in step. They
// had already drifted: pkg/cli covered `keyword overrides bare` and cmd/cli did
// not. Both surfaces now call ParseCoSNameTypeArgs, so there is one grammar to
// test. The per-surface tests that remain assert WIRING (that each surface
// routes through these functions), not the grammar itself.

func TestParseCoSNameTypeArgs6848(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantName string
		wantType string
	}{
		{"empty", nil, "", ""},
		// The bare positional form. cmdtree offers rule names directly under
		// the command, so this is what an operator submits after tab-completing
		// a name; before #6848 it was silently ignored and every rule was
		// dumped.
		{"bare name", []string{"rw-dscp"}, "rw-dscp", ""},
		{"keyword name", []string{"name", "rw-dscp"}, "rw-dscp", ""},
		{"keyword type", []string{"type", "dscp"}, "", "dscp"},
		{"both keywords", []string{"name", "rw-pcp", "type", "ieee-802.1"}, "rw-pcp", "ieee-802.1"},
		{"bare name then type", []string{"rw-pcp", "type", "ieee-802.1"}, "rw-pcp", "ieee-802.1"},
		{"keyword overrides bare", []string{"rw-dscp", "name", "rw-pcp"}, "rw-pcp", ""},
		{"comma in bare name", []string{"rw,x"}, "rw,x", ""},
		{"comma in keyword name", []string{"name", "rw,x", "type", "dscp"}, "rw,x", "dscp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotType, err := ParseCoSNameTypeArgs(tc.args)
			if err != nil {
				t.Fatalf("ParseCoSNameTypeArgs(%q) error = %v", tc.args, err)
			}
			if gotName != tc.wantName || gotType != tc.wantType {
				t.Errorf("ParseCoSNameTypeArgs(%q) = (%q, %q), want (%q, %q)",
					tc.args, gotName, gotType, tc.wantName, tc.wantType)
			}
		})
	}
}

func TestParseCoSNameTypeArgsRejectsUnknownAndDangling11834(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"unknown token", []string{"name", "rw-dscp", "naem"}, `unknown argument "naem"`},
		{"dangling name", []string{"name"}, `missing value for "name"`},
		{"name before next keyword", []string{"name", "type", "dscp"}, `missing value for "name"`},
		{"dangling type", []string{"type"}, `missing value for "type"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseCoSNameTypeArgs(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseCoSNameTypeArgs(%q) error = %v, want containing %q",
					tc.args, err, tc.want)
			}
		})
	}
}

// TestCoSNameTypeTopicRoundTrip6858 is the parity proof.
//
// Local and remote both derive their filters from ParseCoSNameTypeArgs. The
// remote path then carries them through a topic string and back. So "the same
// keystrokes give the same answer on both binaries" reduces to exactly one
// property: ParseCoSNameTypeTopic inverts CoSNameTypeTopic. This asserts the
// REASON parity holds rather than one instance of it.
//
// The comma case is the one that was live: the encoder joined params with `,`
// and the decoder split on `,`, so `rw,x` truncated to `rw` on the remote
// surface and rendered a DIFFERENT rule — or, where `rw` named nothing, told
// the operator no rule matched.
func TestCoSNameTypeTopicRoundTrip6858(t *testing.T) {
	for _, tc := range []struct{ name, typ string }{
		{"", ""},
		{"rw-dscp", ""},
		{"", "dscp"},
		{"rw-pcp", "ieee-802.1"},
		// Every byte that carries structure in the topic encoding.
		{"rw,x", "dscp"},
		{"rw=x", "dscp"},
		{"rw:x", "dscp"},
		{"rw%x", "dscp"},
		{"rw x", "dscp"},
		{"a,b=c:d%e f", "inet-precedence"},
		// Leading/trailing space survives the decoder's TrimSpace because the
		// encoder escapes it.
		{" rw ", "exp"},
		// A value that already looks like an escape must not be double-decoded.
		{"rw%2Cx", "dscp"},
		{"%", ""},
		{",", ""},
	} {
		topic := CoSNameTypeTopic("cos-rewrite-rule", tc.name, tc.typ)
		gotName, gotType := ParseCoSNameTypeTopic(topic, "cos-rewrite-rule")
		if gotName != tc.name || gotType != tc.typ {
			t.Errorf("round trip of (%q, %q) via %q = (%q, %q)",
				tc.name, tc.typ, topic, gotName, gotType)
		}
	}
}

// TestCoSNameTypeTopicUnchangedForOrdinaryNames6858 pins the compatibility
// claim in escapeCoSTopicValue's doc: a name with none of the structural bytes
// encodes byte-identically to the pre-#6858 form, so an ordinary topic is
// unchanged on the wire and a new `cli` keeps working against an old xpfd.
func TestCoSNameTypeTopicUnchangedForOrdinaryNames6858(t *testing.T) {
	for _, tc := range []struct {
		name, typ, want string
	}{
		{"", "", "cos-rewrite-rule"},
		{"rw-dscp", "", "cos-rewrite-rule:name=rw-dscp"},
		{"", "dscp", "cos-rewrite-rule:type=dscp"},
		{"rw-pcp", "ieee-802.1", "cos-rewrite-rule:name=rw-pcp,type=ieee-802.1"},
	} {
		if got := CoSNameTypeTopic("cos-rewrite-rule", tc.name, tc.typ); got != tc.want {
			t.Errorf("CoSNameTypeTopic(%q, %q) = %q, want the unescaped legacy form %q",
				tc.name, tc.typ, got, tc.want)
		}
	}
}

// TestParseCoSNameTypeTopicTolerance6858 covers topics this decoder did not
// produce: hand-written ones, and ones from a `cli` older than #6858 that never
// escaped anything. A bare `%` that is not a valid two-hex-digit escape stays
// literal, so such a name still decodes to itself.
func TestParseCoSNameTypeTopicTolerance6858(t *testing.T) {
	for _, tc := range []struct {
		topic, wantName, wantType string
	}{
		{"cos-rewrite-rule", "", ""},
		{"cos-rewrite-rule:", "", ""},
		{"cos-rewrite-rule:name=rw-dscp", "rw-dscp", ""},
		{"cos-rewrite-rule:name=rw-dscp, type=dscp", "rw-dscp", "dscp"},
		// Legacy, unescaped: a lone `%` and a truncated escape stay literal.
		{"cos-rewrite-rule:name=rw%x", "rw%x", ""},
		{"cos-rewrite-rule:name=rw%2", "rw%2", ""},
		{"cos-rewrite-rule:name=100%", "100%", ""},
		// A param with no `=` is skipped rather than mis-split.
		{"cos-rewrite-rule:name", "", ""},
		// The first `=` separates key from value, so an unescaped `=` in a
		// legacy value still lands in the value.
		{"cos-rewrite-rule:name=rw=x", "rw=x", ""},
		// Unknown params are ignored.
		{"cos-rewrite-rule:bogus=1,name=rw-dscp", "rw-dscp", ""},
	} {
		gotName, gotType := ParseCoSNameTypeTopic(tc.topic, "cos-rewrite-rule")
		if gotName != tc.wantName || gotType != tc.wantType {
			t.Errorf("ParseCoSNameTypeTopic(%q) = (%q, %q), want (%q, %q)",
				tc.topic, gotName, gotType, tc.wantName, tc.wantType)
		}
	}
}
