package config

import (
	"strings"
	"testing"
)

// #13969 (H18-06): a 6-bit DSCP bit-string such as `101110` (the Junos /
// `show class-of-service` spelling of EF, decimal 46) in a CoS code-points
// leaf was parsed as DECIMAL by expandCoSCodePointToken. The valid patterns
// `000010` and `000011` silently compiled to 10 and 11 instead of 2 and 3;
// most other six-bit patterns (including `101110`) were rejected as
// out-of-range decimal numbers. The inet-precedence twin
// (coSINetPrecedenceCodePointValue, #7084) already reads its 3-bit field as
// binary when the token is exactly field-width all-[01]; the 6-bit DSCP side
// never got the same treatment.
//
// Only exact-width binary tokens are interpreted as bits. Shorter tokens keep
// decimal meaning (`10` stays decimal 10, and `10111` stays out-of-range), and
// a six-character token containing 2-9 (e.g. `123456`) stays decimal/rejected.

func TestExpandCoSCodePointTokenDSCPBitStrings13969(t *testing.T) {
	cases := []struct {
		token string
		want  []uint8
	}{
		{"000000", []uint8{0}},
		{"000001", []uint8{1}},
		{"000010", []uint8{2}},
		{"000011", []uint8{3}},
		{"001010", []uint8{10}}, // af11
		{"101000", []uint8{40}}, // cs5
		{"101110", []uint8{46}}, // ef
		{"111111", []uint8{63}},
		// Decimal and alias behaviour unchanged.
		{"0", []uint8{0}},
		{"10", []uint8{10}},
		{"46", []uint8{46}},
		{"063", []uint8{63}},
		{"ef", []uint8{46}},
		{"EF", []uint8{46}},
	}
	for _, tc := range cases {
		got, err := expandCoSCodePointToken(tc.token)
		if err != nil {
			t.Errorf("expandCoSCodePointToken(%q) error = %v, want %v", tc.token, err, tc.want)
			continue
		}
		if len(got) != len(tc.want) || (len(got) > 0 && got[0] != tc.want[0]) {
			t.Errorf("expandCoSCodePointToken(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
	// Still rejected: 6-char non-binary decimal, 7-char bit-string (not the
	// field width — decimal, and out of range), short bit-string read as
	// decimal (out of range), plain decimal out of range, and an overflowing
	// decimal that must not wrap into a valid DSCP value.
	for _, tok := range []string{
		"123456", "1011111", "10111", "64", "999999", "999999999999999999999999999999",
	} {
		if got, err := expandCoSCodePointToken(tok); err == nil {
			t.Errorf("expandCoSCodePointToken(%q) = %v, want rejection", tok, got)
		}
	}
}

func TestCoSDSCPBitStringClassifierAndRewriteCompile13969(t *testing.T) {
	cases := []struct {
		token string
		want  uint8
	}{
		{"000010", 2},
		{"000011", 3},
		{"101110", 46},
		{"001010", 10},
		{"10", 10},
		{"ef", 46},
	}
	for _, tc := range cases {
		t.Run(tc.token, func(t *testing.T) {
			cfg := cpCompileHier(t,
				"class-of-service { classifiers { dscp cp-cl { forwarding-class voice { loss-priority low { code-points [ "+tc.token+" ]; } } } } }")
			c := cfg.ClassOfService.DSCPClassifiers["cp-cl"]
			if c == nil || len(c.Entries) != 1 {
				t.Fatalf("dscp classifier did not compile")
			}
			if got := c.Entries[0].DSCPValues; len(got) != 1 || got[0] != tc.want {
				t.Fatalf("classifier DSCPValues = %v, want [%d]", got, tc.want)
			}

			p := NewParser(cpForwardingClasses + "\n" +
				"class-of-service { rewrite-rules { dscp cp-rw { forwarding-class voice { loss-priority low code-point " + tc.token + "; } } } }")
			tree, errs := p.Parse()
			if len(errs) > 0 {
				t.Fatalf("parse rewrite: %v", errs)
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("compile rewrite code-point %q: %v", tc.token, err)
			}
			r := cfg.ClassOfService.DSCPRewriteRules["cp-rw"]
			if r == nil || len(r.Entries) != 1 || r.Entries[0].DSCPValue != tc.want {
				t.Fatalf("rewrite for %q = %+v, want DSCP %d", tc.token, r, tc.want)
			}
		})
	}

	// A six-character non-binary decimal stays decimal and is rejected.
	p := NewParser(cpForwardingClasses + "\n" +
		"class-of-service { classifiers { dscp cp-cl { forwarding-class voice { loss-priority low { code-points [ 123456 ]; } } } } }")
	tree, _ := p.Parse()
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("compile classifier 123456 err = %v, want out-of-range rejection", err)
	}
}
func TestCoS8021ThreeBitCodePointParity13969(t *testing.T) {
	// The finding identifies the 802.1p parser as the loud-failure sibling.
	// It has the same field-width rule: only three-character all-[01] tokens
	// are binary, while the existing one-character decimal form remains valid.
	classifier := cpFamilies()[1]
	cfg := cpCompileHier(t,
		classifier.stanza("{ code-points [ 101 010 ]; }"))
	cpCheck(t, "802.1p bit-string classifier", cfg, classifier, []uint8{5, 2})

	for _, index := range []int{5, 6} {
		rewrite := cpFamilies()[index]
		cfg := cpCompileHier(t,
			rewrite.stanza(rewrite.leaf+" 101;"))
		cpCheck(t, "802.1p bit-string rewrite "+rewrite.leaf, cfg, rewrite, []uint8{5})
	}

	inet := cpCompileHier(t, cpClassifierStanza("inet-precedence")(
		"{ code-points [ 101 010 ]; }"))
	precs := inet.ClassOfService.INetPrecedenceClassifierDefs["cp-cl"]
	if precs == nil || len(precs.Entries) != 1 ||
		len(precs.Entries[0].Precedences) != 2 ||
		precs.Entries[0].Precedences[0] != 5 ||
		precs.Entries[0].Precedences[1] != 2 {
		t.Errorf("inet-precedence sibling values = %+v, want [5 2]", precs)
	}
}
