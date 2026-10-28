package userspace

import (
	"fmt"
	"strings"
	"testing"
)

// rustWireProbeTB captures Fatalf so a probe can assert that a helper
// failed loudly instead of silently first-matching. The scanner helpers
// are written against *testing.T and call t.Fatalf -> runtime.Goexit, so
// probes that expect a fatal pass this captured TB whose Fatalf only
// records; the helper then returns its zero value without binding an
// answer, and the assertion is on the recorded message.
type rustWireProbeTB struct {
	fatal string
}

func (p *rustWireProbeTB) Helper() {}

func (p *rustWireProbeTB) Errorf(format string, args ...any) {
	if p.fatal == "" {
		p.fatal = fmt.Sprintf(format, args...)
	}
}

func (p *rustWireProbeTB) Fatalf(format string, args ...any) {
	if p.fatal == "" {
		p.fatal = fmt.Sprintf(format, args...)
	}
}

// TestRustWireScannerCommentStringProbes17142 is the review-18193
// adversarial suite for the shared Rust serde scanner. Each probe is a
// named acceptance shape: a fake declaration hidden in a comment must
// not win the lookup, a duplicate declaration in one file must fail
// loud, and braces inside strings/comments must neither truncate nor
// invent a struct. Probes that expect a parse assert the REAL struct's
// fields; probes that expect a failure assert a fatal was recorded.
// Each probe fails against the pre-fold scanner (raw first-match over
// unstripped text, per-file duplicate counting) and passes after it.
func TestRustWireScannerCommentStringProbes17142(t *testing.T) {
	real := "pub struct SessionDeltaInfo {\n" +
		"    #[serde(rename = \"ingress_ifindex\", default)]\n" +
		"    pub ingress_ifindex: i32,\n" +
		"    #[serde(rename = \"nat_scope_ifindex\", default)]\n" +
		"    pub nat_scope_ifindex: i32,\n" +
		"}\n"

	t.Run("BlockCommentFakeDoesNotWin", func(t *testing.T) {
		src := "/*\npub struct SessionDeltaInfo {\n" +
			"    #[serde(rename = \"nat_scope_ifindex\")]\n" +
			"    pub ingress_ifindex: i32,\n" +
			"}\n*/\n" + real
		fields := rustWireFieldsInStructSource(t, src, "SessionDeltaInfo")
		if got := keyOf17142(fields, "ingress_ifindex"); got != "ingress_ifindex" {
			t.Fatalf("block-comment fake won the lookup: ingress_ifindex -> %q, fields=%+v", got, fields)
		}
		if got := keyOf17142(fields, "nat_scope_ifindex"); got != "nat_scope_ifindex" {
			t.Fatalf("real struct not parsed after block-comment fake: nat_scope_ifindex -> %q", got)
		}
	})

	t.Run("NestedBlockCommentFakeDoesNotWin", func(t *testing.T) {
		src := "/* outer /* pub struct SessionDeltaInfo { pub fake: u8 } */ still comment */\n" + real
		fields := rustWireFieldsInStructSource(t, src, "SessionDeltaInfo")
		if got := keyOf17142(fields, "ingress_ifindex"); got != "ingress_ifindex" {
			t.Fatalf("nested block-comment fake won: ingress_ifindex -> %q, fields=%+v", got, fields)
		}
		if len(fields) != 2 {
			t.Fatalf("nested block-comment fake changed the field set: fields=%+v", fields)
		}
	})

	t.Run("LineCommentFakeDoesNotWin", func(t *testing.T) {
		src := "// pub struct SessionDeltaInfo { pub fake: u8 }\n" +
			"/// pub struct SessionDeltaInfo { pub fake2: u8 }\n" + real
		fields := rustWireFieldsInStructSource(t, src, "SessionDeltaInfo")
		if len(fields) != 2 || keyOf17142(fields, "ingress_ifindex") != "ingress_ifindex" {
			t.Fatalf("line-comment fake won or real struct lost: fields=%+v", fields)
		}
	})

	t.Run("DuplicateInOneFileFailsLoud", func(t *testing.T) {
		src := "mod a {\n    pub struct SessionDeltaInfo { pub one: u8 }\n}\n" +
			"mod b {\n    pub struct SessionDeltaInfo { pub two: u8 }\n}\n"
		probe := &rustWireProbeTB{}
		_ = rustWireFieldsInStructSource(probe, src, "SessionDeltaInfo")
		if probe.fatal == "" {
			t.Fatalf("duplicate declarations in one file silently first-matched (no fatal recorded)")
		}
		if !strings.Contains(probe.fatal, "declared 2 times") {
			t.Fatalf("duplicate failure did not name the count: %q", probe.fatal)
		}
	})

	t.Run("BraceInStringParsesCorrectly", func(t *testing.T) {
		src := `pub struct SessionDeltaInfo {
    #[serde(rename = "ingress_ifindex", default = "make_{")]
    pub ingress_ifindex: i32,
    #[serde(rename = "close}brace", default)]
    pub nat_scope_ifindex: i32,
}
`
		fields := rustWireFieldsInStructSource(t, src, "SessionDeltaInfo")
		if len(fields) != 2 {
			t.Fatalf("brace-in-string truncated or split the struct: fields=%+v", fields)
		}
		if got := keyOf17142(fields, "nat_scope_ifindex"); got != "close}brace" {
			t.Fatalf("field after brace-in-string lost: nat_scope_ifindex -> %q, fields=%+v", got, fields)
		}
		if got := keyOf17142(fields, "ingress_ifindex"); got != "ingress_ifindex" {
			t.Fatalf("rename before brace-in-string lost: ingress_ifindex -> %q", got)
		}
	})

	t.Run("BraceInRawStringParsesCorrectly", func(t *testing.T) {
		src := `pub struct SessionDeltaInfo {
    #[serde(rename = "ingress_ifindex", default = r#"make_{"#)]
    pub ingress_ifindex: i32,
    pub nat_scope_ifindex: i32,
}
`
		fields := rustWireFieldsInStructSource(t, src, "SessionDeltaInfo")
		if len(fields) != 2 || keyOf17142(fields, "ingress_ifindex") != "ingress_ifindex" {
			t.Fatalf("brace-in-raw-string broke the parse: fields=%+v", fields)
		}
	})

	t.Run("DocCommentBraceDoesNotTruncate", func(t *testing.T) {
		src := "pub struct SessionDeltaInfo {\n" +
			"    /// closes a brace } and opens { one\n" +
			"    #[serde(rename = \"ingress_ifindex\", default)]\n" +
			"    pub ingress_ifindex: i32,\n" +
			"    pub nat_scope_ifindex: i32,\n" +
			"}\n"
		fields := rustWireFieldsInStructSource(t, src, "SessionDeltaInfo")
		if len(fields) != 2 || keyOf17142(fields, "nat_scope_ifindex") != "nat_scope_ifindex" {
			t.Fatalf("doc-comment brace truncated the struct: fields=%+v", fields)
		}
	})

	t.Run("CharAndLifetimeShapesParseCorrectly", func(t *testing.T) {
		src := "const SEP: char = '}';\n" +
			"const OPEN: char = '{';\n" +
			"pub struct SessionDeltaInfo {\n" +
			"    #[serde(rename = \"ingress_ifindex\", default)]\n" +
			"    pub ingress_ifindex: i32,\n" +
			"    pub sep: char,\n" +
			"    pub nat_scope_ifindex: i32,\n" +
			"}\n" +
			"fn keep<'a>(x: &'a str) -> &'a str { x }\n"
		fields := rustWireFieldsInStructSource(t, src, "SessionDeltaInfo")
		if len(fields) != 3 || keyOf17142(fields, "sep") != "sep" ||
			keyOf17142(fields, "ingress_ifindex") != "ingress_ifindex" {
			t.Fatalf("char/lifetime-adjacent parse broke: fields=%+v", fields)
		}
		stripped := rustStripCommentsAndStrings(src)
		if !strings.Contains(stripped, "fn keep<'a>(x: &'a str)") {
			t.Fatalf("lifetime quotes were blanked as char literals: %q", stripped)
		}
	})

	t.Run("FakeInStringDoesNotWin", func(t *testing.T) {
		src := "const FAKE: &str = \"pub struct SessionDeltaInfo { pub fake: u8 }\";\n" + real
		fields := rustWireFieldsInStructSource(t, src, "SessionDeltaInfo")
		if len(fields) != 2 || keyOf17142(fields, "ingress_ifindex") != "ingress_ifindex" {
			t.Fatalf("string-hidden fake won or real struct lost: fields=%+v", fields)
		}
	})

	t.Run("CommentFakeAloneIsNotFound", func(t *testing.T) {
		src := "/* pub struct SessionDeltaInfo { pub fake: u8 } */\n"
		probe := &rustWireProbeTB{}
		_ = rustWireFieldsInStructSource(probe, src, "SessionDeltaInfo")
		if probe.fatal == "" {
			t.Fatalf("comment-only fake declaration was accepted as the struct (no fatal recorded)")
		}
	})

	t.Run("StripperBlanksCommentAndStringKeepsCode", func(t *testing.T) {
		src := "let a = \"keep? no }\"; // struct Fake { }\nlet b = '}';\nlet c = r#\"{\"#;\ncode_after();\n"
		stripped := rustStripCommentsAndStrings(src)
		if len(stripped) != len(src) {
			t.Fatalf("stripper changed length: %d != %d", len(stripped), len(src))
		}
		if strings.Contains(stripped, "Fake") || strings.Contains(stripped, "keep?") {
			t.Fatalf("comment/string text survived stripping: %q", stripped)
		}
		if !strings.Contains(stripped, "code_after();") {
			t.Fatalf("code after literals was blanked: %q", stripped)
		}
		if strings.Count(stripped, "\n") != strings.Count(src, "\n") {
			t.Fatalf("stripper changed newline count: %q", stripped)
		}
	})
}

func keyOf17142(fields []rustStructWireField, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.WireKey
		}
	}
	return ""
}
