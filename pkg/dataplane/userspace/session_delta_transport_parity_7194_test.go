package userspace

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/wireschema"
)

// session_delta_transport_parity_7194_test.go — #7194 item 1.
//
// xpf has two HA session-open transports and, until this file, nothing that
// made them equivalent — only the discipline of remembering to edit both.
//
// The evidence #5865 collected is the whole argument for this test. Five fields
// existed on the binary open frame and the Go consumer but not on the Rust JSON
// producer, so the JSON leg installed zeros. Worse, the Go struct's own doc
// comment asserted those fields were "mirrored on the JSON RPC-fallback delta",
// and that sentence was FALSE from the day it was written — nothing detected it,
// because nothing compared the two transports. #6312 is the recurrence: a field
// added to the binary leg in #5212 reached the JSON leg one issue later.
//
// The parity itself is currently CORRECT — #6949 closed the five-field gap, and
// both sides carry 41 fields as of this commit. That is what this test is for.
// It is a REGRESSION GUARD, not a fix: it exists so the next field added to one
// leg reds the suite instead of shipping, which is precisely what did not happen
// the last two times.
//
// WHY IT COMPARES WIRE NAMES AND NOT FIELD NAMES.
//
// The Rust struct carries 35 `#[serde(rename = "...")]` attributes and the Go
// struct carries json tags. Today every rename is an identity rename, so a
// field-name comparison would also pass — and would keep passing through a
// future rename that broke the wire while leaving both field names alone. The
// contract between these two programs is the JSON on the wire, so that is what
// is compared. Pinning the field names instead would encode the wrong SSOT.

// The wire names of the Go consumer: the SINGLE production extractor
// wireschema.WireNamesOf (#17137). Until #17137 this helper
// was a second, test-only copy of the extraction and the pkg/daemon
// production copy was compared with nothing; now the parity guard, the
// schema-agreement cell and the live daemon gate all derive from the
// same production function. The map value repeats the wire name (the
// production extractor intentionally exposes names, not fields).
func goWireNames7194(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range wireschema.WireNamesOf(SessionDeltaInfo{}) {
		out[name] = name
	}
	return out
}

var (
	rustFieldRE7194  = regexp.MustCompile(`^\s*(?:pub(?:\([a-z]+\))?\s+)?([a-z_0-9]+)\s*:`)
	rustRenameRE7194 = regexp.MustCompile(`rename\s*=\s*"([^"]+)"`)
	rustSkipRE7194   = regexp.MustCompile(`serde\s*\(\s*(?:[^)]*\bskip\b)`)
	rustStructRE7194 = regexp.MustCompile(`\bstruct\s+SessionDeltaInfo\s*\{`)
)

// The wire names of the Rust JSON producer's SessionDeltaInfo.
//
// Braces are counted to find the struct's real end rather than reading a fixed
// number of lines. That is not fussiness: my first pass at this used a fixed
// range, truncated the 139-line struct at line 88, and produced a six-field
// "gap" that does not exist. A truncated extraction and a real divergence are
// indistinguishable in the output.
func rustWireNames7194(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "..", "userspace-dp", "src", "protocol", "binding.rs")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(b), "\n")

	// EXACT declaration, not a substring. `strings.Contains(l, "struct
	// SessionDeltaInfo")` also matches `struct SessionDeltaInfoV2` and
	// `struct SessionDeltaInfoRenamed` — my own mutation matrix caught that:
	// renaming the struct left this test GREEN because the renamed type still
	// contained the old name as a prefix. A neighbouring struct declared
	// earlier in the file would have been parsed instead of this one, and the
	// parity result would have described the wrong type entirely.
	start := -1
	for i, l := range lines {
		if rustStructRE7194.MatchString(l) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s no longer declares `struct SessionDeltaInfo`. This test cannot "+
			"compare what it cannot find, and a rename here would otherwise make it "+
			"pass over an empty set", path)
	}

	out := map[string]bool{}
	pendingRename := ""
	pendingSkip := false
	depth := 0
	for i := start; i < len(lines); i++ {
		l := lines[i]
		depth += strings.Count(l, "{") - strings.Count(l, "}")
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "#[") {
			if m := rustRenameRE7194.FindStringSubmatch(trimmed); m != nil {
				pendingRename = m[1]
			}
			if rustSkipRE7194.MatchString(trimmed) {
				pendingSkip = true
			}
			continue
		}
		if i > start {
			if m := rustFieldRE7194.FindStringSubmatch(l); m != nil {
				name := m[1]
				if pendingRename != "" {
					name = pendingRename
				}
				if !pendingSkip {
					out[name] = true
				}
			}
			pendingRename, pendingSkip = "", false
		}
		if depth == 0 && i > start {
			break
		}
	}
	return out
}

// Neither transport may carry a session-open field the other does not.
func TestSessionDeltaTransportsCarryTheSameFields7194(t *testing.T) {
	goNames := goWireNames7194(t)
	rustNames := rustWireNames7194(t)

	// ANTI-VACUITY FLOOR. Both extractions are text- or reflection-driven and
	// both can silently come back short — a moved file, a renamed struct, a
	// regex that stops matching after a syntax change. Every comparison below
	// would then pass over a near-empty set and certify a parity nobody
	// measured. 35 is comfortably under the current 41 and comfortably over
	// anything a broken extractor would produce.
	const floor = 35
	if len(goNames) < floor {
		t.Fatalf("the Go struct reflected only %d wire fields (floor %d); the "+
			"extraction is broken, so a clean result here would certify nothing",
			len(goNames), floor)
	}
	if len(rustNames) < floor {
		t.Fatalf("the Rust struct parsed to only %d wire fields (floor %d); the "+
			"extraction is broken, so a clean result here would certify nothing",
			len(rustNames), floor)
	}

	for wire, goField := range goNames {
		if !rustNames[wire] {
			t.Errorf("the Go consumer expects session-open field %q (%s) that the "+
				"Rust JSON producer does not emit. The JSON leg will decode it as a "+
				"ZERO, and a zero is indistinguishable from a legitimately-absent "+
				"value at the consumer — which is exactly how #5865's five-field gap "+
				"survived for months (#7194)", wire, goField)
		}
	}
	for wire := range rustNames {
		if _, ok := goNames[wire]; !ok {
			t.Errorf("the Rust JSON producer emits session-open field %q that the Go "+
				"consumer does not read. Adding a field to one transport and not the "+
				"other is the #6312 recurrence this test exists to catch (#7194)", wire)
		}
	}
}

// The Rust extractor must survive its own failure modes visibly.
//
// Without this, a regex that matched nothing would make the test above fail on
// the floor with a message about parity rather than about parsing — and the
// next reader would go looking for a missing field instead of a broken test.
func TestRustSessionDeltaExtractorFindsKnownFields7194(t *testing.T) {
	rustNames := rustWireNames7194(t)
	// Three shapes deliberately: a plain field, one whose Go spelling differs
	// sharply from the wire name, and one of the five #5865 added late. If the
	// parser regressed to matching only the simplest shape, the first would
	// still be found and the others would not.
	for _, want := range []string{"timestamp", "rt_flow_session_id", "nat64_snat_v4"} {
		if !rustNames[want] {
			t.Errorf("the Rust extractor did not find field %q. Either the struct "+
				"changed shape or the parser regressed; until that is resolved the "+
				"parity assertion above is not measuring what it claims", want)
		}
	}
}
