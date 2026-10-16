package config

import (
	"reflect"
	"testing"
)

// #14147: the authorization gate tokenized copy/rename/insert with the
// config lexer (unquoting strings, stripping comments) while every
// executor split the same line with strings.Fields (keeping quotes,
// keeping comment words). A quoted keyword ("to"/"before"/"after") or a
// comment word therefore made the gate adjudicate different endpoints
// than the store acted on — an allow-listed class could rename into a
// path its allow-configuration never covered.
//
// The fix is one canonical split in pkg/config used by the gate and by
// every executor. These cells pin the parser directly and the gate
// decision on the same lines.

func TestParseCopyRenameCommand14147(t *testing.T) {
	for name, tc := range map[string]struct {
		line    string
		wantSrc []string
		wantDst []string
		wantOK  bool
	}{
		"plain rename": {
			"rename system services ssh to system services telnet",
			[]string{"system", "services", "ssh"}, []string{"system", "services", "telnet"}, true,
		},
		"quoted to is data not separator": {
			`rename system services ssh "to" foo to system root-authentication`,
			[]string{"system", "services", "ssh", "to", "foo"}, []string{"system", "root-authentication"}, true,
		},
		"quoted dst keyword": {
			`copy system services ssh to system services "to"`,
			[]string{"system", "services", "ssh"}, []string{"system", "services", "to"}, true,
		},
		"comment words are not separators": {
			`rename system services /* to */ ssh to system root-authentication`,
			[]string{"system", "services", "ssh"}, []string{"system", "root-authentication"}, true,
		},
		"quoted separator alone is malformed": {
			`rename system services ssh "to" foo`,
			nil, nil, false,
		},
		"missing dst": {"rename system services ssh to", nil, nil, false},
		"missing src": {"rename to system x", nil, nil, false},
		"wrong verb":  {"copyx system a to system b", nil, nil, false},
		"empty":       {"", nil, nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			src, dst, ok := ParseCopyRenameCommand(tc.line)
			if ok != tc.wantOK || !reflect.DeepEqual(src, tc.wantSrc) || !reflect.DeepEqual(dst, tc.wantDst) {
				t.Fatalf("ParseCopyRenameCommand(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.line, src, dst, ok, tc.wantSrc, tc.wantDst, tc.wantOK)
			}
		})
	}
}

func TestParseInsertCommand14147(t *testing.T) {
	for name, tc := range map[string]struct {
		line     string
		wantElem []string
		wantRef  []string
		wantBef  bool
		wantOK   bool
	}{
		"plain before": {
			"insert system services ssh before telnet",
			[]string{"system", "services", "ssh"}, []string{"system", "services", "telnet"}, true, true,
		},
		"quoted before is data not keyword": {
			`insert system services ssh "before" x before root-authentication`,
			[]string{"system", "services", "ssh", "before", "x"}, []string{"system", "services", "ssh", "before", "root-authentication"}, true, true,
		},
		"comment after is not keyword": {
			`insert system services ssh /* after */ foo after bar`,
			[]string{"system", "services", "ssh", "foo"}, []string{"system", "services", "ssh", "bar"}, false, true,
		},
		"quoted keyword alone is malformed": {
			`insert system services ssh "before" x`,
			nil, nil, false, false,
		},
		"missing ref": {"insert system services ssh before", nil, nil, false, false},
		"wrong verb":  {"insertx system a before b", nil, nil, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			elem, ref, before, ok := ParseInsertCommand(tc.line)
			if ok != tc.wantOK || !reflect.DeepEqual(elem, tc.wantElem) ||
				!reflect.DeepEqual(ref, tc.wantRef) || before != tc.wantBef {
				t.Fatalf("ParseInsertCommand(%q) = (%q, %q, %v, %v), want (%q, %q, %v, %v)",
					tc.line, elem, ref, before, ok, tc.wantElem, tc.wantRef, tc.wantBef, tc.wantOK)
			}
		})
	}
}

// The decisive #14147 gate cells: an allow-list covering only
// ^system services must NOT admit a rename whose real destination is
// system root-authentication, however the separator is disguised.
func TestAuthorizeConfigMutationCopyRenameInsertAgreeWithExecutor14147(t *testing.T) {
	cfg := classWithConfigRegex9154(t, "^system services", "")
	for name, line := range map[string]string{
		"quoted to":     `rename system services ssh "to" foo to system root-authentication`,
		"quoted copy":   `copy system services ssh "to" foo to system root-authentication`,
		"comment to":    `rename system services /* to */ ssh to system root-authentication`,
		"quoted src to": `rename system "to" foo to system root-authentication`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := AuthorizeConfigMutation(cfg, "limited", nil, line); err == nil {
				t.Fatalf("%q was ALLOWED under allow-configuration %q; the executor "+
					"renames into system root-authentication, which the allow never covers (#14147)",
					line, "^system services")
			}
		})
	}
	// Positive control: both real endpoints under the allow must pass.
	for _, line := range []string{
		`rename system services ssh "to" foo to system services telnet`,
		"rename system services ssh to system services telnet",
		`copy system services ssh to system services "to"`,
	} {
		if err := AuthorizeConfigMutation(cfg, "limited", nil, line); err != nil {
			t.Errorf("%q was refused though both real endpoints are allowed: %v (#14147)", line, err)
		}
	}
}

// Insert: the gate adjudicates the element path; a quoted "before" must
// not truncate it short of the denied tail.
func TestAuthorizeConfigMutationInsertQuotedKeyword14147(t *testing.T) {
	cfg := classWithConfigRegex9154(t, "", "^system root-authentication$")
	// Element is `system services ssh before x` — not the anchored deny.
	// (Gate must not refuse it for the wrong reason, and must not let a
	// quoted keyword hide a denied element — see executor cells.)
	if err := AuthorizeConfigMutation(cfg, "limited", nil,
		`insert system services ssh "before" x before y`); err != nil {
		t.Errorf("insert with quoted keyword in element was refused: %v (#14147)", err)
	}
	denyCfg := classWithConfigRegex9154(t, "", "^system services ssh before x$")
	if err := AuthorizeConfigMutation(denyCfg, "limited", nil,
		`insert system services ssh "before" x before y`); err == nil {
		t.Error("insert whose real element is the anchored deny was ALLOWED; " +
			"the quoted keyword truncated the gated element (#14147)")
	}
}
