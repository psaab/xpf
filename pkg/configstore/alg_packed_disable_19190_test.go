package configstore

import (
	"reflect"
	"strings"
	"testing"
)

// algPackedDisableCases19190: per modeled ALG, a packed `<inert flag or valued
// statement> disable` line. #19190: it used to commit clean and leave the ALG
// ENABLED, because the inert statement "owned" the operator's disable. A flag
// has no body and a valued statement owns only its value, so the disable is
// the class's. tftp and pptp declare only traceoptions (a container) and are
// covered by the control below.
var algPackedDisableCases19190 = []struct{ proto, stmt string }{
	{"ftp", "allow-mismatch-ip-address"},
	{"ftp", "line-break-extension"},
	{"dns", "oversize-message-drop"},
	{"dns", "maximum-message-length 1024"},
	{"sip", "hide-via-headers"},
	{"sip", "c-timeout 5"},
	// A valued statement with its value omitted: `disable` is never a value.
	{"dns", "doctoring"},
}

func TestALGPackedDisableAfterFlagOrValueCommitsDisabled19190(t *testing.T) {
	for _, c := range algPackedDisableCases19190 {
		t.Run(c.proto+" "+c.stmt, func(t *testing.T) {
			spellings := []string{
				"set security alg " + c.proto + " " + c.stmt + " disable",                                   // packed flat-set
				"security { alg " + c.proto + " " + c.stmt + " disable; }",                                  // packed hierarchical
				"set security alg " + c.proto + " " + c.stmt + "\nset security alg " + c.proto + " disable", // split flat-set
				"security { alg { " + c.proto + " { " + c.stmt + "; disable; } } }",                         // braced split
			}
			var want interface{}
			for i, text := range spellings {
				cfg, err := CheckText(text, -1)
				if err != nil {
					t.Fatalf("%q refused: %v", text, err)
				}
				if !cfg.Security.ALG.ALGDisabled(c.proto) {
					t.Fatalf("%q committed with ALG %s ENABLED; the operator's disable was dropped", text, c.proto)
				}
				// The whole compiled ALGConfig, not just the flag: every
				// spelling must compile identically to the braced split.
				if i == 0 {
					want = cfg.Security.ALG
				} else if !reflect.DeepEqual(cfg.Security.ALG, want) {
					t.Fatalf("%q compiled ALGConfig %+v, want %+v (the packed flat-set spelling)", text, cfg.Security.ALG, want)
				}
			}
		})
	}
}

// tftp and pptp declare only traceoptions, a CONTAINER. A flat-set
// `traceoptions disable` has exactly the tree shape of the braced
// `traceoptions { disable; }`, which #16814 pins as an accepted body. So every
// packed or braced spelling keeps the body reading and the ALG ENABLED, while
// the split `disable` disables it. This is the named residual of #19190: a
// change here is a #16814 contract change.
func TestALGContainerOnlyClassesKeepTheBodyReading19190(t *testing.T) {
	for _, proto := range []string{"tftp", "pptp"} {
		for _, text := range []string{
			"set security alg " + proto + " traceoptions disable",
			"security { alg " + proto + " traceoptions disable; }",
			"security { alg { " + proto + " { traceoptions { disable; } } } }",
		} {
			cfg, err := CheckText(text, -1)
			if err != nil {
				t.Fatalf("%q refused: %v", text, err)
			}
			if cfg.Security.ALG.ALGDisabled(proto) {
				t.Fatalf("%q disabled ALG %s; a container's body must not reach the class", text, proto)
			}
		}
		cfg, err := CheckText("set security alg "+proto+" traceoptions\nset security alg "+proto+" disable", -1)
		if err != nil || !cfg.Security.ALG.ALGDisabled(proto) {
			t.Fatalf("split `%s disable` (err=%v) did not disable the ALG", proto, err)
		}
	}
}

// Control (#16814's contract, unchanged): a container such as traceoptions
// owns the rest of its line, so `traceoptions flag disable` and
// `traceoptions disable` are its body and do NOT disable the ALG.
func TestALGContainerStillOwnsItsLine19190(t *testing.T) {
	for _, text := range []string{
		"set security alg tftp traceoptions flag disable",
		"set security alg pptp traceoptions disable",
		"set security alg ftp allow-mismatch-ip-address traceoptions flag disable",
	} {
		cfg, err := CheckText(text, -1)
		if err != nil {
			t.Fatalf("%q refused: %v", text, err)
		}
		if cfg.Security.ALG.TFTPDisable || cfg.Security.ALG.PPTPDisable || cfg.Security.ALG.FTPDisable {
			t.Fatalf("%q disabled an ALG; a container's body must not reach the class: %+v", text, cfg.Security.ALG)
		}
	}
}

// A bodiless flag owns nothing, so a token after it that is not class-level
// is an unknown keyword. It used to be swallowed as the flag's "body".
func TestALGTokenAfterABodilessFlagIsChecked19190(t *testing.T) {
	_, err := CheckText("set security alg ftp allow-mismatch-ip-address xpfbogus", -1)
	if err == nil || !strings.Contains(err.Error(), `unknown configuration keyword "xpfbogus"`) {
		t.Fatalf("a token after a bodiless flag committed unchecked (err=%v)", err)
	}
}

// After a flag the line is class-level again, so a later inert statement on
// the same packed line is recorded (its advisory) exactly as in the split
// spelling: the whole compiled ALGConfig must match.
func TestALGPackedLineAfterAFlagCompilesLikeSplit19190(t *testing.T) {
	packed, err := CheckText("set security alg ftp allow-mismatch-ip-address disable ftps-extension", -1)
	if err != nil {
		t.Fatalf("packed refused: %v", err)
	}
	split, err := CheckText("set security alg ftp allow-mismatch-ip-address\nset security alg ftp disable\nset security alg ftp ftps-extension", -1)
	if err != nil {
		t.Fatalf("split refused: %v", err)
	}
	if !reflect.DeepEqual(packed.Security.ALG, split.Security.ALG) {
		t.Fatalf("packed ALGConfig %+v, split %+v", packed.Security.ALG, split.Security.ALG)
	}
}
