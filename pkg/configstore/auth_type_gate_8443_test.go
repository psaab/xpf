package configstore

import (
	"strings"
	"testing"
)

// #8443: `authentication-type` is a typed leaf, so a value the FRR renderers do
// not recognize is rejected at COMMIT rather than silently downgrading md5 to
// plaintext at render time.
//
// These go through CheckText, not CompileConfig: typed-leaf validators run in
// config.SchemaValidate, which sits ABOVE the compiler in compileTreeStrict.
// A cell calling CompileConfig would never reach the validator and would pass
// no matter what the schema said.
//
// Fixture spellings were verified by compiling one and dumping the struct
// before this table was written — `authentication-type md5;` really does
// populate AuthType in all three stanzas. A fixture whose authoring spelling
// silently produces an empty field makes every row, including the controls,
// pass for the wrong reason.

const (
	isisAuthCfg = `protocols {
    isis {
        authentication-type %s;
        authentication-key "k";
    }
}
`
	ripAuthCfg = `protocols {
    rip {
        authentication-type %s;
        authentication-key "k";
    }
}
`
	// #14399: the RI IS-IS fixture now carries a key as well — a bare
	// `authentication-type` with no key is rejected as unauthenticated,
	// which is not what this #8443 spelling control is about.
	riISISAuthCfg = `routing-instances {
    vrf1 {
        instance-type virtual-router;
        protocols {
            isis {
                authentication-type %s;
                authentication-key "k";
            }
        }
    }
}
`
)

func checkAuthType(t *testing.T, tmpl, value string) error {
	t.Helper()
	_, err := CheckText(strings.Replace(tmpl, "%s", value, 1), 0)
	return err
}

// Every canonical spelling COMMITS, in all three stanzas.
//
// This is the positive control and it leads deliberately: without it, a
// rejection below could mean the stanza is unreachable — a typo in my own
// fixture, a schema path that never matches — rather than the validator firing.
func TestCanonicalAuthTypesCommit8443(t *testing.T) {
	for _, tmpl := range []struct {
		name string
		cfg  string
	}{
		{"protocols isis", isisAuthCfg},
		{"protocols rip", ripAuthCfg},
		{"routing-instances isis", riISISAuthCfg},
	} {
		for _, v := range []string{"md5", "simple", "text"} {
			if err := checkAuthType(t, tmpl.cfg, v); err != nil {
				t.Errorf("%s: authentication-type %q was REJECTED at commit: %v",
					tmpl.name, v, err)
			}
		}
	}
}

// An unrecognized value is rejected in all three stanzas.
//
// The routing-instance row is listed explicitly because stripping the validator
// from THAT schema copy alone is a mutation the top-level rows cannot see —
// there are five copies and a fix that types only the obvious ones leaves the
// instance path open.
func TestUnrecognizedAuthTypeRejectedAtCommit8443(t *testing.T) {
	for _, tmpl := range []struct {
		name string
		cfg  string
	}{
		{"protocols isis", isisAuthCfg},
		{"protocols rip", ripAuthCfg},
		{"routing-instances isis", riISISAuthCfg},
	} {
		for _, v := range []string{"md5-typo", "MD5", "plaintext", "none"} {
			err := checkAuthType(t, tmpl.cfg, v)
			if err == nil {
				t.Errorf("%s: authentication-type %q COMMITTED; it renders as "+
					"plaintext, so the key would travel in the clear while "+
					"`show configuration` still says otherwise", tmpl.name, v)
				continue
			}
			// The message must name the offending value and the accepted set —
			// an operator has to learn what to write, not merely that they were
			// wrong.
			if !strings.Contains(err.Error(), v) {
				t.Errorf("%s: rejection of %q does not name the value: %v", tmpl.name, v, err)
			}
			if !strings.Contains(err.Error(), "md5") || !strings.Contains(err.Error(), "simple") {
				t.Errorf("%s: rejection of %q does not name the accepted set: %v", tmpl.name, v, err)
			}
		}
	}
}
