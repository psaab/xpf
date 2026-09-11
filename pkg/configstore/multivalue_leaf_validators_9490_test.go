package configstore

import (
	"strings"
	"testing"
)

// #9490: four multi-value leaves accepted and compiled undeclared trailing
// tokens on the operator commit channel. Every row of the issue must now be
// refused, naming the bogus token. The acceptance note is the load-bearing
// half: every authored spelling of a VALID value set (bracketed list, flat
// run, repeated line, block form) must keep committing, because "reject the
// garbage" is satisfiable by rejecting the list spelling outright.
func TestMultiValueLeavesRefuseUndeclaredTokens9490(t *testing.T) {
	const book = `address a1 10.0.0.0/24; address a2 10.0.1.0/24; address-set base { address a1; } `
	for _, tc := range []struct {
		name string
		bad  []string
		good []string
	}{
		{"login class permissions",
			[]string{
				`system { login { class c1 { permissions view xpfbogus9206 v1; } } }`,
				`system { login { class c1 { permissions [ view xpfbogus9206 v1 ]; } } }`,
			},
			[]string{
				`system { login { class c1 { permissions [ view configure interface-control ]; } } }`,
				`system { login { class c1 { permissions view configure; } } }`,
				`system { login { class c1 { permissions view; permissions configure; } } }`,
			}},
		{"community members",
			[]string{
				`policy-options { community c1 { members [ 65000:1 xpfbogus9206 v1 ]; } }`,
				`policy-options { community c1 { members 65000:1 xpfbogus9206 v1; } }`,
			},
			[]string{
				`policy-options { community c1 { members [ 65000:1 65000:2 no-export ]; } }`,
				`policy-options { community c1 { members 65000:1 65000:2; } }`,
				`policy-options { community c1 { members 65000:1; members no-export; } }`,
			}},
		{"global address-set address",
			[]string{`security { address-book { global { ` + book + `address-set s1 { address a1 xpfbogus9206 v1; } } } }`},
			[]string{
				`security { address-book { global { ` + book + `address-set s1 { address [ a1 a2 ]; } } } }`,
				`security { address-book { global { ` + book + `address-set s1 { address a1 a2; } } } }`,
				`security { address-book { global { ` + book + `address-set s1 { address a1; address a2; } } } }`,
			}},
		{"zone-local address-set address",
			[]string{`security { zones { security-zone z1 { address-book { ` + book + `address-set s1 { address a1 xpfbogus9206 v1; } } } } }`},
			[]string{`security { zones { security-zone z1 { address-book { ` + book + `address-set s1 { address a1; address a2; } } } } }`}},
		{"global address-set address-set",
			[]string{`security { address-book { global { ` + book + `address-set s1 { address-set base xpfbogus9206 v1; } } } }`},
			[]string{`security { address-book { global { ` + book + `address-set s1 { address-set base; } } } }`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, good := range tc.good {
				if _, err := CheckText(good, 0); err != nil {
					t.Errorf("a valid spelling was refused, so the gate over-rejects: %s\n  %v", good, err)
				}
			}
			for _, bad := range tc.bad {
				_, err := CheckText(bad, 0)
				if err == nil {
					t.Errorf("committed with an undeclared token: %s", bad)
					continue
				}
				if !strings.Contains(err.Error(), "xpfbogus9206") {
					t.Errorf("refused without naming the bogus token: %s\n  %v", bad, err)
				}
			}
		})
	}
}
