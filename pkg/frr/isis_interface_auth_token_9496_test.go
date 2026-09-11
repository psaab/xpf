package frr

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func isisIfaceAuth9496(authType, key string) string {
	m := New()
	return m.generateProtocols(nil, nil, nil, nil, &config.ISISConfig{
		NET:        "49.0001.0100.0000.0001.00",
		Level:      "level-2",
		Interfaces: []*config.ISISInterface{{Name: "trust0", AuthType: authType, AuthKey: config.Secret(key)}},
	}, "", 0, nil, nil)
}

// #9496: #9050 belted eight of the ten routing-auth render sites. The two IS-IS
// per-interface sites still went through sanitizeFRRValue, which passes a space
// and turns a TAB into a splitter, so a persisted whitespace secret arriving via
// a tolerant load, HA peer sync or rollback rendered a splittable
// `isis password` line. FRR either truncates it (a silently weakened secret) or
// refuses the line and fails the whole frr-reload.
func TestISISInterfaceAuthSecretIsTokenBelted_9496(t *testing.T) {
	for _, at := range []struct{ authType, keyword string }{{"md5", "md5"}, {"simple", "clear"}} {
		// REFERENCE ARM: a single-token secret is still emitted. Without it,
		// every row below is satisfied by rendering no password at all.
		good := isisIfaceAuth9496(at.authType, "goodsecret")
		if !strings.Contains(good, " isis password "+at.keyword+" goodsecret\n") {
			t.Fatalf("%s: a single-token interface secret must still be emitted:\n%s", at.authType, good)
		}
		for _, tc := range []struct{ name, key string }{
			{"embedded space", "my secret pass"},
			{"embedded tab", "my\tsecret"},
			{"newline", "pw\nagentx"},
			{"DEL", "pw\x7fagentx"},
			{"leading space", " lead"},
			{"trailing space", "trail "},
		} {
			t.Run(at.authType+"/"+tc.name, func(t *testing.T) {
				got := isisIfaceAuth9496(at.authType, tc.key)
				if strings.Contains(got, " isis password ") {
					t.Errorf("#9496: an IS-IS interface secret that is not a single vtysh token was emitted:\n%s", got)
				}
				// The interface must stay configured: omitting the auth line confines
				// the damage to authentication on that circuit.
				if !strings.Contains(got, "interface trust0") {
					t.Errorf("the IS-IS interface was dropped along with its auth line:\n%s", got)
				}
			})
		}
	}
}

// secretRenderUnbelted9496 matches a render line that interpolates a routing auth
// secret through sanitizeFRRValue instead of authTokenOrOmit.
var secretRenderUnbelted9496 = regexp.MustCompile(`Fprintf\(.*(password|authentication-key|message-digest-key).*sanitizeFRRValue\(`)

// #9496 census: no auth-bearing render line in pkg/frr may bypass authTokenOrOmit,
// so an eleventh site cannot repeat the gap #9050's enumeration left.
func TestNoRoutingAuthRenderBypassesTheTokenBelt_9496(t *testing.T) {
	// POSITIVE CONTROL: the matcher must catch the exact pre-fix shape, or an
	// empty census below proves nothing.
	pre := `fmt.Fprintf(&b, " isis password md5 %s\n", sanitizeFRRValue(iface.AuthKey.Reveal()))`
	if !secretRenderUnbelted9496.MatchString(pre) {
		t.Fatalf("census matcher does not recognise the pre-#9496 line; the census below would be vacuous")
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for i, line := range strings.Split(string(body), "\n") {
			if secretRenderUnbelted9496.MatchString(line) {
				t.Errorf("#9496: %s:%d renders an auth secret through sanitizeFRRValue; use authTokenOrOmit:\n  %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	if scanned < 5 {
		t.Fatalf("precondition: census scanned %d non-test files in pkg/frr; expected the package source", scanned)
	}
}
