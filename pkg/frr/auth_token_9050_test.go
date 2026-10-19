package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func bgpWithPassword9050(pw string) string {
	m := New()
	return m.generateProtocols(nil, nil, &config.BGPConfig{
		LocalAS: 65000,
		Neighbors: []*config.BGPNeighbor{
			{Address: "10.0.0.1", PeerAS: 65001, AuthPassword: config.Secret(pw)},
		},
	}, nil, nil, "", 0, nil, nil)
}

// #9050: a routing auth secret containing whitespace rendered as a SPLITTABLE
// vtysh line on the tolerant load / HA peer-sync path.
//
// The strict commit gate (frrTokenUnsafeIndex) rejects ' ', '\t', < 0x20 and
// 0x7f. The lenient path downgrades that gate to a warning. And the render belt
// (sanitizeFRRValue) rejects only < 0x20 / 0x7f — mapping them TO ' ' — while
// its own doc defers the whitespace case to "the commit gate", which is the gate
// that was just downgraded.
func TestWhitespaceAuthSecretIsNotEmitted9050(t *testing.T) {
	// REFERENCE ARM: an ordinary secret must still be emitted. Without it,
	// every row below is satisfied by a render that emits no password at all.
	if got := bgpWithPassword9050("goodsecret"); !strings.Contains(got, " neighbor 10.0.0.1 password goodsecret\n") {
		t.Fatalf("a single-token secret must still be emitted:\n%s", got)
	}

	for _, tc := range []struct{ name, pw string }{
		{"embedded space", "my secret pass"},
		// A TAB is the sharp one: sanitizeFRRValue converts it INTO a splitter,
		// so the belt manufactures the shape it exists to prevent.
		{"embedded tab", "my\tsecret"},
		{"newline", "pw\nagentx"},
		{"DEL", "pw\x7fagentx"},
		{"leading space", " lead"},
		{"trailing space", "trail "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := bgpWithPassword9050(tc.pw)
			if strings.Contains(got, " neighbor 10.0.0.1 password ") {
				t.Errorf("a secret that is not a single vtysh token was emitted. FRR "+
					"either truncates it to the first token — a silently weakened "+
					"secret — or refuses the line, and a refused line fails the WHOLE "+
					"frr-reload:\n%s", got)
			}
			// #14977: the neighbor itself must NOT be configured either.
			// #9050 kept it, reasoning the adjacency "fails to
			// authenticate" — true only when the peer requires MD5; a
			// peer that does not establishes an unauthenticated session.
			// Fail closed on the enclosing capability instead.
			if strings.Contains(got, " neighbor 10.0.0.1 remote-as 65001\n") {
				t.Errorf("the neighbor with an unrenderable password was still declared (unauthenticated adjacency):\n%s", got)
			}
		})
	}
}

// The render belt's character set must MATCH the commit gate's. A belt that
// admits a character the gate rejects is a seam, and this file exists because
// there was one — the belt covered < 0x20 and 0x7f, the gate also covered ' '
// and '\t', and the gap was exactly the whitespace case.
func TestAuthTokenSetMatchesTheCommitGate9050(t *testing.T) {
	for _, c := range []byte{' ', '\t', '\n', '\r', 0x00, 0x1f, 0x7f} {
		if !frrAuthTokenUnsafe(string([]byte{'a', c, 'b'})) {
			t.Errorf("byte %#x is admitted by the render belt; the commit gate "+
				"rejects it, and the lenient path has only the belt", c)
		}
	}
	// And it must not over-reject: an ordinary printable secret is fine, or the
	// gate becomes an outage of its own.
	for _, s := range []string{"secret", "S3cr3t!", "a-b_c.d", "~!@#$%^&*()"} {
		if frrAuthTokenUnsafe(s) {
			t.Errorf("%q was rejected; only whitespace and control bytes split a "+
				"vtysh token, and refusing a valid secret takes an adjacency down "+
				"for nothing", s)
		}
	}
}
