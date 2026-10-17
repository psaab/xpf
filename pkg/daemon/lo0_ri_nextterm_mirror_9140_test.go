package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9140 mirror guard. A term carrying BOTH `then routing-instance <x>` and
// `then next term` is now rejected at commit
// (validateFilterTerminalConflictStrict, pkg/config), but the TOLERANT load /
// peer-sync path downgrades that gate to a warning (#1960 no-brick), so the
// shape can still reach this renderer from an already-persisted or peer-synced
// config. This cell pins what the renderer does with it, and — more
// importantly — pins that it AGREES with the Rust evaluator.
//
// Both runtimes terminate the term as accept:
//
//   - Rust: `continue_term: snap.next_term && snap.action.is_empty() && snap.routing_instance.is_empty()` (#14632)
//     (userspace-dp/src/filter/compiler.rs) is FALSE when the routing-instance
//     is set — even with next_term set — and `resolve_term_action` maps the
//     empty action to FilterAction::Accept.
//   - Go nft mirror: the fall-through arm in nftRulesFromTerm is guarded by
//     `term.RoutingInstance == ""`, so the term falls to the terminating
//     switch and renders `accept`.
//
// The external review that produced #9140 proposed "fixing" the Go side alone,
// to `if term.NextTerm || (term.Action == "" && term.RoutingInstance == "")`.
// That would make nft fall through while the Rust evaluator still terminates —
// a kernel-vs-userspace divergence on a shape the tolerant path can still
// deliver, contradicting the mirror contract stated in
// daemon_nft_term_lower.go. If the semantics are ever changed deliberately,
// BOTH sides move together and this cell is updated with them; it going red on
// a one-sided edit is the point.
func TestNftRoutingInstanceWithNextTermStillTerminatesMirroringRust9140(t *testing.T) {
	for _, c := range []struct {
		fam  string
		addr string
		want string
	}{
		{"ip", "10.0.0.0/8", "ip saddr 10.0.0.0/8 accept"},
		{"ip6", "2001:db8::/32", "ip6 saddr 2001:db8::/32 accept"},
	} {
		term := &config.FirewallFilterTerm{
			Name:            "steer-and-next",
			SourceAddresses: []string{c.addr},
			RoutingInstance: "mgmt-vrf",
			NextTerm:        true,
		}
		got := nftRule(t, term, c.fam, nil)
		if got != c.want {
			t.Errorf("routing-instance + next-term (%s): got %q, want %q "+
				"(terminate-as-accept, mirroring userspace-dp compiler.rs)",
				c.fam, got, c.want)
		}
	}
}

// The end-to-end consequence the commit gate now prevents: with the
// contradiction present, the later SSH deny is DEAD for the steer term's match
// set. This documents the harm in the rendered payload rather than describing
// it in prose, and it is the reason the gate is a hard reject at commit rather
// than a warning.
func TestLo0PayloadRoutingInstanceNextTermShadowsLaterDeny9140(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"lo0-in": {
			Name: "lo0-in",
			Terms: []*config.FirewallFilterTerm{
				{
					Name:            "steer",
					SourceAddresses: []string{"10.0.0.0/8"},
					RoutingInstance: "mgmt-vrf",
					NextTerm:        true,
				},
				{
					Name:             "block-ssh",
					Protocols:        []string{"tcp"},
					DestinationPorts: []string{"22"},
					Action:           "discard",
				},
			},
		},
	}
	payload := buildLo0FilterPayload(cfg, "lo0-in", "")
	steer := strings.Index(payload, "ip saddr 10.0.0.0/8 accept")
	deny := strings.Index(payload, "th dport 22 drop")
	if steer < 0 || deny < 0 {
		t.Fatalf("expected both the steer accept and the ssh drop in the payload:\n%s", payload)
	}
	if steer > deny {
		t.Fatalf("term order inverted in the payload:\n%s", payload)
	}
	// First-match-wins: the terminating accept above the deny is exactly why
	// the operator must not be able to commit this. Nothing to assert beyond
	// the ordering — the commit gate is the fix, and pkg/config owns its cell.
}
