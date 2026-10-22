package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #3393: a firewall-filter `from protocol ipv6` term must stay coherent across
// the Go commit gate and the Rust apply path. The Go gate
// (config.filterProtocolResolvable) was widened to accept "ipv6" when
// appid.ProtocolNumber("ipv6") was closed to IANA 41, but the filter snapshot
// builder emits the protocol token VERBATIM (no name->number canonicalization,
// unlike the application/NAT lowering paths). The Rust filter compiler resolves
// that verbatim token through ip_proto::proto_number; before the fix
// proto_number had no "ipv6" arm, so a gate-passing `from protocol ipv6` filter
// committed in Go yet failed snapshot compilation with
// UnrepresentableFilterProtocol — commit/apply drift (the #1961 class).
//
// This guard pins the Go half of the contract: the gate accepts "ipv6" AND the
// builder emits exactly that token, so the token the Rust resolver must handle
// is "ipv6". The Rust half (proto_number("ipv6") == 41, no
// UnrepresentableFilterProtocol) is pinned by
// userspace-dp filter::tests::protocol_3393_ipv6_resolves_scoped and the
// filter_protocol_accept_set_subset_of_resolver contract test.
func TestFilterSnapshotIPv6ProtocolEmittedAndResolvable(t *testing.T) {
	const token = "ipv6"

	// (a) The commit gate accepts the token — i.e. `from protocol ipv6`
	// passes commit and reaches the snapshot builder.
	if !config.FilterProtocolResolvable(token) {
		t.Fatalf("config.FilterProtocolResolvable(%q) = false, want true (#3393 commit gate)", token)
	}

	// (b) The snapshot builder emits the token VERBATIM (proving the Rust
	// resolver, not a Go-side number canonicalization, is what must handle it).
	cfg := &config.Config{}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"f6": {Name: "f6", Terms: []*config.FirewallFilterTerm{{
			Name:      "scoped",
			Protocols: []string{token},
			Action:    config.FilterActionDiscard,
		}}},
	}
	snaps := buildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("expected 1 filter with 1 term, got %#v", snaps)
	}
	got := snaps[0].Terms[0].Protocols
	if len(got) != 1 || got[0] != token {
		t.Fatalf("emitted protocols = %v, want exactly [%q] verbatim (#3393)", got, token)
	}
}
