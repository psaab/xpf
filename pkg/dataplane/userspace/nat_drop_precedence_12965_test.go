// nat_drop_precedence_12965_test.go: #12965 (follow-up #12853).
//
// #12961 gave a present-empty fail-mode drop overlay precedence over a
// same-named static entry in the POLICY address-book resolver, but NAT
// lowering (resolveNATAddressNamePrefixes -> expandBookNameRecursive) kept
// appending the static value after the dropped overlay, so a NAT
// `match {source,destination}-address-name <drop+alias>` resolved to the
// static prefix while the policy book row enforced match-none — breaking the
// book-row parity the nat.go doc claims. These pins fail on that divergence
// and pass once the NAT traversal honors the same precedence, including for
// a drop+alias member nested inside an address-set.
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// dropAliasCfg12965 builds a static address "denylist" (10.0.0.0/8) shadowed
// by a same-named dynamic-address binding with the given fail-mode.
func dropAliasCfg12965(failMode string, sets map[string]*config.AddressSet) *config.Config {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"denylist": {Name: "denylist", Value: "10.0.0.0/8"},
		},
		AddressSets: sets,
	}
	cfg.Security.DynamicAddress.AddressBindings = map[string]*config.AddressBinding{
		"denylist": {Name: "denylist", FeedNames: []string{"threat"}, FailMode: failMode},
	}
	return cfg
}

func TestNATDropHoldPrecedenceOverStaticAlias12965(t *testing.T) {
	cfg := dropAliasCfg12965("drop", nil)
	overlay := map[string][]string{"denylist": {}}

	// The hold-dropped fail-mode drop binding is match-none: the static alias
	// must not resurrect as a NAT prefix.
	if got := resolveNATAddressNamePrefixes(cfg, overlay, "denylist"); len(got) != 0 {
		t.Fatalf("dropped feed + static alias must resolve to no prefix, got %v", got)
	}
	if got := appendNATSourceAddressName(cfg, overlay, nil, "denylist"); len(got) != 1 || got[0] != natUnresolvedAddressNamePrefix+"denylist" {
		t.Fatalf("dropped feed + static alias must use the unparseable fallback, got %v", got)
	}
	if got := appendNATDestinationAddressName(cfg, overlay, nil, "denylist"); len(got) != 1 || got[0] != natUnresolvedAddressNamePrefix+"denylist" {
		t.Fatalf("dropped feed + static alias must use the DNAT fallback, got %v", got)
	}
	// Book-row parity with the #12961 policy resolver: both match-none.
	if v4, v6 := expandBookNameToCIDRs(cfg, overlay, "denylist"); len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("policy row kept prefixes %v %v the NAT path dropped", v4, v6)
	}

	// Controls: a ready feed unions with the static alias; a DECLARED binding
	// absent from the overlay is quarantined fail-closed as an unready feed
	// (#12216 poison — the static alias must not rescue it, matching the
	// simulator's content rejection); a name with NO declared binding keeps
	// the static alias; a present-empty overlay for a RETAIN binding is not
	// the drop predicate, so static stays (predicate parity with
	// addressBookExpansionResolver.expand).
	if got := resolveNATAddressNamePrefixes(cfg, map[string][]string{"denylist": {"198.51.100.0/24"}}, "denylist"); len(got) != 2 {
		t.Fatalf("ready feed must union with static alias, got %v", got)
	}
	if got := appendNATSourceAddressName(cfg, map[string][]string{}, nil, "denylist"); len(got) != 1 || got[0] != natUnresolvedAddressNamePrefix+"denylist" {
		t.Fatalf("declared-but-unready binding must use the fallback, got %v", got)
	}
	staticOnly := dropAliasCfg12965("drop", nil)
	staticOnly.Security.DynamicAddress.AddressBindings = nil
	if got := resolveNATAddressNamePrefixes(staticOnly, map[string][]string{}, "denylist"); len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("pure static alias must keep resolving, got %v", got)
	}
	retain := dropAliasCfg12965("", nil)
	if got := resolveNATAddressNamePrefixes(retain, overlay, "denylist"); len(got) != 1 || got[0] != "10.0.0.0/8" {
		t.Fatalf("present-empty retain overlay must keep the static alias, got %v", got)
	}
}

func TestNATDropHoldNestedMemberSkipsStaticAlias12965(t *testing.T) {
	cfg := dropAliasCfg12965("drop", map[string]*config.AddressSet{
		"partners-set": {Name: "partners-set", Addresses: []string{"denylist"}},
	})
	overlay := map[string][]string{"denylist": {}}

	// A drop+alias MEMBER nested in a set is match-none for the set too —
	// the nested static alias must not resurrect through the set closure.
	if got := resolveNATAddressNamePrefixes(cfg, overlay, "partners-set"); len(got) != 0 {
		t.Fatalf("set with a hold-dropped drop+alias member must resolve to no prefix, got %v", got)
	}
	if v4, v6 := expandBookNameToCIDRs(cfg, overlay, "partners-set"); len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("policy row diverged from NAT for the nested case: %v %v", v4, v6)
	}
	// Control: the nested member's ready feed still unions through the set.
	if got := resolveNATAddressNamePrefixes(cfg, map[string][]string{"denylist": {"198.51.100.0/24"}}, "partners-set"); len(got) != 2 {
		t.Fatalf("ready nested feed must union with the static alias, got %v", got)
	}
}
