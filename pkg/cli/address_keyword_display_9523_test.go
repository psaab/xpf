package cli

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9523: the CLI renderers resolve a policy address token the way the dataplane
// does. A match-all keyword is never looked up as a name, so a tolerant-loaded
// object carrying the keyword's name cannot make `show security policies` display
// a narrowing the dataplane does not enforce.
func TestAddressResolversNeverResolveAKeywordAsAName9523(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.AddressBook = &config.AddressBook{
		Addresses: map[string]*config.Address{
			"any4":     {Name: "any4", Value: "10.98.0.0/16"},
			"any-ipv6": {Name: "any-ipv6", Value: "2001:db8:97::/48"},
			"corp":     {Name: "corp", Value: "10.0.0.0/8"},
		},
		AddressSets: map[string]*config.AddressSet{},
	}
	for _, kw := range []string{"any", "any4", "any-ipv6"} {
		if got := resolveAddress(cfg, kw); got != "" {
			t.Errorf("resolveAddress(%q) = %q: the keyword was resolved as a name", kw, got)
		}
		if got := resolveAddressDetail(cfg, kw); got != kw {
			t.Errorf("resolveAddressDetail(%q) = %q: the keyword was resolved as a name", kw, got)
		}
	}
	if got := resolveAddress(cfg, "corp"); got != " (10.0.0.0/8)" {
		t.Errorf("control: an ordinary name must still resolve, got %q", got)
	}
	if got := resolveAddressDetail(cfg, "corp"); got != "10.0.0.0/8" {
		t.Errorf("control: an ordinary name must still resolve, got %q", got)
	}
}
