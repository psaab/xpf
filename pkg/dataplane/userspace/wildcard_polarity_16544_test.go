package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16544 — the userspace address-book resolver must see the Junos-polarity
// expansion: the host wildcard must be a /32 (/128), never 0.0.0.0/0 / ::/0.

func TestWildcardPolarityUserspace16544(t *testing.T) {
	mk := func(spec string) *config.Config {
		t.Helper()
		tree, errs := config.NewParser(`security { address-book { global { address wc { wildcard-address ` + spec + `; } } } zones { security-zone trust; } }`).Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %s: %v", spec, errs)
		}
		cfg, err := config.CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile %s: %v", spec, err)
		}
		return cfg
	}
	cfg := mk("10.1.2.3/255.255.255.255")
	if v4, v6 := expandBookNameToCIDRs(cfg, nil, "wc"); !reflect.DeepEqual(v4, []string{"10.1.2.3/32"}) || len(v6) != 0 {
		t.Fatalf("host wildcard userspace v4=%v v6=%v, want [10.1.2.3/32] (never 0.0.0.0/0)", v4, v6)
	}
	cfg6 := mk("2001:db8::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	if v4, v6 := expandBookNameToCIDRs(cfg6, nil, "wc"); len(v4) != 0 || !reflect.DeepEqual(v6, []string{"2001:db8::1/128"}) {
		t.Fatalf("v6 host wildcard userspace v4=%v v6=%v, want [2001:db8::1/128] (never ::/0)", v4, v6)
	}
	cfg24 := mk("10.1.2.3/255.255.255.0")
	if v4, _ := expandBookNameToCIDRs(cfg24, nil, "wc"); !reflect.DeepEqual(v4, []string{"10.1.2.0/24"}) {
		t.Fatalf("/24 wildcard userspace v4=%v, want [10.1.2.0/24]", v4)
	}
	// Cisco-polarity spelling must not reach the resolver as 10.1.2.0/24.
	tree, errs := config.NewParser(`security { address-book { global { address wc { wildcard-address 10.1.2.3/0.0.0.255; } } } zones { security-zone trust; } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("Cisco-polarity wildcard must be refused at strict commit")
	}
	lenient, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient must boot: %v", err)
	}
	if v4, v6 := expandBookNameToCIDRs(lenient, nil, "wc"); len(v4) != 0 || len(v6) != 0 {
		t.Fatalf("lenient Cisco-polarity wildcard resolved to v4=%v v6=%v, want match-none", v4, v6)
	}
}
