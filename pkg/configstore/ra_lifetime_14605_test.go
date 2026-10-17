package configstore

import (
	"strings"
	"testing"
)

// #14605 — RFC 4861 §6.2.1: AdvDefaultLifetime MUST be either zero or
// between MaxRtrAdvInterval and 9000 seconds. Strict commit must reject
// 0 < default-lifetime < effective max-advertisement-interval (including
// the 600s default when no max leaf is set) and default-lifetime > 9000.
// On revert (no lifetime arm in crossCheckRAIntervals) every reject case
// below compiles cleanly and CheckText returns nil.

func raLifetimeText(maxI, lifetime string) string {
	body := ""
	if maxI != "" {
		body += "            max-advertisement-interval " + maxI + ";\n"
	}
	if lifetime != "" {
		body += "            default-lifetime " + lifetime + ";\n"
	}
	return `protocols {
    router-advertisement {
        interface ge-0-0-0 {
` + body + `        }
    }
}`
}

func TestCheckText_RALifetime14605_RejectsBelowEffectiveMax(t *testing.T) {
	for _, c := range []struct{ maxI, lifetime string }{
		{"600", "10"}, // issue probe: dl=10 with periodic gap up to 600s
		{"600", "599"},
		{"1800", "1799"},
		{"", "10"}, // no max leaf -> effective max is the 600s default
		{"", "599"},
	} {
		_, err := CheckText(raLifetimeText(c.maxI, c.lifetime), -1)
		if err == nil {
			t.Fatalf("expected reject for max=%q default-lifetime=%s (0 < lifetime < effective max, RFC 4861 §6.2.1), got nil", c.maxI, c.lifetime)
		}
		for _, want := range []string{"default-lifetime", "RFC 4861", "max-advertisement-interval"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error should name %q: %v", want, err)
			}
		}
	}
}

func TestCheckText_RALifetime14605_RejectsOver9000(t *testing.T) {
	// 9001 is inside the per-leaf 16-bit range (0..65535), so only the
	// cross-field RFC ceiling can reject it.
	_, err := CheckText(raLifetimeText("600", "9001"), -1)
	if err == nil {
		t.Fatal("expected reject for default-lifetime 9001 (> 9000, RFC 4861 §6.2.1), got nil")
	}
	if !strings.Contains(err.Error(), "default-lifetime") || !strings.Contains(err.Error(), "9000") {
		t.Fatalf("error should name default-lifetime and the 9000 ceiling: %v", err)
	}
}

func TestCheckText_RALifetime14605_AcceptsValid(t *testing.T) {
	for _, c := range []struct{ maxI, lifetime string }{
		{"600", "0"},    // explicit not-a-default-router
		{"600", "600"},  // equal to max: lower boundary legal
		{"600", "1800"}, // canonical 3*max
		{"600", "9000"}, // RFC ceiling
		{"1800", "1800"},
		{"1800", "9000"},
		{"", "0"},
		{"", "600"},
		{"", "9000"},
		{"", ""}, // both unset: sender derives 1800
	} {
		if _, err := CheckText(raLifetimeText(c.maxI, c.lifetime), -1); err != nil {
			t.Fatalf("max=%q default-lifetime=%q should validate: %v", c.maxI, c.lifetime, err)
		}
	}
}
