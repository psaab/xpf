package api

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16552: REST address-book must render #15673 forms via the shared
// renderer: authored form + enforced set, unresolved marker for down.

func stageAddressBookForms16552(t *testing.T) *Server {
	t.Helper()
	restore := config.SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		if fqdn == "up.example.com" {
			return []string{"198.51.100.10"}, nil
		}
		return nil, nil
	})
	t.Cleanup(restore)
	return stageShowTextConfig(t, []string{
		"set security address-book global address h1 10.0.0.1/32",
		"set security address-book global address rng range-address 192.0.2.1 to 192.0.2.3",
		"set security address-book global address wc wildcard-address 10.1.2.3/255.255.255.0",
		"set security address-book global address up dns-name up.example.com ipv4-only",
		"set security address-book global address down dns-name down.example.com",
		"set security address-book global address-set s1 address up",
		"set security address-book global address-set s1 address down",
	})
}

func TestShowTextAddressBookForms16552(t *testing.T) {
	s := stageAddressBookForms16552(t)
	out := renderShowTextBody(t, s, "address-book")
	for _, want := range []string{
		"h1", "10.0.0.1/32",
		"range-address 192.0.2.1 to 192.0.2.3", "192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32",
		"wildcard-address 10.1.2.3/255.255.255.0", "10.1.2.0/24",
		"dns-name up.example.com", "[ipv4-only]", "198.51.100.10/32",
		"dns-name down.example.com", "unresolved", "matches nothing",
		"members: up, down",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("address-book missing %q:\n%s", want, out)
		}
	}
	// Resolved vs unresolved dns lines must differ.
	var upLine, downLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, " up ") || strings.HasPrefix(strings.TrimSpace(line), "up ") {
			upLine = line
		}
		if strings.Contains(line, "down") && strings.Contains(line, "dns-name") {
			downLine = line
		}
	}
	if upLine == downLine || upLine == "" || downLine == "" {
		t.Errorf("up/down lines not distinct: up=%q down=%q\n%s", upLine, downLine, out)
	}

	cfg := s.store.ActiveConfig()
	var sb strings.Builder
	config.RenderAddressBook(&sb, cfg.Security.AddressBook)
	if sb.String() != out {
		t.Errorf("REST output not byte-equal to shared renderer:\nREST:\n%s\nshared:\n%s", out, sb.String())
	}
}
