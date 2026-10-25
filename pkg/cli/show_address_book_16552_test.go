package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16552: local CLI must render #15673 forms (listing + set-member
// detail) via the shared renderer instead of blank Value.

func TestShowAddressBookForms16552(t *testing.T) {
	restore := config.SetLookupAddressDNSNameForTest(func(fqdn string) ([]string, error) {
		if fqdn == "up.example.com" {
			return []string{"198.51.100.10"}, nil
		}
		return nil, nil
	})
	defer restore()
	seed := config.SeedDNSAnswerCacheForTest("up.example.com", "ipv4-only", []string{"198.51.100.10/32"})
	defer seed()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"security address-book global address h1 10.0.0.1/32",
		"security address-book global address rng range-address 192.0.2.1 to 192.0.2.3",
		"security address-book global address wc wildcard-address 10.1.2.3/255.255.255.0",
		"security address-book global address up dns-name up.example.com ipv4-only",
		"security address-book global address down dns-name down.example.com",
		"security address-book global address-set s1 address up",
		"security address-book global address-set s1 address down",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := &CLI{store: store}

	out := captureStdout(t, func() {
		if err := c.showAddressBook(nil); err != nil {
			t.Fatalf("showAddressBook: %v", err)
		}
	})
	for _, want := range []string{
		"10.0.0.1/32",
		"range-address 192.0.2.1 to 192.0.2.3", "192.0.2.2/31",
		"wildcard-address 10.1.2.3/255.255.255.0", "10.1.2.0/24",
		"dns-name up.example.com", "[ipv4-only]", "198.51.100.10/32",
		"dns-name down.example.com", "unresolved", "matches nothing",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("CLI listing missing %q:\n%s", want, out)
		}
	}

	// Filtered by set name: member detail must also show forms.
	detail := captureStdout(t, func() {
		if err := c.showAddressBook([]string{"s1"}); err != nil {
			t.Fatalf("showAddressBook(s1): %v", err)
		}
	})
	for _, want := range []string{"members: up, down", "dns-name up.example.com", "198.51.100.10/32", "dns-name down.example.com", "unresolved"} {
		if !strings.Contains(detail, want) {
			t.Errorf("CLI set detail missing %q:\n%s", want, detail)
		}
	}

	// Filtered by address name.
	one := captureStdout(t, func() {
		if err := c.showAddressBook([]string{"up"}); err != nil {
			t.Fatalf("showAddressBook(up): %v", err)
		}
	})
	if !strings.Contains(one, "198.51.100.10/32") {
		t.Errorf("CLI filtered address missing resolved prefix:\n%s", one)
	}
}
