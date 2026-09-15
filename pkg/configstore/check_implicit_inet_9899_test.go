package configstore

import "testing"

func TestCheckImplicitInetFilter9899(t *testing.T) {
	for _, nodeID := range []int{-1, 0} {
		cfg, err := CheckText(`firewall { filter F { term T { from { protocol tcp; } then { discard; } } } }`, nodeID)
		if err != nil {
			t.Fatal(err)
		}
		filter := cfg.Firewall.FiltersInet["F"]
		if filter == nil || len(filter.Terms) != 1 || filter.Terms[0].Action != "discard" {
			t.Fatalf("node=%d: commit check accepted but omitted implicit inet filter: %#v", nodeID, filter)
		}
		for _, match := range []string{"protocol;", "destination-port 65536;", "unknown-match 1;"} {
			if _, err := CheckText(`firewall { filter F { term T { from { `+match+` } then { accept; } } } }`, nodeID); err == nil {
				t.Errorf("node=%d: implicit inet bypassed match validation for %q", nodeID, match)
			}
		}
	}
}
