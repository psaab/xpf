package config

import "testing"

func TestDynamicAddressRepeatedNamedBlocks12824(t *testing.T) {
	input := `security {
    dynamic-address {
        feed-server partners { hostname feeds.example.test; feed-name partners; }
        address-name allow-partners { profile { feed-name partners; } }
        address-name allow-partners { profile { fail-mode drop; } }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	binding := cfg.Security.DynamicAddress.AddressBindings["allow-partners"]
	if binding == nil || binding.FailMode != "drop" || len(binding.FeedNames) != 1 || binding.FeedNames[0] != "partners" {
		t.Fatalf("repeated address-name blocks compiled as %+v; want feed partners and fail-mode drop", binding)
	}
}

func TestDynamicAddressRepeatedLeafFeedNames12824(t *testing.T) {
	input := `security { dynamic-address { feed-server partners { hostname feeds.example.test; feed-name partners-ips; feed-name partners-domains; } } }`
	tree, errs := NewParser(input).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	server := cfg.Security.DynamicAddress.FeedServers["partners"]
	if server == nil || len(server.FeedEntries) != 2 || server.FeedEntries[0] != (FeedEntry{Name: "partners-ips"}) || server.FeedEntries[1] != (FeedEntry{Name: "partners-domains"}) {
		t.Fatalf("repeated feed-name leaves compiled as %+v; want two entries", server)
	}
}

func TestDynamicAddressPeeledFeedNamePath12824(t *testing.T) {
	input := `security {
    dynamic-address {
        feed-server partners {
            hostname feeds.example.test;
            feed-name {
                partners-ips { path /lists/partners.txt; }
            }
        }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	server := cfg.Security.DynamicAddress.FeedServers["partners"]
	if server == nil || len(server.FeedEntries) != 1 || server.FeedEntries[0] != (FeedEntry{Name: "partners-ips", Path: "/lists/partners.txt"}) {
		t.Fatalf("peeled feed-name compiled as %+v; want partners-ips with its path", server)
	}
}
