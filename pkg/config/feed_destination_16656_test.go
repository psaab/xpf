package config

import (
	"strings"
	"testing"
)

// TestFeedServerBlockedDestinationLiteral16656 is the #16656 RED-on-revert
// pin: a feed-server URL (or hostname) whose host is an IP literal the
// shared destination predicate would refuse passes strict commit on
// master but can never be fetched (SSRF guard #10177/#14177), so its
// bound names fail closed and freeze policy publication (#5645).
// Strict commit must reject it naming the destination class; the
// `allow-destination` override and the public controls must compile.
func TestFeedServerBlockedDestinationLiteral16656(t *testing.T) {
	blocked := []struct {
		name  string
		host  string
		class string
	}{
		{"rfc1918", "10.1.2.3", "private"},
		{"loopback", "127.0.0.1", "loopback"},
		{"link-local", "169.254.169.254", "link-local"},
		{"cgnat", "100.64.0.1", "special-purpose"},
		{"benchmarking", "198.18.0.1", "special-purpose"},
		{"ula", "fd00::1", "private"},
	}
	for _, tc := range blocked {
		t.Run("commit rejects https literal/"+tc.name, func(t *testing.T) {
			host := tc.host
			if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
			tree := buildTree5183(t, []string{
				"set security dynamic-address feed-server threat url https://" + host + "/list.txt",
				"set security dynamic-address address-name bad profile feed-name threat",
			})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig should reject blocked feed destination %s", tc.host)
			}
			if !strings.Contains(err.Error(), "threat") {
				t.Fatalf("error should name the feed-server, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.class) {
				t.Fatalf("error should name destination class %q, got: %v", tc.class, err)
			}
			if !strings.Contains(err.Error(), "allow-destination") {
				t.Fatalf("error should name the override leaf, got: %v", err)
			}
		})
	}

	t.Run("commit rejects hostname literal", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server threat hostname 192.168.1.10",
			"set security dynamic-address address-name bad profile feed-name threat",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatal("CompileConfig should reject a private hostname literal")
		}
		if !strings.Contains(err.Error(), "private") {
			t.Fatalf("error should name the private class, got: %v", err)
		}
	})

	// Plaintext-http control: the pre-existing http:// gate fires first
	// (unchanged behaviour); the https literal above proves the new gate.
	t.Run("http literal still rejected as plaintext", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server threat url http://10.1.2.3/list.txt",
			"set security dynamic-address address-name bad profile feed-name threat",
		})
		_, err := CompileConfig(tree)
		if err == nil || !strings.Contains(err.Error(), "plaintext http") {
			t.Fatalf("http literal should hit the plaintext gate, got: %v", err)
		}
	})

	t.Run("tolerant load downgrades to warning", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server threat url https://10.1.2.3/list.txt",
			"set security dynamic-address address-name bad profile feed-name threat",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient load must not brick, got: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "feed-server endpoint") && strings.Contains(w, "private") {
				found = true
			}
		}
		if !found {
			t.Fatalf("lenient load should warn about the blocked destination, warnings: %v", cfg.Warnings)
		}
	})

	t.Run("allow-destination override compiles and is stored", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server threat url https://10.1.2.3/list.txt",
			"set security dynamic-address feed-server threat allow-destination 10.0.0.0/8",
			"set security dynamic-address address-name bad profile feed-name threat",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("allow-destination covering the literal must compile, got: %v", err)
		}
		fs := cfg.Security.DynamicAddress.FeedServers["threat"]
		if fs == nil || len(fs.AllowedDestinationPrefixes) != 1 || fs.AllowedDestinationPrefixes[0] != "10.0.0.0/8" {
			t.Fatalf("override leaf not compiled into FeedServer: %+v", fs)
		}
	})

	t.Run("non-covering allow-destination still rejects", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server threat url https://10.1.2.3/list.txt",
			"set security dynamic-address feed-server threat allow-destination 192.168.0.0/16",
			"set security dynamic-address address-name bad profile feed-name threat",
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("a non-covering allow-destination must not admit the literal")
		}
	})

	// Controls unchanged: public hostname, public literal, https.
	for _, tc := range []struct{ name, line string }{
		{"public hostname", "set security dynamic-address feed-server threat url https://feeds.example/list.txt"},
		{"public literal", "set security dynamic-address feed-server threat url https://8.8.8.8/list.txt"},
		{"public hostname leaf", "set security dynamic-address feed-server threat hostname feeds.example"},
	} {
		t.Run("commit accepts/"+tc.name, func(t *testing.T) {
			tree := buildTree5183(t, []string{
				tc.line,
				"set security dynamic-address address-name bad profile feed-name threat",
			})
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("control %s must compile, got: %v", tc.name, err)
			}
		})
	}
}
