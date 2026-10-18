package config

import (
	"strings"
	"testing"
)

// TestFeedServerMalformedFeedPathRejected14723 is the commit-path half
// of #14723: whether strict validation today rejects a malformed
// per-feed `path` (the %ZZ repro) bounds the reachability of the
// joinFeedURL wrong-endpoint fetch. On master the strict gate validates
// only the base url and never the per-feed path, so a path such as
// /denylist%ZZ.txt commits clean and the runtime silently fetches the
// base. Strict commit must reject it; the tolerant path warns.
func TestFeedServerMalformedFeedPathRejected14723(t *testing.T) {
	bad := map[string]string{
		"percent escape":   "/denylist%ZZ.txt",
		"network path":     "//denylist.txt",
		"colon opaque":     "v1:prod/list.txt",
		"absolute url":     "https://evil.example/m.txt",
		"network path url": "//evil.example/m.txt",
	}
	for label, p := range bad {
		t.Run("commit rejects "+label, func(t *testing.T) {
			tree := buildTree5183(t, []string{
				"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
				`set security dynamic-address feed-server threat feed-name threat path "` + p + `"`,
				"set security dynamic-address address-name bad profile feed-name threat",
			})
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig should reject malformed feed path %q", p)
			}
			if !strings.Contains(err.Error(), "threat") {
				t.Fatalf("error should name the feed/server, got: %v", err)
			}
		})
	}

	t.Run("tolerant load downgrades to warning", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
			`set security dynamic-address feed-server threat feed-name threat path "/denylist%ZZ.txt"`,
			"set security dynamic-address address-name bad profile feed-name threat",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient should NOT reject a malformed feed path (warn, not brick): %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "threat") {
				found = true
			}
		}
		if !found {
			t.Fatalf("tolerant load should surface a malformed-feed-path warning, got: %v", cfg.Warnings)
		}
	})

	// Controls: correct escapes / ordinary paths still compile clean.
	for _, p := range []string{"/list.txt", "/a%2Fb.txt", "lists/v1:prod/list.txt", "/list.txt?token=abc"} {
		t.Run("commit accepts "+p, func(t *testing.T) {
			tree := buildTree5183(t, []string{
				"set security dynamic-address feed-server threat url https://feeds.example/list.txt",
				`set security dynamic-address feed-server threat feed-name threat path "` + p + `"`,
				"set security dynamic-address address-name bad profile feed-name threat",
			})
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("valid feed path %q must compile, got: %v", p, err)
			}
		})
	}
}
