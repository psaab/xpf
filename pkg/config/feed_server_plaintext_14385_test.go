package config

import (
	"strings"
	"testing"
)

// TestFeedServerPlaintextHTTPRejected14385 is the #14385 (DR5-H13)
// fail-on-revert pin for the strict half: a plaintext-http dynamic-address
// feed body would be installed as enforced policy with no integrity check,
// so strict commit must reject `url http://...`. Reverting the plaintext
// check in validateDynamicAddressFeedServerEndpointStrict turns the strict
// sub-tests RED (the http:// config compiles clean).
func TestFeedServerPlaintextHTTPRejected14385(t *testing.T) {
	t.Run("commit rejects http url", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server FEED1 url http://feeds.example.invalid/list.txt",
			"set security dynamic-address feed-server FEED1 feed-name THREAT",
			"set security dynamic-address address-name blocked profile feed-name THREAT",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig should reject a plaintext http:// feed-server url")
		}
		if !strings.Contains(err.Error(), "FEED1") {
			t.Fatalf("error should name the feed-server, got: %v", err)
		}
		if !strings.Contains(err.Error(), "plaintext http") {
			t.Fatalf("error should explain the plaintext-http refusal, got: %v", err)
		}
		// The echoed URL must be redacted: no credential may leak.
		if strings.Contains(err.Error(), "feeds.example.invalid/list.txt") && strings.Contains(err.Error(), "?") {
			t.Fatalf("error leaks URL detail: %v", err)
		}
	})

	t.Run("commit rejects uppercase HTTP url", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server FEED1 url HTTP://feeds.example.invalid/list.txt",
			"set security dynamic-address address-name blocked profile feed-name FEED1",
		})
		if _, err := CompileConfig(tree); err == nil {
			t.Fatalf("CompileConfig should reject an uppercase HTTP:// feed-server url")
		}
	})

	t.Run("commit rejects credentialed http url without leaking secret", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			`set security dynamic-address feed-server FEED1 url "http://user:feedsecret@feeds.example.invalid/list.txt"`,
			"set security dynamic-address address-name blocked profile feed-name FEED1",
		})
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig should reject a credentialed http:// feed-server url")
		}
		if strings.Contains(err.Error(), "feedsecret") {
			t.Fatalf("error leaks embedded credential: %v", err)
		}
	})

	// Tolerant load / peer-sync must NOT brick — it downgrades to a warning
	// so an already-persisted config still boots; the runtime skip in
	// feeds.Manager.Apply keeps the bound name fail-closed (#5645).
	t.Run("tolerant load downgrades to warning", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server FEED1 url http://feeds.example.invalid/list.txt",
			"set security dynamic-address address-name blocked profile feed-name FEED1",
		})
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient should NOT reject a plaintext feed url (warn, not brick): %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "plaintext http") && strings.Contains(w, "FEED1") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("tolerant load should surface a plaintext-http warning, got warnings: %v", cfg.Warnings)
		}
	})

	// Controls: https and hostname-only (resolves to https://) still compile.
	t.Run("commit accepts https url", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server FEED1 url https://feeds.example.invalid/list.txt",
			"set security dynamic-address address-name blocked profile feed-name FEED1",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("valid https feed-server url must compile, got: %v", err)
		}
	})

	t.Run("commit accepts hostname-only server", func(t *testing.T) {
		tree := buildTree5183(t, []string{
			"set security dynamic-address feed-server FEED1 hostname feeds.example.invalid",
			"set security dynamic-address address-name blocked profile feed-name FEED1",
		})
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("hostname-only feed-server (https://) must compile, got: %v", err)
		}
	})
}
