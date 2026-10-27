// Copyright 2026 PSAAB. All rights reserved.
// Use of this source code is governed by the Apache 2.0 license.

package feeds

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// buildTree17180 compiles a set-command list into a ConfigTree for the
// #17180 parity test, mirroring the other feeds/config fixtures
// (ParseSetCommand + SetPath, never NewParser).
func buildTree17180(t *testing.T, setCommands []string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range setCommands {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

// TestFeedURLGateRuntimeParity17180 is the #17180 parity cell: for each
// case, Manager.Apply registers no feed exactly when the strict
// CompileConfig gate rejects the same feed-server. Before the fix the
// gate and the runtime each carried a hand-copied resolution
// (feedServerResolvedBaseURL / feedServerBaseURLEmpty /
// feedEntryPathMalformed in pkg/config vs resolveBaseURL / joinFeedURL
// / isPlaintextFeedURL in pkg/feeds) with no test binding them, so a
// drift would let commit accept a config whose feed the runtime
// silently skips (the #3300 match-none class), or vice versa.
//
// The cases exercise the five shapes named in #17180 — slash-only,
// query/fragment-slash, scheme-less, %zz and IPv6-literal — in both
// directions: each row is built twice, once as a ConfigTree through
// CompileConfig (strict) and once as a DynamicAddressConfig through
// Manager.Apply, and the reject/register verdicts must agree where the
// issue's "registers no feed exactly when strict rejects" predicate is
// defined. Two shapes sit outside that predicate by design and are
// pinned as documented divergences below (wantDivergent): a scheme-less
// or unparseable (%zz) base is commit-rejected by the #5183
// unconstructible-request gate, but the lenient runtime still
// registers it (every fetch then fails and the bound name fails
// CLOSED, #5645 — Apply is the tolerant path, not the commit gate).
// The blocked-destination gate (#16656) is likewise commit-only for
// IP literals, so the IPv6 rows use a public literal
// (2001:4860:4860::8888) that FeedDestinationBlocked does not refuse;
// for those rows registration is the parity surface, not fetchability.
// URL values containing '?' or a '//' path tail are quoted in the set
// commands: the unquoted lexer splits on '?' and treats '//' as a
// comment, which would compile a different config than the fsCfg row.
func TestFeedURLGateRuntimeParity17180(t *testing.T) {
	cases := []struct {
		name          string
		setCmds       []string
		fsCfg         *config.FeedServer
		feeds         []string
		wantURL       string // exact joined URL Apply must register on accept ("" = skip check)
		wantDivergent bool
	}{
		{
			name: "slash-only url",
			setCmds: []string{
				"set security dynamic-address feed-server threat url /",
				"set security dynamic-address feed-server threat hostname feeds.example.com",
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "/", Hostname: "feeds.example.com",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/malware.txt"}},
			},
			feeds: []string{"malware"},
		},
		{
			name: "query slash token preserved",
			setCmds: []string{
				`set security dynamic-address feed-server threat url "https://feeds.example.com/base/?token=abc/"`,
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "https://feeds.example.com/base/?token=abc/",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/malware.txt"}},
			},
			feeds:   []string{"malware"},
			wantURL: "https://feeds.example.com/base/malware.txt?token=abc/",
		},
		{
			name: "fragment slash preserved",
			setCmds: []string{
				`set security dynamic-address feed-server threat url "https://feeds.example.com/base#frag/"`,
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "https://feeds.example.com/base#frag/",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/malware.txt"}},
			},
			feeds:   []string{"malware"},
			wantURL: "https://feeds.example.com/base/malware.txt#frag/",
		},
		{
			name: "scheme-less url",
			setCmds: []string{
				"set security dynamic-address feed-server threat url feeds.example.com/list.txt",
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "feeds.example.com/list.txt",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/malware.txt"}},
			},
			feeds:         []string{"malware"},
			wantDivergent: true,
		},
		{
			name: "percent-zz base url",
			setCmds: []string{
				"set security dynamic-address feed-server threat url https://feeds.example.com/%zz",
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "https://feeds.example.com/%zz",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/malware.txt"}},
			},
			feeds:         []string{"malware"},
			wantDivergent: true,
		},
		{
			name: "percent-zz feed path",
			setCmds: []string{
				"set security dynamic-address feed-server threat url https://feeds.example.com/base",
				"set security dynamic-address feed-server threat feed-name malware path /list%zz.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "https://feeds.example.com/base",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/list%zz.txt"}},
			},
			feeds: []string{"malware"},
		},
		{
			name: "network-path feed path",
			setCmds: []string{
				"set security dynamic-address feed-server threat url https://feeds.example.com/base",
				`set security dynamic-address feed-server threat feed-name malware path "//evil.example/list.txt"`,
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "https://feeds.example.com/base",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "//evil.example/list.txt"}},
			},
			feeds: []string{"malware"},
		},
		{
			name: "scheme-opaque feed path",
			setCmds: []string{
				"set security dynamic-address feed-server threat url https://feeds.example.com/base",
				"set security dynamic-address feed-server threat feed-name malware path v1:prod/list.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "https://feeds.example.com/base",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "v1:prod/list.txt"}},
			},
			feeds: []string{"malware"},
		},
		{
			name: "ipv6 literal host",
			setCmds: []string{
				"set security dynamic-address feed-server threat url https://[2001:4860:4860::8888]/base",
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "https://[2001:4860:4860::8888]/base",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/malware.txt"}},
			},
			feeds:   []string{"malware"},
			wantURL: "https://[2001:4860:4860::8888]/base/malware.txt",
		},
		{
			name: "ipv6 literal hostname leaf",
			setCmds: []string{
				"set security dynamic-address feed-server threat hostname [2001:4860:4860::8888]",
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", Hostname: "[2001:4860:4860::8888]",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/malware.txt"}},
			},
			feeds:   []string{"malware"},
			wantURL: "https://[2001:4860:4860::8888]/malware.txt",
		},
		{
			name: "plaintext http url",
			setCmds: []string{
				"set security dynamic-address feed-server threat url http://feeds.example.com/list.txt",
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "http://feeds.example.com/list.txt",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/malware.txt"}},
			},
			feeds: []string{"malware"},
		},
		{
			name: "valid https url",
			setCmds: []string{
				"set security dynamic-address feed-server threat url https://feeds.example.com/list.txt",
				"set security dynamic-address feed-server threat feed-name malware path /malware.txt",
				"set security dynamic-address address-name bad profile feed-name malware",
			},
			fsCfg: &config.FeedServer{
				Name: "threat", URL: "https://feeds.example.com/list.txt",
				FeedEntries: []config.FeedEntry{{Name: "malware", Path: "/malware.txt"}},
			},
			feeds:   []string{"malware"},
			wantURL: "https://feeds.example.com/list.txt/malware.txt",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, gateErr := config.CompileConfig(buildTree17180(t, tc.setCmds))
			gateRejects := gateErr != nil

			m := New(nil)
			fsCfg := *tc.fsCfg
			fsCfg.UpdateInterval = 3600
			m.Apply(context.Background(), &config.DynamicAddressConfig{
				FeedServers: map[string]*config.FeedServer{tc.fsCfg.Name: &fsCfg},
			})
			defer m.StopAll()
			registered := m.AllFeeds()
			runtimeRegistersNone := len(registered) == 0

			if tc.wantDivergent {
				if !gateRejects || runtimeRegistersNone {
					t.Fatalf("documented divergence changed (#17180/#5183): gate rejects=%v (err=%v), Apply registered %v; want gate-reject + runtime-register", gateRejects, gateErr, registered)
				}
				return
			}
			// On accept, pin the exact URL Apply registered the feed
			// with: this binds the #14723 query/fragment-slash path-only
			// trim and the path join to literal expectations, so a
			// regression in FeedServerBaseURL (e.g. trimming the raw
			// string and cutting a "?token=abc/" or "#frag/" token)
			// turns RED here even though gate and runtime share the
			// helper and would still agree on registration.
			if !gateRejects && tc.wantURL != "" {
				for _, feed := range tc.feeds {
					info, ok := registered[feed]
					if !ok {
						t.Fatalf("gate accepted but Apply did not register feed %q (registered %v)", feed, registered)
					}
					if info.URL != tc.wantURL {
						t.Fatalf("registered feed %q url = %q, want %q", feed, info.URL, tc.wantURL)
					}
				}
			}
			if gateRejects != runtimeRegistersNone {
				t.Fatalf("parity drift (#17180): strict gate rejects=%v (err=%v) but Apply registered %v; gate and runtime must agree", gateRejects, gateErr, registered)
			}
			if !gateRejects {
				for _, feed := range tc.feeds {
					if _, ok := registered[feed]; !ok {
						t.Fatalf("gate accepted but Apply did not register feed %q (registered %v)", feed, registered)
					}
				}
			}
		})
	}
}
