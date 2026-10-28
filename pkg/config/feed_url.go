// Copyright 2026 PSAAB. All rights reserved.
// Use of this source code is governed by the Apache 2.0 license.

package config

import (
	"fmt"
	"net/url"
	"strings"
)

// FeedServerBaseURL returns the base URL for a feed server: explicit
// `url` wins, else `https://<hostname>`, else "".
//
// Trailing "/" is trimmed from the URL *path* only (#14723): trimming
// the raw string cut a query or fragment token that itself ends in "/"
// (https://h/base/?token=abc/ lost the token's slash; a query-free
// https://h/base#frag/ lost the fragment's). An unparseable or
// scheme-less value keeps the historical raw slash-trim so slash-only
// URLs still resolve to "".
//
// This is the single shared implementation (#17180): the strict
// compiler gate (pkg/config) and the runtime (pkg/feeds, which already
// imports pkg/config) both call it, so the commit gate and
// Manager.Apply cannot drift on which endpoint a server resolves to.
func FeedServerBaseURL(fs *FeedServer) string {
	if fs == nil {
		return ""
	}
	raw := fs.URL
	if raw == "" && fs.Hostname != "" {
		raw = "https://" + fs.Hostname
	}
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return strings.TrimRight(raw, "/")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.RawPath = ""
	} else if u.RawPath != "" {
		u.RawPath = strings.TrimRight(u.RawPath, "/")
	}
	return u.String()
}

// FeedEntryPathError reports why a per-feed path cannot back a feed, or
// "" if it is a plain relative path tail (#14723). A non-empty path
// must parse and carry no scheme, no opaque part and no authority; an
// empty path is the base itself and is not malformed.
//
// The runtime (pkg/feeds join) rejects exactly the paths this reports,
// so a path rejected at commit is the same path for which
// Manager.Apply registers no feed.
func FeedEntryPathError(rawPath string) string {
	if rawPath == "" {
		return ""
	}
	ref, err := url.Parse(rawPath)
	if err != nil {
		return fmt.Sprintf("not a parseable URL path: %v", err)
	}
	if ref.Scheme != "" || ref.Opaque != "" || ref.Host != "" || ref.User != nil {
		return "not a plain relative path (scheme, opaque, or authority present)"
	}
	return ""
}

// IsPlaintextFeedURL reports whether url is a plaintext-http feed URL.
// Such a feed has no transport integrity and there is no per-feed
// signature / pinned-hash verification, so a substituted body would
// install as enforced policy (#14385). Manager.Apply refuses to
// register plaintext-http feeds and the strict compiler gate rejects
// them at commit; both call this one predicate (#17180).
func IsPlaintextFeedURL(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "http://")
}
