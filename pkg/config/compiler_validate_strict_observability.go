package config

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// validateLogEventModeFormatStrict rejects a top-level `security log format`
// that the EVENT-mode writer cannot honor (#3349 follow-up). The top-level
// format leaf is schema-validated to one of {binary, sd-syslog, structured,
// syslog} regardless of mode, and BOTH runtimes now honor every one of those
// values (#3409 closed the event-mode gap):
//
//   - stream mode (remote syslog): honors binary (formatBinaryRecord),
//     structured (formatStructuredMsg), sd-syslog (RFC 5424 envelope in
//     SyslogClient.Send), and the standard RFC 3164 default.
//   - event mode (local file, pkg/logging LocalLogWriter via
//     ringbuf.go ProcessRawEvent local-writer fanout): honors binary
//     (formatBinaryRecord), structured (Junos RT_FLOW body), sd-syslog
//     (RFC 5424 envelope in LocalLogWriter.Send), and the standard default.
//
// Before #3409 the event-mode fanout branched ONLY on `binary` and wrote
// standard text for every other value, so `structured` and `sd-syslog`
// SILENTLY fell back to standard text — the exact silent-config-fallback #3349
// exists to eliminate. That gap is closed: each format now produces distinct
// output, so every schema value is accepted in event mode too.
//
// This stays as a CROSS-FIELD validator (format validity in principle depends
// on the sibling mode, which the declarative per-leaf SchemaValidate walker
// cannot express) so the contract is documented in one place and a future
// event-only format remains easy to gate. Today it accepts the full schema
// enum for either mode.
//
// On the tolerant load / peer-sync paths the call site still downgrades any
// rejection to a warning (opts.lenientLogEventModeFormat); with the full enum
// accepted this path is now inert for the four known formats and only fires if
// a future value is added to the schema but not yet honored here.
//
// The event-honorable set MUST stay in sync with the LocalLogWriter fanout in
// pkg/logging/ringbuf.go: a value allowed here but unhonored there would
// reintroduce the silent fallback.
func validateLogEventModeFormatStrict(cfg *Config) error {
	if cfg == nil || cfg.Security.Log.Mode != "event" {
		return nil
	}
	switch cfg.Security.Log.Format {
	case "", "binary", "syslog", "structured", "sd-syslog":
		// All four schema formats are honored by the event-mode LocalLogWriter
		// fanout (#3409): "" / "syslog" => standard RFC 3164 text; "binary" =>
		// binary records; "structured" => Junos RT_FLOW body; "sd-syslog" =>
		// RFC 5424 envelope. Nothing silently falls back.
		return nil
	default:
		// Defensive: the schema leaf already constrains the value to the set
		// above. An unknown value reaching here would be emitted as standard
		// text by the writer, so reject it rather than silently no-op — the
		// #3349 contract.
		return fmt.Errorf("security log format %q is not honored in event mode "+
			"(the local-file writer emits binary, structured, sd-syslog, or "+
			"standard text); use one of those formats", cfg.Security.Log.Format)
	}
}

// validateLogProfileStreamReferencesStrict hard-rejects a
// `security log profile <name>` whose `stream-name` reference does not
// resolve to a configured `security log stream` (#2008 H7). xpf routes
// log events per stream (a Junos superset — every matching stream
// receives the event), so a profile's `stream-name` designates the
// stream that carries its events. A profile naming a stream that is not
// configured routes to nowhere: the operator authored a log profile
// whose target silently never fires. Before H7 the whole profile stanza
// was dropped before compile, so the typo was invisible; now the
// reference is validated.
//
// A profile with no `stream-name` is accepted: Junos permits a profile
// that relies on the global routing inheritance, and there is nothing to
// dangle. Only a non-empty `stream-name` that misses the stream map is
// rejected.
//
// Note: compileLog only records a stream in Log.Streams when it has a
// host (a host-less stream is not a real destination and is dropped by
// the stream loop), so a profile referencing a host-less stream is
// treated as a dangling reference — consistent with the stream's own
// "must have a host to exist" semantics.
//
// On the tolerant load / peer-sync paths the call site downgrades this
// to a warning (opts.lenientLogProfileStreamRef) so an already-persisted
// config (older binaries dropped the stanza entirely) or a peer-synced
// config still boots. Mirrors validateIPsecPolicyProposalReferencesStrict.
func validateLogProfileStreamReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	profiles := cfg.Security.Log.Profiles
	if len(profiles) == 0 {
		return nil
	}
	streams := cfg.Security.Log.Streams
	// Profiles is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := profiles[name]
		if p == nil || p.StreamName == "" {
			continue
		}
		if _, ok := streams[p.StreamName]; ok {
			continue
		}
		return fmt.Errorf("security log profile %q references undefined "+
			"log stream %q (the profile would route to nowhere — define "+
			"the stream or fix the stream-name)", p.Name, p.StreamName)
	}
	return nil
}

// validateDynamicAddressFeedServerEndpointStrict hard-rejects a
// `security dynamic-address feed-server <name>` whose resolved base url either
// configures no endpoint — neither `url` nor `hostname` (#3300 residual) — or
// is non-empty but MALFORMED so it cannot back an HTTP fetch (#5183).
// feeds.Manager.Apply derives
// each server's base URL via resolveBaseURL (feeds.go): explicit `url`, else
// `https://<hostname>`, else the empty string — and an empty base URL makes
// Apply SKIP the whole server (it registers NONE of its feeds, including any
// nested feed-name entries). The endpoint-less server still compiles into
// SecurityConfig.DynamicAddress.FeedServers, so its feed names are
// syntactically "declared", but at runtime no feed exists: the address-name
// bound to one is UNRESOLVABLE and fails CLOSED (#5645: omitted -> the policy
// lowering treats it as unrepresentable -> __unsupported_address__ -> the
// userspace snapshot preflight rejects the whole publication -> previous-good /
// fresh-boot default-deny). Historically this was the #3300 fail-open symptom
// one layer up (silent match-none for a deny); #5645 makes the runtime fail
// closed, and this gate still turns the silent default-deny into an
// operator-visible commit error at the feed-server root rather than the binding.
//
// This gate replicates resolveBaseURL's emptiness condition directly on the
// FeedServer config struct (feedServerBaseURLEmpty) rather than importing
// pkg/feeds (pkg/config must not depend on pkg/feeds). resolveBaseURL prefers
// `url` and returns strings.TrimRight(url, "/") BEFORE it ever falls back to
// `hostname`, so a slash-only `url` (e.g. `/`, `//`) trims to "" and the
// server is skipped even when a hostname is also set — feedServerBaseURLEmpty
// mirrors that branch order exactly. Keep in sync with resolveBaseURL.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientDynamicAddressFeedRef, shared with the feed-name
// cross-reference gate) so an already-persisted or peer-synced config carrying
// an endpoint-less server still boots — the runtime already drops the server
// (registers no feed), so any bound address-name is unresolvable and fails
// CLOSED (#5645: omitted -> __unsupported_address__ -> whole-snapshot preflight
// reject -> previous-good/default-deny) rather than bricking the load (#1960 /
// #3261 class). Commit / commit-check stay strict. Mirrors
// validateLogProfileStreamReferencesStrict.
func validateDynamicAddressFeedServerEndpointStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	servers := cfg.Security.DynamicAddress.FeedServers
	if len(servers) == 0 {
		return nil
	}
	// FeedServers is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fs := servers[name]
		if fs == nil {
			continue
		}
		if feedServerBaseURLEmpty(fs) {
			display := fs.Name
			if display == "" {
				display = name
			}
			return fmt.Errorf("security dynamic-address feed-server %q resolves "+
				"to an empty endpoint (no url or hostname, or a slash-only url) "+
				"so it registers no feeds — any address-name bound to it is "+
				"unresolvable and fails CLOSED at runtime (omitted -> "+
				"__unsupported_address__ -> whole-snapshot preflight reject -> "+
				"previous-good/default-deny, #5645), not silently match-none; "+
				"set a valid url or hostname",
				display)
		}
		// #5183: a NON-empty but MALFORMED base url (e.g. `http://%`, a
		// scheme-less `example.com/list`, or `https://` with no host) clears
		// the emptiness gate above but is not constructible as the HTTP request
		// the runtime issues — feeds.Manager.readFeed does
		// http.NewRequestWithContext(ctx, "GET", fs.url, nil), which errors
		// BEFORE any I/O, so the feed registers no content and any deny policy
		// bound to that address-name is unresolvable and fails CLOSED (#5645:
		// omitted -> __unsupported_address__ -> whole-snapshot preflight reject
		// -> previous-good/default-deny) — historically the #3300 fail-open
		// symptom one layer up from the emptiness case, now caught. Validate the
		// resolved base url with the SAME request-construction semantics the
		// runtime uses so a garbage endpoint is operator-visible at commit
		// instead of silently non-functional. Tolerant load / peer-sync
		// downgrades to a warning via the shared lenient wrapper at the call
		// site (the runtime is already fail-closed for the dead feed — #5645:
		// the bound name is omitted -> __unsupported_address__ -> whole-snapshot
		// preflight reject -> previous-good/default-deny — so a leniently-loaded
		// config still boots, #1960 / #3261).
		if reason := feedServerBaseURLUnconstructible(feedServerResolvedBaseURL(fs)); reason != "" {
			display := fs.Name
			if display == "" {
				display = name
			}
			// Redact the echoed URL: a malformed-but-credentialed base url
			// (e.g. "https://user:token@" with no host) would otherwise leak
			// the embedded userinfo / query token into this operator-visible
			// commit error and any log capturing it (#5521; matches the DDNS
			// validation warnings that already RedactURL their server/template).
			return fmt.Errorf("security dynamic-address feed-server %q base url "+
				"%q is malformed (%s) — http.NewRequestWithContext fails before "+
				"any fetch, so it registers no feeds and any address-name bound "+
				"to it is unresolvable and fails CLOSED at runtime (omitted -> "+
				"__unsupported_address__ -> whole-snapshot preflight reject, "+
				"#5645), not silently match-none; set a valid http(s) url or hostname",
				display, RedactURL(feedServerResolvedBaseURL(fs)), reason)
		}
	}
	return nil
}

// feedServerResolvedBaseURL returns the base url feeds.resolveBaseURL
// (pkg/feeds/feeds.go) would produce for this server: explicit `url` (trimmed
// of trailing slashes) wins, else `https://<hostname>`, else "". Mirrors
// resolveBaseURL branch-for-branch; keep in sync (pkg/config cannot import
// pkg/feeds — import cycle). Callers here reach it only after
// feedServerBaseURLEmpty has ruled out the "" result.
func feedServerResolvedBaseURL(fs *FeedServer) string {
	if fs.URL != "" {
		return strings.TrimRight(fs.URL, "/")
	}
	if fs.Hostname != "" {
		return "https://" + strings.TrimRight(fs.Hostname, "/")
	}
	return ""
}

// feedServerBaseURLUnconstructible reports why a non-empty resolved feed base
// url could NOT back the HTTP request the runtime issues, or "" if it is well
// formed. The contract is the runtime's own: feeds.Manager.readFeed calls
// http.NewRequestWithContext(ctx, "GET", url, nil), which fails (before any
// network I/O) for an unparseable url or one url.Parse cannot fully handle.
// url.Parse alone accepts a scheme-less or host-less string, so this ALSO
// requires an http/https scheme and a non-empty host — the two properties a
// feed fetch needs to reach a server at all. Returning a reason string (rather
// than an error) keeps the caller's message assembly in one place.
func feedServerBaseURLUnconstructible(resolved string) string {
	if resolved == "" {
		// Empty is the emptiness gate's job, not this one.
		return ""
	}
	u, err := url.Parse(resolved)
	if err != nil {
		return fmt.Sprintf("not a parseable URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		if u.Scheme == "" {
			return "missing http/https scheme"
		}
		return fmt.Sprintf("scheme %q is not http or https", u.Scheme)
	}
	if u.Host == "" {
		return "missing host"
	}
	if _, err := http.NewRequestWithContext(context.Background(), http.MethodGet, resolved, nil); err != nil {
		return fmt.Sprintf("http.NewRequestWithContext rejects it: %v", err)
	}
	return ""
}

// feedServerBaseURLEmpty reports whether feeds.resolveBaseURL would return ""
// for this feed-server — i.e. feeds.Manager.Apply would SKIP it and register
// none of its feeds. It mirrors resolveBaseURL (pkg/feeds/feeds.go)
// BRANCH-FOR-BRANCH:
//
//	if URL != "":            empty iff strings.TrimRight(URL, "/") == ""
//	else if Hostname != "":  never empty ("https://" + ... is always non-empty)
//	else:                    empty
//
// The URL branch wins outright, so a slash-only `url` (e.g. `/`, `//`) trims to
// "" and the server is skipped EVEN IF a hostname is also configured — the
// fallback is never reached. resolveBaseURL performs no whitespace trimming
// (only strings.TrimRight on "/"), so this does not either. pkg/config cannot
// import pkg/feeds (import cycle); keep this in sync with resolveBaseURL.
func feedServerBaseURLEmpty(fs *FeedServer) bool {
	if fs.URL != "" {
		return strings.TrimRight(fs.URL, "/") == ""
	}
	if fs.Hostname != "" {
		return false
	}
	return true
}

// validateDynamicAddressFeedNameUniquenessStrict hard-rejects two
// dynamic-address feeds that resolve to the SAME effective feed name (#4913).
//
// feeds.Manager keys its worker map AND its enforcement snapshot by the
// effective feed name (pkg/feeds/feeds.go Apply): a feed-server with per-feed
// entries contributes each FeedEntry.Name; a single-feed server contributes its
// FeedName, falling back to the server name. Two feeds sharing a name are a
// config authoring error (a typo): the pre-#4913 Apply ranged the UNORDERED
// FeedServers map and assigned m.feeds[name] = fs per entry, so the duplicate
// OVERWROTE the earlier worker — orphaning its cancel func (a goroutine leak:
// StopAll cancels only the survivor, so the overwritten refresh loop kept
// fetching / firing onUpdate until the daemon's parent context ended) — and
// enforcement read whichever provider won the last map iteration
// (nondeterministic across commits / restarts). Reject the collision at commit
// so the operator fixes the typo instead of shipping a denylist backed by a
// nondeterministic provider.
//
// The effective-name derivation mirrors feeds.Manager EXACTLY (and the
// declared-name set built by validateDynamicAddressFeedReferencesStrict). An
// endpoint-less feed-server (rejected just before by
// validateDynamicAddressFeedServerEndpointStrict) is SKIPPED by Apply and
// registers no worker, so it is excluded here too (feedServerBaseURLEmpty) —
// otherwise a benign endpoint-less shadow name would be miscounted as a live
// collision. This gate runs AFTER the endpoint gate so, on the strict path, the
// surviving servers are exactly the ones Apply would register.
//
// Strict path (commit / commit-check): the first collision is a hard error
// naming the feed and both declaring servers. Lenient path (load / peer-sync,
// opts.lenientDynamicAddressFeedRef): warn so an already-persisted or
// peer-synced config an older binary accepted still boots — the runtime is now
// deterministic-with-a-warning via the feeds.Apply de-dup (#4913), starting one
// worker for the lexicographically-first server instead of leaking, now
// flagged. Mirrors validateDynamicAddressFeedReferencesStrict.
func validateDynamicAddressFeedNameUniquenessStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	servers := cfg.Security.DynamicAddress.FeedServers
	if len(servers) == 0 {
		return nil
	}
	// FeedServers is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs, and so the "first"
	// declaring server recorded per name matches feeds.Apply's sorted winner.
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	owner := make(map[string]string) // effective feed name -> first declaring server display name
	for _, name := range names {
		fs := servers[name]
		if fs == nil || feedServerBaseURLEmpty(fs) {
			continue
		}
		display := fs.Name
		if display == "" {
			display = name
		}
		add := func(feedName string) error {
			if feedName == "" {
				return nil
			}
			if prev, ok := owner[feedName]; ok {
				return fmt.Errorf("security dynamic-address feed name %q is "+
					"declared by more than one feed-server (%q and %q) — a feed "+
					"name is a unique identity: the duplicate would start an "+
					"orphaned refresh loop and back enforcement with a "+
					"nondeterministic provider; rename one feed", feedName, prev, display)
			}
			owner[feedName] = display
			return nil
		}
		if len(fs.FeedEntries) > 0 {
			for _, fe := range fs.FeedEntries {
				if err := add(fe.Name); err != nil {
					return err
				}
			}
			continue
		}
		key := fs.FeedName
		if key == "" {
			key = fs.Name
		}
		if err := add(key); err != nil {
			return err
		}
	}
	return nil
}

// validateDynamicAddressFeedReferencesStrict hard-rejects a
// `security dynamic-address address-name <addr> profile feed-name <feed>`
// binding whose `<feed>` resolves to no declared feed (#3300). The
// address-name→feed binding is recorded verbatim into
// AddressBinding.FeedNames with no cross-reference against the configured
// feed-servers (compileDynamicAddress in compiler_services.go), and at
// runtime an unknown feed name contributes nothing: feeds.Manager.
// SnapshotForBindings OMITS a binding whose feeds have no installed snapshot
// (an unregistered/unfetched feed name) rather than publishing an empty
// prefix set (#5645), so the binding name stays UNRESOLVED and the policy
// lowering compiles it to __unsupported_address__ → whole-snapshot preflight
// reject → fail-closed (previous-good retained, or fresh-boot default-deny).
// The runtime fail-closed posture is correct for "feed declared but not yet
// fetched", but a TYPO in the feed-name is indistinguishable from that at
// runtime — it too fails closed (the referencing deny is enforced via
// default-deny, not silently ignored), with no commit error. Junos rejects
// an address-name whose profile
// feed-name does not resolve to a declared feed at commit; this gate
// restores that behavior.
//
// The valid feed-name set mirrors the keys feeds.Manager registers (feeds.go
// Start): a feed-server with per-feed entries contributes each FeedEntry.Name;
// a single-feed server contributes its FeedName, or the server name itself
// when no explicit feed-name is set. This parity is EXACT because
// validateDynamicAddressFeedServerEndpointStrict (run just before this gate)
// rejects any feed-server with no url/hostname — the only servers
// feeds.Manager.Apply silently SKIPS — so every server in the declared set is
// one Apply would actually register. The schema accepts `profile feed-name` as
// a free-form value leaf (schema_security.go), so the undefined-token gate
// (#2008/#2009) does NOT cover a typo here — only this cross-reference does.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientDynamicAddressFeedRef) so an already-persisted config
// (older binaries never validated the reference) or a peer-synced config
// still boots — the runtime is already fail-closed for an unknown feed
// (#5645: the name is omitted → whole-snapshot reject → previous-good /
// fresh-boot default-deny), so a leniently-loaded typo fails closed rather
// than bricking the load (#1960 / #3261 class). Commit / commit-check stay strict
// so the operator's next edit fails loudly. Mirrors
// validateLogProfileStreamReferencesStrict.
func validateDynamicAddressFeedReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	da := cfg.Security.DynamicAddress
	if len(da.AddressBindings) == 0 {
		return nil
	}

	// Build the set of declared feed names exactly as feeds.Manager keys
	// them (pkg/feeds Start): FeedEntries name each feed; a single-feed
	// server keys on FeedName, falling back to the server name.
	declared := make(map[string]bool)
	for _, fs := range da.FeedServers {
		if fs == nil {
			continue
		}
		if len(fs.FeedEntries) > 0 {
			for _, fe := range fs.FeedEntries {
				declared[fe.Name] = true
			}
			continue
		}
		key := fs.FeedName
		if key == "" {
			key = fs.Name
		}
		if key != "" {
			declared[key] = true
		}
	}

	// AddressBindings is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(da.AddressBindings))
	for name := range da.AddressBindings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ab := da.AddressBindings[name]
		if ab == nil {
			continue
		}
		for _, fn := range ab.FeedNames {
			if fn == "" || declared[fn] {
				continue
			}
			return fmt.Errorf("security dynamic-address address-name %q "+
				"profile references undefined feed-name %q (the binding is "+
				"unresolvable, so at runtime it is OMITTED and lowers to the "+
				"__unsupported_address__ sentinel; the userspace snapshot "+
				"preflight then REJECTS the whole publication and the dataplane "+
				"retains previous-good or fresh-boot default-deny — the "+
				"feed-backed policy fails CLOSED, it does NOT silently match "+
				"nothing (#5645); declare the feed under a dynamic-address "+
				"feed-server or fix the feed-name)", ab.Name, fn)
		}
	}
	return nil
}

// validateFlowServerTemplateReferencesStrict hard-rejects a per-flow-server
// NetFlow v9 / IPFIX template reference (`version9 { template <name> }`,
// `version9-template <name>`, `version-ipfix { template <name> }`, or
// `version-ipfix-template <name>`) that names no template defined under the
// matching `services flow-monitoring` version stanza (#2461).
//
// Without this gate the live exporter (pkg/flowexport) ignored the per-server
// reference entirely and built one export config from the FIRST Go-map-
// iteration template, broadcasting it to every collector of that version. A
// collector that asked for a specific template silently received whichever
// template the map happened to yield first, and that choice flipped across
// process restarts (map order is not an operator contract). A reference to a
// template that does not exist at all is the clearest form of the same defect:
// the operator's intent (timeouts / export-extensions) is simply dropped.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientFlowServerTemplateRef) so an already-persisted or
// peer-synced config carrying the typo still boots (#1960 fail-closed-on-load
// class). The resolver (ResolveV9TemplateGroups / ResolveIPFIXTemplateGroups)
// drops a group whose referenced template is undefined, so a leniently-loaded
// bad config exports nothing for that collector rather than the wrong
// template. Commit / commit-check stay strict so the operator's next edit
// fails loudly. Mirrors validateLogProfileStreamReferencesStrict.
func validateFlowServerTemplateReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	fm := cfg.Services.FlowMonitoring
	if cfg.ForwardingOptions.Sampling == nil {
		return nil
	}

	v9Defined := map[string]bool{}
	ipfixDefined := map[string]bool{}
	if fm != nil {
		if fm.Version9 != nil {
			for name := range fm.Version9.Templates {
				v9Defined[name] = true
			}
		}
		if fm.VersionIPFIX != nil {
			for name := range fm.VersionIPFIX.Templates {
				ipfixDefined[name] = true
			}
		}
	}

	// Walk the sampling instances in a deterministic key order so the
	// first-error commit-check message is stable across runs (the instance
	// map is unordered).
	instNames := make([]string, 0, len(cfg.ForwardingOptions.Sampling.Instances))
	for name := range cfg.ForwardingOptions.Sampling.Instances {
		instNames = append(instNames, name)
	}
	sort.Strings(instNames)

	for _, instName := range instNames {
		inst := cfg.ForwardingOptions.Sampling.Instances[instName]
		if inst == nil {
			continue
		}
		for _, fam := range []*SamplingFamily{inst.FamilyInet, inst.FamilyInet6} {
			if fam == nil {
				continue
			}
			for _, fs := range fam.FlowServers {
				if fs == nil {
					continue
				}
				if fs.Version9Template != "" && !v9Defined[fs.Version9Template] {
					return fmt.Errorf("forwarding-options sampling instance %q "+
						"flow-server %s references undefined version9 template %q "+
						"(define it under services flow-monitoring version9, or fix "+
						"the template name — the collector would otherwise receive "+
						"an arbitrary template)", instName, fs.Address, fs.Version9Template)
				}
				if fs.VersionIPFIXTemplate != "" && !ipfixDefined[fs.VersionIPFIXTemplate] {
					return fmt.Errorf("forwarding-options sampling instance %q "+
						"flow-server %s references undefined version-ipfix template "+
						"%q (define it under services flow-monitoring version-ipfix, "+
						"or fix the template name — the collector would otherwise "+
						"receive an arbitrary template)", instName, fs.Address, fs.VersionIPFIXTemplate)
				}
			}
		}
	}
	return nil
}

// flowServerExportVersion mirrors flowexport.resolveFlowServerVersion: it
// returns the export protocol a single flow-server binds to, given the
// per-server selector and which global `services flow-monitoring` version
// stanzas are configured. It is duplicated here (not imported) because
// pkg/config must not depend on pkg/flowexport. Returns "" when the server
// resolves to no configured version. Keep in sync with
// pkg/flowexport.resolveFlowServerVersion.
func flowServerExportVersion(fs *FlowServer, hasV9, hasIPFIX bool) string {
	switch fs.Version {
	case FlowServerVersion9:
		if hasV9 {
			return FlowServerVersion9
		}
		return ""
	case FlowServerVersionIPFIX:
		if hasIPFIX {
			return FlowServerVersionIPFIX
		}
		return ""
	}
	switch {
	case hasIPFIX:
		return FlowServerVersionIPFIX
	case hasV9:
		return FlowServerVersion9
	default:
		return ""
	}
}

// validateSamplingInstanceConflictsStrict hard-rejects an unsupported
// multi-sampling-instance configuration (#2462).
//
// The defect: multiple `forwarding-options sampling instance` blocks were
// silently flattened into one global export policy — one rate (the first
// nonzero InputRate in Go map order), one merged collector set, one zone
// eligibility map. Flows from instance A could export to instance B's
// collectors and the effective rate depended on map-iteration order.
//
// The fix makes each instance a first-class export policy: its own rate, its
// own 1-in-N counter, its own collectors. A flow is attributed to an instance
// by ADDRESS FAMILY (the only per-flow selector available — the interface
// `family inet { sampling { input; } }` stanza is a plain boolean; there is
// NO per-interface sampling-instance selector in the config model, so two
// instances serving the SAME family for the SAME export version are genuinely
// ambiguous: the runtime cannot tell which instance a given IPv4 (or IPv6)
// flow belongs to). Rather than guess (the flatten-and-hope behavior this
// issue reports), that combination is rejected.
//
// Supported: a single instance (any rate / families / collectors — the common
// case, unchanged); multiple instances disambiguated by family (e.g. instance
// A serves inet, instance B serves inet6) and/or by export version (an inet
// instance bound to version9 vs an inet instance bound to version-ipfix —
// distinct datagram streams, the flow is duplicated to both intentionally,
// same as today's single-instance dual-version behavior).
//
// Rejected: two or more instances each configuring a flow-server that
// resolves to the SAME (export-version, address-family) pair.
//
// Strict on commit / commit-check (hard reject so the operator sees it);
// lenient on load / peer-sync (the call site downgrades to a warning via
// opts.lenientSamplingInstanceConflicts so an already-persisted or
// peer-synced config still boots — #1960; the resolver still emits both
// instances' independent ExportConfigs, so a leniently-loaded conflicting
// config duplicates eligible flows to both instances rather than bricking).
func validateSamplingInstanceConflictsStrict(cfg *Config) error {
	if cfg == nil || cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	insts := cfg.ForwardingOptions.Sampling.Instances
	if len(insts) < 2 {
		return nil // single instance is always unambiguous
	}
	fm := cfg.Services.FlowMonitoring
	hasV9 := fm != nil && fm.Version9 != nil
	hasIPFIX := fm != nil && fm.VersionIPFIX != nil

	// Deterministic instance order so the first-conflict message is stable.
	names := make([]string, 0, len(insts))
	for name := range insts {
		names = append(names, name)
	}
	sort.Strings(names)

	// claim key "<version>\x00<family>" -> first instance that claimed it.
	claimed := map[string]string{}
	for _, name := range names {
		inst := insts[name]
		if inst == nil {
			continue
		}
		fams := []struct {
			fam    *SamplingFamily
			family string
		}{
			{inst.FamilyInet, "inet"},
			{inst.FamilyInet6, "inet6"},
		}
		// Collect THIS instance's distinct (version, family) claims, so the
		// same instance binding two collectors to the same (version, family)
		// does not self-conflict.
		selfClaims := map[string]bool{}
		for _, fe := range fams {
			if fe.fam == nil {
				continue
			}
			for _, fs := range fe.fam.FlowServers {
				if fs == nil {
					continue
				}
				ver := flowServerExportVersion(fs, hasV9, hasIPFIX)
				if ver == "" {
					continue // resolves to no configured version; exports nothing
				}
				selfClaims[ver+"\x00"+fe.family] = true
			}
		}
		// Deterministic order over this instance's claims.
		keys := make([]string, 0, len(selfClaims))
		for k := range selfClaims {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if owner, ok := claimed[key]; ok {
				parts := strings.SplitN(key, "\x00", 2)
				return fmt.Errorf("forwarding-options sampling instances %q and %q "+
					"both export %s family %s flows: the runtime cannot attribute a "+
					"flow to one instance (there is no per-interface sampling-instance "+
					"selector — eligibility is per address family), so the two would "+
					"silently merge. Use a single instance for this version/family, or "+
					"separate the instances by family or export version",
					owner, name, parts[0], parts[1])
			}
			claimed[key] = name
		}
	}
	return nil
}

// validateSamplingInputRateStrict hard-rejects a `forwarding-options sampling
// instance <name> input rate` below zero (#5244).
//
// The defect: compileSampling stored the parsed rate with no lower-bound check,
// so a typo like `input rate -1` committed cleanly. A negative rate is a
// fail-open: the 1-in-N export gate in the flow exporter
// (ExportConfig.ShouldExport, pkg/flowexport) treats `SamplingRate > 1` as
// false for a negative value, so the operator's intended 1-in-N ratio is
// silently ignored (every eligible flow exports) — while the userspace
// snapshot path defensively clamps `rate <= 0 -> 1` and the retired eBPF
// compiler cast `uint32(InputRate)` would wrap it into a ~4.29e9 divisor. Any
// way it lands, the configured rate is not what runs and the operator gets no
// signal. The sibling port-mirroring path already rejects the same class
// inline in compilePortMirroring ("input rate must not be negative"); sampling
// was missed.
//
// `0` is VALID and preserved: it means "sample every packet" per Junos, matches
// the port-mirroring sibling ("0 mirrors every packet"), and is the codebase
// contract (SamplingInstance.InputRate doc, the `rate <= 0 -> 1` snapshot
// clamp, and the `SamplingRate > 1` exporter gate all treat 0 as sample-all).
// Only a strictly negative rate is rejected; there is no upper bound here
// (the sibling has none either, and the snapshot builder already caps at the
// Rust u32 max, #1977).
//
// Strict on commit / commit-check (hard reject so the typo is operator-
// visible); lenient on load / peer-sync (the call site downgrades to a warning
// via opts.lenientSamplingInputRate so an already-persisted or peer-synced
// config authored by a pre-guard version still BOOTS — #1960; the snapshot
// clamp keeps the running dataplane safe). Mirrors
// validateSamplingInstanceConflictsStrict.
// validateFlowExportSecondsStrict hard-rejects a `services flow-monitoring`
// template `seconds` knob whose value cannot be converted to a duration
// (#6769).
//
// The compiler stores `template-refresh-rate`, `flow-active-timeout` and
// `flow-inactive-timeout` with a bare `strconv.Atoi` and NO range check, and
// the consumer computes `time.Duration(n) * time.Second`. For a large enough
// n that multiply overflows int64 and WRAPS. The wrapped value can be small and
// POSITIVE, which is the dangerous half: `templateRefreshInterval` only rejects
// `<= 0`, so it is accepted and `time.NewTicker` fires on it.
//
// Because gcd(1e9, 2^64) = 512, the wrapped residues are multiples of 512 ns and
// the smallest positive one is exactly 512 ns —
// `template-refresh-rate seconds 20211507185753197` produces a 512 ns template
// ticker, and 18446744074 produces 290 ms. The exporter then re-emits its
// templates thousands of times a second at every collector.
//
// The ceiling is the existing MaxDurationSeconds (math.MaxInt64 / 1e9 =
// 9223372036) — the honest runtime-derived bound this codebase already uses for
// second-denominated leaves, NOT a new policy cap ("no schema-only caps", Codex
// review on PR #1845).
//
// Three layers, one constant. `setSchema` types the leaves (#1979 Layer B), so
// strict operator commit rejects before the compiler runs; this gate is the
// compiler-side defense-in-depth for the paths SchemaValidate does not cover
// (tolerant load / peer-sync / direct CompileConfig callers), exactly mirroring
// validateSamplingInputRateStrict (#5244); and `secondsToDuration`
// (pkg/flowexport) falls back at the consumer, so a running exporter is safe
// regardless. This gate exists so an operator finds out at COMMIT rather than
// discovering the knob was silently defaulted.
//
// Not an ambiguity — unlike the #6735 packed-tail shape, a seconds value has
// exactly one reading and it is simply out of range, so rejecting names the
// fault precisely rather than guessing between two intents.
func validateFlowExportSecondsStrict(cfg *Config) error {
	fm := cfg.Services.FlowMonitoring
	if fm == nil {
		return nil
	}
	type namedSeconds struct {
		template string
		leaf     string
		value    int
	}
	var found []namedSeconds
	collect := func(version string, name string, refresh, active, inactive int) {
		for _, item := range []struct {
			leaf  string
			value int
		}{
			{"template-refresh-rate", refresh},
			{"flow-active-timeout", active},
			{"flow-inactive-timeout", inactive},
		} {
			if int64(item.value) > MaxDurationSeconds || item.value < 0 {
				found = append(found, namedSeconds{
					template: version + " template " + name,
					leaf:     item.leaf,
					value:    item.value,
				})
			}
		}
	}
	if v9 := fm.Version9; v9 != nil {
		names := make([]string, 0, len(v9.Templates))
		for name := range v9.Templates {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if t := v9.Templates[name]; t != nil {
				collect("version9", name, t.TemplateRefreshRate, t.FlowActiveTimeout, t.FlowInactiveTimeout)
			}
		}
	}
	if ipfix := fm.VersionIPFIX; ipfix != nil {
		names := make([]string, 0, len(ipfix.Templates))
		for name := range ipfix.Templates {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if t := ipfix.Templates[name]; t != nil {
				collect("version-ipfix", name, t.TemplateRefreshRate, t.FlowActiveTimeout, t.FlowInactiveTimeout)
			}
		}
	}
	if len(found) == 0 {
		return nil
	}
	f := found[0]
	return fmt.Errorf("services flow-monitoring %s: %s is %d seconds, outside the "+
		"accepted range 0-%d (0 = use the default). Past that ceiling `time.Duration(n) "+
		"* time.Second` overflows int64 and WRAPS, and the wrapped value can be small "+
		"and positive — 20211507185753197 yields a 512ns template ticker, which floods "+
		"every collector with template re-exports. The exporter falls back to the "+
		"default for such a value, so the number you configured would be silently "+
		"ignored either way",
		f.template, f.leaf, f.value, MaxDurationSeconds)
}

func validateSamplingInputRateStrict(cfg *Config) error {
	if cfg == nil || cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	insts := cfg.ForwardingOptions.Sampling.Instances
	// Deterministic instance order so the first-offender message is stable.
	names := make([]string, 0, len(insts))
	for name := range insts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		inst := insts[name]
		if inst == nil {
			continue
		}
		if inst.InputRate < 0 {
			return fmt.Errorf("forwarding-options sampling instance %q: input "+
				"rate must not be negative, got %d (a 1-in-N sampling rate must "+
				"be >= 0; 0 samples every packet)", name, inst.InputRate)
		}
	}
	return nil
}

// validateSamplingSourceAddressesStrict rejects source-address values that
// cannot be bound by the flow exporter (#11445). Sampling source addresses
// belong to an explicit inet/inet6 family, and a literal collector address
// must use the same family as the selected source. Hostname collectors have
// no commit-time family to compare, just as RPM source-address validation
// skips hostnames.
func validateSamplingSourceAddressesStrict(cfg *Config) error {
	if cfg == nil || cfg.ForwardingOptions.Sampling == nil {
		return nil
	}

	insts := cfg.ForwardingOptions.Sampling.Instances
	names := make([]string, 0, len(insts))
	for name := range insts {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		inst := insts[name]
		if inst == nil {
			continue
		}
		families := []struct {
			name string
			v6   bool
			cfg  *SamplingFamily
		}{
			{name: "inet", cfg: inst.FamilyInet},
			{name: "inet6", v6: true, cfg: inst.FamilyInet6},
		}
		for _, family := range families {
			if family.cfg == nil {
				continue
			}
			outputIP, err := validateSamplingSourceAddressFamily(name, family.name,
				"output", family.cfg.SourceAddress, family.v6)
			if err != nil {
				return err
			}
			inlineIP, err := validateSamplingSourceAddressFamily(name, family.name,
				"inline-jflow", family.cfg.InlineJflowSourceAddress, family.v6)
			if err != nil {
				return err
			}

			for _, server := range family.cfg.FlowServers {
				if server == nil {
					continue
				}
				serverIP, err := validateSamplingSourceAddressFamily(name, family.name,
					fmt.Sprintf("flow-server %q", server.Address), server.SourceAddress, family.v6)
				if err != nil {
					return err
				}

				source, sourceIP := server.SourceAddress, serverIP
				if source == "" {
					source, sourceIP = family.cfg.SourceAddress, outputIP
				}
				if source == "" {
					source, sourceIP = family.cfg.InlineJflowSourceAddress, inlineIP
				}
				if sourceIP == nil {
					continue
				}
				collectorIP := samplingCollectorIP(server.Address)
				if collectorIP != nil && (sourceIP.To4() == nil) != (collectorIP.To4() == nil) {
					return fmt.Errorf("forwarding-options sampling instance %q family %s "+
						"flow-server %q: source-address %q address family does not match "+
						"collector family", name, family.name, server.Address, source)
				}
			}
		}
	}
	return nil
}

func validateSamplingSourceAddressFamily(instance, family, location, source string, v6 bool) (net.IP, error) {
	if source == "" {
		return nil, nil
	}
	ip := net.ParseIP(source)
	if ip == nil {
		return nil, fmt.Errorf("forwarding-options sampling instance %q family %s %s "+
			"source-address: invalid IP address %q", instance, family, location, source)
	}
	if (ip.To4() == nil) != v6 {
		return nil, fmt.Errorf("forwarding-options sampling instance %q family %s %s "+
			"source-address %q address family does not match family %s",
			instance, family, location, source, family)
	}
	return ip, nil
}

func samplingCollectorIP(address string) net.IP {
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		address = address[1 : len(address)-1]
	}
	if ip := net.ParseIP(address); ip != nil {
		return ip
	}
	if i := strings.LastIndexByte(address, '%'); i > 0 {
		return net.ParseIP(address[:i])
	}
	return nil
}

// samplingSourceAddressLocalityWarnings reports parseable sampling source
// addresses that are not among configured interface addresses or VRRP
// virtual addresses. This remains an advisory because dynamic addresses may
// only become local after a runtime lease or failover.
func samplingSourceAddressLocalityWarnings(cfg *Config) []string {
	if cfg == nil || cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	local := make(map[string]struct{})
	if len(cfg.Interfaces.Interfaces) > 0 {
		for _, iface := range cfg.Interfaces.Interfaces {
			if iface == nil {
				continue
			}
			for _, unit := range iface.Units {
				if unit == nil {
					continue
				}
				for _, address := range unit.Addresses {
					if ip := samplingConfiguredIP(address); ip != nil {
						local[samplingAddressKey(ip)] = struct{}{}
					}
				}
				for _, group := range unit.VRRPGroups {
					if group == nil {
						continue
					}
					for _, address := range group.VirtualAddresses {
						if ip := samplingConfiguredIP(address); ip != nil {
							local[samplingAddressKey(ip)] = struct{}{}
						}
					}
				}
			}
		}
	}

	insts := cfg.ForwardingOptions.Sampling.Instances
	names := make([]string, 0, len(insts))
	for name := range insts {
		names = append(names, name)
	}
	sort.Strings(names)
	var warnings []string
	for _, name := range names {
		inst := insts[name]
		if inst == nil {
			continue
		}
		families := []struct {
			name string
			cfg  *SamplingFamily
		}{
			{name: "inet", cfg: inst.FamilyInet},
			{name: "inet6", cfg: inst.FamilyInet6},
		}
		for _, family := range families {
			if family.cfg == nil {
				continue
			}
			seen := make(map[string]struct{})
			warnIfNonlocal := func(source string) {
				ip := net.ParseIP(source)
				if ip == nil || ip.IsLoopback() {
					return
				}
				key := samplingAddressKey(ip)
				if _, ok := local[key]; ok {
					return
				}
				if _, ok := seen[key]; ok {
					return
				}
				seen[key] = struct{}{}
				warnings = append(warnings, fmt.Sprintf(
					"forwarding-options sampling instance %q family %s: source-address %q "+
						"is not configured on a local interface or VRRP address",
					name, family.name, source))
			}
			warnIfNonlocal(family.cfg.SourceAddress)
			warnIfNonlocal(family.cfg.InlineJflowSourceAddress)
			for _, server := range family.cfg.FlowServers {
				if server != nil {
					warnIfNonlocal(server.SourceAddress)
				}
			}
		}
	}
	return warnings
}

func samplingConfiguredIP(address string) net.IP {
	if ip := net.ParseIP(address); ip != nil {
		return ip
	}
	ip, _, err := net.ParseCIDR(address)
	if err != nil {
		return nil
	}
	return ip
}

func samplingAddressKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.To16().String()
}
