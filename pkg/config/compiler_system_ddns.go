package config

// compiler_system_ddns.go holds the `system services dynamic-dns`
// compiler evicted from compiler_system.go (#16146): pure in-package
// code motion, unchanged call graph.

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ddnsProviderStringProps are the per-provider leaves that carry a string
// value, used by compileDDNSProvider's walker to recognize a "<leaf> <value>"
// pair at any AST depth (#2691 P2).
var ddnsProviderStringProps = map[string]bool{
	"backend":               true,
	"update-server":         true,
	"forward-zone":          true,
	"reverse-zone":          true,
	"tsig-key":              true,
	"tsig-algorithm":        true,
	"tsig-secret":           true,
	"source-address":        true,
	"destination-interface": true,
	"routing-instance":      true,
	// HTTP-provider leaves (#2691 P3).
	"server":            true,
	"username":          true,
	"password":          true,
	"url-template":      true,
	"ok-response":       true,
	"api-token":         true,
	"zone":              true,
	"aws-access-key":    true,
	"aws-secret-key":    true,
	"aws-region":        true,
	"hosted-zone-id":    true,
	"checkip-url":       true,
	"checkip-allowlist": true,
	"install-id":        true,
}

// compileDDNSServices compiles the `system services dynamic-dns` block into a
// typed *DDNSServicesConfig: the named provider catalog + the engine tunables
// (forced-refresh / error-backoff-max). Returns a nil *DDNSServicesConfig for
// a truly empty block so a garbage/empty stanza does not materialize a
// catalog (#2691 P2, plan §5.9) — that can still happen alongside a non-nil
// warnings slice (an all-malformed block warns but has nothing to publish).
//
// #4837: forced-refresh / error-backoff-max accept a Go duration string
// ("24h") or a bare-seconds integer ("86400"), but a value that parses as
// NEITHER form (a typo like "24hh", or a non-positive value like "-5" — the
// downstream engine has no defined meaning for a non-positive interval) was
// previously silently discarded: the field was left unset, falling back to
// its downstream default, with no commit-time error or warning telling the
// operator their value was rejected. Strict (commit / commit-check):
// hard-reject on the first malformed leaf, naming it and its value. Lenient
// (load / peer-sync): downgrade to a warning, accumulated across both
// leaves, so an already-persisted config an older binary accepted still
// boots (#1960 fail-closed-on-load class) — the field stays unset either
// way, matching pre-#4837 runtime behavior exactly; only the warning is new.
func compileDDNSServices(node *Node, lenient bool) (*DDNSServicesConfig, []string, error) {
	cat := &DDNSServicesConfig{Providers: map[string]*DDNSProvider{}}
	var warnings []string
	// #8436: two `provider P { ... }` blocks are ONE provider. Before this each
	// block compiled to a fresh object stored under one key, so the second
	// discarded the first's backend, credentials and endpoint silently — while
	// the flat-set spelling merged.
	//
	// The merge is done by walking BOTH blocks' nodes into one property map and
	// materialising once, rather than by folding two finished structs
	// field-by-field. That matters for a struct this wide: a field-wise merge
	// is a second enumeration of ~21 leaves that a later field would have to be
	// added to, and forgetting one is a silent loss of exactly the kind this
	// census exists to find. Walking the nodes has no such list.
	//
	// THE DIFFERENT-NAMES CASE IS PRESERVED BY CONSTRUCTION: the grouping is
	// keyed on the authored provider NAME, so two blocks naming different
	// providers stay two entries with their own settings.
	byName := map[string][]*Node{}
	var order []string
	for _, inst := range namedInstances(node.FindChildren("provider")) {
		if _, seen := byName[inst.name]; !seen {
			order = append(order, inst.name)
		}
		byName[inst.name] = append(byName[inst.name], inst.node)
	}
	for _, name := range order {
		p := compileDDNSProvider(name, byName[name]...)
		if p == nil {
			continue
		}
		cat.Providers[p.Name] = p
		// TLS enforcement (#4861 + #14372 + #14386): a credentialed HTTP
		// backend (dyndns2/duckdns/cloudflare/route53/generic) must not carry
		// its update credential over a plaintext http:// server/url-template,
		// and NO backend may use a plaintext checkip-url — its response is an
		// unauthenticated oracle Surface A publishes as this firewall's DNS
		// record. Strict (commit / commit-check) hard-rejects; lenient (load
		// / peer-sync) DROPS the provider (#14386, no engine, no updates) and
		// warns that it was dropped, rather than warn-and-keep transmitting
		// the credential (or trusting a spoofed checkip response) in
		// cleartext on every update. The config still boots (#1960); only
		// the offending provider is inert. The redirect-downgrade half (an
		// https endpoint 30x'd to http) is blocked at runtime by the shared
		// client's CheckRedirect (pkg/ddns); the runtime CheckIP gate refuses
		// http outright.
		if field, val, bad := ddnsPlaintextCredentialEndpoint(p); bad {
			msg := fmt.Sprintf("system services dynamic-dns provider %q (backend %s) "+
				"%s %q must be an https:// endpoint — a credentialed backend over a "+
				"plaintext http:// endpoint transmits the update credential in cleartext",
				p.Name, p.Backend, field, RedactURL(val))
			if field == "checkip-url" {
				// The value is OMITTED, not redacted: a checkip-url commonly
				// carries an API key and RedactURL preserves a bracketed
				// IP-literal host, so rendering any part of it can leak the
				// key (mirrors the warning pass + pkg/ddns, #6545).
				msg = fmt.Sprintf("system services dynamic-dns provider %q (backend %s) "+
					"%s must be an https:// endpoint — a plaintext checkip "+
					"response is trusted as this firewall's public address",
					p.Name, p.Backend, field)
			}
			if !lenient {
				return nil, nil, fmt.Errorf("%s", msg)
			}
			if field == "checkip-url" {
				// #14372: lenient keeps the provider (its update endpoint may
				// be https); the runtime CheckIP gate refuses http outright,
				// so no spoofed response is trusted. Warn only.
				warnings = append(warnings, msg)
			} else {
				// #14386: warn-and-keep would transmit the credential in
				// cleartext on every update — drop the provider instead.
				delete(cat.Providers, p.Name)
				warnings = append(warnings, msg+" — provider dropped, no DDNS updates will be sent for it")
			}
		}
	}
	// Engine tunables: a duration ("24h") or a bare-seconds integer. They may
	// appear as a child node OR packed into the block's Keys (flat-set).
	for _, leaf := range []string{"forced-refresh", "error-backoff-max"} {
		v := ddnsServicesScalar(node, leaf)
		if v == "" {
			continue
		}
		s := parseDurationSeconds(v)
		if s <= 0 {
			msg := fmt.Sprintf(
				"system services dynamic-dns %s %q: not a valid duration "+
					"(e.g. \"24h\") or a positive bare-seconds integer; "+
					"ignored — falls back to the built-in default", leaf, v)
			if !lenient {
				return nil, nil, fmt.Errorf("%s", msg)
			}
			warnings = append(warnings, msg)
			continue
		}
		switch leaf {
		case "forced-refresh":
			cat.ForcedRefreshSeconds = s
		case "error-backoff-max":
			cat.ErrorBackoffMaxSeconds = s
		}
	}
	if len(cat.Providers) == 0 && cat.ForcedRefreshSeconds == 0 && cat.ErrorBackoffMaxSeconds == 0 {
		return nil, warnings, nil
	}
	return cat, warnings, nil
}

// ddnsServicesScalar finds a top-level scalar leaf value under the dynamic-dns
// block, tolerating both the hierarchical (child node `key value`) and flat-set
// (key+value packed into the block's Keys) AST shapes.
func ddnsServicesScalar(node *Node, key string) string {
	if c := node.FindChild(key); c != nil {
		if v := nodeVal(c); v != "" {
			return v
		}
	}
	for i := 0; i+1 < len(node.Keys); i++ {
		if node.Keys[i] == key {
			return node.Keys[i+1]
		}
	}
	return ""
}

// parseDurationSeconds parses a duration leaf as either a Go duration string
// ("24h", "30m", "1h30m") or a bare integer count of seconds ("86400"),
// returning whole seconds. Returns 0 for an unparseable value (the engine then
// uses its default).
func parseDurationSeconds(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	if d, err := time.ParseDuration(v); err == nil {
		return int(d.Seconds())
	}
	return 0
}

// compileDDNSProvider compiles one `provider <name> { ... }` entry. It walks
// the provider subtree (both AST shapes) for its string leaves. Returns nil for
// an empty provider block (just a name with no settings).
// compileDDNSProvider materialises one provider from EVERY block that names it.
//
// Variadic since #8436: a duplicate `provider P` block used to overwrite the
// first, so the walk now accumulates across all of them and the struct is
// built once at the end. A leaf no block mentions stays absent — the same "a
// block that never mentions a leaf cannot reset it" property the other #8436
// sites rely on, here obtained from the accumulated map rather than from switch
// arms. The two orderings involved are explained at `cur` below; the short form
// is FIRST-wins within a block, LATER-wins across blocks, which is what the
// flat-set spelling produces.
func compileDDNSProvider(name string, nodes ...*Node) *DDNSProvider {
	props := map[string]string{}
	// cur is the CURRENT block's properties. The walk writes here, not straight
	// into props, so the two orderings this function needs can differ (#8436):
	//
	//   WITHIN one block, FIRST occurrence wins — the guard below. The walker
	//   descends children, so one leaf can be seen at several depths, and the
	//   outermost statement is the authoritative one.
	//
	//   ACROSS blocks, the LATER block wins, applied when cur is folded into
	//   props after each walk. That is what the flat-set spelling does, and it
	//   is the oracle: `set ... update-server first` then `... second` compiles
	//   to "second" — measured, not assumed. Before #8436 made this function
	//   variadic the two blocks never shared a map, so the question could not
	//   arise; sharing one without this split would have made the FIRST block
	//   win and quietly inverted a leaf the operator restated.
	cur := props
	var walk func(n *Node, isRoot bool)
	walk = func(n *Node, isRoot bool) {
		start := 0
		if isRoot {
			// Skip the leading "provider" + "<name>" tokens. The named-instance
			// node's Keys begin with the value (name) when packed flat-set; be
			// conservative and skip until we are past the name.
			for start < len(n.Keys) && (n.Keys[start] == "provider" || n.Keys[start] == name) {
				start++
			}
		}
		for i := start; i < len(n.Keys); i++ {
			k := n.Keys[i]
			if k == "require-tsig" {
				if _, ok := cur[k]; !ok {
					cur[k] = "true"
				}
				continue
			}
			if ddnsProviderStringProps[k] && i+1 < len(n.Keys) {
				if _, ok := cur[k]; !ok {
					cur[k] = n.Keys[i+1]
				}
				i++
			}
		}
		for _, c := range n.Children {
			walk(c, false)
		}
	}
	for _, node := range nodes {
		cur = map[string]string{}
		walk(node, true)
		for k, v := range cur {
			props[k] = v
		}
	}

	p := &DDNSProvider{
		Name:               name,
		Backend:            props["backend"],
		RFC2136Endpoint:    compileRFC2136Endpoint(props),
		Server:             props["server"],
		Username:           props["username"],
		Password:           NewSecret(props["password"]),
		URLTemplate:        props["url-template"],
		OKResponse:         props["ok-response"],
		APIToken:           NewSecret(props["api-token"]),
		Zone:               props["zone"],
		AWSAccessKeyID:     props["aws-access-key"],
		AWSSecretAccessKey: NewSecret(props["aws-secret-key"]),
		AWSRegion:          props["aws-region"],
		HostedZoneID:       props["hosted-zone-id"],
		CheckIPURL:         props["checkip-url"],
		CheckIPAllowlist:   props["checkip-allowlist"],
		InstallID:          props["install-id"],
	}
	if p.Backend == "" && p.RFC2136Endpoint.IsZero() &&
		p.Server == "" && p.Username == "" && p.Password.Reveal() == "" &&
		p.URLTemplate == "" && p.OKResponse == "" && p.APIToken.Reveal() == "" &&
		p.Zone == "" && p.AWSAccessKeyID == "" && p.AWSSecretAccessKey.Reveal() == "" &&
		p.AWSRegion == "" && p.HostedZoneID == "" && p.CheckIPURL == "" &&
		p.CheckIPAllowlist == "" && p.InstallID == "" {
		return nil
	}
	return p
}
