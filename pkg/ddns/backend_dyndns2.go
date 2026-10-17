package ddns

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// backend_dyndns2.go: the dyndns2 HTTP DDNS backend (#2691 P3, plan §3.1/§5.2).
// dyndns2 is the de-facto consumer-DDNS protocol: a single GET
//
//	https://user:pass@<server>/nic/update?hostname=<H>&myip=<IP>
//
// with HTTP Basic auth, whose response BODY (HTTP 200) carries a status keyword
// (good/nochg/nohost/badauth/abuse/notfqdn/911/...) the client parses into a
// verdict. The inadyn idea adopted here (idea #2, plan §3.7): ONE implementation
// behind MANY provider names — a name→endpoint table (dyndns2Endpoints) maps the
// provider backend token (or an explicit `server`) to the right host. dyn,
// no-ip, dynu, etc. all speak this protocol; only the endpoint differs. (DuckDNS
// does NOT — it has its own backend, backend_duckdns.go, #2960; it was wrongly an
// alias here.)
//
// This backend implements the SAME DNSUpdater interface as rfc2136, so the
// Surface A engine drives it identically. A router record carries no PTR and no
// ClientID (the firewall owns its own name), so Upsert sends exactly one GET.
//
// Withdraw (#2772): the previous DeleteLease was a no-op that returned nil, so
// the Surface A engine dropped local ownership while the public record kept
// resolving forever (the comments assumed a provider TTL/liveness reap that is
// NOT a portable dyndns2 contract). DeleteLease now performs the de-facto
// dyndns2 withdraw verb — the SAME update GET with `offline=YES` — which dyn,
// no-ip, and dns-o-matic honour by taking the hostname offline (it stops
// resolving / serves the provider's offline redirect). The provider's body
// verdict (good/nochg/...) is parsed exactly like the upsert path, so a failed
// withdraw returns a non-nil error and the engine keeps ownership for retry
// instead of silently orphaning the record.

// dyndns2Endpoints maps a known dyndns2 provider name to its update base URL.
// The provider's `backend` token selects the protocol (dyndns2); when the
// `backend` token is itself a known provider NAME we use its endpoint, else the
// operator must set `server`. Keep this table small and well-known; everything
// else uses the generic backend or an explicit `server`.
var dyndns2Endpoints = map[string]string{
	"dyn":       "https://members.dyndns.org/v3/update",
	"dyndns":    "https://members.dyndns.org/v3/update",
	"no-ip":     "https://dynupdate.no-ip.com/nic/update",
	"noip":      "https://dynupdate.no-ip.com/nic/update",
	"dynu":      "https://api.dynu.com/nic/update",
	"easydns":   "https://api.cp.easydns.com/dyn/generic.php",
	"dnsomatic": "https://updates.dnsomatic.com/nic/update",
}

// dyndns2Backend publishes a single A/AAAA record via the dyndns2 protocol.
type dyndns2Backend struct {
	name     string // provider name (for logs)
	endpoint string // resolved update base URL
	username string
	password string // revealed at construction; never logged
	client   *http.Client
}

// newDyndns2Backend resolves a provider-catalog entry into a live dyndns2
// backend. The endpoint is the explicit `server` (a full URL, or a bare host we
// suffix with /nic/update) else the built-in endpoint for the named provider.
// Returns an error when no endpoint can be resolved so the manager falls back to
// no-op (logged + counted) rather than emitting to a wrong host. A non-nil
// client is reused (the cached reconcile-path client, #2904); nil builds a
// fresh bound client.
func newDyndns2Backend(p *config.DDNSProvider, client *http.Client) (*dyndns2Backend, error) {
	if p == nil {
		return nil, fmt.Errorf("ddns dyndns2: nil provider")
	}
	endpoint, err := resolveDyndns2Endpoint(p)
	if err != nil {
		return nil, err
	}
	// #14386 runtime belt: refuse a credentialed plaintext http:// endpoint
	// at construction (direct construction bypasses the compiler drop).
	if dyndns2CarriesCredentials(p) {
		if err := plaintextEndpointRefusal("dyndns2", p.Name, endpoint); err != nil {
			return nil, err
		}
	}
	// Bind the dial to the configured source-address/interface/VRF (#2846). A
	// cached client (#2904) is reused when supplied; nil builds a fresh one.
	client, err = ensureProviderHTTPClient(p, client)
	if err != nil {
		return nil, fmt.Errorf("ddns dyndns2: provider %q: %w", p.Name, err)
	}
	return &dyndns2Backend{
		name:     p.Name,
		endpoint: endpoint,
		username: p.Username,
		password: p.Password.Reveal(),
		client:   client,
	}, nil
}

// resolveDyndns2Endpoint picks the update base URL for a dyndns2 provider.
//
// A `server` carrying a URL scheme is a full update URL; anything else is a
// bare host that is suffixed with the canonical dyndns2 path over HTTPS. URL
// schemes are case-INSENSITIVE (RFC 3986 §3.1), so "HTTPS://host" is a full
// URL, not a bare host — the full-URL case is detected by the "://" delimiter
// and validated with url.Parse + a case-insensitive scheme compare, mirroring
// validateCheckIPURL (#2842) and validateGenericURLTemplate (#2841). Both the
// full-URL and bare-host cases require a non-empty host so a hostless value
// ("http://", "https:///nic/update", ":8080") fails at construction (fall back
// to no-op at the manager) instead of returning a URL that only fails at the
// first publish (#3737).
func resolveDyndns2Endpoint(p *config.DDNSProvider) (string, error) {
	if s := strings.TrimSpace(p.Server); s != "" {
		if strings.Contains(s, "://") {
			u, err := url.Parse(s)
			if err != nil {
				// PARSE-FAILURE BRANCH: render NO part of the input (#6606).
				//
				// This is the #6594 split, and both halves of it are load-
				// bearing. Dropping the %w matters because (*url.Error).Error()
				// re-embeds the whole raw URL — but dropping it alone is not
				// enough, because several INNER net/url causes embed input too,
				// and one is unbounded: `invalid port %q after host` quotes an
				// arbitrary-length substring. The realistic trigger IS the
				// credentialed case: an operator who omits the '@' in
				// "https://user:s3cr3t@host/" leaves net/url parsing host
				// "user" and port ":s3cr3t", so the failure mode puts the
				// PASSWORD in the message. urlParseCause returns only closed
				// parseReason constants, which is what makes the diagnostic
				// safe.
				//
				// And not even a redacted render of the input belongs here:
				// config.RedactURL is sound for a URL that PARSED, but this one
				// did not, so a credential can be sitting in a slot no redactor
				// can identify (a bad %-escape mid-path, say). The provider name
				// plus the cause is enough to act on.
				return "", fmt.Errorf("ddns dyndns2: provider %q server is not a valid URL: %s",
					p.Name, urlParseCause(err))
			}
			// PARSED: from here config.RedactURL is provably sound — a
			// successfully-parsed URL cannot hide a credential in the host:port
			// slot ("http://h:abc/x" is itself a parse error) — so the value is
			// rendered redacted, which keeps the message actionable.
			if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
				return "", fmt.Errorf("ddns dyndns2: provider %q server %q must be an http(s) URL",
					p.Name, config.RedactURL(s))
			}
			// Hostname() (not Host) so a port-only authority ("https://:8080/…")
			// is rejected as hostless rather than accepted with an empty host.
			if u.Hostname() == "" {
				return "", fmt.Errorf("ddns dyndns2: provider %q server %q has no host",
					p.Name, config.RedactURL(s))
			}
			return s, nil
		}
		// Bare host → canonical dyndns2 path over HTTPS. Validate the host by
		// parsing the composed URL so a hostless value (":8080", "/path") is
		// rejected here instead of at the first publish.
		//
		// The two failure modes are SPLIT (#6606) rather than sharing one
		// message: they had opposite safety properties behind a single `err !=
		// nil || Hostname() == ""` condition, so one render had to be wrong for
		// one of them.
		full := "https://" + s + "/nic/update"
		u, err := url.Parse(full)
		if err != nil {
			return "", fmt.Errorf("ddns dyndns2: provider %q server is not a valid host: %s",
				p.Name, urlParseCause(err))
		}
		if u.Hostname() == "" {
			return "", fmt.Errorf("ddns dyndns2: provider %q server %q is not a valid host",
				p.Name, config.RedactURL(s))
		}
		return full, nil
	}
	// No explicit server: use the built-in endpoint for the named provider. The
	// `backend` token is "dyndns2"; the provider NAME (or an alias in the table)
	// selects the host.
	if ep, ok := dyndns2Endpoints[strings.ToLower(p.Name)]; ok {
		return ep, nil
	}
	if ep, ok := dyndns2Endpoints[strings.ToLower(p.Backend)]; ok {
		return ep, nil
	}
	return "", fmt.Errorf("ddns dyndns2: provider %q has no server and no built-in endpoint "+
		"(set `server`, or name the provider after a known dyndns2 service)", p.Name)
}

// UpsertLease publishes one A/AAAA via a single dyndns2 GET. The reverse PTR and
// ClientID fields of the record are ignored (dyndns2 is a forward-only consumer
// protocol; the firewall owns its own name).
func (b *dyndns2Backend) UpsertLease(ctx context.Context, rec LeaseDNSRecord) error {
	q := url.Values{}
	q.Set("hostname", rec.FQDN)
	q.Set("myip", rec.Addr.Unmap().String())
	return b.update(ctx, q)
}

// DeleteLease withdraws the firewall's own A/AAAA via the de-facto dyndns2
// offline verb (#2772): the SAME update GET, this time with `offline=YES`, which
// instructs the provider to take the hostname offline (stop resolving it / serve
// the provider's offline redirect). dyndns2 has no separate "remove the RR"
// call, so `offline=YES` is the portable withdraw the well-known dyndns2
// services (dyn, no-ip, dns-o-matic) implement; the response is parsed exactly
// like an upsert, so a provider failure propagates as a non-nil error and the
// Surface A engine keeps ownership for retry rather than reporting a false
// withdraw and orphaning the public record.
//
// SIBLING-FAMILY GUARD (#3738): offline=YES is HOSTNAME-level — it takes the
// whole hostname (both the A and the AAAA) offline. A dual-stack same-name
// dyndns2 scope therefore cannot express a single-family withdraw on the wire:
// offlining to drop ONE family while its sibling is still live would blackhole
// the sibling. When the engine flags rec.SiblingFamilyOwned we do the LEAST-
// DESTRUCTIVE thing — SKIP the offline (a logged no-op) — preserving the live
// sibling. The withdrawn family's record is left in place (stale) rather than the
// sibling being taken down; the manager still drops this family's ownership, so a
// later withdraw of the LAST family (no sibling left → the flag is false) issues
// offline=YES and takes the whole name down as intended.
func (b *dyndns2Backend) DeleteLease(ctx context.Context, rec LeaseDNSRecord) error {
	if rec.SiblingFamilyOwned {
		slog.Warn("ddns dyndns2: skipping hostname-level offline to preserve the live sibling family "+
			"(offline=YES takes down BOTH A and AAAA; dyndns2 has no per-family withdraw)",
			"provider", b.name, "fqdn", rec.FQDN, "withdraw_type", rec.ForwardType)
		return nil
	}
	q := url.Values{}
	q.Set("hostname", rec.FQDN)
	// myip is still required by some providers' parsers; send the address being
	// withdrawn so the request is well-formed. offline=YES is the operative verb.
	q.Set("myip", rec.Addr.Unmap().String())
	q.Set("offline", "YES")
	return b.update(ctx, q)
}

// update issues one dyndns2 GET against the resolved endpoint with the supplied
// query, then parses the body verdict. Shared by UpsertLease and DeleteLease so
// both paths apply identical auth, status, and response-keyword handling.
func (b *dyndns2Backend) update(ctx context.Context, q url.Values) error {
	// #14386 belt at issuance: never send a credentialed request over
	// plaintext http:// to a non-loopback host, even if the backend was
	// constructed without going through newDyndns2Backend.
	if (b.username != "" || b.password != "" || templateAuthorityUserinfo(b.endpoint)) &&
		plaintextEndpointRefusal("dyndns2", b.name, b.endpoint) != nil {
		return fmt.Errorf("ddns dyndns2: provider %q endpoint %q must be an https:// endpoint — refusing to transmit the update credential in cleartext (#14386)",
			b.name, config.RedactURL(b.endpoint))
	}
	u, err := url.Parse(b.endpoint)
	if err != nil {
		// SECURITY: the endpoint derives from the `server` leaf and may carry
		// userinfo; %w would re-embed it. Same class as duckdns/cloudflare/
		// route53 even though resolveDyndns2Endpoint already url.Parsed it
		// (#6545) — the invariant must not depend on that reachability argument.
		return fmt.Errorf("ddns dyndns2: bad endpoint: %s", scrubURLError(err))
	}
	// Merge the caller's parameters onto any the endpoint already carries.
	base := u.Query()
	for k, vs := range q {
		base[k] = vs
	}
	u.RawQuery = base.Encode()

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		// SECURITY: as above — never %w a URL-bearing build error (#6545).
		return fmt.Errorf("ddns dyndns2: build request: %s", scrubURLError(err))
	}
	// Basic auth via the header (set explicitly, NOT in the URL userinfo, so the
	// password never lands in a logged URL string).
	if b.username != "" || b.password != "" {
		req.SetBasicAuth(b.username, b.password)
	}
	req.Header.Set("User-Agent", "xpf-ddns/1.0")

	code, body, err := doRequest(ctx, b.client, req)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		// dyndns2 is a 200-with-body protocol; a non-200 is itself the verdict.
		if cerr := classifyHTTPStatus(code); cerr != nil {
			return fmt.Errorf("ddns dyndns2: %s: %w", b.name, cerr)
		}
		return fmt.Errorf("ddns dyndns2: %s: unexpected status %d", b.name, code)
	}
	return parseDyndns2Response(string(body), b.name)
}

// parseDyndns2Response maps a dyndns2 response body's first status keyword to a
// verdict (plan §3.1; sources help.dyn.com / ddclient wiki):
//   - good / nochg            → success (record set / unchanged)
//   - badauth / !donator      → hard auth failure (errHTTPAuth)
//   - abuse / blocked         → hard abuse lockout (errHTTPAuth — back off hard)
//   - 911 / dnserr           → provider error / rate-limit (errHTTPRateLimited)
//   - nohost / notfqdn / numhost / nofqdn / badagent → config error (hard)
//   - anything else          → unknown (treated as a transient failure)
func parseDyndns2Response(body, name string) error {
	// The status keyword is the first whitespace-delimited token of the first
	// non-empty line ("good 203.0.113.5").
	first := ""
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			first = line
			break
		}
	}
	fields := strings.Fields(first)
	keyword := ""
	if len(fields) > 0 {
		keyword = strings.ToLower(fields[0])
	}
	switch keyword {
	case "good", "nochg":
		return nil
	case "badauth", "!donator":
		return fmt.Errorf("ddns dyndns2: %s: response %q: %w", name, keyword, errHTTPAuth)
	case "abuse", "blocked":
		return fmt.Errorf("ddns dyndns2: %s: response %q (account locked): %w", name, keyword, errHTTPAuth)
	case "911", "dnserr":
		return fmt.Errorf("ddns dyndns2: %s: response %q (provider error): %w", name, keyword, errHTTPRateLimited)
	case "nohost", "notfqdn", "numhost", "nofqdn", "badagent":
		return fmt.Errorf("ddns dyndns2: %s: response %q (hostname/request rejected)", name, keyword)
	default:
		// SECURITY (#6634): `first` is the provider's own first response line,
		// up to httpMaxResponseBody (64 KiB) of provider-chosen bytes, rendered
		// into an error the daemon logs every reconcile tick of a persistent
		// failure and retains as the provider's lastErr. %q already neutralizes
		// control characters; what it does not neutralize is a credential — the
		// dyndns2 `server` leaf can carry userinfo, so an endpoint that echoes
		// the request back echoes the credential — or 64 KiB of anything.
		return fmt.Errorf("ddns dyndns2: %s: unrecognized response %q", name, scrubProviderText(first))
	}
}
