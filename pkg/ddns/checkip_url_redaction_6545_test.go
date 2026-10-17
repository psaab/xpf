package ddns

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// checkip_url_redaction_6545_test.go: a MALFORMED checkip-url must not put its
// credential in the refusal error (#6545 review, security MINOR).
//
// #6545 made CheckIP/CheckIPBound RETURN the reason a probe failed so a
// permanently misconfigured checkip-url stops masquerading as a transient miss.
// The daemon observer then logs that reason (slog.Warn "err", cerr) AND uses its
// text as the checkIPProbeWarned dedup map key. validateCheckIPURL built those
// errors with the RAW url, so the new operator-visible signal wrote a
// query-string API key into journald in cleartext:
//
//	ddns checkip: url "ftp://checkip.example/?apikey=SECRET" must be https
//
// A checkip endpoint with a per-account API key in its query is ordinary
// (ipify, ip-api, and the whole "what is my IP" API tier all offer one), and the
// key is exactly the kind of credential this package redacts everywhere else —
// backend_generic.go runs url-template through config.RedactURL, doRequest runs
// transport errors through scrubURLError. The checkip validator was the hole.
//
// checkIPCredential is the sentinel every case below plants in the position an
// operator's key actually occupies. It is deliberately not a substring of any
// host or scheme in these URLs, so a hit is unambiguous evidence of a leak.
const checkIPCredential = "CHECKIP-SECRET-MUST-NOT-LOG"

// malformedCredentialedURLs covers ALL THREE validateCheckIPURL refusal
// branches with a credential attached, plus the userinfo shape. A fix that
// redacts only the branch Codex quoted would stay RED on the others.
var malformedCredentialedURLs = []struct {
	name string
	url  string
	// want is a fragment the message must STILL carry, so a "redaction" that
	// simply drops the URL (and the operator's ability to tell which provider
	// leaf is wrong) does not pass this test either.
	want string
}{
	{
		name: "bad scheme, credential in query",
		url:  "ftp://checkip.example/?apikey=" + checkIPCredential,
		want: "must be https",
	},
	{
		name: "no host, credential in query",
		url:  "https://?apikey=" + checkIPCredential,
		want: "has no host",
	},
	// PARSE-SUCCESS leaks. These are the shapes that disprove any
	// "redact once url.Parse has succeeded" rule: all three parse cleanly, and
	// config.RedactURL returns each of them UNCHANGED.
	{
		name: "scheme-relative authority, credential in userinfo (parses)",
		// No "://", so RedactURL's scan starts at index 0, meets the leading
		// '/' immediately and takes the authority to be empty — the userinfo is
		// never found. url.Parse, by contrast, populates User just fine.
		url:  "//user:" + checkIPCredential + "@checkip.example/",
		want: "must be https",
	},
	{
		name: "credential in the fragment, bad scheme (parses)",
		// RedactURL only ever drops the query; a fragment is never touched.
		url:  "ftp://checkip.example/#apikey=" + checkIPCredential,
		want: "must be https",
	},
	{
		name: "credential in the fragment, no host (parses)",
		url:  "https:///path#" + checkIPCredential,
		want: "has no host",
	},
	{
		name: "unparseable, credential in query",
		// An unterminated IPv6 literal: url.Parse FAILS here, so the error is
		// the *url.Error whose Error() re-embeds the whole raw input. This is
		// the case a naive "RedactURL(u) + %w" fix still leaks through.
		url:  "http://[::1/?apikey=" + checkIPCredential,
		want: "missing ']' in host",
	},
	{
		name: "bad scheme, credential in userinfo",
		url:  "ftp://user:" + checkIPCredential + "@checkip.example/",
		want: "must be https",
	},
	{
		name: "unparseable, credential in userinfo",
		url:  "ftp://user:" + checkIPCredential + "@[::1/",
		want: "missing ']' in host",
	},
	// The cases below put the sentinel INSIDE the malformed portion itself.
	// Everything above leaves the credential in a well-formed userinfo/query,
	// so a fix that only stopped %w-wrapping would pass those and still leak
	// here. Each `want` is the CLASS-SPECIFIC constant urlParseCause selects,
	// so these also prove the sanitization kept a useful diagnostic instead of
	// collapsing everything to the generic reason.
	{
		name: "unparseable, credential lands in the port (missing @)",
		// The realistic operator typo: a credentialed URL with the '@' left
		// out. net/url reads host "user", port ":<credential>.example", and
		// reports invalid port %q after host — the whole password, unbounded.
		// This case ALSO covers the second surface: RedactURL keys on '@' to
		// find userinfo, so with the '@' missing it returns the string
		// unchanged and the display half leaks even with the cause sanitized.
		url:  "http://user:" + checkIPCredential + ".example/",
		want: "invalid port after host",
	},
	{
		name: "unparseable, credential in an IP-literal host",
		// invalid host: ParseAddr("<raw host>") — also unbounded. RedactURL
		// deliberately preserves hosts, so this too is only safe because the
		// URL is omitted outright from the parse-failure branch.
		url:  "http://user:pass@[" + checkIPCredential + "]/",
		want: "invalid host",
	},
	{
		name: "unparseable, credential begins with a bad percent-escape",
		// url.EscapeError quotes 3 bytes of input; bounded, but still input.
		url:  "http://user:%" + checkIPCredential + "@checkip.example/",
		want: "invalid percent-escape",
	},
}

// TestValidateCheckIPURLOmitsTheURLInEveryBranch pins the structural rule all of
// the above rests on: NO refusal, from ANY branch, may echo ANY part of the
// input. Not the parse-failure branch, and not the scheme/host branches either —
// the earlier "RedactURL is sound once url.Parse succeeded" carve-out was FALSE,
// because scheme-relative and fragment-bearing URLs parse cleanly and RedactURL
// returns them unchanged.
//
// Asserting on a benign, highly legible host rather than a credential sentinel
// is deliberate: it makes the test independent of where a secret happens to sit.
// If the host survives into the message, so would a password in the same
// position — which is precisely how the scheme-relative hole was missed.
func TestValidateCheckIPURLOmitsTheURLInEveryBranch(t *testing.T) {
	const host = "checkip.example"
	cases := []struct {
		url        string
		wantParses bool // documents which branch this exercises
	}{
		// Parse FAILURES.
		{"http://user:pw." + host + ":notaport/", false},
		{"http://" + host + ":notaport/", false},
		{"http://[" + host + "]/", false},
		{"http://%zz@" + host + "/", false},
		// Parse SUCCESSES that must still be refused (bad scheme / no host).
		{"ftp://" + host + "/", true},
		{"//user:pw@" + host + "/", true},
		{"ftp://" + host + "/#tag-" + host, true},
		{"http:///path#" + host, true},
		{"ftp://" + host + "/?q=" + host, true},
	}
	for _, tc := range cases {
		_, perr := url.Parse(tc.url)
		if (perr == nil) != tc.wantParses {
			t.Fatalf("%q: url.Parse parses=%v, case declares parses=%v; the case no longer "+
				"exercises the branch it was written for", tc.url, perr == nil, tc.wantParses)
		}
		err := validateCheckIPURL(tc.url)
		if err == nil {
			t.Fatalf("validateCheckIPURL(%q) = nil, want a refusal; the assertion below "+
				"would be vacuous", tc.url)
		}
		if strings.Contains(err.Error(), host) {
			t.Errorf("validateCheckIPURL(%q) = %q: the refusal echoed part of the input "+
				"(parses=%v). config.RedactURL is a best-effort scrubber, not a parser — it "+
				"misses a missing-'@' credential, a scheme-relative authority, and anything "+
				"in a fragment — so no branch may print the URL at all.",
				tc.url, err, tc.wantParses)
		}
	}
}

// TestValidateCheckIPURLRedactsCredentials is the fail-on-revert gate: restore
// the raw %q/%w in validateCheckIPURL and every case here fails by assertion,
// naming the leaked sentinel.
func TestValidateCheckIPURLRedactsCredentials(t *testing.T) {
	for _, tc := range malformedCredentialedURLs {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCheckIPURL(tc.url)
			if err == nil {
				t.Fatalf("validateCheckIPURL(%q) = nil; this URL is malformed and must be "+
					"refused — the redaction assertions below would be vacuous", tc.url)
			}
			if got := err.Error(); strings.Contains(got, checkIPCredential) {
				t.Fatalf("validateCheckIPURL leaked the checkip-url credential into its error:\n"+
					"  error    = %q\n"+
					"  contains = %q\n"+
					"This error is logged by the Surface A observer (slog.Warn \"err\", cerr) and "+
					"is retained as the checkIPProbeWarned dedup map key, so the operator's API "+
					"key lands in journald in cleartext. Render the URL through config.RedactURL "+
					"and do not %%w-wrap url.Parse's error (it re-embeds the raw input).",
					got, checkIPCredential)
			}
			if got := err.Error(); !strings.Contains(got, tc.want) {
				t.Fatalf("validateCheckIPURL(%q) = %q, want it to still contain %q; the "+
					"redaction must strip the credential, not the diagnostic", tc.url, got, tc.want)
			}
		})
	}
}

// TestCheckIPMalformedURLErrorRedactsCredentials proves the redaction survives
// the path the DAEMON actually takes. validateCheckIPURL is unexported; what
// reaches the log is CheckIP's third return, so assert on that end to end.
func TestCheckIPMalformedURLErrorRedactsCredentials(t *testing.T) {
	// A transport that fails loudly if it is ever reached: every URL here must
	// be refused BEFORE any request is issued.
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("a malformed checkip-url reached the transport (%q); the validator must "+
			"fail closed before any request", r.URL.String())
		return nil, nil
	})}

	for _, tc := range malformedCredentialedURLs {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := CheckIP(context.Background(), client, tc.url, true, nil)
			if ok {
				t.Fatalf("CheckIP(%q) ok=true; a malformed checkip-url must fail closed", tc.url)
			}
			if err == nil {
				t.Fatalf("CheckIP(%q) err=nil; #6545 requires the refusal to be reportable", tc.url)
			}
			if got := err.Error(); strings.Contains(got, checkIPCredential) {
				t.Fatalf("CheckIP returned an error carrying the checkip-url credential:\n"+
					"  error    = %q\n"+
					"  contains = %q\n"+
					"The daemon logs this string verbatim and keys its dedup map on it.",
					got, checkIPCredential)
			}
		})
	}
}

// urlParseCauseAllowed is the closed set of reasons urlParseCause may return,
// declared HERE as literals and deliberately NOT derived from anything in the
// production file.
//
// The previous version of this gate built its allowed set by ranging over the
// production slice, which made it circular: whatever the function returned from
// that slice was admissible by definition, and a mutation swapping the returned
// constant for the input-derived string still passed. Copying the values by hand
// is the point — if production adds a reason, this list must be edited too, and
// that edit is exactly the review moment the gate exists to create.
var urlParseCauseAllowed = map[parseReason]bool{
	"malformed URL":                                  true,
	"missing protocol scheme":                        true,
	"invalid control character in URL":               true,
	"empty url":                                      true,
	"invalid URI for request":                        true,
	"first path segment in URL cannot contain colon": true,
	"invalid userinfo":                               true,
	"invalid IP-literal":                             true,
	"missing ']' in host":                            true,
	"invalid port after host":                        true,
	"invalid host":                                   true,
	"invalid percent-escape":                         true,
	"invalid character in host":                      true,
}

// TestURLParseCauseAlwaysReturnsAConstant is the VALUE-based gate, NOT the
// structural one — the structural gate lives in
// checkip_cause_structural_6545_test.go and walks urlParseCause's AST. (An
// earlier revision of this comment called this one "the structural gate", which
// was exactly backwards and mattered: this test is a COVERAGE check by nature
// and cannot see a pass-through on a branch its inputs never reach, which is
// the entire reason the AST gate exists alongside it.)
//
// What it pins: urlParseCause must return one of a CLOSED set of literals,
// whatever it is handed. That
// property — not the particular net/url causes enumerated today — is what makes
// the helper safe to reuse (the other DDNS URL validators inherit it, #6606),
// and it is what a stdlib rewording or a brand-new cause must not be able to
// break: an unrecognized cause has to fail CLOSED, never pass through.
//
// MUTATION-VERIFIED. The gate is only meaningful if it can fail for the reason
// it exists, so it is built to detect a pass-through directly: alongside real
// url.Parse errors it feeds SYNTHETIC *url.Error values whose inner cause is a
// hostile string that is NOT any recognised net/url message. Any implementation
// that returns its input — including one that returns the compared string rather
// than the matched constant — surfaces that sentinel and fails here. Changing
// production's fallback to return the raw cause makes this test RED.
func TestURLParseCauseAlwaysReturnsAConstant(t *testing.T) {
	check := func(t *testing.T, label string, err error) {
		t.Helper()
		got := urlParseCause(err)
		if !urlParseCauseAllowed[got] {
			t.Errorf("urlParseCause for %s returned %q, which is NOT one of the reasons "+
				"declared in this test file; the helper must never return a string derived "+
				"from its input", label, got)
		}
		if strings.Contains(string(got), checkIPCredential) {
			t.Errorf("urlParseCause leaked the credential for %s: %q", label, got)
		}
	}

	// (a) Real url.Parse failures, sentinel planted in every position that can
	// end up inside one.
	for _, in := range []string{
		"http://user:" + checkIPCredential + ".example/",
		"http://checkip.example:" + checkIPCredential + "/",
		"http://user:pass@[" + checkIPCredential + "]/",
		"http://%" + checkIPCredential + "@h/",
		"http://h/p%" + checkIPCredential,
		"http://h/#%" + checkIPCredential,
		"http://h\x7f" + checkIPCredential + "/",
		"http://[::1/?apikey=" + checkIPCredential,
		"http://user:" + checkIPCredential + "@[::1/",
		"ht tp://x/?apikey=" + checkIPCredential,
		"://nohost/?apikey=" + checkIPCredential,
		"", "%", ":", "//", "http://[", string([]byte{0x00}),
	} {
		if _, err := url.Parse(in); err != nil {
			check(t, "input "+strconv.Quote(in), err)
		}
	}

	// (b) SYNTHETIC causes. These are what make the gate non-circular: none of
	// them is a recognised net/url message, so a correct implementation must
	// funnel every one to the generic reason, while ANY pass-through returns the
	// sentinel and fails. They also model the realistic future in which the
	// stdlib rewords a message or adds a new one.
	for _, tc := range []struct {
		label string
		inner error
	}{
		{"unknown stdlib message", errors.New("brand new net/url message " + checkIPCredential)},
		{"reworded invalid-port", errors.New("bad port \"" + checkIPCredential + "\" after the host")},
		{"escape error", url.EscapeError("%" + checkIPCredential[:2])},
		{"invalid host char", url.InvalidHostError(checkIPCredential[:1])},
		{"wrapped host error", fmt.Errorf("invalid host: %w",
			errors.New("ParseAddr(\""+checkIPCredential+"\"): unable to parse IP"))},
		{"raw sentinel", errors.New(checkIPCredential)},
		{"empty inner", errors.New("")},
	} {
		check(t, tc.label, &url.Error{Op: "parse", URL: "http://" + checkIPCredential + "/", Err: tc.inner})
	}

	// (c) The recognised fixed sentences must still map to a declared reason —
	// so the allowlist half is exercised, not just the fallback.
	for _, fixed := range []string{
		"missing protocol scheme",
		"net/url: invalid control character in URL",
		"empty url",
		"invalid URI for request",
		"first path segment in URL cannot contain colon",
		"net/url: invalid userinfo",
		"invalid IP-literal",
		"missing ']' in host",
	} {
		check(t, "fixed sentence "+strconv.Quote(fixed),
			&url.Error{Op: "parse", URL: "http://" + checkIPCredential + "/", Err: errors.New(fixed)})
	}

	// (d) A non-*url.Error must fail closed rather than render its own text.
	if got := urlParseCause(errors.New("boom " + checkIPCredential)); got != causeMalformedURL {
		t.Errorf("urlParseCause(non-url.Error) = %q, want %q; an unaudited error must fail "+
			"closed to the fixed reason, not be passed through", got, causeMalformedURL)
	}
	// (e) A *url.Error with a nil inner cause must not panic or pass through.
	if got := urlParseCause(&url.Error{Op: "parse", URL: "http://" + checkIPCredential + "/"}); got != causeMalformedURL {
		t.Errorf("urlParseCause(nil inner) = %q, want %q", got, causeMalformedURL)
	}
}

// TestCheckIPValidURLStillAccepted is the over-reach guard for the redaction:
// the validator must keep ACCEPTING a well-formed credentialed checkip-url. A
// "fix" that redacted the URL before parsing it would refuse every checkip
// endpoint that carries an API key — turning a log-hygiene bug into a total
// outage of the feature.
//
// The USERINFO cases are what make this a real guard: RedactURL renders userinfo
// as "<redacted>@", and url.Parse REJECTS that with "net/url: invalid userinfo"
// (verified against Go 1.26.4), so parsing the redacted value fails loudly. A
// query-only case would be vacuous — RedactURL renders a query as "?<redacted>"
// and url.Parse accepts that as an ordinary raw query — so the query cases below
// are coverage of the accept path, NOT of the redact-before-parse mistake.
func TestCheckIPValidURLStillAccepted(t *testing.T) {
	for _, good := range []string{
		"https://checkip.example/?apikey=" + checkIPCredential,
		"https://user:" + checkIPCredential + "@checkip.example/",
		"HTTPS://checkip.example/?apikey=" + checkIPCredential,
		// Userinfo + query together: the shape a redact-before-parse fix
		// mangles most thoroughly.
		"https://user:" + checkIPCredential + "@checkip.example/?apikey=" + checkIPCredential,
	} {
		if err := validateCheckIPURL(good); err != nil {
			t.Fatalf("validateCheckIPURL(%q) = %v, want nil; a credentialed but VALID "+
				"checkip-url must still be accepted", good, err)
		}
	}
}
