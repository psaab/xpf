package ddns

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// provider_response_text_6634_test.go: #6634. Four backends rendered text taken
// from the PROVIDER'S HTTP RESPONSE BODY straight into a returned error the
// daemon logs and retains as the provider's lastErr. The provider is the
// untrusted party: no hostile transport is needed, only an API that answers
// "your request was invalid: <the request>" and echoes our own update URL back.
// DuckDNS makes that concrete — its token travels in the QUERY STRING, so the
// echo IS the credential.
//
// EVERY CELL DRIVES THE REAL BACKEND THROUGH A REAL httptest SERVER. That is
// deliberate: a unit test on the scrubber alone would pass whether or not any
// backend called it, and "the credential is absent" is satisfied just as well by
// an input that never reached the function. Each cell therefore asserts the
// request was actually SERVED, that the returned error is non-nil, and that the
// message still carries the provider's ordinary prose — before asserting the
// credential is gone.
//
// WHAT IS ACTUALLY BEING FIXED, since two thirds of this issue's surface turned
// out to be closed already and the tests should not claim otherwise:
//
//   - control-character forgery at the TERMINAL is closed by
//     termsafe.SanitizeForDisplay on both `show services ddns` surfaces (#6468);
//   - control characters in the JOURNAL are closed by slog's TextHandler, which
//     strconv.Quote-s any value carrying a byte outside printable ASCII;
//   - what NEITHER closes is a CREDENTIAL in the bytes, or 64 KiB of them
//     (httpMaxResponseBody), logged on every reconcile tick of a persistent
//     failure and retained in lastErr.
//
// So the assertions here are about the credential and the bound, not escaping.

const (
	// providerEchoURL is the shape a credential arrives in when a provider
	// echoes our own request back. The sentinel is inside the userinfo.
	providerEchoSecret = "S3CR3T-PROVIDER-6634"
	providerEchoURL    = "https://user:" + providerEchoSecret + "@prov.example/update?token=" +
		providerEchoSecret

	// providerProse is ordinary, useful provider text. The negative controls
	// require it to SURVIVE — a fix that withheld everything would pass every
	// leak assertion above and destroy the one diagnostic an operator gets.
	providerProse = "zone not found for this token"
)

// hostileBody is a provider response whose error text echoes our credentialed
// request URL back, wrapped in prose exactly as a real API would.
func hostileBody(shape string) string {
	return strings.Replace(shape, "%ECHO%", providerProse+": "+providerEchoURL, 1)
}

// decodeSentinel is the leak vector for the DECODE sites, which is a different
// shape from the render sites and NARROWER than the issue implies. Measured
// against Go's decoder rather than assumed:
//
//	number into a slice   -> "cannot unmarshal number into Go value of type []ddns.cfZone"
//	number into a string  -> "cannot unmarshal number into Go struct field cfZone.id of type string"
//	number OVERFLOWING an int field
//	                      -> "cannot unmarshal number 98765…7890 into Go struct field cfRecord.ttl of type int"
//	syntax error          -> "invalid character '9' looking for beginning of object key string"
//
// So the literal is quoted in exactly ONE case: a numeric overflow into an int
// field. A syntax error quotes a single character. That matters for what each
// cell below can honestly assert, and it is why two of them assert the render
// SHAPE rather than sentinel absence — a cell whose payload cannot produce a
// literal would pass whether or not the site was scrubbed at all, which is how
// the first version of this test let two mutations through.
const decodeSentinel = "9876543210123456789012345678901234567890"

// serveOnce answers every request with the given status + body and records that
// it was reached, so a cell cannot pass because nothing was requested.
type recordingProvider struct {
	served int
	status int
	body   string
	srv    *httptest.Server
}

func newRecordingProvider(t *testing.T, status int, body string) *recordingProvider {
	t.Helper()
	p := &recordingProvider{status: status, body: body}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.served++
		w.WriteHeader(p.status)
		_, _ = w.Write([]byte(p.body))
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func testRec() LeaseDNSRecord {
	return LeaseDNSRecord{
		FQDN:        "wan.example.net",
		Addr:        netip.MustParseAddr("203.0.113.7"),
		ForwardType: "A",
		TTL:         60,
	}
}

// ---------------------------------------------------------------------------
// The four render sites, each driven end to end.
// ---------------------------------------------------------------------------

func TestProviderResponseTextDoesNotLeakCredential_6634(t *testing.T) {
	echo := providerProse + ": " + providerEchoURL

	for _, tc := range []struct {
		name   string
		status int
		body   string
		run    func(t *testing.T, u string) error
	}{
		{
			name:   "cloudflare_envelope_message",
			status: http.StatusOK,
			body:   `{"success":false,"errors":[{"code":1001,"message":"` + echo + `"}],"result":null}`,
			run:    runCloudflare,
		},
		{
			name:   "cloudflare_decode_error",
			status: http.StatusOK,
			// Not JSON at all: the decoder quotes the offending input back.
			body: echo,
			run:  runCloudflare,
		},
		{
			name:   "route53_error_message",
			status: http.StatusBadRequest,
			body: `<?xml version="1.0"?><ErrorResponse><Error><Code>InvalidInput</Code>` +
				`<Message>` + echo + `</Message></Error></ErrorResponse>`,
			run: runRoute53,
		},
		{
			name:   "dyndns2_unrecognized_response",
			status: http.StatusOK,
			body:   echo,
			run:    runDyndns2,
		},
		{
			name:   "duckdns_unrecognized_response",
			status: http.StatusOK,
			body:   echo,
			run:    runDuckDNS,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRecordingProvider(t, tc.status, tc.body)
			err := tc.run(t, p.srv.URL)

			// NON-VACUITY. The request must actually have been served and the
			// operation must actually have failed; otherwise "the sentinel is
			// absent" is true for the wrong reason.
			if p.served == 0 {
				t.Fatal("the fake provider was never reached; this cell must drive the REAL " +
					"backend through a round trip, not assert on a helper in isolation")
			}
			if err == nil {
				t.Fatal("a provider error response must produce a non-nil error; got nil, so " +
					"every assertion below would be vacuous")
			}
			msg := err.Error()

			// THE LEAK.
			if strings.Contains(msg, providerEchoSecret) {
				t.Errorf("provider-supplied response text carried the credential into the "+
					"returned error:\n  error = %s\n"+
					"This error is logged by the daemon and retained as the provider's "+
					"lastErr. Render provider-chosen text through scrubProviderText.", msg)
			}
			// WHAT IT BECAME. Absence alone would also be satisfied by an empty
			// error, by a typo in the sentinel, or by a body that never reached
			// the render site.
			if !strings.Contains(msg, providerURLWithheld) &&
				!strings.Contains(msg, string(transportWithheld)) {
				t.Errorf("the URL-shaped token must be REPLACED by a marker (%q), or the whole "+
					"text withheld (%q) on the decode path — not merely absent; got:\n  %s",
					providerURLWithheld, string(transportWithheld), msg)
			}
			// The message must stay attributable.
			if !strings.Contains(msg, "ddns ") {
				t.Errorf("the error must still name the backend; got:\n  %s", msg)
			}
		})
	}
}

// TestProviderResponseTextKeepsOrdinaryProse_6634 is the NEGATIVE CONTROL the
// issue asks for, and it is the half that stops this fix from being blanket
// suppression. "token invalid" / "zone not found" / "rate limited" is the single
// most useful thing an operator gets out of a failing provider; a fix that
// withheld it would satisfy every leak assertion above and be a regression.
func TestProviderResponseTextKeepsOrdinaryProse_6634(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		run    func(t *testing.T, u string) error
	}{
		{
			name:   "cloudflare_envelope_message",
			status: http.StatusOK,
			body:   `{"success":false,"errors":[{"code":1001,"message":"` + providerProse + `"}],"result":null}`,
			run:    runCloudflare,
		},
		{
			name:   "route53_error_message",
			status: http.StatusBadRequest,
			body: `<?xml version="1.0"?><ErrorResponse><Error><Code>InvalidInput</Code>` +
				`<Message>` + providerProse + `</Message></Error></ErrorResponse>`,
			run: runRoute53,
		},
		{
			name:   "dyndns2_unrecognized_response",
			status: http.StatusOK,
			body:   providerProse,
			run:    runDyndns2,
		},
		{
			name:   "duckdns_unrecognized_response",
			status: http.StatusOK,
			body:   providerProse,
			run:    runDuckDNS,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRecordingProvider(t, tc.status, tc.body)
			err := tc.run(t, p.srv.URL)
			if p.served == 0 {
				t.Fatal("the fake provider was never reached")
			}
			if err == nil {
				t.Fatal("a provider error response must produce a non-nil error")
			}
			if msg := err.Error(); !strings.Contains(msg, providerProse) {
				t.Errorf("ordinary provider prose must SURVIVE — it is the diagnostic the "+
					"operator is reading. Withholding it wholesale passes every leak test and "+
					"is a regression.\n  want to contain: %q\n  got: %s", providerProse, msg)
			}
		})
	}
}

// TestProviderResponseTextIsBounded_6634 pins the half of this fix that IS a
// proof. readCappedBody admits httpMaxResponseBody (64 KiB), and every byte of a
// provider-chosen message was reaching a journal line on every reconcile tick of
// a persistent failure, plus the retained lastErr. The bound is on the RENDER,
// so it holds whatever the provider sends.
func TestProviderResponseTextIsBounded_6634(t *testing.T) {
	// A single enormous whitespace-free token, so nothing but the cap can
	// shorten it, and one that is NOT URL-shaped, so it is not withheld for a
	// different reason and the cell keeps testing the bound.
	//
	// SIZED TO FIT UNDER readCappedBody, deliberately. A message at
	// httpMaxResponseBody makes the enclosing JSON/XML document itself exceed
	// the read cap, so the body arrives truncated, the decode fails, and the
	// cell never reaches the render site it exists to test — a green that
	// measures nothing. 8 KiB is 40x the render bound and comfortably inside the
	// 64 KiB read cap, so the ONLY thing that can shorten it is this fix. The
	// read cap is a real second layer, but it bounds the BODY at 64 KiB, which
	// is three orders of magnitude past what belongs in a log line.
	huge := strings.Repeat("A", 8<<10)

	for _, tc := range []struct {
		name   string
		status int
		body   string
		run    func(t *testing.T, u string) error
	}{
		{
			name:   "cloudflare_envelope_message",
			status: http.StatusOK,
			body:   `{"success":false,"errors":[{"code":1001,"message":"` + huge + `"}],"result":null}`,
			run:    runCloudflare,
		},
		{
			name:   "route53_error_message",
			status: http.StatusBadRequest,
			body: `<?xml version="1.0"?><ErrorResponse><Error><Code>InvalidInput</Code>` +
				`<Message>` + huge + `</Message></Error></ErrorResponse>`,
			run: runRoute53,
		},
		{
			name:   "dyndns2_unrecognized_response",
			status: http.StatusOK,
			body:   huge,
			run:    runDyndns2,
		},
		{
			name:   "duckdns_unrecognized_response",
			status: http.StatusOK,
			body:   huge,
			run:    runDuckDNS,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newRecordingProvider(t, tc.status, tc.body)
			err := tc.run(t, p.srv.URL)
			if p.served == 0 {
				t.Fatal("the fake provider was never reached")
			}
			if err == nil {
				t.Fatal("a provider error response must produce a non-nil error")
			}
			msg := err.Error()
			// A generous ceiling: the bound plus this package's own fixed prefix
			// prose. The point is that it is O(maxProviderTextBytes), not
			// O(httpMaxResponseBody).
			const ceiling = maxProviderTextBytes + 256
			if len(msg) > ceiling {
				t.Errorf("a provider-chosen message reached the error at %d bytes, want at most "+
					"%d. readCappedBody admits %d, and this error is logged every reconcile "+
					"tick of a persistent failure and retained as lastErr.",
					len(msg), ceiling, httpMaxResponseBody)
			}
			if !strings.Contains(msg, providerTextTruncated) {
				t.Errorf("a bounded render must SAY it was truncated (%q), otherwise the "+
					"operator reads a silently-cut message as the whole one; got %d bytes:\n  %s",
					providerTextTruncated, len(msg), msg)
			}
		})
	}
}

// TestCloudflareErrorCountIsBounded_6634 closes the repetition bypass. The
// per-message cap is not a bound when the PROVIDER chooses how many messages the
// envelope carries: ten thousand short errors is still an unbounded log line.
func TestCloudflareErrorCountIsBounded_6634(t *testing.T) {
	var items []string
	const n = 500
	for i := 0; i < n; i++ {
		items = append(items, `{"code":1001,"message":"`+providerProse+`"}`)
	}
	body := `{"success":false,"errors":[` + strings.Join(items, ",") + `],"result":null}`

	p := newRecordingProvider(t, http.StatusOK, body)
	err := runCloudflare(t, p.srv.URL)
	if p.served == 0 {
		t.Fatal("the fake provider was never reached")
	}
	if err == nil {
		t.Fatal("a success:false envelope must produce a non-nil error")
	}
	msg := err.Error()
	const ceiling = maxCFErrors*(maxProviderTextBytes+64) + 256
	if len(msg) > ceiling {
		t.Errorf("a %d-error envelope rendered %d bytes, want at most %d: the per-message cap "+
			"is defeated by repetition when the provider picks the COUNT", n, len(msg), ceiling)
	}
	if !strings.Contains(msg, "more]") {
		t.Errorf("a count-bounded render must say how many errors were dropped; got:\n  %s", msg)
	}
}

// ---------------------------------------------------------------------------
// Backend drivers. Each builds the REAL backend against the fake provider and
// runs the operation whose failure path renders provider text.
// ---------------------------------------------------------------------------

func runCloudflare(t *testing.T, u string) error {
	t.Helper()
	b, err := newCloudflareBackend(&config.DDNSProvider{
		Name: "cf", Backend: "cloudflare", Zone: "example.net",
		APIToken: config.NewSecret("cf-token"), Server: u,
	}, &http.Client{})
	if err != nil {
		t.Fatalf("build cloudflare backend: %v", err)
	}
	return b.UpsertLease(context.Background(), testRec())
}

func runRoute53(t *testing.T, u string) error {
	t.Helper()
	b, err := newRoute53Backend(&config.DDNSProvider{
		Name: "r53", Backend: "route53", HostedZoneID: "Z123",
		AWSAccessKeyID: "AKID", AWSSecretAccessKey: config.NewSecret("aws-secret"),
		Server: u,
	}, &http.Client{})
	if err != nil {
		t.Fatalf("build route53 backend: %v", err)
	}
	return b.UpsertLease(context.Background(), testRec())
}

func runDyndns2(t *testing.T, u string) error {
	t.Helper()
	b, err := newDyndns2Backend(&config.DDNSProvider{
		Name: "dd2", Backend: "dyndns2", Server: u,
		Username: "u", Password: config.NewSecret("p"),
	}, &http.Client{})
	if err != nil {
		t.Fatalf("build dyndns2 backend: %v", err)
	}
	return b.UpsertLease(context.Background(), testRec())
}

func runDuckDNS(t *testing.T, u string) error {
	t.Helper()
	b, err := newDuckDNSBackend(&config.DDNSProvider{
		Name: "duck", Backend: "duckdns", APIToken: config.NewSecret("duck-token"),
		Server: u,
	}, &http.Client{})
	if err != nil {
		t.Fatalf("build duckdns backend: %v", err)
	}
	return b.UpsertLease(context.Background(), testRec())
}

// TestProviderDecodeScopeIsLoadBearing_6634 proves the file scope on
// json.Unmarshal is doing work in BOTH directions, because a scope that is
// vacuous either way is worse than none: one that never excludes anything is
// noise, and one that never includes anything is a gate that passes on nothing.
//
// The second half is the important one. It re-walks state.go while LYING about
// its filename, so the scope does not apply — and asserts the walk finds an
// unscrubbed json.Unmarshal render there. That is the direct evidence the scope
// is load-bearing rather than decorative: without it, adding json.Unmarshal to
// urlErrorProducers would have turned the class gate red on a site that decodes
// a file this daemon wrote itself.
func TestProviderDecodeScopeIsLoadBearing_6634(t *testing.T) {
	if !producerFileScope("json.Unmarshal", "backend_cloudflare.go") {
		t.Error("json.Unmarshal MUST be a producer in a backend file — that is where it " +
			"decodes a provider-chosen response body, which is the whole point of the entry")
	}
	if producerFileScope("json.Unmarshal", "state.go") {
		t.Error("json.Unmarshal must NOT be a producer in state.go, which decodes the " +
			"ownership state file this daemon wrote itself")
	}
	// Every other producer is unscoped.
	if !producerFileScope("url.Parse", "state.go") {
		t.Error("the scope must apply to json.Unmarshal ONLY; url.Parse is unscoped")
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "state.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse state.go: %v", err)
	}
	aliases := importAliases(file)
	unscrubbed := 0
	for _, decl := range file.Decls {
		fn, isFunc := decl.(*ast.FuncDecl)
		if !isFunc || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			// Pretend state.go is a backend file, which disables the scope.
			for _, site := range urlErrorHandlers(n, "backend_pretend.go", aliases) {
				if site.producer != "json.Unmarshal" {
					continue
				}
				unscrubbed += len(unscrubbedUses(fset, site.stmts, site.errVar, aliases))
			}
			return true
		})
	}
	if unscrubbed == 0 {
		t.Error("state.go no longer has an unscrubbed json.Unmarshal render, so the file scope " +
			"excludes nothing and should be DELETED rather than left standing — a scope that " +
			"covers no site silently exempts whatever moves into it next")
	}
}

// ---------------------------------------------------------------------------
// Staged providers: the SECOND surface of a two-call backend.
//
// A single always-fail fake reaches only the FIRST call a backend makes, and
// this issue is precisely a one-of-N-surfaces class — Route 53 renders provider
// text in listRRSet AND in change(), and Cloudflare decodes a provider body in
// do(), resolveZoneID() AND listRecords(). A fake that answers everything with
// an error never gets past listRRSet or past do(), so those later sites would
// have been "covered" by a cell that never executed them.
// ---------------------------------------------------------------------------

// stagedProvider answers each request from a per-request script, so a cell can
// let the first call succeed and fail the one it is actually testing. It records
// how many requests were served, which the cells assert on: reaching the second
// site requires TWO round trips, and a cell that saw only one never got there.
type stagedProvider struct {
	t      *testing.T
	served int
	// stages are consumed in order; the last one repeats.
	stages []stagedResponse
	srv    *httptest.Server
}

type stagedResponse struct {
	status int
	body   string
}

func newStagedProvider(t *testing.T, stages ...stagedResponse) *stagedProvider {
	t.Helper()
	p := &stagedProvider{t: t, stages: stages}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := p.stages[len(p.stages)-1]
		if p.served < len(p.stages) {
			st = p.stages[p.served]
		}
		p.served++
		w.WriteHeader(st.status)
		_, _ = w.Write([]byte(st.body))
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// TestProviderResponseTextSecondSurfaces_6634 covers the render and decode sites
// a single-response fake cannot reach. Each cell asserts the request COUNT, so
// it fails loudly if the backend short-circuits before the site under test
// rather than passing on an assertion that never ran.
func TestProviderResponseTextSecondSurfaces_6634(t *testing.T) {
	echo := providerProse + ": " + providerEchoURL

	for _, tc := range []struct {
		name string
		// stages script the responses; the site under test is driven by the last.
		stages []stagedResponse
		run    func(t *testing.T, u string) error
		// wantServed is how many round trips reaching the site requires.
		wantServed int
		// sentinel is what must not survive. Empty when the payload cannot
		// produce a provider-chosen literal at all (see decodeSentinel) — those
		// cells rely on wantMarker instead.
		sentinel string
		// wantMarker is a fixed string the scrubbed render must CONTAIN. It is
		// what makes a cell an assertion about the render rather than about the
		// payload: a decode site rendered raw does not produce it.
		wantMarker string
	}{
		{
			// Route 53 change(): the GET rrset list must SUCCEED so UpsertLease
			// proceeds to the POST, which is the site that renders Code/Message.
			name: "route53_change_error_message",
			stages: []stagedResponse{
				{http.StatusOK, `<?xml version="1.0"?><ListResourceRecordSetsResponse>` +
					`<ResourceRecordSets></ResourceRecordSets></ListResourceRecordSetsResponse>`},
				{http.StatusBadRequest, `<?xml version="1.0"?><ErrorResponse><Error>` +
					`<Code>InvalidChangeBatch</Code><Message>` + echo +
					`</Message></Error></ErrorResponse>`},
			},
			run:        runRoute53,
			wantServed: 2,
			sentinel:   providerEchoSecret,
			wantMarker: providerURLWithheld,
		},
		{
			// Cloudflare resolveZoneID(): the envelope must decode so the flow
			// reaches the SECOND json.Unmarshal, over env.Result.
			//
			// NO SENTINEL IS POSSIBLE HERE, and saying so is the point. cfZone
			// has only string fields, so no provider-chosen literal can reach
			// this decoder's error — a number yields "cannot unmarshal number
			// into Go value of type []ddns.cfZone" with no value in it. The scrub
			// at this site is UNIFORMITY, not a closed leak, so the cell asserts
			// the render SHAPE. Asserting sentinel-absence here would pass
			// whether or not the site was scrubbed, which is a green that
			// measures nothing.
			name: "cloudflare_decode_zones",
			stages: []stagedResponse{
				{http.StatusOK, `{"success":true,"errors":[],"result":` + decodeSentinel + `}`},
			},
			run:        runCloudflare,
			wantServed: 1,
			wantMarker: string(transportWithheld),
		},
		{
			// Cloudflare listRecords(): zones must resolve first, so this needs
			// two round trips to reach the THIRD json.Unmarshal.
			// cfRecord DOES carry an int field (ttl), so an overflowing ttl is a
			// real literal-bearing payload here — the one decode shape that
			// quotes provider-chosen bytes back in full.
			name: "cloudflare_decode_records",
			stages: []stagedResponse{
				{http.StatusOK, `{"success":true,"errors":[],` +
					`"result":[{"id":"ZONEID1","name":"example.net"}]}`},
				{http.StatusOK, `{"success":true,"errors":[],"result":` +
					`[{"id":"a","type":"A","name":"n","content":"c","ttl":` + decodeSentinel + `}]}`},
			},
			run:        runCloudflare,
			wantServed: 2,
			sentinel:   decodeSentinel,
			wantMarker: string(transportWithheld),
		},
		{
			// Cloudflare do(): the ENVELOPE decode. result_info.page is an int, so
			// an overflowing page is a literal-bearing payload — this is the
			// issue's own reproduction, reproduced rather than taken on trust.
			name: "cloudflare_decode_response",
			stages: []stagedResponse{
				{http.StatusOK, `{"success":true,"errors":[],"result":[],` +
					`"result_info":{"page":` + decodeSentinel + `}}`},
			},
			run:        runCloudflare,
			wantServed: 1,
			sentinel:   decodeSentinel,
			wantMarker: string(transportWithheld),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newStagedProvider(t, tc.stages...)
			err := tc.run(t, p.srv.URL)

			if p.served != tc.wantServed {
				t.Fatalf("this cell needs %d round trips to REACH the site under test; the "+
					"backend made %d. The assertions below would be measuring a different "+
					"site, or none.", tc.wantServed, p.served)
			}
			if err == nil {
				t.Fatal("the staged failure must produce a non-nil error; got nil, so every " +
					"assertion below would be vacuous")
			}
			msg := err.Error()
			if tc.sentinel != "" && strings.Contains(msg, tc.sentinel) {
				t.Errorf("provider-chosen bytes reached the returned error:\n  error = %s\n"+
					"Render provider text through scrubProviderText, and a decoder's own error "+
					"through scrubInnerError.", msg)
			}
			// WHAT IT BECAME. This is the assertion that binds the RENDER rather
			// than the payload, and it is what catches a site restored to a raw
			// render whose particular error text happens to carry no literal.
			if !strings.Contains(msg, tc.wantMarker) {
				t.Errorf("the render must go through the scrubber, observable as %q in the "+
					"message; got:\n  %s", tc.wantMarker, msg)
			}
			if len(msg) > maxProviderTextBytes+256 {
				t.Errorf("the error is %d bytes; a provider-chosen render must stay O(%d), "+
					"not O(%d):\n  %s", len(msg), maxProviderTextBytes, httpMaxResponseBody, msg)
			}
			if !strings.Contains(msg, "ddns ") {
				t.Errorf("the error must still name the backend; got:\n  %s", msg)
			}
		})
	}
}

// TestScrubProviderTextRules_6634 is the per-RULE table. The end-to-end cells
// above prove the BACKENDS call the scrubber; this proves each rule inside it
// does its own work. Without it a mutation that disabled exactly one of the
// three shapes would still be caught by a cell whose payload happens to trip
// two of them, and the matrix would report a red that localises nothing.
//
// Each row therefore trips ONE rule and only one. The echo URL used end to end
// carries both a scheme separator and userinfo, which is realistic but useless
// for localisation.
func TestScrubProviderTextRules_6634(t *testing.T) {
	const secret = "S3CR3T-RULE-6634"

	for _, tc := range []struct {
		name string
		in   string
		// wantWithheld is true when the sentinel-bearing token must be replaced.
		wantWithheld bool
		// note says which rule the row exercises, so a failure names it.
		note string
	}{
		{
			name:         "scheme_separator_only",
			in:           "invalid request https://prov.example/update?token=" + secret,
			wantWithheld: true,
			note:         `the "://" rule — a URL with no userinfo, which is the DuckDNS echo shape`,
		},
		{
			name:         "userinfo_only_no_scheme",
			in:           "rejected credentials user:" + secret + "@prov.example",
			wantWithheld: true,
			note:         "the userinfo rule — a ':' before an '@', with no scheme to trip the first rule",
		},
		{
			name:         "percent_encoded_only",
			in:           "bad target https%3A%2F%2Fuser%3A" + secret + "%40prov.example",
			wantWithheld: true,
			note:         "the %XX rule — the encoded form, which trips neither of the other two",
		},
		{
			name:         "bare_email_survives",
			in:           "quota exceeded, contact support@prov.example",
			wantWithheld: false,
			note:         "a bare user@host carries no secret; withholding it would eat legitimate prose",
		},
		{
			name:         "percentage_survives",
			in:           "you are at 80% of quota",
			wantWithheld: false,
			note:         "a '%' not followed by two hex digits is not an escape",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scrubProviderText(tc.in)

			// NON-VACUITY: the input must have carried something to withhold, and
			// the surrounding prose must survive either way — a row that passes
			// because everything was withheld is not testing a rule.
			firstWord := strings.Fields(tc.in)[0]
			if !strings.Contains(got, firstWord) {
				t.Fatalf("the leading prose %q must survive; scrubbing everything makes this "+
					"row pass for the wrong reason.\n  in:  %q\n  got: %q", firstWord, tc.in, got)
			}

			if tc.wantWithheld {
				if strings.Contains(got, secret) {
					t.Errorf("%s: the credential-bearing token was rendered.\n  in:  %q\n  got: %q",
						tc.note, tc.in, got)
				}
				if !strings.Contains(got, providerURLWithheld) {
					t.Errorf("%s: the token must be REPLACED by %q, not merely dropped — the "+
						"operator has to see that something was withheld.\n  got: %q",
						tc.note, providerURLWithheld, got)
				}
				return
			}
			if got != tc.in {
				t.Errorf("%s: this text carries no credential and must pass through unchanged.\n"+
					"  in:  %q\n  got: %q", tc.note, tc.in, got)
			}
		})
	}
}

// TestScrubProviderTextEmptyIsDistinguishable_6634 keeps "the provider said
// nothing" separable from "the provider's text was withheld". They are different
// diagnoses — one means an empty body, the other means the body was a URL — and
// collapsing them would send an operator looking in the wrong place.
func TestScrubProviderTextEmptyIsDistinguishable_6634(t *testing.T) {
	if got := scrubProviderText(""); got != providerTextEmpty {
		t.Errorf("empty provider text must render %q; got %q", providerTextEmpty, got)
	}
	if got := scrubProviderText("   \n\t "); got != providerTextEmpty {
		t.Errorf("whitespace-only provider text must render %q; got %q", providerTextEmpty, got)
	}
	if got := scrubProviderText("https://user:pw@h/"); got == providerTextEmpty {
		t.Errorf("a withheld URL must NOT render as %q — that reads as an empty response",
			providerTextEmpty)
	}
}
