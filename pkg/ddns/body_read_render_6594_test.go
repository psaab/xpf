package ddns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The round-10 review found doRequest hardening ONE of its two adjacent error
// returns. client.Do's error was scrubbed; readCappedBody's, four lines below,
// was rendered with %w. The structural gate could not see it — readCappedBody
// was not a urlErrorProducer, so no site was built for `rerr` — so the package
// was green over a verbatim render inside the very function the scrubber
// exists to protect.
//
// These are the behavioural half. The structural half (readCappedBody as a
// producer, scrubInnerError as a renderer) lives in
// url_render_class_6545_test.go and is what stops the shape returning.

// bodyErrRoundTripper answers with a real response whose BODY read fails, which
// is the only way to reach readCappedBody's error return. The caller supplies
// the *http.Client throughout this package, so a caller that owns RoundTrip
// owns resp.Body too — the same adversary model rounds 7 and 8 were built for.
type bodyErrRoundTripper struct{ readErr error }

func (rt bodyErrRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(errReader{rt.readErr}),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestBodyReadErrorIsClassifiedNotEchoed pins the credential half: a body-read
// error that echoes the request URL must not reach the returned error, because
// the daemon logs that string verbatim.
func TestBodyReadErrorIsClassifiedNotEchoed(t *testing.T) {
	const secret = "SUPERSECRET"
	hostile := errors.New("upstream read of http://prov.example/update?token=" + secret + " failed")
	client := &http.Client{Transport: bodyErrRoundTripper{readErr: hostile}}

	_, _, err := CheckIP(context.Background(), client, "https://prov.example/ip", true, nil)
	if err == nil {
		t.Fatal("a failing body read reported success")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("body-read error echoed the credential: %v", err)
	}
	if strings.Contains(err.Error(), "prov.example/update") {
		t.Fatalf("body-read error echoed a provider-supplied URL: %v", err)
	}
}

// TestBodyReadErrorIsStableAcrossConnections pins the availability half, which
// is the part with no adversary at all. A mid-body RST yields a *net.OpError
// whose text embeds the EPHEMERAL LOCAL PORT, so it differs on every
// connection. The daemon keys a process-lifetime sync.Map on this string to log
// "once per (provider, error)"; a varying string mints a new key and a new WARN
// every reconcile tick, forever, and the map is never pruned.
//
// Distinct transport-level texts must therefore collapse to the SAME rendered
// error, which is what classification buys and what %w did not.
func TestBodyReadErrorIsStableAcrossConnections(t *testing.T) {
	renders := make(map[string]struct{})
	for _, port := range []string{"50876", "50886", "50894"} {
		rt := bodyErrRoundTripper{readErr: &net_OpErrorStub{
			text: "read tcp 127.0.0.1:" + port + "->127.0.0.1:41397: read: connection reset by peer",
		}}
		_, _, err := CheckIP(context.Background(), &http.Client{Transport: rt},
			"https://prov.example/ip", true, nil)
		if err == nil {
			t.Fatal("a failing body read reported success")
		}
		renders[err.Error()] = struct{}{}
	}
	if len(renders) != 1 {
		keys := make([]string, 0, len(renders))
		for k := range renders {
			keys = append(keys, k)
		}
		t.Fatalf("three connection-varying read errors produced %d distinct rendered "+
			"strings, want 1; the daemon keys a never-pruned sync.Map on this text, so "+
			"each distinct string is a permanent entry and a fresh WARN every tick:\n%s",
			len(renders), strings.Join(keys, "\n"))
	}
}

// net_OpErrorStub stands in for a *net.OpError without depending on the kernel
// producing a real RST. Only its text varies, which is the property under test.
type net_OpErrorStub struct{ text string }

func (e *net_OpErrorStub) Error() string { return e.text }

// TestCyclicURLErrorDoesNotOverflowTheStack pins the mutual recursion between
// scrubURLError and scrubInnerError. maxUnwrapDepth's comment claimed to bound
// "every chain walk in this file"; it bounded findRedirectRefusal and the
// Location-prefix loop but NOT this pair, so a caller-supplied *url.Error whose
// Err points at itself overflowed the stack.
//
// That is a `fatal error`, not a panic: recover() does not catch it and the
// whole xpfd process dies. Unreachable from production — net/http never builds
// a cyclic *url.Error — but the guard is cheap and the claim should be true.
func TestCyclicURLErrorDoesNotOverflowTheStack(t *testing.T) {
	const secret = "SUPERSECRET"
	ue := &url.Error{Op: "Get", URL: "http://prov.example/?p=" + secret}
	ue.Err = ue

	got := scrubURLError(ue)

	if strings.Contains(got, secret) {
		t.Fatalf("cyclic *url.Error leaked the credential: %s", got)
	}
	if !strings.Contains(got, string(transportWithheld)) {
		t.Fatalf("cyclic *url.Error did not terminate at the depth bound; got: %s", got)
	}
}

// TestDeeplyNestedURLErrorDoesNotOverflowTheStack is the non-cyclic sibling:
// a finite but very deep nest reaches the same recursion by a different route,
// so a fix that special-cased self-reference would pass the test above and
// still die here.
func TestDeeplyNestedURLErrorDoesNotOverflowTheStack(t *testing.T) {
	// SAME VACUITY SHAPE as TestDeepUnwrapChainTerminates, found in the sibling
	// by round 15 after the first was fixed: an unrecognised leaf renders
	// transportWithheld, which is ALSO classifyTransportError's ordinary
	// fallback, so the assertion held even with the depth checks removed — the
	// newer entry-tree guard returned first and the comment's claim about which
	// bound it tests was false.
	//
	// A RECOGNISED leaf separates the outcomes: terminating at a bound yields
	// withheld, while walking the whole nest reaches io.ErrUnexpectedEOF and
	// yields transportEOF.
	const secret = "SUPERSECRET"
	var err error = io.ErrUnexpectedEOF
	for i := 0; i < 100_000; i++ {
		err = &url.Error{Op: "Get", URL: "http://prov.example/?p=" + secret, Err: err}
	}

	got := scrubURLError(err)

	if strings.Contains(got, secret) {
		t.Fatalf("deeply nested *url.Error leaked the credential: %s", got)
	}
	if got == string(transportEOF) {
		t.Fatalf("deep nest classified as %q: the walk reached the recognised leaf, "+
			"so nothing bounded it", got)
	}
	if !strings.Contains(got, string(transportWithheld)) {
		t.Fatalf("deeply nested *url.Error did not terminate at a bound; got: %s", got)
	}
}

// --- round 12: the stdlib's own traversal ---
//
// Round 11 bounded this package's recursion between scrubURLError and
// scrubInnerError and stopped there. That was not the whole walk: errors.Is and
// errors.As traverse the tree themselves, dispatching to the error's Unwrap,
// and Unwrap belongs to the caller. The round-11 cyclic test could not see this
// because its root was directly a *url.Error, so errors.As matched on the first
// node and never followed Unwrap at all.

// selfUnwrapError unwraps to itself. errors.As spins on it forever.
type selfUnwrapError struct{}

func (*selfUnwrapError) Error() string   { return "hostile" }
func (e *selfUnwrapError) Unwrap() error { return e }

// selfMultiUnwrapError is the Unwrap() []error form. The stdlib walks a
// multi-error tree RECURSIVELY, so a self-cycle here overflows the stack —
// a fatal error, which recover() cannot catch, taking the whole daemon down.
type selfMultiUnwrapError struct{}

func (*selfMultiUnwrapError) Error() string { return "hostile-multi" }
func (e *selfMultiUnwrapError) Unwrap() []error {
	return []error{e}
}

func TestSelfUnwrappingErrorTerminates(t *testing.T) {
	// The failure mode is a HANG, so the value of this test is that it returns
	// at all; `go test` timing out is the red.
	for name, err := range map[string]error{
		"Unwrap() error":   &selfUnwrapError{},
		"Unwrap() []error": &selfMultiUnwrapError{},
	} {
		got := scrubInnerError(err)
		if got != string(transportWithheld) {
			t.Errorf("%s: scrubInnerError = %q, want %q — a self-cycle must be "+
				"withheld, not classified", name, got, transportWithheld)
		}
		if gotURL := scrubURLError(err); gotURL != string(transportWithheld) {
			t.Errorf("%s: scrubURLError = %q, want %q", name, gotURL, transportWithheld)
		}
	}
}

// TestDeepUnwrapChainTerminates is the non-cyclic sibling: a finite chain long
// enough to matter must also be withheld rather than walked, since the budget
// cannot tell the two apart and should not try.
func TestDeepUnwrapChainTerminates(t *testing.T) {
	// VACUITY TRAP, found in review: asserting only that a deep chain renders
	// transportWithheld proves nothing, because that is ALSO
	// classifyTransportError's ordinary fallback for an unrecognised error. With
	// errTreeWithinBound removed from both entry points this test still passed —
	// it just walked the whole 10k chain first and fell through to the same
	// string.
	//
	// So the leaf is a RECOGNISED error. A bounded walk must refuse the tree and
	// return withheld; an UNBOUNDED walk reaches io.ErrUnexpectedEOF and returns
	// transportEOF. The two outcomes are now distinguishable, which is what makes
	// this bind.
	var err error = io.ErrUnexpectedEOF
	for i := 0; i < 10_000; i++ {
		err = fmt.Errorf("wrap %d: %w", i, err)
	}
	got := scrubInnerError(err)
	if got == string(transportEOF) {
		t.Fatalf("deep chain classified as %q: the traversal was NOT bounded — it "+
			"walked 10k frames to the recognised leaf. The bound must refuse the "+
			"tree before any errors.Is/As sees it.", got)
	}
	if got != string(transportWithheld) {
		t.Errorf("deep chain: scrubInnerError = %q, want %q", got, transportWithheld)
	}
}

// TestBoundedChainStillClassifies is the NEGATIVE CONTROL for the budget: an
// ordinary shallow wrap must still be classified normally, so the guard cannot
// pass by withholding everything.
func TestBoundedChainStillClassifies(t *testing.T) {
	err := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", io.ErrUnexpectedEOF))
	if got := scrubInnerError(err); got != string(transportEOF) {
		t.Errorf("shallow wrapped EOF = %q, want %q — the depth budget is "+
			"withholding errors it should be classifying", got, transportEOF)
	}
}

// nilFanoutError returns N nil children from Unwrap() []error. The budget used
// to charge only for non-nil children, because walk(nil) returns immediately
// without spending any — so a root handing back maxUnwrapDepth+1 nil slots
// passed the guard, after which every stdlib traversal scanned that fanout.
// Fanout is work whether or not the slot is nil.
type nilFanoutError struct{ n int }

func (*nilFanoutError) Error() string { return "fanout" }
func (e *nilFanoutError) Unwrap() []error {
	return make([]error, e.n)
}

func TestNilFanoutSpendsBudget(t *testing.T) {
	if errTreeWithinBound(&nilFanoutError{n: maxUnwrapDepth + 1}) {
		t.Error("a root with maxUnwrapDepth+1 NIL children passed the budget; nil " +
			"slots must be charged or the stdlib still scans an unbounded fanout")
	}
	// NEGATIVE CONTROL: an ordinary small fanout must still be accepted, so the
	// per-slot charge cannot pass by rejecting every multi-error.
	if !errTreeWithinBound(&nilFanoutError{n: 3}) {
		t.Error("a 3-slot nil fanout was rejected; the per-slot charge is over-broad")
	}
}

// TestRefusedRedirectRendersStablyAcrossHosts is the MAJOR from round 14, and
// the fourth instance of the same shape in this file's history: doRequest has
// two error returns four lines apart, and hardening one left the other
// producing a per-request string.
//
// A refused cross-host redirect used to render the provider-chosen Location
// TWICE — once as scrubURLError's target (net/http sets url.Error.URL to the
// Location) and once inside the refusal prose. The daemon keys a never-pruned,
// process-lifetime sync.Map on that string to warn once per (provider, error),
// so a provider redirecting to per-request hostnames minted a fresh key and a
// fresh WARN every 30s tick, forever. No adversary needed: a provider 30x-ing
// to per-request edge hostnames does it by accident.
func TestRefusedRedirectRendersStablyAcrossHosts(t *testing.T) {
	const secret = "SUPERSECRET"
	renders := make(map[string]struct{})
	for i := 0; i < 5; i++ {
		to := fmt.Sprintf("https://h%d.%s.evil.example/x", i, secret)
		refusal := &redirectRefusal{
			reason: redirectReasonCrossHost,
			from:   mustParseURL(t, "https://prov.example/upd"),
			to:     mustParseURL(t, to),
		}
		// Exactly the shape net/http produces: the refusal wrapped in a
		// *url.Error whose URL is the refused Location.
		got := scrubURLError(&url.Error{Op: "Get", URL: to, Err: refusal})
		if strings.Contains(got, secret) {
			t.Fatalf("refused redirect leaked the credential-shaped host: %s", got)
		}
		renders[got] = struct{}{}
	}
	if len(renders) != 1 {
		keys := make([]string, 0, len(renders))
		for k := range renders {
			keys = append(keys, k)
		}
		t.Fatalf("five refused redirects to DIFFERENT provider hosts produced %d "+
			"distinct rendered strings, want 1. The daemon keys a never-pruned "+
			"sync.Map on this text, so each distinct string is a permanent entry "+
			"and a fresh WARN every 30s tick:\n%s", len(renders), strings.Join(keys, "\n"))
	}
}

// TestRefusedRedirectAfterAnAllowedHopIsStable is round 15's MAJOR: the refusal
// rendered `via[len(via)-1]` as its FROM host, and same-host comparison is
// deliberately lenient about case, a trailing dot and the default port. So a
// provider could take an ALLOWED first hop to its own chosen spelling of our
// host, and only then attempt the cross-host one — putting a provider-chosen
// string back into the message and defeating the daemon's dedup again, one hop
// further out than the direct case.
//
// via[0] is the URL this package built from configuration, so it is stable
// whatever spelling the provider echoes back.
func TestRefusedRedirectAfterAnAllowedHopIsStable(t *testing.T) {
	renders := make(map[string]struct{})
	for _, spelling := range []string{
		"https://prov.example/upd",
		"https://Prov.Example/upd",
		"https://PROV.EXAMPLE/upd",
		"https://prov.example.:443/upd",
		"https://prov.example:443/upd",
	} {
		origin := httptest.NewRequest(http.MethodGet, "https://prov.example/upd", nil)
		hop := httptest.NewRequest(http.MethodGet, spelling, nil)
		next := httptest.NewRequest(http.MethodGet, "https://evil.example/x", nil)

		err := guardRedirect(next, []*http.Request{origin, hop})
		if err == nil {
			t.Fatalf("spelling %q: a cross-host hop must be refused", spelling)
		}
		renders[err.Error()] = struct{}{}
	}
	if len(renders) != 1 {
		keys := make([]string, 0, len(renders))
		for k := range renders {
			keys = append(keys, k)
		}
		t.Fatalf("five provider spellings of our OWN host produced %d distinct "+
			"refusal strings, want 1 — the refusal is rendering a provider-echoed "+
			"value, which defeats the never-pruned dedup map:\n%s",
			len(renders), strings.Join(keys, "\n"))
	}
}
