package ddns

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// mustParseURL is a test helper for building the *url.URL fields a
// redirectRefusal carries.
func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return u
}

// url_render_class_6545_test.go: the CLASS gate for URL rendering in pkg/ddns
// (#6545 review round 6).
//
// The first five rounds of this PR each closed ONE surface and left another
// standing — the parse-failure branch, then the validator refusals, then the
// fragment on the transport path. Each fix was correct and each time the next
// review found the same bug one call site over. This file stops that by
// asserting the PROPERTY rather than the instances:
//
//	No error leaving pkg/ddns renders more of a URL than SCHEME://HOST,
//	and every URL-bearing error goes through scrubURLError.
//
// It is enforced from both ends:
//
//   - BEHAVIOURALLY — scrubURLError's output is pinned by EXACT EQUALITY, not by
//     probing for a sentinel, so a field that is neither dropped nor expected
//     fails the gate whether or not anyone thought to plant a secret in it. Plus
//     end-to-end drives through every backend's build-request path.
//   - STRUCTURALLY — TestDDNSURLErrorRendersGoThroughScrubber walks the AST of
//     every production file in the package and fails any site that takes an
//     error from http.NewRequest / url.Parse / client.Do and renders it without
//     the scrubber, and TestClientDoHasExactlyOneCallSite denies the move that
//     would put a round trip somewhere the walk cannot see.
//
// WHAT THE STRUCTURAL HALF IS AND IS NOT (round 7). It is a TRIPWIRE on the
// shapes this leak has actually taken six times running. It is NOT a proof. A
// reviewer walked round 6's version with an aliased import, a `do := client.Do`
// method value, a non-adjacent guard, and an errors.As extraction; those four
// are closed now (importAliases, the .Do site count, reach-based sites,
// extraction taint) but the underlying limit stands — an AST walk cannot follow
// a value through a helper's return, and nothing here claims otherwise. The
// count gate is what makes that limit bite: you cannot introduce the helper
// without failing it.
//
// The BEHAVIOURAL half is the load-bearing one, and it is the half to extend
// first when a new leak shape turns up.
//
// The two MAJORs of round 6, both closed here:
//
//  1. scrubURLError preserved Path. The generic backend accepts %p ANYWHERE in
//     its template, so the supported template "https://prov.example/update/%p"
//     put the expanded password into the transport error — which the Surface A
//     observer logs AND keeps as its process-lifetime dedup key. A checkip-url
//     with an API key in its path had the same exposure.
//  2. The DuckDNS, Cloudflare and both Route 53 build-request paths %w-wrapped
//     the raw *url.Error, which re-embeds the complete offending URL. All three
//     take their endpoint from the `server` leaf UNPARSED, so a credentialed,
//     malformed server value was rendered verbatim.

// buildURLSentinel sits where an operator credential would in a `server` leaf.
// It deliberately begins with a NON-hex byte pair after the '%' so that a URL
// carrying it as "#%<sentinel>" fails url.Parse with an escape error — the
// build-request failure these paths are reached by.
const buildURLSentinel = "BUILD-URL-MUST-NOT-LOG"

// poisonedServer is a `server` value that is credential-bearing AND unparseable:
// url.Parse rejects the fragment's "%BU" escape, and (*url.Error).Error() then
// re-embeds the WHOLE string, sentinel included.
const poisonedServer = "https://prov.example/#%" + buildURLSentinel

// pathSentinel sits where an operator credential would in a URL PATH — the
// position scrubURLError used to preserve.
const pathSentinel = "PATH-CREDENTIAL-MUST-NOT-LOG"

// hostSentinel sits where round 7 found the credential could still reach: INSIDE
// url.URL.Host. It is deliberately spelled with only characters that are legal
// in a hostname label and in an RFC 6874 zone id, so a URL carrying it PARSES
// and reaches the render path — a sentinel that made the URL invalid would test
// the withhold-unparseable branch instead and prove nothing about the host.
const hostSentinel = "ZONE-PASSWORD-MUST-NOT-LOG"

// The fixed notes scrubURLError appends when it withholds part of the target.
// Written out as literals, not built by calling the code under test, so a change
// to the rendering has to be made HERE too rather than tracking itself.
const (
	zoneNote   = " (IPv6 zone id withheld)"
	hostNote   = " (host withheld: not a plain host name)"
	schemeNote = " (url withheld: scheme is not http or https)"
)

// wantSyntheticRender is how the classifier renders errSyntheticTransport: an
// error whose CLASS it cannot recognise is withheld to a FIXED CONSTANT. Round 7
// appended the Go type via %T on the reasoning that a type name is a
// compile-time symbol; round 8 removed that — reflect.StructOf builds a runtime
// type whose name embeds an input-derived struct TAG, so %T is an input channel.
// A literal here, so this pins the contract instead of restating the code.
const wantSyntheticRender = "transport error withheld"

// forgedIsError is Codex's round-8 attack in its purest form: an error that
// LIES about its identity. errors.Is dispatches to this method, so any check of
// the shape "is this error one of ours?" answers YES — and round 7 then printed
// Error() verbatim as a trusted refusal.
//
// This is reachable by construction: CheckIP takes a caller-supplied
// *http.Client, so its RoundTripper's errors are arbitrary values.
type forgedIsError struct{ text string }

func (e forgedIsError) Error() string      { return e.text }
func (e forgedIsError) Is(error) bool      { return true }
func (e forgedIsError) As(target any) bool { return false }
func (e forgedIsError) Unwrap() error      { return nil }
func (e forgedIsError) Timeout() bool      { return true }
func (e forgedIsError) Temporary() bool    { return true }
func (e forgedIsError) private()           {}

var _ error = forgedIsError{}

// CodexBaseError is the embedded base for the reflect.StructOf attack. It must
// be EXPORTED (reflect.StructOf panics on an unexported field name, and an
// embedded field is named for its type) and must carry exactly ONE method —
// reflect refuses to promote from an embedded type with methods when the struct
// has more than one field, and a fatter base hits other limits. Method
// promotion through StructOf is what makes the built type satisfy `error` and
// therefore reach the renderer.
type CodexBaseError struct{}

func (CodexBaseError) Error() string { return "codex base" }

// backendHTTPSourceFile is the file the transportReason gate reads.
const backendHTTPSourceFile = "backend_http.go"

// transportClassifiers are the functions whose EVERY return must name a
// declared transportReason constant. classifyTransportError may additionally
// return a direct call to one of these, which is how errnoReason is reached.
var transportClassifiers = map[string]bool{
	"classifyTransportError": true,
	"errnoReason":            true,
}

// TestClassifyTransportErrorReturnsOnlyConstants is the round-8 structural
// gate, and the direct analogue of TestURLParseCauseReturnsOnlyDeclaredConstants
// next door.
//
// The behavioural gates catch the leaks someone thought to plant. This one
// covers branches no input reaches, and it is what makes the closed
// transportReason type mean something: the type alone stops `return text` from
// COMPILING, but an explicit transportReason(x) conversion compiles fine, and
// round 7 shipped THREE of them — errnoReason's Errno.Error() passthrough, the
// OpError op+net concatenation, and the %T fallback. Every one turned out to be
// an input channel.
//
// IT RESOLVES, IT DOES NOT NAME-MATCH. A local variable shadowing a constant
// name would satisfy a string comparison while returning arbitrary text, which
// is exactly how the reviewer walked the first version of the urlParseCause
// gate. go/types is asked what each returned identifier actually IS.
func TestClassifyTransportErrorReturnsOnlyConstants(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, backendHTTPSourceFile, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", backendHTTPSourceFile, err)
	}

	// Type-check backend_http.go on its own. Import errors are EXPECTED and
	// ignored; what must work is package-scope resolution of our own constants.
	info := &types.Info{
		Defs: map[*ast.Ident]types.Object{},
		Uses: map[*ast.Ident]types.Object{},
	}
	conf := types.Config{
		Importer:                 unresolvedImporter{},
		Error:                    func(error) {},
		DisableUnusedImportCheck: true,
	}
	pkg, _ := conf.Check("ddns", fset, []*ast.File{file}, info)
	if pkg == nil {
		t.Fatal("go/types returned no package for " + backendHTTPSourceFile +
			"; the gate cannot resolve identifiers and must not silently pass")
	}
	if len(info.Uses) == 0 {
		t.Fatal("go/types resolved no identifier uses in " + backendHTTPSourceFile +
			"; the gate would pass vacuously")
	}

	// Non-vacuity of the resolution: transportReason must be a named type in
	// package scope and at least one of its constants must resolve.
	reasonType := pkg.Scope().Lookup("transportReason")
	if _, isType := reasonType.(*types.TypeName); !isType {
		t.Fatalf("package scope does not resolve transportReason to a type (got %T); "+
			"the resolution this gate depends on is broken", reasonType)
	}
	declared := 0
	for _, name := range pkg.Scope().Names() {
		c, isConst := pkg.Scope().Lookup(name).(*types.Const)
		if isConst && types.Identical(c.Type(), reasonType.Type()) {
			declared++
		}
	}
	if declared == 0 {
		t.Fatal("found no transportReason constants; this gate cannot work and must not " +
			"silently pass")
	}

	checked := map[string]int{}
	for _, decl := range file.Decls {
		fn, isFunc := decl.(*ast.FuncDecl)
		if !isFunc || fn.Recv != nil || !transportClassifiers[fn.Name.Name] {
			continue
		}
		// The signature is half the invariant: widening the result to `string`
		// would re-open the bare `return text` form the closed type forbids.
		if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
			t.Fatalf("%s must return exactly one result", fn.Name.Name)
		}
		resultType, isIdent := fn.Type.Results.List[0].Type.(*ast.Ident)
		if !isIdent || resultType.Name != "transportReason" {
			t.Fatalf("%s returns %v, want the closed transportReason type", fn.Name.Name,
				fn.Type.Results.List[0].Type)
		}
		// A NAMED result admits a naked `return`, which carries whatever the body
		// last assigned to that name — attacker text included — and presents NO
		// expression for the walk below to inspect. Requiring the result to be
		// unnamed makes that shape a COMPILE error instead of one more form this
		// gate has to recognise.
		if len(fn.Type.Results.List[0].Names) != 0 {
			t.Fatalf("%s declares a NAMED result; it must be unnamed. A named result "+
				"permits a bare `return` whose value never appears as an expression, "+
				"so no amount of return-inspection can see what it carries.",
				fn.Name.Name)
		}

		ast.Inspect(fn.Body, func(n ast.Node) bool {
			// Do NOT descend into a closure: its returns are the closure's, and
			// counting them would let one satisfy the floor below while the real
			// body was gutted.
			if _, isFuncLit := n.(*ast.FuncLit); isFuncLit {
				return false
			}
			ret, isReturn := n.(*ast.ReturnStmt)
			if !isReturn {
				return true
			}
			pos := fset.Position(ret.Pos())
			// SKIPPING a return that is not exactly one expression is how a gate
			// stops binding: the unnamed-result check above makes the zero-result
			// form uncompilable, and this makes the skip itself impossible to
			// reintroduce silently if that check is ever relaxed.
			if len(ret.Results) != 1 {
				t.Errorf("%s: %s returns %d expressions, want exactly 1. A return "+
					"this gate does not inspect is a return that carries anything.",
					pos, fn.Name.Name, len(ret.Results))
				return true
			}
			checked[fn.Name.Name]++

			// Form (ii): a direct call to a sibling classifier, itself gated.
			if call, isCall := ret.Results[0].(*ast.CallExpr); isCall {
				callee, isCalleeIdent := call.Fun.(*ast.Ident)
				if isCalleeIdent && transportClassifiers[callee.Name] {
					// The NAME is not the function. A local closure
					// `errnoReason := func(e error) transportReason { return
					// transportReason(e.Error()) }` spells a gated classifier
					// exactly, and its body is skipped above as a FuncLit — so
					// spelling alone would wave through the one shape the FuncLit
					// skip cannot see. Resolve the identifier through go/types and
					// require it to BE the package-scope func of that name.
					obj := info.Uses[callee]
					declared, isFuncObj := obj.(*types.Func)
					if isFuncObj && pkg.Scope().Lookup(callee.Name) == declared {
						return true
					}
					t.Errorf("%s: %s returns a call to %q, which go/types resolves "+
						"to %T rather than the package-scope classifier of that "+
						"name. A local closure or variable that merely SPELLS a "+
						"gated classifier shadows it, and its body is skipped as a "+
						"FuncLit — so its return is never inspected at all.",
						pos, fn.Name.Name, callee.Name, obj)
					return true
				}
				t.Errorf("%s: %s returns a call that is not a gated classifier. "+
					"Only %v may be returned as calls; everything else must be a "+
					"declared constant.", pos, fn.Name.Name, sortedKeys(transportClassifiers))
				return true
			}

			// Form (i): a bare identifier resolving to a package-scope
			// transportReason CONSTANT.
			id, isIdentResult := ret.Results[0].(*ast.Ident)
			if !isIdentResult {
				t.Errorf("%s: %s returns %T, not a bare identifier. A conversion, a "+
					"concatenation or a fmt.Sprintf here is how an error's own text "+
					"gets out — round 7 shipped three of them (Errno.Error(), "+
					"OpError op+net, and %%T) and all three were input channels.",
					pos, fn.Name.Name, ret.Results[0])
				return true
			}
			obj := info.Uses[id]
			c, isConst := obj.(*types.Const)
			if !isConst {
				t.Errorf("%s: %s returns %q, which go/types resolves to %T, not a "+
					"constant. A local variable that merely SPELLS a constant's name "+
					"shadows it and carries arbitrary text out.", pos, fn.Name.Name, id.Name, obj)
				return true
			}
			if c.Parent() != pkg.Scope() {
				t.Errorf("%s: %s returns %q, a constant that is NOT package-scope; "+
					"a local const declared from input satisfies a name check but not this one",
					pos, fn.Name.Name, id.Name)
				return true
			}
			if !types.Identical(c.Type(), reasonType.Type()) {
				t.Errorf("%s: %s returns %q of type %v, want transportReason",
					pos, fn.Name.Name, id.Name, c.Type())
			}
			return true
		})
	}

	// Non-vacuity floor: both classifiers must have been found and walked.
	for name := range transportClassifiers {
		if checked[name] == 0 {
			t.Errorf("no single-value returns were checked in %s. If it was renamed or "+
				"inlined, move this gate with it rather than letting it pass vacuously.", name)
		}
	}
}

// sortedKeys renders a set deterministically for an error message.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestScrubURLErrorRendersOnlySchemeAndHost pins the scrub by EXACT EQUALITY.
//
// This is deliberately not a "does the output contain my sentinel" test. Those
// only find the leak you already thought of, and that is precisely how Path
// survived three rounds of fragment/query/userinfo fixes. Asserting the whole
// rendered string means any field that starts surviving — a new net/url field,
// a reinstated Path clear, an Opaque pass-through — fails here.
func TestScrubURLErrorRendersOnlySchemeAndHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		want string // the ONLY URL text allowed out
		note string // the fixed note naming whatever was withheld
	}{
		{"plain", "https://prov.example", "https://prov.example", ""},
		{"path", "https://prov.example/update/" + pathSentinel, "https://prov.example", ""},
		{"generic %p expanded into the path", "https://prov.example/update/" + pathSentinel + "?x=1",
			"https://prov.example", ""},
		{"query", "https://prov.example/upd?token=" + pathSentinel, "https://prov.example", ""},
		{"fragment", "https://prov.example/upd#token=" + pathSentinel, "https://prov.example", ""},
		{"userinfo", "https://user:" + pathSentinel + "@prov.example/upd", "https://prov.example", ""},
		{"everything at once", "https://user:" + pathSentinel + "@prov.example:8443/a/" +
			pathSentinel + "?q=" + pathSentinel + "#f=" + pathSentinel, "https://prov.example:8443", ""},
		{"host and port retained", "https://prov.example:8443/x", "https://prov.example:8443", ""},

		// --- round 7: Host is not credential-free -----------------------------
		// Each of these reaches Host through a SUPPORTED generic template or a
		// provider Location, and each was rendered verbatim before the grammar.
		{"ipv6 zone id", "https://[fe80::1%25" + hostSentinel + "]/upd",
			"https://[fe80::1]", zoneNote},
		{"ipv6 zone id with port", "https://[fe80::1%25" + hostSentinel + "]:8443/upd",
			"https://[fe80::1]:8443", zoneNote},
		{"raw non-ascii byte decoded into host", "https://ex%FFample.com/upd", "https:", hostNote},
		{"percent-decoded utf8 host", "https://ex%C3%A9mple.com/upd", "https:", hostNote},
		{"empty label", "https://prov..example/upd", "https:", hostNote},
		// A port outside 1..65535 is dropped on its own: the host still fits the
		// grammar, and erasing it would cost diagnosis for nothing.
		{"port out of range", "https://prov.example:99999/upd", "https://prov.example", ""},
		{"opaque", "mailto:" + pathSentinel + "@prov.example", "", schemeNote},
		{"non-http scheme with a host", "ftp://" + hostSentinel + ".example/upd", "", schemeNote},

		// Over-reach floor: legitimate hosts must still be identifiable.
		{"ipv4 literal", "https://192.0.2.7:8443/upd", "https://192.0.2.7:8443", ""},
		{"ipv6 literal, no zone", "https://[2001:db8::1]:8443/upd", "https://[2001:db8::1]:8443", ""},
		{"underscore label", "https://ddns_v2.prov.example/upd", "https://ddns_v2.prov.example", ""},
		{"trailing root dot", "https://prov.example./upd", "https://prov.example.", ""},
		{"mixed case preserved", "https://Prov.EXAMPLE/upd", "https://Prov.EXAMPLE", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scrubURLError(&url.Error{Op: "Get", URL: tc.url, Err: errSyntheticTransport})
			want := fmt.Sprintf("Get %q%s: %s", tc.want, tc.note, wantSyntheticRender)
			if got != want {
				t.Fatalf("scrubURLError(%q):\n  got  = %q\n  want = %q\n"+
					"The safe URL must be rebuilt by ALLOWLIST at BOTH levels. Field level: a "+
					"fresh scheme+host, so User, Path, RawPath, RawQuery, Fragment, RawFragment, "+
					"Opaque and anything net/url adds later are absent by construction. Clearing "+
					"fields one at a time is a blocklist and it already missed Path once.\n"+
					"CHARACTER level (round 7): Host is NOT credential-free — it carries an IPv6 "+
					"zone id, a reg-name label, decoded non-ASCII bytes and a port, all of which "+
					"a supported generic template can put a %%p-expanded password into. Render it "+
					"through safeHostText's closed grammar, not verbatim.",
					tc.url, got, want)
			}
		})
	}
}

// TestScrubURLErrorWithholdsUnparseableURL covers the input the build-request
// paths are DEFINED by: a URL that does not parse. The old helper fell back to
// ue.URL verbatim in that case, which was survivable only while the helper was
// reachable from the transport path alone.
func TestScrubURLErrorWithholdsUnparseableURL(t *testing.T) {
	got := scrubURLError(&url.Error{
		Op:  "parse",
		URL: poisonedServer,
		Err: fmt.Errorf("invalid URL escape %q", "%BU"),
	})
	if strings.Contains(got, buildURLSentinel) {
		t.Fatalf("scrubURLError leaked an unparseable URL verbatim:\n  in  = %q\n  out = %q\n"+
			"Nothing can be recovered safely from a URL that does not parse — not even the "+
			"host. Report the sanitized urlParseCause reason and no part of the input.",
			poisonedServer, got)
	}
	if !strings.Contains(got, "not a valid URL") {
		t.Fatalf("scrubURLError(%q) = %q; want it to still SAY the URL is invalid — "+
			"withholding the URL must not withhold the diagnosis too", poisonedServer, got)
	}
}

// TestCheckIPTransportFailureRedactsPath is the fail-on-revert gate for MAJOR 1
// on the checkip path: a VALID checkip-url carrying an API key in its PATH must
// not leak it when the probe fails at transport. Restore Path/RawPath in
// scrubURLError and this fails by assertion naming the leaked sentinel.
func TestCheckIPTransportFailureRedactsPath(t *testing.T) {
	urlStr := "https://checkip.example/v1/" + pathSentinel + "/myip"
	if err := validateCheckIPURL(urlStr); err != nil {
		t.Fatalf("validateCheckIPURL(%q) = %v; this URL must be ACCEPTED or the test "+
			"never reaches the transport path it exists to cover", urlStr, err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errSyntheticTransport
	})}

	_, ok, err := CheckIP(context.Background(), client, urlStr, true, nil)
	if ok {
		t.Fatal("a failing transport must not yield an observation")
	}
	if err == nil {
		t.Fatal("a transport failure must be reported (#6545); got err=nil, so the " +
			"assertion below would be vacuous")
	}
	if !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("CheckIP err = %q, want the transport-failure error; the test is not "+
			"exercising doRequest/scrubURLError", err)
	}
	if strings.Contains(err.Error(), pathSentinel) {
		t.Fatalf("a transport failure on a VALID checkip-url leaked the PATH credential:\n"+
			"  error = %q\n"+
			"scrubURLError cleared userinfo, query and fragment but deliberately preserved "+
			"Path. The daemon copies this string into the checkIPProbeWarned dedup key and "+
			"the journal attribute, so an API key in the path reaches both.", err)
	}
}

// TestGenericTransportFailureRedactsPasswordInPath is Codex's exact round-6
// repro: %p is permitted ANYWHERE in a generic url-template, including the
// path, so the transport error rendered the expanded password.
func TestGenericTransportFailureRedactsPasswordInPath(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errSyntheticTransport
	})}
	b, err := newGenericBackend(&config.DDNSProvider{
		Name:        "gen",
		Backend:     "generic",
		URLTemplate: "https://prov.example/update/%p",
		Username:    "u",
		Password:    config.NewSecret(pathSentinel),
	}, client)
	if err != nil {
		t.Fatalf("newGenericBackend: %v; the template must be ACCEPTED or this test is vacuous", err)
	}
	err = b.UpsertLease(context.Background(), LeaseDNSRecord{
		FQDN: "host.example.com", Addr: netip.MustParseAddr("192.0.2.7"), TTL: 60, ForwardType: "A",
	})
	if err == nil {
		t.Fatal("a synthetic transport failure must surface an error")
	}
	// REACHED-TRANSPORT floor, and the third vacuous shape found in this file.
	// Without it, ANY earlier unrelated failure inside UpsertLease — a template
	// rejection, a bind error, a validation refusal — satisfies both the
	// non-nil check above and the does-not-contain check below, so the test
	// passes while never exercising the transport render it is named for. The
	// host sibling already carried this assertion; this one did not.
	if !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("error %q did not come from the transport path; UpsertLease failed "+
			"EARLIER, so this test never rendered a transport error and its "+
			"redaction check proved nothing", err)
	}
	if strings.Contains(err.Error(), pathSentinel) {
		t.Fatalf("the %%p-expanded password leaked from the URL PATH on transport failure:\n"+
			"  error = %q\n"+
			"A generic template may place %%p anywhere; only scheme://host may be rendered.", err)
	}
}

// TestGenericTransportFailureRedactsPasswordInHost is Codex's round-7 repro,
// driven end to end through the SAME path he used: a supported generic
// url-template that expands %p inside an IPv6 zone id.
//
// RFC 6874 lets a zone id use "basically any %-encoding it likes" and net/url
// honours that, so "https://[fe80::1%25%p]/update" parses cleanly and lands the
// expanded password in url.URL.Host. The round-6 fix allowlisted the url.URL
// FIELDS and admitted Host whole, so this walked straight through it: a field
// allowlist is only as good as the safety of the fields it admits.
//
// u.Hostname() is not the fix either — it unwraps the brackets and KEEPS the
// zone. Only re-rendering the address from netip with the zone dropped removes
// it structurally.
func TestGenericTransportFailureRedactsPasswordInHost(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errSyntheticTransport
	})}
	b, err := newGenericBackend(&config.DDNSProvider{
		Name:        "gen",
		Backend:     "generic",
		URLTemplate: "https://[fe80::1%25%p]/update",
		Username:    "u",
		Password:    config.NewSecret(hostSentinel),
	}, client)
	if err != nil {
		t.Fatalf("newGenericBackend: %v; the template must be ACCEPTED or this test is vacuous", err)
	}
	err = b.UpsertLease(context.Background(), LeaseDNSRecord{
		FQDN: "host.example.com", Addr: netip.MustParseAddr("192.0.2.7"), TTL: 60, ForwardType: "A",
	})
	if err == nil {
		t.Fatal("a synthetic transport failure must surface an error")
	}
	// NON-VACUITY: the failure must be the TRANSPORT, not a rejected template or
	// a build error, or the sentinel check below proves nothing about Host.
	if !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("generic UpsertLease err = %q, want the transport failure. If this is a "+
			"build/parse error the template never reached url.URL.Host and the assertion "+
			"below is vacuous.", err)
	}
	if strings.Contains(err.Error(), hostSentinel) {
		t.Fatalf("the %%p-expanded password leaked from the IPv6 ZONE ID inside url.URL.Host:\n"+
			"  error = %q\n"+
			"Host is not credential-free. Render it through safeHostText, which re-renders an "+
			"IP literal from netip with WithZone(\"\") — copying u.Host, or even u.Hostname(), "+
			"keeps the zone.", err)
	}
}

// TestScrubInnerErrorWithholdsURLFromArbitraryTransportError is Codex's round-7
// repro for the INNER error. scrubInnerError used to return any non-*url.Error
// verbatim, reasoning that transport errors name a host, never a URL. CheckIP
// takes a caller-supplied *http.Client, so that reasoning does not hold: a
// RoundTripper that mentions req.URL put the complete path credential through.
//
// The wrapped form is covered too. The round-6 handling of net/http's
// Location-parse message was an exact PREFIX match on the top-level text, so the
// same message one wrap deep walked past it.
func TestScrubInnerErrorWithholdsURLFromArbitraryTransportError(t *testing.T) {
	urlStr := "https://checkip.example/v1/" + pathSentinel + "/myip"
	for _, tc := range []struct {
		name string
		make func(req *http.Request) error
	}{
		{"roundtripper embeds the request URL", func(req *http.Request) error {
			return fmt.Errorf("request %s failed: %w", req.URL, context.DeadlineExceeded)
		}},
		{"roundtripper embeds only the query", func(req *http.Request) error {
			return fmt.Errorf("upstream rejected %q", req.URL.RequestURI())
		}},
		{"wrapped Location-header echo", func(req *http.Request) error {
			return fmt.Errorf("while following redirect: %w",
				fmt.Errorf("failed to parse Location header %q: bad escape", req.URL.String()))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return nil, tc.make(req)
			})}
			_, ok, err := CheckIP(context.Background(), client, urlStr, true, nil)
			if ok {
				t.Fatal("a failing transport must not yield an observation")
			}
			if err == nil {
				t.Fatal("a transport failure must be reported; got nil, so this test is vacuous")
			}
			if !strings.Contains(err.Error(), "request failed") {
				t.Fatalf("CheckIP err = %q, want the transport-failure error; the test is not "+
					"exercising doRequest/scrubURLError", err)
			}
			if strings.Contains(err.Error(), pathSentinel) {
				t.Fatalf("the inner transport error leaked the URL PATH credential:\n"+
					"  error = %q\n"+
					"scrubInnerError must be TOTAL: render an error's text only when its "+
					"provenance is known (our own refusals, a syscall.Errno, a recognised "+
					"stdlib class). A caller-supplied RoundTripper can return anything.", err)
			}
		})
	}
}

// TestScrubInnerErrorResistsForgedProvenance is the round-8 gate.
//
// Round 7 made scrubInnerError "total" by asking, of each error, whether its
// PROVENANCE was known — and every way of asking that question routes through
// something a caller-supplied error controls. Codex demonstrated four:
//
//  1. errors.Is dispatches to the error's own Is(error) bool. An error whose Is
//     always returns true was accepted as one of our own redirect refusals and
//     its Error() — the request URL — printed verbatim.
//  2. url.Error.Op was never rebuilt, so a RoundTripper returning
//     &url.Error{Op: req.URL.String(), URL: "https://safe.example/"} leaked the
//     whole URL through the one field the scrub skipped.
//  3. syscall.Errno.Error() is NOT a closed table — an unknown value renders
//     "errno 65432", so a numeric credential survived the "kernel vocabulary"
//     argument.
//  4. %T is not a compile-time symbol. reflect.StructOf builds a runtime type
//     whose NAME embeds a struct tag, and the tag is input.
//
// The fix is not a better provenance check — it is that no error's own Error()
// or type name reaches the output at all. These cases assert that.
func TestScrubInnerErrorResistsForgedProvenance(t *testing.T) {
	const cred = "FORGED-CREDENTIAL-MUST-NOT-LOG"
	urlStr := "https://checkip.example/v1/" + cred + "/myip"

	// A RUNTIME type whose NAME embeds input, via a struct tag. reflect promotes
	// CodexBaseError's Error method, so the value satisfies `error` and reaches
	// the renderer; %T then prints the whole synthesized type, tag included.
	forgedType := reflect.StructOf([]reflect.StructField{{
		Name:      "CodexBaseError",
		Type:      reflect.TypeOf(CodexBaseError{}),
		Anonymous: true,
		Tag:       reflect.StructTag(`secret:"` + cred + `"`),
	}})

	for _, tc := range []struct {
		name string
		make func(req *http.Request) error
	}{
		{"error whose Is() always says true, text is the URL", func(req *http.Request) error {
			return forgedIsError{text: req.URL.String()}
		}},
		{"forged url.Error carries the URL in Op", func(req *http.Request) error {
			return &url.Error{
				Op:  req.URL.String(),
				URL: "https://safe.example/",
				Err: errors.New("x"),
			}
		}},
		{"unknown errno renders dynamically", func(req *http.Request) error {
			// A numeric credential steered into the errno slot. 65432 is far
			// outside the kernel's table, so Errno.Error() formats it.
			return syscall.Errno(65432)
		}},
		{"runtime type name carries an input-derived struct tag", func(req *http.Request) error {
			return reflect.New(forgedType).Elem().Interface().(error)
		}},
		{"forged Is() nested under a real url.Error", func(req *http.Request) error {
			return &url.Error{Op: "Get", URL: req.URL.String(),
				Err: forgedIsError{text: req.URL.String()}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return nil, tc.make(req)
			})}
			_, ok, err := CheckIP(context.Background(), client, urlStr, true, nil)
			if ok {
				t.Fatal("a failing transport must not yield an observation")
			}
			if err == nil {
				t.Fatal("a transport failure must be reported; got nil, so this test is vacuous")
			}
			if !strings.Contains(err.Error(), "request failed") {
				t.Fatalf("CheckIP err = %q, want the transport-failure error; the test is not "+
					"exercising doRequest/scrubURLError", err)
			}
			if strings.Contains(err.Error(), cred) {
				t.Fatalf("a caller-supplied error smuggled its own text into the rendered "+
					"error:\n  error = %q\n"+
					"PROVENANCE IS FORGEABLE. errors.Is/As dispatch to methods the error "+
					"defines; url.Error.Op is caller-set; syscall.Errno.Error() is not a "+
					"closed table; %%T is not a compile-time symbol (reflect.StructOf). The "+
					"rendered text must come from THIS package's declared constants — plus "+
					"*redirectRefusal, found by TYPE ASSERTION, which cannot be impersonated "+
					"from outside the package.", err)
			}
		})
	}
	// The unknown errno must also not surface its numeric form at all.
	if got := scrubInnerError(syscall.Errno(65432)); strings.Contains(got, "65432") {
		t.Fatalf("scrubInnerError(syscall.Errno(65432)) = %q; an errno outside the allowlist "+
			"must be withheld, not formatted — Errno.Error() renders unknown values as "+
			"\"errno N\", which is a channel for a numeric credential", got)
	}
}

// TestScrubInnerErrorKeepsRecognisedDiagnostics is the over-reach floor for the
// totality fix above. Withholding everything would satisfy the leak test and
// destroy the package's diagnostics, so the classes an operator actually reads
// must still come out — including, above all, the cross-host redirect refusal,
// which is the very thing #6545 exists to produce.
func TestScrubInnerErrorKeepsRecognisedDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		want    string
		notWant string // must NOT appear; "" skips the check
	}{
		{"errno", syscall.ECONNREFUSED, "connection refused", ""},
		{"errno wrapped by net.OpError", &net.OpError{
			Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED,
		}, "connection refused", ""},
		{"no route to host", syscall.EHOSTUNREACH, "no route to host", ""},
		{"opError with no recognised errno", &net.OpError{
			Op: "dial", Net: "tcp", Err: errors.New("x"),
		}, "dial failed", ""},
		{"context deadline", context.DeadlineExceeded, "context deadline exceeded", ""},
		{"dns not found", &net.DNSError{Err: "x", Name: hostSentinel, IsNotFound: true},
			"dns lookup failed: no such host", ""},
		{"unknown authority", x509.UnknownAuthorityError{},
			"tls: certificate signed by unknown authority", ""},
		{"our own redirect refusal", &redirectRefusal{
			reason: redirectReasonCrossHost,
			from:   mustParseURL(t, "https://prov.example/a"),
			to:     mustParseURL(t, "https://evil.example/b"),
			// The TARGET is deliberately NOT named. It is provider-chosen, so
			// rendering it both leaked a credential-shaped reg-name and varied
			// per request, breaking the daemon's once-per-(provider,error)
			// dedup on a never-pruned map. The FROM host is our configured
			// endpoint and is stable, so it stays.
		}, "refusing cross-host redirect from prov.example to a provider-supplied host",
			"evil.example"},
		{"our own refusal, wrapped by the http client", fmt.Errorf("wrapped: %w",
			&redirectRefusal{reason: redirectReasonHopCap}), "stopped after 10 redirects", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := scrubInnerError(tc.err)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("scrubInnerError(%T) = %q, want it to contain %q.\n"+
					"Making the classifier total must not make it useless — these are the "+
					"classes an operator diagnoses from.", tc.err, got, tc.want)
			}
			// Presence of the generic phrase does not prove ABSENCE of the
			// target. Round 15 caught this: the case was described as "strictly
			// stronger" than the old name-the-target assertion when it only
			// checked the replacement wording had arrived.
			if tc.notWant != "" && strings.Contains(got, tc.notWant) {
				t.Fatalf("scrubInnerError(%T) = %q, which still names the "+
					"provider-chosen target %q. That value varies per request and "+
					"defeats the daemon's once-per-(provider,error) dedup.",
					tc.err, got, tc.notWant)
			}
		})
	}
	// The refusal path must be reachable ONLY by our own type. An impostor that
	// answers errors.Is(…, errRedirectRefused) with true must NOT be rendered.
	if got := scrubInnerError(forgedIsError{text: "IMPOSTOR-TEXT"}); strings.Contains(got, "IMPOSTOR-TEXT") {
		t.Fatalf("scrubInnerError rendered an impostor's text: %q\n"+
			"The refusal must be found by TYPE ASSERTION on the unexported *redirectRefusal, "+
			"never by errors.Is on a sentinel — errors.Is asks the error itself.", got)
	}
	// And the classifier must not smuggle host text out of a class it recognises:
	// net.DNSError.Name is the request host.
	if got := scrubInnerError(&net.DNSError{Err: "x", Name: hostSentinel, IsNotFound: true}); strings.Contains(got, hostSentinel) {
		t.Fatalf("scrubInnerError rendered net.DNSError.Name: %q\n"+
			"Recognised classes must be read STRUCTURALLY (IsNotFound/IsTimeout), never by "+
			"their message text — DNSError.Name and OpError.Addr are the request host.", got)
	}
}

// TestGuardRedirectRefusalBoundsProviderSuppliedHost covers the half of round 7
// that is remote-controlled rather than operator-controlled. It USED to check
// that the refusal's rendering of the redirect TARGET was character-bounded,
// because a provider echoing our own credential back as a hostname got the hop
// refused — correctly — and the credential written to the log.
//
// Round 14 went further and stopped rendering the target at all: the grammar
// bounded its character set but not its content, so a well-formed reg-name came
// out verbatim, and being provider-chosen it also varied per request and
// defeated the daemon's dedup. This now asserts the target is ABSENT, which is
// strictly stronger than asserting it was sanitised.
//
// The host is bounded by the same grammar, not withheld: naming the host you
// refused to follow is the entire diagnostic.
func TestGuardRedirectRefusalBoundsProviderSuppliedHost(t *testing.T) {
	prev := httptest.NewRequest(http.MethodGet, "https://prov.example/upd", nil)
	for _, tc := range []struct {
		name     string
		location string
		wantOut  string // must NOT appear
		wantIn   string // must appear
	}{
		// wantIn is now the STABLE part of the refusal — the reason and our own
		// endpoint — never the refused target. Round 14 stopped rendering the
		// target at all: the grammar bounded its character SET but not its
		// CONTENT, so a well-formed reg-name like `<password>.evil.example`
		// came out verbatim, and being provider-chosen it also varied per
		// request and defeated the daemon's dedup. Asserting its ABSENCE is a
		// strictly stronger guard than asserting it was character-bounded.
		{"zone id in a cross-host Location",
			"https://[fe80::1%25" + hostSentinel + "]/next", "fe80::1", "provider-supplied host"},
		{"non-ascii bytes in a cross-host Location",
			"https://ex%FFample.com/next", "example.com", "provider-supplied host"},
		{"downgrade to a zoned host",
			"http://[fe80::1%25" + hostSentinel + "]/next", "fe80::1", "cleartext"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := httptest.NewRequest(http.MethodGet, tc.location, nil)
			err := guardRedirect(next, []*http.Request{prev})
			if err == nil {
				t.Fatal("a cross-host / downgrade hop must be refused; got nil, so this " +
					"test is vacuous")
			}
			if strings.Contains(err.Error(), tc.wantOut) {
				t.Fatalf("the refusal leaked provider-supplied host text:\n  error = %q\n"+
					"The Location header is attacker-influenced; render its host through "+
					"safeHostText, and remember the refusal reaches the log via "+
					"scrubInnerError's errRedirectRefused branch.", err)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Fatalf("refusal = %q, want it to still contain %q — bounding the host "+
					"must not erase which hop was refused", err, tc.wantIn)
			}
		})
	}
}

// TestScrubURLErrorWithholdsLocationHeaderEcho covers the one transport-layer
// message that embeds a URL: net/http quotes the RAW Location header when it
// fails to parse it, and it builds that message BEFORE CheckRedirect runs — so
// the cross-host refusal does not cover it. A provider that 3xx-es to a
// malformed Location echoing our own credential back at us would land it in
// ue.Err, nested past the URL scrub.
//
// The echo must sit in the Location's PATH (or fragment), not its query:
// url.Parse does not unescape RawQuery, so "?token=X%ZZ" parses CLEANLY and no
// Location-parse error is produced at all. An earlier revision of this test
// used the query form; it "passed" against a deliberately neutralized guard
// because the request instead died on the 10-hop redirect cap. The assertion
// below that the error really IS the Location failure is what caught that, and
// is why it stays.
//
// This drives a REAL http.Client redirect rather than asserting on the literal
// prefix constant, so if the stdlib rewords the message the gate goes RED
// instead of silently fail-opening.
func TestScrubURLErrorWithholdsLocationHeaderEcho(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			// Unparseable AND echoing the caller's credential back at us.
			Header: http.Header{"Location": []string{"/retry/" + pathSentinel + "%ZZ"}},
			Body:   http.NoBody,
		}, nil
	})}
	req, err := http.NewRequest(http.MethodGet, "https://prov.example/upd", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	_, _, derr := doRequest(context.Background(), client, req)
	if derr == nil {
		t.Fatal("an unparseable Location must fail the request; got nil, so this test is vacuous")
	}
	// NON-VACUITY: the failure must be the Location parse, not the redirect cap
	// or a transport error, or the sentinel check below proves nothing.
	if !strings.Contains(derr.Error(), "Location") {
		t.Fatalf("doRequest err = %q, want the Location-header parse failure. If this says "+
			"\"stopped after 10 redirects\", the Location is PARSING and the test is not "+
			"exercising the path it exists to cover — put the bad escape in the Location's "+
			"PATH, not its query.", derr)
	}
	if strings.Contains(derr.Error(), pathSentinel) {
		t.Fatalf("the provider-echoed Location header leaked a credential:\n  error = %q\n"+
			"net/http renders `failed to parse Location header %%q` with the RAW header, and "+
			"that string is nested in ue.Err where the URL scrub does not reach.", derr)
	}
}

// TestBackendBuildRequestErrorsWithholdCredentials is MAJOR 2's fail-on-revert
// gate. Each backend is driven with a credential-bearing, unparseable endpoint
// and the resulting build error must name no part of it.
//
// dyndns2 is constructed as a struct literal on purpose: resolveDyndns2Endpoint
// refuses a malformed `server` at construction (and renders it raw — that is
// #6606, out of scope here), so the ctor never yields a backend whose update()
// build path can be reached. The struct literal exercises the update() path the
// source gate below also covers.
func TestBackendBuildRequestErrorsWithholdCredentials(t *testing.T) {
	ctx := context.Background()
	rec := LeaseDNSRecord{
		FQDN: "host.example.com", Addr: netip.MustParseAddr("192.0.2.7"), TTL: 60, ForwardType: "A",
	}
	// Every transport below must be UNREACHED: the failure is in building the
	// request, before any I/O. A round trip means the test is not exercising
	// what it claims to.
	tripped := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		tripped = true
		return nil, errSyntheticTransport
	})}

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"duckdns", func() error {
			b, err := newDuckDNSBackend(&config.DDNSProvider{
				Name: "duck", Backend: "duckdns", Server: poisonedServer,
				APIToken: config.NewSecret("tok"),
			}, client)
			if err != nil {
				return err
			}
			return b.UpsertLease(ctx, rec)
		}},
		{"cloudflare", func() error {
			b, err := newCloudflareBackend(&config.DDNSProvider{
				Name: "cf", Backend: "cloudflare", Server: poisonedServer,
				Zone: "example.com", APIToken: config.NewSecret("tok"),
			}, client)
			if err != nil {
				return err
			}
			return b.UpsertLease(ctx, rec)
		}},
		{"route53", func() error {
			b, err := newRoute53Backend(&config.DDNSProvider{
				Name: "r53", Backend: "route53", Server: poisonedServer,
				HostedZoneID: "Z123", AWSAccessKeyID: "AKID",
				AWSSecretAccessKey: config.NewSecret("sek"), AWSRegion: "us-east-1",
			}, client)
			if err != nil {
				return err
			}
			return b.UpsertLease(ctx, rec)
		}},
		{"dyndns2", func() error {
			b := &dyndns2Backend{name: "dd2", endpoint: poisonedServer, client: client}
			return b.UpsertLease(ctx, rec)
		}},
		{"generic", func() error {
			b, err := newGenericBackend(&config.DDNSProvider{
				Name: "gen", Backend: "generic",
				URLTemplate: "https://prov.example/upd#%" + buildURLSentinel,
			}, client)
			if err != nil {
				return err
			}
			return b.UpsertLease(ctx, rec)
		}},
		{"checkip", func() error {
			_, _, err := CheckIP(ctx, client, poisonedServer, true, nil)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tripped = false
			err := tc.run()
			if err == nil {
				t.Fatal("a credential-bearing, unparseable endpoint must fail; got nil, so " +
					"the assertion below would be vacuous")
			}
			if tripped {
				t.Fatalf("the transport was reached; this test must exercise the BUILD path, "+
					"not a round trip (err = %v)", err)
			}
			if strings.Contains(err.Error(), buildURLSentinel) {
				t.Fatalf("the build-request error rendered the raw endpoint:\n  error = %q\n"+
					"%%w-wrapping a *url.Error re-embeds the COMPLETE offending URL, and the "+
					"`server` leaf reaches this constructor unparsed. Render through "+
					"scrubURLError, which withholds a URL that does not parse.", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The structural half: no NEW call site can reintroduce the class.
// ---------------------------------------------------------------------------

// urlErrorProducers are the calls whose error may embed a request URL.
// http.NewRequest returns url.Parse's *url.Error VERBATIM; client.Do returns a
// *url.Error whose Error() embeds the full request URL.
var urlErrorProducers = map[string]bool{
	"http.NewRequest":            true,
	"http.NewRequestWithContext": true,
	"url.Parse":                  true,
	"url.ParseRequestURI":        true,
	".Do":                        true, // any client.Do / b.client.Do
	// xml.Unmarshal was the gap at round 12, found the same way as the one
	// below: by asking which OTHER call can put attacker text in an error.
	// Go's XML decoder quotes declaration values back ("xml: unsupported
	// version %q"), and Route 53 decodes a 2xx RESPONSE BODY, so a provider
	// chooses that string outright. It rendered with %w at
	// backend_route53.go:203.
	"xml.Unmarshal": true,
	// json.Unmarshal was the gap at #6634, and it is FILE-SCOPED — see
	// producerFileScope below. Go's JSON decoder quotes the offending input
	// back ("json: cannot unmarshal number 9876543210… into Go struct field"),
	// and the Cloudflare backend decodes a PROVIDER-CHOSEN response body, so
	// that string is attacker-selected. Three sites rendered it with %w.
	"json.Unmarshal": true,
	// readCappedBody was the gap this list had at round 10. doRequest has TWO
	// adjacent error returns; .Do covered the first, and the second — four
	// lines below it — rendered readCappedBody's error with %w and no producer
	// entry, so no site was ever built for it and the gate was green over a
	// verbatim render inside the very function it exists to protect. Reading
	// the body is part of issuing the request: the error is caller-reachable
	// (the caller supplies the *http.Client, hence resp.Body) and carries
	// connection-varying text.
	"readCappedBody": true,
}

// urlErrorRenderers are the ONLY things such an error may be handed to. The
// first two sanitize; errors.As/Is inspect without rendering.
var urlErrorRenderers = map[string]bool{
	"scrubURLError": true,
	// scrubInnerError is a sanitizer on the same footing as scrubURLError: it
	// returns a declared transportReason constant, our own refusal's fixed
	// prose, or recurses back through scrubURLError — never the error's own
	// text. It is the correct renderer for an error that is NOT a *url.Error,
	// which is what readCappedBody produces.
	"scrubInnerError": true,
	"urlParseCause":   true,
	"errors.As":       true,
	"errors.Is":       true,
}

// #6606 CLOSED: this gate used to carry a self-expiring exemption for
// resolveDyndns2Endpoint, the ONE site that rendered a malformed `server` (and
// its %w-wrapped parse error) raw. That site is fixed, so the exemption is gone
// and pkg/ddns now has NO exempted URL-error render at all: every handler in
// the package must scrub.
//
// The exemption did its job on the way out. It was written to assert it was
// actually HIT, so landing the fix turned this test RED and forced the stale
// entry out rather than leaving a silently-widened hole for whatever occupied
// that slot next.

// minURLErrorSites is the non-vacuity floor. If a refactor renames the
// producers or restructures the error handling, the walk must not silently
// find nothing and report success.
const minURLErrorSites = 12

// TestDDNSURLErrorRendersGoThroughScrubber is the class gate. It walks every
// production file in pkg/ddns, finds each place an error from a URL-bearing
// call is handled, and fails any that renders that error other than through
// scrubURLError / urlParseCause.
//
// This is the check that generalises: rounds 1-5 each fixed the instance a
// reviewer found, and round 6 found three more of the same shape in backends
// nobody had touched. A site added tomorrow fails HERE, before review.
func TestDDNSURLErrorRendersGoThroughScrubber(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	sites := 0
	exemptedSites := 0

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Clean(name), nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fn.Body == nil {
				continue
			}
			aliases := importAliases(file)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				for _, site := range urlErrorHandlers(n, name, aliases) {
					sites++
					bad := unscrubbedUses(fset, site.stmts, site.errVar, aliases)
					for _, pos := range bad {
						t.Errorf("%s: %s renders the error from a URL-bearing call (%q) without "+
							"the scrubber.\n"+
							"A *url.Error's Error() embeds the COMPLETE request URL — userinfo, "+
							"path, query and fragment — and every DDNS endpoint reaches these "+
							"call sites from an operator `server` / `url-template` / `checkip-url` "+
							"leaf that may carry a credential in any of them. The resulting string "+
							"is logged by the daemon and retained as a process-lifetime dedup key.\n"+
							"Render it as: fmt.Errorf(\"...: %%s\", scrubURLError(%s)).",
							pos, fn.Name.Name, site.errVar, site.errVar)
					}
				}
				return true
			})
		}
	}

	if sites < minURLErrorSites {
		t.Errorf("found only %d URL-bearing error handlers in pkg/ddns, want at least %d; "+
			"the walk is probably not matching the code it is supposed to check, and a gate "+
			"that matches nothing passes vacuously", sites, minURLErrorSites)
	}
	// #6606: there is no longer ANY exempted site, so the gate is now a plain
	// "every URL-error handler in pkg/ddns scrubs". The two assertions that used
	// to police the exemption's own liveness are gone with it; minURLErrorSites
	// above remains the non-vacuity floor.
	if exemptedSites != 0 {
		t.Errorf("%d handler(s) were treated as exempt, want 0 — pkg/ddns has no exempted "+
			"URL-error render since #6606. An exemption reintroduced here must come with "+
			"its own self-expiry assertion.", exemptedSites)
	}
}

// TestClientDoHasExactlyOneCallSite is the second axis, added in round 7.
//
// The walk above matches CALL SHAPES, and a reviewer walked past it by moving
// the round trip behind a helper: the helper's own error is a plain `error`, so
// nothing downstream looks like a URL-bearing handler and the gate sees an empty
// package. No amount of shape-widening fixes that — it is a dataflow question.
//
// What DOES fix it is denying the move. `client.Do` is the only way a URL
// reaches an error in this package that is not a build-time url.Parse, and every
// caller is meant to go through doRequest, which scrubs. So this pins the count:
// ONE mention of a `.Do` selector on an HTTP client, in doRequest. A wrapper
// helper, a `do := client.Do` method value, or a second backend calling Do
// directly each ADD a site and fail here — no shape-matching involved.
func TestClientDoHasExactlyOneCallSite(t *testing.T) {
	type site struct{ file, fn string }
	var found []site

	forEachProductionFunc(t, func(name string, file *ast.File, fn *ast.FuncDecl) {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			// A SELECTOR, not a call: `do := client.Do` never calls anything.
			sel, isSel := n.(*ast.SelectorExpr)
			if isSel && sel.Sel.Name == "Do" {
				found = append(found, site{name, fn.Name.Name})
			}
			return true
		})
	})

	want := site{"backend_http.go", "doRequest"}
	if len(found) != 1 || found[0] != want {
		t.Errorf("`.Do` sites in pkg/ddns = %v, want exactly one: %v.\n"+
			"Every HTTP round trip in this package must go through doRequest, which renders "+
			"the resulting *url.Error through scrubURLError. A new call site — a helper "+
			"wrapping client.Do, a `do := client.Do` method value, a backend calling Do "+
			"itself — reintroduces the #6545 leak class in a shape the AST walk next door "+
			"cannot see, because the error it hands back is a plain `error`.\n"+
			"Route it through doRequest. If a new site is genuinely unavoidable, it must "+
			"scrub, and this expectation must be widened DELIBERATELY.", found, want)
	}
}

// forEachProductionFunc walks every function declared in a non-test .go file of
// the package. Both source gates share it so they cannot drift over which files
// count as production.
func forEachProductionFunc(t *testing.T, visit func(name string, file *ast.File, fn *ast.FuncDecl)) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Clean(name), nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if !isFunc || fn.Body == nil {
				continue
			}
			visit(name, file, fn)
		}
	}
}

// handlerSite is one place a URL-bearing error is handled: the error variable's
// name and every statement the value can still be read from.
type handlerSite struct {
	errVar   string
	producer string // the call whose error this is, e.g. "url.Parse"
	stmts    []ast.Stmt
}

// urlErrorHandlers recognises the two shapes in which a URL-bearing error is
// handled. A block may contain SEVERAL (duckdns's update() has both a
// url.Parse and an http.NewRequest), so every one is returned:
//
//	v, err := url.Parse(s)          |  if v, err := url.Parse(s); err != nil {
//	if err != nil { ... }           |      ...
//	                                |  }
//
// ROUND 7 WIDENED SHAPE 1. It used to require the `if err != nil` to be the very
// NEXT statement and inspected only that if's body, so an intervening statement,
// or a render that never used an `if` at all
//
//	resp, err := client.Do(req)
//	return nil, fmt.Errorf("request failed: %w", err)
//
// walked past it. The site is now the whole REACH of the value: every statement
// after the assignment until the identifier is reassigned. That subsumes both
// bypasses, and the reassignment cut is what keeps
//
//	req, err := http.NewRequest(...)   // tainted
//	...
//	code, body, err := doRequest(...)  // a DIFFERENT, already-scrubbed value
//	if err != nil { return fmt.Errorf("...: %w", err) }
//
// from reading as a leak.
func urlErrorHandlers(n ast.Node, file string, aliases map[string]string) []handlerSite {
	switch node := n.(type) {
	case *ast.BlockStmt:
		// Shape 1: the assignment is a preceding statement in the same block.
		var sites []handlerSite
		for i := 0; i+1 < len(node.List); i++ {
			errVar, producer := producedErrVar(node.List[i], file, aliases)
			if errVar == "" {
				continue
			}
			reach := node.List[i+1:]
			for j, stmt := range reach {
				if assignsVar(stmt, errVar) {
					reach = reach[:j]
					break
				}
			}
			if len(reach) > 0 {
				sites = append(sites, handlerSite{errVar: errVar, producer: producer, stmts: reach})
			}
		}
		return sites
	case *ast.IfStmt:
		// Shape 2: `if v, err := url.Parse(s); err != nil {`
		if node.Init == nil {
			return nil
		}
		errVar, producer := producedErrVar(node.Init, file, aliases)
		if errVar == "" || !testsErrVar(node.Cond, errVar) {
			return nil
		}
		return []handlerSite{{errVar: errVar, producer: producer, stmts: node.Body.List}}
	}
	return nil
}

// producerFileScope narrows a producer to the files where its error can carry
// FOREIGN bytes. Only json.Unmarshal needs it, and the scope is a PREDICATE, not
// a list of sites: an entry naming individual files would go stale the moment a
// backend was added, and would fail OPEN in exactly the direction that matters.
//
// json.Unmarshal decodes two completely different things in this package. In a
// `backend_*.go` file it decodes a PROVIDER RESPONSE BODY, so the decoder quotes
// bytes an untrusted party chose. In state.go it decodes the ownership state
// file this daemon wrote itself, at a root-owned path — an attacker who can
// choose those bytes already has root, and the decoder's detail ("invalid
// character '}' after object key") is the whole diagnostic an operator gets when
// repairing a corrupt store. Scrubbing that would cost a real capability and
// close nothing.
//
// This is a SCOPE, not an exemption: it says where a call can carry foreign
// input, not that a known-unsafe site is tolerated. Any NEW backend file is
// covered automatically, which is the direction a scope has to fail.
// TestProviderDecodeScopeIsLoadBearing_6634 pins both halves.
func producerFileScope(callee, file string) bool {
	if callee == "json.Unmarshal" {
		return strings.HasPrefix(file, "backend_")
	}
	return true
}

// producedErrVar returns the name of the error variable assigned from a
// URL-bearing call, or "" if the statement is not such an assignment.
func producedErrVar(stmt ast.Stmt, file string, aliases map[string]string) (errVar, producer string) {
	assign, isAssign := stmt.(*ast.AssignStmt)
	if !isAssign || len(assign.Rhs) != 1 || len(assign.Lhs) == 0 {
		return "", ""
	}
	call, isCall := assign.Rhs[0].(*ast.CallExpr)
	if !isCall {
		return "", ""
	}
	callee := calleeName(call.Fun, aliases)
	if !urlErrorProducers[callee] || !producerFileScope(callee, file) {
		return "", ""
	}
	last, isIdent := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
	if !isIdent || last.Name == "_" {
		return "", ""
	}
	return last.Name, callee
}

// assignsVar reports whether stmt assigns to name, which ends the reach of the
// value the identifier held before it.
func assignsVar(stmt ast.Stmt, name string) bool {
	assign, isAssign := stmt.(*ast.AssignStmt)
	if !isAssign {
		return false
	}
	for _, lhs := range assign.Lhs {
		if id, isIdent := lhs.(*ast.Ident); isIdent && id.Name == name {
			return true
		}
	}
	return false
}

// importAliases maps each file-local package name onto the canonical last
// element of its import path, so an ALIASED import cannot dodge the walk:
//
//	import nh "net/http"
//	req, err := nh.NewRequest(...)   // resolves to "http.NewRequest"
//
// Round 6 matched the receiver's spelling directly and this walked past it.
func importAliases(file *ast.File) map[string]string {
	aliases := map[string]string{}
	for _, spec := range file.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		canonical := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			canonical = path[i+1:]
		}
		local := canonical
		if spec.Name != nil {
			local = spec.Name.Name
		}
		aliases[local] = canonical
	}
	return aliases
}

// testsErrVar reports whether cond is (or begins with) `errVar != nil`.
func testsErrVar(cond ast.Expr, errVar string) bool {
	bin, isBin := cond.(*ast.BinaryExpr)
	if !isBin {
		return false
	}
	if bin.Op == token.LOR || bin.Op == token.LAND {
		return testsErrVar(bin.X, errVar)
	}
	if bin.Op != token.NEQ {
		return false
	}
	x, isIdent := bin.X.(*ast.Ident)
	y, isNil := bin.Y.(*ast.Ident)
	return isIdent && isNil && x.Name == errVar && y.Name == "nil"
}

// unscrubbedUses returns the position of every occurrence of errVar inside stmts
// that is NOT a direct argument to one of the sanctioned renderers. A bare
// `return err`, a `%w` wrap, and a `%v` interpolation all land here.
//
// ROUND 7 ADDED EXTRACTION TAINT. errors.As is sanctioned because it INSPECTS
// rather than renders — but it also hands the caller a fresh variable holding
// the same URL:
//
//	var ue *url.Error
//	if errors.As(err, &ue) { return fmt.Errorf("%w", ue) }   // walked past
//
// so whatever errors.As extracts inherits errVar's taint and is checked too.
func unscrubbedUses(fset *token.FileSet, stmts []ast.Stmt, errVar string, aliases map[string]string) []token.Position {
	tainted := map[string]bool{errVar: true}
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall || calleeName(call.Fun, aliases) != "errors.As" || len(call.Args) != 2 {
				return true
			}
			src, isIdent := call.Args[0].(*ast.Ident)
			if !isIdent || !tainted[src.Name] {
				return true
			}
			unary, isUnary := call.Args[1].(*ast.UnaryExpr)
			if !isUnary || unary.Op != token.AND {
				return true
			}
			if dst, isDstIdent := unary.X.(*ast.Ident); isDstIdent {
				tainted[dst.Name] = true
			}
			return true
		})
	}

	sanctioned := map[*ast.Ident]bool{}
	for _, stmt := range stmts {
		// `err != nil` / `err == nil` TESTS the value, it does not render it.
		// Widening the site to the value's whole reach (round 7) brought the
		// guard condition itself into view, which the body-only walk never saw.
		ast.Inspect(stmt, func(n ast.Node) bool {
			bin, isBin := n.(*ast.BinaryExpr)
			if !isBin || (bin.Op != token.NEQ && bin.Op != token.EQL) {
				return true
			}
			for _, side := range [2]ast.Expr{bin.X, bin.Y} {
				other := bin.Y
				if side == bin.Y {
					other = bin.X
				}
				id, isIdent := side.(*ast.Ident)
				nilIdent, isNil := other.(*ast.Ident)
				if isIdent && isNil && tainted[id.Name] && nilIdent.Name == "nil" {
					sanctioned[id] = true
				}
			}
			return true
		})
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall || !urlErrorRenderers[calleeName(call.Fun, aliases)] {
				return true
			}
			for _, arg := range call.Args {
				if id, isIdent := arg.(*ast.Ident); isIdent && tainted[id.Name] {
					sanctioned[id] = true
				}
				// `errors.As(err, &ue)` — the destination is inspected, not
				// rendered, so its mention here is not a use.
				if unary, isUnary := arg.(*ast.UnaryExpr); isUnary && unary.Op == token.AND {
					if id, isIdent := unary.X.(*ast.Ident); isIdent {
						sanctioned[id] = true
					}
				}
			}
			return true
		})
	}

	var bad []token.Position
	for _, stmt := range stmts {
		ast.Inspect(stmt, func(n ast.Node) bool {
			id, isIdent := n.(*ast.Ident)
			if !isIdent || !tainted[id.Name] || sanctioned[id] {
				return true
			}
			bad = append(bad, fset.Position(id.Pos()))
			return true
		})
	}
	return bad
}

// calleeName renders a call's callee as "fn", "pkg.Fn", or ".Method" (for a
// method on an arbitrary receiver expression, which is how client.Do is
// matched regardless of what holds the client). The receiver is resolved
// through the file's import aliases, so `nh.NewRequest` on `import nh
// "net/http"` still reads as "http.NewRequest".
func calleeName(fun ast.Expr, aliases map[string]string) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, isIdent := f.X.(*ast.Ident); isIdent {
			pkg := x.Name
			if canonical, isImport := aliases[pkg]; isImport {
				pkg = canonical
			}
			if name := pkg + "." + f.Sel.Name; urlErrorProducers[name] || urlErrorRenderers[name] {
				return name
			}
		}
		return "." + f.Sel.Name
	}
	return ""
}
