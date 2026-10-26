package ddnsplaintextvectors

// vectors.go: the single shared test-vector table for the
// DDNS plaintext-credential detector (#17005, R4-Q40-03).
//
// Previously pkg/config (ddns_plaintext_15225_test.go, 6 probes) and
// pkg/ddns (ddns_plaintext_15225_test.go, 8 probes) each carried their own
// copy of the template vectors and the copies had drifted: the runtime
// table added the combined token= row and the authority-userinfo row that
// the compiler table lacked, and no test ran one table through both
// detectors. Both packages' tests now consume this union table.
//
// The table is in an internal package so tests in both packages can import
// it without placing test data in either package's production code.

// DDNSPlaintextVector is one row of DDNSPlaintextVectors: a generic
// url-template plus the detector verdicts both packages must agree on.
// CredentialBearing is the verdict of DDNSCredentialBearing for a generic
// provider carrying no typed username/password (so the verdict is driven
// purely by the template itself); LiteralToken is the verdict of
// DDNSTemplateCarriesLiteralToken on the same template. The two differ
// exactly for the authority-userinfo row: a literal "user:pass@host"
// carries a credential but no literal query/path token.
type DDNSPlaintextVector struct {
	Template          string
	CredentialBearing bool
	LiteralToken      bool
}

// DDNSPlaintextVectors is the union of the two pre-#17005 test tables:
//
//   - probes (CredentialBearing=true): the 6 config probes
//     (pass=/key=/api-token=/pwd=/p=/foo=) plus the 2 extra runtime probes
//     (a literal token= alongside specifier-only pairs, and literal
//     authority userinfo);
//   - controls: the rows both tables pinned as non-credentialed
//     (specifier-only, value-less flag, bare path segment) plus the https
//     literal-token row, which IS credential-bearing as a template — the
//     plaintext gates simply never refuse an https endpoint.
var DDNSPlaintextVectors = []DDNSPlaintextVector{
	// Probes: any literal query value is credential-carrying (#15225).
	{Template: "http://host.example/upd?pass=LITERALPW", CredentialBearing: true, LiteralToken: true},
	{Template: "http://host.example/upd?key=LITERALKEY", CredentialBearing: true, LiteralToken: true},
	{Template: "http://host.example/upd?api-token=LITERALTOK", CredentialBearing: true, LiteralToken: true},
	{Template: "http://host.example/upd?pwd=LITERALPW", CredentialBearing: true, LiteralToken: true},
	{Template: "http://host.example/upd?p=LITERALP", CredentialBearing: true, LiteralToken: true},
	{Template: "http://host.example/upd?foo=LITERALBAR", CredentialBearing: true, LiteralToken: true},
	{Template: "http://host.example/upd?hostname=%h&myip=%i&token=LITERALTOKEN", CredentialBearing: true, LiteralToken: true},
	// Literal authority userinfo: credential-bearing, but no literal
	// query/path token (the query is specifier-only).
	{Template: "http://user:pass@host.example/upd?ip=%i", CredentialBearing: true, LiteralToken: false},
	// Controls.
	{Template: "https://host.example/upd?token=LITERALTOKEN", CredentialBearing: true, LiteralToken: true},
	{Template: "http://host.example/upd?ip=%i&hostname=%h", CredentialBearing: false, LiteralToken: false},
	{Template: "http://host.example/upd?flag&ip=%i", CredentialBearing: false, LiteralToken: false},
	{Template: "http://host.example/update/SECRET", CredentialBearing: false, LiteralToken: false},
}
