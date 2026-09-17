package config

import (
	"testing"
)

// #6463: a literal `from source-address` / `destination-address` token that is
// not parseable OR not representable by the Rust dataplane (including a
// zone-scoped `%zone` literal) must be RECORDED on term.UnknownAddresses at
// compile time (kept verbatim in the address list) so the snapshot builder can
// set the AddressUnrepresentable wire marker on the tolerant load / peer-sync
// path — the Rust parse_address drops such a token per-token, and a
// PARTIALLY-malformed list would otherwise silently narrow a discard/reject
// term to only the surviving prefixes (fail-open). The strict commit gate
// (validateFilterAddressLiteralsStrict, #3433) remains the primary defense.
//
// FAIL-ON-REVERT: remove the recordFilterAddrTokens call in compileFilterFrom
// and these tests go RED — UnknownAddresses comes back empty.

func TestFilterMalformedAddressRecorded_6463(t *testing.T) {
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from source-address [ 10.0.0.0/8 garbage.example ]",
		"set firewall family inet filter f term t from destination-address 192.0.2.0/24",
		"set firewall family inet filter f term t then discard",
	)
	// The tolerant load / peer-sync path — the exact path #6463 narrows on.
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	term := firstInetTerm(t, cfg, "f")
	if len(term.UnknownAddresses) != 1 || term.UnknownAddresses[0] != "garbage.example" {
		t.Fatalf("the malformed literal must be recorded on UnknownAddresses, got %v "+
			"(an empty record means the wire marker can never fire — the #6463 fail-open)",
			term.UnknownAddresses)
	}
	// The token is kept VERBATIM in the address list (the pre-#6463 compile
	// shape), so the term still carries the surviving prefix alongside it.
	if len(term.SourceAddresses) != 2 ||
		term.SourceAddresses[0] != "10.0.0.0/8" ||
		term.SourceAddresses[1] != "garbage.example" {
		t.Fatalf("source addresses must keep both tokens verbatim, got %v", term.SourceAddresses)
	}
	// A fully-valid direction records nothing.
	if len(term.DestAddresses) != 1 || term.DestAddresses[0] != "192.0.2.0/24" {
		t.Fatalf("destination addresses unchanged, got %v", term.DestAddresses)
	}
}

func TestFilterAddressPlaceholdersNotRecorded_6463(t *testing.T) {
	// `any` and bare host IPs / CIDRs are NOT malformed: `any` is a
	// no-constraint placeholder (the matcher drops it), the rest parse.
	tree := buildFilterTree(t,
		"set firewall family inet filter f term t from source-address any",
		"set firewall family inet filter f term t from destination-address [ 10.0.0.1 192.0.2.0/24 ]",
		"set firewall family inet filter f term t then accept",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	term := firstInetTerm(t, cfg, "f")
	if len(term.UnknownAddresses) != 0 {
		t.Fatalf("valid literals and the `any` placeholder must not be recorded, got %v",
			term.UnknownAddresses)
	}
}

func TestFilterMalformedAddressRecordedInet6_6463(t *testing.T) {
	// Family-symmetric: a malformed token in an inet6 filter records the same
	// way (the classifier is family-agnostic; wrong-FAMILY literals are the
	// separate #3433 gate, not this record).
	tree := buildFilterTree(t,
		"set firewall family inet6 filter f6 term t from destination-address [ 2001:db8::/32 not-an-address ]",
		"set firewall family inet6 filter f6 term t then discard",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	f := cfg.Firewall.FiltersInet6["f6"]
	if f == nil || len(f.Terms) == 0 {
		t.Fatal("inet6 filter f6 missing or has no terms")
	}
	term := f.Terms[0]
	if len(term.UnknownAddresses) != 1 || term.UnknownAddresses[0] != "not-an-address" {
		t.Fatalf("the malformed inet6 literal must be recorded, got %v", term.UnknownAddresses)
	}
}
