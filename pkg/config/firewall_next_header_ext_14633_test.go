package config

import (
	"strings"
	"testing"
)

// #14633 (Y26-03): inet6 `next-header` extension-header values commit clean
// but can never match. compileFilterFrom aliases next-header to
// term.Protocols, the Rust walk traverses 0/43/44/51/60/135/139/140/253/254
// to the terminal protocol, and the nft mirror emits `meta l4proto` (also
// the terminal protocol). A term written `next-header 43` therefore never
// fires: an [nh=43][RH][TCP] packet is seen as protocol 6 everywhere.
//
// The fix rejects those values at strict commit with a named reason.
// Controls: terminal next-header values (tcp/6/esp/50/no-next-header 59)
// and every inet `protocol` value (including 0/43/44/51/60, ordinary IPv4
// protocol numbers there) must still commit.

func filterWithNextHeader14633(family, leaf, value string) []string {
	return []string{
		"set firewall family " + family + " filter f1 term t1 from " + leaf + " " + value,
		"set firewall family " + family + " filter f1 term t1 then discard",
	}
}

func TestNextHeaderExtValuesRejectAtCommit14633(t *testing.T) {
	// Numeric extension-header values and the name that resolves to one
	// (ah = 51). 44 has no name in the SSOT, so only its numeric form is
	// listed; 0 is HOPOPT.
	for _, value := range []string{"0", "43", "44", "51", "60", "135", "139", "140", "253", "254", "ah"} {
		t.Run(value, func(t *testing.T) {
			tree := flatTreeFromSets(t, filterWithNextHeader14633("inet6", "next-header", value)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("inet6 next-header %s committed clean, want strict rejection (dead term: dataplane walk traverses it to the terminal protocol)", value)
			}
			if !strings.Contains(err.Error(), "next-header") || !strings.Contains(err.Error(), value) {
				t.Fatalf("error %q must name next-header and the offending value %q", err.Error(), value)
			}
		})
	}
}

func TestNextHeaderTerminalValuesCommit14633(t *testing.T) {
	for _, value := range []string{"tcp", "udp", "6", "17", "esp", "50", "59", "58", "icmp6", "132", "255"} {
		t.Run(value, func(t *testing.T) {
			tree := flatTreeFromSets(t, filterWithNextHeader14633("inet6", "next-header", value)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("inet6 next-header %s (terminal protocol) must commit, got %v", value, err)
			}
		})
	}
}

func TestProtocolInetExtNumbersCommit14633(t *testing.T) {
	// In family inet these numbers are ordinary IPv4 protocol numbers with
	// no extension-header meaning; the gate must not reach them.
	for _, value := range []string{"0", "43", "44", "51", "60"} {
		t.Run(value, func(t *testing.T) {
			tree := flatTreeFromSets(t, filterWithNextHeader14633("inet", "protocol", value)...)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("inet protocol %s must commit, got %v", value, err)
			}
		})
	}
}

func TestNextHeaderMixedListRejects14633(t *testing.T) {
	// A bracket list mixing a terminal and an extension value is dead on
	// the extension value; reject naming it.
	tree := flatTreeFromSets(t,
		"set firewall family inet6 filter f1 term t1 from next-header [ tcp 43 ]",
		"set firewall family inet6 filter f1 term t1 then discard",
	)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("mixed [ tcp 43 ] next-header list committed clean, want rejection")
	}
	if !strings.Contains(err.Error(), "43") {
		t.Fatalf("error %q must name the extension-header value 43", err.Error())
	}
}

func TestNextHeaderExtLenientWarns14633(t *testing.T) {
	tree := flatTreeFromSets(t, filterWithNextHeader14633("inet6", "next-header", "43")...)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient load must not fail (#1960 no-brick): %v", err)
	}
	var warned bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "next-header") && strings.Contains(w, "43") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("expected lenient warning naming next-header 43, got %v", cfg.Warnings)
	}
}
