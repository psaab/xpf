package ipsec

import (
	"strings"
	"testing"
)

// #9641 revision 3: the generation marker is an UNREFERENCED address pool. These cells
// parse REAL strongSwan 6.0.5 output, captured from a pool-only file
// (testdata/swanctl_list_pools_source_9641.conf) loaded with `swanctl --load-all`
// (capture procedure in docs/log/9641.md).

func TestParseListPoolsRawRealFixture9641(t *testing.T) {
	got, err := parseListPoolsRaw(readFixture9641(t, "swanctl_list_pools_raw_9641.txt"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || got["xpf-gen-proof9641"] != "192.0.2.1" {
		t.Fatalf("pools = %v, want exactly xpf-gen-proof9641 -> 192.0.2.1", got)
	}
}

// Independent second instrument over the SAME load: the text listing names the pool in
// its first column and the base address in the second.
func TestParseListPoolsRawAgreesWithTextFixture9641(t *testing.T) {
	raw, err := parseListPoolsRaw(readFixture9641(t, "swanctl_list_pools_raw_9641.txt"))
	if err != nil {
		t.Fatalf("parse raw: %v", err)
	}
	text := map[string]string{}
	for _, line := range strings.Split(readFixture9641(t, "swanctl_list_pools_text_9641.txt"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			text[f[0]] = f[1]
		}
	}
	if len(text) == 0 {
		t.Fatal("FIXTURE: the text reading found no pools; the cross-check would pass vacuously")
	}
	if len(raw) != len(text) {
		t.Fatalf("raw %v and text %v disagree", raw, text)
	}
	for name, base := range text {
		if raw[name] != base {
			t.Errorf("pool %q: raw base %q, text base %q", name, raw[name], base)
		}
	}
}

// INERTNESS, measured: the same load that carried the marker pool listed NO connection.
// A pool is not a connection, so it cannot initiate or respond and never reaches the
// SA-name and initiate paths that enumerate connections.
func TestMarkerPoolLoadsNoConnection9641(t *testing.T) {
	conns, err := parseListConnsRaw(readFixture9641(t, "swanctl_list_pools_conns_raw_9641.txt"))
	if err != nil {
		t.Fatalf("parse conns: %v", err)
	}
	if len(conns) != 0 {
		t.Errorf("the pool-only load produced connections %v; the marker must not be a connection", conns)
	}
}

func TestParseListPoolsRawEmptyAndMalformed9641(t *testing.T) {
	got, err := parseListPoolsRaw("get-pools reply {}\n")
	if err != nil || len(got) != 0 {
		t.Errorf("no pools must parse to empty, got %v (err %v)", got, err)
	}
	if _, err := parseListPoolsRaw("get-pools reply {xpf-gen-x {base=192.0.2.1}\n"); err == nil {
		t.Error("unbalanced output must be an error, not a partial pool set")
	}
}
