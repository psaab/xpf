package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15719 downstream half: the loop parsers behind Options:true nodes
// must reject a repeated option keyword instead of silently keeping
// the last (or ignoring the duplicate), matching ParsePingOptions and
// ParseCoSNameTypeArgs. Canonicalize refuses these lines for a
// restricted class; an unrestricted class reaches these parsers, which
// must not execute a different filter than any single-occurrence form.
func TestParseSessionFilterRejectsDuplicates15719(t *testing.T) {
	c := &CLI{store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	for _, args := range [][]string{
		{"zone", "guest", "zone", "untrust"},
		{"source-prefix", "10.0.0.0/8", "source-prefix", "192.168.0.0/16"},
		{"destination-port", "22", "destination-port", "80"},
		{"summary", "summary"},
		{"sort-by", "bytes", "sort-by", "packets"},
		{"nat", "nat"},
	} {
		for _, clearMode := range []bool{false, true} {
			var f sessionFilter
			if clearMode {
				f = c.parseClearSessionFilter(args)
			} else {
				f = c.parseSessionFilter(args)
			}
			// On the clear path a presentation token already errors
			// as a display modifier (first error wins, #5066); either
			// rejection is fail-closed. Only the show path must name
			// the duplicate.
			want := "duplicate"
			if clearMode && (args[0] == "summary" || args[0] == "sort-by" || args[0] == "brief") {
				want = "display modifier"
			}
			if f.parseErr == nil || !strings.Contains(f.parseErr.Error(), want) {
				t.Errorf("clearMode=%v parse %v: parseErr=%v, want %q rejection", clearMode, args, f.parseErr, want)
			}
		}
	}
	// Controls: single occurrences and distinct nat spellings stay lawful.
	for _, args := range [][]string{
		{"zone", "trust", "destination-port", "22"},
		{"nat"},
		{"nat-only"},
		{"sort-by", "bytes"},
	} {
		if f := c.parseSessionFilter(args); f.parseErr != nil {
			t.Errorf("show parse %v: unexpected parseErr %v", args, f.parseErr)
		}
	}
}

func TestHandleShowFirewallRejectsDuplicateOptions15719(t *testing.T) {
	store := filterDSCPSyncStore(t)
	c := &CLI{store: store}
	for _, args := range [][]string{
		{"firewall", "filter", "mark", "effective", "effective"},
		{"firewall", "filter", "mark", "family", "inet", "family", "inet6"},
	} {
		err := c.handleShow(args)
		if err == nil {
			t.Errorf("handleShow(%v) = nil, want duplicate-option rejection", args)
		}
	}
	// Control: single forms still render (error, if any, must not be
	// the duplicate usage error).
	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"firewall", "filter", "mark", "family", "inet", "effective"}); err != nil {
			t.Errorf("complete firewall form: %v", err)
		}
	})
	if out == "" {
		t.Errorf("complete firewall form must render output")
	}
}
