package config

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// #6940 — thirteen typed integer leaves discarded `strconv.Atoi`'s error, so a
// malformed value silently compiled to 0.
//
// TWO MECHANISMS, because the reachability differs and so does the fix:
//
//   - FIVE leaves carried no schema validator at all, so a malformed value was
//     accepted at COMMIT and silently zeroed. They get validators.
//   - ALL THIRTEEN remain reachable through `compileTreeLenient` (Store.Load /
//     Store.SyncApply), which does not schema-validate. There the value must
//     WARN, not reject — rejecting would refuse a persisted config on boot or
//     fail an HA sync (#1960) — and not silently rewrite either.
//
// "A wrong number" is the wrong severity. For five of these leaves ZERO IS THE
// DOCUMENTED SENTINEL for "not configured" — `LeaseTime` "0 = default",
// `NTPThreshold` "0 = default" (consumers gate on > 0), `TransferInterval`
// "0 = on commit only", and the two prefix lengths — so the malformed value
// landed exactly where "the operator never wrote this leaf" lands. Production
// whose fallback equals the sentinel.

// leafProbe is one leaf under test: a `set` path plus a VALID value for it.
type leafProbe6940 struct {
	name     string
	path     string
	okValue  string
	badValue string
}

// The five leaves that had no validator before #6940. Each `okValue` is a
// PATH CONTROL: if the valid value is rejected, the path is wrong and a
// "rejected the bad value" verdict would be meaningless.
var bareLeaves6940 = []leafProbe6940{
	{"minimum-links", "set interfaces ae0 aggregated-ether-options minimum-links", "2", "banana"},
	{"lease-time", "set interfaces ge-0/0/0 unit 0 family inet dhcp lease-time", "3600", "banana"},
	{"retransmission-attempt", "set interfaces ge-0/0/0 unit 0 family inet dhcp retransmission-attempt", "4", "banana"},
	{"retransmission-interval", "set interfaces ge-0/0/0 unit 0 family inet dhcp retransmission-interval", "2", "banana"},
	{"ntp threshold", "set system ntp threshold", "128", "banana"},
}

func buildTree6940(t *testing.T, cmd string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	p, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.SetPath(p); err != nil {
		t.Fatalf("SetPath(%q): %v", cmd, err)
	}
	return tree
}

// TestBareIntegerLeavesRejectMalformedAtCommit_6940 is the strict half, paired
// on the same path so only the VALUE differs.
func TestBareIntegerLeavesRejectMalformedAtCommit_6940(t *testing.T) {
	for _, tc := range bareLeaves6940 {
		t.Run(tc.name, func(t *testing.T) {
			// PATH CONTROL first. Without it, "the bad value was rejected"
			// cannot be told apart from a path the schema walk never reached —
			// which is exactly how a probe of mine read `ring-entries` as
			// protected when the control value itself was invalid.
			if err := SchemaValidate(buildTree6940(t, tc.path+" "+tc.okValue)); err != nil {
				t.Fatalf("PATH CONTROL FAILED: the VALID value %q was rejected (%v). "+
					"A rejection of the malformed value below would prove nothing.",
					tc.okValue, err)
			}
			err := SchemaValidate(buildTree6940(t, tc.path+" "+tc.badValue))
			if err == nil {
				t.Fatalf("`%s %s` was ACCEPTED at commit-check. `strconv.Atoi` "+
					"discards its error, so this compiles to 0 — and for this leaf "+
					"class 0 is the documented 'not configured' sentinel, making the "+
					"typo indistinguishable from an absent leaf (#6940)",
					tc.path, tc.badValue)
			}
			if !strings.Contains(err.Error(), tc.badValue) {
				t.Errorf("rejected, but not for the value: %v", err)
			}
		})
	}
}

// TestMalformedIntegerLeafWarnsOnTheLenientPath_6940 is the lenient half, and
// it is the half that covers all thirteen: the tolerant ingress does not
// schema-validate, so it is the ONLY path a malformed value can still reach.
//
// PAIRED on the same fixture, one axis:
//
//	lenient compile -> SUCCEEDS (no brick) AND warns (not silent)
//	the field       -> left at its zero value, not a half-parsed number
func TestMalformedIntegerLeafWarnsOnTheLenientPath_6940(t *testing.T) {
	cases := []struct {
		name, cmd, wantIn string
	}{
		{"bare leaf", "set interfaces ae0 aggregated-ether-options minimum-links banana", "minimum-links"},
		{"validated leaf", "set system dataplane workers banana", "workers"},
		{"validated leaf, archival mode change", "set system archival configuration transfer-interval banana", "transfer-interval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(buildTree6940(t, tc.cmd))
			if err != nil {
				t.Fatalf("the tolerant path must NOT reject: a persisted config would "+
					"fail to boot and an HA sync would fail (#1960): %v", err)
			}
			var found string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tc.wantIn) && strings.Contains(w, "not an integer") {
					found = w
				}
			}
			if found == "" {
				t.Fatalf("no warning naming %q. Before #6940 this compiled to 0 in "+
					"silence; a tolerant path that accepts AND rewrites without "+
					"reporting is the accept-and-rewrite posture #1960 forbids.\n"+
					"warnings: %v", tc.wantIn, cfg.Warnings)
			}
			// The warning must name the OFFENDING VALUE, or an operator cannot
			// find it in a large config.
			if !strings.Contains(found, "banana") {
				t.Errorf("warning does not quote the offending value: %q", found)
			}
		})
	}
}

// TestNoDiscardedAtoiRemainsInTheConfigCompiler_6940 is the cohort census: the
// defect is a SHAPE, and a new site added later would reintroduce it silently.
//
// Comment-stripped, because the prose above and in int_leaf_parse_6940.go
// quotes the very pattern it scans for — a gate its own doc comment can satisfy
// is not a gate.
func TestNoDiscardedAtoiRemainsInTheConfigCompiler_6940(t *testing.T) {
	files := configPackageGoFiles6940(t)
	// NON-VACUITY: a walk that found no files would report a clean census.
	if len(files) < 20 {
		t.Fatalf("scanned only %d non-test files in pkg/config — the walk is not "+
			"reaching the package, so this census proves nothing", len(files))
	}
	var offenders []string
	scanned := 0
	for _, f := range files {
		src := stripGoComments6940(readFile6940(t, f))
		scanned += strings.Count(src, "strconv.")
		for _, form := range []string{
			", _ = strconv.Atoi(", ", _ := strconv.Atoi(",
			", _ = strconv.ParseInt(", ", _ := strconv.ParseInt(",
			", _ = strconv.ParseUint(", ", _ := strconv.ParseUint(",
		} {
			if strings.Contains(src, form) {
				offenders = append(offenders, f+" -> "+form)
			}
		}
	}
	// NON-VACUITY: the stripper must not have eaten the code it scans.
	if scanned == 0 {
		t.Fatal("comment-stripped sources contain no `strconv.` at all — the " +
			"stripper removed the code, so the scan above is vacuous")
	}
	if len(offenders) > 0 {
		t.Errorf("a numeric leaf parse discards its error again (#6940): %v\n\n"+
			"`Atoi` returns 0 with its error, and for several config leaves 0 is "+
			"the documented 'not configured' sentinel — so the malformed value is "+
			"indistinguishable from an absent leaf. Use parseIntLeaf.", offenders)
	}
}

func configPackageGoFiles6940(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read pkg/config: %v", err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func readFile6940(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// stripGoComments6940 blanks // and /* */ comments so the census cannot be
// satisfied — or tripped — by prose that quotes the pattern.
func stripGoComments6940(src string) string {
	var b strings.Builder
	inBlock := false
	for _, line := range strings.Split(src, "\n") {
		l := line
		if inBlock {
			if i := strings.Index(l, "*/"); i >= 0 {
				inBlock = false
				l = l[i+2:]
			} else {
				continue
			}
		}
		if i := strings.Index(l, "/*"); i >= 0 {
			inBlock = true
			l = l[:i]
		}
		if i := strings.Index(l, "//"); i >= 0 {
			l = l[:i]
		}
		b.WriteString(l)
		b.WriteString("\n")
	}
	return b.String()
}
