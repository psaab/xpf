package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #8104: the AST config-read route had no census, and that is how a
// credential-bearing feed path rendered verbatim on `show configuration` for
// years while the REST route redacted the same value.
//
// THREE INSTANCES, all the same shape — the typed route redacts, the AST route
// does not, and nothing compares them:
//
//   - `feed-server <s> feed-name <f> path`  — #7406, fixed 250031dfc
//   - `feed-server <s> hostname`            — found by THIS census, fixed here
//   - `wireguard peer <p> endpoint`         — found by THIS census, fixed here
//
// The second one was predicted in writing by the change that created the
// divergence. FeedServer.Hostname's redaction comment (#6733) says it is
// "named for what it IS, not for what it may carry, so the name-keyed
// redaction pass never masked it — and an operator who writes
// `user:token@feeds.example` here leaks it through the authenticated REST
// GET." That fix covered the REST surface and nothing carried it to the AST
// one.
//
// WHY THE TWO SURFACES DIVERGED AND STAYED DIVERGED. The JSON census
// (url_field_redaction_census_6733_test.go) enumerates its population by
// REFLECTION over typed *Config fields, so it maintains itself. The AST
// redactor has no type to reflect over — `urlLeafIndices` matches keywords in
// a []string path — so its population can only be enumerated deliberately,
// which is exactly why nobody did.
//
// THE PREDICATE. A leaf is URL-shaped iff THE TYPED ROUTE RUNS ITS FIELD
// THROUGH A URL-REDACTION HELPER. That is checkable, stable, and it asserts
// the AGREEMENT between the two surfaces rather than pinning either to a
// heuristic — a heuristic encodes which side you trust, and the defect here is
// precisely that the two sides disagreed. It also maintains itself: adding a
// RedactURL call on the typed side enrols the leaf here automatically.
//
// A name heuristic was measured and rejected. Copying the JSON census's
// patterns selects 18 of the schema's 2,171 leaves and includes NetFlow
// `version9-template` — template NAMES, not URLs — reproducing the exact
// false-population failure that census's own comment records from its first
// draft. The agreement predicate selects 12, with no judgement in it.

// urlRedactionHelpers are the calls that constitute "the typed route redacts
// this as a URL".
//
// FOLLOW THE HELPERS, NOT ONE FUNCTION NAME. redactURLSlice is here because the
// first version of this scan defined the population as "calls RedactURL" and
// SILENTLY MISSED the archive-sites class, which reaches RedactURL through that
// wrapper. It would have shipped as a census that appears to enumerate a
// population while omitting a class — and the omission would have been
// invisible, because this file is what you would consult to find it.
//
// The general form, for whoever extends this and reaches for the same grep:
// defining a set as "things that call X" is a CLAIM that X is the only route to
// the behaviour. That is a population claim and it owes the same scrutiny as
// any other. Whenever a set is defined that way, check what reaches X through a
// wrapper before trusting the count.
var urlRedactionHelpers = regexp.MustCompile(`\b(RedactURL|redactURLSlice)\(`)

var marshalJSONRe = regexp.MustCompile(`func \(\s*\w+\s+\*?(\w+)\s*\) MarshalJSON\(`)

// astLeafClaim maps one typed-route redaction site to the config leaf that
// must ALSO redact on the AST route.
type astLeafClaim struct {
	// set is a `set` command with a single %s for the planted URL.
	set string
	// accepted, when non-empty, records that this leaf deliberately does NOT
	// redact on the AST route, with the reason. It is a strong claim — the
	// typed route DOES redact it — so it is reserved for the unsatisfiable
	// class and each entry owes a justification.
	accepted string
}

// astLeafForRedactedField is the mapping every discovered typed-route site
// must have. It is NOT the population: the population is discovered by
// scanning, and an unmapped site fails the census.
var astLeafForRedactedField = map[string]astLeafClaim{
	"WgPeerConfig.Endpoint": {
		set: `set interfaces wg0 tunnel wireguard peer p1 endpoint "%s"`,
	},
	"FeedServer.URL": {
		set: `set security dynamic-address feed-server fs1 url "%s"`,
	},
	"FeedServer.Hostname": {
		set: `set security dynamic-address feed-server fs1 hostname "%s"`,
	},
	"FeedEntry.Path": {
		set: `set security dynamic-address feed-server fs1 feed-name f1 path "%s"`,
	},
	"RPMTest.Target": {
		set: `set services rpm probe p1 test t1 target url "%s"`,
	},
	"SystemConfig.LicenseAutoUpdate": {
		set: `set system license autoupdate url "%s"`,
	},
	"SystemConfig.LicenseAutoUpdateURLs": {
		set: `set system license autoupdate url "%s"`,
	},
	"ArchivalConfig.ArchiveSites": {
		set: `set system archival configuration archive-sites "%s"`,
	},
	"ArchivalConfig.ArchiveSitesWithPassword": {
		set: `set system syslog file f1 archive archive-sites "%s"`,
	},
	"DDNSProvider.UpdateServer": {
		set: `set system services dynamic-dns provider p1 update-server "%s"`,
	},
	"DDNSProvider.Server": {
		set: `set system services dynamic-dns provider p1 server "%s"`,
	},
	"DDNSProvider.URLTemplate": {
		set: `set system services dynamic-dns provider p1 url-template "%s"`,
	},
	"DDNSProvider.CheckIPURL": {
		set: `set system services dynamic-dns provider p1 checkip-url "%s"`,
	},
}

// discoverTypedURLRedactionSites returns "Type.Field" for every URL-redaction
// call inside a MarshalJSON in pkg/config/types_*.go. Restricting to
// MarshalJSON is what excludes the RedactURL calls in warning and validation
// messages — those are not the config-read route and carry no AST obligation.
func discoverTypedURLRedactionSites(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("types_*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no types_*.go found; the census would pass vacuously")
	}
	assign := regexp.MustCompile(`^\s*\w+\.(\w+)\s*=\s*`)
	out := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var recv string
		depth := 0
		for i, line := range strings.Split(string(b), "\n") {
			if m := marshalJSONRe.FindStringSubmatch(line); m != nil {
				recv, depth = m[1], 0
			}
			if recv == "" {
				continue
			}
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if urlRedactionHelpers.MatchString(line) {
				fm := assign.FindStringSubmatch(line)
				if fm == nil {
					t.Errorf("%s:%d: a URL-redaction call inside %s.MarshalJSON is not a "+
						"simple field assignment, so the census cannot name it:\n  %s",
						f, i+1, recv, strings.TrimSpace(line))
					continue
				}
				out[recv+"."+fm[1]] = fmt.Sprintf("%s:%d", f, i+1)
			}
			if depth <= 0 && strings.Contains(line, "}") {
				recv = ""
			}
		}
	}
	return out
}

// TestASTURLRedactionCensusCoversEveryTypedSite is the population check: every
// field the typed route redacts as a URL must be mapped to an AST leaf here.
// A new RedactURL call on the typed route therefore fails this test until its
// AST counterpart is considered — which is the property the name-keyed switch
// never had, and the reason it could only grow by someone remembering.
func TestASTURLRedactionCensusCoversEveryTypedSite(t *testing.T) {
	sites := discoverTypedURLRedactionSites(t)
	if len(sites) == 0 {
		t.Fatal("discovered no typed-route URL-redaction sites; the scan is broken " +
			"and every other assertion in this file would pass vacuously")
	}
	var missing []string
	for name, where := range sites {
		if _, ok := astLeafForRedactedField[name]; !ok {
			missing = append(missing, fmt.Sprintf("%s (%s)", name, where))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("the typed config-read route redacts these as URLs, but the AST route "+
			"census does not map them to a leaf:\n  %s\n\n"+
			"That asymmetry is #8104: the typed route redacts, `show configuration` and "+
			"the gRPC config RPCs render verbatim, and nothing compares the two. Add an "+
			"astLeafForRedactedField entry with the `set` spelling of the leaf; if the AST "+
			"route deliberately does not redact it, set `accepted` with the reason.",
			strings.Join(missing, "\n  "))
	}
}

// TestASTURLRedactionCensusHasNoDeadEntries is the dead-entry rejection. An
// accepted-list without it decays into a permission slip: an entry that stops
// corresponding to a real typed-route site would keep excusing a leaf nobody
// redacts any more.
func TestASTURLRedactionCensusHasNoDeadEntries(t *testing.T) {
	sites := discoverTypedURLRedactionSites(t)
	var dead []string
	for name := range astLeafForRedactedField {
		if _, ok := sites[name]; !ok {
			dead = append(dead, name)
		}
	}
	sort.Strings(dead)
	if len(dead) > 0 {
		t.Errorf("these census entries name a typed-route redaction site that no longer "+
			"exists:\n  %s\n\nEither the field was renamed, or its typed-route redaction "+
			"was removed — in which case the AST-side obligation may have gone with it, or "+
			"may now be the ONLY thing redacting it. Re-derive before deleting the entry.",
			strings.Join(dead, "\n  "))
	}
}

// TestASTRouteRedactsEveryURLShapedLeaf is the behavioural verdict. It plants a
// credential-bearing URL in each mapped leaf, renders through RedactedClone on
// every format the config-read route can emit, and requires the credential to
// be gone.
//
// The assertion is on BEHAVIOUR — does the planted secret appear in the render
// — never on the presence of a case in urlLeafIndices. A case can exist and be
// gated so it never fires, which is indistinguishable from a correct one by
// inspection.
func TestASTRouteRedactsEveryURLShapedLeaf(t *testing.T) {
	for name, claim := range astLeafForRedactedField {
		t.Run(name, func(t *testing.T) {
			const secret = "SECRET8104TOKEN"
			planted := fmt.Sprintf("https://user:%s@host.example.com/base?token=%s", secret, secret)
			line := fmt.Sprintf(claim.set, planted)

			toks, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v — the census entry does not parse, so "+
					"this row asserts nothing", line, err)
			}
			tree := &ConfigTree{}
			if err := tree.SetPath(toks); err != nil {
				t.Fatalf("SetPath(%q): %v — the census entry is not a real leaf, so this "+
					"row asserts nothing", line, err)
			}

			red := tree.RedactedClone()
			renders := map[string]string{
				"Format":     red.Format(),
				"FormatSet":  red.FormatSet(),
				"FormatJSON": red.FormatJSON(),
				"FormatXML":  red.FormatXML(),
			}
			leaked := false
			for _, out := range renders {
				if strings.Contains(out, secret) {
					leaked = true
				}
			}

			if claim.accepted != "" {
				if !leaked {
					t.Errorf("%s is on the accepted list (%q) but the AST route now REDACTS "+
						"it. The acceptance is stale — remove it. An accepted entry that has "+
						"stopped being true excuses a leaf that no longer needs excusing, and "+
						"the next reader will trust it.", name, claim.accepted)
				}
				return
			}
			for format, out := range renders {
				if strings.Contains(out, secret) {
					t.Errorf("%s: the typed config-read route redacts this field, but the AST "+
						"route rendered the planted credential VERBATIM in %s.\n  set: %s\n\n"+
						"This is the #8104 class: two surfaces over one value, only one "+
						"redacting. Either add the leaf to urlLeafIndices, or record it in the "+
						"census as `accepted` with the reason it cannot be redacted.",
						name, format, line)
				}
			}
		})
	}
}
