package config

import (
	"strings"
	"testing"
)

// #15979 (H-6, regression from #15973): FormatPathInheritanceRedactedForNode
// passed a nil ancestor base to redactMatches15942, so every context-gated
// predicate (snmp>community, authentication/md5>key, archive-sites>password,
// gated URL leaves) saw a truncated flattened path and never fired. The
// sibling scoped renderers pass path[:len(path)-width]; this renderer now
// mirrors them. These fixtures assert on the rendered output: each scope
// names the container, and the secret VALUE inside the matched node must
// render as SecretDataPlaceholder (or RedactURL'd), never cleartext.

const (
	leakSNMP15979    = "LEAK-SNMP-COMMUNITY-15979"
	leakOSPF15979    = "LEAK-OSPF-MD5-15979"
	leakArchive15979 = "LEAK-ARCHIVE-PW-15979"
	leakURLPW15979   = "LEAK-URL-PW-15979"
)

func inheritanceRedacted15979(t *testing.T, tree *ConfigTree, path []string) string {
	t.Helper()
	out, err := tree.FormatPathInheritanceRedactedForNode(path, -1)
	if err != nil {
		t.Fatalf("FormatPathInheritanceRedactedForNode(%v): %v", path, err)
	}
	if out == "" {
		t.Fatalf("FormatPathInheritanceRedactedForNode(%v) returned \"\"; the scoped subtree must render", path)
	}
	return out
}

func assertMasked15979(t *testing.T, out, leak, keep string) {
	t.Helper()
	if strings.Contains(out, leak) {
		t.Errorf("scoped inheritance render leaked %q in cleartext:\n%s", leak, out)
	}
	if !strings.Contains(out, SecretDataPlaceholder) {
		t.Errorf("scoped inheritance render did not mask with %s:\n%s", SecretDataPlaceholder, out)
	}
	if keep != "" && !strings.Contains(out, keep) {
		t.Errorf("scoped inheritance render lost non-secret content %q:\n%s", keep, out)
	}
}

// Scoped INHERITANCE fixture at [snmp community]: navigation consumes only
// `snmp` (width=1), the matched nodes' Keys begin `community,<value>`, and
// the community gate needs the discarded `snmp` ancestor.
func TestInheritanceRedactedSNMPCommunity15979(t *testing.T) {
	tree := buildRedactTree(t, []string{
		"set snmp community " + leakSNMP15979 + " authorization read-only",
		"set system host-name fw-h6",
	})
	out := inheritanceRedacted15979(t, tree, []string{"snmp", "community"})
	assertMasked15979(t, out, leakSNMP15979, "read-only")
	if strings.Contains(tree.Format(), SecretDataPlaceholder) {
		t.Error("scoped inheritance render mutated the source tree")
	}
}

// OSPF MD5 + archive masking at scopes where the secret subtree is fully
// inside the matched node: the (authentication, md5) pair and the
// archive-sites token travel with the clone, so these pin that the fix
// keeps masking them (and keeps the credential-free URL payload) without
// over-masking. The discriminating ancestor-loss cases are the SNMP and
// DDNS fixtures below, whose gating tokens are consumed by navigation.
func TestInheritanceRedactedOSPFMD5_15979(t *testing.T) {
	tree := buildRedactTree(t, []string{
		"set protocols ospf area 0.0.0.0 interface ge-0-0-1 authentication md5 1 key " + leakOSPF15979,
	})
	out := inheritanceRedacted15979(t, tree, []string{"protocols", "ospf", "area", "0.0.0.0", "interface", "ge-0-0-1"})
	assertMasked15979(t, out, leakOSPF15979, "md5")
}

func TestInheritanceRedactedArchive15979(t *testing.T) {
	tree := buildRedactTree(t, []string{
		`set system archival configuration archive-sites "scp://user:` + leakURLPW15979 + `@host/dir" password "` + leakArchive15979 + `"`,
		"set system archival configuration transfer-on-commit",
	})
	out := inheritanceRedacted15979(t, tree, []string{"system", "archival", "configuration"})
	assertMasked15979(t, out, leakArchive15979, "transfer-on-commit")
	if strings.Contains(out, leakURLPW15979) {
		t.Errorf("scoped inheritance render leaked the archive URL credential:\n%s", out)
	}
	if !strings.Contains(out, "scp://") || !strings.Contains(out, "host/dir") {
		t.Errorf("scoped inheritance render must keep the credential-free URL payload:\n%s", out)
	}
}

// DDNS provider scope: navigation consumes `dynamic-dns` (and `provider`),
// so the matched `provider dy` clone no longer carries the ancestor that
// gates both its `password` secret and its credential-bearing `server`
// URL. With a nil base both printed clear; with the true prefix the
// password is placeholder-masked and the URL is RedactURL'd while its
// scheme/host/path payload survives.
func TestInheritanceRedactedDDNSProvider15979(t *testing.T) {
	tree := buildRedactTree(t, []string{
		"set system services dynamic-dns provider dy backend dyndns2",
		`set system services dynamic-dns provider dy server "https://user:` + leakURLPW15979 + `@ddns.example/nic/update"`,
		"set system services dynamic-dns provider dy password " + leakArchive15979,
	})
	out := inheritanceRedacted15979(t, tree, []string{"system", "services", "dynamic-dns", "provider", "dy"})
	assertMasked15979(t, out, leakArchive15979, "dyndns2")
	if strings.Contains(out, leakURLPW15979) {
		t.Errorf("scoped inheritance render leaked the DDNS server URL credential:\n%s", out)
	}
	if !strings.Contains(out, "ddns.example/nic/update") {
		t.Errorf("scoped inheritance render must keep the credential-free URL payload:\n%s", out)
	}
}

// Apply-groups inheritance: the community is contributed by a group, so it
// exists only after expansion — exactly the copies whose ancestors are most
// likely above the caller's scope. The inherited copy must render (proving
// expansion ran) and must be masked.
func TestInheritanceRedactedInheritedCommunity15979(t *testing.T) {
	tree := parseHierText(t, `groups {
    g-secrets {
        snmp {
            community `+leakSNMP15979+` {
                authorization read-only;
            }
        }
    }
}
apply-groups g-secrets;
system { host-name fw-h6; }
`)
	out := inheritanceRedacted15979(t, tree, []string{"snmp", "community"})
	assertMasked15979(t, out, leakSNMP15979, "read-only")
	if !strings.Contains(out, "was inherited from group 'g-secrets'") {
		t.Errorf("inherited community must carry its inheritance annotation:\n%s", out)
	}
}

// Over-masking guard: a routing-policy `community` is not an SNMP secret and
// a GRE tunnel `key` has no OSPF MD5 ancestor; both must render verbatim
// under a scoped inheritance render.
func TestInheritanceRedactedKeepsNonSecrets15979(t *testing.T) {
	tree := buildRedactTree(t, []string{
		"set policy-options community CUST members 65000:100",
		"set interfaces gr-0-0-0 unit 0 tunnel key 4242",
	})
	out := inheritanceRedacted15979(t, tree, []string{"policy-options", "community"})
	if !strings.Contains(out, "CUST") || !strings.Contains(out, "65000:100") {
		t.Errorf("policy community was masked (over-redaction):\n%s", out)
	}
	out = inheritanceRedacted15979(t, tree, []string{"interfaces", "gr-0-0-0"})
	if !strings.Contains(out, "4242") {
		t.Errorf("GRE tunnel key was masked (over-redaction):\n%s", out)
	}
}
