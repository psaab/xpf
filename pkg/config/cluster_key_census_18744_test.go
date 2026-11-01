package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// #18744 census: no tracked config or document carries a real chassis
// cluster key. Every cluster key value of 16 characters or more in a tracked
// .conf, .set or .md file must be a published placeholder or the #18732
// render token. Shorter values cannot be real keys (the strict gate refuses a
// primary under MinAdvisedControlLinkKeyLen); they are prose like `A`, `B`
// and `<key>`.

// renderToken18732 is test/incus/deploy-lib.sh's DEPLOY_CLUSTER_KEY_TOKEN.
const renderToken18732 = "xpf-lab-cluster-key-substituted-at-deploy-CHANGE-ME"

// censusExempt18744 are generated mirrors of GitHub issue and PR text
// (scripts sync-history). They quote test fixtures verbatim, and they are
// regenerated rather than edited, so a hand fix there would not stick.
var censusExempt18744 = map[string]bool{
	"docs/issues/issue-history.md": true,
	"docs/issues/pr-history.md":    true,
}

var (
	setFormKey18744  = regexp.MustCompile(`set chassis cluster (?:additional-)?authentication-key\s+("[^"]*"|[^\s` + "`" + `|)]+)`)
	leafFormKey18744 = regexp.MustCompile(`(?:^|\s)(?:additional-)?authentication-key\s+("[^"]*"|[^\s;]+)`)
)

// clusterKeyValues18744 returns every chassis cluster key value in text: the
// set form anywhere, and the hierarchical leaf form inside a
// `chassis { cluster { ... } }` block (a line-based brace stack, reset at a
// Markdown fence).
func clusterKeyValues18744(text string) []string {
	var out []string
	var stack []string
	for _, raw := range strings.Split(text, "\n") {
		line := raw
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			stack = nil
			continue
		}
		for _, m := range setFormKey18744.FindAllStringSubmatch(line, -1) {
			out = append(out, m[1])
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasSuffix(trimmed, "{"):
			fields := strings.Fields(strings.TrimSuffix(trimmed, "{"))
			name := ""
			if len(fields) > 0 {
				name = fields[0]
			}
			stack = append(stack, name)
			continue
		case strings.HasPrefix(trimmed, "}"):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		inCluster := false
		for i := 0; i+1 < len(stack); i++ {
			if stack[i] == "chassis" && stack[i+1] == "cluster" {
				inCluster = true
			}
		}
		if !inCluster || strings.Contains(line, "set chassis cluster") {
			continue
		}
		for _, m := range leafFormKey18744.FindAllStringSubmatch(line, -1) {
			out = append(out, m[1])
		}
	}
	for i, v := range out {
		out[i] = strings.Trim(v, "\"`',;")
	}
	return out
}

func censusProblem18744(v string) bool {
	return len(v) >= MinAdvisedControlLinkKeyLen && v != renderToken18732 && !clusterKeyIsPublishedPlaceholder(v)
}

func TestNoTrackedFileCarriesARealClusterKey18744(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "-C", root, "ls-files", "--", "*.conf", "*.set", "*.md").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	files := strings.Fields(string(out))
	scanned, values := 0, 0
	shipped := map[string]bool{}
	for _, f := range files {
		if censusExempt18744[f] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		scanned++
		for _, v := range clusterKeyValues18744(string(data)) {
			values++
			if strings.HasPrefix(f, "docs/ha-cluster") {
				shipped[f] = true
			}
			if censusProblem18744(v) {
				// Never print the value: it may be a real key.
				t.Errorf("%s carries a chassis cluster key of %d characters that is neither a "+
					"published placeholder nor the #18732 render token; take it out of the "+
					"repository and rotate the cluster that used it", f, len(v))
			}
		}
	}
	// Non-vacuity: the census must have reached the shipped HA confs.
	if scanned < 100 || len(shipped) < 5 {
		t.Fatalf("census scanned %d files and found keys in %d docs/ha-cluster*.conf (want >= 100 and >= 5); "+
			"the scan is not reading what it claims to", scanned, len(shipped))
	}
	t.Logf("scanned %d tracked files, %d chassis cluster key values", scanned, values)
}

// The extractor itself: it must find a real-looking key in each form it
// claims, and ignore keys outside chassis cluster.
func TestClusterKeyCensusExtractor18744(t *testing.T) {
	const real = "Vszxr1XqVetBwtLPWlm0vLadzri2JmBTjdmn2FbSKgI="
	for name, tc := range map[string]struct {
		text string
		want bool
	}{
		"set form":         {"set chassis cluster authentication-key " + real + "\n", true},
		"set form quoted":  {"`set chassis cluster additional-authentication-key \"" + real + "\"`\n", true},
		"hierarchical":     {"chassis {\n    cluster {\n        authentication-key \"" + real + "\";\n    }\n}\n", true},
		"in a md fence":    {"```\nchassis {\n  cluster {\n    authentication-key " + real + ";\n  }\n}\n```\n", true},
		"token":            {"chassis {\n cluster {\n  authentication-key \"" + renderToken18732 + "\";\n }\n}\n", false},
		"placeholder":      {"set chassis cluster authentication-key xpf-lab-ha-psk-cluster-22-CHANGE-ME\n", false},
		"ospf key":         {"protocols {\n ospf {\n  area 0 {\n   interface ge-0-0-1 {\n    authentication-key \"" + real + "\";\n   }\n  }\n }\n}\n", false},
		"short metasyntax": {"set chassis cluster authentication-key B\n", false},
	} {
		got := false
		for _, v := range clusterKeyValues18744(tc.text) {
			if censusProblem18744(v) {
				got = true
			}
		}
		if got != tc.want {
			t.Errorf("%s: flagged=%v, want %v (values %q)", name, got, tc.want, clusterKeyValues18744(tc.text))
		}
	}
}
