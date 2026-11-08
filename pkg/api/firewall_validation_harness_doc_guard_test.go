package api

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func formatIntWithCommas(n int) string {
	in := strconv.Itoa(n)
	var out []byte
	l := len(in)
	for i, c := range in {
		if i > 0 && (l-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// TestFirewallValidationHarnessDocGuard binds docs/firewall-validation-harness-design.md
// to the codebase so the design specification cannot silently drift from live runtime invariants.
func TestFirewallValidationHarnessDocGuard(t *testing.T) {
	root := filepath.Join("..", "..")

	// 1. Doc must exist and be cited in docs/README.md
	docRel := filepath.Join("docs", "firewall-validation-harness-design.md")
	docPath := filepath.Join(root, docRel)
	docBytes, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("design doc %s missing: %v", docPath, err)
	}
	doc := string(docBytes)

	readmeBytes, err := os.ReadFile(filepath.Join(root, "docs", "README.md"))
	if err != nil {
		t.Fatalf("docs/README.md missing: %v", err)
	}
	if !strings.Contains(string(readmeBytes), "firewall-validation-harness-design.md") {
		t.Errorf("docs/README.md must cite %s", docRel)
	}

	// 2. Bind claim: DEFAULT_MAX_SESSIONS must match Rust session constant dynamically
	sessionModPath := filepath.Join(root, "userspace-dp", "src", "session", "mod.rs")
	sessionBytes, err := os.ReadFile(sessionModPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", sessionModPath, err)
	}
	sessionRe := regexp.MustCompile(`const\s+DEFAULT_MAX_SESSIONS:\s*usize\s*=\s*([0-9]+);`)
	match := sessionRe.FindStringSubmatch(string(sessionBytes))
	if len(match) < 2 {
		t.Fatalf("cannot parse DEFAULT_MAX_SESSIONS from %s", sessionModPath)
	}
	maxSessionsInt, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("invalid maxSessions int: %v", err)
	}

	// Assert the doc names the one replicated table's ceiling derived from
	// DEFAULT_MAX_SESSIONS and does not restate the old six-worker sum.
	docDerivedSessionStr := "logical session capacity is " + formatIntWithCommas(maxSessionsInt)
	if !strings.Contains(doc, docDerivedSessionStr) {
		t.Errorf("doc does not contain derived per-table session capacity %q", docDerivedSessionStr)
	}
	sixWorkersDerived := formatIntWithCommas(6 * maxSessionsInt)
	if strings.Contains(doc, sixWorkersDerived) {
		t.Errorf("doc still states the old six-worker multiplied ceiling %q", sixWorkersDerived)
	}

	// 3. Bind claim: Buffer model field UmemInflightFrames exists in protocol_binding.go
	bindingPath := filepath.Join(root, "pkg", "dataplane", "userspace", "protocol_binding.go")
	bindingBytes, err := os.ReadFile(bindingPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", bindingPath, err)
	}
	const bufferField = "UmemInflightFrames"
	if !strings.Contains(string(bindingBytes), bufferField) {
		t.Fatalf("%s missing %s field", bindingPath, bufferField)
	}
	if !strings.Contains(doc, bufferField) {
		t.Errorf("doc does not cite buffer telemetry field %q", bufferField)
	}

	// 4. Bind claim: Cluster lock path agrees with cluster-lock.sh dynamically
	lockScriptPath := filepath.Join(root, "test", "incus", "cluster-lock.sh")
	lockBytes, err := os.ReadFile(lockScriptPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", lockScriptPath, err)
	}
	lockRe := regexp.MustCompile(`XPF_CLUSTER_LOCK="\$\{XPF_CLUSTER_LOCK:-([^}]+)\}"`)
	lockMatch := lockRe.FindStringSubmatch(string(lockBytes))
	if len(lockMatch) < 2 {
		t.Fatalf("cannot parse XPF_CLUSTER_LOCK from %s", lockScriptPath)
	}
	lockPath := lockMatch[1]
	if !strings.Contains(doc, lockPath) {
		t.Errorf("doc does not cite cluster lock path %q", lockPath)
	}

	// 5. Bind claim: Interface rename pattern agrees with linksetup.go
	linksetupPath := filepath.Join(root, "pkg", "daemon", "linksetup.go")
	linksetupBytes, err := os.ReadFile(linksetupPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", linksetupPath, err)
	}
	const renamePrefix = "ge-0-0-"
	if !strings.Contains(string(linksetupBytes), renamePrefix) {
		t.Fatalf("%s missing %s renaming pattern", linksetupPath, renamePrefix)
	}
	if !strings.Contains(doc, renamePrefix) {
		t.Errorf("doc does not cite interface renaming prefix %q", renamePrefix)
	}

	// 6. Bind claim: Fail-closed contract is cited
	if !strings.Contains(doc, "#68 fail-closed") {
		t.Errorf("doc does not cite #68 fail-closed contract")
	}

	// 7. Bind claim: Ledger gate table contract
	// Extract gates from column 5 of the markdown table
	gateRe := regexp.MustCompile(`\|\s*` + "`?" + `([a-z0-9_]+)` + "`?" + `\s*\|\s*$`)
	var foundGates []string
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "| **") {
			m := gateRe.FindStringSubmatch(line)
			if len(m) >= 2 {
				foundGates = append(foundGates, m[1])
			}
		}
	}
	if len(foundGates) < 5 {
		t.Errorf("expected at least 5 declared ledger gates in matrix table, found %d: %v", len(foundGates), foundGates)
	}
	for _, gateName := range foundGates {
		if !strings.HasPrefix(gateName, "wire_") && !strings.HasPrefix(gateName, "fault_") && !strings.HasPrefix(gateName, "parity_") {
			t.Errorf("gate %q does not conform to standard prefix (wire_, fault_, parity_)", gateName)
		}
	}

	// 8. Bind claim: Ledger result infrastructure paths.
	//
	// #8385: these anchor the doc to paths that must EXIST, not merely to
	// strings. The previous version pinned "test/results/ledger.jsonl", which
	// #8346/#8359 replaced with the per-run ledger.d/ shard directory -- and it
	// stayed GREEN, because the doc was stale in the same direction. A pin
	// between two spellings only fires when they disagree, so migrating the
	// underlying artifact and updating neither leaves the pair self-consistent
	// and both wrong. Worse, it then RESISTS the correction: the first person to
	// fix the doc gets a red test and reasonably concludes their change is the
	// defect.
	//
	// The repair is that at least one side must be anchored to something that
	// cannot drift silently. Each path below is checked against the filesystem
	// first, so a future migration reds this test AT THE MIGRATION rather than
	// later at the doc fix.
	for _, p := range []string{
		"test/results/ledger.d",
		"test/incus/harness-result.sh",
	} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Errorf("path %q named by this guard does not exist (%v); the guard is "+
				"asserting a path the tree no longer has -- update the guard AND the "+
				"doc together (#8385)", p, err)
			continue
		}
		if !strings.Contains(doc, p) {
			t.Errorf("doc does not cite %q", p)
		}
	}
}
