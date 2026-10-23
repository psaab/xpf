package docsref

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #16111: in-VM tcpdump captures zero packets for AF_XDP fast-path flows.
// The fix is documentation (fix shape 1 in the issue): the active failover
// runbook and the failover skills must state the blindness and name the
// working observation points, so a "capture on both nodes" play cannot be
// misread as "traffic never arrived".
//
// FAIL-ON-REVERT: delete the #16111 observation section from
// testing-docs/failover-testing.md (or any required working-observation
// marker below) and this test fails.
func TestTCPdumpBlindnessGuidance16111(t *testing.T) {
	root := repoRoot(t)

	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}
	require := func(rel, content string, markers ...string) {
		t.Helper()
		for _, m := range markers {
			if !strings.Contains(content, m) {
				t.Errorf("%s missing #16111 marker %q", rel, m)
			}
		}
	}

	failover := read("testing-docs/failover-testing.md")
	require("testing-docs/failover-testing.md", failover,
		// The blindness claim, its mechanism, and its scope.
		"in-VM `tcpdump` is blind",
		"AF_PACKET",
		"AF_XDP",
		"0 packets captured",
		"does not prove the traffic never arrived",
		// Interfaces the issue proved blind.
		"AF_XDP-bound physical NICs",
		"`.80` VLAN sub-interfaces",
		"`xpf-usp0`/`xpf-usp1`",
		"`monitor traffic`",
		// Working observation points.
		"LAN/WAN host captures",
		"`cluster-userspace-host`",
		"gRPC capture service",
		"show chassis cluster data-plane statistics",
		"`RX packets`",
		"`Flow cache hits`",
		"show chassis cluster data-plane interfaces",
		"show chassis cluster data-plane flows",
		"`Last resolution`",
		"`Recent exceptions`",
		"`monitor interface <interface>`",
		"show security flow session",
		// The before/after-on-both-nodes protocol that replaces
		// "capture on both nodes".
		"before and after the failover event, on both nodes",
	)

	// The packet-capture section must not list firewall interfaces as
	// capture targets for fast-path flows.
	if strings.Contains(failover, "- primary WAN parent\n- primary fabric parent\n- secondary fabric parent") {
		t.Errorf("testing-docs/failover-testing.md still lists firewall parents as tcpdump targets (#16111)")
	}

	skill := read(".claude/skills/failover-test/SKILL.md")
	require(".claude/skills/failover-test/SKILL.md", skill,
		"in-VM `tcpdump` is blind",
		"does not prove the traffic never arrived",
		"show chassis cluster data-plane statistics",
	)

	grpcSkill := read(".codex/skills/iperf-grpc-tcpdump/SKILL.md")
	require(".codex/skills/iperf-grpc-tcpdump/SKILL.md", grpcSkill,
		"in-VM `tcpdump` is blind",
		"fw-lan.txt",
		"kernel-visible control only",
		"server-grpc.txt",
	)

	// The capture helper must label its firewall-side artifacts as blind
	// in the summary it emits, not present them as wire evidence.
	script := read(".codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh")
	require(".codex/skills/iperf-grpc-tcpdump/scripts/capture_iperf.sh", script,
		"firewall_tcpdump_note=",
		"blind to AF_XDP fast-path",
	)

	// The historical archive must point readers at the warning instead of
	// being usable as a capture playbook.
	historical := read("testing-docs/ha-failover-validation.md")
	require("testing-docs/ha-failover-validation.md", historical,
		"#16111",
		"in-VM `tcpdump` is blind",
		"failover-testing.md",
	)
}
