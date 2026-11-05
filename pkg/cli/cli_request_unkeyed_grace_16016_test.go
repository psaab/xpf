package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/osident"
)

func TestRequestUnkeyedGraceRestartUsesCurrentOperatorAndReportsCutoff16016(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "unkeyed-authority-grace")
	restorePath := cluster.SetUnkeyedAuthorityGraceStatePathForTesting(statePath)
	t.Cleanup(restorePath)

	wall := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	mono := int64(time.Second)
	restoreClocks := cluster.SetUnkeyedAuthorityClocksForTesting(
		func() time.Time { return wall },
		func() int64 { return mono },
	)
	t.Cleanup(restoreClocks)

	manager := cluster.NewManager(0, 1)
	manager.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0"})
	wall = wall.Add(73 * time.Hour)
	mono += int64(73 * time.Hour)
	if !manager.UnkeyedAuthorityExpired() {
		t.Fatal("test setup did not expire the initial unkeyed-authority grace")
	}

	operator := osident.Current().String()
	var auditedOperator string
	manager.SetUnkeyedRecoveryAuditHook(func(action, gotOperator string, rgID, nodeID int, at time.Time, reason string) {
		if action == "unkeyed-grace-restart" && rgID == -1 && nodeID == manager.NodeID() &&
			!at.IsZero() && reason != "" {
			auditedOperator = gotOperator
		}
	})

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	oldStdout := os.Stdout
	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
		_ = writer.Close()
		_ = reader.Close()
	}()

	callErr := (&CLI{cluster: manager, username: "stale-cached-operator"}).handleRequestChassis(
		[]string{"cluster", "unkeyed-grace", "restart"})
	_ = writer.Close()
	os.Stdout = oldStdout
	output, readErr := io.ReadAll(reader)
	if readErr != nil {
		t.Fatalf("read command output: %v", readErr)
	}
	if callErr != nil {
		t.Fatalf("unkeyed-grace restart: %v", callErr)
	}

	cutoff := manager.UnkeyedGraceExpiry()
	if cutoff.IsZero() {
		t.Fatal("successful restart did not publish a grace cutoff")
	}
	if auditedOperator != operator {
		t.Fatalf("audit operator = %q, want current OS identity %q", auditedOperator, operator)
	}
	for _, want := range []string{
		"operator " + operator,
		"node 0",
		cutoff.Format(time.RFC3339Nano),
	} {
		if !strings.Contains(string(output), want) {
			t.Errorf("restart output %q missing %q", output, want)
		}
	}
	if strings.Contains(string(output), "stale-cached-operator") {
		t.Fatalf("restart used cached CLI username: %q", output)
	}
}

func TestRequestForcePrimaryUsesCurrentOperator16016(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "unkeyed-authority-grace")
	restorePath := cluster.SetUnkeyedAuthorityGraceStatePathForTesting(statePath)
	t.Cleanup(restorePath)

	wall := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	mono := int64(time.Second)
	restoreClocks := cluster.SetUnkeyedAuthorityClocksForTesting(
		func() time.Time { return wall },
		func() int64 { return mono },
	)
	t.Cleanup(restoreClocks)

	groups := []*config.RedundancyGroup{{ID: 0, NodePriorities: map[int]int{0: 100, 1: 200}}}
	manager := cluster.NewManager(0, 1)
	manager.UpdateConfig(&config.ClusterConfig{ControlInterface: "em0", RedundancyGroups: groups})
	wall = wall.Add(73 * time.Hour)
	mono += int64(73 * time.Hour)
	if !manager.UnkeyedAuthorityExpired() {
		t.Fatal("test setup did not expire the initial unkeyed-authority grace")
	}
	manager.UpdateConfig(&config.ClusterConfig{
		ControlInterface: "em0", RedundancyGroups: groups,
		ControlLinkAuthKey: config.NewSecret("force-primary-cli-16016"),
	})

	operator := osident.Current().String()
	var auditedOperator string
	manager.SetUnkeyedRecoveryAuditHook(func(action, gotOperator string, rgID, nodeID int, at time.Time, reason string) {
		if action == "force-primary" && rgID == 0 && nodeID == manager.NodeID() &&
			!at.IsZero() && reason != "" {
			auditedOperator = gotOperator
		}
	})
	err := (&CLI{cluster: manager, username: "stale-cached-operator"}).handleRequestChassis(
		[]string{"cluster", "failover", "force-primary", "redundancy-group", "0", "override", "unkeyed-recovery"})
	if err != nil {
		t.Fatalf("force-primary request: %v", err)
	}
	if auditedOperator != operator {
		t.Fatalf("force-primary audit operator = %q, want current OS identity %q", auditedOperator, operator)
	}
}
