package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestCheckConfigRequiresNodeIDForHA10744(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "ha-cluster.conf"))
	if err != nil {
		t.Fatal(err)
	}

	generic, err := configstore.CheckText(string(content), -1)
	if err != nil {
		t.Fatalf("generic CheckText must retain its standalone fallback contract: %v", err)
	}
	if generic.Chassis.Cluster == nil {
		t.Fatal("HA fixture did not compile a chassis cluster")
	}
	if _, err := checkConfigForDay0(string(content), -1); err == nil ||
		!strings.Contains(err.Error(), "requires -node-id 0 or 1") {
		t.Fatalf("check-config accepted HA config without node ID: %v", err)
	}

	for _, nodeID := range []int{0, 1} {
		compiled, err := checkConfigForDay0(string(content), nodeID)
		if err != nil {
			t.Fatalf("checkConfigForDay0(node %d): %v", nodeID, err)
		}
		if compiled.Chassis.Cluster == nil {
			t.Fatalf("node %d: HA fixture lost its cluster config", nodeID)
		}
	}

	standalone, err := checkConfigForDay0("system { host-name standalone; }", -1)
	if err != nil {
		t.Fatalf("checkConfigForDay0(standalone): %v", err)
	}
	if standalone.Chassis.Cluster != nil {
		t.Fatal("standalone config compiled a chassis cluster")
	}
}
