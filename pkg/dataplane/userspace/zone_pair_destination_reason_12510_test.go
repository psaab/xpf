package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestMergedFromListContextsRetainEachDestination12510(t *testing.T) {
	tree := &config.ConfigTree{}
	commands := []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security zones security-zone D",
	}
	for _, toZone := range []string{"B", "D"} {
		prefix := "set security policies from-zone [ A C ] to-zone " + toZone + " policy p1 "
		commands = append(commands,
			prefix+"match source-address any",
			prefix+"match destination-address any",
			prefix+"match application any",
			prefix+"then deny")
	}
	for _, command := range commands {
		path, quoted, grouped, err := config.ParseSetCommandGrouped(command)
		if err != nil {
			t.Fatalf("ParseSetCommandGrouped(%q): %v", command, err)
		}
		if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
			t.Fatalf("SetPathQuotedGrouped(%q): %v", command, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	if len(cfg.Security.MalformedZonePairs) != 1 {
		t.Fatalf("want merged malformed context, got %q", cfg.Security.MalformedZonePairs)
	}
	reasons := PolicyContentRejectionReasons(cfg, nil)
	if len(reasons) != 1 {
		t.Fatalf("want one mirror reason, got %q", reasons)
	}
	for _, toZone := range []string{"B", "D"} {
		if !strings.Contains(cfg.Security.MalformedZonePairs[0], toZone) {
			t.Errorf("merged malformed diagnostic does not retain destination %s: %q", toZone, cfg.Security.MalformedZonePairs[0])
		}
	}
	if !strings.Contains(reasons[0], "to-zone B, D") {
		t.Errorf("merged mirror reason does not retain full destination context: %s", reasons[0])
	}
}

func TestMalformedFromZoneMirrorNamesDestination12510(t *testing.T) {
	cases := []struct {
		name       string
		fromZone   string
		toZone     string
		wantToZone string
	}{
		{name: "scalar B", fromZone: "[ A C ]", toZone: "B", wantToZone: "B"},
		{name: "scalar D", fromZone: "[ A C ]", toZone: "D", wantToZone: "D"},
		{name: "destination list", fromZone: "[ A C ]", toZone: "[ B D ]", wantToZone: "[ B D ]"},
	}
	seenReasons := make(map[string]bool, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := malformedZonePairMirrorConfig12288(t, tc.fromZone, tc.toZone)
			reasons := PolicyContentRejectionReasons(cfg, nil)
			if len(reasons) != 1 {
				t.Fatalf("want one mirror reason, got %q", reasons)
			}
			reason := reasons[0]
			if !strings.Contains(reason, "to-zone "+tc.wantToZone) {
				t.Errorf("reason does not name destination zone %q: %s", tc.wantToZone, reason)
			}
			if seenReasons[reason] {
				t.Errorf("distinct malformed destination contexts produced identical mirror reason %q", reason)
			}
			seenReasons[reason] = true
			repeat := PolicyContentRejectionReasons(cfg, nil)
			if len(repeat) != 1 || repeat[0] != reason {
				t.Errorf("mirror reason is not deterministic: first=%q repeat=%q", reasons, repeat)
			}
		})
	}
}
