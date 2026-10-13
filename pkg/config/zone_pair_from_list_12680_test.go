package config

import (
	"strings"
	"testing"
)

func fromListTree12680(t *testing.T, grouped bool, fromZone string) *ConfigTree {
	t.Helper()
	commands := []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security zones security-zone D",
		"set security zones security-zone E",
		"set security policies default-policy permit-all",
	}
	prefix := "set security policies from-zone " + fromZone + " to-zone B policy p1 "
	commands = append(commands, prefix+"match source-address any", prefix+"match destination-address any",
		prefix+"match application any", prefix+"then deny")
	tree := &ConfigTree{}
	for _, command := range commands {
		if grouped {
			path, quoted, group, err := ParseSetCommandGrouped(command)
			if err != nil {
				t.Fatalf("ParseSetCommandGrouped(%q): %v", command, err)
			}
			if err := tree.SetPathQuotedGrouped(path, quoted, group); err != nil {
				t.Fatalf("SetPathQuotedGrouped(%q): %v", command, err)
			}
		} else {
			path, err := ParseSetCommand(command)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", command, err)
			}
			tree.SetPath(path)
		}
	}
	return tree
}

func TestThreeMemberFromZoneListsAreRefused12680(t *testing.T) {
	for _, parser := range []struct {
		name    string
		grouped bool
	}{
		{"grouped", true},
		{"legacy", false},
	} {
		for _, list := range []string{"[ A C D ]", "[ A C D E ]", "[ A A D ]", "[ A B D ]"} {
			t.Run(parser.name+"/"+list, func(t *testing.T) {
				tree := fromListTree12680(t, parser.grouped, list)
				_, err := CompileConfig(tree)
				if err == nil || !strings.Contains(err.Error(), "from-zone") || !strings.Contains(err.Error(), "to-zone B") {
					t.Fatalf("malformed from-zone list %s must be rejected with its destination, got %v", list, err)
				}
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("lenient compile must remain bootable: %v", err)
				}
				if len(cfg.Security.MalformedZonePairs) != 1 || len(cfg.Security.Policies) != 0 {
					t.Fatalf("malformed from-list must be recorded and skipped, malformed=%q policies=%+v",
						cfg.Security.MalformedZonePairs, cfg.Security.Policies)
				}
			})
		}
	}
}

func TestThreeMemberFromZoneListReasonsRemainDistinct12680(t *testing.T) {
	for _, tc := range []struct{ list, reason string }{
		{"[ A C D ]", "from-zone [ A C D ] to-zone B:"},
		{"[ A C E ]", "from-zone [ A C E ] to-zone B:"},
		{"[ A A D ]", "from-zone [ A A D ] to-zone B:"},
		{"[ A B D ]", "from-zone [ A B D ] to-zone B:"},
	} {
		tree := fromListTree12680(t, true, tc.list)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient: %v", err)
		}
		if got := cfg.Security.MalformedZonePairs; len(got) != 1 || !strings.Contains(got[0], tc.reason) {
			t.Fatalf("diagnostic for %s = %q, want %q", tc.list, got, tc.reason)
		}
	}
}

func TestSingleMemberFromZoneBracketAndSeparatePairsRemainValid12680(t *testing.T) {
	for _, parser := range []struct {
		name    string
		grouped bool
	}{
		{"grouped", true},
		{"legacy", false},
	} {
		t.Run(parser.name, func(t *testing.T) {
			cfg, err := CompileConfig(fromListTree12680(t, parser.grouped, "[ A ]"))
			if err != nil {
				t.Fatalf("single-member bracket must remain valid: %v", err)
			}

			if len(cfg.Security.Policies) != 1 || cfg.Security.Policies[0].FromZone != "A" ||
				cfg.Security.Policies[0].ToZone != "B" || len(cfg.Security.Policies[0].Policies) != 1 {
				t.Fatalf("single-member bracket compiled incorrectly: %+v", cfg.Security.Policies)
			}
		})
	}
}
func TestThreeSeparateFromZonePairsRemainValid12680(t *testing.T) {
	for _, parser := range []struct {
		name    string
		grouped bool
	}{
		{"grouped", true},
		{"legacy", false},
	} {
		t.Run(parser.name, func(t *testing.T) {
			tree := &ConfigTree{}
			commands := []string{
				"set security zones security-zone A",
				"set security zones security-zone B",
				"set security zones security-zone C",
				"set security zones security-zone D",
				"set security zones security-zone E",
			}
			for _, toZone := range []string{"B", "C", "D"} {
				prefix := "set security policies from-zone A to-zone " + toZone + " policy p1 "
				commands = append(commands, prefix+"match source-address any", prefix+"match destination-address any",
					prefix+"match application any", prefix+"then deny")
			}
			for _, command := range commands {
				if parser.grouped {
					path, quoted, group, err := ParseSetCommandGrouped(command)
					if err != nil {
						t.Fatalf("ParseSetCommandGrouped(%q): %v", command, err)
					}
					if err := tree.SetPathQuotedGrouped(path, quoted, group); err != nil {
						t.Fatalf("SetPathQuotedGrouped(%q): %v", command, err)
					}
				} else {
					path, err := ParseSetCommand(command)
					if err != nil {
						t.Fatalf("ParseSetCommand(%q): %v", command, err)
					}
					tree.SetPath(path)
				}
			}
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("three separate one-pair contexts must remain valid: %v", err)
			}
			if len(cfg.Security.Policies) != 3 || len(cfg.Security.MalformedZonePairs) != 0 {
				t.Fatalf("three separate pairs compiled unexpectedly: policies=%+v malformed=%q",
					cfg.Security.Policies, cfg.Security.MalformedZonePairs)
			}
		})
	}
}
