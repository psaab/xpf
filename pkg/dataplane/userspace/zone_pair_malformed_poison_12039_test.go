package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func malformedZonePairSnapshot12039(t *testing.T, action string, fallback string) (*config.Config, *ConfigSnapshot) {
	t.Helper()
	tree := &config.ConfigTree{}
	commands := []string{
		"set security zones security-zone A",
		"set security zones security-zone B",
		"set security zones security-zone C",
		"set security policies from-zone A to-zone [ B C ] policy p1 match source-address any",
		"set security policies from-zone A to-zone [ B C ] policy p1 match destination-address any",
		"set security policies from-zone A to-zone [ B C ] policy p1 match application any",
		"set security policies from-zone A to-zone [ B C ] policy p1 then " + action,
	}
	if fallback == "global permit" {
		commands = append(commands,
			"set security policies global policy g-permit match source-address any",
			"set security policies global policy g-permit match destination-address any",
			"set security policies global policy g-permit match application any",
			"set security policies global policy g-permit then permit")
	} else if fallback == "default permit-all" {
		commands = append(commands, "set security policies default-policy permit-all")
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
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	return cfg, snap
}

// #12039 wire-path proof: a malformed multizone context containing a DENY
// must poison the complete snapshot, not disappear and leave A->B/A->C to a
// global permit or default-policy permit-all. The existing
// LenientContentDropped lowering emits the __unsupported__ application term,
// which the Rust helper's integrity preflight rejects for the whole snapshot.
func TestMalformedZonePairSnapshotRefused12039(t *testing.T) {
	for _, fallback := range []string{"global permit", "default permit-all"} {
		t.Run(fallback, func(t *testing.T) {
			cfg, snap := malformedZonePairSnapshot12039(t, "deny", fallback)
			if len(cfg.Security.MalformedZonePairs) == 0 {
				t.Fatal("fixture did not record a malformed zone pair")
			}
			if len(snap.Capabilities.PolicyContentRejected) == 0 {
				t.Fatalf("snapshot has no whole-snapshot refusal diagnostic: malformed A->B/A->C DENY "+
					"was dropped and traffic falls through to %s; policies=%+v", fallback, snap.Policies)
			}
			sawSentinel := false
			for _, rule := range snap.Policies {
				for _, term := range rule.ApplicationTerms {
					if term.Name == unsupportedApplicationSentinel || term.Protocol == unsupportedApplicationSentinel {
						sawSentinel = true
					}
				}
			}
			if !sawSentinel {
				t.Fatalf("snapshot carries a rejection reason but no __unsupported__ wire sentinel; "+
					"helper preflight cannot refuse the malformed pair before %s fallback", fallback)
			}
			if fallback == "global permit" {
				found := false
				for _, rule := range snap.Policies {
					if rule.Name == "g-permit" && rule.Action == "permit" {
						found = true
					}
				}
				if !found {
					t.Fatal("fixture lacks its global permit fallback")
				}
			}
			if fallback == "default permit-all" && snap.DefaultPolicy != "permit" {
				t.Fatalf("default policy = %q, want permit fallback", snap.DefaultPolicy)
			}
			if reasons := PolicyContentRejectionReasons(cfg, nil); len(reasons) == 0 {
				t.Fatalf("config-level simulator does not refuse the malformed snapshot: %v", reasons)
			}
		})
	}
}

// The #11366 then-permit fixture remains part of the contract: both actions
// must remain bootable at tolerant compile, warn, and poison rather than
// partially enforce the first listed zone.
func TestMalformedZonePairPermitStillPoisonsSnapshot12039(t *testing.T) {
	cfg, snap := malformedZonePairSnapshot12039(t, "permit", "default permit-all")
	if len(snap.Capabilities.PolicyContentRejected) == 0 {
		t.Fatalf("malformed then-permit context must remain quarantined; warnings=%s", strings.Join(cfg.Warnings, "\n"))
	}
}
