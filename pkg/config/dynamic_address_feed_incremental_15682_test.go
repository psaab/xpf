package config

import (
	"strings"
	"testing"
)

// #15682: incremental `set ... feed-name <feed>` followed by
// `feed-name <feed> path <path>` must upsert one FeedEntry, not append a
// duplicate that the strict uniqueness gate self-rejects and the lenient
// feeds.Manager path resolves to the bare (path-less) entry.

func feedServer15682(t *testing.T, cfg *Config, name string) *FeedServer {
	t.Helper()
	fs := cfg.Security.DynamicAddress.FeedServers[name]
	if fs == nil {
		t.Fatalf("feed-server %q missing from %+v", name, cfg.Security.DynamicAddress.FeedServers)
	}
	return fs
}

func TestDynamicAddressIncrementalFeedNamePath15682(t *testing.T) {
	cmds := []string{
		"set security dynamic-address feed-server s1 url https://feeds.example/list.txt",
		"set security dynamic-address feed-server s1 feed-name f1",
		"set security dynamic-address feed-server s1 feed-name f1 path /list.txt",
	}
	t.Run("strict commits single server", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree4913(t, cmds))
		if err != nil {
			t.Fatalf("incremental bare+path feed-name should commit, got: %v", err)
		}
		fs := feedServer15682(t, cfg, "s1")
		if len(fs.FeedEntries) != 1 || fs.FeedEntries[0] != (FeedEntry{Name: "f1", Path: "/list.txt"}) {
			t.Fatalf("FeedEntries = %+v (FeedName=%q); want exactly one {f1 /list.txt}", fs.FeedEntries, fs.FeedName)
		}
		if fs.FeedName != "" {
			t.Fatalf("FeedName = %q; want cleared once a path entry exists", fs.FeedName)
		}
	})
	t.Run("lenient keeps configured path", func(t *testing.T) {
		cfg, err := CompileConfigLenient(buildTree4913(t, cmds))
		if err != nil {
			t.Fatalf("lenient compile: %v", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "more than one feed-server") {
				t.Fatalf("lenient compile should not warn of self-duplicate feed, warnings=%v", cfg.Warnings)
			}
		}
		fs := feedServer15682(t, cfg, "s1")
		if len(fs.FeedEntries) != 1 || fs.FeedEntries[0].Path != "/list.txt" {
			t.Fatalf("lenient FeedEntries = %+v; want one entry with path /list.txt", fs.FeedEntries)
		}
	})
	t.Run("bare after path does not drop path", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree4913(t, []string{
			"set security dynamic-address feed-server s1 url https://feeds.example/list.txt",
			"set security dynamic-address feed-server s1 feed-name f1 path /list.txt",
			"set security dynamic-address feed-server s1 feed-name f1",
		}))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		fs := feedServer15682(t, cfg, "s1")
		if len(fs.FeedEntries) != 1 || fs.FeedEntries[0] != (FeedEntry{Name: "f1", Path: "/list.txt"}) {
			t.Fatalf("FeedEntries = %+v; want one {f1 /list.txt}", fs.FeedEntries)
		}
	})
}

func TestDynamicAddressFeedPathOverrideMergedBlocks15682(t *testing.T) {
	input := `security {
    dynamic-address {
        feed-server s1 {
            url https://feeds.example/list.txt;
            feed-name f1;
        }
        feed-server s1 {
            feed-name f1 {
                path /new.txt;
            }
        }
        feed-server s2 {
            url https://feeds.example/other.txt;
            feed-name f2 {
                path /old.txt;
            }
        }
        feed-server s2 {
            feed-name f2 {
                path /new2.txt;
            }
        }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("merged blocks should commit, got: %v", err)
	}

	fs := feedServer15682(t, cfg, "s1")
	if len(fs.FeedEntries) != 1 || fs.FeedEntries[0] != (FeedEntry{Name: "f1", Path: "/new.txt"}) {
		t.Fatalf("s1 FeedEntries = %+v (FeedName=%q); want one {f1 /new.txt}", fs.FeedEntries, fs.FeedName)
	}
	fs2 := feedServer15682(t, cfg, "s2")
	if len(fs2.FeedEntries) != 1 || fs2.FeedEntries[0] != (FeedEntry{Name: "f2", Path: "/new2.txt"}) {
		t.Fatalf("s2 FeedEntries = %+v; want one {f2 /new2.txt} (later path overrides)", fs2.FeedEntries)
	}
}
func TestDynamicAddressBindingFeedNamesDedupHierarchical15682(t *testing.T) {
	input := `security {
    dynamic-address {
        feed-server s1 { url https://feeds.example/list.txt; feed-name f1 { path /list.txt; } }
        address-name addr1 { profile { feed-name f1; } }
        address-name addr1 { profile { feed-name f1; } }
    }
}`
	tree, errs := NewParser(input).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ab := cfg.Security.DynamicAddress.AddressBindings["addr1"]
	if ab == nil || len(ab.FeedNames) != 1 || ab.FeedNames[0] != "f1" {
		t.Fatalf("AddressBindings[addr1] = %+v; want FeedNames [f1] exactly once", ab)
	}
}

func TestDynamicAddressBindingFeedNamesDedup15682(t *testing.T) {
	cmds := []string{
		"set security dynamic-address feed-server s1 url https://feeds.example/list.txt",
		"set security dynamic-address feed-server s1 feed-name f1 path /list.txt",
		"set security dynamic-address address-name addr1 profile feed-name f1",
		"set security dynamic-address address-name addr1 profile feed-name f1",
	}
	cfg, err := CompileConfig(buildTree4913(t, cmds))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ab := cfg.Security.DynamicAddress.AddressBindings["addr1"]
	if ab == nil || len(ab.FeedNames) != 1 || ab.FeedNames[0] != "f1" {
		t.Fatalf("AddressBindings[addr1] = %+v; want FeedNames [f1] exactly once", ab)
	}
}

// Applied container shapes that are genuine policy actions with modifiers,
// not feed refinements, must keep the two-node split the #3114/#3115/#3141
// gates inspect (compiler_policy_then_twonode_3377_test.go): SetPath must
// NOT promote the bare leaf into a container for these.
func TestDynamicAddressSetPathKeepsThenActionSplit15682(t *testing.T) {
	tree := &ConfigTree{}
	for _, cmd := range []string{
		"set security policies from-zone trust to-zone untrust policy p then permit",
		"set security policies from-zone trust to-zone untrust policy p then permit application-services utm",
	} {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatal(err)
		}
	}
	sec := tree.FindChild("security")
	pol := sec.FindChild("policies").FindChild("from-zone").FindChild("policy")
	then := pol.FindChild("then")
	if n := len(then.FindChildren("permit")); n != 2 {
		t.Fatalf("then permit nodes = %d; want 2 (bare leaf + extended node preserved)", n)
	}
}
