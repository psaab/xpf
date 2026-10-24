package config

import "testing"

// #16044: `security flow drop-foreign-session-hits` compiles, and its
// absence leaves the #9519 adjudicate-in-place default untouched.

func compile16044(t *testing.T, commands []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, command := range commands {
		path, err := ParseSetCommand(command)
		if err != nil {
			t.Fatalf("ParseSetCommand %q: %v", command, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", command, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func TestDropForeignSessionHitsCompiles16044(t *testing.T) {
	cfg := compile16044(t, []string{"set security flow drop-foreign-session-hits"})
	if !cfg.Security.Flow.DropForeignSessionHits {
		t.Fatal("drop-foreign-session-hits must compile true")
	}
}

func TestDropForeignSessionHitsDefaultsOff16044(t *testing.T) {
	cfg := compile16044(t, []string{"set security flow allow-dns-reply"})
	if cfg.Security.Flow.DropForeignSessionHits {
		t.Fatal("drop-foreign-session-hits must default off (adjudicate-in-place)")
	}
}
