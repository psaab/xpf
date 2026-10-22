package config

import "testing"

// Tests for #4821: a hand-authored `load override` config can carry two
// literal `host <name> { ... }` TOP-LEVEL sibling blocks under
// `ssh-known-hosts` (e.g. one declaring an ecdsa key, one declaring an
// ed25519 key for the same host, from concatenated snippets). Same root
// cause as #4818/#4820: the hierarchical parser keeps repeated same-name
// blocks as separate siblings — it does NOT merge — and `load override`
// splices that raw candidate straight into the compiler. Before #4821, the
// `ssh-known-hosts` case in compileSecurity's switch
// (pkg/config/compiler_security.go) built a fresh `keys []SSHKnownHostKey`
// slice per host instance and did an unconditional
// `sec.SSHKnownHosts[hostInst.name] = keys`, so the SECOND host instance
// silently REPLACED the first, discarding its key(s) entirely — an
// operator-visible SSH host-key verification failure. Junos merges repeated
// blocks; the compiler now APPENDS each host's keys onto the existing slice
// for that host name.
//
// SHAPE NOTE (per CLAUDE.md): a duplicate top-level host block is only
// expressible via the hierarchical / NewParser (load-override) path.
// Flat-set ParseSetCommand + SetPath merges two lines with an identical
// key-path into one node, so it is structurally immune and is NOT the
// reproducer here — parseHierText is.

// TestSSHKnownHostsDupBlock4821KeysMerge is the primary RED-on-revert guard:
// two `host h1 { ... }` top-level instances, each declaring a different key
// type. Reverting compileSecurity's ssh-known-hosts case to a bare
// `sec.SSHKnownHosts[hostInst.name] = keys` overwrite makes the second
// instance replace the first, so the ecdsa key is dropped — RED.
func TestSSHKnownHostsDupBlock4821KeysMerge(t *testing.T) {
	tree := parseHierText(t, `
security {
    ssh-known-hosts {
        host h1 {
            ecdsa-sha2-nistp256-key AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY;
        }
        host h1 {
            ssh-ed25519-key AAAAC3NzaC1lZDI1NTE5AAAA;
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	keys := cfg.Security.SSHKnownHosts["h1"]
	if len(keys) != 2 {
		t.Fatalf("host h1 keys = %d, want 2 (ecdsa key dropped by block 2 overwrite — #4821): %+v", len(keys), keys)
	}
	var haveECDSA, haveED25519 bool
	for _, k := range keys {
		switch k.Type {
		case "ecdsa-sha2-nistp256-key":
			haveECDSA = true
			if k.Key != "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY" {
				t.Fatalf("ecdsa key value = %q", k.Key)
			}
		case "ssh-ed25519-key":
			haveED25519 = true
			if k.Key != "AAAAC3NzaC1lZDI1NTE5AAAA" {
				t.Fatalf("ed25519 key value = %q", k.Key)
			}
		}
	}
	if !haveECDSA {
		t.Fatalf("keys = %+v, want ecdsa-sha2-nistp256-key present (#4821)", keys)
	}
	if !haveED25519 {
		t.Fatalf("keys = %+v, want ssh-ed25519-key present (#4821)", keys)
	}
}

// TestSSHKnownHostsDupBlock4821DifferentHostsUnaffected guards against an
// over-broad fix: two DIFFERENT host names must remain independent entries,
// each with its own single key.
func TestSSHKnownHostsDupBlock4821DifferentHostsUnaffected(t *testing.T) {
	tree := parseHierText(t, `
security {
    ssh-known-hosts {
        host h1 {
            ecdsa-sha2-nistp256-key AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY;
        }
        host h2 {
            ssh-ed25519-key AAAAC3NzaC1lZDI1NTE5AAAA;
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if len(cfg.Security.SSHKnownHosts) != 2 {
		t.Fatalf("SSHKnownHosts count = %d, want 2: %+v", len(cfg.Security.SSHKnownHosts), cfg.Security.SSHKnownHosts)
	}
	if len(cfg.Security.SSHKnownHosts["h1"]) != 1 || len(cfg.Security.SSHKnownHosts["h2"]) != 1 {
		t.Fatalf("per-host key counts = h1:%d h2:%d, want 1 each",
			len(cfg.Security.SSHKnownHosts["h1"]), len(cfg.Security.SSHKnownHosts["h2"]))
	}
}

// TestSSHKnownHostsDupBlock4821SingleBlockUnchanged is the byte-identical
// negative control: a single host block with one key must compile exactly
// as before the append change.
func TestSSHKnownHostsDupBlock4821SingleBlockUnchanged(t *testing.T) {
	tree := parseHierText(t, `
security {
    ssh-known-hosts {
        host 192.168.0.253 {
            ecdsa-sha2-nistp256-key AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY;
        }
    }
}`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	keys := cfg.Security.SSHKnownHosts["192.168.0.253"]
	if len(keys) != 1 {
		t.Fatalf("host keys count = %d, want 1", len(keys))
	}
	if keys[0].Type != "ecdsa-sha2-nistp256-key" || keys[0].Key != "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY" {
		t.Fatalf("key = %+v, unexpected", keys[0])
	}
}
