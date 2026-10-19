package config

import (
	"testing"
)

// #15018 (A13-01): a second `system` root or a repeated
// `root-authentication` / `archival` / `internet-options` block reset the
// stanza to a fresh struct. compileSystem is called once per `system`
// root (compiler_dispatch.go) and its child loop sees every repeated
// child, so an unconditional `sys.X = &T{}` discarded everything the
// earlier block contributed. For root-authentication that is a
// management lockout: applyRootAuth writes the compiled set as the whole
// of root's authorized_keys and locks an xpf-provisioned root password
// when the stanza comes back empty, after a commit reported success.
//
// The fix allocates once (the #6957 `sys.Login` shape one stanza over)
// and accumulates: SSH keys and archive-sites append, scalar leaves
// (encrypted-password, transfer-interval) stay last-writer-wins only
// when actually authored in the later block.

const (
	rootAuthHash15018   = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	rootAuthHash2_15018 = "$6$othersalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
	rootAuthKey1_15018  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfirst a@b"
	rootAuthKey2_15018  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKsecond c@d"
)

func compile15018(t *testing.T, text string) *Config {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse error for %q: %v", text, perrs[0])
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile failed for %q: %v", text, err)
	}
	return cfg
}

func wantRootAuth15018(t *testing.T, cfg *Config, wantPW string, wantKeys int) {
	t.Helper()
	ra := cfg.System.RootAuthentication
	if ra == nil {
		t.Fatal("RootAuthentication is nil — applyRootAuth would revoke root credentials")
	}
	if got := ra.EncryptedPassword.Reveal(); got != wantPW {
		t.Errorf("EncryptedPassword = %q, want %q (earlier block's password must survive a later block)", got, wantPW)
	}
	if len(ra.SSHKeys) != wantKeys {
		t.Fatalf("SSHKeys = %v (%d), want %d keys accumulated across blocks", ra.SSHKeys, len(ra.SSHKeys), wantKeys)
	}
}

func TestRepeatedRootAuthenticationAccumulates15018(t *testing.T) {
	t.Run("two children under one system", func(t *testing.T) {
		cfg := compile15018(t, "system {\n"+
			" root-authentication {\n  encrypted-password \""+rootAuthHash15018+"\";\n  ssh-ed25519 \""+rootAuthKey1_15018+"\";\n }\n"+
			" root-authentication {\n  ssh-ed25519 \""+rootAuthKey2_15018+"\";\n }\n"+
			"}")
		wantRootAuth15018(t, cfg, rootAuthHash15018, 2)
		if cfg.System.RootAuthentication.SSHKeys[0] != rootAuthKey1_15018 ||
			cfg.System.RootAuthentication.SSHKeys[1] != rootAuthKey2_15018 {
			t.Errorf("SSHKeys order = %v, want [first second]", cfg.System.RootAuthentication.SSHKeys)
		}
	})

	t.Run("two system roots", func(t *testing.T) {
		cfg := compile15018(t,
			"system {\n root-authentication {\n  encrypted-password \""+rootAuthHash15018+"\";\n  ssh-ed25519 \""+rootAuthKey1_15018+"\";\n }\n}\n"+
				"system {\n root-authentication {\n  ssh-ed25519 \""+rootAuthKey2_15018+"\";\n }\n}")
		wantRootAuth15018(t, cfg, rootAuthHash15018, 2)
	})

	t.Run("later password is last-writer-wins, keys still accumulate", func(t *testing.T) {
		cfg := compile15018(t, "system {\n"+
			" root-authentication {\n  encrypted-password \""+rootAuthHash15018+"\";\n  ssh-ed25519 \""+rootAuthKey1_15018+"\";\n }\n"+
			" root-authentication {\n  encrypted-password \""+rootAuthHash2_15018+"\";\n  ssh-ed25519 \""+rootAuthKey2_15018+"\";\n }\n"+
			"}")
		wantRootAuth15018(t, cfg, rootAuthHash2_15018, 2)
	})

	t.Run("empty repeated block revokes nothing", func(t *testing.T) {
		cfg := compile15018(t, "system {\n"+
			" root-authentication {\n  encrypted-password \""+rootAuthHash15018+"\";\n  ssh-ed25519 \""+rootAuthKey1_15018+"\";\n }\n"+
			" root-authentication {\n }\n"+
			"}")
		wantRootAuth15018(t, cfg, rootAuthHash15018, 1)
	})

	// Control: the single-block spelling is unchanged.
	t.Run("single block control", func(t *testing.T) {
		cfg := compile15018(t, "system {\n root-authentication {\n  encrypted-password \""+rootAuthHash15018+"\";\n  ssh-ed25519 \""+rootAuthKey1_15018+"\";\n }\n}")
		wantRootAuth15018(t, cfg, rootAuthHash15018, 1)
	})
}

func TestRepeatedArchivalAccumulates15018(t *testing.T) {
	t.Run("two children under one system keep both sites", func(t *testing.T) {
		cfg := compile15018(t, `system {
 archival {
  configuration {
   transfer-on-commit;
   archive-sites { "scp://backup@10.0.0.1:/configs"; }
  }
 }
 archival {
  configuration {
   transfer-interval 30;
   archive-sites { "scp://backup@10.0.0.2:/configs"; }
  }
 }
}`)
		arch := cfg.System.Archival
		if arch == nil {
			t.Fatal("Archival is nil")
		}
		if len(arch.ArchiveSites) != 2 ||
			arch.ArchiveSites[0] != "scp://backup@10.0.0.1:/configs" ||
			arch.ArchiveSites[1] != "scp://backup@10.0.0.2:/configs" {
			t.Errorf("ArchiveSites = %v, want both sites accumulated across blocks", arch.ArchiveSites)
		}
		if !arch.TransferOnCommit {
			t.Error("TransferOnCommit lost when the second archival block compiled")
		}
		if arch.TransferInterval != 30 {
			t.Errorf("TransferInterval = %d, want 30 from the second block", arch.TransferInterval)
		}
		if arch.ArchiveDir != "/var/lib/xpf/archive" || arch.MaxArchives != 10 {
			t.Errorf("defaults = %q/%d, want /var/lib/xpf/archive/10", arch.ArchiveDir, arch.MaxArchives)
		}
	})

	t.Run("two system roots keep first root's sites", func(t *testing.T) {
		cfg := compile15018(t,
			"system {\n archival {\n  configuration {\n   archive-sites { \"scp://backup@10.0.0.1:/configs\"; }\n  }\n }\n}\n"+
				"system {\n archival {\n  configuration {\n   transfer-on-commit;\n  }\n }\n}")
		arch := cfg.System.Archival
		if arch == nil {
			t.Fatal("Archival is nil")
		}
		if len(arch.ArchiveSites) != 1 || arch.ArchiveSites[0] != "scp://backup@10.0.0.1:/configs" {
			t.Errorf("ArchiveSites = %v, want the first root's site to survive the second root", arch.ArchiveSites)
		}
		if !arch.TransferOnCommit {
			t.Error("TransferOnCommit from the second root was not applied")
		}
	})
}

func TestRepeatedInternetOptionsAccumulates15018(t *testing.T) {
	t.Run("empty second block does not clear the flag", func(t *testing.T) {
		cfg := compile15018(t, `system {
 internet-options { no-ipv6-reject-zero-hop-limit; }
 internet-options { }
}`)
		io := cfg.System.InternetOptions
		if io == nil {
			t.Fatal("InternetOptions is nil")
		}
		if !io.NoIPv6RejectZeroHopLimit {
			t.Error("NoIPv6RejectZeroHopLimit cleared by a repeated empty internet-options block")
		}
	})

	t.Run("two system roots", func(t *testing.T) {
		cfg := compile15018(t,
			"system {\n internet-options { no-ipv6-reject-zero-hop-limit; }\n}\n"+
				"system {\n internet-options { }\n}")
		io := cfg.System.InternetOptions
		if io == nil || !io.NoIPv6RejectZeroHopLimit {
			t.Errorf("InternetOptions = %+v, want flag preserved across system roots", io)
		}
	})

	// Control: a lone empty block still compiles to a present, unset stanza.
	t.Run("single empty block control", func(t *testing.T) {
		cfg := compile15018(t, "system {\n internet-options { }\n}")
		io := cfg.System.InternetOptions
		if io == nil {
			t.Fatal("InternetOptions is nil for a single empty block")
		}
		if io.NoIPv6RejectZeroHopLimit {
			t.Error("NoIPv6RejectZeroHopLimit set by an empty block")
		}
	})
}
