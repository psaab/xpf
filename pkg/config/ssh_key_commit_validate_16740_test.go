package config

import (
	"strings"
	"testing"
)

// #16740 (R3-A45-04): the ssh-ed25519 / ssh-rsa / ssh-dsa leaves under
// `system root-authentication` and `system login user <name>
// authentication` carried no commit-time validator, so a trailing
// token (e.g. a value of `from 10.1.1.1` — an authorized_keys OPTION,
// not a key) or any malformed key committed clean and durable. At
// apply, validateAuthorizedSSHKeys then refused ALL of that
// principal's keys and skipped both install and revoke (#14694), so
// the previously installed key stayed live on every later apply —
// a rotation carrying one bad value silently kept the old (possibly
// compromised) key working while the committed config no longer
// listed it.
//
// The fix moves the apply predicate into pkg/config
// (ValidAuthorizedSSHKey / ValidateAuthorizedSSHKey,
// schema_validators_sshkey_16740.go), wires it as the leaf validator
// on all six leaf sites, and makes the daemon belt delegate to the
// same predicate, so commit-accepts and apply-accepts are one set.
//
// RED pre-fix: every reject row below returned nil from
// SchemaValidate (the leaves were untyped, so the typed-leaf walk arm
// never fired). The accept rows are the cited positive/control cells:
// they must stay clean post-fix, including an ecdsa key filed under
// an ssh-* leaf (#14111 — the accepted set is the OpenSSH key-type
// vocabulary, not the leaf name).

const (
	sshKey16740Ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfirst a@b"
	sshKey16740RSA     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfirst a@b"
	sshKey16740DSA     = "ssh-dss AAAAB3NzaC1kc3MAAACBAfirst a@b"
	sshKey16740ECDSA   = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYfirst a@b"
)

// TestSSHKeyLeavesRejectMalformedAtCommit16740 is the decisive cell:
// each malformed value must fail SchemaValidate (the strict commit
// gate) naming its leaf, on BOTH principals and across leaf spellings.
func TestSSHKeyLeavesRejectMalformedAtCommit16740(t *testing.T) {
	rejects := []struct {
		name string
		key  string
	}{
		{"trailing option token only", "from 10.1.1.1"},
		{"option-prefixed line", `command="true" ssh-ed25519 AAAA key`},
		{"bare blob no type", "AAAAB3NzaC1yc2EAAAADAQABAAABAQCtest"},
		{"type without blob", "ssh-ed25519"},
		{"unknown type", "unknown-type AAAAblob user@host"},
		{"malformed blob chars", "ssh-ed25519 AAAA!!! user@host"},
		{"empty", ""},
	}
	leaves := []string{"ssh-ed25519", "ssh-rsa", "ssh-dsa"}
	for _, leaf := range leaves {
		for _, tc := range rejects {
			if tc.key == "" && leaf != "ssh-ed25519" {
				continue // one empty row is enough; spelled per-leaf below via missing value
			}
			t.Run("root/"+leaf+"/"+tc.name, func(t *testing.T) {
				tree := parseHierText(t, "system {\n root-authentication {\n  "+leaf+" \""+tc.key+"\";\n }\n}")
				err := SchemaValidate(tree)
				if err == nil {
					t.Fatalf("SchemaValidate accepted malformed %s value %q at commit (#16740: it would commit durable, then apply would refuse all root keys and leave the old key live)", leaf, tc.key)
				}
				if !strings.Contains(err.Error(), leaf) {
					t.Errorf("error must name the leaf %q: %v", leaf, err)
				}
			})
			t.Run("user/"+leaf+"/"+tc.name, func(t *testing.T) {
				tree := parseHierText(t, "system {\n login {\n  user alice {\n   class super-user;\n   authentication {\n    "+leaf+" \""+tc.key+"\";\n   }\n  }\n }\n}\n")
				err := SchemaValidate(tree)
				if err == nil {
					t.Fatalf("SchemaValidate accepted malformed %s value %q at commit (#16740)", leaf, tc.key)
				}
				if !strings.Contains(err.Error(), leaf) {
					t.Errorf("error must name the leaf %q: %v", leaf, err)
				}
			})
		}
	}
}

// TestSSHKeyLeavesAcceptValidAtCommit16740 is the positive/control
// cell: well-formed keys — including the #14111 ecdsa-under-ssh-leaf
// and comment-less forms — stay clean on both principals.
func TestSSHKeyLeavesAcceptValidAtCommit16740(t *testing.T) {
	accepts := []struct {
		name string
		leaf string
		key  string
	}{
		{"ed25519 with comment", "ssh-ed25519", sshKey16740Ed25519},
		{"rsa with comment", "ssh-rsa", sshKey16740RSA},
		{"dsa value under ssh-dsa leaf", "ssh-dsa", sshKey16740DSA},
		{"ecdsa filed under ssh-ed25519 leaf (14111)", "ssh-ed25519", sshKey16740ECDSA},
		{"comment optional", "ssh-ed25519", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfirst"},
		{"sk-ed25519 under ssh-ed25519 leaf", "ssh-ed25519", "sk-ssh-ed25519@openssh.com AAAAC3NzaC1lZDI1NTE5AAAAIKfirst a@b"},
	}
	for _, tc := range accepts {
		t.Run("root/"+tc.name, func(t *testing.T) {
			tree := parseHierText(t, "system {\n root-authentication {\n  "+tc.leaf+" \""+tc.key+"\";\n }\n}")
			if err := SchemaValidate(tree); err != nil {
				t.Errorf("SchemaValidate rejected valid key: %v (#16740 control must stay clean)", err)
			}
		})
		t.Run("user/"+tc.name, func(t *testing.T) {
			tree := parseHierText(t, "system {\n login {\n  user alice {\n   class super-user;\n   authentication {\n    "+tc.leaf+" \""+tc.key+"\";\n   }\n  }\n }\n}\n")
			if err := SchemaValidate(tree); err != nil {
				t.Errorf("SchemaValidate rejected valid key: %v (#16740 control must stay clean)", err)
			}
		})
	}
}

// TestSSHKeyMultiValueEveryValueValidated16740 pins the issue's
// "applied to every multi value" acceptance: a valid first key does
// not launder a malformed second value on the same multi leaf, in
// either the hierarchical (one statement per key) or flat-set
// (accumulated Keys tail) spelling.
func TestSSHKeyMultiValueEveryValueValidated16740(t *testing.T) {
	t.Run("hierarchical second key bad", func(t *testing.T) {
		tree := parseHierText(t, "system {\n root-authentication {\n  ssh-ed25519 \""+sshKey16740Ed25519+"\";\n  ssh-ed25519 \"from 10.1.1.1\";\n }\n}")
		if err := SchemaValidate(tree); err == nil {
			t.Fatal("SchemaValidate accepted a malformed second ssh-ed25519 value (#16740: validator must run on every multi value)")
		}
	})
	t.Run("flat-set second key bad", func(t *testing.T) {
		tree := parseSetCommands(t,
			`set system root-authentication ssh-ed25519 "`+sshKey16740Ed25519+`"`,
			`set system root-authentication ssh-ed25519 "from 10.1.1.1"`)
		if err := SchemaValidate(tree); err == nil {
			t.Fatal("SchemaValidate accepted a malformed accumulated ssh-ed25519 value (#16740)")
		}
	})
	t.Run("flat-set both keys good control", func(t *testing.T) {
		tree := parseSetCommands(t,
			`set system root-authentication ssh-ed25519 "`+sshKey16740Ed25519+`"`,
			`set system root-authentication ssh-ed25519 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKsecond c@d"`)
		if err := SchemaValidate(tree); err != nil {
			t.Errorf("SchemaValidate rejected two valid keys: %v", err)
		}
	})
	t.Run("user hierarchical second key bad", func(t *testing.T) {
		tree := parseHierText(t, "system {\n login {\n  user alice {\n   class super-user;\n   authentication {\n    ssh-rsa \""+sshKey16740RSA+"\";\n    ssh-rsa \"not-a-key\";\n   }\n  }\n }\n}\n")
		if err := SchemaValidate(tree); err == nil {
			t.Fatal("SchemaValidate accepted a malformed second ssh-rsa value for a login user (#16740)")
		}
	})
}

// TestValidateAuthorizedSSHKeyDirect16740 unit-pins the shared
// validator in both directions and the #16066 no-echo rule: the error
// must name the defect class without rendering any fragment of the
// submitted value.
func TestValidateAuthorizedSSHKeyDirect16740(t *testing.T) {
	for _, k := range []string{sshKey16740Ed25519, sshKey16740RSA, sshKey16740DSA, sshKey16740ECDSA} {
		if err := ValidateAuthorizedSSHKey(k); err != nil {
			t.Errorf("ValidateAuthorizedSSHKey(%q) = %v, want nil", k, err)
		}
		if !ValidAuthorizedSSHKey(k) {
			t.Errorf("ValidAuthorizedSSHKey(%q) = false, want true", k)
		}
	}
	probe := "CANARYPROBE16740"
	// The no-echo probe rides a malformed blob (illegal '!' byte): the
	// validator must reject it and its error must not quote it back.
	for _, k := range []string{"from 10.1.1.1", "ssh-ed25519 " + probe + "!", probe, "ssh-ed25519", ""} {
		err := ValidateAuthorizedSSHKey(k)
		if err == nil {
			t.Errorf("ValidateAuthorizedSSHKey(%q) = nil, want reject", k)
			continue
		}
		if strings.Contains(err.Error(), probe) {
			t.Errorf("validator error echoed the submitted value (%q): %v (#16066)", probe, err)
		}
		if ValidAuthorizedSSHKey(k) {
			t.Errorf("ValidAuthorizedSSHKey(%q) = true, want false", k)
		}
	}
	// Multiline smuggling stays refused (the daemon belt's #10725 case).
	if ValidAuthorizedSSHKey("ssh-ed25519 AAAA first\nssh-rsa AAAA forged") {
		t.Error("ValidAuthorizedSSHKey accepted a multiline value")
	}
}
