package config

import (
	"strings"
	"testing"
)

func TestWebManagementCustomTLSCertificatePathsCompile10827(t *testing.T) {
	const certPath = "/etc/xpf/tls/server-chain.pem"
	const keyPath = "/etc/xpf/tls/server-key.pem"
	tree := buildTreeFromSets(t,
		"set system services web-management https certificate "+certPath,
		"set system services web-management https private-key "+keyPath)

	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	wm := cfg.System.Services.WebManagement
	if wm == nil || !wm.HTTPS {
		t.Fatal("custom TLS credentials must enable web-management HTTPS")
	}
	if wm.TLSCertificate != certPath || wm.TLSPrivateKey != keyPath {
		t.Fatalf("compiled TLS paths = (%q, %q), want (%q, %q)", wm.TLSCertificate,
			wm.TLSPrivateKey, certPath, keyPath)
	}
	if wm.SystemGeneratedCert {
		t.Fatal("custom TLS credentials must not select the generated certificate")
	}
}

func TestWebManagementCustomTLSCertificateFlatSetChain10827(t *testing.T) {
	const certPath = "/etc/xpf/tls/server-chain.pem"
	const keyPath = "/etc/xpf/tls/server-key.pem"
	tree := buildTreeFromSets(t,
		"set system services web-management https certificate "+certPath+
			" private-key "+keyPath)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	wm := cfg.System.Services.WebManagement
	if wm == nil || wm.TLSCertificate != certPath || wm.TLSPrivateKey != keyPath {
		t.Fatalf("compiled flat SetPath chain = %+v", wm)
	}
}

func TestWebManagementCustomTLSCertificatePackedTail10827(t *testing.T) {
	input := `
system {
    services {
        web-management {
            https certificate "/etc/xpf/tls/server-chain.pem" private-key "/etc/xpf/tls/server-key.pem";
        }
    }
}
`
	tree, parseErrs := NewParser(input).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse packed HTTPS tail: %v", parseErrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	wm := cfg.System.Services.WebManagement
	if wm == nil || wm.TLSCertificate != "/etc/xpf/tls/server-chain.pem" ||
		wm.TLSPrivateKey != "/etc/xpf/tls/server-key.pem" {
		t.Fatalf("compiled packed HTTPS tail = %+v", wm)
	}
}

func TestWebManagementCustomTLSCertificateBlockSyntax10827(t *testing.T) {
	input := `
system {
    services {
        web-management {
            https {
                certificate "/etc/xpf/tls/server-chain.pem";
                private-key "/etc/xpf/tls/server-key.pem";
            }
        }
    }
}
`
	tree, parseErrs := NewParser(input).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse custom HTTPS block: %v", parseErrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	wm := cfg.System.Services.WebManagement
	if wm == nil || wm.TLSCertificate != "/etc/xpf/tls/server-chain.pem" ||
		wm.TLSPrivateKey != "/etc/xpf/tls/server-key.pem" {
		t.Fatalf("compiled custom TLS block = %+v", wm)
	}
}

func TestWebManagementCustomTLSCertificateRequiresPair10827(t *testing.T) {
	tree := buildTreeFromSets(t, "set system services web-management https certificate /etc/xpf/tls/server.pem")
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "both certificate and private-key") {
		t.Fatalf("CompileConfig error = %v, want custom credential pair rejection", err)
	}
	if cfg, err := CompileConfigLenient(tree); err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	} else if len(cfg.Warnings) == 0 || !strings.Contains(strings.Join(cfg.Warnings, " "), "certificate") {
		t.Fatalf("tolerant load warnings = %v, want TLS credential warning", cfg.Warnings)
	}
}

func TestWebManagementCustomAndGeneratedTLSCertificatesAreExclusive10827(t *testing.T) {
	tree := buildTreeFromSets(t,
		"set system services web-management https certificate /etc/xpf/tls/server.pem",
		"set system services web-management https private-key /etc/xpf/tls/server-key.pem",
		"set system services web-management https system-generated-certificate")
	if _, err := CompileConfig(tree); err == nil || !strings.Contains(err.Error(), "choose either") {
		t.Fatalf("CompileConfig error = %v, want certificate-mode conflict rejection", err)
	}
}
