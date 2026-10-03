package config

import (
	"strings"
	"testing"
)

func TestURLHasPassword11774(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		want bool
	}{
		{"userinfo password", "scp://alice:secret@archive.example/configs", true},
		{"userinfo password without scheme", "alice:secret@archive.example/configs", true},
		{"bare userinfo", "scp://alice@archive.example/configs", false},
		{"host port", "scp://archive.example:22/configs", false},
		{"ipv6 host port", "scp://[2001:db8::1]:22/configs", false},
		{"at in path", "scp://archive.example/p@th", false},
		{"at in query", "scp://archive.example/configs?user=a@b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := URLHasPassword(tc.url); got != tc.want {
				t.Fatalf("URLHasPassword(%q) = %v, want %v", tc.url, got, tc.want)
			}
		})
	}
}

func TestCompileConfigRejectsArchivalURLPassword11774(t *testing.T) {
	const password = "ARCHIVE-PW-SENTINEL"
	tree := mustParse(t, `system {
    archival {
        configuration {
            archive-sites { "scp://alice:`+password+`@archive.example/configs"; }
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted an archive-site URL with an inline password")
	}
	if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), "alice:") {
		t.Fatalf("rejection exposed inline URL credentials: %v", err)
	}
	if !strings.Contains(err.Error(), "archive.example") || !strings.Contains(err.Error(), "SSH key") {
		t.Fatalf("rejection lost useful site/authentication guidance: %v", err)
	}
}
