package config

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestFormatXMLInterfaceNamesAreWellFormed10977(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
	})
	out := tree.FormatXML()
	var parsed struct{}
	if err := xml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("FormatXML returned malformed XML for interface-bearing config: %v\n%s", err, out)
	}
	if !strings.Contains(out, "<name>ge-0/0/0</name>") ||
		!strings.Contains(out, "<name>ge-0/0/0.0</name>") {
		t.Fatalf("FormatXML must preserve interface names as XML text:\n%s", out)
	}
}

func TestFormatXMLZonePairIsRecoverable10977(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow-web then permit",
	})
	out := tree.FormatXML()
	var parsed struct {
		Security struct {
			Policies struct {
				Pair struct {
					From string `xml:"name"`
					To   struct {
						Name string `xml:"name"`
					} `xml:"to-zone"`
				} `xml:"from-zone"`
			} `xml:"policies"`
		} `xml:"security"`
	}
	if err := xml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("FormatXML returned malformed XML for zone-pair config: %v\n%s", err, out)
	}
	if parsed.Security.Policies.Pair.From != "trust" || parsed.Security.Policies.Pair.To.Name != "untrust" {
		t.Fatalf("zone-pair endpoints were not recoverable: from=%q to=%q\n%s",
			parsed.Security.Policies.Pair.From, parsed.Security.Policies.Pair.To.Name, out)
	}
}
