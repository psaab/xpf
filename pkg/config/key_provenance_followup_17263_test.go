package config

import "testing"

func TestPackedInstanceSchemaWalkerCopiesKeyProvenance17263(t *testing.T) {
	seen := false
	values := &schemaNode{
		args: 1, multi: true,
		nodeValidator: func(n *Node, _ *schemaNode) error {
			seen = true
			if len(n.KeysQuoted) != len(n.Keys) || !n.KeyQuoted(1) {
				t.Errorf("packed value quote provenance = keys %q mask %v", n.Keys, n.KeysQuoted)
			}
			if len(n.KeysBracketed) != len(n.Keys) || !n.KeyBracketed(1) || !n.KeyBracketed(2) {
				t.Errorf("packed value bracket provenance = keys %q mask %v", n.Keys, n.KeysBracketed)
			}
			if !n.BracketedClosed {
				t.Error("packed value lost BracketedClosed")
			}
			return nil
		},
	}
	container := &schemaNode{
		args: 1, packedTail: true,
		children: map[string]*schemaNode{"values": values},
	}
	node := &Node{
		Keys:            []string{"instance", "values", "good", "other"},
		KeysQuoted:      []bool{false, false, true, false},
		KeysBracketed:   []bool{false, false, true, true},
		BracketedClosed: true,
	}
	if err := walkInstanceChildren(node, container, 1, 0, nil, nil, false); err != nil {
		t.Fatalf("walkInstanceChildren: %v", err)
	}
	if !seen {
		t.Fatal("packed schema walk did not consume the bracketed value run")
	}
}

func TestRoutingInstancePackedPropertyCarriesClosedBracketSpan17263(t *testing.T) {
	inst := &Node{
		Keys:            []string{"VR1", "security", "policies", "P"},
		KeysQuoted:      []bool{false, false, true, false},
		KeysBracketed:   []bool{false, false, true, true},
		BracketedClosed: true,
	}
	properties := routingInstancePropertyNodes9323(inst)
	if len(properties) != 1 {
		t.Fatalf("packed property count = %d, want 1", len(properties))
	}
	property := properties[0]
	if !property.BracketedClosed || !property.KeyBracketed(1) || !property.KeyBracketed(2) || !property.KeyQuoted(1) {
		t.Fatalf("packed property lost its sliced provenance: keys=%q quoted=%v bracketed=%v closed=%v",
			property.Keys, property.KeysQuoted, property.KeysBracketed, property.BracketedClosed)
	}

	identityOnly := &Node{
		Keys:            []string{"VR1", "security"},
		KeysBracketed:   []bool{true, false},
		BracketedClosed: true,
	}
	identityProperty := routingInstancePropertyNodes9323(identityOnly)[0]
	if identityProperty.BracketedClosed {
		t.Fatalf("close bit from the discarded identity span leaked into property keys %q", identityProperty.Keys)
	}
}

func TestBGPFusedMultiSplitCarriesClosedBracketToOwningSegment17263(t *testing.T) {
	schema := bgpNeighborSchema9792()
	t.Run("close on split head", func(t *testing.T) {
		prop := &Node{
			Keys:            []string{"export", "POLICY-A", "POLICY-B", "peer-as", "65002"},
			KeysBracketed:   []bool{false, true, true, false, false},
			BracketedClosed: true,
		}
		got := splitFusedMultiLeaves14409([]*Node{prop}, schema)
		if len(got) != 2 || got[0].Keys[0] != "export" || got[1].Keys[0] != "peer-as" {
			t.Fatalf("split nodes = %+v, want export and peer-as", got)
		}
		if !got[0].BracketedClosed || got[1].BracketedClosed {
			t.Fatalf("close bit not assigned to split head: first=%v second=%v", got[0].BracketedClosed, got[1].BracketedClosed)
		}
	})

	t.Run("close follows packed remainder expansion", func(t *testing.T) {
		prop := &Node{
			Keys:            []string{"export", "POLICY-A", "peer-as", "65002", "import", "IMPORT-A", "IMPORT-B"},
			KeysBracketed:   []bool{false, false, false, false, false, true, true},
			BracketedClosed: true,
		}
		got := splitFusedMultiLeaves14409([]*Node{prop}, schema)
		if len(got) != 3 || got[0].Keys[0] != "export" || got[1].Keys[0] != "peer-as" || got[2].Keys[0] != "import" {
			t.Fatalf("split nodes = %+v, want export, peer-as, import", got)
		}
		if !got[2].BracketedClosed || !got[2].KeyBracketed(1) || !got[2].KeyBracketed(2) {
			t.Fatalf("packed remainder lost closing bracket provenance: keys=%q mask=%v closed=%v",
				got[2].Keys, got[2].KeysBracketed, got[2].BracketedClosed)
		}
	})
}
