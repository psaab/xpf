package configstore

import (
	"strings"
	"testing"
)

func TestCheckTextRejectsUncreatableRoutingInstanceVRFName_11391(t *testing.T) {
	text := `routing-instances {
    Comcast-GigabitPro {
        instance-type virtual-router;
    }
}
`
	_, err := CheckText(text, -1)
	if err == nil {
		t.Fatalf("CheckText accepted a routing instance whose derived vrf-Comcast-GigabitPro name exceeds IFNAMSIZ")
	}
	for _, part := range []string{"Comcast-GigabitPro", "vrf-Comcast-GigabitPro", "IFNAMSIZ", "#11391"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("CheckText error %q does not include %q", err, part)
		}
	}
}

func TestCheckTextAcceptsRoutingInstanceAtVRFNameLimit_11391(t *testing.T) {
	text := `routing-instances {
    abcdefghijk {
        instance-type virtual-router;
    }
}
`
	if _, err := CheckText(text, -1); err != nil {
		t.Fatalf("CheckText rejected 11-byte routing-instance name whose vrf-<name> device fits IFNAMSIZ: %v", err)
	}
}
