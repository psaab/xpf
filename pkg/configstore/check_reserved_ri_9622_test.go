package configstore

import (
	"strings"
	"testing"
)

// #9622: CheckText (`xpfd check-config`) is the strict gate for an untrusted
// day-0 config file, the input most likely to arrive in the hierarchical and
// brace-elided spellings. It must reject a routing instance of the reserved
// management name in both.
func TestCheckTextRejectsReservedRoutingInstanceName_9622(t *testing.T) {
	for _, text := range []string{
		"routing-instances {\n    mgmt {\n        instance-type virtual-router;\n    }\n}\n",
		"routing-instances {\n    mgmt instance-type virtual-router;\n}\n",
	} {
		if _, err := CheckText(text, -1); err == nil || !strings.Contains(err.Error(), "reserved for") {
			t.Errorf("#9622: CheckText did not reject a routing instance of the reserved name (err=%v):\n%s", err, text)
		}
	}
	// Control: the same stanza under an ordinary name checks clean.
	if _, err := CheckText("routing-instances {\n    blue instance-type virtual-router;\n}\n", -1); err != nil {
		t.Errorf("#9622 control: an ordinary packed routing instance must check clean: %v", err)
	}
}
