package configstore

import (
	"strings"
	"testing"
)

func TestRoutingInstanceVRFTargetBlockBracketParity9736(t *testing.T) {
	valid := []string{
		`ri1 vrf-target export [ target:65000:1 target:65000:2 ];`,
		`ri1 { vrf-target { export [ target:65000:1 target:65000:2 ]; } }`,
	}
	for _, instance := range valid {
		if _, err := checkRoutingInstance9736(t, instance); err != nil {
			t.Errorf("valid block/list vrf-target spelling was rejected: %q: %v", instance, err)
		}
	}
}

func TestRoutingInstanceVRFTargetBlockBracketRejectsInvalidChildren9736(t *testing.T) {
	for _, instance := range []string{
		`ri1 { vrf-target { export [ junk-token ]; } }`,
		`ri1 { vrf-target { export [ ]; } }`,
	} {
		if _, err := checkRoutingInstance9736(t, instance); err == nil || !strings.Contains(err.Error(), "vrf-target") {
			t.Errorf("invalid block/list vrf-target spelling was accepted: %q: %v", instance, err)
		}
	}
}
