package config

import "testing"

// #16067: with argument samples registered, an argument-scoped pattern
// is enforceable and must not be reported on-box-only; without samples
// (a surface that has not proven it reconstructs arguments) the #8189
// advisory keeps speaking.

func TestArgumentSamplesSilenceAdvisory16067(t *testing.T) {
	withSurface(t, "the gRPC surface", []string{"show route", "show route table", "show interfaces", "request system reboot"})
	RegisterCommandSurfaceArgumentSamples("the gRPC surface", func() []string {
		return []string{"show route table inet.0", "ping 192.0.2.1"}
	})
	t.Cleanup(func() { delete(registeredArgumentSamples, "the gRPC surface") })

	rules, ok, err := OperationalLoginRegexesFor(loginClassCfg(t, `^show route table secret-vrf$`), "limited")
	if err != nil || !ok {
		t.Fatalf("precondition: %v %v", ok, err)
	}
	if got := UnenforceableDenySurfaces(rules); len(got) != 0 {
		t.Errorf("argument-scoped deny with registered samples must not be reported unenforceable; got %v", got)
	}

	rules2, _, _ := OperationalLoginRegexesFor(loginClassCfg(t, `^qqq-not-a-command$`), "limited")
	if got := UnenforceableDenySurfaces(rules2); len(got) != 1 {
		t.Errorf("a pattern naming no command in any spelling must still be reported; got %v", got)
	}
}

func TestNoSamplesKeepsAdvisory16067(t *testing.T) {
	withSurface(t, "the gRPC surface", []string{"show route", "show route table"})
	rules, _, _ := OperationalLoginRegexesFor(loginClassCfg(t, `^show route table secret-vrf$`), "limited")
	if got := UnenforceableDenySurfaces(rules); len(got) != 1 {
		t.Errorf("without registered samples the advisory must keep speaking; got %v", got)
	}
}
