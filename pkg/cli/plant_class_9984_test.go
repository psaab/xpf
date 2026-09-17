package cli

import "testing"

func TestCLIMutationCarriesAuthenticatedPlantClass9984(t *testing.T) {
	c, store := cliWithRestrictedClass9892(t, "limited")
	// cliWithRestrictedClass9892 leaves the candidate in configure mode after
	// seeding the active class config, which is the same session state the CLI
	// dispatcher uses for subsequent operator mutations.
	for _, line := range []string{
		`set event-options policy p events ping_test_failed`,
		`set event-options policy p then change-configuration commands "set system host-name cli-stamped"`,
	} {
		if err := c.dispatchConfig(line); err != nil {
			t.Fatalf("dispatchConfig(%q): %v", line, err)
		}
	}
	cfg, err := store.CompileCandidate()
	if err != nil {
		t.Fatalf("CompileCandidate: %v", err)
	}
	for _, policy := range cfg.EventOptions {
		if policy != nil && policy.Name == "p" {
			if policy.PlantClass != "limited" {
				t.Fatalf("CLI planted class=%q, want limited", policy.PlantClass)
			}
			return
		}
	}
	t.Fatal("CLI candidate did not contain event policy p")
}
