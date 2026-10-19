package rpm

import "testing"

// TestResultsVersionedGeneration15233 pins that ResultsVersioned returns
// the snapshot and the transition generation atomically under the lock:
// after a transition the generation has advanced and the snapshot rows
// carry that transition's verdict. A consumer comparing generations
// (ipmon ApplyVersioned) can then reject a pre-transition snapshot.
func TestResultsVersionedGeneration15233(t *testing.T) {
	m := New()
	m.mu.Lock()
	m.results["WAN/wan-a"] = &ProbeResult{ProbeName: "WAN", TestName: "wan-a", LastStatus: "unknown"}
	m.mu.Unlock()

	results, gen := m.ResultsVersioned()
	if gen != 0 {
		t.Fatalf("generation before any transition = %d, want 0", gen)
	}
	if len(results) != 1 || results[0].LastStatus != "unknown" {
		t.Fatalf("snapshot before transition = %+v", results)
	}

	tr, _ := m.prepareTransition("WAN", "wan-a", "fail")
	if tr.Generation == 0 {
		t.Fatal("prepareTransition did not stamp a generation")
	}
	results, gen = m.ResultsVersioned()
	if gen != tr.Generation {
		t.Fatalf("ResultsVersioned generation = %d, want transition generation %d", gen, tr.Generation)
	}
	if len(results) != 1 || results[0].LastStatus != "fail" {
		t.Fatalf("snapshot after fail transition = %+v, want fail row", results)
	}
	// The plain Results() snapshot must agree on rows.
	if got := m.Results(); len(got) != 1 || got[0].LastStatus != "fail" {
		t.Fatalf("Results() after transition = %+v", got)
	}
}
