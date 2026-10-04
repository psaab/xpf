package config

import (
	"strings"
	"testing"
)

// #11800: a scheduler child not declared in schema_cos.go can be ignored by
// compileClassOfService's child-name switch. Keep both parser shapes on the
// strict schema gate so a typo cannot commit with the scheduler field unset.
func TestClosedWorldCoSSchedulersRejectUnknownChildren11800(t *testing.T) {
	for _, keyword := range []string{"priorty", "transmit-rtae", "buffer-szie", "xpf-unknown"} {
		t.Run(keyword, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set class-of-service schedulers be " + keyword + " high",
			})
			err := SchemaValidate(tree, nil)
			if err == nil {
				t.Fatalf("unknown scheduler child %q was accepted and would be silently dropped (RED on revert of scheduler closedWorld)", keyword)
			}
			if !strings.Contains(err.Error(), keyword) || !strings.Contains(err.Error(), "closed-world") {
				t.Fatalf("error = %q, want unknown keyword %q and closed-world diagnostic", err, keyword)
			}
		})
	}

	hier, parseErrs := NewParser(`class-of-service { schedulers { be { priorty high; } } }`).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse hierarchical typo: %v", parseErrs[0])
	}
	if err := SchemaValidate(hier, nil); err == nil || !strings.Contains(err.Error(), "priorty") {
		t.Fatalf("hierarchical scheduler typo must be rejected and named, got %v", err)
	}
	grouped := buildTree(t, []string{
		"set groups g1 class-of-service schedulers be priorty high",
	})
	if err := SchemaValidate(grouped, nil); err == nil || !strings.Contains(err.Error(), "priorty") {
		t.Fatalf("scheduler typo under a configuration group must be rejected, got %v", err)
	}
}

// `drop-profile-map` is a valid Junos scheduler knob but is not implemented by
// this userspace scheduler; reject it rather than silently accepting a config
// whose requested drop behavior would never be applied.
func TestClosedWorldCoSSchedulersRejectUnsupportedDropProfileMap11800(t *testing.T) {
	tree := buildTree(t, []string{
		"set class-of-service schedulers be drop-profile-map low protocol any drop-profile RED",
	})
	err := SchemaValidate(tree, nil)
	if err == nil || !strings.Contains(err.Error(), "drop-profile-map") {
		t.Fatalf("unsupported Junos scheduler child must be rejected and named, got %v", err)
	}
}

// Every scheduler child currently consumed by the compiler, including the
// heterogeneous value tails and their modifiers, remains accepted by the
// closed-world gate in flat-set and hierarchical AST forms.
func TestClosedWorldCoSSchedulersAcceptSupportedChildren11800(t *testing.T) {
	flat := buildTree(t, []string{
		"set class-of-service schedulers exact transmit-rate 10m exact",
		"set class-of-service schedulers exact priority high",
		"set class-of-service schedulers exact buffer-size 16m",
		"set class-of-service schedulers exact equal-flow-enforcement",
		"set class-of-service schedulers exact equal-flow-target-policy mean",
		"set class-of-service schedulers exact codel-target 5",
		"set class-of-service schedulers surplus transmit-rate 10m exact",
		"set class-of-service schedulers surplus surplus-sharing",
		"set class-of-service schedulers percent transmit-rate percent 30",
		"set class-of-service schedulers remainder transmit-rate remainder",
		"set class-of-service schedulers buffer-percent buffer-size 10%",
		"set class-of-service schedulers buffer-temporal buffer-size temporal 10000",
	})
	if err := SchemaValidate(flat, nil); err != nil {
		t.Fatalf("supported flat-set scheduler children must pass closed-world validation: %v", err)
	}

	hier, parseErrs := NewParser(`class-of-service {
		schedulers {
			be {
				transmit-rate 10m exact;
				priority high;
				buffer-size temporal 10000;
				surplus-sharing;
				equal-flow-target-policy mean;
				codel-target 5;
			}
		}
	}`).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse hierarchical scheduler: %v", parseErrs[0])
	}
	if err := SchemaValidate(hier, nil); err != nil {
		t.Fatalf("supported hierarchical scheduler children must pass closed-world validation: %v", err)
	}
}

// #1960 no-brick contract: strict SchemaValidate rejects an unknown scheduler
// child, while tolerant compile still loads an older persisted config.
func TestClosedWorldCoSSchedulersLenientLoadDoesNotBrick11800(t *testing.T) {
	tree := buildTree(t, []string{
		"set class-of-service schedulers be priorty high",
	})
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("strict schema validation must reject the scheduler typo")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not brick on the persisted typo: %v", err)
	}
	if got := cfg.ClassOfService.Schedulers["be"].Priority; got != "" {
		t.Fatalf("unknown typo must remain uncompiled on tolerant load, got Priority %q", got)
	}
}
