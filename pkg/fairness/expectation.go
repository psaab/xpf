package fairness

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
)

type RSSExpectationKind string

const (
	RSSExpectationAny                  RSSExpectationKind = "any"
	RSSExpectationBalanced             RSSExpectationKind = "balanced"
	RSSExpectationAtLeastActiveWorkers RSSExpectationKind = "at-least-active-workers"
	RSSExpectationMaxWorkerFlowShare   RSSExpectationKind = "max-worker-flow-share"
	RSSExpectationCstructMax           RSSExpectationKind = "cstruct-max"
)

type RSSExpectation struct {
	Kind          RSSExpectationKind
	ActiveWorkers uint32
	Threshold     float64
}

func (e RSSExpectation) Canonical() string {
	switch e.Kind {
	case RSSExpectationAny:
		return "any"
	case RSSExpectationBalanced:
		return "balanced"
	case RSSExpectationAtLeastActiveWorkers:
		return fmt.Sprintf("at-least-active-workers:%d", e.ActiveWorkers)
	case RSSExpectationMaxWorkerFlowShare:
		return fmt.Sprintf("max-worker-flow-share:%g", e.Threshold)
	case RSSExpectationCstructMax:
		return fmt.Sprintf("cstruct-max:%g", e.Threshold)
	default:
		return string(e.Kind)
	}
}

func (e RSSExpectation) MetricKind() string {
	if !knownRSSExpectationKind(e.Kind) {
		return "unknown"
	}
	return string(e.Kind)
}

func (e RSSExpectation) MetricValue() (float64, bool) {
	switch e.Kind {
	case RSSExpectationAtLeastActiveWorkers:
		return float64(e.ActiveWorkers), true
	case RSSExpectationMaxWorkerFlowShare, RSSExpectationCstructMax:
		return e.Threshold, true
	default:
		return 0, false
	}
}

type RSSExpectationResult struct {
	Pass   bool
	Reason string
}

func ParseRSSExpectation(raw string) (RSSExpectation, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "any") {
		return RSSExpectation{Kind: RSSExpectationAny}, nil
	}
	if strings.EqualFold(raw, "balanced") {
		return RSSExpectation{Kind: RSSExpectationBalanced}, nil
	}

	compact := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, raw)
	// Parse the operator explicitly instead of normalizing it away:
	// collapsing <=, >=, and = into ':' silently inverted the meaning
	// of e.g. cstruct>=X (a ceiling key) or active-workers<=N (a floor
	// key). Only the operator(s) matching each key's hardcoded
	// semantics are accepted; anything else fails closed.
	opIdx := strings.IndexAny(compact, "<>=:")
	if opIdx < 0 {
		return RSSExpectation{}, fmt.Errorf("unknown RSS expectation %q; expected any, balanced, at-least-active-workers:N, max-worker-flow-share:X, or cstruct-max:X", raw)
	}
	var op string
	var opLen int
	switch {
	case strings.HasPrefix(compact[opIdx:], "<="):
		op, opLen = "<=", 2
	case strings.HasPrefix(compact[opIdx:], ">="):
		op, opLen = ">=", 2
	case compact[opIdx] == ':':
		op, opLen = ":", 1
	default:
		return RSSExpectation{}, fmt.Errorf("invalid RSS expectation operator in %q; expected ':' or a comparison operator valid for the key (<= for cstruct, >= for at-least-active-workers)", raw)
	}
	key, value := compact[:opIdx], compact[opIdx+opLen:]
	checkOp := func(allowed ...string) error {
		for _, a := range allowed {
			if op == a {
				return nil
			}
		}
		return fmt.Errorf("invalid RSS expectation operator %q for %s in %q; expected %s", op, key, raw, strings.Join(allowed, " or "))
	}

	switch key {
	case "at-least-active-workers", "active-workers":
		if err := checkOp(":", ">="); err != nil {
			return RSSExpectation{}, err
		}
		n, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return RSSExpectation{}, fmt.Errorf("invalid RSS expectation active worker count %q", raw)
		}
		return RSSExpectation{Kind: RSSExpectationAtLeastActiveWorkers, ActiveWorkers: uint32(n)}, nil
	case "max-worker-flow-share":
		if err := checkOp(":"); err != nil {
			return RSSExpectation{}, err
		}
		share, err := parseFractionOrPercent(value)
		if err != nil {
			return RSSExpectation{}, fmt.Errorf("invalid RSS expectation max-worker-flow-share: %w", err)
		}
		return RSSExpectation{Kind: RSSExpectationMaxWorkerFlowShare, Threshold: share}, nil
	case "cstruct", "cstruct-max":
		if err := checkOp(":", "<="); err != nil {
			return RSSExpectation{}, err
		}
		max, err := parseNonnegativeNumberOrPercent(value)
		if err != nil {
			return RSSExpectation{}, fmt.Errorf("invalid RSS expectation cstruct threshold: %w", err)
		}
		return RSSExpectation{Kind: RSSExpectationCstructMax, Threshold: max}, nil
	default:
		return RSSExpectation{}, fmt.Errorf("unknown RSS expectation %q; expected any, balanced, at-least-active-workers:N, max-worker-flow-share:X, or cstruct-max:X", raw)
	}
}

func EvaluateRSSExpectation(
	expectation RSSExpectation,
	distribution []uint32,
	cstruct float64,
	nTotalWorkers uint32,
) RSSExpectationResult {
	if nTotalWorkers == 0 {
		nTotalWorkers = uint32(len(distribution))
	}

	var total uint64
	var activeWorkers uint32
	var minActive uint32
	var maxActive uint32
	for _, active := range distribution {
		total += uint64(active)
		if active == 0 {
			continue
		}
		activeWorkers++
		if minActive == 0 || active < minActive {
			minActive = active
		}
		if active > maxActive {
			maxActive = active
		}
	}
	maxShare := 0.0
	if total > 0 {
		maxShare = float64(maxActive) / float64(total)
	}

	switch expectation.Kind {
	case RSSExpectationAny:
		return RSSExpectationResult{Pass: true, Reason: "any: no RSS/workload expectation configured"}
	}
	if !knownRSSExpectationKind(expectation.Kind) {
		return RSSExpectationResult{Pass: false, Reason: fmt.Sprintf("unknown RSS expectation kind %q", expectation.Kind)}
	}
	if total == 0 {
		return RSSExpectationResult{Pass: false, Reason: fmt.Sprintf("%s: no active flows observed", expectation.Kind)}
	}

	switch expectation.Kind {
	case RSSExpectationAtLeastActiveWorkers:
		if activeWorkers >= expectation.ActiveWorkers {
			return RSSExpectationResult{Pass: true, Reason: fmt.Sprintf("active_workers=%d >= expected %d", activeWorkers, expectation.ActiveWorkers)}
		}
		return RSSExpectationResult{Pass: false, Reason: fmt.Sprintf("active_workers=%d < expected %d", activeWorkers, expectation.ActiveWorkers)}
	case RSSExpectationMaxWorkerFlowShare:
		if maxShare <= expectation.Threshold {
			return RSSExpectationResult{Pass: true, Reason: fmt.Sprintf("max_worker_flow_share=%.4f <= expected %.4f", maxShare, expectation.Threshold)}
		}
		return RSSExpectationResult{Pass: false, Reason: fmt.Sprintf("max_worker_flow_share=%.4f > expected %.4f", maxShare, expectation.Threshold)}
	case RSSExpectationCstructMax:
		if cstruct <= expectation.Threshold {
			return RSSExpectationResult{Pass: true, Reason: fmt.Sprintf("cstruct=%.4f <= expected %.4f", cstruct, expectation.Threshold)}
		}
		return RSSExpectationResult{Pass: false, Reason: fmt.Sprintf("cstruct=%.4f > expected %.4f", cstruct, expectation.Threshold)}
	case RSSExpectationBalanced:
		expectedActive := uint64(nTotalWorkers)
		if total < expectedActive {
			expectedActive = total
		}
		pass := uint64(activeWorkers) == expectedActive && maxActive-minActive <= 1
		if pass {
			return RSSExpectationResult{Pass: true, Reason: fmt.Sprintf("balanced: active_workers=%d, min=%d, max=%d", activeWorkers, minActive, maxActive)}
		}
		return RSSExpectationResult{Pass: false, Reason: fmt.Sprintf("balanced: active_workers=%d expected %d, min=%d, max=%d", activeWorkers, expectedActive, minActive, maxActive)}
	default:
		return RSSExpectationResult{Pass: false, Reason: fmt.Sprintf("unknown RSS expectation kind %q", expectation.Kind)}
	}
}

func knownRSSExpectationKind(kind RSSExpectationKind) bool {
	switch kind {
	case RSSExpectationAny,
		RSSExpectationBalanced,
		RSSExpectationAtLeastActiveWorkers,
		RSSExpectationMaxWorkerFlowShare,
		RSSExpectationCstructMax:
		return true
	default:
		return false
	}
}

func parseNumberOrPercent(raw string) (float64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("missing value")
	}
	var value float64
	var err error
	if percent, ok := strings.CutSuffix(raw, "%"); ok {
		value, err = strconv.ParseFloat(percent, 64)
		value /= 100.0
	} else {
		value, err = strconv.ParseFloat(raw, 64)
	}
	if err != nil {
		return 0, fmt.Errorf("%q is not a number", raw)
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("%q is not a finite number", raw)
	}
	return value, nil
}

func parseFractionOrPercent(raw string) (float64, error) {
	value, err := parseNumberOrPercent(raw)
	if err != nil {
		return 0, err
	}
	if value < 0 || value > 1 {
		return 0, fmt.Errorf("%q must be between 0 and 1 or 0%% and 100%%", raw)
	}
	return value, nil
}

func parseNonnegativeNumberOrPercent(raw string) (float64, error) {
	value, err := parseNumberOrPercent(raw)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("%q must be non-negative", raw)
	}
	return value, nil
}
