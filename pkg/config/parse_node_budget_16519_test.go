package config

import (
	"strings"
	"testing"
)

// #16519: the #15195 fix reset p.nodes to before+1+len(Keys) after each
// statement, discarding every unit the statement's children had charged.
// Several sibling blocks, each just under maxParseNodes, therefore built
// an AST of any size with no budget error — the #8597 guard was per-block
// again, contradicting parser.go's "parser-wide" contract and the README.

// budgetBlock16519 returns one block carrying leaves leaf statements.
// Each `x;` leaf charges 1+len(Keys)=2 units and the block node charges
// 2, so a block of 80_000 leaves charges 160_002 units: under the
// 200_000 budget on its own.
func budgetBlock16519(name string, leaves int) string {
	return name + " {\n" + strings.Repeat("x;\n", leaves) + "}\n"
}

// TestParseBudget_SiblingBlocksAggregate_16519 is the RED-on-base core:
// three sibling blocks, each under the budget, exceed it in aggregate
// (3*160_002 = 480_006 units, the source report's measured figure).
// The budget error must fire.
func TestParseBudget_SiblingBlocksAggregate_16519(t *testing.T) {
	text := budgetBlock16519("blk", 80_000) +
		budgetBlock16519("blk", 80_000) +
		budgetBlock16519("blk", 80_000)
	_, errs := NewParser(text).Parse()
	if !hasBudgetError(errs) {
		t.Fatalf("three sibling blocks of 160_002 units each (480_006 total) produced "+
			"no budget ParseError; the node budget is per-block, not parser-wide (#16519); errs=%v", errs)
	}
}

// TestParseBudget_NestedSiblingBlocksAggregate_16519: the same aggregate
// excess nested one level down — sibling sub-blocks inside a single outer
// block, each sub-block under the budget, combined over it. The budget
// error must fire.
func TestParseBudget_NestedSiblingBlocksAggregate_16519(t *testing.T) {
	text := "outer {\n" +
		budgetBlock16519("inner", 80_000) +
		budgetBlock16519("inner", 80_000) +
		budgetBlock16519("inner", 80_000) +
		"}\n"
	_, errs := NewParser(text).Parse()
	if !hasBudgetError(errs) {
		t.Fatalf("three nested sibling blocks of 160_002 units each (480_006 total) produced "+
			"no budget ParseError; the node budget is per-block, not parser-wide (#16519); errs=%v", errs)
	}
}

// TestParseBudget_SingleBlockUnderBudgetControl_16519 is the over-broad
// control: one block of the exact shape used above, on its own under the
// budget, must parse clean — the fix must aggregate charges, not lower
// the cap.
func TestParseBudget_SingleBlockUnderBudgetControl_16519(t *testing.T) {
	tree, errs := NewParser(budgetBlock16519("blk", 80_000)).Parse()
	if hasBudgetError(errs) {
		t.Fatalf("single 160_002-unit block hit the budget (#16519 over-broad): %v", errs)
	}
	if len(errs) != 0 {
		t.Fatalf("single under-budget block errors: %v", errs)
	}
	if tree == nil || tree.NodeCount() != 160_002 {
		got := 0
		if tree != nil {
			got = tree.NodeCount()
		}
		t.Fatalf("single block NodeCount = %d, want 160_002", got)
	}
}
