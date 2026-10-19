package cli

import (
	"fmt"
	"os"

	"github.com/psaab/xpf/pkg/cmdtree"
)

func (c *CLI) showOperationalHelp() {
	// #14988: help lists only commands the class may run.
	cands := c.filteredOperationalHelp()
	pairs := make([]cmdtree.Candidate, len(cands))
	for i, cand := range cands {
		pairs[i] = cmdtree.Candidate{Name: cand.name, Desc: cand.desc}
	}
	cmdtree.WriteHelp(os.Stdout, pairs)
	fmt.Println()
	fmt.Println("  <command> | match/grep <pattern>    Filter output by pattern")
	fmt.Println("  <command> | except <pattern>        Exclude lines matching pattern")
	fmt.Println("  <command> | find <pattern>          Show from first match to end")
	fmt.Println("  <command> | count                   Count output lines")
	fmt.Println("  <command> | last [N]                Show last N lines (default 10)")
	fmt.Println("  <command> | no-more                 Disable paging")
	fmt.Println("  Use <TAB> for command completion, ? for context help")
}

func (c *CLI) showConfigHelp() {
	cands := c.filteredConfigHelp()
	pairs := make([]cmdtree.Candidate, len(cands))
	for i, cand := range cands {
		pairs[i] = cmdtree.Candidate{Name: cand.name, Desc: cand.desc}
	}
	cmdtree.WriteHelp(os.Stdout, pairs)
	fmt.Println()
	fmt.Println("  Use <TAB> for command completion, ? for context help")
}
