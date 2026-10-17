package config

import "fmt"

// validateFlowTraceFileTail14577 validates the whole tail of
// `security flow traceoptions file <name> [size <s>] [files <n>]`
// (#14577, #3424). tokens is the flattened tail after `file`:
// [name, size, s, files, n] in any modifier order, with either modifier
// omittable. The filename is validated as a non-empty token here; the
// basename/path-traversal gate stays validateFlowTraceFileAST (#3420).
// size/files values are checked against the #3424 bounds SSOT, mirroring
// validateFlowTraceSizeFilesAST so the schema walk and the compiler
// prewalk reject the same values with the same bounds.
func validateFlowTraceFileTail14577(tokens []string, _ [][]string) error {
	if len(tokens) == 0 || tokens[0] == "" {
		return fmt.Errorf("missing value")
	}
	rest := tokens[1:]
	for i := 0; i < len(rest); {
		kw := rest[i]
		if kw != "size" && kw != "files" {
			return fmt.Errorf("unknown modifier %q", kw)
		}
		if i+1 >= len(rest) {
			return fmt.Errorf("modifier %q requires a value", kw)
		}
		v := rest[i+1]
		var err error
		if kw == "size" {
			err = ValidateInteger(FlowTraceMinFileSize, FlowTraceMaxFileSize)(v, nil)
		} else {
			err = ValidateInteger(FlowTraceMinFileCount, FlowTraceMaxFileCount)(v, nil)
		}
		if err != nil {
			return fmt.Errorf("invalid value %q for %q: %v", v, kw, err)
		}
		i += 2
	}
	return nil
}
