package main

import "flag"

// parseAnywhere parses args with fs, accepting flags anywhere among the
// positional arguments: "gaps accept PC 1-5 --config f why", "--config f
// gaps accept …" and "gaps accept … --config f" all work (CLI2). Go's flag
// package stops at the first non-flag, which is the subcommand. "--" ends
// the flags: everything after it is positional, so a reason may start with
// a dash. It returns the positional arguments in order; an unknown flag is
// an error, and -h is flag.ErrHelp.
func parseAnywhere(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		// fs.Args is a suffix of args: the parser stopped either at a
		// non-flag or just after a "--" it consumed.
		if i := len(args) - len(rest); i > 0 && args[i-1] == "--" && !consumedAsValue(fs, args[:i-1]) {
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// consumedAsValue reports whether the "--" following args was the value
// of a flag that takes one ("--host --"), rather than the end of flags.
func consumedAsValue(fs *flag.FlagSet, args []string) bool {
	if len(args) == 0 {
		return false
	}
	last := args[len(args)-1]
	if len(last) < 2 || last[0] != '-' {
		return false
	}
	name := last[1:]
	if name[0] == '-' {
		name = name[1:]
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '=' {
			return false // -name=value: the value is in this argument
		}
	}
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
		return false
	}
	return true
}
