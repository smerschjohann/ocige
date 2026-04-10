package main

import (
	"os"

	"golang.org/x/term"
)

// IsTerminal returns true if the given file is a terminal.
func IsTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
