package main

import (
	"bufio"
	"io"
	"os"
	"runtime"
	"strings"
)

// asciiFold replaces the typographic characters Blackbox's messages use
// with ASCII. Windows PowerShell 5.1 reads a redirected program's output
// in the console's code page, so "—" became "ΓÇö" in files and tickets
// (CLI1).
var asciiFold = strings.NewReplacer("—", "-", "–", "-", "·", "-", "…", "...", "→", "->", "←", "<-", "×", "x",
	"‘", "'", "’", "'", "“", `"`, "”", `"`, "✓", "OK", "✕", "X")

// flushOut is set while standard output is folded to ASCII: it waits
// until everything written has been passed on.
var flushOut = func() {}

// foldRedirectedOutput folds standard output and error to ASCII on
// Windows when they are redirected to a file or another program; a
// console shows Unicode as it is.
func foldRedirectedOutput() {
	if runtime.GOOS != "windows" {
		return
	}
	var waits []chan struct{}
	var closers []*os.File
	for _, f := range []**os.File{&os.Stdout, &os.Stderr} {
		real := *f
		if fi, err := real.Stat(); err != nil || fi.Mode()&os.ModeCharDevice != 0 {
			continue
		}
		r, w, err := os.Pipe()
		if err != nil {
			continue
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			copyFolded(real, r)
		}()
		*f = w
		waits, closers = append(waits, done), append(closers, w)
	}
	flushOut = func() {
		for _, w := range closers {
			w.Close()
		}
		for _, d := range waits {
			<-d
		}
	}
}

// copyFolded copies r to w line by line, folded to ASCII.
func copyFolded(w io.Writer, r io.Reader) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			io.WriteString(w, asciiFold.Replace(line))
		}
		if err != nil {
			return
		}
	}
}

// exit flushes folded output, then exits.
func exit(code int) {
	flushOut()
	os.Exit(code)
}
