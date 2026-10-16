package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/report"
)

// cmdOpen opens the latest report, or the index, in the browser of the
// person running it (READ1): the Linux "Blackbox reports" launcher. A
// browser that can only read the home folder (Ubuntu's snap Firefox) gets
// a copy in ~/Blackbox reports.
func cmdOpen(args []string) error {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	index := fs.Bool("index", false, "open the reports index instead of the latest report")
	dir := fs.String("dir", "", "the reports folder (default: report_dir in the settings)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	err := openReports(*dir, *index)
	if err != nil && !onTerminal() {
		notify(err.Error()) // started from the applications menu: no terminal to print to
	}
	return err
}

func openReports(dir string, index bool) error {
	if runtime.GOOS != "linux" {
		return errors.New("blackbox open is for Linux; on Windows use the status icon")
	}
	if os.Geteuid() == 0 {
		return errors.New("run it as yourself, without sudo, so the report opens in your browser")
	}
	if dir == "" {
		cfg, err := config.Load(config.DefaultPath())
		if err != nil {
			return fmt.Errorf("could not read the settings (%v); give the reports folder: blackbox open --dir FOLDER", err)
		}
		dir = cfg.ReportsDir()
	}
	target := filepath.Join(dir, "index.html")
	if !index {
		latest, ok := report.Latest(dir)
		if !ok {
			if _, err := os.Stat(dir); err != nil {
				return cantRead(dir, err)
			}
			return fmt.Errorf("no report in %s yet (or you can't read them)", dir)
		}
		target = filepath.Join(latest.Dir, "report.html")
	}
	if f, err := os.Open(target); err != nil {
		return cantRead(target, err)
	} else {
		f.Close()
	}
	home, _ := os.UserHomeDir()
	if home != "" && !within(dir, home) && homeOnlyBrowser() {
		copyDir := filepath.Join(home, "Blackbox reports")
		if err := mirror(dir, copyDir); err != nil {
			return fmt.Errorf("copy the reports to %s: %w", copyDir, err)
		}
		rel, _ := filepath.Rel(dir, target)
		target = filepath.Join(copyDir, rel)
		fmt.Printf("Your browser can only open files in your home folder, so the reports are copied to %s (original logs stay in %s).\n", copyDir, dir)
	}
	if err := exec.Command("xdg-open", target).Start(); err != nil {
		return fmt.Errorf("open %s: %w", target, err)
	}
	fmt.Println("Opened", target)
	return nil
}

func cantRead(p string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("you can't read %s. An administrator can let a group open the reports: sudo blackbox config set report_group GROUP, then sudo blackbox setup (and add you to that group)", p)
	}
	return err
}

// homeOnlyBrowser says whether the default browser is a snap, which can't
// read files outside the home folder whatever their permissions.
func homeOnlyBrowser() bool {
	out, err := exec.Command("xdg-settings", "get", "default-web-browser").Output()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		// A snap's desktop file is named SNAP_APP.desktop (firefox_firefox.desktop).
		return strings.Contains(string(out), "_")
	}
	_, err = os.Stat("/snap/bin/firefox")
	return err == nil
}

func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// mirror copies the reports folder into dst for a home-only browser: the
// index every time, a report folder once (reports don't change). The
// original-log zips are left out: they can be large, and open from the
// reports folder itself.
func mirror(src, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(src, "index.html"), filepath.Join(dst, "index.html")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		from, to := filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())
		if _, err := os.Stat(filepath.Join(to, "summary.json")); err == nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(from, "summary.json")); err != nil {
			continue // not a report folder, or not readable
		}
		tmp := to + ".copying"
		os.RemoveAll(tmp)
		err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(from, p)
			out := filepath.Join(tmp, rel)
			switch {
			case d.IsDir():
				return os.MkdirAll(out, 0o700)
			case !d.Type().IsRegular(), strings.HasSuffix(strings.ToLower(p), ".zip"):
				return nil
			}
			return copyFile(p, out)
		})
		if err != nil {
			os.RemoveAll(tmp)
			return err
		}
		os.RemoveAll(to)
		if err := os.Rename(tmp, to); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst+".part", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(dst+".part", dst)
}

func onTerminal() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// notify shows msg on the desktop, where the launcher has no terminal.
func notify(msg string) {
	if exec.Command("notify-send", "Blackbox reports", msg).Run() != nil {
		exec.Command("zenity", "--error", "--title=Blackbox reports", "--text="+msg).Run()
	}
}
