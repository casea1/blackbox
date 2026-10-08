package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/selfaudit"
	"github.com/casea1/blackbox/internal/store"
)

// The report ledger: every scheduled report this computer made, with the
// hash of its manifest. A scheduled report holds the only copy of its
// period's original logs, so one that is deleted or changed is pointed
// out (in status, the status icon, the next report and the index) until
// someone records why with "blackbox reports accept". Removal under
// retention_days is expected and not pointed out.

func manifestHash(dir string) (string, error) {
	f, err := os.Open(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// manifestFiles are the files manifest.sha256 lists, with their hashes.
func manifestFiles(dir string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.sha256"))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if sum, name, ok := strings.Cut(strings.TrimSpace(l), "  "); ok {
			out[name] = strings.ToLower(sum)
		}
	}
	return out, nil
}

// noteReport adds a scheduled report just written to the ledger, with
// the size of each of its files.
func noteReport(st *store.Store, dir string, from, to, made time.Time) {
	sum, _ := manifestHash(dir)
	rec := store.ReportRecord{Dir: dir, From: from, To: to, Made: made, Manifest: sum, Verified: made}
	if files, err := manifestFiles(dir); err == nil {
		rec.Files = map[string]int64{}
		for name := range files {
			if fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(name))); err == nil {
				rec.Files[name] = fi.Size()
			}
		}
	}
	rec.FileCount = report.CountFiles(dir)
	st.State.Reports = append(st.State.Reports, rec)
}

// fillReportFiles gives the reports recorded before 0.20, which have no
// file list, one from their manifest, while the manifest is the one
// written (LEDGER1b): a file moved out of one is then noticed at once,
// not at the next daily hash. A file the manifest lists that is already
// gone is kept as -1, so it is reported missing.
func fillReportFiles(st *store.Store) bool {
	changed := false
	for i := range st.State.Reports {
		r := &st.State.Reports[i]
		if r.Files != nil || !r.Removed.IsZero() || r.Accepted != nil {
			continue
		}
		if sum, err := manifestHash(r.Dir); err != nil || (r.Manifest != "" && sum != r.Manifest) {
			continue // gone or changed: reported as such
		}
		files, err := manifestFiles(r.Dir)
		if err != nil {
			continue
		}
		r.Files = map[string]int64{}
		for name := range files {
			r.Files[name] = -1
			if fi, err := os.Stat(filepath.Join(r.Dir, filepath.FromSlash(name))); err == nil {
				r.Files[name] = fi.Size()
			}
		}
		changed = true
	}
	return changed
}

// verifyEvery is how often every file of every scheduled report is hashed
// again (LEDGER1); each run checks only that they are there, at their
// size.
const verifyEvery = 24 * time.Hour

// verifyReports hashes the files of each scheduled report against its
// manifest, once a day, and keeps what it finds for status and reports.
func (a *App) verifyReports(st *store.Store) {
	now := a.now()
	changed := fillReportFiles(st)
	for i := range st.State.Reports {
		r := &st.State.Reports[i]
		if !r.Removed.IsZero() || r.Accepted != nil || now.Sub(r.Verified) < verifyEvery {
			continue
		}
		files, err := manifestFiles(r.Dir)
		if err != nil {
			continue // missing: the quick check says so
		}
		names := make([]string, 0, len(files))
		for n := range files {
			names = append(names, n)
		}
		sort.Strings(names)
		bad := ""
		for _, n := range names {
			got, err := fileSHA256(filepath.Join(r.Dir, filepath.FromSlash(n)))
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					bad = n + " is missing"
					break
				}
				// A listed file that can't be read is not verified (VER2).
				bad = n + " could not be read, so it is not verified (" + err.Error() + ")"
				break
			}
			if got != files[n] {
				bad = n + " was changed (its SHA-256 no longer matches the manifest)"
				break
			}
		}
		if bad != r.Bad {
			if bad != "" {
				a.logf("REPORT CHANGED: %s: %s", filepath.Base(r.Dir), bad)
			}
		}
		r.Verified, r.Bad, changed = now, bad, true
	}
	if a.alertReports(st) {
		changed = true
	}
	if changed {
		if err := st.Save(); err != nil {
			a.logf("saving the state: %v", err)
		}
	}
}

// alertReports writes each scheduled report newly found missing or
// changed to the system log, once per report and problem (LEDGER4): the
// Application log, event 101, on Windows; the journal/syslog, ident
// blackbox, on Linux. It says whether the ledger changed.
func (a *App) alertReports(st *store.Store) bool {
	alert := a.ReportAlert
	if alert == nil {
		alert = selfaudit.ReportProblem
	}
	changed := false
	for i := range st.State.Reports {
		r := &st.State.Reports[i]
		p, what := "", ""
		if r.Removed.IsZero() && r.Accepted == nil {
			p, what = reportProblem(*r)
		}
		if p == r.Alerted {
			continue
		}
		if p != "" {
			m := report.MissingReport{Name: filepath.Base(r.Dir), Dir: r.Dir, From: r.From, To: r.To, Problem: p, What: what}
			msg := "REPORT " + strings.ToUpper(p) + ": " + ReportProblemText(m, a.loc()) + ". Folder: " + r.Dir
			if err := alert(msg); err != nil {
				a.logf("writing the %s report %s to the system log failed: %v", p, m.Name, err)
				continue // tried again at the next run
			}
		}
		r.Alerted, changed = p, true
	}
	return changed
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// markRemoved records reports removed under retention_days.
func markRemoved(st *store.Store, reportsDir string, names []string, now time.Time) {
	for _, n := range names {
		for i := range st.State.Reports {
			r := &st.State.Reports[i]
			if r.Removed.IsZero() && sameDir(r.Dir, filepath.Join(reportsDir, n)) {
				r.Removed = now
			}
		}
	}
}

func sameDir(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if os.PathSeparator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// reportProblems lists the scheduled reports that are missing or changed
// and not accepted.
func reportProblems(st *store.Store) []report.MissingReport {
	var out []report.MissingReport
	for _, r := range st.State.Reports {
		if !r.Removed.IsZero() || r.Accepted != nil {
			continue
		}
		if p, what := reportProblem(r); p != "" {
			out = append(out, report.MissingReport{Name: filepath.Base(r.Dir), Dir: r.Dir, From: r.From, To: r.To, Problem: p, What: what})
		}
	}
	return out
}

// indexReports are reportProblems and, for the index, the scheduled
// reports accepted as gone that are no longer in the folder: their row
// stays, muted, saying who accepted it and why (LEDGER2).
func indexReports(st *store.Store, loc *time.Location) []report.MissingReport {
	out := reportProblems(st)
	for _, r := range st.State.Reports {
		if !r.Removed.IsZero() || r.Accepted == nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(r.Dir, "summary.json")); err == nil {
			continue // still there: its own row shows
		}
		ac := r.Accepted
		out = append(out, report.MissingReport{Name: filepath.Base(r.Dir), Dir: r.Dir, From: r.From, To: r.To, Problem: "missing",
			Accepted: fmt.Sprintf("Accepted as moved by %s on %s: %s", ac.Who, ac.When.In(loc).Format("2 Jan 2006"), ac.Reason)})
	}
	return out
}

// reportProblem is "missing" when the report's folder is gone, "changed"
// when its manifest differs from the one written, a file it lists is gone
// or not the size it was, or the daily hash check found one changed; else
// "". what says which file.
func reportProblem(r store.ReportRecord) (problem, what string) {
	sum, err := manifestHash(r.Dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if _, derr := os.Stat(r.Dir); derr == nil {
			return "changed", "manifest.sha256 is missing"
		}
		return "missing", ""
	case err != nil:
		return "", "" // can't tell (no access now): not reported as missing
	case r.Manifest != "" && sum != r.Manifest:
		return "changed", "manifest.sha256 was changed"
	}
	files := r.Files
	if files == nil {
		// Recorded before 0.20: the files the manifest lists must be
		// there (LEDGER1b).
		if m, err := manifestFiles(r.Dir); err == nil {
			files = map[string]int64{}
			for n := range m {
				files[n] = -1
			}
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fi, err := os.Stat(filepath.Join(r.Dir, filepath.FromSlash(n)))
		switch {
		case errors.Is(err, os.ErrNotExist):
			return "changed", n + " is missing"
		case err == nil && files[n] >= 0 && fi.Size() != files[n]:
			return "changed", n + " was changed (its size differs)"
		}
	}
	// A file added since it was written, anywhere in the folder (VER2):
	// more files than when it was written, named when the manifest does
	// not list them.
	if n := report.CountFiles(r.Dir); r.FileCount > 0 && n > r.FileCount {
		what := fmt.Sprintf("%d files were added after the report was written (it had %d, now %d)", n-r.FileCount, r.FileCount, n)
		if added, err := report.Unlisted(r.Dir); err == nil && len(added) == 1 {
			what = fmt.Sprintf("%s was added after the report was written (it is not in the manifest)", added[0])
		} else if err == nil && len(added) > 1 {
			what = fmt.Sprintf("%s and %d more files were added after the report was written (they are not in the manifest)", added[0], len(added)-1)
		}
		return "changed", what
	}
	if r.Bad != "" {
		return "changed", r.Bad
	}
	return "", ""
}

// ReportProblemText says what is wrong with a scheduled report.
func ReportProblemText(m report.MissingReport, loc *time.Location) string {
	what := "is missing (deleted or moved)"
	if m.Problem == "changed" {
		what = "was changed after it was written"
		if m.What != "" {
			what += ": " + m.What
		}
	}
	held := ""
	if m.LostLogs() {
		held = " It held the only copy of that period's original logs." // LEDGER4b
	}
	return fmt.Sprintf("The scheduled report for %s to %s (%s) %s.%s If this was on purpose: blackbox reports accept %s \"why\"",
		stampLocal(m.From, loc), stampLocal(m.To, loc), m.Name, what, held, m.Name)
}

// Reports lists the scheduled reports in the ledger and their state.
func (a *App) Reports(w io.Writer) error {
	st, err := store.Open(a.Cfg.DataDir)
	if err != nil {
		return err
	}
	if len(st.State.Reports) == 0 {
		fmt.Fprintln(w, "No scheduled reports recorded yet (the record starts with the first scheduled report made by 0.19 or later).")
		return nil
	}
	var bad []string
	for _, r := range st.State.Reports {
		state := "OK"
		p, what := reportProblem(r)
		if p != "" && r.Removed.IsZero() && r.Accepted == nil {
			bad = append(bad, "a scheduled report is "+p)
		}
		switch {
		case !r.Removed.IsZero():
			state = "removed under retention_days on " + stampLocal(r.Removed, a.loc())
		case r.Accepted != nil:
			state = fmt.Sprintf("accepted as %s by %s on %s: %s", map[bool]string{true: p, false: "gone or changed"}[p != ""], r.Accepted.Who, stampLocal(r.Accepted.When, a.loc()), r.Accepted.Reason)
		case p == "missing":
			state = "MISSING (deleted or moved)"
		case p == "changed":
			state = "CHANGED: " + what
		}
		fmt.Fprintf(w, "%s to %s  %s  %s\n", stampLocal(r.From, a.loc()), stampLocal(r.To, a.loc()), filepath.Base(r.Dir), state)
	}
	// Exit code 4, like status, when one is missing or changed (LEDGER1b).
	if len(bad) > 0 {
		return &NeedsAttention{What: bad}
	}
	return nil
}

// AcceptReport records that a missing or changed scheduled report is so on
// purpose: it is no longer pointed out, and the next report has a row
// saying who accepted it, when and why (recorded like a setting change).
func (a *App) AcceptReport(name, reason string) error {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return errors.New("say why the report is gone or changed")
	}
	who := selfaudit.Who()
	st, unlock, err := a.open()
	if err != nil {
		return err
	}
	var rec *store.ReportRecord
	for i := range st.State.Reports {
		r := &st.State.Reports[i]
		if strings.EqualFold(filepath.Base(r.Dir), name) && r.Removed.IsZero() && r.Accepted == nil {
			rec = r
		}
	}
	if rec == nil {
		unlock()
		return fmt.Errorf("no missing or changed scheduled report named %s (see blackbox reports)", name)
	}
	problem, _ := reportProblem(*rec)
	if problem == "" {
		unlock()
		return fmt.Errorf("the report %s is in place and unchanged", name)
	}
	rec.Accepted = &store.ReportAcceptance{Who: who, When: a.now(), Reason: reason}
	err = st.Save()
	unlock()
	if err != nil {
		return err
	}
	record := a.RecordSelf
	if record == nil {
		record = selfaudit.Record
	}
	c := event.SelfChange{Kind: "report_accepted", Who: who, Setting: name, New: problem, Old: reason, Program: "blackbox reports accept"}
	if rerr := record(a.Cfg.DataDir, c, a.now()); rerr != nil {
		a.logf("the report was accepted, but recording it failed: %v", rerr)
	}
	return nil
}

// refreshIndex rebuilds the reports index, so reports deleted since the
// last report drop off it and missing scheduled ones are shown.
func (a *App) refreshIndex(st *store.Store) {
	if !a.Cfg.MakesReports() {
		return
	}
	if err := report.WriteIndex(a.ReportsDir(), a.Cfg.SiteName, a.Cfg.ReportAt.Describe(a.Cfg.ReportEvery), a.loc(), indexReports(st, a.loc())); err != nil {
		a.logf("updating report index: %v", err)
	}
}
