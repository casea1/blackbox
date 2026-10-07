package app

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// noteReport adds a scheduled report just written to the ledger.
func noteReport(st *store.Store, dir string, from, to, made time.Time) {
	sum, _ := manifestHash(dir)
	st.State.Reports = append(st.State.Reports, store.ReportRecord{Dir: dir, From: from, To: to, Made: made, Manifest: sum})
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
		if p := reportProblem(r); p != "" {
			out = append(out, report.MissingReport{Name: filepath.Base(r.Dir), Dir: r.Dir, From: r.From, To: r.To, Problem: p})
		}
	}
	return out
}

// reportProblem is "missing" when the report's manifest is gone, "changed"
// when it differs from the one written, else "".
func reportProblem(r store.ReportRecord) string {
	sum, err := manifestHash(r.Dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "missing"
	case err != nil:
		return "" // can't tell (no access now): not reported as missing
	case r.Manifest != "" && sum != r.Manifest:
		return "changed"
	}
	return ""
}

// ReportProblemText says what is wrong with a scheduled report.
func ReportProblemText(m report.MissingReport, loc *time.Location) string {
	what := "is missing (deleted or moved)"
	if m.Problem == "changed" {
		what = "was changed after it was written (its manifest no longer matches)"
	}
	return fmt.Sprintf("The scheduled report for %s to %s (%s) %s. It held the only copy of that period's original logs. If this was on purpose: blackbox reports accept %s \"why\"",
		stampLocal(m.From, loc), stampLocal(m.To, loc), m.Name, what, m.Name)
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
	for _, r := range st.State.Reports {
		state := "OK"
		switch p := reportProblem(r); {
		case !r.Removed.IsZero():
			state = "removed under retention_days on " + stampLocal(r.Removed, a.loc())
		case r.Accepted != nil:
			state = fmt.Sprintf("accepted as %s by %s on %s: %s", map[bool]string{true: p, false: "gone or changed"}[p != ""], r.Accepted.Who, stampLocal(r.Accepted.When, a.loc()), r.Accepted.Reason)
		case p == "missing":
			state = "MISSING (deleted or moved)"
		case p == "changed":
			state = "CHANGED (its manifest no longer matches)"
		}
		fmt.Fprintf(w, "%s to %s  %s  %s\n", stampLocal(r.From, a.loc()), stampLocal(r.To, a.loc()), filepath.Base(r.Dir), state)
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
	problem := reportProblem(*rec)
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
	if err := report.WriteIndex(a.ReportsDir(), a.Cfg.SiteName, a.Cfg.ReportAt.Describe(a.Cfg.ReportEvery), a.loc(), reportProblems(st)); err != nil {
		a.logf("updating report index: %v", err)
	}
}
