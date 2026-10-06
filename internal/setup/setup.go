// Package setup runs an install from chosen settings: it installs, checks
// the audit settings and produces the first report or first send. The
// console setup and the setup window both use it, so they do the same
// thing and report it in the same words.
package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/casea1/blackbox/internal/app"
	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/install"
	"github.com/casea1/blackbox/internal/store"
)

// Options for Run.
type Options struct {
	Answers   install.Answers
	Version   string
	Reinstall bool // already installed: an upgrade or a change of settings
	NoReport  bool // do not produce a report (or send) straight away
	StartTray bool // start the status icon for the person running setup
	// Logf receives each line of progress; "" is a blank line.
	Logf func(format string, args ...any)
}

// Result says what was produced.
type Result struct {
	Report     string // the first report's report.html, if one was made
	ReportsDir string // where reports are saved ("" on a sender)
}

// Run installs with the chosen settings and does the first run.
func Run(o Options) (Result, error) {
	var res Result
	logf := o.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	// A collector that stops collecting (AR3): said below.
	wasCollector, madeReports := false, false
	if prev, err := config.Load(config.DefaultPath()); err == nil && o.Reinstall {
		wasCollector = prev.Inbox != ""
		madeReports = prev.MakesReports()
	}
	logf("Installing Blackbox %s", o.Version)
	if err := install.Install(install.Options{Answers: o.Answers, Version: o.Version, Logf: logf}); err != nil {
		return res, err
	}

	logf("")
	logf("Checking audit settings against the DISA STIG (nothing will be changed)...")
	for _, l := range CheckLines(check.Run(), false) {
		logf("%s", l)
	}

	cfg, err := config.Load(config.DefaultPath())
	if err != nil {
		return res, err
	}
	a := &app.App{Cfg: cfg, Version: o.Version, Logf: logf, QuietSend: true}
	if cfg.MakesReports() {
		res.ReportsDir = cfg.ReportsDir()
		// Made now, not with the first report: an upgrade makes no report,
		// and "Open reports folder" must open it.
		if err := ensureDir(res.ReportsDir); err != nil {
			logf("Note: the reports folder %s could not be made yet: %v", res.ReportsDir, err)
		}
	}
	switch {
	case !cfg.MakesReports():
		logf("")
		if o.NoReport {
			logf("Done. Events will be collected and sent at the next scheduled run.")
			break
		}
		logf("Collecting events and sending them to the collector (the first run reads the whole log and can take a few minutes)...")
		r, err := a.SendNow()
		logf("")
		for _, l := range sentLines(r, err, cfg.SendTo, madeReports) {
			logf("%s", l)
		}
	case o.NoReport:
		logf("")
		logf("Done. The first report will be produced at the next scheduled run.")
		logf("Reports will be saved in %s", cfg.ReportsDir())
	case o.Reinstall && Reported(a):
		// An upgrade or a settings change keeps the report schedule: the
		// next scheduled report covers the whole period as usual.
		_, next, _ := a.NextScheduled()
		logf("")
		logf("Done. No report was produced now, so the schedule is unchanged (reports %s).", cfg.ReportAt.Describe(cfg.ReportEvery))
		logf("Next scheduled report: %s", app.NextText(next))
		logf("For a manual report now, run: blackbox report")
	default:
		logf("")
		logf("Collecting events and producing the first report (the first run reads the whole log and can take a few minutes)...")
		dir, err := a.ReportNow(true)
		if err != nil {
			return res, err
		}
		res.Report = filepath.Join(dir, "report.html")
		logf("")
		logf("Done. First report: %s", res.Report)
		logf("All reports:        %s", filepath.Join(a.ReportsDir(), "index.html"))
	}
	if wasCollector && cfg.Inbox == "" && cfg.MakesReports() {
		logf("")
		logf("This computer no longer receives from other computers. What they sent so far, with their original logs, is in its next report. Set them to send to the new collector.")
	}
	if cfg.Inbox != "" {
		logf("")
		logf("Other computers can now send to this collector's inbox: %s", cfg.Inbox)
		logf("Their events appear in reports after their first collection. See: blackbox status")
	}
	// Last, so its first look sees the first report. An icon already
	// running restarts itself into the new version.
	if o.StartTray && o.Answers.Tray && o.Answers.Role != install.RoleSender && runtime.GOOS == "windows" {
		if err := install.StartTray(); err != nil {
			logf("Note: the status icon could not be started now (%v); it appears at the next logon.", err)
		}
	}
	return res, nil
}

// sentLines says how the first send went.
// madeReports: before this setup, the computer made reports (a collector
// or standalone).
func sentLines(r app.SendResult, err error, sendTo string, madeReports bool) []string {
	var out []string
	if madeReports && r.FinalReport == "" && err == nil {
		// AR3b: no scheduled report since it last sent, so nothing to
		// finalise: what it collected meanwhile goes to the collector.
		out = append(out, "This computer made no scheduled report since it last sent to a collector, so no final report was needed: what it collected in the meantime is sent to the collector with its events below.", "")
	}
	if r.FinalReport != "" {
		// AR3: it made reports before; what it had stays in this one.
		out = append(out, "This computer made reports before. Its final report, with everything it had collected and received and the original logs it held (its own and other computers'), is in:",
			"  "+r.FinalReport,
			"From now on it sends only its own events. Set any computers that sent to it to send to the new collector.", "")
	}
	return append(out, sendLines(r, err, sendTo)...)
}

func sendLines(r app.SendResult, err error, sendTo string) []string {
	switch {
	case errors.Is(err, store.ErrBusy):
		// S14: a scheduled run holds the lock; nothing is wrong with
		// the connection, and that run or the next one sends.
		return []string{"Done. A collection was already running, so this computer's events go to the collector at the next run.",
			"Check with: blackbox status"}
	case err != nil:
		return []string{"Done, but the collector could not be reached yet: " + err.Error(),
			fmt.Sprintf("The events are kept safely on this computer (%d batch%s waiting) and are sent at the next scheduled run that can reach it.", r.Waiting, es(r.Waiting)),
			"Check with: blackbox status"}
	}
	return []string{fmt.Sprintf("Done. Sent %d batch%s to %s.", r.Delivered, es(r.Delivered), sendTo),
		"This computer's events will appear in the collector's reports."}
}

// Reported says whether this computer has produced a scheduled report.
func Reported(a *app.App) bool {
	last, _, err := a.NextScheduled()
	return err == nil && !last.IsZero()
}

// CheckLines describes audit-setting check results, one line each: the
// ones needing attention (or all), then a count.
func CheckLines(rs []check.Result, all bool) []string {
	var out []string
	pass, fail, warn := check.Summary(rs)
	for _, r := range rs {
		if r.Area == "Baseline" {
			out = append(out, fmt.Sprintf("  Compared with the %s.", r.Have))
			continue
		}
		if r.Status == check.Pass && !all {
			continue
		}
		stig := ""
		if r.STIG != "" {
			stig = " [" + r.STIG + "]"
		}
		out = append(out, fmt.Sprintf("  [%-5s] %s: %s%s — have %s, need %s", strings.ToUpper(string(r.Status)), r.Area, r.Item, stig, r.Have, r.Want))
		if r.Affects != "" && r.Status != check.Pass {
			out = append(out, "           Affects: "+r.Affects)
		}
		if r.Fix != "" {
			out = append(out, "           Fix:     "+r.Fix)
		}
	}
	last := fmt.Sprintf("  %d settings pass, %d need attention", pass, fail)
	if warn > 0 {
		last += fmt.Sprintf(", %d warnings", warn)
	}
	return append(out, last+".")
}

func es(n int) string {
	if n == 1 {
		return ""
	}
	return "es"
}

// Current returns the settings setup starts from: the installed ones on a
// re-install (reinstall is true), otherwise the defaults. defaultReports
// is the reports folder used when none is chosen.
func Current() (a install.Answers, defaultReports string, reinstall bool, err error) {
	cur, err := config.Load(config.DefaultPath())
	if err != nil {
		return a, "", false, fmt.Errorf("%w\n(fix or remove the file, then run setup again)", err)
	}
	_, statErr := os.Stat(config.DefaultPath())
	a = install.Answers{Site: cur.SiteName, ReportEvery: cur.ReportEvery, ReportAt: cur.ReportAt, ReportDir: cur.ReportDir, ArchiveDir: cur.ArchiveDir,
		CollectEvery: cur.CollectEvery, SendTo: cur.SendTo, ShareUser: cur.ShareUser, Inbox: cur.Inbox,
		ShareInbox: install.InboxShared(), Tray: install.TrayWanted()}
	return a, filepath.Join(config.DefaultDataDir(), "reports"), statErr == nil, nil
}

// ensureDir makes the reports folder if it doesn't exist. The default
// folder is inside the data folder and takes its permissions, as the
// first report would; a chosen folder was already made by the install.
func ensureDir(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}
