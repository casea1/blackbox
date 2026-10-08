// Command blackbox collects Windows (and soon Linux) audit logs and
// produces plain-English audit reports for air-gapped systems.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/app"
	"github.com/casea1/blackbox/internal/check"
	"github.com/casea1/blackbox/internal/config"
	"github.com/casea1/blackbox/internal/gui"
	"github.com/casea1/blackbox/internal/install"
	"github.com/casea1/blackbox/internal/lan"
	"github.com/casea1/blackbox/internal/report"
	"github.com/casea1/blackbox/internal/selfaudit"
	"github.com/casea1/blackbox/internal/setup"
	"github.com/casea1/blackbox/internal/store"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const usage = `Blackbox — audit log review for air-gapped systems

Usage:
  blackbox install               Set up (or change) scheduled collection and reporting; asks each setting
  blackbox setup                 Windows: the same, in a window (also what double-clicking blackbox.exe does)
  blackbox tray                  Windows: show Blackbox's status in the notification area (administrators)
  blackbox config                Show settings; "blackbox config set report_dir D:\Reports" changes one
  blackbox status                Show what this computer does, when it last collected, and what is waiting
  blackbox run                   Collect new events; send them or produce a report if one is due (what the schedule runs)
  blackbox send                  Collect and send to the collector now (e.g. before shutting down a VM)
  blackbox send --resend 214-219 Send batches again that the collector reports missing (kept keep_sent_days after delivery)
  blackbox send --new-id         Give this computer a new sender ID (a computer cloned from another)
  blackbox systems               List the computers whose events this collector reports on
  blackbox systems remove NAME   Stop listing a retired computer
  blackbox systems rename OLD NEW
                                 Accept OLD as a former name of NEW
  blackbox inbox                 List the senders' own folders in this collector's inbox
  blackbox inbox add NAME ACCOUNT [--host COMPUTER]
                                 Make a folder in the inbox that only ACCOUNT can write to
  blackbox gaps                  List batches that never arrived (collector)
  blackbox gaps accept NAME FROM-TO "why"
                                 Accept that those batches will not arrive
  blackbox reports               List the scheduled reports made here, and any missing or changed
  blackbox reports accept NAME "why"
                                 Accept that a scheduled report is gone or changed on purpose
  blackbox report [options]      Collect and produce a report now
  blackbox report --xml FILE     Produce a report from exported Windows event logs (any OS)
  blackbox report --audit FILE --syslog FILE
                                 Produce a report from copied Linux logs (any OS)
  blackbox check                 Check audit settings against the DISA STIG (report only; changes nothing)
  blackbox check --audit-rules   Linux: print the recommended auditd rules file
  blackbox verify FOLDER         Confirm a report has not been altered since it was produced
  blackbox uninstall             Remove the scheduled task (keeps reports and data)
  blackbox version               Show the version

Run "blackbox <command> -h" for a command's options. Options may go anywhere after
the command (blackbox gaps accept PC 1-5 "why" --config FILE); "--" ends them.
`

func main() {
	if len(os.Args) < 2 {
		// Double-clicked (the setup file, or blackbox.exe in Explorer):
		// open the setup window.
		if gui.Launched() {
			if gui.Setup(version, false) != nil {
				exit(1)
			}
			return
		}
		fmt.Fprint(os.Stderr, usage)
		exit(2)
	}
	gui.AttachConsole() // the setup file run from a prompt with a command
	foldRedirectedOutput()
	defer flushOut()
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "install":
		err = cmdInstall(args)
	case "setup", "tray":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		selftest := fs.Bool("selftest", false, "build the window, then close it (for testing)")
		if err = fs.Parse(args); err == nil {
			if cmd == "setup" {
				err = gui.Setup(version, *selftest)
			} else {
				err = gui.Tray(version, *selftest)
			}
		}
	case "run":
		err = cmdRun(args)
	case "report":
		err = cmdReport(args)
	case "collect":
		err = cmdCollect(args)
	case "check":
		err = cmdCheck(args)
	case "config":
		err = cmdConfig(args)
	case "status":
		err = cmdStatus(args)
	case "send":
		err = cmdSend(args)
	case "systems":
		err = cmdSystems(args)
	case "inbox":
		err = cmdInbox(args)
	case "gaps":
		err = cmdGaps(args)
	case "reports":
		err = cmdReports(args)
	case "verify":
		err = cmdVerify(args)
	case "uninstall":
		err = install.Uninstall(printf)
	case "version", "--version", "-v":
		fmt.Println("blackbox", version)
		fmt.Println(fipsState()) // COMP3
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			exit(0)
		}
		fmt.Fprintln(os.Stderr, "blackbox:", err)
		if hint := permissionHint(err, cmd); hint != "" {
			fmt.Fprintln(os.Stderr, hint)
		}
		exit(1)
	}
}

var geteuid = os.Geteuid

// permissionHint says how to run a command again when it was refused its
// settings or data (CLI1): they are readable by root or Administrators only.
func permissionHint(err error, cmd string) string {
	if !errors.Is(err, fs.ErrPermission) {
		return ""
	}
	if runtime.GOOS == "windows" {
		return "Its settings and data are readable by Administrators only: run it from an administrator prompt."
	}
	if geteuid() == 0 {
		return ""
	}
	return "Its settings and data are readable by root only: run it with sudo, e.g. sudo blackbox " + cmd
}

func printf(format string, args ...any) { fmt.Printf(format+"\n", args...) }

// common flags shared by commands that read the config.
type common struct {
	configPath string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.configPath, "config", config.DefaultPath(), "settings file (\"none\" for the built-in defaults)")
}

func (c *common) load() (*config.Config, error) {
	// Without a settings file the defaults are used, but a file named on
	// the command line must exist: a typing mistake should not silently
	// run with different settings.
	if c.configPath == "none" {
		return config.Default(), nil
	}
	if c.configPath != config.DefaultPath() {
		if _, err := os.Stat(c.configPath); err != nil {
			return nil, fmt.Errorf("settings file %s: %w", c.configPath, err)
		}
	}
	return config.Load(c.configPath)
}

func newApp(cfg *config.Config, logf func(string, ...any)) *app.App {
	return &app.App{Cfg: cfg, Version: version, Logf: logf}
}

func cmdInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: blackbox install [options]

Run with no options to be asked each setting (current settings are offered
as defaults when Blackbox is already installed). Options are for scripted
or unattended installs; any setting not given keeps its current value.

`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
The share password for --share-user is read from the BLACKBOX_SHARE_PASSWORD
environment variable (so it is not shown in the process list).
`)
	}
	site := fs.String("site", "", "site or system name shown on reports (\"-\" clears it)")
	every := fs.String("report-every", "", "how often to produce a report: daily, weekly or monthly")
	reportAt := fs.String("report-at", "", "when each report is ready, e.g. \"Wednesday 00:00\" (weekly) or \"06:00\" (daily, monthly)")
	reportDir := fs.String("report-dir", "", "folder for reports (\"default\" for the standard location)")
	collectEvery := fs.Duration("collect-every", 0, "how often to collect events: 1h, 30m or 15m")
	sendTo := fs.String("send-to", "", "send events to this collector inbox (a share or folder; \"none\" to stop sending)")
	shareUser := fs.String("share-user", "", "account on the collector for --send-to (\"-\" for none)")
	inbox := fs.String("inbox", "", "make this computer a collector that receives in this folder (\"none\" to stop)")
	shareInbox := fs.Bool("share-inbox", false, "Windows collector: share the inbox on the network as "+install.ShareName)
	var writers listFlag
	fs.Var(&writers, "inbox-writer", "Windows collector: an account allowed to deliver to the inbox, e.g. the user who runs VirtualBox (repeatable)")
	yes := fs.Bool("yes", false, "do not ask questions; use the options given and current or default settings")
	noReport := fs.Bool("no-first-report", false, "do not produce a report (or send) straight away")
	tray := fs.Bool("tray", true, "Windows collector or standalone: show Blackbox's status in the notification area for administrators")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := install.RequireAdmin(); err != nil {
		return err
	}

	// Current settings (or defaults on a first install) are the starting point.
	ans, defaultReports, reinstall, err := setup.Current()
	if err != nil {
		return err
	}

	given := 0
	fs.Visit(func(f *flag.Flag) {
		if f.Name != "no-first-report" && f.Name != "yes" && f.Name != "tray" {
			given++
		}
	})
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "tray" {
			ans.Tray = *tray
		}
	})
	if given == 0 && !*yes && install.IsTerminal(os.Stdin) {
		ans, err = install.Wizard(os.Stdin, os.Stdout, ans, defaultReports, reinstall && install.Installed())
		if err != nil {
			return err
		}
		fmt.Println()
	} else {
		if *site == "-" {
			ans.Site = ""
		} else if *site != "" {
			ans.Site = *site
		}
		if *every != "" {
			ans.ReportEvery = strings.ToLower(*every)
		}
		if *reportAt != "" {
			r, err := config.ParseReportAt(*reportAt)
			if err != nil {
				return err
			}
			ans.ReportAt = r
		}
		switch *reportDir {
		case "":
		case "default", defaultReports:
			ans.ReportDir = ""
		default:
			ans.ReportDir = *reportDir
		}
		if *collectEvery != 0 {
			ans.CollectEvery = *collectEvery
		}
		switch *sendTo {
		case "":
		case "none":
			ans.SendTo, ans.ShareUser = "", ""
		default:
			ans.SendTo = *sendTo
		}
		switch *shareUser {
		case "":
		case "-":
			ans.ShareUser = ""
		default:
			ans.ShareUser = *shareUser
		}
		ans.SharePassword = os.Getenv("BLACKBOX_SHARE_PASSWORD")
		switch *inbox {
		case "":
		case "none":
			ans.Inbox, ans.ShareInbox = "", false
		default:
			ans.Inbox = *inbox
		}
		if *shareInbox {
			ans.ShareInbox = true
		}
		ans.InboxWriters = writers
	}
	ans.Role = install.RoleOf(ans.SendTo, ans.Inbox)
	ans = install.ForRole(ans)
	if err := validateInstall(ans); err != nil {
		return err
	}

	// A person at a prompt (with or without --yes) gets the status icon
	// straight away, as with the setup window; a script or deployment
	// tool doesn't (it appears at the next logon).
	interactive := install.IsTerminal(os.Stdin)
	if _, err := setup.Run(setup.Options{Answers: ans, Version: version, Reinstall: reinstall, NoReport: *noReport,
		StartTray: interactive, Logf: printf}); err != nil {
		return err
	}
	fmt.Println("\nTo change settings later, run the installer again (it shows the current settings),")
	fmt.Println("or use: blackbox config set <setting> <value>")
	return nil
}

func validateInstall(a install.Answers) error {
	switch a.ReportEvery {
	case "daily", "weekly", "monthly":
	default:
		return fmt.Errorf("report schedule must be daily, weekly or monthly (got %q)", a.ReportEvery)
	}
	d := a.CollectEvery
	if d < 5*time.Minute || d > 24*time.Hour || d%time.Minute != 0 {
		return fmt.Errorf("collection interval must be whole minutes between 5m and 24h (got %s)", d)
	}
	if runtime.GOOS == "linux" && time.Hour%d != 0 && (d%time.Hour != 0 || (24*time.Hour)%d != 0) {
		return fmt.Errorf("collection interval must divide an hour or a day evenly on Linux (e.g. 15m, 30m, 1h, 2h)")
	}
	if a.ReportDir != "" && !config.IsAbs(a.ReportDir) {
		return fmt.Errorf("report folder must be a full path (got %q)", a.ReportDir)
	}
	if a.SendTo != "" && !config.IsAbs(a.SendTo) && !config.IsShare(a.SendTo) {
		return fmt.Errorf("--send-to must be a full path or a share (got %q)", a.SendTo)
	}
	if a.Inbox != "" && (!config.IsAbs(a.Inbox) || config.IsShare(a.Inbox)) {
		return fmt.Errorf("--inbox must be a full path to a folder on this computer (got %q)", a.Inbox)
	}
	if a.ShareUser != "" && a.SharePassword == "" && runtime.GOOS == "linux" && config.IsShare(a.SendTo) {
		if _, err := os.Stat("/etc/blackbox/share.cred"); err != nil {
			return fmt.Errorf("set BLACKBOX_SHARE_PASSWORD to the password for %s", a.ShareUser)
		}
	}
	return nil
}

// cmdConfig shows or changes settings after installation.
func cmdConfig(args []string) error {
	path := config.DefaultPath()
	if len(args) == 0 || args[0] == "show" {
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		src := path
		if cfg.Path == "" {
			src += " (not found: showing defaults)"
		}
		dir := cfg.ReportsDir()
		if cfg.ReportDir == "" {
			dir += " (default)"
		}
		fmt.Printf("Settings file:   %s\n\n", src)
		fmt.Printf("  site_name          %s\n", cfg.SiteName)
		fmt.Printf("  report_every       %s\n", cfg.ReportEvery)
		fmt.Printf("  report_at          %s   (%s)\n", cfg.ReportAt.Show(cfg.ReportEvery), cfg.ReportAt.Describe(cfg.ReportEvery))
		fmt.Printf("  report_dir         %s\n", dir)
		logs := cfg.ArchivesDir()
		if cfg.ArchiveDir == "" {
			logs += " (default)"
		}
		fmt.Printf("  archive_dir        %s   (original logs waiting for the next scheduled report)\n", logs)
		fmt.Printf("  collect_every      %s\n", config.FormatDuration(cfg.CollectEvery))
		fmt.Printf("  retention_days     %d%s\n", cfg.RetentionDays, map[bool]string{true: "   (keep forever)"}[cfg.RetentionDays == 0])
		fmt.Printf("  exclude_users      %s\n", strings.Join(cfg.ExcludeUsers, ", "))
		fmt.Printf("  exclude_processes  %s\n", strings.Join(cfg.ExcludeProcesses, ", "))
		fmt.Printf("\n  role               %s\n", cfg.Role())
		fmt.Printf("  send_to            %s\n", cfg.SendTo)
		fmt.Printf("  share_user         %s\n", cfg.ShareUser)
		fmt.Printf("  inbox              %s\n", cfg.Inbox)
		fmt.Printf("\nChange a setting:  blackbox config set <setting> <value>\n")
		return nil
	}
	if args[0] != "set" || len(args) < 2 {
		return fmt.Errorf("usage: blackbox config                     (show settings)\n       blackbox config set <setting> <value>\nsettings: collect_every, %s", strings.Join(config.Settable, ", "))
	}
	yes := false
	var rest []string
	for _, a := range args[2:] {
		if a == "--yes" || a == "-yes" {
			yes = true
		} else {
			rest = append(rest, a)
		}
	}
	key, value := strings.ToLower(args[1]), strings.Join(rest, " ")
	if err := install.RequireAdmin(); err != nil {
		return err
	}
	if err := confirmRetention(key, value, yes, install.IsTerminal(os.Stdin), os.Stdin); err != nil {
		return err
	}
	// A run that is already going would read the new setting but keep the
	// old service sandbox (and could not write the new report folder), so
	// wait for it to finish and keep new runs out until the change is done.
	if cfg, err := config.Load(path); err == nil {
		if st, err := store.Open(cfg.DataDir); err == nil {
			unlock, err := st.WaitLock(15*time.Minute, func() {
				fmt.Println("Waiting for the current collection run to finish...")
			})
			if err != nil {
				return err
			}
			defer unlock()
		}
	}
	before := config.RawValues(path)
	if key == "collect_every" {
		d, err := time.ParseDuration(value)
		if err != nil || d < 5*time.Minute {
			return fmt.Errorf("collect_every must be a duration of at least 5m, e.g. 15m or 1h")
		}
		if err := install.SetCollectEvery(path, d, printf); err != nil {
			return err
		}
		recordChanges(path, before, "blackbox config set")
		return nil
	}
	if key == "archive_dir" {
		if value == "default" || value == filepath.Join(config.DefaultDataDir(), "archives") {
			value = ""
		}
		if err := install.SetArchiveDir(path, value, printf); err != nil {
			return err
		}
		cfg, _ := config.Load(path)
		recordChanges(path, before, "blackbox config set")
		fmt.Printf("Original logs will now wait in %s until the next scheduled report. Those already waiting go into that report from where they are.\n", cfg.ArchivesDir())
		return nil
	}
	if key == "report_dir" {
		if value == "default" || value == filepath.Join(config.DefaultDataDir(), "reports") {
			value = ""
		}
		if err := install.SetReportDir(path, value, printf); err != nil {
			return err
		}
		cfg, _ := config.Load(path)
		recordChanges(path, before, "blackbox config set")
		fmt.Printf("Reports will now be saved in %s (existing reports were not moved).\n", cfg.ReportsDir())
		return nil
	}
	// "none" clears a setting that can be empty (L5).
	if strings.EqualFold(value, "none") && (key == "send_to" || key == "inbox" || key == "share_user" ||
		key == "exclude_users" || key == "exclude_processes" || key == "working_hours") {
		value = ""
	}
	if err := config.SetValue(path, key, value); err != nil {
		return err
	}
	recordChanges(path, before, "blackbox config set")
	if key == "send_to" || key == "inbox" || key == "share_user" {
		if err := install.ApplyLAN(path, printf); err != nil {
			return err
		}
	}
	fmt.Println(savedText(key, value))
	return nil
}

// recordChanges has Blackbox record the settings it just changed, in its
// spool and in the system log (A15). A setting that was refused or left
// as it was is not recorded.
func recordChanges(path string, before map[string]string, program string) {
	cfg, err := config.Load(path)
	if err != nil {
		return
	}
	for _, c := range selfaudit.Changes(before, config.RawValues(path), program) {
		if err := selfaudit.Record(cfg.DataDir, c, time.Now()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: the change to %s was saved, but recording it failed: %v\n", c.Setting, err)
		}
	}
}

// savedText confirms a setting change. Settings are read at the start of
// every run, scheduled or by hand, so a change applies from the next one.
func savedText(key, value string) string {
	const applies = "It applies from the next collection or report, including one you run now with \"blackbox report\"."
	if value == "" {
		return fmt.Sprintf("Cleared %s. %s", key, applies) // E1: not "Saved exclude_users = ."
	}
	s := fmt.Sprintf("Saved %s = %s. %s", key, value, applies)
	if key == "keep_sent_days" && strings.TrimSpace(value) == "0" {
		// CLI1: say what 0 means.
		s += " With 0, delivered batches are not kept: if the collector reports one missing, it cannot be sent again (blackbox send --resend has nothing to send)."
	}
	return s
}

// retentionFloor is a year: below it the prompt also says the period is
// short.
const retentionFloor = 365

// confirmRetention asks before any retention period is set (A9, RET1):
// retention_days deletes reports and their original logs at the next
// scheduled report. The period is the site's records schedule, not
// Blackbox's to choose, and a legal hold overrides it.
func confirmRetention(key, value string, yes, interactive bool, in io.Reader) error {
	if key != "retention_days" {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n <= 0 || yes {
		return nil // invalid values are refused by the settings check
	}
	warn := fmt.Sprintf("retention_days = %d deletes, at every scheduled report, each report whose period ended more than %d days ago, "+
		"with the original logs saved in it, for good.", n, n)
	if n < retentionFloor {
		warn += fmt.Sprintf(" That is less than a year (%d days).", retentionFloor)
	}
	warn += " Take the period from your site's records schedule (NARA General Records Schedule or your DoD component's records schedule; ask your ISSM), " +
		"not from AU-11, which leaves it to the organization. Do not set it while a legal hold, investigation or audit covers these records. " +
		"Original logs that were never put in a report are never deleted."
	if !interactive {
		return fmt.Errorf("%s\nTo do this anyway, add --yes: blackbox config set retention_days %d --yes", warn, n)
	}
	fmt.Println(warn)
	fmt.Print("Type yes to keep reports for only ", n, " days: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(strings.ToLower(line)) != "yes" {
		return fmt.Errorf("not changed")
	}
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	var c common
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	err = newApp(cfg, nil).Status(os.Stdout)
	if errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w\nBlackbox's data folder can only be read by administrators: run this from an elevated Command Prompt (Windows) or with sudo (Linux)", err)
	}
	var na *app.NeedsAttention
	if errors.As(err, &na) {
		exit(4) // the status says what; lets scripts and monitoring notice (L10)
	}
	return err
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	var c common
	c.register(fs)
	resend := fs.String("resend", "", "send kept batches again, for example 214-219 (the numbers the collector reports missing)")
	newID := fs.Bool("new-id", false, "give this computer a new sender ID (a computer cloned from another)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	logf, closeLog := openLog(cfg.DataDir)
	defer closeLog()
	if *newID {
		if err := install.RequireAdmin(); err != nil {
			return err
		}
		old, id, err := newApp(cfg, logf).NewSendID()
		if err != nil {
			return err
		}
		fmt.Printf("This computer now sends as %s (it was %s). The collector treats it as a new sender from its next delivery.\n", id, orNone(old))
		return nil
	}
	if *resend != "" {
		return resendBatches(cfg, logf, *resend)
	}
	r, err := newApp(cfg, logf).SendNow()
	if err != nil {
		return err
	}
	fmt.Printf("Sent %d batch%s to %s. Nothing is waiting.\n", r.Delivered, map[bool]string{true: "es"}[r.Delivered != 1], cfg.SendTo)
	return nil
}

// resendBatches is "blackbox send --resend 214-219" (L11). It fails when
// nothing could be sent again (L11b), so a script notices.
func resendBatches(cfg *config.Config, logf func(string, ...any), arg string) error {
	from, to, err := lan.ParseRange(arg)
	if err != nil {
		return err
	}
	r, err := newApp(cfg, logf).Resend(from, to)
	lines, rerr := resendOutcome(r, err, cfg.SendTo, cfg.KeepSentDays)
	for _, l := range lines {
		fmt.Println(l)
	}
	return rerr
}

// resendOutcome says what a resend did, and is an error when nothing was
// sent again.
func resendOutcome(r app.ResendResult, err error, sendTo string, keepDays int) ([]string, error) {
	var out []string
	if n := len(r.Sent); n > 0 {
		out = append(out, fmt.Sprintf("Sent %d batch%s again to %s. The collector imports those it is missing at its next run.", n, map[bool]string{true: "es"}[n != 1], sendTo))
	}
	if len(r.Missing) > 0 {
		out = append(out, fmt.Sprintf("Not kept on this computer: %s. Batches are kept for keep_sent_days (%d) after delivery; the events in these cannot be sent again.",
			joinSeqs(r.Missing), keepDays))
	}
	switch {
	case err != nil:
		return out, err
	case len(r.Sent) == 0 && len(r.Missing) > 0:
		return out, errors.New("nothing was sent again")
	case len(r.Sent) == 0:
		out = append(out, "Those batches have not been delivered yet; they go with the next delivery.")
	}
	return out, nil
}

func joinSeqs(s []uint64) string {
	parts := make([]string, len(s))
	for i, n := range s {
		parts[i] = strconv.FormatUint(n, 10)
	}
	return strings.Join(parts, ", ")
}

func cmdSystems(args []string) error {
	fs := flag.NewFlagSet("systems", flag.ContinueOnError)
	var c common
	c.register(fs)
	rest, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	a := newApp(cfg, nil)
	switch {
	case len(rest) == 0:
		return a.Systems(os.Stdout)
	case len(rest) == 2 && (rest[0] == "remove" || rest[0] == "forget"):
		if err := install.RequireAdmin(); err != nil {
			return err
		}
		if err := a.RemoveSystem(rest[1]); err != nil {
			return err
		}
		fmt.Printf("%s will no longer be listed or reported as silent. Its events stay in earlier reports.\nIf it sends again, it will be listed again.\n", rest[1])
		return nil
	case len(rest) == 3 && rest[0] == "rename":
		if err := install.RequireAdmin(); err != nil {
			return err
		}
		if err := a.RenameSystem(rest[1], rest[2]); err != nil {
			return err
		}
		fmt.Printf("%s is accepted as a former name of %s: data recorded under %s is shown as %s's.\n", rest[1], rest[2], rest[1], rest[2])
		return nil
	}
	return errors.New("usage: blackbox systems                  (list)\n       blackbox systems remove NAME      (stop listing a retired computer)\n       blackbox systems rename OLD NEW   (OLD is a former name of NEW)")
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// cmdInbox lists the senders' own folders in this collector's inbox, or
// makes one (SEC1).
func cmdInbox(args []string) error {
	fs := flag.NewFlagSet("inbox", flag.ContinueOnError)
	var c common
	c.register(fs)
	host := fs.String("host", "", "the computer that delivers there (default: the first one that does)")
	rest, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	a := newApp(cfg, nil)
	switch {
	case len(rest) == 0:
		return a.InboxFolders(os.Stdout)
	case len(rest) == 3 && rest[0] == "add":
		if err := install.RequireAdmin(); err != nil {
			return err
		}
		dir, err := a.AddSenderFolder(rest[1], rest[2], *host)
		if err != nil {
			return err
		}
		fmt.Printf("Made %s: only %s can write there.\nSenders from 0.23 find it themselves and deliver into it from their next run.\n", dir, rest[2])
		return nil
	}
	return errors.New("usage: blackbox inbox                                   (list the senders' folders)\n       blackbox inbox add NAME ACCOUNT [--host COMPUTER]  (a folder only ACCOUNT can write to)")
}

// cmdGaps lists batches that never arrived, or accepts a known gap (L13b).
func cmdGaps(args []string) error {
	fs := flag.NewFlagSet("gaps", flag.ContinueOnError)
	var c common
	c.register(fs)
	rest, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	a := newApp(cfg, nil)
	switch {
	case len(rest) == 0:
		return a.Gaps(os.Stdout)
	case len(rest) >= 4 && rest[0] == "accept":
		if err := install.RequireAdmin(); err != nil {
			return err
		}
		from, to, err := lan.ParseRange(rest[2])
		if err != nil {
			return err
		}
		reason := strings.Join(rest[3:], " ")
		if err := a.AcceptGap(rest[1], from, to, reason); err != nil {
			return err
		}
		fmt.Printf("Batches %d-%d from %s are accepted as not arriving: %s\nThey no longer count as missing; the next report shows who accepted them, when and why.\n", from, to, rest[1], reason)
		return nil
	}
	return errors.New("usage: blackbox gaps                                  (list)\n       blackbox gaps accept NAME FROM-TO \"why\"  (accept that those batches will not arrive)")
}

// cmdReports lists the scheduled reports this computer made and whether
// each is still in place, or accepts one gone or changed on purpose.
func cmdReports(args []string) error {
	fs := flag.NewFlagSet("reports", flag.ContinueOnError)
	var c common
	c.register(fs)
	rest, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	a := newApp(cfg, nil)
	switch {
	case len(rest) == 0:
		err := a.Reports(os.Stdout)
		var na *app.NeedsAttention
		if errors.As(err, &na) {
			exit(4) // a scheduled report is missing or changed (LEDGER1b)
		}
		return err
	case len(rest) >= 3 && rest[0] == "accept":
		if err := install.RequireAdmin(); err != nil {
			return err
		}
		reason := strings.Join(rest[2:], " ")
		if err := a.AcceptReport(rest[1], reason); err != nil {
			return err
		}
		fmt.Printf("The report %s is accepted as gone or changed: %s\nIt is no longer pointed out; the next report shows who accepted it, when and why.\n", rest[1], reason)
		return nil
	}
	return errors.New("usage: blackbox reports                        (list the scheduled reports and whether each is in place)\n       blackbox reports accept NAME \"why\"  (accept that a report is gone or changed on purpose)")
}

// cmdRun is what the scheduled task runs. Output goes to a log file in
// the data folder as well as the console.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var c common
	c.register(fs)
	noDeliver := fs.Bool("no-deliver", false, "make the data ready to send, but leave delivery to blackbox-send.service")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	logf, closeLog := openLog(cfg.DataDir)
	defer closeLog()
	a := newApp(cfg, logf)
	a.NoDeliver = *noDeliver
	logf("run started (blackbox %s)", version)
	install.RemoveOld() // programs replaced by an upgrade, once nothing runs them
	dir, err := a.Scheduled()
	if err != nil {
		logf("run failed: %v", err)
		if !errors.Is(err, store.ErrBusy) { // another run is working; not a failure
			a.RecordRun(err)
		}
		return err
	}
	a.RecordRun(nil)
	if dir != "" {
		logf("report written: %s", filepath.Join(dir, "report.html"))
	}
	logf("run finished")
	return nil
}

func cmdCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	var c common
	c.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	run, err := newApp(cfg, nil).Collect()
	if err != nil {
		return err
	}
	fmt.Print(app.Describe(run))
	return nil
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	var c common
	c.register(fs)
	var in app.Inputs
	fs.Var((*listFlag)(&in.XML), "xml", "Windows: exported event XML (wevtutil qe … /f:xml, or Event Viewer \"Save as XML\"); repeatable")
	fs.Var((*listFlag)(&in.EVTX), "evtx", "Windows: exported .evtx file (read on Windows only); repeatable")
	fs.Var((*listFlag)(&in.Audit), "audit", "Linux: auditd log (audit.log, rotated copies, .gz); repeatable")
	fs.Var((*listFlag)(&in.Syslog), "syslog", "Linux: syslog/messages/kern.log (USB), or auth.log/secure when there is no audit log; repeatable")
	fs.StringVar(&in.Host, "host", "", "Linux: host name to show, if the logs do not include it")
	fs.StringVar(&in.Passwd, "passwd", "", "Linux: copy of /etc/passwd, to show names instead of user IDs")
	out := fs.String("out", "", "output folder for reports from files (default: ./blackbox-report-<time>)")
	fs.Bool("preview", false, "no effect; kept for older scripts (a report run by hand is always a manual report)")
	fromS := fs.String("from", "", "report on a chosen period from this date (YYYY-MM-DD, or YYYY-MM-DD HH:MM), as far back as the events go")
	toS := fs.String("to", "", "with --from: end of the period (default: now; a date alone means the end of that day)")
	days := fs.Int("days", 0, "report on the last N days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := c.load()
	if err != nil {
		return err
	}
	a := newApp(cfg, printf)
	loc := time.Local
	from, to, err := reportRange(*fromS, *toS, *days, time.Now(), loc)
	if err != nil {
		return err
	}
	// Run by hand with nothing chosen: ask which period.
	if from.IsZero() && in.Empty() && *fromS == "" && *days == 0 && install.IsTerminal(os.Stdin) {
		fmt.Print("Report on which period?\n" +
			"  Enter               since the last report\n" +
			"  a number, e.g. 30   the last 30 days\n" +
			"  a date, 2026-09-01  from that date to now (add a second date to end there)\n> ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if from, to, err = parseRangeAnswer(strings.TrimSpace(line), time.Now(), loc); err != nil {
			return err
		}
	}
	var dir string
	switch {
	case !in.Empty():
		dir, err = a.ReportFromFiles(in, *out, from, to) // the period applies to files too (R9)
	case !from.IsZero():
		dir, err = a.ReportRange(from, to)
	default:
		dir, err = a.ReportNow(false)
	}
	if err != nil {
		return err
	}
	fmt.Println("Report written:", filepath.Join(dir, "report.html"))
	if in.Empty() && !from.IsZero() {
		fmt.Println("This report covers the period you chose; the schedule is unchanged.")
	} else if in.Empty() {
		if _, next, err := a.NextScheduled(); err == nil {
			fmt.Printf("This is a manual report; the schedule is unchanged. Next scheduled report: %s\n", app.NextText(next))
		}
	}
	return nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	all := fs.Bool("all", false, "also list settings that pass")
	rules := fs.Bool("audit-rules", false, "Linux: print Blackbox's recommended auditd rules file and exit")
	missing := fs.Bool("missing", false, "with --audit-rules: print only the rules this system does not already have loaded (run as root)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rules && *missing {
		text, locked, err := check.MissingRulesLive()
		if err != nil {
			return err
		}
		fmt.Print(text)
		next := "augenrules --load"
		if locked {
			next = "reboot (the loaded rules are locked with -e 2)"
		}
		how := fmt.Sprintf("blackbox check --audit-rules --missing | sudo install -m 0600 /dev/stdin %s", check.RulesFile)
		for _, f := range check.OldRulesFilesPresent() {
			how += "; sudo rm " + f // an earlier version's file: rules in both would stop auditctl
		}
		fmt.Fprintf(os.Stderr, "To install: %s, then %s.\n", how, next)
		if only := check.RulesOnlyInAuditRules(); len(only) > 0 {
			// Only the rules rules.d lacks, so nothing is loaded twice (I2).
			fmt.Fprintf(os.Stderr, "\nCAUTION: /etc/audit/audit.rules has %d rule(s) that no file in /etc/audit/rules.d holds (a tool\n"+
				"wrote audit.rules without its rules.d file). augenrules rebuilds audit.rules from rules.d, so they would\n"+
				"be dropped at the next augenrules --load or reboot. To keep them, save just these as\n"+
				"/etc/audit/rules.d/50-existing.rules (mode 0600) first:\n\n", len(only))
			for _, l := range only {
				fmt.Fprintln(os.Stderr, "  "+l)
			}
		}
		return nil
	}
	if *rules {
		// On Linux, rules for files this system doesn't have are left
		// out: auditctl refuses them, and the rest would not load.
		var exists func(string) bool
		if runtime.GOOS == "linux" {
			exists = func(p string) bool { _, err := os.Stat(p); return err == nil }
		}
		fmt.Print(check.RulesForThisSystem(check.AuditRules, exists))
		return nil
	}
	if !check.Supported {
		return errors.New("the audit settings check runs on Windows and Linux")
	}
	// The log sizes from the rate status uses, when the data folder can be
	// read (LOG1d).
	if cfg, err := config.Load(config.DefaultPath()); err == nil {
		check.Turnover = newApp(cfg, nil).CheckTurnover()
	}
	rs := check.Run()
	printChecks(rs, *all)
	if _, fail, _ := check.Summary(rs); fail > 0 {
		exit(3) // lets scripts detect non-compliance
	}
	return nil
}

func printChecks(rs []check.Result, all bool) {
	for _, l := range setup.CheckLines(rs, all) {
		fmt.Println(l)
	}
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dirs, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(dirs) == 0 {
		return errors.New("usage: blackbox verify <report folder> [more folders…]")
	}
	bad := false
	for _, dir := range dirs {
		problems, err := report.Verify(dir)
		switch {
		case err != nil:
			fmt.Printf("%s: cannot verify: %v\n", dir, err)
			bad = true
		case len(problems) > 0:
			fmt.Printf("%s: FAILED\n", dir)
			for _, p := range problems {
				fmt.Println("   ", p)
			}
			bad = true
		default:
			fmt.Printf("%s: OK — all files match the manifest\n", dir)
		}
	}
	if bad {
		exit(1)
	}
	return nil
}

// openLog appends to <data>/blackbox.log (rotated at 5 MB) and echoes to
// the console.
func openLog(dataDir string) (func(string, ...any), func()) {
	os.MkdirAll(dataDir, 0o750)
	p := filepath.Join(dataDir, "blackbox.log")
	if fi, err := os.Stat(p); err == nil && fi.Size() > 5<<20 {
		os.Rename(p, p+".1")
	}
	var w io.Writer = os.Stdout
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err == nil {
		w = io.MultiWriter(os.Stdout, f)
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(w, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	}
	return logf, func() {
		if f != nil {
			f.Close()
		}
	}
}

// reportRange reads --from, --to and --days. A zero from means no period
// was chosen.
func reportRange(fromS, toS string, days int, now time.Time, loc *time.Location) (time.Time, time.Time, error) {
	switch {
	case days < 0:
		return time.Time{}, time.Time{}, errors.New("--days must be a positive number")
	case days > 0 && fromS != "":
		return time.Time{}, time.Time{}, errors.New("use --days or --from, not both")
	case days > 0:
		return now.AddDate(0, 0, -days), now, nil
	case fromS == "":
		if toS != "" {
			return time.Time{}, time.Time{}, errors.New("--to needs --from")
		}
		return time.Time{}, time.Time{}, nil
	}
	from, _, err := parseWhen(fromS, loc)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("--from: %w", err)
	}
	to := now
	if toS != "" {
		t, dateOnly, err := parseWhen(toS, loc)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("--to: %w", err)
		}
		if dateOnly {
			t = t.AddDate(0, 0, 1) // the whole of that day
		}
		if t.After(now) {
			t = now
		}
		to = t
	}
	if !from.Before(to) {
		return time.Time{}, time.Time{}, errors.New("the period must start before it ends")
	}
	return from, to, nil
}

// parseRangeAnswer reads the answer to "Report on which period?".
func parseRangeAnswer(s string, now time.Time, loc *time.Location) (time.Time, time.Time, error) {
	if s == "" {
		return time.Time{}, time.Time{}, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return reportRange("", "", n, now, loc)
	}
	f := strings.Fields(s)
	switch len(f) {
	case 1:
		return reportRange(f[0], "", 0, now, loc)
	case 2:
		return reportRange(f[0], f[1], 0, now, loc)
	}
	return time.Time{}, time.Time{}, fmt.Errorf("could not read %q: give a number of days, a date, or two dates", s)
}

// parseWhen reads YYYY-MM-DD or YYYY-MM-DD HH:MM (or with a T) in loc.
func parseWhen(s string, loc *time.Location) (time.Time, bool, error) {
	s = strings.TrimSpace(strings.Replace(s, "T", " ", 1))
	if t, err := time.ParseInLocation("2006-01-02 15:04", s, loc); err == nil {
		return t, false, nil
	}
	t, err := time.ParseInLocation("2006-01-02", s, loc)
	if err != nil {
		return t, false, fmt.Errorf("%q is not a date like 2026-09-01 or 2026-09-01 08:00", s)
	}
	return t, true, nil
}
