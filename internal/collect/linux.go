package collect

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/linuxlog"
	"github.com/casea1/blackbox/internal/store"
)

// Default Linux log locations. The first one that exists is used.
var (
	AuditLog    = "/var/log/audit/audit.log"
	SystemLogs  = []string{"/var/log/syslog", "/var/log/messages"} // Ubuntu, Alma
	AuthLogs    = []string{"/var/log/auth.log", "/var/log/secure"} // Ubuntu, Alma
	PasswdFile  = "/etc/passwd"
	journalName = "systemd journal"
)

func firstExisting(paths []string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// Linux collects from the live Linux logs.
func Linux(st *store.Store, opt Options) (*store.Run, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	start := opt.Now()
	host := LocalHost()
	tr := linuxlog.NewTranslator(host, linuxlog.LoadUsers(PasswdFile))
	parser := &linuxlog.LineParser{Loc: time.Local, Ref: start}
	run := &store.Run{Time: start, Host: host, OS: runtime.GOOS, Version: opt.Version}

	haveAudit := false
	if fi, err := os.Stat(AuditLog); err == nil && !fi.IsDir() {
		haveAudit = true
		run.Channels = append(run.Channels, followAudit(st, tr, host, start, opt))
		status, statusErr := exec.Command("auditctl", "-s").Output()
		run.Channels = append(run.Channels, kernelLost(st, host, status, statusErr))
		active, _ := exec.Command("systemctl", "is-active", "auditd").Output()
		run.AuditOff = AuditOffText(string(status), statusErr, string(active))
	} else {
		run.Channels = append(run.Channels, store.ChannelRun{Channel: AuditLog,
			Unavailable: "auditd is not installed or not logging — logons, sudo and account changes are read from the authentication log instead"})
	}
	tr.AuthFromSyslog = !haveAudit
	tr.SudoFromSyslog = haveAudit && SudoRs()

	sys := firstExisting(SystemLogs)
	if sys == "" {
		// No syslog files (e.g. minimal Ubuntu 24.04): read the journal,
		// which holds kernel, udisks and authentication messages.
		run.Channels = append(run.Channels, followJournal(st, tr, parser, host, start, opt))
	} else {
		run.Channels = append(run.Channels, followSyslog(st, tr, parser, host, sys, start, opt))
		if !haveAudit || tr.SudoFromSyslog {
			if auth := firstExisting(AuthLogs); auth != "" {
				run.Channels = append(run.Channels, followSyslog(st, tr, parser, host, auth, start, opt))
			}
		}
	}
	run.Duration = opt.Now().Sub(start).Seconds()
	st.State.LastCollect = start
	if err := st.AppendRun(run); err != nil {
		return run, err
	}
	return run, st.Save()
}

// batcher appends events to the spool in chunks and moves the bookmark
// only after they are safely written.
type batcher struct {
	st    *store.Store
	now   time.Time
	key   string
	batch []*event.Event
	cr    *store.ChannelRun
}

func (b *batcher) add(e *event.Event) error {
	e.Collected = b.now
	b.batch = append(b.batch, e)
	b.cr.Kept++
	if len(b.batch) >= flushEvery {
		return b.flush(nil)
	}
	return nil
}

func (b *batcher) flush(bm *store.Bookmark) error {
	if err := b.st.AppendEvents(b.now, b.batch); err != nil {
		return err
	}
	b.batch = b.batch[:0]
	if bm != nil {
		b.st.State.Bookmarks[b.key] = *bm
		return b.st.Save()
	}
	return nil
}

func followAudit(st *store.Store, tr *linuxlog.Translator, host string, now time.Time, opt Options) store.ChannelRun {
	cr := store.ChannelRun{Channel: AuditLog, TypeCounts: map[string]int{}}
	key := store.BookmarkKey(host, AuditLog)
	bm := st.State.Bookmarks[key]
	b := &batcher{st: st, now: now, key: key, cr: &cr}
	var last time.Time
	asm := linuxlog.NewAssembler(func(ev *linuxlog.Event) error {
		last = ev.Time
		if cr.FirstTime.IsZero() || ev.Time.Before(cr.FirstTime) {
			cr.FirstTime = ev.Time
		}
		if e := tr.Audit(ev); e != nil {
			return b.add(e)
		}
		return nil
	})
	res, err := linuxlog.Follow(AuditLog, bm, func(line string) error {
		rec, perr := linuxlog.ParseRecord(line)
		if perr != nil {
			return nil
		}
		cr.Read++
		cr.TypeCounts[rec.Type]++
		return asm.Add(rec)
	})
	if ferr := asm.Flush(); ferr != nil && err == nil {
		err = ferr
	}
	finishChannel(&cr, b, res, bm, last, err, opt)
	return cr
}

func followSyslog(st *store.Store, tr *linuxlog.Translator, p *linuxlog.LineParser, host, path string, now time.Time, opt Options) store.ChannelRun {
	cr := store.ChannelRun{Channel: path, TypeCounts: map[string]int{}}
	key := store.BookmarkKey(host, path)
	bm := st.State.Bookmarks[key]
	b := &batcher{st: st, now: now, key: key, cr: &cr}
	var last time.Time
	source := filepath.Base(path)
	res, err := linuxlog.Follow(path, bm, func(s string) error {
		l, ok := p.Parse(s)
		if !ok {
			return nil
		}
		cr.Read++
		cr.TypeCounts[progName(l.Prog)]++
		last = l.Time
		if cr.FirstTime.IsZero() || l.Time.Before(cr.FirstTime) {
			cr.FirstTime = l.Time
		}
		if e := tr.Syslog(l, source); e != nil {
			return b.add(e)
		}
		return nil
	})
	finishChannel(&cr, b, res, bm, last, err, opt)
	return cr
}

func finishChannel(cr *store.ChannelRun, b *batcher, res linuxlog.FollowResult, prev store.Bookmark, last time.Time, err error, opt Options) {
	next := res.Bookmark
	next.Time = prev.Time
	if !last.IsZero() {
		next.Time = last
	}
	if err == nil || next.Inode != 0 {
		if ferr := b.flush(&next); ferr != nil && err == nil {
			err = ferr
		}
	}
	if res.Gap != nil {
		res.Gap.To = firstTime(last, prev.Time)
		cr.Gap = res.Gap
		opt.Logf("%s: %s", cr.Channel, res.Gap.Note)
	}
	cr.Reset = res.Reset
	if err != nil {
		cr.Error = err.Error()
		opt.Logf("%s: %v", cr.Channel, err)
	}
	opt.Logf("%s: read %d lines, kept %d events", cr.Channel, cr.Read, cr.Kept)
}

func firstTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

func followJournal(st *store.Store, tr *linuxlog.Translator, p *linuxlog.LineParser, host string, now time.Time, opt Options) store.ChannelRun {
	cr := store.ChannelRun{Channel: journalName, TypeCounts: map[string]int{}}
	key := store.BookmarkKey(host, journalName)
	bm := st.State.Bookmarks[key]
	b := &batcher{st: st, now: now, key: key, cr: &cr}
	var last time.Time
	cursor, err := linuxlog.ReadJournal(bm.Cursor, func(s string) error {
		l, ok := p.Parse(s)
		if !ok {
			return nil
		}
		cr.Read++
		cr.TypeCounts[progName(l.Prog)]++
		last = l.Time
		if cr.FirstTime.IsZero() || l.Time.Before(cr.FirstTime) {
			cr.FirstTime = l.Time
		}
		if e := tr.Syslog(l, "journal"); e != nil {
			return b.add(e)
		}
		return nil
	})
	next := store.Bookmark{Cursor: cursor, Time: firstTime(last, bm.Time)}
	if ferr := b.flush(&next); ferr != nil && err == nil {
		err = ferr
	}
	if err != nil {
		cr.Error = err.Error()
	}
	return cr
}

func progName(p string) string {
	if p == "" {
		return "(no program name)"
	}
	return p
}

var lostRE = regexp.MustCompile(`(?m)^lost (\d+)`)

// kernelLost records audit records the kernel dropped because its backlog
// was full (reported by `auditctl -s`). They never reach the log file, so
// this is the only way to know they are missing.
func kernelLost(st *store.Store, host string, out []byte, err error) store.ChannelRun {
	cr := store.ChannelRun{Channel: "kernel audit backlog"}
	if err != nil {
		cr.Unavailable = "could not run auditctl -s"
		return cr
	}
	m := lostRE.FindSubmatch(out)
	if m == nil {
		return cr
	}
	lost, _ := strconv.ParseUint(string(m[1]), 10, 64)
	key := store.BookmarkKey(host, cr.Channel)
	prev := st.State.Bookmarks[key]
	if lost > prev.RecordID && prev.Time.After(time.Time{}) {
		cr.Gap = &store.Gap{Lost: lost - prev.RecordID, From: prev.Time, To: time.Now(),
			Note: fmt.Sprintf("the kernel dropped %d audit records because its audit backlog was full (raise backlog_limit with auditctl -b)", lost-prev.RecordID)}
	}
	st.State.Bookmarks[key] = store.Bookmark{RecordID: lost, Time: time.Now()}
	return cr
}

// SudoRs reports whether sudo is sudo-rs, which records no audit events
// of the commands it runs.
func SudoRs() bool {
	if p, err := filepath.EvalSymlinks("/usr/bin/sudo"); err == nil && strings.Contains(p, "sudo-rs") {
		return true
	}
	out, _ := exec.Command("sudo", "-V").Output()
	return strings.Contains(strings.ToLower(string(out)), "sudo-rs")
}

var enabledRE = regexp.MustCompile(`(?m)^enabled (\d+)`)

// AuditOffText says why auditing isn't running, from `auditctl -s` and
// `systemctl is-active auditd`, or "" when it is (or it can't be told).
func AuditOffText(status string, statusErr error, active string) string {
	var why []string
	if statusErr == nil {
		if m := enabledRE.FindStringSubmatch(status); m != nil && m[1] == "0" {
			why = append(why, "kernel auditing is off (auditctl -s shows enabled 0)")
		}
	}
	switch a := strings.TrimSpace(active); a {
	case "inactive", "failed", "deactivating":
		why = append(why, "the audit service (auditd) is not running (systemctl is-active auditd: "+a+")")
	}
	return strings.Join(why, "; ")
}

// LinuxFiles translates exported Linux logs for a one-off report. Audit
// logs are read first so user names learned from them apply to the other
// logs. Authentication messages in the syslog files are used only when no
// audit log is given.
func LinuxFiles(auditFiles, syslogFiles []string, host, passwd string, now time.Time) ([]*event.Event, *store.Run, error) {
	users := linuxlog.Users{}
	if passwd != "" {
		users = linuxlog.LoadUsers(passwd)
	}
	parser := &linuxlog.LineParser{Loc: time.Local, Ref: now}
	if host == "" {
		host = hostFromSyslog(syslogFiles, parser)
	}
	tr := linuxlog.NewTranslator(host, users)
	tr.AuthFromSyslog = len(auditFiles) == 0
	var events []*event.Event
	run := &store.Run{Time: now, Host: host}
	for _, f := range auditFiles {
		cr := store.ChannelRun{Channel: filepath.Base(f), TypeCounts: map[string]int{}}
		asm := linuxlog.NewAssembler(func(ev *linuxlog.Event) error {
			if e := tr.Audit(ev); e != nil {
				e.Collected = now
				events = append(events, e)
				cr.Kept++
			}
			return nil
		})
		err := linuxlog.ReadAll(f, func(line string) error {
			rec, perr := linuxlog.ParseRecord(line)
			if perr != nil {
				return nil
			}
			cr.Read++
			cr.TypeCounts[rec.Type]++
			return asm.Add(rec)
		})
		if err == nil {
			err = asm.Flush()
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		run.Channels = append(run.Channels, cr)
	}
	for _, f := range syslogFiles {
		cr := store.ChannelRun{Channel: filepath.Base(f), TypeCounts: map[string]int{}}
		err := linuxlog.ReadAll(f, func(s string) error {
			l, ok := parser.Parse(s)
			if !ok {
				return nil
			}
			cr.Read++
			cr.TypeCounts[progName(l.Prog)]++
			if e := tr.Syslog(l, filepath.Base(f)); e != nil {
				e.Collected = now
				events = append(events, e)
				cr.Kept++
			}
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		run.Channels = append(run.Channels, cr)
	}
	return events, run, nil
}

func hostFromSyslog(files []string, p *linuxlog.LineParser) string {
	for _, f := range files {
		host := ""
		errStop := fmt.Errorf("stop")
		linuxlog.ReadAll(f, func(s string) error {
			if l, ok := p.Parse(s); ok && l.Host != "" {
				host = l.Host
				return errStop
			}
			return nil
		})
		if host != "" {
			return host
		}
	}
	return ""
}
