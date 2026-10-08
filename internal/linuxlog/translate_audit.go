package linuxlog

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/casea1/blackbox/internal/event"
)

// Translator turns Linux log entries into normalized events. One
// Translator should see a host's entries in order, because USB devices are
// assembled from several kernel messages.
type Translator struct {
	Host  string // used when entries do not carry a host name
	Users Users  // uid → name, for logs not in ENRICHED format

	// AuthFromSyslog makes logons, sudo, su and account changes come from
	// auth.log/secure. Only set it when auditd is not available; otherwise
	// the same activity would be reported twice.
	AuthFromSyslog bool
	// SudoFromSyslog makes sudo commands come from auth.log or the journal
	// as well: sudo-rs (Ubuntu 26.04's sudo) writes no audit record of
	// them (O1).
	SudoFromSyslog bool
	// SSHFromSyslog makes SSH sign-ins and failed sign-ins come from
	// sshd's lines in auth.log or the journal as well. Set it with auditd:
	// Ubuntu 26.04's sshd-session writes no USER_LOGIN record of a
	// sign-in, and only sshd's own lines say how someone signed in
	// (password or key). The report merges them with the audit records of
	// the same sign-in (LNX1).
	SSHFromSyslog bool

	usb      map[string]*usbDevice // host|port → device being set up
	scsiHost map[string]string     // host|scsi host number → USB port
	recent   []recentCmd           // latest commands, to name groups usermod does not record
	groupPID map[string]string     // host|pid → group just created by useradd
	tried    []triedName           // account names in recent failed SSH password checks
	sshFails []string              // host|addr|port of recent connections with a failed SSH try
	starting map[string]startup    // host|session → login scripts running in it
	motdPIDs map[string]time.Time  // host|pid → a login message process, when seen
}

// NewTranslator returns a ready Translator.
func NewTranslator(host string, users Users) *Translator {
	if users == nil {
		users = Users{}
	}
	return &Translator{Host: host, Users: users, usb: map[string]*usbDevice{}, scsiHost: map[string]string{},
		groupPID: map[string]string{}}
}

// ---------------------------------------------------------------- auditd

// Audit translates one auditd event, or returns nil if it is routine.
func (t *Translator) Audit(ev *Event) *event.Event {
	t.learnUsers(ev)
	e := t.audit(ev)
	if e == nil {
		return nil
	}
	main := ev.Main()
	e.Time = ev.Time
	e.Host = ev.Node
	if e.Host == "" {
		e.Host = t.Host
	}
	e.OS = "linux"
	e.Source = "auditd"
	e.RecordType = main.Type
	e.RecordID = ev.Serial
	if e.Severity == "" {
		e.Severity = event.SevInfo
	}
	if e.Fields == nil {
		e.Fields = map[string]string{}
		for _, r := range ev.Records {
			for k, v := range r.Fields {
				if _, dup := e.Fields[k]; !dup && v != "" && !strings.HasPrefix(k, "_") {
					e.Fields[k] = v
				}
			}
		}
	}
	e.RedactSecrets()
	return e
}

func (t *Translator) audit(ev *Event) *event.Event {
	if avc := ev.First("AVC"); avc != nil {
		return t.avc(ev, avc)
	}
	r := ev.Main()
	switch r.Type {
	case "USER_LOGIN":
		return t.userLogin(r)
	case "USER_AUTH":
		return t.userAuth(r)
	case "USER_ACCT":
		return t.userAcct(r)
	case "USER_CMD":
		return t.userCmd(r)
	case "USER_START":
		return t.userStart(r)
	case "USER_LOGOUT":
		user := t.acct(r)
		if user == "" {
			return nil
		}
		return &event.Event{Category: event.CatLogon, Action: "logoff", User: user, Outcome: "success",
			Summary: fmt.Sprintf("%s logged off.", user), DedupeKey: "lxlogoff|" + user}
	case "USER_CHAUTHTOK":
		return t.chauthtok(r)
	case "ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "USER_MGMT", "GRP_MGMT", "CHUSER_ID", "CHGRP_ID":
		return t.accountMgmt(r)
	case "CONFIG_CHANGE":
		return t.configChange(r)
	case "DAEMON_START":
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevInfo, Action: "audit_started",
			DedupeKey: "auditd-start", Summary: "The audit service (auditd) started."}
	case "DAEMON_END":
		return t.auditdStopped(r, 2)
	case "SERVICE_STOP":
		if r.Get("unit") == "auditd" {
			return t.auditdStopped(r, 1)
		}
		return nil
	case "DAEMON_ABORT":
		return &event.Event{Category: event.CatIntegrity, Severity: event.SevHigh, Action: "audit_stopped",
			Summary: "The audit service (auditd) stopped because of an error — events after this were not recorded."}
	case "SYSTEM_BOOT":
		return &event.Event{Category: event.CatIntegrity, Action: "system_start", DedupeKey: "boot",
			Summary: "The system started."}
	case "SYSTEM_SHUTDOWN":
		return &event.Event{Category: event.CatIntegrity, Action: "system_stop",
			Summary: "The system shut down."}
	case "ANOM_PROMISCUOUS":
		if r.Get("prom") == "0" || r.Get("prom") == "" {
			return nil
		}
		by := t.actor(r)
		dev := r.Get("dev")
		e := &event.Event{Category: event.CatOther, Severity: event.SevMedium, Action: "promiscuous_mode", User: by,
			Target: dev, Summary: fmt.Sprintf("Network interface %s was put into promiscuous mode (packet capture)", dev)}
		if by != "" {
			e.Summary += " by " + by
		}
		e.Summary += "."
		return e
	case "ANOM_LOGIN_FAILURES", "RESP_ACCT_LOCK", "RESP_ACCT_LOCK_TIMED":
		acct := firstNonEmpty(t.acct(r), r.Fields["SUID"])
		if acct == "" {
			acct = t.Users.Name(r.Get("suid"))
		}
		return &event.Event{Category: event.CatFailedLogon, Severity: event.SevMedium, Action: "account_locked",
			User: acct, Target: acct, Outcome: "failure", DedupeKey: "lock|" + acct,
			Summary: fmt.Sprintf("Account %s was locked after too many failed logon attempts.", orUnknown(acct))}
	case "MAC_STATUS":
		if r.Get("enforcing") == "0" && r.Get("old_enforcing") == "1" {
			by := t.actor(r)
			return &event.Event{Category: event.CatOther, Severity: event.SevHigh, Action: "selinux_permissive", User: by,
				Summary: fmt.Sprintf("SELinux was switched from enforcing to permissive mode by %s — it no longer blocks anything.", orUnknown(by))}
		}
		return nil
	case "SYSCALL":
		return t.syscall(ev, r)
	case "USER_DEVICE":
		return usbguard(r)
	}
	return nil
}

var (
	ruleNameRE = regexp.MustCompile(`name "([^"]*)"`)
	ruleIDRE   = regexp.MustCompile(`\bid ([0-9a-fA-F]{4}:[0-9a-fA-F]{4})`)
)

// usbguard translates a USBGuard decision (it logs USER_DEVICE records with
// target=allow, block or reject). The kernel still logs a blocked device as
// connected, so the report must say it was blocked.
func usbguard(r *Record) *event.Event {
	target := strings.ToLower(r.Get("target"))
	if target != "block" && target != "reject" {
		return nil // allowed devices are reported from the kernel messages
	}
	rule := r.Get("device_rule")
	name, id := "", ""
	if m := ruleNameRE.FindStringSubmatch(rule); m != nil {
		name = m[1]
	}
	if m := ruleIDRE.FindStringSubmatch(rule); m != nil {
		id = m[1]
	}
	what := firstNonEmpty(name, id, "a USB device")
	if name != "" && id != "" {
		what = fmt.Sprintf("%s (ID %s)", name, id)
	}
	e := &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "usb_blocked", Target: what,
		DedupeKey: "usbblock|" + firstNonEmpty(id, name), Priority: 2,
		Summary: fmt.Sprintf("USBGuard blocked %s; it could not be used.", what)}
	if target == "reject" {
		e.Summary = fmt.Sprintf("USBGuard rejected %s (removed from the system); it could not be used.", what)
	}
	e.AddDetail("Decision", target)
	e.AddDetail("Device rule", rule)
	e.AddDetail("Operation", r.Get("op"))
	return e
}

// learnUsers records uid → name pairs from enriched records, so later
// entries that only carry a number (e.g. udisks "on behalf of uid 1001")
// can show a name.
func (t *Translator) learnUsers(ev *Event) {
	for _, r := range ev.Records {
		for _, p := range [][2]string{{"auid", "AUID"}, {"uid", "UID"}, {"euid", "EUID"}, {"suid", "SUID"}, {"id", "ID"}} {
			num, name := r.Fields[p[0]], r.Fields[p[1]]
			if num == "" || name == "" || name == "unset" || strings.HasPrefix(name, "unknown") {
				continue
			}
			if id, err := strconv.Atoi(num); err == nil && id >= 0 && id < 4294967295 {
				if _, known := t.Users[id]; !known {
					t.Users[id] = name
				}
			}
		}
	}
}

func (t *Translator) hostOf(r *Record) string {
	if r.Node != "" {
		return r.Node
	}
	return t.Host
}

// actor is the person behind an event: the login (audit) user ID, which
// sudo and su do not change.
func (t *Translator) actor(r *Record) string {
	if n := r.Fields["AUID"]; n != "" && n != "unset" {
		return n
	}
	return t.Users.Name(r.Get("auid"))
}

// acct is the account an authentication or account record is about.
func (t *Translator) acct(r *Record) string {
	if a := r.Get("acct"); a != "" {
		return a
	}
	if id := r.Get("id"); id != "" {
		if n := r.Fields["ID"]; n != "" && n != "unknown("+id+")" {
			return n
		}
		return t.Users.Name(id)
	}
	return ""
}

// program names a program by its file name. OpenSSH 9.8 and later split
// the server into sshd, sshd-session and sshd-auth, which record the same
// logon; they are all "sshd" here, so their records merge.
func program(exe string) string {
	switch b := base(exe); b {
	case "sshd-session", "sshd-auth":
		return "sshd"
	default:
		return b
	}
}

func base(p string) string {
	if p == "" {
		return ""
	}
	return coreutil(path.Base(p))
}

// coreutils are the GNU core utilities. Ubuntu 26.04 makes the Rust
// versions the default and keeps GNU's with a "gnu" prefix (gnurm,
// gnucp); people know them by their usual names (U12).
var coreutils = map[string]bool{
	"rm": true, "mv": true, "cp": true, "ls": true, "cat": true, "chmod": true, "chown": true, "chgrp": true, "ln": true,
	"mkdir": true, "rmdir": true, "touch": true, "dd": true, "install": true, "shred": true, "truncate": true, "tee": true,
	"date": true, "stat": true, "id": true, "whoami": true, "uname": true, "head": true, "tail": true, "sort": true,
	"cut": true, "tr": true, "wc": true, "env": true, "nohup": true, "sleep": true, "echo": true, "printf": true,
	"test": true, "readlink": true, "realpath": true, "basename": true, "dirname": true, "df": true, "du": true,
	"mktemp": true, "sync": true, "timeout": true, "stty": true, "tty": true, "who": true, "users": true, "base64": true,
	"sha256sum": true, "sha1sum": true, "md5sum": true, "split": true, "comm": true, "join": true, "paste": true,
	"od": true, "nl": true, "seq": true, "groups": true, "nproc": true, "pwd": true, "link": true, "unlink": true,
	"mknod": true, "mkfifo": true, "chroot": true, "chcon": true, "runcon": true, "csplit": true, "expand": true,
	"factor": true, "fmt": true, "fold": true, "hostid": true, "logname": true, "numfmt": true, "pathchk": true,
	"pinky": true, "pr": true, "ptx": true, "shuf": true, "stdbuf": true, "sum": true, "tac": true, "tsort": true,
	"unexpand": true, "uniq": true, "vdir": true, "dir": true, "dircolors": true, "printenv": true, "yes": true,
}

func coreutil(name string) string {
	if strings.HasPrefix(name, "gnu") && coreutils[name[3:]] {
		return name[3:]
	}
	return name
}

func orUnknown(s string) string {
	if s == "" {
		return "an unknown account"
	}
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

var avcRE = regexp.MustCompile(`avc:\s+(denied|granted)\s+\{\s*([^}]*?)\s*\}`)

func (t *Translator) avc(ev *Event, avc *Record) *event.Event {
	comm := firstNonEmpty(avc.Get("comm"), ev.Main().Get("comm"))
	name := firstNonEmpty(avc.Get("name"), avc.Get("path"))
	if aa := avc.Get("apparmor"); aa != "" {
		if aa != "DENIED" {
			return nil
		}
		main := ev.Main()
		if t.inLoginMessage(t.hostOf(avc), firstNonEmpty(avc.Get("pid"), main.Get("pid")), main.Get("ppid"), avc.Time) {
			return nil // a login message script's program (U4c)
		}
		op := avc.Get("operation")
		profile := avc.Get("profile")
		e := &event.Event{Category: event.CatOther, Severity: event.SevLow, Action: "mac_denied", Process: comm, Target: name,
			DedupeKey: "mac|" + profile + "|" + op + "|" + name,
			Summary:   fmt.Sprintf("AppArmor blocked %s from %s on %s.", orUnknownProg(comm), op, orUnknownProg(name))}
		e.AddDetail("Profile", profile)
		e.AddDetail("Requested", avc.Get("requested_mask"))
		return e
	}
	m := avcRE.FindStringSubmatch(avc.Fields["_raw"])
	if m == nil || m[1] != "denied" {
		return nil
	}
	perms := m[2]
	class := avc.Get("tclass")
	e := &event.Event{Category: event.CatOther, Severity: event.SevLow, Action: "mac_denied", Process: comm, Target: name,
		DedupeKey: "mac|" + comm + "|" + perms + "|" + name}
	if avc.Get("permissive") == "1" {
		e.Summary = fmt.Sprintf("SELinux would have blocked %s from %s on %s %s (permissive mode, so it was allowed).", orUnknownProg(comm), perms, class, orUnknownProg(name))
	} else {
		e.Summary = fmt.Sprintf("SELinux blocked %s from %s on %s %s.", orUnknownProg(comm), perms, class, orUnknownProg(name))
	}
	e.AddDetail("Process context", avc.Get("scontext"))
	e.AddDetail("Target context", avc.Get("tcontext"))
	return e
}

func orUnknownProg(s string) string {
	if s == "" {
		return "an unknown program"
	}
	return s
}

// The translations by kind of record are in translate_*.go: logon,
// commands, account, config (the audit system itself), syscall and files.
