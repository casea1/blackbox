package linuxlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/casea1/blackbox/internal/event"
	"github.com/casea1/blackbox/internal/store"
)

var ny, _ = time.LoadLocation("America/New_York")

func TestParseRecord(t *testing.T) {
	line := `type=USER_LOGIN msg=audit(1790604001.040:1100): pid=5000 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=login acct=28696E76616C6964207573657229 exe="/usr/sbin/sshd" hostname=? addr=10.1.1.99 terminal=ssh res=failed'` + "\x1d" + `UID="root" AUID="unset"`
	r, err := ParseRecord(line)
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "USER_LOGIN" || r.Serial != 1100 || r.Time.Unix() != 1790604001 {
		t.Errorf("header parsed wrong: %+v", r)
	}
	want := map[string]string{"acct": "(invalid user)", "exe": "/usr/sbin/sshd", "addr": "10.1.1.99", "res": "failed", "UID": "root", "pid": "5000"}
	for k, v := range want {
		if r.Fields[k] != v {
			t.Errorf("%s = %q, want %q", k, r.Fields[k], v)
		}
	}
	if r.Get("auid") != "" || r.Get("hostname") != "" {
		t.Error("unset/? values should read as empty")
	}
	// Numeric fields and SYSCALL registers that look like hex are not decoded.
	r2, _ := ParseRecord(`type=SYSCALL msg=audit(1.000:2): arch=c000003e syscall=59 a0=55d2 a2=80 items=2 auid=1002 key="execpriv"`)
	if r2.Fields["a2"] != "80" || r2.Fields["syscall"] != "59" {
		t.Errorf("numbers were decoded: %v", r2.Fields)
	}
	r3, _ := ParseRecord(`type=PROCTITLE msg=audit(1.000:2): proctitle=6D6F6470726F626500776972656775617264`)
	if r3.Fields["proctitle"] != "modprobe wireguard" {
		t.Errorf("proctitle = %q", r3.Fields["proctitle"])
	}
	if _, err := ParseRecord("not an audit line"); err == nil {
		t.Error("expected error for non-audit line")
	}
}

func TestAssemblerGroupsBySerial(t *testing.T) {
	lines := []string{
		`type=SYSCALL msg=audit(1.000:7): syscall=257 auid=1002 key="identity"`,
		`type=USER_LOGIN msg=audit(1.001:8): pid=1 msg='op=login acct="x" res=success'`,
		`type=PATH msg=audit(1.000:7): item=0 name="/etc/passwd" nametype=NORMAL`,
		`type=EOE msg=audit(1.000:7): `,
	}
	var got []*Event
	_, err := ParseAuditStream(strings.NewReader(strings.Join(lines, "\n")), func(e *Event) error { got = append(got, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Serial != 8 || got[1].Serial != 7 || len(got[1].Records) != 2 {
		t.Fatalf("grouping wrong: %d events", len(got))
	}
}

func translateSample(t *testing.T) []*event.Event {
	t.Helper()
	tr := NewTranslator("ubu-ws12", nil)
	f, err := os.Open("../../testdata/linux/ubuntu-audit.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []*event.Event
	if _, err := ParseAuditStream(f, func(e *Event) error {
		if x := tr.Audit(e); x != nil {
			out = append(out, x)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := &LineParser{Loc: ny, Ref: time.Date(2026, 9, 30, 0, 0, 0, 0, ny)}
	if err := ReadAll("../../testdata/linux/ubuntu-syslog", func(s string) error {
		if l, ok := p.Parse(s); ok {
			if x := tr.Syslog(l, "syslog"); x != nil {
				out = append(out, x)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTranslateUbuntuSample(t *testing.T) {
	evs := translateSample(t)
	find := func(substr string) *event.Event {
		for _, e := range evs {
			if strings.Contains(e.Summary, substr) {
				return e
			}
		}
		return nil
	}
	cases := []struct {
		substr string
		cat    event.Category
		sev    event.Severity
	}{
		{"jsmith logged on at the graphical console.", event.CatLogon, event.SevInfo},
		{"admin_jd logged on via SSH from 10.1.1.20.", event.CatLogon, event.SevInfo},
		{"Failed logon for root via SSH from 10.1.1.99", event.CatFailedLogon, event.SevLow},
		{"Failed logon for (unknown user name) via SSH from 10.1.1.99 — the user name does not exist.", event.CatFailedLogon, event.SevLow},
		{"Failed logon for mjones at the text console — wrong password.", event.CatFailedLogon, event.SevLow},
		{"Account mjones was locked", event.CatFailedLogon, event.SevMedium},
		{"admin_jd ran with sudo: useradd -m tempuser", event.CatPrivileged, event.SevLow},
		{"admin_jd created the user account tempuser.", event.CatAccount, event.SevMedium},
		{"admin_jd added tempuser to the privileged group sudo.", event.CatAccount, event.SevHigh},
		{"admin_jd changed the sudo rules: /etc/sudoers.d/tempuser (using tee).", event.CatPrivileged, event.SevHigh},
		{"admin_jd opened a root shell with sudo", event.CatPrivileged, event.SevLow},
		{"admin_jd edited /etc/passwd directly (using vim.basic)", event.CatAccount, event.SevHigh},
		{"admin_jd loaded a kernel module: modprobe wireguard", event.CatOther, event.SevMedium},
		{"admin_jd changed the system time (using date)", event.CatIntegrity, event.SevMedium},
		{"eth0 was put into promiscuous mode (packet capture) by admin_jd.", event.CatOther, event.SevMedium},
		{"used sudo to run a command that can stop or weaken auditing: systemctl stop auditd", event.CatPrivileged, event.SevHigh},
		{"The audit service (auditd) was stopped by admin_jd", event.CatIntegrity, event.SevHigh},
		{"admin_jd removed an audit rule (identity)", event.CatIntegrity, event.SevHigh},
		{"jsmith ran the privileged program passwd.", event.CatPrivileged, event.SevLow},
		{"jsmith changed their own password.", event.CatAccount, event.SevLow},
		{"jsmith failed to switch to root with su — wrong password.", event.CatFailedLogon, event.SevLow},
		{"jsmith tried to run a command with sudo but was not permitted: apt install nmap", event.CatPrivileged, event.SevMedium},
		{"AppArmor blocked cupsd from open on /etc/shadow.", event.CatOther, event.SevLow},
		{"USB storage connected: SanDisk Cruzer Blade (serial 4C530001231109115405), 15.6 GB.", event.CatRemovable, event.SevMedium},
		{"USB storage connected: Kingston DataTraveler 3.0 (serial E0D55EA573DCF450E97C0A7F), 30.9 GB.", event.CatRemovable, event.SevMedium},
		{"jsmith opened removable storage: /dev/sdb1 was mounted at /media/jsmith/CRUZER.", event.CatRemovable, event.SevMedium},
		{"USB storage disconnected: SanDisk Cruzer Blade", event.CatRemovable, event.SevInfo},
		{"A USB network adapter was connected: Google Pixel 7 (usb0, driver rndis_host)", event.CatRemovable, event.SevHigh},
	}
	for _, c := range cases {
		e := find(c.substr)
		if e == nil {
			t.Errorf("missing event %q", c.substr)
			continue
		}
		if e.Category != c.cat || e.Severity != c.sev {
			t.Errorf("%q: got %s/%s, want %s/%s", c.substr, e.Category, e.Severity, c.cat, c.sev)
		}
		if e.Host != "ubu-ws12" || e.OS != "linux" || e.Time.IsZero() {
			t.Errorf("%q: host/os/time missing: %s %s %v", c.substr, e.Host, e.OS, e.Time)
		}
	}
	// Routine activity must not be reported.
	for _, e := range evs {
		for _, bad := range []string{"cron", "tcpdump -i", "Logitech", "add_rule", "SERVICE_START"} {
			if strings.Contains(e.Summary, bad) {
				t.Errorf("routine activity reported: %s", e.Summary)
			}
		}
	}
	if e := find("jsmith opened removable storage"); e != nil && e.User != "jsmith" {
		t.Errorf("udisks uid not resolved to a name: %q", e.User)
	}
}

func TestSyslogFormats(t *testing.T) {
	p := &LineParser{Loc: ny, Ref: time.Date(2026, 1, 5, 12, 0, 0, 0, ny)}
	cases := []struct {
		line, host, prog, msg string
		want                  time.Time
	}{
		{"Dec 31 23:59:58 ws1 sshd[42]: Accepted publickey for bob from 10.0.0.5 port 22 ssh2", "ws1", "sshd", "Accepted publickey for bob from 10.0.0.5 port 22 ssh2",
			time.Date(2025, 12, 31, 23, 59, 58, 0, ny)}, // previous year: December read in January
		{"2026-01-05T08:30:01.123456-05:00 ubu24 kernel: usb 1-2: Product: Cruzer Blade", "ubu24", "kernel", "usb 1-2: Product: Cruzer Blade",
			time.Date(2026, 1, 5, 8, 30, 1, 123456000, ny)},
		{"2026-01-05T08:30:01-0500 alma8 udisksd[912]: Mounted /dev/sdb1 at /run/media/bob/X on behalf of uid 1000", "alma8", "udisksd", "Mounted /dev/sdb1 at /run/media/bob/X on behalf of uid 1000",
			time.Date(2026, 1, 5, 8, 30, 1, 0, ny)},
		{"Jan  5 08:30:01 ws1 kernel: [ 1926.123456] usb 1-2: USB disconnect, device number 5", "ws1", "kernel", "usb 1-2: USB disconnect, device number 5",
			time.Date(2026, 1, 5, 8, 30, 1, 0, ny)},
	}
	for _, c := range cases {
		l, ok := p.Parse(c.line)
		if !ok {
			t.Errorf("not parsed: %s", c.line)
			continue
		}
		if l.Host != c.host || l.Prog != c.prog || l.Msg != c.msg || !l.Time.Equal(c.want) {
			t.Errorf("%s\n got %+v (time %v)", c.line, l, l.Time)
		}
	}
}

// Without auditd, logons, sudo, su and account changes come from
// auth.log (Ubuntu) or secure (Alma).
func TestAuthLogFallback(t *testing.T) {
	lines := []string{
		"Sep 28 10:02:01 ubu sshd[5001]: Failed password for root from 10.1.1.99 port 50122 ssh2",
		"Sep 28 10:03:02 ubu sshd[5100]: Failed password for invalid user bob from 10.1.1.99 port 50130 ssh2",
		"Sep 28 09:15:30 ubu sshd[2900]: Accepted password for admin_jd from 10.1.1.20 port 51000 ssh2",
		"Sep 28 13:01:40 ubu sudo: admin_jd : TTY=pts/1 ; PWD=/home/admin_jd ; USER=root ; COMMAND=/usr/sbin/useradd -m tempuser",
		"Sep 28 13:40:00 ubu sudo: admin_jd : TTY=pts/1 ; PWD=/home/admin_jd ; USER=root ; COMMAND=/usr/bin/systemctl stop auditd",
		"Sep 28 14:21:40 ubu sudo:   jsmith : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/apt install nmap",
		"Sep 28 14:22:00 ubu sudo:   jsmith : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/jsmith ; USER=root ; COMMAND=/usr/bin/ls",
		"Sep 28 13:01:41 ubu useradd[3002]: new user: name=tempuser, UID=1005, GID=1005, home=/home/tempuser, shell=/bin/sh, from=/dev/pts/1",
		"Sep 28 13:02:05 ubu usermod[3010]: add 'tempuser' to group 'sudo'",
		"Sep 28 13:02:05 ubu usermod[3010]: add 'tempuser' to shadow group 'sudo'",
		"Sep 28 14:25:00 ubu su: pam_unix(su-l:session): session opened for user root(uid=0) by jsmith(uid=1001)",
		"Sep 28 14:20:03 alma su[6200]: FAILED SU (to root) jsmith on pts/2",
		"Sep 28 11:15:41 ubu login[5200]: pam_faillock(login:auth): Consecutive login failures for user mjones account temporarily locked",
		"Sep 28 08:02:11 ubu gdm-password]: pam_unix(gdm-password:session): session opened for user jsmith(uid=1001) by (uid=0)",
	}
	tr := NewTranslator("ubu", nil)
	tr.AuthFromSyslog = true
	p := &LineParser{Loc: ny, Ref: time.Date(2026, 9, 30, 0, 0, 0, 0, ny)}
	var got []string
	for _, s := range lines {
		l, ok := p.Parse(s)
		if !ok {
			t.Fatalf("not parsed: %s", s)
		}
		if e := tr.Syslog(l, "auth.log"); e != nil {
			got = append(got, string(e.Severity)+"|"+e.Summary)
		}
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{
		"low|Failed logon for root via SSH from 10.1.1.99 — wrong password.",
		"low|Failed logon for bob via SSH from 10.1.1.99 — the user name does not exist.",
		"info|admin_jd logged on via SSH from 10.1.1.20.",
		"low|admin_jd ran with sudo: /usr/sbin/useradd -m tempuser",
		"high|admin_jd used sudo to run a command that can stop or weaken auditing: /usr/bin/systemctl stop auditd",
		"medium|jsmith tried to run a command with sudo but was not permitted: /usr/bin/apt install nmap",
		"low|jsmith entered a wrong password for sudo (3 incorrect password attempts).",
		"medium|The user account tempuser was created.",
		"high|An administrator added tempuser to the privileged group sudo.",
		"low|jsmith switched to root with su.",
		"low|jsmith failed to switch to root with su — wrong password.",
		"medium|Account mjones was locked after too many failed logon attempts.",
		"info|jsmith logged on at the graphical console.",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q\ngot:\n%s", want, all)
		}
	}
	// Without the fallback flag (auditd present) auth lines are ignored.
	tr2 := NewTranslator("ubu", nil)
	l, _ := p.Parse(lines[0])
	if tr2.Syslog(l, "auth.log") != nil {
		t.Error("auth.log line translated although auditd is the source")
	}
}

func TestFollowRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	write := func(name, s string) {
		f, _ := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		f.WriteString(s)
		f.Close()
	}
	collect := func(bm store.Bookmark) ([]string, FollowResult) {
		var got []string
		res, err := Follow(p, bm, func(s string) error { got = append(got, s); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return got, res
	}
	write(p, "a\nb\npartial")
	got, res := collect(store.Bookmark{})
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("first read = %v (a partial last line must wait)", got)
	}
	write(p, "-done\nc\n")
	got, res = collect(res.Bookmark)
	if strings.Join(got, ",") != "partial-done,c" {
		t.Fatalf("second read = %v", got)
	}
	// Rotate: audit.log → audit.log.1, new lines in both.
	write(p, "d\n")
	os.Rename(p, p+".1")
	write(p, "e\n")
	got, res = collect(res.Bookmark)
	if strings.Join(got, ",") != "d,e" {
		t.Fatalf("after rotation = %v", got)
	}
	// Truncate in place.
	os.WriteFile(p, []byte("f\n"), 0o600)
	got, res2 := collect(res.Bookmark)
	if strings.Join(got, ",") != "f" || !res2.Reset {
		t.Fatalf("after truncation = %v reset=%v", got, res2.Reset)
	}
	// Rotated away and gone (compressed): gap reported, new file read.
	os.Remove(p + ".1")
	os.Rename(p, p+".1.gz")
	write(p, "g\n")
	got, res3 := collect(res2.Bookmark)
	if strings.Join(got, ",") != "g" || res3.Gap == nil {
		t.Fatalf("after lost rotation = %v gap=%v", got, res3.Gap)
	}
}

// Records copied from a real Ubuntu 24.04 system (the linux-live CI job):
// usermod writes "adding user to group" as USER_CHAUTHTOK, unquoted and
// without the group name, which comes from the sudo command before it.
func TestUbuntu2404AccountRecords(t *testing.T) {
	lines := []string{
		`type=ADD_GROUP msg=audit(1790729792.469:253): pid=3711 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=adding group acct="bbtestuser" exe="/usr/sbin/useradd" hostname=? addr=? terminal=? res=success'` + "\x1d" + `UID="root" AUID="unset"`,
		`type=ADD_USER msg=audit(1790729792.471:254): pid=3711 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=adding user id=1002 exe="/usr/sbin/useradd" hostname=? addr=? terminal=? res=success'` + "\x1d" + `UID="root" AUID="unset" ID="unknown(1002)"`,
		`type=ADD_USER msg=audit(1790729792.482:259): pid=3711 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=adding home directory id=1002 exe="/usr/sbin/useradd" hostname=? addr=? terminal=? res=success'` + "\x1d" + `UID="root" AUID="unset" ID="bbtestuser"`,
		`type=USER_CMD msg=audit(1790729891.290:268): pid=3736 uid=1001 auid=4294967295 ses=4294967295 subj=unconfined msg='cwd="/home/runner" cmd=757365726D6F64202D6147207375646F2062627465737475736572 exe="/usr/bin/sudo" terminal=? res=success'` + "\x1d" + `UID="runner" AUID="unset"`,
		`type=USER_CHAUTHTOK msg=audit(1790729891.298:271): pid=3737 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=adding user to group acct="bbtestuser" exe="/usr/sbin/usermod" hostname=? addr=? terminal=? res=success'` + "\x1d" + `UID="root" AUID="unset"`,
		`type=USER_CHAUTHTOK msg=audit(1790729891.298:272): pid=3737 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=adding user to shadow group acct="bbtestuser" exe="/usr/sbin/usermod" hostname=? addr=? terminal=? res=success'` + "\x1d" + `UID="root" AUID="unset"`,
		`type=USER_CHAUTHTOK msg=audit(1790729990.000:280): pid=3800 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:chauthtok grantors=pam_unix acct="bbtestuser" exe="/usr/bin/passwd" hostname=? addr=? terminal=? res=success'` + "\x1d" + `UID="root" AUID="unset"`,
	}
	tr := NewTranslator("runnervm", nil)
	var got []string
	ParseAuditStream(strings.NewReader(strings.Join(lines, "\n")), func(ev *Event) error {
		if e := tr.Audit(ev); e != nil {
			got = append(got, e.Summary)
		}
		return nil
	})
	want := []string{
		"An administrator created the group bbtestuser.",
		"An administrator created the user account bbtestuser.",
		"runner ran with sudo: usermod -aG sudo bbtestuser",
		"An administrator added bbtestuser to the privileged group sudo.",
		"An administrator added bbtestuser to the privileged group sudo.", // shadow group; merged by the report
		"The password of bbtestuser was changed.",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	r, _ := ParseRecord(lines[4])
	if r.Fields["op"] != "adding user to group" || r.Fields["acct"] != "bbtestuser" {
		t.Errorf("unquoted multi-word op parsed as %q", r.Fields["op"])
	}
}

func TestGroupsFromCommand(t *testing.T) {
	cases := map[string]string{
		"usermod -aG sudo bob":                "sudo",
		"usermod -a -G sudo,adm bob":          "sudo,adm",
		"usermod --append --groups=wheel bob": "wheel",
		"gpasswd -a bob sudo":                 "sudo",
		"adduser bob sudo":                    "sudo",
		"usermod -aG sudo alice":              "",
		"useradd -m bob":                      "",
	}
	for cmd, want := range cases {
		if got := strings.Join(groupsFromCommand(cmd, "bob"), ","); got != want {
			t.Errorf("groupsFromCommand(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// On a STIG-hardened system the audit rules watch /var/log/sudo.log,
// wtmp and lastlog, which sudo and logins write on every use. Only
// deleting, renaming or emptying a log file is tampering.
func TestLogTamperingIsOnlyDestructiveChanges(t *testing.T) {
	rec := func(serial int, syscall, a1, a2, comm, exe, file, key string) []string {
		head := fmt.Sprintf("type=SYSCALL msg=audit(1790730000.%03d:%d): arch=c000003e syscall=%s success=yes exit=3 a0=ffffff9c a1=%s a2=%s a3=1b6 items=1 ppid=1 pid=%d auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm=%q exe=%q subj=unconfined key=%q",
			serial, serial, syscall, a1, a2, 4000+serial, comm, exe, key)
		return []string{head,
			fmt.Sprintf(`type=PATH msg=audit(1790730000.%03d:%d): item=0 name=%q inode=12 dev=08:01 mode=0100600 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL`, serial, serial, file),
			fmt.Sprintf(`type=EOE msg=audit(1790730000.%03d:%d):`, serial, serial)}
	}
	var lines []string
	lines = append(lines, rec(1, "257", "7ffd0000", "441", "sudo", "/usr/bin/sudo", "/var/log/sudo.log", "maintenance")...) // append: routine
	lines = append(lines, rec(2, "257", "7ffd0000", "401", "sshd", "/usr/sbin/sshd", "/var/log/wtmp", "logins")...)         // write: routine
	lines = append(lines, rec(3, "257", "7ffd0000", "241", "bash", "/usr/bin/bash", "/var/log/auth.log", "")...)            // "> auth.log": emptied
	lines = append(lines, rec(4, "263", "7ffd0000", "0", "rm", "/usr/bin/rm", "/var/log/syslog.1", "delete")...)            // deleted
	tr := NewTranslator("ws12", Users{1001: "jsmith"})
	var tampered []string
	ParseAuditStream(strings.NewReader(strings.Join(lines, "\n")), func(ev *Event) error {
		if e := tr.Audit(ev); e != nil && e.Action == "log_tampered" {
			tampered = append(tampered, e.Target)
		}
		return nil
	})
	if strings.Join(tampered, ",") != "/var/log/auth.log,/var/log/syslog.1" {
		t.Errorf("log tampering reported for %v; want only the emptied and the deleted file", tampered)
	}
}

// xrdp logons are remote: they must not look like someone at the console
// (the report names the console user when a USB device is connected).
func TestXrdpIsRemoteDesktop(t *testing.T) {
	if _, label := session("/usr/sbin/xrdp-sesman", "?"); label != "Remote Desktop" {
		t.Errorf("xrdp session labelled %q", label)
	}
	if _, label := session("/usr/libexec/gdm-session-worker", "/dev/tty2"); label != "Graphical console" {
		t.Errorf("gdm session labelled %q", label)
	}
	if _, label := consoleSession("xrdp-sesman"); label != "Remote Desktop" {
		t.Errorf("xrdp syslog session labelled %q", label)
	}
}

func TestUSBGuardBlock(t *testing.T) {
	line := `type=USER_DEVICE msg=audit(1790731000.000:400): pid=812 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=changed-authorization-state-for device="/devices/pci0000:00/0000:00:14.0/usb1/1-2" target=block device_rule="block id 0781:5567 serial \"4C530001231109115405\" name \"Cruzer Blade\" via-port \"1-2\" with-interface 08:06:50" exe="/usr/sbin/usbguard-daemon" hostname=? addr=? terminal=? res=success'`
	tr := NewTranslator("ws12", nil)
	var got []string
	ParseAuditStream(strings.NewReader(line+"\n"), func(ev *Event) error {
		if e := tr.Audit(ev); e != nil {
			got = append(got, e.Action+": "+e.Summary)
		}
		return nil
	})
	if len(got) != 1 || !strings.Contains(got[0], "usb_blocked: USBGuard blocked Cruzer Blade (ID 0781:5567)") {
		t.Errorf("got %v", got)
	}
}

// D1: failed logons for different accounts from one address are kept
// apart, so "one source tried several accounts" can see them.
func TestFailedLogonsKeepTheAccount(t *testing.T) {
	var lines []string
	for i, acct := range []string{"root", "admin", "oracle"} {
		lines = append(lines, fmt.Sprintf(`type=USER_AUTH msg=audit(1790730000.%03d:%d): pid=5000 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication grantors=? acct="%s" exe="/usr/sbin/sshd" hostname=10.1.1.99 addr=10.1.1.99 terminal=ssh res=failed'`, i, 10+i, acct))
	}
	tr := NewTranslator("ws12", nil)
	keys := map[string]bool{}
	ParseAuditStream(strings.NewReader(strings.Join(lines, "\n")), func(ev *Event) error {
		if e := tr.Audit(ev); e != nil && e.Action == "logon_failed" {
			keys[e.DedupeKey] = true
		}
		return nil
	})
	if len(keys) != 3 {
		t.Errorf("want 3 separate failed logons, got merge keys %v", keys)
	}
}

// Review item: two sudo commands of the same program are two rows, so
// "systemctl stop rsyslog" is not hidden behind "systemctl status cron";
// a command's own record and its program's still merge.
func TestSudoCommandsKeepTheirArguments(t *testing.T) {
	if cmdKey("/usr/bin/systemctl stop rsyslog") != cmdKey("systemctl stop rsyslog") {
		t.Error("the sudo record and the program it ran should merge")
	}
	if cmdKey("systemctl stop rsyslog") == cmdKey("systemctl status cron") {
		t.Error("different systemctl commands merged")
	}
	var lines []string
	for i, cmd := range []string{"systemctl status cron", "systemctl stop rsyslog"} {
		lines = append(lines, fmt.Sprintf(`type=USER_CMD msg=audit(1790730000.%03d:%d): pid=600%d uid=1001 auid=1001 ses=3 msg='cwd="/home/jsmith" cmd="%s" exe="/usr/bin/sudo" terminal=pts/0 res=success'`, i, 20+i, i, cmd))
	}
	tr := NewTranslator("ws12", Users{1001: "jsmith"})
	keys := map[string]bool{}
	ParseAuditStream(strings.NewReader(strings.Join(lines, "\n")), func(ev *Event) error {
		if e := tr.Audit(ev); e != nil && e.DedupeKey != "" {
			keys[e.DedupeKey] = true
		}
		return nil
	})
	if len(keys) != 2 {
		t.Errorf("want 2 commands kept apart, got %v", keys)
	}
}

// LNX1: with auditd, only sshd's sign-in lines are read from auth.log (the
// rest is in the audit log). A connection closed while signing in is a
// failed try only when no "Failed" line came for it.
func TestSSHFromSyslog(t *testing.T) {
	lines := []string{
		"2026-10-05T11:33:20.098765+00:00 ubu sshd-session[12301]: Accepted publickey for claude from 192.168.1.11 port 50522 ssh2: ED25519 SHA256:Xq3vJ1bH0wq8m5yQm1r7S0e2Fq6kTzv9yP4uLr2aB8c",
		"2026-10-05T11:33:20.131902+00:00 ubu sshd-session[12301]: pam_unix(sshd:session): session opened for user claude(uid=1000) by claude(uid=0)",
		"2026-10-05T11:34:00.000000+00:00 ubu sudo:   claude : TTY=pts/0 ; PWD=/home/claude ; USER=root ; COMMAND=/usr/bin/id",
		"2026-10-05T11:37:02.511873+00:00 ubu sshd-session[12380]: Failed password for claude from 192.168.1.23 port 41000 ssh2",
		"2026-10-05T11:37:03.102559+00:00 ubu sshd-session[12380]: Connection closed by authenticating user claude 192.168.1.23 port 41000 [preauth]",
		"2026-10-05T11:38:00.214736+00:00 ubu sshd-session[12390]: Connection closed by authenticating user claude 192.168.1.23 port 41012 [preauth]",
		"2026-10-05T11:38:30.000000+00:00 ubu sshd-session[12395]: Failed publickey for invalid user bob from 192.168.1.23 port 41020 ssh2: RSA SHA256:abc",
	}
	tr := NewTranslator("ubu", nil)
	tr.SSHFromSyslog = true
	p := &LineParser{Loc: time.UTC, Ref: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)}
	var got []string
	for _, s := range lines {
		l, ok := p.Parse(s)
		if !ok {
			t.Fatalf("not parsed: %s", s)
		}
		if e := tr.Syslog(l, "auth.log"); e != nil {
			got = append(got, e.Summary)
		}
	}
	want := []string{
		"claude logged on via SSH from 192.168.1.11.",
		"Failed logon for claude via SSH from 192.168.1.23 — wrong password.",
		"Failed logon for claude via SSH from 192.168.1.23 — no key or password was accepted before the connection closed.",
		"Failed logon for bob via SSH from 192.168.1.23 — the user name does not exist.",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
