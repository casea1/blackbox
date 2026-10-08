package linuxlog

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/casea1/blackbox/internal/event"
)

// usbDevice collects what the kernel says about a USB device across
// several messages.
type usbDevice struct {
	port, vendorID, productID     string
	manufacturer, product, serial string
	storage                       bool
	disk, capacity                string
	announced                     bool
	netDriver, netIface           string
}

func (d *usbDevice) name() string {
	n := strings.TrimSpace(d.manufacturer + " " + d.product)
	if strings.HasPrefix(strings.ToLower(d.product), strings.ToLower(d.manufacturer)) && d.manufacturer != "" {
		n = d.product // "SanDisk" + "SanDisk Ultra" → "SanDisk Ultra"
	}
	if n == "" && d.vendorID != "" {
		n = "USB device " + d.vendorID + ":" + d.productID
	}
	if n == "" {
		n = "unnamed USB device"
	}
	return n
}

func (d *usbDevice) key() string {
	if d.serial != "" {
		return strings.ToLower(d.serial)
	}
	return strings.ToLower(d.vendorID + ":" + d.productID + ":" + d.product)
}

var (
	usbNewRE      = regexp.MustCompile(`^usb (\S+): new \S+ USB device number \d+`)
	usbFoundRE    = regexp.MustCompile(`^usb (\S+): New USB device found, idVendor=(\w+), idProduct=(\w+)`)
	usbStringRE   = regexp.MustCompile(`^usb (\S+): (Product|Manufacturer|SerialNumber): (.*)$`)
	usbStorageRE  = regexp.MustCompile(`^usb-storage (\d+-[\d.]+):[\d.]+: USB Mass Storage device detected`)
	uasRE         = regexp.MustCompile(`^scsi host(\d+): (?:usb-storage|uas) (\d+-[\d.]+):`)
	sdSizeRE      = regexp.MustCompile(`^sd (\d+):\d+:\d+:\d+: \[(\w+)\] \d+ \d+-byte logical blocks: \(([^/)]+)`)
	sdAttachRE    = regexp.MustCompile(`^sd (\d+):\d+:\d+:\d+: \[(\w+)\] Attached SCSI removable disk`)
	usbGoneRE     = regexp.MustCompile(`^usb (\S+): USB disconnect, device number \d+`)
	usbNetRE      = regexp.MustCompile(`^(rndis_host|cdc_ether|cdc_ncm|cdc_mbim|r8152|ax88179_178a|asix|qmi_wwan|rtl8xxxu|rtl8192cu|mt7601u|ath9k_htc|rt2800usb|mt76x0u|mt76x2u|rtw88_\w+|8821cu|88x2bu) (\d+-[\d.]+):[\d.]+ (\S+?):`)
	udisksMountRE = regexp.MustCompile(`^Mounted (/dev/\S+) at (.+?) on behalf of uid (\d+)`)
	udisksUmntRE  = regexp.MustCompile(`^Unmounted (/dev/\S+) on behalf of uid (\d+)`)
)

// Syslog translates one syslog line. source is the file or log it came
// from (e.g. "syslog", "auth.log", "journal"). Most lines return nothing;
// a USB device is reported once the kernel has finished setting it up.
func (t *Translator) Syslog(l Line, source string) *event.Event {
	var e *event.Event
	switch {
	case l.Prog == "kernel":
		e = t.kernel(l)
	case l.Prog == "udisksd" || l.Prog == "udisks2":
		e = t.udisks(l)
	case l.Prog == "blackbox":
		// Blackbox's own record of a change to itself, also in its spool
		// (A15); the two merge.
		if c, ok := event.ParseSelfChange(l.Msg); ok {
			e = c.Event()
		}
	case t.AuthFromSyslog:
		e = t.auth(l)
	case t.SSHFromSyslog && isSSHD(l.Prog):
		e = t.sshd(l)
	case t.SudoFromSyslog && (l.Prog == "sudo" || l.Prog == "sudo-rs"):
		e = t.auth(l)
	}
	if e == nil {
		return nil
	}
	e.Time = l.Time
	e.Host = l.Host
	if e.Host == "" {
		e.Host = t.Host
	}
	e.OS = "linux"
	e.Source = source
	e.RecordType = l.Prog
	if e.Severity == "" {
		e.Severity = event.SevInfo
	}
	if e.Fields == nil {
		e.Fields = map[string]string{"message": l.Msg}
	}
	e.RedactSecrets()
	return e
}

func (t *Translator) dev(host, port string) *usbDevice {
	k := host + "|" + port
	d := t.usb[k]
	if d == nil {
		d = &usbDevice{port: port}
		t.usb[k] = d
	}
	return d
}

func (t *Translator) kernel(l Line) *event.Event {
	m := l.Msg
	if x := usbNewRE.FindStringSubmatch(m); x != nil {
		t.usb[l.Host+"|"+x[1]] = &usbDevice{port: x[1]} // new device on this port
		return nil
	}
	if x := usbFoundRE.FindStringSubmatch(m); x != nil {
		d := t.dev(l.Host, x[1])
		d.vendorID, d.productID = x[2], x[3]
		return nil
	}
	if x := usbStringRE.FindStringSubmatch(m); x != nil {
		d := t.dev(l.Host, x[1])
		v := strings.TrimSpace(x[3])
		switch x[2] {
		case "Product":
			d.product = v
		case "Manufacturer":
			d.manufacturer = v
		case "SerialNumber":
			d.serial = v
		}
		return nil
	}
	if x := usbStorageRE.FindStringSubmatch(m); x != nil {
		t.dev(l.Host, x[1]).storage = true
		return nil
	}
	if x := uasRE.FindStringSubmatch(m); x != nil {
		t.scsiHost[l.Host+"|"+x[1]] = x[2]
		t.dev(l.Host, x[2]).storage = true
		return nil
	}
	if x := sdSizeRE.FindStringSubmatch(m); x != nil {
		if port, ok := t.scsiHost[l.Host+"|"+x[1]]; ok {
			d := t.dev(l.Host, port)
			d.disk, d.capacity = x[2], strings.TrimSpace(x[3])
		}
		return nil
	}
	if x := sdAttachRE.FindStringSubmatch(m); x != nil {
		port, ok := t.scsiHost[l.Host+"|"+x[1]]
		if !ok {
			return nil
		}
		d := t.dev(l.Host, port)
		d.disk = x[2]
		return t.usbConnected(d)
	}
	if x := usbNetRE.FindStringSubmatch(m); x != nil {
		d := t.dev(l.Host, x[2])
		if d.netDriver != "" {
			return nil
		}
		d.netDriver, d.netIface = x[1], x[3]
		e := &event.Event{Category: event.CatRemovable, Severity: event.SevHigh, Action: "usb_network_adapter",
			Target: d.name(), DedupeKey: "usbnet|" + d.key(),
			Summary: fmt.Sprintf("A USB network adapter was connected: %s (%s, driver %s) — this can bridge the system to another network (for example a phone's USB tethering or a Wi-Fi adapter).", d.name(), d.netIface, d.netDriver)}
		t.deviceDetails(e, d)
		return e
	}
	if x := usbGoneRE.FindStringSubmatch(m); x != nil {
		k := l.Host + "|" + x[1]
		d := t.usb[k]
		delete(t.usb, k)
		if d == nil || !d.storage {
			return nil
		}
		e := &event.Event{Category: event.CatRemovable, Action: "usb_disconnected", Target: d.name(),
			DedupeKey: "usboff|" + d.key(),
			Summary:   fmt.Sprintf("USB storage disconnected: %s%s.", d.name(), serialSuffix(d.serial))}
		t.deviceDetails(e, d)
		return e
	}
	return nil
}

func serialSuffix(s string) string {
	if s == "" {
		return ""
	}
	return " (serial " + s + ")"
}

func (t *Translator) usbConnected(d *usbDevice) *event.Event {
	if d.announced {
		return nil
	}
	d.announced = true
	e := &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "usb_connected",
		Target: d.name(), DedupeKey: "usb|" + d.key(), Priority: 3}
	e.Summary = fmt.Sprintf("USB storage connected: %s%s", d.name(), serialSuffix(d.serial))
	if d.capacity != "" {
		e.Summary += ", " + d.capacity
	}
	e.Summary += "."
	t.deviceDetails(e, d)
	return e
}

func (t *Translator) deviceDetails(e *event.Event, d *usbDevice) {
	e.AddDetail("Manufacturer", d.manufacturer)
	e.AddDetail("Product", d.product)
	e.AddDetail("Serial number", d.serial)
	if d.vendorID != "" {
		e.AddDetail("USB ID", d.vendorID+":"+d.productID)
	}
	e.AddDetail("Capacity", d.capacity)
	if d.disk != "" {
		e.AddDetail("Disk", "/dev/"+d.disk)
	}
	e.AddDetail("Network interface", d.netIface)
	e.AddDetail("USB port", d.port)
}

func (t *Translator) udisks(l Line) *event.Event {
	if x := udisksMountRE.FindStringSubmatch(l.Msg); x != nil {
		user := t.Users.Name(x[3])
		e := &event.Event{Category: event.CatRemovable, Severity: event.SevMedium, Action: "removable_mounted",
			User: user, Target: x[2],
			Summary: fmt.Sprintf("%s opened removable storage: %s was mounted at %s.", orUnknown(user), x[1], x[2])}
		e.AddDetail("Device", x[1])
		e.AddDetail("Mounted at", x[2])
		return e
	}
	if x := udisksUmntRE.FindStringSubmatch(l.Msg); x != nil {
		user := t.Users.Name(x[2])
		return &event.Event{Category: event.CatRemovable, Action: "removable_unmounted", User: user, Target: x[1],
			Summary: fmt.Sprintf("%s unmounted %s.", orUnknown(user), x[1])}
	}
	return nil
}

// ---------------------------------------------------------------- auth.log / secure (no auditd)

var (
	sshFailRE     = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)`)
	sshOkRE       = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+(?: ssh2)?(?:: (\S+) (\S+))?`)
	sshClosedRE   = regexp.MustCompile(`^(?:Connection closed by|Disconnected from) authenticating user (\S+) (\S+) port (\d+)`)
	sessCloseRE   = regexp.MustCompile(`^pam_unix\((sshd|login|gdm-password|lightdm|sddm):session\): session closed for user (\S+)`)
	sessOpenRE    = regexp.MustCompile(`^pam_unix\((login|gdm-password|lightdm|sddm):session\): session opened for user ([^\s(]+)`)
	consoleFailRE = regexp.MustCompile(`^pam_unix\((login|gdm-password|lightdm|sddm):auth\): authentication failure;.*\buser=(\S+)`)
	sudoRE        = regexp.MustCompile(`^\s*(\S+) : (.*?)\s*;?\s*(?:TTY=(\S+) ; )?PWD=(.*?) ; USER=(\S+) ;(?: COMMAND=(.*))?$`)
	suOpenRE      = regexp.MustCompile(`^pam_unix\(su(?:-l)?:session\): session opened for user ([^\s(]+)(?:\(uid=\d+\))? by ([^\s(]*)`)
	suFailRE      = regexp.MustCompile(`^pam_unix\(su(?:-l)?:auth\): authentication failure;.*\bruser=(\S*).*\buser=(\S+)`)
	suFailAlmaRE  = regexp.MustCompile(`^FAILED SU \(to (\S+)\) (\S+) on`)
	faillockRE    = regexp.MustCompile(`Consecutive login failures for user (\S+) account temporarily locked`)
	newUserRE     = regexp.MustCompile(`^new user: name=([^,]+),`)
	newGroupRE    = regexp.MustCompile(`^new group: name=([^,]+),`)
	delUserRE     = regexp.MustCompile(`^delete user '([^']+)'`)
	addGroupRE    = regexp.MustCompile(`^add '([^']+)' to (?:shadow )?group '([^']+)'`)
	gpasswdAddRE  = regexp.MustCompile(`^user (\S+) added by (\S+) to group (\S+)`)
	delGroupMemRE = regexp.MustCompile(`^delete '([^']+)' from (?:shadow )?group '([^']+)'`)
	pwChangedRE   = regexp.MustCompile(`^pam_unix\(passwd:chauthtok\): password changed for (\S+)`)
)

func (t *Translator) auth(l Line) *event.Event {
	m := l.Msg
	switch l.Prog {
	case "sshd", "sshd-session", "sshd-auth":
		if e := t.sshd(l); e != nil {
			return e
		}
	case "sudo", "sudo-rs":
		if x := sudoRE.FindStringSubmatch(m); x != nil {
			user, note, runas, cmd := x[1], x[2], x[5], x[6]
			as := "with sudo"
			if runas != "root" {
				as = "as " + runas + " with sudo"
			}
			// Merges with the root command the audit log records for it.
			e := &event.Event{Category: event.CatPrivileged, User: user, Target: runas, Command: cmd,
				DedupeKey: "cmd|" + user + "|" + cmdKey(cmd), Priority: 2}
			switch {
			case strings.Contains(note, "incorrect password"):
				e.Category, e.Action, e.Severity, e.Outcome = event.CatFailedLogon, "logon_failed", event.SevLow, "failure"
				e.Target = user
				e.Summary = fmt.Sprintf("%s entered a wrong password for sudo (%s).", user, strings.TrimSpace(note))
			case strings.Contains(note, "NOT in sudoers") || strings.Contains(note, "not allowed"):
				e.Action, e.Severity, e.Outcome = "sudo_denied", event.SevMedium, "failure"
				e.Summary = fmt.Sprintf("%s tried to run a command %s but was not permitted: %s", user, as, cmd)
			case tampers(cmd):
				e.Action, e.Severity = "audit_tamper_command", event.SevHigh
				e.Summary = fmt.Sprintf("%s used sudo to run a command that can stop or weaken auditing: %s", user, cmd)
			case blackboxChange(e, cmd, user):
			default:
				e.Action, e.Severity = "sudo_command", event.SevLow
				e.Summary = fmt.Sprintf("%s ran %s: %s", user, as, cmd)
			}
			e.AddDetail("Command", cmd)
			e.AddDetail("Runs as", runas)
			e.AddDetail("Working directory", x[4])
			e.AddDetail("Terminal", x[3])
			return e
		}
	case "su", "su-l":
		if x := suOpenRE.FindStringSubmatch(m); x != nil {
			return &event.Event{Category: event.CatPrivileged, Severity: event.SevLow, Action: "switch_user", User: x[2], Target: x[1],
				Summary: fmt.Sprintf("%s switched to %s with su.", orUnknown(x[2]), x[1])}
		}
		if x := suFailRE.FindStringSubmatch(m); x != nil {
			return &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed", User: x[1], Target: x[2],
				Outcome: "failure", DedupeKey: "sufail|" + x[1], Priority: 2,
				Summary: fmt.Sprintf("%s failed to switch to %s with su — wrong password.", orUnknown(x[1]), x[2])}
		}
		if x := suFailAlmaRE.FindStringSubmatch(m); x != nil {
			return &event.Event{Category: event.CatFailedLogon, Severity: event.SevLow, Action: "logon_failed", User: x[2], Target: x[1],
				Outcome: "failure", DedupeKey: "sufail|" + x[2], Priority: 1,
				Summary: fmt.Sprintf("%s failed to switch to %s with su — wrong password.", x[2], x[1])}
		}
	case "useradd", "adduser":
		if x := newUserRE.FindStringSubmatch(m); x != nil {
			return &event.Event{Category: event.CatAccount, Severity: event.SevMedium, Action: "account_created", Target: x[1],
				Summary: fmt.Sprintf("The user account %s was created.", x[1])}
		}
	case "groupadd", "addgroup":
		if x := newGroupRE.FindStringSubmatch(m); x != nil {
			return &event.Event{Category: event.CatAccount, Severity: event.SevLow, Action: "group_created", Target: x[1],
				Summary: fmt.Sprintf("The group %s was created.", x[1])}
		}
	case "userdel", "deluser":
		if x := delUserRE.FindStringSubmatch(m); x != nil {
			return &event.Event{Category: event.CatAccount, Severity: event.SevMedium, Action: "account_deleted", Target: x[1],
				Summary: fmt.Sprintf("The user account %s was deleted.", x[1])}
		}
	case "passwd":
		if x := pwChangedRE.FindStringSubmatch(m); x != nil {
			return &event.Event{Category: event.CatAccount, Severity: event.SevLow, Action: "password_change", Target: x[1],
				Summary: fmt.Sprintf("The password of %s was changed.", x[1])}
		}
	}
	if x := addGroupRE.FindStringSubmatch(m); x != nil {
		return groupAdd("", x[1], x[2])
	}
	if x := gpasswdAddRE.FindStringSubmatch(m); x != nil {
		return groupAdd(x[2], x[1], x[3])
	}
	if x := delGroupMemRE.FindStringSubmatch(m); x != nil {
		return &event.Event{Category: event.CatAccount, Severity: event.SevMedium, Action: "group_member_removed", Target: x[1],
			DedupeKey: "grp|del|" + x[1] + "|" + x[2], Summary: fmt.Sprintf("%s was removed from the group %s.", x[1], x[2])}
	}
	if x := faillockRE.FindStringSubmatch(m); x != nil {
		return &event.Event{Category: event.CatFailedLogon, Severity: event.SevMedium, Action: "account_locked", User: x[1], Target: x[1],
			Outcome: "failure", DedupeKey: "lock|" + x[1],
			Summary: fmt.Sprintf("Account %s was locked after too many failed logon attempts.", x[1])}
	}
	if x := consoleFailRE.FindStringSubmatch(m); x != nil {
		how, label := consoleSession(x[1])
		return t.failedLogon(x[2], how, label, "", x[1], x[1], "wrong password", 1)
	}
	if x := sessOpenRE.FindStringSubmatch(m); x != nil {
		how, label := consoleSession(x[1])
		e := &event.Event{Category: event.CatLogon, Action: "logon", User: x[2], Outcome: "success", Interactive: true,
			Summary: fmt.Sprintf("%s logged on %s.", x[2], how), DedupeKey: logonKey(x[2], "")}
		e.AddDetail("Logon type", label)
		return e
	}
	if x := sessCloseRE.FindStringSubmatch(m); x != nil {
		return &event.Event{Category: event.CatLogon, Action: "logoff", User: x[2], Outcome: "success",
			Summary: fmt.Sprintf("%s logged off.", x[2]), DedupeKey: "lxlogoff|" + x[2]}
	}
	return nil
}

func isSSHD(prog string) bool {
	return prog == "sshd" || prog == "sshd-session" || prog == "sshd-auth"
}

// sshd translates sshd's sign-in lines: "Accepted", "Failed", and a
// connection closed while signing in with no "Failed" line before it,
// which is how a refused key shows at sshd's usual log level.
func (t *Translator) sshd(l Line) *event.Event {
	m := l.Msg
	if x := sshFailRE.FindStringSubmatch(m); x != nil {
		acct, reason := x[3], "wrong password"
		if x[2] != "" {
			reason = "the user name does not exist"
		} else if x[1] == "publickey" {
			reason = "key not accepted"
		}
		addr := cleanAddr(x[4])
		t.sshFailed(l.Host + "|" + addr + "|" + x[5])
		e := t.failedLogon(acct, "via SSH", "SSH", addr, "ssh", "sshd", reason, 2)
		e.AddDetail("Authentication", x[1])
		return e
	}
	if x := sshClosedRE.FindStringSubmatch(m); x != nil {
		addr := cleanAddr(x[2])
		if !t.sshFailed(l.Host + "|" + addr + "|" + x[3]) {
			return nil // the failed tries of this connection are already rows
		}
		return t.failedLogon(x[1], "via SSH", "SSH", addr, "ssh", "sshd",
			"no key or password was accepted before the connection closed", 1)
	}
	if x := sshOkRE.FindStringSubmatch(m); x != nil {
		addr := cleanAddr(x[3])
		e := logon(x[2], "via SSH", "SSH", addr, "", "")
		e.AddDetail("Authentication", x[1])
		if x[4] != "" {
			e.AddDetail("Key", x[4]+" "+x[5])
		}
		return e
	}
	return nil
}

// sshFailed notes a failed SSH try on a connection (host|addr|port) and
// reports whether it is the connection's first.
func (t *Translator) sshFailed(conn string) bool {
	if slices.Contains(t.sshFails, conn) {
		return false
	}
	t.sshFails = append(t.sshFails, conn)
	if len(t.sshFails) > 64 {
		t.sshFails = t.sshFails[len(t.sshFails)-64:]
	}
	return true
}

// logonKey merges the records of one sign-in: the same line read from two
// logs, or the two audit records some systems write for one login.
func logonKey(user, addr string) string { return "lxlogon|" + user + "|" + addr }

func consoleSession(service string) (string, string) {
	if strings.Contains(service, "xrdp") {
		return "via Remote Desktop (RDP)", "Remote Desktop"
	}
	if service == "login" {
		return "at the text console", "Text console"
	}
	return "at the graphical console", "Graphical console"
}

func groupAdd(by, member, group string) *event.Event {
	who := "An administrator"
	if by != "" {
		who = by
	}
	e := &event.Event{Category: event.CatAccount, Severity: event.SevMedium, Action: "group_member_added", User: by, Target: member,
		DedupeKey: "grp|add|" + member + "|" + group,
		Summary:   fmt.Sprintf("%s added %s to the group %s.", who, member, group)}
	if privilegedGroups[group] {
		e.Severity = event.SevHigh
		e.Summary = fmt.Sprintf("%s added %s to the privileged group %s.", who, member, group)
	}
	return e
}
