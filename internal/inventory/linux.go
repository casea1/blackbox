package inventory

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Linux reads a Linux computer's inventory under root ("/" normally; a
// copy of /sys, /proc and /etc in tests). serialOf, if not nil, finds a
// drive's serial number when sysfs has none (udevadm on a live system).
func Linux(root string, serialOf func(dev string) string) *Inventory {
	inv := &Inventory{}
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	dmi := "sys/class/dmi/id/"
	inv.Manufacturer, inv.Model, inv.Serial = Clean(read(dmi+"sys_vendor")), Clean(read(dmi+"product_name")), Clean(read(dmi+"product_serial"))
	if inv.Serial == "" {
		inv.Serial = Clean(read(dmi + "chassis_serial"))
	}
	inv.BIOS = Clean(strings.TrimSpace(read(dmi+"bios_vendor") + " " + read(dmi+"bios_version")))
	for _, l := range strings.Split(read("etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			inv.OS = strings.Trim(v, `"`)
		}
	}
	for _, l := range strings.Split(read("proc/cpuinfo"), "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.TrimSpace(k) == "model name" {
			inv.CPU = strings.Join(strings.Fields(v), " ")
			break
		}
	}
	for _, l := range strings.Split(read("proc/meminfo"), "\n") {
		if v, ok := strings.CutPrefix(l, "MemTotal:"); ok {
			kb, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
			inv.Memory = kb * 1024
		}
	}
	inv.Server = !linuxDesktop(root, read)
	inv.Drives = linuxDrives(root, read, serialOf)
	inv.Accounts = linuxAccounts(read("etc/passwd"), read("etc/group"), read("etc/shadow"), int(time.Now().Unix()/86400))
	return inv
}

// linuxDesktop says whether a desktop is installed: a display manager, or
// a graphical (X11 or Wayland) session to log on to.
func linuxDesktop(root string, read func(string) string) bool {
	if read("etc/X11/default-display-manager") != "" {
		return true
	}
	for _, d := range []string{"usr/share/xsessions", "usr/share/wayland-sessions"} {
		if entries, _ := os.ReadDir(filepath.Join(root, d)); len(entries) > 0 {
			return true
		}
	}
	return false
}

func linuxDrives(root string, read func(string) string, serialOf func(string) string) []Drive {
	entries, _ := os.ReadDir(filepath.Join(root, "sys/block"))
	var out []Drive
	for _, e := range entries {
		n := e.Name()
		switch {
		case strings.HasPrefix(n, "loop"), strings.HasPrefix(n, "ram"), strings.HasPrefix(n, "zram"), strings.HasPrefix(n, "dm-"),
			strings.HasPrefix(n, "md"), strings.HasPrefix(n, "sr"), strings.HasPrefix(n, "fd"), strings.HasPrefix(n, "nbd"):
			continue
		}
		b := "sys/block/" + n + "/"
		d := Drive{Model: strings.TrimSpace(Clean(read(b+"device/vendor")) + " " + Clean(read(b+"device/model")))}
		d.Serial = Clean(read(b + "device/serial"))
		if d.Serial == "" && serialOf != nil {
			d.Serial = Clean(serialOf(n))
		}
		if s, err := strconv.ParseUint(read(b+"size"), 10, 64); err == nil {
			d.Size = s * 512
		}
		link, _ := os.Readlink(filepath.Join(root, "sys/block", n))
		switch {
		case strings.HasPrefix(n, "nvme"):
			d.Interface = "NVMe"
		case strings.Contains(link, "/usb"):
			d.Interface = "USB"
		case strings.HasPrefix(n, "vd"):
			d.Interface = "VirtIO"
		case strings.HasPrefix(n, "sd"):
			d.Interface = "SATA/SAS"
		case strings.HasPrefix(n, "mmcblk"):
			d.Interface = "MMC"
		}
		switch {
		case d.Interface == "VirtIO":
			d.Media = "Virtual"
			if d.Model == "" {
				d.Model = "VirtIO disk"
			}
		case read(b+"removable") == "1" || d.Interface == "USB":
			d.Media = "Removable"
		case read(b+"queue/rotational") == "0":
			d.Media = "SSD"
		case read(b+"queue/rotational") == "1":
			d.Media = "HDD"
		}
		out = append(out, d)
	}
	return out
}

// linuxAccounts lists root and the people's accounts (UID 1000 to 65533)
// from /etc/passwd: administrators are members of sudo, wheel or admin. An
// account is disabled when its shell refuses logons (nologin, false) or it
// has expired; a password locked in /etc/shadow (! or *) is only noted,
// as the account can still log on with a key or through sudo. Nothing
// about the password itself is kept.
func linuxAccounts(passwd, group, shadow string, today int) []Account {
	admins := map[string]bool{}
	adminGIDs := map[string]bool{}
	for _, l := range lines(group) {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		if f[0] == "sudo" || f[0] == "wheel" || f[0] == "admin" {
			adminGIDs[f[2]] = true
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					admins[m] = true
				}
			}
		}
	}
	locked, expired := map[string]bool{}, map[string]bool{}
	for _, l := range lines(shadow) {
		f := strings.Split(l, ":")
		if len(f) >= 2 && (strings.HasPrefix(f[1], "!") || strings.HasPrefix(f[1], "*")) {
			locked[f[0]] = true
		}
		if len(f) >= 8 && f[7] != "" {
			if d, err := strconv.Atoi(f[7]); err == nil && today > 0 && d <= today {
				expired[f[0]] = true
			}
		}
	}
	var out []Account
	for _, l := range lines(passwd) {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil || (uid != 0 && (uid < 1000 || uid >= 65534)) {
			continue
		}
		a := Account{Name: f[0], ID: "uid " + f[2], Enabled: true, Admin: uid == 0 || admins[f[0]] || adminGIDs[f[3]], Kind: "Local"}
		switch {
		case strings.HasSuffix(f[6], "nologin") || strings.HasSuffix(f[6], "/false"):
			a.Enabled = false
		case expired[f[0]]:
			a.Enabled, a.Note = false, "expired"
		case locked[f[0]]:
			a.Note = "password locked"
		}
		out = append(out, a)
	}
	return out
}

func lines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}
