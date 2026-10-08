package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSIDTail(t *testing.T) {
	for in, want := range map[string]string{
		"S-1-5-21-3623811015-3361044348-30300820-1001": "…1001",
		"S-1-5-21-3623811015-3361044348-30300820-500":  "…500",
		"S-1-5-21-1-2-3-1104231":                       "…4231",
		"":                                             "",
	} {
		if got := SIDTail(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// What WindowsQuery prints on a domain-joined Windows 11 PC: local accounts
// with their SIDs reduced to four digits, a domain user's profile, drives
// with their type from Get-PhysicalDisk.
func TestParseWindows(t *testing.T) {
	out := `{"Manufacturer":"Dell Inc.","Model":"OptiPlex 7090","Serial":"7XK2PQ3","BIOS":"2.18.0","OS":"Microsoft Windows 11 Enterprise 10.0.26100","CPU":"11th Gen Intel(R) Core(TM) i7-11700   @ 2.50GHz","Memory":17179869184,"Domain":"corp.example.mil",
"Drives":[{"Index":1,"Model":"WD Elements 25A3 USB Device","Serial":"5758413144","Size":2000365289472,"Interface":"USB","Media":"Removable Media"},{"Index":0,"Model":"Samsung SSD 980 PRO 1TB","Serial":"S5GXNX0T123456A","Size":1000202273280,"Interface":"SCSI","Media":"Fixed hard disk media"}],
"Media":{"0":"SSD","1":"Unspecified"},
"Accounts":[{"Name":"Administrator","SID":"S-1-5-21-111-222-333-500","Enabled":false,"Admin":true,"LastLogon":""},{"Name":"localadmin","SID":"S-1-5-21-111-222-333-1001","Enabled":true,"Admin":true,"LastLogon":"2026-10-04T13:05:22.0000000Z"}],
"Profiles":[{"Name":"CORP\\jsmith","SID":"S-1-5-21-999-888-777-23105","Admin":false,"LastUse":"2026-10-05T08:01:00.1234567Z"},{"Name":"","SID":"S-1-5-21-111-222-333-1001","Admin":true,"LastUse":""},{"Name":"NT SERVICE\\x","SID":"S-1-5-80-1","Admin":false,"LastUse":""}]}`
	inv, err := ParseWindows([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if inv.Manufacturer != "Dell Inc." || inv.Model != "OptiPlex 7090" || inv.Serial != "7XK2PQ3" || inv.CPU != "11th Gen Intel(R) Core(TM) i7-11700 @ 2.50GHz" || inv.Memory != 16<<30 || inv.Domain != "corp.example.mil" {
		t.Errorf("system: %+v", inv)
	}
	if len(inv.Drives) != 2 || inv.Drives[0].Media != "Removable" || inv.Drives[1].Media != "SSD" || inv.Drives[1].Serial != "S5GXNX0T123456A" {
		t.Errorf("drives: %+v", inv.Drives)
	}
	want := []Account{
		{Name: "Administrator", ID: "…500", Enabled: false, Admin: true, Kind: "Local"},
		{Name: "localadmin", ID: "…1001", Enabled: true, Admin: true, Kind: "Local", LastLogon: time.Date(2026, 10, 4, 13, 5, 22, 0, time.UTC)},
		{Name: `CORP\jsmith`, ID: "…3105", Enabled: true, Kind: "Domain (profile)", LastLogon: time.Date(2026, 10, 5, 8, 1, 0, 123456700, time.UTC)},
	}
	if len(inv.Accounts) != len(want) {
		t.Fatalf("accounts: %+v", inv.Accounts)
	}
	for i := range want {
		if inv.Accounts[i] != want[i] {
			t.Errorf("account %d: %+v, want %+v", i, inv.Accounts[i], want[i])
		}
	}
	if strings.Contains(out, "S-1-5-21-111-222-333-1001") && strings.Contains(strings.Join(flat(inv), " "), "S-1-5-21") {
		t.Error("a whole SID was kept")
	}
}

func flat(inv *Inventory) []string {
	var s []string
	for _, a := range inv.Accounts {
		s = append(s, a.Name, a.ID)
	}
	return s
}

// Linux: DMI, the drives in /sys/block (loop and device-mapper left out),
// and root and the people's accounts, locked ones as disabled.
func TestLinux(t *testing.T) {
	root := t.TempDir()
	put := func(p, s string) {
		f := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(f), 0o755)
		os.WriteFile(f, []byte(s), 0o644)
	}
	put("sys/class/dmi/id/sys_vendor", "LENOVO\n")
	put("sys/class/dmi/id/product_name", "20XW00GJUS\n")
	put("sys/class/dmi/id/product_serial", "PF3ABCDE\n")
	put("etc/os-release", "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n")
	put("proc/cpuinfo", "processor\t: 0\nmodel name\t: Intel(R) Core(TM) i5-1145G7 @ 2.60GHz\n")
	put("proc/meminfo", "MemTotal:       16303488 kB\n")
	put("sys/block/nvme0n1/device/model", "SAMSUNG MZVL2512HCJQ\n")
	put("sys/block/nvme0n1/device/serial", "S64KNX0R700001\n")
	put("sys/block/nvme0n1/size", "1000215216\n")
	put("sys/block/nvme0n1/queue/rotational", "0\n")
	put("sys/block/sda/device/vendor", "ATA\n")
	put("sys/block/sda/device/model", "ST2000DM008\n")
	put("sys/block/sda/size", "3907029168\n")
	put("sys/block/sda/queue/rotational", "1\n")
	put("sys/block/loop0/size", "100\n")
	put("sys/block/dm-0/size", "100\n")
	put("etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\nclaude:x:1000:1000::/home/claude:/bin/bash\nbbuser:x:1001:1001::/home/bbuser:/bin/bash\nold:x:1002:1002::/home/old:/bin/bash\nsvc:x:1003:1003::/:/usr/sbin/nologin\nnobody:x:65534:65534::/:/usr/sbin/nologin\n")
	put("sys/block/vda/device/vendor", "0x1af4\n")
	put("sys/block/vda/size", "2048\n")
	put("sys/block/vda/queue/rotational", "1\n")
	put("etc/group", "sudo:x:27:claude\nwheel:x:10:\n")
	put("etc/shadow", "root:*:19000::::::\nclaude:$6$abc:19000::::::\nbbuser:!$6$def:19000::::::\nold:$6$x:19000:::::20000:\n")
	inv := Linux(root, func(dev string) string {
		if dev == "sda" {
			return "ZFL1QWERT"
		}
		return ""
	})
	if inv.Manufacturer != "LENOVO" || inv.Model != "20XW00GJUS" || inv.Serial != "PF3ABCDE" || inv.OS != "Ubuntu 24.04.1 LTS" || inv.Memory != 16303488*1024 {
		t.Errorf("system: %+v", inv)
	}
	// No desktop installed: a server (UX10); one with a graphical
	// session is not.
	if !inv.Server {
		t.Error("a Linux computer without a desktop is not a server")
	}
	put("usr/share/xsessions/ubuntu.desktop", "[Desktop Entry]\n")
	if Linux(root, nil).Server {
		t.Error("a Linux computer with a desktop session is a server")
	}
	if len(inv.Drives) != 3 {
		t.Fatalf("drives: %+v", inv.Drives)
	}
	byName := map[string]Drive{}
	for _, d := range inv.Drives {
		byName[d.Serial] = d
	}
	if d := byName["S64KNX0R700001"]; d.Interface != "NVMe" || d.Media != "SSD" || d.Size != 1000215216*512 {
		t.Errorf("nvme: %+v", d)
	}
	if d := byName["ZFL1QWERT"]; d.Model != "ATA ST2000DM008" || d.Media != "HDD" || d.Interface != "SATA/SAS" {
		t.Errorf("sata: %+v", d)
	}
	if d := byName[""]; d.Model != "VirtIO disk" || d.Media != "Virtual" || d.Interface != "VirtIO" {
		t.Errorf("virtio: %+v", d)
	}
	want := []Account{
		{Name: "root", ID: "uid 0", Enabled: true, Admin: true, Kind: "Local", Note: "password locked"},
		{Name: "claude", ID: "uid 1000", Enabled: true, Admin: true, Kind: "Local"},
		{Name: "bbuser", ID: "uid 1001", Enabled: true, Kind: "Local", Note: "password locked"}, // can still use a key
		{Name: "old", ID: "uid 1002", Enabled: false, Kind: "Local", Note: "expired"},
		{Name: "svc", ID: "uid 1003", Enabled: false, Kind: "Local"},
	}
	if len(inv.Accounts) != len(want) {
		t.Fatalf("accounts: %+v", inv.Accounts)
	}
	for i := range want {
		if inv.Accounts[i] != want[i] {
			t.Errorf("account %d: %+v, want %+v", i, inv.Accounts[i], want[i])
		}
	}
}
