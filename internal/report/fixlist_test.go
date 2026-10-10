package report

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// FIX1: the fix list has every system with something to fix, with
// commands to copy, and no events or people.
func TestFixList(t *testing.T) {
	r, _ := demo30(t)
	fl := r.FixList()
	if len(fl.Systems) == 0 {
		t.Fatal("no systems in the fix list")
	}
	hp := r.healthPage()
	want := map[string]bool{}
	for _, g := range hp.Groups {
		for _, row := range g.Rows {
			for _, l := range row.Table {
				if l.Class == "bad" && l.Check != "Logs intact" && l.Check != "Reporting" && l.Check != "STIG compliance (SCAP)" {
					want[row.Name] = true
				}
			}
			for _, so := range row.Scap {
				if len(so.Rules) > 0 {
					want[row.Name] = true
				}
			}
		}
	}
	got := map[string]bool{}
	cmds := 0
	for _, s := range fl.Systems {
		got[s.Name] = true
		for _, it := range append(s.Settings, s.Logs...) {
			cmds += len(it.Cmds)
		}
	}
	for h := range want {
		if !got[h] {
			t.Errorf("%s has something to fix but is not in the fix list", h)
		}
	}
	if cmds == 0 {
		t.Error("no commands to copy")
	}
	var b bytes.Buffer
	if err := r.WriteFixList(&b); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	for _, w := range []string{"<button type=\"button\">Copy</button>", "Save as PDF", "@media print"} {
		if !strings.Contains(page, w) {
			t.Errorf("page lacks %q", w)
		}
	}
	for _, u := range r.Users {
		if u.User != "" && strings.Contains(page, ">"+u.User+"<") {
			t.Errorf("page names the person %s", u.User)
		}
	}
	if p := os.Getenv("BLACKBOX_FIXLIST_OUT"); p != "" {
		os.WriteFile(p, b.Bytes(), 0o644)
	}
}

func TestFixCommands(t *testing.T) {
	for _, c := range []struct {
		item, fix string
		win       bool
		want      []string
	}{
		{"Logon", "Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Logon/Logoff > Audit Logon: Configure the following audit events: Success and Failure", true,
			[]string{`auditpol /set /subcategory:"Logon" /success:enable /failure:enable`}},
		{"Security", "Computer Configuration > Policies > Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size (KB): Enabled, 1024000", true,
			[]string{`wevtutil sl "Security" /ms:1048576000`}},
		{"x", `No Group Policy setting turns this log on. In Event Viewer: … (or once, as administrator: wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true)`, true,
			[]string{`wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true`}},
		{"rules", "blackbox check --audit-rules --missing | install -m 0600 /dev/stdin /etc/audit/rules.d/blackbox.rules, then augenrules --load", false,
			[]string{"blackbox check --audit-rules --missing | install -m 0600 /dev/stdin /etc/audit/rules.d/blackbox.rules", "augenrules --load"}},
		{"perm", "chmod 0600 /var/log/audit/audit.log && chmod 0750 /var/log/audit (and set log_group = root in /etc/audit/auditd.conf)", false,
			[]string{"chmod 0600 /var/log/audit/audit.log && chmod 0750 /var/log/audit"}},
		{"fmt", "set log_format = ENRICHED in /etc/audit/auditd.conf, then restart auditd", false, nil},
	} {
		var got []string
		for _, x := range fixCommands(c.item, c.fix, c.win) {
			got = append(got, x.Text)
		}
		if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
			t.Errorf("%s: got %q, want %q", c.item, got, c.want)
		}
	}
}
