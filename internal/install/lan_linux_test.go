//go:build linux

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/config"
)

func TestLinuxLANUnits(t *testing.T) {
	cfg := config.Default()
	cfg.SendTo = "//COLLECTOR/BlackboxInbox"
	svc := serviceFor("/usr/local/bin/blackbox", cfg)
	if !strings.Contains(svc, "Wants="+mountUnitName()) || strings.Contains(svc, "COLLECTOR") {
		t.Errorf("SMB sender service:\n%s", svc)
	}
	if mountUnitName() != "var-lib-blackbox-collector.mount" {
		t.Errorf("mount unit name %q must match its mount point", mountUnitName())
	}
	m := mountUnit(cfg.SendTo)
	for _, want := range []string{"What=//COLLECTOR/BlackboxInbox", "Where=/var/lib/blackbox/collector", "Type=cifs", "credentials=/etc/blackbox/share.cred", "noexec"} {
		if !strings.Contains(m, want) {
			t.Errorf("mount unit missing %q", want)
		}
	}
	if c := credentialText(`LAB\bbsend`, "p w"); c != "username=bbsend\npassword=p w\ndomain=LAB\n" {
		t.Errorf("credentials: %q", c)
	}

	// A VM sending through a VirtualBox shared folder: the run does not
	// name the folder; blackbox-send.service delivers (L8).
	cfg.SendTo = "/media/sf_BlackboxInbox"
	svc = serviceFor("/usr/local/bin/blackbox", cfg)
	if strings.Contains(svc, "sf_BlackboxInbox") || !strings.Contains(svc, "Wants=blackbox-send.service") {
		t.Errorf("shared-folder sender service:\n%s", svc)
	}
	// A Linux collector receiving in a folder.
	cfg.SendTo, cfg.Inbox = "", "/srv/inbox"
	svc = serviceFor("/usr/local/bin/blackbox", cfg)
	if !strings.Contains(svc, "-/srv/inbox") || strings.Contains(svc, "Wants=") {
		t.Errorf("collector service:\n%s", svc)
	}

	// A sender also sends before shutdown; like blackbox-send.service, its
	// sandbox does not name the folder (L8).
	cfg.SendTo, cfg.Inbox = "/media/sf_BlackboxInbox", ""
	sd := shutdownFor("/usr/local/bin/blackbox", cfg)
	for _, want := range []string{"ExecStop=/usr/local/bin/blackbox send", "RemainAfterExit=yes", "After=network-online.target remote-fs.target vboxadd-service.service",
		"PrivateNetwork=yes", "ProtectSystem=full", "WantedBy=multi-user.target"} {
		if !strings.Contains(sd, want) {
			t.Errorf("shutdown unit missing %q:\n%s", want, sd)
		}
	}
	if strings.Contains(sd, "sf_BlackboxInbox") {
		t.Errorf("shutdown unit names the folder:\n%s", sd)
	}
	if strings.Contains(sd, "TimeoutStartSec") {
		t.Error("the shutdown unit must not carry the collection run's start timeout")
	}
}

// S15: a sender that stops sending removes its shutdown unit and clears
// its failed state, so systemctl --failed does not list it.
func TestShutdownUnitRemoved(t *testing.T) {
	var calls []string
	defer func(f func(...string)) { systemctl = f }(systemctl)
	systemctl = func(args ...string) { calls = append(calls, strings.Join(args, " ")) }
	unit := filepath.Join(t.TempDir(), "blackbox-shutdown.service")
	os.WriteFile(unit, []byte("[Unit]\n"), 0o644)
	removeShutdownUnit(unit)
	if _, err := os.Stat(unit); err == nil {
		t.Error("unit file left")
	}
	want := "disable --now blackbox-shutdown.service|daemon-reload|reset-failed blackbox-shutdown.service"
	if got := strings.Join(calls, "|"); got != want {
		t.Errorf("systemctl calls: %s", got)
	}
}
