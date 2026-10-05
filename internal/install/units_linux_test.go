//go:build linux

package install

import (
	"strings"
	"testing"

	"github.com/casea1/blackbox/internal/config"
)

// L8: a sender to a folder the site mounted (sshfs) never names that
// folder in the run unit, so a dead mount cannot stop collection: the run
// only queues, and blackbox-send.service delivers, remounting first.
func TestSendUnitSeparate(t *testing.T) {
	cfg := &config.Config{DataDir: "/var/lib/blackbox", SendTo: "/mnt/blackbox inbox"}
	svc := serviceFor("/usr/local/bin/blackbox", cfg)
	if strings.Contains(svc, "/mnt/blackbox") || !strings.Contains(svc, "ExecStart=/usr/local/bin/blackbox run --no-deliver") ||
		!strings.Contains(svc, "Wants=blackbox-send.service") {
		t.Errorf("run unit:\n%s", svc)
	}
	send := systemdSendService("/usr/local/bin/blackbox", cfg.SendTo)
	for _, want := range []string{`ExecStartPre=-+/usr/bin/systemctl start "mnt-blackbox\\x20inbox.mount"`, "ExecStart=/usr/local/bin/blackbox send\n", "After=blackbox.service", "ProtectSystem=full"} {
		if !strings.Contains(send, want) {
			t.Errorf("send unit missing %q:\n%s", want, send)
		}
	}
	for _, unit := range []string{send, shutdownFor("/usr/local/bin/blackbox", cfg)} {
		if strings.Contains(unit, "ReadWritePaths") || strings.Contains(unit, "/mnt/blackbox") {
			t.Errorf("unit names the collector's folder:\n%s", unit)
		}
	}
	// An SMB share Blackbox mounts itself: delivered from the run, as before.
	cfg.SendTo = "//collector/BlackboxInbox"
	if svc := serviceFor("/usr/local/bin/blackbox", cfg); strings.Contains(svc, "--no-deliver") || strings.Contains(svc, "blackbox-send") {
		t.Errorf("SMB run unit:\n%s", svc)
	}
}

// L12: the send unit has systemd mount the folder (PrivateNetwork keeps a
// mount started inside the unit from reaching the collector). Unit names
// match systemd-escape --path --suffix=mount.
func TestMountUnitFor(t *testing.T) {
	for in, want := range map[string]string{
		"/mnt/blackbox-inbox":      `mnt-blackbox\x2dinbox.mount`,
		"/media/sf_BlackboxInbox/": "media-sf_BlackboxInbox.mount",
		"/srv//inbox":              "srv-inbox.mount",
		"/mnt/.hidden/a b":         `mnt-.hidden-a\x20b.mount`,
		"/.x":                      `\x2ex.mount`,
		"/":                        "-.mount",
	} {
		if got := MountUnitFor(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	if u := systemdSendService("/usr/local/bin/blackbox", "/mnt/blackbox-inbox"); !strings.Contains(u, `ExecStartPre=-+/usr/bin/systemctl start "mnt-blackbox\\x2dinbox.mount"`) || strings.Contains(u, "/bin/mount") {
		t.Errorf("send unit:\n%s", u)
	}
}
