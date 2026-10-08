package install

import (
	"strings"
	"testing"
)

func TestIsSFTP(t *testing.T) {
	for s, want := range map[string]bool{
		"bbsend@COLLECTOR:/C:/BlackboxInbox":        true,
		"svc@10.10.99.100:/E:/Shared Folders/Inbox": true,
		"bbsend@collector.corp.example:/srv/inbox":  true,
		"//COLLECTOR/BlackboxInbox":                 false,
		"/mnt/blackbox-inbox":                       false,
		`\\COLLECTOR\BlackboxInbox`:                 false,
		"COLLECTOR:/C:/BlackboxInbox":               false,
		"bbsend@COLLECTOR:relative":                 false,
	} {
		if IsSFTP(s) != want {
			t.Errorf("IsSFTP(%q) = %v", s, !want)
		}
	}
	if u, h, p := SplitSFTP("svc@10.10.99.100:/E:/Shared Folders/Inbox"); u != "svc" || h != "10.10.99.100" || p != "/E:/Shared Folders/Inbox" {
		t.Errorf("split: %q %q %q", u, h, p)
	}
	if got, err := SendToAnswer(" bbsend@COLLECTOR:/C:/BlackboxInbox ", false); err != nil || got != "bbsend@COLLECTOR:/C:/BlackboxInbox" {
		t.Errorf("Linux answer: %q %v", got, err)
	}
	if _, err := SendToAnswer("bbsend@COLLECTOR:/C:/BlackboxInbox", true); err == nil {
		t.Error("a Windows sender took an SFTP inbox")
	}
}

// The mount uses only the pinned host key and Blackbox's own key, and
// does not stop the computer starting when the collector is down.
func TestSFTPMountUnit(t *testing.T) {
	u := sftpMountUnit("bbsend@COLLECTOR:/C:/BlackboxInbox", SFTPMountPoint)
	for _, want := range []string{sftpMarker + "\n", "What=bbsend@COLLECTOR:/C:/BlackboxInbox\n", "Where=/mnt/blackbox-inbox\n", "Type=fuse.sshfs\n",
		"IdentityFile=" + SFTPKey, "UserKnownHostsFile=" + SFTPKnownHosts, "StrictHostKeyChecking=yes", "BatchMode=yes", "reconnect", "nofail", "_netdev"} {
		if !strings.Contains(u, want) {
			t.Errorf("mount unit lacks %q:\n%s", want, u)
		}
	}
	if !strings.HasPrefix(u, sftpMarker) {
		t.Error("marker is not the first line")
	}
}

// The collector keeps the key restricted to file transfer; the script
// writes the file OpenSSH reads for the account and quotes the key.
func TestAddKeyScript(t *testing.T) {
	line := AuthorizedKeyLine("ecdsa-sha2-nistp384 AAAAE2 blackbox o'brien-pc\n")
	if line != "restrict ecdsa-sha2-nistp384 AAAAE2 blackbox o'brien-pc" || AuthorizedKeyLine(line) != line {
		t.Fatalf("line %q", line)
	}
	s := AddKeyScript(line)
	for _, want := range []string{`$k = 'restrict ecdsa-sha2-nistp384 AAAAE2 blackbox o''brien-pc'`, `administrators_authorized_keys`, `$env:USERPROFILE\.ssh`, `S-1-5-32-544`, `/inheritance:r`} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
}
