package share

import (
	"strings"
	"testing"
)

// N2: the firewall is never changed; the message gives the one rule, by
// command and by Group Policy.
func TestFirewallAdvice(t *testing.T) {
	smb := strings.Join(FirewallAdvice(SMBPort), "\n")
	for _, want := range []string{"TCP 445", "New-NetFirewallRule", "-Direction Inbound -Protocol TCP -LocalPort 445", "-RemoteAddress", "-Profile Domain,Private",
		"Group Policy", `Windows Defender Firewall with Advanced Security > Inbound Rules`, "does not change the firewall"} {
		if !strings.Contains(smb, want) {
			t.Errorf("SMB advice lacks %q:\n%s", want, smb)
		}
	}
	ssh := strings.Join(FirewallAdvice(SSHPort), "\n")
	for _, want := range []string{"OpenSSH server", "TCP 22", "-LocalPort 22"} {
		if !strings.Contains(ssh, want) {
			t.Errorf("SFTP advice lacks %q:\n%s", want, ssh)
		}
	}
	if strings.Contains(ssh, "445") {
		t.Error("SFTP advice names 445")
	}
}
