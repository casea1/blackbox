package share

import "fmt"

// The ports a collector's inbox is reached on.
const (
	SMBPort = 445 // Windows file sharing
	SSHPort = 22  // the OpenSSH server, for SFTP (sshfs) senders
)

// FirewallAdvice is what setup and status print when Windows Firewall
// blocks senders from reaching this collector (N2). Blackbox never changes
// the firewall: it gives the one rule an administrator can add, limited to
// the senders' addresses and the Domain and Private profiles, by command
// and by Group Policy.
func FirewallAdvice(port int) []string {
	what, name := "file sharing (SMB)", "Blackbox inbox - SMB from senders"
	if port == SSHPort {
		what, name = "the OpenSSH server (SFTP)", "Blackbox inbox - SFTP from senders"
	}
	return []string{
		fmt.Sprintf("Windows Firewall does not allow %s in on TCP %d, so other computers cannot deliver.", what, port),
		"Blackbox does not change the firewall. To allow only the senders, run as administrator (put the senders' addresses after -RemoteAddress):",
		fmt.Sprintf(`  New-NetFirewallRule -DisplayName "%s" -Direction Inbound -Protocol TCP -LocalPort %d -RemoteAddress 192.0.2.21,192.0.2.22 -Profile Domain,Private -Action Allow`, name, port),
		`Or by Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Inbound Rules > New Rule:`,
		fmt.Sprintf("  Port, TCP %d, Allow the connection, Domain and Private only; then under the rule's Scope, Remote IP address: the senders' addresses.", port),
	}
}
