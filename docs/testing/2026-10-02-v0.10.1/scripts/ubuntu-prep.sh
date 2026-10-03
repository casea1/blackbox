#!/bin/bash
# ubuntu-server: prerequisites, audit rules, boot settings. Run as claude; reboot afterwards.
set -x
B=~/bb/blackbox-0.10.1-linux-amd64/blackbox
sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=1800 install -y auditd cifs-utils openssh-server sshpass smbclient
# Blackbox's recommended rules (ends with -e 2)
sudo $B check --audit-rules | sudo tee /etc/audit/rules.d/99-blackbox.rules >/dev/null
# Ubuntu STIG rules Blackbox's file lacks (findings A3/A4), loaded first
sudo tee /etc/audit/rules.d/50-stig-extra.rules >/dev/null <<'R'
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/run/utmp -p wa -k session
-w /etc/cron.d/ -p wa -k cron
-w /etc/ssh/sshd_config -p wa -k sshd
R
sudo augenrules --load
# audit=1 and backlog on the kernel command line (STIG)
sudo sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1 audit_backlog_limit=8192"/' /etc/default/grub
sudo update-grub 2>&1 | tail -1
grep -E '^(log_format|space_left_action|admin_space_left_action|disk_full_action|disk_error_action|max_log_file|num_logs|max_log_file_action)' /etc/audit/auditd.conf
sudo systemctl enable --now ssh
sudo $B check 2>&1 | tail -25
echo PREP-DONE
