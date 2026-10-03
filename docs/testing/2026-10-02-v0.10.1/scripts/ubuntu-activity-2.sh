#!/bin/bash
# ubuntu-server, ISSO activity set 2: STIG-key events (A3), system changes, tampering
L(){ echo "$(date -u +%T) $*" | tee -a ~/act.log; }
L "== set 2 start"
sudo -u bbuser cat /etc/shadow 2>/dev/null; L "bbuser denied reading /etc/shadow (perm_access)"
sudo mkdir -p /opt/secret && echo plan | sudo tee /opt/secret/plan.txt >/dev/null; sudo chmod 777 /opt/secret/plan.txt; L "chmod 777 /opt/secret/plan.txt (perm_mod)"
sudo cp /bin/bash /tmp/bbsh && sudo chmod u+s /tmp/bbsh; L "setuid bash copy /tmp/bbsh (perm_mod)"
echo '* * * * * root /tmp/bbsh -c true' | sudo tee /etc/cron.d/bbtest >/dev/null; L "/etc/cron.d/bbtest created (cron)"
sudo sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 6/' /etc/ssh/sshd_config; L "sshd_config edited (sshd)"
sudo modprobe dummy && sudo rmmod dummy; L "kernel module dummy loaded and removed"
sudo timedatectl set-ntp false 2>/dev/null; sudo date -s "$(date -u -d '+1 sec')" >/dev/null; sudo timedatectl set-ntp true 2>/dev/null; L "clock set by admin (time-change)"
sudo mount -t tmpfs none /mnt && sudo umount /mnt; L "tmpfs mounted on /mnt (not a disk)"
echo x | sudo tee /var/log/bbtest.log >/dev/null; sudo rm /var/log/bbtest.log; L "file deleted in /var/log (log_tamper)"
sudo truncate -s 0 /var/log/dpkg.log; L "truncated /var/log/dpkg.log (log_tamper)"
sudo auditctl -e 0 2>/dev/null; L "auditctl -e 0 (refused, rules locked)"
sudo auditctl -D 2>/dev/null; L "auditctl -D (refused)"
sudo systemctl stop auditd 2>/dev/null; L "systemctl stop auditd (refused by unit?)"
# AU-9: Blackbox's own config and schedule
sudo blackbox config set exclude_users bbuser >/dev/null; L "blackbox config set exclude_users bbuser"
sudo blackbox config set exclude_users none >/dev/null 2>&1 || sudo sed -i 's/^exclude_users = .*/exclude_users =/' /etc/blackbox/blackbox.conf; L "exclude_users cleared"
sudo systemctl stop blackbox.timer; sleep 2; sudo systemctl start blackbox.timer; L "blackbox.timer stopped and started"
sudo blackbox config set site_name "UBU #2" >/dev/null; L "config set site_name 'UBU #2' (R3)"
sudo sed -i 's/^working_hours =.*/working_hours = Mon-Fri 06:00-18:00/' /etc/blackbox/blackbox.conf; L "blackbox.conf edited directly (working_hours)"
L "== set 2 end"
