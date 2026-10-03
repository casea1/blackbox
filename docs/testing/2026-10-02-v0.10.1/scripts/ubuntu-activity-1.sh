#!/bin/bash
# ubuntu-server, ISSO activity set 1 (run as claude, sudo without password). Each action is logged to ~/act.log (UTC).
L(){ echo "$(date -u +%T) $*" | tee -a ~/act.log; }
P="${BB_TEST_PW:?set BB_TEST_PW to bbuser's test password}"
L "== set 1 start"
# AC-2 account lifecycle
sudo useradd -m -s /bin/bash bbuser && echo "bbuser:$P" | sudo chpasswd; L "created bbuser (stays), password set"
sudo useradd -m bbtemp && L "created bbtemp"
sudo usermod -aG sudo bbtemp && L "added bbtemp to sudo"
sudo gpasswd -d bbtemp sudo >/dev/null && L "removed bbtemp from sudo"
sudo usermod -L bbtemp && L "locked bbtemp"; sudo usermod -U bbtemp; L "unlocked bbtemp"
sudo userdel -r bbtemp 2>/dev/null; L "deleted bbtemp (created+deleted same day)"
sudo groupadd bbgroup && sudo gpasswd -a bbuser bbgroup >/dev/null && L "created bbgroup, added bbuser"
# AC-7 / password guessing over ssh (localhost only); cloud image disables password auth, so enable it first
echo "PasswordAuthentication yes" | sudo tee /etc/ssh/sshd_config.d/01-bbtest.conf >/dev/null; sudo systemctl reload ssh; L "ssh password auth enabled for testing"
for i in 1 2 3 4 5 6; do sshpass -p wrong$i ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password bbuser@localhost true 2>/dev/null; done; L "6 wrong ssh passwords for bbuser"
for u in admin oracle test guest ubuntu postgres; do sshpass -p x ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password $u@localhost true 2>/dev/null; done; L "ssh spray: 6 unknown accounts"
sshpass -p "$P" ssh -o StrictHostKeyChecking=no bbuser@localhost 'id >/dev/null'; L "1 successful ssh logon+logoff as bbuser (C4: expect 1 row)"
# AC-6 privileged functions
echo wrong | sudo -u bbuser sudo -S -k true 2>/dev/null; L "bbuser tried sudo (not in sudoers)"
sudo -u bbuser sshpass -p wrongpw su -c true root 2>/dev/null; L "bbuser failed su to root"
sudo -i bash -c 'id >/dev/null; cat /etc/shadow >/dev/null'; L "sudo -i root shell: id, cat /etc/shadow"
echo 'bbuser ALL=(ALL) NOPASSWD: /usr/bin/systemctl' | sudo tee /etc/sudoers.d/90-bbtest >/dev/null; sudo chmod 440 /etc/sudoers.d/90-bbtest; L "sudoers.d/90-bbtest created for bbuser"
L "== set 1 end"
