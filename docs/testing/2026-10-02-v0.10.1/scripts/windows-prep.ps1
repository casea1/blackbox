# windows-11: download and verify the setup file; create the sender account. Run in an elevated PowerShell.
$v = '0.10.1'; $d = "$env:USERPROFILE\Downloads"
$base = "https://github.com/casea1/blackbox/releases/download/v$v"
Invoke-WebRequest "$base/Blackbox-Setup-$v.exe" -OutFile "$d\Blackbox-Setup-$v.exe" -UseBasicParsing
Invoke-WebRequest "$base/SHA256SUMS" -OutFile "$d\SHA256SUMS" -UseBasicParsing
$h = (Get-FileHash "$d\Blackbox-Setup-$v.exe").Hash.ToLower()
if ((Get-Content "$d\SHA256SUMS") -match "^$h\s+\*?Blackbox-Setup-$v.exe$") { "SHA256 OK $h" } else { "SHA256 MISMATCH $h" }
Get-AuthenticodeSignature "$d\Blackbox-Setup-$v.exe" | Format-List Status, SignerCertificate
# Local account for the Linux sender. Use a password with ',' '#' and '=' to test the cifs credentials file.
# Set $env:BB_SEND_PW first; it is not stored here.
net user bbsend $env:BB_SEND_PW /add /passwordchg:no /expires:never
Get-NetConnectionProfile | Format-Table Name, NetworkCategory
Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Where-Object { $_.Direction -eq 'Inbound' -and $_.DisplayName -like '*SMB-In*' } | Format-Table DisplayName, Profile, Enabled
auditpol /get /category:* | Select-String -Pattern 'No Auditing' | Measure-Object | Select-Object -ExpandProperty Count
