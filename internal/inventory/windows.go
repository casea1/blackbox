package inventory

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WindowsQuery is the PowerShell that reads a Windows computer's
// inventory (CIM and the local accounts), as JSON. Times are ISO 8601 and
// each SID is reduced to its last four digits before it leaves PowerShell's
// output in Go (ParseWindows).
const WindowsQuery = `$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{}
$cs=Get-CimInstance Win32_ComputerSystem; $bios=Get-CimInstance Win32_BIOS; $os=Get-CimInstance Win32_OperatingSystem
$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1
function iso($d){ if($d){ ([datetime]$d).ToUniversalTime().ToString('o') } else { '' } }
$o.Manufacturer="$($cs.Manufacturer)"; $o.Model="$($cs.Model)"; $o.Serial="$($bios.SerialNumber)"; $o.BIOS="$($bios.SMBIOSBIOSVersion)"
$o.OS=("$($os.Caption) $($os.Version)").Trim(); $o.CPU="$($cpu.Name)"; $o.Memory=[uint64]$cs.TotalPhysicalMemory
if($cs.PartOfDomain){ $o.Domain="$($cs.Domain)" }
$o.Drives=@(Get-CimInstance Win32_DiskDrive | ForEach-Object { [ordered]@{Index=[int]$_.Index;Model="$($_.Model)";Serial=("$($_.SerialNumber)").Trim();Size=[uint64]$_.Size;Interface="$($_.InterfaceType)";Media="$($_.MediaType)"} })
$media=@{}; Get-PhysicalDisk | ForEach-Object { $media["$($_.DeviceId)"]="$($_.MediaType)" }
$o.Media=$media
$admins=@{}; try { Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $admins["$($_.SID)"]=1 } } catch { $o.Note="Administrators group members could not be read: $_" }
$o.Accounts=@(Get-LocalUser | ForEach-Object { [ordered]@{Name="$($_.Name)";SID="$($_.SID)";Enabled=[bool]$_.Enabled;Admin=$admins.ContainsKey("$($_.SID)");LastLogon=(iso $_.LastLogon)} })
$o.Profiles=@(Get-CimInstance Win32_UserProfile -Filter 'Special=False' | ForEach-Object { $n=''; try { $n=(New-Object System.Security.Principal.SecurityIdentifier($_.SID)).Translate([System.Security.Principal.NTAccount]).Value } catch {}; [ordered]@{Name=$n;SID="$($_.SID)";Admin=$admins.ContainsKey("$($_.SID)");LastUse=(iso $_.LastUseTime)} })
$o | ConvertTo-Json -Compress -Depth 4`

type winJSON struct {
	Manufacturer, Model, Serial, BIOS, OS, CPU, Domain, Note string
	Memory                                                   uint64
	Drives                                                   []struct {
		Model, Serial, Interface, Media string
		Size                            uint64
		Index                           int // the disk number, as Get-PhysicalDisk's DeviceId
	}
	Media    map[string]string // Get-PhysicalDisk: device number → HDD/SSD
	Accounts []struct {
		Name, SID, LastLogon string
		Enabled, Admin       bool
	}
	Profiles []struct {
		Name, SID, LastUse string
		Admin              bool
	}
}

// ParseWindows reads WindowsQuery's output.
func ParseWindows(b []byte) (*Inventory, error) {
	var w winJSON
	if err := json.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	inv := &Inventory{Manufacturer: Clean(w.Manufacturer), Model: Clean(w.Model), Serial: Clean(w.Serial), BIOS: Clean(w.BIOS),
		OS: strings.TrimSpace(w.OS), CPU: strings.Join(strings.Fields(w.CPU), " "), Memory: w.Memory, Domain: w.Domain}
	if w.Note != "" {
		inv.Notes = append(inv.Notes, w.Note)
	}
	for _, d := range w.Drives {
		media := d.Media
		if m := w.Media[fmt.Sprint(d.Index)]; m == "SSD" || m == "HDD" {
			media = m
		}
		switch {
		case strings.Contains(media, "Removable"):
			media = "Removable"
		case strings.Contains(media, "Fixed"):
			media = "Fixed"
		}
		inv.Drives = append(inv.Drives, Drive{Model: Clean(d.Model), Serial: Clean(d.Serial), Size: d.Size, Interface: d.Interface, Media: media})
	}
	local := map[string]bool{}
	for _, a := range w.Accounts {
		local[a.SID] = true
		inv.Accounts = append(inv.Accounts, Account{Name: a.Name, ID: SIDTail(a.SID), Enabled: a.Enabled, Admin: a.Admin, Kind: "Local", LastLogon: isoTime(a.LastLogon)})
	}
	for _, p := range w.Profiles {
		if local[p.SID] || !strings.HasPrefix(p.SID, "S-1-5-21-") {
			continue // a local account (listed above), or a service's profile
		}
		name := p.Name
		if name == "" {
			name = "(unknown account)"
		}
		inv.Accounts = append(inv.Accounts, Account{Name: name, ID: SIDTail(p.SID), Enabled: true, Admin: p.Admin, Kind: "Domain (profile)", LastLogon: isoTime(p.LastUse)})
	}
	return inv, nil
}

func isoTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil || t.Year() < 1980 {
		return time.Time{}
	}
	return t.UTC()
}
