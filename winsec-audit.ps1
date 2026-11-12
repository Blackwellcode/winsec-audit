<#
.SYNOPSIS
    winsec-audit - read-only security audit for Windows 10/11 workstations.

.DESCRIPTION
    Runs 44 checks (patching, Microsoft Defender, firewall, network exposure, accounts,
    boot integrity, logging, persistence, software updates, system integrity) and writes
    report.md and report.json. The script never changes system state; tests/Test-ReadOnly.ps1
    enforces that on every commit. Without elevation, admin-only checks are reported as Skipped.

.PARAMETER OutputPath
    Folder for the reports. A sub folder <computer>-<timestamp> is created inside it.

.PARAMETER Deep
    Adds DISM /ScanHealth and sfc /verifyonly (elevated, several minutes). Both only verify.

.PARAMETER SkipWinget
    Skips the winget upgrade listing (no network access at all).

.PARAMETER Redact
    Replaces user name, computer name and profile path in the report.

.PARAMETER FailOn
    Exit code 3 if a check failed with at least this severity. Default: None (always exit 0).

.EXAMPLE
    .\winsec-audit.ps1
    .\winsec-audit.ps1 -Deep -Redact
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'reports'),
    [switch]$Deep,
    [switch]$SkipWinget,
    [switch]$Redact,
    [ValidateSet('None', 'Critical', 'High', 'Medium', 'Low')][string]$FailOn = 'None',
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Version = '0.1.0'
$script:Results = New-Object System.Collections.Generic.List[object]
$script:SigCache = @{}
$script:SeverityRank = @{ Info = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
$script:IsAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# The only external programs this tool may start, with fixed arguments. Nothing else is executed.
# Programs are never resolved through PATH: System32 tools by fixed path, winget from the
# App Installer package with a verified Microsoft signature (see Resolve-NativeCommand).
$script:NativeCommands = @{
    TpmInfo    = @{ Exe = 'tpmtool.exe'; Location = 'System32'; Args = @('getdeviceinformation') }
    WingetList = @{ Exe = 'winget.exe'; Location = 'AppInstaller'; Args = @('upgrade', '--include-unknown', '--disable-interactivity') }
    DismScan   = @{ Exe = 'dism.exe'; Location = 'System32'; Args = @('/Online', '/Cleanup-Image', '/ScanHealth') }
    SfcVerify  = @{ Exe = 'sfc.exe'; Location = 'System32'; Args = @('/verifyonly') }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function New-Finding {
    param(
        [Parameter(Mandatory, Position = 0)][ValidateSet('Pass', 'Warn', 'Fail', 'Info')][string]$Status,
        [Parameter(Mandatory, Position = 1)][AllowEmptyString()][string]$Evidence,
        [Parameter(Position = 2)][string]$Fix = ''
    )
    [pscustomobject]@{ Status = $Status; Evidence = $Evidence; Fix = $Fix }
}

function Invoke-Check {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')][string]$Severity = 'Medium',
        [int]$Weight = 0,
        [switch]$RequiresAdmin,
        [switch]$DeepOnly,
        [Parameter(Mandatory)][scriptblock]$Body
    )
    $status = 'Skipped'; $evidence = ''; $fix = ''
    if ($DeepOnly -and -not $Deep) { $evidence = 'Only with -Deep.' }
    elseif ($RequiresAdmin -and -not $script:IsAdmin) { $evidence = 'Requires an elevated PowerShell.' }
    else {
        try {
            $finding = @(& $Body) | Select-Object -Last 1
            if ($null -eq $finding -or -not $finding.PSObject.Properties['Status']) { throw 'Check returned no finding.' }
            $status = $finding.Status; $evidence = $finding.Evidence; $fix = $finding.Fix
        }
        catch {
            $status = 'Error'
            $evidence = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
        }
    }
    if (-not $Quiet) {
        $color = @{ Pass = 'Green'; Warn = 'Yellow'; Fail = 'Red'; Error = 'Magenta'; Info = 'Cyan'; Skipped = 'DarkGray' }[$status]
        Write-Host ('[{0,-7}] {1,-7} {2}' -f $status, $Id, $Title) -ForegroundColor $color
    }
    $script:Results.Add([pscustomobject]@{
            Id = $Id; Category = $Category; Title = $Title; Severity = $Severity; Weight = $Weight
            Status = $status; Evidence = $evidence; Fix = $fix
        })
}

function Get-RegValue([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $key = Get-Item -LiteralPath $Path
    if ($key.GetValueNames() -contains $Name) { return $key.GetValue($Name) }
    return $null
}

function Get-PropValue($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Resolve-Executable([string]$CommandLine) {
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine).Trim()
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { $c = $c.Substring(1, $end - 1) }
    }
    else {
        $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|dll|sys))(\s|,|$)', 'IgnoreCase')
        if ($m.Success) { $c = $m.Groups[1].Value } else { $c = ($c -split '\s+')[0] }
    }
    $c = $c -replace '^\\\?\?\\', ''
    $c = $c -replace '^(?i)\\SystemRoot\\', ($env:SystemRoot + '\')
    $c = $c -replace '^(?i)system32\\', ($env:SystemRoot + '\System32\')
    if ([IO.Path]::IsPathRooted($c)) { return $c }
    $cmd = Get-Command -Name $c -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $c
}

function Get-SignatureState([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'Missing' }
    $k = $Path.ToLowerInvariant()
    if (-not $script:SigCache.ContainsKey($k)) {
        $script:SigCache[$k] = (Get-AuthenticodeSignature -LiteralPath $Path).Status.ToString()
    }
    return $script:SigCache[$k]
}

function Resolve-NativeCommand($Spec) {
    if ($Spec.Location -eq 'System32') {
        # 32-bit PowerShell on 64-bit Windows sees a redirected System32; Sysnative is the real one
        $dir = 'System32'
        if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { $dir = 'Sysnative' }
        $path = Join-Path (Join-Path $env:SystemRoot $dir) $Spec.Exe
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw (New-Object System.IO.FileNotFoundException("$path not found")) }
        return $path
    }
    # winget.exe on PATH is a per-user execution alias (reparse point, not signable) and any folder
    # earlier in PATH could shadow it. Use the binary inside the App Installer package instead.
    $pkg = @(Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction Stop) | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $pkg -or -not $pkg.InstallLocation) { throw (New-Object System.IO.FileNotFoundException('App Installer (winget) is not installed')) }
    $path = Join-Path $pkg.InstallLocation $Spec.Exe
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw (New-Object System.IO.FileNotFoundException("$path not found")) }
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
    if ($sig.Status -ne 'Valid' -or $subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw (New-Object System.Security.SecurityException("$path is not validly signed by Microsoft ($($sig.Status); $subject)"))
    }
    return $path
}

function Invoke-ReadOnlyNative {
    param([Parameter(Mandatory)][ValidateSet('TpmInfo', 'WingetList', 'DismScan', 'SfcVerify')][string]$Key)
    $spec = $script:NativeCommands[$Key]
    $exe = Resolve-NativeCommand $spec
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'   # native stderr must not abort the check
    try { $out = & $exe @($spec.Args) 2>&1 }
    finally { $ErrorActionPreference = $prev }
    [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Text     = ((@($out) | ForEach-Object { "$_" }) -join "`n") -replace "`0", ''
    }
}

function Join-Limited([object[]]$Items, [int]$Max = 12) {
    $list = @($Items)
    $shown = ($list | Select-Object -First $Max) -join '; '
    if ($list.Count -gt $Max) { $shown += "; ... (+$($list.Count - $Max) more)" }
    return $shown
}

# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$os = Get-CimInstance Win32_OperatingSystem
$script:Meta = [ordered]@{
    Tool         = "winsec-audit $script:Version"
    Timestamp    = (Get-Date).ToString('s')
    Computer     = $env:COMPUTERNAME
    User         = $env:USERNAME
    Elevated     = $script:IsAdmin
    OS           = "$($os.Caption) $(Get-PropValue $cv 'DisplayVersion') (Build $($cv.CurrentBuild).$(Get-PropValue $cv 'UBR'))"
    PowerShell   = $PSVersionTable.PSVersion.ToString()
    Deep         = [bool]$Deep
}

$script:MpStatus = $null; $script:MpPref = $null; $script:MpError = ''
try { $script:MpStatus = Get-MpComputerStatus; $script:MpPref = Get-MpPreference }
catch { $script:MpError = $_.Exception.Message }

function Assert-Defender {
    if (-not $script:MpStatus) { throw "Microsoft Defender not queryable: $script:MpError" }
}

if (-not $Quiet) {
    Write-Host "winsec-audit $script:Version - read-only. Elevated: $script:IsAdmin" -ForegroundColor White
}

# ---------------------------------------------------------------------------
# Patching
# ---------------------------------------------------------------------------

Invoke-Check -Id 'OS-01' -Category 'Patching' -Title 'Windows updates installed recently' -Severity 'High' -Weight 10 -Body {
    $dates = @()
    $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($hf) { $dates += [datetime]$hf.InstalledOn }
    $wu = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastInstallationSuccessDate
    if ($wu -and ([datetime]$wu).Year -gt 2000) { $dates += [datetime]$wu }
    if (-not $dates) { return New-Finding Warn 'No update install date found.' 'Run Windows Update.' }
    $last = ($dates | Sort-Object -Descending)[0]
    $age = [int]((Get-Date) - $last).TotalDays
    $ev = "$($script:Meta.OS); last successful update install $($last.ToString('yyyy-MM-dd')) ($age days ago)."
    if ($age -le 35) { return New-Finding Pass $ev }
    if ($age -le 60) { return New-Finding Warn $ev 'Install pending Windows updates.' }
    New-Finding Fail $ev 'Install pending Windows updates; at least one monthly security update is missing.'
}

Invoke-Check -Id 'OS-02' -Category 'Patching' -Title 'No reboot pending for updates' -Severity 'Low' -Weight 2 -Body {
    $pending = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'Windows Update' }
    if ($pending) { return New-Finding Warn "Reboot pending: $($pending -join ', ')." 'Reboot to finish installing updates.' }
    New-Finding Pass 'No pending reboot flags.'
}

# ---------------------------------------------------------------------------
# Microsoft Defender
# ---------------------------------------------------------------------------

Invoke-Check -Id 'DEF-01' -Category 'Defender' -Title 'Real-time protection and tamper protection on' -Severity 'Critical' -Weight 10 -Body {
    if (-not $script:MpStatus) {
        $av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object displayName)
        if ($av) { return New-Finding Info "Defender not queryable; registered antivirus: $($av -join ', ')." }
        Assert-Defender
    }
    $s = $script:MpStatus
    $off = @()
    foreach ($n in 'AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'OnAccessProtectionEnabled') {
        if (-not (Get-PropValue $s $n)) { $off += $n }
    }
    $ev = "Platform $($s.AMProductVersion), engine $($s.AMEngineVersion), tamper protection $($s.IsTamperProtected)."
    if ($off) { return New-Finding Fail "$ev Off: $($off -join ', ')." 'Turn real-time protection back on in Windows Security.' }
    if (-not $s.IsTamperProtected) { return New-Finding Warn $ev 'Enable Tamper Protection in Windows Security.' }
    New-Finding Pass $ev
}

Invoke-Check -Id 'DEF-02' -Category 'Defender' -Title 'Security intelligence up to date' -Severity 'High' -Weight 5 -Body {
    Assert-Defender
    $age = [int]$script:MpStatus.AntivirusSignatureAge
    $ev = "Signature $($script:MpStatus.AntivirusSignatureVersion), $age day(s) old."
    if ($age -le 2) { return New-Finding Pass $ev }
    if ($age -le 7) { return New-Finding Warn $ev 'Update-MpSignature or Windows Update.' }
    New-Finding Fail $ev 'Signatures are outdated: run Update-MpSignature and check Windows Update.'
}

Invoke-Check -Id 'DEF-03' -Category 'Defender' -Title 'Recent quick and full scan' -Severity 'Low' -Weight 3 -Body {
    Assert-Defender
    $q = [int64]$script:MpStatus.QuickScanAge; $f = [int64]$script:MpStatus.FullScanAge
    $fs = if ($f -ge 4294967295) { 'never' } else { "$f day(s) ago" }
    $ev = "Quick scan $q day(s) ago, full scan $fs."
    if ($q -le 7 -and $f -le 35) { return New-Finding Pass $ev }
    New-Finding Warn $ev 'Run a full scan: Start-MpScan -ScanType FullScan (elevated).'
}

Invoke-Check -Id 'DEF-04' -Category 'Defender' -Title 'Cloud protection, PUA and network protection' -Severity 'Medium' -Weight 5 -Body {
    Assert-Defender
    $p = $script:MpPref
    $miss = @()
    if ([int]$p.MAPSReporting -eq 0) { $miss += 'cloud protection (MAPS) off' }
    if ([int]$p.PUAProtection -ne 1) { $miss += 'PUA protection not blocking' }
    if ([int]$p.EnableNetworkProtection -ne 1) { $miss += 'network protection not enabled' }
    if ([int]$p.CloudBlockLevel -lt 2) { $miss += "cloud block level $([int]$p.CloudBlockLevel) (<2 High)" }
    $ev = "MAPS=$([int]$p.MAPSReporting), PUA=$([int]$p.PUAProtection), NetworkProtection=$([int]$p.EnableNetworkProtection), CloudBlockLevel=$([int]$p.CloudBlockLevel)."
    $fix = 'Set-MpPreference -CloudBlockLevel High -EnableNetworkProtection Enabled -PUAProtection Enabled'
    if (-not $miss) { return New-Finding Pass $ev }
    if ($miss.Count -le 2) { return New-Finding Warn "$ev $($miss -join '; ')." $fix }
    New-Finding Fail "$ev $($miss -join '; ')." $fix
}

Invoke-Check -Id 'DEF-05' -Category 'Defender' -Title 'Attack surface reduction rules' -Severity 'Medium' -Weight 8 -Body {
    Assert-Defender
    $ids = @($script:MpPref.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
    $acts = @($script:MpPref.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
    $block = @($acts | Where-Object { $_ -eq 1 }).Count
    $audit = @($acts | Where-Object { $_ -eq 2 }).Count
    $warn = @($acts | Where-Object { $_ -eq 6 }).Count
    $ev = "$($ids.Count) rule(s) configured: $block block, $warn warn, $audit audit."
    $fix = 'Enable ASR rules (start with audit mode, then block): https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference'
    if ($block -ge 10) { return New-Finding Pass $ev }
    if ($block -gt 0 -or $warn -gt 0 -or $audit -gt 0) { return New-Finding Warn $ev $fix }
    New-Finding Fail $ev $fix
}

Invoke-Check -Id 'DEF-06' -Category 'Defender' -Title 'No Defender exclusions' -Severity 'High' -Weight 4 -RequiresAdmin -Body {
    Assert-Defender
    $p = $script:MpPref
    $ex = @()
    foreach ($n in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress') {
        foreach ($v in @(Get-PropValue $p $n)) { if ($v) { $ex += "$n=$v" } }
    }
    if (-not $ex) { return New-Finding Pass 'No exclusions configured.' }
    New-Finding Warn "$($ex.Count) exclusion(s): $(Join-Limited $ex)" 'Remove exclusions that are not strictly required (Remove-MpPreference).'
}

Invoke-Check -Id 'DEF-07' -Category 'Defender' -Title 'No active threats' -Severity 'Critical' -Weight 6 -Body {
    Assert-Defender
    # -ErrorAction Stop: a failed query must end as Error, never as "no threats" (Pass)
    $threats = @(Get-MpThreat -ErrorAction Stop)
    $names = @{}; foreach ($t in $threats) { $names[[string]$t.ThreatID] = $t.ThreatName }
    $active = @($threats | Where-Object { $_.IsActive })
    $since = (Get-Date).AddDays(-30)
    $recent = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt $since } | ForEach-Object {
            $n = $names[[string]$_.ThreatID]; if (-not $n) { $n = "ThreatID $($_.ThreatID)" }
            "$($_.InitialDetectionTime.ToString('yyyy-MM-dd')) $n (remediated: $($_.ActionSuccess))"
        })
    $ev = "$($active.Count) active threat(s); $($recent.Count) detection(s) in the last 30 days. $(Join-Limited $recent 6)"
    if ($active) { return New-Finding Fail "$ev Active: $(($active | ForEach-Object ThreatName) -join ', ')." 'Open Windows Security > Protection history and remediate.' }
    New-Finding Pass $ev
}

Invoke-Check -Id 'DEF-08' -Category 'Defender' -Title 'Smart App Control state' -Severity 'Info' -Body {
    Assert-Defender
    $sac = Get-PropValue $script:MpStatus 'SmartAppControlState'
    if ($null -eq $sac) { return New-Finding Info 'Not reported by this Windows version.' }
    New-Finding Info "Smart App Control: $sac. (Once off it can only be re-enabled by reinstalling Windows.)"
}

# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------

Invoke-Check -Id 'FW-01' -Category 'Firewall' -Title 'Firewall on for all profiles, inbound blocked by default' -Severity 'Critical' -Weight 8 -Body {
    $profiles = @(Get-NetFirewallProfile)
    $bad = @($profiles | Where-Object { $_.Enabled.ToString() -eq 'False' -or $_.DefaultInboundAction.ToString() -eq 'Allow' })
    $ev = ($profiles | ForEach-Object { "$($_.Name): enabled=$($_.Enabled), inbound=$($_.DefaultInboundAction)" }) -join '; '
    if ($bad) { return New-Finding Fail $ev 'Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block' }
    New-Finding Pass "$ev (NotConfigured = Windows default: block)."
}

Invoke-Check -Id 'FW-02' -Category 'Firewall' -Title 'No script interpreters reachable inbound on Public networks' -Severity 'Medium' -Weight 5 -Body {
    $pattern = '(?i)\\(powershell|pwsh|python\d*|pythonw|node|java|javaw|cmd|wscript|cscript|mshta|ruby|perl|php|bash|wsl)\.exe$'
    $hits = @()
    foreach ($rule in @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object { $_.Profile.ToString() -match 'Public|Any' })) {
        # per-rule association: the -All enumeration of address filters is denied without elevation
        $prog = ($rule | Get-NetFirewallApplicationFilter).Program
        if ($prog -notmatch $pattern) { continue }
        $remote = (($rule | Get-NetFirewallAddressFilter).RemoteAddress) -join ','
        if ($remote -eq 'Any') { $hits += "$($rule.DisplayName) [$(Split-Path $prog -Leaf)]" }
    }
    $hits = @($hits | Sort-Object -Unique)
    if (-not $hits) { return New-Finding Pass 'No inbound allow rule for interpreters on Public/Any with remote address Any.' }
    New-Finding Fail "$($hits.Count) rule(s): $(Join-Limited $hits)" 'Disable these rules (Disable-NetFirewallRule) or limit them to -RemoteAddress LocalSubnet.'
}

Invoke-Check -Id 'FW-03' -Category 'Firewall' -Title 'Network categories' -Severity 'Info' -Body {
    $p = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.InterfaceAlias): $($_.NetworkCategory)" })
    New-Finding Info "$(Join-Limited $p). Public is the safer category for untrusted networks."
}

# ---------------------------------------------------------------------------
# Network exposure
# ---------------------------------------------------------------------------

Invoke-Check -Id 'NET-01' -Category 'Network' -Title 'SMBv1 server disabled' -Severity 'High' -Weight 6 -Body {
    $c = Get-SmbServerConfiguration
    if ($c.EnableSMB1Protocol) { return New-Finding Fail 'EnableSMB1Protocol = True.' 'Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false' }
    New-Finding Pass 'EnableSMB1Protocol = False.'
}

Invoke-Check -Id 'NET-02' -Category 'Network' -Title 'SMB signing required, no insecure guest logons' -Severity 'Medium' -Weight 3 -Body {
    $s = Get-SmbServerConfiguration; $c = Get-SmbClientConfiguration
    $ev = "Server RequireSecuritySignature=$($s.RequireSecuritySignature); client RequireSecuritySignature=$($c.RequireSecuritySignature), EnableInsecureGuestLogons=$($c.EnableInsecureGuestLogons)."
    if ($c.EnableInsecureGuestLogons) { return New-Finding Fail $ev 'Set-SmbClientConfiguration -EnableInsecureGuestLogons $false' }
    if (-not $s.RequireSecuritySignature -or -not $c.RequireSecuritySignature) { return New-Finding Warn $ev 'Require SMB signing on server and client.' }
    New-Finding Pass $ev
}

Invoke-Check -Id 'NET-03' -Category 'Network' -Title 'Remote Desktop off or protected by NLA' -Severity 'High' -Weight 4 -Body {
    $deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $nla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    if ($deny -eq 1) { return New-Finding Pass 'Remote Desktop disabled.' }
    if ($nla -eq 1) { return New-Finding Warn 'Remote Desktop enabled with Network Level Authentication.' 'Disable RDP if unused; never expose 3389 to the internet.' }
    New-Finding Fail 'Remote Desktop enabled WITHOUT Network Level Authentication.' 'Enable NLA or disable Remote Desktop.'
}

Invoke-Check -Id 'NET-04' -Category 'Network' -Title 'Remote management services off' -Severity 'Medium' -Weight 3 -Body {
    $issues = @()
    foreach ($n in 'WinRM', 'RemoteRegistry', 'sshd', 'TlntSvr') {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s -and $s.Status.ToString() -eq 'Running') { $issues += "$n running" }
    }
    if ((Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp') -eq 1) { $issues += 'Remote Assistance allowed' }
    if (-not $issues) { return New-Finding Pass 'WinRM, RemoteRegistry, sshd, Telnet not running; Remote Assistance off.' }
    $sev = if ($issues -match 'RemoteRegistry|TlntSvr') { 'Fail' } else { 'Warn' }
    New-Finding $sev ($issues -join '; ') 'Stop and disable services that are not needed; turn off Remote Assistance (System > Remote settings).'
}

Invoke-Check -Id 'NET-05' -Category 'Network' -Title 'LLMNR and NetBIOS name resolution off' -Severity 'Medium' -Weight 3 -Body {
    $llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    $nb = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object { $_.GetValue('NetbiosOptions') })
    $nbOn = @($nb | Where-Object { $_ -ne 2 }).Count
    $ev = "LLMNR policy EnableMulticast=$(if ($null -eq $llmnr) { 'not set (on)' } else { $llmnr }); NetBIOS active on $nbOn of $($nb.Count) interface(s)."
    if ($llmnr -eq 0 -and $nbOn -eq 0) { return New-Finding Pass $ev }
    New-Finding Warn $ev 'Disable LLMNR (policy EnableMulticast=0) and NetBIOS over TCP/IP (NetbiosOptions=2) unless legacy name resolution is needed.'
}

Invoke-Check -Id 'NET-06' -Category 'Network' -Title 'Listening ports (non-loopback)' -Severity 'Info' -Body {
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } | Sort-Object LocalPort -Unique |
        ForEach-Object { "tcp/$($_.LocalPort) $($procs[[int]$_.OwningProcess])" })
    New-Finding Info "$($tcp.Count) TCP listener(s): $(Join-Limited $tcp 25)"
}

Invoke-Check -Id 'NET-07' -Category 'Network' -Title 'Hosts file not redirecting security domains' -Severity 'High' -Weight 2 -Body {
    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $entries = @(Get-Content -LiteralPath $path | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
    $sec = @($entries | Where-Object { $_ -match '(?i)(microsoft|windowsupdate|msftncsi|defender|smartscreen|avast|kaspersky|eset|bitdefender|malwarebytes|virustotal)' })
    if ($sec) { return New-Finding Fail "Suspicious entries: $(Join-Limited $sec)" 'Remove entries that block or redirect security/update domains.' }
    New-Finding Pass "$($entries.Count) active entr(y/ies). $(Join-Limited $entries 5)"
}

# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

Invoke-Check -Id 'ACC-01' -Category 'Accounts' -Title 'User Account Control enforced' -Severity 'High' -Weight 4 -Body {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua = Get-RegValue $k 'EnableLUA'; $cp = Get-RegValue $k 'ConsentPromptBehaviorAdmin'; $sd = Get-RegValue $k 'PromptOnSecureDesktop'
    $ev = "EnableLUA=$lua, ConsentPromptBehaviorAdmin=$cp, PromptOnSecureDesktop=$sd."
    if ($lua -ne 1) { return New-Finding Fail $ev 'Re-enable UAC (EnableLUA=1).' }
    if ($cp -eq 0 -or $sd -eq 0) { return New-Finding Warn $ev 'Restore the UAC default (prompt on secure desktop).' }
    New-Finding Pass $ev
}

Invoke-Check -Id 'ACC-02' -Category 'Accounts' -Title 'Built-in Administrator and Guest disabled' -Severity 'Medium' -Weight 3 -Body {
    $users = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True')
    $on = @($users | Where-Object { $_.SID -match '-50[01]$' -and -not $_.Disabled } | ForEach-Object Name)
    if ($on) { return New-Finding Fail "Enabled: $($on -join ', ')." 'Disable the built-in Administrator/Guest account.' }
    New-Finding Pass 'Built-in Administrator and Guest are disabled.'
}

Invoke-Check -Id 'ACC-03' -Category 'Accounts' -Title 'Few local administrators' -Severity 'Medium' -Weight 2 -Body {
    $grp = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
    $members = @(Get-CimAssociatedInstance -InputObject $grp -Association Win32_GroupUser)
    $active = @($members | Where-Object { -not (Get-PropValue $_ 'Disabled') } | ForEach-Object { "$($_.Domain)\$($_.Name)" })
    $ev = "$($active.Count) enabled member(s): $(Join-Limited $active)"
    if ($active.Count -le 2) { return New-Finding Pass $ev }
    New-Finding Warn $ev 'Use a standard account for daily work; keep the Administrators group minimal.'
}

Invoke-Check -Id 'ACC-04' -Category 'Accounts' -Title 'No auto-logon password in the registry' -Severity 'High' -Weight 4 -Body {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (Get-RegValue $k 'DefaultPassword') { return New-Finding Fail 'Winlogon DefaultPassword is set (plain text).' 'Remove DefaultPassword and disable AutoAdminLogon.' }
    New-Finding Pass "No DefaultPassword; AutoAdminLogon=$(Get-RegValue $k 'AutoAdminLogon')."
}

Invoke-Check -Id 'ACC-05' -Category 'Accounts' -Title 'Enabled local accounts' -Severity 'Info' -Body {
    $u = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Where-Object { -not $_.Disabled } | ForEach-Object Name)
    New-Finding Info "$($u.Count) enabled: $(Join-Limited $u). Review accounts you do not recognise."
}

# ---------------------------------------------------------------------------
# Boot and platform security
# ---------------------------------------------------------------------------

Invoke-Check -Id 'BOOT-01' -Category 'Platform' -Title 'Secure Boot enabled' -Severity 'High' -Weight 8 -Body {
    if ($env:firmware_type -and $env:firmware_type -ne 'UEFI') { return New-Finding Fail "Firmware: $env:firmware_type." 'Convert the disk to GPT (mbr2gpt), switch to UEFI, enable Secure Boot.' }
    $on = $null; $src = 'registry'
    if ($script:IsAdmin) {
        try { $on = Confirm-SecureBootUEFI; $src = 'Confirm-SecureBootUEFI' }
        catch [System.PlatformNotSupportedException] { return New-Finding Fail 'Secure Boot not supported by this firmware/VM.' 'Use UEFI firmware with Secure Boot (Gen2 VM).' }
    }
    if ($null -eq $on) { $on = (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled') -eq 1 }
    if ($on) { return New-Finding Pass "Secure Boot on ($src)." }
    New-Finding Fail "Secure Boot off ($src)." 'Enable Secure Boot in UEFI setup (CSM off, standard keys). Check boot loaders first.'
}

Invoke-Check -Id 'BOOT-02' -Category 'Platform' -Title 'TPM 2.0 present and ready' -Severity 'Medium' -Weight 4 -Body {
    if ($script:IsAdmin) {
        $t = Get-Tpm
        $ev = "Present=$($t.TpmPresent), Ready=$($t.TpmReady), Version info $($t.ManufacturerVersion)."
        if ($t.TpmPresent -and $t.TpmReady) { return New-Finding Pass $ev }
        return New-Finding Fail $ev 'Enable the (f)TPM in UEFI setup.'
    }
    $r = Invoke-ReadOnlyNative TpmInfo
    $present = $r.Text -match '(?im)^-TPM[ -](Present|vorhanden):\s*(True|Wahr)'
    $v2 = $r.Text -match '(?im)^-TPM[ -]Version:\s*2\.0'
    if ($present -and $v2) { return New-Finding Pass 'TPM 2.0 present (tpmtool).' }
    if ($r.Text -match '(?im)^-TPM[ -](Present|vorhanden):\s*(False|Falsch)') { return New-Finding Fail 'No TPM present (tpmtool).' 'Enable the (f)TPM in UEFI setup.' }
    New-Finding Warn 'tpmtool output not recognised (language?). Run elevated for Get-Tpm.' ''
}

Invoke-Check -Id 'BOOT-03' -Category 'Platform' -Title 'System drive encrypted (BitLocker)' -Severity 'High' -Weight 8 -Body {
    if ($script:IsAdmin) {
        $vols = @(Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume)
        $map = @{ 0 = 'off'; 1 = 'on'; 2 = 'unknown' }
        $ev = ($vols | Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter) protection $($map[[int]$_.ProtectionStatus])" }) -join '; '
        $sys = $vols | Where-Object { $_.DriveLetter -eq $env:SystemDrive } | Select-Object -First 1
        if ($sys -and [int]$sys.ProtectionStatus -eq 1) { return New-Finding Pass $ev }
        return New-Finding Fail $ev 'Enable BitLocker; back up the recovery key (Microsoft account and offline) first.'
    }
    $item = (New-Object -ComObject Shell.Application).NameSpace(17).ParseName($env:SystemDrive + '\')
    $v = $item.ExtendedProperty('System.Volume.BitLockerProtection')
    if ($v -eq 1) { return New-Finding Pass "BitLocker protection on for $env:SystemDrive (shell property)." }
    New-Finding Warn "Shell property BitLockerProtection=$v for $env:SystemDrive; not confirmed without elevation." 'Run elevated to confirm; enable BitLocker if it is off.'
}

Invoke-Check -Id 'BOOT-04' -Category 'Platform' -Title 'Memory integrity (HVCI) and Credential Guard running' -Severity 'Medium' -Weight 8 -Body {
    $dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard
    $run = @($dg.SecurityServicesRunning)
    $hvci = $run -contains 2; $cg = $run -contains 1
    $ev = "VBS status $($dg.VirtualizationBasedSecurityStatus) (2=running); HVCI running=$hvci; Credential Guard running=$cg."
    if ($hvci -and $cg) { return New-Finding Pass $ev }
    if ($hvci -or $cg) { return New-Finding Warn $ev 'Enable the missing feature (Windows Security > Device security > Core isolation). Check driver compatibility first.' }
    New-Finding Fail $ev 'Enable memory integrity (Core isolation). Incompatible drivers are listed on that page.'
}

Invoke-Check -Id 'BOOT-05' -Category 'Platform' -Title 'LSA protection on, WDigest off' -Severity 'High' -Weight 5 -Body {
    $ppl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    $wd = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    $ev = "RunAsPPL=$ppl; WDigest UseLogonCredential=$wd."
    if ($wd -eq 1) { return New-Finding Fail $ev 'Set WDigest UseLogonCredential=0 (plain-text credentials in memory).' }
    if ($ppl -in 1, 2) { return New-Finding Pass $ev }
    New-Finding Fail $ev 'Enable LSA protection (Windows Security > Device security > Core isolation > Local Security Authority protection).'
}

Invoke-Check -Id 'BOOT-06' -Category 'Platform' -Title 'Vulnerable driver blocklist on' -Severity 'Medium' -Weight 3 -Body {
    $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
    if ($v -eq 1) { return New-Finding Pass 'VulnerableDriverBlocklistEnable=1.' }
    if ($null -eq $v) { return New-Finding Warn 'Not set explicitly (Windows 11 default is on, but it can be switched off silently).' 'Turn on "Microsoft Vulnerable Driver Blocklist" under Core isolation.' }
    New-Finding Fail "VulnerableDriverBlocklistEnable=$v." 'Turn on "Microsoft Vulnerable Driver Blocklist" under Core isolation.'
}

# ---------------------------------------------------------------------------
# PowerShell and logging
# ---------------------------------------------------------------------------

Invoke-Check -Id 'LOG-01' -Category 'Logging' -Title 'PowerShell script block logging and process command lines' -Severity 'Medium' -Weight 4 -Body {
    $sbl = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    $cmd = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
    $ev = "ScriptBlockLogging=$sbl; ProcessCreationIncludeCmdLine=$cmd."
    if ($sbl -eq 1 -and $cmd -eq 1) { return New-Finding Pass $ev }
    $fix = 'Enable script block logging and command lines in event 4688 (policy or registry). Logs may contain secrets passed on command lines.'
    if ($sbl -eq 1 -or $cmd -eq 1) { return New-Finding Warn $ev $fix }
    New-Finding Fail $ev $fix
}

Invoke-Check -Id 'LOG-02' -Category 'Logging' -Title 'Execution policy not Unrestricted/Bypass (machine)' -Severity 'Low' -Weight 2 -Body {
    $lm = (Get-ExecutionPolicy -Scope LocalMachine).ToString()
    if ($lm -in 'Unrestricted', 'Bypass') { return New-Finding Warn "LocalMachine=$lm." 'Set-ExecutionPolicy RemoteSigned -Scope LocalMachine (elevated).' }
    New-Finding Pass "LocalMachine=$lm."
}

Invoke-Check -Id 'LOG-03' -Category 'Logging' -Title 'PowerShell 2.0 engine removed' -Severity 'Medium' -Weight 3 -RequiresAdmin -Body {
    $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction SilentlyContinue
    if ($f -and $f.State.ToString() -eq 'Enabled') { return New-Finding Fail 'PowerShell 2.0 is enabled (bypasses logging and AMSI).' 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root' }
    $state = if ($f) { $f.State } else { 'not present' }
    New-Finding Pass "PowerShell 2.0: $state."
}

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

Invoke-Check -Id 'PER-01' -Category 'Persistence' -Title 'Autostart entries signed' -Severity 'Medium' -Weight 4 -Body {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    $bad = @(); $n = 0
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $key = Get-Item $k
        foreach ($name in $key.GetValueNames()) {
            if (-not $name) { continue }
            $n++
            $exe = Resolve-Executable ([string]$key.GetValue($name))
            $sig = Get-SignatureState $exe
            if ($sig -ne 'Valid') { $bad += "$name -> $exe [$sig]" }
        }
    }
    $shell = New-Object -ComObject WScript.Shell
    foreach ($dir in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $n++
            $target = if ($f.Extension -eq '.lnk') { $shell.CreateShortcut($f.FullName).TargetPath } else { $f.FullName }
            $sig = Get-SignatureState $target
            if ($sig -ne 'Valid') { $bad += "Startup\$($f.Name) -> $target [$sig]" }
        }
    }
    if (-not $bad) { return New-Finding Pass "$n autostart entr(y/ies), all signed." }
    New-Finding Warn "$($bad.Count) of $n not validly signed: $(Join-Limited $bad)" 'Verify each entry; remove what you do not recognise (Task Manager > Startup apps).'
}

Invoke-Check -Id 'PER-02' -Category 'Persistence' -Title 'Third-party scheduled tasks point to signed, existing files' -Severity 'Medium' -Weight 4 -Body {
    $hostPattern = '(?i)\\(wscript|cscript|powershell|pwsh|cmd|mshta|conhost)\.exe$'
    $issues = @(); $n = 0
    foreach ($t in @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State.ToString() -ne 'Disabled' })) {
        foreach ($a in @($t.Actions)) {
            $exec = Get-PropValue $a 'Execute'
            if (-not $exec) { continue }
            $n++
            $exe = Resolve-Executable $exec
            $sig = Get-SignatureState $exe
            $label = "$($t.TaskPath)$($t.TaskName)"
            if ($sig -ne 'Valid') { $issues += "$label -> $exe [$sig]"; continue }
            $taskArgs = [string](Get-PropValue $a 'Arguments')
            if ($exe -match $hostPattern -and $taskArgs) {
                $m = [regex]::Match([Environment]::ExpandEnvironmentVariables($taskArgs), '(?i)([a-z]:\\[^"]+?\.(vbs|js|ps1|bat|cmd|hta))')
                if ($m.Success -and -not (Test-Path -LiteralPath $m.Groups[1].Value)) { $issues += "$label -> script missing: $($m.Groups[1].Value)" }
            }
        }
    }
    if (-not $issues) { return New-Finding Pass "$n task action(s) checked." }
    New-Finding Warn "$($issues.Count) issue(s): $(Join-Limited $issues)" 'Disable orphaned or unsigned tasks you do not recognise (Task Scheduler).'
}

Invoke-Check -Id 'PER-03' -Category 'Persistence' -Title 'Services signed, no unquoted service paths' -Severity 'Medium' -Weight 4 -Body {
    $all = @(Get-CimInstance Win32_Service)
    $unsigned = @($all | Where-Object { ($_.StartMode -eq 'Auto' -or $_.State -eq 'Running') -and $_.PathName } | ForEach-Object {
            $exe = Resolve-Executable $_.PathName
            $sig = Get-SignatureState $exe
            if ($sig -ne 'Valid') { "$($_.Name) [$sig] $exe" }
        })
    $unquoted = @($all | Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '^[^"]*\s[^"]*\.exe' -and $_.PathName -notmatch '(?i)^[a-z]:\\windows\\' } |
        ForEach-Object { "$($_.Name): $($_.PathName)" })
    $ev = "Unsigned/missing: $($unsigned.Count) $(Join-Limited $unsigned 8). Unquoted paths: $($unquoted.Count) $(Join-Limited $unquoted 5)"
    if ($unquoted) { return New-Finding Fail $ev 'Quote the ImagePath of the listed services (HKLM\SYSTEM\CurrentControlSet\Services\<name>).' }
    if ($unsigned) { return New-Finding Warn $ev 'Verify the vendor of each unsigned service; remove what you do not need.' }
    New-Finding Pass 'All auto/running services signed; no unquoted paths.'
}

Invoke-Check -Id 'PER-04' -Category 'Persistence' -Title 'No Winlogon, AppInit or IFEO hijacks' -Severity 'High' -Weight 5 -Body {
    $issues = @()
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shellValue = [string](Get-RegValue $wl 'Shell'); $userinit = [string](Get-RegValue $wl 'Userinit')
    if ($shellValue -and $shellValue -notmatch '^(?i)explorer\.exe$') { $issues += "Winlogon Shell=$shellValue" }
    if ($userinit -and $userinit -notmatch '^(?i)[a-z]:\\windows\\system32\\userinit\.exe,?$') { $issues += "Winlogon Userinit=$userinit" }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $dlls = [string](Get-RegValue $k 'AppInit_DLLs')
        if ($dlls.Trim() -and (Get-RegValue $k 'LoadAppInit_DLLs') -eq 1) { $issues += "AppInit_DLLs=$dlls" }
    }
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
        $d = $_.GetValue('Debugger'); if ($d) { $issues += "IFEO $($_.PSChildName) Debugger=$d" }
    }
    if (-not $issues) { return New-Finding Pass 'Winlogon defaults, no AppInit DLLs, no IFEO debuggers.' }
    New-Finding Fail (Join-Limited $issues) 'Investigate each entry; these are classic persistence/hijack points.'
}

Invoke-Check -Id 'PER-05' -Category 'Persistence' -Title 'No WMI event subscriptions' -Severity 'High' -Weight 4 -Body {
    $c = @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction Stop | Where-Object { $_.Name -ne 'SCM Event Log Consumer' } |
        ForEach-Object { "$($_.CimClass.CimClassName) '$($_.Name)'" })
    if (-not $c) { return New-Finding Pass 'Only the Windows default consumer present.' }
    New-Finding Fail "Consumers: $(Join-Limited $c)" 'Inspect root\subscription consumers, filters and bindings; remove unknown ones.'
}

Invoke-Check -Id 'PER-06' -Category 'Persistence' -Title 'No locally generated root CAs with private key' -Severity 'Low' -Weight 3 -Body {
    $certs = @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root | Where-Object { $_.HasPrivateKey } |
        ForEach-Object { "$(($_.Subject -split ',')[0]) ($($_.Thumbprint.Substring(0, 8))...)" } | Sort-Object -Unique)
    if (-not $certs) { return New-Finding Pass 'No trusted root certificate with a local private key.' }
    New-Finding Warn "$($certs.Count): $(Join-Limited $certs)" 'A trusted root whose private key sits on this machine enables TLS interception if stolen. Remove roots you do not need.'
}

# ---------------------------------------------------------------------------
# Software
# ---------------------------------------------------------------------------

Invoke-Check -Id 'SW-01' -Category 'Software' -Title 'Installed software up to date (winget)' -Severity 'High' -Weight 8 -Body {
    if ($SkipWinget) { return New-Finding Info 'Skipped (-SkipWinget).' }
    $r = Invoke-ReadOnlyNative WingetList
    $lines = @($r.Text -split "`n" | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ -and $_ -notmatch '^\s*[-\\|/]\s*$' })
    $sep = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^-{10,}') { $sep = $i; break } }
    if ($sep -lt 0) {
        if ($r.ExitCode -eq 0) { return New-Finding Pass "No upgrades listed. $(($lines | Select-Object -Last 1))" }
        return New-Finding Warn "winget exit code $($r.ExitCode): $(Join-Limited ($lines | Select-Object -Last 3) 3)" 'Run "winget upgrade" once interactively (source agreements).'
    }
    $pkgs = @()
    for ($i = $sep + 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\d+\s' -or $lines[$i] -notmatch '\S\s{2,}\S') { break }
        $pkgs += ($lines[$i] -replace '\s{2,}', ' | ')
    }
    if (-not $pkgs) { return New-Finding Pass 'No upgrades listed.' }
    $ev = "$($pkgs.Count) upgrade(s) available: $(Join-Limited $pkgs 15)"
    $fix = 'Review and run: winget upgrade --id <Id>. Prioritise browsers, runtimes (.NET, Java, Python), Git, archivers, media players, VPN/remote tools.'
    if ($pkgs.Count -le 5) { return New-Finding Warn $ev $fix }
    New-Finding Fail $ev $fix
}

# ---------------------------------------------------------------------------
# System integrity
# ---------------------------------------------------------------------------

Invoke-Check -Id 'INT-01' -Category 'Integrity' -Title 'All kernel drivers in System32\drivers signed' -Severity 'High' -Weight 5 -Body {
    $files = @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'System32\drivers') -Filter *.sys -File)
    $bad = @($files | ForEach-Object { $s = Get-SignatureState $_.FullName; if ($s -ne 'Valid') { "$($_.Name) [$s, $($_.LastWriteTime.ToString('yyyy-MM-dd'))]" } })
    if (-not $bad) { return New-Finding Pass "$($files.Count) driver file(s), all validly signed." }
    New-Finding Fail "$($bad.Count) of $($files.Count) not validly signed: $(Join-Limited $bad)" 'Back up the file for analysis, then repair with sfc /scannow (elevated).'
}

Invoke-Check -Id 'INT-02' -Category 'Integrity' -Title 'Component store healthy (DISM /ScanHealth)' -Severity 'Medium' -Weight 3 -RequiresAdmin -DeepOnly -Body {
    $r = Invoke-ReadOnlyNative DismScan
    $last = ($r.Text -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' '
    if ($r.ExitCode -ne 0) { return New-Finding Fail "Exit code $($r.ExitCode): $last" 'DISM /Online /Cleanup-Image /RestoreHealth (elevated).' }
    if ($r.Text -match '(?i)repairable|reparierbar') { return New-Finding Fail $last 'DISM /Online /Cleanup-Image /RestoreHealth (elevated).' }
    New-Finding Pass $last
}

Invoke-Check -Id 'INT-03' -Category 'Integrity' -Title 'Protected system files intact (sfc /verifyonly)' -Severity 'Medium' -Weight 3 -RequiresAdmin -DeepOnly -Body {
    $r = Invoke-ReadOnlyNative SfcVerify
    # sfc returns exit code 0 even when it finds violations: the text decides
    if ($r.Text -match '(?i)did not find any integrity violations|keine Integrit') { return New-Finding Pass 'No integrity violations.' }
    if ($r.Text -match '(?i)found integrity violations|Integrit.{1,3}tsverletzungen gefunden') {
        return New-Finding Fail 'Integrity violations found. Details: CBS.log, lines with "[SR]" or "Corrupt file".' 'Back up affected files, then sfc /scannow (elevated).'
    }
    New-Finding Warn "Output not recognised (exit $($r.ExitCode))." 'Check C:\Windows\Logs\CBS\CBS.log.'
}

# ---------------------------------------------------------------------------
# Score and report
# ---------------------------------------------------------------------------

$scored = @($script:Results | Where-Object { $_.Weight -gt 0 -and $_.Status -in 'Pass', 'Warn', 'Fail' })
$possible = 0; $earned = 0.0
foreach ($r in $scored) {
    $possible += $r.Weight
    if ($r.Status -eq 'Pass') { $earned += $r.Weight } elseif ($r.Status -eq 'Warn') { $earned += $r.Weight / 2 }
}
$score = if ($possible -gt 0) { [int][math]::Round(100 * $earned / $possible) } else { 0 }
$script:Meta['Score'] = $score
$script:Meta['ScoredWeight'] = $possible

if ($Redact) {
    $pairs = @(
        @{ From = $env:USERPROFILE; To = '<PROFILE>' }, @{ From = $env:COMPUTERNAME; To = '<HOST>' }, @{ From = $env:USERNAME; To = '<USER>' }
    )
    foreach ($r in $script:Results) {
        foreach ($p in $pairs) {
            if ($p.From) {
                $r.Evidence = $r.Evidence -replace [regex]::Escape($p.From), $p.To
                $r.Fix = $r.Fix -replace [regex]::Escape($p.From), $p.To
            }
        }
    }
    $script:Meta['Computer'] = '<HOST>'; $script:Meta['User'] = '<USER>'
}

function ConvertTo-MdCell([string]$Text) {
    if ($null -eq $Text) { return '' }
    return (($Text -replace '\|', '\|') -replace "`r?`n", '<br>')
}

function Write-Report {
    param([Parameter(Mandatory)][string]$Directory)
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $res = $script:Results.ToArray()
    $counts = @{}; foreach ($s in 'Pass', 'Warn', 'Fail', 'Info', 'Skipped', 'Error') { $counts[$s] = @($res | Where-Object { $_.Status -eq $s }).Count }

    $md = New-Object System.Collections.Generic.List[string]
    $md.Add("# Windows security audit: $($script:Meta.Computer)")
    $md.Add('')
    $md.Add('| | |'); $md.Add('| :--- | :--- |')
    foreach ($k in $script:Meta.Keys) { $md.Add("| $k | $(ConvertTo-MdCell ([string]$script:Meta[$k])) |") }
    $md.Add('')
    $md.Add("**Score: $score / 100**: Pass $($counts.Pass), Warn $($counts.Warn), Fail $($counts.Fail), Info $($counts.Info), Skipped $($counts.Skipped), Error $($counts.Error).")
    $md.Add('')
    $md.Add('Score = weighted share of passed checks (Warn counts half; Info, Skipped and Error are not scored). It is a heuristic, not a certification.')
    $md.Add('')
    $md.Add('## Findings to act on')
    $md.Add('')
    $act = @($res | Where-Object { $_.Status -in 'Fail', 'Warn', 'Error' } |
        Sort-Object @{ Expression = { $script:SeverityRank[$_.Severity] }; Descending = $true }, @{ Expression = { $_.Status -eq 'Fail' }; Descending = $true }, Id)
    if ($act) {
        $md.Add('| ID | Severity | Status | Check | Evidence | Fix |'); $md.Add('| :--- | :--- | :--- | :--- | :--- | :--- |')
        foreach ($r in $act) { $md.Add("| $($r.Id) | $($r.Severity) | $($r.Status) | $(ConvertTo-MdCell $r.Title) | $(ConvertTo-MdCell $r.Evidence) | $(ConvertTo-MdCell $r.Fix) |") }
    }
    else { $md.Add('Nothing to act on.') }
    $md.Add('')
    $md.Add('## All checks')
    foreach ($cat in @($res | ForEach-Object Category | Select-Object -Unique)) {
        $md.Add(''); $md.Add("### $cat"); $md.Add('')
        $md.Add('| ID | Status | Check | Evidence |'); $md.Add('| :--- | :--- | :--- | :--- |')
        foreach ($r in @($res | Where-Object { $_.Category -eq $cat })) { $md.Add("| $($r.Id) | $($r.Status) | $(ConvertTo-MdCell $r.Title) | $(ConvertTo-MdCell $r.Evidence) |") }
    }
    $md.Add('')
    $md.Add('_Generated by winsec-audit. The tool only reads system state; it changed nothing._')

    Set-Content -LiteralPath (Join-Path $Directory 'report.md') -Value $md -Encoding UTF8
    $json = [ordered]@{ meta = $script:Meta; summary = $counts; results = $res }
    Set-Content -LiteralPath (Join-Path $Directory 'report.json') -Value ($json | ConvertTo-Json -Depth 5) -Encoding UTF8
}

$hostTag = if ($Redact) { 'host' } else { $env:COMPUTERNAME }
$reportDir = Join-Path $OutputPath ('{0}-{1}' -f $hostTag, (Get-Date -Format 'yyyyMMdd_HHmmss'))
Write-Report -Directory $reportDir

if (-not $Quiet) {
    Write-Host ''
    Write-Host "Score $score/100 - report: $reportDir" -ForegroundColor White
    if (-not $script:IsAdmin) { Write-Host 'Some checks were skipped: run elevated for the full audit.' -ForegroundColor DarkGray }
}

if ($FailOn -ne 'None') {
    $threshold = $script:SeverityRank[$FailOn]
    $hit = @($script:Results | Where-Object { $_.Status -eq 'Fail' -and $script:SeverityRank[$_.Severity] -ge $threshold })
    if ($hit) { exit 3 }
}
exit 0
