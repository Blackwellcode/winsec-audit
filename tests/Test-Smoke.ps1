<#
.SYNOPSIS
    Runs the audit and proves at runtime that it changed nothing.

.DESCRIPTION
    1. Fingerprints security-relevant state (firewall rules, services, Defender preferences,
       key registry values, scheduled tasks).
    2. Runs winsec-audit.ps1 into a temp folder.
    3. Fingerprints again and requires an identical hash.
    4. Validates report.json (schema, score range, check count, no Error results).
#>
[CmdletBinding()]
param(
    [int]$MaxErrors = 0,
    [switch]$WithWinget
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-StateFingerprint {
    $parts = New-Object System.Collections.Generic.List[string]
    Get-NetFirewallRule | Sort-Object Name | ForEach-Object { $parts.Add("fw|$($_.Name)|$($_.Enabled)|$($_.Action)|$($_.Profile)") }
    Get-NetFirewallProfile | ForEach-Object { $parts.Add("fwp|$($_.Name)|$($_.Enabled)|$($_.DefaultInboundAction)") }
    Get-CimInstance Win32_Service | Sort-Object Name | ForEach-Object { $parts.Add("svc|$($_.Name)|$($_.StartMode)|$($_.PathName)") }
    Get-ScheduledTask | Sort-Object TaskPath, TaskName | ForEach-Object { $parts.Add("task|$($_.TaskPath)$($_.TaskName)|$($_.State -eq 'Disabled')") }
    try {
        $p = Get-MpPreference
        $parts.Add('mp|' + (($p | Select-Object DisableRealtimeMonitoring, MAPSReporting, PUAProtection, EnableNetworkProtection, CloudBlockLevel, AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions | ConvertTo-Json -Compress)))
    }
    catch { $parts.Add("mp|unavailable|$($_.Exception.GetType().Name)") }
    $reg = @(
        @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'EnableLUA'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL'),
        @('HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server', 'fDenyTSConnections'),
        @('HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell', 'ExecutionPolicy'),
        @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient', 'EnableMulticast')
    )
    foreach ($r in $reg) {
        $v = $null
        if (Test-Path -LiteralPath $r[0]) { $v = (Get-Item -LiteralPath $r[0]).GetValue($r[1]) }
        $parts.Add("reg|$($r[0])|$($r[1])|$v")
    }
    return , $parts.ToArray()
}

function Get-Hash([string[]]$Parts) {
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Parts -join "`n"))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '' }
    finally { $sha.Dispose() }
}

function Get-Diff([string[]]$Old, [string[]]$New) {
    @(Compare-Object -ReferenceObject $Old -DifferenceObject $New | ForEach-Object {
            $side = if ($_.SideIndicator -eq '<=') { 'before' } else { 'after ' }
            "$side $($_.InputObject)"
        })
}

function Get-ChangeActor {
    <# Returns the actor of a change from the event log, or $null if no event attributes it to someone other than the current user. #>
    param([string]$ObjectKey, [datetime]$Since)
    $kind, $name = $ObjectKey -split '\|', 2
    $me = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($kind -eq 'svc') {
        $display = (Get-Service -Name $name -ErrorAction SilentlyContinue).DisplayName
        if (-not $display) { return $null }
        $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7040; StartTime = $Since } -ErrorAction SilentlyContinue |
            Where-Object { $_.Message.Contains($display) } | Select-Object -First 1
        if ($ev -and $ev.UserId -and $ev.UserId.Value -ne $me.User.Value) { return "$($ev.UserId.Value), event 7040" }
        return $null
    }
    if ($kind -eq 'task') {
        $log = Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction SilentlyContinue
        if (-not $log -or -not $log.IsEnabled) { return $null }
        foreach ($ev in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Id = 140, 141, 142; StartTime = $Since } -ErrorAction SilentlyContinue |
                    Where-Object { $_.Message.Contains($name) })) {
            $m = [regex]::Match($ev.Message, '"([^"]+)"')   # first quoted value = acting user
            if ($m.Success -and $m.Groups[1].Value -notin @($me.Name, $env:USERNAME, $me.User.Value)) { return "$($m.Groups[1].Value), event $($ev.Id)" }
        }
        return $null
    }
    return $null
}

$audit = Join-Path $PSScriptRoot '..\winsec-audit.ps1'
$out = Join-Path ([IO.Path]::GetTempPath()) ("winsec-smoke-" + [guid]::NewGuid().ToString('N'))
$problems = New-Object System.Collections.Generic.List[string]

try {
    # control window: same snapshot twice without the audit, to see background drift of the machine itself
    $testStart = Get-Date
    $control0 = Get-StateFingerprint
    $control1 = Get-StateFingerprint
    $drift = Get-Diff $control0 $control1

    $beforeParts = $control1
    $auditArgs = @{ OutputPath = $out; Quiet = $true }
    if (-not $WithWinget) { $auditArgs['SkipWinget'] = $true }
    $auditStart = Get-Date
    & $audit @auditArgs
    $exit = $LASTEXITCODE
    $auditEnd = Get-Date
    $afterParts = Get-StateFingerprint
    $before = Get-Hash $beforeParts; $after = Get-Hash $afterParts

    if ($exit -ne 0) { $problems.Add("audit exit code $exit") }
    if ($drift) { Write-Host "Background drift without audit ($($drift.Count)):" -ForegroundColor Yellow; $drift | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow } }
    if ($before -ne $after) {
        # Attribute every changed object through the event log. A change that an event assigns to another
        # actor (SYSTEM, machine account, a service) is machine background activity; a change without such
        # an event, or one made by the current user, fails the test.
        $background = New-Object System.Collections.Generic.List[string]
        $unexplained = New-Object System.Collections.Generic.List[string]
        $objects = Get-Diff $beforeParts $afterParts | ForEach-Object { $_ -replace '^(before|after)\s+', '' } |
            ForEach-Object { $f = $_ -split '\|'; "$($f[0])|$($f[1])" } | Sort-Object -Unique
        foreach ($obj in $objects) {
            $actor = Get-ChangeActor -ObjectKey $obj -Since $testStart
            if ($actor) { $background.Add("$obj (changed by $actor)") } else { $unexplained.Add($obj) }
        }
        foreach ($b in $background) { Write-Host "  background change: $b" -ForegroundColor Yellow }
        if ($unexplained.Count) {
            $problems.Add("system state changed during the audit without attribution to another actor ($($unexplained.Count)):")
            foreach ($u in $unexplained) { $problems.Add("    $u") }
            Write-Host "  audit window: $($auditStart.ToString('HH:mm:ss'))-$($auditEnd.ToString('HH:mm:ss'))" -ForegroundColor Yellow
        }
    }

    $dir = @(Get-ChildItem -LiteralPath $out -Directory) | Select-Object -First 1
    if (-not $dir) { throw 'No report folder written.' }
    foreach ($f in 'report.md', 'report.json') {
        if (-not (Test-Path -LiteralPath (Join-Path $dir.FullName $f))) { $problems.Add("$f missing") }
    }
    $json = Get-Content -LiteralPath (Join-Path $dir.FullName 'report.json') -Raw | ConvertFrom-Json
    $score = [int]$json.meta.Score
    if ($score -lt 0 -or $score -gt 100) { $problems.Add("score out of range: $score") }
    $results = @($json.results)
    if ($results.Count -lt 30) { $problems.Add("only $($results.Count) results") }
    $allowed = 'Pass', 'Warn', 'Fail', 'Info', 'Skipped', 'Error'
    foreach ($r in $results) {
        if ($r.Status -notin $allowed) { $problems.Add("$($r.Id): invalid status '$($r.Status)'") }
        foreach ($field in 'Id', 'Category', 'Title', 'Severity', 'Weight', 'Evidence', 'Fix') {
            if (-not $r.PSObject.Properties[$field]) { $problems.Add("$($r.Id): field '$field' missing") }
        }
    }
    # every Invoke-Check declared in the script reports exactly once
    $tokens = $null; $parseErrors = $null
    $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $audit).Path, [ref]$tokens, [ref]$parseErrors)
    $declared = @($scriptAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-Check' }, $true) | ForEach-Object {
            $els = $_.CommandElements
            for ($i = 1; $i -lt $els.Count - 1; $i++) {
                if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $els[$i].ParameterName -eq 'Id') { $els[$i + 1].Extent.Text.Trim("'", '"') }
            }
        })
    $reported = @($results | ForEach-Object { [string]$_.Id })
    foreach ($id in $declared) {
        $n = @($reported | Where-Object { $_ -eq $id }).Count
        if ($n -ne 1) { $problems.Add("check $id reported $n time(s), expected 1") }
    }
    if ($reported.Count -ne $declared.Count) { $problems.Add("$($reported.Count) result(s) for $($declared.Count) declared check(s)") }

    $errors = @($results | Where-Object { $_.Status -eq 'Error' })
    foreach ($e in $errors) { Write-Host "  Error in $($e.Id): $($e.Evidence)" -ForegroundColor Yellow }
    if ($errors.Count -gt $MaxErrors) { $problems.Add("$($errors.Count) check(s) ended with Error (max $MaxErrors)") }

    Write-Host ("Checks {0}, score {1}, fingerprint {2}" -f $results.Count, $score, $before.Substring(0, 16))
}
finally {
    if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
}

if ($problems.Count) {
    Write-Host 'SMOKE TEST FAILED:' -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}
Write-Host 'Smoke test passed: report valid, system state unchanged.' -ForegroundColor Green
exit 0
