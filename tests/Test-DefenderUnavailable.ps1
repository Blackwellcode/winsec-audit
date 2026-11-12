<#
.SYNOPSIS
    Defender checks must end as Error, never as Pass, when Defender data cannot be read.

.DESCRIPTION
    Shadows two Defender cmdlets with functions for one audit run (functions take precedence over cmdlets):
      - Get-MpPreference throws (preferences not readable),
      - Get-MpComputerStatus returns a status object whose signature and scan ages are $null.
    Casting $null gives 0/False, which used to turn into a Pass. The test requires Error for every check that
    depends on the missing data. Nothing on the system is read or changed through Defender in this run.
#>
[CmdletBinding()]
param(
    # Folder for the temporary report (default: the user's temp folder)
    [string]$WorkDir = [IO.Path]::GetTempPath()
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$audit = Join-Path $PSScriptRoot '..\winsec-audit.ps1'
$out = Join-Path $WorkDir ("winsec-defender-" + [guid]::NewGuid().ToString('N'))
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$problems = New-Object System.Collections.Generic.List[string]

# check id -> required status
$expect = [ordered]@{
    'DEF-02' = 'Error'   # AntivirusSignatureAge $null
    'DEF-03' = 'Error'   # QuickScanAge/FullScanAge $null
    'DEF-04' = 'Error'   # preferences not readable
    'DEF-05' = 'Error'
    'DEF-06' = $(if ($isAdmin) { 'Error' } else { 'Skipped' })
    'DEF-09' = 'Error'
}

function global:Get-MpPreference { throw (New-Object System.UnauthorizedAccessException('simulated: preferences not readable')) }
function global:Get-MpComputerStatus {
    [pscustomobject]@{
        AMServiceEnabled = $true; AntivirusEnabled = $true; RealTimeProtectionEnabled = $true; BehaviorMonitorEnabled = $true
        IoavProtectionEnabled = $true; OnAccessProtectionEnabled = $true; IsTamperProtected = $true
        AMProductVersion = 'simulated'; AMEngineVersion = 'simulated'; AntivirusSignatureVersion = 'simulated'
        AntivirusSignatureAge = $null; QuickScanAge = $null; FullScanAge = $null
    }
}

Write-Host "Elevated: $isAdmin"
try {
    & $audit -OutputPath $out -SkipWinget -Quiet
    if ($LASTEXITCODE -ne 0) { $problems.Add("audit exit code $LASTEXITCODE") }
    $dir = @(Get-ChildItem -LiteralPath $out -Directory) | Select-Object -First 1
    if (-not $dir) { throw 'No report folder written.' }
    $results = @((Get-Content -LiteralPath (Join-Path $dir.FullName 'report.json') -Raw | ConvertFrom-Json).results)
    foreach ($id in $expect.Keys) {
        $r = @($results | Where-Object { $_.Id -eq $id }) | Select-Object -First 1
        if (-not $r) { $problems.Add("$id missing from report"); continue }
        $mark = if ($r.Status -eq $expect[$id]) { 'ok  ' } else { 'FAIL' }
        Write-Host ("[{0}] {1,-7} {2,-7} (expected {3}) {4}" -f $mark, $id, $r.Status, $expect[$id], $r.Evidence)
        if ($r.Status -ne $expect[$id]) { $problems.Add("${id}: status $($r.Status), expected $($expect[$id])") }
    }
}
finally {
    Remove-Item -LiteralPath function:global:Get-MpPreference, function:global:Get-MpComputerStatus
    if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }
}

if ($problems.Count) {
    Write-Host 'DEFENDER-UNAVAILABLE TEST FAILED:' -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}
Write-Host "Defender-unavailable test passed: $($expect.Count) check(s) end as expected, none as Pass." -ForegroundColor Green
exit 0
