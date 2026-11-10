<#
.SYNOPSIS
    Negative tests for Test-ReadOnly.ps1: every sample must be rejected, the clean sample accepted.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$guard = Join-Path $PSScriptRoot 'Test-ReadOnly.ps1'
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("winsec-guard-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null

$samples = [ordered]@{
    'clean'            = @{ Expect = 0; Code = 'Get-Service | Where-Object { $_.Status } | Out-Null' }
    'set-itemproperty' = @{ Expect = 1; Code = "Set-ItemProperty -Path 'HKLM:\X' -Name A -Value 1" }
    'remove-item'      = @{ Expect = 1; Code = 'Remove-Item C:\temp\x' }
    'invoke-expr'      = @{ Expect = 1; Code = 'Invoke-Expression "calc"' }
    'start-process'    = @{ Expect = 1; Code = 'Start-Process notepad' }
    'native-direct'    = @{ Expect = 1; Code = 'sfc.exe /scannow' }
    'ampersand'        = @{ Expect = 1; Code = '& $x' }
    'registry-method'  = @{ Expect = 1; Code = '$k.SetValue("a", 1)' }
    'file-write'       = @{ Expect = 1; Code = '[IO.File]::WriteAllText("x", "y")' }
    'redirect'         = @{ Expect = 1; Code = '"x" > C:\temp\x.txt' }
    'set-content'      = @{ Expect = 1; Code = 'Set-Content -Path x -Value y' }
    'com-object'       = @{ Expect = 1; Code = 'New-Object -ComObject Scripting.FileSystemObject' }
    'repair-arg'       = @{ Expect = 1; Code = '$a = @("/Online", "/Cleanup-Image", "/RestoreHealth")' }
    'unknown-exe'      = @{ Expect = 1; Code = '$e = "reg.exe"' }
    'mp-preference'    = @{ Expect = 1; Code = 'Set-MpPreference -DisableRealtimeMonitoring $true' }
    'cim-method'       = @{ Expect = 1; Code = 'Invoke-CimMethod -ClassName Win32_Process -MethodName Create' }
}

$failed = 0
try {
    foreach ($name in $samples.Keys) {
        $file = Join-Path $tmp "$name.ps1"
        Set-Content -LiteralPath $file -Value $samples[$name].Code -Encoding UTF8
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $guard -Path $file *> $null
        $code = $LASTEXITCODE
        $ok = $code -eq $samples[$name].Expect
        if (-not $ok) { $failed++ }
        Write-Host ('[{0}] {1,-17} exit {2} (expected {3})' -f $(if ($ok) { 'ok  ' } else { 'FAIL' }), $name, $code, $samples[$name].Expect) -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
    }
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force
}

if ($failed) { Write-Host "Guard self-test failed: $failed sample(s)." -ForegroundColor Red; exit 1 }
Write-Host "Guard self-test passed: $($samples.Count) sample(s)." -ForegroundColor Green
exit 0
