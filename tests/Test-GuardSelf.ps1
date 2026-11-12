<#
.SYNOPSIS
    Negative tests for Test-ReadOnly.ps1: every sample must be rejected, the clean sample accepted.
#>
[CmdletBinding()]
param(
    # Folder for the temporary sample files (default: the user's temp folder)
    [string]$WorkDir = [IO.Path]::GetTempPath()
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$guard = Join-Path $PSScriptRoot 'Test-ReadOnly.ps1'
# Run the guard in the same edition as this test (powershell.exe 5.1 or pwsh 7)
$hostExe = if ($PSVersionTable.PSEdition -eq 'Core') { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'powershell.exe' }
$tmp = Join-Path $WorkDir ("winsec-guard-" + [guid]::NewGuid().ToString('N'))
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
    'clean-write'      = @{ Expect = 0; Code = 'Write-Verbose "x"; Write-Warning "y"; throw (New-Object System.IO.FileNotFoundException("z"))' }
    'write-eventlog'   = @{ Expect = 1; Code = 'Write-EventLog -LogName Application -Source x -EventId 1 -Message y' }
    'write-progress'   = @{ Expect = 1; Code = 'Write-Progress -Activity x' }
    'stream-writer'    = @{ Expect = 1; Code = '$w = New-Object System.IO.StreamWriter("C:\temp\x.txt")' }
    'stream-typename'  = @{ Expect = 1; Code = '$w = New-Object -TypeName IO.FileStream -ArgumentList "x", "Create"' }
    'stream-new'       = @{ Expect = 1; Code = '$w = [IO.StreamWriter]::new("x")' }
    'file-create'      = @{ Expect = 1; Code = '[IO.File]::Create("x")' }
    'file-copy'        = @{ Expect = 1; Code = '[IO.File]::Copy("a", "b")' }
    'file-move'        = @{ Expect = 1; Code = '[IO.File]::Move("a", "b")' }
    'file-replace'     = @{ Expect = 1; Code = '[IO.File]::Replace("a", "b", "c")' }
    'file-openwrite'   = @{ Expect = 1; Code = '[IO.File]::OpenWrite("x")' }
    'create-directory' = @{ Expect = 1; Code = '[IO.Directory]::CreateDirectory("x")' }
    'service-stop'     = @{ Expect = 1; Code = '(Get-Service Spooler).Stop()' }
    'wmi-terminate'    = @{ Expect = 1; Code = '(Get-CimInstance Win32_Process -Filter "Name=''x''").Terminate()' }
    'start-mode'       = @{ Expect = 1; Code = '$svc.ChangeStartMode("Disabled")' }
    'remove-method'    = @{ Expect = 1; Code = '$acl.Remove($rule)' }
}

$failed = 0
try {
    foreach ($name in $samples.Keys) {
        $file = Join-Path $tmp "$name.ps1"
        Set-Content -LiteralPath $file -Value $samples[$name].Code -Encoding UTF8
        & $hostExe -NoProfile -ExecutionPolicy Bypass -File $guard -Path $file *> $null
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
