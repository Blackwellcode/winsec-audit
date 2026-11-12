<#
.SYNOPSIS
    Static guard: proves from the AST that winsec-audit.ps1 cannot change system state.

.DESCRIPTION
    Fails (exit 1) when the audit script contains
      - a command outside the read-only allowlist (verbs Get/Test/Select/..., script functions, a few exact names),
      - file writes (New-Item, Set-Content, redirection) outside Write-Report,
      - '&' invocations outside Invoke-ReadOnlyNative / Invoke-Check,
      - direct calls of *.exe files,
      - Write-* other than Host/Output/Verbose/Warning/Error/Information (e.g. Write-EventLog),
      - .NET/COM methods that write, copy, move, create, delete, start, stop or kill,
      - New-Object / ::new() of file and stream types,
      - COM objects outside the allowlist,
      - native arguments that repair, install or configure.
#>
[CmdletBinding()]
param([string]$Path)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Resolved here, not as a param default: with [CmdletBinding()], Windows PowerShell 5.1 leaves $PSScriptRoot
# empty while it evaluates param defaults under "powershell -File".
if (-not $Path) { $Path = Join-Path $PSScriptRoot '..\winsec-audit.ps1' }

$file = (Resolve-Path -LiteralPath $Path).Path
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors)
$violations = New-Object System.Collections.Generic.List[string]
foreach ($e in @($parseErrors)) { $violations.Add("line $($e.Extent.StartLineNumber): parse error: $($e.Message)") }

$readVerbs = 'Get', 'Test', 'Select', 'Where', 'ForEach', 'Sort', 'Group', 'Measure', 'Format', 'ConvertTo', 'ConvertFrom', 'Join', 'Split', 'Resolve', 'Compare', 'Confirm'
# Write-* only for the console streams; Write-EventLog, Write-Progress etc. are not allowed
$exact = 'New-Object', 'Add-Member', 'Out-String', 'Out-Null', 'Set-StrictMode', '%', '?', 'where', 'foreach', 'select', 'sort',
'Write-Host', 'Write-Output', 'Write-Verbose', 'Write-Warning', 'Write-Error', 'Write-Information'
$writeOnlyInReport = 'New-Item', 'Set-Content'
$nativeHosts = 'Invoke-ReadOnlyNative', 'Invoke-Check'
$comAllow = 'Microsoft.Update.AutoUpdate', 'Shell.Application', 'WScript.Shell'
$denyMethods = 'Delete', 'DeleteSubKey', 'DeleteSubKeyTree', 'DeleteValue', 'SetValue', 'CreateSubKey', 'Kill', 'Start',
'WriteAllText', 'WriteAllBytes', 'WriteAllLines', 'AppendAllText', 'MoveTo', 'CopyTo', 'Encrypt', 'Decrypt', 'SetAccessControl',
'Run', 'Exec', 'RegWrite', 'RegDelete', 'ShellExecute', 'InvokeVerb', 'Save', 'InvokeMethod', 'Put',
'Create', 'Copy', 'Move', 'Replace', 'OpenWrite', 'CreateDirectory', 'Stop', 'Terminate', 'ChangeStartMode', 'Remove'
# .NET types that open or create files/streams (exceptions such as FileNotFoundException are fine)
$denyTypes = '(?i)(Stream|Writer|File|Directory)'
$allowTypes = '(?i)Exception$'
$denyArgs = '(?i)^(/scannow|/restorehealth|/startcomponentcleanup|/enable-feature|/disable-feature|/set|/delete|/offline|install|uninstall|upgrade --all|--all|-on|-off|-forceuninstall|/f|-force)$'

$functions = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object Name)

function Get-EnclosingFunction($Node) {
    $p = $Node.Parent
    while ($p) {
        if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $p.Name }
        $p = $p.Parent
    }
    return $null
}

# 1) commands
foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
    $line = $c.Extent.StartLineNumber
    $fn = Get-EnclosingFunction $c
    $name = $c.GetCommandName()
    if ($c.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand) {
        if ($fn -notin $nativeHosts) { $violations.Add("line ${line}: '&' invocation outside $($nativeHosts -join '/')") }
        continue
    }
    if ($c.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot) { $violations.Add("line ${line}: dot-sourcing"); continue }
    if (-not $name) { $violations.Add("line ${line}: dynamic command name"); continue }
    if ($name -match '(?i)\.(exe|com|bat|cmd)$') { $violations.Add("line ${line}: direct native call '$name'"); continue }
    if ($name -in $writeOnlyInReport) {
        if ($fn -ne 'Write-Report') { $violations.Add("line ${line}: '$name' outside Write-Report") }
        continue
    }
    if ($name -eq 'New-Object') {
        $els = $c.CommandElements
        $typeName = $null
        $isCom = $false
        for ($i = 1; $i -lt $els.Count; $i++) {
            if ($els[$i] -is [System.Management.Automation.Language.CommandParameterAst]) {
                if ($els[$i].ParameterName -eq 'Strict' -or $i + 1 -ge $els.Count) { continue }
                if ($els[$i].ParameterName -eq 'ComObject') {
                    $isCom = $true
                    $val = $els[$i + 1].Extent.Text.Trim("'", '"')
                    if ($val -notin $comAllow) { $violations.Add("line ${line}: COM object '$val' not allowlisted") }
                }
                elseif ($els[$i].ParameterName -eq 'TypeName') { $typeName = $els[$i + 1].Extent.Text }
                $i++
            }
            elseif (-not $typeName) { $typeName = $els[$i].Extent.Text }
        }
        if (-not $isCom -and $typeName) {
            $typeName = ($typeName.Trim("'", '"') -split '[\(\[]')[0]
            if ($typeName -match $denyTypes -and $typeName -notmatch $allowTypes) { $violations.Add("line ${line}: New-Object of file/stream type '$typeName'") }
        }
        continue
    }
    if ($name -in $exact -or $name -in $functions) { continue }
    $verb = ($name -split '-')[0]
    if ($name -match '-' -and $verb -in $readVerbs) { continue }
    $violations.Add("line ${line}: command '$name' is not on the read-only allowlist")
}

# 2) .NET / COM methods
foreach ($m in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
    $member = $m.Member.Extent.Text.Trim("'", '"')
    if ($member -in $denyMethods) { $violations.Add("line $($m.Extent.StartLineNumber): method '$member' can change state") }
    # [IO.StreamWriter]::new(...) and similar constructors
    if ($m.Static -and $member -eq 'new' -and $m.Expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
        $typeName = $m.Expression.TypeName.FullName
        if ($typeName -match $denyTypes -and $typeName -notmatch $allowTypes) { $violations.Add("line $($m.Extent.StartLineNumber): constructor of file/stream type '$typeName'") }
    }
}

# 3) redirection to files
foreach ($r in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst] }, $true)) {
    if ((Get-EnclosingFunction $r) -ne 'Write-Report') { $violations.Add("line $($r.Extent.StartLineNumber): file redirection outside Write-Report") }
}

# 4) native argument strings
foreach ($s in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)) {
    if ($s.Value -match $denyArgs) { $violations.Add("line $($s.Extent.StartLineNumber): forbidden argument '$($s.Value)'") }
}

# 5) native allowlist must stay exactly these programs
$exeStrings = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -match '(?i)^[\w-]+\.exe$' }, $true) | ForEach-Object { $_.Value.ToLowerInvariant() } | Sort-Object -Unique)
$allowedExe = 'dism.exe', 'sfc.exe', 'tpmtool.exe', 'winget.exe'
foreach ($e in $exeStrings) { if ($e -notin $allowedExe) { $violations.Add("native program '$e' not in the allowlist ($($allowedExe -join ', '))") } }

if ($violations.Count) {
    Write-Host "READ-ONLY GUARD FAILED ($($violations.Count)):" -ForegroundColor Red
    $violations | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}
Write-Host "Read-only guard passed: $file" -ForegroundColor Green
exit 0
