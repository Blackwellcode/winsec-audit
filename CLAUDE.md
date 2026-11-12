# winsec-audit – Projektanker

Read-only Security-Audit für Windows 10/11, ein PowerShell-Skript (`winsec-audit.ps1`), kompatibel mit Windows PowerShell 5.1 und PowerShell 7. Herkunft: das manuelle Audit vom 2026-11-09, archiviert unter `F:\archiv\windows-security-audit-20261112` (dort auch das schreibende Härtungsskript `Invoke-SecurityHardening.ps1`, das hier bewusst nicht übernommen wurde).

## Invarianten (nicht verhandelbar)

- Das Skript ändert **nie** Systemzustand. Neue Checks verwenden nur lesende Cmdlets.
- Externe Programme laufen ausschließlich über `Invoke-ReadOnlyNative` mit der festen Tabelle `$script:NativeCommands`.
- Dateien schreibt nur `Write-Report`.
- Vor jedem Commit:
  - `.\tests\Test-ReadOnly.ps1` (Exit 0)
  - `.\tests\Test-GuardSelf.ps1` (Exit 0)
  - `.\tests\Test-Smoke.ps1` (Exit 0, Fingerprint unverändert)
- Guard-Regeln nicht aufweichen, um einen Check durchzubringen: Der Check wird angepasst, nicht der Guard.

## Konventionen

- Code, Report und README auf Englisch (öffentliches GitHub-Repo).
- Neuer Check: `Invoke-Check -Id <BEREICH-NN> … -Body { … New-Finding Pass|Warn|Fail|Info "<Beleg>" "<Fix>" }`. Der Beleg nennt den gemessenen Wert, nicht nur die Bewertung.
- Lokalisierte Ausgaben (z. B. tpmtool, sfc) immer für Deutsch **und** Englisch matchen.
- Fehler in Checks werden nicht verschluckt: `Invoke-Check` setzt den Status `Error` mit Exception-Typ und Meldung.
