# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Five read-only checks carried over from the original manual audit (now 49):
  - DEF-09 email and removable drive scanning, extended cloud check (`CloudExtendedTimeout` 50 s);
  - NET-08 Point and Print driver installation restricted to administrators (PrintNightmare);
  - NET-09 legacy Telnet/TFTP clients (elevated; `EnablePending` counts as on);
  - LOG-04 maximum size of the Security, PowerShell and Defender event logs (a log that cannot be read or does not exist is reported as Info, not scored);
  - LOG-05 process creation auditing, proven by a recorded event 4688 (elevated; Retain log mode warns; a switch-off within the last 24 h is not detectable and the finding says so).
### Security
- `dism`, `sfc` and `tpmtool` are started from `%SystemRoot%\System32` (Sysnative under 32-bit PowerShell) instead of being resolved through `PATH`.
- `winget.exe` is taken from the installed App Installer package and must carry a valid Microsoft signature; the per-user execution alias on `PATH` is no longer used.

### Fixed
- DEF-07 (*No active threats*) reports **Error** when the Defender threat query fails instead of reporting **Pass**.
- Unreadable Defender data no longer yields a false **Pass**: `Get-MpPreference` is queried separately from `Get-MpComputerStatus`, DEF-04/05/06/09 require readable preferences, and DEF-02/03/04/09 end as **Error** when a value is not reported (a `$null` cast to 0/False used to pass).

### Tests
- Read-only guard: `Write-*` is limited to Host/Output/Verbose/Warning/Error/Information (`Write-EventLog` and `Write-Progress` fail); `New-Object` and `::new()` of file and stream types are rejected; the method deny list adds `Create`, `Copy`, `Move`, `Replace`, `OpenWrite`, `CreateDirectory`, `Stop`, `Terminate`, `ChangeStartMode` and `Remove`.
- Guard self-test: one negative sample per new rule (32 samples), runs the guard under the same PowerShell edition, `-WorkDir` for the sample files.
- Smoke test: every `Invoke-Check` declared in the script must appear exactly once in `report.json`; parse errors of the script fail the test.
- New `Test-DefenderUnavailable.ps1`: shadows `Get-MpPreference` (throws) and `Get-MpComputerStatus` (ages `$null`) and requires **Error** for DEF-02/03/04/05/09 (DEF-06 when elevated).

### CI
- GitHub Actions pinned to commit SHAs; PSScriptAnalyzer pinned with `-RequiredVersion`.

### Changed
- License holder: Blackwell Code.
- NET-01 *SMBv1 disabled* also reads the `SMB1Protocol` optional feature (SMBv1 client) when elevated. SMBv1 is scored only in NET-01.

## [0.1.0] - 2026-11-10

### Added
- Initial release: 44 read-only checks (patching, Microsoft Defender, firewall, network exposure, accounts, boot integrity, logging, persistence, software updates, system integrity), `report.md` and `report.json`, `-Deep`, `-SkipWinget`, `-Redact`, `-FailOn`.
- Static read-only guard, guard self-test and runtime smoke test (state fingerprint before/after) in CI under Windows PowerShell 5.1 and PowerShell 7.
