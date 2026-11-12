# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Five read-only checks carried over from the original manual audit (now 49):
  - DEF-09 email and removable drive scanning;
  - NET-08 Point and Print driver installation restricted to administrators (PrintNightmare);
  - NET-09 legacy SMB1/Telnet/TFTP client features (elevated);
  - LOG-04 maximum size of the Security, PowerShell and Defender event logs;
  - LOG-05 process creation auditing, proven by a recorded event 4688 (elevated).

### Security
- `dism`, `sfc` and `tpmtool` are started from `%SystemRoot%\System32` (Sysnative under 32-bit PowerShell) instead of being resolved through `PATH`.
- `winget.exe` is taken from the installed App Installer package and must carry a valid Microsoft signature; the per-user execution alias on `PATH` is no longer used.

### Fixed
- DEF-07 (*No active threats*) reports **Error** when the Defender threat query fails instead of reporting **Pass**.

### Tests
- Read-only guard: `Write-*` is limited to Host/Output/Verbose/Warning/Error/Information (`Write-EventLog` and `Write-Progress` fail); `New-Object` and `::new()` of file and stream types are rejected; the method deny list adds `Create`, `Copy`, `Move`, `Replace`, `OpenWrite`, `CreateDirectory`, `Stop`, `Terminate`, `ChangeStartMode` and `Remove`.
- Guard self-test: one negative sample per new rule (32 samples), runs the guard under the same PowerShell edition, `-WorkDir` for the sample files.
- Smoke test: every `Invoke-Check` declared in the script must appear exactly once in `report.json`.

### CI
- GitHub Actions pinned to commit SHAs; PSScriptAnalyzer pinned with `-RequiredVersion`.

### Changed
- License holder: Blackwell Code.

## [0.1.0] - 2026-11-10

### Added
- Initial release: 44 read-only checks (patching, Microsoft Defender, firewall, network exposure, accounts, boot integrity, logging, persistence, software updates, system integrity), `report.md` and `report.json`, `-Deep`, `-SkipWinget`, `-Redact`, `-FailOn`.
- Static read-only guard, guard self-test and runtime smoke test (state fingerprint before/after) in CI under Windows PowerShell 5.1 and PowerShell 7.
