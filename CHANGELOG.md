# Changelog

All notable changes to BlackSentinel Strike will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.0] - 2026-10-15

### Added
- **War Room**: one-command, scope-gated engagement orchestrator
  (`modules/orchestrator.py`) with a hard authorization gate (operator +
  authorization reference + confirmation phrase), per-target scope
  enforcement, refusal of indiscriminate targets, dry-run by default, an
  operator-artifact rollback ledger, and a full audited engagement report.
- **AI / LLM Red-Team** module (`modules/ai_redteam.py`): canary-based
  resilience testing of authorized chat endpoints against the OWASP Top-10
  for LLM Applications (prompt injection, system-prompt leakage, data
  exfiltration, jailbreak, excessive agency), with a resilience score.
- **ARSENAL** sidebar section exposing previously-unreachable core modules in
  the GUI: Brute Force (12 services), Network Attacks, Wireless Kit, Forensic
  Kit, Social Eng Kit.
- 22 new headless tests for the orchestrator and AI red-team harness.

### Changed
- Added a shared `_run_async` GUI helper to remove thread boilerplate.
- Bumped version to 4.1.0 across all version strings.

### Fixed
- Removed 54 unused imports (F401) across modules and tests.

## [4.0.0] - 2025-01-01

### Added
- War Exploit automated attack pipeline
- Multi-vector attack capability
- 131 CVE database
- 7-stage attack pipeline
- Real-time vulnerability detection
- Automated exploitation framework
- Post-exploitation enumeration
- Encrypted vault with AES-256-CBC
- IP Jumper for automatic IP rotation
- MAC address randomization
- DNS switcher with presets
- Professional dark orange/black theme
- Multi-language support (English/Spanish)
- Docker deployment support
- Kubernetes deployment support
- Comprehensive documentation

### Changed
- Renamed from Phantom Pentest Suite to BlackSentinel Strike
- Updated vault path to ~/.blacksentinel-strike/vault/
- Improved color scheme consistency
- Enhanced GUI responsiveness
- Optimized module imports

### Fixed
- Vault path synchronization across all modules
- Color consistency in GUI elements
- Quick start launcher functionality
- Documentation accuracy

## [3.5.0] - 2024-12-01

### Added
- Social engineering module
- Wireless attack capabilities
- Network attack framework
- Forensic analysis tools
- Audit logging system
- Scope authorization module
- Notification system
- Rate limiting and stealth mode

### Changed
- Improved error handling
- Enhanced module organization
- Updated dependencies

## [3.0.0] - 2024-09-01

### Added
- Initial release as Phantom Pentest Suite
- Core penetration testing modules
- AES-256 encryption
- GUI interface
- Report generation

## [2.0.0] - 2024-06-01

### Added
- Beta release
- Basic scanning capabilities
- Simple GUI

## [1.0.0] - 2024-03-01

### Added
- Initial development
- Proof of concept
