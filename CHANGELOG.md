# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-05

### Added

- Desktop app for macOS and Windows (Electron + React).
- SSH scanning with key files or the SSH agent, an import from `~/.ssh/config`, and passphrases stored in the OS keychain.
- Health checks: load, memory, swap, disks, top processes, reboot required.
- Threat detection: SSH brute force (per IP and distributed), root password logins, SYN floods, connection floods, HTTP floods, martian packets, `rp_filter` and SYN cookie hardening, ARP and gateway MAC spoofing, extra UID-0 accounts, processes running from temp directories, crypto-miner names.
- Pinned SSH host keys, with a critical alert when a server's key changes.
- Automatic and manual fail2ban bans, with whitelist protection, optional fleet-wide bans and a ban log with unban.
- Desktop notifications, per-server score, and history sparklines.

[Unreleased]: https://github.com/PraiseKeyz/sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PraiseKeyz/sentinel/releases/tag/v0.1.0
