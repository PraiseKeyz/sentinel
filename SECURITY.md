# Security policy

Sentinel holds SSH access to its users' servers, so we take vulnerabilities in it seriously.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub instead: go to the repository's **Security** tab and choose **Report a vulnerability**.

Please include:

- what an attacker could do, and under which conditions,
- steps to reproduce, or a proof of concept,
- the Sentinel version, and your OS.

We aim to acknowledge reports within 3 days and to ship a fix for confirmed critical issues within 14 days. We'll credit you in the release notes unless you'd rather stay anonymous.

## In scope

- Command injection into remote commands, or anything that makes Sentinel run commands other than the read-only probe and `fail2ban-client banip/unbanip`.
- Ways to make Sentinel ban the user's own IP, a whitelisted IP or a monitored server.
- Leaks of private keys, passphrases or host data, including through the renderer, IPC or logs.
- Bypassing SSH host-key verification.
- Escaping the renderer sandbox or abusing the preload bridge.

## Out of scope

- Missed detections or false positives. Please open a normal issue for these.
- Attacks that need an already-compromised local machine or server.
- Problems in fail2ban, OpenSSH or other third-party software. Report those upstream.

## Supported versions

Until 1.0, only the latest release gets security fixes.
