# Linux Security Audit Toolkit

## Dependency Packages:

- rkhunter
- clamscan
- Apparmor
- auditd
- tcpdump

## Overview
A bash script that automates a simple Linux security audit across rootkit detection, mandatory access control status, SUID/SGID binary review, kernel audit subsystem coverage, and basic network capture analysis — and outputs a single human-readable report.

Built out of a manual host security audit and converted into repeatable tooling so the same checks run consistently across multiple machines instead of being a one-off exercise.

## What it checks

| Category | Tooling | What it surfaces |
|---|---|---|
| Rootkits / known malware signatures | `rkhunter`, `clamscan` | Known rootkit signatures, suspicious file properties |
| Mandatory Access Control | `aa-status` (AppArmor) | Enforced vs. complain-mode profiles, unconfined processes |
| Privilege escalation surface | custom `find` audit | World-writable files, SUID/SGID binaries outside an expected baseline |
| Audit subsystem | `auditctl`, `/etc/audit/rules.d/` | Whether `auditd` rules cover key syscalls (execve, file deletion, privilege changes) |
| Network | `tcpdump` capture + parsing | Unexpected outbound connections, plaintext credential exposure |

## Usage
```bash
sudo ./audit.sh --full                # run all checks
sudo ./audit.sh --quick                # rkhunter + SUID audit only
sudo ./audit.sh --pcap-duration 300    # capture 5 minutes of traffic for analysis
```

Output is written to `./reports/audit-<hostname>-<date>.md`, with findings tagged `INFO` / `WARN` / `CRITICAL`.

## Sample finding output
```
[WARN] SUID binary not in baseline allowlist: /usr/local/bin/legacy-tool
[INFO] AppArmor: 12 profiles enforced, 2 in complain mode
[CRITICAL] auditd: no rule watching /etc/shadow for write access
```

## Why this exists
Manual security audits are easy to do once and hard to do consistently. This script turns a checklist into something re-runnable after every patch cycle or config change, with diffable output so regressions are visible immediately.

## Roadmap
- [ ] YAML-based baseline config (per-host SUID/SGID allowlists)
- [ ] CIS Benchmark mapping for each check
- [ ] JSON output mode for SIEM ingestion
## Disclaimer
Intended for auditing systems you own or are explicitly authorized to assess.

## License
MIT
