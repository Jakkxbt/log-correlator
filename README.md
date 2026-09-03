<p align="center">
  <img src="assets/banner.png" alt="CobraSEC · Blue Arsenal · log-correlator" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/CobraSEC-Blue_Arsenal-22d3ee?style=for-the-badge&labelColor=0a0f1a">
  <img src="https://img.shields.io/badge/License-MIT-38bdf8?style=for-the-badge&labelColor=0a0f1a">
  <img src="https://img.shields.io/badge/Python-3.x-7dd3fc?style=for-the-badge&labelColor=0a0f1a">
  <img src="https://img.shields.io/badge/Status-Active-16a34a?style=for-the-badge&labelColor=0a0f1a">
</p>

<h1 align="center">log-correlator</h1>
<p align="center"><b>Stateful multi-source log correlation</b><br><sub><i>CobraSEC · Attack in order to Defend.</i></sub></p>

---


Ingests auth.log / syslog / kern.log / dmesg and applies stateful
correlation rules to chain events into actionable alerts:

  SSH brute force → SSH success            (compromise chain)
  New user + sudo grant                    (privilege escalation)
  Cron modification + payload download     (persistence)
  Firewall disabled / iptables flush       (defense evasion)
  Failed sudo → root session               (lateral escalation)
  Kernel module load / taint               (rootkit precursor)
  Package changes, service tampering       (system integrity)

Features:
  - 20+ built-in correlation rules with MITRE ATT&CK mappings
  - Time-windowed state tracking with sliding windows
  - Alert deduplication / throttling per source
  - JSON alert export (SIEM/ELK friendly)
  - Live tail mode (follow log like -f) or one-shot analysis
  - Custom rule file support (JSON)

Usage:
  python3 log_correlator.py --analyze /var/log/auth.log
  python3 log_correlator.py --analyze-dir /var/log --since 24h
  python3 log_correlator.py --tail /var/log/auth.log
  python3 log_correlator.py --analyze /var/log/auth.log --output alerts.json
  python3 log_correlator.py --rules custom_rules.json --analyze /var/log/syslog

## Requirements

- Python 3.8+ (standard library only — no external dependencies)

## Usage

```
python3 log_correlator.py --help
```

```
usage: log_correlator.py [-h] [--analyze ANALYZE] [--analyze-dir ANALYZE_DIR]
                         [--tail TAIL] [--stdin] [--rules RULES]
                         [--output OUTPUT] [--quiet] [--since SINCE]

Log Correlator — Lightweight SIEM

options:
  -h, --help            show this help message and exit
  --analyze ANALYZE     Analyze a log file
  --analyze-dir ANALYZE_DIR
                        Analyze all logs in a directory
  --tail TAIL           Follow a log file live (-f mode)
  --stdin               Read log lines from stdin
  --rules RULES         Custom rules JSON file (overrides defaults)
  --output, -o OUTPUT   Export alerts to JSON
  --quiet, -q
  --since SINCE         Only analyze lines newer than this (e.g. 24h, 30m)
```

## Notes

- Defensive tooling: run only on systems you own or are authorized to assess.
- Read-only by design where possible; review flags before use on production hosts.
- Some checks (disk sectors, process memory, raw sockets) require root.
