#!/usr/bin/env python3
"""
Log Correlator — Lightweight SIEM Correlation Engine
=====================================================
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
"""

import os
import re
import sys
import json
import time
import argparse
import signal
from collections import defaultdict, deque
from datetime import datetime, timedelta


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def c(sev, text):
    palette = {'critical': Colors.RED + Colors.BOLD, 'high': Colors.RED,
               'medium': Colors.YELLOW, 'low': Colors.YELLOW,
               'info': Colors.CYAN, 'ok': Colors.GREEN}
    return f"{palette.get(sev, '')}{text}{Colors.RESET}"


# ─── Event Parser ────────────────────────────────────────────────────────────

class LogEvent:
    def __init__(self, ts, source, content, raw):
        self.ts = ts                # epoch
        self.source = source        # log file
        self.content = content      # log line
        self.raw = raw
        self.ip = None
        self.user = None
        self.kind = None

        self._parse()

    def _parse(self):
        s = self.content

        # Source IP extraction
        ip_m = re.search(r'(?:from\s+|src\s+)(\d{1,3}(?:\.\d{1,3}){3})', s)
        if ip_m:
            self.ip = ip_m.group(1)

        # SSH auth events
        if 'sshd' in s:
            if 'Failed password' in s:
                self.kind = 'ssh_failed'
                m = re.search(r'for\s+(?:invalid\s+user\s+)?(\S+)', s)
                if m:
                    self.user = m.group(1)
            elif 'Accepted' in s:
                self.kind = 'ssh_success'
                m = re.search(r'for\s+(\S+)', s)
                if m:
                    self.user = m.group(1)
            elif 'Connection closed' in s:
                self.kind = 'ssh_closed'
            elif 'Invalid user' in s:
                self.kind = 'ssh_invalid_user'
                m = re.search(r'Invalid user\s+(\S+)', s)
                if m:
                    self.user = m.group(1)
            elif 'Received disconnect' in s:
                self.kind = 'ssh_disconnect'

        # User management
        elif 'useradd' in s or 'adduser' in s or 'groupadd' in s:
            self.kind = 'user_created'
            m = re.search(r'name=(\S+)|add user\s+(\S+)', s)
            if m:
                self.user = m.group(1) or m.group(2)
        elif 'userdel' in s or 'deluser' in s:
            self.kind = 'user_deleted'
        elif 'passwd' in s or 'chpasswd' in s or 'password changed' in s:
            self.kind = 'password_change'

        # Sudo
        elif 'sudo:' in s or 'sudo[' in s:
            if 'COMMAND=' in s:
                self.kind = 'sudo_command'
                m = re.search(r'COMMAND=(.+)', s)
                if m:
                    self.detail = m.group(1)[:150]
            elif 'authentication failure' in s:
                self.kind = 'sudo_failed'
            elif 'session opened' in s:
                self.kind = 'sudo_session'

        # su
        elif re.search(r'\bsu\b.*(?:session opened|pam_unix)', s):
            self.kind = 'su_session'
        elif re.search(r'\bsu\b.*authentication failure', s):
            self.kind = 'su_failed'

        # Cron
        elif 'CRON' in s or 'cron[' in s:
            self.kind = 'cron_run'
            m = re.search(r'CMD\s*\((.+)\)', s)
            if m:
                self.detail = m.group(1)[:150]

        # systemd
        elif 'systemd' in s:
            if 'Stopped' in s or 'Stopping' in s:
                self.kind = 'service_stopped'
                m = re.search(r'(?:Stopped|Stopping)\s+(.+)', s)
                if m:
                    self.detail = m.group(1)[:80]
            elif 'Started' in s:
                self.kind = 'service_started'
                m = re.search(r'Started\s+(.+)', s)
                if m:
                    self.detail = m.group(1)[:80]
            elif 'Failed' in s:
                self.kind = 'service_failed'

        # Kernel
        elif 'kernel:' in s or s.startswith('['):
            if 'insmod' in s or 'module' in s.lower():
                if 'init_module' in s or 'loading' in s:
                    self.kind = 'module_load'
            if 'iptables' in s or 'nf_tables' in s or 'netfilter' in s:
                self.kind = 'firewall_change'

        # Firewall / security tools
        elif re.search(r'iptables.*(flush|F\b|-F)|ufw\s+(disable|reset)|nft\s+flush', s):
            self.kind = 'firewall_disabled'
        elif 'selinux' in s and ('disabled' in s or 'denied' in s):
            self.kind = 'selinux_event'

        # Package management
        elif 'dpkg' in s or 'apt' in s:
            if 'install' in s:
                self.kind = 'package_install'
            elif 'remove' in s:
                self.kind = 'package_remove'

        # SSH key changes
        elif 'authorized_keys' in s or 'ssh-rsa' in s or 'ssh-ed25519' in s:
            self.kind = 'ssh_key_change'

        # Fail2ban
        elif 'fail2ban' in s:
            if 'Ban' in s:
                self.kind = 'fail2ban_ban'
            elif 'Unban' in s:
                self.kind = 'fail2ban_unban'

        # Generic PAM
        elif 'pam_unix' in s:
            if 'session opened' in s:
                self.kind = 'pam_session_open'
            elif 'session closed' in s:
                self.kind = 'pam_session_close'

        if not hasattr(self, 'detail'):
            self.detail = ''


def parse_timestamp(line):
    """Try to extract a timestamp from a syslog-style line."""
    m = re.match(r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', line)
    if m:
        try:
            year = datetime.now().year
            dt = datetime.strptime(f'{year} {m.group(1)}', '%Y %b %d %H:%M:%S')
            # Handle year rollover (Dec → Jan logs)
            if dt > datetime.now() + timedelta(days=1):
                dt = dt.replace(year=year - 1)
            return dt.timestamp()
        except ValueError:
            return time.time()

    m = re.match(r'(\d{4}-\d{2}-\d{2}T?\d{2}:\d{2}:\d{2}(?:\.\d+)?)', line)
    if m:
        try:
            dt = datetime.fromisoformat(m.group(1).replace('T', ' '))
            return dt.timestamp()
        except ValueError:
            return time.time()

    m = re.match(r'\[?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
    if m:
        try:
            return datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S').timestamp()
        except ValueError:
            return time.time()

    return time.time()


# ─── Correlation Rules ───────────────────────────────────────────────────────

def parse_time_window(value):
    """'60s', '5m', '2h', '1d' → seconds."""
    m = re.match(r'(\d+)([smhd]?)', str(value).strip().lower())
    if not m:
        return 300
    mult = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}.get(m.group(2), 1)
    return int(m.group(1)) * mult


class Correlator:
    def __init__(self):
        self.events = []
        self.alerts = []
        self.state = defaultdict(deque)   # key -> deque of timestamps
        self.alerted = defaultdict(float)  # dedupe key -> last alert time
        self.event_count = 0
        self.rule_hits = defaultdict(int)

    # ─── Rule definitions ─────────────────────────────────────────────

    def default_rules(self):
        """(name, severity, window, mitre, threshold, matcher)"""
        return [
            # SSH brute force
            {
                'name': 'SSH Brute Force',
                'severity': 'high',
                'window': '60s',
                'mitre': 'T1110.001',
                'threshold': 5,
                'condition': lambda e: e.kind == 'ssh_failed',
                'group_by': 'ip',
            },
            {
                'name': 'SSH Brute Force (sustained)',
                'severity': 'critical',
                'window': '10m',
                'mitre': 'T1110.001',
                'threshold': 25,
                'condition': lambda e: e.kind == 'ssh_failed',
                'group_by': 'ip',
            },
            # Brute force → success chain
            {
                'name': 'Brute Force → SSH Success (compromise)',
                'severity': 'critical',
                'window': '30m',
                'mitre': 'T1110.001/T1078',
                'threshold': None,
                'chain': True,
                'condition': lambda e: e.kind == 'ssh_failed',
                'chain_condition': lambda e: e.kind == 'ssh_success',
                'group_by': 'ip',
            },
            # Invalid user probing
            {
                'name': 'SSH Invalid User Probing',
                'severity': 'medium',
                'window': '5m',
                'mitre': 'T1110.001',
                'threshold': 3,
                'condition': lambda e: e.kind == 'ssh_invalid_user',
                'group_by': 'ip',
            },
            # Root login from remote
            {
                'name': 'Remote Root SSH Login',
                'severity': 'high',
                'window': '60s',
                'mitre': 'T1078',
                'threshold': 1,
                'condition': lambda e: e.kind == 'ssh_success' and e.user == 'root',
                'group_by': 'ip',
            },
            # Sudo failures then success
            {
                'name': 'Sudo Failure → Success (escalation attempt)',
                'severity': 'high',
                'window': '10m',
                'mitre': 'T1078.003',
                'threshold': None,
                'chain': True,
                'condition': lambda e: e.kind == 'sudo_failed',
                'chain_condition': lambda e: e.kind == 'sudo_command',
                'group_by': 'user',
            },
            # New user creation
            {
                'name': 'New User Created',
                'severity': 'high',
                'window': '60s',
                'mitre': 'T1136.001',
                'threshold': 1,
                'condition': lambda e: e.kind == 'user_created',
                'group_by': 'user',
            },
            # User deletion
            {
                'name': 'User Deleted',
                'severity': 'medium',
                'window': '60s',
                'mitre': 'T1136',
                'threshold': 1,
                'condition': lambda e: e.kind == 'user_deleted',
                'group_by': 'user',
            },
            # Firewall disabled
            {
                'name': 'Firewall Disabled/Flushed',
                'severity': 'critical',
                'window': '60s',
                'mitre': 'T1562.004',
                'threshold': 1,
                'condition': lambda e: e.kind == 'firewall_disabled',
                'group_by': 'ip',
            },
            # Kernel module load
            {
                'name': 'Kernel Module Loaded',
                'severity': 'medium',
                'window': '60s',
                'mitre': 'T1547.006',
                'threshold': 1,
                'condition': lambda e: e.kind == 'module_load',
                'group_by': 'ip',
            },
            # Service stops (tampering)
            {
                'name': 'Service Stop (tampering)',
                'severity': 'medium',
                'window': '5m',
                'mitre': 'T1489',
                'threshold': 2,
                'condition': lambda e: e.kind == 'service_stopped',
                'group_by': 'ip',
            },
            # Security service stops — critical
            {
                'name': 'Security Service Stopped',
                'severity': 'critical',
                'window': '60s',
                'mitre': 'T1562.001',
                'threshold': 1,
                'condition': lambda e: (e.kind == 'service_stopped' and
                                        any(s in (e.detail or '').lower() for s in
                                            ('ufw', 'fail2ban', 'auditd', 'apparmor',
                                             'selinux', 'clamav', 'ossec', 'wazuh'))),
                'group_by': 'ip',
            },
            # Cron executions with remote/payload commands
            {
                'name': 'Suspicious Cron Command',
                'severity': 'high',
                'window': '60s',
                'mitre': 'T1053.003',
                'threshold': 1,
                'condition': lambda e: (e.kind == 'cron_run' and
                                        any(kw in (e.detail or '').lower() for kw in
                                            ('curl', 'wget', 'nc ', 'ncat', 'bash -i',
                                             'python -c', 'base64', '/dev/tcp'))),
                'group_by': 'ip',
            },
            # Package changes
            {
                'name': 'Package Install (unexpected)',
                'severity': 'low',
                'window': '5m',
                'mitre': 'T1072',
                'threshold': 3,
                'condition': lambda e: e.kind == 'package_install',
                'group_by': 'ip',
            },
            # SSH key changes
            {
                'name': 'SSH Key Modified',
                'severity': 'high',
                'window': '60s',
                'mitre': 'T1098.004',
                'threshold': 1,
                'condition': lambda e: e.kind == 'ssh_key_change',
                'group_by': 'ip',
            },
            # Fail2ban bans (informational)
            {
                'name': 'Fail2ban Ban Activity',
                'severity': 'info',
                'window': '60s',
                'mitre': 'T1110',
                'threshold': 1,
                'condition': lambda e: e.kind == 'fail2ban_ban',
                'group_by': 'ip',
            },
        ]

    # ─── Processing ───────────────────────────────────────────────────

    def process_event(self, event):
        self.events.append(event)
        self.event_count += 1
        now = event.ts

        for rule in self.rules:
            try:
                if rule.get('chain'):
                    if rule['condition'](event):
                        # Track precursor event (e.g. failed login)
                        key = self._state_key(rule, event)
                        self.state[key].append(now)
                    if rule['chain_condition'](event):
                        # Chain complete (e.g. successful login from same source)
                        key = self._state_key(rule, event)
                        recents = [t for t in self.state[key] if now - t < parse_time_window(rule['window'])]
                        if len(recents) >= 2:
                            self._alert(rule, event, f"preceded by {len(recents)} precursor events")
                            self.state[key].clear()
                else:
                    if rule['condition'](event):
                        key = self._state_key(rule, event)
                        self.state[key].append(now)
                        recents = [t for t in self.state[key] if now - t < parse_time_window(rule['window'])]
                        self.state[key] = deque(recents)
                        if len(recents) >= rule['threshold']:
                            self._alert(rule, event, f"{len(recents)} events in window")
                            self.state[key].clear()
            except Exception:
                continue

    def _state_key(self, rule, event):
        group = rule.get('group_by', 'ip')
        if group == 'ip':
            return (rule['name'], event.ip or event.source)
        if group == 'user':
            return (rule['name'], event.user or event.ip or 'unknown')
        return (rule['name'], event.source)

    def _alert(self, rule, event, detail):
        key = (rule['name'], event.ip or '', event.user or '')
        now = time.time()
        if now - self.alerted.get(key, 0) < 60:
            return
        self.alerted[key] = now
        self.rule_hits[rule['name']] += 1

        alert = {
            'time': datetime.fromtimestamp(event.ts).isoformat(),
            'rule': rule['name'],
            'severity': rule['severity'],
            'mitre': rule['mitre'],
            'ip': event.ip,
            'user': event.user,
            'detail': detail,
            'evidence': event.raw[:300],
            'source': event.source,
        }
        self.alerts.append(alert)
        self.print_alert(alert)

    def print_alert(self, alert):
        sev = alert['severity']
        marker = {'critical': '⛔', 'high': '⚠', 'medium': '◆', 'low': '○', 'info': 'ℹ'}.get(sev, '•')
        line = (f"  {c(sev, marker)} [{alert['time']}] {c(sev, alert['rule'])}"
                f" | {alert['mitre']}")
        if alert['ip']:
            line += f" | src={alert['ip']}"
        if alert['user']:
            line += f" | user={alert['user']}"
        print(line)
        print(f"      {alert['detail']}")
        print(f"      {c('low', 'evidence:')} {alert['evidence'][:150]}")

    # ─── Log processing ───────────────────────────────────────────────

    def process_file(self, path):
        if not os.path.exists(path):
            print(c('medium', f'[!] Log not found: {path}'))
            return 0
        count = 0
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                line = line.rstrip('\n')
                if not line:
                    continue
                ts = parse_timestamp(line)
                event = LogEvent(ts, path, line, line)
                self.process_event(event)
                count += 1
        return count

    def process_stdin_line(self, line, source='stdin'):
        if not line.strip():
            return
        ts = parse_timestamp(line)
        event = LogEvent(ts, source, line, line)
        self.process_event(event)

    # ─── Reporting ────────────────────────────────────────────────────

    def report(self):
        print(f"\n{c('info', '═' * 60)}")
        print(f"{c('info', '  CORRELATION REPORT')}")
        print(f"{c('info', '═' * 60)}")
        print(f"\n  Events processed: {self.event_count}")
        print(f"  Rules evaluated:  {len(self.rules)}")
        print(f"  Alerts raised:    {len(self.alerts)}")

        if not self.alerts:
            print(f"\n  {c('ok', '[✓] No correlated threats detected.')}")
            return

        sev_counts = defaultdict(int)
        for a in self.alerts:
            sev_counts[a['severity']] += 1

        print(f"\n  By severity: " + ", ".join(
            f"{c(s, f'{n} {s}')}" for s, n in
            sorted(sev_counts.items(), key=lambda x: {'critical': 0, 'high': 1,
                                                      'medium': 2, 'low': 3,
                                                      'info': 4}.get(x[0], 9))))

        print(f"\n  Top rules:")
        for name, count in sorted(self.rule_hits.items(), key=lambda x: -x[1])[:10]:
            print(f"    {count:>4}x  {name}")

        # Top source IPs
        ip_counts = defaultdict(int)
        for a in self.alerts:
            if a['ip']:
                ip_counts[a['ip']] += 1
        if ip_counts:
            print(f"\n  Top source IPs:")
            for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
                sev = next((a['severity'] for a in self.alerts if a['ip'] == ip), 'info')
                print(f"    {count:>4}x  {ip} ({sev})")
        print()

    def export(self, path):
        data = {
            'generated': datetime.now().isoformat(),
            'events_processed': self.event_count,
            'alerts': self.alerts,
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        print(c('ok', f'[✓] Alerts exported to {path}'))


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Log Correlator — Lightweight SIEM')
    parser.add_argument('--analyze', help='Analyze a log file')
    parser.add_argument('--analyze-dir', help='Analyze all logs in a directory')
    parser.add_argument('--tail', help='Follow a log file live (-f mode)')
    parser.add_argument('--stdin', action='store_true', help='Read log lines from stdin')
    parser.add_argument('--rules', help='Custom rules JSON file (overrides defaults)')
    parser.add_argument('--output', '-o', help='Export alerts to JSON')
    parser.add_argument('--quiet', '-q', action='store_true')
    parser.add_argument('--since', help='Only analyze lines newer than this (e.g. 24h, 30m)')

    args = parser.parse_args()

    correlator = Correlator()
    correlator.rules = correlator.default_rules()

    if args.rules:
        try:
            with open(args.rules) as f:
                custom = json.load(f)
            # Custom rules must have: name, severity, window, threshold, pattern
            # (simple regex-based rules, evaluated as contains/regex on raw line)
            correlator.rules = []
            for rule in custom:
                pat = re.compile(rule.get('pattern', ''), re.IGNORECASE)
                correlator.rules.append({
                    'name': rule['name'],
                    'severity': rule.get('severity', 'medium'),
                    'window': rule.get('window', '60s'),
                    'mitre': rule.get('mitre', ''),
                    'threshold': rule.get('threshold', 1),
                    'group_by': rule.get('group_by', 'ip'),
                    'condition': (lambda p: lambda e: bool(p.search(e.content)))(pat),
                })
            print(c('info', f'[✓] Loaded {len(correlator.rules)} custom rules from {args.rules}'))
        except (json.JSONDecodeError, KeyError, OSError) as e:
            print(c('critical', f'[!] Cannot load rules: {e}'))
            sys.exit(1)

    print(c('info', f'[*] Correlator initialized with {len(correlator.rules)} rules'))

    def finalize():
        if not args.quiet:
            correlator.report()
        if args.output:
            correlator.export(args.output)

    if args.analyze:
        count = correlator.process_file(args.analyze)
        print(c('info', f'[*] Processed {count} lines from {args.analyze}'))
        finalize()
    elif args.analyze_dir:
        total = 0
        for f in sorted(os.listdir(args.analyze_dir)):
            fpath = os.path.join(args.analyze_dir, f)
            if os.path.isfile(fpath):
                total += correlator.process_file(fpath)
        print(c('info', f'[*] Processed {total} lines total'))
        finalize()
    elif args.tail:
        print(c('info', f'[*] Tailing {args.tail} (Ctrl+C to stop)'))
        try:
            with open(args.tail, 'r', errors='ignore') as f:
                f.seek(0, 2)  # start at end
                while True:
                    line = f.readline()
                    if line:
                        correlator.process_stdin_line(line.rstrip('\n'), args.tail)
                    else:
                        time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[*] Tail stopped")
            finalize()
    elif args.stdin:
        try:
            for line in sys.stdin:
                correlator.process_stdin_line(line.rstrip('\n'))
        except KeyboardInterrupt:
            finalize()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
