"""Week 9: users, events, alerts and a password auditor."""
import log_rules
from log_rules import load_logs
"""Classes for users, login records and security alerts."""
from datetime import datetime


class LoginEvent:
    """Store the details of one login attempt."""

    def __init__(self, record):
        """Copy a cleaned CSV record into attributes."""
        self.timestamp = record['timestamp']
        self.username = record['username']
        self.ip_address = record['ip_address']
        self.country = record['country']
        self.branch = record['branch']
        self.channel = record['channel']
        self.status = record['status']

    def to_dict(self):
        """Return the event in the format used by the first version."""
        return vars(self).copy()


class User:
    """Store a user and check their fictional practice password."""

    def __init__(self, username, branch, role, password=''):
        """Set the user's details without displaying the password."""
        self.username = username
        self.branch = branch
        self.role = role
        self.failed_login_count = 0
        self._password = password

    def record_failure(self):
        """Increase this user's failed-login counter."""
        self.failed_login_count += 1

    def check_strength(self):
        """Give one point for each policy rule passed, from zero to six."""
        password = self._password
        score = 0
        score += len(password) >= 12
        score += any(letter.isdigit() for letter in password)
        score += any(not letter.isalnum() and not letter.isspace() for letter in password)
        score += any(letter.isupper() for letter in password)
        score += any(letter.islower() for letter in password)
        score += bool(password) and not any(word in password.lower() for word in ('password', 'nkabom'))
        return int(score)

    def can_login(self, hour):
        """Allow an ordinary user to log in at any hour."""
        return True


class Alert:
    """Describe one finding for the IT officer to investigate."""

    def __init__(self, alert_type, severity, user, time, message):
        """Store the type, severity, account, time and explanation."""
        self.type = alert_type
        self.severity = severity
        self.user = user
        self.time = time
        self.message = message

    def __str__(self):
        """Format one alert without including any password."""
        return f'[{self.severity}] {self.time:%Y-%m-%d %H:%M} {self.type} | {self.user}: {self.message}'
"""Read fictional staff records and save password audit scores."""
import csv


class PasswordAuditor:
    """Check staff passwords without writing them to output files."""

    def __init__(self):
        """Start with no staff and an empty list of data problems."""
        self.users = []
        self.skipped = []

    def load_staff(self, path):
        """Read staff records, recording missing files and invalid rows."""
        self.users = []
        self.skipped = []
        seen = set()
        try:
            with open(path, newline='', encoding='utf-8-sig') as file:
                reader = csv.DictReader(file)
                required = {'username', 'full_name', 'branch', 'role', 'password'}
                if not required.issubset(reader.fieldnames or []):
                    self.skipped.append('Staff file has missing columns')
                    return []
                for number, row in enumerate(reader, 2):
                    if None in row or any(value is None for value in row.values()):
                        self.skipped.append(f'Line {number}: wrong number of columns')
                        continue
                    username = row['username'].strip()
                    if not username or username in seen:
                        self.skipped.append(f'Line {number}: blank or duplicate username')
                        continue
                    seen.add(username)
                    self.users.append(User(username, row['branch'].strip() or 'Unknown',
                                                row['role'].strip() or 'Unknown', row['password']))
        except OSError as error:
            self.skipped.append(f'Cannot read staff file: {error}')
        return self.users

    def scores(self):
        """Return only usernames and scores; a score below six is weak."""
        return [(user.username, user.check_strength()) for user in self.users]

    def save_weak_passwords(self, path):
        """Write accounts that do not meet every rule, never passwords."""
        with open(path, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['username', 'score'])
            writer.writerows((name, score) for name, score in self.scores() if score < 6)
"""Load login objects and write readable incident alerts."""


def load_events(path, skipped=None):
    """Read validated log dictionaries and turn them into objects."""
    return [LoginEvent(row) for row in load_logs(path, skipped)]


def save_alerts(path, alerts, skipped):
    """Save alerts and the reasons for skipped login records."""
    with open(path, 'w', encoding='utf-8') as file:
        file.write('SentinelGH security findings\n')
        file.write(f'Alerts: {len(alerts)} | Skipped rows: {len(skipped)}\n\n')
        for alert in alerts:
            file.write(str(alert) + '\n')
        file.write('\nSkipped records\n')
        for row in skipped:
            file.write(f"Line {row['line']}: {row['reason']}\n")


def convert_alerts(results):
    """Create Alert objects from the Week 8 findings."""
    return [Alert(row['type'], row['severity'], row['user'], row['time'], row['message']) for row in results]


def find_brute_force(events, limit=5):
    """Return brute-force findings as Alert objects."""
    return convert_alerts(log_rules.find_brute_force([event.to_dict() for event in events], limit))


def find_off_hours(events):
    """Return off-hours findings as Alert objects."""
    return convert_alerts(log_rules.find_off_hours([event.to_dict() for event in events]))


def find_foreign_ips(events):
    """Return foreign-IP findings as Alert objects."""
    return convert_alerts(log_rules.find_foreign_ips([event.to_dict() for event in events]))


def run_detectors(events):
    """Collect this week's three object-based detection results."""
    return find_brute_force(events) + find_off_hours(events) + find_foreign_ips(events)
"""Run SentinelGH from a simple menu or generate outputs with --report."""
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent


def generate():
    """Read both files, run the checks and save safe audit results."""
    skipped = []
    events = load_events(BASE.parent / 'logs' / 'auth_log.csv', skipped)
    auditor = PasswordAuditor()
    users = auditor.load_staff(BASE.parent / 'logs' / 'staff.csv')
    lookup = {user.username: user for user in users}
    for event in events:
        if event.status in ('FAIL', 'LOCKED') and event.username in lookup:
            lookup[event.username].record_failure()
    alerts = run_detectors(events)
    save_alerts(BASE / 'alerts.txt', alerts, skipped)
    auditor.save_weak_passwords(BASE / 'weak_passwords.csv')
    (BASE / 'staff_data_issues.txt').write_text('\n'.join(auditor.skipped) or 'No staff data problems.', encoding='utf-8')
    print(f'Loaded {len(events)} logins; skipped {len(skipped)} rows; found {len(alerts)} alerts.')
    print(f'Audited {len(users)} staff accounts. Outputs saved beside this program.')
    return events, auditor, alerts


def main():
    """Keep showing the menu until the user chooses to leave."""
    if '--report' in sys.argv:
        generate()
        return
    while True:
        print('\nSentinelGH\n1. Analyse files and save reports\n0. Exit')
        try:
            choice = input('Choose: ').strip()
        except EOFError:
            return
        if choice == '0':
            return
        if choice == '1':
            generate()
        else:
            print('Please enter 1 or 0.')


if __name__ == '__main__':
    main()
