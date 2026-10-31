"""Run SentinelGH from a simple menu or generate outputs with --report."""
from pathlib import Path
import sys
from auditor import PasswordAuditor
from file_io import load_events, save_alerts
from detectors import run_detectors

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
    from analysis import analyse
    try:
        analyse(auditor, events, alerts)
    except ValueError as error:
        print(error)
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
