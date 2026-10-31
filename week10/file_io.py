"""Load login objects and write readable incident alerts."""
from log_rules import load_logs
from models import LoginEvent


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
