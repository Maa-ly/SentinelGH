"""Detection rules with a shared scan method."""
from datetime import timedelta
import log_rules
from models import Alert, StaffUser


def convert_alerts(results):
    """Turn the dictionary results from Week 8 into Alert objects."""
    return [Alert(row['type'], row['severity'], row['user'], row['time'], row['message'])
            for row in results]


class Detector:
    """Define the common method that each detector must provide."""

    def scan(self, events):
        """Require a subclass to supply its own detection rule."""
        raise NotImplementedError('Use a detector subclass')


class BruteForceDetector(Detector):
    """Find five or more rejected attempts in ten minutes."""

    def scan(self, events):
        """Reuse the Week 8 time-window rule and return Alert objects."""
        rows = sorted((event.to_dict() for event in events), key=lambda row: row['timestamp'])
        return convert_alerts(log_rules.find_brute_force(rows))


class OffHoursDetector(Detector):
    """Find successful staff access outside working hours."""

    def scan(self, events):
        """Use the staff subclass rule to check login hours."""
        alerts = []
        for event in events:
            user = StaffUser(event.username, event.branch, 'staff')
            if event.channel == 'staff' and event.status == 'SUCCESS' and not user.can_login(event.timestamp.hour):
                alerts.append(Alert('OFF HOURS', 'MEDIUM' if event.country in ('Ghana', 'Unknown') else 'HIGH',
                                    event.username, event.timestamp, f'Staff access from {event.ip_address} ({event.country})'))
        return alerts


class ForeignIPDetector(Detector):
    """Find unique IP addresses recorded outside Ghana."""

    def scan(self, events):
        """Use the foreign-country field and return one alert per IP."""
        rows = sorted((event.to_dict() for event in events), key=lambda row: row['timestamp'])
        return convert_alerts(log_rules.find_foreign_ips(rows))


class LockoutDetector(Detector):
    """Find accounts locked at least three times in ten minutes."""

    def scan(self, events):
        """Keep a ten-minute list of lockouts for each user."""
        windows = {}
        alerts = []
        for event in sorted(events, key=lambda event: event.timestamp):
            if event.status != 'LOCKED':
                continue
            recent = windows.setdefault(event.username, [])
            recent[:] = [time for time in recent if event.timestamp - time <= timedelta(minutes=10)]
            recent.append(event.timestamp)
            if len(recent) >= 3:
                alerts.append(Alert('REPEATED LOCKOUT', 'HIGH', event.username, event.timestamp,
                                    'Three lockouts within ten minutes'))
                recent.clear()
        return alerts


def run_detectors(events):
    """Call the same method on different detector objects (polymorphism)."""
    alerts = []
    for detector in [BruteForceDetector(), OffHoursDetector(), ForeignIPDetector(), LockoutDetector()]:
        alerts.extend(detector.scan(events))
    return sorted(alerts, key=lambda alert: alert.time)
