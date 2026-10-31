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


class StaffUser(User):
    """Apply the working-hours rule to staff accounts."""

    def can_login(self, hour):
        """Allow staff access from 5am until just before 10pm."""
        return 5 <= hour < 22


class CustomerUser(User):
    """Allow customers to use web and USSD services all day."""

    def can_login(self, hour):
        """Allow customer access at every hour."""
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
