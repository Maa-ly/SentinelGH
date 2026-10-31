"""Read fictional staff records and save password audit scores."""
import csv
from models import StaffUser


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
                    self.users.append(StaffUser(username, row['branch'].strip() or 'Unknown',
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
