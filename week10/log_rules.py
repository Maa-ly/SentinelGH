"""
Shared log loading and detection functions from Week 8
WIT 102 Group Project - Nkabom Savings & Loans

Reads auth_log.csv, skips bad rows, and checks for brute-force attacks,
password spraying, late night staff logins and logins from outside Ghana.
The results are saved to alerts_week8.txt.
"""

import csv
from datetime import datetime, timedelta
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "auth_log.csv"
ALERT_FILE = Path(__file__).parent / "alerts_week8.txt"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

COLUMNS = ["timestamp", "username", "ip_address", "country", "branch", "channel", "status"]
VALID_STATUS = ["SUCCESS", "FAIL", "LOCKED"]
FAILED_STATUS = ["FAIL", "LOCKED"]   # LOCKED means the attempt was also rejected

TEN_MINUTES = timedelta(minutes=10)
SPRAY_LIMIT = 5      # one IP failing on 5+ different accounts
NIGHT_START = 22     # 10pm
NIGHT_END = 5        # 5am


# ---------- reading the file ----------

def clean_row(row):
    """Check one row and tidy it up. Raises ValueError if the row is bad."""
    for column in ["timestamp", "username", "ip_address", "status"]:
        if row[column] == "":
            raise ValueError("missing " + column)

    try:
        row["timestamp"] = datetime.strptime(row["timestamp"], TIME_FORMAT)
    except ValueError:
        raise ValueError("bad timestamp '" + row["timestamp"] + "'")

    row["channel"] = row["channel"].lower()
    row["country"] = row["country"].title()
    row["status"] = row["status"].upper()   # some rows say 'Fail'
    if row["status"] not in VALID_STATUS:
        raise ValueError("unknown status '" + row["status"] + "'")

    # a blank branch or country is not serious, so we keep the row
    for column in ["country", "branch", "channel"]:
        if row[column] == "":
            row[column] = "Unknown"
    return row


def get_time(record):
    """Return the timestamp of a record (used for sorting)."""
    return record["timestamp"]


def load_logs(path, skipped=None):
    """Read the log file and return a list of dictionaries, one per login.

    Bad rows and duplicate rows are not loaded. If a list is passed in as
    skipped, each skipped row is added to it with the reason.
    """
    if skipped is None:
        skipped = []
    logs = []
    seen = set()   # to find duplicate rows

    try:
        with open(path, "r", encoding="utf-8") as file:
            reader = csv.reader(file)
            header = next(reader, [])
            header = [name.strip().lower() for name in header]

            for column in COLUMNS:
                if column not in header:
                    print("Error: column", column, "is missing from", path)
                    return []

            line_number = 1
            for values in reader:
                line_number += 1
                raw_line = ",".join(values)

                if raw_line.strip(",").strip() == "":
                    continue   # empty line

                if raw_line in seen:
                    skipped.append({"line": line_number, "reason": "duplicate row", "raw": raw_line})
                    continue
                seen.add(raw_line)

                if len(values) != len(header):
                    skipped.append({"line": line_number, "reason": "wrong number of columns", "raw": raw_line})
                    continue

                row = {}
                for i in range(len(header)):
                    row[header[i]] = values[i].strip()

                try:
                    logs.append(clean_row(row))
                except ValueError as error:
                    skipped.append({"line": line_number, "reason": str(error), "raw": raw_line})

    except FileNotFoundError:
        print("Error: could not find the file", path)
        return []

    logs.sort(key=get_time)
    return logs


# ---------- detection rules ----------

def make_alert(alert_type, severity, user, time, message):
    """Put the details of one alert into a dictionary."""
    return {"type": alert_type, "severity": severity, "user": user,
            "time": time, "message": message}


def get_alert_time(alert):
    """Return the time of an alert (used for sorting)."""
    return alert["time"]


def find_brute_force(logs, limit=5):
    """Find users with `limit` or more failed logins within 10 minutes."""
    # group the failed logins by user (logs are already in time order)
    failed = {}
    for record in logs:
        if record["status"] in FAILED_STATUS:
            user = record["username"]
            if user not in failed:
                failed[user] = []
            failed[user].append(record)

    alerts = []
    for user in failed:
        attempts = failed[user]
        i = 0
        while i < len(attempts):
            # move j forward while the attempts are still within 10 minutes of attempt i
            j = i
            while j + 1 < len(attempts) and attempts[j + 1]["timestamp"] - attempts[i]["timestamp"] <= TEN_MINUTES:
                j += 1
            count = j - i + 1

            if count >= limit:
                ips = set()
                for attempt in attempts[i:j + 1]:
                    ips.add(attempt["ip_address"] + " (" + attempt["country"] + ")")
                message = f"{count} failed logins in 10 minutes from {', '.join(ips)}"
                alerts.append(make_alert("BRUTE FORCE", "HIGH", user, attempts[i]["timestamp"], message))
                i = j + 1   # skip this attack so it is only reported once
            else:
                i += 1

    alerts.sort(key=get_alert_time)
    return alerts


def find_password_spray(logs):
    """Find IP addresses that failed to log in to many different accounts.

    This is one password tried on many accounts, so find_brute_force
    does not see it (each account only fails once or twice).
    """
    accounts = {}   # ip -> set of usernames
    first_try = {}  # ip -> first failed record
    for record in logs:
        if record["status"] in FAILED_STATUS:
            ip = record["ip_address"]
            if ip not in accounts:
                accounts[ip] = set()
                first_try[ip] = record
            accounts[ip].add(record["username"])

    alerts = []
    for ip in accounts:
        if len(accounts[ip]) >= SPRAY_LIMIT:
            first = first_try[ip]
            message = f"{ip} ({first['country']}) failed on {len(accounts[ip])} different accounts"
            alerts.append(make_alert("PASSWORD SPRAY", "HIGH", "many accounts", first["timestamp"], message))
    return alerts


def find_off_hours(logs):
    """Find successful staff logins between 10pm and 5am."""
    alerts = []
    for record in logs:
        hour = record["timestamp"].hour
        if record["channel"] == "staff" and record["status"] == "SUCCESS":
            if hour >= NIGHT_START or hour < NIGHT_END:
                # at night AND from abroad is worse than just at night
                if record["country"] != "Ghana":
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                message = f"staff login at {record['timestamp'].strftime('%H:%M')} from {record['ip_address']} ({record['country']})"
                alerts.append(make_alert("OFF HOURS", severity, record["username"], record["timestamp"], message))
    return alerts


def find_foreign_ips(logs):
    """Find logins from outside Ghana. Gives one alert per foreign IP address."""
    foreign_ips = set()
    for record in logs:
        if record["country"] != "Ghana" and record["country"] != "Unknown":
            foreign_ips.add(record["ip_address"])

    alerts = []
    for ip in foreign_ips:
        users = set()
        staff_logins = set()
        attempts = 0
        successes = 0
        country = ""
        first_time = None

        for record in logs:
            if record["ip_address"] == ip:
                attempts += 1
                users.add(record["username"])
                country = record["country"]
                if first_time is None:
                    first_time = record["timestamp"]
                if record["status"] == "SUCCESS":
                    successes += 1
                    if record["channel"] == "staff":
                        staff_logins.add(record["username"])

        # a staff account logged in from abroad is the worst case
        if len(staff_logins) > 0:
            severity = "CRITICAL"
        elif successes > 0:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        message = f"{ip} ({country}): {attempts} attempts, {successes} successful, accounts: {', '.join(sorted(users))}"
        if len(staff_logins) > 0:
            message += " -> STAFF LOGGED IN: " + ", ".join(sorted(staff_logins))
        alerts.append(make_alert("FOREIGN IP", severity, ", ".join(sorted(users)), first_time, message))

    alerts.sort(key=get_alert_time)
    return alerts



# ---------- counting ----------

def count_failures(logs, column):
    """Count failed logins for each value in a column, e.g. 'username' or 'ip_address'."""
    counts = {}
    for record in logs:
        if record["status"] in FAILED_STATUS:
            key = record[column]
            if key in counts:
                counts[key] += 1
            else:
                counts[key] = 1
    return counts


def get_count(item):
    """Return the count part of a (name, count) pair (used for sorting)."""
    return item[1]


def top_ten(counts):
    """Return the 10 biggest counts as a list of (name, count) pairs."""
    items = list(counts.items())
    items.sort(key=get_count, reverse=True)
    return items[:10]


# ---------- output ----------

def alert_to_text(alert):
    """Turn one alert into a line of text."""
    time = alert["time"].strftime("%Y-%m-%d %H:%M")
    return f"[{alert['severity']}] {time}  {alert['user']}: {alert['message']}"


def show_alerts(title, alerts):
    """Print a list of alerts on the screen."""
    print(f"\n--- {title}: {len(alerts)} found ---")
    for alert in alerts:
        print(alert_to_text(alert))


def show_counts(logs):
    """Print the top 10 users and IP addresses by failed logins."""
    print("\nTop 10 accounts by failed logins:")
    for user, count in top_ten(count_failures(logs, "username")):
        print(f"  {user:<15}{count:>4}")
    print("\nTop 10 IP addresses by failed logins:")
    for ip, count in top_ten(count_failures(logs, "ip_address")):
        print(f"  {ip:<18}{count:>4}")


def write_alerts(path, logs, skipped):
    """Run all the checks and save the results to a text file."""
    sections = [
        ("BRUTE-FORCE ATTEMPTS", find_brute_force(logs)),
        ("PASSWORD SPRAYING", find_password_spray(logs)),
        ("LOGINS FROM FOREIGN IP ADDRESSES", find_foreign_ips(logs)),
        ("STAFF LOGINS BETWEEN 10PM AND 5AM", find_off_hours(logs)),
    ]

    total = 0
    for title, alerts in sections:
        total += len(alerts)

    try:
        with open(path, "w", encoding="utf-8") as file:
            file.write("SentinelGH Security Alerts - Week 8\n")
            file.write("Nkabom Savings & Loans\n")
            file.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
            file.write("=" * 60 + "\n\n")

            file.write(f"Records loaded:  {len(logs)}\n")
            file.write(f"Rows skipped:    {len(skipped)}\n")
            file.write(f"Failed logins:   {sum(count_failures(logs, 'username').values())}\n")
            file.write(f"Total alerts:    {total}\n\n")

            for title, alerts in sections:
                file.write(f"{title} ({len(alerts)})\n")
                file.write("-" * 60 + "\n")
                if len(alerts) == 0:
                    file.write("None found\n")
                for alert in alerts:
                    file.write(alert_to_text(alert) + "\n")
                file.write("\n")

            file.write("TOP 10 ACCOUNTS BY FAILED LOGINS\n")
            file.write("-" * 60 + "\n")
            for user, count in top_ten(count_failures(logs, "username")):
                file.write(f"{user:<15}{count:>4}\n")

            file.write("\nTOP 10 IP ADDRESSES BY FAILED LOGINS\n")
            file.write("-" * 60 + "\n")
            for ip, count in top_ten(count_failures(logs, "ip_address")):
                file.write(f"{ip:<18}{count:>4}\n")

            file.write(f"\nSKIPPED ROWS ({len(skipped)})\n")
            file.write("-" * 60 + "\n")
            for row in skipped:
                file.write(f"line {row['line']}: {row['reason']}  ->  {row['raw']}\n")
    except OSError:
        print("Error: could not write to", path)
        return 0

    return total


# ---------- menu ----------

def show_menu():
    """Print the menu options."""
    print("\n===== SentinelGH - Week 8 =====")
    print("1. Load log file")
    print("2. Brute-force attempts")
    print("3. Password spraying")
    print("4. Off-hours staff logins")
    print("5. Foreign IP addresses")
    print("6. Failed login counts")
    print("7. Skipped rows")
    print("8. Save all alerts to alerts_week8.txt")
    print("0. Exit")


def main():
    """Load the logs, then keep showing the menu until the user exits."""
    skipped = []
    logs = load_logs(LOG_FILE, skipped)
    if len(logs) > 0:
        print(f"Loaded {len(logs)} records, skipped {len(skipped)} bad rows.")

    running = True
    while running:
        show_menu()
        try:
            choice = input("Enter choice: ").strip()
        except EOFError:
            break

        if choice == "0":
            print("Goodbye!")
            running = False
        elif choice == "1":
            path = input("File name (press Enter for auth_log.csv): ").strip()
            if path == "":
                path = LOG_FILE
            skipped = []
            logs = load_logs(path, skipped)
            if len(logs) > 0:
                print(f"Loaded {len(logs)} records, skipped {len(skipped)} bad rows.")
        elif choice in ["2", "3", "4", "5", "6", "7", "8"] and len(logs) == 0:
            print("No data loaded yet. Use option 1 first.")
        elif choice == "2":
            show_alerts("Brute-force attempts", find_brute_force(logs))
        elif choice == "3":
            show_alerts("Password spraying", find_password_spray(logs))
        elif choice == "4":
            show_alerts("Off-hours staff logins", find_off_hours(logs))
        elif choice == "5":
            show_alerts("Foreign IP addresses", find_foreign_ips(logs))
        elif choice == "6":
            show_counts(logs)
        elif choice == "7":
            print(f"\n--- Skipped rows: {len(skipped)} ---")
            for row in skipped:
                print(f"line {row['line']}: {row['reason']}")
        elif choice == "8":
            total = write_alerts(ALERT_FILE, logs, skipped)
            print(f"Saved {total} alerts to {ALERT_FILE}")
        else:
            print("Invalid choice, try again.")


if __name__ == "__main__":
    main()
