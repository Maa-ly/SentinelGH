# Week 9 presentation: modelling users, logins and alerts

**Time:** 5 minutes | **Presenter:** ________ | **Team:** ________

## 1. What changed this week (45 seconds)

“Last week our login records and alerts were dictionaries. This week we added
classes so each part of the bank's data has a clear structure. We also added
a password auditor that checks the fictional staff passwords and saves only
usernames and scores.”

## 2. How our classes work (1 minute)

Open `week9/sentinelgh.py` and `week9/class_diagram.md`.

- `LoginEvent` represents one accepted login row. Its constructor copies the
  timestamp, username, IP, country, branch, channel and status into attributes.
- `User` stores username, branch, role and `failed_login_count`.
  `record_failure()` increases the counter when a rejected staff login is found.
- `Alert` stores type, severity, user, time and message. Its `__str__()` method
  produces the readable line written to the report.
- `PasswordAuditor` loads staff records and creates `User` objects. It records
  missing files, malformed rows and duplicate or blank usernames.

“The underscore in `_password` marks it as an internal attribute by Python
convention. It is not encryption. We call `check_strength()` to get a score
instead of printing the password.”

## 3. How the audit and detection work (1 minute)

`User.check_strength()` gives one point for each of these six rules:

1. At least 12 characters.
2. At least one digit.
3. At least one symbol that is neither a letter, a digit nor whitespace.
4. At least one uppercase letter.
5. At least one lowercase letter.
6. A nonempty password without “password” or “nkabom”, ignoring case.

“Our chosen policy requires all six points. A score below six is saved in
`weak_passwords.csv`. A blank password scores zero. No password is written to
that output. The three detection functions now return `Alert` objects. They
reuse the Week 8 rules in `log_rules.py`, converting the dictionaries returned
by those helpers into objects. This lets us keep the earlier working rules.”

## Where our files are

All four versions use the same input folder:

```text
project1-python/
    logs/
        auth_log.csv
        staff.csv
    week8/
    week9/
    week10/
    week11/
```

`auth_log.csv` contains login attempts. `staff.csv` contains staff details and
fictional passwords for the audit. We do not copy these files into every week.
The code uses `Path(__file__).resolve()` to find its own location and then goes
up to the project folder to find `logs`. This avoids depending on where the
terminal was opened. Each version saves its outputs inside its own week folder.

The commands below start from the `project1-python` folder. Use Python 3.10 or later.
If your computer uses `python` instead of `python3`, use that command throughout.

## 4. How to run and demonstrate it (1 minute 30 seconds)

No extra libraries are needed. Run:

```sh
python3 week9/sentinelgh.py
```

Enter `1` to analyse both shared CSV files and save results. Enter `0` to exit.
For a direct run without using the menu:

```sh
python3 week9/sentinelgh.py --report
```

The supplied data gives **4,948 accepted logins, 32 skipped rows, 49 alerts and
60 staff accounts audited**. Open these files:

- `week9/alerts.txt`: readable Alert objects and skipped-row explanations.
- `week9/weak_passwords.csv`: usernames and scores for **43 accounts** below 6/6.
- `week9/staff_data_issues.txt`: issues found while reading staff records.

Show one alert line and explain how its fields match the `Alert` constructor.
Show one score row and point out that its password is absent.

## 5. What we learned and what comes next (45 seconds)

“We had to connect our new objects to the existing dictionary-based rules.
`LoginEvent.to_dict()` and the alert conversion function provide that link.
Next week we will create a common Detector class, add repeated lockout checks
and split the program into modules.”

**Be ready to answer:** What is a constructor? `__init__()` sets the starting
attributes when an object is created. What does encapsulation do here? It
keeps password scoring inside `User` and gives the rest of the program a
method to request the result.
