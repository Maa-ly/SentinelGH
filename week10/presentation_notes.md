# Week 10 presentation: inheritance, polymorphism and modules

**Time:** 10 minutes | **Presenter:** ________ | **Team:** ________

## 1. What we built this week (1 minute)

“This week we organised SentinelGH into separate modules and added inheritance.
We created a base Detector class, four detector subclasses and separate staff
and customer user classes. We also added a repeated-lockout rule. Every module,
class and function has a docstring explaining its purpose.”

## 2. Why we split the code into modules (1 minute 30 seconds)

Open `week10/module_notes.md`, then show the files in the editor.

| Module | What we put there and why |
|---|---|
| `models.py` | User, StaffUser, CustomerUser, LoginEvent and Alert: the data our program represents. |
| `detectors.py` | The base Detector and four subclasses: the rules that inspect events. |
| `auditor.py` | PasswordAuditor: staff loading and safe password score output. |
| `file_io.py` | `load_events()` and `save_alerts()`: reading login objects and writing findings. |
| `main.py` | The menu and `generate()`: connects the parts in the order needed. |
| `log_rules.py` | The reusable CSV loader and earlier detection helpers from Week 8. |

“Keeping these jobs in separate files makes it easier to find a rule or change
an output without searching through the whole program. Imports let the modules
use each other's classes and functions.”

## 3. How inheritance and overriding work (1 minute 30 seconds)

Open `models.py`.

“`StaffUser` and `CustomerUser` inherit from `User`. They share its constructor,
identity attributes, failed-login counter and password-scoring method. Each
subclass overrides `can_login(hour)` with its own rule. Staff are allowed from
05:00 until before 22:00. Customers are allowed at every hour because web and
USSD services are available all day.”

Open `detectors.py`.

“`Detector` defines `scan(events)`. Its base implementation raises
`NotImplementedError`, telling us a subclass must provide the actual rule.
Each detector overrides that method and returns a list of Alert objects.”

## 4. What each detector checks (1 minute)

- `BruteForceDetector`: five or more rejected attempts for one user within ten
  minutes. It reuses the earlier function and converts its results to objects.
- `OffHoursDetector`: successful staff access outside `StaffUser.can_login()`.
- `ForeignIPDetector`: one alert per foreign IP, using the supplied country field.
- `LockoutDetector`: three `LOCKED` records for one user within ten minutes.
  This threshold is our choice because the brief does not give one.

For lockouts, we keep a list of recent times per user. Before adding a new
lockout we remove times older than ten minutes. When the list reaches three,
we create an alert and clear that user's list to avoid repeating that group.

## 5. Walk through polymorphism (1 minute)

Show `run_detectors()`:

```python
for detector in [BruteForceDetector(), OffHoursDetector(),
                 ForeignIPDetector(), LockoutDetector()]:
    alerts.extend(detector.scan(events))
```

“The loop makes the same `scan(events)` call on each object. Python runs the
implementation belonging to that object's class. That is polymorphism.
`extend()` collects the returned alerts into one list. We then sort them by
time. To add another detector, we can give it a scan method and add its object
to this list.”

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

## 6. How to run the live demonstration (2 minutes)

No extra libraries are needed. From the project folder:

```sh
python3 week10/main.py
```

1. Enter `1` to load the shared logs and staff records, run all four detectors
   and write the reports.
2. Point out **4,948 logins, 32 skipped rows, 66 alerts and 60 staff audited**.
3. Open `week10/alerts.txt`. Find a `REPEATED LOCKOUT` line and explain that
   it came from `LockoutDetector.scan()`.
4. Open `week10/weak_passwords.csv`. Its scores still follow the six-rule policy.
5. Return to the terminal and enter `0` to exit.

For a direct demonstration without menu input:

```sh
python3 week10/main.py --report
```

`generate()` loads events, loads staff, builds a username-to-user dictionary,
updates staff failure counters, runs the detector loop and saves the outputs.
All outputs stay in `week10`; neither input CSV is modified.

## 7. Checks, limitations and next step (1 minute)

“We checked that five failures within exactly ten minutes trigger an alert,
while the same five spread over eleven minutes do not. We also checked three
lockouts at the boundary and the staff/customer hour rules. These checks help
us catch mistakes at the edges of our conditions.

The rules generate investigation leads. A night login may be approved overtime,
and the country field comes from the CSV. Next week we will use Pandas and
NumPy to summarise the data and create charts for management.”

**Be ready to answer:** How is overriding different from inheritance?
Inheritance supplies shared behaviour from a parent class; overriding replaces
one inherited method with the subclass's version. Why 66 alerts instead of
Week 9's 49? The added lockout detector contributes 17 alerts in these logs.
