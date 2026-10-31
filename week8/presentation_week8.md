# Week 8 presentation: reading logs and finding suspicious logins

**Time:** 5 minutes | **Presenter:** ________ | **Team:** ________

## 1. What we did this week (45 seconds)

“We started with the problem at Nkabom Savings & Loans: customers were being
locked out and staff accounts were being accessed at unusual times. We built
a first version of SentinelGH that reads the login CSV, checks suspicious
activity and saves the results. This week we used functions, lists,
dictionaries, sets, loops and file handling.”

## 2. How we read and cleaned the file (1 minute)

Open `week8/sentinelgh.py` and show `load_logs()` and `clean_row()`.

“`load_logs()` opens the file with a `with` statement, so Python closes it when
reading finishes. `csv.reader` separates the columns. We store each valid
login as a dictionary, and all these dictionaries go into a list.

`clean_row()` checks required fields, converts the timestamp using
`datetime.strptime`, and standardises status and country values. Missing
optional fields become `Unknown`. We use a set to recognise duplicate rows.
Bad rows are recorded with their line numbers and reasons. `try` and `except`
handle missing files and invalid values. Finally, we sort the accepted
records by timestamp so the detection rules can work in time order.”

## 3. How our detection rules work (1 minute)

- `find_brute_force()` groups rejected attempts by username. It checks how many
  fit into a ten-minute window. Five or more produce an alert. We count both
  `FAIL` and `LOCKED` as rejected attempts and skip past a reported group to
  avoid reporting that same group repeatedly.
- `find_off_hours()` checks successful staff logins. Hours from 22:00 until
  before 05:00 are flagged; 05:00 itself is allowed.
- `find_foreign_ips()` uses a set of unique IP addresses whose country is
  outside Ghana. It produces one alert per foreign IP. `Unknown` is not
  treated as evidence of a foreign location.
- We also added `find_password_spray()`: one IP failing on five or more
  different accounts across the loaded file. This rule has no time window.
- `count_failures()` uses a dictionary to count rejections per username or IP.

“These rules flag activity for the IT officer to check. They do not prove an
attack or automatically block anyone.”

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

In a terminal, from the project folder, run:

```sh
python3 week8/sentinelgh.py
```

1. The program loads `logs/auth_log.csv` automatically. Point out the message
   showing **4,948 accepted records and 32 skipped rows**.
2. Enter `7` to show why rows were skipped.
3. Enter `2` to show brute-force alerts.
4. Enter `4` to show off-hours staff logins, then `5` for foreign IP alerts.
5. Enter `6` to show failure counts per user and IP.
6. Enter `8` to write all findings to `week8/alerts_week8.txt`.
7. Enter `0` to exit, then open the saved text file in the editor.

Option `1` reloads a file. Press Enter at its filename prompt to use the shared
log again. You can also enter a different file path to test another CSV.

## 5. What we learned and what comes next (45 seconds)

“Our main challenge was reading imperfect data without stopping the program.
Recording skipped rows lets us explain what was left out. The first version
uses dictionaries for records and alerts. Next week we will model them with
classes and add the staff password audit.”

**Be ready to answer:** Why do we use a set for duplicate rows? Because each
value is kept only once and membership checks make duplicates easy to detect.
Why ten minutes and five attempts? Those are the thresholds in the brief.
