# Week 11 presentation: turning the logs into evidence

**Time:** 5 minutes | **Presenter:** ________ | **Team:** ________

## 1. What we added this week (30 seconds)

“This week we kept the detector system and added data analysis in `analysis.py`.
We used Pandas to clean and summarise the logs, NumPy to calculate an average,
and Matplotlib and Seaborn to save four charts. We also generated a draft
incident report for the latest date in the supplied logs.”

## 2. How the cleaning and calculations work (1 minute)

Open `week11/analysis.py` and point to `clean_data()`.

“`pd.read_csv()` loads the records into a DataFrame, which is a table with named
columns. We trim spaces and standardise statuses and channels. We convert dates
with `pd.to_datetime(..., errors='coerce')`; unparseable dates become missing
dates. We remove rows missing essential values or containing invalid statuses.
We fill missing country, branch and channel with `Unknown`, then remove
duplicates and sort by time.”

The supplied file has **4,980 rows**. Cleaning removes **16 invalid rows and
16 duplicate valid rows**, leaving **4,948**. Show `cleaning_summary.txt`.

“We create a Boolean `failed` column for `FAIL` or `LOCKED`. Grouping by branch
lets us count total attempts and rejections. Failure rate is rejections divided
by all attempts, multiplied by 100. We group by username and use NumPy's mean
on those rejection counts, including users with zero rejections. We group
rejections by IP and sort them to find the top ten candidate attacking IPs.”

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

## 3. How to install and run it (1 minute)

Week 11 needs the four libraries listed in `requirements.txt`. From the project
folder, create an environment and install them:

```sh
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r week11/requirements.txt
python3 week11/main.py
```

On Windows, replace the activation command with `.venv\Scripts\activate`.
Enter `1` to generate the analysis, reports and charts; enter `0` to exit.
After installation, this command runs everything without the menu:

```sh
python3 week11/main.py --report
```

`main.generate()` first runs the Week 10 checks and audit, then calls
`analyse(auditor, events, alerts)`. No chart window needs to open: Matplotlib
uses the `Agg` backend to save PNG files directly into `week11/charts`.

## 4. Explain the four charts and one finding (1 minute 30 seconds)

Open each PNG in `week11/charts`:

| Chart | How we made it | What it shows |
|---|---|---|
| `failed_logins_per_day.png` | Set timestamp as the index and resample rejected attempts by day; plot a line. | How rejection totals change across September. |
| `failed_logins_by_branch.png` | Group the failed column by branch and sum it; draw a Seaborn bar chart. | Which branches have the most rejected attempts. |
| `login_attempts_by_hour.png` | Extract the hour, count attempts and include all 24 hours; draw bars. | When all login activity occurs, including successful attempts. |
| `password_strength_distribution.png` | Count audited staff at each score from zero to six; draw a Seaborn bar chart. | How staff passwords perform against our policy. |

“Our key finding is that Takoradi had the highest failure rate among named
branches: **197 of 1,700 attempts, or 11.59%**. Accra had **8.83%** and Kumasi
had **10.04%**. Four records had an unknown branch; we keep them in the outputs
but exclude Unknown from this named-branch comparison. Our audit also found
**43 of 60** staff passwords below the required score of six.”

## 5. Show the daily report and explain its scope (1 minute)

Open `week11/draft_daily_report.txt`.

“The report uses **30 September 2026**, the latest date in the log. That day
had **205 attempts and 10 rejected attempts**, a **4.88%** failure rate. It shows
alerts starting on that day, then labels the whole-file statistics separately.
We did this so September totals are not presented as one day's activity.
The charts cover the whole file.”

Other generated evidence includes `cleaned_logs.csv`, `branch_summary.csv`,
`top_10_attacking_ips.csv` and `password_scores.csv`. Password outputs contain
scores and usernames only.

“Our recommendation is to confirm unusual staff access, review accounts with
weak passwords and investigate high-failure IPs. A large rejection count is a
reason to investigate, not proof that an IP belongs to an attacker.”

**Be ready to answer:** Why remove bad dates? We cannot safely guess the right
day. Why compare rates as well as counts? Branches have different numbers of
attempts, so counts alone can give an incomplete comparison.
