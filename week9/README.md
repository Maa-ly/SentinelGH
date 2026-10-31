# SentinelGH — Week 9

WIT 102: Introduction to Python Programming
Team number: ________ | Members: ________

Run from this folder with Python 3.10 or later:

```sh
python3 sentinelgh.py
```

Generate all outputs without the menu: `python3 sentinelgh.py --report`.

The supplied staff passwords are fictional course data. Password audit outputs
contain usernames and scores only. Keep real passwords out of this project.

We count FAIL and LOCKED as rejected attempts. The brute-force rule is five
rejected attempts within ten minutes. Off-hours means 22:00 up to, but not
including, 05:00. Unknown countries do not prove foreign access.

Our password policy gives one point each for: 12 or more characters, a digit,
a symbol, uppercase, lowercase, and no occurrence of "password" or "nkabom"
(case insensitive). A password must score 6/6 to pass. A blank password scores
zero. These rules and thresholds are our choices for the exercise.

Before presenting, run the menu and read the code. Each member should explain
one function, one rule and one limitation. Fill in team details before submission.
The ZIP uses "TeamNo" as a placeholder: rename it to your actual team number.

Input files are shared: `../logs/auth_log.csv` and `../logs/staff.csv`.
Paths are resolved from the script location, so any working directory works.
When extracting a weekly ZIP, put its week folder beside the project `logs` folder.
