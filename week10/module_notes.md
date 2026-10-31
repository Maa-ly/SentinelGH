# Week 10: how we organised our program

- `models.py`: User, StaffUser, CustomerUser, LoginEvent and Alert store our data. Staff log in from 05:00 to before 22:00; customers can log in all day.
- `detectors.py`: Detector gives us a common scan method. Four subclasses override it. The loop in run_detectors calls scan on each object, which demonstrates polymorphism.
- `auditor.py`: PasswordAuditor loads staff and writes weak usernames and scores.
- `file_io.py`: reads login objects and saves alert files.
- `main.py`: runs the menu and connects the parts.
- `log_rules.py`: keeps the working CSV reader and detection helpers from Week 8 so we do not repeat them.

Repeated lockout means three LOCKED records for the same account within ten minutes.
We count FAIL and LOCKED as rejected attempts, matching our Week 8 choice.
The rules flag events for investigation; they do not block accounts.
